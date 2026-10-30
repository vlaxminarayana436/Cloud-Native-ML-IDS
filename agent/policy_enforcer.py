"""Optional Linux IPv4 iptables reconciler; disabled by default.

Only use in an authorized namespace on the traffic path. Staged chains are
swapped after population. Failures retain the previous rules; inspect and clean
up after abnormal termination. Automated tests mock iptables.
"""
from __future__ import annotations
import ipaddress
import platform
import subprocess
import threading

NON_PUBLIC=('0.0.0.0/8','10.0.0.0/8','100.64.0.0/10','127.0.0.0/8','169.254.0.0/16','172.16.0.0/12','192.168.0.0/16','224.0.0.0/4','240.0.0.0/4')
PRIVATE=tuple(ipaddress.ip_network(v) for v in ('10.0.0.0/8','172.16.0.0/12','192.168.0.0/16'))

def network(value,private=False):
    try: net=ipaddress.ip_network(str(value),strict=False)
    except ValueError: return None
    if net.version!=4 or net.prefixlen<(24 if private else 16): return None
    if private and not any(net.subnet_of(p) for p in PRIVATE): return None
    return str(net)

def safe_block_host(value):
    try: address=ipaddress.ip_address(str(value))
    except ValueError: return None
    if address.version!=4 or address.is_loopback or address.is_unspecified or address.is_multicast or address.is_link_local or address.is_reserved: return None
    return f'{address}/32'

def port_arg(value):
    try:
        parts=str(value).split('-');start=int(parts[0]);end=int(parts[-1])
        if len(parts)>2 or not 1<=start<=end<=65535: return None
        return str(start) if start==end else f'{start}:{end}'
    except ValueError: return None

def compile_access(bundle):
    settings=bundle.get('settings',{});incoming=[];forward=[]
    if not settings.get('enabled') or settings.get('mode')!='enforce': return incoming,forward
    trusted=sorted({net for item in bundle.get('trusted_networks',[]) if item.get('enabled') for net in [network(item.get('cidr',''))] if net})
    for resource in bundle.get('resources',[]):
        if not resource.get('enabled'): continue
        target=network(resource.get('destination_cidr',''),private=True)
        if not target: continue
        proto=resource.get('protocol','TCP').lower();protocols=['tcp','udp'] if proto=='any' else [proto]
        for protocol in protocols:
            if protocol not in {'tcp','udp'}: continue
            for raw in resource.get('ports',[]):
                port=port_arg(raw)
                if not port: continue
                for net in trusted: incoming.append(['-s',net,'-d',target,'-p',protocol,'--dport',port,'-j','RETURN'])
                incoming.append(['-d',target,'-p',protocol,'--dport',port,'-j','DROP'])
    forward=list(incoming)
    if settings.get('egress_enabled'):
        managed=[net for value in settings.get('egress_cidrs',[]) for net in [network(value,private=True)] if net]
        if managed:
            forward.extend([['-s',net,'-j','RETURN'] for net in trusted])
            for source in managed:
                forward.extend([['-s',source,'-d',dest,'-j','RETURN'] for dest in NON_PUBLIC]);forward.append(['-s',source,'-j','DROP'])
    return incoming,forward

def run_iptables(args):
    try: return subprocess.run(['iptables',*args],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=5).returncode==0
    except (OSError,subprocess.SubprocessError): return False

class Enforcer(threading.Thread):
    def __init__(self,session,api_base,access=False,blocklist=False,interval=5):
        super().__init__(daemon=True,name='firewall-enforcer');self.session=session;self.base=api_base;self.access=access;self.blocklist=blocklist;self.interval=interval;self.stop_event=threading.Event();self.lock=threading.Lock();self.signatures={};self.hooks={}
        if access: self.hooks.update({'access_in':('INPUT','MLIDS_ACCESS_IN','MLIDS_IN_A','MLIDS_IN_B'),'access_fwd':('FORWARD','MLIDS_ACCESS_FWD','MLIDS_FWD_A','MLIDS_FWD_B')})
        if blocklist: self.hooks.update({'block_in':('INPUT','MLIDS_BLOCK_IN','MLIDS_BI_A','MLIDS_BI_B'),'block_fwd':('FORWARD','MLIDS_BLOCK_FWD','MLIDS_BF_A','MLIDS_BF_B')})
    @staticmethod
    def ensure(chain): return run_iptables(['-n','-L',chain]) or run_iptables(['-N',chain]) or run_iptables(['-n','-L',chain])
    def sync_hook(self,key,rules,allow_established):
        hook,dispatch,a,b=self.hooks[key]
        if not all(self.ensure(c) for c in (dispatch,a,b)): return False
        active=a if run_iptables(['-C',dispatch,'-j',a]) else (b if run_iptables(['-C',dispatch,'-j',b]) else None);stage=b if active==a else a
        if not run_iptables(['-F',stage]): return False
        wanted=([['-m','conntrack','--ctstate','ESTABLISHED,RELATED','-j','RETURN']] if allow_established else [])+rules+[['-j','RETURN']]
        for rule in wanted:
            if not run_iptables(['-A',stage,*rule]): run_iptables(['-F',stage]);return False
        if active:
            if not run_iptables(['-R',dispatch,'1','-j',stage]): return False
        elif not run_iptables(['-F',dispatch]) or not run_iptables(['-A',dispatch,'-j',stage]): return False
        if not run_iptables(['-C',hook,'-j',dispatch]) and not run_iptables(['-I',hook,'1','-j',dispatch]): return False
        return True
    def refresh(self):
        desired={}
        if self.access:
            response=self.session.get(self.base+'/access-policy',timeout=5);response.raise_for_status();incoming,forward=compile_access(response.json());desired.update(access_in=(incoming,True),access_fwd=(forward,True))
        if self.blocklist:
            response=self.session.get(self.base+'/blocklist',timeout=5);response.raise_for_status();hosts=[]
            for item in response.json():
                host=safe_block_host(item.get('ip',''))
                if item.get('active') and item.get('enforceable') is True and host: hosts.append(host)
            rules=[['-s',host,'-j','DROP'] for host in sorted(set(hosts))];desired.update(block_in=(rules,False),block_fwd=(rules,False))
        with self.lock:
            for key,(rules,allow_established) in desired.items():
                if self.stop_event.is_set(): return
                signature=repr((rules,allow_established));hook,dispatch,_,_=self.hooks[key]
                if signature==self.signatures.get(key) and run_iptables(['-C',hook,'-j',dispatch]): continue
                if self.sync_hook(key,rules,allow_established): self.signatures[key]=signature;print(f'[ENFORCER] {key}: {len(rules)} IPv4 rules',flush=True)
                else: print(f'[WARN] {key} sync failed; last rules retained when possible',flush=True)
    def cleanup(self):
        with self.lock:
            for hook,dispatch,a,b in self.hooks.values():
                while run_iptables(['-C',hook,'-j',dispatch]):
                    if not run_iptables(['-D',hook,'-j',dispatch]): break
                run_iptables(['-F',dispatch]);run_iptables(['-F',a]);run_iptables(['-F',b]);run_iptables(['-X',dispatch]);run_iptables(['-X',a]);run_iptables(['-X',b])
    def run(self):
        if platform.system()!='Linux': print('[WARN] Firewall enforcement requires Linux',flush=True);return
        while not self.stop_event.is_set():
            try: self.refresh()
            except Exception as exc: print(f'[WARN] Enforcer refresh failed; retaining previous rules: {exc}',flush=True)
            self.stop_event.wait(self.interval)
