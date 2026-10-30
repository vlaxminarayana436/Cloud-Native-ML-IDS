"""Sentinel: labeled synthetic demo or opt-in live IPv4 capture."""
from __future__ import annotations
import argparse
import os
import random
import signal
import socket
import threading
import time
from dataclasses import dataclass
from queue import Empty,Full,Queue
from urllib.parse import urlsplit
import requests
from policy_enforcer import Enforcer

@dataclass
class Flow:
    key:tuple;first:float;last:float;count:int=0;bytes:int=0;iat:float=0.;syn:int=0;ack:int=0
    def add(self,timestamp,size,flags):
        if self.count: self.iat+=max(0,timestamp-self.last)
        self.last=timestamp;self.count+=1;self.bytes+=size;self.syn+=int('S' in flags);self.ack+=int('A' in flags)
    def record(self,agent_id):
        src,dst,sport,dport,protocol=self.key
        return {'timestamp':self.last,'agent_id':agent_id,'traffic_source':'capture','src_ip':src,'dst_ip':dst,'src_port':sport,'dst_port':dport,'protocol':protocol,'flow_duration':max(0,self.last-self.first),'packet_count':self.count,'byte_count':self.bytes,'iat_mean':self.iat/max(1,self.count-1),'average_packet_size':self.bytes/max(1,self.count),'syn_count':self.syn,'ack_count':self.ack,'syn_ack_ratio':self.syn/max(1,self.ack)}

class Client:
    def __init__(self,url,key=''):
        self.url=url;self.base=url.removesuffix('/flows/process').rstrip('/');self.session=requests.Session();self.heartbeat_session=requests.Session();self.enforcer_session=requests.Session()
        if key:
            for session in (self.session,self.heartbeat_session,self.enforcer_session): session.headers['X-API-Key']=key
    def send(self,flow):
        try:
            response=self.session.post(self.url,json=flow,timeout=5);response.raise_for_status();result=response.json()
            prefix='ALERT' if result['classification']=='Malicious' else ('POLICY' if result['policy_action']!='allow' else 'NORMAL')
            print(f"[{prefix}] {result['attack_type']} · {flow['src_ip']} → {flow['dst_ip']}:{flow['dst_port']} · {result['action']}",flush=True);return True
        except (requests.RequestException,ValueError,KeyError) as exc: print(f'[WARN] Flow submission failed: {exc}',flush=True);return False
    def heartbeat(self,agent_id,source,interface=None):
        try: response=self.heartbeat_session.post(self.base+'/agents/heartbeat',json={'agent_id':agent_id,'traffic_source':source,'interface':interface},timeout=3);response.raise_for_status()
        except requests.RequestException as exc: print(f'[WARN] Heartbeat failed: {exc}',flush=True)

def demo_flow(agent_id,rng):
    kind=rng.choices(['normal','policy','syn','scan','brute','udp','novel'],[52,8,10,8,6,7,9])[0]
    dst=rng.choice(['192.168.1.50','142.250.190.46','52.96.0.1']) if kind=='normal' else '192.168.1.50'
    src=f"10.0.0.{rng.randint(20,230)}" if kind=='normal' else (f"198.51.100.{rng.randint(2,250)}" if kind in ('policy','novel') else f"203.0.113.{rng.randint(2,250)}")
    protocol='UDP' if kind=='udp' else 'TCP';port=53 if kind=='udp' else rng.choice([22,443])
    if kind in ('normal','policy'): n=rng.randint(8,55);size=rng.randint(400,1100);duration=rng.uniform(5,30);syn=1;ack=int(n*.75)
    elif kind=='syn': n=rng.randint(400,1000);size=rng.randint(60,130);duration=rng.uniform(.3,3);syn=int(n*.9);ack=rng.randint(0,4)
    elif kind=='scan': n=rng.randint(150,400);size=rng.randint(60,150);duration=rng.uniform(2,8);syn=int(n*.75);ack=int(n*.1)
    elif kind=='brute': n=rng.randint(100,300);size=rng.randint(220,420);duration=rng.uniform(10,30);syn=int(n*.22);ack=int(n*.55)
    elif kind=='udp': n=rng.randint(300,1000);size=rng.randint(200,400);duration=rng.uniform(.4,3);syn=ack=0
    else: n=rng.randint(600,850);size=rng.randint(900,1300);duration=rng.uniform(1,3);syn=rng.randint(1,5);ack=int(n*rng.uniform(.6,.95))
    return {'timestamp':time.time(),'agent_id':agent_id,'traffic_source':'synthetic','src_ip':src,'dst_ip':dst,'src_port':rng.randint(40000,65000),'dst_port':port,'protocol':protocol,'flow_duration':duration,'packet_count':n,'byte_count':n*size,'iat_mean':duration/max(1,n-1),'average_packet_size':size,'syn_count':syn,'ack_count':ack,'syn_ack_ratio':syn/max(1,ack)}

def commander_endpoint(url):
    parsed=urlsplit(url);host=parsed.hostname;port=parsed.port or (443 if parsed.scheme=='https' else 80)
    if not host: return set(),port
    try: addresses={item[4][0] for item in socket.getaddrinfo(host,port,socket.AF_INET,socket.SOCK_STREAM)}
    except socket.gaierror: addresses=set()
    return addresses,port

def is_commander_flow(src,dst,sport,dport,addresses,port): return (dport==port and dst in addresses) or (sport==port and src in addresses)

def flush_due_flows(flows,now,agent_id,idle_timeout,window_seconds,submit,flush_all=False):
    dropped=0
    for key,flow in list(flows.items()):
        if flush_all or now-flow.last>=idle_timeout or now-flow.first>=window_seconds:
            flows.pop(key,None)
            if flow.count and not submit(flow.record(agent_id)): dropped+=1
    return dropped

def live(client,agent_id,interface,flow_timeout=5,window_seconds=5):
    from scapy.all import IP,TCP,UDP,sniff
    flows={};running=True;dropped_packets=0;dropped_flows=0;addresses,api_port=commander_endpoint(client.url)
    if not addresses: print('[WARN] Cannot resolve Commander; its own uploads may appear as flows',flush=True)
    pending=Queue(maxsize=2000);sender_done=threading.Event()
    def sender():
        while not sender_done.is_set() or not pending.empty():
            try: flow=pending.get(timeout=.3)
            except Empty: continue
            try: client.send(flow)
            finally: pending.task_done()
    worker=threading.Thread(target=sender,daemon=True,name='flow-sender');worker.start()
    def enqueue(flow):
        try: pending.put_nowait(flow);return True
        except Full: return False
    def stop(*_):
        nonlocal running
        running=False
    signal.signal(signal.SIGINT,stop);signal.signal(signal.SIGTERM,stop)
    def packet_handler(packet):
        nonlocal dropped_packets
        if IP not in packet: return
        ip=packet[IP]
        if TCP in packet: transport=packet[TCP];proto='TCP';flags=str(transport.flags)
        elif UDP in packet: transport=packet[UDP];proto='UDP';flags=''
        else: return
        key=(str(ip.src),str(ip.dst),int(transport.sport),int(transport.dport),proto);ts=float(packet.time)
        if proto=='TCP' and is_commander_flow(*key[:4],addresses,api_port): return
        if key not in flows:
            if len(flows)>=10000: dropped_packets+=1;return
            flows[key]=Flow(key,ts,ts)
        flows[key].add(ts,len(packet),flags)
    print(f'[INFO] Live IPv4 capture on {interface or "default interface"}; windows up to {window_seconds:g}s',flush=True)
    client.heartbeat(agent_id,'capture',interface);last_heartbeat=time.monotonic();last_resolve=last_heartbeat
    try:
        while running:
            sniff(iface=interface,prn=packet_handler,store=False,timeout=1);dropped_flows+=flush_due_flows(flows,time.time(),agent_id,flow_timeout,window_seconds,enqueue)
            if dropped_packets or dropped_flows: print(f'[WARN] Capture capacity exceeded; {dropped_packets} packets and {dropped_flows} flow windows not recorded',flush=True);dropped_packets=dropped_flows=0
            if time.monotonic()-last_heartbeat>=5: client.heartbeat(agent_id,'capture',interface);last_heartbeat=time.monotonic()
            if time.monotonic()-last_resolve>=60:
                fresh,port=commander_endpoint(client.url)
                if fresh: addresses,api_port=fresh,port
                last_resolve=time.monotonic()
    finally:
        dropped_flows+=flush_due_flows(flows,time.time(),agent_id,flow_timeout,window_seconds,enqueue,True);sender_done.set();worker.join(timeout=10)
        if dropped_flows or not pending.empty(): print(f'[WARN] {dropped_flows+pending.qsize()} flow windows not delivered',flush=True)

def main():
    parser=argparse.ArgumentParser(description='Cloud-Native ML-IDS Sentinel');parser.add_argument('--mode',choices=['synthetic','live'],default=os.getenv('AGENT_MODE'));parser.add_argument('--api-url',default=os.getenv('COMMANDER_API_URL','http://127.0.0.1:8000/api/v1/flows/process'));parser.add_argument('--agent-id',default=os.getenv('AGENT_ID'));parser.add_argument('--api-key',default=os.getenv('COMMANDER_API_KEY',''));parser.add_argument('--interval',type=float,default=float(os.getenv('AGENT_INTERVAL','2')));parser.add_argument('--interface',default=os.getenv('CAPTURE_INTERFACE') or None);parser.add_argument('--flow-timeout',type=float,default=5);parser.add_argument('--window-seconds',type=float,default=5);parser.add_argument('--enforce-blocklist',action='store_true',default=os.getenv('ENFORCE_BLOCKLIST','').lower() in {'1','true','yes'});parser.add_argument('--enforce-access-policy',action='store_true',default=os.getenv('ENFORCE_ACCESS_POLICY','').lower() in {'1','true','yes'})
    args=parser.parse_args()
    if args.mode not in {'synthetic','live'}: parser.error('Choose --mode live or --mode synthetic (or set AGENT_MODE).')
    args.agent_id=args.agent_id or f'sentinel-{args.mode}-{socket.gethostname()}'
    if args.interval<=0 or args.flow_timeout<=0 or args.window_seconds<=0: parser.error('Intervals must be greater than zero')
    client=Client(args.api_url,args.api_key);enforcer=None
    if args.enforce_blocklist or args.enforce_access_policy: enforcer=Enforcer(client.enforcer_session,client.base,args.enforce_access_policy,args.enforce_blocklist);enforcer.start()
    print(f'[INFO] Sentinel {args.agent_id} mode={args.mode} API={args.api_url} enforcement={bool(enforcer)}',flush=True)
    try:
        if args.mode=='live': live(client,args.agent_id,args.interface,args.flow_timeout,args.window_seconds)
        else:
            def stop_synthetic(*_): raise KeyboardInterrupt
            signal.signal(signal.SIGTERM,stop_synthetic);rng=random.Random();last=0
            while True:
                if time.monotonic()-last>=5: client.heartbeat(args.agent_id,'synthetic');last=time.monotonic()
                client.send(demo_flow(args.agent_id,rng));time.sleep(args.interval)
    except KeyboardInterrupt: pass
    finally:
        if enforcer: enforcer.stop_event.set();enforcer.join(timeout=15);enforcer.cleanup()
if __name__=='__main__': main()
