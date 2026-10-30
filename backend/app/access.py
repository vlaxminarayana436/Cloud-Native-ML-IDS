"""Narrow trusted-network policy. IP/CIDR is not employee authentication."""
from ipaddress import ip_address, ip_network

PRIVATE=[ip_network(v) for v in ('10.0.0.0/8','172.16.0.0/12','192.168.0.0/16','fc00::/7')]

def trusted_cidr(value):
    net=ip_network(value,strict=False)
    if net.prefixlen < (16 if net.version==4 else 48): raise ValueError('Trusted networks must be IPv4 /16 or IPv6 /48 or narrower')
    return str(net)

def private_cidr(value):
    net=ip_network(value,strict=False)
    if net.prefixlen < (24 if net.version==4 else 64) or not any(net.version==p.version and net.subnet_of(p) for p in PRIVATE): raise ValueError('Scope must be private IPv4 /24 or IPv6 /64 or narrower')
    return str(net)

def ports(value):
    values=value if isinstance(value,list) else str(value).split(',')
    if not values or len(values)>40: raise ValueError('Specify one or more ports')
    result=[]
    for raw in values:
        parts=str(raw).strip().split('-')
        try:
            if len(parts) not in (1,2): raise ValueError()
            start=int(parts[0]);end=int(parts[-1])
            if not 1<=start<=end<=65535: raise ValueError()
        except ValueError: raise ValueError('Ports must be 1–65535 or ranges such as 8000-8002') from None
        item=str(start) if start==end else f'{start}-{end}'
        if item not in result: result.append(item)
    return result

def port_matches(port,specification):
    if port is None: return False
    return any(int(str(item).split('-')[0])<=int(port)<=int(str(item).split('-')[-1]) for item in specification)

def evaluate(flow,policy):
    src=ip_address(flow['src_ip']); dst=ip_address(flow['dst_ip']); settings=policy['settings']
    trusted=any(item['enabled'] and src.version==ip_network(item['cidr']).version and src in ip_network(item['cidr']) for item in policy['trusted_networks'])
    matched=None
    for item in policy['resources']:
        net=ip_network(item['destination_cidr'])
        if item['enabled'] and dst.version==net.version and dst in net and (item['protocol']=='ANY' or item['protocol']==flow['protocol']) and port_matches(flow.get('dst_port'),item['ports']): matched=item; break
    decision='allow';reason='No protected service matched'
    if settings['enabled'] and not trusted and matched:
        decision='untrusted_source';reason=f"Source is not in a trusted network for {matched['name']}"
    elif settings['enabled'] and settings['egress_enabled'] and not trusted and dst.is_global and not dst.is_multicast:
        if any(src.version==ip_network(c).version and src in ip_network(c) for c in settings['egress_cidrs']): decision='unregistered_egress';reason='Untrusted managed source attempted external egress'
    action='allow' if decision=='allow' else ('deny' if settings['mode']=='enforce' else 'monitor')
    return {'action':action,'decision':decision,'reason':reason,'trusted':bool(trusted),'resource':matched['name'] if matched else None}
