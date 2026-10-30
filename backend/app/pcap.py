"""Bounded offline packet aggregation; never modifies firewall state."""
from __future__ import annotations
import time
from scapy.all import IP,TCP,UDP,PcapReader
from .config import MAX_PCAP_FLOWS,MAX_PCAP_PACKETS

def extract_flows(path,agent_id='offline-pcap'):
    flows={};packets=0
    with PcapReader(str(path)) as reader:
        for packet in reader:
            packets+=1
            if packets>MAX_PCAP_PACKETS: raise ValueError(f'Capture exceeds {MAX_PCAP_PACKETS:,} packets')
            if IP not in packet: continue
            ip=packet[IP]
            if TCP in packet: transport=packet[TCP];protocol='TCP';flags=str(transport.flags)
            elif UDP in packet: transport=packet[UDP];protocol='UDP';flags=''
            else: continue
            key=(str(ip.src),str(ip.dst),int(transport.sport),int(transport.dport),protocol);stamp=float(getattr(packet,'time',time.time()))
            if key not in flows:
                if len(flows)>=MAX_PCAP_FLOWS: raise ValueError(f'Capture exceeds {MAX_PCAP_FLOWS:,} distinct flows')
                flows[key]={'first':stamp,'last':stamp,'packets':0,'bytes':0,'iat':0.,'syn':0,'ack':0}
            row=flows[key]
            if row['packets']: row['iat']+=max(0,stamp-row['last'])
            row['last']=stamp;row['packets']+=1;row['bytes']+=len(packet);row['syn']+=int('S' in flags);row['ack']+=int('A' in flags)
    result=[]
    for (src,dst,sport,dport,protocol),v in flows.items():
        result.append({'timestamp':v['last'],'agent_id':agent_id,'traffic_source':'pcap','src_ip':src,'dst_ip':dst,'src_port':sport,'dst_port':dport,'protocol':protocol,'flow_duration':max(0,v['last']-v['first']),'packet_count':v['packets'],'byte_count':v['bytes'],'iat_mean':v['iat']/max(1,v['packets']-1),'average_packet_size':v['bytes']/max(1,v['packets']),'syn_count':v['syn'],'ack_count':v['ack'],'syn_ack_ratio':v['syn']/max(1,v['ack'])})
    return result
