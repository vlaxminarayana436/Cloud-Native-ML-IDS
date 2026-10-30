from __future__ import annotations
import numpy as np
import pandas as pd

BASE_FEATURES = ['flow_duration','packet_count','byte_count','iat_mean','average_packet_size','syn_count','ack_count','syn_ack_ratio']
CLASSES = ['Normal','DDoS_SYN_Flood','Port_Scan','Brute_Force','UDP_Flood']


def feature_frame(data):
    frame = pd.DataFrame([data]) if isinstance(data, dict) else pd.DataFrame(data).copy()
    for name in BASE_FEATURES:
        if name not in frame: frame[name] = 0.0
        frame[name] = pd.to_numeric(frame[name], errors='coerce').replace([np.inf, -np.inf], 0).fillna(0).clip(lower=0, upper=1e12)
    frame = frame[BASE_FEATURES].astype(float)
    duration = frame.flow_duration.clip(lower=.001); packets = frame.packet_count.clip(lower=1)
    frame['packets_per_second'] = frame.packet_count / duration
    frame['bytes_per_second'] = frame.byte_count / duration
    frame['syn_ratio'] = frame.syn_count / packets
    frame['ack_ratio'] = frame.ack_count / packets
    return frame


def profile(flow):
    row = feature_frame(flow).iloc[0]
    return {key:float(row[key]) for key in ('packets_per_second','bytes_per_second','average_packet_size','syn_ratio','ack_ratio')}
