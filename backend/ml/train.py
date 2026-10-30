"""Train a laptop-sized hybrid flow model on synthetic demonstration data."""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.metrics import accuracy_score, f1_score, classification_report
from sklearn.model_selection import train_test_split
from app.features import CLASSES, feature_frame


def generate_dataset(rows=20000, seed=42):
    rng = np.random.default_rng(seed); count = max(100, rows // len(CLASSES)); frames = []
    for name in CLASSES:
        if name == 'Normal':
            packets=np.clip(rng.lognormal(3.6,.85,count),4,600); size=np.clip(rng.normal(720,240,count),100,1500); duration=np.clip(rng.lognormal(2.5,.8,count),.15,150)
            syn=np.minimum(packets,rng.integers(0,4,count)).astype(float); ack=np.minimum(packets,packets*rng.uniform(.45,.9,count))
            udp=rng.random(count)<.15; packets[udp]=rng.integers(4,46,udp.sum()); size[udp]=rng.uniform(180,520,udp.sum()); duration[udp]=rng.uniform(6,24,udp.sum()); syn[udp]=0; ack[udp]=0
            # Capture windows can contain short, small benign exchanges or partial
            # handshakes. Include synthetic examples, but do not treat them as a
            # substitute for labeled, representative traffic validation.
            short=rng.random(count)<.35; n=int(short.sum()); short_packets=rng.integers(1,41,n).astype(float)
            short_duration=np.exp(rng.uniform(np.log(.001),np.log(6),n)); short_duration[short_packets==1]=0
            packets[short]=short_packets; duration[short]=short_duration; size[short]=np.exp(rng.uniform(np.log(55),np.log(1300),n))
            syn[short]=np.minimum(short_packets,rng.integers(0,4,n)); short_ack=np.rint(short_packets*rng.uniform(.4,1,n)); short_ack[rng.random(n)<.2]=0; ack[short]=short_ack
        elif name == 'DDoS_SYN_Flood':
            packets=np.clip(rng.lognormal(6.15,.65,count),45,3500); size=np.clip(rng.normal(100,45,count),45,400); duration=np.clip(rng.lognormal(.9,.7,count),.1,35)
            syn=packets*rng.uniform(.7,.99,count); ack=packets*rng.uniform(0,.15,count)
        elif name == 'Port_Scan':
            packets=np.clip(rng.lognormal(4.8,.7,count),15,900); size=np.clip(rng.normal(105,45,count),45,400); duration=np.clip(rng.lognormal(1.8,.65,count),.2,50)
            syn=packets*rng.uniform(.55,.9,count); ack=packets*rng.uniform(0,.3,count)
        elif name == 'Brute_Force':
            packets=np.clip(rng.lognormal(4.7,.65,count),15,900); size=np.clip(rng.normal(300,100,count),70,800); duration=np.clip(rng.lognormal(3,.65,count),1,160)
            syn=packets*rng.uniform(.08,.38,count); ack=packets*rng.uniform(.32,.76,count)
        else:
            packets=np.clip(rng.lognormal(6.1,.65,count),40,3500); size=np.clip(rng.normal(280,110,count),60,900); duration=np.clip(rng.lognormal(.9,.65,count),.1,30)
            syn=np.zeros(count); ack=np.zeros(count)
        packets=np.maximum(1,np.rint(packets)); syn=np.minimum(packets,np.rint(syn)); ack=np.minimum(packets,np.rint(ack)); byte_count=np.maximum(1,np.rint(packets*size*rng.uniform(.92,1.08,count)))
        frames.append(pd.DataFrame({'flow_duration':duration,'packet_count':packets,'byte_count':byte_count,'iat_mean':duration/np.maximum(packets-1,1)*rng.uniform(.75,1.25,count),'average_packet_size':byte_count/packets,'syn_count':syn,'ack_count':ack,'syn_ack_ratio':syn/np.maximum(ack,1),'label':name}))
    return pd.concat(frames,ignore_index=True).sample(frac=1,random_state=seed).reset_index(drop=True)


def train(data, directory, name='model', source='synthetic', seed=42):
    directory=Path(directory); directory.mkdir(parents=True,exist_ok=True); x=feature_frame(data); y=data['label'].astype(str)
    xt,xe,yt,ye=train_test_split(x,y,test_size=.3,stratify=y,random_state=seed)
    classifier=RandomForestClassifier(n_estimators=80,max_depth=18,min_samples_leaf=2,n_jobs=1,random_state=seed).fit(xt,yt)
    normal=xt.loc[yt=='Normal']; anomaly=IsolationForest(n_estimators=80,max_samples=min(512,len(normal)),contamination=.04,n_jobs=1,random_state=seed).fit(normal)
    predicted=classifier.predict(xe); decision=anomaly.decision_function(xe); scores=1/(1+np.exp(np.clip(decision/.05,-20,20)))
    reference=generate_dataset(2500,seed=101); ref_x=feature_frame(reference)
    metrics={'source':source,'model':'Random Forest','rows':len(data),'train_rows':len(xt),'test_rows':len(xe),'accuracy':float(accuracy_score(ye,predicted)),'weighted_f1':float(f1_score(ye,predicted,average='weighted',zero_division=0)),'reference_f1':float(f1_score(reference.label,classifier.predict(ref_x),average='weighted',zero_division=0)),'report':classification_report(ye,predicted,output_dict=True,zero_division=0),'anomaly':{'normal_false_flag_rate':float(np.mean(scores[ye.to_numpy()=='Normal']>=.65)),'attack_flag_rate':float(np.mean(scores[ye.to_numpy()!='Normal']>=.65)),'threshold':.65},'classes':list(map(str,classifier.classes_))}
    artifact={'model':classifier,'anomaly_model':anomaly,'threshold':.65,'anomaly_threshold':.65,'anomaly_scale':.05,'metrics':metrics,'feature_importance':dict(zip(x.columns,map(float,classifier.feature_importances_)))}
    tmp=directory/f'.{name}.joblib.tmp'
    try: joblib.dump(artifact,tmp,compress=3); os.replace(tmp,directory/f'{name}.joblib')
    finally: tmp.unlink(missing_ok=True)
    (directory/f'{name}_metrics.json').write_text(json.dumps(metrics,indent=2))
    return metrics


def main():
    parser=argparse.ArgumentParser(); parser.add_argument('--rows',type=int,default=20000); parser.add_argument('--output',type=Path,default=Path(__file__).resolve().parents[1]/'models'); args=parser.parse_args()
    metrics=train(generate_dataset(args.rows),args.output)
    print(json.dumps({k:metrics[k] for k in ('model','accuracy','weighted_f1','reference_f1','test_rows','anomaly')},indent=2),flush=True)

if __name__=='__main__': main()
