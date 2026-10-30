from __future__ import annotations
import math
import threading
import joblib
from .config import MODEL_DIR
from .features import CLASSES, feature_frame

def validate_artifact(artifact):
    required={'model','anomaly_model','threshold','anomaly_threshold','anomaly_scale','metrics'}
    if not isinstance(artifact,dict) or not required.issubset(artifact): raise ValueError('Invalid model artifact')
    model=artifact['model'];anomaly=artifact['anomaly_model']
    if 'Normal' not in list(getattr(model,'classes_',[])) or not callable(getattr(model,'predict_proba',None)) or not callable(getattr(anomaly,'decision_function',None)): raise ValueError('Incompatible model artifact')
    if not math.isfinite(float(artifact['anomaly_scale'])) or float(artifact['anomaly_scale'])<=0: raise ValueError('Invalid anomaly scale')
    for field in ('threshold','anomaly_threshold'):
        if not 0<=float(artifact[field])<=1: raise ValueError('Invalid threshold')
    return artifact

class ModelService:
    def __init__(self): self.lock=threading.RLock();self.artifact=None;self.load()
    def load(self):
        path=MODEL_DIR/'model.joblib'
        with self.lock: self.artifact=validate_artifact(joblib.load(path)) if path.exists() else None
    @property
    def loaded(self): return self.artifact is not None
    def predict(self,flow):
        with self.lock:
            if not self.artifact: raise RuntimeError('Model unavailable')
            a=self.artifact;frame=feature_frame(flow);model=a['model'];raw=model.predict_proba(frame)[0]
            probabilities={str(label):float(raw[i]) for i,label in enumerate(model.classes_)}
            for label in CLASSES: probabilities.setdefault(label,0.)
            score=1-probabilities.get('Normal',0.);decision=float(a['anomaly_model'].decision_function(frame)[0]);z=max(-20,min(20,decision/float(a['anomaly_scale'])))
            anomaly_score=1/(1+math.exp(z));anomalous=anomaly_score>=a['anomaly_threshold']
            if score>=a['threshold']:
                attack=max((k for k in probabilities if k!='Normal'),key=probabilities.get);classification='Malicious';source='hybrid' if anomalous else 'supervised'
            elif anomalous: attack='Unknown_Anomaly';classification='Malicious';source='anomaly';score=max(score,anomaly_score)
            else: attack='Normal';classification='Normal';source='supervised'
            return {'classification':classification,'attack_type':attack,'confidence':float(score),'anomaly_score':float(anomaly_score),'detection_source':source,'probabilities':probabilities}
    def info(self):
        with self.lock:
            if not self.artifact: return {'loaded':False,'metrics':{},'feature_importance':{}}
            return {'loaded':True,'metrics':self.artifact['metrics'],'feature_importance':self.artifact.get('feature_importance',{})}
