"""Commander API: observation, decisions and analyst review; no kernel firewall writes."""
from __future__ import annotations
import asyncio
import csv
import io
import json
import math
import os
import random
import secrets
import shutil
import sqlite3
import tempfile
import threading
import time
from contextlib import asynccontextmanager
from ipaddress import ip_address
from pathlib import Path
from typing import Literal
import joblib
import pandas as pd
from fastapi import Depends,FastAPI,File,Header,HTTPException,Query,UploadFile,WebSocket,WebSocketDisconnect
from fastapi.responses import StreamingResponse
from . import db
from .access import evaluate
from .config import API_KEY,FIREWALL_MODE,KNOWN_BLOCK_MINUTES,UNKNOWN_BLOCK_MINUTES,MODEL_DIR,MAX_PCAP_BYTES
from .features import BASE_FEATURES,profile
from .model import ModelService,validate_artifact
from .pcap import extract_flows
from .schemas import Approval,Block,EventReview,Flow,Heartbeat,Network,PolicySettings,Resource,Toggle

TrafficSource=Literal['all','capture','synthetic','pcap','unknown']
ReviewDetection=Literal['all','alerts','normal']
ReviewStatus=Literal['all','unreviewed','reviewed','benign','malicious','unsure']
model=ModelService();clients=set();app_loop=None;training_lock=threading.Lock()
training_state={'state':'idle','error':None,'started_at':None,'finished_at':None,'metrics':None,'traffic_source':None}

@asynccontextmanager
async def lifespan(_):
    global app_loop
    db.init_db();model.load();app_loop=asyncio.get_running_loop()
    try: yield
    finally: app_loop=None

app=FastAPI(title='Cloud-Native ML-IDS Commander',version='1.0',lifespan=lifespan)

async def require_key(x_api_key:str|None=Header(default=None)):
    if API_KEY and (not x_api_key or not secrets.compare_digest(x_api_key,API_KEY)): raise HTTPException(401,'Invalid or missing API key')

async def broadcast(payload):
    async def deliver(ws):
        try: await asyncio.wait_for(ws.send_json(payload),timeout=.5)
        except Exception: clients.discard(ws)
    await asyncio.gather(*(deliver(ws) for ws in list(clients)))

def notify_from_thread(payload):
    if app_loop is not None and not app_loop.is_closed():
        try: asyncio.run_coroutine_threadsafe(broadcast(payload),app_loop)
        except RuntimeError: pass

def inspect_and_store(flow,offline=False):
    if offline: flow={**flow,'traffic_source':'pcap'}
    policy=evaluate(flow,db.policy_bundle());pred=model.predict(flow);p=profile(flow);matched=db.match_rule(flow,p);pattern_id=None
    if matched:
        pattern_id=matched['pattern_id']
        if pred['classification']=='Normal' or pred['detection_source']=='anomaly': pred.update(classification='Malicious',attack_type=matched['approved_label'] or 'Learned_Pattern',detection_source='learned_pattern')
    if policy['action']=='deny' and pred['classification']=='Normal': pred.update(classification='Policy_Denied',attack_type='Unauthorized_Egress' if policy['decision']=='unregistered_egress' else 'Unauthorized_Source',detection_source='access_policy')
    if pred['detection_source']=='anomaly': candidate=db.create_candidate(flow,p,pred['anomaly_score']);pattern_id=candidate['id']
    if offline: action='OFFLINE_ANALYSIS'
    elif pred['classification']=='Policy_Denied': action='POLICY_DENY_RECORDED'
    elif pred['classification']!='Malicious': action='POLICY_MONITORED' if policy['action']=='monitor' else 'ALLOWED'
    elif FIREWALL_MODE=='ALERT_ONLY': action='ALERT_ONLY'
    else:
        minutes=UNKNOWN_BLOCK_MINUTES if pred['detection_source']=='anomaly' else KNOWN_BLOCK_MINUTES
        db.add_block(flow['src_ip'],pred['attack_type'],'auto',flow['traffic_source'],time.time()+minutes*60);action='BLOCKED_SIMULATED'
    event=db.insert_event(flow,pred,action,policy,pattern_id)
    result={**pred,'status':'processed','event_id':event['id'],'action':action,'pattern_id':pattern_id,'policy_action':policy['action'],'policy_decision':policy['decision'],'policy_reason':policy['reason'],'trusted_source':policy['trusted']}
    return event,result

async def process(flow,offline=False):
    event,result=await asyncio.to_thread(inspect_and_store,flow,offline);await broadcast({'type':'event','event':event});return result

@app.get('/')
def root(): return {'name':'Cloud-Native ML-IDS Commander','docs':'/docs','health':'/health'}
@app.get('/health')
def health(): return {'status':'ok','database':'ok','model_loaded':model.loaded,'firewall_mode':FIREWALL_MODE,'access_policy':db.policy_bundle()['settings']['mode']}
@app.post('/api/v1/flows/process',dependencies=[Depends(require_key)])
async def process_flow(flow:Flow):
    if not model.loaded: raise HTTPException(503,'Detection model unavailable')
    return await process(flow.model_dump())
@app.post('/api/v1/agents/heartbeat',dependencies=[Depends(require_key)])
async def heartbeat(item:Heartbeat):
    agent=await asyncio.to_thread(db.record_heartbeat,item.agent_id,item.traffic_source,item.interface);await broadcast({'type':'heartbeat','agent':agent});return {'status':'recorded','agent':agent}
@app.get('/api/v1/summary')
def summary(source:TrafficSource='all'): return db.summary(source)
@app.get('/api/v1/events')
def events(limit:int=200,source:TrafficSource='all'): return db.events(source=source,limit=limit)

@app.get('/api/v1/reviews')
def flow_reviews(source:TrafficSource='all',detection:ReviewDetection='alerts',status:ReviewStatus='unreviewed',before_id:int|None=Query(default=None,ge=1),limit:int=Query(default=20,ge=1,le=100)):
    return db.review_events(source,detection,status,before_id,limit)

@app.get('/api/v1/reviews/export.csv')
def export_review_features(source:TrafficSource='all',detection:ReviewDetection='alerts',status:ReviewStatus='unreviewed'):
    # This is an explicit allowlist: the stored flow JSON also contains IPs,
    # ports, timestamps and an agent ID, none of which belong in this export.
    fields=['traffic_source','prediction','detector','protocol','from_port_443','to_port_443','anomaly_score',*BASE_FEATURES,'analyst_label']
    output=io.StringIO();writer=csv.DictWriter(output,fieldnames=fields);writer.writeheader()
    page=db.review_events(source,detection,status,limit=1000)
    def number(value):
        return value if isinstance(value,(int,float)) and not isinstance(value,bool) and math.isfinite(value) else ''
    for event in page['items']:
        features=event['features'] if isinstance(event['features'],dict) else {}
        row={'traffic_source':event['traffic_source'] if event['traffic_source'] in {'capture','synthetic','pcap','unknown'} else 'unknown',
             'prediction':event['classification'] if event['classification'] in {'Normal','Malicious','Policy_Denied'} else 'Other',
             'detector':event['detection_source'] if event['detection_source'] in {'supervised','anomaly','hybrid','learned_pattern','access_policy'} else 'other',
             'protocol':event['protocol'] if event['protocol'] in {'TCP','UDP'} else 'OTHER',
             'from_port_443':event['src_port']==443,'to_port_443':event['dst_port']==443,
             'anomaly_score':number(event['anomaly_score']),
             'analyst_label':event['review']['label'] if event['review'] else ''}
        row.update({name:number(features.get(name)) for name in BASE_FEATURES})
        writer.writerow(row)
    return StreamingResponse(iter([output.getvalue()]),media_type='text/csv',headers={'Content-Disposition':'attachment; filename=flow-features.csv','X-Export-Truncated':str(page['has_more']).lower()})

@app.put('/api/v1/events/{event_id}/review',dependencies=[Depends(require_key)])
async def save_event_review(event_id:int,item:EventReview):
    result=await asyncio.to_thread(db.put_event_review,event_id,item.label,item.note)
    if result is None: raise HTTPException(404,'Flow record not found')
    await broadcast({'type':'event_review'});return {'status':'saved','review':result}

@app.delete('/api/v1/events/{event_id}/review',dependencies=[Depends(require_key)])
async def remove_event_review(event_id:int):
    if not await asyncio.to_thread(db.clear_event_review,event_id): raise HTTPException(404,'Review not found')
    await broadcast({'type':'event_review'});return {'status':'removed'}

@app.get('/api/v1/alerts')
def alerts(attack_type:str|None=None,src_ip:str|None=None,min_confidence:float|None=None,limit:int=100,source:TrafficSource='all'): return db.events(source,True,attack_type,src_ip,min_confidence,limit)
@app.get('/api/v1/alerts/export.csv')
def export_alerts(source:TrafficSource='all',attack_type:str|None=None,src_ip:str|None=None,min_confidence:float|None=None):
    fields=['id','timestamp','agent_id','traffic_source','src_ip','dst_ip','src_port','dst_port','protocol','classification','attack_type','confidence','anomaly_score','detection_source','policy_action','policy_reason','action']
    output=io.StringIO();writer=csv.DictWriter(output,fieldnames=fields,extrasaction='ignore');writer.writeheader()
    for row in db.events(source,True,attack_type,src_ip,min_confidence,1000):
        # Agent identifiers and other text are user-controlled. Neutralize
        # spreadsheet formulas before exporting CSV for an analyst to open.
        safe={key:("'"+value if isinstance(value,str) and value.lstrip().startswith(('=','+','-','@')) else value) for key,value in row.items()}
        writer.writerow(safe)
    return StreamingResponse(iter([output.getvalue()]),media_type='text/csv',headers={'Content-Disposition':'attachment; filename=alerts.csv'})
@app.get('/api/v1/blocklist')
def blocklist(source:TrafficSource='all'): return db.blocks(source)
@app.post('/api/v1/blocklist',dependencies=[Depends(require_key)])
async def create_block(item:Block):
    result=db.add_block(item.ip,item.reason,'manual','manual');await broadcast({'type':'blocklist'});return {'status':'recorded','action':'BLOCK_ENTRY_RECORDED','block':result}
@app.delete('/api/v1/blocklist/{ip}',dependencies=[Depends(require_key)])
async def delete_block(ip:str):
    try: address=str(ip_address(ip))
    except ValueError: raise HTTPException(422,'Invalid IP address')
    if not db.delete_block(address): raise HTTPException(404,'IP not found')
    await broadcast({'type':'blocklist'});return {'status':'removed'}
@app.get('/api/v1/access-policy')
def access_policy(source:TrafficSource='all'): return {**db.policy_bundle(),'attempts':db.policy_attempts(source)}
@app.put('/api/v1/access-policy/settings',dependencies=[Depends(require_key)])
async def update_policy(item:PolicySettings):
    result=db.update_policy(item.model_dump());await broadcast({'type':'policy'});return {'status':'updated','settings':result}
@app.post('/api/v1/access-policy/networks',status_code=201,dependencies=[Depends(require_key)])
async def create_network(item:Network):
    try: item_id=db.create_network(item.model_dump())
    except sqlite3.IntegrityError: raise HTTPException(409,'Network already exists')
    await broadcast({'type':'policy'});return {'status':'created','id':item_id}
@app.post('/api/v1/access-policy/resources',status_code=201,dependencies=[Depends(require_key)])
async def create_resource(item:Resource):
    try: item_id=db.create_resource(item.model_dump())
    except sqlite3.IntegrityError: raise HTTPException(409,'Resource already exists')
    await broadcast({'type':'policy'});return {'status':'created','id':item_id}
@app.patch('/api/v1/access-policy/{kind}/{item_id}',dependencies=[Depends(require_key)])
async def toggle_policy(kind:str,item_id:int,item:Toggle):
    table={'networks':'trusted_networks','resources':'protected_resources'}.get(kind)
    if not table or not db.toggle_or_delete(table,item_id,item.enabled): raise HTTPException(404,'Entry not found')
    await broadcast({'type':'policy'});return {'status':'updated'}
@app.delete('/api/v1/access-policy/{kind}/{item_id}',dependencies=[Depends(require_key)])
async def delete_policy(kind:str,item_id:int):
    table={'networks':'trusted_networks','resources':'protected_resources'}.get(kind)
    if not table or not db.toggle_or_delete(table,item_id): raise HTTPException(404,'Entry not found')
    await broadcast({'type':'policy'});return {'status':'deleted'}
@app.get('/api/v1/patterns')
def patterns(source:TrafficSource='all'): return db.patterns(source)
@app.get('/api/v1/rules')
def rules(source:TrafficSource='all'): return db.rules(source)
@app.post('/api/v1/patterns/{pattern_id}/approve',dependencies=[Depends(require_key)])
async def approve(pattern_id:int,item:Approval):
    result=db.approve(pattern_id,item.label)
    if result is None: raise HTTPException(404,'Pattern not found')
    await broadcast({'type':'patterns'});return {'status':'approved','pattern':result}
@app.post('/api/v1/patterns/{pattern_id}/reject',dependencies=[Depends(require_key)])
async def reject(pattern_id:int):
    if not db.reject(pattern_id): raise HTTPException(404,'Pattern not found')
    await broadcast({'type':'patterns'});return {'status':'rejected'}
@app.get('/api/v1/model/info')
def model_info():
    candidate_available=(MODEL_DIR/'candidate.joblib').exists();candidate_metrics=None;metrics_path=MODEL_DIR/'candidate_metrics.json'
    if candidate_available and metrics_path.exists():
        try: candidate_metrics=json.loads(metrics_path.read_text())
        except (OSError,ValueError): pass
    return {**model.info(),'candidate_available':candidate_available,'candidate_metrics':candidate_metrics,'rollback_available':(MODEL_DIR/'previous.joblib').exists()}

def train_worker(source):
    global training_state
    try:
        from ml.train import generate_dataset,train
        rows=db.feedback(source)
        if not rows: raise ValueError('No approved feedback in this source')
        rng=random.Random(19);additions=[]
        for row in rows:
            for _ in range(24):
                features={key:max(0,float(row['features'].get(key,0))*rng.uniform(.9,1.1)) for key in BASE_FEATURES};additions.append({**features,'label':row['label']})
        data=pd.concat([generate_dataset(10000,seed=43),pd.DataFrame(additions)],ignore_index=True);metrics=train(data,MODEL_DIR,name='candidate',source=f'synthetic baseline + {source} feedback',seed=43)
        training_state={**training_state,'state':'ready','metrics':metrics,'finished_at':time.time(),'error':None}
    except Exception as exc: training_state={**training_state,'state':'failed','finished_at':time.time(),'error':str(exc)}
    finally: training_lock.release();notify_from_thread({'type':'training'})
@app.post('/api/v1/model/retrain',status_code=202,dependencies=[Depends(require_key)])
async def retrain(source:TrafficSource='all'):
    global training_state
    if not db.feedback(source): raise HTTPException(400,'Approve a pattern in this source before training')
    if not training_lock.acquire(blocking=False): raise HTTPException(409,'Training already running')
    training_state={'state':'running','error':None,'started_at':time.time(),'finished_at':None,'metrics':None,'traffic_source':source}
    threading.Thread(target=train_worker,args=(source,),daemon=True).start();await broadcast({'type':'training'});return {'status':'started','traffic_source':source}
@app.get('/api/v1/model/retrain/status')
def retrain_status(): return training_state
@app.post('/api/v1/model/activate',dependencies=[Depends(require_key)])
async def activate():
    path=MODEL_DIR/'candidate.joblib';active=MODEL_DIR/'model.joblib';previous=MODEL_DIR/'previous.joblib'
    if training_lock.locked(): raise HTTPException(409,'Training is running')
    if not path.exists(): raise HTTPException(404,'No candidate is available')
    try: candidate=validate_artifact(joblib.load(path))
    except Exception: raise HTTPException(400,'Candidate artifact is invalid')
    with model.lock: shutil.copy2(active,previous);os.replace(path,active);model.artifact=candidate
    await broadcast({'type':'model'});return {'status':'activated'}
@app.post('/api/v1/model/rollback',dependencies=[Depends(require_key)])
async def rollback():
    previous=MODEL_DIR/'previous.joblib';active=MODEL_DIR/'model.joblib'
    if training_lock.locked(): raise HTTPException(409,'Training is running')
    if not previous.exists(): raise HTTPException(404,'No previous model is available')
    try: artifact=validate_artifact(joblib.load(previous))
    except Exception: raise HTTPException(400,'Previous artifact is invalid')
    with model.lock: os.replace(previous,active);model.artifact=artifact
    await broadcast({'type':'model'});return {'status':'rolled_back'}
@app.post('/api/v1/pcap/analyze',dependencies=[Depends(require_key)])
async def analyze_pcap(file:UploadFile=File(...)):
    filename=Path(file.filename or 'capture.pcap').name
    if not filename.lower().endswith(('.pcap','.pcapng','.cap')): raise HTTPException(400,'Choose a PCAP, PCAPNG or CAP file')
    if not model.loaded: raise HTTPException(503,'Detection model unavailable')
    tmp=None
    try:
        with tempfile.NamedTemporaryFile(delete=False,suffix='.pcap') as f:
            tmp=Path(f.name);size=0
            while chunk:=await file.read(1024*1024):
                size+=len(chunk)
                if size>MAX_PCAP_BYTES: raise HTTPException(413,'Capture exceeds 25 MB')
                f.write(chunk)
        flows=await asyncio.to_thread(extract_flows,tmp,'offline-pcap')
        if not flows: raise HTTPException(400,'No supported IPv4 TCP/UDP flows were found')
        counts={};malicious=0;policy_only=0
        for flow in flows:
            result=await process(flow,offline=True);counts[result['attack_type']]=counts.get(result['attack_type'],0)+1;malicious+=int(result['classification']=='Malicious');policy_only+=int(result['classification']=='Policy_Denied')
        return {'filename':filename,'total_flows':len(flows),'malicious_flows':malicious,'policy_only_flows':policy_only,'by_attack_type':counts,'response':'offline_no_firewall_changes'}
    except HTTPException: raise
    except Exception as exc: raise HTTPException(400,f'Could not analyse capture: {exc}')
    finally:
        await file.close()
        if tmp: tmp.unlink(missing_ok=True)
@app.get('/api/v1/lab/status')
def lab_status():
    with db.connect() as conn:
        count=conn.execute("SELECT COUNT(*) FROM events WHERE LOWER(agent_id) LIKE '%sandbox%'").fetchone()[0];heartbeat=conn.execute("SELECT MAX(last_seen) FROM agent_heartbeats WHERE LOWER(agent_id) LIKE '%sandbox%' AND traffic_source='capture'").fetchone()[0]
    return {'sandbox_events':count,'sandbox_last_seen':heartbeat,'sandbox_active':bool(heartbeat and time.time()-heartbeat<20),'mode':'docker-lab-ready'}
@app.websocket('/ws/alerts')
async def websocket(ws:WebSocket):
    await ws.accept();clients.add(ws)
    try:
        while True:
            if await ws.receive_text()=='ping': await ws.send_text('pong')
    except WebSocketDisconnect: pass
    finally: clients.discard(ws)
