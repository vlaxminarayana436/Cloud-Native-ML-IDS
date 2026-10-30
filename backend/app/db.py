"""SQLite persistence for the local IDS control plane."""
from __future__ import annotations
import ipaddress
import json
import sqlite3
import time
from .config import DB_PATH

SOURCES={'all','capture','synthetic','pcap','unknown'}

def connect():
    DB_PATH.parent.mkdir(parents=True,exist_ok=True);db=sqlite3.connect(DB_PATH,timeout=10);db.row_factory=sqlite3.Row
    db.execute('PRAGMA journal_mode=WAL');db.execute('PRAGMA foreign_keys=ON');return db

def init_db():
    with connect() as db:
        db.executescript('''
        CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY AUTOINCREMENT,timestamp REAL NOT NULL,agent_id TEXT NOT NULL,traffic_source TEXT NOT NULL DEFAULT 'unknown',src_ip TEXT NOT NULL,dst_ip TEXT NOT NULL,src_port INTEGER,dst_port INTEGER,protocol TEXT NOT NULL,classification TEXT NOT NULL,attack_type TEXT NOT NULL,confidence REAL NOT NULL,anomaly_score REAL NOT NULL,detection_source TEXT NOT NULL,action TEXT NOT NULL,policy_action TEXT NOT NULL,policy_decision TEXT NOT NULL,policy_reason TEXT NOT NULL,trusted INTEGER NOT NULL,pattern_id INTEGER,features TEXT NOT NULL,probabilities TEXT NOT NULL);
        CREATE INDEX IF NOT EXISTS events_source_time ON events(traffic_source,timestamp DESC,id DESC);
        CREATE INDEX IF NOT EXISTS events_class_time ON events(classification,timestamp DESC);
        CREATE TABLE IF NOT EXISTS blocks (ip TEXT PRIMARY KEY,reason TEXT NOT NULL,source TEXT NOT NULL,traffic_source TEXT NOT NULL,blocked_at REAL NOT NULL,expires_at REAL);
        CREATE TABLE IF NOT EXISTS patterns (id INTEGER PRIMARY KEY AUTOINCREMENT,signature TEXT UNIQUE NOT NULL,title TEXT NOT NULL,status TEXT NOT NULL,protocol TEXT NOT NULL,traffic_source TEXT NOT NULL,profile TEXT NOT NULL,exemplar TEXT NOT NULL,explanation TEXT NOT NULL,anomaly_score REAL NOT NULL,occurrences INTEGER NOT NULL,first_seen REAL NOT NULL,last_seen REAL NOT NULL,approved_label TEXT,rule_id INTEGER);
        CREATE INDEX IF NOT EXISTS patterns_source_status ON patterns(traffic_source,status);
        CREATE TABLE IF NOT EXISTS learned_rules (id INTEGER PRIMARY KEY AUTOINCREMENT,pattern_id INTEGER UNIQUE NOT NULL,name TEXT NOT NULL,protocol TEXT NOT NULL,criteria TEXT NOT NULL,enabled INTEGER NOT NULL,created_at REAL NOT NULL,FOREIGN KEY(pattern_id) REFERENCES patterns(id));
        CREATE TABLE IF NOT EXISTS feedback (id INTEGER PRIMARY KEY AUTOINCREMENT,pattern_id INTEGER UNIQUE NOT NULL,label TEXT NOT NULL,features TEXT NOT NULL,created_at REAL NOT NULL,FOREIGN KEY(pattern_id) REFERENCES patterns(id));
        CREATE TABLE IF NOT EXISTS agent_heartbeats (agent_id TEXT PRIMARY KEY,traffic_source TEXT NOT NULL,interface TEXT,last_seen REAL NOT NULL);
        CREATE TABLE IF NOT EXISTS policy_settings (id INTEGER PRIMARY KEY CHECK(id=1),enabled INTEGER NOT NULL,mode TEXT NOT NULL,egress_enabled INTEGER NOT NULL,egress_cidrs TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS trusted_networks (id INTEGER PRIMARY KEY AUTOINCREMENT,label TEXT NOT NULL,cidr TEXT UNIQUE NOT NULL,kind TEXT NOT NULL,enabled INTEGER NOT NULL,source TEXT NOT NULL,created_at REAL NOT NULL);
        CREATE TABLE IF NOT EXISTS protected_resources (id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT NOT NULL,destination_cidr TEXT NOT NULL,protocol TEXT NOT NULL,ports TEXT NOT NULL,enabled INTEGER NOT NULL,source TEXT NOT NULL,created_at REAL NOT NULL,UNIQUE(destination_cidr,protocol,ports));
        ''')
        # Start with no trusted networks or protected services. Operators must
        # configure their actual scopes instead of inheriting fabricated ones.
        db.execute("INSERT OR IGNORE INTO policy_settings VALUES (1,1,'monitor',0,'[]')")
        # Remove only the two exact starter records created by older versions.
        # User-created or modified policy entries and historical events remain.
        db.execute("DELETE FROM trusted_networks WHERE source='example' AND label='Example office' AND cidr='10.0.0.0/24' AND kind='office'")
        db.execute("DELETE FROM protected_resources WHERE source='example' AND name='Example internal service' AND destination_cidr='192.168.1.50/32' AND protocol='TCP' AND ports='[\"22\",\"443\"]'")

def source_clause(source,field='traffic_source'):
    if source not in SOURCES: raise ValueError('Invalid traffic source')
    return ('',[]) if source=='all' else (f' AND {field}=?',[source])

def event_row(row):
    value=dict(row);value['features']=json.loads(value['features']);value['probabilities']=json.loads(value['probabilities']);value['trusted']=bool(value['trusted']);return value

def insert_event(flow,pred,action,policy,pattern_id=None):
    with connect() as db:
        cur=db.execute('''INSERT INTO events(timestamp,agent_id,traffic_source,src_ip,dst_ip,src_port,dst_port,protocol,classification,attack_type,confidence,anomaly_score,detection_source,action,policy_action,policy_decision,policy_reason,trusted,pattern_id,features,probabilities) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)''',(flow['timestamp'],flow['agent_id'],flow['traffic_source'],flow['src_ip'],flow['dst_ip'],flow.get('src_port'),flow.get('dst_port'),flow['protocol'],pred['classification'],pred['attack_type'],pred['confidence'],pred['anomaly_score'],pred['detection_source'],action,policy['action'],policy['decision'],policy['reason'],int(policy['trusted']),pattern_id,json.dumps(flow),json.dumps(pred['probabilities'])))
        return event_row(db.execute('SELECT * FROM events WHERE id=?',(cur.lastrowid,)).fetchone())

def events(source='all',alerts=False,attack_type=None,src_ip=None,min_confidence=None,limit=100):
    clause,args=source_clause(source)
    if alerts: clause+=" AND classification IN ('Malicious','Policy_Denied')"
    if attack_type: clause+=' AND attack_type=?';args.append(attack_type)
    if src_ip: clause+=' AND src_ip LIKE ?';args.append(f'%{src_ip}%')
    if min_confidence is not None: clause+=" AND detection_source NOT IN ('access_policy','learned_pattern') AND confidence>=?";args.append(min_confidence)
    with connect() as db: return [event_row(row) for row in db.execute('SELECT * FROM events WHERE 1=1'+clause+' ORDER BY timestamp DESC,id DESC LIMIT ?',(*args,max(1,min(1000,limit))))]

def enforcement_reason(row):
    try: addr=ipaddress.ip_address(row['ip'])
    except ValueError: return 'invalid_address'
    if addr.version!=4: return 'unsupported_family'
    if addr.is_loopback or addr.is_unspecified or addr.is_multicast or addr.is_link_local or addr.is_reserved: return 'protected_address'
    if row['source']=='manual': return 'manual'
    return 'captured' if row['traffic_source']=='capture' else 'non_capture_source'

def add_block(ip,reason,source='auto',traffic_source='unknown',expires_at=None):
    if source not in {'auto','manual'} or traffic_source not in {'capture','synthetic','unknown','manual'}: raise ValueError('Invalid block provenance')
    now=time.time()
    with connect() as db:
        db.execute('''INSERT INTO blocks(ip,reason,source,traffic_source,blocked_at,expires_at) VALUES (?,?,?,?,?,?) ON CONFLICT(ip) DO UPDATE SET reason=excluded.reason,source=excluded.source,traffic_source=excluded.traffic_source,blocked_at=excluded.blocked_at,expires_at=excluded.expires_at WHERE excluded.source='manual' OR (blocks.source!='manual' AND (blocks.traffic_source!='capture' OR excluded.traffic_source='capture' OR (blocks.expires_at IS NOT NULL AND blocks.expires_at<=excluded.blocked_at)))''',(ip,reason,source,traffic_source,now,expires_at))
        row=dict(db.execute('SELECT * FROM blocks WHERE ip=?',(ip,)).fetchone())
    row['enforcement_reason']=enforcement_reason(row);row['enforceable']=row['enforcement_reason'] in {'manual','captured'};return row

def blocks(source='all'):
    if source not in SOURCES: raise ValueError('Invalid traffic source')
    clause='' if source=='all' else " WHERE (traffic_source=? OR source='manual')";args=[] if source=='all' else [source];now=time.time()
    with connect() as db: rows=[dict(row) for row in db.execute('SELECT * FROM blocks'+clause+' ORDER BY blocked_at DESC LIMIT 1000',args)]
    for row in rows:
        row['active']=row['expires_at'] is None or row['expires_at']>now;row['enforcement_reason']=enforcement_reason(row);row['enforceable']=row['enforcement_reason'] in {'manual','captured'}
    return rows

def delete_block(ip):
    with connect() as db: return bool(db.execute('DELETE FROM blocks WHERE ip=?',(ip,)).rowcount)

def record_heartbeat(agent_id,source,interface):
    now=time.time()
    with connect() as db: db.execute('''INSERT INTO agent_heartbeats(agent_id,traffic_source,interface,last_seen) VALUES (?,?,?,?) ON CONFLICT(agent_id) DO UPDATE SET traffic_source=excluded.traffic_source,interface=excluded.interface,last_seen=excluded.last_seen''',(agent_id,source,interface,now))
    return {'agent_id':agent_id,'traffic_source':source,'interface':interface,'last_seen':now}

def policy_bundle():
    with connect() as db:
        settings=dict(db.execute('SELECT * FROM policy_settings WHERE id=1').fetchone());networks=[dict(row) for row in db.execute('SELECT * FROM trusted_networks ORDER BY id')];resources=[dict(row) for row in db.execute('SELECT * FROM protected_resources ORDER BY id')]
    settings['enabled']=bool(settings['enabled']);settings['egress_enabled']=bool(settings['egress_enabled']);settings['egress_cidrs']=json.loads(settings['egress_cidrs'])
    for row in networks: row['enabled']=bool(row['enabled'])
    for row in resources: row['enabled']=bool(row['enabled']);row['ports']=json.loads(row['ports'])
    return {'settings':settings,'trusted_networks':networks,'resources':resources}

def update_policy(settings):
    with connect() as db: db.execute('UPDATE policy_settings SET enabled=?,mode=?,egress_enabled=?,egress_cidrs=? WHERE id=1',(int(settings['enabled']),settings['mode'],int(settings['egress_enabled']),json.dumps(settings['egress_cidrs'])))
    return policy_bundle()['settings']

def create_network(item):
    with connect() as db: return db.execute("INSERT INTO trusted_networks(label,cidr,kind,enabled,source,created_at) VALUES (?,?,?,1,'manual',?)",(item['label'],item['cidr'],item['kind'],time.time())).lastrowid

def create_resource(item):
    with connect() as db: return db.execute("INSERT INTO protected_resources(name,destination_cidr,protocol,ports,enabled,source,created_at) VALUES (?,?,?,?,1,'manual',?)",(item['name'],item['destination_cidr'],item['protocol'],json.dumps(item['ports']),time.time())).lastrowid

def toggle_or_delete(table,item_id,enabled=None):
    if table not in {'trusted_networks','protected_resources'}: raise ValueError('Invalid policy table')
    with connect() as db:
        if enabled is None: cur=db.execute(f'DELETE FROM {table} WHERE id=?',(item_id,))
        else: cur=db.execute(f'UPDATE {table} SET enabled=? WHERE id=?',(int(enabled),item_id))
        return bool(cur.rowcount)

def policy_attempts(source='all',limit=30):
    clause,args=source_clause(source)
    with connect() as db: return [event_row(row) for row in db.execute("SELECT * FROM events WHERE policy_action IN ('deny','monitor')"+clause+' ORDER BY timestamp DESC,id DESC LIMIT ?',(*args,max(1,min(200,limit))))]

def pattern_row(row):
    item=dict(row)
    for key in ('profile','exemplar','explanation'): item[key]=json.loads(item[key])
    return item

def signature(protocol,p):
    def bucket(value,edges): return sum(value>=edge for edge in edges)
    return '|'.join([protocol,str(bucket(p['packets_per_second'],[1,10,50,200])),str(bucket(p['bytes_per_second'],[1000,10000,50000,200000])),str(bucket(p['average_packet_size'],[128,384,900])),str(bucket(p['syn_ratio'],[.1,.4,.75])),str(bucket(p['ack_ratio'],[.1,.35,.7]))])

def create_candidate(flow,profile,score):
    source=flow['traffic_source'];key=source+'|'+signature(flow['protocol'],profile);now=time.time();explanation=[]
    if profile['packets_per_second']>50: explanation.append('Elevated packet rate')
    if profile['syn_ratio']>.5 and profile['ack_ratio']<.2: explanation.append('Many SYNs and few acknowledgements')
    if not explanation: explanation.append('Flow differs from the synthetic normal baseline')
    with connect() as db:
        row=db.execute('SELECT * FROM patterns WHERE signature=?',(key,)).fetchone()
        if row:
            pid=row['id']
            if row['status']!='rejected': db.execute('UPDATE patterns SET occurrences=occurrences+1,last_seen=?,anomaly_score=MAX(anomaly_score,?) WHERE id=?',(now,score,pid))
        else:
            cur=db.execute('''INSERT INTO patterns(signature,title,status,protocol,traffic_source,profile,exemplar,explanation,anomaly_score,occurrences,first_seen,last_seen) VALUES (?,?,'pending',?,?,?,?,?,?,1,?,?)''',(key,'Unknown anomalous '+flow['protocol']+' pattern',flow['protocol'],source,json.dumps(profile),json.dumps(flow),json.dumps(explanation),score,now,now));pid=cur.lastrowid
        return pattern_row(db.execute('SELECT * FROM patterns WHERE id=?',(pid,)).fetchone())

def patterns(source='all'):
    clause,args=source_clause(source)
    with connect() as db: return [pattern_row(row) for row in db.execute('SELECT * FROM patterns WHERE 1=1'+clause+' ORDER BY last_seen DESC LIMIT 200',args)]

def rules(source='all'):
    clause,args=source_clause(source,'p.traffic_source')
    with connect() as db: rows=[dict(row) for row in db.execute('SELECT r.*,p.traffic_source,p.approved_label FROM learned_rules r JOIN patterns p ON p.id=r.pattern_id WHERE 1=1'+clause+' ORDER BY r.id DESC',args)]
    for row in rows: row['criteria']=json.loads(row['criteria']);row['enabled']=bool(row['enabled'])
    return rows

def match_rule(flow,profile):
    for row in rules(flow['traffic_source']):
        if row['enabled'] and row['protocol']==flow['protocol'] and all(limits[0]<=profile[key]<=limits[1] for key,limits in row['criteria'].items()): return row
    return None

def approve(pattern_id,label):
    with connect() as db:
        row=db.execute('SELECT * FROM patterns WHERE id=?',(pattern_id,)).fetchone()
        if not row: return None
        item=pattern_row(row);p=item['profile'];criteria={}
        for key in ('packets_per_second','bytes_per_second'):
            val=p[key];criteria[key]=[max(0,val*.55),max(val*1.75,val+1)]
        val=p['average_packet_size'];criteria['average_packet_size']=[max(0,val*.78),max(val*1.28,val+40)]
        for key in ('syn_ratio','ack_ratio'):
            val=p[key];delta=max(.08,val*.45);criteria[key]=[max(0,val-delta),min(1,val+delta)]
        cleaned='_'.join(label.split())
        db.execute('''INSERT INTO learned_rules(pattern_id,name,protocol,criteria,enabled,created_at) VALUES (?,?,?,?,1,?) ON CONFLICT(pattern_id) DO UPDATE SET name=excluded.name,criteria=excluded.criteria,enabled=1''',(pattern_id,'Review '+label,item['protocol'],json.dumps(criteria),time.time()))
        rule_id=db.execute('SELECT id FROM learned_rules WHERE pattern_id=?',(pattern_id,)).fetchone()[0];db.execute("UPDATE patterns SET status='approved',approved_label=?,rule_id=? WHERE id=?",(cleaned,rule_id,pattern_id))
        db.execute('''INSERT INTO feedback(pattern_id,label,features,created_at) VALUES (?,?,?,?) ON CONFLICT(pattern_id) DO UPDATE SET label=excluded.label,features=excluded.features''',(pattern_id,cleaned,json.dumps(item['exemplar']),time.time()))
        return pattern_row(db.execute('SELECT * FROM patterns WHERE id=?',(pattern_id,)).fetchone())

def reject(pattern_id):
    with connect() as db:
        cur=db.execute("UPDATE patterns SET status='rejected' WHERE id=?",(pattern_id,));db.execute('UPDATE learned_rules SET enabled=0 WHERE pattern_id=?',(pattern_id,));db.execute('DELETE FROM feedback WHERE pattern_id=?',(pattern_id,));return bool(cur.rowcount)

def feedback(source='all'):
    clause,args=source_clause(source,'p.traffic_source')
    with connect() as db: rows=[dict(row) for row in db.execute('SELECT f.* FROM feedback f JOIN patterns p ON p.id=f.pattern_id WHERE 1=1'+clause,args)]
    for row in rows: row['features']=json.loads(row['features'])
    return rows

def summary(source='all'):
    clause,args=source_clause(source);pattern_clause,pattern_args=source_clause(source,'p.traffic_source');now=time.time();minute=int(now//60)
    with connect() as db:
        def count(query,params=()): return db.execute(query,params).fetchone()[0]
        def event_count(condition=''): return count('SELECT COUNT(*) FROM events WHERE 1=1'+clause+condition,args)
        active_clause='' if source=='all' else " AND (traffic_source=? OR source='manual')";active_args=[] if source=='all' else [source]
        sensors={r['traffic_source']:{'active_agents':r['n'],'last_seen':r['last_seen']} for r in db.execute('SELECT traffic_source,COUNT(*) n,MAX(last_seen) last_seen FROM agent_heartbeats WHERE last_seen>? GROUP BY traffic_source',(now-20,))}
        source_counts={r['traffic_source']:r['n'] for r in db.execute('SELECT traffic_source,COUNT(*) n FROM events GROUP BY traffic_source')}
        timeline=[{'timestamp':(minute-11+i)*60,'normal':0,'alerts':0} for i in range(12)]
        for row in db.execute('SELECT CAST(timestamp/60 AS INTEGER) m,classification,COUNT(*) n FROM events WHERE timestamp>=? AND timestamp<?'+clause+' GROUP BY m,classification',[(minute-11)*60,(minute+1)*60,*args]):
            i=row['m']-(minute-11)
            if 0<=i<12: timeline[i]['normal' if row['classification']=='Normal' else 'alerts']+=row['n']
        score=db.execute("SELECT COUNT(*) n,AVG(confidence) average FROM events WHERE classification='Malicious' AND detection_source IN ('supervised','hybrid')"+clause,args).fetchone()
        return {'totalEvents':event_count(),'totalAlerts':event_count(" AND classification IN ('Malicious','Policy_Denied')"),'mlAlerts':event_count(" AND classification='Malicious'"),'policyOnly':event_count(" AND classification='Policy_Denied'"),'normalEvents':event_count(" AND classification='Normal'"),'unknownAlerts':event_count(" AND attack_type='Unknown_Anomaly'"),'policyDenied':event_count(" AND policy_action='deny'"),'policyMonitored':event_count(" AND policy_action='monitor'"),'trustedFlows':event_count(' AND trusted=1'),'activeBlocks':count('SELECT COUNT(*) FROM blocks WHERE (expires_at IS NULL OR expires_at>?)'+active_clause,[now,*active_args]),'pendingPatterns':count("SELECT COUNT(*) FROM patterns p WHERE p.status='pending'"+pattern_clause,pattern_args),'approvedPatterns':count("SELECT COUNT(*) FROM patterns p WHERE p.status='approved'"+pattern_clause,pattern_args),'activeRules':count('SELECT COUNT(*) FROM learned_rules r JOIN patterns p ON p.id=r.pattern_id WHERE r.enabled=1'+pattern_clause,pattern_args),'feedbackExamples':count('SELECT COUNT(*) FROM feedback f JOIN patterns p ON p.id=f.pattern_id WHERE 1=1'+pattern_clause,pattern_args),'activeAgents':sum(v['active_agents'] for k,v in sensors.items() if source=='all' or source==k),'attackTypes':{r[0]:r[1] for r in db.execute("SELECT attack_type,COUNT(*) FROM events WHERE classification IN ('Malicious','Policy_Denied')"+clause+' GROUP BY attack_type ORDER BY COUNT(*) DESC',args)},'protocols':{r[0]:r[1] for r in db.execute("SELECT protocol,COUNT(*) FROM events WHERE classification IN ('Malicious','Policy_Denied')"+clause+' GROUP BY protocol',args)},'modelScores':{'count':score['n'],'average':score['average']},'timeline':timeline,'sourceCounts':source_counts,'sensorActivity':sensors,'latestEventAt':db.execute('SELECT MAX(timestamp) FROM events WHERE 1=1'+clause,args).fetchone()[0]}
