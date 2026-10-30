"""Separate opt-in enforcer for an authorized Linux network namespace."""
import os
import signal
import requests
from policy_enforcer import Enforcer

def enabled(name): return os.getenv(name,'').lower() in {'1','true','yes'}
def main():
    access=enabled('ENFORCE_ACCESS_POLICY');blocks=enabled('ENFORCE_BLOCKLIST')
    if not access and not blocks: print('[INFO] No enforcement selected; set an explicit ENFORCE_* flag.',flush=True);return
    url=os.getenv('COMMANDER_API_URL','http://127.0.0.1:8000/api/v1/flows/process');base=url.removesuffix('/flows/process').rstrip('/');session=requests.Session()
    if os.getenv('COMMANDER_API_KEY'): session.headers['X-API-Key']=os.environ['COMMANDER_API_KEY']
    worker=Enforcer(session,base,access,blocks);worker.start()
    def stop(*_): worker.stop_event.set()
    signal.signal(signal.SIGINT,stop);signal.signal(signal.SIGTERM,stop)
    try:
        while worker.is_alive() and not worker.stop_event.wait(1): pass
    finally: worker.stop_event.set();worker.join(timeout=15);worker.cleanup()
if __name__=='__main__': main()
