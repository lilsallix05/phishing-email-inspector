"""Opt-in GET-only mailbox adapters. No sends, labels, moves, deletes, or link fetches."""
import argparse, base64, hashlib, json, os, re, time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote, urlsplit
from urllib.request import Request, build_opener, HTTPRedirectHandler
from urllib.error import HTTPError, URLError
from analyzer import analyze, MAX_EMAIL
ROOT=Path(__file__).resolve().parent
class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs): raise ValueError('Provider redirect refused')

def get(url,token,opener=None):
    if not token or '\n' in token or '\r' in token: raise ValueError('Provide a valid access token through MAIL_ACCESS_TOKEN')
    parsed=urlsplit(url)
    if parsed.scheme!='https' or parsed.hostname not in {'gmail.googleapis.com','graph.microsoft.com'} or parsed.username or parsed.password or parsed.port not in (None,443):
        raise ValueError('Only fixed HTTPS mailbox API hosts are allowed')
    req=Request(url,headers={'Authorization':'Bearer '+token,'Accept':'application/json'},method='GET')
    opener=opener or build_opener(NoRedirect())
    try:
        with opener.open(req,timeout=20) as response:
            data=response.read(MAX_EMAIL*2+1)
            if len(data)>MAX_EMAIL*2: raise ValueError('Provider response exceeds local size limit')
            return data
    except HTTPError as e: raise ValueError(f'Provider returned HTTP {e.code}; check consent, scope, token expiry, or throttling.') from None
    except URLError: raise ValueError('Provider connection failed; check network access.') from None

def list_ids(provider,token,opener=None):
    if provider=='gmail':
        d=json.loads(get('https://gmail.googleapis.com/gmail/v1/users/me/messages?maxResults=20&labelIds=INBOX',token,opener)); return [x['id'] for x in d.get('messages',[])]
    if provider=='graph':
        d=json.loads(get('https://graph.microsoft.com/v1.0/me/mailFolders/inbox/messages?$top=20&$select=id&$orderby=receivedDateTime%20desc',token,opener)); return [x['id'] for x in d.get('value',[])]
    raise ValueError('Unknown provider')

def read_raw(provider,message_id,token,opener=None):
    if not message_id or len(message_id)>2048: raise ValueError('Invalid message id')
    mid=quote(message_id,safe='')
    if provider=='gmail':
        payload=json.loads(get('https://gmail.googleapis.com/gmail/v1/users/me/messages/'+mid+'?format=raw',token,opener))['raw']
        try: return base64.b64decode(payload+'='*(-len(payload)%4),altchars=b'-_',validate=True)
        except (ValueError,TypeError): raise ValueError('Invalid Gmail raw MIME payload') from None
    if provider=='graph': return get('https://graph.microsoft.com/v1.0/me/messages/'+mid+'/$value',token,opener)
    raise ValueError('Unknown provider')

def write_private(path,data):
    path.parent.mkdir(parents=True,exist_ok=True)
    temp=path.with_suffix('.tmp'); fd=os.open(str(temp),os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o600)
    with os.fdopen(fd,'w') as f: json.dump(data,f,indent=2)
    os.chmod(temp,0o600); temp.replace(path)

def main():
    p=argparse.ArgumentParser(description=__doc__); p.add_argument('provider',choices=['gmail','graph','fixture']); p.add_argument('--id'); p.add_argument('--watch',action='store_true'); p.add_argument('--interval',type=int,default=60); p.add_argument('--once',action='store_true'); args=p.parse_args()
    if args.interval<30: p.error('Minimum polling interval is 30 seconds')
    token=os.environ.get('MAIL_ACCESS_TOKEN',''); model=json.loads((ROOT/'model/baseline.json').read_text())
    if args.provider!='fixture' and not token: p.error('Set MAIL_ACCESS_TOKEN in your shell. Never put tokens in source files or command arguments.')
    if not args.watch:
        if args.provider=='fixture': raw=(ROOT/'corpus/p01-0.eml').read_bytes()
        elif args.id: raw=read_raw(args.provider,args.id,token)
        else: p.error('Supply --id or --watch')
        print(json.dumps(analyze(raw,model),indent=2)); return
    seen=set(); alerts=[]
    try:
        while True:
            ids=['p01-0','b13-0'] if args.provider=='fixture' else list_ids(args.provider,token)
            for mid in ids:
                marker=hashlib.sha256((args.provider+':'+mid).encode()).hexdigest()[:16]
                if marker in seen: continue
                raw=(ROOT/'corpus'/(mid+'.eml')).read_bytes() if args.provider=='fixture' else read_raw(args.provider,mid,token)
                r=analyze(raw,model); seen.add(marker)
                # No subject, address, body, token, attachment, or provider message ID is saved.
                alerts.insert(0,{'id':marker,'level':r['rules']['level'],'score':r['rules']['score'],'findings':[f['title'] for f in r['rules']['findings']], 'model_label':r['model']['label'],'observed_at':datetime.now(timezone.utc).isoformat()})
            alerts=alerts[:100]
            write_private(ROOT/'work/alerts.json',{'mode':'Synthetic adapter fixture' if args.provider=='fixture' else args.provider+' read-only polling','last_checked':datetime.now(timezone.utc).isoformat(),'interval_seconds':args.interval,'alerts':alerts})
            print(f'Checked {len(ids)} messages; {len(alerts)} local observations. No mail changes.',flush=True)
            if args.once: break
            time.sleep(args.interval)
    except (ValueError,KeyboardInterrupt) as e:
        if isinstance(e,ValueError): raise SystemExit(str(e))
if __name__=='__main__': main()
