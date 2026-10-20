"""Loopback-only, stateless inspection service. No mailbox token handling in the UI."""
import argparse, base64, json, secrets
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit
from analyzer import analyze, MAX_EMAIL
ROOT=Path(__file__).resolve().parent
STATIC={'/':'index.html','/app.js':'app.js','/style.css':'style.css'}
MODEL=json.loads((ROOT/'model/baseline.json').read_text())
SAMPLES=[('p01-0','Password request'),('p20-0','Subtle document lure'),('b13-0','Legitimate urgent notice'),('b06-0','Awareness workshop')]
TOKEN=secrets.token_urlsafe(24)
class Handler(BaseHTTPRequestHandler):
    def log_message(self,*args): pass # Do not log message content or URL parameters.
    def send(self,status,data,ctype='application/json'):
        if not isinstance(data,bytes): data=json.dumps(data,ensure_ascii=True).encode()
        self.send_response(status); self.send_header('Content-Type',ctype); self.send_header('Content-Length',str(len(data)))
        self.send_header('Cache-Control','no-store'); self.send_header('X-Content-Type-Options','nosniff'); self.send_header('Referrer-Policy','no-referrer')
        self.send_header('Content-Security-Policy',"default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; object-src 'none'; base-uri 'none'; form-action 'self'")
        self.end_headers(); self.wfile.write(data)
    def allowed(self):
        return self.headers.get('Host') in (f'127.0.0.1:{self.server.server_port}', f'localhost:{self.server.server_port}')
    def do_GET(self):
        if not self.allowed(): return self.send(403,{'error':'Use the loopback address printed by the server.'})
        p=urlsplit(self.path).path
        if p in STATIC:
            c={'/':'text/html; charset=utf-8','/app.js':'text/javascript; charset=utf-8','/style.css':'text/css; charset=utf-8'}[p]
            return self.send(200,(ROOT/'static'/STATIC[p]).read_bytes(),c)
        if p=='/api/session': return self.send(200,{'token':TOKEN,'mode':'Local inspection; no mail changes'})
        if p=='/api/samples': return self.send(200,[{'id':i,'name':n,'raw':(ROOT/'corpus'/(i+'.eml')).read_text(),'synthetic':True} for i,n in SAMPLES])
        if p=='/api/evaluation': return self.send(200,json.loads((ROOT/'evidence/evaluation.json').read_text()))
        if p=='/api/alerts':
            file=ROOT/'work/alerts.json'
            try: data=json.loads(file.read_text()) if file.exists() else {'mode':'Not connected','alerts':[]}
            except (json.JSONDecodeError,OSError): data={'mode':'Watcher data unavailable','alerts':[]}
            return self.send(200,data)
        return self.send(404,{'error':'Not found'})
    def do_POST(self):
        if not self.allowed(): return self.send(403,{'error':'Invalid host'})
        origin=self.headers.get('Origin')
        if origin and origin not in (f'http://127.0.0.1:{self.server.server_port}',f'http://localhost:{self.server.server_port}'):
            return self.send(403,{'error':'Cross-origin requests are not accepted.'})
        if self.headers.get('X-Inspection-Token')!=TOKEN: return self.send(403,{'error':'Reload the page to establish a local session.'})
        if self.path!='/api/analyze': return self.send(404,{'error':'Not found'})
        try:
            n=int(self.headers.get('Content-Length','0'))
            if not 0<n<MAX_EMAIL*2: return self.send(413,{'error':'Import one email smaller than 2 MiB.'})
            if not self.headers.get('Content-Type','').startswith('application/json'): return self.send(415,{'error':'Expected JSON'})
            data=json.loads(self.rfile.read(n)); raw=base64.b64decode(data['raw_base64'],validate=True) if 'raw_base64' in data else data['raw'].encode('utf-8')
            result=analyze(raw,MODEL); self.send(200,result)
        except (ValueError,KeyError,TypeError,UnicodeError) as e: self.send(400,{'error':str(e)[:200]})
        except Exception: self.send(422,{'error':'This email could not be parsed. Export its original .eml and try again.'})

def main():
    parser=argparse.ArgumentParser(); parser.add_argument('--port',type=int,default=18766); args=parser.parse_args()
    server=ThreadingHTTPServer(('127.0.0.1',args.port),Handler)
    print(f'Postmark inspection desk: http://127.0.0.1:{server.server_port} (Ctrl+C to stop)',flush=True)
    try: server.serve_forever()
    except KeyboardInterrupt: pass
    finally: server.server_close()
if __name__=='__main__': main()
