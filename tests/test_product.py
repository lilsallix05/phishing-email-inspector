import base64, json, unittest, sys, threading, urllib.request, urllib.error
from pathlib import Path
from email.message import EmailMessage
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from analyzer import analyze, parse_email, inspect_url, rules, MAX_EMAIL
from baseline import split, canonical, train, predict, metrics, ROOT
import mail_readers

class ParsingTests(unittest.TestCase):
    def eml(self,body='Hello',**headers):
        m=EmailMessage();m['From']=headers.pop('From','sender@example.org');m['Subject']=headers.pop('Subject','Test')
        for k,v in headers.items():m[k]=v
        m.set_content(body);return m
    def test_mime_base64_quoted_headers_and_attachments(self):
        m=self.eml('Hello café',Subject='Résumé');m.add_alternative('<p>Hello <b>café</b></p><script>secret_script</script><img src="https://track.invalid/pixel">',subtype='html');m.add_attachment(b'not executed',maintype='application',subtype='octet-stream',filename='payload.exe')
        r=analyze(m.as_bytes());self.assertEqual(r['message']['subject'],'Résumé');self.assertIn('café',r['message']['body']);self.assertNotIn('secret_script',r['message']['body']);self.assertEqual(r['message']['remote_images'],1);self.assertTrue(any(f['id']=='attachment' for f in r['rules']['findings']))
    def test_visible_url_mismatch(self):
        m=self.eml();m.add_alternative('<a href="https://unrelated.example.net/x">https://bank.example.org</a>',subtype='html');r=analyze(m.as_bytes());self.assertTrue(any('differs' in i for l in r['message']['links'] for i in l['issues']))
    def test_url_scheme_ip_userinfo_malformed(self):
        for url,word in [('javascript:alert(1)','scheme'),('http://192.0.2.1/','Numeric'),('https://trusted.example@other.example/','information'),('https://[bad','Malformed')]:
            self.assertTrue(any(word in i for i in inspect_url(url)['issues']),url)
    def test_idn_and_shortener(self):
        self.assertTrue(inspect_url('https://xn--bnk-5qa.example/')['issues']);self.assertTrue(inspect_url('https://bit.ly/abc')['issues'])
    def test_reply_mismatch_is_signal(self):
        r=analyze(self.eml(**{'Reply-To':'other@different.example'}).as_bytes());self.assertTrue(any(f['id']=='reply_domain' for f in r['rules']['findings']))
    def test_negated_credential_request(self):
        r=analyze(self.eml('Never share your OTP. Do not send your password.').as_bytes());self.assertFalse(any(f['id']=='credentials' for f in r['rules']['findings']))
    def test_negated_first_request_does_not_hide_later_request(self):
        r=analyze(self.eml('Never share your OTP. Verify your password immediately.').as_bytes());self.assertTrue(any(f['id']=='credentials' for f in r['rules']['findings']))
    def test_missing_headers_empty_and_size(self):
        for raw in [b'',b'just a body',b'x'*(MAX_EMAIL+1)]:
            with self.assertRaises(ValueError):parse_email(raw)
    def test_attachment_text_not_used_as_body(self):
        m=self.eml('ordinary');m.add_attachment('verify your password',filename='notes.txt');self.assertNotIn('password',parse_email(m.as_bytes())['body'])
    def test_broken_boundary(self):
        r=parse_email(b'From: x@example.org\nContent-Type: multipart/mixed; boundary=missing\n\nbody');self.assertTrue(r['defects'])
    def test_duplicate_link_cap(self):
        m=self.eml();m.add_alternative(''.join('<a href="http://192.0.2.1/'+str(i)+'">https://safe.example</a>' for i in range(20)),subtype='html');r=analyze(m.as_bytes());self.assertLessEqual(r['rules']['score'],40)
    def test_received_spf_failure_is_checked_per_header(self):
        for headers in [{'Received-SPF':'SoftFail (mx.example.net)'},{'Authentication-Results':'mx.example.net; spf=pass; dkim=pass','Received-SPF':'Fail (mx.example.net)'}]:
            r=analyze(self.eml(**headers).as_bytes());self.assertTrue(any(f['id']=='auth_fail' for f in r['rules']['findings']),headers)
        r=analyze(self.eml(**{'Authentication-Results':'mx.example.net; spf=pass; dkim=pass; dmarc=pass','Received-SPF':'Pass (mx.example.net)'}).as_bytes());self.assertFalse(any(f['id']=='auth_fail' for f in r['rules']['findings']))
    def test_script_is_never_rendered(self):
        r=analyze(self.eml('<script>alert("x")</script>').as_bytes());self.assertIn('<script>',r['message']['body']) # Plain text preserved; frontend escapes.

class ModelTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rows=json.loads((ROOT/'corpus/manifest.json').read_text())
        for r in cls.rows:r['parsed']=parse_email((ROOT/'corpus'/r['file']).read_bytes())
        cls.tr,cls.te=split(cls.rows)
    def test_grouped_holdout(self):
        self.assertEqual(len(self.rows),160);self.assertEqual(len(self.te),48)
        self.assertFalse({r['family'] for r in self.tr}&{r['family'] for r in self.te})
        self.assertFalse({canonical(r['parsed']) for r in self.tr}&{canonical(r['parsed']) for r in self.te})
    def test_duplicate_across_families_stays_together(self):
        row=dict(self.rows[0]);row['family']='new_family';tr,te=split(self.rows+[row]);self.assertFalse({canonical(r['parsed']) for r in tr}&{canonical(r['parsed']) for r in te})
    def test_reproducible_model_and_metrics(self):
        model=train(self.tr);stored=json.loads((ROOT/'model/baseline.json').read_text());self.assertEqual(model,stored)
        ps=[{'label':r['label'],'prediction':predict(model,r['parsed'])['label']} for r in self.te];self.assertEqual(metrics(ps),json.loads((ROOT/'evidence/evaluation.json').read_text())['model_metrics'])
    def test_vocab_fit_on_training_only(self):
        vocabulary=set(train(self.tr)['vocabulary']);from baseline import tokens
        self.assertTrue(vocabulary<=set(w for r in self.tr for w in tokens(r['parsed'])))

class FakeResponse:
    def __init__(self,data):self.data=data
    def read(self,n):return self.data[:n]
    def __enter__(self):return self
    def __exit__(self,*args):pass
class FakeOpener:
    def __init__(self,data):self.data=data;self.requests=[]
    def open(self,req,timeout):self.requests.append(req);return FakeResponse(self.data)
class AdapterTests(unittest.TestCase):
    def test_gmail_raw_get(self):
        raw=b'From: x@example.org\n\nHello';fake=FakeOpener(json.dumps({'raw':base64.urlsafe_b64encode(raw).decode().rstrip('=')}).encode());self.assertEqual(mail_readers.read_raw('gmail','abc', 'fixture-token',fake),raw);req=fake.requests[0];self.assertEqual(req.method,'GET');self.assertIn('?format=raw',req.full_url)
    def test_graph_raw_get_and_escaped_id(self):
        fake=FakeOpener(b'raw MIME');self.assertEqual(mail_readers.read_raw('graph','ab/c?x','fixture-token',fake),b'raw MIME');self.assertTrue(fake.requests[0].full_url.endswith('ab%2Fc%3Fx/$value'))
    def test_lists_and_unknown_provider(self):
        self.assertEqual(mail_readers.list_ids('gmail','x',FakeOpener(b'{"messages":[{"id":"abc"}]}')),['abc']);self.assertEqual(mail_readers.list_ids('graph','x',FakeOpener(b'{"value":[{"id":"def"}]}')),['def'])
        with self.assertRaises(ValueError):mail_readers.read_raw('other','id','x')
    def test_redirect_and_token_validation(self):
        with self.assertRaises(ValueError):mail_readers.NoRedirect().redirect_request(None,None,None,None,None,None)
        with self.assertRaises(ValueError):mail_readers.get('https://gmail.googleapis.com/','')
        with self.assertRaises(ValueError):mail_readers.get('https://unapproved.invalid/','fixture-token')

class ServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import server;cls.mod=server;cls.server=server.ThreadingHTTPServer(('127.0.0.1',0),server.Handler);cls.thread=threading.Thread(target=cls.server.serve_forever,daemon=True);cls.thread.start();cls.url='http://127.0.0.1:'+str(cls.server.server_port)
    @classmethod
    def tearDownClass(cls):cls.server.shutdown();cls.server.server_close()
    def request(self,path,data=None,headers=None):return urllib.request.urlopen(urllib.request.Request(self.url+path,data=data,headers=headers or {}))
    def test_static_and_security_headers(self):
        with self.request('/') as r:self.assertIn("frame-ancestors 'none'",r.headers['Content-Security-Policy']);self.assertIn(b'Postmark',r.read())
    def test_real_analysis_api(self):
        raw=(ROOT/'corpus/p01-0.eml').read_bytes();data=json.dumps({'raw_base64':base64.b64encode(raw).decode()}).encode()
        with self.request('/api/analyze',data,{'Content-Type':'application/json','X-Inspection-Token':self.mod.TOKEN}) as r:self.assertGreaterEqual(json.load(r)['rules']['score'],55)
    def test_cross_origin_and_missing_token_rejected(self):
        for headers in [{'Content-Type':'application/json'},{'Content-Type':'application/json','X-Inspection-Token':self.mod.TOKEN,'Origin':'https://evil.invalid'}]:
            with self.assertRaises(urllib.error.HTTPError) as ctx:self.request('/api/analyze',b'{}',headers)
            self.assertEqual(ctx.exception.code,403);ctx.exception.close()
    def test_path_not_exposed(self):
        with self.assertRaises(urllib.error.HTTPError) as ctx:self.request('/../model/baseline.json')
        self.assertEqual(ctx.exception.code,404);ctx.exception.close()

if __name__=='__main__':unittest.main(verbosity=2)
