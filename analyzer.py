"""Offline MIME and phishing signal inspection. Never resolves or fetches message URLs."""
import hashlib, ipaddress, re
from email import policy
from email.parser import BytesParser
from email.utils import getaddresses
from html.parser import HTMLParser
from urllib.parse import urlsplit

MAX_EMAIL = 2 * 1024 * 1024
URL_RE = re.compile(r'(?:https?://|www\.)[^\s<>"\']+', re.I)
SHORTENERS = {'bit.ly','tinyurl.com','t.co','is.gd','ow.ly','rb.gy'}

class VisibleHTML(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True); self.text=[]; self.links=[]; self.anchor=None; self.hidden=0; self.images=0
    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag in ('script','style','head'): self.hidden += 1
        if tag in ('p','br','div','li','tr'): self.text.append('\n')
        if tag == 'img' and a.get('src','').startswith(('http:','https:')): self.images += 1
        if tag == 'a':
            if self.anchor: self.links.append(self.anchor)
            self.anchor = {'url':a.get('href',''), 'display':''}
    def handle_endtag(self, tag):
        if tag in ('script','style','head'): self.hidden=max(0,self.hidden-1)
        if tag == 'a' and self.anchor: self.links.append(self.anchor); self.anchor=None
    def handle_data(self, data):
        if not self.hidden:
            self.text.append(data)
            if self.anchor: self.anchor['display'] += data


def domain(address):
    try: return address.rsplit('@',1)[1].rstrip('.').lower().encode('idna').decode('ascii')
    except (IndexError, UnicodeError): return ''


def address_list(message, header):
    try: return [{'name':n,'address':a,'domain':domain(a)} for n,a in getaddresses([str(x) for x in message.get_all(header,[])]) if a]
    except (ValueError, IndexError): return []


def inspect_url(raw, display=''):
    raw=raw.strip(); issues=[]; host=''; scheme=''
    try:
        p=urlsplit('https://'+raw if raw.lower().startswith('www.') else raw)
        host=(p.hostname or '').rstrip('.').lower(); scheme=p.scheme.lower()
        if scheme not in ('http','https','mailto','tel','cid',''):
            issues.append('Non-web scheme; never open from this report')
        if p.username is not None: issues.append('User information before the real host can disguise the destination')
        if scheme=='http': issues.append('Unencrypted HTTP destination')
        try:
            ipaddress.ip_address(host)
            issues.append('Numeric IP address instead of a named host')
        except ValueError: pass
        if 'xn--' in host or any(ord(c)>127 for c in host): issues.append('Internationalized host; check for lookalike characters')
        if host in SHORTENERS: issues.append('Shortened link hides its final destination')
        shown=URL_RE.search(display)
        if shown:
            dp=urlsplit(shown.group(0) if not shown.group(0).startswith('www.') else 'https://'+shown.group(0))
            if dp.hostname and host and dp.hostname.lower().rstrip('.') != host: issues.append('Visible link host differs from the destination host')
    except ValueError: issues.append('Malformed URL')
    return {'url':raw[:3000], 'display':display[:500] or raw[:500], 'host':host, 'scheme':scheme, 'issues':issues}


def parse_email(raw):
    if not isinstance(raw,bytes): raise ValueError('Provide email bytes')
    if not raw.strip(): raise ValueError('Paste or import a nonempty email first.')
    if len(raw)>MAX_EMAIL: raise ValueError('Email exceeds the 2 MiB local inspection limit.')
    m=BytesParser(policy=policy.default).parsebytes(raw)
    if not m.keys(): raise ValueError('No email headers found. Include at least a Subject: or From: header and a blank line before the body.')
    parts=[]; attachments=[]; defects=[]; links=[]; texts=[]; images=0; count=0; limited=False
    def visit(part,depth=0):
        nonlocal count,images,limited
        count+=1
        if count>100 or depth>10: limited=True; return
        defects.extend(type(d).__name__ for d in part.defects)
        name=part.get_filename()
        if part.get_content_disposition()=='attachment' or name:
            payload=part.get_payload(decode=True) or b''
            attachments.append({'name':name or '(unnamed)', 'type':part.get_content_type(), 'bytes':len(payload), 'sha256':hashlib.sha256(payload).hexdigest() if payload else None})
            return
        if part.is_multipart():
            for child in part.iter_parts(): visit(child,depth+1)
            return
        ct=part.get_content_type(); parts.append(ct)
        if ct not in ('text/plain','text/html'): return
        try: text=part.get_content()
        except (LookupError,UnicodeError,KeyError):
            text=(part.get_payload(decode=True) or b'').decode('utf-8','replace'); defects.append('UndecodableCharset')
        if not isinstance(text,str): return
        if len(text)>131072: text=text[:131072]; limited=True
        if ct=='text/html':
            parser=VisibleHTML(); parser.feed(text); parser.close()
            if parser.anchor: parser.links.append(parser.anchor)
            links.extend(parser.links); text=''.join(parser.text); images+=parser.images
        texts.append(text)
        links.extend({'url':u.rstrip('.,);]'), 'display':u.rstrip('.,);]')} for u in URL_RE.findall(text))
    visit(m)
    # Multipart alternatives often repeat the same content. Preserve each distinct body only once.
    body='\n\n'.join(dict.fromkeys(t.strip() for t in texts if t.strip()))
    unique={}
    for link in links:
        if link['url'] and len(unique)<100: unique.setdefault((link['url'],link['display']),inspect_url(link['url'],link['display']))
    headers={h:[str(v) for v in m.get_all(h,[])] for h in ['From','To','Reply-To','Return-Path','Subject','Date','Message-ID','Authentication-Results','Received-SPF','Received']}
    return {'sha256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw),'subject':str(m.get('Subject','(No subject)')),'from':address_list(m,'From'),'reply_to':address_list(m,'Reply-To'),'return_path':address_list(m,'Return-Path'),'headers':headers,'body':body[:131072], 'links':list(unique.values()),'attachments':attachments,'mime_types':parts,'remote_images':images,'defects':sorted(set(defects)),'truncated':limited or len(body)>131072 or len(links)>100}


def rules(message):
    findings=[]
    def add(key,title,weight,evidence,why,action):
        findings.append({'id':key,'title':title,'weight':weight,'evidence':evidence[:700],'explanation':why,'action':action})
    fr=message['from']; rp=message['reply_to']; text=message['subject']+'\n'+message['body']
    if not fr: add('sender_missing','No usable sender address',8,'From header missing or unreadable','Missing identity limits assessment; forwarded exports may lose headers.','Obtain the original message headers.')
    if fr and rp and fr[0]['domain']!=rp[0]['domain']:
        add('reply_domain','Replies go to a different host',18,fr[0]['domain']+' → '+rp[0]['domain'],'Legitimate services may use separate reply hosts; the difference needs context.','Confirm the reply address through a known contact.')
    if len(fr)>1: add('multiple_senders','More than one sender address',12,str(fr),'Multiple author addresses can be legitimate but complicate identity.','Review the original From and Sender headers.')
    if fr:
        visible=getaddresses([fr[0]['name']])
        if '@' in fr[0]['name'] and any(a and domain(a)!=fr[0]['domain'] for _,a in visible):
            add('display_spoof','Display name suggests another email identity',22,fr[0]['name']+' <'+fr[0]['address']+'>','The friendly name is controlled by the sender.','Use the actual address, not the display name.')
    for i,link in enumerate(message['links']):
        if not link['issues']: continue
        mismatch=any('differs' in x for x in link['issues'])
        weight=24 if mismatch else (16 if any('scheme' in x or 'Numeric' in x or 'User information' in x for x in link['issues']) else 8)
        add('link_'+str(i),'Link requires inspection',weight,link['display']+' → '+link['url'],'; '.join(link['issues']),'Navigate using your saved bookmark or independently verified address.')
    pattern=r'(?i)\b(?:confirm|verify|enter|provide|send|share|update|reset)\b[^.!?\n]{0,45}?\b(?:password|passcode|otp|one.time code|login credentials|bank details)\b'
    for active in re.finditer(pattern,text):
        prefix=text[max(0,active.start()-30):active.start()].lower()
        if not re.search(r"(?:do not|don't|never|won't|will not|not to)\s+(?:\w+\s+){0,3}$",prefix):
            add('credentials','Request involving credentials',22,active.group(0),'Credential and one-time-code requests deserve independent verification. A legitimate reset notice may also match.','Open the official app directly. Never share one-time codes.')
            break
    urgent=re.search(r'(?i)\b(?:within \d+ hours?|immediately|urgent|account (?:suspended|blocked)|final warning|last chance)\b',text)
    if urgent: add('urgency','Pressure to act quickly',9,urgent.group(0),'Time pressure can discourage checking; it is not proof of abuse.','Pause and verify through a channel you already trust.')
    money=re.search(r'(?i)\b(?:gift cards?|wire transfer|processing fee|release fee|crypto(?:currency)?|bitcoin|transfer funds)\b',text)
    if money: add('payment','Sensitive payment request',12,money.group(0),'Payment requests can be legitimate; unexpected changes require a separate check.','Call a known number to confirm payment details.')
    # Check each header on its own: a Received-SPF result starts its own value and can be SoftFail.
    failures=re.findall(r'(?i)\b(?:spf|dkim|dmarc)\s*=\s*(?:fail|softfail|permerror)',' '.join(message['headers']['Authentication-Results']))
    failures+=['Received-SPF: '+m.group(1) for value in message['headers']['Received-SPF'] if (m:=re.match(r'(?i)\s*(fail|softfail|permerror)\b',value))]
    if failures: add('auth_fail','Header reports authentication failure',14,'; '.join(failures),'Imported authentication headers are untrusted claims. This tool does not verify DNS, signatures, or the receiving server.','Check trusted gateway logs; forwarding can cause failures.')
    risky=[a['name'] for a in message['attachments'] if re.search(r'(?i)\.(?:exe|scr|js|vbs|hta|lnk|iso|docm|xlsm|bat|cmd|ps1)(?:\s*)$',a['name'])]
    if risky: add('attachment','Attachment can run active content',22,', '.join(risky),'Only metadata is inspected. The file was not executed or scanned.','Do not open it until a trusted security workflow reviews it.')
    if message['defects']: add('malformed','Parser reported message defects',5,', '.join(message['defects']),'Malformed exports can hide content or simply be damaged.','Obtain the original .eml before drawing conclusions.')
    if message['truncated']: add('limited','Inspection limit reached',0,'Content or MIME structure exceeds inspection limits.','The report is incomplete.','Review through a dedicated mail security tool.')
    # Repeated links cannot dominate the result by repetition.
    link_total=sum(f['weight'] for f in findings if f['id'].startswith('link_'))
    score=min(100,sum(f['weight'] for f in findings)-max(0,link_total-40))
    level='High concern' if score>=55 else 'Needs review' if score>=20 else 'Few rule signals'
    return {'score':score,'level':level,'findings':findings,'score_meaning':'Additive triage points, not a probability. Link evidence is capped at 40 points; total at 100.'}


def analyze(raw, model=None):
    msg=parse_email(raw); result={'schema_version':1,'message':msg,'rules':rules(msg),'model':None,'limitations':['No URL, image, DNS, attachment content, or reputation service was contacted.','Imported authentication headers are observations, not verified authentication.','A low score does not establish safety. Use a trusted channel to verify unusual requests.']}
    if model:
        from baseline import predict
        result['model']=predict(model,msg)
    return result
