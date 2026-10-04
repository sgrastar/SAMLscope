"""Reference-only local SAML form driver; returns observations, never verdicts.

Credentials and cookies remain in memory. This driver does not execute JavaScript.
"""
import base64
import hashlib
import html
import http.cookiejar
import os
import re
import urllib.request as u
import urllib.parse as p
import urllib.error
import xml.etree.ElementTree as ET
import smoke

class SignatureMutation:
 """Corrupt only signature bytes, retaining the original signed XML/query bytes."""
 def __init__(self): self.records=[]
 def corrupt(self,value):
  raw=base64.b64decode(value,validate=True)
  if not raw:raise ValueError('Empty signature')
  return base64.b64encode(bytes([raw[0]^1])+raw[1:]).decode()
 def redirect(self,url):
  parts=p.urlsplit(url);fields=parts.query.split('&')
  if not any(f.startswith('SAMLRequest=') for f in fields):return url
  indexes=[i for i,f in enumerate(fields) if f.startswith('Signature=')]
  if len(indexes)!=1:raise ValueError('Expected one Redirect signature')
  index=indexes[0];original=fields[index].split('=',1)[1]
  fields[index]='Signature='+p.quote(self.corrupt(p.unquote(original)),safe='')
  self.records.append(dict(binding='redirect',original_query_sha256=hashlib.sha256(parts.query.encode()).hexdigest(),
    mutated_query_sha256=hashlib.sha256('&'.join(fields).encode()).hexdigest()))
  return p.urlunsplit(parts._replace(query='&'.join(fields)))
 def post(self,fields):
  import re
  if 'SAMLRequest' not in fields:return fields
  raw=base64.b64decode(fields['SAMLRequest'],validate=True)
  # Replace text only; serializing an XML tree would also change the signed document.
  pattern=rb'(<(?:[\w.-]+:)?SignatureValue\b[^>]*>)([^<]+)(</(?:[\w.-]+:)?SignatureValue>)'
  matches=list(re.finditer(pattern,raw))
  if len(matches)!=1:raise ValueError('Expected one POST signature')
  match=matches[0];value=''.join(html.unescape(match[2].decode()).split())
  mutated=raw[:match.start(2)]+self.corrupt(value).encode()+raw[match.end(2):]
  self.records.append(dict(binding='post',original_request_sha256=hashlib.sha256(raw).hexdigest(),
    mutated_request_sha256=hashlib.sha256(mutated).hexdigest()))
  return dict(fields,SAMLRequest=base64.b64encode(mutated).decode())

class MutationRedirectHandler(u.HTTPRedirectHandler):
 def __init__(self,mutation):self.mutation=mutation
 def redirect_request(self,req,fp,code,msg,headers,newurl):
  if p.urlparse(newurl).hostname not in {'localhost','127.0.0.1'}:raise RuntimeError('Nonlocal redirect')
  return super().redirect_request(req,fp,code,msg,headers,self.mutation.redirect(newurl))

class SuccessfulControlParser(smoke.FormParser):
 def handle_starttag(self,tag,attrs):
  values=dict(attrs)
  if tag.lower()=='input' and values.get('type','text').lower() in {'checkbox','radio'} and 'checked' not in values:return
  super().handle_starttag(tag,attrs)

def parse_forms(document):
 parser=SuccessfulControlParser();parser.feed(document);return parser.forms

class LocalCookiePolicy(http.cookiejar.DefaultCookiePolicy):
 def return_ok_secure(self,cookie,request):
  if p.urlparse(request.full_url).hostname in {'localhost','127.0.0.1'}:return True
  return super().return_ok_secure(cookie,request)

class Client:
 def __init__(self,signature_mutation=None):
  self.signature_mutation=signature_mutation
  self.jar=http.cookiejar.CookieJar(policy=LocalCookiePolicy())
  handlers=[u.HTTPCookieProcessor(self.jar)]
  if signature_mutation:handlers.append(MutationRedirectHandler(signature_mutation))
  self.op=u.build_opener(*handlers)
 def request(self,url,fields=None):
  if p.urlparse(url).hostname not in {'localhost','127.0.0.1'}: raise RuntimeError('Nonlocal target')
  req=u.Request(url,data=None if fields is None else p.urlencode(fields).encode())
  try:
   with self.op.open(req,timeout=30) as r:
    page=r.read().decode();url=r.geturl();code=r.status
  except urllib.error.HTTPError as e:
   page=e.read().decode(errors='replace');url=e.geturl();code=e.code
  if os.environ.get('SAML_SCOPE_FLOW_DIAGNOSTIC') == '1':
   title=re.search(r'<title[^>]*>(.*?)</title>',page,re.I|re.S)
   label=' '.join(html.unescape(title.group(1)).split())[:100] if title else ''
   print('flow-page',p.urlparse(url).path,'status',code,'title',label,flush=True)
  smoke.permit_localhost_http_cookies(self.jar,url)
  return url,page,code
 def flow(self,url,fields,user,password,terminal_observer=None):
  passive=False
  for i in range(20):
   url,page,code=self.request(url,fields)
   forms=parse_forms(page)
   saml=next((f for f in forms if 'SAMLRequest' in f.fields or 'SAMLResponse' in f.fields),None)
   if saml:
    if 'SAMLRequest' in saml.fields:
     root=ET.fromstring(base64.b64decode(saml.fields['SAMLRequest']));passive=root.get('IsPassive') in {'true','1'}
    url=p.urljoin(url,saml.action);fields=saml.fields
    if self.signature_mutation:fields=self.signature_mutation.post(fields)
    continue
   if 'SAML Response recorded' in page or 'SAML check recorded' in page or 'M0 SSO round trip completed' in page:
    return 'recorded'
   confirm=next((f for f in forms if 'freshSessionConfirmed' in f.fields),None)
   if confirm:
    # The Suite's browser-assisted probe page requires the private-session confirmation
    # before it dispatches the one-time fixture. A browser does this with a click; the
    # reference driver resubmits the same form without inventing a verdict.
    fields=dict(confirm.fields);fields['freshSessionConfirmed']='true'
    url=p.urljoin(url,confirm.action);continue
   if 'name="freshSessionConfirmed"' in page:
    # Unchecked checkboxes are not successful controls, so the parser omits them. The
    # probe page's form posts to itself; confirm the private-session boundary explicitly.
    fields={'freshSessionConfirmed':'true'};continue
   if 'Continue with this request' in page:
    # The probe page's submit button carries no field. Submitting an empty form dispatches
    # the one-time fixture exactly as the browser's button does.
    fields={};continue
   login=next((f for f in forms if 'password' in f.fields or 'j_password' in f.fields),None)
   if login:
    if passive:return 'passive-interaction-required'
    fields=login.fields
    if 'j_password' in fields:fields.update(j_username=user,j_password=password,_eventId_proceed='')
    else:fields.update(username=user,password=password)
    url=p.urljoin(url,login.action);continue
   if 'Check recorded' in page or 'Response recorded' in page:return 'recorded'
   for label in ['Invalid redirect uri','Unsupported NameIDFormat','RequestDenied','NoPassive','Invalid requester','Invalid Request','Message Security Error','Stale Request']:
    if label in page:
     if terminal_observer is not None: terminal_observer(url,page,code,label)
     return 'no-response:'+label
   if code>=400 and p.urlparse(url).port in {18180,18280,18380} and 'cookie not found' not in page.lower():
    if terminal_observer is not None: terminal_observer(url,page,code,'HTTP-'+str(code))
    return 'no-response:HTTP-'+str(code)
   print('unhandled location',p.urlparse(url).path,'status',code,flush=True)
   return 'unhandled-page-http-'+str(code)
  raise RuntimeError('Form hop limit')
