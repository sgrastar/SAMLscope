"""Reference-only local SAML form driver; returns observations, never verdicts.

Credentials and cookies remain in memory. This driver does not execute JavaScript.
"""
import base64
import http.cookiejar
import urllib.request as u
import urllib.parse as p
import urllib.error
import xml.etree.ElementTree as ET
import smoke

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
 def __init__(self):
  self.jar=http.cookiejar.CookieJar(policy=LocalCookiePolicy());self.op=u.build_opener(u.HTTPCookieProcessor(self.jar))
 def request(self,url,fields=None):
  if p.urlparse(url).hostname not in {'localhost','127.0.0.1'}: raise RuntimeError('Nonlocal target')
  req=u.Request(url,data=None if fields is None else p.urlencode(fields).encode())
  try:
   with self.op.open(req,timeout=30) as r:
    page=r.read().decode();url=r.geturl();code=r.status
  except urllib.error.HTTPError as e:
   page=e.read().decode(errors='replace');url=e.geturl();code=e.code
  smoke.permit_localhost_http_cookies(self.jar,url)
  return url,page,code
 def flow(self,url,fields,user,password):
  passive=False
  for i in range(20):
   url,page,code=self.request(url,fields)
   forms=parse_forms(page)
   saml=next((f for f in forms if 'SAMLRequest' in f.fields or 'SAMLResponse' in f.fields),None)
   if saml:
    if 'SAMLRequest' in saml.fields:
     root=ET.fromstring(base64.b64decode(saml.fields['SAMLRequest']));passive=root.get('IsPassive') in {'true','1'}
    url=p.urljoin(url,saml.action);fields=saml.fields;continue
   if 'SAML Response recorded' in page or 'SAML check recorded' in page or 'M0 SSO round trip completed' in page:
    return 'recorded'
   login=next((f for f in forms if 'password' in f.fields or 'j_password' in f.fields),None)
   if login:
    if passive:return 'passive-interaction-required'
    fields=login.fields
    if 'j_password' in fields:fields.update(j_username=user,j_password=password,_eventId_proceed='')
    else:fields.update(username=user,password=password)
    url=p.urljoin(url,login.action);continue
   if 'Check recorded' in page or 'Response recorded' in page:return 'recorded'
   for label in ['Invalid redirect uri','Unsupported NameIDFormat','RequestDenied','NoPassive','Invalid requester','Invalid Request','Message Security Error','Stale Request']:
    if label in page:return 'no-response:'+label
   if code>=400 and p.urlparse(url).port in {18180,18280,18380} and 'cookie not found' not in page.lower():return 'no-response:HTTP-'+str(code)
   print('unhandled location',p.urlparse(url).path,'status',code,flush=True)
   return 'unhandled-page-http-'+str(code)
  raise RuntimeError('Form hop limit')
