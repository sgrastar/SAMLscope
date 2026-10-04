"""Observe the initial native Password challenge, without exporting login/session credentials."""
from datetime import datetime, timezone
import base64
import hashlib
import json
from pathlib import Path
import re
import urllib.parse as urls
import urllib.request as http
import xml.etree.ElementTree as ET
import zlib

from reference_flow import Client, parse_forms

TARGET='localhost:18280'
NOW=lambda:datetime.now(timezone.utc).isoformat()
SHA=lambda raw:hashlib.sha256(raw).hexdigest()


class ChallengeClient(Client):
    def __init__(self,output):
        super().__init__();self.output=Path(output);self.output.mkdir(exist_ok=False)
        self.target_request=None;self.challenge=None;self.challenge_saved=False;self.interactions=[]
        self.initial_cookie_count=len(self.jar)
        owner=self
        class NativeRedirect(http.HTTPRedirectHandler):
            def redirect_request(self,req,fp,code,msg,headers,newurl):
                parsed=urls.urlsplit(newurl)
                if parsed.netloc==TARGET:
                    values=urls.parse_qs(parsed.query)
                    if 'SAMLRequest' in values:
                        if owner.target_request is not None:raise ValueError('Ambiguous native initial request')
                        raw=zlib.decompress(base64.b64decode(values['SAMLRequest'][0]),-15)
                        root=ET.fromstring(raw)
                        if root.tag!='{urn:oasis:names:tc:SAML:2.0:protocol}AuthnRequest':raise ValueError('Wrong native request type')
                        owner.target_request=dict(requestId=root.get('ID'),targetUrl=newurl,rawQuery=parsed.query,
                            requestSha256=SHA(raw),observedAt=NOW())
                return super().redirect_request(req,fp,code,msg,headers,newurl)
        self.op=http.build_opener(http.HTTPCookieProcessor(self.jar),NativeRedirect())

    def request(self,url,fields=None):
        parsed=urls.urlsplit(url)
        if fields and parsed.netloc==TARGET and ('j_password' in fields or 'password' in fields):
            # Record only names and actual dispatch time. Username/password values,
            # authorization headers, cookies and form tokens never leave memory.
            self.interactions.append(dict(method='POST',targetUrl=url,fieldNames=sorted(fields),observedAt=NOW()))
        result=super().request(url,fields)
        actual,page,status=result
        if urls.urlsplit(actual).netloc==TARGET and any('j_password' in form.fields or 'password' in form.fields for form in parse_forms(page)):
            if self.challenge_saved:raise ValueError('Repeated native challenge is not the positive control')
            if self.target_request is None:raise ValueError('Native challenge has no observed SAML request')
            if self.interactions:raise ValueError('Native challenge was reached after credential submission')
            # Anti-CSRF input values are transport credentials. Remove them before
            # persisting the original response; the password/username fields must be empty.
            if any(form.fields.get(name) for form in parse_forms(page)
                   for name in ('j_password','password','j_username','username')):
                raise ValueError('Native challenge contains a populated login input')
            def redact_input(match):
                tag=match.group(0)
                if re.search(r'\btype\s*=\s*(?:[\"\']hidden[\"\']|hidden(?=\s|>))|\bname\s*=\s*[\"\'][^\"\']*(?:csrf|token)[^\"\']*[\"\']',tag,re.I):
                    return re.sub(r'\bvalue\s*=\s*(?:"[^"]*"|\'[^\']*\'|[^\s>]+)',
                                  'value="[REDACTED]"',tag,flags=re.I)
                return tag
            redacted=re.sub(r'<input\b[^>]*>',redact_input,page,flags=re.I)
            raw=redacted.encode();(self.output/'native-challenge.html').write_bytes(raw)
            self.challenge=dict(schema='samlscope-native-authentication-challenge-v1',
                request=self.target_request,response=dict(url=actual,status=status,recordedAt=NOW(),
                bodyFile='native-challenge.html',bodySha256=SHA(raw),redaction='csrf-token-values-before-persistence'),
                initialCookieCount=self.initial_cookie_count)
            self.challenge_saved=True
        return result

    def finish(self):
        if not self.challenge_saved or self.challenge is None or len(self.interactions)!=1:
            raise ValueError('Exactly one pre-credential challenge and credential submission required')
        self.challenge['credentialSubmissions']=self.interactions
        (self.output/'native-challenge.json').write_text(json.dumps(self.challenge,indent=2)+'\n')
