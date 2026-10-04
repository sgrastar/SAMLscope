"""Native responses to exact Suite-generated metadata probe requests; no credentials/verdicts."""
from datetime import datetime, timezone
import base64
import hashlib
from pathlib import Path
import re
import urllib.parse
import xml.etree.ElementTree as ET

from reference_flow import Client,parse_forms

SHA=lambda raw:hashlib.sha256(raw).hexdigest()
NOW=lambda:datetime.now(timezone.utc).isoformat()


class MetadataNativeClient(Client):
    def __init__(self, records, directory=None):
        super().__init__(); self.records=records; self.directory=None if directory is None else Path(directory)

    def request(self,url,fields=None):
        observation=None
        if urllib.parse.urlsplit(url).netloc=='localhost:18280' and fields and 'SAMLRequest' in fields:
            raw=base64.b64decode(fields['SAMLRequest'],validate=True)
            root=ET.fromstring(raw)
            if root.tag!='{urn:oasis:names:tc:SAML:2.0:protocol}AuthnRequest':
                raise ValueError('Unexpected native metadata request')
            observation=dict(requestId=root.get('ID'),requestSha256=SHA(raw),requestUrl=url,requestMethod='POST',startedAt=NOW())
        final,page,status=super().request(url,fields)
        if observation is not None:
            replies=[f for f in parse_forms(page) if 'SAMLResponse' in f.fields]
            if len(replies)==1:observation['responseSamlSha256']=SHA(base64.b64decode(replies[0].fields['SAMLResponse'],validate=True))
            observation.update(responseUrl=final,responseStatus=status,responseBodySha256=SHA(page.encode()),
                completedAt=NOW(),nativeMessageSecurityError=('Message Security Error' in page),
                samlResponseFormPresent=('name="SAMLResponse"' in page or "name='SAMLResponse'" in page))
            if self.directory is not None and status>=400 and final==url and observation['nativeMessageSecurityError']:
                # Only an assertion-free native error without any input fields is exported.
                # Login/CSRF/session form values and transport headers are never persisted.
                if not re.search(r'<input(?:\s|/?>)|SAMLResponse|Authorization:|Cookie:',page,re.I):
                    request_id=observation['requestId']
                    if not re.fullmatch(r'[A-Za-z0-9_-]+',request_id):raise ValueError('Unsafe native request ID')
                    name='native-rejection-'+request_id+'.html'
                    (self.directory/name).write_bytes(page.encode())
                    observation['responseBodyFile']=name
            self.records.append(observation)
        return final,page,status
