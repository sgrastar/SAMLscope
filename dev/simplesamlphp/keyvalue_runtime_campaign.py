#!/usr/bin/env python3
"""Native accepted-metadata key resolution, full representation controls, exact restore.

No result is adopted here. A missing-key exception is recorded separately from
cryptographic rejection; configuration unavailability remains unverified.
"""
import argparse
import base64
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import urllib.request
import urllib.parse
import http.cookiejar

from persistent_nameid_normal_campaign import REPO,CONTAINER,IDP,api,save,BASE,native,batch,raw,settled
from metadata_refresh_campaign import RefreshSignatureClient
from import_metadata_batch import flow
from metadata_replacement_campaign import READBACK,arm

VARIANTS=['control','entity-root','keyvalue-only','certificate-runtime-same-key','certificate-runtime-other-key']
SOURCES={'parser':'/var/simplesamlphp/src/SimpleSAML/Metadata/SAMLParser.php',
    'message':'/var/simplesamlphp/modules/saml/src/Message.php',
    'configuration':'/var/simplesamlphp/src/SimpleSAML/Configuration.php',
    'idp-saml2':'/var/simplesamlphp/modules/saml/src/IdP/SAML2.php',
    'web-browser-sso':'/var/simplesamlphp/modules/saml/src/Controller/WebBrowserSingleSignOn.php'}
def sha(value):return hashlib.sha256(value).hexdigest()
def inspect_identity():
    source=json.loads(subprocess.check_output(['docker','inspect',CONTAINER],timeout=30))[0]
    return dict(containerId=source['Id'],imageId=source['Image'],image=source['Config']['Image'],
        startedAt=source['State']['StartedAt'],running=source['State']['Running'])

class RedirectTracker(urllib.request.HTTPRedirectHandler):
    def __init__(self):self.count=0
    def redirect_request(self,*args,**kwargs):
        self.count+=1
        return super().redirect_request(*args,**kwargs)

class KeyValueClient(RefreshSignatureClient):
    def __init__(self,records,response_originals,request_originals):
        super().__init__(records,response_originals);self.request_originals=request_originals
        self.redirects=RedirectTracker();self.op=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar),self.redirects)
    def request(self,url,fields=None):
        before=len(self.records);started=datetime.now(timezone.utc).isoformat();redirects_before=self.redirects.count
        raw_request=None
        if urllib.parse.urlparse(url).port==18380 and fields and 'SAMLRequest' in fields:
            if not set(fields)<={'SAMLRequest','RelayState'}:raise ValueError('Unsafe transport fields')
            raw_request=base64.b64decode(fields['SAMLRequest'],validate=True)
            transport_body=urllib.parse.urlencode(fields).encode()
        result=super().request(url,fields)
        if raw_request is not None and len(self.records)==before+1:
            record=self.records[-1];record['started_at']=started
            self.request_originals[record['request_id']]=(raw_request,transport_body)
            record['request_body_sha256']=sha(transport_body)
            record['redirect_hops']=self.redirects.count-redirects_before
            if sha(raw_request)!=record['request_sha256']:raise ValueError('Submitted request original differs')
        return result
def readback(folder,remote,entity,label):
    path=folder/label;path.mkdir()
    current=settled(remote.container_path,remote.expected)
    (path/'configuration.php').write_bytes(current)
    value=subprocess.check_output(['docker','exec',CONTAINER,'php','-r',READBACK,entity],timeout=30)
    (path/'native.json').write_bytes(value)
    if json.loads(value)['remoteSha256']!=sha(current):raise ValueError('Native key configuration readback differs')
    save(path/'observed.json',dict(recordedAt=datetime.now(timezone.utc).isoformat()))

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    out=a.output.resolve();out.mkdir(parents=True,exist_ok=False)
    remote=batch('saml20-sp-remote.php');(out/'original-sp-config.php').write_bytes(remote.original)
    (out/'native-collector.py').write_bytes(Path(__file__).read_bytes())
    (out/'native-signature-client.py').write_bytes((REPO/'dev/simplesamlphp/signed_request_observation.py').read_bytes())
    (out/'native-reference-flow.py').write_bytes((REPO/'dev/keycloak/reference_flow.py').read_bytes())
    (out/'native-parser-command.php').write_text(native.PHP);(out/'native-readback-command.php').write_text(READBACK)
    for name,path in SOURCES.items():(out/('native-'+name+'.php')).write_bytes(raw(path))
    save(out/'native-inspect-before.json',inspect_identity())
    credentials=(os.environ.get('REFERENCE_USERNAME','samlscope-m0-user'),os.environ.get('REFERENCE_PASSWORD','samlscope-m0-password'))
    operations=[];records=[];originals={};request_originals={};run=None;parsers=attempts=0
    try:
        created=api('/api/plans',dict(name='SimpleSAMLphp native KeyValue runtime resolution',profile='metadata_idp',
            targetKind='IDP',targetEntityId=IDP,metadataSourceKind='URL',
            metadataSourceLocation='http://samlscope-reference-ssp/simplesaml/module.php/saml/idp/metadata',
            suiteMetadataDelivery='HTTP_URL',declaredFeatures={},parameters=dict(clockSkewToleranceSeconds=180,
            metadataRefreshWaitSeconds=300,testUserHint=credentials[0],requestSigningMode='REQUIRED'),
            interaction=dict(allowBrowserSteps=True,allowAttestation=False,preset='quick'),authorizedTarget=True))
        save(out/'plan.json',created);plan=created['plan']['plan']['id'];entity=BASE+'/p/'+plan
        if entity.encode() in remote.original:raise ValueError('Fresh metadata entity already configured')
        created=api('/api/plans/'+plan+'/runs',{});save(out/'created.json',created);run=created['run']['id']
        save(out/'preflight.json',api('/api/runs/'+run+'/preflight',{}))
        save(out/'campaign.json',api('/api/runs/'+run+'/metadata-lab/automatic-polling',dict(variants=VARIANTS,pollingDelaySeconds=0)))
        for variant in VARIANTS:
            folder=out/variant;folder.mkdir();row=dict(variant=variant,status='incomplete');operations.append(row)
            save(out/'operations.json',operations);state,fixture=arm(run,folder,variant)
            parsers+=1
            parsed=subprocess.run(['docker','exec','-i',CONTAINER,'php','-r',native.PHP,entity,'default'],
                input=fixture,capture_output=True,timeout=40)
            (folder/'parser.stdout').write_bytes(parsed.stdout);(folder/'parser.stderr').write_bytes(parsed.stderr)
            row['nativeParserReturncode']=parsed.returncode
            if parsed.returncode:
                row['status']='configuration-unavailable';raise ValueError('Native product did not accept fixture')
            data=json.loads(parsed.stdout)
            if data['entity_id']!=entity or data['validate_authnrequest'] is not True:raise ValueError('Native entity/signature policy differs')
            remote.apply(data['php'].encode());time.sleep(3);readback(folder,remote,entity,'before')
            before=api('/api/runs/'+run+'/transcript');attempts+=2
            try:
                flow(run,folder/'flow.json',suite_signature_control=True,login_inputs=credentials,
                    client_factory=lambda **kwargs:KeyValueClient(records,originals,request_originals))
                row['status']='correlated-success'
            except RuntimeError as error:
                row['status']='runtime-unresolved';row['diagnosis']=str(error)
                if variant=='control':raise
            readback(folder,remote,entity,'after')
            after=api('/api/runs/'+run+'/transcript');ids={e['id'] for e in before}
            save(folder/'transcript.json',[e for e in after if e['id'] not in ids]);save(out/'operations.json',operations)
            if variant=='control':save(out/'tests-start.json',api('/api/runs/'+run+'/tests/start',{}))
            pending=api('/api/runs/'+run+'/metadata-lab')
            if pending['campaignIndex']==state['campaignIndex']:
                with urllib.request.urlopen(urllib.request.Request(pending['automaticContinueUrl'],data=b''),timeout=30) as response:response.read()
                row['continuedWithoutVerdict']=True
    finally:
        restore=remote.restore();final=settled(remote.container_path,remote.original)
        (out/'final-sp-config.php').write_bytes(final);save(out/'restoration.json',restore)
        save(out/'native-http-observations.json',dict(runId=run,records=records,productVerdictAssigned=False))
        folder=out/'native-http-originals';folder.mkdir()
        for record in records:
            original=originals[record['request_id']]
            if sha(original)!=record['response_body_sha256']:raise ValueError('Native HTTP original hash differs')
            # The positive X509 body is only a login page. Its one-time AuthState
            # is not used by the Reader and must never be persisted.
            from html.parser import HTMLParser
            class LoginTokens(HTMLParser):
                def __init__(self):super().__init__();self.values=[]
                def handle_starttag(self,tag,attrs):
                    fields=dict(attrs)
                    if tag=='input' and fields.get('name')=='AuthState' and fields.get('type','').lower()=='hidden' and fields.get('value'):
                        self.values.append(fields['value'])
                        import re
                        match=re.search(r'\bvalue\s*=\s*(?:"([^"]*)"|\'([^\']*)\'|([^\s>]+))',self.get_starttag_text(),re.I)
                        if match:self.values.append(next(value for value in match.groups() if value is not None))
            tokens=LoginTokens();tokens.feed(original.decode());projected=original
            for value in tokens.values:projected=projected.replace(value.encode(),b'[REDACTED-AUTHSTATE]')
            if tokens.values:
                if record['response_status']!=200 or record['native_signature_rejection'] is not None:raise ValueError('Unexpected login-state-bearing native error')
                record['persisted_body_sha256']=sha(projected);record['body_sanitized']=True
            (folder/(record['request_id']+'.html')).write_bytes(projected)
            request_raw,body=request_originals[record['request_id']]
            (folder/(record['request_id']+'.request.xml')).write_bytes(request_raw)
            (folder/(record['request_id']+'.request.body')).write_bytes(body)
        save(out/'native-http-observations.json',dict(runId=run,records=records,productVerdictAssigned=False))
        save(out/'native-inspect-after.json',inspect_identity())
        save(out/'operation-counts.json',dict(productConfigurationWriteAttempts=remote.write_count,
            configurationApplyWrites=remote.applied_count,restorationWrites=remote.restoration_writes,
            nativeParserInvocations=parsers,protocolOperationsAttempted=attempts,runCreations=int(run is not None),
            productRestarts=0,humanOperations=0,restored=restore['restored']))
        if run:
            sys.path.insert(0,str(REPO/'dev/reference-acceptance'));from capture_run_originals import capture
            entries=api('/api/runs/'+run+'/transcript');save(out/'transcript.json',entries);capture(out,run,entries)
            save(out/'result-before.json',api('/api/runs/'+run+'/result.json'))
            save(out/'protocol-evidence-before.json',api('/api/runs/'+run+'/protocol-evidence'))
        if not restore['restored'] or final!=remote.original:raise ValueError('Native product restoration failed')
    print(run,'native KeyValue runtime observations recorded; exact restore; no adoption')

if __name__=='__main__':main()
