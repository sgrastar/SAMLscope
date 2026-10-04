#!/usr/bin/env python3
"""Record native HTTP configuration and used paths for the MD06.a3 TLS-unused control."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import re
import subprocess
import sys
import urllib.request
import xml.etree.ElementTree as ET

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'reference-acceptance'))
from capture_run_originals import capture
from export_metadata_key_receipt import export

BASE='http://localhost:18080'
PRODUCT='samlscope-reference-keycloak'
SHA=lambda raw:hashlib.sha256(raw).hexdigest()

def api(path):
    with urllib.request.urlopen(BASE+path,timeout=45) as response:return json.load(response)

def save(path,value):path.write_text(json.dumps(value,indent=2)+'\n')

def collect(folder):
    folder=Path(folder).resolve()
    created=json.loads((folder/'created.json').read_bytes())
    run=created['run']['id'];plan=created['run']['planId']
    target=(folder/'target-metadata.xml').read_bytes()
    info=json.loads(subprocess.check_output(['docker','inspect',PRODUCT]))[0]
    runtime=dict(image=info['Image'],command=info['Config']['Cmd'],portBindings=info['HostConfig']['PortBindings'])
    # Full native configuration is inspected in memory; only public HTTP/TLS configuration is retained.
    output=subprocess.check_output(['docker','exec',PRODUCT,'/opt/keycloak/bin/kc.sh','show-config'],text=True)
    selected=[];tls=[]
    for line in output.splitlines():
        value=line.strip()
        if value.startswith(('kc.hostname =','kc.http-enabled =')):selected.append(value)
        if value.startswith(('kc.https-certificate-file =','kc.https-certificate-key-file =',
                'kc.https-key-store-file =','kc.https-client-auth =','kc.https-trust-store-file =')):tls.append(value)
    if tls or set(runtime['portBindings'])!={'8080/tcp'} or 'start-dev' not in runtime['command']:
        raise ValueError('Native TLS-unused precondition is not established')
    safe_lines=[]
    for line in output.splitlines():
        name=line.split('=',1)[0]
        if '=' in line and re.search(r'password|secret|token|credential|username',name,re.I):
            line=name.rstrip()+' = [REDACTED]'
        safe_lines.append(line)
    safe_text='\n'.join(safe_lines)+'\n'
    native=dict(source='kc.sh show-config',originalText=safe_text,originalTextSha256=SHA(safe_text.encode()),
        selectedConfiguration=selected,tlsConfiguration=tls)
    original=dict(schema='samlscope-keycloak-role-signing-transport-v1',runId=run,
        targetEntityId=ET.fromstring(target).get('entityID'),targetMetadataSha256=SHA(target),
        runtime=runtime,nativeConfiguration=native)
    raw=(json.dumps(original,sort_keys=True,separators=(',',':'))+'\n').encode()
    before=api('/api/runs/'+run+'/transcript');ids={e['id'] for e in before}
    request=urllib.request.Request(BASE+'/p/'+plan+'/sp/paos?run='+run,data=raw,method='POST',
        headers={'Content-Type':'application/json'})
    with urllib.request.urlopen(request,timeout=30) as response:
        if response.status!=204:raise ValueError('Native HTTP original was not recorded')
    after=api('/api/runs/'+run+'/transcript')
    added=[e for e in after if e['id'] not in ids and e.get('decodedSamlRef') and e.get('status')==204]
    if len(added)!=1:raise ValueError('Native HTTP original reference is ambiguous')
    ref=dict(reference=added[0]['id'],sha256=SHA(raw),configurationTextSha256=SHA(safe_text.encode()))
    prior=folder/'role-signing-transport-capture.json'
    revision=1+(json.loads(prior.read_bytes()).get('revision',1) if prior.exists() else 0)
    save(prior,dict(run=run,original=ref,revision=revision,
        product_configuration_writes=0,protocol_requests=0,recorder_original_posts=revision,human_operations=0))
    (folder/'role-signing-transport-original.json').write_bytes(raw)
    (folder/'native-show-config-redacted.txt').write_text(safe_text)
    save(folder/'native-http-runtime.json',runtime)
    backup=folder/('preparation-before-transport-'+str(revision));backup.mkdir()
    for name in ['transcript.json','decoded-manifest.json','qualified-metadata-key-receipt.json']:
        shutil.copy2(folder/name,backup/name)
    save(folder/'transcript.json',after)
    capture(folder,run,after)
    receipt=export(folder)
    save(folder/'qualified-metadata-key-receipt.json',receipt)
    print('Native HTTP-unused original captured; no verdict adopted',run)
    return original

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--evidence',type=Path,required=True)
    collect(parser.parse_args().evidence)
