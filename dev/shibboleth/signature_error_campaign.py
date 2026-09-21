#!/usr/bin/env python3
"""Exercise signature fixtures with native remote-error handling; restore exact configuration, no verdict."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import time
import urllib.request
import xml.etree.ElementTree as ET
from attribute_name_capability import docker

B='http://www.springframework.org/schema/beans'
U='http://www.springframework.org/schema/util'
CONFIG='/opt/reference-idp/conf/errors.xml'
SHA=lambda raw:hashlib.sha256(raw).hexdigest()


def remote_signature_errors(original):
    root=ET.fromstring(original)
    maps=[n for n in root if n.tag=='{'+U+'}map' and n.get('id')=='shibboleth.LocalEventMap']
    if len(maps)!=1:raise ValueError('Ambiguous native local error map')
    entries=[n for n in maps[0] if n.tag=='{'+B+'}entry' and n.get('key')=='MessageAuthenticationError']
    if len(entries)!=1 or entries[0].get('value')!='true':raise ValueError('Expected audited local signature error policy')
    maps[0].remove(entries[0])
    return ET.tostring(root,encoding='utf-8',xml_declaration=True)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();out=args.output.resolve();out.mkdir(parents=True,exist_ok=False)
    original=docker('cat',CONFIG);configured=remote_signature_errors(original)
    (out/'original-errors.xml').write_bytes(original);(out/'configured-errors.xml').write_bytes(configured)
    operations=[]
    def save():
        (out/'operations.json').write_text(json.dumps(operations,indent=2)+'\n')
    def write(raw,label):
        operation=dict(operation='write',label=label,sha256=SHA(raw),read_back=False);operations.append(operation);save()
        docker('sh','-c','cat > '+CONFIG,data=raw)
        if docker('cat',CONFIG)!=raw:raise RuntimeError('Native error configuration readback differs')
        operation['read_back']=True;save()
    def restart(label):
        operation=dict(operation='container-restart',label=label,completed=False);operations.append(operation);save()
        subprocess.run(['docker','restart','samlscope-reference-shibboleth'],check=True,stdout=subprocess.DEVNULL,timeout=60)
        docker('/usr/local/tomcat/bin/startup.sh')
        operations.append(dict(operation='tomcat-start',label=label));save()
        deadline=time.monotonic()+90
        while time.monotonic()<deadline:
            try:
                with urllib.request.urlopen('http://localhost:18280/idp/shibboleth',timeout=3) as response:
                    if response.status==200:operation['completed']=True;save();return
            except Exception:time.sleep(1)
        raise RuntimeError('Native IdP did not start')
    changed=False;failures=[]
    try:
        changed=True;write(configured,'remote-signature-errors');restart('remote-signature-errors')
        for profile in ['browser_sso_idp','metadata_idp']:
            if docker('cat',CONFIG)!=configured:raise RuntimeError('Concurrent native error policy change')
            child=subprocess.run(['python3',str(Path(__file__).with_name('import_metadata_batch.py')),
                '--output',str(out/profile),'--variants','control,ecdsa-sha256,ecdsa-sha256-invalid-signature',
                '--profile',profile,'--continue-inconclusive'],check=False,timeout=240,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
            (out/(profile+'-execution.log')).write_bytes(child.stdout)
            operations.append(dict(operation='signature-campaign',profile=profile,exit_code=child.returncode));save()
            if docker('cat',CONFIG)!=configured:raise RuntimeError('Native error policy changed during collection')
            print(profile,'completed with exit',child.returncode,flush=True)
            if child.returncode:raise RuntimeError('Nested signature campaign failed')
    finally:
        if changed:
            try:
                if docker('cat',CONFIG) not in (original,configured):raise RuntimeError('Concurrent configuration change')
                write(original,'restore-error-policy');restart('restore-error-policy')
            except Exception as error:failures.append(type(error).__name__)
        final=docker('cat',CONFIG)
        (out/'restoration.json').write_text(json.dumps(dict(restored=not failures and final==original,
            original_sha256=SHA(original),final_sha256=SHA(final),failures=failures),indent=2)+'\n')
        if failures:raise RuntimeError('Native error policy restoration incomplete')


if __name__=='__main__':main()
