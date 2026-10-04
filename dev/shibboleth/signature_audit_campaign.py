#!/usr/bin/env python3
"""Collect request-bound native signature audit events without changing authentication or error policy."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time
import urllib.request
from attribute_name_capability import docker
from signature_audit_format import signature_audit, FORMAT

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'reference-acceptance'))

CONFIG='/opt/reference-idp/conf/audit.xml'
SHA=lambda raw:hashlib.sha256(raw).hexdigest()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--profiles',default='browser_sso_idp,metadata_idp')
    parser.add_argument('--scenario',choices=['ec-signature','signed-request','metadata-key-signature'],default='ec-signature')
    parser.add_argument('--variants',help='Select a native metadata-key group, retaining its baseline and paired controls')
    args=parser.parse_args();out=args.output.resolve();out.mkdir(parents=True,exist_ok=False)
    profiles=args.profiles.split(',')
    allowed={'browser_sso_idp','metadata_idp','ecp_idp','single_logout_idp'}
    if not profiles or len(set(profiles))!=len(profiles) or not set(profiles)<=allowed:raise ValueError('Unsupported or duplicated profiles')
    key_variants=None
    if args.scenario=='metadata-key-signature':
        from metadata_key_matrix import KEY_CAMPAIGN
        key_variants=list(KEY_CAMPAIGN)
        if args.variants:
            key_variants=args.variants.split(',')
            if not key_variants or key_variants[0]!='control' or len(set(key_variants))!=len(key_variants) or not set(key_variants)<=set(KEY_CAMPAIGN):
                raise ValueError('Selected native keys must be unique, allowed, and begin with control')
        (out/'matrix.json').write_text(json.dumps(dict(matrix='keys',variants=key_variants,verdict_adopted=False),indent=2)+'\n')
    elif args.variants:raise ValueError('Variant selection requires a metadata-key signature campaign')
    original=docker('cat',CONFIG);configured=signature_audit(original)
    (out/'original-audit.xml').write_bytes(original);(out/'configured-audit.xml').write_bytes(configured)
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
        changed=True;write(configured,'request-bound-audit');restart('request-bound-audit')
        for profile in profiles:
            if docker('cat',CONFIG)!=configured:raise RuntimeError('Concurrent native error policy change')
            if args.scenario=='ec-signature':
                command=['python3',str(Path(__file__).with_name('import_metadata_batch.py')),
                    '--output',str(out/profile),'--variants','control,ecdsa-sha256,ecdsa-sha256-invalid-signature',
                    '--profile',profile,'--continue-inconclusive']
            elif args.scenario=='metadata-key-signature':
                command=['python3',str(Path(__file__).with_name('import_metadata_batch.py')),
                    '--output',str(out/profile),'--variants',','.join(key_variants),
                    '--profile',profile,'--continue-inconclusive']
            else:
                command=['python3',str(Path(__file__).with_name('signed_request_batch.py')),
                    '--output',str(out/profile),'--profile',profile]
            child=subprocess.run(command,check=False,timeout=900,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
            (out/(profile+'-execution.log')).write_bytes(child.stdout)
            operations.append(dict(operation='signature-campaign',profile=profile,exit_code=child.returncode));save()
            if docker('cat',CONFIG)!=configured:raise RuntimeError('Native error policy changed during collection')
            # Keep only allowlisted fields for request IDs issued by this Run, never entire identity/session logs.
            entries=json.loads((out/profile/'transcript.json').read_text())
            request_ids={e['samlSummary'].get('id') or ('_'+str(e['samlSummary'].get('action_id'))) for e in entries if e['direction']=='OUTBOUND' and e['samlSummary'].get('type')=='AuthnRequest'}
            raw=docker('cat','/opt/reference-idp/logs/idp-audit.log').decode()
            rows=[]
            for line in raw.splitlines():
                if 'SAMLscope-signature-v1|' not in line:continue
                fields=line.split('SAMLscope-signature-v1|',1)[1].split('|')
                if len(fields)!=8 or fields[0] not in request_ids:continue
                rows.append(dict(zip(['request_id','sp','event','status','signed_inbound','binding','profile','timestamp'],fields)))
            (out/profile/'native-signature-audit.json').write_text(json.dumps(dict(format=FORMAT,rows=rows,run=entries[0]['runId']),indent=2)+'\n')
            if args.scenario=='metadata-key-signature' and not child.returncode:
                from capture_run_originals import capture
                run_id=entries[0]['runId']
                if not (out/profile/'decoded-manifest.json').exists():
                    capture(out/profile,run_id,entries)
                (out/profile/'configuration.json').write_text(json.dumps(dict(signature_policy=True,verdict_adopted=False,
                    provider_original_sha256=SHA((out/profile/'original-providers.xml').read_bytes()),
                    provider_configured_sha256=SHA((out/profile/'configured-providers.xml').read_bytes())),indent=2)+'\n')
            print(profile,'completed with exit',child.returncode,flush=True)
            if child.returncode:raise RuntimeError('Nested signature campaign failed')
    finally:
        if changed:
            try:
                if docker('cat',CONFIG) not in (original,configured):raise RuntimeError('Concurrent configuration change')
                write(original,'restore-audit-format');restart('restore-audit-format')
            except Exception as error:failures.append(type(error).__name__)
        final=docker('cat',CONFIG)
        restored=not failures and final==original
        (out/'restoration.json').write_text(json.dumps(dict(restored=restored,
            original_sha256=SHA(original),final_sha256=SHA(final),failures=failures),indent=2)+'\n')
        (out/'operation-counts.json').write_text(json.dumps(dict(restored=restored,human_operations=0,
            product_restarts=sum(1 for op in operations if op['operation']=='container-restart'),
            configuration_write_attempts=sum(1 for op in operations if op['operation']=='write'),
            verdict_adopted=False),indent=2)+'\n')
        if failures:raise RuntimeError('Native error policy restoration incomplete')


if __name__=='__main__':main()
