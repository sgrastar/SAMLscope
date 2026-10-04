#!/usr/bin/env python3
"""Adopt complete native key-policy controls, rerunning the pinned production Reader."""
import argparse
import hashlib
import json
import re
from pathlib import Path
import subprocess
import tempfile
import zipfile

from export_metadata_key_receipt import export

REPO=Path(__file__).resolve().parents[2]
FOLDER='keycloak-native-key-policy-v165-r3/observations/metadata_idp'
SUITE='samlscope-reference-suite'
HELPER=REPO/'dev/reference-acceptance/VerifyKeycloakNativeKeyPolicyEvidence.java'
CLASSES=tuple('com/samlscope/runner/cases/'+name+'.class' for name in (
    'MetadataKeySelectionEvidenceFile','MetadataKeySelectionComparison',
    'MetadataKeySelectionConfigurationTestCase','MetadataRoleSigningTransportEvidence'))
EXPECTED={
    'IIP-MD05-ad-idp-01':('VIOLATED','WARNING','metadata.keys.selection-violated'),
    'IIP-MD05-cd-idp-01':('VIOLATED','FAIL','metadata.keys.selection-violated'),
    'IIP-MD06-a5-idp-01':('VIOLATED','FAIL','metadata.keys.selection-violated'),
    'IIP-MD06-a7-idp-01':('VIOLATED','FAIL','metadata.keys.selection-violated'),
    'IIP-MD06-a3-idp-01':('SATISFIED_WITH_NOTE','WARNING','metadata.role-signing.http-transport-observed'),
}
SHA=lambda raw:hashlib.sha256(raw).hexdigest()
read=lambda path:json.loads(Path(path).read_bytes())

def require(value,reason):
    if not value:raise ValueError(reason)

def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':')).encode()

def archive_runtime(folder):
    runtime=folder/'runtime';runtime.mkdir(exist_ok=True)
    jar=runtime/'runner.jar'
    require(not jar.exists(),'Pinned runtime already exists')
    subprocess.run(['docker','cp',SUITE+':/opt/samlscope/lib/runner-0.1.0.jar',str(jar)],check=True,capture_output=True)
    with zipfile.ZipFile(jar) as source:classes={name:SHA(source.read(name)) for name in CLASSES}
    (runtime/HELPER.name).write_bytes(HELPER.read_bytes())
    pins=dict(runnerSha256=SHA(jar.read_bytes()),classes=classes,helperSha256=SHA(HELPER.read_bytes()),
        nativeShowConfigSha256=SHA((folder/"native-show-config-redacted.txt").read_bytes()),
        nativeRuntimeSha256=SHA((folder/"native-http-runtime.json").read_bytes()))
    (runtime/'pins.json').write_text(json.dumps(pins,indent=2)+'\n')
    return pins

def replay(folder):
    jar=folder/'runtime/runner.jar';pins=read(folder/'runtime/pins.json')
    helper=folder/'runtime'/HELPER.name
    require(SHA(jar.read_bytes())==pins['runnerSha256'] and SHA(helper.read_bytes())==pins['helperSha256'],
        'Pinned Runner/helper bytes differ')
    with zipfile.ZipFile(jar) as archive:
        require(all(SHA(archive.read(name))==pins['classes'][name] for name in CLASSES),'Pinned Reader classes differ')
    dependencies=Path('/private/tmp/samlscope-runner-runtime-classpath.txt')
    require(dependencies.is_file(),'Runtime dependency classpath is unavailable')
    # The archived production Runner is FIRST; current workspace Runner classes cannot shadow it.
    cp=str(jar)+':'+dependencies.read_text().strip()
    with tempfile.TemporaryDirectory(prefix='samlscope-kc-native-key-replay-') as temp:
        compile_result=subprocess.run(['javac','-cp',cp,'-d',temp,str(helper)],capture_output=True,text=True)
        require(compile_result.returncode==0,'Production replay helper compilation failed: '+compile_result.stderr[-1000:])
        out=Path(temp)/'replay.json'
        result=subprocess.run(['java','-cp',str(jar)+':'+temp+':'+dependencies.read_text().strip(),
            'com.samlscope.runner.cases.VerifyKeycloakNativeKeyPolicyEvidence',str(folder),str(out)],
            capture_output=True,text=True,timeout=90)
        require(result.returncode==0,'Production Reader replay failed: '+result.stderr[-1000:])
        return read(out)

def operation_counts(folder):
    attempts=[]
    for name in ['keycloak-native-key-policy-v165','keycloak-native-key-policy-v165-r2','keycloak-native-key-policy-v165-r3']:
        campaign=folder.parents[2]/name
        require(campaign.exists(),'A campaign attempt record is missing')
        operations=read(campaign/'operations.json');batch=read(campaign/'observations/operations.json')
        restoration=read(campaign/'observer/restoration.json')
        require(all(restoration.get(k) for k in ('provider_removed','realm_configuration_restored','product_restart_verified'))
            and not restoration['failures'],'Campaign attempt restoration incomplete')
        rows=[]
        for path in (campaign/'observations/metadata_idp').glob('*/import.json'):rows.append(read(path))
        baseline_path=campaign/'observations/metadata_idp/baseline/operations.json'
        baseline=read(baseline_path) if baseline_path.exists() else dict(admin_operations=[])
        attempts.append(dict(campaign=name,product_restarts=sum(o.get('operation')=='product-restart' for o in operations),
            provider_write_attempts=sum(o.get('operation') in {'provider-install','provider-remove'} for o in operations),
            event_configuration_write_attempts=sum(o['method']=='PUT' for o in batch['admin_operations']),
            import_attempts=len(rows),import_save_attempts=sum(r.get('import',{}).get('save_clicked',False) for r in rows),
            signature_policy_write_attempts=sum(r.get('import',{}).get('request_signature_policy',{}).get('write_attempts',0) for r in rows),
            imported_client_deletes=sum(r.get('cleanup',{}).get('deleted_status')==204 for r in rows),
            baseline_client_mutations=sum(o['method'] in {'POST','DELETE'} for o in baseline['admin_operations']),
            human_operations=0,restored=True))
    return dict(attempts=attempts,totals={key:sum(a[key] for a in attempts) for key in attempts[0] if key not in {'campaign','restored'}},
        http_native_original_recorder_posts=read(folder/"role-signing-transport-capture.json")["recorder_original_posts"],restored=True,verdict_adopted=False)

def verify(folder,formal=True,live=True):
    folder=Path(folder).resolve();receipt=read(folder/'qualified-metadata-key-receipt.json')
    require(export(folder)==receipt,'Receipt differs from native/original regeneration')
    run=receipt['runId'];entries=read(folder/'transcript.json')
    require(len({e['id'] for e in entries})==len(entries) and all(e['runId']==run for e in entries),'Mixed transcript')
    for item in read(folder/'decoded-manifest.json'):
        path=folder/item['file']
        require(not path.is_symlink() and path.resolve().parent==(folder/'decoded').resolve()
            and SHA(path.read_bytes())==item['sha256'],'Original bytes/hash/path differ')
    pins=read(folder/'runtime/pins.json')
    require(SHA((folder/'native-show-config-redacted.txt').read_bytes())==pins['nativeShowConfigSha256']
        and SHA((folder/'native-http-runtime.json').read_bytes())==pins['nativeRuntimeSha256'],
        'Pinned full native source export changed')
    transport=read(folder/'role-signing-transport-original.json')
    require(transport['nativeConfiguration']['originalText']==(folder/'native-show-config-redacted.txt').read_text()
        and transport['nativeConfiguration']['originalTextSha256']==SHA((folder/'native-show-config-redacted.txt').read_bytes())
        and receipt['roleSigningTransport']['configurationTextSha256']==SHA((folder/'native-show-config-redacted.txt').read_bytes())
        and transport['runtime']==read(folder/'native-http-runtime.json'),'Full native source export differs')
    native_rows=[m for m in read(folder/'decoded-manifest.json') if m['id']==receipt['roleSigningTransport']['reference']]
    require(len(native_rows)==1 and (folder/native_rows[0]['file']).read_bytes()==(folder/'role-signing-transport-original.json').read_bytes(),
        'Native source export differs from Recorder original')
    counts=operation_counts(folder)
    require(read(folder/'campaign-operation-counts.json')==counts,'Operation ledger differs')
    imports={p.parent.name:read(p) for p in folder.glob('*/import.json')}
    for row in imports.values():
        policy=row['import']['request_signature_policy']
        require(policy['enabled_read_back'] is True and policy['key_material_modified'] is False
            and row['import']['read_back']['saml_attributes']['saml.client.signature']=='true'
            and row['import']['read_back']['saml_attributes']['saml.encrypt']=='false'
            and row['cleanup']['read_back_absent'] is True,'Native policy/key preservation or client restore differs')
        require(row['import']['read_back']['saml_attributes'].get('saml.signing.certificate')==policy['original_signing_certificate'],
            'Suite changed imported signing key material')
    fresh=replay(folder);saved=read(folder/'native-reader-replay.json')
    require(canonical(fresh)==canonical(saved),'Actual pinned production Reader replay differs')
    require(fresh['production_comparison']['IIP-MD07-b-idp-01']['outcome']=='NOT_VERIFIED',
        'MD07.b lost its first-key positive control')
    require(len(fresh['negative_controls'])==121 and set(fresh['negative_controls'].values())=={'NOT_VERIFIED'},
        'Native/transport evidence mutation controls differ')
    if live:
        output=subprocess.check_output(['docker','exec','samlscope-reference-keycloak','/opt/keycloak/bin/kc.sh','show-config'],text=True)
        safe=[]
        for line in output.splitlines():
            name=line.split('=',1)[0]
            if '=' in line and re.search(r'password|secret|token|credential|username',name,re.I):line=name.rstrip()+' = [REDACTED]'
            safe.append(line)
        require(sorted(safe)==sorted(transport['nativeConfiguration']['originalText'].splitlines()),
            'Live full native source export differs')
        info=json.loads(subprocess.check_output(['docker','inspect','samlscope-reference-keycloak']))[0]
        require(dict(image=info['Image'],command=info['Config']['Cmd'],portBindings=info['HostConfig']['PortBindings'])==transport['runtime'],
            'Live native runtime binding differs')
        with tempfile.TemporaryDirectory() as temp:
            current=Path(temp)/'runner.jar'
            subprocess.run(['docker','cp',SUITE+':/opt/samlscope/lib/runner-0.1.0.jar',str(current)],check=True,capture_output=True)
            require(SHA(current.read_bytes())==read(folder/'runtime/pins.json')['runnerSha256'],'Live production runtime differs')
        require(subprocess.check_output(['docker','exec',SUITE,'sha256sum',
            '/data/metadata-key-evidence/'+run+'.json']).decode().split()[0]==SHA((folder/'qualified-metadata-key-receipt.json').read_bytes()),
            'Installed receipt read-back differs')
    if not formal:return fresh
    evaluation=folder/'evaluation';result=read(evaluation/'result.json')
    require(result['run']['id']==run and result['target']['metadata_digest']=='sha256:'+receipt['targetMetadataSha256'],'Formal target/Run differs')
    installed=read(evaluation/'receipt-installation.json')
    require(installed['run']==run and installed['read_back'] is True
        and installed['sha256']==fresh['receipt_sha256'],'Formal receipt installation differs')
    saved_transcript={e['id']:e for e in entries}
    require(all({e['id']:e for e in read(evaluation/name)}==saved_transcript for name in ['transcript-before.json','transcript.json']),
        'Transcript changed during formal re-evaluation')
    cases={c['id']:c for r in result['requirements'] for c in r['cases']}
    selected={}
    for case,want in EXPECTED.items():
        row=cases[case];observed=fresh['production_comparison'][case]
        require((row['outcome'],row['verdict'],row['reason_code'])==want and row['attested'] is False,
            'Formal outcome/verdict differs: '+case)
        require((observed['outcome'],observed['reasonCode'])==(want[0],want[2]),'Pinned Reader outcome differs: '+case)
        require({(e['kind'],e['reference']) for e in row['evidence']}=={(e['kind'],e['reference']) for e in observed['evidence']},
            'Formal native evidence references differ: '+case)
        selected[case]=row
    return evaluation/'result.json',selected

def verify_adoption(root,live=False):return verify(Path(root)/FOLDER,live=live)

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--root',type=Path,required=True)
    parser.add_argument('--prepare-runtime',action='store_true');parser.add_argument('--offline',action='store_true')
    args=parser.parse_args();folder=args.root/FOLDER
    if args.prepare_runtime:
        archive_runtime(folder)
        (folder/'campaign-operation-counts.json').write_text(json.dumps(operation_counts(folder),indent=2)+'\n')
        (folder/'native-reader-replay.json').write_text(json.dumps(replay(folder),indent=2)+'\n')
    _,cases=verify_adoption(args.root,live=not args.offline)
    for case,row in cases.items():print(case,row['verdict'])
