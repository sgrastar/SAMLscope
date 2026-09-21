#!/usr/bin/env python3
"""Bind a native signature matrix to immutable outbox originals and restored native configuration."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import datetime
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'shibboleth'))
from signature_audit_format import signature_audit, FORMAT

CASES={'IIP-ALG01-a-idp-01','IIP-ALG02-a-idp-01'}
SHA=lambda raw:hashlib.sha256(raw).hexdigest()


def collect(folder):
    run=json.loads((folder/'created.json').read_text())['run']['id']
    assert re.fullmatch(r'run_[0-9A-HJKMNP-TV-Z]{26}',run)
    manifest=[]
    for entry in json.loads((folder/'transcript.json').read_text()):
        ref=entry.get('decodedSamlRef')
        if not ref:continue
        assert entry['runId']==run and re.fullmatch(r'tx_[0-9A-HJKMNP-TV-Z]{26}',entry['id'])
        assert not Path(ref).is_absolute() and '..' not in Path(ref).parts
        path=folder/'decoded'/(entry['id']+'.xml');path.parent.mkdir(exist_ok=True)
        raw=subprocess.check_output(['docker','exec','samlscope-reference-suite','cat','/data/'+ref])
        assert len(raw)==entry['decodedSamlBytes']
        if path.exists():assert path.read_bytes()==raw
        else:path.write_bytes(raw)
        manifest.append(dict(id=entry['id'],file=str(path.relative_to(folder)),sha256=SHA(raw)))
    raw=(json.dumps(manifest,indent=2)+'\n').encode();path=folder/'decoded-manifest.json'
    if path.exists():assert path.read_bytes()==raw
    else:path.write_bytes(raw)
    raw=subprocess.check_output(['docker','exec','samlscope-reference-suite','cat','/data/target-metadata/'+run+'.xml'])
    path=folder/'target-metadata.xml'
    if path.exists():assert path.read_bytes()==raw
    else:path.write_bytes(raw)


def export(folder,output,case_id):
    assert case_id in CASES
    read=lambda name:json.loads((folder/name).read_text())
    run=read('created.json')['run']['id'];parent=folder.parent
    original=(parent/'original-audit.xml').read_bytes();configured=(parent/'configured-audit.xml').read_bytes()
    assert signature_audit(original)==configured
    restore=json.loads((parent/'restoration.json').read_text())
    assert restore['restored'] and not restore['failures'] and restore['original_sha256']==restore['final_sha256']==SHA(original)
    restore=read('restoration.json')
    assert restore['restored'] and not restore['failures'] and restore['temporary_file_removed']
    assert restore['original_sha256']==restore['final_sha256']==SHA((folder/'original-providers.xml').read_bytes())
    writes=[r for r in read('operations.json') if r['operation']=='write']
    assert len(writes)==3 and all(r['read_back'] for r in writes)
    assert next(r for r in writes if r['label']=='native-metadata')['sha256']==SHA((folder/'fixture.xml').read_bytes())
    assert read('baseline.json')['receipt']=='recorded'
    audits=read('native-signature-audit.json');assert audits['run']==run and audits['format']==FORMAT
    entries={e['id']:e for e in read('transcript.json')}
    for m in read('decoded-manifest.json'):
        path=(folder/m['file']).resolve();assert path.parent==(folder/'decoded').resolve()
        assert SHA(path.read_bytes())==m['sha256'] and len(path.read_bytes())==entries[m['id']]['decodedSamlBytes']
    exchanges=[]
    for fixture in ['VALID','TAMPERED_ACS','BAD_REFERENCE','BAD_SIGNATURE_VALUE']:
        sent=[e for e in entries.values() if e['direction']=='OUTBOUND' and e['samlSummary'].get('scenario_case_id')==case_id
              and e['samlSummary'].get('fixture_id')==fixture.lower().replace('_','-')]
        assert len(sent)==1;sent=sent[0];request_id='_'+sent['samlSummary']['action_id']
        rows=[r for r in audits['rows'] if r['request_id']==request_id];assert len(rows)==1
        received=[e for e in entries.values() if e['direction']=='INBOUND' and e['samlSummary'].get('inResponseTo')==request_id]
        if fixture=='VALID':assert len(received)==1 and rows[0]['status']=='Success' and not rows[0]['event']
        else:assert not received and rows[0]['event']=='MessageAuthenticationError' and not rows[0]['status']
        exchanges.append(dict(fixture=fixture,requestReference=sent['id'],responseReference=received[0]['id'] if received else None,audit=rows[0]))
    receipt=dict(schema='samlscope-native-signed-request-v1',runId=run,caseId=case_id,
        targetMetadataSha256=SHA((folder/'target-metadata.xml').read_bytes()),
        nativeAuditSha256=SHA((folder/'native-signature-audit.json').read_bytes()),nativeConfigurationSha256=SHA(configured),
        collectedAt=datetime.datetime.fromtimestamp((folder/'native-signature-audit.json').stat().st_mtime,datetime.timezone.utc).isoformat(),
        exchanges=exchanges,rawEvidence=[dict(reference=m['id'],sha256=m['sha256']) for m in read('decoded-manifest.json')])
    raw=(json.dumps(receipt,indent=2)+'\n').encode();output.parent.mkdir(parents=True,exist_ok=True)
    if output.exists():assert not output.is_symlink() and output.read_bytes()==raw
    else:
        with output.open('xb') as stream:stream.write(raw)
    return receipt


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--evidence',type=Path,required=True)
    parser.add_argument('--collect-originals',action='store_true');args=parser.parse_args();folder=args.evidence.resolve()
    if args.collect_originals:collect(folder)
    run=json.loads((folder/'created.json').read_text())['run']['id']
    for case in sorted(CASES):export(folder,folder/'preparation-receipts'/(run+'-'+case+'.json'),case)
    print('Native signed-request matrices bound',run)
