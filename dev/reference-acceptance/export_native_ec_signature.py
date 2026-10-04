#!/usr/bin/env python3
"""Export request-bound native audit records for the original EC signature evidence checker."""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'shibboleth'))
from signature_audit_format import signature_audit, FORMAT
SHA=lambda raw:hashlib.sha256(raw).hexdigest()


def export(folder, output):
    read=lambda path:json.loads(path.read_text())
    parent=folder.parent
    restored=read(parent/'restoration.json');native=read(folder/'restoration.json')
    original=(parent/'original-audit.xml').read_bytes();configured=(parent/'configured-audit.xml').read_bytes()
    assert signature_audit(original)==configured
    assert restored['restored'] and not restored['failures'] and restored['original_sha256']==restored['final_sha256']==SHA(original)
    assert native['restored'] and native['temporary_file_removed'] and native['original_sha256']==native['final_sha256']
    run=read(folder/'created.json')['run']['id']
    audit_path=folder/'native-signature-audit.json';audit=read(audit_path)
    assert audit['run']==run and audit['format']==FORMAT
    entries={e['id']:e for e in read(folder/'transcript.json')}
    originals={}
    for item in read(folder/'decoded-manifest.json'):
        path=(folder/item['file']).resolve()
        assert path.parent==(folder/'decoded').resolve()
        raw=path.read_bytes();assert SHA(raw)==item['sha256'] and item['id'] not in originals
        assert entries[item['id']]['runId']==run and len(raw)==entries[item['id']]['decodedSamlBytes']
        originals[item['id']]=raw
    exchanges=[]
    for variant in ['control','ecdsa-sha256','ecdsa-sha256-invalid-signature']:
        imported=read(folder/variant/'import.json')
        assert imported['variant']==variant and imported['run']==run and imported['import_path']=='native-filesystem-provider'
        assert imported['configuration_read_back'] and imported['provider_reloaded'] and imported['restored']
        fixture=(folder/variant/'fixture.xml').read_bytes();assert imported['fixture_sha256']==SHA(fixture)
        requests=[e for e in entries.values() if e['direction']=='OUTBOUND' and e['samlSummary'].get('type')=='AuthnRequest'
                  and e['samlSummary'].get('variant')==variant and e['samlSummary'].get('metadataSignatureControl','valid')=='valid']
        assert len(requests)==1
        sent=requests[0];request_id=sent['samlSummary']['id']
        prepared=[e for e in entries.values() if e['direction']=='OUTBOUND' and e['samlSummary'].get('type')=='MetadataPrepared'
                  and e['samlSummary'].get('variant')==variant and e['timestamp']<sent['timestamp'] and originals.get(e['id'])==fixture]
        assert prepared
        selected=max(prepared,key=lambda e:e['timestamp'])
        rows=[row for row in audit['rows'] if row['request_id']==request_id];assert len(rows)==1
        responses=[e for e in entries.values() if e['direction']=='INBOUND' and e['samlSummary'].get('type')=='Response'
                   and e['samlSummary'].get('inResponseTo')==request_id]
        if variant.endswith('invalid-signature'):
            assert not responses and rows[0]['event']=='MessageAuthenticationError' and not rows[0]['status']
        else:
            assert len(responses)==1 and rows[0]['status']=='Success' and not rows[0]['event']
        exchanges.append(dict(variant=variant,metadataReference=selected['id'],requestReference=sent['id'],
                              responseReference=responses[0]['id'] if responses else None,audit=rows[0]))
    receipt=dict(schema='samlscope-native-ec-signature-v1',runId=run,targetMetadataSha256=SHA((folder/'target-metadata.xml').read_bytes()),
        collectedAt=datetime.datetime.fromtimestamp(audit_path.stat().st_mtime,datetime.timezone.utc).isoformat(),
        nativeAuditSha256=SHA(audit_path.read_bytes()),nativeConfigurationSha256=SHA(configured),exchanges=exchanges,
        rawEvidence=[dict(reference=item['id'],sha256=item['sha256']) for item in read(folder/'decoded-manifest.json')])
    raw=(json.dumps(receipt,indent=2)+'\n').encode();output.parent.mkdir(parents=True,exist_ok=True)
    if output.exists():assert not output.is_symlink() and output.read_bytes()==raw
    else:
        with output.open('xb') as stream:stream.write(raw)
    return receipt


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--evidence',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();x=export(a.evidence.resolve(),a.output.resolve());print('Bound native signature controls',x['runId'])
