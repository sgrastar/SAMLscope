#!/usr/bin/env python3
"""Bind native import fixtures to original metadata bytes prepared by the Suite, without asserting delivery."""
import hashlib
import json
from pathlib import Path
from native_algorithm_preparation import verify as verify_preparation

def load(folder,name):return json.loads((folder/name).read_text())
def verify(folder):
    folder=Path(folder);result=load(folder,'result.json');run=result['run']['id']
    entries={e['id']:e for e in load(folder,'transcript.json')}
    manifest={e['id']:e for e in load(folder,'decoded-manifest.json')}
    operations=load(folder,'operations.json')
    receipts=[]
    for imported in operations:
        variant=imported['variant'];fixture=(folder/variant/'fixture.xml').read_bytes()
        digest=hashlib.sha256(fixture).hexdigest()
        assert imported['fixture_sha256']==digest==verify_preparation(folder,variant)
        matches=[]
        for entry in entries.values():
            summary=entry['samlSummary']
            if summary.get('type')!='MetadataPrepared' or summary.get('variant')!=variant:continue
            assert entry['runId']==run and entry['direction']=='OUTBOUND' and entry['status']==200
            assert summary['delivery']=='PREPARED' and summary['sourceType']=='MetadataFetch'
            fetch=entries[summary['fetchTranscriptId']]
            assert fetch['runId']==run and fetch['direction']=='INBOUND' and fetch['samlSummary']['type']=='MetadataFetch'
            assert fetch['samlSummary']['variant']==variant and fetch['status']==200
            assert entry['correlationId']==fetch['id'] and entry['url']==fetch['url']
            assert entry['timestamp']>=fetch['timestamp']
            original=manifest[entry['id']];raw=(folder/original['file']).read_bytes()
            assert hashlib.sha256(raw).hexdigest()==original['sha256']==summary['metadataSha256']
            if raw==fixture:matches.append(entry['id'])
        assert matches,variant+': original prepared metadata not found'
        receipts.append(dict(variant=variant,metadata_sha256=digest,prepared_entries=matches,
            product_configuration_read_back=True,restored=True,delivery_status='PREPARED',affects_verdict=False))
    assert len({r['variant'] for r in receipts})==len(operations)
    output=dict(run=run,receipts=receipts,scope='Byte identity between Suite prepared response and native import input; target consumption still requires correlated protocol evidence')
    (folder/'prepared-metadata-verification.json').write_text(json.dumps(output,indent=2)+'\n')
    return receipts

if __name__=='__main__':
    import sys
    print('Verified prepared metadata originals:',len(verify(sys.argv[1])))
