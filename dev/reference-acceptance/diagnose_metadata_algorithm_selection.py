#!/usr/bin/env python3
"""Compare cryptographically verified signature algorithms with advertised lists; no Verdict mapping."""
import hashlib
import json
from pathlib import Path

TYPES={'SigningMethod':'signatureAlgorithm','DigestMethod':'digestAlgorithm'}

def diagnose(folder):
    folder=Path(folder)
    advertised=json.loads((folder/'algorithm-observations.json').read_text())
    verified=json.loads((folder/'verified-algorithm-signatures.json').read_text())
    assert advertised['run']==verified['run']
    variants={row['variant']:row for row in advertised['observations']}
    assert len(variants)==len(advertised['observations'])
    findings=[]
    for proof in verified['observations']:
        row=variants[proof['variant']]
        assert (row['request'],row['response'])==(proof['request'],proof['response'])
        assert proof['signed_response_verified']
        for kind,field in TYPES.items():
            role=row['advertised_sp'][kind];entity=row['advertised_entity'][kind]
            effective=role or entity
            actual=sorted({signature[field] for signature in proof['verified_signatures']})
            assert actual
            if not effective:state='no-advertisement-no-support-inference'
            elif any(value not in effective for value in actual):state='selected-outside-advertised-list'
            elif actual==[effective[0]]:state='first-advertised-selected'
            else:state='later-advertised-selected-policy-unverified'
            findings.append(dict(variant=proof['variant'],algorithm_type=kind,
                selected_level='role' if role else 'entity' if entity else 'absent',
                advertised_algorithms=effective,verified_algorithms=actual,observation=state,
                local_policy_verified=False,affects_verdict=False,
                request=proof['request'],response=proof['response']))
    output=dict(run=verified['run'],source_sha256={name:hashlib.sha256((folder/name).read_bytes()).hexdigest()
        for name in ['algorithm-observations.json','verified-algorithm-signatures.json']},findings=findings,
        limitation='Facts about algorithm selection only. Approved-case controls, metadata-consumption proof and applicable policy must be connected before assigning a conformance outcome.')
    (folder/'algorithm-selection-diagnosis.json').write_text(json.dumps(output,indent=2)+'\n')
    return findings

if __name__=='__main__':
    import sys,collections
    findings=diagnose(sys.argv[1]);print(dict(collections.Counter(f['observation'] for f in findings)))
