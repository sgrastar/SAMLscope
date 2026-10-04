#!/usr/bin/env python3
"""Bind native generator-list transition to verified original exchanges; no verdict submission."""
import argparse
import hashlib
import json
from pathlib import Path
import sys
import xml.etree.ElementTree as ET
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'shibboleth'))
from nameid_omission_preparation import verify_transition


def digest(raw):return hashlib.sha256(raw).hexdigest()


def export(folder, output):
    def read(name):return json.loads((folder/name).read_text())
    run=read('created.json')['run']['id'];prepared=read('preparation.json');restored=read('restoration.json')
    transition=verify_transition((folder/'original-nameid.xml').read_bytes(),(folder/'disabled-nameid.xml').read_bytes())
    if transition!=read('native-transition.json'):raise ValueError('Native transition changed')
    if not restored['restored'] or restored['failures'] or not restored['temporary_removed'] \
            or restored['original_sha256']!=restored['final_sha256']:raise ValueError('Restoration unproven')
    if prepared['run']!=run or prepared['login_provenance']!='fixed-in-memory-driver-input':raise ValueError('Preparation scope unproven')
    if transition['original_sha256']!=restored['original_sha256']['saml-nameid'] \
            or prepared['native']['saml-nameid']!=transition['original_sha256']:raise ValueError('Native baseline mismatch')
    observations=read('observations.json');protocol=read('production-observation.json')
    if [row['condition'] for row in observations]!=['baseline','name-id-disabled']:raise ValueError('Incomplete native conditions')
    if protocol['run']!=run or protocol['issues'] or len(protocol['observations'])!=2:raise ValueError('Verified exchanges missing')
    if protocol['transcript_sha256']!=digest((folder/'transcript.json').read_bytes()) \
            or protocol['target_metadata_sha256']!=digest((folder/'target-metadata.xml').read_bytes()):raise ValueError('Original scope changed')
    entries={row['id']:row for row in read('transcript.json')};originals={}
    for row in read('decoded-manifest.json'):
        path=(folder/row['file']).resolve()
        if path.parent!=(folder/'decoded').resolve() or row['id'] in originals:raise ValueError('Invalid original path')
        raw=path.read_bytes()
        if digest(raw)!=row['sha256'] or len(raw)!=entries[row['id']]['decodedSamlBytes'] or entries[row['id']]['runId']!=run:
            raise ValueError('Original evidence changed')
        originals[row['id']]=raw
    exchanges=[];used=set();requests=set();metadata=set()
    for index,(observed,verified) in enumerate(zip(observations,protocol['observations'])):
        expected=dict(prepared['native'])
        if index:expected['saml-nameid']=transition['configured_sha256']
        if observed['before']!=expected or observed['after']!=expected \
                or observed['login_input_binding']!=prepared['login_input_binding']:raise ValueError('Native state or login input changed')
        condition=['BASELINE','NAME_ID_DISABLED'][index]
        if verified['condition']!=condition or verified['presence']!=['NAME_ID','OMITTED'][index] \
                or verified['entity_id']!=prepared['entity_id']:raise ValueError('Required behavior unobserved')
        refs=[ref['reference'] for ref in verified['evidence']]
        if len(refs)!=4 or set(refs[2:])!=set(observed['new_transcript_ids']) or used.intersection(refs[2:]):raise ValueError('Exchange binding differs')
        used.update(refs[2:]);requests.add(verified['request_fingerprint']);metadata.add(verified['metadata_sha256'])
        if originals[refs[1]]!=(folder/'fixture.xml').read_bytes():raise ValueError('Imported metadata differs')
        stable=digest(json.dumps(dict(metadata=digest((folder/'fixture.xml').read_bytes()),
            native_fixed={k:v for k,v in prepared['native'].items() if k!='saml-nameid'},
            native_transition=transition),sort_keys=True,separators=(',',':')).encode())
        exchanges.append(dict(condition=condition,metadataReference=refs[1],requestReference=refs[2],responseReference=refs[3],
            loginInputFingerprint=prepared['login_input_binding'],stableInputFingerprint=stable))
    if len(requests)!=1 or len(metadata)!=1:raise ValueError('Protocol comparison inputs changed')
    target=(folder/'target-metadata.xml').read_bytes()
    receipt=dict(schema='samlscope-native-nameid-omission-receipt-v1',runId=run,targetEntityId=ET.fromstring(target).get('entityID'),
        targetMetadataSha256=digest(target),preparation=dict(runId=run,experimentId='native-nameid-omission-'+run,exchanges=exchanges),
        rawEvidence=[dict(reference=row['id'],sha256=row['sha256']) for row in read('decoded-manifest.json')])
    raw=(json.dumps(receipt,indent=2)+'\n').encode();output.parent.mkdir(parents=True,exist_ok=True)
    if output.exists():
        if output.is_symlink() or output.read_bytes()!=raw:raise ValueError('Receipt is immutable')
    else:
        with output.open('xb') as stream:stream.write(raw)
    return receipt


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--evidence',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();receipt=export(args.evidence.resolve(),args.output.resolve());print('Native preparation bound:',receipt['runId'])
