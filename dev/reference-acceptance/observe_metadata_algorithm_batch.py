#!/usr/bin/env python3
"""Export original protocol XML and diagnose metadata algorithm selection, without changing Verdicts."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import xml.etree.ElementTree as ET
from native_algorithm_preparation import verify as verify_preparation

MD='urn:oasis:names:tc:SAML:2.0:metadata'
ALG='urn:oasis:names:tc:SAML:metadata:algsupport'
DS='http://www.w3.org/2000/09/xmldsig#'
PROTOCOL='urn:oasis:names:tc:SAML:2.0:protocol'
ASSERTION='urn:oasis:names:tc:SAML:2.0:assertion'

def digest(raw):return hashlib.sha256(raw).hexdigest()
def read(path):return json.loads(path.read_text())
def save(path,value):path.write_text(json.dumps(value,indent=2,ensure_ascii=False)+'\n')
def advertised(parent):
    if parent is None:return {}
    ext=parent.find('{'+MD+'}Extensions')
    return {kind:[] if ext is None else [m.get('Algorithm') for m in ext.findall('{'+ALG+'}'+kind)]
        for kind in ['SigningMethod','DigestMethod']}

def observe(folder):
    result=read(folder/'result.json');run=result['run']['id']
    entries=read(folder/'transcript.json');originals={};manifest=[]
    for entry in entries:
        assert entry['runId']==run
        ref=entry.get('decodedSamlRef')
        if not ref:continue
        relative=Path('decoded')/(entry['id']+'.xml');path=folder/relative;path.parent.mkdir(exist_ok=True)
        if not path.exists():subprocess.run(['docker','cp','samlscope-reference-suite:/data/'+ref,str(path)],check=True,stdout=subprocess.DEVNULL)
        raw=path.read_bytes();originals[entry['id']]=ET.fromstring(raw)
        manifest.append(dict(id=entry['id'],file=str(relative),sha256=digest(raw)))
    save(folder/'decoded-manifest.json',manifest)
    requests={}
    for entry in entries:
        xml=originals.get(entry['id']);summary=entry.get('samlSummary',{})
        if xml is None or entry['direction']!='OUTBOUND' or xml.tag!='{'+PROTOCOL+'}AuthnRequest':continue
        if summary.get('metadataSignatureControl')=='invalid':continue
        request_id=xml.get('ID');assert request_id not in requests
        requests[request_id]=entry
    observations=[]
    for entry in entries:
        xml=originals.get(entry['id'])
        if xml is None or entry['direction']!='INBOUND' or xml.tag!='{'+PROTOCOL+'}Response':continue
        request=requests.get(xml.get('InResponseTo'))
        if request is None:continue
        variant=request['samlSummary'].get('variant')
        if not variant or (variant!='control' and not variant.startswith('algorithm-')):continue
        expected_digest=verify_preparation(folder,variant)
        fixture_raw=(folder/variant/'fixture.xml').read_bytes();assert digest(fixture_raw)==expected_digest
        fixture=ET.fromstring(fixture_raw)
        signatures=[]
        for parent in [xml,*xml.findall('{'+ASSERTION+'}Assertion')]:
            for signed in parent.findall('{'+DS+'}Signature/{'+DS+'}SignedInfo'):
                method=signed.find('{'+DS+'}SignatureMethod')
                signatures.append(dict(signed_element=parent.tag,signature_method=None if method is None else method.get('Algorithm'),
                    digest_methods=[d.get('Algorithm') for d in signed.findall('{'+DS+'}Reference/{'+DS+'}DigestMethod')]))
        status=xml.find('{'+PROTOCOL+'}Status/{'+PROTOCOL+'}StatusCode')
        observations.append(dict(variant=variant,request=request['id'],response=entry['id'],
            response_status=None if status is None else status.get('Value'),
            advertised_entity=advertised(fixture),advertised_sp=advertised(fixture.find('{'+MD+'}SPSSODescriptor')),
            observed_signed_info=signatures,signature_verified=False,affects_verdict=False))
    save(folder/'algorithm-observations.json',dict(run=run,observations=observations,
        limitation='Selection diagnostics only. Target signature verification, complete controls and local policy evidence remain required.'))
    return observations

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('folder',type=Path);args=parser.parse_args()
    for observation in observe(args.folder):
        print(observation['variant'],observation['response_status'],observation['observed_signed_info'])
