#!/usr/bin/env python3
"""Export public native consent UI originals, not operator conclusions."""
import argparse,hashlib,json
from pathlib import Path
import xml.etree.ElementTree as ET
VARIANTS=['ui-safety-logo-data','ui-safety-information-javascript','ui-safety-privacy-javascript']
def sha(raw):return hashlib.sha256(raw).hexdigest()
def export(source,output):
    output.mkdir(parents=True,exist_ok=False);files={}
    def copy(path):
        name=path.replace('/','.');raw=(source/path).read_bytes();(output/name).write_bytes(raw);files[name]=sha(raw);return name
    read=lambda name:json.loads((source/name).read_bytes())
    entries=read('transcript.json');decoded={v['id']:ET.fromstring((source/v['file']).read_bytes()) for v in read('decoded-manifest.json')}
    run=read('created.json')['run']['id'];rows=[]
    for path in sorted(source.iterdir()):
        if path.is_file() and (path.name.startswith('native-') or path.name in ['created.json','campaign.json','target-metadata.xml','restoration.json','operations.json','operation-counts.json','identity-before.json','identity-after.json','collector.py','browser.mjs'] or path.name.endswith('-original.php') or path.name.endswith('-final.php')):copy(path.name)
    for variant in ['control']+VARIANTS:
        for path in sorted((source/variant).rglob('*')):
            if path.is_file():copy(str(path.relative_to(source)))
        prepared=[e for e in entries if e['samlSummary'].get('type')=='MetadataPrepared' and e['samlSummary'].get('variant')==variant];assert len(prepared)==1
        requests=[e for e in entries if e['samlSummary'].get('type')=='AuthnRequest' and e['samlSummary'].get('variant')==variant];assert len(requests)==2
        row=dict(variant=variant,metadataReference=prepared[0]['id'],fetchReference=prepared[0]['samlSummary']['fetchTranscriptId'])
        for request in requests:
            identity=decoded[request['id']].get('ID');slot='negative' if request['samlSummary'].get('metadataSignatureControl')=='invalid' else 'positive'
            responses=[e for e in entries if e['direction']=='INBOUND' and e['samlSummary'].get('type')=='Response' and decoded[e['id']].get('InResponseTo')==identity]
            assert len(responses)<=1;row[slot]=dict(requestReference=request['id'])
            if responses:row[slot]['responseReference']=responses[0]['id']
            for suffix in ['html','request.xml','request.body']:copy('native-http-originals/'+identity+'.'+suffix)
        rows.append(row)
    manifest=dict(schema='samlscope-simplesamlphp-consent-safety-v1',runId=run,campaignId='metadata-ui-safety',targetEntityId='http://localhost:18380/idp',targetMetadataSha256=sha((source/'target-metadata.xml').read_bytes()),files=files,conditions=rows)
    (output/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n');return manifest
if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('source',type=Path);p.add_argument('output',type=Path);a=p.parse_args();export(a.source,a.output)
