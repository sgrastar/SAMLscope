#!/usr/bin/env python3
"""Export originals for accepted native metadata whose KeyValue was lost at runtime."""
import argparse,base64,datetime,hashlib,json,shutil
from pathlib import Path
import xml.etree.ElementTree as ET

VARIANTS=['entity-root','keyvalue-only','certificate-runtime-same-key','certificate-runtime-other-key']
SHA=lambda raw:hashlib.sha256(raw).hexdigest()
def export(source,output):
    source=source.resolve();output.mkdir(parents=True,exist_ok=False)
    read=lambda name:json.loads((source/name).read_bytes())
    run=read('created.json')['run']['id'];plan=read('created.json')['run']['planId'];entity='http://localhost:18080/p/'+plan
    entries=read('transcript.json');rawrefs=[];xml={}
    for row in read('decoded-manifest.json'):
        raw=(source/row['file']).read_bytes();assert SHA(raw)==row['sha256']
        xml[row['id']]=ET.fromstring(raw);rawrefs.append(dict(reference=row['id'],sha256=SHA(raw)))
    http=read('native-http-observations.json');assert http['runId']==run and http['productVerdictAssigned'] is False
    restore=read('restoration.json');assert restore['restored'] and restore['original_sha256']==restore['final_sha256']
    files={}
    def copy(name,alias=None):
        raw=(source/name).read_bytes();alias=alias or name
        assert '/' not in alias and alias not in files
        (output/alias).write_bytes(raw);files[alias]=SHA(raw)
    for name in ['created.json','campaign.json','target-metadata.xml','restoration.json','original-sp-config.php','final-sp-config.php',
        'operations.json','operation-counts.json','native-http-observations.json','native-parser-command.php','native-readback-command.php',
        'native-parser.php','native-message.php','native-configuration.php','native-idp-saml2.php','native-web-browser-sso.php',
        'native-collector.py','native-signature-client.py','native-reference-flow.py','native-inspect-before.json','native-inspect-after.json']:
        copy(name)
    rows=[]
    for variant in VARIANTS:
        for name in ['fixture.xml','parser.stdout','parser.stderr','flow.json']:
            copy(variant+'/'+name,variant+'.'+name)
        for phase in ['before','after']:
            for name in ['configuration.php','native.json','observed.json']:
                copy(variant+'/'+phase+'/'+name,variant+'.'+phase+'.'+name)
        raw=(source/variant/'fixture.xml').read_bytes();parsed=read(variant+'/parser.stdout')
        prepared=[e for e in entries if e['samlSummary'].get('type')=='MetadataPrepared' and e['samlSummary'].get('variant')==variant]
        assert len(prepared)==1;prepared=prepared[0]
        assert xml[prepared['id']].get('entityID')==entity
        before=read(variant+'/before/native.json')
        row=dict(variant=variant,metadataReference=prepared['id'],nativeImport=dict(source='native-parser-cli',
            fixtureSha256=SHA(raw),entityId=entity,readbackVerified=True,signaturePolicy=True,
            configurationSha256=before['remoteSha256'],parserOutputBase64=base64.b64encode((source/variant/'parser.stdout').read_bytes()).decode(),
            parserOutputSha256=SHA((source/variant/'parser.stdout').read_bytes())))
        requests=[e for e in entries if e['samlSummary'].get('type')=='AuthnRequest' and e['samlSummary'].get('variant')==variant]
        assert len(requests)==2
        for request in requests:
            identity=xml[request['id']].get('ID');slot='negative' if request['samlSummary'].get('metadataSignatureControl')=='invalid' else 'positive'
            records=[r for r in http['records'] if r['request_id']==identity];assert len(records)==1
            responses=[e for e in entries if e['direction']=='INBOUND' and e['samlSummary'].get('type')=='Response' and xml[e['id']].get('InResponseTo')==identity]
            assert len(responses)<=1
            row[slot]=dict(requestReference=request['id'],nativeHttp=records[0])
            if responses:row[slot]['responseReference']=responses[0]['id']
            for suffix in ['html','request.xml','request.body']:copy('native-http-originals/'+identity+'.'+suffix,identity+'.'+suffix)
        rows.append(row)
    collected=datetime.datetime.fromtimestamp((source/'restoration.json').stat().st_mtime,datetime.timezone.utc).isoformat()
    receipt=dict(schema='samlscope-native-key-selection-receipt-v1',runId=run,
        targetMetadataSha256=SHA((source/'target-metadata.xml').read_bytes()),restored=True,evidenceAdapter='simplesamlphp-native-http',
        collectedAt=collected,configurationOriginalSha256=restore['original_sha256'],configurationFinalSha256=restore['final_sha256'],
        rawEvidence=rawrefs,conditions=rows,conditionIssues=[])
    raw=(json.dumps(receipt,indent=2)+'\n').encode();(output/(run+'.json')).write_bytes(raw);files[run+'.json']=SHA(raw)
    manifest=dict(schema='samlscope-simplesamlphp-keyvalue-runtime-v1',runId=run,campaignId='metadata-fixture-refresh',
        targetEntityId='http://localhost:18380/idp',spEntityId=entity,targetMetadataSha256=receipt['targetMetadataSha256'],files=files)
    (output/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    return manifest
if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--evidence',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();export(a.evidence,a.output);print('Native KeyValue originals exported; no verdict adopted')
