"""Flatten full stock transient/persistence native originals without altering transcript bytes."""
import argparse,hashlib,json,xml.etree.ElementTree as ET
from pathlib import Path
CASE='IIP-SSO01-fp-idp-01';P='urn:oasis:names:tc:SAML:2.0:protocol'
KEYS=['transient-allow-create-'+v for v in ['true','false','omitted']]+['implicit-transient-allow-create-'+v for v in ['true','false','omitted']]
def sha(raw):return hashlib.sha256(raw).hexdigest()
def export(source,output):
 source=Path(source);output=Path(output);output.mkdir(parents=True,exist_ok=False);files={}
 for p in sorted(source.iterdir()):
  if p.is_file() and (p.name.startswith('native-') or p.name in ['collector.py','created.json','plan.json','campaign.json','target-metadata.xml','suite-sp-metadata.xml','restoration.json','operation-counts.json','parser.stdout','parser.stderr','identity-before.json','identity-after.json','steps.json'] or p.name.endswith('-original.php') or p.name.endswith('-final.php')):
   raw=p.read_bytes();(output/p.name).write_bytes(raw);files[p.name]=sha(raw)
 for name in ['control','control-before','control-after','before','after','native-http-originals']+['matrix-'+str(i)+'-'+phase for i in range(6) for phase in ['before','after']]:
  for p in sorted((source/name).rglob('*')):
   if p.is_file():
    target=str(p.relative_to(source)).replace('/','.');raw=p.read_bytes();(output/target).write_bytes(raw);files[target]=sha(raw)
 entries=json.loads((source/'transcript.json').read_bytes());prepared=[e for e in entries if e['samlSummary'].get('type')=='MetadataPrepared'];assert len(prepared)==1
 flow=json.loads((source/'control/flow.json').read_bytes());run=json.loads((source/'created.json').read_bytes())['run']['id'];decoded={row['id']:(source/row['file']).read_bytes() for row in json.loads((source/'decoded-manifest.json').read_bytes())}
 steps=[s for s in json.loads((source/'steps.json').read_bytes()) if s.get('caseId')==CASE and s.get('sentToTarget')];assert [s['key'] for s in steps]==KEYS
 http=json.loads((source/'native-http-observations.json').read_bytes())['records'];matrix=[]
 for step in steps:
  requests=[e for e in entries if e['direction']=='OUTBOUND' and e['samlSummary'].get('type')=='AuthnRequest' and e['samlSummary'].get('scenario_case_id')==CASE and e['id'] in decoded and ET.fromstring(decoded[e['id']]).get('ID')=='_'+step['actionId']];assert len(requests)==1
  ident=ET.fromstring(decoded[requests[0]['id']]).get('ID');responses=[e for e in entries if e['direction']=='INBOUND' and e['samlSummary'].get('type')=='Response' and e['id'] in decoded and ET.fromstring(decoded[e['id']]).get('InResponseTo')==ident];assert len(responses)==1 and responses[0]['id'] in step['transcriptIds']
  pairs=[row for row in http if row['request_id']==ident];assert len(pairs)==1
  matrix.append(dict(key=step['key'],requestReference=requests[0]['id'],responseReference=responses[0]['id'],dispatchStartedAt=pairs[0]['started_at'],dispatchCompletedAt=step['dispatchCompletedAt']))
 manifest=dict(schema='samlscope-simplesamlphp-transient-allow-create-v1',runId=run,campaignId='native-transient-allow-create',targetEntityId='http://localhost:18380/idp',targetMetadataSha256=sha((source/'target-metadata.xml').read_bytes()),files=files,matrix=matrix,
  metadataReference=prepared[0]['id'],fetchReference=prepared[0]['samlSummary']['fetchTranscriptId'],positiveRequestReference=flow['positive_exchange']['transcript_ids'][0],positiveResponseReference=flow['positive_exchange']['transcript_ids'][1],negativeRequestReference=flow['negative_control']['exchange']['transcript_ids'][0])
 (output/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n');return manifest
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('source',type=Path);p.add_argument('output',type=Path);a=p.parse_args();export(a.source,a.output)
