import hashlib,json,xml.etree.ElementTree as ET
from pathlib import Path
sha=lambda b:hashlib.sha256(b).hexdigest()
def export(source,destination):
 source=Path(source);destination=Path(destination);destination.mkdir(exist_ok=False,parents=True);files={}
 for p in source.iterdir():
  if p.is_file() and (p.name.startswith(('native-','helper-')) or p.name in ['collector.py','created.json','plan.json','target-metadata.xml','restoration.json','identity-before.json','identity-after.json','operation-counts.json','fresh-passive-client.json','producer.json','read-only-producer-completion.json','wrong-principal.xml','error-with-assertion.xml','steps.json'] or p.name.endswith(('-original.php','-final.php'))):
   (destination/p.name).write_bytes(p.read_bytes());files[p.name]=sha(p.read_bytes())
 for label in ['control','baseline','control-before','control-after','passive-before','passive-after','native-http-originals']:
  for p in (source/label).iterdir():
   if p.is_file():name=label+'.'+p.name;(destination/name).write_bytes(p.read_bytes());files[name]=sha(p.read_bytes())
 flow=json.loads((source/'control/flow.json').read_bytes());positive=flow['positive_exchange']['transcript_ids'];negative=flow['negative_control']['exchange']['transcript_ids'];entries=json.loads((source/'transcript.json').read_bytes());decoded={r['id']:(source/r['file']).read_bytes() for r in json.loads((source/'decoded-manifest.json').read_bytes())};requests=[e for e in entries if e['direction']=='OUTBOUND' and e['samlSummary'].get('fixture_id')=='force-authn-passive'];assert len(requests)==1;rid=ET.fromstring(decoded[requests[0]['id']]).get('ID');responses=[e for e in entries if e['direction']=='INBOUND' and e['id'] in decoded and ET.fromstring(decoded[e['id']]).get('InResponseTo')==rid];assert len(responses)==1
 manifest={'schema':'samlscope-simplesamlphp-authentication-identity-v1','runId':json.loads((source/'created.json').read_bytes())['run']['id'],'caseId':'IIP-SSO01-ae-idp-01','campaignId':'native-authentication-identity','targetEntityId':'http://localhost:18380/idp','targetMetadataSha256':sha((source/'target-metadata.xml').read_bytes()),'files':files,'positiveRequestReference':positive[0],'positiveResponseReference':positive[1],'negativeRequestReference':negative[0],'errorRequestReference':requests[0]['id'],'errorResponseReference':responses[0]['id']};(destination/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n');return manifest
if __name__=='__main__':
 import argparse;p=argparse.ArgumentParser();p.add_argument('source',type=Path);p.add_argument('destination',type=Path);a=p.parse_args();export(a.source,a.destination)
