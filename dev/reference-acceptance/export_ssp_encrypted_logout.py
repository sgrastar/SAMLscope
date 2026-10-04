"""Native encrypted SLO originals; unresolved negative controls never synthesize PASS."""
import hashlib,json,xml.etree.ElementTree as ET
from pathlib import Path
sha=lambda raw:hashlib.sha256(raw).hexdigest()
P='urn:oasis:names:tc:SAML:2.0:protocol'
def export(source,destination):
 source=Path(source);destination=Path(destination);destination.mkdir(parents=True,exist_ok=False);files={}
 def copy(name,p):
  raw=p.read_bytes();(destination/name).write_bytes(raw);files[name]=sha(raw)
 for p in source.iterdir():
  if p.is_file() and (p.name.startswith('native-') or p.name in ['collector.py','created.json','plan.json','target-metadata.xml','restoration.json','identity-before.json','identity-after.json','operation-counts.json','steps.json','new-public-certificate.pem','supplemental-submit.json','pre-send-checks.json','ephemeral-key-cleanup.json'] or p.name.endswith('-original.php') or p.name.endswith('-final.php')):copy(p.name,p)
 for name in ['control','before','baseline','baseline-before','after','native-http-originals']+[p.name for p in source.iterdir() if p.is_dir() and p.name.startswith('stage-')]:
  for p in (source/name).iterdir():
   if p.is_file():copy(name+'.'+p.name,p)
 entries=json.loads((source/'transcript.json').read_bytes());decoded={r['id']:(source/r['file']).read_bytes() for r in json.loads((source/'decoded-manifest.json').read_bytes())};flow=json.loads((source/'control/flow.json').read_bytes());normal=flow['positive_exchange']['transcript_ids'];negative=flow['negative_control']['exchange']['transcript_ids'];assert len(normal)==2 and len(negative)==1
 matrix=[]
 for e in entries:
  if e['direction']!='OUTBOUND' or e['samlSummary'].get('type')!='LogoutRequest' or e['samlSummary'].get('scenario_case_id') not in ['IIP-IDP17-a-idp-01','IIP-IDP19-a-idp-01','IIP-IDP19-c-idp-01']:continue
  r=ET.fromstring(decoded[e['id']]);ident=r.get('ID');responses=[v for v in entries if v['direction']=='INBOUND' and v['samlSummary'].get('type')=='LogoutResponse' and ET.fromstring(decoded[v['id']]).get('InResponseTo')==ident];assert len(responses)==1
  # Exact scenario's preceding recorded AuthnResponse is the native session origin.
  logins=[v for v in entries if v['direction']=='OUTBOUND' and v['samlSummary'].get('type')=='AuthnRequest' and v['samlSummary'].get('scenario_case_id')==e['samlSummary']['scenario_case_id'] and v['timestamp']<e['timestamp']];assert logins
  login=max(logins,key=lambda v:v['timestamp']);loginId=ET.fromstring(decoded[login['id']]).get('ID');loginReplies=[v for v in entries if v['direction']=='INBOUND' and v['samlSummary'].get('type')=='Response' and ET.fromstring(decoded[v['id']]).get('InResponseTo')==loginId];assert len(loginReplies)==1
  matrix.append(dict(caseId=e['samlSummary']['scenario_case_id'],fixtureId=e['samlSummary']['fixture_id'],requestReference=e['id'],responseReference=responses[0]['id'],loginRequestReference=login['id'],loginResponseReference=loginReplies[0]['id']))
 manifest=dict(schema='samlscope-simplesamlphp-encrypted-logout-v1',runId=json.loads((source/'created.json').read_bytes())['run']['id'],campaignId='native-encrypted-logout',targetEntityId='http://localhost:18380/idp',targetMetadataSha256=sha((source/'target-metadata.xml').read_bytes()),positiveRequestReference=normal[0],positiveResponseReference=normal[1],negativeRequestReference=negative[0],files=files,matrix=matrix)
 (destination/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n');return manifest
if __name__=='__main__':
 import argparse;p=argparse.ArgumentParser();p.add_argument('source',type=Path);p.add_argument('destination',type=Path);a=p.parse_args();export(a.source,a.destination)
