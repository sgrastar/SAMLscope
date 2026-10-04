"""Copy immutable public originals for two approved native no-opportunity cases."""
import argparse,hashlib,json
from pathlib import Path
def sha(raw):return hashlib.sha256(raw).hexdigest()
def export(source,output):
 output.mkdir(parents=True,exist_ok=False);files={}
 for p in sorted(source.iterdir()):
  if p.is_file() and (p.name.startswith('native-') or p.name in ['collector.py','created.json','plan.json','campaign.json','target-metadata.xml','restoration.json','operation-counts.json','parser-attempt.json','producer.json','identity-before.json','identity-after.json'] or p.name.endswith('-original.php') or p.name.endswith('-final.php') or p.name in ['foreign-positive.xml','foreign-missing-identifier.xml','multiple-positive.xml','multiple-packed-identifiers.xml']):
   raw=p.read_bytes();(output/p.name).write_bytes(raw);files[p.name]=sha(raw)
 for name in ['control','before','after','native-http-originals']:
  for p in sorted((source/name).rglob('*')):
   if p.is_file():
    target=str(p.relative_to(source)).replace('/','.');raw=p.read_bytes();(output/target).write_bytes(raw);files[target]=sha(raw)
 entries=json.loads((source/'transcript.json').read_bytes());prepared=[e for e in entries if e['samlSummary'].get('type')=='MetadataPrepared'];assert len(prepared)==1
 flow=json.loads((source/'control/flow.json').read_bytes());run=json.loads((source/'created.json').read_bytes())['run']['id']
 manifest=dict(schema='samlscope-simplesamlphp-subject-confirmation-v1',runId=run,campaignId='native-subject-confirmation',targetEntityId='http://localhost:18380/idp',targetMetadataSha256=sha((source/'target-metadata.xml').read_bytes()),files=files,
  metadataReference=prepared[0]['id'],fetchReference=prepared[0]['samlSummary']['fetchTranscriptId'],positiveRequestReference=flow['positive_exchange']['transcript_ids'][0],positiveResponseReference=flow['positive_exchange']['transcript_ids'][1],negativeRequestReference=flow['negative_control']['exchange']['transcript_ids'][0])
 (output/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n');return manifest
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('source',type=Path);p.add_argument('output',type=Path);a=p.parse_args();export(a.source,a.output)
