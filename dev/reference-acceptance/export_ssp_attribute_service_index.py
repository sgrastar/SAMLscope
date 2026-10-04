"""Export complete immutable native selector originals, never synthesize conclusions."""
import hashlib,json
from pathlib import Path
sha=lambda b:hashlib.sha256(b).hexdigest()
def export(source,destination):
 source=Path(source);destination=Path(destination);destination.mkdir(parents=True,exist_ok=False);files={}
 def copy(name,p):
  raw=p.read_bytes();(destination/name).write_bytes(raw);files[name]=sha(raw)
 for p in source.iterdir():
  if p.is_file() and (p.name.startswith('native-') or p.name in ['collector.py','created.json','plan.json','campaign.json','target-metadata.xml','restoration.json','identity-before.json','identity-after.json','operation-counts.json','operations.json'] or p.name.endswith('-original.php') or p.name.endswith('-final.php')):copy(p.name,p)
 for name in ['control','control-before','control-after','index-0','index-1','index-2']+['index-'+str(i)+'-'+v for i in range(3) for v in ['before','after']]+['native-http-originals','producer-controls']:
  for p in (source/name).iterdir():
   if p.is_file():copy(name+'.'+p.name,p)
 entries=json.loads((source/'transcript.json').read_text());lookup={e['id']:e for e in entries};decoded={r['id']:(source/r['file']).read_bytes() for r in json.loads((source/'decoded-manifest.json').read_text())};control=json.loads((source/'control/flow.json').read_text());manifest=dict(schema='samlscope-simplesamlphp-attribute-service-index-v1',runId=json.loads((source/'created.json').read_text())['run']['id'],campaignId='native-attribute-service-index',targetEntityId='http://localhost:18380/idp',targetMetadataSha256=sha((source/'target-metadata.xml').read_bytes()),files=files,matrix=[])
 normal=control['positive_exchange']['transcript_ids'];negative=control['negative_control']['exchange']['transcript_ids'];assert len(normal)==2 and len(negative)==1
 manifest.update(positiveRequestReference=normal[0],positiveResponseReference=normal[1],negativeRequestReference=negative[0]);http=json.loads((source/'native-http-observations.json').read_text())['records'];operations=json.loads((source/'operations.json').read_text())
 def binding(folder,request):
  fixture=(source/folder/'fixture.xml').read_bytes();before=lookup[request]['timestamp'];preps=[e for e in entries if e['samlSummary'].get('type')=='MetadataPrepared' and e['timestamp']<=before and decoded.get(e['id'])==fixture];assert preps;prep=max(preps,key=lambda e:e['timestamp']);return dict(metadataReference=prep['id'],fetchReference=prep['samlSummary']['fetchTranscriptId'])
 manifest.update(binding('control',normal[0]))
 for i,row in enumerate(operations):
  flow=json.loads((source/('index-'+str(i))/'flow.json').read_text());refs=flow['positive_exchange']['transcript_ids'];assert len(refs)==2;record=[r for r in http if r['request_id']==lookup[refs[0]]['correlationId']];assert len(record)==1
  manifest['matrix'].append(dict(key=row['condition'],selector=row['selector'],requestReference=refs[0],responseReference=refs[1],dispatchStartedAt=record[0]['started_at'],dispatchCompletedAt=row['flowCompletedAt'],**binding('index-'+str(i),refs[0])))
 (destination/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n');return manifest
if __name__=='__main__':
 import argparse;p=argparse.ArgumentParser();p.add_argument('source',type=Path);p.add_argument('destination',type=Path);a=p.parse_args();export(a.source,a.destination)
