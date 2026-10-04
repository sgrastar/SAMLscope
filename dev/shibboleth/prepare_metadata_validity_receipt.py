#!/usr/bin/env python3
"""Bind captured native expiry originals to actual Suite Recorder entries; never infer an outcome."""
import argparse,hashlib,json,pathlib,shutil
SHA=lambda raw:hashlib.sha256(raw).hexdigest()
READ=lambda p:json.loads(pathlib.Path(p).read_bytes())
VARIANTS=['live-validity-root','live-validity-parent','live-validity-child']
def prepare(folder):
 folder=pathlib.Path(folder);receipt=folder/'receipt';created=READ(folder/'created.json')['run'];run=created['id'];entries=READ(folder/'transcript.json');seen=set()
 for entry in entries:
  if entry['runId']!=run or entry['id'] in seen:raise ValueError('Foreign or duplicate Recorder entry')
  seen.add(entry['id'])
 if (receipt/'manifest.json').exists():raise ValueError('Receipt already exists; preserve prior evidence')
 rows=READ(folder/'observations.json')
 if [r['variant'] for r in rows]!=VARIANTS:raise ValueError('All three expiry observations required')
 for row in rows:
  fixture=(receipt/(row['variant']+'-fixture.xml')).read_bytes();digest=SHA(fixture)
  selected=[e for e in entries if e['direction']=='OUTBOUND' and e['samlSummary'].get('type')=='MetadataPrepared' and e['samlSummary'].get('variant')==row['variant'] and e['samlSummary'].get('metadataSha256')==digest]
  if len(selected)!=1:raise ValueError('Loaded fixture must have one exact Recorder original')
  row['preparedReference']=selected[0]['id'];row['fetchReference']=selected[0]['samlSummary']['fetchTranscriptId']
  (receipt/(row['variant']+'-loaded-prepared-binding.json')).write_text(json.dumps(dict(runId=run,fixtureSha256=digest,preparedReference=row['preparedReference'],fetchReference=row['fetchReference']),indent=2)+'\n')
 for name in ['created.json','restoration.json','operation-counts.json','operations.json','target-metadata.xml']:shutil.copy2(folder/name,receipt/name)
 originals={p.name:SHA(p.read_bytes()) for p in receipt.iterdir() if p.is_file()}
 manifest=dict(schema='samlscope-metadata-validity-epoch-v1',adapter='shibboleth-native-filesystem-validity-v1',runId=run,entityId='http://localhost:18080/p/'+created['planId'],sourcePath='/opt/reference-idp/metadata/validity-'+run+'.xml',targetMetadataSha256=SHA((folder/'target-metadata.xml').read_bytes()),observations=rows,signatureControl=READ(receipt/'invalid-signature-control-exchange.json'),originals=originals)
 (receipt/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n');return manifest
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('folder',type=pathlib.Path);a=p.parse_args();print(prepare(a.folder)['runId'],'original-only expiry receipt prepared')
