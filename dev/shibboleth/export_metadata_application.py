#!/usr/bin/env python3
"""Freeze a new qualified public export without altering any historical collection original."""
import argparse,hashlib,json,pathlib,shutil

def sha(raw):return hashlib.sha256(raw).hexdigest()
def write(p,n):p.write_text(json.dumps(n,indent=2,sort_keys=True)+'\n')
def export(source,dest,causes):
 source=source.resolve();assert not dest.exists();dest.mkdir(parents=True)
 for name in ('transcript.json','decoded-manifest.json','target-metadata.xml','created.json','plan.json','actual-case-slot-preflight.json','result.json'):
  shutil.copyfile(source/name,dest/name)
 shutil.copytree(source/'decoded',dest/'decoded');shutil.copytree(source/'receipt',dest/'receipt')
 m=json.loads((dest/'receipt/manifest.json').read_text());original=(source/'receipt/manifest.json').read_bytes()
 for name in ('flow-control.json','flow-no-valid-until.json'):
  shutil.copyfile(source/name,dest/'receipt'/name)
 shutil.copyfile(causes,dest/'receipt/native-paos-cause-projection.json')
 write(dest/'receipt/collection-lineage.json',{'schema':'samlscope-metadata-application-export-lineage-v1','sourceManifestSha256':sha(original),'sourceRunId':m['runId'],'sourceBytesChanged':False,'publicCausesSha256':sha(causes.read_bytes())})
 m['files']={p.relative_to(dest/'receipt').as_posix():sha(p.read_bytes()) for p in (dest/'receipt').rglob('*') if p.is_file() and p.name!='manifest.json'}
 write(dest/'receipt/manifest.json',m)
 evidence=dest/'evidence';evidence.mkdir();shutil.copytree(dest/'receipt',evidence/m['runId'])
 return m['runId']
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('source',type=pathlib.Path);p.add_argument('destination',type=pathlib.Path);p.add_argument('causes',type=pathlib.Path);a=p.parse_args();print(export(a.source,a.destination,a.causes))
