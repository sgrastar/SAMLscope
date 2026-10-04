#!/usr/bin/env python3
"""Copy public original references for native registered signer proof, without new observations."""
import argparse,hashlib,json,os,pathlib,shutil
sha=lambda b:hashlib.sha256(b).hexdigest()
load=lambda p:json.loads(p.read_bytes())
def main():
 p=argparse.ArgumentParser();p.add_argument('source',type=pathlib.Path);p.add_argument('output',type=pathlib.Path);a=p.parse_args();r=a.source.resolve();out=a.output.resolve();out.mkdir(parents=True,exist_ok=False)
 def copy(name,src=None):
  source=src or r/name;dst=out/name;dst.parent.mkdir(parents=True,exist_ok=True)
  if source.suffix=='.jar':os.link(source,dst)
  else:shutil.copyfile(source,dst)
 for name in ['target-metadata.xml','peers.json','operation-counts.json','operations.json','restoration.json','observations.json','probes.json','probe-state.json']:copy(name)
 peers=load(r/'peers.json')
 for peer in peers:
  label=peer['label']
  for name in ['created.json','fixture.xml','target-metadata.xml','transcript.json','decoded-manifest.json','browser-originals-manifest.json']:copy(label+'/'+name)
  for manifest in ['decoded-manifest.json','browser-originals-manifest.json']:
   for row in load(r/label/manifest):copy(label+'/'+row['file'])
 copy('preparation.json',r/'preparation-primary/preparation.json')
 for folder in ['native-originals','native-runtime']:
  for file in (r/folder).iterdir():copy(folder+'/'+file.name)
 by={row['sha256']:row['id'] for row in load(out/'primary/decoded-manifest.json')};refs={}
 for file in (out/'native-originals').iterdir():refs[file.stem]=dict(reference=by[sha(file.read_bytes())],sha256=sha(file.read_bytes()))
 files={str(f.relative_to(out)):sha(f.read_bytes()) for f in out.rglob('*') if f.is_file()}
 m=dict(schema='samlscope-keycloak-registered-signer-v1',adapter='keycloak-native-issuer-key-locator-v1',campaignId='native-registered-signer',runId=peers[0]['runId'],planId=peers[0]['planId'],targetEntityId='http://localhost:18180/realms/samlscope',targetMetadataSha256=sha((out/'target-metadata.xml').read_bytes()),peers=peers,originals=refs,files=files,probes=load(out/'probes.json'),configuredAt=load(out/'native-originals/probes-before.json')['recordedAt'],completedAt=load(out/'native-originals/probes-after.json')['recordedAt'])
 (out/'manifest.json').write_text(json.dumps(m,indent=2)+'\n');print('Public registered signer receipt prepared',m['runId'])
if __name__=='__main__':main()
