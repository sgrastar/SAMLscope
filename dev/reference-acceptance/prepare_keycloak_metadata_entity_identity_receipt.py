#!/usr/bin/env python3
"""Assemble public original references; never create native observations or modify r1."""
import argparse,pathlib,json,hashlib,shutil
sha=lambda b:hashlib.sha256(b).hexdigest()
def load(p):return json.loads(p.read_bytes())
def main():
 p=argparse.ArgumentParser();p.add_argument('source',type=pathlib.Path);p.add_argument('output',type=pathlib.Path);a=p.parse_args();r=a.source.resolve();out=a.output.resolve();out.mkdir(parents=True,exist_ok=False)
 def copy(name,src=None):
  dst=out/name;dst.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(src or r/name,dst)
 copy('target-metadata.xml');copy('peers.json');copy('operation-counts.json');copy('operations.json');copy('restoration.json');copy('qualification.json',r/'read-only-completion/qualification.json');copy('observations.json',r/'read-only-completion/observations.json');copy('duplicate-fixture.xml');copy('restoration-ref.json')
 peers=load(r/'peers.json')
 for peer in peers:
  label=peer['label']
  for name in ['created.json','plan.json','fixture.xml','target-metadata.xml']:copy(label+'/'+name)
  f=r/'read-only-completion'/label
  for name in ['transcript.json','decoded-manifest.json']:copy(label+'/'+name,f/name)
  for row in load(f/'decoded-manifest.json'):copy(label+'/'+row['file'],f/row['file'])
 for folder in ['native-originals','native-runtime']:
  for file in (r/folder).iterdir():copy(folder+'/'+file.name)
 by={row['sha256']:row['id'] for row in load(out/'primary/decoded-manifest.json')};refs={}
 for file in (out/'native-originals').iterdir():
  refs[file.stem]={'reference':by[sha(file.read_bytes())],'sha256':sha(file.read_bytes())}
 files={str(f.relative_to(out)):sha(f.read_bytes()) for f in out.rglob('*') if f.is_file()}
 m=dict(schema='samlscope-keycloak-metadata-entity-identity-v1',adapter='keycloak-native-simultaneous-entity-registration-v1',campaignId='native-metadata-entity-identity',runId=peers[0]['runId'],planId=peers[0]['planId'],targetEntityId='http://localhost:18180/realms/samlscope',targetMetadataSha256=sha((out/'target-metadata.xml').read_bytes()),peers=peers,originals=refs,files=files)
 (out/'manifest.json').write_text(json.dumps(m,indent=2)+'\n');print('Public native entity identity manifest assembled',m['runId'])
if __name__=='__main__':main()
