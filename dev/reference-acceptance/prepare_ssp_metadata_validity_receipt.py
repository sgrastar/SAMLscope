#!/usr/bin/env python3
"""Prepare a hash-bound native expiry receipt from already saved public originals."""
import argparse,hashlib,json,pathlib,shutil
sha=lambda b:hashlib.sha256(b).hexdigest()
load=lambda p:json.loads(p.read_bytes())

def prepare(folder):
 folder=pathlib.Path(folder).resolve();receipt=folder/'receipt'
 for name in ['created.json','plan.json','operation-counts.json']:
  source=folder/name;destination=receipt/name
  if destination.exists() and destination.read_bytes()!=source.read_bytes():raise ValueError('Refuse existing original replacement')
  if not destination.exists():shutil.copyfile(source,destination)
 identity=load(receipt/'identity.json');created=load(folder/'created.json')['run'];target=folder/'target-metadata.xml'
 if identity['runId']!=created['id'] or identity['targetMetadataSha256']!=sha(target.read_bytes()):raise ValueError('Saved identity differs')
 originals={f.name:sha(f.read_bytes()) for f in receipt.iterdir() if f.is_file() and f.name!='manifest.json'}
 if any(f.is_symlink() or not f.is_file() for f in receipt.iterdir()):raise ValueError('Unsafe original')
 manifest=dict(schema='samlscope-simplesamlphp-metadata-validity-v1',adapter='simplesamlphp-native-filesystem-validity-v1',runId=created['id'],caseId='IIP-MD05-ar-idp-01',campaignId='native-metadata-validity',entityId=identity['entityId'],targetEntityId='http://localhost:18380/idp',targetMetadataSha256=sha(target.read_bytes()),observations=load(receipt/'observations.json'),signatureControl=load(receipt/'signature-control.json'),originals=originals)
 raw=(json.dumps(manifest,indent=2)+'\n').encode();path=receipt/'manifest.json'
 if path.exists() and path.read_bytes()!=raw:raise ValueError('Refuse existing manifest replacement')
 if not path.exists():path.write_bytes(raw)
 return manifest
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('folder',type=pathlib.Path);a=p.parse_args();print(prepare(a.folder)['runId'])
