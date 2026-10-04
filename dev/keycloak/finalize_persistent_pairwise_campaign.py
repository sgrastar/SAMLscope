#!/usr/bin/env python3
"""Bind two restored native peer campaigns to their original Recorder entries."""
import argparse,hashlib,json,pathlib
p=argparse.ArgumentParser(description=__doc__);p.add_argument('folder',type=pathlib.Path);a=p.parse_args();folder=a.folder.resolve()
def load(path):return json.loads(path.read_bytes())
def sha(raw):return hashlib.sha256(raw).hexdigest()
peers=[]
if load(folder/'restoration.json')['restored'] is not True:raise ValueError('Native restoration incomplete')
for label in ['primary','secondary']:
 source=folder/label;created=load(source/'created.json')['run'];entries=load(source/'transcript.json');by={e['id']:e for e in entries};decoded={m['id']:(source/m['file']).read_bytes() for m in load(source/'decoded-manifest.json')}
 if len(by)!=len(entries) or any(e['runId']!=created['id'] for e in entries):raise ValueError('Ambiguous peer history')
 def original(name):
  raw=(source/'native-originals'/(name+'.json')).read_bytes();matches=[id for id,body in decoded.items() if body==raw]
  if len(matches)!=1:raise ValueError('Original Recorder binding differs '+name)
  if len(raw)!=by[matches[0]]['decodedSamlBytes']:raise ValueError('Original Recorder length differs')
  return dict(reference=matches[0],sha256=sha(raw))
 peers.append(dict(runId=created['id'],entityId='http://localhost:18080/p/'+created['planId'],metadataSha256=sha((source/'fixture.xml').read_bytes()),initial=original('initial-inventory'),converter=original('converter'),application=original('application'),before=original('before'),after=original('after'),restoration=original('restored'),baseline=load(source/'baseline-exchange.json'),persistent=load(source/'persistent-exchange.json')))
target=(folder/'primary/target-metadata.xml').read_bytes()
if target!=(folder/'secondary/target-metadata.xml').read_bytes():raise ValueError('Peers target snapshots differ')
receipt=dict(schema='samlscope-keycloak-persistent-pairwise-v1',runId=peers[0]['runId'],campaignId='native-persistent-pairwise',targetMetadataSha256=sha(target),peers=peers)
(folder/'qualified-receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
print('Native pairwise original references bound; no verdict adopted')
