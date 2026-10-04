#!/usr/bin/env python3
"""Bind native recorded originals without supplying a target judgment."""
import argparse, hashlib, json, pathlib, subprocess
def install(folder):
 folder=pathlib.Path(folder).resolve();load=lambda name:json.loads((folder/name).read_bytes());sha=lambda raw:hashlib.sha256(raw).hexdigest()
 created=load('created.json')['run'];run=created['id'];entries=load('transcript.json');phases=load('phases.json')
 for phase in phases:
  raw=(folder/phase['variant']/'fixture.xml').read_bytes();prepared=[e for e in entries if e['samlSummary'].get('type')=='MetadataPrepared' and e['samlSummary'].get('variant')==phase['variant'] and e['samlSummary'].get('metadataSha256')==sha(raw)]
  if len(prepared)!=1:raise ValueError('Native original preparation ambiguous')
  phase['preparedReference']=prepared[0]['id']
 target=(folder/'target-metadata.xml').read_bytes();receipt=dict(schema='samlscope-keycloak-native-supersession-v1',adapter='keycloak-native-converter-same-client-v1',runId=run,campaignId='native-metadata-supersession',targetEntityId='http://localhost:18180/realms/samlscope',targetMetadataSha256=sha(target),peerEntityId='http://localhost:18080/p/'+created['planId'],phases=phases,probes=load('probes.json'),probeState=load('probe-state-references.json'),restoration=load('restoration.json'))
 path=folder/'qualified-receipt.json';path.write_text(json.dumps(receipt,indent=2)+'\n')
 target='/data/metadata-rejection-evidence/'+run+'.keycloak-supersession.json'
 subprocess.run(['docker','cp',str(path),'samlscope-reference-suite:'+target],check=True,capture_output=True)
 observed=subprocess.check_output(['docker','exec','samlscope-reference-suite','sha256sum',target],text=True).split()[0]
 if observed!=sha(path.read_bytes()):raise ValueError('Installed native receipt readback differs')
 (folder/'receipt-install.json').write_text(json.dumps(dict(target=target,sha256=observed),indent=2)+'\n');return run
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('folder',type=pathlib.Path);print(install(p.parse_args().folder))
