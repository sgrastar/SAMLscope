#!/usr/bin/env python3
"""Install captured native conflict and previously recorded distinct-peer originals."""
import argparse,hashlib,json,pathlib,shutil,subprocess
REPO=pathlib.Path(__file__).resolve().parents[2]
SHA=lambda b:hashlib.sha256(b).hexdigest()
READ=lambda p:json.loads(pathlib.Path(p).read_text())
def command(args):return subprocess.run(args,check=True,capture_output=True)
def main():
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('folder',type=pathlib.Path);args=parser.parse_args();folder=args.folder.resolve()
 run=READ(folder/'created.json')['run']['id'];receipt=folder/'receipt';receipt.mkdir(exist_ok=False)
 # Copy exactly the native original files, excluding protocol duplicates read directly by Recorder.
 for name in ['created.json','target-metadata.xml','original-providers.xml','configured-providers.xml','configured-providers-readback.xml','final-providers.xml',
              'restoration.json','native-resolver-epochs.json','native-resolver-source.json','native-abstract-metadata-resolver.class','native-opensaml-saml-impl.jar',
              'target-container-inspect-start.json','target-container-inspect-end.json']:
  shutil.copy2(folder/name,receipt/name)
 for variant in ['control','duplicate-entity-ids']:
  (receipt/variant).mkdir()
  for name in ['fixture.xml','fixture-readback.xml','native-resolver-warn.log','native-effective-sp-metadata.xml','native-effective-sp-metadata-read.json',
               *[phase+'-'+kind+'.xml' for phase in ['reload-before','reload-after','flow-before','flow-after'] for kind in ['providers','fixture']]]:
   shutil.copy2(folder/variant/name,receipt/variant/name)
 distinct=REPO/'build/acceptance/reference-20260930/shibboleth-persistent-pairwise-v165-r1'
 pair=READ(distinct/'receipt-v1/manifest.json');primary=pair['runId']
 proof=receipt/'distinct-proof'/primary;shutil.copytree(distinct/'receipt-v1',proof)
 runtime=[]
 for label,source in [('parent',distinct),('primary',distinct/'primary'),('secondary',distinct/'secondary')]:
  for phase in ['start','end']:
   name='distinct-'+label+'-runtime-'+phase+'.json';shutil.copy2(source/('target-container-inspect-'+phase+'.json'),receipt/name);runtime.append(name)
 originals={str(p.relative_to(receipt)):SHA(p.read_bytes()) for p in sorted(receipt.rglob('*')) if p.is_file()}
 manifest=dict(schema='samlscope-shibboleth-entityid-uniqueness-v1',runId=run,targetEntityId='http://localhost:18280/idp/shibboleth',
  targetMetadataSha256=SHA((receipt/'target-metadata.xml').read_bytes()),distinctRunId=primary,distinctRuntimeFiles=runtime,originals=originals)
 (receipt/'manifest.json').write_text(json.dumps(manifest,sort_keys=True,indent=2)+'\n')
 files={str(p.relative_to(receipt)):SHA(p.read_bytes()) for p in sorted(receipt.rglob('*')) if p.is_file()}
 (folder/'receipt-originals.json').write_text(json.dumps(files,sort_keys=True,indent=2)+'\n')
 suite='samlscope-reference-suite';remote='/data/entityid-uniqueness-evidence/'+run
 probe=subprocess.run(['docker','exec',suite,'test','-e',remote],capture_output=True)
 if probe.returncode==0:raise ValueError('Refusing to replace installed evidence')
 uid=command(['docker','exec',suite,'id','-u']).stdout.decode().strip()
 command(['docker','exec','--user','0',suite,'mkdir','-p','/data/entityid-uniqueness-evidence'])
 command(['docker','cp',str(receipt),suite+':'+remote]);command(['docker','exec','--user','0',suite,'chown','-R',uid+':'+uid,remote])
 checked=command(['docker','exec',suite,'sha256sum',*[remote+'/'+f for f in files]]).stdout.decode().splitlines()
 actual={line.split()[1][len(remote)+1:]:line.split()[0] for line in checked}
 if actual!=files:raise ValueError('Installed originals differ')
 (folder/'receipt-installation.json').write_text(json.dumps(dict(runId=run,readBackMatched=True,files=actual),sort_keys=True,indent=2)+'\n')
 print(run,len(files),'originals installed/read back')
if __name__=='__main__':main()
