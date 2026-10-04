#!/usr/bin/env python3
"""Install only existing public G02 native originals for the SSO07.b counterexample."""
import argparse,hashlib,json,pathlib,shutil,subprocess
REPO=pathlib.Path(__file__).resolve().parents[2]
READ=lambda p:json.loads(pathlib.Path(p).read_bytes())
SHA=lambda b:hashlib.sha256(b).hexdigest()
def command(args):return subprocess.run(args,check=True,capture_output=True)
def main():
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('folder',type=pathlib.Path);args=parser.parse_args();folder=args.folder.resolve();source=folder/'browser';receipt=folder/'subject-match-receipt';receipt.mkdir(exist_ok=False)
 run=READ(source/'created.json')['run']['id']
 for name in ['created.json','suite-sp-metadata.xml']:shutil.copy2(source/name,receipt/name)
 for name in ['native-subject-binding.json','native-idp-conf-impl.jar','native-source.json','native-request-bound-audit.log','restoration.json',
              *[phase+'-'+kind+'.xml' for phase in ['original','configured','final','before-run','before-protocol','after-protocol'] for kind in ['c14n','audit']],
              *[phase+'-readback.json' for phase in ['before-run','before-protocol','after-protocol']]]:shutil.copy2(folder/name,receipt/name)
 for phase in ['start','end']:shutil.copy2(source/('target-container-inspect-'+phase+'.json'),receipt/('target-container-inspect-'+phase+'.json'))
 originals={p.name:SHA(p.read_bytes()) for p in sorted(receipt.iterdir())}
 manifest=dict(schema='samlscope-shibboleth-requested-subject-match-v1',runId=run,targetMetadataSha256=SHA((source/'target-metadata.xml').read_bytes()),originals=originals,
  exchanges=[dict(requestReference='tx_5TVTCFGZHP98BMWR7E3ZQMJZA9',responseReference='tx_5QW91EMV23J2GQHFRXW2Y6THH1'),dict(requestReference='tx_WPYSXV7TXAY6XWCJNAFMGD2RYY',responseReference='tx_JKNTNPSWC2DQ2N0427BBTF8Z51')])
 (receipt/'manifest.json').write_text(json.dumps(manifest,sort_keys=True,indent=2)+'\n');files={p.name:SHA(p.read_bytes()) for p in sorted(receipt.iterdir())}
 (folder/'subject-match-receipt-originals.json').write_text(json.dumps(files,sort_keys=True,indent=2)+'\n')
 suite='samlscope-reference-suite';remote='/data/subject-match-evidence/'+run
 if subprocess.run(['docker','exec',suite,'test','-e',remote],capture_output=True).returncode==0:raise ValueError('Existing evidence must remain immutable')
 uid=command(['docker','exec',suite,'id','-u']).stdout.decode().strip();command(['docker','exec','--user','0',suite,'mkdir','-p','/data/subject-match-evidence'])
 command(['docker','cp',str(receipt),suite+':'+remote]);command(['docker','exec','--user','0',suite,'chown','-R',uid+':'+uid,remote])
 checked=command(['docker','exec',suite,'sha256sum',*[remote+'/'+f for f in files]]).stdout.decode().splitlines();actual={r.split()[1][len(remote)+1:]:r.split()[0] for r in checked}
 if actual!=files:raise ValueError('Receipt readback differs')
 (folder/'subject-match-receipt-installation.json').write_text(json.dumps(dict(readBackMatched=True,files=actual,productOperations=0,protocolSends=0,humanOperations=0),sort_keys=True,indent=2)+'\n')
 print(run,len(files),'existing public originals installed; product operations 0')
if __name__=='__main__':main()
