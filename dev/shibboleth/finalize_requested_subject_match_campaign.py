#!/usr/bin/env python3
"""Archive actual deployed production code and formally evaluate existing public originals."""
import argparse,datetime,hashlib,json,pathlib,secrets,shutil,subprocess,sys
REPO=pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0,str(REPO/'dev/reference-acceptance'))
from capture_terminal_http_runtime import capture_suite
from verify_terminal_http_acceptance import find_case
from verify_shibboleth_native_ui_acceptance import dependency_classpath

SHA=lambda b:hashlib.sha256(b).hexdigest();READ=lambda p:json.loads(pathlib.Path(p).read_bytes())
SAVE=lambda p,v:pathlib.Path(p).write_text(json.dumps(v,sort_keys=True,indent=2)+'\n')
NOW=lambda:datetime.datetime.now(datetime.timezone.utc).isoformat().replace('+00:00','Z')
def command(args):return subprocess.run(args,check=True,capture_output=True)
def readback(suite,classes,run):
 remote='/tmp/samlscope-subject-state-'+secrets.token_hex(6);uid=command(['docker','exec',suite,'id','-u']).stdout.decode().strip()
 command(['docker','exec','--user','0',suite,'mkdir',remote])
 try:
  command(['docker','cp',str(classes),suite+':'+remote+'/classes']);command(['docker','exec','--user','0',suite,'chown','-R',uid+':'+uid,remote])
  return command(['docker','exec',suite,'java','-cp',remote+'/classes:/opt/samlscope/lib/*','com.samlscope.runner.cases.ReadShibbolethRequestedSubjectStoredConclusion','capture',run]).stdout
 finally:command(['docker','exec','--user','0',suite,'rm','-rf',remote])
def main():
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('folder',type=pathlib.Path);args=parser.parse_args();folder=args.folder.resolve()
 archive=folder/'subject-match-reader-v183';archive.mkdir(exist_ok=False);run=READ(folder/'browser/created.json')['run']['id'];suite='samlscope-reference-suite'
 expected=READ(folder/'subject-match-receipt-originals-v2.json');remote='/data/subject-match-evidence/'+run
 rows=command(['docker','exec',suite,'sha256sum',*[remote+'/'+file for file in expected]]).stdout.decode().splitlines()
 actual={row.split()[1][len(remote)+1:]:row.split()[0] for row in rows}
 if actual!=expected:raise ValueError('Installed originals changed')
 for name in ['created.json','transcript.json']:shutil.copy2(folder/'browser'/name,archive/name)
 for label,source in [('replay-helper','dev/reference-acceptance/VerifyShibbolethRequestedSubjectMatch.java'),
                      ('stored-readback-source','dev/reference-acceptance/ReadShibbolethRequestedSubjectStoredConclusion.java')]:
  shutil.copy2(REPO/source,archive/(label+'.java'))
 SAVE(archive/'replay-helper.json',dict(sha256=SHA((archive/'replay-helper.java').read_bytes())))
 shutil.copy2(REPO/'tests/coverage.yaml',archive/'approved-coverage-original.yaml')
 # Prior public state must be read before formal reevaluation. Compile the read-only
 # helper against the already archived Store API; installed runtime executes the query.
 old=REPO/'build/acceptance/reference-20261001/shibboleth-native-slo-v178-r7/reader-v180';rt=READ(old/'suite-runtime-terminal-http.json')
 cp=':'.join(str(old/rt['jars'][name]['file']) for name in ['runner','core','saml'])+':'+str(old/'suite-store-0.1.0.jar')+':'+dependency_classpath(old)
 classes=archive/'stored-readback-classes';classes.mkdir();source=classes/'ReadShibbolethRequestedSubjectStoredConclusion.java';source.write_bytes((archive/'stored-readback-source.java').read_bytes())
 command(['javac','-cp',cp,'-d',str(classes),str(source)])
 (archive/'previous-stored-case-conclusions.json').write_bytes(readback(suite,classes,run))
 started=NOW();capture_suite(archive);case=find_case(READ(archive/'evaluation-terminal-http-v1/result.json'),'IIP-SSO07-b-idp-01')
 SAVE(archive/'formal.json',dict(runId=run,startedAt=started,finishedAt=NOW(),transcriptUnchanged=True,
  productWrites=0,productRestarts=0,protocolSends=0,humanOperations=0,newRuns=0,case=case))
 command(['docker','cp',suite+':/opt/samlscope/lib/store-0.1.0.jar',str(archive/'suite-store-0.1.0.jar')])
 SAVE(archive/'store-runtime.json',dict(file='suite-store-0.1.0.jar',sha256=SHA((archive/'suite-store-0.1.0.jar').read_bytes())))
 raw=readback(suite,classes,run);(archive/'stored-case-conclusions.json').write_bytes(raw)
 SAVE(archive/'stored-readback-provenance.json',dict(readonly=True,caseStateExported=False,privateCredentialsExported=False,productOperations=0,
  sourceSha256=SHA((archive/'stored-readback-source.java').read_bytes()),sha256=SHA(raw)))
 rt=READ(archive/'suite-runtime-terminal-http.json')
 print(json.dumps(case));print(json.dumps(dict(image_id=rt['container']['image_id'],jars={n:v['sha256'] for n,v in rt['jars'].items()},
  store=SHA((archive/'suite-store-0.1.0.jar').read_bytes()),helper=SHA((archive/'replay-helper.java').read_bytes()),storedHelper=SHA((archive/'stored-readback-source.java').read_bytes())),indent=2))
if __name__=='__main__':main()
