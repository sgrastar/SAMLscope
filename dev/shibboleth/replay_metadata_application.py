#!/usr/bin/env python3
"""Candidate source replay, explicitly not an actual deployed-runtime adoption verifier."""
import argparse,pathlib,subprocess,json
ROOT=pathlib.Path(__file__).resolve().parents[2];SUITE='samlscope-reference-suite';JAVA='/Library/Java/JavaVirtualMachines/jdk-21.jdk/Contents/Home/bin/javac'
def run(args):
 r=subprocess.run(args,capture_output=True,timeout=60)
 if r.returncode:raise RuntimeError('Public replay failed: '+r.stderr.decode(errors='replace')[:1800])
 return r.stdout
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('folder',type=pathlib.Path);p.add_argument('report_name');a=p.parse_args();assert a.report_name.replace('-','').replace('.','').isalnum();assert not(a.folder/a.report_name).exists()
 classes=pathlib.Path('/private/tmp/shib-application-reader-classes');classes.mkdir(exist_ok=True);cp=':'.join(map(str,(ROOT/'api/build/install/samlscope/lib').glob('*.jar')))
 files=[ROOT/'runner/src/main/java/com/samlscope/runner/cases'/n for n in ['ShibbolethMetadataApplicationEvidence.java','ShibbolethMetadataApplicationSource.java','MetadataSupersessionProbeTestCase.java']]+[ROOT/'dev/reference-acceptance'/n for n in ['VerifyShibbolethMetadataApplicationEvidence.java','VerifyNativeRoleKeyConsumption.java']]
 run([JAVA,'-cp',cp,'-d',str(classes),*map(str,files)])
 remote='/tmp/shib-application-candidate-'+a.report_name.replace('.','-');assert remote.startswith('/tmp/shib-application-candidate-')
 try:
  run(['docker','exec',SUITE,'mkdir','-p',remote+'/classes']);run(['docker','cp',str(a.folder),SUITE+':'+remote+'/source']);run(['docker','cp',str(classes/'com'),SUITE+':'+remote+'/classes/com']);run(['docker','exec','--user','0:0',SUITE,'chmod','-R','a+rX',remote]);run(['docker','exec','--user','0:0',SUITE,'java','-cp',remote+'/classes:/opt/samlscope/lib/*','com.samlscope.runner.cases.VerifyShibbolethMetadataApplicationEvidence',remote+'/source','/data',remote+'/report.json']);run(['docker','cp',SUITE+':'+remote+'/report.json',str(a.folder/a.report_name)]);print(json.dumps(json.loads((a.folder/a.report_name).read_text())['diagnosticStages'],indent=2))
 finally:run(['docker','exec','--user','0:0',SUITE,'rm','-rf',remote])
