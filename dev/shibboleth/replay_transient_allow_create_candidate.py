#!/usr/bin/env python3
"""Run compiled candidate in an ephemeral Suite JVM; never a formal adoption."""
import argparse,json,pathlib,secrets,subprocess
REPO=pathlib.Path(__file__).resolve().parents[2]
def main():
 p=argparse.ArgumentParser();p.add_argument('root',type=pathlib.Path);p.add_argument('--label',default='candidate-replay');a=p.parse_args();folder=a.root.resolve();suite='samlscope-reference-suite';remote='/tmp/shib-fp-candidate-'+secrets.token_hex(5)
 def command(args):return subprocess.run(args,capture_output=True,check=True)
 command(['docker','exec','-u','0',suite,'mkdir',remote]);uid=command(['docker','exec',suite,'id','-u']).stdout.decode().strip()
 try:
  marker=next(folder.glob('run_*.shibboleth-transient-allow-create.json'))
  for source,name in [(folder/'receipt','receipt'),(folder/'browser/created.json','created.json'),(folder/'transcript.json','transcript.json'),(marker,marker.name),(REPO/'build/shib-fp-check','classes')]:command(['docker','cp',str(source),suite+':'+remote+'/'+name])
  command(['docker','exec','-u','0',suite,'chown','-R',uid+':'+uid,remote]);result=subprocess.run(['docker','exec',suite,'java','-Dsamlscope.shibTransientAllowCreate.debug=true','-cp',remote+'/classes:/opt/samlscope/lib/*','com.samlscope.runner.cases.VerifyShibbolethTransientAllowCreate',remote+'/receipt',remote,remote+'/report.json'],capture_output=True)
  (folder/(a.label+'.stdout')).write_bytes(result.stdout);(folder/(a.label+'.stderr')).write_bytes(result.stderr)
  if result.returncode:print(result.stderr.decode(errors='replace')[-2400:]);raise ValueError('Candidate production leaf rejected')
  command(['docker','cp',suite+':'+remote+'/report.json',str(folder/(a.label+'.json'))]);report=json.loads((folder/(a.label+'.json')).read_bytes());print(report['outcome']['outcome'],len(report['negativeControls']))
 finally:command(['docker','exec','-u','0',suite,'rm','-rf',remote])
if __name__=='__main__':main()
