#!/usr/bin/env python3
"""Archive and formally evaluate complete certificate originals; no target operations."""
import argparse,datetime,hashlib,json,pathlib,secrets,shutil,subprocess,sys,time
REPO=pathlib.Path(__file__).resolve().parents[2];sys.path.insert(0,str(REPO/'dev/reference-acceptance'))
from public_runtime_capture import capture_suite
from capture_run_originals import capture
from capture_terminal_http_runtime import api
from verify_terminal_http_acceptance import find_case
SHA=lambda b:hashlib.sha256(b).hexdigest();READ=lambda p:json.loads(pathlib.Path(p).read_bytes())
def save(p,value):pathlib.Path(p).write_text(json.dumps(value,indent=2)+'\n')
def command(args):return subprocess.run(args,check=True,capture_output=True,timeout=90)
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('folder',type=pathlib.Path);a=p.parse_args();folder=a.folder.resolve();archive=folder/'reader-v197';archive.mkdir(exist_ok=False);run=READ(folder/'created.json')['run']['id'];suite='samlscope-reference-suite';remote='/data/metadata-certificate-runtime-evidence/'+run
 uid=command(['docker','exec',suite,'id','-u']).stdout.decode().strip()
 for name in ['created.json','transcript.json']:shutil.copy2(folder/name,archive/name)
 for name,source in [('replay-helper.java','VerifyMetadataCertificateRuntime.java'),('stored-helper.java','ReadMetadataCertificateRuntimeStoredConclusion.java')]:shutil.copy2(REPO/'dev/reference-acceptance'/source,archive/name)
 # Capture prior selected public conclusion before adopting the receipt.
 classes=archive/'stored-helper-classes';classes.mkdir();source=classes/'ReadMetadataCertificateRuntimeStoredConclusion.java';source.write_bytes((archive/'stored-helper.java').read_bytes());command(['javac','-cp',str(REPO/'api/build/install/samlscope/lib/*'),'-d',str(classes),str(source)]);tmp='/tmp/certificate-runtime-prior-'+secrets.token_hex(6);command(['docker','exec','-u','0',suite,'mkdir',tmp])
 try:
  command(['docker','cp',str(classes),suite+':'+tmp+'/classes']);command(['docker','exec','-u','0',suite,'chown','-R',uid+':'+uid,tmp]);(archive/'previous-stored-conclusion.json').write_bytes(command(['docker','exec',suite,'java','-cp',tmp+'/classes:/opt/samlscope/lib/*','com.samlscope.runner.cases.ReadMetadataCertificateRuntimeStoredConclusion','capture',run]).stdout)
 finally:command(['docker','exec','-u','0',suite,'rm','-rf',tmp])
 outbox_source=classes/'ReadMetadataCertificateRuntimeOutboxState.java';outbox_source.write_bytes((REPO/'dev/reference-acceptance/ReadMetadataCertificateRuntimeOutboxState.java').read_bytes());shutil.copy2(outbox_source,archive/'outbox-helper.java');command(['javac','-cp',str(REPO/'api/build/install/samlscope/lib/*'),'-d',str(classes),str(outbox_source)]);tmp='/tmp/certificate-before-'+secrets.token_hex(6);command(['docker','exec','-u','0',suite,'mkdir',tmp])
 try:
  command(['docker','cp',str(classes),suite+':'+tmp+'/classes']);command(['docker','exec','-u','0',suite,'chown','-R',uid+':'+uid,tmp]);(archive/'outbox-before-formal.json').write_bytes(command(['docker','exec',suite,'java','-cp',tmp+'/classes:/opt/samlscope/lib/*','com.samlscope.runner.cases.ReadMetadataCertificateRuntimeOutboxState',run]).stdout)
 finally:command(['docker','exec','-u','0',suite,'rm','-rf',tmp])
 command(['docker','exec','-u','0',suite,'mkdir','-p',remote.rsplit('/',1)[0]]);command(['docker','cp',str(folder/'receipt'),suite+':'+remote]);command(['docker','exec','-u','0',suite,'chown','-R',uid+':'+uid,remote]);expected={file.name:SHA(file.read_bytes()) for file in (folder/'receipt').iterdir()};raw=command(['docker','exec',suite,'sha256sum',*[remote+'/'+name for name in expected]]).stdout.decode().splitlines();actual={row.split()[1][len(remote)+1:]:row.split()[0] for row in raw};assert actual==expected;save(folder/'receipt-readback-v197.json',dict(path=remote,files=expected,readBack=actual,productOperations=0,credentialsPersisted=False))
 started=time.time();capture_suite(archive);command(['docker','cp',suite+':/opt/samlscope/lib/store-0.1.0.jar',str(archive/'suite-store-0.1.0.jar')]);case=find_case(READ(archive/'evaluation-terminal-http-v1/result.json'),'IIP-MD06-a6-idp-01');save(archive/'formal-lifecycle.json',dict(runId=run,runtimeCapturedAtEpoch=started,transcriptUnchanged=True,case=case,productOperations=0,credentialsPersisted=False));(archive/'full-run-originals').mkdir();shutil.copy2(archive/'transcript.json',archive/'full-run-originals/transcript.json');capture(archive/'full-run-originals',run,api('/api/runs/'+run+'/transcript'))
 outbox=classes/'ReadMetadataCertificateRuntimeOutboxState.java';outbox.write_bytes((REPO/'dev/reference-acceptance/ReadMetadataCertificateRuntimeOutboxState.java').read_bytes());shutil.copy2(outbox,archive/'outbox-helper.java');command(['javac','-cp',str(REPO/'api/build/install/samlscope/lib/*'),'-d',str(classes),str(outbox)]);tmp='/tmp/certificate-runtime-after-'+secrets.token_hex(6);command(['docker','exec','-u','0',suite,'mkdir',tmp])
 try:
  command(['docker','cp',str(classes),suite+':'+tmp+'/classes']);command(['docker','exec','-u','0',suite,'chown','-R',uid+':'+uid,tmp]);raw=command(['docker','exec',suite,'java','-cp',tmp+'/classes:/opt/samlscope/lib/*','com.samlscope.runner.cases.ReadMetadataCertificateRuntimeOutboxState',run]).stdout;(archive/'outbox-after-formal.json').write_bytes(raw);assert READ(archive/'outbox-after-formal.json')==READ(archive/'outbox-before-formal.json')
 finally:command(['docker','exec','-u','0',suite,'rm','-rf',tmp])
 rt=READ(archive/'suite-runtime-terminal-http.json');print(json.dumps(dict(case=case,pins=dict(image_id=rt['container']['image_id'],jars={n:v['sha256'] for n,v in rt['jars'].items()}),store=SHA((archive/'suite-store-0.1.0.jar').read_bytes()),helper=SHA((archive/'replay-helper.java').read_bytes()),storedHelper=SHA((archive/'stored-helper.java').read_bytes())),indent=2))
if __name__=='__main__':main()
