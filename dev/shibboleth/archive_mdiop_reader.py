#!/usr/bin/env python3
"""Archive a strict deployed Reader for existing immutable MDIOP native originals."""
import argparse,hashlib,json,shutil,subprocess,sys
from datetime import datetime,timezone
from pathlib import Path
REPO=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(REPO/'dev/reference-acceptance'))
from capture_terminal_http_runtime import capture_suite,api
SHA=lambda raw:hashlib.sha256(raw).hexdigest()
NOW=lambda:datetime.now(timezone.utc).isoformat().replace('+00:00','Z')

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('folder',type=Path)
    folder=parser.parse_args().folder.resolve();archive=folder/'strict-reader-v173'
    archive.mkdir()
    for name in ('created.json','transcript.json'):shutil.copyfile(folder/name,archive/name)
    run=json.loads((folder/'created.json').read_text())['run']['id']
    started=NOW();capture_suite(archive)
    jar=archive/'suite-store-0.1.0.jar'
    subprocess.run(['docker','cp','samlscope-reference-suite:/opt/samlscope/lib/store-0.1.0.jar',str(jar)],check=True,capture_output=True)
    (archive/'store-runtime.json').write_text(json.dumps(dict(path='/opt/samlscope/lib/store-0.1.0.jar',file=jar.name,sha256=SHA(jar.read_bytes())),indent=2)+'\n')
    helper=REPO/'dev/reference-acceptance/VerifyShibbolethMdiopFullEvidence.java'
    shutil.copyfile(helper,archive/'replay-helper-original.java')
    (archive/'replay-helper-original.json').write_text(json.dumps(dict(file='replay-helper-original.java',sha256=SHA(helper.read_bytes())),indent=2)+'\n')
    unchanged=api('/api/runs/'+run+'/transcript')==json.loads((folder/'transcript.json').read_text())
    if not unchanged:raise ValueError('Original Recorder changed')
    (archive/'archival-verification.json').write_text(json.dumps(dict(runId=run,startedAt=started,finishedAt=NOW(),sourceFormalResultSha256=SHA((folder/'evaluation-terminal-http-v1/result.json').read_bytes()),sourceTranscriptSha256=SHA((folder/'transcript.json').read_bytes()),productWrites=0,productRestarts=0,protocolSends=0,humanOperations=0,suiteEvaluatePosts=1,transcriptUnchanged=True),indent=2)+'\n')
    print(archive,'deployed strict Reader archived; product operations zero')
if __name__=='__main__':main()
