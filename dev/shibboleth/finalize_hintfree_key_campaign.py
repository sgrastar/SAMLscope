#!/usr/bin/env python3
"""Formally evaluate a restored, selected native hint-free key campaign."""
import argparse,hashlib,json,shutil,subprocess,sys
from datetime import datetime,timezone
from pathlib import Path
REPO=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(REPO/'dev/reference-acceptance'))
from capture_terminal_http_runtime import api,capture_suite
from verify_terminal_http_acceptance import find_case
SHA=lambda raw:hashlib.sha256(raw).hexdigest()
NOW=lambda:datetime.now(timezone.utc).isoformat().replace('+00:00','Z')
CASE='IIP-MD05-cd-idp-01'
def main():
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('folder',type=Path)
 folder=parser.parse_args().folder.resolve();child=folder/'metadata_idp'
 raw=(child/'qualified-metadata-key-receipt.json').read_bytes();receipt=json.loads(raw);run=receipt['runId']
 if {r['variant'] for r in receipt['conditions']}!={'entity-root','keyvalue-only'}:raise ValueError('Selected condition inventory differs')
 if not json.loads((folder/'restoration.json').read_text())['restored']:raise ValueError('Restore native audit first')
 destination='/data/metadata-key-evidence/'+run+'.json'
 subprocess.run(['docker','exec','samlscope-reference-suite','mkdir','-p','/data/metadata-key-evidence'],check=True,capture_output=True)
 check=subprocess.run(['docker','exec','samlscope-reference-suite','test','-e',destination],capture_output=True)
 if check.returncode==0:raise ValueError('Receipt destination already exists')
 subprocess.run(['docker','cp',str(child/'qualified-metadata-key-receipt.json'),'samlscope-reference-suite:'+destination],check=True,capture_output=True)
 actual=subprocess.check_output(['docker','exec','samlscope-reference-suite','cat',destination])
 if actual!=raw:raise ValueError('Receipt read-back differs')
 (folder/'receipt-placement-readback.json').write_text(json.dumps(dict(runId=run,destination=destination,sha256=SHA(actual),readBackMatched=True,evidenceFileWrites=1),indent=2)+'\n')
 started=NOW();capture_suite(child)
 jar=child/'suite-store-0.1.0.jar'
 subprocess.run(['docker','cp','samlscope-reference-suite:/opt/samlscope/lib/store-0.1.0.jar',str(jar)],check=True,capture_output=True)
 (child/'store-runtime.json').write_text(json.dumps(dict(path='/opt/samlscope/lib/store-0.1.0.jar',file=jar.name,sha256=SHA(jar.read_bytes())),indent=2)+'\n')
 case=find_case(json.loads((child/'evaluation-terminal-http-v1/result.json').read_text()),CASE)
 if (case['outcome'],case['verdict'],case['reason_code'],case['attested'])!=('SATISFIED','PASS','metadata.keys.selection-observed',False):raise ValueError('Native hint-free result unproven: '+str(case))
 if api('/api/runs/'+run+'/transcript')!=json.loads((child/'transcript.json').read_text()):raise ValueError('Recorder changed')
 (child/'formal-hintfree-key-evaluation.json').write_text(json.dumps(dict(runId=run,startedAt=started,finishedAt=NOW(),transcriptUnchanged=True,case=case),indent=2)+'\n')
 helper=REPO/'dev/reference-acceptance/VerifyShibbolethHintFreeKeyEvidence.java';shutil.copyfile(helper,folder/'replay-helper-original.java')
 (folder/'replay-helper-original.json').write_text(json.dumps(dict(file='replay-helper-original.java',sha256=SHA(helper.read_bytes())),indent=2)+'\n')
 print(run,CASE,'native two-representation key campaign formally PASS; transcript unchanged')
if __name__=='__main__':main()
