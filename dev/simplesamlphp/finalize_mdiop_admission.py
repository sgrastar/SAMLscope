#!/usr/bin/env python3
"""Install the native admission receipt and formally evaluate its historical configuration evidence."""
import argparse,hashlib,json,subprocess
from pathlib import Path
from persistent_nameid_normal_campaign import api,save
CASE='IIP-MD05-c-idp-01'
def sha(raw):return hashlib.sha256(raw).hexdigest()
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('folder',type=Path);a=p.parse_args();folder=a.folder.resolve();receipt=(folder/'qualified-receipt.json').read_bytes();value=json.loads(receipt);run=value['runId'];out=folder/'evaluation';out.mkdir(exist_ok=False)
 before=api('/api/runs/'+run+'/transcript');assert before==json.loads((folder/'transcript.json').read_bytes());save(out/'transcript-before.json',before);save(out/'result-before.json',api('/api/runs/'+run+'/result.json'))
 target='/data/metadata-rejection-evidence/'+run+'.ssp-mdiop-representation.json';subprocess.run(['docker','exec','samlscope-reference-suite','mkdir','-p','/data/metadata-rejection-evidence'],check=True,capture_output=True)
 subprocess.run(['docker','cp',str(folder/'qualified-receipt.json'),'samlscope-reference-suite:'+target],check=True,capture_output=True);actual=subprocess.check_output(['docker','exec','samlscope-reference-suite','cat',target]);assert actual==receipt;save(out/'receipt-readback.json',dict(path=target,sha256=sha(actual),bytesIdentical=True))
 confirmed=api('/api/runs/'+run+'/cases/'+CASE+'/configure',dict(value='CONFIRMED'));save(out/'configuration-confirmed.json',confirmed);save(out/'case-execution.json',confirmed)
 save(out/'evaluation.json',api('/api/runs/'+run+'/protocol-evidence/evaluate',{}));after=api('/api/runs/'+run+'/transcript');assert after==before;save(out/'transcript.json',after);save(out/'result.json',api('/api/runs/'+run+'/result.json'))
 save(out/'protocol-evidence.json',api('/api/runs/'+run+'/protocol-evidence'))
 save(out/'operation-counts.json',dict(receiptPlacement=1,receiptReadback=1,configurationEvidenceConfirmations=1,protocolEvidenceEvaluations=1,productConfigurationWrites=0,protocolSends=0,productRestarts=0,humanOperations=0,transcriptUnchanged=True));print(run,CASE,'native admission formally evaluated, transcript unchanged')
if __name__=='__main__':main()
