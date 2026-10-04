#!/usr/bin/env python3
"""Assemble checked originals for the native SSP pairwise reader; install without a verdict claim."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

def sha(raw):return hashlib.sha256(raw).hexdigest()
def read(path):return json.loads(path.read_bytes())

def prepare(folder):
    folder=Path(folder).resolve();receipt=folder/'receipt-v1';receipt.mkdir(exist_ok=False)
    def copy(source,name):
        raw=source.read_bytes();(receipt/name).write_bytes(raw);return sha(raw)
    manifest=dict(schema='samlscope-simplesamlphp-persistent-pairwise-v1',
      runId=read(folder/'primary/created.json')['run']['id'],
      targetMetadataSha256=sha((folder/'primary/target-metadata.xml').read_bytes()),peers=[],restoration={},readBacks=[])
    for label in ['primary','secondary']:
        member=folder/label;created=read(member/'created.json')['run'];entity='http://localhost:18080/p/'+created['planId']
        entries=read(member/'transcript.json');requests=[e for e in entries if e['direction']=='OUTBOUND'];responses=[e for e in entries if e['direction']=='INBOUND']
        if len(requests)!=2 or len(responses)!=2:raise ValueError('Incomplete normal two-exchange originals')
        peer=dict(runId=created['id'],entityId=entity,createdFile=label+'-created.json',metadataFile=label+'-metadata.xml',exchanges=[])
        peer['createdSha256']=copy(member/'created.json',peer['createdFile']);peer['metadataSha256']=copy(member/'fixture.xml',peer['metadataFile'])
        copy(member/'parser.stdout',label+'-parser.json')
        for request in requests:
            matches=[e for e in responses if e['samlSummary'].get('inResponseTo')==request['correlationId']]
            if len(matches)!=1:raise ValueError('Ambiguous response')
            peer['exchanges'].append(dict(requestReference=request['id'],responseReference=matches[0]['id']))
        manifest['peers'].append(peer)
    if (folder/'primary/target-metadata.xml').read_bytes()!=(folder/'secondary/target-metadata.xml').read_bytes():raise ValueError('Target changed')
    for name in ['hosted','remote','salt']:
        manifest['restoration'][name]=dict(originalFile=name+'-original.php',finalFile=name+'-final.php')
        for key in ['original','final']:
            manifest['restoration'][name][key+'Sha256']=copy(folder/(name+'-'+key+'.php'),name+'-'+key+'.php')
    for name in ['hosted','remote']:copy(folder/(name+'-configured.php'),name+'-configured.php')
    for name in ['persistent-filter','base-generator','attribute-generator','userpass']:copy(folder/('native-'+name+'.php'),'native-'+name+'.php')
    copy(folder/'native-readback-command.php','native-readback-command.php')
    for phase in ['primary-before','primary-after','secondary-before','secondary-after']:
        row=dict(phase=phase,file=phase+'-native.json',recordedAt=read(folder/phase/'observed.json')['recordedAt'])
        row['sha256']=copy(folder/phase/'native.json',row['file'])
        for kind in ['hosted','remote']:
            row[kind+'File']=phase+'-'+kind+'.php';row[kind+'Sha256']=copy(folder/phase/(kind+'.php'),row[kind+'File'])
        manifest['readBacks'].append(row)
    (receipt/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    return receipt,manifest

def install(folder):
    folder=Path(folder).resolve();receipt=folder/'receipt-v1'
    if not receipt.exists():receipt,manifest=prepare(folder)
    else:manifest=read(receipt/'manifest.json')
    run=manifest['runId'];remote='/data/persistent-nameid-evidence/'+run
    subprocess.run(['docker','exec','samlscope-reference-suite','mkdir','-p','/data/persistent-nameid-evidence'],check=True,capture_output=True)
    if subprocess.run(['docker','exec','samlscope-reference-suite','test','-e',remote],capture_output=True).returncode==0:raise ValueError('Existing receipt would be overwritten')
    subprocess.run(['docker','cp',str(receipt),'samlscope-reference-suite:'+remote],check=True,capture_output=True)
    for file in receipt.iterdir():
        raw=subprocess.check_output(['docker','exec','samlscope-reference-suite','cat',remote+'/'+file.name])
        if raw!=file.read_bytes():raise ValueError('Receipt read-back differs')
    (folder/'receipt-installation.json').write_text(json.dumps(dict(runId=run,directory=remote,files=len(list(receipt.iterdir())),readBack=True),indent=2)+'\n')
    return run

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('folder',type=Path);p.add_argument('--prepare-only',action='store_true');args=p.parse_args()
    print(prepare(args.folder)[1]['runId'] if args.prepare_only else install(args.folder))
