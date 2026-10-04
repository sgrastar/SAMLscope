#!/usr/bin/env python3
"""Flat immutable original assembly; never copies credentials or native private keys."""
import argparse
import hashlib
import json
import re
from pathlib import Path
import subprocess

def sha(raw):return hashlib.sha256(raw).hexdigest()
def read(path):return json.loads(path.read_bytes())
def prepare(folder):
    folder=Path(folder).resolve();receipt=folder/'receipt-v1';receipt.mkdir(exist_ok=False)
    names=['created.json','fixture.xml','parser.stdout','flows.json','restoration.json','operation-counts.json','producer.json',
        'native-persistent-filter.php','native-base-generator.php','native-userpass.php','native-xml-signer.php',
        'native-resolver-command.php','native-producer-command.php',
        'same-principal-different-format.xml','multiple-same-principal-confirmations.xml','different-confirmation-principal.xml','different-attribute-principal.xml']
    names += [label+'-'+suffix for label in ['hosted','remote','salt'] for suffix in ['original.php','final.php']]
    names += [label+'-original-hash.json' for label in ['hosted','remote','salt','authsource']]
    originals={name:folder/name for name in names}
    for phase in ['before','after']:
        for name in ['native-resolution.json','observed.json','hosted.php','remote.php','hosted-hash.json','remote-hash.json','salt-hash.json','authsource-hash.json']:
            originals[phase+'-'+name]=folder/phase/name
    hashes={}
    for name,path in originals.items():
        raw=path.read_bytes();(receipt/name).write_bytes(raw);hashes[name]=sha(raw)
    run=read(folder/'created.json')['run']['id']
    manifest=dict(schema='samlscope-simplesamlphp-subject-principal-v1',runId=run,
        targetMetadataSha256=sha((folder/'target-metadata.xml').read_bytes()),files=hashes)
    (receipt/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n');return receipt

def install(folder):
    folder=Path(folder).resolve();receipt=folder/'receipt-v1'
    if not receipt.exists():prepare(folder)
    run=read(receipt/'manifest.json')['runId'];target='/data/subject-principal-evidence/'+run
    if not re.fullmatch(r'run_[0-9A-HJKMNP-TV-Z]{26}',run):raise ValueError('Invalid receipt Run')
    existing=subprocess.run(['docker','exec','samlscope-reference-suite','test','-e',target],capture_output=True).returncode==0
    if existing:
        names=subprocess.check_output(['docker','exec','samlscope-reference-suite','ls','-1',target]).decode().splitlines()
        if set(names)!={file.name for file in receipt.iterdir()}:raise ValueError('Existing receipt file set differs')
    else:
        subprocess.run(['docker','exec','samlscope-reference-suite','mkdir','-p',target],check=True,capture_output=True)
    records=[]
    for file in sorted(receipt.iterdir()):
        if not existing:subprocess.run(['docker','cp',str(file),'samlscope-reference-suite:'+target+'/'+file.name],check=True,capture_output=True)
        observed=subprocess.check_output(['docker','exec','samlscope-reference-suite','cat',target+'/'+file.name])
        if observed!=file.read_bytes():raise ValueError('Receipt readback differs')
        records.append(dict(file=file.name,sha256=sha(observed)))
    (folder/'receipt-installation.json').write_text(json.dumps(dict(runId=run,path=target,records=records,readBackVerified=True,reusedExact=existing),indent=2)+'\n')
    return not existing

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('folder',type=Path);p.add_argument('--prepare-only',action='store_true');a=p.parse_args()
    prepare(a.folder) if a.prepare_only else install(a.folder)
