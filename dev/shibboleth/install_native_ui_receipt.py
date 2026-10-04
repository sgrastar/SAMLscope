#!/usr/bin/env python3
"""Bind grouped native UI originals to Recorder, preserving every original attempt."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess

SHA=lambda raw:hashlib.sha256(raw).hexdigest()
CONFIG=['login-template','authn-properties','password-config','relying-party','global','parent-ui-authn-properties']
def load(path):return json.loads(path.read_text())
def save(path,value):path.write_text(json.dumps(value,indent=2)+'\n')

def prepare(original,append):
    original=original.resolve();append=append.resolve();receipt=original/'receipt';receipt.mkdir(exist_ok=False)
    run=load(original/'created.json')['run']['id']
    if not re.fullmatch(r'run_[0-9A-HJKMNP-TV-Z]{26}',run) or load(append/'created.json')['run']['id']!=run:raise ValueError('Mixed Run')
    for folder in [original,append]:
        if load(folder/'restoration.json')['restored'] is not True:raise ValueError('Native state not restored')
    for file in ['created.json','plan.json','original-providers.xml','configured-providers.xml','final-providers.xml',
            'native-ui-context.class','native-flow-selection.xml','native-view-inventory.txt','native-views.json',
            'target-runtime-start.json','target-runtime-end.json',*['original-'+kind for kind in CONFIG],*['final-'+kind for kind in CONFIG]]:
        shutil.copy2(original/file,receipt/file)
    for row in load(original/'native-views.json'):shutil.copy2(original/row['file'],receipt/row['file'])
    for folder in [original,append]:
        for file in ['original-providers.xml','configured-providers.xml','final-providers.xml',*['original-'+kind for kind in CONFIG],*['final-'+kind for kind in CONFIG]]:
            if (folder/file).read_bytes()!=(original/file).read_bytes():raise ValueError('Append native scope differs')
    observations=[]
    for row in load(original/'observations.json'):
        variant=row['variant'];source=append if variant=='ui-url-logo-https' else original
        matches=[value for value in load(source/'observations.json') if value['variant']==variant]
        if len(matches)!=1:raise ValueError('Missing/duplicate original')
        observations.append(matches[0]);shutil.copytree(source/variant,receipt/variant)
    save(receipt/'observations.json',observations)
    for file in ['transcript.json','decoded-manifest.json']:shutil.copy2(append/file,receipt/file)
    shutil.copytree(append/'decoded',receipt/'decoded')
    target=receipt/'target-metadata.xml'
    subprocess.run(['docker','cp','samlscope-reference-suite:/data/target-metadata/'+run+'.xml',str(target)],check=True,capture_output=True)
    save(receipt/'original-selection.json',dict(runId=run,base=str(original),append=str(append),
        selections={row['variant']:str(append if row['variant']=='ui-url-logo-https' else original) for row in observations}))
    baseline_ids={e['id'] for e in load(original/'transcript.json')}
    new=[e for e in load(append/'transcript.json') if e['id'] not in baseline_ids]
    save(append/'operation-counts-delta.json',dict(productConfigurationWrites=3,productReloads=2,productRestarts=0,
        humanOperations=0,protocolSends=sum(e['direction']=='OUTBOUND' and e.get('samlSummary',{}).get('type')=='AuthnRequest' for e in new),
        totalRunProtocolSends=load(append/'operation-counts.json')['protocolSends'],restored=True))
    print('Grouped original selection prepared',receipt)

def finish(original,install):
    receipt=original.resolve()/'receipt';run=load(receipt/'created.json')['run']['id'];transcript=load(receipt/'transcript.json')
    by_id={entry['id']:entry for entry in transcript}
    if len(by_id)!=len(transcript) or any(e['runId']!=run for e in transcript):raise ValueError('Foreign/duplicate Recorder entry')
    def digest(file):return SHA((receipt/file).read_bytes())
    manifest=dict(schema='samlscope-shibboleth-native-ui-v1',runId=run,targetEntityId='http://localhost:18280/idp/shibboleth',
        targetMetadataSha256=digest('target-metadata.xml'))
    def pin(row,prefix,file):row[prefix+'File']=file;row[prefix+'Sha256']=digest(file)
    for field,file in dict(runtimeBefore='target-runtime-start.json',runtimeAfter='target-runtime-end.json',
        providerOriginal='original-providers.xml',providerConfigured='configured-providers.xml',providerFinal='final-providers.xml',
        nativeClass='native-ui-context.class',nativeClassBefore='native-getter-v3-before.class',nativeClassAfter='native-getter-v3-after.class',
        nativeGetterSource='native-getter-v3-source.java',nativeGetterOutput='native-getter-v3-stdout.txt',
        flowSelection='native-flow-selection.xml',viewInventory='native-view-inventory.txt').items():pin(manifest,field,file)
    manifest['configurationFiles']=[]
    for kind in CONFIG:
        row=dict(kind=kind);pin(row,'original','original-'+kind);pin(row,'final','final-'+kind);manifest['configurationFiles'].append(row)
    manifest['observations']=[]
    for observation in load(receipt/'observations.json'):
        variant=observation['variant'];row=dict(variant=variant,fixtureSha256=observation['fixtureSha256'])
        candidates=[e for e in transcript if e['direction']=='OUTBOUND' and e.get('samlSummary',{}).get('type')=='AuthnRequest'
            and e['samlSummary'].get('variant')==variant and e['samlSummary'].get('metadataSignatureControl')=='valid']
        if variant!='control':
            browser=load(receipt/variant/'browser-original.json');request_id=browser['requests'][0]['requestId']
            candidates=[e for e in candidates if e['samlSummary'].get('id')==request_id]
        if len(candidates)!=1:raise ValueError('Request not uniquely original-bound '+variant)
        request=candidates[0]
        prepared=[e for e in transcript if e['direction']=='OUTBOUND' and e.get('samlSummary',{}).get('type')=='MetadataPrepared'
            and e['samlSummary'].get('variant')==variant and e['samlSummary'].get('metadataSha256')==observation['fixtureSha256']
            and e['timestamp']<=request['timestamp']]
        if len(prepared)!=1:raise ValueError('Metadata not uniquely original-bound '+variant)
        prepared=prepared[0];row.update(metadataReference=prepared['id'],fetchReference=prepared['samlSummary']['fetchTranscriptId'],requestReference=request['id'])
        pin(row,'nativeMetadata',variant+'/native-effective-metadata.xml');pin(row,'nativeValues',variant+'/native-values-v3.json')
        if variant!='control':
            pin(row,'browser',variant+'/browser-original.json');pin(row,'challenge',variant+'/native-challenge.html')
        if variant=='ui-safety-logo-data':pin(row,'slotControl',variant+'/native-slot-control.json')
        row['readBacks']=[]
        for phase in ['before','after']:
            value=load(receipt/variant/(phase+'-readback.json'))
            for field in ['providerFile','fixtureFile']:value[field]=variant+'/'+value[field]
            for file in value['configurationFiles']:file['file']=variant+'/'+file['file']
            row['readBacks'].append(value)
        manifest['observations'].append(row)
    save(receipt/'manifest.json',manifest)
    originals={str(p.relative_to(receipt)):SHA(p.read_bytes()) for p in receipt.rglob('*') if p.is_file()}
    save(original.resolve()/'receipt-originals.json',originals)
    if install:
        remote='/data/ui-url-evidence/'+run
        subprocess.run(['docker','exec','samlscope-reference-suite','mkdir','-p',remote],check=True)
        subprocess.run(['docker','cp',str(receipt)+'/.','samlscope-reference-suite:'+remote],check=True,capture_output=True)
        owner=subprocess.check_output(['docker','exec','samlscope-reference-suite','id','-u']).decode().strip()
        if not owner.isdigit():raise ValueError('Unsafe Suite owner')
        subprocess.run(['docker','exec','--user','0','samlscope-reference-suite','chown','-R',owner+':'+owner,remote],check=True)
        for name,digest in originals.items():
            raw=subprocess.check_output(['docker','exec','samlscope-reference-suite','cat',remote+'/'+name])
            if SHA(raw)!=digest:raise ValueError('Installed read-back differs')
        save(original.resolve()/'receipt-installation.json',dict(runId=run,readBackMatched=True,files=originals))
    print('Original-bound native UI receipt ready',run,'installed',install)

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--evidence',type=Path,required=True)
    parser.add_argument('--append',type=Path);parser.add_argument('--prepare',action='store_true');parser.add_argument('--install',action='store_true')
    args=parser.parse_args()
    if args.prepare:
        if args.append is None:raise ValueError('Append evidence required')
        prepare(args.evidence,args.append)
    else:finish(args.evidence,args.install)
