#!/usr/bin/env python3
"""Bind captured native identity controls to original Recorder entries; no verdict."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import xml.etree.ElementTree as ET

SHA=lambda raw:hashlib.sha256(raw).hexdigest()
P='urn:oasis:names:tc:SAML:2.0:protocol'
S='urn:oasis:names:tc:SAML:2.0:assertion'


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence',type=Path,required=True)
    parser.add_argument('--install',action='store_true')
    args=parser.parse_args();out=args.evidence.resolve();child=out/'browser'
    restoration=json.loads((out/'restoration.json').read_text())
    if restoration.get('restored') is not True:raise ValueError('Native restoration not verified')
    campaign=json.loads((out/'campaign.json').read_text());run=campaign['runId']
    if not re.fullmatch(r'run_[0-9A-HJKMNP-TV-Z]{26}',run):raise ValueError('Unsafe Run')
    entries=json.loads((child/'transcript.json').read_text());body={}
    for entry in entries:
        if entry['runId']!=run:raise ValueError('Foreign transcript')
        if not entry.get('decodedSamlRef'):continue
        raw=(child/'decoded'/(entry['id']+'.xml')).read_bytes()
        if len(raw)!=entry['decodedSamlBytes']:raise ValueError('Original size mismatch')
        body[entry['id']]=ET.fromstring(raw)
    responses=[e for e in entries if e['direction']=='INBOUND' and e.get('samlSummary',{}).get('type')=='Response']
    if len(responses)!=2:raise ValueError('Expected exactly positive and unable original responses')
    exchanges={}
    for response in responses:
        root=body[response['id']];request_id=root.get('InResponseTo')
        requests=[e for e in entries if e['direction']=='OUTBOUND' and body.get(e['id']) is not None
                  and body[e['id']].tag=='{'+P+'}AuthnRequest' and body[e['id']].get('ID')==request_id]
        if len(requests)!=1:raise ValueError('Original request not uniquely correlated')
        request=requests[0];request_root=body[request['id']]
        name='unable' if request_root.get('IsPassive') in {'true','1'} else 'positive'
        if name in exchanges:raise ValueError('Duplicate native control')
        exchanges[name]=dict(requestReference=request['id'],responseReference=response['id'])
    if set(exchanges)!={'positive','unable'}:raise ValueError('Missing native control')
    receipt=out/'receipt';receipt.mkdir(exist_ok=True)
    def copy(source,name):
        raw=source.read_bytes();(receipt/name).write_bytes(raw);return name,SHA(raw)
    manifest=dict(schema='samlscope-shibboleth-authentication-identity-v1',runId=run,
        targetEntityId='http://localhost:18280/idp/shibboleth',
        targetMetadataSha256=SHA((child/'target-metadata.xml').read_bytes()),
        completedAt=datetime.now(timezone.utc).isoformat(),**exchanges)
    manifest['spMetadataFile'],manifest['spMetadataSha256']=copy(out/'native-effective-sp-metadata.xml','native-effective-sp-metadata.xml')
    manifest['spMetadataReadFile'],manifest['spMetadataReadSha256']=copy(out/'native-effective-sp-metadata-read.json','native-effective-sp-metadata-read.json')
    manifest['auditFile'],manifest['auditSha256']=copy(out/'native-identity-audit.log','native-identity-audit.log')
    challenge=child/'authentication-challenge'
    manifest['challengeFile'],manifest['challengeSha256']=copy(challenge/'native-challenge.json','native-challenge.json')
    copy(challenge/'native-challenge.html','native-challenge.html')
    manifest['operationsFile'],manifest['operationsSha256']=copy(out/'operations.json','operations.json')
    manifest['parentPropertiesFile'],manifest['parentPropertiesSha256']=copy(out/'original-parent-authn.properties','original-parent-authn.properties')
    manifest['parentPropertiesFinalFile'],manifest['parentPropertiesFinalSha256']=copy(out/'final-parent-authn.properties','final-parent-authn.properties')
    manifest['customFlowInventoryFile'],manifest['customFlowInventorySha256']=copy(out/'native-custom-flow-inventory.txt','native-custom-flow-inventory.txt')
    for field,kind in [('flowDescriptors','flow-descriptors'),('flowSelection','flow-selection'),('conditions','conditions')]:
        manifest[field+'File'],manifest[field+'Sha256']=copy(out/('native-'+kind+'.xml'),'native-'+kind+'.xml')
    readbacks=json.loads((out/'readbacks.json').read_text());files=[]
    for kind in ['authn-properties','password-validator','global','relying-party','providers','audit',
                 'condition-base','condition-locked','condition-expired','condition-expiring']:
        row=dict(kind=kind)
        for field,phase in [('original','original'),('configured','configured'),('final','final')]:
            row[field+'File'],row[field+'Sha256']=copy(out/(phase+'-'+kind),phase+'-'+kind)
        row['readBacks']=[]
        for phase in ['before','after']:
            matches=[r for r in readbacks if r['kind']==kind and r['phase']==phase]
            if len(matches)!=1:raise ValueError('Native readback missing')
            back=matches[0];name,digest=copy(out/back['file'],back['file'])
            if digest!=back['sha256'] or digest!=row['configuredSha256']:raise ValueError('Native readback differs')
            row['readBacks'].append(dict(phase=phase,file=name,sha256=digest,recordedAt=back['recordedAt']))
        if row['originalSha256']!=row['finalSha256']:raise ValueError('Native restoration differs')
        files.append(row)
        if kind.startswith('condition-'):
            row['packagedOriginalFile'],row['packagedOriginalSha256']=copy(out/('native-'+kind+'.xml'),'native-'+kind+'.xml')
            if row['configuredSha256']!=row['packagedOriginalSha256']:raise ValueError('Condition flow differs from native package original')
    manifest['configurationFiles']=files;manifest['parentPropertiesReadBacks']=[]
    for phase in ['before','after']:
        name,digest=copy(out/(phase+'-parent-authn.properties'),phase+'-parent-authn.properties')
        times=[r['recordedAt'] for r in readbacks if r['phase']==phase]
        manifest['parentPropertiesReadBacks'].append(dict(phase=phase,file=name,sha256=digest,
            recordedAt=min(times) if phase=='before' else max(times)))
    raw=(json.dumps(manifest,indent=2)+'\n').encode();(receipt/'manifest.json').write_bytes(raw)
    originals={p.name:SHA(p.read_bytes()) for p in receipt.iterdir() if p.is_file()}
    (out/'receipt-originals.json').write_text(json.dumps(originals,indent=2)+'\n')
    if args.install:
        remote='/data/authentication-identity-evidence/'+run
        subprocess.run(['docker','exec','samlscope-reference-suite','mkdir','-p',remote],check=True)
        for path in receipt.iterdir():
            if not path.is_file() or path.is_symlink():raise ValueError('Unsafe original')
            subprocess.run(['docker','cp',str(path),'samlscope-reference-suite:'+remote+'/'+path.name],check=True,stdout=subprocess.DEVNULL)
            actual=subprocess.run(['docker','exec','samlscope-reference-suite','cat',remote+'/'+path.name],check=True,stdout=subprocess.PIPE).stdout
            if SHA(actual)!=originals[path.name]:raise ValueError('Installed read-back differs')
        (out/'receipt-installation.json').write_text(json.dumps(dict(runId=run,files=originals,readBackMatched=True),indent=2)+'\n')
    print('Native identity receipt prepared:',run,'files',len(originals),'installed',args.install)


if __name__=='__main__':main()
