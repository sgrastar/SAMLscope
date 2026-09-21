#!/usr/bin/env python3
"""Run independent signing configurations through an isolated native relying-party override, then restore."""
import argparse
import hashlib
import os
from pathlib import Path
import re
import sys
import urllib.request
import xml.etree.ElementTree as ET
from attribute_name_capability import docker, api, save, BASE, Client, REPO, XSI
sys.path.insert(0,str(REPO/'dev/reference-acceptance'))
from capture_run_originals import capture

SHA = lambda raw: hashlib.sha256(raw).hexdigest()
BEANS='http://www.springframework.org/schema/beans'
UTIL='http://www.springframework.org/schema/util'
P='http://www.springframework.org/schema/p'
C='http://www.springframework.org/schema/c'
MD='urn:mace:shibboleth:2.0:metadata'
PHASES=[('both',True,True),('assertion-only',False,True),('response-only',True,False)]


def relying_party(original, entity, run, response_signed, assertion_signed):
    for prefix,uri in [('',BEANS),('util',UTIL),('p',P),('c',C),('xsi',XSI)]: ET.register_namespace(prefix,uri)
    tree=ET.fromstring(original)
    candidates=[e for e in tree.findall('{'+UTIL+'}list') if e.get('id')=='shibboleth.RelyingPartyOverrides']
    if len(candidates)!=1: raise ValueError('Ambiguous native override container')
    override=ET.SubElement(candidates[0],'{'+BEANS+'}bean',dict(id='SignatureModes'+run,parent='RelyingPartyByName'))
    override.set('{'+C+'}relyingPartyIds',entity)
    prop=ET.SubElement(override,'{'+BEANS+'}property',dict(name='profileConfigurations'))
    values=ET.SubElement(prop,'{'+BEANS+'}list')
    profile=ET.SubElement(values,'{'+BEANS+'}bean',dict(parent='SAML2.SSO'))
    for name,value in [('signResponses',response_signed),('signAssertions',assertion_signed),('encryptAssertions',False)]:
        profile.set('{'+P+'}'+name,str(value).lower())
    return ET.tostring(tree)


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path,required=True)
    out=parser.parse_args().output.resolve();out.mkdir(parents=True,exist_ok=False)
    provider_path='/opt/reference-idp/conf/metadata-providers.xml'; rp_path='/opt/reference-idp/conf/relying-party.xml'
    originals={path:docker('cat',path) for path in [provider_path,rp_path]}; expected=dict(originals)
    operations=[];phases=[];temporary_written=False;changed=[]
    created=api('/api/plans',dict(name='Shibboleth native signature modes',profile='browser_sso_idp',
        targetKind='IDP',targetEntityId='http://localhost:18280/idp/shibboleth',metadataSourceKind='URL',
        metadataSourceLocation='http://samlscope-reference-shibboleth:8080/idp/shibboleth',
        suiteMetadataDelivery='HTTP_URL',declaredFeatures={},parameters=dict(clockSkewToleranceSeconds=180,
        metadataRefreshWaitSeconds=300,testUserHint='samlscope-m0-user',requestSigningMode='REQUIRED'),
        interaction=dict(allowBrowserSteps=True,allowAttestation=False,preset='quick'),authorizedTarget=True))
    save(out/'plan.json',created);plan=created['plan']['plan']['id'];entity=BASE+'/p/'+plan
    if not re.fullmatch(r'plan_[0-9A-HJKMNP-TV-Z]{26}',plan):raise ValueError('Invalid plan')
    if any(entity.encode() in raw for raw in originals.values()):raise ValueError('Existing SP cannot be overwritten')
    created=api('/api/plans/'+plan+'/runs',{});save(out/'created.json',created);run=created['run']['id']
    if not re.fullmatch(r'run_[0-9A-HJKMNP-TV-Z]{26}',run):raise ValueError('Invalid Run')
    save(out/'preflight.json',api('/api/runs/'+run+'/preflight',{}))
    with urllib.request.urlopen(entity+'/metadata?variant=signature-modes-optional&run='+run,timeout=30) as response:fixture=response.read()
    (out/'fixture.xml').write_bytes(fixture)
    role=ET.fromstring(fixture).find('{urn:oasis:names:tc:SAML:2.0:metadata}SPSSODescriptor')
    if role is None or role.get('WantAssertionsSigned')!='false':raise ValueError('Optional-signing metadata required')
    temporary='/opt/reference-idp/metadata/signature-modes-'+run+'.xml'
    if docker('sh','-c','if test -e '+temporary+'; then echo exists; fi').strip():raise ValueError('Temporary metadata exists')
    def write(path,raw,label):
        if path in expected and docker('cat',path)!=expected[path]:raise RuntimeError('Concurrent configuration change')
        row=dict(operation='write',label=label,attempted=True,read_back=False);operations.append(row)
        if path in expected and path not in changed:changed.append(path)
        docker('sh','-c','cat > '+path,data=raw)
        if docker('cat',path)!=raw:raise RuntimeError('Configuration readback mismatch')
        if path in expected:expected[path]=raw
        row.update(read_back=True,sha256=SHA(raw))
    def reload(service,label):
        row=dict(operation='reload',service=service,label=label,attempted=True,completed=False);operations.append(row)
        log=docker('/opt/reference-idp/bin/reload-service.sh','-id',service,'-u','http://localhost:8080/idp')
        (out/(label+'-reload.log')).write_bytes(log);row['completed']=True
    try:
        temporary_written=True;write(temporary,fixture,'temporary-metadata')
        ET.register_namespace('',MD);ET.register_namespace('xsi',XSI)
        tree=ET.fromstring(originals[provider_path]);provider=ET.Element('{'+MD+'}MetadataProvider',dict(id='SignatureModes'+run,metadataFile=temporary))
        provider.set('{'+XSI+'}type','FilesystemMetadataProvider');tree.insert(0,provider)
        write(provider_path,ET.tostring(tree),'metadata-provider');reload('shibboleth.MetadataResolverService','metadata-provider')
        for mode,response_signed,assertion_signed in PHASES:
            folder=out/mode;folder.mkdir()
            configured=relying_party(originals[rp_path],entity,run,response_signed,assertion_signed)
            write(rp_path,configured,mode);reload('shibboleth.RelyingPartyResolverService',mode)
            before={e['id'] for e in api('/api/runs/'+run+'/transcript')}
            receipt=Client().flow(entity+'/start/m0-roundtrip?run='+run,None,
                os.environ.get('REFERENCE_USERNAME','samlscope-m0-user'),os.environ.get('REFERENCE_PASSWORD','samlscope-m0-password'))
            after=api('/api/runs/'+run+'/transcript')
            row=dict(phase=mode,requested=dict(response_signed=response_signed,assertion_signed=assertion_signed,encrypted=False),
                receipt=receipt,configuration_sha256=SHA(configured),configuration_readback=True,
                added_transcripts=[e['id'] for e in after if e['id'] not in before],verdict_adopted=False)
            phases.append(row);save(folder/'flow.json',row)
            if receipt!='recorded':raise RuntimeError('Native signing flow did not complete')
            print(mode,'recorded',flush=True)
        save(out/'tests-start.json',api('/api/runs/'+run+'/tests/start',{}))
        save(out/'evaluation.json',api('/api/runs/'+run+'/protocol-evidence/evaluate',{}))
        save(out/'result.json',api('/api/runs/'+run+'/result.json'))
    finally:
        failures=[]
        for path,service,label in [(rp_path,'shibboleth.RelyingPartyResolverService','restore-relying-party'),
                                    (provider_path,'shibboleth.MetadataResolverService','restore-provider')]:
            if path not in changed:continue
            try:write(path,originals[path],label);reload(service,label)
            except Exception as error:failures.append(dict(path=path,error=type(error).__name__))
        if temporary_written and not failures:
            operations.append(dict(operation='delete',label='temporary-metadata',attempted=True));docker('rm','--',temporary)
        removed=not docker('sh','-c','if test -e '+temporary+'; then echo exists; fi').strip()
        restored=not failures and removed and all(docker('cat',path)==raw for path,raw in originals.items())
        save(out/'restoration.json',dict(restored=restored,temporary_removed=removed,failures=failures,
            original_sha256={path:SHA(raw) for path,raw in originals.items()},final_sha256={path:SHA(docker('cat',path)) for path in originals}))
        save(out/'operations.json',dict(run=run,phases=phases,operations=operations,restored=restored,product_restarts=0,human_operations=0))
        entries=api('/api/runs/'+run+'/transcript');save(out/'transcript.json',entries);capture(out,run,entries)
        if not restored:raise RuntimeError('Native configuration restoration incomplete')
    print('Run',run,'native configuration restored; formal results require evidence audit')


if __name__=='__main__':main()
