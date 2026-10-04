#!/usr/bin/env python3
"""Exercise custom attribute encoders and SP-specific release, restoring every modified file."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import urllib.request
import xml.etree.ElementTree as ET

REPO=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(REPO/'dev/keycloak'))
from import_metadata_batch import api,save,BASE
from reference_flow import Client
CONTAINER='samlscope-reference-shibboleth'
XSI='http://www.w3.org/2001/XMLSchema-instance'
CASE='IIP-IDP01-a-idp-01'


def docker(*args,data=None):
    return subprocess.run(['docker','exec','-i',CONTAINER,*args],input=data,stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=True,timeout=90).stdout


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path,required=True);args=parser.parse_args();out=args.output.resolve()
    if out.exists() and any(out.iterdir()):raise ValueError('Evidence directory must be empty')
    out.mkdir(parents=True,exist_ok=True)
    files={name:'/opt/reference-idp/conf/'+name+'.xml' for name in ['metadata-providers','attribute-resolver','attribute-filter']}
    originals={name:docker('cat',path) for name,path in files.items()}
    originals_sha={name:hashlib.sha256(raw).hexdigest() for name,raw in originals.items()}
    records=[];changed=[];reloads=[]
    def write(path,raw,label):
        docker('sh','-c','cat > '+path,data=raw)
        if docker('cat',path)!=raw:raise RuntimeError('Configuration read-back failed')
        records.append(dict(operation='write',label=label,sha256=hashlib.sha256(raw).hexdigest(),read_back=True))
    def reload(service,label):
        log=docker('/opt/reference-idp/bin/reload-service.sh','-id',service,'-u','http://localhost:8080/idp')
        (out/(label+'-reload.log')).write_bytes(log);reloads.append(dict(service=service,label=label))
    plan_result=api('/api/plans',dict(name='Shibboleth arbitrary attribute names and formats',profile='browser_sso_idp',targetKind='IDP',
        targetEntityId='http://localhost:18280/idp/shibboleth',metadataSourceKind='URL',metadataSourceLocation='http://samlscope-reference-shibboleth:8080/idp/shibboleth',
        suiteMetadataDelivery='HTTP_URL',declaredFeatures={},parameters=dict(clockSkewToleranceSeconds=180,metadataRefreshWaitSeconds=300,testUserHint='samlscope-m0-user',requestSigningMode='REQUIRED'),
        interaction=dict(allowBrowserSteps=True,allowAttestation=False,preset='quick'),authorizedTarget=True))
    save(out/'plan.json',plan_result);plan=plan_result['plan']['plan']['id'];entity=BASE+'/p/'+plan
    if not re.fullmatch(r'plan_[0-9A-HJKMNP-TV-Z]{26}',plan):raise ValueError('Invalid plan')
    created=api('/api/plans/'+plan+'/runs',{});save(out/'created.json',created);run=created['run']['id']
    if not re.fullmatch(r'run_[0-9A-HJKMNP-TV-Z]{26}',run):raise ValueError('Invalid Run')
    save(out/'preflight.json',api('/api/runs/'+run+'/preflight',{}))
    temporary='/opt/reference-idp/metadata/attributes-'+run+'.xml'
    if docker('sh','-c','if test -e '+temporary+'; then echo exists; fi').strip():raise ValueError('Temporary metadata already exists')
    with urllib.request.urlopen(BASE+'/p/'+plan+'/metadata',timeout=30) as response:fixture=response.read()
    (out/'fixture.xml').write_bytes(fixture)
    ET.register_namespace('xsi',XSI)
    ns='urn:mace:shibboleth:2.0:metadata';ET.register_namespace('',ns)
    providers=ET.fromstring(originals['metadata-providers'])
    providers.insert(0,ET.Element('{'+ns+'}MetadataProvider',{'id':'Attributes'+run,'{'+XSI+'}type':'FilesystemMetadataProvider','metadataFile':temporary}))
    provider_xml=ET.tostring(providers)
    ns='urn:mace:shibboleth:2.0:resolver';ET.register_namespace('',ns)
    resolver=ET.fromstring(originals['attribute-resolver'])
    ids=['samlscopeCapabilityUrn','samlscopeCapabilityString']
    if any(e.get('id') in ids for e in resolver):raise ValueError('Attribute definitions already exist')
    for id_,name in zip(ids,['urn:samlscope:test:attribute-name','SAMLscope arbitrary attribute']):
        definition=ET.SubElement(resolver,'{'+ns+'}AttributeDefinition',{'id':id_,'{'+XSI+'}type':'Simple'})
        ET.SubElement(definition,'{'+ns+'}InputAttributeDefinition',{'ref':'uid'})
        ET.SubElement(definition,'{'+ns+'}AttributeEncoder',{'{'+XSI+'}type':'SAML2String','name':name,'nameFormat':'urn:samlscope:test:attribute-name-format','encodeType':'false'})
    resolver_xml=ET.tostring(resolver)
    ns='urn:mace:shibboleth:2.0:afp';ET.register_namespace('',ns)
    filters=ET.fromstring(originals['attribute-filter'])
    policy=ET.SubElement(filters,'{'+ns+'}AttributeFilterPolicy',{'id':'AttributeCapability'+run})
    ET.SubElement(policy,'{'+ns+'}PolicyRequirementRule',{'{'+XSI+'}type':'Requester','value':entity})
    for id_ in ids:ET.SubElement(policy,'{'+ns+'}AttributeRule',{'attributeID':id_,'permitAny':'true'})
    filter_xml=ET.tostring(filters)
    temp_written=False
    try:
        temp_written=True;write(temporary,fixture,'temporary-metadata')
        changed.append('metadata-providers');write(files['metadata-providers'],provider_xml,'metadata-providers')
        reload('shibboleth.MetadataResolverService','metadata-import')
        receipt=Client().flow(BASE+'/p/'+plan+'/start/m0-roundtrip?run='+run,None,'samlscope-m0-user','samlscope-m0-password')
        save(out/'control-flow.json',dict(receipt=receipt))
        save(out/'tests-start.json',api('/api/runs/'+run+'/tests/start',{}))
        save(out/'control-protocol-evidence.json',api('/api/runs/'+run+'/protocol-evidence'))
        for name,raw,service in [('attribute-resolver',resolver_xml,'shibboleth.AttributeResolverService'),('attribute-filter',filter_xml,'shibboleth.AttributeFilterService')]:
            changed.append(name);write(files[name],raw,name);reload(service,name)
            if name=='attribute-resolver':reload('shibboleth.AttributeRegistryService','attribute-registry')
        receipt=Client().flow(BASE+'/p/'+plan+'/start/m0-roundtrip?run='+run,None,'samlscope-m0-user','samlscope-m0-password')
        save(out/'custom-flow.json',dict(receipt=receipt))
        save(out/'protocol-evidence-before.json',api('/api/runs/'+run+'/protocol-evidence'))
        save(out/'result-before.json',api('/api/runs/'+run+'/result.json'))
        save(out/(CASE+'-configure.json'),api('/api/runs/'+run+'/cases/'+CASE+'/configure',{'value':'confirmed'}))
    finally:
        failures=[]
        services={'metadata-providers':'shibboleth.MetadataResolverService','attribute-resolver':'shibboleth.AttributeResolverService','attribute-filter':'shibboleth.AttributeFilterService'}
        for name in reversed(changed):
            try:
                write(files[name],originals[name],'restore-'+name);reload(services[name],'restore-'+name)
                if name=='attribute-resolver':reload('shibboleth.AttributeRegistryService','restore-attribute-registry')
            except Exception as error:failures.append(name+':'+type(error).__name__)
        if temp_written:
            try:docker('rm','--',temporary);records.append(dict(operation='delete',label='temporary-metadata'))
            except Exception as error:failures.append('temporary-metadata:'+type(error).__name__)
        final_sha={name:hashlib.sha256(docker('cat',path)).hexdigest() for name,path in files.items()}
        removed=not docker('sh','-c','if test -e '+temporary+'; then echo exists; fi').strip()
        restored=not failures and removed and final_sha==originals_sha
        save(out/'restoration.json',dict(restored=restored,original_sha256=originals_sha,final_sha256=final_sha,temporary_file_removed=removed,failures=failures))
        save(out/'operations.json',dict(run=run,operations=records,reloads=reloads,restored=restored))
        for endpoint in ['result.json','transcript','protocol-evidence']:
            save(out/(endpoint if endpoint.endswith('.json') else endpoint+'.json'),api('/api/runs/'+run+'/'+endpoint))
        if not restored:raise RuntimeError('Restoration failed; result adoption is blocked')
    manifest=[]
    for entry in json.loads((out/'transcript.json').read_text()):
        if not entry.get('decodedSamlRef'):continue
        path=out/'decoded'/(entry['id']+'.xml');path.parent.mkdir(exist_ok=True)
        subprocess.run(['docker','cp','samlscope-reference-suite:/data/'+entry['decodedSamlRef'],str(path)],check=True,stdout=subprocess.DEVNULL)
        manifest.append(dict(id=entry['id'],file=str(path.relative_to(out)),sha256=hashlib.sha256(path.read_bytes()).hexdigest()))
    save(out/'decoded-manifest.json',manifest)
    subprocess.run(['docker','cp','samlscope-reference-suite:/data/target-metadata/'+run+'.xml',str(out/'target-metadata.xml')],check=True)
    print('Run',run,'restored',restored)


if __name__=='__main__':main()
