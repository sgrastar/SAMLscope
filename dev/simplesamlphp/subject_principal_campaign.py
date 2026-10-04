#!/usr/bin/env python3
"""Native principal resolution and target-signed semantic controls, with secret-free evidence."""
import argparse
from datetime import datetime,timezone
import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import time
import urllib.request
import xml.etree.ElementTree as ET

from persistent_nameid_normal_campaign import (REPO,PREFIX,CONTAINER,IDP,FORMAT,api,save,BASE,
    Client,batch,raw,settled,native,ConfigurationBatch)

RESOLVE=r'''
require '/var/simplesamlphp/lib/_autoload.php';
$input=json_decode(stream_get_contents(STDIN),true,512,JSON_THROW_ON_ERROR);
$global=\SimpleSAML\Configuration::getInstance();
$metadata=[];require '/var/simplesamlphp/metadata/saml20-idp-hosted.php';$host=$metadata[$argv[1]];
$auth=\SimpleSAML\Configuration::getConfig('authsources.php')->getArray($host['auth']);
$users=[];foreach($auth['users'] as $key=>$attributes){$parts=explode(':',$key,2);if(count($parts)!==2)throw new \RuntimeException('Native user key invalid');$users[]=['principal'=>$parts[0],'attributes'=>$attributes];}
$source=new \SimpleSAML\Module\exampleauth\Auth\Source\UserPass(['AuthId'=>$host['auth']],$auth);
$login=new ReflectionMethod($source,'login');$login->setAccessible(true);
$results=[];foreach($input['credentials'] as $credential){
 $attributes=$login->invoke($source,$credential['principal'],$credential['password']);
 $filter=new \SimpleSAML\Module\saml\Auth\Process\PersistentNameID(['identifyingAttribute'=>'uid'],null);
 $state=['Source'=>['entityid'=>$argv[1]],'Destination'=>['entityid'=>$argv[2]],'IdPMetadata'=>['entityid'=>$argv[1]],'SPMetadata'=>['entityid'=>$argv[2]],'Attributes'=>$attributes];
 $filter->process($state);$name=$state['saml:NameID']['urn:oasis:names:tc:SAML:2.0:nameid-format:persistent'];
 $results[]=['principal'=>$credential['principal'],'attributes'=>$attributes,'nameId'=>['value'=>$name->getValue(),'format'=>$name->getFormat(),'nameQualifier'=>$name->getNameQualifier(),'spNameQualifier'=>$name->getSPNameQualifier()]];
}
$metadata=[];require '/var/simplesamlphp/metadata/saml20-sp-remote.php';
echo json_encode(['targetEntityId'=>$argv[1],'spEntityId'=>$argv[2],'authenticationSource'=>['id'=>$host['auth'],'class'=>$auth[0],'authproc'=>$auth['authproc']??null,'users'=>$users,'originalSha256'=>hash_file('sha256','/var/simplesamlphp/config/authsources.php')],
 'nativeAuthenticatedPrincipals'=>$results,'hostedAuthproc'=>$host['authproc']??null,'hostedNameIDFormat'=>$host['NameIDFormat']??null,
 'globalAuthproc'=>$global->getOptionalArray('authproc.idp',[]),'peer'=>$metadata[$argv[2]],
 'saltSha256'=>hash('sha256',(new \SimpleSAML\Utils\Config())->getSecretSalt())],JSON_THROW_ON_ERROR);
'''

PRODUCER=r'''
require '/var/simplesamlphp/lib/_autoload.php';
$input=json_decode(stream_get_contents(STDIN),true,512,JSON_THROW_ON_ERROR);
$document=\SAML2\DOMDocumentFactory::fromString($input['response']);$xp=new DOMXPath($document);
$xp->registerNamespace('s','urn:oasis:names:tc:SAML:2.0:assertion');$xp->registerNamespace('d','http://www.w3.org/2000/09/xmldsig#');
foreach(iterator_to_array($xp->query('//d:Signature')) as $signature)$signature->parentNode->removeChild($signature);
$assertion=$xp->query('//s:Assertion')->item(0);$subject=$xp->query('./s:Subject',$assertion)->item(0);
$direct=$xp->query('./s:NameID',$subject)->item(0);$confirmation=$xp->query('./s:SubjectConfirmation',$subject)->item(0);
$kind=$input['kind'];
if($kind==='different-attribute-principal'){$direct->nodeValue=$input['otherPersistent'];}
else{
 $name=$document->createElementNS('urn:oasis:names:tc:SAML:2.0:assertion','saml:NameID');
 $name->setAttribute('Format',$kind==='same-principal-different-format'?'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified':$direct->getAttribute('Format'));
 $name->nodeValue=$kind==='different-confirmation-principal'?$input['otherPersistent']:$input['uid'];
 if($kind!=='same-principal-different-format')$name->setAttribute('SPNameQualifier',$direct->getAttribute('SPNameQualifier'));
 $confirmation->insertBefore($name,$confirmation->firstChild);
 if($kind==='multiple-same-principal-confirmations'){
  $name->setAttribute('Format','urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified');$name->removeAttribute('SPNameQualifier');
  $clone=$confirmation->cloneNode(true);$copy=$xp->query('./s:NameID',$clone)->item(0);
  $copy->nodeValue=$direct->textContent;$copy->setAttribute('Format',$direct->getAttribute('Format'));$copy->setAttribute('SPNameQualifier',$direct->getAttribute('SPNameQualifier'));$subject->appendChild($clone);
 }
}
$key=new \RobRichards\XMLSecLibs\XMLSecurityKey(\RobRichards\XMLSecLibs\XMLSecurityKey::RSA_SHA256,['type'=>'private']);
$key->loadKey('/var/simplesamlphp/cert/server.pem',true);
$certificate=file_get_contents('/var/simplesamlphp/cert/server.crt');
\SAML2\Utils::insertSignature($key,[$certificate],$assertion,$subject);
$response=$document->documentElement;$status=$response->getElementsByTagNameNS('urn:oasis:names:tc:SAML:2.0:protocol','Status')->item(0);
\SAML2\Utils::insertSignature($key,[$certificate],$response,$status);
echo $document->saveXML();
'''

def sha(raw):return hashlib.sha256(raw).hexdigest()
def capture_readback(out,label,configs,entity,credentials):
    folder=out/label;folder.mkdir()
    for name,config in configs.items():
        value=settled(config.container_path,config.expected)
        save(folder/(name+'-hash.json'),dict(sha256=sha(value),bytes=len(value)))
        if name in {'hosted','remote'}:(folder/(name+'.php')).write_bytes(value)
    result=subprocess.run(['docker','exec','-i',CONTAINER,'php','-r',RESOLVE,IDP,entity],
        input=json.dumps(dict(credentials=[dict(principal=u,password=p) for u,p in credentials])).encode(),capture_output=True,timeout=40)
    if result.returncode:raise ValueError('Native principal resolution failed: '+str(result.returncode))
    (folder/'native-resolution.json').write_bytes(result.stdout)
    save(folder/'observed.json',dict(recordedAt=datetime.now(timezone.utc).isoformat()))

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True)
    args=p.parse_args();out=args.output.resolve();out.mkdir(parents=True,exist_ok=False)
    hosted,remote=batch('saml20-idp-hosted.php'),batch('saml20-sp-remote.php')
    salt=ConfigurationBatch(PREFIX/'config-override.php');salt.container_path='/var/simplesamlphp/config/config-override.php'
    auth=ConfigurationBatch(PREFIX/'authsources.php');auth.container_path='/var/simplesamlphp/config/authsources.php'
    configs=dict(hosted=hosted,remote=remote,salt=salt,authsource=auth)
    for label,config in configs.items():
        if raw(config.container_path)!=config.original or b'?>' in config.original:raise ValueError('Native baseline differs')
        if label in {'hosted','remote','salt'}:(out/(label+'-original.php')).write_bytes(config.original)
        save(out/(label+'-original-hash.json'),dict(sha256=sha(config.original),bytes=len(config.original)))
    if b'secretsalt' in salt.original:raise ValueError('Unexpected configured salt baseline')
    for label,path in [('persistent-filter','modules/saml/src/Auth/Process/PersistentNameID.php'),
        ('base-generator','modules/saml/src/BaseNameIDGenerator.php'),('userpass','modules/exampleauth/src/Auth/Source/UserPass.php'),
        ('xml-signer','vendor/simplesamlphp/saml2-legacy/src/SAML2/Utils.php')]:
        (out/('native-'+label+'.php')).write_bytes(raw('/var/simplesamlphp/'+path))
    (out/'native-resolver-command.php').write_text(RESOLVE);(out/'native-producer-command.php').write_text(PRODUCER)
    primary=(os.environ.get('REFERENCE_USERNAME','samlscope-m0-user'),os.environ.get('REFERENCE_PASSWORD','samlscope-m0-password'))
    other=('samlscope-principal-control-'+secrets.token_hex(6),secrets.token_hex(32));secret=secrets.token_hex(32)
    credentials=[primary,other];run=None;flows=[];producer_count=0;parser_count=0
    try:
        salt.apply(("$config['secretsalt'] = "+repr(secret)+';').encode())
        auth.apply(("$config['example-userpass']['users']["+repr(other[0]+':'+other[1])+'] = ["uid" => ['+repr(other[0])+'], "eduPersonAffiliation" => ["member"]];').encode())
        hosted.apply(('$metadata['+repr(IDP)+']["authproc"] = [20 => ["class" => "saml:PersistentNameID", "identifyingAttribute" => "uid"]];\n'
            '$metadata['+repr(IDP)+']["NameIDFormat"] = ['+repr(FORMAT)+'];').encode())
        created=api('/api/plans',dict(name='SimpleSAMLphp native subject principal resolution',profile='browser_sso_idp',
            targetKind='IDP',targetEntityId=IDP,metadataSourceKind='URL',metadataSourceLocation='http://samlscope-reference-ssp/simplesaml/module.php/saml/idp/metadata',
            suiteMetadataDelivery='HTTP_URL',declaredFeatures={},parameters=dict(clockSkewToleranceSeconds=180,metadataRefreshWaitSeconds=300,testUserHint=primary[0],requestSigningMode='REQUIRED'),
            interaction=dict(allowBrowserSteps=True,allowAttestation=False,preset='quick'),authorizedTarget=True))
        save(out/'plan.json',created);plan=created['plan']['plan']['id'];entity=BASE+'/p/'+plan
        if entity.encode() in remote.original:raise ValueError('Fresh SP already configured')
        created=api('/api/plans/'+plan+'/runs',{});save(out/'created.json',created);run=created['run']['id']
        save(out/'preflight.json',api('/api/runs/'+run+'/preflight',{}))
        with urllib.request.urlopen(entity+'/metadata',timeout=30) as response:fixture=response.read()
        (out/'fixture.xml').write_bytes(fixture);parser_count+=1
        parsed=subprocess.run(['docker','exec','-i',CONTAINER,'php','-r',native.PHP,entity,'default'],input=fixture,capture_output=True,timeout=40)
        (out/'parser.stdout').write_bytes(parsed.stdout);(out/'parser.stderr').write_bytes(parsed.stderr)
        if parsed.returncode:raise ValueError('Native metadata parser failed')
        data=json.loads(parsed.stdout)
        if data['entity_id']!=entity or data['validate_authnrequest'] is not True:raise ValueError('Native accepted peer differs')
        remote.apply(data['php'].encode());time.sleep(3)
        capture_readback(out,'before',configs,entity,credentials)
        for user,password in credentials:
            for iteration in range(2):
                before={e['id'] for e in api('/api/runs/'+run+'/transcript')};row=dict(principal=user,iteration=iteration,attempted=True);flows.append(row);save(out/'flows.json',flows)
                row['receipt']=Client().flow(entity+'/start/m0-roundtrip?run='+run,None,user,password)
                row['transcriptIds']=[e['id'] for e in api('/api/runs/'+run+'/transcript') if e['id'] not in before];save(out/'flows.json',flows)
                if row['receipt']!='recorded':raise ValueError('Native normal principal flow not recorded')
        capture_readback(out,'after',configs,entity,credentials)
        save(out/'tests-start.json',api('/api/runs/'+run+'/tests/start',{}))
        sys.path.insert(0,str(REPO/'dev/reference-acceptance'));from capture_run_originals import capture
        entries=api('/api/runs/'+run+'/transcript');save(out/'transcript.json',entries);capture(out,run,entries)
        primary_response=[e for e in entries if e['id'] in flows[0]['transcriptIds'] and e['direction']=='INBOUND'][0]
        source=(out/'decoded'/(primary_response['id']+'.xml')).read_bytes()
        mappings=json.loads((out/'before/native-resolution.json').read_bytes())['nativeAuthenticatedPrincipals']
        for kind in ['same-principal-different-format','multiple-same-principal-confirmations','different-confirmation-principal','different-attribute-principal']:
            producer_count+=1
            payload=dict(response=source.decode(),kind=kind,uid=mappings[0]['attributes']['uid'][0],otherPersistent=mappings[1]['nameId']['value'])
            result=subprocess.run(['docker','exec','-i',CONTAINER,'php','-r',PRODUCER],input=json.dumps(payload).encode(),capture_output=True,timeout=40)
            if result.returncode:raise ValueError('Native signed producer failed: '+str(result.returncode))
            (out/(kind+'.xml')).write_bytes(result.stdout)
        save(out/'producer.json',dict(baseResponseReference=primary_response['id'],baseResponseSha256=sha(source),
            nativePrivateKeyExported=False,controlsAdopted=False,commandSha256=sha(PRODUCER.encode())))
    finally:
        restoration={}
        for label,config in reversed(list(configs.items())):
            restored=config.restore();final=settled(config.container_path,config.original)
            restored['nativeFinalSha256']=sha(final);restored['bytesEqual']=final==config.original
            restoration[label]=restored
            if label in {'hosted','remote','salt'}:(out/(label+'-final.php')).write_bytes(final)
        save(out/'restoration.json',restoration);save(out/'flows.json',flows)
        save(out/'operation-counts.json',dict(productConfigurationWriteAttempts=sum(c.write_count for c in configs.values()),
            configurationApplyWrites=sum(c.applied_count for c in configs.values()),restorationWrites=sum(c.restoration_writes for c in configs.values()),
            nativeParserInvocations=parser_count,normalFlowsAttempted=len(flows),nativeSignedProducerInvocations=producer_count,
            runCreations=int(run is not None),productRestarts=0,humanOperations=0,restored=all(r['restored'] and r['bytesEqual'] for r in restoration.values())))
        if run:
            save(out/'result-before.json',api('/api/runs/'+run+'/result.json'));save(out/'protocol-evidence-before.json',api('/api/runs/'+run+'/protocol-evidence'))
        for path in out.rglob('*'):
            if path.is_file() and any(value.encode() in path.read_bytes() for value in [other[1],secret]):raise ValueError('Ephemeral secret found in evidence')
        if not all(r['restored'] and r['bytesEqual'] for r in restoration.values()):raise ValueError('Native restore failed')
    print(run,'native principal originals and signed controls recorded; all 4 files restored')

if __name__=='__main__':main()
