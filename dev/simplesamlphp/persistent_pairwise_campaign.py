#!/usr/bin/env python3
"""Native two-SP persistent identifiers; signed uid proves one identifying principal.

Both fresh SPs use original Suite metadata consumed by the installed product parser.
The short normal flow is used twice per SP, with one native generator and salt held
unchanged across all operations. Credentials and the ephemeral salt stay in memory.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess
import time
import urllib.request

from persistent_nameid_normal_campaign import (REPO, PREFIX, CONTAINER, IDP, FORMAT,
    api, save, BASE, Client, batch, raw, settled, native, ConfigurationBatch)

READBACK=r'''
require '/var/simplesamlphp/lib/_autoload.php';
$global=\SimpleSAML\Configuration::getInstance();
$metadata=[];require '/var/simplesamlphp/metadata/saml20-idp-hosted.php';
$host=$metadata[$argv[1]];
$auth=\SimpleSAML\Configuration::getConfig('authsources.php')->getArray($host['auth']);
$users=[];foreach($auth['users']??[] as $key=>$attributes){$parts=explode(':',$key,2);if(count($parts)!==2)throw new \RuntimeException('Invalid native user key');$users[]=['principal'=>$parts[0],'uid'=>$attributes['uid']??null];}
$remote=[];$metadata=[];require '/var/simplesamlphp/metadata/saml20-sp-remote.php';
foreach(array_slice($argv,2) as $entity){if(!isset($metadata[$entity]))throw new \RuntimeException('Missing native SP');$remote[$entity]=$metadata[$entity];}
echo json_encode(['entityId'=>$argv[1], 'hostedAuthproc'=>$host['authproc']??null,
 'hostedNameIDFormat'=>$host['NameIDFormat']??null,
 'globalAuthproc'=>$global->getOptionalArray('authproc.idp',[]), 'peers'=>$remote,
 'authenticationSource'=>['id'=>$host['auth'],'class'=>$auth[0]??null,'users'=>$users,
   'authproc'=>$auth['authproc']??null,'originalSha256'=>hash_file('sha256','/var/simplesamlphp/config/authsources.php')],
 'saltSha256'=>hash('sha256',(new \SimpleSAML\Utils\Config())->getSecretSalt())],JSON_THROW_ON_ERROR);
'''

def sha(raw):return hashlib.sha256(raw).hexdigest()
def capture_readback(out, label, hosted, remote, salt, peers):
    folder=out/label;folder.mkdir()
    for name,config in [('hosted',hosted),('remote',remote),('salt',salt)]:
        value=settled(config.container_path,config.expected)
        if name!='salt':(folder/(name+'.php')).write_bytes(value)
        save(folder/(name+'-hash.json'),dict(sha256=sha(value),bytes=len(value)))
    value=subprocess.check_output(['docker','exec',CONTAINER,'php','-r',READBACK,IDP,*peers],timeout=30)
    (folder/'native.json').write_bytes(value)
    save(folder/'observed.json',dict(recordedAt=datetime.now(timezone.utc).isoformat()))

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True)
    p.add_argument('--same-value-mutant',action='store_true')
    args=p.parse_args();out=args.output.resolve();out.mkdir(parents=True,exist_ok=False)
    save(out/'campaign.json',dict(case='IIP-SSO05-a3-idp-01',sameValueMutant=args.same_value_mutant,adopted=False))
    (out/'native-readback-command.php').write_text(READBACK)
    hosted,remote=batch('saml20-idp-hosted.php'),batch('saml20-sp-remote.php')
    salt=ConfigurationBatch(PREFIX/'config-override.php');salt.container_path='/var/simplesamlphp/config/config-override.php'
    if b'secretsalt' in salt.original or raw(salt.container_path)!=salt.original:raise ValueError('Unexpected salt override baseline')
    for name,config in [('hosted',hosted),('remote',remote),('salt',salt)]: (out/(name+'-original.php')).write_bytes(config.original)
    for name,path in [('persistent-filter','/var/simplesamlphp/modules/saml/src/Auth/Process/PersistentNameID.php'),
      ('base-generator','/var/simplesamlphp/modules/saml/src/BaseNameIDGenerator.php'),
      ('attribute-generator','/var/simplesamlphp/modules/saml/src/Auth/Process/AttributeNameID.php')]:
        (out/('native-'+name+'.php')).write_bytes(raw(path))
    (out/'native-userpass.php').write_bytes(raw('/var/simplesamlphp/modules/exampleauth/src/Auth/Source/UserPass.php'))
    operations=[];save(out/'operations.json',operations);peers=[]
    credentials=(os.environ.get('REFERENCE_USERNAME','samlscope-m0-user'),os.environ.get('REFERENCE_PASSWORD','samlscope-m0-password'))
    secret=secrets.token_hex(32)
    try:
        salt.apply(("$config['secretsalt'] = "+repr(secret)+';').encode());settled(salt.container_path,salt.expected)
        filter='saml:AttributeNameID' if args.same_value_mutant else 'saml:PersistentNameID'
        filter_text='["class" => '+repr(filter)+', "identifyingAttribute" => "uid"'+(', "Format" => '+repr(FORMAT) if args.same_value_mutant else '')+']'
        overlay=('$metadata['+repr(IDP)+']["authproc"] = [20 => '+filter_text+'];\n'
          '$metadata['+repr(IDP)+']["NameIDFormat"] = ['+repr(FORMAT)+'];\n').encode()
        hosted.apply(overlay);(out/'hosted-configured.php').write_bytes(settled(hosted.container_path,hosted.expected))
        chunks=[]
        for label in ['primary','secondary']:
            folder=out/label;folder.mkdir();row=dict(peer=label,status='incomplete',normalFlowsAttempted=0);operations.append(row);save(out/'operations.json',operations)
            created=api('/api/plans',dict(name='SimpleSAMLphp native persistent pairwise '+label,profile='browser_sso_idp',
              targetKind='IDP',targetEntityId=IDP,metadataSourceKind='URL',metadataSourceLocation='http://samlscope-reference-ssp/simplesaml/module.php/saml/idp/metadata',
              suiteMetadataDelivery='HTTP_URL',declaredFeatures={},parameters=dict(clockSkewToleranceSeconds=180,metadataRefreshWaitSeconds=300,testUserHint=credentials[0],requestSigningMode='REQUIRED'),
              interaction=dict(allowBrowserSteps=True,allowAttestation=False,preset='quick'),authorizedTarget=True))
            save(folder/'plan.json',created);plan=created['plan']['plan']['id'];entity=BASE+'/p/'+plan
            if entity.encode() in remote.original:raise ValueError('Fresh peer already configured')
            created=api('/api/plans/'+plan+'/runs',{});save(folder/'created.json',created);run=created['run']['id'];row.update(run=run,entityId=entity);peers.append(entity)
            save(folder/'preflight.json',api('/api/runs/'+run+'/preflight',{}))
            with urllib.request.urlopen(entity+'/metadata',timeout=30) as response:fixture=response.read()
            (folder/'fixture.xml').write_bytes(fixture)
            parsed=subprocess.run(['docker','exec','-i',CONTAINER,'php','-r',native.PHP,entity,'default'],input=fixture,capture_output=True,timeout=40)
            (folder/'parser.stdout').write_bytes(parsed.stdout);(folder/'parser.stderr').write_bytes(parsed.stderr);row['nativeParserReturncode']=parsed.returncode
            if parsed.returncode:raise ValueError('Native parser failed')
            data=json.loads(parsed.stdout)
            if data['entity_id']!=entity or data['validate_authnrequest'] is not True:raise ValueError('Native SP identity/signature policy differs')
            chunks.append(data['php'].encode());save(out/'operations.json',operations)
        remote.apply(b'\n'.join(chunks));(out/'remote-configured.php').write_bytes(settled(remote.container_path,remote.expected))
        time.sleep(3)
        for row in operations:
            folder=out/row['peer'];capture_readback(out,row['peer']+'-before',hosted,remote,salt,peers)
            receipts=[]
            for _ in range(2):
                row['normalFlowsAttempted']+=1;save(out/'operations.json',operations)
                receipt=Client().flow(row['entityId']+'/start/m0-roundtrip?run='+row['run'],None,*credentials)
                receipts.append(receipt);save(folder/'flows.json',receipts)
                if receipt!='recorded':raise ValueError('Native persistent normal flow not recorded')
            capture_readback(out,row['peer']+'-after',hosted,remote,salt,peers)
            save(folder/'tests-start.json',api('/api/runs/'+row['run']+'/tests/start',{}))
            save(folder/'evaluation.json',api('/api/runs/'+row['run']+'/protocol-evidence/evaluate',{}))
            row['status']='recorded';save(out/'operations.json',operations)
    finally:
        restoration={}
        for name,config in [('remote',remote),('hosted',hosted),('salt',salt)]:
            restoration[name]=config.restore();final=settled(config.container_path,config.original);(out/(name+'-final.php')).write_bytes(final)
            if final!=config.original:restoration[name]['restored']=False
        save(out/'restoration.json',restoration)
        save(out/'operation-counts.json',dict(productConfigurationWriteAttempts=hosted.write_count+remote.write_count+salt.write_count,
          configurationApplyWrites=hosted.applied_count+remote.applied_count+salt.applied_count,restorationWrites=hosted.restoration_writes+remote.restoration_writes+salt.restoration_writes,
          nativeParserInvocations=sum('nativeParserReturncode' in row for row in operations),normalFlowsAttempted=sum(row['normalFlowsAttempted'] for row in operations),
          runCreations=sum('run' in row for row in operations),productRestarts=0,humanOperations=0,restored=all(v['restored'] for v in restoration.values())))
        import sys;sys.path.insert(0,str(REPO/'dev/reference-acceptance'));from capture_run_originals import capture
        for row in operations:
            if 'run' not in row:continue
            folder=out/row['peer'];run=row['run']
            for suffix in ['transcript','result.json','protocol-evidence']:
                try:save(folder/(suffix if '.' in suffix else suffix+'.json'),api('/api/runs/'+run+'/'+suffix))
                except Exception as error:save(folder/(suffix.replace('.','-')+'-error.json'),dict(error=str(error)))
            capture(folder,run,api('/api/runs/'+run+'/transcript'))
            subprocess.run(['docker','cp','samlscope-reference-suite:/data/target-metadata/'+run+'.xml',str(folder/'target-metadata.xml')],check=True,capture_output=True)
        if not all(v['restored'] for v in restoration.values()):raise ValueError('Exact native restoration failed')
        if any(secret.encode() in path.read_bytes() for path in out.rglob('*') if path.is_file()):raise ValueError('Ephemeral salt leaked')
    print('Native pairwise campaign recorded; all 3 configuration files exactly restored')

if __name__=='__main__':main()
