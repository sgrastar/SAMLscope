#!/usr/bin/env python3
"""Reference-only native SimpleSAMLphp parser import, protocol exercise, and exact restore.

Invokes the installed product's XML validator and metadata parser used by its admin converter.
No Suite XML-to-attribute translation is performed. This is a CLI parser path, not a UI test.
"""
import argparse
import hashlib
import json
import pathlib
import subprocess
import sys
import time
import urllib.request

REPO=pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0,str(REPO/'dev/keycloak'))
from import_metadata_batch import api, save, flow, BASE

PHP = r'''
require '/var/simplesamlphp/lib/_autoload.php';
$xml=stream_get_contents(STDIN);
(new \SimpleSAML\Utils\XML())->checkSAMLMessage($xml,'saml-meta');
$entities=\SimpleSAML\Metadata\SAMLParser::parseDescriptorsString($xml);
$entity=$argv[1];
if (!isset($entities[$entity])) { throw new \RuntimeException('Expected entity missing'); }
$metadata=$entities[$entity]->getMetadata20SP();
if ($metadata===null) { throw new \RuntimeException('SP descriptor missing'); }
// Match the product admin converter's documented static-import output.
unset($metadata['entityDescriptor'],$metadata['expire']);
if (($argv[2] ?? '') === 'encrypt') { $metadata['assertion.encryption'] = true; }
echo json_encode(['entity_id'=>$entity,'validate_authnrequest'=>$metadata['validate.authnrequest']??null,
 'assertion_encryption'=>$metadata['assertion.encryption']??null,
 'php'=>'$metadata['.var_export($entity,true).'] = '.var_export($metadata,true).';']);
'''

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output',type=pathlib.Path,required=True)
    p.add_argument('--variants',required=True)
    p.add_argument('--encrypt-assertions',action='store_true',help='Enable the product assertion.encryption setting for each imported test client')
    p.add_argument('--profile', choices=['metadata_idp','browser_sso_idp'], default='metadata_idp')
    args=p.parse_args();out=args.output.resolve()
    if out.exists() and any(out.iterdir()):raise ValueError('Evidence directory must be empty')
    out.mkdir(parents=True,exist_ok=True)
    variants=args.variants.split(',')
    if variants[0]!='control':raise ValueError('Start with control')
    config=REPO/'build/acceptance/reference-20260914/ssp-config/saml20-sp-remote.php'
    original=config.read_bytes()
    if b'?>' in original:raise ValueError('Unexpected PHP closing tag')
    created=api('/api/plans',dict(name='SimpleSAMLphp native metadata parser batch',profile=args.profile,
        targetKind='IDP',targetEntityId='http://localhost:18380/idp',metadataSourceKind='URL',
        metadataSourceLocation='http://samlscope-reference-ssp/simplesaml/module.php/saml/idp/metadata',
        suiteMetadataDelivery='HTTP_URL',declaredFeatures={},parameters=dict(clockSkewToleranceSeconds=180,
        metadataRefreshWaitSeconds=300,testUserHint='samlscope-m0-user',requestSigningMode='REQUIRED'),
        interaction=dict(allowBrowserSteps=True,allowAttestation=False,preset='quick'),authorizedTarget=True))
    save(out/'plan.json',created);plan=created['plan']['plan']['id'];entity=BASE+'/p/'+plan
    if entity.encode() in original:raise ValueError('Refusing to overwrite an existing entity')
    created=api('/api/plans/'+plan+'/runs',{});save(out/'created.json',created);run=created['run']['id']
    save(out/'preflight.json',api('/api/runs/'+run+'/preflight',{}))
    save(out/'campaign.json',api('/api/runs/'+run+'/metadata-lab/automatic-polling',dict(variants=variants,pollingDelaySeconds=0)))
    operations=[]
    try:
        for variant in variants:
            state=api('/api/runs/'+run+'/metadata-lab')
            if state['selectedVariant']!=variant:raise RuntimeError('Unexpected campaign member')
            folder=out/variant;folder.mkdir()
            record=dict(variant=variant,product='simplesamlphp',import_path='native-parser-cli',status='incomplete')
            try:
                with urllib.request.urlopen(state['automaticStartUrl'],timeout=30) as response:
                    if response.status!=202:raise RuntimeError('Expected fetch gate')
                with urllib.request.urlopen(state['metadataUrl'],timeout=30) as response:fixture=response.read()
                (folder/'fixture.xml').write_bytes(fixture)
                record['fixture_sha256']=hashlib.sha256(fixture).hexdigest()
                parsed=subprocess.run(['docker','exec','-i','samlscope-reference-ssp','php','-r',PHP,entity,'encrypt' if args.encrypt_assertions else 'default'],
                    input=fixture,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=40)
                (folder/'parser.stderr').write_bytes(parsed.stderr)
                if parsed.returncode:raise RuntimeError('Product native parser rejected fixture')
                data=json.loads(parsed.stdout);record['entity_id']=data['entity_id']
                record['validate_authnrequest']=data['validate_authnrequest']
                record['assertion_encryption_override']=args.encrypt_assertions
                record['assertion_encryption']=data['assertion_encryption']
                if args.encrypt_assertions and data['assertion_encryption'] is not True:
                    raise RuntimeError('Product encryption setting was not applied')
                record['parser_output_sha256']=hashlib.sha256(parsed.stdout).hexdigest()
                (folder/'parser-output.json').write_bytes(parsed.stdout)
                configured=original+b'\n'+data['php'].encode()+b'\n'
                config.write_bytes(configured);record['configuration_written']=True
                record['configuration_read_back']=config.read_bytes()==configured
                # The pinned reference image enables OPcache timestamp validation with a
                # two-second revalidation interval. Let Apache observe each new PHP file.
                time.sleep(3)
                record['configuration_settle_seconds']=3
                # Default-ACS requests deliberately omit destination-selection attributes.
                # Their control is the observed destination change after changing metadata;
                # the API's separate signature mutant currently supports ordinary requests only.
                signature_control = not variant.startswith('default-acs-')
                record['signature_control_requested'] = signature_control
                flow(run,folder/'flow.json',suite_signature_control=signature_control)
                record['status']='success'
            except Exception as error:
                record['reason']=str(error)
            finally:
                if record.get('configuration_written'):
                    config.write_bytes(original)
                record['restored']=config.read_bytes()==original
                save(folder/'import.json',record);operations.append(record);save(out/'operations.json',operations)
            print(variant,record['status'],flush=True)
            if not record['restored']:raise RuntimeError('Restore verification failed')
            if variant=='control':
                if record['status']!='success':raise RuntimeError('Baseline failed')
                save(out/'tests-start.json',api('/api/runs/'+run+'/tests/start',{}))
            pending=api('/api/runs/'+run+'/metadata-lab')
            if pending['campaignIndex']==state['campaignIndex']:
                with urllib.request.urlopen(urllib.request.Request(pending['automaticContinueUrl'],data=b''),timeout=30) as response:response.read()
    finally:
        config.write_bytes(original)
        save(out/'restoration.json',dict(restored=config.read_bytes()==original,
            original_sha256=hashlib.sha256(original).hexdigest(),final_sha256=hashlib.sha256(config.read_bytes()).hexdigest()))
        try:save(out/'evaluation.json',api('/api/runs/'+run+'/protocol-evidence/evaluate',{}))
        except Exception as error:save(out/'evaluation-error.json',dict(reason=str(error)))
        for suffix in ['result.json','transcript','protocol-evidence']:
            try:
                with urllib.request.urlopen(BASE+'/api/runs/'+run+'/'+suffix,timeout=30) as response:
                    (out/(suffix if '.' in suffix else suffix+'.json')).write_bytes(response.read())
            except Exception as error:print('Export unavailable',suffix,type(error).__name__)
        print('Run',run,flush=True)

if __name__=='__main__':main()
