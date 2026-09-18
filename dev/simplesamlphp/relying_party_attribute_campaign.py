#!/usr/bin/env python3
"""Native SSP per-RP AttributeCopy experiment; one overlay, exact restore, no verdict."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
import time
import urllib.request as http
import urllib.parse as urls
from configuration_batch import ConfigurationBatch
REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / 'dev/shibboleth'))
from relying_party_attribute_campaign import StopAtAcs, AcsSubmitted, VARIANTS
sys.path.insert(0, str(REPO / 'dev/keycloak'))
from import_metadata_batch import api, save, BASE
from reference_flow import Client
SHA = lambda raw: hashlib.sha256(raw).hexdigest()
PHP = r'''
require '/var/simplesamlphp/lib/_autoload.php';
$xml=stream_get_contents(STDIN);
(new \SimpleSAML\Utils\XML())->checkSAMLMessage($xml,'saml-meta');
$parsed=\SimpleSAML\Metadata\SAMLParser::parseDescriptorsString($xml);
$entities=json_decode($argv[1],true,512,JSON_THROW_ON_ERROR);
$output=[];
foreach($entities as $side=>$entity) {
 if(!isset($parsed[$entity])) throw new \RuntimeException('Missing peer');
 $metadata=$parsed[$entity]->getMetadata20SP();
 if($metadata===null || ($metadata['validate.authnrequest']??null)!==true) throw new \RuntimeException('Unusable peer');
 unset($metadata['entityDescriptor'],$metadata['expire']);
 // Explicit native policy settings; not claims about XML interpretation.
 $metadata['assertion.encryption']=true;
 $metadata['attributes.NameFormat']='urn:oasis:names:tc:SAML:2.0:attrname-format:uri';
 $metadata['authproc']=[50=>['class'=>'core:AttributeCopy','uid'=>[
   'urn:samlscope:test:relying-party:anchor','urn:samlscope:test:relying-party:'.$side]]];
 $output[$side]=['entity_id'=>$entity,'php'=>'$metadata['.var_export($entity,true).'] = '.var_export($metadata,true).';',
 'policy'=>['authproc'=>$metadata['authproc'],'name_format'=>$metadata['attributes.NameFormat'],
 'encryption'=>$metadata['assertion.encryption'],'validate_authnrequest'=>$metadata['validate.authnrequest']]];
}
echo json_encode($output,JSON_THROW_ON_ERROR);
'''
READBACK = r'''
$metadata=[];require '/var/simplesamlphp/metadata/saml20-sp-remote.php';
$entities=json_decode($argv[1],true,512,JSON_THROW_ON_ERROR);$result=[];
foreach($entities as $side=>$entity) {
 if(!isset($metadata[$entity])) throw new \RuntimeException('Missing configured peer');
 $m=$metadata[$entity];$result[$side]=['authproc'=>$m['authproc'],'name_format'=>$m['attributes.NameFormat'],
 'encryption'=>$m['assertion.encryption'],'validate_authnrequest'=>$m['validate.authnrequest']];
}
echo json_encode($result,JSON_THROW_ON_ERROR);
'''


def php(script, entities, raw=None):
    result = subprocess.run(['docker', 'exec', '-i', 'samlscope-reference-ssp', 'php', '-r', script,
        json.dumps(entities)], input=raw, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        timeout=60)
    if result.returncode: raise RuntimeError('Native SSP parser or policy read-back failed')
    return result.stdout


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    out = parser.parse_args().output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    configuration = ConfigurationBatch(REPO / 'build/acceptance/reference-20260914/ssp-config/saml20-sp-remote.php')
    if b'?>' in configuration.original: raise ValueError('Ambiguous native overlay')
    credentials = (os.environ.get('REFERENCE_USERNAME', 'samlscope-m0-user'), os.environ.get('REFERENCE_PASSWORD', 'samlscope-m0-password'))
    login_binding = secrets.token_hex(32)
    plan_result = api('/api/plans', dict(name='SimpleSAMLphp relying-party attributes', profile='browser_sso_idp',
        targetKind='IDP', targetEntityId='http://localhost:18380/idp', metadataSourceKind='URL',
        metadataSourceLocation='http://samlscope-reference-ssp/simplesaml/module.php/saml/idp/metadata',
        suiteMetadataDelivery='HTTP_URL', declaredFeatures={}, parameters=dict(clockSkewToleranceSeconds=180,
        metadataRefreshWaitSeconds=300,testUserHint='samlscope-m0-user',requestSigningMode='REQUIRED'),
        interaction=dict(allowBrowserSteps=True,allowAttestation=False,preset='quick'),authorizedTarget=True))
    save(out / 'plan.json', plan_result)
    plan = plan_result['plan']['plan']['id']
    created = api('/api/plans/' + plan + '/runs', {}); save(out / 'created.json', created)
    run = created['run']['id']
    if not re.fullmatch(r'plan_[0-9A-HJKMNP-TV-Z]{26}',plan) or not re.fullmatch(r'run_[0-9A-HJKMNP-TV-Z]{26}',run):
        raise ValueError('Invalid generated identity')
    entities = {side: BASE + '/p/' + plan + '/metadata-peer/' + variant for side,variant in VARIANTS.items()}
    if any(entity.encode() in configuration.original for entity in entities.values()): raise ValueError('Existing peer collision')
    save(out / 'preflight.json',api('/api/runs/' + run + '/preflight',{}))
    campaign = api('/api/runs/' + run + '/metadata-lab/preloaded',dict(variants=list(VARIANTS.values()))); save(out / 'campaign.json',campaign)
    with http.urlopen(campaign['preloadedMetadataUrl'],timeout=60) as response: raw=response.read()
    (out / 'fixture.xml').write_bytes(raw)
    parsed_raw=php(PHP,entities,raw);(out / 'parser-output.json').write_bytes(parsed_raw)
    parsed=json.loads(parsed_raw)
    expected={side:value['policy'] for side,value in parsed.items()}
    overlay='\n'.join(parsed[side]['php'] for side in ['first','second']).encode()
    (out / 'overlay.php').write_bytes(overlay)
    observations=[]
    try:
        configured_hash=configuration.apply(overlay)
        time.sleep(3)  # Operational OPcache revalidation wait, not a conformance threshold.
        def readback():
            if SHA(configuration.path.read_bytes())!=configured_hash: raise ValueError('Concurrent configuration change')
            actual=json.loads(php(READBACK,entities))
            if actual!=expected: raise ValueError('Native policy read-back differs')
            return dict(configuration_sha256=configured_hash,policies=actual)
        save(out / 'preparation.json',dict(run=run,entity_ids=entities,native=readback(),login_input_binding=login_binding,
            login_provenance='fixed-in-memory-driver-input',authenticated_principal_verified=False,parser_sha256=SHA(parsed_raw),
            fixture_sha256=SHA(raw),overlay_sha256=SHA(overlay),source='native-parser-cli-and-core-AttributeCopy'))
        start=urls.urlsplit(campaign['preloadedStartUrl'])
        for condition,side in [('first','first'),('second','second'),('first-repeat','first')]:
            variant=VARIANTS[side]; index=campaign['preloadedVariants'].index(variant)
            url=urls.urlunsplit(start._replace(path='/p/'+plan+'/start/metadata-preloaded/'+str(index)))
            before={entry['id'] for entry in api('/api/runs/'+run+'/transcript')}
            record=dict(condition=condition,entity_id=entities[side],variant=variant,before=readback(),login_input_binding=login_binding)
            observations.append(record)
            client=Client();client.op=http.build_opener(http.HTTPCookieProcessor(client.jar),StopAtAcs())
            try: record['flow_status']=client.flow(url,None,*credentials)
            except AcsSubmitted as submitted: record.update(flow_status='acs-submitted',http_status=submitted.status)
            finally:
                record['after']=readback()
                record['new_transcript_ids']=[entry['id'] for entry in api('/api/runs/'+run+'/transcript') if entry['id'] not in before]
                save(out/'observations.json',observations)
    finally:
        restoration=configuration.restore(); save(out/'restoration.json',restoration)
        save(out/'operations.json',dict(run=run,restored=restoration['restored'],configuration_settle_seconds=3,
            parser_invocations=1,protocol_starts=len(observations),configuration_write_attempts=restoration['configuration_write_attempts'],verdict_adopted=False))
        entries=api('/api/runs/'+run+'/transcript');save(out/'transcript.json',entries)
        manifest=[]
        for entry in entries:
            ref=entry.get('decodedSamlRef')
            if not ref:continue
            if not re.fullmatch(r'tx_[0-9A-HJKMNP-TV-Z]{26}',entry['id']) or Path(ref).is_absolute() or '..' in Path(ref).parts:
                raise ValueError('Invalid transcript reference')
            path=out/'decoded'/(entry['id']+'.xml');path.parent.mkdir(exist_ok=True)
            subprocess.run(['docker','cp','samlscope-reference-suite:/data/'+ref,str(path)],check=True,stdout=subprocess.DEVNULL)
            manifest.append(dict(id=entry['id'],file=str(path.relative_to(out)),sha256=SHA(path.read_bytes())))
        save(out/'decoded-manifest.json',manifest)
        subprocess.run(['docker','cp','samlscope-reference-suite:/data/target-metadata/'+run+'.xml',str(out/'target-metadata.xml')],check=True,stdout=subprocess.DEVNULL)
    print('Recorded',len(observations),'conditions;',run,'; restored',restoration['restored'],'; no verdict assigned')


if __name__=='__main__':main()
