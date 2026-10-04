#!/usr/bin/env python3
"""Native metadata-only provisioning, default-ACS replacement and obsolete-key control.

All normal configuration is derived by the installed product parser from original
Suite fixtures. The last diagnostic producer deliberately keeps the old native
configuration and is never adopted as a product result. Credentials stay in memory.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import urllib.request
import xml.etree.ElementTree as ET

from persistent_nameid_normal_campaign import (REPO, CONTAINER, IDP, api, save,
    BASE, native, batch, raw, settled)
from metadata_refresh_campaign import RefreshSignatureClient
from import_metadata_batch import flow

VARIANTS=['control','default-acs-first','default-acs-second']
READBACK=r'''
require '/var/simplesamlphp/lib/_autoload.php';
$handler=\SimpleSAML\Metadata\MetaDataStorageHandler::getMetadataHandler();
echo json_encode(['entityId'=>$argv[1],
 'metadata'=>$handler->getMetaData($argv[1],'saml20-sp-remote'),
 'metadataSources'=>\SimpleSAML\Configuration::getInstance()->getArray('metadata.sources'),
 'remoteSha256'=>hash_file('sha256','/var/simplesamlphp/metadata/saml20-sp-remote.php')],JSON_THROW_ON_ERROR);
'''

def sha(raw):return hashlib.sha256(raw).hexdigest()
def metadata_semantics(raw):
    root=ET.fromstring(raw);root.attrib.pop('validUntil',None)
    for child in list(root):
        if child.tag=='{http://www.w3.org/2000/09/xmldsig#}Signature':root.remove(child)
    return ET.tostring(root)
def arm(run,folder,variant):
    state=api('/api/runs/'+run+'/metadata-lab')
    if state['selectedVariant']!=variant:raise ValueError('Unexpected campaign member')
    with urllib.request.urlopen(state['automaticStartUrl'],timeout=30) as response:
        if response.status!=202:raise ValueError('Expected fetch gate')
        response.read()
    with urllib.request.urlopen(state['metadataUrl'],timeout=30) as response:fixture=response.read()
    (folder/'fixture.xml').write_bytes(fixture);save(folder/'state.json',state)
    return state,fixture

def readback(folder,remote,entity,label):
    path=folder/label;path.mkdir()
    current=settled(remote.container_path,remote.expected)
    (path/'configuration.php').write_bytes(current)
    value=subprocess.check_output(['docker','exec',CONTAINER,'php','-r',READBACK,entity],timeout=30)
    (path/'native.json').write_bytes(value)
    if json.loads(value)['remoteSha256']!=sha(current):raise ValueError('Native readback hash differs')
    save(path/'observed.json',dict(recordedAt=datetime.now(timezone.utc).isoformat()))

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True)
    args=p.parse_args();out=args.output.resolve();out.mkdir(parents=True,exist_ok=False)
    remote=batch('saml20-sp-remote.php');(out/'original-sp-config.php').write_bytes(remote.original)
    (out/'native-parser-command.php').write_text(native.PHP)
    (out/'native-readback-command.php').write_text(READBACK)
    (out/'native-parser.php').write_bytes(raw('/var/simplesamlphp/src/SimpleSAML/Metadata/SAMLParser.php'))
    credentials=(os.environ.get('REFERENCE_USERNAME','samlscope-m0-user'),
        os.environ.get('REFERENCE_PASSWORD','samlscope-m0-password'))
    operations=[];records=[];response_originals={};run=None;native_parsers=0;protocol_attempts=0
    save(out/'operations.json',operations)
    try:
        created=api('/api/plans',dict(name='SimpleSAMLphp native metadata replacement',profile='metadata_idp',
            targetKind='IDP',targetEntityId=IDP,metadataSourceKind='URL',
            metadataSourceLocation='http://samlscope-reference-ssp/simplesaml/module.php/saml/idp/metadata',
            suiteMetadataDelivery='HTTP_URL',declaredFeatures={},parameters=dict(clockSkewToleranceSeconds=180,
            metadataRefreshWaitSeconds=300,testUserHint=credentials[0],requestSigningMode='REQUIRED'),
            interaction=dict(allowBrowserSteps=True,allowAttestation=False,preset='quick'),authorizedTarget=True))
        save(out/'plan.json',created);plan=created['plan']['plan']['id'];entity=BASE+'/p/'+plan
        if entity.encode() in remote.original:raise ValueError('Fresh peer already configured')
        created=api('/api/plans/'+plan+'/runs',{});save(out/'created.json',created);run=created['run']['id']
        save(out/'preflight.json',api('/api/runs/'+run+'/preflight',{}))
        save(out/'campaign.json',api('/api/runs/'+run+'/metadata-lab/automatic-polling',dict(variants=VARIANTS,pollingDelaySeconds=0)))
        old_php=None
        for variant in VARIANTS:
            folder=out/variant;folder.mkdir();row=dict(variant=variant,status='incomplete');operations.append(row)
            save(out/'operations.json',operations)
            state,fixture=arm(run,folder,variant)
            native_parsers+=1
            parsed=subprocess.run(['docker','exec','-i',CONTAINER,'php','-r',native.PHP,entity,'default'],
                input=fixture,capture_output=True,timeout=40)
            (folder/'parser.stdout').write_bytes(parsed.stdout);(folder/'parser.stderr').write_bytes(parsed.stderr)
            row['parserReturncode']=parsed.returncode
            if parsed.returncode:raise ValueError('Native parser rejected fixture')
            data=json.loads(parsed.stdout)
            if data['entity_id']!=entity or data['validate_authnrequest'] is not True:raise ValueError('Native SP scope/policy differs')
            remote.apply(data['php'].encode());time.sleep(3)
            if variant=='default-acs-first':old_php=data['php'].encode()
            readback(folder,remote,entity,'before')
            protocol_attempts+=2 if variant=='control' else 1
            flow(run,folder/'flow.json',suite_signature_control=variant=='control',login_inputs=credentials,
                client_factory=lambda **kwargs:RefreshSignatureClient(records,response_originals))
            readback(folder,remote,entity,'after');row['status']='recorded';save(out/'operations.json',operations)
            if variant=='control':save(out/'tests-start.json',api('/api/runs/'+run+'/tests/start',{}))
        # Reissue a valid old-A request without importing its served metadata. B stays accepted.
        folder=out/'obsolete-key';folder.mkdir()
        save(folder/'campaign.json',api('/api/runs/'+run+'/metadata-lab/automatic-polling',dict(variants=['default-acs-first'],pollingDelaySeconds=0)))
        state,fixture=arm(run,folder,'default-acs-first')
        if metadata_semantics(fixture)!=metadata_semantics((out/'default-acs-first/fixture.xml').read_bytes()):
            raise ValueError('Old fixture semantic content changed between campaigns')
        readback(folder,remote,entity,'before');before=api('/api/runs/'+run+'/transcript')
        protocol_attempts+=1
        receipt=RefreshSignatureClient(records,response_originals).flow(state['automaticStartUrl'],None,*credentials)
        save(folder/'flow.json',dict(receipt=receipt,beforeIds=[e['id'] for e in before]))
        readback(folder,remote,entity,'after')
        new=[e for e in api('/api/runs/'+run+'/transcript') if e['id'] not in {e['id'] for e in before}]
        requests=[e for e in new if e['direction']=='OUTBOUND' and e.get('samlSummary',{}).get('type')=='AuthnRequest']
        if len(requests)!=1:raise ValueError('Obsolete-key request ambiguous')
        observed=[r for r in records if r['request_id']==requests[0]['samlSummary']['id']]
        if len(observed)!=1 or observed[0]['native_signature_rejection']!='signature-value-invalid':
            raise ValueError('Explicit obsolete-key signature rejection unavailable')
        record=observed[0];save(folder/'native-rejection.json',record)
        original=response_originals[record['request_id']]
        if sha(original)!=record['response_body_sha256']:raise ValueError('Native rejection original differs')
        (folder/'native-rejection.html').write_bytes(original)
        save(folder/'references.json',dict(requestReference=requests[0]['id']))
        # Actual native stale-configuration producer: retain A instead of B, then the same
        # previously rejected A request can succeed at A's old default endpoint. Diagnostic.
        folder=out/'stale-configuration-producer';folder.mkdir()
        remote.apply(old_php);time.sleep(3);readback(folder,remote,entity,'before')
        protocol_attempts+=1
        flow(run,folder/'flow.json',login_inputs=credentials,
            client_factory=lambda **kwargs:RefreshSignatureClient(records,response_originals))
        readback(folder,remote,entity,'after')
        save(folder/'producer.json',dict(adopted=False,nativeOldConfigurationRetained=True,
            originalFixture='default-acs-first/fixture.xml',expectedAcceptedFixture='default-acs-second/fixture.xml'))
    finally:
        restore=remote.restore();final=settled(remote.container_path,remote.original)
        (out/'final-sp-config.php').write_bytes(final);save(out/'restoration.json',restore)
        save(out/'native-http-observations.json',dict(run=run,records=records,productVerdictAssigned=False))
        for record in records:
            if record['native_signature_rejection']:
                original=response_originals.get(record['request_id'])
                if original is not None:
                    folder=out/'native-rejection-originals';folder.mkdir(exist_ok=True)
                    (folder/(record['request_id']+'.html')).write_bytes(original)
        save(out/'operation-counts.json',dict(productConfigurationWriteAttempts=remote.write_count,
            configurationApplyWrites=remote.applied_count,restorationWrites=remote.restoration_writes,
            nativeParserInvocations=native_parsers,protocolOperationsAttempted=protocol_attempts,
            runCreations=int(run is not None),productRestarts=0,humanOperations=0,restored=restore['restored']))
        if run:
            sys.path.insert(0,str(REPO/'dev/reference-acceptance'));from capture_run_originals import capture
            entries=api('/api/runs/'+run+'/transcript');save(out/'transcript.json',entries);capture(out,run,entries)
            save(out/'result-before.json',api('/api/runs/'+run+'/result.json'))
            save(out/'protocol-evidence-before.json',api('/api/runs/'+run+'/protocol-evidence'))
        if not restore['restored'] or final!=remote.original:raise ValueError('Native restoration failed')
    print(run,'native replacement campaign recorded, including actual stale producer; restored')

if __name__=='__main__':main()
