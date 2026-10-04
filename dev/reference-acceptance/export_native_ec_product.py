#!/usr/bin/env python3
"""Bind native product imports and request-specific signature errors to the EC originals."""
import argparse
import base64
import datetime
import hashlib
import json
from pathlib import Path
import xml.etree.ElementTree as ET
from export_native_signed_request import collect

SHA=lambda raw:hashlib.sha256(raw).hexdigest()
VARIANTS=['control','ecdsa-sha256','ecdsa-sha256-invalid-signature']
MD='{urn:oasis:names:tc:SAML:2.0:metadata}'
DS='{http://www.w3.org/2000/09/xmldsig#}'


def export(folder,output,product):
    assert product in {'keycloak','simplesamlphp'}
    read=lambda name:json.loads((folder/name).read_text())
    run=read('created.json')['run']['id'];events=[]
    baseline='baseline-retry' if (folder/'baseline-retry').exists() else 'baseline'
    assert read(baseline+'/flow.json')=='recorded'
    if product=='keycloak':
        observer=json.loads((folder.parent/'native-observer.json').read_text())
        assert observer['provider_removed'] and observer['realm_configuration_restored'] and observer['product_restart_verified']
        assert observer['source_sha256']==SHA((folder.parent/'native-observer-source.java').read_bytes())
        baseline_record=read(baseline+'/operations.json')
        assert baseline_record['run']==run and baseline_record['restored'] and not baseline_record['failures']
        audit=read('native-signature-audit.json');assert audit['run']==run and audit['listener']=='samlscope-signature-observation'
        events=audit['rows'];collected=(folder/'native-signature-audit.json').stat().st_mtime
    else:
        restored=json.loads((folder.parent/'restoration.json').read_text())
        assert restored['restored'] and restored['original_sha256']==restored['final_sha256']
        collected=(folder/'native-http-observations.json').stat().st_mtime
    observations_raw=(folder/'native-http-observations.json').read_bytes()
    observations=json.loads(observations_raw);assert observations['run']==run and observations['product_verdict_assigned'] is False
    entries={entry['id']:entry for entry in read('transcript.json')};originals={}
    for item in read('decoded-manifest.json'):
        path=(folder/item['file']).resolve();assert path.parent==(folder/'decoded').resolve()
        raw=path.read_bytes();assert SHA(raw)==item['sha256'] and len(raw)==entries[item['id']]['decodedSamlBytes']
        assert item['id'] not in originals;originals[item['id']]=raw
    exchanges=[]
    for variant in VARIANTS:
        imported=read(variant+'/import.json');fixture=(folder/variant/'fixture.xml').read_bytes()
        descriptor=ET.fromstring(fixture);issuer=descriptor.get('entityID')
        if product=='keycloak':
            assert imported['fixture']['sha256']==SHA(fixture) and imported['fixture']['entity_id']==issuer
            assert imported['import']['ui_status']=='client-settings-page' and imported['cleanup']['read_back_absent']
            assert imported['client']['database_id']
            native=imported['import']['read_back'];assert native['client_id']==issuer
            assert native['saml_attributes']['saml.client.signature']=='true'
            certs=[cert.text for role in descriptor.findall(MD+'SPSSODescriptor') for key in role.findall(MD+'KeyDescriptor')
                   if key.get('use','signing')=='signing' for cert in key.findall('.//'+DS+'X509Certificate')]
            assert len(certs)==1
            assert ''.join(native['saml_attributes']['saml.signing.certificate'].split())==''.join(certs[0].split())
        else:
            assert imported['run']==run and imported['entity_id']==issuer and imported['fixture_sha256']==SHA(fixture)
            assert imported['import_path']=='native-parser-cli' and imported['configuration_read_back'] and imported['validate_authnrequest'] is True
            parsed=read(variant+'/parser-output.json');assert parsed['entity_id']==issuer and parsed['validate_authnrequest'] is True
            assert imported['parser_output_sha256']==SHA((folder/variant/'parser-output.json').read_bytes())
        requests=[entry for entry in entries.values() if entry['direction']=='OUTBOUND' and entry['samlSummary'].get('type')=='AuthnRequest'
                  and entry['samlSummary'].get('variant')==variant and entry['samlSummary'].get('metadataSignatureControl','valid')=='valid']
        assert len(requests)==1;sent=requests[0];request_id=sent['samlSummary']['id']
        prepared=[entry for entry in entries.values() if entry['direction']=='OUTBOUND' and entry['samlSummary'].get('type')=='MetadataPrepared'
                  and entry['samlSummary'].get('variant')==variant and entry['timestamp']<sent['timestamp'] and originals.get(entry['id'])==fixture]
        assert prepared;selected=max(prepared,key=lambda entry:entry['timestamp'])
        http=[item for item in observations['records'] if item['request_id']==request_id];assert len(http)==1;http=http[0]
        assert http['request_sha256']==SHA(originals[sent['id']]) and http['request_url']==sent['url']
        responses=[entry for entry in entries.values() if entry['direction']=='INBOUND' and entry['samlSummary'].get('type')=='Response'
                   and entry['samlSummary'].get('inResponseTo')==request_id]
        native_event=None
        if variant=='control':assert len(responses)==1
        elif variant.endswith('invalid-signature') or not responses:
            assert not responses and http['response_url']==http['request_url'] and not http['saml_response_form_present']
            if product=='keycloak':
                rows=[row for row in events if row['request_id']==request_id];assert len(rows)==1;native_event=rows[0]
                assert native_event['issuer']==issuer and native_event['request_sha256']==http['request_sha256']
                assert native_event['event_type']=='LOGIN_ERROR' and native_event['error']=='invalid_signature'
                assert http['response_status']==400 and http['response_url_exact_match']
            else:assert http['response_status']==500 and http['native_signature_rejection']=='signature-value-invalid'
        else:assert len(responses)==1
        exchanges.append(dict(variant=variant,metadataReference=selected['id'],requestReference=sent['id'],
            responseReference=responses[0]['id'] if responses else None,nativeHttp=http,nativeEvent=native_event))
    receipt=dict(schema='samlscope-native-ec-signature-v1',runId=run,
        evidenceAdapter='keycloak-native-event' if product=='keycloak' else 'simplesamlphp-native-http',
        targetMetadataSha256=SHA((folder/'target-metadata.xml').read_bytes()),normalLoginEvidence=baseline,
        collectedAt=datetime.datetime.fromtimestamp(collected,datetime.timezone.utc).isoformat(),
        nativeHttpObservationsSha256=SHA(observations_raw))
    if product=='simplesamlphp':
        receipt['nativeHttpObservationsBase64']=base64.b64encode(observations_raw).decode('ascii')
    receipt['exchanges']=exchanges
    receipt['rawEvidence']=[dict(reference=item['id'],sha256=item['sha256']) for item in read('decoded-manifest.json')]
    if product=='simplesamlphp' and (folder.parent/'native-verifier-source.php').is_file():
        source=(folder.parent/'native-verifier-source.php').read_bytes()
        source_record=json.loads((folder.parent/'native-verifier-source.json').read_text())
        counts=json.loads((folder.parent/'operation-counts.json').read_text())
        call_path=json.loads((folder.parent/'native-call-path-sources.json').read_text())
        start=json.loads((folder.parent/call_path['start_original']).read_text())
        end=json.loads((folder.parent/call_path['end_original']).read_text())
        assert source_record['container_path']=='/var/simplesamlphp/modules/saml/src/Message.php'
        assert source_record['sha256']==counts['native_verifier_sha256']==SHA(source)
        assert counts['native_verifier_read_back'] is True and source_record['image_id'].startswith('sha256:')
        binding=observations['product_binding']
        assert observations['native_verifier_sha256']==SHA(source)
        assert binding['container_name']=='samlscope-reference-ssp' and len(binding['container_id'])==64
        assert binding['image_id']==source_record['image_id'] and binding['container_id']==source_record['container_id']
        assert binding['container_started_at']==source_record['container_started_at'] and binding['running_at_capture'] is True
        assert call_path['binding']==binding==start['binding']==end['binding']
        assert counts['native_call_path_sources_read_back']==5 and counts['runtime_identity_read_backs']==2
        assert start['sources']==call_path['sources']==end['sources']
        runtime_sources=[]
        for name in ['module','routes','web-browser-sso','idp-saml2']:
            entry=start['sources'][name];raw=(folder.parent/entry['file']).read_bytes()
            assert entry['sha256']==SHA(raw) and entry['container_path'].startswith('/var/simplesamlphp/')
            runtime_sources.append(dict(name=name,containerPath=entry['container_path'],sha256=SHA(raw),
                base64=base64.b64encode(raw).decode('ascii')))
        start_inspect=(folder.parent/start['inspect_file']).read_bytes();end_inspect=(folder.parent/end['inspect_file']).read_bytes()
        assert json.loads(start_inspect)[0]['Id']==binding['container_id']==json.loads(end_inspect)[0]['Id']
        text=source.decode('utf-8')
        check=text.split('public static function checkSign(',1)[1].split('public static function validateMessage(',1)[0]
        validate=text.split('public static function validateMessage(',1)[1].split('public static function getDecryptionKeys(',1)[0]
        assert "$srcMetadata->getPublicKeys('signing')" in check
        assert "new XMLSecurityKey(XMLSecurityKey::RSA_SHA256, ['type' => 'public'])" in check
        assert check.count('new XMLSecurityKey(')==1 and 'ECDSA' not in check
        assert 'self::checkSign($srcMetadata, $message)' in validate
        receipt['nativeVerifierSource']=dict(sha256=SHA(source),imageId=source_record['image_id'],
            containerId=source_record['container_id'],containerName=source_record['container_name'],
            containerStartedAt=source_record['container_started_at'],containerPath=source_record['container_path'],
            base64=base64.b64encode(source).decode('ascii'))
        receipt['nativeRuntime']=dict(startInspectSha256=SHA(start_inspect),startInspectBase64=base64.b64encode(start_inspect).decode('ascii'),
            endInspectSha256=SHA(end_inspect),endInspectBase64=base64.b64encode(end_inspect).decode('ascii'),sources=runtime_sources)
    raw=(json.dumps(receipt,indent=2)+'\n').encode();output.parent.mkdir(parents=True,exist_ok=True)
    if output.exists():assert not output.is_symlink() and output.read_bytes()==raw
    else:
        with output.open('xb') as stream:stream.write(raw)
    return receipt


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--evidence',type=Path,required=True)
    parser.add_argument('--product',choices=['keycloak','simplesamlphp'],required=True);parser.add_argument('--collect-originals',action='store_true')
    args=parser.parse_args();folder=args.evidence.resolve()
    if args.collect_originals:collect(folder)
    run=json.loads((folder/'created.json').read_text())['run']['id']
    export(folder,folder/'preparation-receipts'/(run+'.json'),args.product)
    print('Native EC product evidence bound',run)
