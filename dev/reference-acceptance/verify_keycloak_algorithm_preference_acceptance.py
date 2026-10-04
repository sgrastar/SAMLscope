#!/usr/bin/env python3
"""Diagnostic-only native preference verification: compiled default criteria remain unproven."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import urllib.request
import urllib.parse
import subprocess
import xml.etree.ElementTree as ET
import zipfile

REPO=Path(__file__).resolve().parents[2]
FOLDER='keycloak-algorithm-preference-v169-r1'
CASES={'IIP-MD05-e7-idp-01','IIP-MD05-e9-idp-01','IIP-MD05-ea-idp-01'}
SPEC=importlib.util.spec_from_file_location('keycloak_preference_pinned_runtime',REPO/'dev/reference-acceptance/verify_ssp_intersection_capability_acceptance.py')
runtime=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(runtime)
runtime.HELPER='VerifyKeycloakAlgorithmPreferenceEvidence'
runtime.CLASSES=('com/samlscope/runner/cases/KeycloakAlgorithmPreferenceEvidenceFile.class',
    'com/samlscope/runner/cases/KeycloakAlgorithmPreferenceConfigurationTestCase.class',
    'com/samlscope/runner/cases/MetadataAlgorithmEvidence.class')
import sys
sys.path.insert(0,str(REPO/'dev/keycloak'))
from algorithm_preference_campaign import REQUIRED,CLASSES,admin

def sha(raw):return hashlib.sha256(raw).hexdigest()
def load(path):return json.loads(path.read_bytes())
def require(value,message):
    if not value:raise ValueError(message)
def rows(result):return {c['id']:c for r in result['requirements'] for c in r['cases']}
def api(path):
    with urllib.request.urlopen('http://localhost:18080'+path,timeout=40) as r:return json.load(r)

def verify_adoption(root,live=False,formal=True):
    raise ValueError('Keycloak built-in RSA_SHA256 preference does not prove absence of local criteria; e7 producer scope is also unproven. No observation is adoptable.')

def verify_diagnostic(root,live=False):
    folder=Path(root).resolve()
    if folder.name!=FOLDER:folder=folder/FOLDER
    run=load(folder/'created.json')['run']['id'];plan=load(folder/'created.json')['run']['planId'];entity='http://localhost:18080/p/'+plan
    target=(folder/'target-metadata.xml').read_bytes();receipt=load(folder/'qualified-receipt.json')
    require(receipt['runId']==run and receipt['targetMetadataSha256']==sha(target)
        and receipt['targetEntityId']==ET.fromstring(target).get('entityID')
        and receipt['schema']=='samlscope-keycloak-algorithm-preference-v1'
        and receipt['adapter']=='keycloak-native-default-selector-v1'
        and receipt['campaignId']=='metadata-fixture-refresh','Run/native schema differs')
    entries=load(folder/'transcript.json');by_id={e['id']:e for e in entries}
    require(len(entries)==len(by_id) and all(e['runId']==run for e in entries),'Foreign/ambiguous transcript')
    originals={}
    for row in load(folder/'decoded-manifest.json'):
        p=(folder/row['file']).resolve();raw=p.read_bytes()
        require(p.parent==(folder/'decoded').resolve() and sha(raw)==row['sha256'] and len(raw)==by_id[row['id']]['decodedSamlBytes']
            and row['id'] not in originals,'Original hash/length/path differs')
        originals[row['id']]=raw
    def original(ref):
        raw=originals[ref['reference']];require(sha(raw)==ref['sha256'],'Native original reference differs');return json.loads(raw)
    before=original(receipt['policyBefore']);after=original(receipt['policyAfter'])
    require(before==after and before['clientPolicies']=={'policies':[]} and before['clientProfiles']=={'profiles':[]},'Native policy state changed/unproven')
    native_pins=load(folder/'native-runtime/pins.json')
    require(set(native_pins)==set(CLASSES.values()),'Native source JAR inventory differs')
    for jar,pin in native_pins.items():require(sha((folder/'native-runtime'/(jar+'.jar')).read_bytes())==pin,'Original native JAR changed')
    for c,jar in CLASSES.items():
        import base64
        with zipfile.ZipFile(folder/'native-runtime'/(jar+'.jar')) as z:raw=z.read(c)
        require(base64.b64decode(before['nativeClasses'][c])==raw,'Native class original differs from actual binary')
    operations=load(folder/'operations.json')
    require(len(operations)==14 and {r['variant'] for r in operations if r['capability'] is None}==set(REQUIRED)
        and all(r['restored'] and r['driver_exit']==0 for r in operations),'Native full matrix incomplete/restoration failed')
    client_ids=set();write_attempts=0
    for op in operations:
        member=folder/op['label'];imported=load(member/'import.json');flow=load(member/'flow.json');cfg=load(member/'native-configuration.json')
        raw=(member/'fixture.xml').read_bytes()
        require(imported['status']=='success' and imported['fixture']['entity_id']==entity and imported['fixture']['sha256']==sha(raw)
            and imported['import']['ui_status']=='client-settings-page' and imported['import']['save_clicked']
            and imported['client']['database_id'] not in client_ids and imported['cleanup']=={'deleted_status':204,'read_back_absent':True},'Native import/UI/restore original differs')
        client_ids.add(imported['client']['database_id'])
        require(cfg['client']['id']==imported['client']['database_id'] and cfg['client']['clientId']==entity
            and cfg['client']['samlAttributes']==imported['import']['read_back']['saml_attributes']
            and cfg['fixtureSha256']==sha(raw) and cfg['runId']==run and cfg['targetMetadataSha256']==sha(target), 'Native configuration/import binding differs')
        refs=load(member/'native-configuration-reference.json');require(original(refs)==cfg,'Native read-back was not recorded as original')
        policy=imported['import'].get('native_default_signature_selector') if op['capability'] is None else imported['import']['signing_capability_policy']
        before_attrs=policy['original_saml_attributes'];effective=cfg['client']['samlAttributes']
        wanted={k:v for k,v in before_attrs.items() if k!='saml.signature.algorithm'}
        if op['capability'] is not None:wanted['saml.signature.algorithm']=op['capability']
        require(effective==wanted and policy['key_material_modified'] is False and policy['read_back_verified'] is True,'Native selector changed keys/other policy')
        write_attempts+=policy['write_attempts']
        if policy['write_attempts']:require(policy['write_status']==204,'Native selector write failed')
        require(flow['run']==run and flow['variant']==op['variant'] and flow['correlated_success'] and flow['after_index']==flow['before_index']+1,
            'Native SAML Success correlation missing')
        require(any(e['direction']=='OUTBOUND' and e['samlSummary'].get('type')=='MetadataPrepared' and originals.get(e['id'])==raw
            for e in entries),'Native original fixture not bound to Suite preparation')
        require(flow['negative_control']['source']=='suite' and flow['negative_control']['correlated_success'] is False,'Invalid signature diagnostic contradicted by Success')
    require(len(client_ids)==14,'Native isolated client inventory differs')
    counts=load(folder/'operation-counts.json')
    require(counts==dict(native_import_attempts=14,temporary_clients_removed=14,native_selector_write_attempts=write_attempts,
        protocol_operation_pairs_attempted=14,recovery_client_removals=0,product_restarts=0,human_operations=0,restored=True,verdict_adopted=False),'Native operation counts differ')
    require(load(folder/'restoration.json')==dict(restored=True,remaining_clients=[],recovery_client_removals=0), 'Native restore read-back differs')
    restored=original(receipt['restoration']);require(restored['originalClients']==restored['remainingClients']==[],'Native remaining clients not restored')
    recorded=load(folder/'native-reader-replay.json');require(runtime.replay(folder)==recorded,'Pinned production reader replay differs')
    require(recorded['runId']==run and set(recorded['cases'])==CASES and recorded['privateKeyExported'] is False
        and recorded['configurationWrites']==0 and len(recorded['checks'])==18,'Replay scope/controls incomplete')
    require(recorded['checks']['complete-native-campaign']=={c:'NOT_VERIFIED' for c in CASES}
        and all(v=={c:'NOT_VERIFIED' for c in CASES} for k,v in recorded['checks'].items() if k!='complete-native-campaign'), 'Altered evidence adopted')
    for c in CASES:
        row=recorded['cases'][c];require(row['outcome']=='NOT_VERIFIED' and row['reasonCode']==('metadata.algorithms.producer-preference-unproven' if c=='IIP-MD05-e7-idp-01' else 'metadata.algorithms.local-policy-unverified')
            and row['details']['local_policy_verified'] is False
            and row['details']['native_receipt_sha256']==sha((folder/'qualified-receipt.json').read_bytes()),'Native reader outcome/receipt differs')
    if live:
        require(admin('/clients?clientId='+urllib.parse.quote(entity,safe=''))==[],'Live native temporary client remains')
        require(api('/api/runs/'+run+'/transcript')==entries,'Live original transcript differs')
    return recorded

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('root',type=Path);p.add_argument('--prepare-runtime',action='store_true')
    p.add_argument('--record-replay',action='store_true');p.add_argument('--diagnostic-only',action='store_true');p.add_argument('--live',action='store_true')
    args=p.parse_args();folder=args.root.resolve()
    if folder.name!=FOLDER:folder=folder/FOLDER
    if args.prepare_runtime:runtime.capture_runtime(folder)
    if args.record_replay:
        path=folder/'native-reader-replay.json';require(not path.exists(),'Immutable replay exists');path.write_text(json.dumps(runtime.replay(folder),indent=2)+'\n')
    verify_diagnostic(folder,live=args.live);print('Verified diagnostic originals; all three native preference cases remain NOT_VERIFIED')
