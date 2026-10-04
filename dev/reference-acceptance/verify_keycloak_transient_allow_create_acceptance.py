#!/usr/bin/env python3
"""Verify six native transient policy inputs, source execution and recovered restoration.

The initial expired-token observations remain immutable failed evidence. Qualification
uses separately captured recovery originals; no protocol operation is repeated.
"""
import argparse
import base64
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import urllib.parse
import xml.etree.ElementTree as ET

REPO=Path(__file__).resolve().parents[2]
FOLDER='keycloak-native-transient-allow-create-v185-r1'
CASE='IIP-SSO01-fp-idp-01'
SCHEMA='samlscope-keycloak-transient-allow-create-v1'
spec=importlib.util.spec_from_file_location('kc_transient_runtime',REPO/'dev/reference-acceptance/verify_ssp_intersection_capability_acceptance.py')
runtime=importlib.util.module_from_spec(spec);spec.loader.exec_module(runtime)
runtime.HELPER='VerifyKeycloakTransientAllowCreateEvidence'
runtime.CLASSES=('com/samlscope/runner/cases/KeycloakTransientAllowCreateEvidence.class',
    'com/samlscope/runner/cases/KeycloakSubjectConfirmationEvidence.class',
    'com/samlscope/runner/cases/KeycloakNativeSchemaAdmissionEvidence.class',
    'com/samlscope/runner/cases/SimpleSamlPhpTransientAllowCreateEvidence.class',
    'com/samlscope/runner/cases/MetadataAlgorithmEvidence.class',
    'com/samlscope/runner/cases/TransientAllowCreateScenarioTestCase.class')
sha,load,require=runtime.sha,runtime.load,runtime.require
spec2=importlib.util.spec_from_file_location('kc_transient_originals',REPO/'dev/reference-acceptance/verify_keycloak_subject_confirmation_acceptance.py')
originals=importlib.util.module_from_spec(spec2);spec2.loader.exec_module(originals)
from algorithm_preference_campaign import admin
from mdiop_representation_campaign import runtime as product_runtime

KEYS=['transient-allow-create-'+value for value in ['true','false','omitted']]+['implicit-transient-allow-create-'+value for value in ['true','false','omitted']]
S='{urn:oasis:names:tc:SAML:2.0:assertion}';P='{urn:oasis:names:tc:SAML:2.0:protocol}'
TRANSIENT='urn:oasis:names:tc:SAML:2.0:nameid-format:transient'
CONTROLS={'wrong-run','wrong-campaign','wrong-target','wrong-peer','missing-restoration','restore-client-remains',
    'native-runtime-changed','classpath-injected','process-injected','unknown-factory','unknown-effective-mapper',
    'client-signature-disabled','persistent-nameid-setting','client-before-after-differ','native-source-mutated',
    'missing-member','member-order-swapped','request-reused','foreign-user','persistent-state-added','session-changed',
    'duplicate-transcript','foreign-transcript-run','foreign-content-reference','directory-receipt','symlink-receipt','partial-sidecar'}


def verify_adoption(root,live=False,formal=True):
    folder=Path(root).resolve()
    if folder.name!=FOLDER:folder=folder/FOLDER
    qualified=folder/'qualified-originals';receipt=load(folder/'qualified-receipt.json')
    run=load(folder/'created.json')['run']['id'];target=(folder/'target-metadata.xml').read_bytes()
    peer='http://localhost:18080/p/'+load(folder/'created.json')['run']['planId']
    require((receipt['schema'],receipt['runId'],receipt['campaignId'],receipt['targetEntityId'],receipt['targetMetadataSha256'],receipt['peerEntityId'])==
        (SCHEMA,run,'native-transient-allow-create',originals.TARGET,sha(target),peer),'Native receipt identity changed')
    for name,digest in receipt['files'].items():
        path=qualified/name
        require(path.resolve().is_relative_to(qualified.resolve()) and path.is_file() and not any(p.is_symlink() for p in [path,*path.parents]),'Unsafe native original')
        require(sha(path.read_bytes())==digest,'Qualified native original changed')
    require(set(receipt['files'])=={str(path.relative_to(qualified)) for path in qualified.rglob('*') if path.is_file()},'Qualified original inventory changed')
    # Derived copies never overwrite the initial expired-token originals.
    source_index=load(folder/'qualified-source-index.json')
    require(source_index['schema']=='samlscope-keycloak-transient-recovery-original-index-v1' and source_index['originals_unchanged'] is True and source_index['extra_protocol_operations']==0,'Recovery original provenance changed')
    replacements=source_index['replacements']
    require(set(replacements)=={'native-matrix-client-after.json','native-scopes-after.json','matrix-after.principal.json',
        'native-client-removal.json','client-inventory-after.json','global-policy-after.json','restoration.json',
        'server-info-after.json','environment-after.json','after.native-classpath.txt'},'Recovery substitution scope changed')
    for name,row in replacements.items():
        source=folder/row['source'];require(source.resolve().parent==(folder/'recovery').resolve() and source.read_bytes()==(qualified/name).read_bytes() and sha(source.read_bytes())==row['sha256'],'Recovery substituted evidence changed')
    for name in receipt['files']:
        if name in replacements:continue
        source=(folder/'originals'/name) if (folder/'originals'/name).is_file() else folder/name
        require(source.is_file() and source.read_bytes()==(qualified/name).read_bytes(),'Original qualification copy differs')
    initial=load(folder/'operations.json');recovery=load(folder/'recovery/operations.json')
    require(len(initial)==94 and len(recovery)==21 and any(row['status']==401 for row in initial),'Expired-token failure history changed')
    require(load(folder/'restoration.json')['restored'] is False and load(folder/'restoration.json')['recovery_failures']==1 and
        load(folder/'restoration.json')['remaining_clients']=={'error':'HTTP 401 Unauthorized'},'Initial failed restoration was hidden')
    restored=load(folder/'recovery/restoration.json')
    require(restored==dict(restored=True,remaining_clients=[],originally_absent=True,client_removed=True,recovery_failures=0,
        failed_initial_delete_status=401,recovery_delete_attempts=1),'Recovery not complete')
    native_id=receipt['nativeClientId'];url=originals.ADMIN+'/clients/'+native_id
    require(originals.http(load(qualified/'client-inventory-before.json'),'GET',originals.ADMIN+'/clients?clientId='+urllib.parse.quote(peer,safe=''),200)==[] and
        originals.http(load(qualified/'client-inventory-after.json'),'GET',originals.ADMIN+'/clients?clientId='+urllib.parse.quote(peer,safe=''),200)==[],'Native temporary client not absent/restored')
    originals.http(load(qualified/'native-client-removal.json'),'DELETE',url,204)
    before=load(qualified/'environment-before.json');after=load(qualified/'environment-after.json')
    require(before['runtime']==after['runtime'] and before['runtime']['image']==originals.IMAGE,'Native runtime changed')
    for phase,environment in [('before',before),('after',after)]:
        inventory=(qualified/(phase+'.native-classpath.txt')).read_bytes()
        require(sha(inventory)==environment['nativeClasspathSha256']==originals.INVENTORY and len(inventory.splitlines())==471,'Complete stock classpath changed')
        require(sha(json.dumps(environment['publicProcessArguments'],separators=(',',':')).encode())==originals.PROCESS and environment['processRedactions']==[],'Stock process changed')
    require(originals.scope_state(load(qualified/'native-scopes-before.json'))==originals.scope_state(load(qualified/'native-scopes-after.json')),'Effective mapper scopes changed')
    native_client=originals.http(load(qualified/'native-matrix-client-before.json'),'GET',url,200)
    require(native_client==originals.http(load(qualified/'native-matrix-client-after.json'),'GET',url,200) and
        native_client['attributes']['saml_name_id_format']=='transient' and native_client['attributes']['saml.client.signature']=='true' and native_client['attributes']['saml.encrypt']=='false','Native fixed policy changed')
    for name,digest in receipt['files'].items():
        if name.startswith('native-runtime/') and name.endswith('.jar'):
            require(any(line.split()[0]==digest and line.split()[1].endswith('/'+Path(name).name) for line in (qualified/'before.native-classpath.txt').read_text().splitlines()),'Native generator JAR not in operative classpath')
    require(len(list((qualified/'native-runtime').glob('*.jar')))==13,'Native execution dependency closure changed')
    entries=load(folder/'transcript.json');by_id={entry['id']:entry for entry in entries}
    require(len(by_id)==len(entries) and all(entry['runId']==run for entry in entries),'Foreign/duplicate transcript')
    bodies={}
    for row in load(folder/'decoded-manifest.json'):
        path=(folder/row['file']).resolve();require(path.parent==(folder/'decoded').resolve() and row['id'] not in bodies,'Unsafe decoded original')
        raw=path.read_bytes();entry=by_id[row['id']]
        require(sha(raw)==row['sha256'] and len(raw)==entry['decodedSamlBytes'] and entry['decodedSamlRef']=='transcripts/'+run+'/'+row['id']+'.saml.xml','Actual decoded original changed');bodies[row['id']]=raw
    require(set(bodies)=={entry['id'] for entry in entries if entry['decodedSamlRef'] is not None},'Decoded original set changed')
    steps=load(folder/'steps.json');sent=[row for row in steps if row.get('sentToTarget') is True]
    require(len(sent)==6 and [row['key'] for row in sent]==KEYS and len(steps)-len(sent)==126 and all(row['caseId']==CASE for row in sent),'Complete selected/aborted operation inventory changed')
    require([member['key'] for member in receipt['members']]==KEYS,'Required policy members changed')
    indices=set()
    for step,member in zip(sent,receipt['members']):
        request=ET.fromstring(bodies[member['requestReference']]);response=ET.fromstring(bodies[member['responseReference']])
        require(member['actionId']==step['actionId'] and request.get('ID')=='_'+step['actionId'] and
            set(step['transcriptIds'])=={member['requestReference'],member['responseReference']} and response.get('InResponseTo')==request.get('ID'),'Own outbox action/request/response binding changed')
        name=response.find('.//'+S+'NameID');auth=response.find('.//'+S+'AuthnStatement')
        require(name is not None and name.get('Format')==TRANSIENT and auth is not None,'Actual transient production changed');indices.add(auth.get('SessionIndex'))
    require(len(indices)==1,'Authentication session changed between policy inputs')
    user_before=load(qualified/'matrix-before.principal.json');user_after=load(qualified/'matrix-after.principal.json')
    require(base64.b64decode(user_before['user']['response_base64'])==base64.b64decode(user_after['user']['response_base64']) and
        base64.b64decode(user_before['federatedIdentities']['response_base64'])==base64.b64decode(user_after['federatedIdentities']['response_base64']),'Identity association state changed')
    counts=load(folder/'complete-operation-counts.json')
    require(counts==dict(native_http_attempts=115,product_setting_write_attempts=4,product_setting_writes=3,protocol_operations_attempted=8,
        suite_only_prepared_aborts=126,management_token_acquisitions=3,native_source_jar_captures=13,human_operations=0,product_restarts=0,
        restored=True,original_failure_preserved=True,recovery_protocol_operations=0),'Complete failed/recovery operation costs changed')
    require(sum(row['product_setting_write'] for row in initial+recovery)==4 and sum(row['product_setting_write'] and row['status'] in [201,204] for row in initial+recovery)==3,'Setting/recovery attempts changed')
    recorded=load(folder/'native-reader-replay.json');require(runtime.replay(folder)==recorded,'Archived production reader replay changed')
    outcome=recorded['production_outcomes'][CASE]
    require(recorded['runId']==run and set(recorded['production_outcomes'])=={CASE} and outcome['outcome']=='SATISFIED' and
        outcome['reasonCode']=='browser.nameid.transient-allow-create-ignored' and set(recorded['negative_controls'])==CONTROLS and
        set(recorded['negative_controls'].values())=={'NOT_VERIFIED'} and recorded['native_generator_executed'] is True and
        recorded['native_state_models_read_by_generator'] is False and recorded['transcriptSha256']==sha((folder/'transcript.json').read_bytes()),'Native producer/proof controls changed')
    require(outcome['details']['ordinary_session_storage_asserted_absent'] is False and outcome['details']['scope']=='this-run-stock-native-transient-factory-and-effective-configuration','Persistence claim exceeded actual scope')
    if live:
        require(product_runtime()==before['runtime'] and admin('/clients?clientId='+urllib.parse.quote(peer,safe=''))==[],'Live Keycloak not restored')
        require(originals.api('/api/runs/'+run+'/transcript')==entries,'Live actual Run changed')
    if not formal:return recorded
    evaluation=folder/'evaluation';result=load(evaluation/'result.json');rows={case['id']:case for requirement in result['requirements'] for case in requirement['cases']};case=rows[CASE]
    require(result['run']['id']==run and result['target']['metadata_digest']=='sha256:'+sha(target),'Formal target/Run changed')
    require((case['outcome'],case['verdict'],case['reason_code'],case['attested'],case['evidence_class'])==('SATISFIED','PASS',outcome['reasonCode'],False,'PROTOCOL_OBSERVED'),'Formal native verdict/provenance changed')
    require(load(evaluation/'transcript-before.json')==load(evaluation/'transcript.json')==entries,'Formal reevaluation changed actual history')
    require(load(evaluation/'receipt-readback.json')['sha256']==sha((folder/'qualified-receipt.json').read_bytes()),'Installed receipt changed')
    stored=load(evaluation/(CASE+'.case-execution.json'));execution=stored['cases'][CASE];observed=dict(execution['outcome']);details=dict(observed['details']);previous=details.pop('previous_recorded_evidence_result',None);observed['details']=details
    require(stored['runId']==run and execution['status']=='FINISHED' and execution['outboxCount']==6 and observed==outcome and
        case['evidence']==outcome['evidence'] and execution['verdict']==case['verdict'],'Full formal native outcome/outbox changed')
    if previous is not None:
        old_rows={row['id']:row for requirement in load(evaluation/'result-before.json')['requirements'] for row in requirement['cases']}
        require(previous['outcome']==old_rows[CASE]['outcome']=='NOT_VERIFIED' and previous['reason_code']==old_rows[CASE]['reason_code'],'Previous outcome audit changed')
    return evaluation/'result.json',{CASE:case}


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('root',type=Path);parser.add_argument('--capture-runtime',action='store_true');parser.add_argument('--record-replay',action='store_true');parser.add_argument('--live',action='store_true');parser.add_argument('--diagnostic-only',action='store_true');args=parser.parse_args();folder=args.root.resolve()
    if folder.name!=FOLDER:folder=folder/FOLDER
    if args.capture_runtime:runtime.capture_runtime(folder)
    if args.record_replay:
        require(not(folder/'native-reader-replay.json').exists(),'Immutable replay exists');(folder/'native-reader-replay.json').write_text(json.dumps(runtime.replay(folder),indent=2)+'\n')
    verify_adoption(folder,live=args.live,formal=not args.diagnostic_only);print('Native six-condition transient AllowCreate acceptance verified; one observation')
