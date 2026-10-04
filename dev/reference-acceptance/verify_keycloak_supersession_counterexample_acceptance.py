#!/usr/bin/env python3
"""Reuse the accepted A-case campaign for a narrow MD06.ab runtime counterexample.

Original request case IDs and historical unknown delivery remain unchanged. A complete
SATISFIED matrix is never inferred from this single valid endpoint counterexample.
"""
import argparse
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile

REPO=Path(__file__).resolve().parents[2]
FOLDER='keycloak-native-supersession-counterexample-v187-r1'
SOURCE='keycloak-native-supersession-v177-r3'
CASE='IIP-MD06-ab-idp-01'
APPLICATION='IIP-MD06-a-idp-01'
VARIANT='IIP-MD06.ab#v-7e4460130e'
def module(name,path):
    spec=importlib.util.spec_from_file_location(name,path);value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value
original=module('historical_native_application',REPO/'dev/reference-acceptance/verify_keycloak_metadata_supersession_acceptance.py')
runtime=module('native_supersession_counterexample_runtime',REPO/'dev/reference-acceptance/verify_ssp_intersection_capability_acceptance.py')
runtime.HELPER='VerifyKeycloakMetadataSupersessionCounterexample'
runtime.CLASSES=('com/samlscope/runner/cases/KeycloakMetadataSupersessionEvidenceFile.class','com/samlscope/runner/cases/MetadataSupersessionProbeTestCase.class')
sha,load,require=runtime.sha,runtime.load,runtime.require
ADDITIONAL={'replacement-native-client-differs','replacement-peer-differs','replacement-reused-epoch','accepted-B-fixture-binding-mismatch','accepted-B-positive-key-differs'}


def replay_trust_regression(folder):
    prior=folder.parent/'keycloak-native-self-contained-trust-v178-r1'
    helper=folder/'regression/VerifyKeycloakSelfContainedTrustEvidence.java'
    binding=load(folder/'regression/runtime-binding.json');pins=load(folder/'runtime/pins.json')
    require(binding['runtime']=='reference-combined-v187' and binding['jars']==pins['jars'] and binding['full_report_identical'] is True and binding['product_setting_writes']==binding['protocol_sends']==0,'Trust regression runtime binding differs')
    require(helper.read_bytes()==(prior/'runtime'/helper.name).read_bytes() and sha(helper.read_bytes())==binding['helper_sha256'] and sha((prior/'native-reader-replay.json').read_bytes())==binding['source_report_sha256'],'Trust regression source/helper differs')
    suite='samlscope-reference-suite';remote='/tmp/kc-ab-trust-regression-'+sha(folder.as_posix().encode())[:20]
    with tempfile.TemporaryDirectory(prefix='kc-ab-trust-regression-') as temporary:
        temporary=Path(temporary);cp=':'.join(str(folder/'runtime'/(name+'.jar')) for name in ['runner','core','saml','store'])+':'+Path('/private/tmp/samlscope-runner-runtime-classpath.txt').read_text().strip()
        subprocess.run(['javac','-cp',cp,'-d',str(temporary/'classes'),str(helper)],check=True,capture_output=True)
        subprocess.run(['docker','exec',suite,'mkdir','-p',remote],check=True,capture_output=True)
        try:
            subprocess.run(['docker','cp',str(prior),suite+':'+remote+'/campaign'],check=True,capture_output=True)
            subprocess.run(['docker','cp',str(temporary/'classes'),suite+':'+remote+'/classes'],check=True,capture_output=True)
            subprocess.run(['docker','cp',str(folder/'runtime'),suite+':'+remote+'/runtime'],check=True,capture_output=True)
            cp=':'.join(remote+'/runtime/'+name+'.jar' for name in ['runner','core','saml','store'])
            result=subprocess.run(['docker','exec',suite,'java','-cp',cp+':'+remote+'/classes:/opt/samlscope/lib/*','com.samlscope.runner.cases.VerifyKeycloakSelfContainedTrustEvidence',remote+'/campaign','/data',remote+'/report.json'],capture_output=True,text=True,timeout=90)
            require(result.returncode==0,'Actual archived trust regression failed: '+result.stderr[-1000:])
            subprocess.run(['docker','cp',suite+':'+remote+'/report.json',str(temporary/'report.json')],check=True,capture_output=True)
            report=load(temporary/'report.json');require(report==load(prior/'native-reader-replay.json')==load(folder/'regression/md06-c-runtime-replay.json') and sha((folder/'regression/md06-c-runtime-replay.json').read_bytes())==binding['new_report_sha256'],'Existing full trust outcome/controls regressed')
            return report
        finally:subprocess.run(['docker','exec','--user','0',suite,'rm','-rf',remote],check=True,capture_output=True)



def read_live_own_outbox(folder,run):
    source=folder/'evaluation/ReadKeycloakOwnOutbox.java'
    expected=load(folder/'evaluation/own-outbox-readback.json')
    # Public SQL projection only; never export outbox payloads or credentials.
    text=source.read_text()
    require('mode=ro' in text and 'SELECT action_id,status,transcript_entry_id,created_at,updated_at FROM outbox_actions WHERE run_id=? AND case_id=? ORDER BY created_at,action_id' in text and not any(term in text for term in ['action_json','send_result','Authorization','Cookie']),'Own outbox helper exceeds public read-only scope')
    suite='samlscope-reference-suite';remote='/tmp/kc-ab-own-outbox-'+sha(folder.as_posix().encode())[:20]
    with tempfile.TemporaryDirectory(prefix='kc-ab-own-outbox-') as temporary:
        temporary=Path(temporary);cp=':'.join(str(folder/'runtime'/(name+'.jar')) for name in ['runner','core','saml','store'])+':'+Path('/private/tmp/samlscope-runner-runtime-classpath.txt').read_text().strip()
        subprocess.run(['javac','-cp',cp,'-d',str(temporary/'classes'),str(source)],check=True,capture_output=True)
        subprocess.run(['docker','exec',suite,'mkdir','-p',remote],check=True,capture_output=True)
        try:
            subprocess.run(['docker','cp',str(temporary/'classes'),suite+':'+remote+'/classes'],check=True,capture_output=True)
            subprocess.run(['docker','cp',str(folder/'runtime'),suite+':'+remote+'/runtime'],check=True,capture_output=True)
            cp=':'.join(remote+'/runtime/'+name+'.jar' for name in ['runner','core','saml','store'])
            result=subprocess.run(['docker','exec',suite,'java','-cp',cp+':'+remote+'/classes:/opt/samlscope/lib/*','com.samlscope.runner.cases.ReadKeycloakOwnOutbox',run,CASE],capture_output=True,text=True,timeout=30)
            require(result.returncode==0,'Live public own outbox read failed')
            require(json.loads(result.stdout)==expected,'Own outbox delivery/state changed')
        finally:subprocess.run(['docker','exec','--user','0',suite,'rm','-rf',remote],check=True,capture_output=True)


def verify_adoption(root,live=False,formal=True):
    folder=Path(root).resolve()
    if folder.name!=FOLDER:folder=folder/FOLDER
    source=folder.parent/SOURCE
    # Reruns the archived v177 production reader and its original accepted-case verifier.
    original.verify_adoption(source,live=live)
    manifest=load(folder/'source-originals-manifest.json')
    require(manifest['schema']=='samlscope-keycloak-supersession-shared-originals-v1' and manifest['source_folder']==SOURCE and manifest['shared_campaign'] is True and manifest['new_product_settings']==manifest['new_protocol_sends']==0,'Shared original reuse scope differs')
    for name,digest in manifest['source_files'].items():
        relative=Path(name);path=folder/relative;prior=source/relative
        require(not relative.is_absolute() and '..' not in relative.parts and path.is_file() and not any(p.is_symlink() for p in [path,*path.parents]),'Unsafe shared original')
        require(path.read_bytes()==prior.read_bytes() and sha(path.read_bytes())==digest,'Historical shared original altered')
    for name,digest in manifest['historical_application_files'].items():
        require(name in {'native-reader-replay.json','result.json'},'Unexpected historical projection')
        prior=source/('evaluation/result.json' if name=='result.json' else name)
        require((folder/'historical-application'/name).read_bytes()==prior.read_bytes() and sha(prior.read_bytes())==digest,'Historical native application conclusion altered')
    projection=manifest['historical_application_outcome_projection'];require(projection['source']=='evaluation/case-execution.json' and projection['projection']=='historical-application/application-outcome.json' and projection['included_fields']==['runId','caseId','revision','status','outcome','updatedAt'],'Historical public outcome projection changed')
    stored_before=load(source/projection['source']);public={key:stored_before[key] for key in projection['included_fields']}
    require(sha((source/projection['source']).read_bytes())==projection['source_sha256'] and public==load(folder/projection['projection']) and sha((folder/projection['projection']).read_bytes())==projection['projection_sha256'],'Historical full public outcome differs')
    run=load(folder/'created.json')['run']['id'];entries=load(folder/'transcript.json');by_id={entry['id']:entry for entry in entries};receipt=load(folder/'qualified-receipt.json')
    require(len(by_id)==len(entries) and all(entry['runId']==run for entry in entries) and [phase['variant'] for phase in receipt['phases']]==['control','multiple-signing-keys-first','multiple-signing-keys','no-valid-until'],'Native replacement epochs differ')
    require(all(by_id[probe['requestReference']]['samlSummary']['scenario_case_id']==APPLICATION for probe in receipt['probes']) and not any(entry.get('samlSummary',{}).get('scenario_case_id')==CASE for entry in entries),'Shared A-case operations were relabelled as new AB sends')
    expected=load(folder/'historical-application/application-outcome.json')['outcome'];expected=dict(expected,details=dict(expected['details']));expected['details'].pop('previous_recorded_evidence_result',None)
    report=runtime.replay(folder);require(report==load(folder/'native-reader-replay.json'),'Actual archived production replay differs');replay_trust_regression(folder)
    require(report['applicationRegression']==expected,'Existing MD06.a full outcome regressed')
    old=load(folder/'historical-application/native-reader-replay.json');require(set(report['checks'])==set(old['checks'])|ADDITIONAL and all(report['checks'][name]==value for name,value in old['checks'].items()),'Old native application controls regressed')
    require(report['runId']==run and report['caseId']==CASE and report['outcome']=='VIOLATED' and report['reasonCode']=='metadata.supersession.accepted-post-endpoint-rejected' and report['privateKeyExported'] is False and len(report['checks'])==23 and all(report['checks'][name]=='NOT_VERIFIED' for name in ADDITIONAL),'Native replacement/runtime controls failed')
    details=report['details'];require(details['violated_variant']==VARIANT and details['scope']=='accepted-B-endpoint-runtime-reflection' and details['other_binding_profile_reflection_not_concluded'] is True and details['counterexample']=='accepted-second-post-acs-after-same-entity-replacement' and details['native_originals_verified'] is True and details['restoration_verified'] is True,'Counterexample exceeds proved scope')
    require(details['receipt_sha256']==sha((folder/'qualified-receipt.json').read_bytes()) and details['accepted_metadata_b_sha256']==receipt['phases'][-1]['fixtureSha256'],'Native accepted B binding differs')
    require(load(folder/'additional-operation-counts.json')==dict(product_setting_writes=0,protocol_saml_requests=0,run_creations=0,product_restarts=0,human_operations=0,shared_originals_reused=True,historical_configuration_operations=15,historical_protocol_saml_requests=45,historical_runs=3,historical_costs_reused_not_new=True),'Historical campaign costs double counted or omitted')
    if not formal:return report
    evaluation=folder/'evaluation';result=load(evaluation/'result.json');before=load(evaluation/'result-before.json')
    rows=lambda value:{case['id']:case for requirement in value['requirements'] for case in requirement['cases']}
    cases=rows(result);prior=rows(before);case=cases[CASE]
    require(result['run']['id']==run and result['target']['metadata_digest']=='sha256:'+receipt['targetMetadataSha256'],'Formal Run/target differs')
    require((case['outcome'],case['verdict'],case['reason_code'],case['attested'],case['evidence_class'])==('VIOLATED','FAIL',report['reasonCode'],False,'OPERATOR_ASSISTED'),'Formal native supersession conclusion/provenance differs')
    require(load(evaluation/'transcript-before.json')==load(evaluation/'transcript.json')==entries,'Formal evaluation changed shared transcript')
    require(load(evaluation/'receipt-readback.json')['sha256']==sha((folder/'qualified-receipt.json').read_bytes()),'Installed source receipt changed')
    captured=load(evaluation/'case-execution.json');execution=captured['cases'][CASE];outcome=dict(execution['outcome']);details=dict(outcome['details']);previous=details.pop('previous_recorded_evidence_result',None);outcome['details']=details
    require(captured['runId']==run and execution['status']=='FINISHED' and execution['outboxCount']==1,'AB was not concluded from shared originals only')
    require(outcome==dict(outcome='VIOLATED',notVerifiedReason=None,reasonCode=report['reasonCode'],reasonMessageKey=report['reasonCode'],evidence=report['evidence'],details=report['details']) and execution['verdict']==case['verdict'] and case['evidence']==report['evidence'],'Full formal outcome differs from actual production reader')
    historical=rows(load(folder/'historical-application/result.json'))[CASE]
    require(historical['outcome']=='NOT_VERIFIED' and historical['reason_code']=='case.pending-interaction','Historical v177 unresolved AB result changed')
    require(prior[CASE]==case and load(evaluation/'case-execution-before.json')==captured,'The explicit formal POST changed an already reconciled result')
    require(previous is not None and previous['outcome']=='NOT_VERIFIED' and previous['reason_code']=='metadata.supersession.awaiting-native-receipt' and previous['revision']+1==execution['revision'],'Previous stored unresolved AB audit differs')
    own=load(evaluation/'own-outbox-readback.json');outbox=own['rows']
    incident=load(evaluation/'finished-case-pending-outbox-diagnostic.json');require(incident['runId']==run and incident['caseId']==CASE and incident['case_status']=='FINISHED' and incident['own_outbox_status']=='PENDING' and incident['own_action_was_sent'] is False and incident['shared_original_case_id']==APPLICATION and incident['changed_case_id_or_delivery'] is False and incident['unknown_delivery_incident'] is False and incident['pending_outbox_readback_sha256']==sha((evaluation/'own-outbox-readback.json').read_bytes()),'Finished-case pending-outbox Suite diagnostic differs')
    require(own['schema']=='samlscope-keycloak-own-outbox-readonly-v1' and own['runId']==run and own['caseId']==CASE and len(outbox)==1 and outbox[0]==dict(actionId='action_74621bae6664e232e8df449ba094ace9',status='PENDING',transcriptEntryId=None,createdAt='2026-10-01T04:05:26.987676088Z',updatedAt='2026-10-01T04:05:26.987676088Z'),'Existing unsent own action/delivery differs')
    require(outbox[0]['actionId'] not in {entry.get('samlSummary',{}).get('action_id') for entry in entries},'Unsent AB action was confused with the shared campaign')
    natural=load(evaluation/'natural-re-evaluation.json')
    require(natural['schema']=='samlscope-keycloak-supersession-natural-re-evaluation-v1' and natural['runId']==run and natural['caseId']==CASE and natural['first_v187_snapshot_already_conclusive'] is True and natural['explicit_evaluate_changed_conclusion'] is False and natural['new_product_settings']==natural['new_protocol_sends']==0 and natural['stored_revision_before']==natural['stored_revision_after']==execution['revision'] and natural['existing_own_action_status']=='PENDING' and natural['existing_own_action_transcript_reference'] is None,'Natural reevaluation scope differs')
    for relative,digest in natural['originals'].items():
        require(relative in {'historical-application/result.json','evaluation/result-before.json','evaluation/result.json','evaluation/case-execution-before.json','evaluation/case-execution.json','evaluation/own-outbox-readback.json'} and sha((folder/relative).read_bytes())==digest,'Natural reevaluation original differs')
    require(cases[APPLICATION]==prior[APPLICATION],'Existing formal MD06.a result changed')
    trust='IIP-MD06-c-idp-01';require(cases[trust]==prior[trust]==rows(load(folder.parent/'keycloak-native-self-contained-trust-v178-r1/evaluation-v179/result.json'))[trust],'Existing accepted native-trust formal result/provenance changed')
    require(not any(row['kind']=='UNKNOWN_DELIVERY' and row['case_id']==CASE for row in result['suite_incidents']),'AB shares unknown own delivery')
    if live:
        read_live_own_outbox(folder,run)
        actual=original.api('/api/runs/'+run+'/result.json');require(rows(actual)[CASE]==case,'Live formal AB conclusion changed')
        require(original.api('/api/runs/'+run+'/transcript')==entries,'Live shared transcript changed')
    return evaluation/'result.json',{CASE:case}


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('root',type=Path);parser.add_argument('--capture-runtime',action='store_true');parser.add_argument('--record-replay',action='store_true');parser.add_argument('--diagnostic-only',action='store_true');parser.add_argument('--live',action='store_true');args=parser.parse_args();folder=args.root.resolve()
    if folder.name!=FOLDER:folder=folder/FOLDER
    if args.capture_runtime:runtime.capture_runtime(folder)
    if args.record_replay:
        require(not(folder/'native-reader-replay.json').exists(),'Immutable replay exists');(folder/'native-reader-replay.json').write_text(json.dumps(runtime.replay(folder),indent=2)+'\n')
    verify_adoption(folder,live=args.live,formal=not args.diagnostic_only);print('Native accepted-B supersession counterexample verified; shared A-case original sends unchanged')
