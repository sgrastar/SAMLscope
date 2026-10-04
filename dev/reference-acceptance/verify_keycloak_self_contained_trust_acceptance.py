#!/usr/bin/env python3
"""Native MD06.c adoption using metadata-derived SIG/ENC originals, never self-attestation."""
import argparse,importlib.util,json,pathlib,subprocess,sys,zipfile
REPO=pathlib.Path(__file__).resolve().parents[2]
FOLDER='keycloak-native-self-contained-trust-v178-r1';SOURCE='keycloak-native-supersession-v177-r3';CASE='IIP-MD06-c-idp-01'
def module(name,path):
 spec=importlib.util.spec_from_file_location(name,path);result=importlib.util.module_from_spec(spec);spec.loader.exec_module(result);return result
runtime=module('native_trust_runtime',REPO/'dev/reference-acceptance/verify_ssp_intersection_capability_acceptance.py')
runtime.HELPER='VerifyKeycloakSelfContainedTrustEvidence'
runtime.CLASSES=tuple('com/samlscope/runner/cases/'+name+'.class' for name in ['KeycloakMetadataSupersessionEvidenceFile','KeycloakNativeRunEvidenceBridge','KeycloakSelfContainedTrustEvidenceFile','KeycloakSelfContainedTrustAttestedTestCase','ApprovedAttestedCaseRegistry'])
supersession=module('native_trust_supersession',REPO/'dev/reference-acceptance/verify_keycloak_metadata_supersession_acceptance.py')
sha,load,require=runtime.sha,runtime.load,runtime.require
SERVICES='213c45bb357e0881ead8284f12308e3c9fd8e09e7f0b6ec816f95f8b0921bea9'
SAML_CORE='191794d8be9289121c628f5e69380771b67f72ea869207248c2bbda253979e84'
def verify_adoption(root,live=False,formal=True):
 folder=pathlib.Path(root).resolve()
 if folder.name!=FOLDER:folder=folder/FOLDER
 source=folder.parent/SOURCE;supersession.verify_adoption(source,live=live)
 binding=load(folder/'source-binding.json');require(binding['folder']==SOURCE and set(binding['files'])=={'created.json','transcript.json','decoded-manifest.json','target-metadata.xml','qualified-receipt.json','browser-originals-manifest.json'},'Source proof binding differs')
 for name,digest in binding['files'].items():require(sha((source/name).read_bytes())==digest and (folder/name).read_bytes()==(source/name).read_bytes(),'Accepted source originals differ')
 receipt=load(folder/'trust-receipt.json');native=load(source/'qualified-receipt.json');created=load(folder/'created.json')['run'];run=created['id']
 require(receipt==dict(schema='samlscope-keycloak-self-contained-trust-v1',caseId=CASE,runId=run,campaignId='native-metadata-trust',targetMetadataSha256=native['targetMetadataSha256'],targetEntityId=native['targetEntityId'],peerEntityId=native['peerEntityId'],nativeCampaignReceiptSha256=sha((source/'qualified-receipt.json').read_bytes()),nativeServicesSha256=SERVICES,nativeSamlCoreSha256=SAML_CORE),'Native trust receipt scope differs')
 require(sha((folder/'native-source/native-services.jar').read_bytes())==SERVICES and (folder/'native-source/native-services.jar').read_bytes()==(source/'native-runtime/before-services.jar').read_bytes(),'Native operative service source differs')
 require(sha((folder/'native-source/native-saml-core.jar').read_bytes())==SAML_CORE,'Native hardcoded locator source differs')
 with zipfile.ZipFile(folder/'native-source/native-saml-core.jar') as jar:require(sha(jar.read('org/keycloak/rotation/HardcodedKeyLocator.class'))=='57eafbd9bb2e50166f3fd1093f9f1c0bdd2c922397b1aaefa73c2084c0322d1c','Actual native key locator differs')
 for row in load(folder/'decoded-manifest.json'):
  require(pathlib.Path(row['file']).parent==pathlib.Path('decoded') and (folder/row['file']).read_bytes()==(source/row['file']).read_bytes(),'Decoded originals altered')
 for row in load(folder/'browser-originals-manifest.json'):require((folder/row['file']).read_bytes()==(source/row['file']).read_bytes(),'Browser originals altered')
 require(load(folder/'operation-counts.json')==dict(product_configuration_writes=0,protocol_saml_requests=0,run_creations=0,product_restarts=0,human_operations=0,native_public_jar_reads=3,native_locator_inventory_reads=1,restoration_reused=True,source_configuration_writes=15,source_protocol_saml_requests=45,source_run_creations=3,source_costs_reused_not_new=True),'Operation costs differ')
 require(not(folder/'runtime/candidate-only.json').exists(),'Candidate runtime cannot be adopted')
 report=runtime.replay(folder);require(report==load(folder/'native-reader-replay.json'),'Archived production trust replay differs')
 require(report['runId']==run and report['caseId']==CASE and report['outcome']=='SATISFIED' and report['reasonCode']=='metadata.trust.self-contained-native-observed' and report['privateKeyExported'] is False and report['plaintextPersisted'] is False,'Native trust proof absent')
 require(len(report['checks'])==24 and report['checks']['native-metadata-only-signature-encryption']=='SATISFIED' and all(v=='NOT_VERIFIED' for k,v in report['checks'].items() if k!='native-metadata-only-signature-encryption'),'Altered original controls accepted')
 details=report['details'];require(details['additional_trust_input_required'] is False and details['proof_scope']=='recorded-native-signature-encryption-flow' and all(details[key] is True for key in ['native_originals_verified','restoration_verified','native_key_locator_source_verified','signature_verification_observed','metadata_key_encryption_decryption_observed','unrelated_key_decryption_rejected']),'Native SIG/ENC closure incomplete')
 if live:
  native_core=subprocess.check_output(['docker','exec','samlscope-reference-keycloak','sha256sum','/opt/keycloak/lib/lib/main/org.keycloak.keycloak-saml-core-26.7.2.jar'],text=True).split()[0]
  require(native_core==SAML_CORE,'Live native key locator implementation differs')
  installed=load(folder/'receipt-install.json');require(installed['runId']==run and len(installed['files'])==4 and installed['productConfigurationWrites']==installed['samlRequests']==0,'Native trust install scope differs')
  for row in installed['files']:
   require(row['path'].startswith('/data/metadata-rejection-evidence/'+run) and row['sha256']==sha((folder/row['file']).read_bytes()),'Installed source differs')
   actual=subprocess.check_output(['docker','exec','samlscope-reference-suite','sha256sum',row['path']],text=True).split()[0];require(actual==row['sha256'],'Live native trust payload differs')
 if not formal:return report
 evaluation=folder/'evaluation-v179';require(evaluation.is_dir(),'Correct provenance formal report absent');legacy=load(folder/'evaluation/result.json');legacy_case=next(c for q in legacy['requirements'] for c in q['cases'] if c['id']==CASE);require(legacy_case['attested'] is True and legacy_case['outcome']=='SATISFIED','Legacy provenance history altered');result=load(evaluation/'result.json');cases={c['id']:c for q in result['requirements'] for c in q['cases']};case=cases[CASE]
 require(result['run']['id']==run and result['target']['metadata_digest']=='sha256:'+native['targetMetadataSha256'],'Formal native trust scope differs')
 require((case['outcome'],case['verdict'],case['reason_code'],case['attested'])==('SATISFIED','PASS','metadata.trust.self-contained-native-observed',False),'Formal native trust outcome differs')
 require(load(evaluation/'transcript-before.json')==load(evaluation/'transcript.json')==load(source/'transcript.json'),'Native trust reconsideration changed history')
 execution=load(evaluation/'case-execution.json');require(execution==load(folder/'evaluation/case-execution.json'),'Provenance projection changed stored case');observed=execution['outcome'];observed_details=dict(observed['details']);previous=observed_details.pop('previous_recorded_evidence_result',None)
 old=next(c for q in load(source/'result.json')['requirements'] for c in q['cases'] if c['id']==CASE)
 require(previous is None or previous.get('details')==old.get('details',{}),'Previous trust details differ')
 require(execution['runId']==run and execution['caseId']==CASE and execution['status']=='FINISHED' and previous is not None and previous['outcome']==old['outcome']=='NOT_VERIFIED' and previous['reason_code']==old['reason_code']=='attestation.interaction-disallowed' and previous['evidence']==old['evidence']==[] and previous['revision']+1==execution['revision'],'Previous native trust result audit differs')
 require(observed['outcome']==report['outcome'] and observed['reasonCode']==report['reasonCode'] and observed_details==report['details'] and observed['evidence']==report['evidence']==case['evidence'],'Formal wrapper differs from production reader')
 require(cases['IIP-MD06-ab-idp-01']['verdict']=='NOT_VERIFIED','Supersession case silently adopted')
 require(case['evidence_class']=='PROTOCOL_OBSERVED' and case==dict(legacy_case,attested=False),'Native proof provenance projection differs');provenance=load(evaluation/'provenance-runtime.json');require(provenance['runtime']=='reference-combined-v179' and provenance['runnerSha256']=='b3a7c7850cbcaa429a3aa054d39060375a5dc846870e5e5a73259cde9511bef0' and provenance['caseExecutionUnchanged'] is True and provenance['productConfigurationWrites']==provenance['samlRequests']==0,'Provenance runtime or scope differs');require(sha((evaluation/'runner.jar').read_bytes())==provenance['runnerSha256'],'Actual provenance renderer binary differs');
 with zipfile.ZipFile(evaluation/'runner.jar') as jar:require(provenance['classes']=={name:sha(jar.read(name)) for name in ['com/samlscope/runner/result/ResultDocument$CaseView.class','com/samlscope/runner/result/ResultDocumentAssembler.class']},'Provenance production classes differ')
 return evaluation/'result.json',{CASE:case}
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('root',type=pathlib.Path);p.add_argument('--capture-runtime',action='store_true');p.add_argument('--record-replay',action='store_true');p.add_argument('--diagnostic-only',action='store_true');p.add_argument('--live',action='store_true');a=p.parse_args();folder=a.root.resolve()
 if folder.name!=FOLDER:folder=folder/FOLDER
 if a.capture_runtime:runtime.capture_runtime(folder)
 if a.record_replay:require(not(folder/'native-reader-replay.json').exists(),'Immutable replay exists');(folder/'native-reader-replay.json').write_text(json.dumps(runtime.replay(folder),indent=2)+'\n')
 verify_adoption(folder,live=a.live,formal=not a.diagnostic_only);print('Native metadata-derived SIG/ENC trust verified')
