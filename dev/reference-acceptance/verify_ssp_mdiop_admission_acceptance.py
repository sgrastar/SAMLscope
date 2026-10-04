#!/usr/bin/env python3
"""Complete native admission, deployed Reader replay and formal outcome; no runtime-key claim."""
import argparse,base64,importlib.util,json,subprocess,tempfile,urllib.request,xml.etree.ElementTree as ET
from pathlib import Path
FOLDER='ssp-mdiop-native-admission-v175-r1';CASE='IIP-MD05-c-idp-01';REPO=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('ssp_mdiop_archived_runtime',Path(__file__).with_name('verify_ssp_consent_ui_acceptance.py'));runtime=importlib.util.module_from_spec(spec);spec.loader.exec_module(runtime)
runtime.HELPER='VerifySimpleSamlPhpMdiopAdmission';runtime.RUNTIME='runtime';runtime.CLASSES=('SimpleSamlPhpMdiopAdmissionEvidence','KeycloakMdiopRepresentationEvidenceFile','KeycloakMdiopRepresentationConfigurationTestCase','MetadataAlgorithmEvidence','ApprovedConfigCaseRegistry')
sha,read,require=runtime.sha,runtime.read,runtime.require
def locate(root):
 root=Path(root).resolve();return root if root.name==FOLDER else root/FOLDER
def api(path,body=None):
 q=urllib.request.Request('http://localhost:18080'+path,data=None if body is None else json.dumps(body).encode(),headers={'Content-Type':'application/json'})
 with urllib.request.urlopen(q,timeout=40) as r:return json.load(r)
def native_parser_replay(folder):
 path=folder/'independent-native-parser-replay.json';require(not path.exists(),'Native replay is immutable');command=(folder/'native-parser-command.php').read_text();peer='http://localhost:18080/p/'+read(folder/'created.json')['run']['planId'];rows=[]
 for operation in read(folder/'operations.json'):
  variant=operation['variant'];raw=(folder/variant/'fixture.xml').read_bytes();result=subprocess.run(['docker','exec','-i','samlscope-reference-ssp','php','-r',command,peer,'default'],input=raw,capture_output=True,timeout=30)
  require(result.returncode==0 and result.stdout==(folder/variant/'parser.stdout').read_bytes() and result.stderr==(folder/variant/'parser.stderr').read_bytes(),'Independent native parse changed: '+variant);rows.append(dict(variant=variant,fixtureSha256=sha(raw),stdoutSha256=sha(result.stdout),bytesIdentical=True))
 for label,lookup,raw in [('missing-sp-role',peer,ET.tostring(ET.Element('{urn:oasis:names:tc:SAML:2.0:metadata}EntityDescriptor',dict(entityID=peer)))),('foreign-entity',peer+'/foreign',(folder/'control/fixture.xml').read_bytes())]:
  result=subprocess.run(['docker','exec','-i','samlscope-reference-ssp','php','-r',command,lookup,'default'],input=raw,capture_output=True,timeout=30);require(result.returncode!=0 and result.stdout==b'' and result.stderr,'Independent parser accepts negative control');rows.append(dict(control=label,returncode=result.returncode,inputSha256=sha(raw),rejected=True))
 path.write_text(json.dumps(dict(records=rows,nativeParserInvocations=21,productConfigurationWrites=0,protocolSends=0,humanOperations=0),indent=2)+'\n')
def verify(root,live=False,formal=True):
 folder=locate(root);created=read(folder/'created.json')['run'];run=created['id'];receipt=read(folder/'qualified-receipt.json');target=(folder/'target-metadata.xml').read_bytes();require(receipt['runId']==run and receipt['targetMetadataSha256']==sha(target),'Run target binding changed')
 transcript=read(folder/'transcript.json');entries={e['id']:e for e in transcript};require(len(entries)==len(transcript) and all(e['runId']==run for e in transcript),'Foreign or duplicate transcript');originals={}
 for row in read(folder/'decoded-manifest.json'):
  path=(folder/row['file']).resolve();raw=path.read_bytes();require(path.parent==(folder/'decoded').resolve() and not path.is_symlink() and row['id'] not in originals and sha(raw)==row['sha256'] and len(raw)==entries[row['id']]['decodedSamlBytes'],'Native original path/hash/length changed');originals[row['id']]=raw
 def original(ref):
  raw=originals[ref['reference']];require(sha(raw)==ref['sha256'],'Original ref changed');return json.loads(raw)
 operations=read(folder/'operations.json');required=set(__import__('verify_mdiop_acceptance').REQUIRED_FIXTURES)|{'control'}
 require(len(operations)==19 and {o['variant'] for o in operations}==required and all(o['status']=='native-admitted' and o['parserReturncode']==0 for o in operations),'Full native admission incomplete')
 require(len(receipt['members'])==19 and {m['variant'] for m in receipt['members']}==required,'Full receipt matrix changed')
 for member in receipt['members']:
  variant=member['variant'];raw=(folder/variant/'fixture.xml').read_bytes();native=original(member['native']);prepared=entries[member['preparedReference']]
  require(originals[prepared['id']]==raw and sha(raw)==member['fixtureSha256']==native['fixtureSha256'] and prepared['samlSummary']['variant']==variant,'Native received fixture differs')
  def decoded(label):
   raw=base64.b64decode(label['base64']);require(sha(raw)==label['sha256'],'Native encoded original changed');return raw
  require(decoded(native['parser']['input'])==raw and decoded(native['parser']['stdout'])==(folder/variant/'parser.stdout').read_bytes() and decoded(native['configuration'])==(folder/variant/'configuration.php').read_bytes() and decoded(native['readback'])==(folder/variant/'readback.json').read_bytes(),'Native collector original differs from Recorder')
 before=(folder/'original-sp-config.php').read_bytes();restore=read(folder/'restoration.json');require(before==(folder/'final-sp-config.php').read_bytes() and restore['restored'] and restore['original_sha256']==restore['final_sha256']==sha(before),'Native exact restoration incomplete')
 require(read(folder/'identity-before.json')==read(folder/'identity-after.json'),'Product identity changed')
 counts=read(folder/'operation-counts.json');require(counts==dict(nativeParserInvocations=21,protocolOperationsAttempted=2,nativeOriginalRecorderWrites=24,productConfigurationWriteAttempts=20,configurationApplyWrites=19,restorationWrites=1,runCreations=1,productRestarts=0,humanOperations=0,runtimeKeyInterpretationProven=False,restored=True,publicOriginalAugmentationAttempts=1),'Attempts or operation counts differ')
 initial=read(folder/'transcript-initial.json');require(transcript[:len(initial)]==initial and len(transcript)==len(initial)+1,'Pre-augmentation originals changed');history=read(folder/'augmentation-history.json');require(history['productConfigurationWrites']==history['productProtocolOperations']==history['humanOperations']==0 and history['addedOriginal']==receipt['baselineProtocolControl'],'Augmentation operation history differs')
 require(read(folder/'independent-native-parser-replay.json')['nativeParserInvocations']==21,'Independent native matrix not replayed')
 recorded=read(folder/'production-reader-replay.json');require(runtime.replay(folder)==recorded,'Archived production replay differs');proof=recorded['production_outcome'];require(proof['outcome']=='SATISFIED' and proof['reasonCode']=='metadata.mdiop.native-representation-admission-observed' and proof['details']['runtime_key_interpretation_proven'] is False and len(recorded['negative_controls'])==34 and set(recorded['negative_controls'].values())=={'NOT_VERIFIED'},'Full production proof or altered controls differs')
 privacy=folder/'privacy-projection-v176/projection.json'
 if privacy.exists():
  projection=read(privacy);require(projection['qualifiedReceiptUnchanged'] and projection['formalOutcomeUnchanged'] and projection['originalTranscriptUnchanged']
   and projection['productConfigurationWrites']==projection['protocolSends']==projection['runtimeProjectionWrites']==projection['humanOperations']==0,'Unused HTML projection affects evaluative evidence')
  require(all(sha((folder/name).read_bytes())==digest for name,digest in projection['protectedFiles'].items()),'Unused HTML projection changed protected proof')
  for row in projection['files']:
   raw=(folder/row['file']).read_bytes();require(sha(raw)==row['afterSha256'] and __import__('re').search(rb'_[0-9a-f]{40}',raw,__import__('re').I) is None,'Unused native HTML retains state identifier')
 if live:
  require(subprocess.check_output(['docker','exec','samlscope-reference-ssp','cat','/var/simplesamlphp/metadata/saml20-sp-remote.php'])==before,'Live SSP not restored');require(api('/api/runs/'+run+'/transcript')==transcript,'Live transcript differs')
 if not formal:return recorded
 evaluation=folder/'evaluation';result=read(evaluation/'result.json');case=next(c for q in result['requirements'] for c in q['cases'] if c['id']==CASE);require((case['outcome'],case['verdict'],case['reason_code'],case['attested'])==('SATISFIED','PASS','metadata.mdiop.native-representation-admission-observed',False),'Formal native admission outcome differs')
 require(result['run']['id']==run and result['target']['metadata_digest']=='sha256:'+sha(target),'Formal Run target changed');require(read(evaluation/'transcript-before.json')==read(evaluation/'transcript.json')==transcript,'Formal evaluation changed original transcript');require({e['reference'] for e in proof['evidence']}<={e['reference'] for e in case['evidence']},'Formal proof refs changed')
 execution=read(evaluation/'case-execution.json');require(execution['status']=='FINISHED' and execution['runId']==run and execution['caseId']==CASE and execution['outcome']['outcome']=='SATISFIED' and execution['outcome']['details']['configuration_confirmed'] is True,'Formal preparation/finish not recorded');require(all(execution['outcome']['details'].get(k)==v for k,v in proof['details'].items()),'Formal wrapper/native proof differs')
 require(read(evaluation/'receipt-readback.json')['sha256']==sha((folder/'qualified-receipt.json').read_bytes()),'Installed receipt readback differs')
 if live:require(next(c for q in api('/api/runs/'+run+'/result.json')['requirements'] for c in q['cases'] if c['id']==CASE)==case,'Live formal outcome differs')
 return evaluation/'result.json',{CASE:case}
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('root',type=Path);p.add_argument('--capture-runtime',action='store_true');p.add_argument('--record-replay',action='store_true');p.add_argument('--native-parser-replay',action='store_true');p.add_argument('--live',action='store_true');p.add_argument('--diagnostic-only',action='store_true');a=p.parse_args();folder=locate(a.root)
 if a.capture_runtime:runtime.capture_runtime(folder)
 if a.native_parser_replay:native_parser_replay(folder)
 if a.record_replay:
  path=folder/'production-reader-replay.json';require(not path.exists(),'Replay is immutable');path.write_text(json.dumps(runtime.replay(folder),indent=2)+'\n')
 if not any([a.capture_runtime,a.record_replay,a.native_parser_replay]):
  outcome=verify(folder,a.live,not a.diagnostic_only);print('SSP complete native MDIOP admission verified')
