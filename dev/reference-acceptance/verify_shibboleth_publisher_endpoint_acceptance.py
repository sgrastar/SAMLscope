#!/usr/bin/env python3
"""Replay the measured static Shibboleth publication and operative native endpoint proof."""
import argparse,hashlib,importlib.util,json,os,pathlib,subprocess,tempfile,urllib.request,zipfile
REPO=pathlib.Path(__file__).resolve().parents[2];FOLDER='shibboleth-publisher-endpoints-r3'
HELPER='VerifyShibbolethPublisherEndpointEvidence';C1='IIP-MD05-c1-idp-01';C3='IIP-MD05-c3-idp-01'
PINS={"ReadNativePublisherKeyStoredConclusions": "b4887c7dd1137ea02b7c75d3bf7405e5669e56f0f4971de26ca80a66b8b593fd", "VerifyShibbolethPublisherEndpointEvidence": "ce6449191d324bf353afcbb45210a2edaf8edc23a315a3847866e77d7daaf8f2", "api": "24cb469496204e912e496ec317e4066fa434d0270a951617277f0b349259de8b", "core": "1d6e0020c915f50e78902554c06b61916a3f49e50de78d3bc23c6089d312babe", "dependencyPrioritySha256": "be641da1b06994329516c188c6727a9591bf2c9a94ca9190e48a5e143c2b7f90", "peer": "133703391229d9ce4247af5bb3d39a1853b9caa816307fe56a17148ff4a3242c", "runner": "6531e5b40901ff1749d5a7bac6f0416b01f51063a1a8c9b7469b116897304a6b", "saml": "875287c4ba53b1f559c22b384efe65cfdbbbd16cdb4a31ecac66ca1f0ee0f1d6", "store": "c4482cd06f9290a3592f0fceac2c9ec2d7603ea0557d1edc885e1c3d51bd8ece"} # Independently qualified deployed v231 archive.
QUALIFIED_DEPENDENCIES='deployment-v231-r2/isolated-test-overlay.json'
sha=lambda b:hashlib.sha256(b).hexdigest();load=lambda p:json.loads(p.read_bytes())
def require(b,why):
 if not b:raise ValueError(why)
def save(p,v):
 require(not p.exists(),'Immutable output exists: '+str(p));p.write_text(json.dumps(v,indent=2)+'\n')
def locate(root,product='shibboleth'):
 require(product=='shibboleth','Unsupported product');root=pathlib.Path(root).absolute();require(not any(p.is_symlink() for p in [root,*root.parents]),'Unsafe evidence root');folder=root if (root/'receipt/manifest.json').is_file() else root/FOLDER
 require(folder.is_dir() and not any(p.is_symlink() for p in [folder,*folder.rglob('*')]),'Unsafe native originals');return folder.resolve()
def generic():
 """Use shared placement/archive/readback operations in a fresh isolated module."""
 spec=importlib.util.spec_from_file_location('shib_publisher_shared_operations',pathlib.Path(__file__).with_name('verify_native_publisher_key_inventory_acceptance.py'));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
 m.HELPER=HELPER;m.PINS=PINS;m.QUALIFIED_DEPENDENCIES=QUALIFIED_DEPENDENCIES;m.verify_files=verify_files;m.replay=replay;return m
HISTORICAL_CATALOG_COMMIT='064df1c2c49d8f4e2b718c056970f06562c40f4e'
HISTORICAL_CATALOG_PINS={'cases_sha256':'431d9aa863d5d882d37266667a8fd20547d1fe6d037274b8d59ff66347f5ecd4','coverage_sha256':'2bee3db74c9be9908710bbe18935c73454f1ed4c5c0f06bdab1cf18deaef843c','specs_sha256':'acee5ce8c348fbc5e02f77bd2f5b8703a632dd69aea857b14b97812ff6cc39d9'}

def same_publisher_case_semantics(old_cases,current_cases,old_coverage,current_coverage):
 """Only exact unchanged selected cases and their owning/transitive obligations may reuse old scope."""
 import yaml
 case_maps=[{r['id']:r for r in yaml.safe_load(raw)['cases']} for raw in [old_cases,current_cases]]
 coverage_maps=[{o['key']:(r,o) for r in yaml.safe_load(raw)['requirements'] for o in r['obligations']} for raw in [old_coverage,current_coverage]]
 pending=[]
 for case in [C1,C3]:
  old=case_maps[0][case];new=case_maps[1][case];require(old==new,'Historical selected case semantics changed')
  canonical={k:v for k,v in old.items() if k not in ['case_digest','review']}
  require('sha256:'+sha(json.dumps(canonical,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode())==old['case_digest'],'Historical case canonical digest differs')
  pending.append(old['obligation'])
 seen=set()
 while pending:
  key=pending.pop()
  if key in seen:continue
  seen.add(key);old_req,old=coverage_maps[0][key];new_req,new=coverage_maps[1][key]
  require(old==new,'Historical owning or linked obligation semantics changed')
  require({k:v for k,v in old_req.items() if k!='obligations'}=={k:v for k,v in new_req.items() if k!='obligations'},'Historical normative source section binding changed')
  for link in old.get('linked_obligations',[]):
   require(isinstance(link,dict) and link.get('obligation') in coverage_maps[0],'Unsupported historical obligation link')
   pending.append(link['obligation'])
 return case_maps[0][C1]

def approved_publisher_source_context(planned):
 import yaml
 from preflight_observation_adoption import approved_case,strict_bytes
 current,current_pins=approved_case(C1,REPO)
 if planned['catalogDigests']==current_pins:return current,current_pins
 require(planned['catalogDigests']==HISTORICAL_CATALOG_PINS,'Unrecognized historical catalog identity')
 proof=subprocess.run(['git','verify-commit',HISTORICAL_CATALOG_COMMIT],cwd=REPO,capture_output=True)
 require(proof.returncode==0,'Historical signed catalog authority verification failed')
 originals={}
 for name in ['cases','coverage','specs','predicates']:
  raw=subprocess.run(['git','show',HISTORICAL_CATALOG_COMMIT+':tests/'+name+'.yaml'],cwd=REPO,capture_output=True,check=True).stdout
  originals[name]=raw
  if name!='predicates':require(sha(raw)==HISTORICAL_CATALOG_PINS[name+'_sha256'],'Historical catalog bytes changed')
 current_bytes={name:strict_bytes(REPO/'tests'/ (name+'.yaml')) for name in originals}
 require(originals['specs']==current_bytes['specs'] and originals['predicates']==current_bytes['predicates'],'Normative source/predicate semantics changed')
 approved=same_publisher_case_semantics(originals['cases'],current_bytes['cases'],originals['coverage'],current_bytes['coverage'])
 return approved,dict(HISTORICAL_CATALOG_PINS)

def publisher_scope_preflight(planned, result_before):
 from preflight_observation_adoption import scope_preflight
 # Use the actual owning catalog bytes for the original preflight report, not
 # current bytes or a rewritten specification_digests field.
 if planned['catalogDigests']!=HISTORICAL_CATALOG_PINS:return scope_preflight(C1,result_before,repo=REPO)
 approved_publisher_source_context(planned)
 with tempfile.TemporaryDirectory(prefix='publisher-owning-catalog-',dir='/private/tmp') as temp:
  root=pathlib.Path(temp);(root/'tests').mkdir()
  for name in ['cases','coverage','specs']:
   raw=subprocess.run(['git','show',HISTORICAL_CATALOG_COMMIT+':tests/'+name+'.yaml'],cwd=REPO,capture_output=True,check=True).stdout
   require(sha(raw)==HISTORICAL_CATALOG_PINS[name+'_sha256'],'Owning preflight catalog changed')
   (root/'tests'/ (name+'.yaml')).write_bytes(raw)
  return scope_preflight(C1,result_before,repo=root)

def verify_files(folder):
 receipt=folder/'receipt';m=load(receipt/'manifest.json');run=m['runId'];require(m['adapter']=='shibboleth-stock-publisher-endpoints-v1' and m['selectedPath']=='stock-current-role' and m['counterfactualCalibrationOnly'] is False,'Non-stock native evidence')
 created=load(folder/'created.json')['run'];plan=load(folder/'plan.json')
 for _ in range(3):
  if 'plan' in plan:plan=plan['plan']
 require(created['id']==run and created['planId']==m['planId']==plan['id'] and plan['profile']=='metadata_idp' and plan['target']['kind']=='IDP' and plan['target']['entityId']==m['entityId'],'Wrong original Run, Plan, profile or target')
 from preflight_observation_adoption import scope_preflight
 planned=load(folder/'planned-scope.json');approved,digests=approved_publisher_source_context(planned);require(planned['runId']==run and planned['caseId']==C1 and planned['caseDigest']==approved['case_digest'] and planned['catalogDigests']==digests and planned['targetMetadataSha256']==m['targetMetadataSha256'],'Approved source scope differs')
 require(sha((folder/'deployed-api.jar').read_bytes())==planned['deployedApiSha256'],'Creation API archive changed')
 with zipfile.ZipFile(folder/'deployed-api.jar') as z:require(z.read('profiles/metadata_idp.json')==(receipt/'planned-profile.json').read_bytes(),'Deployed creation profile differs')
 slots=[r for r in load(receipt/'planned-profile.json')['cases'] if r['id']==C1];require(len(slots)==1 and slots[0]['digest']==approved['case_digest'],'Approved publisher case missing from actual deployed profile')
 require(load(folder/'formal-slot-preflight.json')==publisher_scope_preflight(planned,folder/'result-before.json') and load(folder/'formal-slot-preflight.json')['scope_ready'],'Formal case/profile preflight differs')
 files={str(p.relative_to(receipt)):sha(p.read_bytes()) for p in receipt.rglob('*') if p.is_file() and p.name!='manifest.json'};require(files==m['files'],'Public receipt changed')
 entries=load(folder/'transcript.json');by={e['id']:e for e in entries};require(len(by)==len(entries) and all(e['runId']==run for e in entries),'Foreign or duplicated original history')
 for row in load(folder/'decoded-manifest.json'):
  p=folder/row['file'];raw=p.read_bytes();require(p.parent==folder/'decoded' and sha(raw)==row['sha256'] and len(raw)==by[row['id']]['decodedSamlBytes'],'Decoded original changed')
 require((folder/'target-metadata.xml').read_bytes()==(receipt/'target-metadata.xml').read_bytes() and sha((folder/'target-metadata.xml').read_bytes())==m['targetMetadataSha256'],'Publication changed')
 return m,run,entries
def cumulative_operations(folder,write=False):
 """Preserve failed setups separately from native applications actually observed."""
 attempts=[];total=dict(configurationWriteAttempts=0,successfulConfigurationWrites=0,productSettings=0,configurationRestorations=0,metadataReloadAttempts=0,successfulNativeReloads=0,observedNativeApplications=0,nativeCommands=0,directMetadataGets=0,credentialPosts=0,samlSubmissions=0,personOperations=0,productRestarts=0)
 for name in ['shibboleth-publisher-endpoints-r1','shibboleth-publisher-endpoints-r2',FOLDER]:
  prior=folder.parent/name;require(prior.is_dir() and not any(p.is_symlink() for p in [prior,*prior.rglob('*')]),'Unsafe attempt originals');commands=load(prior/'native-command-counts.json');rows=load(prior/'operations.json') if (prior/'operations.json').exists() else [];reads=load(prior/'publication-reads.json') if (prior/'publication-reads.json').exists() else [];cost=load(prior/'operation-counts.json') if (prior/'operation-counts.json').exists() else dict(credentialPosts=0,samlSubmissions=0,personOperations=0,productRestarts=0)
  settings=[r for r in rows if r['operation']=='write'];reloads=[r for r in rows if r['operation']=='reload'];counts=dict(configurationWriteAttempts=len(settings),successfulConfigurationWrites=sum(r.get('completed',False) for r in settings),productSettings=sum(r.get('completed',False) and not r['label'].startswith('restore-') for r in settings),configurationRestorations=sum(r.get('completed',False) and r['label'].startswith('restore-') for r in settings),metadataReloadAttempts=len(reloads),successfulNativeReloads=sum(r.get('completed',False) for r in reloads),observedNativeApplications=2 if (prior/'receipt/state-before.json').exists() else 0,nativeCommands=len(commands),directMetadataGets=len(reads),**{k:cost[k] for k in ['credentialPosts','samlSubmissions','personOperations','productRestarts']})
  if name!=FOLDER:require((prior/'failure.json').is_file() and counts['credentialPosts']==counts['samlSubmissions']==0,'Failed attempts cannot become protocol proof')
  if name.endswith('-r1'):require(not rows and counts['productSettings']==0,'Initial privacy-guard failure changed settings')
  if name.endswith('-r2'):require(cost['restored'] and len(reloads)==3 and counts['successfulNativeReloads']==2 and counts['observedNativeApplications']==0,'Malformed namespace failure accounting changed')
  if name==FOLDER:require(cost['restored'] and counts['productSettings']==3 and counts['configurationRestorations']==2 and counts['credentialPosts']==counts['samlSubmissions']==1,'Qualified campaign counts changed')
  ledger={str(p.relative_to(prior)):sha(p.read_bytes()) for p in prior.rglob('*') if p.is_file() and (name!=FOLDER or p.parent==prior and p.name in ['operations.json','native-command-counts.json','publication-reads.json','operation-counts.json'])}
  attempts.append(dict(folder=name,counts=counts,originalInventory=ledger,qualified=name==FOLDER))
  for k,v in counts.items():total[k]+=v
 failed=load(folder/'receipt/controls-compilation-r1/failed-attempt.json');native=load(folder/'native-controls-qualification.json');require(failed['compilationAttempts']==1 and failed['executions']==0 and failed['ownedHelperRemoved'] and native['nativeBuilderExecutions']==native['nativeCompilations']==1 and native['ownedHelperRemoved'],'Isolated compilation attempts changed')
 result=dict(schema='samlscope-shibboleth-publisher-cumulative-operations-v1',attempts=attempts,totals=total,isolatedNativeControlCompilationAttempts=2,successfulNativeControlCompilations=1,isolatedNativeControlExecutions=1,ownedNativeHelpersRemoved=True,ecpProtocolSubmissions=0,staticProductPublicationChanged=False,rolloverOrCompromiseOperations=0)
 if write:save(folder/'cumulative-operations.json',result)
 return result
def replay_native_controls(folder):
 """Execute installed native producer bytes every generation, with no outcome cache."""
 receipt=folder/'receipt';m=load(receipt/'manifest.json');c=m['controls'];original=load(receipt/m['originals'][c['original']]['file']);initial=load(receipt/'state-initial.json');pins=initial['classpathSha256']
 require(pins==original['nativeClasspathSha256'],'Native closure differs');libs=receipt/'native-libraries';require({p.name:sha(p.read_bytes()) for p in libs.iterdir()}=={pathlib.Path(k).name:v for k,v in pins.items()},'Immutable native classpath changed')
 source=receipt/c['sourceFile'];require(sha(source.read_bytes())==original['sourceSha256'],'Native source changed');cp=':'.join(str(p.resolve()) for p in sorted(libs.iterdir()));env=dict(os.environ)
 for k in ['JAVA_OPTS','SHIB_OPTS','CLASSPATH','JAVA_TOOL_OPTIONS','JDK_JAVA_OPTIONS']:env.pop(k,None)
 with tempfile.TemporaryDirectory(prefix='shib-publisher-native-replay-') as name:
  tmp=pathlib.Path(name);classes=tmp/'classes';r=subprocess.run(['javac','--release','17','-sourcepath','','-cp',cp,'-d',str(classes),str(source)],capture_output=True,timeout=60,env=env);require(r.returncode==0,'Native control replay compiler failed')
  require(all(p.name.startswith('ObserveShibbolethPublisherControls') for p in classes.rglob('*.class')),'Native helper shadows product classes')
  r=subprocess.run(['java','-cp',str(classes)+':'+cp,'ObserveShibbolethPublisherControls',str((receipt/c['inputFile']).resolve()),str(tmp/'output')],capture_output=True,timeout=90,env=env);require(r.returncode==0,'Native control execution replay failed')
  for name,key in [('positive.xml','positiveOutputFile'),('negative.xml','negativeOutputFile')]:require((tmp/'output'/name).read_bytes()==(receipt/c[key]).read_bytes(),'Native control output replay differs')
  replay=load(tmp/'output/observation.json');captured=load(receipt/c['observationFile']);require({k:v for k,v in replay.items() if k!='nativeClassOrigins'}=={k:v for k,v in captured.items() if k!='nativeClassOrigins'},'Native observation differs')
  require(set(replay['nativeClassOrigins'])==set(captured['nativeClassOrigins']),'Native origin scope differs')
  for name,origin in replay['nativeClassOrigins'].items():require(pathlib.Path(origin.removeprefix('file:')).parent==libs and pathlib.Path(origin).name==pathlib.Path(captured['nativeClassOrigins'][name]).name,'Native class escaped archived library')
 return dict(executions=1,nativeLibraryCount=len(pins),productSettings=0,samlSubmissions=0,credentialPosts=0,personOperations=0)
def replay(folder):
 verify_files(folder);native=replay_native_controls(folder)
 # The shared replay function is deliberately called directly, after restoring
 # its original function identity in this fresh module, to avoid recursion.
 spec=importlib.util.spec_from_file_location('shib_publisher_archived_replay',pathlib.Path(__file__).with_name('verify_native_publisher_key_inventory_acceptance.py'));shared=importlib.util.module_from_spec(spec);spec.loader.exec_module(shared);shared.HELPER=HELPER;shared.PINS=PINS
 result=shared.replay(folder);result['nativeProducerReplay']=native;return result
def capture_runtime(folder):return generic().capture_runtime(folder)
def install(folder):generic().install(folder)
def formal(folder):generic().formal(folder)
def verify(root,product='shibboleth',live=False):
 folder=locate(root,product);m,run,entries=verify_files(folder);observed=load(folder/'native-reader-replay.json');require(replay(folder)==observed,'Archived proof replay differs')
 require(load(folder/'cumulative-operations.json')==cumulative_operations(folder),'Campaign accounting differs')
 require(len(observed['negativeControls'])>=29 and set(observed['negativeControls'].values())=={'NOT_VERIFIED'} and set(observed['approvedMutants'])=={C1} and all(observed['wrapperLifecycle'].values()) and observed['counterfactualAdopted'] is False and observed['developmentOnly'] is False,'Controls or native provenance incomplete')
 outcomes=observed['caseOutcomes'];require(outcomes[C1]['outcome']=='VIOLATED' and outcomes[C3]['outcome']=='NOT_VERIFIED','Partial endpoint proof was overclaimed')
 require(outcomes[C1]['details']['missing_metadata_items']==['endpoint:SingleSignOnService:urn:oasis:names:tc:SAML:2.0:bindings:SOAP:http://localhost:18280/idp/profile/SAML2/SOAP/ECP'],'Different omission')
 shared=generic();installation=load(folder/'receipt-installation.json');require(installation['records']==m['files']|{'manifest.json':sha((folder/'receipt/manifest.json').read_bytes())} and installation['readBackVerified'] and installation['atomicSameDataFilesystem'] and installation['stockSelectedPath'],'Placement differs')
 ev=folder/'evaluation-actual';result=load(ev/'result.json');cases=shared.public_cases(result);before=shared.public_cases(load(ev/'result-before.json'));require(result['run']['id']==run and result['target']['metadata_digest']=='sha256:'+m['targetMetadataSha256'] and load(ev/'transcript-before.json')==load(ev/'transcript.json')==entries,'Formal Run/publication/originals differ')
 import native_publisher_stored_outcome as stored
 after=stored.compare_stored(folder,'runtime-actual',C1,outcomes[C1],before_name='evaluation-actual/stored-before-c1.json',after_name='evaluation-actual/stored-after-c1.json')
 case=cases[C1];require((case['outcome'],case['verdict'],case['reason_code'],case['evidence_class'],case['attested'])==('VIOLATED','FAIL','metadata.publisher.role-description-incomplete','OPERATOR_ASSISTED',False) and case['evidence']==outcomes[C1]['evidence'] and after['verdict']=='FAIL','Central conclusion/provenance differs')
 require(cases[C3]==before[C3] and cases[C3]['outcome']=='NOT_VERIFIED' and {k:v for k,v in cases.items() if k!=C1}=={k:v for k,v in before.items() if k!=C1},'Unrelated or incomplete cases changed')
 if live:
  require(shared.api('/api/runs/'+run+'/transcript')==entries and shared.public_cases(shared.api('/api/runs/'+run+'/result.json'))[C1]==case,'Live formal history differs')
  require(shared.readback_inventory(installation['path'])==installation['records'],'Live receipt differs')
  restored=load(folder/'receipt/state-restored.json');native=json.loads(subprocess.check_output(['docker','inspect','--format','{"containerId":{{json .Id}},"image":{{json .Image}},"startedAt":{{json .State.StartedAt}},"running":{{json .State.Running}},"mounts":{{json .Mounts}}}','samlscope-reference-shibboleth'],timeout=30));require(native==restored['runtime'],'Live product runtime differs')
  for path,ref in restored['configurationFiles'].items():require(subprocess.check_output(['docker','exec','samlscope-reference-shibboleth','sha256sum',path],timeout=30).decode().split()[0]==ref['sha256'],'Live native restoration differs')
  with urllib.request.urlopen(m['entityId'],timeout=30) as r:require(r.status==200 and sha(r.read())==m['targetMetadataSha256'],'Live actual static publication differs')
 return ev/'result.json',{C1:case}
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('root',type=pathlib.Path);p.add_argument('--record-costs',action='store_true');p.add_argument('--capture-runtime',action='store_true');p.add_argument('--record-replay',action='store_true');p.add_argument('--install',action='store_true');p.add_argument('--formal',action='store_true');p.add_argument('--live',action='store_true');a=p.parse_args();folder=locate(a.root)
 if a.record_costs:print(json.dumps(cumulative_operations(folder,True)['totals'],indent=2))
 elif a.capture_runtime:print(json.dumps(capture_runtime(folder),indent=2))
 elif a.record_replay:save(folder/'native-reader-replay.json',replay(folder));print('Archived native producer and Reader replay passed')
 elif a.install:install(folder);print('Stock configuration proof installed')
 elif a.formal:formal(folder);print('Formal readback captured')
 else:path,cases=verify(a.root,live=a.live);print(json.dumps(dict(result=str(path),cases=list(cases))))
