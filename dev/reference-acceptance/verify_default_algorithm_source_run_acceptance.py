#!/usr/bin/env python3
"""One fresh ECP Run bound explicitly to the unchanged complete original browser ALG08.c campaign."""
import argparse,hashlib,importlib.util,json,os,pathlib,re,secrets,shutil,subprocess,sys,tempfile,urllib.request,xml.etree.ElementTree as ET
REPO=pathlib.Path(__file__).resolve().parents[2]
sys.path[:0]=[str(REPO/'dev/shibboleth'),str(REPO/'dev/reference-acceptance')]
from default_algorithm_source_run_capture import capture as capture_scope
import verify_shibboleth_default_algorithm_acceptance as original
spec=importlib.util.spec_from_file_location('source_run_api',REPO/'dev/keycloak/import_metadata_batch.py');api_module=importlib.util.module_from_spec(spec);spec.loader.exec_module(api_module)
api,BASE=api_module.api,api_module.BASE
SHA=lambda b:hashlib.sha256(b).hexdigest()
READ=lambda p:json.loads(pathlib.Path(p).read_bytes())
CASE='IIP-ALG08-c-idp-01';SOURCE='run_K56H9VMXYGKZS1117Y0V66AHYQ'
SOURCE_FOLDER=REPO/'build/acceptance/reference-20261004/shibboleth-default-algorithm-r7'
SUITE='samlscope-reference-suite';NATIVE='samlscope-reference-shibboleth'
def require(value,why):
    if not value:raise ValueError(why)
def command(argv,timeout=90):return subprocess.run(list(map(str,argv)),capture_output=True,check=True,timeout=timeout)
def save(path,value):
    require(not path.exists(),'Immutable campaign artifact already exists')
    path.write_text(json.dumps(value,sort_keys=True,indent=2)+'\n')
def case_digest():
    rows=[r for r in READ(REPO/'profiles/ecp_idp.json')['cases'] if r['id']==CASE]
    require(len(rows)==1,'Approved destination profile lacks whole case');return rows[0]['digest']
def gradle_inputs():
    paths=set(REPO.rglob('build.gradle.kts'))|{REPO/'settings.gradle.kts',REPO/'gradle.properties',REPO/'gradle/libs.versions.toml',REPO/'gradle/verification-metadata.xml'}
    return {str(p.relative_to(REPO)):SHA(p.read_bytes()) for p in sorted(paths) if p.is_file() and 'build' not in p.relative_to(REPO).parts}
def archive(folder,deployed=False):
    a=folder/'reader';a.mkdir();pins={}
    actual_before=live_project_digests() if deployed else None
    for module in ['runner','core','saml','store']:
        p=REPO/module/'build/libs'/(module+'-0.1.0.jar');target=a/('suite-'+module+'-0.1.0.jar')
        if deployed:command(['docker','cp',SUITE+':/opt/samlscope/lib/'+module+'-0.1.0.jar',target])
        else:shutil.copyfile(p,target)
        require(target.stat().st_nlink==1,'Mutable project JAR hardlink');pins[target.name]=SHA(target.read_bytes())
    p=a/'suite-api-0.1.0.jar';command(['docker','cp',SUITE+':/opt/samlscope/lib/api-0.1.0.jar',p]);pins[p.name]=SHA(p.read_bytes())
    if deployed:require(actual_before==live_project_digests()=={name.removeprefix('suite-'):digest for name,digest in pins.items()},'Deployed project JAR bytes changed while archiving')
    helper=a/'VerifyDefaultAlgorithmSourceRun.java';shutil.copyfile(REPO/'dev/reference-acceptance/VerifyDefaultAlgorithmSourceRun.java',helper);pins[helper.name]=SHA(helper.read_bytes())
    dependencies=READ(SOURCE_FOLDER/'reader-v217/verification-dependencies.json');original.dependency_classpath(SOURCE_FOLDER/'reader-v217')
    save(a/'verification-dependencies.json',dependencies)
    java=pathlib.Path(os.environ.get('JAVA_HOME','/Library/Java/JavaVirtualMachines/jdk-21.jdk/Contents/Home'))/'bin'
    projects=[a/('suite-'+m+'-0.1.0.jar') for m in ['runner','core','saml','store','api']]
    cp=':'.join(map(str,projects))+':'+':'.join(r['path'] for r in dependencies);classes=a/'classes';classes.mkdir()
    command([java/'javac','-cp',cp,'-d',classes,helper]);save(a/'pins.json',dict(files=pins,deployedRuntimeArchive=deployed,deployedProjectSha256=actual_before,gradleInputSha256=gradle_inputs(),dependencyInventorySha256=SHA((a/'verification-dependencies.json').read_bytes()),classes={str(p.relative_to(classes)):SHA(p.read_bytes()) for p in classes.rglob('*.class')},projectArchivesFirst=[p.name for p in projects],thirdPartyOrder=[r['name'] for r in dependencies]))
    return a
def remote(folder,mode,run,receipt,output):
    a=folder/'reader';pins=READ(a/'pins.json');dependencies=READ(a/'verification-dependencies.json')
    require(pins['gradleInputSha256']==gradle_inputs(),'Gradle inputs changed; a new explicit verification generation is required')
    for name,digest in pins['files'].items():require(SHA((a/name).read_bytes())==digest,'Immutable reader archive changed')
    require(SHA((a/'verification-dependencies.json').read_bytes())==pins['dependencyInventorySha256'],'Dependency inventory changed')
    for r in dependencies:require(SHA(pathlib.Path(r['path']).read_bytes())==r['sha256'],'Actual dependency bytes changed')
    actual={line.split()[1].rsplit('/',1)[-1]:line.split()[0] for line in command(['docker','exec',SUITE,'sha256sum',*['/opt/samlscope/lib/'+r['name'] for r in dependencies]]).stdout.decode().splitlines()}
    require(actual=={r['name']:r['sha256'] for r in dependencies},'Live dependency bytes differ from the immutable verification generation')
    for name,digest in pins['classes'].items():require(SHA((a/'classes'/name).read_bytes())==digest,'Compiled archived helper changed')
    path='/tmp/default-source-run-'+secrets.token_hex(6);command(['docker','exec','-u','0',SUITE,'mkdir',path])
    try:
        command(['docker','cp',str(a/'classes'),SUITE+':'+path+'/classes'])
        for name in pins['projectArchivesFirst']:command(['docker','cp',str(a/name),SUITE+':'+path+'/'+name])
        command(['docker','cp',str(receipt),SUITE+':'+path+'/receipt']);command(['docker','exec','-u','0',SUITE,'chmod','-R','a+rX',path])
        uid=command(['docker','exec',SUITE,'id','-u']).stdout.decode().strip();command(['docker','exec','-u','0',SUITE,'chown','-R',uid+':'+uid,path])
        cp=':'.join(path+'/'+p for p in pins['projectArchivesFirst'])+':'+path+'/classes:'+':'.join('/opt/samlscope/lib/'+r['name'] for r in dependencies)
        result=subprocess.run(['docker','exec',SUITE,'java','-cp',cp,'com.samlscope.runner.cases.VerifyDefaultAlgorithmSourceRun',mode,'/data',run,SOURCE,case_digest(),path+'/receipt',path+'/report.json'],capture_output=True,timeout=180)
        require(result.returncode==0,'Current source binding replay failed: '+result.stderr.decode(errors='replace')[-5000:])
        command(['docker','cp',SUITE+':'+path+'/report.json',output])
        if mode=='snapshot':
            for name in ['source-store-snapshot.json','source-transcript-snapshot.json']:command(['docker','cp',SUITE+':'+path+'/receipt/'+name,receipt/name])
    finally:command(['docker','exec','-u','0',SUITE,'rm','-rf','--',path])
    return READ(output)
def record_scope(run,plan,receipt,name):
    raw=(receipt/name).read_bytes();before={e['id'] for e in api('/api/runs/'+run+'/transcript')}
    request=urllib.request.Request(BASE+'/p/'+plan+'/sp/paos?run='+run,data=raw,method='POST',headers={'Content-Type':'application/json'})
    with urllib.request.urlopen(request,timeout=30) as response:require(response.status==204,'Suite original Recorder failed')
    rows=[e for e in api('/api/runs/'+run+'/transcript') if e['id'] not in before and e.get('decodedSamlRef')]
    require(len(rows)==1 and rows[0]['runId']==run and rows[0]['decodedSamlBytes']==len(raw),'Current native original Recorder binding ambiguous')
    return dict(reference=rows[0]['id'],sha256=SHA(raw))
def live_project_digests():
    files=[m+'-0.1.0.jar' for m in ['runner','core','saml','store','api']]
    return {line.split()[1].rsplit('/',1)[-1]:line.split()[0] for line in command(['docker','exec',SUITE,'sha256sum',*['/opt/samlscope/lib/'+name for name in files]]).stdout.decode().splitlines()}
def collect(folder):
    folder.mkdir(exist_ok=False);receipt=folder/'receipt';receipt.mkdir()
    # Replay all original native controls before even constructing the destination Run.
    proof=original.replay(SOURCE_FOLDER);save(folder/'source-full-control-replay.json',proof)
    archive(folder)
    made=api('/api/plans',dict(name='Shibboleth unchanged default algorithms with explicit source Run',profile='ecp_idp',targetKind='IDP',targetEntityId='http://localhost:18280/idp/shibboleth',metadataSourceKind='URL',metadataSourceLocation='http://samlscope-reference-shibboleth:8080/idp/shibboleth',suiteMetadataDelivery='HTTP_URL',declaredFeatures={},parameters=dict(clockSkewToleranceSeconds=180,metadataRefreshWaitSeconds=30,testUserHint='samlscope-m0-user',requestSigningMode='REQUIRED'),interaction=dict(allowBrowserSteps=False,allowAttestation=False,preset='quick'),authorizedTarget=True))
    save(folder/'plan.json',made);plan=made['plan']['plan']['id'];created=api('/api/plans/'+plan+'/runs',{});save(folder/'created.json',created);run=created['run']['id']
    save(folder/'preflight.json',api('/api/runs/'+run+'/preflight',{}))
    planned=remote(folder,'snapshot',run,receipt,folder/'approved-membership-and-source-originals.json')
    require(planned['destinationApprovedMembershipVerified'] and planned['sourceApprovedMembershipVerified'],'Approved membership preflight failed')
    # Use a real registered peer whose native selected bean is the stock global DefaultRelyingParty.
    raw=command(['docker','exec',NATIVE,'cat','/opt/reference-idp/metadata/suite.xml']).stdout
    entities=list(ET.fromstring(raw));selected=[e.get('entityID') for e in entities if e.get('entityID') and not e.get('entityID').endswith(('/sp-fail','/sp-remain'))]
    require(len(selected)==1,'Current registered default relying party is ambiguous');selection=selected[0]
    commands=[];refs={}
    try:
        for phase in ['before','after']:
            name=capture_scope(receipt,phase,selection,run,SOURCE_FOLDER/'receipt',commands);refs[phase]=(name,record_scope(run,plan,receipt,name))
    finally:save(folder/'native-read-only-commands.json',commands)
    source_manifest=(SOURCE_FOLDER/'receipt/manifest.json').read_bytes();source_m=json.loads(source_manifest)
    m=dict(schema='samlscope-default-algorithm-source-run-v1',runId=run,planId=plan,sourceRunId=SOURCE,sourcePlanId=planned['sourcePlanId'],caseId=CASE,
           caseDigest=case_digest(),profile='ecp_idp',sourceProfile='browser_sso_idp',scope='transport-independent-unchanged-default-algorithm-prevention',
           adapter='shibboleth-stock-default-security-source-run-v1',counterfactualCalibrationOnly=False,ecpProtocolTrafficVerified=False,
           targetEntityId=source_m['targetEntityId'],targetMetadataSha256=source_m['targetMetadataSha256'],sourceManifestSha256=SHA(source_manifest),
           sourceStoreSnapshotFile='source-store-snapshot.json',sourceTranscriptSnapshotFile='source-transcript-snapshot.json',selectionEntityId=selection,
           beforeScopeFile=refs['before'][0],beforeScopeReference=refs['before'][1]['reference'],beforeScopeSha256=refs['before'][1]['sha256'],
           afterScopeFile=refs['after'][0],afterScopeReference=refs['after'][1]['reference'],afterScopeSha256=refs['after'][1]['sha256'],
           files={p.name:SHA(p.read_bytes()) for p in receipt.iterdir() if p.is_file()})
    save(receipt/'manifest.json',m)
    finish(folder)
    return run
def receipt_for(folder):return folder/'receipt-final' if (folder/'receipt-final').exists() else folder/'receipt'
def finish(folder):
    from metadata_validity_baseline_recovery import complete as complete_baseline
    from capture_run_originals import capture as capture_originals
    run=READ(folder/'created.json')['run']['id'];plan=READ(folder/'created.json')['run']['planId']
    if not (folder/'initial-baseline').exists():complete_baseline(run,folder/'initial-baseline')
    baseline=READ(folder/'initial-baseline/baseline-proof.json');require(baseline['ordinaryBaselineOnly'] and baseline['protocolSubmissions']==1,'Legitimate ordinary prerequisite missing')
    require(READ(folder/'initial-baseline/restoration.json')['restored'],'Ordinary prerequisite registration restoration incomplete')
    receipt=folder/'receipt-final';receipt.mkdir(exist_ok=False)
    planned=remote(folder,'snapshot',run,receipt,folder/'post-baseline-approved-membership.json')
    prior=READ(folder/'receipt/manifest.json');selection=prior['selectionEntityId'];commands=[];refs={}
    try:
        for phase in ['before','after']:
            name=capture_scope(receipt,phase,selection,run,SOURCE_FOLDER/'receipt',commands);refs[phase]=(name,record_scope(run,plan,receipt,name))
    finally:save(folder/'post-baseline-native-read-only-commands.json',commands)
    m=dict(prior);m.update(beforeScopeFile=refs['before'][0],beforeScopeReference=refs['before'][1]['reference'],beforeScopeSha256=refs['before'][1]['sha256'],
                          afterScopeFile=refs['after'][0],afterScopeReference=refs['after'][1]['reference'],afterScopeSha256=refs['after'][1]['sha256'],
                          files={p.name:SHA(p.read_bytes()) for p in receipt.iterdir() if p.is_file()})
    save(receipt/'manifest.json',m)
    save(folder/'tests-start.json',api('/api/runs/'+run+'/tests/start',{}));save(folder/'result-before.json',api('/api/runs/'+run+'/result.json'))
    entries=api('/api/runs/'+run+'/transcript');save(folder/'transcript.json',entries);capture_originals(folder,run,entries)
    counts=READ(folder/'initial-baseline/operation-counts-reconciled.json');ops=READ(folder/'initial-baseline/operations.json')
    save(folder/'operation-counts.json',dict(destinationRunId=run,sourceRunId=SOURCE,targetSettingsWriteAttempts=sum(r['operation']=='write' for r in ops),targetSettingsWrites=counts['productConfigurationWrites'],
            nativeApplicationsChanged=1,restorationWrites=sum(r.get('label')=='restore-provider' for r in ops),metadataReloads=counts['metadataReloads'],protocolSubmissions=1,
            credentialPosts=counts['credentialPosts'],browserOperations=1,personOperations=0,suiteAuxiliaryRecorderPosts=4,ecpProtocolTrafficVerified=False,
            algorithmPolicyChanges=0,nativeReadOnlyCommands=len(commands)+len(READ(folder/'native-read-only-commands.json'))))
    replay=remote(folder,'replay',run,receipt,folder/'current-reader-replay.json');require(replay['outcome']['outcome']=='SATISFIED' and len(replay['negativeControls'])==28,'Current reader/control proof incomplete')
def verify(folder):
    original.replay(SOURCE_FOLDER)
    run=READ(folder/'created.json')['run']['id']
    with tempfile.TemporaryDirectory(prefix='source-run-controls-') as temp:
        result=remote(folder,'replay',run,receipt_for(folder),pathlib.Path(temp)/'replay.json')
    require(result==READ(folder/'current-reader-replay.json'),'Current reader replay changed');return result
def public_assets(folder):
    receipt=receipt_for(folder).absolute();m=READ(receipt/'manifest.json');files=m.get('files');require(isinstance(files,dict) and files,'Receipt file inventory missing')
    assets={}
    for name,digest in {'manifest.json':SHA((receipt/'manifest.json').read_bytes()),**files}.items():
        require(isinstance(name,str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,160}',name) and re.fullmatch(r'[0-9a-f]{64}',digest),'Unsafe receipt inventory')
        path=receipt/name;require(not any(p.is_symlink() for p in [path,*path.parents]) and path.is_file() and 0<path.stat().st_size<=8_388_608,'Receipt original unavailable')
        raw=path.read_bytes();require(SHA(raw)==digest,'Receipt original changed');assets[name]=raw
    require(set(assets)=={p.name for p in receipt.iterdir()} and not any(p.is_dir() for p in receipt.iterdir()),'Unbound receipt asset')
    require(m['runId']==READ(folder/'created.json')['run']['id'] and m['sourceRunId']==SOURCE and m['caseId']==CASE
            and m['ecpProtocolTrafficVerified'] is False and m['counterfactualCalibrationOnly'] is False,'Unsupported receipt provenance')
    return dict(sorted(assets.items()))
def installation_readback(folder):
    run=READ(folder/'created.json')['run']['id'];assets=public_assets(folder);target='/data/default-algorithm-source-bindings/'+run
    rows={};sizes={}
    for name,raw in assets.items():
        require(command(['docker','exec',SUITE,'test','!','-L',target+'/'+name]).returncode==0,'Installed original is a symlink')
        digest=command(['docker','exec',SUITE,'sha256sum',target+'/'+name]).stdout.decode().split()[0]
        size=int(command(['docker','exec',SUITE,'stat','-c','%s',target+'/'+name]).stdout)
        require(digest==SHA(raw) and size==len(raw),'Suite user installed receipt byte readback differs');rows[name]=digest;sizes[name]=size
    actual=command(['docker','exec',SUITE,'find',target,'-mindepth','1','-maxdepth','1','-printf','%f\n']).stdout.decode().splitlines()
    require(set(actual)==set(assets) and len(actual)==len(assets),'Installed receipt has unbound assets')
    return dict(runId=run,sourceRunId=SOURCE,manifestSha256=rows['manifest.json'],files=rows,sizes=sizes,ecpProtocolTrafficVerified=False,
                productSettings=0,protocolSubmissions=0,credentialPosts=0,deployedProjectSha256=live_project_digests())
def central_offline(folder):
    a=folder/'reader';pins=READ(a/'pins.json');dependencies=READ(a/'verification-dependencies.json')
    cp=':'.join(str(a/name) for name in pins['projectArchivesFirst'])+':'+str(a/'classes')+':'+':'.join(r['path'] for r in dependencies)
    java=pathlib.Path(os.environ.get('JAVA_HOME','/Library/Java/JavaVirtualMachines/jdk-21.jdk/Contents/Home'))/'bin/java'
    with tempfile.TemporaryDirectory(prefix='source-run-central-') as temp:
        output=pathlib.Path(temp)/'central.json';command([java,'-cp',cp,'com.samlscope.runner.cases.VerifyDefaultAlgorithmSourceRun','offline',folder/'state-final.json',output])
        require(READ(output)==READ(folder/'state-final.json'),'Archived central Evaluator changed the actual stored conclusion')
def validate_transition(folder,replay):
    run=READ(folder/'created.json')['run']['id'];before=READ(folder/'state-before.json');after=READ(folder/'state-final.json');manifest=READ(receipt_for(folder)/'manifest.json')
    require(before['schema']==after['schema']=='samlscope-default-algorithm-source-stored-v1' and before['destinationRunId']==after['destinationRunId']==run
            and before['sourceRunId']==after['sourceRunId']==SOURCE and before['approvedCaseDigest']==after['approvedCaseDigest']==manifest['caseDigest']==case_digest(),'Stored source/destination identity differs')
    require(all(before[key]==after[key] for key in ['sourceStore','sourceHistory','sourceCase','sourceExecutions','destinationHistory','targetMetadataSha256']),
            'Adoption changed original history, source execution, or target bytes')
    require(before['sourceStore']==READ(receipt_for(folder)/manifest['sourceStoreSnapshotFile']) and before['sourceHistory']==READ(receipt_for(folder)/manifest['sourceTranscriptSnapshotFile']),
            'Source whole-context snapshot no longer matches the bound receipt')
    current={k:v for k,v in before['destinationStore'].items() if k!='caseExecutionSha256'};final={k:v for k,v in after['destinationStore'].items() if k!='caseExecutionSha256'}
    require(current==final and current['outbox']==before['destinationStore']['outbox']==after['destinationStore']['outbox']
            and not any(row['case_id']==CASE for row in current['outbox']),'Formal queued adoption issued or modified an outbound action')
    require({k:v for k,v in before['destinationExecutions'].items() if k!=CASE}=={k:v for k,v in after['destinationExecutions'].items() if k!=CASE},'Formal adoption changed another case slot')
    old,new=before['destinationCase'],after['destinationCase']
    require(old['runId']==new['runId']==run and old['caseId']==new['caseId']==CASE and old['status']=='RUNNING' and old['statePhase']=='runner-queued-front-channel'
            and old['revision']==0 and old['outcome'] is None and old['verdict'] is None and new['status']=='FINISHED' and new['revision']==old['revision']+1
            and new['stateSha256']==old['stateSha256'] and new['waitConditionSha256']==old['waitConditionSha256'] and new['statePhase']==old['statePhase']
            and new['updatedAt']>=old['updatedAt'] and new['outcome']==replay['outcome'] and new['verdict']=='PASS','Actual queued case revision/outcome is not preserved')
    require(before['destinationStore']['caseExecutionSha256']==old['documentSha256']==before['destinationExecutions'][CASE]
            and after['destinationStore']['caseExecutionSha256']==new['documentSha256']==after['destinationExecutions'][CASE],'Actual stored case digests differ')
    require(all(before[key] is True and after[key] is True for key in ['destinationApprovedMembershipVerified','sourceApprovedMembershipVerified']),'Installed approved membership missing')
    return after
def seal(folder):
    require(all((folder/name).is_file() for name in ['result-final.json','state-before.json','state-final.json','installed.json','current-reader-replay.json']),'Formal originals are incomplete')
    files={}
    for path in sorted(folder.rglob('*')):
        require(not path.is_symlink(),'Adopted original cannot be a symlink')
        if path.is_file() and path.name!='acceptance-originals.json':files[path.relative_to(folder).as_posix()]=SHA(path.read_bytes())
    save(folder/'acceptance-originals.json',files)
def verify_adoption(folder,live=False):
    folder=pathlib.Path(folder).resolve();sealed=READ(folder/'acceptance-originals.json')
    for name,digest in sealed.items():
        require(not pathlib.PurePosixPath(name).is_absolute() and '..' not in pathlib.PurePosixPath(name).parts,'Unsafe closed proof path')
        path=folder/name;require(path.is_file() and not any(p.is_symlink() for p in [path,*path.parents]) and SHA(path.read_bytes())==digest,'Closed formal original changed')
    pins=READ(folder/'reader/pins.json');require(pins['deployedRuntimeArchive'] is True and pins['deployedProjectSha256']=={name.removeprefix('suite-'):digest for name,digest in pins['files'].items() if name.startswith('suite-')},'Reader archives lack actual installed project bytes')
    # Every generation replays all original controls and the current source/native controls.
    replay=verify(folder);after=validate_transition(folder,replay);central_offline(folder)
    assets=public_assets(folder);installed=READ(folder/'installed.json');run=READ(folder/'created.json')['run']['id']
    require(installed==dict(runId=run,sourceRunId=SOURCE,manifestSha256=SHA(assets['manifest.json']),files={name:SHA(raw) for name,raw in assets.items()},
            sizes={name:len(raw) for name,raw in assets.items()},ecpProtocolTrafficVerified=False,productSettings=0,protocolSubmissions=0,credentialPosts=0,deployedProjectSha256=pins['deployedProjectSha256']),
            'Actual installed receipt readback differs')
    result_path=folder/'result-final.json';result=READ(result_path)
    selected=[case for requirement in result['requirements'] for case in requirement.get('cases',[]) if case['id']==CASE]
    require(len(selected)==1,'Formal selected case missing');case=selected[0];outcome=after['destinationCase']['outcome']
    require(result['run']['id']==run and result['target']['metadata_digest']=='sha256:'+after['targetMetadataSha256'] and case['mode']=='ATTESTED'
            and case['outcome']==outcome['outcome']=='SATISFIED' and case['verdict']==after['destinationCase']['verdict']=='PASS' and case['attested'] is False
            and case['evidence_class']=='OPERATOR_ASSISTED' and case['evidence']==outcome['evidence'] and case['reason_code']==outcome['reasonCode']
            and any(ref['kind']=='default-algorithm-source-run-evidence' and ref['reference']==run+'/manifest.json#sha256='+SHA(assets['manifest.json']) for ref in case['evidence']),
            'Formal result differs from the installed reader and central stored conclusion')
    counts=READ(folder/'operation-counts.json');restore=READ(folder/'initial-baseline/restoration.json');baseline=READ(folder/'initial-baseline/baseline-proof.json')
    require(restore['restored'] is True and restore['temporaryRemoved'] is True and restore['originalSha256']==restore['finalSha256']
            and baseline['ordinaryBaselineOnly'] is True and baseline['protocolSubmissions']==1 and counts['destinationRunId']==run and counts['sourceRunId']==SOURCE
            and counts['algorithmPolicyChanges']==0 and counts['ecpProtocolTrafficVerified'] is False and counts['protocolSubmissions']==counts['browserOperations']==counts['credentialPosts']==1
            and counts['targetSettingsWriteAttempts']==counts['targetSettingsWrites']==3 and counts['restorationWrites']==1 and counts['metadataReloads']==2 and counts['suiteAuxiliaryRecorderPosts']==4,
            'Ordinary prerequisite/restoration or actual operation burden differs')
    with tempfile.TemporaryDirectory(prefix='source-run-stored-recheck-') as temp:
        actual=remote(folder,'state',run,receipt_for(folder),pathlib.Path(temp)/'state.json');require(actual==after,'Actual source/destination stored history changed after adoption')
    if live:
        require(installation_readback(folder)==installed and live_project_digests()==pins['deployedProjectSha256'],'Live installed receipt/runtime changed')
        original.live(SOURCE_FOLDER)
        provider=command(['docker','exec',NATIVE,'cat','/opt/reference-idp/conf/metadata-providers.xml']).stdout
        require(SHA(provider)==restore['finalSha256'],'Current prerequisite registration restoration differs')
    return result_path,{CASE:case}
def install(folder):
    pins=READ(folder/'reader/pins.json');require(pins['deployedRuntimeArchive'],'Formal adoption requires immutable copies of actual deployed project JARs')
    require(pins['deployedProjectSha256']==live_project_digests(),'Deployed project JARs differ from the archived production reader')
    verify(folder);run=READ(folder/'created.json')['run']['id'];receipt=receipt_for(folder);public_assets(folder)
    remote(folder,'state',run,receipt,folder/'state-before.json')
    target='/data/default-algorithm-source-bindings/'+run
    command(['docker','exec',SUITE,'test','!','-e',target]);command(['docker','exec','-u','0',SUITE,'mkdir','-p','/data/default-algorithm-source-bindings'])
    command(['docker','cp',str(receipt),SUITE+':'+target]);uid=command(['docker','exec',SUITE,'id','-u']).stdout.decode().strip();command(['docker','exec','-u','0',SUITE,'chown','-R',uid+':'+uid,target])
    save(folder/'installed.json',installation_readback(folder))
    save(folder/'formal-reevaluation.json',api('/api/runs/'+run+'/tests/start',{}));final=api('/api/runs/'+run+'/result.json');save(folder/'result-final.json',final)
    selected=[case for requirement in final['requirements'] for case in requirement.get('cases',[]) if case['id']==CASE]
    require(len(selected)==1 and selected[0]['outcome']=='SATISFIED' and selected[0]['verdict']=='PASS' and selected[0]['attested'] is False
            and selected[0]['evidence_class']=='OPERATOR_ASSISTED' and any(ref['kind']=='default-algorithm-source-run-evidence' and ref['reference'].startswith(run+'/manifest.json#sha256=') for ref in selected[0]['evidence']),
            'Central Evaluator did not adopt the whole original-backed source case')
    remote(folder,'state',run,receipt,folder/'state-final.json');validate_transition(folder,READ(folder/'current-reader-replay.json'));central_offline(folder);seal(folder)
    return verify_adoption(folder,live=True)
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('mode',choices=['collect','finish','verify','install','verify-adoption']);p.add_argument('--folder',type=pathlib.Path,required=True);a=p.parse_args()
    if a.mode=='collect':collect(a.folder)
    elif a.mode=='finish':finish(a.folder)
    elif a.mode=='verify':verify(a.folder)
    elif a.mode=='verify-adoption':verify_adoption(a.folder,live=True)
    else:install(a.folder)
if __name__=='__main__':main()
