#!/usr/bin/env python3
"""Close one approved original-backed native ForceAuthn mechanism-access observation."""
import argparse,hashlib,json,os,pathlib,secrets,shutil,subprocess,tempfile,urllib.request,zipfile
REPO=pathlib.Path(__file__).resolve().parents[2]
SUITE='samlscope-reference-suite';CASE='IIP-IDP06-b-idp-01';HELPER='VerifyKeycloakForceAuthnMechanism'
JARS=['runner','core','saml','store','api','peer'];SHA=lambda raw:hashlib.sha256(raw).hexdigest();READ=lambda p:json.loads(pathlib.Path(p).read_bytes())
def require(value,why):
    if not value:raise ValueError(why)
def command(args,timeout=180):return subprocess.run([str(a) for a in args],check=True,capture_output=True,timeout=timeout)
def save(path,value):
    require(not path.exists(),'Immutable evidence already exists: '+str(path));path.write_text(json.dumps(value,sort_keys=True,indent=2)+'\n')
def api(path,body=None):
    request=urllib.request.Request('http://localhost:18080'+path,data=None if body is None else json.dumps(body).encode(),headers={'Content-Type':'application/json'})
    with urllib.request.urlopen(request,timeout=45) as response:return json.load(response)
def gradle_inputs():
    paths=set(REPO.rglob('build.gradle.kts'))|{REPO/'settings.gradle.kts',REPO/'gradle.properties',REPO/'gradle/libs.versions.toml',REPO/'gradle/verification-metadata.xml'}
    return {str(p.relative_to(REPO)):SHA(p.read_bytes()) for p in sorted(paths) if p.is_file() and 'build' not in p.relative_to(REPO).parts}
def reader_path(folder,deployed=False):
    pointer=folder/('active-reader.json' if deployed else 'active-candidate.json')
    name=READ(pointer)['directory'] if pointer.exists() else ('reader' if deployed else 'reader-candidate')
    require(name.startswith('reader') and '/' not in name and '\\' not in name and '..' not in name,'Unsafe reader generation')
    archive=folder/name
    if pointer.exists():require(SHA((archive/'pins.json').read_bytes())==READ(pointer)['pinsSha256'],'Selected reader generation pins changed')
    return archive
def archive(folder,deployed=False,qualification=None,generation=None):
    if generation is not None:require(generation.startswith('reader') and '/' not in generation and '\\' not in generation and '..' not in generation,'Unsafe archive generation')
    a=folder/generation if generation else reader_path(folder,deployed);a.mkdir(exist_ok=True);require(not any(a.iterdir()),'Existing reader archive is immutable')
    dependencies=[];dependency_archive=a/'dependencies';dependency_archive.mkdir()
    # The deployed application resolves dependency conflicts across all modules.
    # Discover its complete physical classpath once for this explicit generation.
    for p in sorted((REPO/'api/build/install/samlscope/lib').glob('*.jar')):
        if p.name.endswith('-0.1.0.jar'):continue
        copied=dependency_archive/p.name;shutil.copyfile(p,copied)
        dependencies.append(dict(path=str(copied),sourcePath=str(p),name=p.name,sha256=SHA(copied.read_bytes())))
    require(dependencies and len({r['name'] for r in dependencies})==len(dependencies),'Dependencies ambiguous')
    live={line.split()[1].rsplit('/',1)[-1]:line.split()[0] for line in command(['docker','exec',SUITE,'sha256sum',*['/opt/samlscope/lib/'+r['name'] for r in dependencies]]).stdout.decode().splitlines()}
    require(live=={r['name']:r['sha256'] for r in dependencies},'Deployed dependency bytes differ')
    projects={}
    before={line.split()[1].rsplit('/',1)[-1]:line.split()[0] for line in command(['docker','exec',SUITE,'sha256sum',*['/opt/samlscope/lib/'+name+'-0.1.0.jar' for name in JARS]]).stdout.decode().splitlines()} if deployed else None
    for name in JARS:
        to=a/(name+'.jar')
        if deployed or name=='api':command(['docker','cp',SUITE+':/opt/samlscope/lib/'+name+'-0.1.0.jar',to])
        else:shutil.copyfile(REPO/name/'build/libs'/(name+'-0.1.0.jar'),to)
        require(to.stat().st_nlink==1,'Mutable project JAR hardlink');projects[name]=SHA(to.read_bytes())
    if deployed:
        after={line.split()[1].rsplit('/',1)[-1]:line.split()[0] for line in command(['docker','exec',SUITE,'sha256sum',*['/opt/samlscope/lib/'+name+'-0.1.0.jar' for name in JARS]]).stdout.decode().splitlines()}
        require(before==after=={name+'-0.1.0.jar':digest for name,digest in projects.items()},'Installed six-module runtime changed during archive')
        require(qualification is not None,'Formal archive requires the coordinated qualified deployment')
        qualification=pathlib.Path(qualification);qualified=READ(qualification/'isolated-test-overlay.json');runtime_path=qualification/'runtime-live-verification.json'
        if not runtime_path.exists():runtime_path=qualification/'deployment.json'
        runtime=READ(runtime_path)
        require(runtime['healthStatus']==200 and qualified['projectJars']==runtime['projectJars']==before,'Installed runtime differs from qualified six-module overlay')
        save(a/'deployment-qualification.json',dict(path=str(qualification),qualificationSha256=SHA((qualification/'isolated-test-overlay.json').read_bytes()),runtimeFile=runtime_path.name,runtimeSha256=SHA(runtime_path.read_bytes()),projectJars=before))
    helper=a/(HELPER+'.java');shutil.copyfile(REPO/'dev/reference-acceptance'/(HELPER+'.java'),helper)
    baseline=a/'VerifyKeycloakAuthenticationIdentity.java';shutil.copyfile(REPO/'dev/reference-acceptance/VerifyKeycloakAuthenticationIdentity.java',baseline)
    java=pathlib.Path('/Library/Java/JavaVirtualMachines/jdk-21.jdk/Contents/Home/bin')
    classpath=':'.join(str(a/(name+'.jar')) for name in JARS)+':'+':'.join(r['path'] for r in dependencies)
    command([java/'javac','-sourcepath','','-cp',classpath,'-d',a/'classes',helper,baseline])
    require(all(p.name.startswith((HELPER,'VerifyKeycloakAuthenticationIdentity')) for p in (a/'classes').rglob('*.class')),'Helper shadows production')
    save(a/'pins.json',dict(projects=projects,helperSha256=SHA(helper.read_bytes()),baselineHelperSha256=SHA(baseline.read_bytes()),dependencies=dependencies,gradleInputs=gradle_inputs(),deployed=deployed,classes={str(p.relative_to(a/'classes')):SHA(p.read_bytes()) for p in (a/'classes').rglob('*.class')}))
    if generation is not None:save(folder/('active-reader.json' if deployed else 'active-candidate.json'),dict(directory=generation,pinsSha256=SHA((a/'pins.json').read_bytes())))
    return a
def remote(folder,mode,output,deployed=False,archive_override=None):
    a=pathlib.Path(archive_override) if archive_override is not None else reader_path(folder,deployed);pins=READ(a/'pins.json');run=READ(folder/'created.json')['run']['id'];receipt=folder/'receipt'
    require(pins['gradleInputs']==gradle_inputs(),'A new verification generation is required after changed Gradle inputs')
    for name,digest in pins['projects'].items():require(SHA((a/(name+'.jar')).read_bytes())==digest,'Archived project bytes changed')
    for row in pins['dependencies']:require(SHA(pathlib.Path(row['path']).read_bytes())==row['sha256'],'Dependency bytes changed')
    require(SHA((a/(HELPER+'.java')).read_bytes())==pins['helperSha256'],'Archived verifier changed')
    for name,digest in pins.get('classes',{}).items():require(SHA((a/'classes'/name).read_bytes())==digest,'Archived compiled verifier changed')
    remote='/tmp/kc-mechanism-reader-'+secrets.token_hex(6);command(['docker','exec','-u','0',SUITE,'mkdir',remote])
    try:
        command(['docker','cp',a/'classes',SUITE+':'+remote+'/classes'])
        for name in JARS:command(['docker','cp',a/(name+'.jar'),SUITE+':'+remote+'/'+name+'.jar'])
        command(['docker','cp',receipt,SUITE+':'+remote+'/receipt'])
        command(['docker','exec','-u','0',SUITE,'chmod','-R','a+rX',remote]);uid=command(['docker','exec',SUITE,'id','-u']).stdout.decode().strip();command(['docker','exec','-u','0',SUITE,'chown','-R',uid+':'+uid,remote])
        cp=':'.join(remote+'/'+name+'.jar' for name in JARS)+':'+remote+'/classes:'+':'.join('/opt/samlscope/lib/'+r['name'] for r in pins['dependencies'])
        value=command(['docker','exec',SUITE,'java','-Xmx768m','-cp',cp,'com.samlscope.runner.cases.'+HELPER,mode,'/data',run,remote+'/receipt',remote+'/proof.json'])
        command(['docker','cp',SUITE+':'+remote+'/proof.json',output])
        if mode=='snapshot':
            for name in ['source-store-snapshot.json','source-history.json']:command(['docker','cp',SUITE+':'+remote+'/receipt/'+name,receipt/name])
        return READ(output)
    finally:command(['docker','exec','-u','0',SUITE,'rm','-rf','--',remote])
def prepare(folder):
    receipt=folder/'receipt';receipt.mkdir(exist_ok=False);run=READ(folder/'created.json')['run']['id'];source=receipt/'source'/run;source.mkdir(parents=True)
    baseline=READ(folder/'manifest.json')
    for name in ['manifest.json',*baseline['files']]:
        to=source/name;to.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(folder/name,to)
    for name in ['transcript.json','decoded-manifest.json',*[row['file'] for row in READ(folder/'decoded-manifest.json')]]:
        to=source/name;to.parent.mkdir(parents=True,exist_ok=True)
        if to.exists():require(to.read_bytes()==(folder/name).read_bytes(),'Source original copy differs')
        else:shutil.copyfile(folder/name,to)
    for name in ['native-helper.java','approved-membership.json','target-metadata.xml','native-scope-before.json','native-scope-after.json']:shutil.copyfile(folder/name,receipt/name)
    shutil.copyfile(folder/'scope-native-trace.json',receipt/'native-trace.json')
    shutil.copyfile(folder/'scope-native-process.json',receipt/'native-process.json')
    shutil.copyfile(folder/'originals/native-realm-before.json',receipt/'native-realm-before.json')
    shutil.copyfile(REPO/'dev/reference-acceptance/capture_keycloak_forceauthn_realm_scope.py',receipt/'native-scope-collector.py')
    shutil.copyfile(folder/'originals/before.native-classpath.txt',receipt/'native-classpath.txt')
    (receipt/'native-complete').mkdir()
    for line in (receipt/'native-classpath.txt').read_text().splitlines():
        native=line.split()[-1];name=native.removeprefix('/opt/keycloak/lib/');to=receipt/'native-complete'/name;to.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(folder/'native-complete'/name,to)
    archive(folder)
    remote(folder,'snapshot',folder/'source-binding-preflight.json')
    files={str(p.relative_to(receipt)):SHA(p.read_bytes()) for p in receipt.rglob('*') if p.is_file()}
    save(receipt/'manifest.json',dict(schema='samlscope-keycloak-forceauthn-mechanism-v1',runId=run,planId=READ(folder/'created.json')['run']['planId'],caseId=CASE,caseDigest=READ(folder/'approved-membership.json')['caseDigest'],campaignId='native-authentication-mechanism',targetMetadataSha256=SHA((folder/'target-metadata.xml').read_bytes()),sourceManifestSha256=SHA((source/'manifest.json').read_bytes()),files=files))
    return remote(folder,'replay',folder/'candidate-reader-replay.json')
def archived_classpath(folder,deployed=False):
    a=reader_path(folder,deployed);pins=READ(a/'pins.json')
    for name,digest in pins['projects'].items():require((a/(name+'.jar')).stat().st_nlink==1 and SHA((a/(name+'.jar')).read_bytes())==digest,'Project archive changed')
    for row in pins['dependencies']:require(SHA(pathlib.Path(row['path']).read_bytes())==row['sha256'],'Archived generation dependency changed')
    return a,pins,':'.join(str(a/(name+'.jar')) for name in JARS)+':'+str(a/'classes')+':'+':'.join(row['path'] for row in pins['dependencies'])
def replay_baseline(folder,deployed=False):
    a,pins,cp=archived_classpath(folder,deployed);source=a/'VerifyKeycloakAuthenticationIdentity.java'
    require(SHA(source.read_bytes())==pins['baselineHelperSha256'],'Baseline verifier changed')
    run=READ(folder/'created.json')['run']['id'];receipt=folder/'receipt';baseline=receipt/'source'/run
    with tempfile.TemporaryDirectory(prefix='kc-forceauthn-baseline-controls-') as temporary:
        temporary=pathlib.Path(temporary);output=temporary/'baseline.json';original=temporary/'original';shutil.copytree(baseline,original);shutil.copyfile(receipt/'target-metadata.xml',original/'target-metadata.xml')
        command(['/Library/Java/JavaVirtualMachines/jdk-21.jdk/Contents/Home/bin/java','-Xmx512m','-cp',cp,'com.samlscope.runner.cases.VerifyKeycloakAuthenticationIdentity',original,output,'candidate-leaf','9f426e9a4449490d8333422e973569bf50a2738ccf4d96d755917d29a20bddaa','3073a5b0513586ca9faa3319c459204209038e2c1dfe9044a77645465a98d68e'])
        result=READ(output);require(len(result['negative_controls'])==36,'Original baseline controls incomplete');return result
def replay_native(folder):
    receipt=folder/'receipt';manifest=READ(receipt/'manifest.json');run=manifest['runId'];jars=[];canonical={}
    for line in (receipt/'native-classpath.txt').read_text().splitlines():
        digest,native=line.split();path=receipt/'native-complete'/native.removeprefix('/opt/keycloak/lib/')
        require(path.stat().st_nlink==1 and SHA(path.read_bytes())==digest,'Independent native classpath changed');jars.append(path);canonical[str(path.resolve())]=native
    helper=receipt/'native-helper.java';require(SHA(helper.read_bytes())=='6fabbc63c3a9e1adadb13c5792c204e78009f012502290094bed2a4970b89c7e','Native producer helper changed')
    java=pathlib.Path('/Library/Java/JavaVirtualMachines/jdk-21.jdk/Contents/Home/bin')
    with tempfile.TemporaryDirectory(prefix='kc-native-original-replay-') as temporary:
        temp=pathlib.Path(temporary);source=temp/'ProbeKeycloakForceAuthnMechanism.java';source.write_bytes(helper.read_bytes());classes=temp/'classes';originals=temp/'originals';originals.mkdir()
        native_source=receipt/'source'/run
        for name in ['native-client-before.json','flow-executions-before.json','flow-creation.json']:shutil.copyfile(native_source/'originals'/name,originals/name)
        shutil.copyfile(receipt/'native-realm-before.json',originals/'native-realm-before.json')
        original=READ(native_source/'manifest.json');decoded={row['id']:native_source/row['file'] for row in READ(native_source/'decoded-manifest.json')}
        cp=':'.join(str(p.resolve()) for p in jars);command([java/'javac','-sourcepath','','-cp',cp,'-d',classes,source])
        require(all(p.name.startswith('ProbeKeycloakForceAuthnMechanism') for p in classes.rglob('*.class')),'Native replay shadows product')
        command([java/'java','-Xmx512m','-cp',str(classes)+':'+cp,'ProbeKeycloakForceAuthnMechanism',temp,decoded[original['positiveRequestReference']],decoded[original['passiveRequestReference']],temp/'trace.json'])
        replay=READ(temp/'trace.json')
        for origin in replay['classes']:origin['jarPath']=canonical[origin['jarPath']]
        require(replay==READ(receipt/'native-trace.json'),'Unchanged native producer/selected-flow replay differs');return replay
def receipt_inventory(folder):
    receipt=folder/'receipt';manifest=READ(receipt/'manifest.json');expected=manifest['files']|{'manifest.json':SHA((receipt/'manifest.json').read_bytes())}
    actual={str(p.relative_to(receipt)):SHA(p.read_bytes()) for p in receipt.rglob('*') if p.is_file()}
    require(actual==expected and all(not p.is_symlink() for p in [receipt,*receipt.rglob('*')]),'Receipt has changed or unbound originals')
    run=READ(folder/'created.json')['run']['id'];require(manifest['runId']==run and manifest['caseId']==CASE,'Foreign receipt identity');return run,manifest,expected
def live_projects():
    return {line.split()[1].rsplit('/',1)[-1].removesuffix('-0.1.0.jar'):line.split()[0] for line in command(['docker','exec',SUITE,'sha256sum',*['/opt/samlscope/lib/'+n+'-0.1.0.jar' for n in JARS]]).stdout.decode().splitlines()}
def installed_readback(folder):
    run,manifest,expected=receipt_inventory(folder);destination='/data/force-authn-mechanism-evidence/'+run+'.keycloak-forceauthn-mechanism'
    require(command(['docker','exec',SUITE,'find',destination,'-type','l']).stdout==b'','Installed receipt has symlinks')
    require(command(['docker','exec',SUITE,'find',destination,'-type','f','!','-perm','0644']).stdout==b'','Installed public receipt permissions differ')
    raw=command(['docker','exec',SUITE,'sh','-c','cd "$1" && find . -type f -exec sha256sum {} +','native-mechanism-readback',destination]).stdout.decode();actual={}
    for line in raw.splitlines():
        digest,name=line.split('  ',1);require(name.startswith('./') and name[2:] not in actual,'Ambiguous installed receipt inventory');actual[name[2:]]=digest
    require(actual==expected,'Actual Suite user receipt bytes differ');return dict(path=destination,records=actual,atomicSameDataFilesystem=True,publicFiles0644=True,productOperations=0,projectJars=READ(reader_path(folder,True)/'pins.json')['projects'])
def install(folder):
    run,manifest,expected=receipt_inventory(folder);pins=READ(reader_path(folder,True)/'pins.json');require(pins['deployed'] and live_projects()==pins['projects'],'Actual deployed archive differs')
    replay_native(folder);baseline=replay_baseline(folder,True)
    with tempfile.TemporaryDirectory(prefix='kc-native-preinstall-controls-') as temporary:observed=remote(folder,'replay',pathlib.Path(temporary)/'report.json',True)
    require(observed['productionOutcome']['outcome']=='SATISFIED' and observed['nativeBaseline']==baseline['production_outcome'],'Original baseline and mechanism reader differ')
    save(folder/'deployed-reader-replay.json',observed);save(folder/'deployed-source-baseline-controls.json',baseline)
    remote(folder,'state',folder/'state-before.json',True);save(folder/'result-before-adoption.json',api('/api/runs/'+run+'/result.json'));save(folder/'transcript-before-adoption.json',api('/api/runs/'+run+'/transcript'))
    base='/data/force-authn-mechanism-evidence';destination=base+'/'+run+'.keycloak-forceauthn-mechanism';stage=base+'/.stage-'+run+'.keycloak-forceauthn-mechanism'
    for path in (destination,stage):require(subprocess.run(['docker','exec',SUITE,'test','-e',path],capture_output=True,timeout=30).returncode==1,'Refusing to overwrite installed evidence')
    with tempfile.TemporaryDirectory(prefix='kc-public-native-placement-') as temporary:
        copy=pathlib.Path(temporary)/'receipt';shutil.copytree(folder/'receipt',copy)
        for path in [copy,*copy.rglob('*')]:path.chmod(0o755 if path.is_dir() else 0o644)
        command(['docker','exec','-u','0',SUITE,'mkdir','-p',base]);command(['docker','cp',copy,SUITE+':'+stage]);command(['docker','exec','-u','0',SUITE,'mv',stage,destination])
    save(folder/'installed.json',installed_readback(folder))
def formal(folder):
    run,_,_=receipt_inventory(folder);require((folder/'installed.json').is_file(),'Receipt placement must precede formal evaluation')
    save(folder/'evaluate.json',api('/api/runs/'+run+'/protocol-evidence/evaluate',{}));save(folder/'result-final.json',api('/api/runs/'+run+'/result.json'));save(folder/'transcript-final.json',api('/api/runs/'+run+'/transcript'))
    remote(folder,'state',folder/'state-final.json',True)
    close(folder)
def replay_transition(folder):
    a,pins,cp=archived_classpath(folder,True);aux=folder/'transition-reader';helper='VerifyKeycloakForceAuthnStateTransition'
    if not aux.exists():
        aux.mkdir();source=aux/(helper+'.java');shutil.copyfile(REPO/'dev/reference-acceptance'/(helper+'.java'),source)
        command(['/Library/Java/JavaVirtualMachines/jdk-21.jdk/Contents/Home/bin/javac','-sourcepath','','-cp',cp,'-d',aux/'classes',source])
        classes={str(p.relative_to(aux/'classes')):SHA(p.read_bytes()) for p in (aux/'classes').rglob('*.class')}
        require(classes and all(path.endswith('/'+helper+'.class') for path in classes),'Transition helper shadows production')
        save(aux/'pins.json',dict(helperSha256=SHA(source.read_bytes()),classes=classes,coreSha256=pins['projects']['core'],storeSha256=pins['projects']['store']))
    binding=READ(aux/'pins.json');require(binding['coreSha256']==pins['projects']['core'] and binding['storeSha256']==pins['projects']['store'] and SHA((aux/(helper+'.java')).read_bytes())==binding['helperSha256'],'Transition reader archive changed')
    for name,digest in binding['classes'].items():require(SHA((aux/'classes'/name).read_bytes())==digest,'Compiled transition reader changed')
    remote_path='/tmp/kc-mechanism-transition-'+secrets.token_hex(6);command(['docker','exec','-u','0',SUITE,'mkdir',remote_path])
    try:
        command(['docker','cp',aux/'classes',SUITE+':'+remote_path+'/classes'])
        for name in JARS:command(['docker','cp',a/(name+'.jar'),SUITE+':'+remote_path+'/'+name+'.jar'])
        command(['docker','exec','-u','0',SUITE,'chmod','-R','a+rX',remote_path]);uid=command(['docker','exec',SUITE,'id','-u']).stdout.decode().strip();command(['docker','exec','-u','0',SUITE,'chown','-R',uid+':'+uid,remote_path])
        classpath=':'.join(remote_path+'/'+name+'.jar' for name in JARS)+':'+remote_path+'/classes:'+':'.join('/opt/samlscope/lib/'+r['name'] for r in pins['dependencies'])
        command(['docker','exec',SUITE,'java','-cp',classpath,'com.samlscope.runner.cases.'+helper,'/data',READ(folder/'created.json')['run']['id'],remote_path+'/proof.json'])
        with tempfile.TemporaryDirectory(prefix='kc-state-transition-') as temp:
            output=pathlib.Path(temp)/'proof.json';command(['docker','cp',SUITE+':'+remote_path+'/proof.json',output]);return READ(output)
    finally:command(['docker','exec','-u','0',SUITE,'rm','-rf','--',remote_path])
def close(folder):
    require((folder/'result-final.json').is_file() and not (folder/'acceptance-originals.json').exists(),'Closure requires unsealed actual formal originals')
    _,pins,_=archived_classpath(folder,True)
    require(live_projects()==pins['projects'],'Actual runtime differs from strengthened reader archive')
    verify_packaged_replay(folder)
    replay_native(folder);baseline=replay_baseline(folder,True)
    with tempfile.TemporaryDirectory(prefix='kc-native-formal-closure-') as temporary:
        observed=remote(folder,'replay',pathlib.Path(temporary)/'controls.json',True)
        actual=remote(folder,'state',pathlib.Path(temporary)/'state.json',True)
    require(actual==READ(folder/'state-final.json') and observed['productionOutcome']==READ(folder/'deployed-reader-replay.json')['productionOutcome']
        and len(observed['negativeControls'])==46 and observed['nativeBaseline']==baseline['production_outcome'],'Strengthened reader changed original formal conclusions')
    for name,value in [('native-reader-closure.json',observed),('native-baseline-closure.json',baseline),('runtime-closure.json',installed_readback(folder))]:
        if (folder/name).exists():require(value==READ(folder/name),'Existing native closure changed')
        else:save(folder/name,value)
    proof=replay_transition(folder)
    if (folder/'state-transition.json').exists():require(proof==READ(folder/'state-transition.json'),'Stored audit-only state transition changed')
    else:save(folder/'state-transition.json',proof)
    validate_transition(folder,observed)
    seal={str(p.relative_to(folder)):SHA(p.read_bytes()) for p in folder.rglob('*') if p.is_file()};save(folder/'acceptance-originals.json',seal)
def verify_packaged_replay(folder):
    a=reader_path(folder,True)
    with zipfile.ZipFile(a/'runner.jar') as archive:
        resource=archive.read('com/samlscope/runner/cases/native-keycloak-forceauthn-helper.json')
        require(SHA(resource)=='2d5f38a4ae72f1c6cfa0f37eba9016f7ee16758832769c61e8e8befaca346b49','Formal archive lacks pinned actual native replay helper')
def validate_transition(folder,replay):
    run,manifest,_=receipt_inventory(folder);before=READ(folder/'state-before.json');after=READ(folder/'state-final.json')
    require(before['schema']==after['schema']=='samlscope-keycloak-forceauthn-stored-v1' and before['runId']==after['runId']==run and before['caseId']==after['caseId']==CASE,'Foreign stored transition')
    require(before['sourceStore']==after['sourceStore']==READ(folder/'receipt/source-store-snapshot.json') and before['sourceHistory']==after['sourceHistory']==READ(folder/'receipt/source-history.json'),'Formal adoption changed original history/configuration/outbox')
    require({k:v for k,v in before['executions'].items() if k!=CASE}=={k:v for k,v in after['executions'].items() if k!=CASE},'Formal adoption changed another case')
    old,new=before['case'],after['case'];outcome=dict(new['outcome']);details=dict(outcome['details']);previous=details.pop('previous_recorded_evidence_result',None);outcome['details']=details
    state=READ(folder/'state-transition.json')
    require(state['schema']=='samlscope-keycloak-forceauthn-state-transition-v1' and state['runId']==run and state['caseId']==CASE and state['revision']==new['revision'] and state['documentSha256']==new['documentSha256'] and state['stateSha256']==new['stateSha256'] and state['stateWithoutPriorAuditSha256']==old['stateSha256'] and state['stateAuditEqualsOutcomeAudit'] is True and state['priorResultAudit']==previous,'Central state changed beyond its exact prior-result audit')
    require(old['runId']==new['runId']==run and old['caseId']==new['caseId']==CASE and new['status']=='FINISHED' and new['revision']==old['revision']+1 and new['waitSha256']==old['waitSha256'] and new['verdict']=='PASS' and outcome==replay['productionOutcome'],'Central stored outcome/revision differs')
    require(old['documentSha256']==before['executions'][CASE] and new['documentSha256']==after['executions'][CASE],'Stored document identity differs')
    if old['outcome'] is None:require(previous is None,'Unexpected prior-result envelope')
    else:
        require(old['outcome']['outcome']=='NOT_VERIFIED' and isinstance(previous,dict) and previous['revision']==old['revision'] and previous['updated_at']==old['updatedAt'],'Missing exact prior recorded-result audit')
        for key,field in [('outcome','outcome'),('not_verified_reason','notVerifiedReason'),('reason_code','reasonCode'),('reason_message_key','reasonMessageKey'),('evidence','evidence'),('details','details')]:require(previous[key]==old['outcome'][field],'Prior recorded result changed')
    require(READ(folder/'transcript-before-adoption.json')==READ(folder/'transcript-final.json')==READ(folder/'transcript.json'),'Actual original transcript changed')
    return after
def verify_adoption(folder,live=False):
    folder=pathlib.Path(folder).resolve();seal=READ(folder/'acceptance-originals.json')
    for name,digest in seal.items():
        require(not pathlib.PurePosixPath(name).is_absolute() and '..' not in pathlib.PurePosixPath(name).parts,'Unsafe sealed original');path=folder/name
        require(path.is_file() and not any(p.is_symlink() for p in [path,*path.parents]) and SHA(path.read_bytes())==digest,'Closed formal original changed')
    run,manifest,_=receipt_inventory(folder);pins=READ(reader_path(folder,True)/'pins.json');require(pins['deployed'] and set(pins['projects'])==set(JARS),'Formal proof lacks all six actual installed archives')
    verify_packaged_replay(folder)
    replay_native(folder);baseline=replay_baseline(folder,True);require(baseline==READ(folder/'native-baseline-closure.json')==READ(folder/'deployed-source-baseline-controls.json'),'Original source control replay differs')
    with tempfile.TemporaryDirectory(prefix='kc-native-adopted-controls-') as temporary:
        temporary=pathlib.Path(temporary);observed=remote(folder,'replay',temporary/'report.json',True);require(observed==READ(folder/'native-reader-closure.json') and len(observed['negativeControls'])==46,'Current native reader/control replay differs')
        actual=remote(folder,'state',temporary/'state.json',True);require(actual==READ(folder/'state-final.json'),'Actual source history/stored conclusions changed after adoption')
        _,_,cp=archived_classpath(folder,True);command(['/Library/Java/JavaVirtualMachines/jdk-21.jdk/Contents/Home/bin/java','-cp',cp,'com.samlscope.runner.cases.'+HELPER,'offline',folder/'state-final.json',temporary/'central.json']);require(READ(temporary/'central.json')==actual,'Archived central Evaluator differs')
    after=validate_transition(folder,observed);result=READ(folder/'result-final.json');cases=[c for q in result['requirements'] for c in q.get('cases',[]) if c['id']==CASE];require(len(cases)==1,'Missing formal native case');case=cases[0]
    require(replay_transition(folder)==READ(folder/'state-transition.json'),'Actual audit-only central state transition changed')
    require(result['run']['id']==run and result['target']['metadata_digest']=='sha256:'+manifest['targetMetadataSha256'] and case['mode']=='ATTESTED' and case['outcome']=='SATISFIED' and case['verdict']=='PASS' and case['attested'] is False and case['evidence']==after['case']['outcome']['evidence'] and case['reason_code']==after['case']['outcome']['reasonCode'],'Formal result differs from native reader/central stored result')
    require(READ(folder/'installed.json')['records']==manifest['files']|{'manifest.json':SHA((folder/'receipt/manifest.json').read_bytes())},'Installed actual byte readback differs')
    counts=READ(folder/'operation-counts.json');require(counts['restored'] is True and counts['automated_credential_submissions']==1 and counts['protocol_operations_attempted']==2,'Original operation/restoration burden differs')
    if live:
        installed=installed_readback(folder);original=READ(folder/'installed.json')
        require(installed==READ(folder/'runtime-closure.json') and {k:v for k,v in installed.items() if k!='projectJars'}=={k:v for k,v in original.items() if k!='projectJars'} and live_projects()==pins['projects'],'Live installed receipt/runtime differs')
    return folder/'result-final.json',{CASE:case}
if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('folder',type=pathlib.Path);parser.add_argument('--prepare',action='store_true');parser.add_argument('--mode',choices=('archive','install','formal','close','verify'));parser.add_argument('--qualification',type=pathlib.Path);parser.add_argument('--reader-generation');args=parser.parse_args()
    if args.prepare:
        result=prepare(args.folder.resolve());print('Current production native mechanism reader PASS:',len(result['negativeControls']),'altered-original controls')
    elif args.mode=='archive':archive(args.folder.resolve(),True,args.qualification,args.reader_generation);print('All six qualified installed modules archived independently')
    elif args.mode=='install':install(args.folder.resolve());print('Installed actual receipt bytes verified')
    elif args.mode=='formal':formal(args.folder.resolve());print('Formal native mechanism conclusion captured')
    elif args.mode=='close':close(args.folder.resolve());print('Existing formal native result closed without Suite writes')
    else:print(verify_adoption(args.folder.resolve())[0])
