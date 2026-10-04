#!/usr/bin/env python3
"""Replay and adopt two approved, scoped native persistent identifier observations."""
import argparse,base64,hashlib,json,pathlib,secrets,shutil,subprocess,tempfile,urllib.request,zipfile

REPO=pathlib.Path(__file__).resolve().parents[2]
SUITE='samlscope-reference-suite';HELPER='VerifyKeycloakPersistentIdentifier'
JARS=['runner','core','saml','store','api','peer']
CASES={'IIP-SSO05-a1-idp-01':'sha256:eb4cdd50dca77f8e286b3f6e7f5166bd4e4723a4e0f4a73589486d871106c4c0','IIP-SSO05-a8-idp-01':'sha256:acd9b10dc4e281800ebc2ebdefbe189e3267a5b5e9f135fa953530b17756c466'}
PRODUCTION=['NativeIdentifierConstructionComparison','NativePersistentIdentifierEvidenceTestCase','KeycloakPersistentIdentifierEvidence']
RESOURCE='com/samlscope/runner/cases/native-keycloak-persistent-helper.json'
RESOURCE_SHA='b104705d67028ef77d2f771978719ca7360c06bc16e1506d652377aefea57512'
SHA=lambda raw:hashlib.sha256(raw).hexdigest();READ=lambda p:json.loads(pathlib.Path(p).read_bytes())
JAVA=pathlib.Path('/Library/Java/JavaVirtualMachines/jdk-21.jdk/Contents/Home/bin')
def require(value,why):
    if not value:raise ValueError(why)
def command(args,timeout=300):
    try:return subprocess.run(list(map(str,args)),check=True,capture_output=True,timeout=timeout)
    except subprocess.CalledProcessError as failed:raise RuntimeError(failed.stderr.decode(errors='replace')[-8000:]) from failed
def save(path,value):
    require(not path.exists(),'Immutable original already exists: '+str(path));path.write_text(json.dumps(value,sort_keys=True,indent=2)+'\n')
def api(path,body=None):
    request=urllib.request.Request('http://localhost:18080'+path,data=None if body is None else json.dumps(body).encode(),headers={'Content-Type':'application/json'})
    with urllib.request.urlopen(request,timeout=45) as response:return json.load(response)
def gradle_inputs():
    paths=set(REPO.rglob('build.gradle.kts'))|{REPO/'settings.gradle.kts',REPO/'gradle.properties',REPO/'gradle/libs.versions.toml',REPO/'gradle/verification-metadata.xml'}
    return {str(p.relative_to(REPO)):SHA(p.read_bytes()) for p in sorted(paths) if p.is_file() and 'build' not in p.relative_to(REPO).parts}
def reader_path(folder,deployed=False):
    pointer=READ(folder/('active-reader.json' if deployed else 'active-candidate.json'));name=pointer['directory']
    require(name.startswith('reader') and '/' not in name and '\\' not in name and '..' not in name,'Unsafe generation')
    result=folder/name;require(SHA((result/'pins.json').read_bytes())==pointer['pinsSha256'],'Selected archive pins changed');return result
def live_projects():
    return {line.split()[1].rsplit('/',1)[-1].removesuffix('-0.1.0.jar'):line.split()[0] for line in command(['docker','exec',SUITE,'sha256sum',*['/opt/samlscope/lib/'+n+'-0.1.0.jar' for n in JARS]]).stdout.decode().splitlines()}
def archive(folder,deployed=False,qualification=None,generation=None):
    name=generation or ('reader-formal' if deployed else 'reader-candidate');require(name.startswith('reader') and '/' not in name and '\\' not in name and '..' not in name,'Unsafe archive')
    destination=folder/name;destination.mkdir();dependencies=destination/'dependencies';dependencies.mkdir();rows=[]
    # One dependency discovery per immutable generation, against the actual complete Suite classpath.
    for source in sorted((REPO/'api/build/install/samlscope/lib').glob('*.jar')):
        if source.name.endswith('-0.1.0.jar'):continue
        path=dependencies/source.name;shutil.copyfile(source,path);rows.append(dict(path=str(path),name=path.name,sha256=SHA(path.read_bytes())))
    require(rows and len({r['name'] for r in rows})==len(rows),'Ambiguous classpath')
    actual={line.split()[1].rsplit('/',1)[-1]:line.split()[0] for line in command(['docker','exec',SUITE,'sha256sum',*['/opt/samlscope/lib/'+r['name'] for r in rows]]).stdout.decode().splitlines()}
    require(actual=={r['name']:r['sha256'] for r in rows},'Actual dependency bytes differ')
    before=live_projects()
    for module in JARS:command(['docker','cp',SUITE+':/opt/samlscope/lib/'+module+'-0.1.0.jar',destination/(module+'.jar')])
    require(before==live_projects()=={module:SHA((destination/(module+'.jar')).read_bytes()) for module in JARS},'All six live module bytes changed during capture')
    cp=':'.join(str(destination/(n+'.jar')) for n in JARS)+':'+':'.join(r['path'] for r in rows)
    sources={}
    if not deployed:
        production=destination/'production';production.mkdir();source_paths=[]
        for type_name in PRODUCTION:
            source=REPO/'runner/src/main/java/com/samlscope/runner/cases'/(type_name+'.java');copied=production/source.name;shutil.copyfile(source,copied);sources[str(source.relative_to(REPO))]=SHA(copied.read_bytes());source_paths.append(copied)
        command([JAVA/'javac','-sourcepath','','-cp',cp,'-d',destination/'production-classes',*source_paths])
        added={str(p.relative_to(destination/'production-classes')):p.read_bytes() for p in (destination/'production-classes').rglob('*.class')}
        require(added and all(any(path.startswith('com/samlscope/runner/cases/'+name) for name in PRODUCTION) for path in added),'Candidate shadows another production class')
        resource=(REPO/'runner/src/main/resources'/RESOURCE).read_bytes();require(SHA(resource)==RESOURCE_SHA,'Pinned native resource changed');added[RESOURCE]=resource
        original=destination/'runner-original.jar';(destination/'runner.jar').rename(original)
        with zipfile.ZipFile(original) as old,zipfile.ZipFile(destination/'runner.jar','w',zipfile.ZIP_DEFLATED) as new:
            for entry in old.infolist():
                if entry.filename not in added:new.writestr(entry,old.read(entry.filename))
            for path,raw in added.items():new.writestr(path,raw)
        with zipfile.ZipFile(original) as old,zipfile.ZipFile(destination/'runner.jar') as new:
            require(set(new.namelist())==set(old.namelist())|set(added),'Candidate entry set differs')
            require(all(old.read(n)==new.read(n) for n in old.namelist() if n not in added),'Candidate modified unrelated bytes')
        save(destination/'candidate-overlay.json',dict(parentProjects=before,changedEntries={n:SHA(raw) for n,raw in added.items()},productionSources=sources,productOperations=0))
    else:
        require(qualification is not None,'Formal archive needs actual deployment qualification');qualification=pathlib.Path(qualification)
        runtime_path=qualification/'runtime-live-verification.json';runtime=READ(runtime_path);overlay=READ(qualification/'isolated-test-overlay.json');expected={n+'-0.1.0.jar':h for n,h in before.items()}
        require(runtime['healthStatus']==200 and runtime['projectJars']==overlay['projectJars']==expected,'Installed six module bytes differ from qualified runtime')
        save(destination/'deployment-qualification.json',dict(path=str(qualification),runtimeSha256=SHA(runtime_path.read_bytes()),overlaySha256=SHA((qualification/'isolated-test-overlay.json').read_bytes()),projects=before))
    helper=destination/(HELPER+'.java');shutil.copyfile(REPO/'dev/reference-acceptance'/(HELPER+'.java'),helper);command([JAVA/'javac','-sourcepath','','-cp',cp,'-d',destination/'classes',helper])
    classes={str(p.relative_to(destination/'classes')):SHA(p.read_bytes()) for p in (destination/'classes').rglob('*.class')};require(classes and all(p.rsplit('/',1)[-1].startswith(HELPER) for p in classes),'Verifier shadows production')
    save(destination/'pins.json',dict(projects={n:SHA((destination/(n+'.jar')).read_bytes()) for n in JARS},dependencies=rows,classes=classes,helperSha256=SHA(helper.read_bytes()),gradleInputs=gradle_inputs(),deployed=deployed,productionSources=sources))
    pointer=folder/('active-reader.json' if deployed else 'active-candidate.json')
    if pointer.exists():
        previous=READ(pointer);require(not deployed,'Installed reader selection is immutable');pointer.rename(folder/('previous-candidate-selection-'+previous['directory']+'.json'))
    save(pointer,dict(directory=name,pinsSha256=SHA((destination/'pins.json').read_bytes())))
    return destination
def archived_classpath(folder,deployed=False):
    archive=reader_path(folder,deployed);pins=READ(archive/'pins.json');require(pins['gradleInputs']==gradle_inputs(),'Gradle inputs changed; new generation required')
    for name,digest in pins['projects'].items():require((archive/(name+'.jar')).stat().st_nlink==1 and SHA((archive/(name+'.jar')).read_bytes())==digest,'Project archive changed')
    for row in pins['dependencies']:require(SHA(pathlib.Path(row['path']).read_bytes())==row['sha256'],'Dependency archive changed')
    require(SHA((archive/(HELPER+'.java')).read_bytes())==pins['helperSha256'],'Verifier changed')
    for name,digest in pins['classes'].items():require(SHA((archive/'classes'/name).read_bytes())==digest,'Verifier class changed')
    with zipfile.ZipFile(archive/'runner.jar') as jar:require(SHA(jar.read(RESOURCE))==RESOURCE_SHA,'Reader lacks pinned native helper')
    return archive,pins,':'.join(str(archive/(n+'.jar')) for n in JARS)+':'+str(archive/'classes')+':'+':'.join(r['path'] for r in pins['dependencies'])
def remote(folder,mode,output,deployed=False):
    archive,pins,_=archived_classpath(folder,deployed);run=READ(folder/'created.json')['run']['id'];remote_path='/tmp/kc-persistent-reader-'+secrets.token_hex(6)
    command(['docker','exec','-u','0',SUITE,'mkdir',remote_path])
    try:
        for name in JARS:command(['docker','cp',archive/(name+'.jar'),SUITE+':'+remote_path+'/'+name+'.jar'])
        command(['docker','cp',archive/'classes',SUITE+':'+remote_path+'/classes']);command(['docker','cp',folder/'receipt',SUITE+':'+remote_path+'/receipt'])
        command(['docker','exec','-u','0',SUITE,'chmod','-R','a+rX',remote_path]);uid=command(['docker','exec',SUITE,'id','-u']).stdout.decode().strip();command(['docker','exec','-u','0',SUITE,'chown','-R',uid+':'+uid,remote_path])
        cp=':'.join(remote_path+'/'+name+'.jar' for name in JARS)+':'+remote_path+'/classes:'+':'.join('/opt/samlscope/lib/'+r['name'] for r in pins['dependencies'])
        command(['docker','exec',SUITE,'java','-Xmx768m','-cp',cp,'com.samlscope.runner.cases.'+HELPER,mode,'/data',run,remote_path+'/receipt',remote_path+'/proof.json'],600)
        command(['docker','cp',SUITE+':'+remote_path+'/proof.json',output])
        if mode=='snapshot':
            for name in ['source-history.json',*['source-store-'+case+'.json' for case in CASES]]:command(['docker','cp',SUITE+':'+remote_path+'/receipt/'+name,folder/'receipt'/name])
        return READ(output)
    finally:command(['docker','exec','-u','0',SUITE,'rm','-rf','--',remote_path])
def prepare(folder):
    receipt=folder/'receipt';receipt.mkdir();shutil.copytree(folder/'originals',receipt/'originals');shutil.copytree(folder/'native-complete',receipt/'native-complete')
    for name in ['approved-membership.json','created.json','plan.json','suite-sp-metadata.xml','target-metadata.xml','native-helper.java','normal-exchange.json','mutant-exchange.json','normal-request.xml','normal-response.xml','mutant-request.xml','mutant-response.xml','operation-counts.json','operations.json','restoration.json','transcript.json']:
        shutil.copyfile(folder/name,receipt/name)
    shutil.copyfile(folder/'native-helper-suite-replay.json',receipt/'native-helper-replay.json');shutil.copyfile(folder/'native-helper-replay.json',receipt/'native-helper-host-prototype.json');shutil.copyfile(folder/'native-helper-suite-process.json',receipt/'native-helper-suite-process.json')
    archive(folder);remote(folder,'snapshot',folder/'source-binding-preflight.json')
    files={str(p.relative_to(receipt)):SHA(p.read_bytes()) for p in receipt.rglob('*') if p.is_file()};created=READ(folder/'created.json')
    save(receipt/'manifest.json',dict(schema='samlscope-keycloak-persistent-identifier-v1',runId=created['run']['id'],planId=created['run']['planId'],caseDigests=CASES,targetMetadataSha256=SHA((receipt/'target-metadata.xml').read_bytes()),files=files))
    return remote(folder,'replay',folder/'candidate-reader-replay.json')
def receipt_inventory(folder):
    receipt=folder/'receipt';manifest=READ(receipt/'manifest.json');expected=manifest['files']|{'manifest.json':SHA((receipt/'manifest.json').read_bytes())};actual={str(p.relative_to(receipt)):SHA(p.read_bytes()) for p in receipt.rglob('*') if p.is_file()}
    require(actual==expected and all(not p.is_symlink() for p in [receipt,*receipt.rglob('*')]),'Receipt has changed or unbound originals')
    run=READ(folder/'created.json')['run']['id'];require(manifest['runId']==run and manifest['caseDigests']==CASES,'Foreign receipt identity');return run,manifest,expected
def installed_readback(folder):
    run,_,expected=receipt_inventory(folder);destination='/data/persistent-identifier-evidence/'+run+'.keycloak-native-identifier'
    require(command(['docker','exec',SUITE,'find',destination,'-type','l']).stdout==b'','Installed receipt has symlinks');require(command(['docker','exec',SUITE,'find',destination,'-type','f','!','-perm','0644']).stdout==b'','Public receipt permissions differ')
    raw=command(['docker','exec',SUITE,'sh','-c','cd "$1" && find . -type f -exec sha256sum {} +','persistent-receipt-readback',destination]).stdout.decode();actual={}
    for line in raw.splitlines():
        digest,name=line.split('  ',1);require(name.startswith('./') and name[2:] not in actual,'Ambiguous installed inventory');actual[name[2:]]=digest
    require(actual==expected,'Actual installed receipt bytes differ');return dict(path=destination,records=actual,projects=READ(reader_path(folder,True)/'pins.json')['projects'],publicFiles0644=True,productOperations=0)
def install(folder):
    run,_,_=receipt_inventory(folder);_,pins,_=archived_classpath(folder,True);require(pins['deployed'] and live_projects()==pins['projects'],'Installed runtime differs from archived qualification')
    with tempfile.TemporaryDirectory(prefix='kc-persistent-preinstall-') as t:observed=remote(folder,'replay',pathlib.Path(t)/'proof.json',True)
    save(folder/'deployed-reader-replay.json',observed);remote(folder,'state',folder/'state-before.json',True);save(folder/'result-before-adoption.json',api('/api/runs/'+run+'/result.json'));save(folder/'transcript-before-adoption.json',api('/api/runs/'+run+'/transcript'))
    base='/data/persistent-identifier-evidence';destination=base+'/'+run+'.keycloak-native-identifier';stage=base+'/.stage-'+run
    for path in [destination,stage]:require(subprocess.run(['docker','exec',SUITE,'test','-e',path],capture_output=True,timeout=30).returncode==1,'Refusing installed receipt overwrite')
    with tempfile.TemporaryDirectory(prefix='kc-persistent-placement-') as t:
        copy=pathlib.Path(t)/'receipt';shutil.copytree(folder/'receipt',copy)
        for path in [copy,*copy.rglob('*')]:path.chmod(0o755 if path.is_dir() else 0o644)
        command(['docker','exec','-u','0',SUITE,'mkdir','-p',base]);command(['docker','cp',copy,SUITE+':'+stage]);command(['docker','exec','-u','0',SUITE,'mv',stage,destination])
    save(folder/'installed.json',installed_readback(folder))
def formal(folder):
    run,_,_=receipt_inventory(folder);require((folder/'installed.json').is_file(),'Install original receipt first')
    save(folder/'evaluate.json',api('/api/runs/'+run+'/protocol-evidence/evaluate',{}));save(folder/'result-final.json',api('/api/runs/'+run+'/result.json'));save(folder/'transcript-final.json',api('/api/runs/'+run+'/transcript'));remote(folder,'state',folder/'state-final.json',True);close(folder)
def validate_transition(folder,replay):
    run,_,_=receipt_inventory(folder);before=READ(folder/'state-before.json');after=READ(folder/'state-final.json');transition=READ(folder/'state-transition.json')
    require(before['runId']==after['runId']==run,'Foreign stored Run')
    require(before['sourceStores']==after['sourceStores'] and before['sourceHistory']==after['sourceHistory']==READ(folder/'receipt/source-history.json'),'Adoption changed source/configuration/outbox/history')
    require({k:v for k,v in before['executions'].items() if k not in CASES}=={k:v for k,v in after['executions'].items() if k not in CASES},'Adoption changed another case')
    for case in CASES:
        require(before['sourceStores'][case]==READ(folder/'receipt'/('source-store-'+case+'.json')),'Source Store differs')
        old,new=before['cases'][case],after['cases'][case];outcome=dict(new['outcome']);details=dict(outcome['details']);previous=details.pop('previous_recorded_evidence_result',None);outcome['details']=details;state=transition['cases'][case]
        require(state['runId']==run and state['caseId']==case and state['revision']==new['revision'] and state['documentSha256']==new['documentSha256'] and state['stateSha256']==new['stateSha256'] and state['stateWithoutPriorAuditSha256']==old['stateSha256'] and state['stateAuditEqualsOutcomeAudit'] is True and state['priorResultAudit']==previous,'Central state changed beyond exact prior-result audit')
        require(old['runId']==new['runId']==run and old['caseId']==new['caseId']==case and new['status']=='FINISHED' and new['revision']==old['revision']+1 and new['waitSha256']==old['waitSha256'] and new['verdict']=='PASS' and outcome==replay['productionOutcomes'][case],'Stored native Outcome/revision differs')
        require(old['documentSha256']==before['executions'][case] and new['documentSha256']==after['executions'][case],'Stored document identity differs')
        require(old['outcome']['outcome']=='NOT_VERIFIED' and isinstance(previous,dict) and previous['revision']==old['revision'] and previous['updated_at']==old['updatedAt'],'Exact prior-result audit missing')
        for key,field in [('outcome','outcome'),('not_verified_reason','notVerifiedReason'),('reason_code','reasonCode'),('reason_message_key','reasonMessageKey'),('evidence','evidence'),('details','details')]:require(previous[key]==old['outcome'][field],'Prior recorded result changed')
    require(READ(folder/'transcript-before-adoption.json')==READ(folder/'transcript-final.json')==READ(folder/'transcript.json'),'Original transcript changed');return after
def close(folder):
    require((folder/'result-final.json').is_file() and not (folder/'acceptance-originals.json').exists(),'Closure requires unsealed actual formal result');_,pins,_=archived_classpath(folder,True);require(live_projects()==pins['projects'],'Actual runtime differs')
    with tempfile.TemporaryDirectory(prefix='kc-persistent-closure-') as t:
        t=pathlib.Path(t);observed=remote(folder,'replay',t/'proof.json',True);actual=remote(folder,'state',t/'state.json',True);transition=remote(folder,'transition',t/'transition.json',True)
        require(actual==READ(folder/'state-final.json') and observed==READ(folder/'deployed-reader-replay.json'),'Current native reader or stored outcome differs');save(folder/'native-reader-closure.json',observed);save(folder/'state-transition.json',transition);save(folder/'runtime-closure.json',installed_readback(folder))
    validate_transition(folder,observed);save(folder/'acceptance-originals.json',{str(p.relative_to(folder)):SHA(p.read_bytes()) for p in folder.rglob('*') if p.is_file()})
def verify_adoption(folder,live=False):
    folder=pathlib.Path(folder).resolve();seal=READ(folder/'acceptance-originals.json')
    for name,digest in seal.items():
        require(not pathlib.PurePosixPath(name).is_absolute() and '..' not in pathlib.PurePosixPath(name).parts,'Unsafe sealed original');path=folder/name;require(path.is_file() and not any(p.is_symlink() for p in [path,*path.parents]) and SHA(path.read_bytes())==digest,'Closed original changed')
    run,manifest,_=receipt_inventory(folder);_,pins,cp=archived_classpath(folder,True);require(pins['deployed'] and set(pins['projects'])==set(JARS),'Missing actual six-module archive')
    with tempfile.TemporaryDirectory(prefix='kc-persistent-adopted-controls-') as t:
        t=pathlib.Path(t);observed=remote(folder,'replay',t/'proof.json',True);actual=remote(folder,'state',t/'state.json',True);transition=remote(folder,'transition',t/'transition.json',True)
        require(observed==READ(folder/'native-reader-closure.json') and actual==READ(folder/'state-final.json') and transition==READ(folder/'state-transition.json'),'Native controls or actual central stored state changed')
        command([JAVA/'java','-cp',cp,'com.samlscope.runner.cases.'+HELPER,'offline',folder/'state-final.json',t/'central.json']);require(READ(t/'central.json')==actual,'Archived central Evaluator differs')
    after=validate_transition(folder,observed);result=READ(folder/'result-final.json');selected={}
    require(result['run']['id']==run and result['target']['metadata_digest']=='sha256:'+manifest['targetMetadataSha256'],'Foreign formal result')
    for case in CASES:
        matches=[c for requirement in result['requirements'] for c in requirement.get('cases',[]) if c['id']==case];require(len(matches)==1,'Missing approved formal case');value=matches[0]
        require(value['mode']=='ATTESTED' and value['outcome']=='SATISFIED' and value['verdict']=='PASS' and value['attested'] is False and value['evidence']==after['cases'][case]['outcome']['evidence'] and value['reason_code']==after['cases'][case]['outcome']['reasonCode'],'Formal result differs from real native/central Outcome');selected[case]=value
    require(READ(folder/'installed.json')==READ(folder/'runtime-closure.json'),'Actual installed readback differs')
    counts=READ(folder/'operation-counts.json');require(counts['restored'] is True and counts['credentialPosts']==1 and counts['protocolOperationsAttempted']==2 and counts['diagnosticPrincipalControlOnly'] is True,'Actual burden/restoration differs')
    if live:require(installed_readback(folder)==READ(folder/'runtime-closure.json') and live_projects()==pins['projects'],'Current installed receipt/runtime differs')
    return folder/'result-final.json',selected
if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('folder',type=pathlib.Path);parser.add_argument('--mode',choices=['prepare','archive','install','formal','close','verify'],required=True);parser.add_argument('--qualification',type=pathlib.Path);parser.add_argument('--reader-generation');args=parser.parse_args();folder=args.folder.resolve()
    if args.mode=='prepare':print(prepare(folder))
    elif args.mode=='archive':print(archive(folder,True,args.qualification,args.reader_generation))
    elif args.mode=='install':install(folder);print('Actual native receipt installed and read back')
    elif args.mode=='formal':formal(folder);print('Two scoped persistent identifier cases formally captured and closed')
    elif args.mode=='close':close(folder);print('Existing formal originals closed')
    else:print(verify_adoption(folder)[0])
