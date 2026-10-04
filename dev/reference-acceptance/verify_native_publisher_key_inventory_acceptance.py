#!/usr/bin/env python3
"""Strict publication adoption; c3 stays outside the map while multi-current is unproven."""
import argparse, hashlib, json, os, pathlib, re, shutil, subprocess, tempfile, urllib.request

REPO=pathlib.Path(__file__).resolve().parents[2]
FOLDER='simplesamlphp-publisher-key-inventory-r3'
SUITE='samlscope-reference-suite'
HELPER='VerifyNativePublisherKeyInventoryEvidence'
STORED='ReadNativePublisherKeyStoredConclusions'
RUNTIME='runtime-actual';EVALUATION='evaluation-actual'
JARS=('runner','core','saml','store','peer','api')
QUALIFIED_DEPENDENCIES='deployment-v223/isolated-test-overlay.json'
C1='IIP-MD05-c1-idp-01';C3='IIP-MD05-c3-idp-01'
PINS={}  # Set only from the independently qualified deployed archive.
PRIOR_ATTEMPTS=('simplesamlphp-publisher-key-inventory-r1','publisher-request-context-preflight-r2','simplesamlphp-publisher-key-inventory-r2')
CONTROLS={'wrong-run','wrong-plan','wrong-target','wrong-adapter','wrong-campaign','wrong-entity','duplicate-history','foreign-history','foreign-decoded-reference','missing-original','missing-publication','publication-bytes-replaced','native-source-replaced','projection-source-replaced','configuration-epoch-unbound','configuration-restore-mismatch','native-runtime-replaced','native-window-reversed','native-publication-unbound','missing-control-id','duplicate-control-id','swapped-control-id','foreign-case-control-id','control-input-replaced','control-invocation-unbound','control-runtime-unbound','native-readback-credential','incomplete-history','calibration-label-only'}
sha=lambda b:hashlib.sha256(b).hexdigest()
load=lambda p:json.loads(p.read_bytes())

def require(value,message):
    if not value:raise ValueError(message)

def save(path,value):
    require(not path.exists(),'Immutable output exists: '+str(path))
    path.write_text(json.dumps(value,indent=2)+'\n')

def locate(root,product='simplesamlphp'):
    require(product=='simplesamlphp','Unimplemented product adapter remains NOT_VERIFIED')
    root=pathlib.Path(root).absolute();require(not any(p.is_symlink() for p in [root,*root.parents]),'Unsafe evidence root')
    root=root.resolve();folder=root if (root/'receipt/manifest.json').is_file() else root/FOLDER
    require(not any(p.is_symlink() for p in [folder,*folder.parents]),'Unsafe attempt folder')
    return folder

def api(path,body=None):
    req=urllib.request.Request('http://localhost:18080'+path,data=None if body is None else json.dumps(body).encode(),headers={} if body is None else {'Content-Type':'application/json'})
    with urllib.request.urlopen(req,timeout=60) as response:return json.load(response)

def public_cases(result):return {c['id']:c for q in result['requirements'] for c in q['cases']}

def cumulative_operations(folder,write=False):
    """Keep failed setup and public context calibration separate from qualification."""
    records=[];total=dict(productSettings=0,configurationRestorations=0,nativePublicCalls=0,metadataGets=0,credentialPosts=0,samlSubmissions=0,personOperations=0)
    for name in PRIOR_ATTEMPTS:
        prior=folder.parent/name
        require(prior.is_dir() and not any(p.is_symlink() for p in [prior,*prior.rglob('*')]),'Unsafe prior attempt')
        inventory={str(p.relative_to(prior)):sha(p.read_bytes()) for p in prior.rglob('*') if p.is_file()}
        if name.endswith('inventory-r1'):
            costs=load(prior/'operation-counts.json');require(costs==dict(productSettings=0,configurationRestorations=0,nativePublicCalls=1,credentialPosts=0,samlSubmissions=0,personOperations=0),'Failed preparation costs changed')
            operations=load(prior/'operations.json');require(len(operations)==1 and operations[0]['exitCode']==0
                and operations[0]['inputSha256']==sha((prior/'receipt/native-public-readback.php').read_bytes())
                and operations[0]['outputSha256']==sha((prior/'receipt/native-readbacks/initial.json').read_bytes()),'Failed CLI original unbound')
            native=load(prior/'receipt/native-readbacks/initial.json');publication=(prior/'receipt/native-publications/initial.xml').read_bytes()
            require(native['nativeProducedMetadataSha256']!=sha(publication) and load(prior/'restoration.json')=={'restored':False},'Failed context attempt no longer preserved')
            costs=costs|dict(metadataGets=1);scope='Stopped before native configuration: CLI context differed from actual GET; no restoration write was needed.'
        elif name.startswith('publisher-request-context'):
            q=load(prior/'qualification.json');require(q['nativePublicCalls']==q['metadataGets']==1 and all(q[k]==0 for k in ('settings','saml','credentials','personOperations'))
                and q['exactNativeProducerBytes'] and q['sourceSha256']==sha((prior/'projection-source.php').read_bytes())
                and q['projectionSha256']==sha((prior/'public-readback.json').read_bytes())
                and q['actualGetSha256']==q['nativeProducedSha256']==sha((prior/'actual-publication.xml').read_bytes()),'Read-only context calibration unbound')
            costs=dict(productSettings=0,configurationRestorations=0,nativePublicCalls=1,metadataGets=1,credentialPosts=0,samlSubmissions=0,personOperations=0)
            scope='Read-only native public HTTP-context calibration; no product configuration or SAML operation.'
        else:
            q=load(prior/'failure-accounting.json');recovery=load(prior/'recovery-restoration.json');operations=load(prior/'operations.json')
            costs=q['costs'];require(costs==dict(productSettings=2,configurationRestorations=1,nativePublicCalls=3,metadataGets=2,credentialPosts=0,samlSubmissions=0,personOperations=0)
                and q['nativePushAttempts']==q['nativePushFailures']==2 and q['adopted'] is False and q['originalsModified'] is False
                and q['collectorSourceSha256']==sha((prior/'collector-source.py').read_bytes()) and q['operationsSha256']==sha((prior/'operations.json').read_bytes())
                and q['recoverySha256']==sha((prior/'recovery-restoration.json').read_bytes()),'Read-only mount failure accounting changed')
            require(len(operations)==3 and operations[0]['outputSha256']==sha((prior/'receipt/native-readbacks/initial.json').read_bytes())
                and operations[1]['outputSha256']==sha((prior/'receipt/control-positive.json').read_bytes())
                and operations[2]['outputSha256']==sha((prior/'receipt/control-negative.json').read_bytes())
                and all(r['exitCode']==0 for r in operations),'Failed mount attempt public operations unbound')
            require(recovery['exactRestored'] and recovery['originalSha256']==recovery['finalHostSha256']==recovery['finalNativeSha256']
                and recovery['restoredPublicationSha256']==recovery['initialTargetSha256']==sha((prior/'recovery-publication.xml').read_bytes())
                and recovery['logicalConfigurationWriteAttempts']==2 and recovery['restorationWriteAttempts']==1
                and recovery['nativePushAttempts']==2 and recovery['nativePushSuccesses']==0,'Failed mount attempt exact restoration missing')
            scope='Host prepare/restoration succeeded; two redundant writes to read-only guest mount failed. Fresh native/hash/publication recovery proves restoration.'
        records.append(dict(folder=name,files=inventory,costs=costs,scope=scope))
        for key,value in costs.items():total[key]+=value
    qualified=load(folder/'operation-counts.json');http=load(folder/'public-read-operations.json')
    require([r['label'] for r in http]==['initial','browser-role','restored'] and all(r['method']=='GET' and r['url']=='http://localhost:18380/simplesaml/module.php/saml/idp/metadata'
        and r['responseStatus']==200 and r['startedAt']<r['finishedAt']
        and r['responseSha256']==sha((folder/('receipt/native-publications/'+r['label']+'.xml')).read_bytes()) for r in http),'Qualified public GET attempts incomplete')
    costs=qualified|dict(metadataGets=len(http))
    for key,value in costs.items():total[key]+=value
    result=dict(schema='samlscope-native-publisher-cumulative-costs-v1',priorAttempts=records,qualifiedAttempt=folder.name,
        qualifiedCosts=costs,cumulativeCosts=total,qualifiedCountsSha256=sha((folder/'operation-counts.json').read_bytes()),
        qualifiedHttpLedgerSha256=sha((folder/'public-read-operations.json').read_bytes()),userInteractions=0)
    path=folder/'cumulative-operation-audit.json'
    if write:save(path,result)
    else:require(load(path)==result,'Prior failed-attempt lineage or cumulative operation audit changed')
    return result

def verify_files(folder):
    receipt=folder/'receipt';m=load(receipt/'manifest.json');run=m['runId'];require(re.fullmatch(r'run_[0-9A-HJKMNP-TV-Z]{26}',run) and re.fullmatch(r'plan_[0-9A-HJKMNP-TV-Z]{26}',m['planId']),'Unsafe Run/Plan')
    require(m['schema']=='samlscope-native-metadata-publisher-key-inventory-v1' and m['campaignId']=='native-metadata-publisher-key-inventory'
        and m['adapter']=='simplesamlphp-stock-publisher-inventory-v1' and m['selectedPath']=='stock-current-role' and m['counterfactualCalibrationOnly'] is False,'Stock-only receipt required')
    inventory={str(p.relative_to(receipt)):sha(p.read_bytes()) for p in receipt.rglob('*') if p.is_file()}
    require(not any(p.is_symlink() for p in receipt.rglob('*')) and inventory==m['files']|{'manifest.json':sha((receipt/'manifest.json').read_bytes())},'Receipt inventory changed')
    require(sha((folder/'target-metadata.xml').read_bytes())==sha((receipt/'target-metadata.xml').read_bytes())==m['targetMetadataSha256'],'Run snapshot changed')
    plan=load(folder/'plan.json');before=load(folder/'result-before.json');slots=public_cases(before)
    require(plan['id']==m['planId'] and plan['profile']=='metadata_idp' and before['run']['id']==run and before['target']['role']=='IDP'
        and before['target']['metadata_digest']=='sha256:'+m['targetMetadataSha256'] and all(c in slots and slots[c]['mode']=='CONFIG' for c in (C1,C3)),'Real same-Run metadata case slots missing')
    entries=load(folder/'transcript.json');by={e['id']:e for e in entries};require(len(by)==len(entries) and all(e['runId']==run for e in entries),'Foreign/duplicate history')
    old=load(folder/'transcript-before-collection.json');require([e for e in entries if e['id'] in {x['id'] for x in old}]==old,'Historical protocol data changed')
    decoded={}
    for row in load(folder/'decoded-manifest.json'):
        p=folder/row['file'];id=row['id'];require(p.parent==folder/'decoded' and not p.is_symlink(),'Foreign decoded original');raw=p.read_bytes()
        require(p.parent==folder/'decoded' and id in by and by[id]['decodedSamlRef']=='transcripts/'+run+'/'+id+'.saml.xml'
            and by[id]['decodedSamlBytes']==len(raw) and sha(raw)==row['sha256'],'Decoded original changed');decoded[id]=raw
    require(set(decoded)=={r['reference'] for r in m['originals'].values()},'Only actual native selected originals may supply decoded evidence')
    for ref in m['originals'].values():require(sha(decoded[ref['reference']])==ref['sha256']==m['files'][ref['file']]
        and decoded[ref['reference']]==(receipt/ref['file']).read_bytes(),'Recorder/native original differs')
    counts=load(folder/'operation-counts.json');require(counts==dict(productSettings=2,configurationRestorations=1,nativePublicCalls=6,credentialPosts=0,samlSubmissions=0,personOperations=0),'Actual native costs differ')
    restored=load(folder/'restoration-write.json');require(restored['restored'] is True and restored['original_sha256']==restored['final_sha256']
        and restored['configuration_write_attempts']==2 and restored['restoration_write_attempts']==1,'Exact native restoration missing')
    mounted=load(folder/'native-mounted-configuration-readbacks.json');mount=mounted['mount'];readbacks=mounted['readbacks']
    require(mount==dict(Type='bind',Source=str((REPO/'build/acceptance/reference-20260914/ssp-config/saml20-idp-hosted.php').resolve()),
        Destination='/var/simplesamlphp/metadata/saml20-idp-hosted.php',RW=False) and mounted['guestWriteAttempts']==0
        and [r['phase'] for r in readbacks]==['initial','before-host-write','after-host-write','before-host-write','after-host-write']
        and all(r['sha256']==r['expectedSha256'] and r['startedAt']<=r['finishedAt'] for r in readbacks)
        and readbacks[0]['sha256']==readbacks[1]['sha256']==readbacks[4]['sha256']==restored['original_sha256']
        and readbacks[2]['sha256']==readbacks[3]['sha256']!=restored['original_sha256'],'Host/native mount epoch proof missing')
    require(load(folder/'qualification.json')['adopted'] is False and load(folder/'qualification.json')['initialTargetSnapshotUnchanged'] is True,'Measurement must remain separate from adoption')
    cumulative_operations(folder)
    return m,run,entries

def capture_runtime(folder):
    require(os.statvfs(REPO).f_bavail*os.statvfs(REPO).f_frsize>=48*1024*1024,'Insufficient archive space')
    dest=folder/RUNTIME;dest.mkdir(exist_ok=False);pins={}
    for name in JARS:
        remote='/opt/samlscope/lib/'+name+'-0.1.0.jar';before=subprocess.check_output(['docker','exec',SUITE,'sha256sum',remote],timeout=30).decode().split()[0]
        subprocess.run(['docker','cp',SUITE+':'+remote,str(dest/(name+'.jar'))],check=True,capture_output=True,timeout=50)
        after=subprocess.check_output(['docker','exec',SUITE,'sha256sum',remote],timeout=30).decode().split()[0]
        require(before==after==sha((dest/(name+'.jar')).read_bytes()),'Deployed bytes changed while archiving');pins[name]=before
    qualification=folder.parent/QUALIFIED_DEPENDENCIES
    qualified=load(qualification);dependencies=qualified['dependencySha256'];priority=[];library=dest/'dependencies';library.mkdir()
    require(qualified['projectJars']=={n+'-0.1.0.jar':pins[n] for n in JARS},'Archive differs from qualified deployed project JARs')
    for name,digest in dependencies.items():
        path=pathlib.Path(name)
        require(path.name not in {n+'-0.1.0.jar' for n in JARS} and path.is_file() and not path.is_symlink()
            and sha(path.read_bytes())==digest,'Qualified third-party dependency changed')
        target=library/path.name;require(not target.exists(),'Duplicate dependency name');shutil.copyfile(path,target)
        priority.append(dict(file='dependencies/'+path.name,sha256=digest))
    save(dest/'dependency-priority.json',dict(schema='samlscope-publisher-replay-dependencies-v1',qualifiedSource=str(qualification.relative_to(folder.parent)),
        qualifiedSourceSha256=sha(qualification.read_bytes()),mutableProjectEntriesExcluded=True,entries=priority))
    pins['dependencyPrioritySha256']=sha((dest/'dependency-priority.json').read_bytes())
    for name in (HELPER,STORED):
        raw=pathlib.Path(__file__).with_name(name+'.java').read_bytes();(dest/(name+'.java')).write_bytes(raw);pins[name]=sha(raw)
    save(dest/'pins.json',pins);save(dest/'archive-provenance.json',dict(actualDeployedByteCopy=True,mutableProjectHardlinks=False,productOperations=0));return pins

def archived_classpath(runtime):
    inventory=load(runtime/'dependency-priority.json');require(inventory['mutableProjectEntriesExcluded'],'Mutable project dependency')
    paths=[];seen=set()
    for row in inventory['entries']:
        path=runtime/row['file'];require(path.parent==runtime/'dependencies' and not path.is_symlink()
            and row['file'] not in seen and sha(path.read_bytes())==row['sha256'],'Archived dependency changed')
        seen.add(row['file']);paths.append(str(path.resolve()))
    return ':'.join(str((runtime/(n+'.jar')).resolve()) for n in JARS)+':'+':'.join(paths)

def replay(folder):
    runtime=folder/RUNTIME;pins=load(runtime/'pins.json');require(PINS and pins==PINS,'Runtime/archive not independently pinned')
    for name in JARS:require(sha((runtime/(name+'.jar')).read_bytes())==pins[name],'Archived JAR changed')
    require(sha((runtime/(HELPER+'.java')).read_bytes())==pins[HELPER] and sha((runtime/(STORED+'.java')).read_bytes())==pins[STORED]
        and sha((runtime/'dependency-priority.json').read_bytes())==pins['dependencyPrioritySha256'],'Archived helpers/dependency order changed')
    cp=archived_classpath(runtime)
    with tempfile.TemporaryDirectory(prefix='publisher-archived-replay-') as name:
        tmp=pathlib.Path(name);classes=tmp/'classes';subprocess.run(['javac','-sourcepath','','-cp',cp,'-d',str(classes),str(runtime/(HELPER+'.java'))],check=True,capture_output=True,timeout=60)
        require(all(p.name.startswith(HELPER) for p in classes.rglob('*.class')),'Helper shadows production Reader')
        subprocess.run(['java','-cp',str(classes)+':'+cp,'com.samlscope.runner.cases.'+HELPER,str(folder.resolve()),str(tmp/'report.json')],check=True,capture_output=True,timeout=90)
        return load(tmp/'report.json')

def with_stored(operation,folder,name,case,proof=None,before=None,after=None):
    import native_publisher_stored_outcome as stored
    if operation=='capture':return stored.capture(folder,RUNTIME,name,load(folder/'created.json')['run']['id'],case)
    return stored.compare_stored(folder,RUNTIME,case,proof,before_name=before,after_name=after)

def install(folder):
    m,run,entries=verify_files(folder);require(replay(folder)==load(folder/'native-reader-replay.json'),'Actual Reader replay must precede placement');ev=folder/EVALUATION;ev.mkdir(exist_ok=False)
    # Reading result.json can auto-re-evaluate: capture both stored originals first.
    for case,label in ((C1,'c1'),(C3,'c3')):with_stored('capture',folder,EVALUATION+'/stored-before-'+label+'.json',case)
    save(ev/'result-before.json',api('/api/runs/'+run+'/result.json'));save(ev/'transcript-before.json',api('/api/runs/'+run+'/transcript'))
    require(load(ev/'transcript-before.json')==entries,'Unexpected history before placement')
    base='/data/metadata-publisher-key-evidence';dest=base+'/'+run;stage=base+'/.stage-'+run
    require(subprocess.run(['docker','exec',SUITE,'test','-e',dest],capture_output=True,timeout=20).returncode==1,'Already owned native proof must not be overwritten')
    require(subprocess.run(['docker','exec',SUITE,'test','-e',stage],capture_output=True,timeout=20).returncode==1,'Unexpected staging state')
    with tempfile.TemporaryDirectory(prefix='publisher-public-placement-') as name:
        copy=pathlib.Path(name)/'receipt';shutil.copytree(folder/'receipt',copy)
        for p in copy.rglob('*'):p.chmod(0o755 if p.is_dir() else 0o644)
        copy.chmod(0o755)
        # Staging is on /data's filesystem. Publish only after Suite-user hash readback.
        subprocess.run(['docker','exec','--user','0',SUITE,'mkdir','-p',base],check=True,capture_output=True,timeout=30)
        subprocess.run(['docker','cp',str(copy),SUITE+':'+stage],check=True,capture_output=True,timeout=90)
        require(readback_inventory(stage)==m['files']|{'manifest.json':sha((folder/'receipt/manifest.json').read_bytes())},'Suite user cannot read exact public inventory')
        subprocess.run(['docker','exec','--user','0',SUITE,'mv',stage,dest],check=True,capture_output=True,timeout=30)
    require(readback_inventory(dest)==m['files']|{'manifest.json':sha((folder/'receipt/manifest.json').read_bytes())},'Final public inventory differs')
    save(folder/'receipt-installation.json',dict(path=dest,readBackVerified=True,records=m['files']|{'manifest.json':sha((folder/'receipt/manifest.json').read_bytes())},atomicSameDataFilesystem=True,publicFiles0644=True,publicDirectories0755=True,stockSelectedPath=True,productOperations=0))

def readback_inventory(path):
    # GNU find/sha256sum in the reference Suite; relative paths are public and bounded.
    result=subprocess.run(['docker','exec',SUITE,'sh','-c','cd "$1" && find . -type f -exec sha256sum {} +','publisher-readback',path],check=True,capture_output=True,timeout=50)
    rows={}
    for line in result.stdout.decode().splitlines():
        digest,name=line.split('  ',1);require(name.startswith('./') and name[2:] not in rows,'Ambiguous placement inventory');rows[name[2:]]=digest
    return rows

def formal(folder):
    m,run,entries=verify_files(folder);ev=folder/EVALUATION;require((ev/'stored-before-c1.json').is_file(),'Before capture must precede placement')
    save(ev/'evaluate.json',api('/api/runs/'+run+'/protocol-evidence/evaluate',{}))
    save(ev/'result.json',api('/api/runs/'+run+'/result.json'));save(ev/'transcript.json',api('/api/runs/'+run+'/transcript'))
    for case,label in ((C1,'c1'),(C3,'c3')):with_stored('capture',folder,EVALUATION+'/stored-after-'+label+'.json',case)

def verify(root,product='simplesamlphp',live=False):
    folder=locate(root,product);m,run,entries=verify_files(folder);observed=load(folder/'native-reader-replay.json')
    require(replay(folder)==observed,'Archived production replay differs')
    require(set(observed['negativeControls'])==CONTROLS and set(observed['negativeControls'].values())=={'NOT_VERIFIED'}
        and set(observed['approvedMutants'])=={C1,C3} and all(x['production']['outcome']=='NOT_VERIFIED' and x['offline']['outcome']=='VIOLATED' for x in observed['approvedMutants'].values())
        and all(observed['wrapperLifecycle'].values()) and observed['counterfactualAdopted'] is False,'Meaningful controls/stock permission incomplete')
    outcomes=observed['caseOutcomes'];require(outcomes[C1]['outcome']=='SATISFIED' and outcomes[C3]['outcome']=='NOT_VERIFIED','Partial c3 cannot be adopted')
    installed=load(folder/'receipt-installation.json');require(installed['readBackVerified'] and installed['records']==m['files']|{'manifest.json':sha((folder/'receipt/manifest.json').read_bytes())}
        and installed['atomicSameDataFilesystem'] and installed['publicFiles0644'] and installed['stockSelectedPath'],'Public stock placement not closed')
    ev=folder/EVALUATION;result=load(ev/'result.json');cases=public_cases(result);before=public_cases(load(ev/'result-before.json'))
    require(result['run']['id']==run and result['target']['metadata_digest']=='sha256:'+m['targetMetadataSha256']
        and load(ev/'transcript-before.json')==load(ev/'transcript.json')==entries,'Formal identity/history changed')
    after=with_stored('compare',folder,None,C1,outcomes[C1],EVALUATION+'/stored-before-c1.json',EVALUATION+'/stored-after-c1.json')
    case=cases[C1];require((case['outcome'],case['verdict'],case['reason_code'],case['evidence_class'],case['attested'])==('SATISFIED','PASS','metadata.publisher.role-description-complete','OPERATOR_ASSISTED',False)
        and case['evidence']==outcomes[C1]['evidence'] and after['verdict']=='PASS','Full native central conclusion/provenance differs')
    require(cases[C3]==before[C3] and cases[C3]['outcome']=='NOT_VERIFIED','Unproven multi-current result changed')
    # Every unrelated result is preserved, including historical source evidence.
    require({c:v for c,v in cases.items() if c!=C1}=={c:v for c,v in before.items() if c!=C1},'Unrelated case changed')
    if live:
        require(api('/api/runs/'+run+'/transcript')==entries and public_cases(api('/api/runs/'+run+'/result.json'))[C1]==case,'Live conclusion/history differs')
        initial=load(folder/'receipt/native-readbacks/initial.json');program=(folder/'receipt/native-public-readback.php').read_bytes()
        raw=subprocess.check_output(['docker','exec','-i','samlscope-reference-ssp','php','-d','display_errors=0','-d','log_errors=0'],input=program,timeout=40);current=json.loads(raw)
        for field in ('publicRequestContext','publicNativeMetadata','currentCredentials','remotePeers','loadedClasses','metadataSources','configurationHashes','roleFeatureFlags','nativeProducedMetadataXmlBase64','nativeProducedMetadataSha256'):require(current[field]==initial[field],'Live native restoration differs')
        native=json.loads(subprocess.check_output(['docker','inspect','--format','{"id":{{json .Id}},"image":{{json .Image}},"running":{{json .State.Running}},"startedAt":{{json .State.StartedAt}},"mounts":{{json .Mounts}}}','samlscope-reference-ssp'],timeout=30))
        native['mounts']=sorted(native['mounts'],key=lambda x:json.dumps(x,sort_keys=True,separators=(',',':'))+'\n')
        original=load(folder/'receipt'/m['originals']['initial']['file']);require(native==original['runtime'],'Live native runtime/mount epoch differs')
        with urllib.request.urlopen('http://localhost:18380/simplesaml/module.php/saml/idp/metadata',timeout=30) as response:require(sha(response.read())==m['targetMetadataSha256'],'Live original publication differs')
        require(readback_inventory(installed['path'])==installed['records'],'Live placement differs')
    return ev/'result.json',{C1:case}

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('root',type=pathlib.Path);p.add_argument('--product',default='simplesamlphp');p.add_argument('--record-costs',action='store_true');p.add_argument('--capture-runtime',action='store_true');p.add_argument('--record-replay',action='store_true');p.add_argument('--install',action='store_true');p.add_argument('--formal',action='store_true');p.add_argument('--live',action='store_true');a=p.parse_args();folder=locate(a.root,a.product)
    if a.record_costs:print(json.dumps(cumulative_operations(folder,True),indent=2))
    elif a.capture_runtime:print(json.dumps(capture_runtime(folder),indent=2))
    elif a.record_replay:save(folder/'native-reader-replay.json',replay(folder));print('Actual archived replay passed')
    elif a.install:install(folder);print('Public stock proof installed after stored-before capture')
    elif a.formal:formal(folder);print('Formal result captured')
    else:path,cases=verify(a.root,a.product,a.live);print(json.dumps(dict(result=str(path),cases=list(cases),additionalSaml=0,additionalCredentials=0,verificationOnlyNativePublicCalls=1 if a.live else 0,verificationOnlyMetadataGets=1 if a.live else 0)))
