#!/usr/bin/env python3
"""Adopt complete native MetadataResolver UI values using the archived deployed reader.

Costs remain advisory. The input/model/configuration/source/restore originals and
explicit offline detector controls are mandatory; no calibration assets are installed.
"""
import argparse,hashlib,importlib.util,json,os,pathlib,shutil,subprocess,tempfile,urllib.request,zipfile
REPO=pathlib.Path(__file__).resolve().parents[2]
FOLDER='shibboleth-full-ui-r2';CASE='IIP-MD05-f-idp-01';SUITE='samlscope-reference-suite'
HELPER='VerifyMetadataFullUiEvidence';RUNTIME='runtime-v206';EVALUATION='evaluation-v206';JARS=('runner','core','saml','store')
PINS={'runner':'ff22905039caea7cd5bc34accb53bbc1e2f7a81fc30e0c40791fbf7204aec7cc',
    'core':'1d6e0020c915f50e78902554c06b61916a3f49e50de78d3bc23c6089d312babe',
    'saml':'d8ea9ebf6048f82ba9773850d8302cca00b19751fa0aac4eca675506c8c737ca',
    'store':'c4482cd06f9290a3592f0fceac2c9ec2d7603ea0557d1edc885e1c3d51bd8ece',
    'helper':'1321023153f52f76c0b89225983427fee24bc1c96784ed5e75e9594bb5e712b6'}
SHA=lambda b:hashlib.sha256(b).hexdigest()
READ=lambda p:json.loads(pathlib.Path(p).read_bytes())
def require(value,message):
    if not value:raise ValueError(message)
def save(path,value):
    with pathlib.Path(path).open('x') as output:output.write(json.dumps(value,indent=2)+'\n')
def command(args):return subprocess.run(args,capture_output=True,check=True,timeout=90)
def locate(root):
    p=pathlib.Path(root).absolute();require(not any(x.is_symlink() for x in [p,*p.parents]),'Unsafe evidence root');p=p.resolve();return p if p.name==FOLDER else p/FOLDER
def api(path,body=None):
    request=urllib.request.Request('http://localhost:18080'+path,data=None if body is None else json.dumps(body).encode(),headers={} if body is None else {'Content-Type':'application/json'})
    with urllib.request.urlopen(request,timeout=45) as response:return json.load(response)
def rows(result):return {c['id']:c for r in result['requirements'] for c in r['cases']}
def stored_helpers():
    spec=importlib.util.spec_from_file_location('_full_ui_stored',pathlib.Path(__file__).with_name('keycloak_registered_signer_stored_outcome.py'))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);module.HELPER='ReadMetadataFullUiStoredConclusions';return module
def capture_runtime(folder):
    folder=pathlib.Path(folder);archive=folder/RUNTIME;archive.mkdir();pins={}
    for name in JARS:
        candidates=list((REPO/'api/build/install/samlscope/lib').glob(name+'-*.jar'));require(len(candidates)==1,'Ambiguous project output')
        source=candidates[0];digest=command(['docker','exec',SUITE,'sha256sum','/opt/samlscope/lib/'+source.name]).stdout.decode().split()[0]
        require(digest==SHA(source.read_bytes()),'Distribution/runtime bytes differ');shutil.copyfile(source,archive/(name+'.jar'));pins[name]=digest
    source=pathlib.Path(__file__).with_name(HELPER+'.java');(archive/source.name).write_bytes(source.read_bytes());pins['helper']=SHA(source.read_bytes());save(archive/'pins.json',pins)
    cp=pathlib.Path('/private/tmp/samlscope-runner-runtime-classpath.txt').read_text().strip()
    paths=[pathlib.Path(p) for p in cp.split(':') if pathlib.Path(p).name not in [n+'-0.1.0.jar' for n in ['core','saml','store','runner','api','peer']]]
    require(all(p.is_file() for p in paths),'Dependency originals unavailable');save(archive/'dependency-pins.json',[dict(path=str(p),sha256=SHA(p.read_bytes())) for p in paths])
    save(archive/'archive-placement.json',dict(mutableProjectHardlinks=False,actualRuntimeBytesVerified=True));return pins
def classpath(folder):
    archive=folder/RUNTIME;actual=READ(archive/'pins.json');require(PINS is not None and actual==PINS,'Actual reader pins not finalized')
    for name in JARS:require(SHA((archive/(name+'.jar')).read_bytes())==actual[name],'Immutable project JAR changed')
    require(SHA((archive/(HELPER+'.java')).read_bytes())==actual['helper'],'Archived detector helper changed');dependencies=READ(archive/'dependency-pins.json')
    for row in dependencies:require(SHA(pathlib.Path(row['path']).read_bytes())==row['sha256'],'Pinned dependency changed')
    return ':'.join(str((archive/(n+'.jar')).resolve()) for n in JARS)+':'+':'.join(x['path'] for x in dependencies)
def replay(folder):
    cp=classpath(folder)
    with tempfile.TemporaryDirectory(prefix='full-ui-archived-replay-') as name:
        temporary=pathlib.Path(name);classes=temporary/'classes';command(['javac','-sourcepath','','-cp',cp,'-d',str(classes),str(folder/RUNTIME/(HELPER+'.java'))])
        require(all(p.name.startswith(HELPER) for p in classes.rglob('*.class')),'Helper shadows production');report=temporary/'report.json'
        result=subprocess.run(['java','-cp',cp+':'+str(classes),'com.samlscope.runner.cases.'+HELPER,str(folder),str(report)],capture_output=True,timeout=90)
        require(result.returncode==0,'Actual archived reader failed: '+result.stderr.decode(errors='replace')[-2400:]);return READ(report)
def bind_originals(folder):
    excluded={RUNTIME,EVALUATION,'acceptance-originals.json','receipt-installation.json','native-reader-replay.json'}
    files=[p for p in folder.rglob('*') if p.is_file() and p.relative_to(folder).parts[0] not in excluded]
    save(folder/'acceptance-originals.json',dict(files={str(p.relative_to(folder)):SHA(p.read_bytes()) for p in files},oldOriginalsUnchanged=True,counterfactualInstalled=False))
def cumulative_counts(folder):
    """Keep the completed but unadoptable v205 campaign separate from this run."""
    failed=folder.parent/'shibboleth-full-ui-r1';records=[];totals={}
    fields=['initialBaselineSubmissions','initialCredentialSubmissions','configurationWriteAttempts',
        'restorationWrites','metadataReloadAttempts','nativeModelQueries','productRestarts','humanOperations',
        'fullUiTesterLogins','fullUiSamlSubmissions']
    for source,selected in [(failed,False),(folder,True)]:
        count=READ(source/'operation-counts.json');restore=READ(source/'restoration.json');created=READ(source/'created.json')
        require(restore['restored'] is True and restore['originalSha256']==restore['finalSha256'],'Failed-attempt restoration unproven')
        require(all(type(count.get(k)) is int and count[k]>=0 for k in fields),'Invalid attempt costs')
        names=['created.json','operation-counts.json','restoration.json','initial-baseline.json']
        if not selected:names+=['non-adoption-diagnostic.json']
        records.append(dict(folder=source.name,runId=created['run']['id'],selectedForQualification=selected,
            files={name:SHA((source/name).read_bytes()) for name in names},counts={k:count[k] for k in fields}))
        for k in fields:totals[k]=totals.get(k,0)+count[k]
    require(records[0]['runId']!=records[1]['runId'],'Failed-attempt Run reused')
    require(READ(failed/'non-adoption-diagnostic.json')['adopted'] is False,'Invalid failed qualification')
    diagnostics=[]
    for source in [failed/'calibration',folder/'calibration-r1-stdout-log-failed',folder/'calibration']:
        original=source/'operations.json';value=READ(original)
        require(value['productSettings']==value['saml']==value['credentials']==value['personOperations']==0
            and value['controlsAdopted'] is False and value['counterfactualCalibrationOnly'] is True,'Diagnostic operation scope differs')
        diagnostics.append(dict(path=str(original.relative_to(folder.parent)),sha256=SHA(original.read_bytes()),
            runId=value['runId'],nativeCompilations=value['nativeCompilations'],nativeModelExecutions=value['nativeModelExecutions']))
    preflight=folder.parent/'shibboleth-full-ui-preflight-failed-r1'
    preflightProof=READ(preflight/'preflight-failure.json')
    require(preflightProof['productSettingWrites']==preflightProof['productSaml']==preflightProof['credentialSubmissions']==0,'Initial preflight scope differs')
    return dict(schema='samlscope-full-ui-cumulative-costs-v1',records=records,totals=totals,
        modelDiagnostics=diagnostics,totalNativeModelCompilations=sum(x['nativeCompilations'] for x in diagnostics),
        totalNativeModelExecutions=sum(x['nativeModelExecutions'] for x in diagnostics),
        preflightFailure=dict(folder=preflight.name,sha256=SHA((preflight/'preflight-failure.json').read_bytes()),
            createdRunSha256=SHA((preflight/'created.json').read_bytes()),settingWrites=0,saml=0,credentials=0),
        failedRawOriginalsUnchanged=True,costsAdvisory=True)
def verify_originals(folder):
    bindings=READ(folder/'acceptance-originals.json');require(bindings['oldOriginalsUnchanged'] and bindings['counterfactualInstalled'] is False,'Ownership differs')
    for name,digest in bindings['files'].items():
        p=folder/name;require(p.resolve().is_relative_to(folder) and not any(x.is_symlink() for x in [p,*p.parents]) and SHA(p.read_bytes())==digest,'Immutable original changed')
    m=READ(folder/'receipt/manifest.json');run=READ(folder/'created.json')['run']['id'];target=SHA((folder/'target-metadata.xml').read_bytes())
    require(m['schema']=='samlscope-metadata-full-ui-native-v1' and m['runId']==run and m['targetMetadataSha256']==target and m['counterfactualCalibrationOnly'] is False and 'calibration' not in m,'Stock receipt scope differs')
    require(READ(folder/'formal-slot-preflight.json')['scope_ready'] is True and READ(folder/'restoration.json')['restored'] is True,'Native slot/restoration incomplete')
    entries=READ(folder/'transcript.json');require(len({e['id'] for e in entries})==len(entries) and all(e['runId']==run for e in entries),'History scope differs')
    counts=READ(folder/'operation-counts.json');ledger=READ(folder/'operations.json');require(counts['ledger']==ledger and counts['restored'] and counts['configurationWriteAttempts']==sum(x['operation']=='write' for x in ledger) and counts['metadataReloadAttempts']==sum(x['operation']=='reload' for x in ledger),'Attempt costs inconsistent')
    baseline=READ(folder/'initial-baseline.json');require(counts['initialBaselineSubmissions']==baseline['actualSamlAttempts'] and counts['initialCredentialSubmissions']==baseline['credentialSubmissions'] and baseline['exchange']['success'],'M0 expense or normal control unproven')
    require(READ(folder/'cumulative-operation-counts.json')==cumulative_counts(folder),'Failed-attempt costs or restoration changed')
    return m,run,target,entries
def install(folder):
    m,run,target,entries=verify_originals(folder);ev=folder/EVALUATION;ev.mkdir();stored_helpers().capture(folder,RUNTIME,EVALUATION+'/stored-before.json',run,CASE)
    save(ev/'result-before.json',api('/api/runs/'+run+'/result.json'));save(ev/'transcript-before.json',api('/api/runs/'+run+'/transcript'))
    require(READ(ev/'transcript-before.json')==entries,'Transcript changed before placement')
    base='/data/metadata-full-ui-evidence/'+run
    check=subprocess.run(['docker','exec',SUITE,'test','-e',base],capture_output=True,timeout=30);require(check.returncode==1,'Existing receipt ownership')
    command(['docker','exec',SUITE,'mkdir','-p',base]);records=[]
    for name in ['manifest.json',*m['files']]:
        source=folder/'receipt'/name;require(source.resolve().is_relative_to(folder/'receipt') and not source.is_symlink(),'Unsafe installed original')
        destination=base+'/'+name;command(['docker','exec',SUITE,'mkdir','-p',str(pathlib.PurePosixPath(destination).parent)])
        command(['docker','cp',str(source),SUITE+':'+destination])
        # Public copy only: preserve immutable host hardlinks and their original mode.
        command(['docker','exec','--user','0',SUITE,'chmod','0644',destination])
        digest=command(['docker','exec',SUITE,'sha256sum',destination]).stdout.decode().split()[0]
        require(digest==SHA(source.read_bytes()),'Native receipt readback differs');records.append(dict(file=name,path=destination,sha256=digest))
    save(folder/'receipt-installation.json',dict(runId=run,files=records,readBackVerified=True,counterfactualInstalled=False,productSettings=0,saml=0,credentials=0))
def resume_installation(folder):
    """Resume only this byte-identical partial placement, retaining its before snapshot."""
    m,run,target,entries=verify_originals(folder);ev=folder/EVALUATION
    require((ev/'stored-before.json').is_file() and (ev/'result-before.json').is_file()
        and READ(ev/'transcript-before.json')==entries and not (ev/'evaluate.json').exists()
        and not (folder/'receipt-installation.json').exists(),'Partial placement cannot be resumed')
    base='/data/metadata-full-ui-evidence/'+run;allowed=['manifest.json',*m['files']]
    actual=command(['docker','exec','--user','0',SUITE,'find',base,'-type','f']).stdout.decode().splitlines()
    require(base+'/manifest.json' in actual and all(x.startswith(base+'/') and x[len(base)+1:] in allowed for x in actual),'Foreign partial receipt ownership')
    for path in actual:
        require(command(['docker','exec','--user','0',SUITE,'sha256sum',path]).stdout.decode().split()[0]
            ==SHA((folder/'receipt'/path[len(base)+1:]).read_bytes()),'Partial receipt original differs')
    records=[]
    for name in allowed:
        source=folder/'receipt'/name;destination=base+'/'+name
        command(['docker','exec',SUITE,'mkdir','-p',str(pathlib.PurePosixPath(destination).parent)])
        command(['docker','cp',str(source),SUITE+':'+destination]);command(['docker','exec','--user','0',SUITE,'chmod','0644',destination])
        digest=command(['docker','exec',SUITE,'sha256sum',destination]).stdout.decode().split()[0]
        require(digest==SHA(source.read_bytes()),'Resumed receipt readback differs');records.append(dict(file=name,path=destination,sha256=digest))
    save(folder/'receipt-installation.json',dict(runId=run,files=records,readBackVerified=True,counterfactualInstalled=False,
        productSettings=0,saml=0,credentials=0,publicCopyModeNormalized=True,partialPlacementResumed=True,beforeSnapshotsPreserved=True))
def formal_preflight(folder,run):
    ev=folder/EVALUATION;status=api('/api/runs/'+run+'/protocol-evidence');save(ev/'readiness.json',status)
    require(isinstance(status.get('cases'),list),'Suite readiness gap; POST skipped');matches=[c for c in status['cases'] if c.get('caseId')==CASE]
    require(len(matches)<=1,'Ambiguous full UI case; POST skipped')
    if matches:require(matches[0].get('ready') is True,'Native full UI proof unready; POST skipped');return
    result=api('/api/runs/'+run+'/result.json');save(ev/'already-conclusive.json',result)
    require(result['run']['id']==run and rows(result).get(CASE,{}).get('outcome') in ['SATISFIED','VIOLATED'],'No ready/conclusive full UI slot; POST skipped')
def formal(folder):
    ev=folder/EVALUATION;run=READ(folder/'created.json')['run']['id'];require((ev/'stored-before.json').is_file() and not (ev/'evaluate.json').exists(),'Before snapshot missing or formal already executed')
    formal_preflight(folder,run);save(ev/'evaluate.json',api('/api/runs/'+run+'/protocol-evidence/evaluate',{}));save(ev/'result.json',api('/api/runs/'+run+'/result.json'))
    save(ev/'transcript.json',api('/api/runs/'+run+'/transcript'));stored_helpers().capture(folder,RUNTIME,EVALUATION+'/stored-after.json',run,CASE)
def verify_adoption(root,live=False):
    folder=locate(root);m,run,target,entries=verify_originals(folder);report=replay(folder);require(report==READ(folder/'native-reader-replay.json'),'Archived replay changed')
    require(report['outcome']['outcome']=='SATISFIED' and report['outcome']['details']['counterfactual_calibration_only'] is False and len(report['negativeControls'])==22 and set(report['negativeControls'].values())=={'NOT_VERIFIED'} and report['approvedMutant']['outcome']=='VIOLATED' and report['productionMutantOutcome']['outcome']=='NOT_VERIFIED' and all(report['wrapperLifecycle'].values()),'Native whole-case proof/detector incomplete')
    require(report['counterfactualAdopted'] is False and report['settings']==report['saml']==report['credentials']==0,'Replay performed product operation')
    ev=folder/EVALUATION;result=READ(ev/'result.json');case=rows(result)[CASE]
    require(result['run']['id']==run and result['target']['metadata_digest']=='sha256:'+target and READ(ev/'transcript-before.json')==READ(ev/'transcript.json')==entries,'Formal scope/history differs')
    stored=stored_helpers().compare_stored(folder,RUNTIME,CASE,report['outcome'],before_name=EVALUATION+'/stored-before.json',after_name=EVALUATION+'/stored-after.json')
    require((case['outcome'],case['verdict'],case['mode'],case['attested'],case['evidence_class'])==('SATISFIED','PASS','CONFIG',False,'OPERATOR_ASSISTED') and case['evidence']==report['outcome']['evidence'] and case['reason_code']==report['outcome']['reasonCode'] and stored['outboxCount']==0,'Central outcome/provenance differs')
    placement=READ(folder/'receipt-installation.json');require(placement['counterfactualInstalled'] is False and placement['readBackVerified'] and {x['file'] for x in placement['files']}=={'manifest.json',*m['files']},'Stock installation inventory differs')
    for row in placement['files']:require(SHA((folder/'receipt'/row['file']).read_bytes())==row['sha256'],'Installed original changed')
    if live:
        require(command(['docker','exec','samlscope-reference-shibboleth','cat','/opt/reference-idp/conf/metadata-providers.xml']).stdout==(folder/'receipt/original-providers.xml').read_bytes(),'Native provider not restored')
        temporary=READ(folder/'before.json')['temporaryPath'];require(subprocess.run(['docker','exec','samlscope-reference-shibboleth','test','-e',temporary],capture_output=True,timeout=20).returncode==1,'Native temporary source remains')
        require(api('/api/runs/'+run+'/transcript')==entries and rows(api('/api/runs/'+run+'/result.json'))[CASE]==case,'Live result/history differs')
        for row in placement['files']:require(command(['docker','exec',SUITE,'sha256sum',row['path']]).stdout.decode().split()[0]==row['sha256'],'Installed evidence changed')
    return ev/'result.json',{CASE:case}
if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('root',type=pathlib.Path);p.add_argument('--capture-runtime',action='store_true');p.add_argument('--bind-originals',action='store_true');p.add_argument('--record-replay',action='store_true');p.add_argument('--install',action='store_true');p.add_argument('--formal',action='store_true');p.add_argument('--live',action='store_true');a=p.parse_args();folder=locate(a.root)
    if a.capture_runtime:print(capture_runtime(folder))
    if a.bind_originals:bind_originals(folder)
    if a.record_replay:save(folder/'native-reader-replay.json',replay(folder))
    if a.install:install(folder)
    if a.formal:formal(folder)
    if not any([a.capture_runtime,a.bind_originals,a.record_replay,a.install,a.formal]):print(verify_adoption(folder,a.live))
