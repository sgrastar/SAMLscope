#!/usr/bin/env python3
"""Original-backed browser SSO01.ep adoption. Counterfactuals are detector controls only."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile

REPO=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(REPO/'dev/keycloak'))
from import_metadata_batch import api,BASE
CASE='IIP-SSO01-ep-idp-01';SUITE='samlscope-reference-suite';NATIVE='samlscope-reference-ssp'
ARCHIVE='reader-actual';EVALUATION='evaluation-actual';FOLDER='simplesamlphp-version-mismatch-r2'
JARS=('runner','core','saml','store')
HELPERS=('VerifyVersionMismatchEvidence','ReadVersionMismatchStoredConclusions')
SHA=lambda raw:hashlib.sha256(raw).hexdigest()
LOAD=lambda p:json.loads(Path(p).read_bytes())
JAVA=Path('/Library/Java/JavaVirtualMachines/jdk-21.jdk/Contents/Home/bin')
# Filled from the completed deployed runtime before the first native campaign.
PINS={'runner': '5543bb1afb6ce41e98992c8e3b572d9c7580c300d6d8706c72dc70581f79edf4', 'core': '1d6e0020c915f50e78902554c06b61916a3f49e50de78d3bc23c6089d312babe', 'saml': 'd8ea9ebf6048f82ba9773850d8302cca00b19751fa0aac4eca675506c8c737ca', 'store': 'c4482cd06f9290a3592f0fceac2c9ec2d7603ea0557d1edc885e1c3d51bd8ece', 'VerifyVersionMismatchEvidence': '5bd4173d4463fc23df20c282013a5bf039c382a57a6148bfc7b9e462e3362676', 'ReadVersionMismatchStoredConclusions': 'd7f6cf3c10c1c6e5f7d395734b8f830acc10402b65bec26d5e7b1782c666f07e', 'dependencies': 'ea446a2b08f4b37e9156831633364ec516ec9eac1ecff8f639eccede35c6c3d8', 'priority': '929c4343e61f74aecabf87a86b4d8c0fc147cc3d8dc19dacb46661cbad39dbaf'}
NEGATIVE={'duplicate-outbound','missing-normal-control','unknown-delivery','tampered-signed-request','invalid-normal-signature-or-cipher','foreign-manifest-run','foreign-adapter','counterfactual-proof','foreign-target-metadata','foreign-http-request','foreign-http-hash','http-with-response-form','foreign-native-runtime','source-covering-mount'}
DIAGNOSTIC={'version-1-1-satisfied','version-1-1-mutant','nonversion-wrong-code'}
SKIPPER_SHA='1ce00a9b324f97a66b76095b2f63a77a65360891a7a798d1d746ef26e6575ed0'


def require(value,message):
    if not value:raise ValueError(message)


def command(argv,timeout=60):return subprocess.run(argv,check=True,capture_output=True,timeout=timeout)


def safe_read(path,limit=64*1024*1024,allow_empty=False):
    path=Path(path).absolute()
    require(not any(p.is_symlink() for p in (path,*path.parents)) and path.is_file() and (0 if allow_empty else 1)<=path.stat().st_size<=limit,'Unsafe/missing public original')
    return path.read_bytes()


def save(path,value):
    path=Path(path);require(not path.exists() and not path.is_symlink(),'Immutable original already exists')
    path.write_bytes((json.dumps(value,sort_keys=True,indent=2)+'\n').encode())


def locate(root):
    p=Path(root).absolute();require(not any(q.is_symlink() for q in (p,*p.parents)),'Unsafe acceptance root');p=p.resolve()
    return p if (p/'receipt/manifest.json').is_file() else p/FOLDER


def stored():
    path=Path(__file__).with_name('keycloak_registered_signer_stored_outcome.py');spec=importlib.util.spec_from_file_location('version_stored_isolated',path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);module.HELPER=HELPERS[1];return module


def archive(folder,deployment):
    folder=Path(folder);deployment=Path(deployment).resolve();dest=folder/ARCHIVE;dest.mkdir(exist_ok=False)
    source=deployment/'isolated-test-overlay.json';q=LOAD(source);pins={};deps=[]
    for name in JARS:
        file=name+'-0.1.0.jar';raw=safe_read(deployment/'runtime-built'/file)
        actual=command(['docker','exec',SUITE,'sha256sum','/opt/samlscope/lib/'+file]).stdout.decode().split()[0]
        require(SHA(raw)==actual,'Selected archive does not match the actual Suite runtime');(dest/(name+'.jar')).write_bytes(raw);pins[name]=actual
    for name in HELPERS:
        raw=safe_read(Path(__file__).with_name(name+'.java'));(dest/(name+'.java')).write_bytes(raw);pins[name]=SHA(raw)
    excluded={n+'-0.1.0.jar' for n in ('api','core','peer','runner','saml','store','auth')}
    for path,digest in q['dependencySha256'].items():
        p=Path(path)
        if p.parent!=REPO/'api/build/install/samlscope/lib' or p.name in excluded:continue
        require(SHA(safe_read(p))==digest,'Dependency differs from the actual builder');deps.append(dict(path=str(p),name=p.name,sha256=digest))
    require(deps and len({r['name'] for r in deps})==len(deps),'Duplicate dependencies')
    native=command(['docker','exec',SUITE,'sha256sum',*['/opt/samlscope/lib/'+r['name'] for r in deps]]).stdout.decode()
    require({line.split()[1].rsplit('/',1)[-1]:line.split()[0] for line in native.splitlines()}=={r['name']:r['sha256'] for r in deps},'Live dependency bytes changed')
    providers={}
    for row in deps:
        with zipfile.ZipFile(row['path']) as jar:
            for name in jar.namelist():
                if name.endswith('.class') and not name.startswith('META-INF/') and name!='module-info.class':providers.setdefault(name,[]).append(row['name'])
    save(dest/'dependencies.json',deps);save(dest/'classpath-priority.json',dict(projectArchivesFirst=list(JARS),thirdPartyOrder=[r['name'] for r in deps],duplicateClasses={k:v for k,v in providers.items() if len(v)>1},builderInventorySha256=SHA(safe_read(source)),deployedReadbackSha256=SHA(native.encode())))
    pins['dependencies']=SHA(safe_read(dest/'dependencies.json'));pins['priority']=SHA(safe_read(dest/'classpath-priority.json'));save(dest/'pins.json',pins)
    save(dest/'placement.json',dict(independentPhysicalCopies=True,mutableBuildHardlinks=False,actualDeployedBytes=True,productSettings=0,protocolSubmissions=0,credentialPosts=0))
    return pins


def runtime(folder):
    a=folder/ARCHIVE;pins=LOAD(a/'pins.json');require(PINS and pins==PINS,'Actual runtime/helper is not pinned by the adoption verifier')
    for name in JARS:require(SHA(safe_read(a/(name+'.jar')))==pins[name] and (a/(name+'.jar')).stat().st_nlink==1,'Mutable or changed archived JAR')
    for name in HELPERS:require(SHA(safe_read(a/(name+'.java')))==pins[name],'Archived helper changed')
    for name,label in [('dependencies.json','dependencies'),('classpath-priority.json','priority')]:require(SHA(safe_read(a/name))==pins[label],'Classpath proof changed')
    deps=LOAD(a/'dependencies.json');priority=LOAD(a/'classpath-priority.json');require(priority['projectArchivesFirst']==list(JARS) and priority['thirdPartyOrder']==[r['name'] for r in deps],'Classpath priority changed')
    for row in deps:require(Path(row['path']).name==row['name'] and SHA(safe_read(row['path']))==row['sha256'],'Dependency bytes changed')
    return a,deps


def replay_layout(folder,destination):
    receipt=folder/'receipt';m=LOAD(receipt/'manifest.json');run=m['runId'];destination.mkdir()
    for name in ('transcript.json','decoded-manifest.json','suite-metadata.xml','target-metadata.xml'):shutil.copyfile(receipt/name,destination/name)
    shutil.copytree(receipt/'decoded',destination/'decoded')
    native=destination/'version-mismatch-evidence';native.mkdir();(native/(run+'.json')).write_bytes(safe_read(receipt/'manifest.json'));side=native/run;side.mkdir()
    for row in m['files']:shutil.copyfile(receipt/row['file'],side/row['file'])
    for row in m['terminals']:
        entry=next(e for e in LOAD(receipt/'transcript.json') if e['id']==row['browserReference']);path=destination/entry['bodyRef'];path.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(receipt/row['bodyFile'],path)
    for p in destination.rglob('*'):p.chmod(0o755 if p.is_dir() else 0o644)
    destination.chmod(0o755)


def replay(folder):
    a,deps=runtime(folder);run=LOAD(folder/'receipt/manifest.json')['runId'];cp=':'.join(str((a/(n+'.jar')).resolve()) for n in JARS)+':'+':'.join(r['path'] for r in deps)
    with tempfile.TemporaryDirectory(prefix='version-actual-replay-') as name:
        tmp=Path(name);classes=tmp/'classes';classes.mkdir(mode=0o755);command([str(JAVA/'javac'),'-sourcepath','','-cp',cp,'-d',str(classes),str(a/(HELPERS[0]+'.java'))])
        require(all(p.name.startswith(HELPERS[0]) for p in classes.rglob('*.class')),'Helper shadows production classes')
        replay_layout(folder,tmp/'originals');remote='/tmp/'+tmp.name;command(['docker','exec','-u','0',SUITE,'mkdir',remote])
        try:
            command(['docker','cp',str(classes),SUITE+':'+remote+'/classes']);command(['docker','cp',str(tmp/'originals'),SUITE+':'+remote+'/originals'])
            for n in JARS:command(['docker','cp',str(a/(n+'.jar')),SUITE+':'+remote+'/'+n+'.jar'])
            command(['docker','cp',str(folder/'calibration/output.json'),SUITE+':'+remote+'/diagnostic.json']);command(['docker','exec','-u','0',SUITE,'chmod','-R','a+rX',remote])
            remote_cp=':'.join(remote+'/'+n+'.jar' for n in JARS)+':'+remote+'/classes:'+':'.join('/opt/samlscope/lib/'+r['name'] for r in deps)
            result=command(['docker','exec',SUITE,'java','-cp',remote_cp,'com.samlscope.runner.cases.'+HELPERS[0],'/data',remote+'/originals',run,remote+'/diagnostic.json'],timeout=90)
            report=json.loads(result.stdout)
            require(report['codeSources']=={'com.samlscope.runner.cases.IdpVersionMismatchScenarioTestCase':'runner.jar','com.samlscope.runner.cases.VersionMismatchTerminalEvidence':'runner.jar','com.samlscope.core.evaluation.CaseOutcome':'core.jar','com.samlscope.saml.normal.SecureXml':'saml.jar','com.samlscope.store.JsonCodec':'store.jar'},'Reader did not load the actual archived code')
            return report
        finally:command(['docker','exec','-u','0',SUITE,'rm','-rf','--',remote])


def account_native_requests(entries,raw_by,native,skips):
    """Partition every issued request, retaining Suite-only aborts outside target costs."""
    import xml.etree.ElementTree as ET
    from urllib.parse import urlsplit,urlunsplit
    require(entries and len({e['runId'] for e in entries})==1 and re.fullmatch(r'run_[0-9A-HJKMNP-TV-Z]{26}',entries[0]['runId']), 'Mixed/foreign Run operation accounting')
    saml=[e for e in entries if e['direction']=='OUTBOUND' and e.get('samlSummary',{}).get('type')=='AuthnRequest']
    require(len({e['id'] for e in saml})==len(saml),'Duplicate request original')
    observed=set();aborted=set();skip_actions=set()
    for operation in native:
        matched=[e for e in saml if e['method']==operation['method'] and SHA(raw_by[e['id']])==operation['requestSha256']]
        require(len(matched)==1 and matched[0]['id'] not in observed,'Native transport operation is not unique in Recorder originals')
        e=matched[0];xml=ET.fromstring(raw_by[e['id']]);require(xml.get('ID')==operation['requestId'],'Native request ID differs from original XML')
        if operation['method']=='GET':
            p=urlsplit(e['url']);require(urlunsplit((p.scheme,p.netloc,p.path,'',''))==operation['requestUrl'],'Native Redirect endpoint changed')
            require(SHA((e.get('rawQuery') or p.query).encode())==operation['rawQuerySha256'],'Native Redirect query bytes differ from Recorder')
        else:require(e['url']==operation['requestUrl'],'Native POST endpoint changed')
        observed.add(e['id'])
    for skip in skips:
        require(skip['sentToTarget'] is False and skip['prepared'] is True and skip['action']=='prepared-and-skipped-before-target-submission'
                and skip['actionId'] not in skip_actions and skip['caseId']!=CASE,'Unqualified/duplicate selected-case skip')
        skip_actions.add(skip['actionId'])
        matched=[e for e in saml if e.get('correlationId')==skip['actionId']]
        require(len(matched)==1 and matched[0]['id'] not in observed,'Skipped request is ambiguous or was sent to native target')
        e=matched[0];summary=e.get('samlSummary',{})
        require(summary.get('action_id')==skip['actionId'] and summary.get('scenario_case_id')==skip['caseId'],'Skipped original action/case differs')
        aborted.add(e['id'])
    require(observed|aborted=={e['id'] for e in saml},'Unclassified issued request cannot be excluded from target cost')
    return dict(nativeProtocolSubmissions=len(observed),suiteOnlyPreparedAndAborted=len(aborted),allIssuedRequestOriginals=len(saml))


def original_inventory(folder):
    receipt=folder/'receipt';m=LOAD(receipt/'manifest.json');run=m['runId'];require(re.fullmatch(r'run_[0-9A-HJKMNP-TV-Z]{26}',run) and m['caseId']==CASE and m['counterfactualCalibrationOnly'] is False,'Foreign/calibration receipt')
    names=set()
    for row in m['files']:
        require(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,127}',row['file']) and row['file'] not in names,'Unsafe or duplicate native original');names.add(row['file']);raw=safe_read(receipt/row['file'],4*1024*1024);require(SHA(raw)==row['sha256'] and len(raw)==row['size'],'Native original hash/size changed')
    require(m['targetMetadataSha256']==SHA(safe_read(receipt/'target-metadata.xml')),'Target metadata changed')
    entries=LOAD(receipt/'transcript.json');by={e['id']:e for e in entries};require(len(by)==len(entries) and all(e['runId']==run for e in entries),'Mixed or duplicated Run originals')
    decoded=LOAD(receipt/'decoded-manifest.json');seen=set()
    for row in decoded:
        e=by[row['id']];require(row['id'] not in seen and e['decodedSamlRef']=='transcripts/'+run+'/'+row['id']+'.saml.xml' and row['file']=='decoded/'+row['id']+'.xml','Foreign decoded reference');raw=safe_read(receipt/row['file']);require(SHA(raw)==row['sha256'] and len(raw)==e['decodedSamlBytes'],'Recorded bytes changed');seen.add(row['id'])
    require(seen=={e['id'] for e in entries if e.get('decodedSamlRef')},'Decoded originals incomplete')
    raw_by={row['id']:safe_read(receipt/row['file']) for row in decoded}
    native=[*LOAD(folder/'native-protocol-posts.json'),*LOAD(folder/'native-protocol-get-operations.json')]
    require(SHA(safe_read(folder/'prepare-and-skip-source.py'))==SKIPPER_SHA,'Suite-only skipper source is not the qualified implementation')
    accounting=account_native_requests(entries,raw_by,native,LOAD(folder/'suite-only-skips.json'))
    require(accounting['nativeProtocolSubmissions']==4,'Native GET/POST operation accounting is incomplete')
    counts=LOAD(folder/'operation-counts.json');state=LOAD(folder/'restoration.json');require(state['restored'] is True and counts['restored'] is True and counts['selectedProbes']==3 and counts['protocolSubmissions']==4 and counts['initialBaselineSubmissions']==1 and counts['credentialPosts']==1 and counts['personOperations']==0 and counts['productRestarts']==0,'Incomplete or unaccounted native campaign')
    require(safe_read(receipt/'original-configuration.php')==safe_read(receipt/'final-configuration.php') and state['original_sha256']==state['final_sha256']==SHA(safe_read(receipt/'original-configuration.php')),'Exact restoration not proven')
    require(counts['productWrites']==state['configuration_write_attempts']==2 and counts['restorationWrites']==state['restoration_write_attempts']==1,'Native write count differs')
    planned=LOAD(folder/'planned-slot-before-login.json');require(planned['runId']==run and planned['caseId']==CASE and planned['profile']=='browser_sso_idp' and planned['mode']=='BROWSER' and planned['caseStarted'] is False,'Approved actual slot is unproven')
    return m


def calibration(folder):
    """One native grouped signing diagnostic. Stock product messages/config remain untouched."""
    m=original_inventory(folder);run=m['runId'];receipt=folder/'receipt';by={e['id']:e for e in LOAD(receipt/'transcript.json')};probes={p['fixtureId']:p for p in LOAD(folder/'probes.json')};raws={r['id']:safe_read(receipt/r['file']) for r in LOAD(receipt/'decoded-manifest.json')}
    import xml.etree.ElementTree as ET
    peer=ET.fromstring(safe_read(receipt/'suite-metadata.xml'));acs=next(e for e in peer.iter() if e.tag.endswith('}AssertionConsumerService') and e.get('index')=='0').get('Location')
    data=dict(schema='samlscope-version-status-calibration-input-v1',runId=run,controls=[])
    for name,fixture,status in [('version-1-1-satisfied','version-1-1','VersionMismatch'),('version-1-1-mutant','version-1-1','Requester'),('nonversion-wrong-code','invalid-issue-instant','VersionMismatch')]:
        q=probes[fixture];request=ET.fromstring(raws[q['requestReference']]);data['controls'].append(dict(fixtureId=name,requestId=request.get('ID'),destination=acs,issuer=ET.fromstring(safe_read(receipt/'target-metadata.xml')).get('entityID'),status=status))
    output=folder/'calibration';output.mkdir(exist_ok=False);source=REPO/'dev/simplesamlphp/version_mismatch_calibration.php';source_raw=safe_read(source);(output/'source.php').write_bytes(source_raw);save(output/'input.json',data)
    remote='/tmp/version-calibration-'+run;command(['docker','exec','-u','0',NATIVE,'mkdir',remote])
    from datetime import datetime,timezone
    started=datetime.now(timezone.utc).isoformat()
    try:
        command(['docker','cp',str(output/'source.php'),NATIVE+':'+remote+'/producer.php']);r=subprocess.run(['docker','exec','-i',NATIVE,'php',remote+'/producer.php'],input=safe_read(output/'input.json'),capture_output=True,timeout=40)
        (output/'stdout.txt').write_bytes(r.stdout);(output/'stderr.txt').write_bytes(r.stderr);require(r.returncode==0,'Native grouped diagnostic failed; retain attempt')
        value=json.loads(r.stdout);require(value['runId']==run and value['sourceSha256']==SHA(source_raw) and value['nativeUtilsSha256']==SHA(safe_read(receipt/'utils-before.php')) and value['counterfactualCalibrationOnly'] is True and value['controlsAdopted'] is False and value['nativePrivateKeyExported'] is False,'Unsafe diagnostic output');(output/'output.json').write_bytes(r.stdout)
    finally:
        command(['docker','exec','-u','0',NATIVE,'rm','-rf','--',remote]);save(output/'operations.json',dict(nativePhpInvocations=1,startedAt=started,completedAt=datetime.now(timezone.utc).isoformat(),sourceSha256=SHA(source_raw),inputSha256=SHA(safe_read(output/'input.json')),command=['php',remote+'/producer.php'],productSettings=0,protocolSubmissions=0,credentialPosts=0,personOperations=0,counterfactualCalibrationOnly=True,controlsAdopted=False))


def install(folder):
    m=original_inventory(folder);runtime(folder);run=m['runId'];ev=folder/EVALUATION;ev.mkdir(exist_ok=False)
    stored().capture(folder,ARCHIVE,EVALUATION+'/stored-before.json',run,CASE);save(ev/'result-before.json',api('/api/runs/'+run+'/result.json'));save(ev/'transcript-before.json',api('/api/runs/'+run+'/transcript'))
    require(LOAD(ev/'transcript-before.json')==LOAD(folder/'receipt/transcript.json'),'Run transcript changed before installation')
    target='/data/version-mismatch-evidence';side=target+'/'+run;manifest=target+'/'+run+'.json'
    for owned in (manifest,side):
        probe=subprocess.run(['docker','exec',SUITE,'test','-e',owned],capture_output=True,timeout=30);require(probe.returncode==1,'Final proof ownership already exists; no overwrite')
    with tempfile.TemporaryDirectory(prefix='version-install-') as name:
        stage=Path(name);(stage/run).mkdir()
        for row in m['files']:(stage/run/row['file']).write_bytes(safe_read(folder/'receipt'/row['file']));(stage/run/row['file']).chmod(0o644)
        (stage/run).chmod(0o755);(stage/(run+'.json')).write_bytes(safe_read(folder/'receipt/manifest.json'));(stage/(run+'.json')).chmod(0o644)
        command(['docker','exec','-u','0',SUITE,'mkdir','-p',target]);command(['docker','cp',str(stage/run),SUITE+':'+side]);command(['docker','cp',str(stage/(run+'.json')),SUITE+':'+manifest]);command(['docker','exec','-u','0',SUITE,'chmod','0755',target,side])
    installed=[]
    for row in [*m['files'],dict(file='../'+run+'.json',sha256=SHA(safe_read(folder/'receipt/manifest.json')),size=(folder/'receipt/manifest.json').stat().st_size)]:
        p=manifest if row['file'].startswith('../') else side+'/'+row['file'];raw=command(['docker','exec',SUITE,'cat',p]).stdout;require(SHA(raw)==row['sha256'] and len(raw)==row['size'],'Suite-user readback differs');installed.append(dict(path=p,sha256=SHA(raw),size=len(raw)))
    save(folder/'installation.json',dict(runId=run,stockOnly=True,counterfactualInstalled=False,readbackAsSuiteUser=True,publicFiles=installed,productSettings=0,protocolSubmissions=0,credentialPosts=0))


def formal(folder):
    m=original_inventory(folder);run=m['runId'];ev=folder/EVALUATION;require((ev/'stored-before.json').is_file() and (folder/'installation.json').is_file(),'Install/readback and stored-before required');require(not (ev/'result.json').exists(),'Formal evaluation is immutable')
    status=api('/api/runs/'+run+'/protocol-evidence');save(ev/'readiness.json',status);selected=[r for r in status.get('cases',[]) if r.get('caseId')==CASE]
    if selected:
        require(len(selected)==1 and selected[0].get('ready') is True,'Native original proof is not ready; evaluation skipped');save(ev/'evaluate.json',api('/api/runs/'+run+'/protocol-evidence/evaluate',{}))
    save(ev/'result.json',api('/api/runs/'+run+'/result.json'));save(ev/'transcript.json',api('/api/runs/'+run+'/transcript'));stored().capture(folder,ARCHIVE,EVALUATION+'/stored-after.json',run,CASE)


def verify(root,live=False):
    folder=locate(root);m=original_inventory(folder);runtime(folder);run=m['runId'];saved=LOAD(folder/'production-replay.json');actual=replay(folder);require(actual==saved,'Archived actual replay changed')
    require(actual['outcome']['outcome'] in ('SATISFIED','SATISFIED_WITH_NOTE') and set(actual['negativeControls'])==NEGATIVE and all(o['outcome']=='NOT_VERIFIED' for o in actual['negativeControls'].values()),'Actual proof/contamination checks incomplete')
    require(set(actual['diagnosticOnlyControls'])==DIAGNOSTIC and actual['diagnosticOnlyControls']['version-1-1-mutant']['outcome']=='VIOLATED' and actual['diagnosticOnlyControls']['nonversion-wrong-code']['outcome']=='NOT_VERIFIED' and actual['diagnosticOnlyControls']['version-1-1-satisfied']['outcome']==actual['outcome']['outcome'],'Approved negative detector failed')
    ev=folder/EVALUATION;after=stored().compare_stored(folder,ARCHIVE,CASE,actual['outcome'],EVALUATION+'/stored-before.json',EVALUATION+'/stored-after.json');before=LOAD(ev/'stored-before.json')['cases'][CASE];require(before['outboxRows']==after['outboxRows'],'Formal evaluation altered or issued Run actions')
    require(LOAD(ev/'transcript-before.json')==LOAD(ev/'transcript.json')==LOAD(folder/'receipt/transcript.json'),'Formal evaluation altered Run transcript')
    report=LOAD(ev/'result.json');items=[c for r in report['requirements'] for c in r['cases'] if c['id']==CASE];require(len(items)==1,'Actual approved case slot absent/duplicate');item=items[0]
    require(report['run']['id']==run and report['target']['metadata_digest']=='sha256:'+m['targetMetadataSha256'] and item['mode']=='BROWSER' and item['outcome']==actual['outcome']['outcome'] and item['verdict']==after['verdict'] and after['verdict'] in ('PASS','WARNING') and item['attested'] is False and item['evidence_class']=='PROTOCOL_OBSERVED' and item['evidence']==after['outcome']['evidence'] and item['reason_code']==actual['outcome']['reasonCode'],'Formal central/provenance differs')
    installed=LOAD(folder/'installation.json');require(installed['runId']==run and installed['stockOnly'] is True and installed['counterfactualInstalled'] is False and installed['readbackAsSuiteUser'] is True,'Diagnostic proof entered production')
    if live:
        raw=command(['docker','exec',NATIVE,'cat','/var/simplesamlphp/metadata/saml20-sp-remote.php']).stdout;require(raw==safe_read(folder/'receipt/original-configuration.php'),'Live restoration differs')
        require(api('/api/runs/'+run+'/transcript')==LOAD(ev/'transcript.json'),'Live transcript changed')
        require(api('/api/runs/'+run+'/result.json')==report,'Live formal result changed')
    seal=LOAD(folder/'acceptance-originals.json')
    for name,row in seal.items():
        raw=safe_read(folder/name,allow_empty=name=='calibration/stderr.txt');require(SHA(raw)==row['sha256'] and len(raw)==row['size'],'Sealed adoption original changed')
    return folder/EVALUATION/'result.json',{CASE}


def seal(folder):
    rows={str(p.relative_to(folder)):dict(sha256=SHA(safe_read(p,allow_empty=str(p.relative_to(folder))=='calibration/stderr.txt')),size=p.stat().st_size) for p in folder.rglob('*') if p.is_file() and p.name!='acceptance-originals.json'};save(folder/'acceptance-originals.json',rows)


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('root',type=Path);parser.add_argument('--live',action='store_true');parser.add_argument('--action',choices=['archive','calibrate','replay','install','formal','seal','verify'],default='verify');parser.add_argument('--deployment',type=Path)
    args=parser.parse_args();folder=locate(args.root)
    if args.action=='archive':require(args.deployment is not None,'Actual deployment path required');print(json.dumps(archive(folder,args.deployment)));return
    if args.action=='calibrate':calibration(folder);return
    if args.action=='replay':save(folder/'production-replay.json',replay(folder));return
    if args.action=='install':install(folder);return
    if args.action=='formal':formal(folder);return
    if args.action=='seal':seal(folder);return
    path,cases=verify(args.root,args.live);print(json.dumps(dict(status='verified',resultPath=str(path),cases=sorted(cases),productSettings=0,protocolSubmissions=0,credentialPosts=0)))
if __name__=='__main__':main()
