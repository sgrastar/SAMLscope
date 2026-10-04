#!/usr/bin/env python3
"""Same-Run SOAP continuation tooling. Production receipt, archived code and controls stay separate."""
import argparse
import hashlib
import importlib.util
import json
import re
from pathlib import Path
import shutil
import subprocess
import tempfile
import sys
import zipfile

REPO=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(REPO/'dev/keycloak'))
from import_metadata_batch import api
CASE='IIP-IDP17-r-idp-01';FOLDER='shibboleth-soap-slo-continuation-r5';SUITE='samlscope-reference-suite'
ARCHIVE='reader-actual';EVALUATION='evaluation-actual';JARS=('runner','core','saml','store')
HELPERS=('VerifySloSoapContinuationEvidence','ReadSloSoapStoredConclusions','VerifyControlledSoapContinuationEvidence')
JAVA=Path('/Library/Java/JavaVirtualMachines/jdk-21.jdk/Contents/Home/bin')
SHA=lambda b:hashlib.sha256(b).hexdigest()
LOAD=lambda p:json.loads(safe(p))
PINS={'ReadSloSoapStoredConclusions': '4a9d109a77f97fdf755d450a683e5fd7b0f8a56d36d87772fb0621235945c227', 'VerifyControlledSoapContinuationEvidence': '708ee4a0dece1ac123c1ad1a9f45c858d0176e6328ddfc4f95af0f1f8464666e', 'VerifySloSoapContinuationEvidence': '135ca6704a9ff1e9e42dd90abb94fb8e0628e1496a093b154253acdc9aaf68fe', 'core': '1d6e0020c915f50e78902554c06b61916a3f49e50de78d3bc23c6089d312babe', 'dependencies': 'ea446a2b08f4b37e9156831633364ec516ec9eac1ecff8f639eccede35c6c3d8', 'priority': 'dbadd0ccd775cf088a2b9b88a8a483c9d04b68e8e3772717cc9c27f3cc36653a', 'proofContract': 'f884538e0d059a5e516d9e34ccde4f37efcc327a5ec763e40574cea7aa56323a', 'runner': 'ec30dc73e10b0c2478543c4fce9bc9e2691073887b46dcf4fa4242b8c8a22c03', 'saml': 'db9f6e715f87b965020311507b56e9a990d30741d5047e8fab35d85aa1de3ab5', 'store': 'c4482cd06f9290a3592f0fceac2c9ec2d7603ea0557d1edc885e1c3d51bd8ece'}
NEGATIVE={'duplicate-recorded-entry','missing-failure-remaining-response','tampered-failure-remaining-response','missing-all-success-remaining-response','tampered-all-success-remaining-response','foreign-manifest-run','foreign-target-metadata','counterfactual-calibration-not-product','missing-all-success-control'}

def require(value,message):
    if not value:raise ValueError(message)

def command(argv,timeout=60):return subprocess.run(argv,check=True,capture_output=True,timeout=timeout)

def safe(path,empty=False):
    p=Path(path).absolute();require(not any(q.is_symlink() for q in (p,*p.parents)) and p.is_file() and (0 if empty else 1)<=p.stat().st_size<=64*1024*1024,'Unsafe or absent public original');return p.read_bytes()

def relative_original(root,name):
    require(isinstance(name,str) and name and '\\' not in name,'Invalid public original reference')
    path=Path(name);require(not path.is_absolute() and all(p not in ('','.', '..') for p in name.split('/')),'Public original escapes proof directory')
    target=Path(root)/path
    require(not any(p.is_symlink() for p in (target,*target.parents)),'Symbolic public original')
    return target

def manifest(folder):
    m=json.loads(safe(folder/'receipt/manifest.json'))
    require(isinstance(m,dict) and isinstance(m.get('runId'),str) and re.fullmatch(r'run_[0-9A-HJKMNP-TV-Z]{26}',m['runId']) is not None,'Invalid same-Run proof')
    require(isinstance(m.get('files'),dict) and m['files'],'Public original inventory absent')
    for name,digest in m['files'].items():
        relative_original(folder/'receipt',name)
        require(isinstance(digest,str) and re.fullmatch(r'[a-f0-9]{64}',digest) is not None,'Invalid public original hash')
    return m

def save(path,value):
    p=Path(path);require(not p.exists(),'Immutable public output already exists');p.parent.mkdir(parents=True,exist_ok=True);p.write_text(json.dumps(value,sort_keys=True,indent=2)+'\n')

def module(name):
    p=Path(__file__).with_name(name+'.py');s=importlib.util.spec_from_file_location('soap_isolated_'+name,p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m

def archive(folder,deployment):
    """Physical copies only, from one qualified actual runtime and exact ordered dependencies."""
    folder=Path(folder);deployment=Path(deployment).resolve();dest=folder/ARCHIVE;dest.mkdir(exist_ok=False)
    source=deployment/'isolated-test-overlay.json';q=LOAD(source);pins={};deps=[]
    for name in JARS:
        file=name+'-0.1.0.jar';raw=safe(deployment/'runtime-built'/file)
        actual=command(['docker','exec',SUITE,'sha256sum','/opt/samlscope/lib/'+file]).stdout.decode().split()[0]
        require(SHA(raw)==actual,'Selected archive differs from the actual Suite runtime')
        (dest/(name+'.jar')).write_bytes(raw);pins[name]=actual
    for name in HELPERS:
        path=REPO/'dev/slo'/ (name+'.java') if name==HELPERS[2] else Path(__file__).with_name(name+'.java')
        raw=safe(path);(dest/(name+'.java')).write_bytes(raw);pins[name]=SHA(raw)
    contract=safe(Path(__file__).with_name('slo_soap_adoption_proof.py'));(dest/'slo_soap_adoption_proof.py').write_bytes(contract);pins['proofContract']=SHA(contract)
    excluded={n+'-0.1.0.jar' for n in ('api','core','peer','runner','saml','store','auth')}
    for path,digest in q['dependencySha256'].items():
        p=Path(path)
        if p.parent!=REPO/'api/build/install/samlscope/lib' or p.name in excluded:continue
        require(SHA(safe(p))==digest,'Dependency differs from the actual builder');deps.append(dict(path=str(p),name=p.name,sha256=digest))
    require(deps and len({r['name'] for r in deps})==len(deps),'Duplicate dependencies')
    native=command(['docker','exec',SUITE,'sha256sum',*['/opt/samlscope/lib/'+r['name'] for r in deps]]).stdout.decode()
    require({line.split()[1].rsplit('/',1)[-1]:line.split()[0] for line in native.splitlines()}=={r['name']:r['sha256'] for r in deps},'Live dependency bytes changed')
    providers={}
    for row in deps:
        with zipfile.ZipFile(row['path']) as jar:
            for name in jar.namelist():
                if name.endswith('.class') and not name.startswith('META-INF/') and name!='module-info.class':providers.setdefault(name,[]).append(row['name'])
    save(dest/'dependencies.json',deps)
    save(dest/'classpath-priority.json',dict(projectArchivesFirst=list(JARS),thirdPartyOrder=[r['name'] for r in deps],
        duplicateClasses={k:v for k,v in providers.items() if len(v)>1},builderInventorySha256=SHA(safe(source)),deployedReadbackSha256=SHA(native.encode())))
    pins['dependencies']=SHA(safe(dest/'dependencies.json'));pins['priority']=SHA(safe(dest/'classpath-priority.json'));save(dest/'pins.json',pins)
    save(dest/'placement.json',dict(independentPhysicalCopies=True,mutableBuildHardlinks=False,actualDeployedBytes=True,
        productSettings=0,protocolSubmissions=0,credentialPosts=0))
    return pins


def calibration(folder,source):
    """Copy existing public actor capture; no actor execution or product operations."""
    from slo_soap_adoption_proof import validate_invocation
    source=Path(source).resolve();dest=folder/'calibration';require(not dest.exists(),'Immutable calibration already exists')
    invocation=LOAD(source/'invocation.json');baseline=LOAD(source/'baseline/receipt/manifest.json');mutant=LOAD(source/'mutant/receipt/manifest.json')
    validate_invocation(invocation,source,baseline,mutant)
    inventory={}
    for path in source.rglob('*'):
        require(not path.is_symlink(),'Symbolic calibration original')
        if path.is_file():inventory[path.relative_to(source).as_posix()]=SHA(safe(path,True))
    shutil.copytree(source,dest)
    require(all(SHA(safe(relative_original(dest,name),True))==sha for name,sha in inventory.items()),'Copied calibration original differs')
    save(folder/'calibration-placement.json',dict(sourceDirectory=str(source),files=inventory,
        controlsAdopted=False,counterfactualCalibrationOnly=True,additionalActorExecutions=0,
        productSettings=0,protocolSubmissions=0,credentialPosts=0))
    return inventory

def runtime(folder):
    v=module('verify_version_mismatch_acceptance');v.ARCHIVE=ARCHIVE;v.HELPERS=HELPERS;v.PINS=PINS
    archive,deps=v.runtime(folder)
    require(SHA(safe(archive/'slo_soap_adoption_proof.py'))==PINS['proofContract']==SHA(safe(Path(__file__).with_name('slo_soap_adoption_proof.py'))),'Typed adoption predicate changed')
    return archive,deps

def layout(folder,out):
    r=folder/'receipt';m=manifest(folder);run=m['runId'];out.mkdir();
    # Collector keeps immutable protocol exports outside the native receipt. Copy actual
    # bytes; do not reconstruct Transcript JSON or append artificial observations.
    for src,name in [(folder/'transcript-final.json','transcript.json'),(folder/'decoded-manifest.json','decoded-manifest.json'),(r/'target-metadata.xml','target-metadata.xml')]:
        safe(src);shutil.copyfile(src,out/name)
    shutil.copytree(folder/'decoded',out/'decoded');native=out/'slo-soap-continuation-evidence'/run;native.mkdir(parents=True)
    shutil.copyfile(r/'manifest.json',native/'manifest.json')
    for file,digest in m['files'].items():
        source=relative_original(r,file);require(SHA(safe(source,True))==digest,'Native public original SHA mismatch');dest=relative_original(native,file);dest.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(source,dest)
    for p in out.rglob('*'):p.chmod(0o755 if p.is_dir() else 0o644)
    out.chmod(0o755)

def replay(folder):
    a,deps=runtime(folder);m=manifest(folder);run=m['runId'];cp=':'.join(str((a/(n+'.jar')).resolve()) for n in JARS)+':'+':'.join(r['path'] for r in deps)
    with tempfile.TemporaryDirectory(prefix='soap-continuation-archived-') as name:
        tmp=Path(name).resolve();classes=tmp/'classes';classes.mkdir()
        command([str(JAVA/'javac'),'-sourcepath','','-cp',cp,'-d',str(classes),*[str(a/(n+'.java')) for n in (HELPERS[0],HELPERS[2])]])
        require(all(p.name.startswith((HELPERS[0],HELPERS[2])) for p in classes.rglob('*.class')),'Helper shadows production reader')
        layout(folder,tmp/'originals');remote='/tmp/'+tmp.name
        command(['docker','exec','-u','0',SUITE,'mkdir',remote])
        try:
            command(['docker','cp',str(classes),SUITE+':'+remote+'/classes']);command(['docker','cp',str(tmp/'originals'),SUITE+':'+remote+'/originals'])
            for n in JARS:command(['docker','cp',str(a/(n+'.jar')),SUITE+':'+remote+'/'+n+'.jar'])
            require((folder/'calibration/invocation.json').is_file(),'Approved paired actor capture is unavailable')
            command(['docker','cp',str(folder/'calibration'),SUITE+':'+remote+'/calibration'])
            command(['docker','exec','-u','0',SUITE,'chmod','-R','a+rX',remote])
            remote_cp=':'.join(remote+'/'+n+'.jar' for n in JARS)+':'+remote+'/classes:'+':'.join('/opt/samlscope/lib/'+r['name'] for r in deps)
            value=json.loads(command(['docker','exec',SUITE,'java','-cp',remote_cp,'com.samlscope.runner.cases.'+HELPERS[0],'/data',remote+'/originals',run],90).stdout)
            require(value['readOnly'] is True and value['outboundActions']==0 and value['privateKeyExported'] is False
                and set(value['negativeControls'])==NEGATIVE and all(v['outcome']=='NOT_VERIFIED' for v in value['negativeControls'].values()),'Reader controls or operation boundary failed')
            reports={}
            for mode in ('baseline','mutant'):
                reports[mode]=json.loads(command(['docker','exec',SUITE,'java','-cp',remote_cp,
                    'com.samlscope.runner.cases.'+HELPERS[2],remote+'/calibration/'+mode],90).stdout)
                require(reports[mode]['fullWrapperLifecycleChecked'] is True and reports[mode]['sameProductionPredicate'] is True
                    and reports[mode]['classBindings']==value['classBindings'],'Control used another whole-case Reader or wrapper')
                reports[mode]['manifestOriginal']['file']=mode+'/'+reports[mode]['manifestOriginal']['file']
            control=reports['mutant'];control.update(schema='samlscope-soap-continuation-approved-control-v1',
                approvedVariantId='IIP-IDP17.r#v-2cdca3181d',mutantId='mut-iip-idp17-r-idp',
                nativeAssociation=dict(runId=run,targetMetadataSha256=m['targetMetadataSha256'],manifestSha256=SHA(safe(folder/'receipt/manifest.json'))),
                counterfactualCalibrationOnly=True,controlsAdopted=False,normalControl=reports['baseline'],
                invocationOriginal=dict(file='invocation.json',sha256=SHA(safe(folder/'calibration/invocation.json'))))
            actor=LOAD(folder/'calibration/mutant/receipt/manifest.json');failure=next(t for t in actor['trials'] if t['trial']=='failure')
            for key,file in [('sourceOriginal',actor['producerSourceFile']),('classesOriginal',actor['producerClassesFile']),
                    ('inputOriginal',failure['operationInputFile']),('outputOriginal',failure['operationOutputFile']),('operationOriginal',failure['operationTraceFile'])]:
                control[key]=dict(file=file,sha256=actor['files'][file])
            value['approvedNegativeControl']=control
            return value
        finally:command(['docker','exec','-u','0',SUITE,'rm','-rf','--',remote])

def stored():
    m=module('keycloak_registered_signer_stored_outcome');m.HELPER=HELPERS[1];return m

def stored_before(folder):
    run=manifest(folder)['runId'];e=folder/EVALUATION;e.mkdir(exist_ok=True)
    value=stored().capture(folder,ARCHIVE,EVALUATION+'/stored-before.json',run,CASE)
    save(e/'transcript-before.json',api('/api/runs/'+run+'/transcript'));save(e/'result-before.json',api('/api/runs/'+run+'/result.json'));return value

def require_approved_negative(folder):
    from slo_soap_adoption_proof import FullCaseAdoptionProof
    report=replay(folder)
    return FullCaseAdoptionProof.validate(fresh_report=report,saved_report=LOAD(folder/ARCHIVE/'production-replay.json'),
        archive=folder/ARCHIVE,pins=PINS,positive_manifest=manifest(folder),positive_root=folder/'receipt',
        calibration_root=folder/'calibration')

def install(folder):
    require_approved_negative(folder)
    from slo_soap_adoption_proof import stock_native_manifest
    r=folder/'receipt';m=manifest(folder);stock_native_manifest(m);run=m['runId'];files={'manifest.json':SHA(safe(r/'manifest.json')) ,**m['files']};remote='/data/slo-soap-continuation-evidence/'+run
    command(['docker','exec','-u','0',SUITE,'sh','-c','test ! -e "$1"', 'test-proof',remote])
    with tempfile.TemporaryDirectory(prefix='soap-continuation-install-') as name:
        stage=Path(name).resolve()/run;stage.mkdir()
        for file,digest in files.items():
            src=relative_original(r,file);raw=safe(src,True);require(SHA(raw)==digest,'Proof original changed before install');dst=relative_original(stage,file);dst.parent.mkdir(parents=True,exist_ok=True);dst.write_bytes(raw);dst.chmod(0o644)
        for p in stage.rglob('*'):
            if p.is_dir():p.chmod(0o755)
        stage.chmod(0o755);command(['docker','exec','-u','0',SUITE,'mkdir','-p','/data/slo-soap-continuation-evidence']);command(['docker','cp',str(stage),SUITE+':'+remote])
        for file,digest in files.items():require(SHA(command(['docker','exec',SUITE,'cat',remote+'/'+file]).stdout)==digest,'Suite user cannot read installed proof exactly')
    save(folder/'receipt-installation.json',dict(runId=run,files=files,readBackMatched=True,publicFilesOnly=True,originalModesUnchanged=True));return files

def formal(folder):
    require_approved_negative(folder)
    installed=LOAD(folder/'receipt-installation.json');require(installed.get('readBackMatched') is True and installed.get('publicFilesOnly') is True,'Stock originals have not been installed and read back')
    run=LOAD(folder/'receipt/manifest.json')['runId'];require(installed.get('runId')==run,'Installation belongs to another Run');require((folder/EVALUATION/'stored-before.json').is_file(),'Stored-before must precede installation/formal evaluation');save(folder/EVALUATION/'protocol-evaluation.json',api('/api/runs/'+run+'/protocol-evidence/evaluate',{}));save(folder/EVALUATION/'result.json',api('/api/runs/'+run+'/result.json'));save(folder/EVALUATION/'transcript.json',api('/api/runs/'+run+'/transcript'));return stored().capture(folder,ARCHIVE,EVALUATION+'/stored-after.json',run,CASE)

def live_restoration(folder):
    m=manifest(folder);r=folder/'receipt';native='samlscope-reference-shibboleth'
    runtime_json=json.loads(command(['docker','inspect',native,'--format',
        '{"id":{{json .Id}},"image":{{json .Image}},"startedAt":{{json .State.StartedAt}},"running":{{json .State.Running}},"mounts":{{json .Mounts}}}']).stdout)
    require(runtime_json['running'] is True,'Native product is not running')
    def mounts(rows):
        require(isinstance(rows,list) and all(isinstance(row,dict) and isinstance(row.get('Destination'),str) for row in rows),'Native mount original is malformed')
        require(len({row['Destination'] for row in rows})==len(rows),'Ambiguous native mount destinations')
        return sorted(rows,key=lambda row:row['Destination'])
    for trial in m['trials']:
        for phase in ('beforeFile','afterFile'):
            state=LOAD(relative_original(r,trial[phase]))['runtime']
            require(state['id']==runtime_json['id'] and state['image']==runtime_json['image']
                and mounts(state['mounts'])==mounts(runtime_json['mounts']),'Current native product identity or mounted bytes changed')
    paths={'target-metadata':'/opt/reference-idp/metadata/idp-metadata.xml',
           'providers':'/opt/reference-idp/conf/metadata-providers.xml','audit':'/opt/reference-idp/conf/audit.xml',
           'global':'/opt/reference-idp/conf/global.xml','services':'/opt/reference-idp/conf/services.xml',
           'relying-party':'/opt/reference-idp/conf/relying-party.xml'}
    for label,path in paths.items():
        original=safe(r/('original-'+label+'.xml'))
        require(original==safe(r/('final-'+label+'.xml'))==command(['docker','exec',native,'cat',path]).stdout,
            'Native restoration no longer matches its original')
    owned='/opt/reference-idp/metadata/registered-signer-'+m['runId']+'.xml'
    absent=subprocess.run(['docker','exec',native,'test','-e',owned],capture_output=True,timeout=30)
    require(absent.returncode==1 and absent.stdout==b'','Temporary native campaign source remains or cannot be read')
    return {'readOnly':True,'nativeIdentityMatched':True,'originalSettingsMatched':True,'temporarySourceAbsent':True,
            'productSettings':0,'protocolSubmissions':0,'credentialPosts':0}

def verify(root,live=False):
    folder=Path(root);folder=folder if (folder/'receipt/manifest.json').exists() else folder/FOLDER;require_approved_negative(folder);m=manifest(folder);run=m['runId'];report=LOAD(folder/ARCHIVE/'production-replay.json');require(report['outcome']['outcome']=='SATISFIED','Native whole-case outcome is incomplete');result=LOAD(folder/EVALUATION/'result.json');require(result['run']['id']==run and result['profile']['id']=='single-logout-idp' and result['target']['metadata_digest']=='sha256:'+m['targetMetadataSha256'],'Case profile, Run or fixed target changed')
    from verify_terminal_http_acceptance import find_case
    case=find_case(result,CASE);require(case['attested'] is False and case['mode']=='BROWSER' and case['evidence_class']=='OPERATOR_ASSISTED' and case['outcome']=='SATISFIED' and case['verdict']=='PASS','Central result differs');require(LOAD(folder/EVALUATION/'transcript-before.json')==LOAD(folder/EVALUATION/'transcript.json')==LOAD(folder/'transcript-final.json'),'Formal evaluation changed transcript');before=stored().verify(folder,ARCHIVE,EVALUATION+'/stored-before.json',run,CASE);after=stored().compare_stored(folder,ARCHIVE,CASE,report['outcome'],EVALUATION+'/stored-before.json',EVALUATION+'/stored-after.json');require(before['outboxRows']==after['outboxRows'],'Formal evaluation modified any Run request');require(case['evidence']==after['outcome']['evidence'] and case['reason_code']==after['outcome']['reasonCode'],'Formal evidence provenance differs');require(LOAD(folder/'receipt/restoration.json')['restored'] is True,'Native restoration is unproven')
    if live:live_restoration(folder)
    return folder/EVALUATION/'result.json',{CASE}

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('folder',type=Path);p.add_argument('--mode',choices=['archive','calibration','replay','before','install','formal','verify'],required=True);p.add_argument('--deployment',type=Path);p.add_argument('--calibration-root',type=Path);p.add_argument('--live',action='store_true');a=p.parse_args()
    global PINS
    if a.mode=='archive':require(a.deployment is not None,'Actual deployment required');v=archive(a.folder,a.deployment)
    elif a.mode=='calibration':require(a.calibration_root is not None,'Existing actor capture required');v=calibration(a.folder,a.calibration_root)
    else:
        require(PINS is not None,'Verifier runtime pin must be frozen before execution')
        if a.mode=='replay':v=replay(a.folder);save(a.folder/ARCHIVE/'production-replay.json',v)
        elif a.mode=='before':v=stored_before(a.folder)
        elif a.mode=='install':v=install(a.folder)
        elif a.mode=='formal':v=formal(a.folder)
        else:v=verify(a.folder,live=a.live)
    print(json.dumps({'mode':a.mode,'completed':True,'result':str(v[0]) if a.mode=='verify' else None}))
if __name__=='__main__':main()
