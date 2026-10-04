#!/usr/bin/env python3
"""Native source-bound semantic identity proof; actual deployed reader replay and formal result."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import urllib.request
import xml.etree.ElementTree as ET
import zipfile

REPO=Path(__file__).resolve().parents[2]
FOLDER='ssp-native-subject-principal-v168-r1'
CASE='IIP-SSO01-cz-idp-01'
SUITE='samlscope-reference-suite'
JARS=('runner','core','saml','store')
CLASSES=('SimpleSamlPhpPrincipalIdentityResolver','SimpleSamlPhpSubjectPrincipalEvidence','NativeSubjectPrincipalTestCase',
    'SamlSubjectPrincipalCase','VerifiedResponseAssertion','ApprovedBrowserCaseRegistry')
HELPER='VerifySspSubjectPrincipalEvidence'
S='{urn:oasis:names:tc:SAML:2.0:assertion}'

def sha(raw):return hashlib.sha256(raw).hexdigest()
def read(path):return json.loads(path.read_bytes())
def require(value,detail):
    if not value:raise ValueError(detail)
def case(result):return next(c for q in result['requirements'] for c in q['cases'] if c['id']==CASE)
def locate(root):
    root=Path(root).resolve();return root if root.name==FOLDER else root/FOLDER

def capture_runtime(folder):
    runtime=folder/'runtime';runtime.mkdir(exist_ok=False);pins=dict(jars={},classes={})
    for name in JARS:
        file=runtime/(name+'.jar');subprocess.run(['docker','cp',SUITE+':/opt/samlscope/lib/'+name+'-0.1.0.jar',str(file)],check=True,capture_output=True)
        pins['jars'][name]=sha(file.read_bytes())
    with zipfile.ZipFile(runtime/'runner.jar') as archive:
        pins['classes']={name:sha(archive.read('com/samlscope/runner/cases/'+name+'.class')) for name in CLASSES}
    source=Path(__file__).with_name(HELPER+'.java').read_bytes();(runtime/(HELPER+'.java')).write_bytes(source)
    pins['helperSha256']=sha(source);pins['suiteImageId']=subprocess.check_output(['docker','inspect','--format','{{.Image}}',SUITE]).decode().strip()
    (runtime/'pins.json').write_text(json.dumps(pins,indent=2)+'\n')

def replay(folder):
    pins=read(folder/'runtime/pins.json');require(set(pins['jars'])==set(JARS),'Archived JAR set differs')
    for name in JARS:require(sha((folder/('runtime/'+name+'.jar')).read_bytes())==pins['jars'][name],'Archived runtime changed')
    require(sha((folder/('runtime/'+HELPER+'.java')).read_bytes())==pins['helperSha256'],'Archived helper changed')
    with zipfile.ZipFile(folder/'runtime/runner.jar') as archive:
        require(pins['classes']=={name:sha(archive.read('com/samlscope/runner/cases/'+name+'.class')) for name in CLASSES},'Archived production classes changed')
    cp=':'.join(str(folder/('runtime/'+n+'.jar')) for n in JARS)+':'+Path('/private/tmp/samlscope-runner-runtime-classpath.txt').read_text().strip()
    with tempfile.TemporaryDirectory(prefix='ssp-subject-principal-replay-') as name:
        temporary=Path(name);classes=temporary/'classes'
        result=subprocess.run(['javac','-sourcepath','','-cp',cp,'-d',str(classes),str(folder/('runtime/'+HELPER+'.java'))],capture_output=True,text=True)
        require(result.returncode==0,'Helper compile failed: '+result.stderr[-1200:])
        require(all(p.name.startswith(HELPER) for p in classes.rglob('*.class')),'Replay shadows a production class')
        result=subprocess.run(['java','-cp',str(classes)+':'+cp,'com.samlscope.runner.cases.'+HELPER,str(folder),str(temporary/'report.json')],capture_output=True,text=True,timeout=60)
        require(result.returncode==0,'Actual production replay failed: '+result.stderr[-1200:]);return read(temporary/'report.json')

def capture_native_producer_replay(folder):
    code=(folder/'native-producer-command.php').read_text();producer=read(folder/'producer.json')
    source=(folder/'decoded'/(producer['baseResponseReference']+'.xml')).read_bytes()
    mappings=read(folder/'before/native-resolution.json')['nativeAuthenticatedPrincipals'];records=[]
    for kind in ['same-principal-different-format','multiple-same-principal-confirmations','different-confirmation-principal','different-attribute-principal']:
        payload=dict(response=source.decode(),kind=kind,uid=mappings[0]['attributes']['uid'][0],otherPersistent=mappings[1]['nameId']['value'])
        result=subprocess.run(['docker','exec','-i','samlscope-reference-ssp','php','-r',code],input=json.dumps(payload).encode(),capture_output=True,timeout=40)
        require(result.returncode==0 and result.stdout==(folder/(kind+'.xml')).read_bytes(),'Native control regeneration differs')
        records.append(dict(kind=kind,sha256=sha(result.stdout),nativeReturncode=result.returncode,bytesIdentical=True))
    file=folder/'independent-native-producer-replay.json';require(not file.exists(),'Refusing native replay replacement')
    file.write_text(json.dumps(dict(commandSha256=sha(code.encode()),controls=records,privateKeyExported=False,
        nativeSignedProducerInvocations=4,productConfigurationWrites=0,protocolSends=0,humanOperations=0),indent=2)+'\n')

def verify(root,live=False):
    folder=locate(root);manifest=read(folder/'receipt-v1/manifest.json');run=read(folder/'created.json')['run']['id']
    require(manifest['runId']==run,'Receipt Run differs')
    for name,digest in manifest['files'].items():require(sha((folder/'receipt-v1'/name).read_bytes())==digest,'Receipt original changed')
    restoration=read(folder/'restoration.json')
    for label in ['hosted','remote','salt','authsource']:
        original=read(folder/(label+'-original-hash.json'));row=restoration[label]
        require(row['restored'] is True and row['bytesEqual'] is True
            and original['sha256']==row['original_sha256']==row['final_sha256']==row['nativeFinalSha256'],'Native restore hash differs')
        if label!='authsource':require((folder/(label+'-original.php')).read_bytes()==(folder/(label+'-final.php')).read_bytes(),'Restored native bytes differ')
    require(not any('authsource' in p.name and p.suffix=='.php' for p in folder.rglob('*')),'Credential-bearing authsource persisted')
    before=read(folder/'before/native-resolution.json');require(before==read(folder/'after/native-resolution.json'),'Native identity mapping changed')
    users=before['authenticationSource']['users'];require(len(users)==2 and all(set(u)=={'principal','attributes'} for u in users),'Native public identity scope differs')
    require(all(set(u['attributes'])=={'uid','eduPersonAffiliation'} and len(u['attributes']['uid'])==1 and u['attributes']['eduPersonAffiliation']==['member'] for u in users),'Native attribute scope differs')
    require(len({u['principal'] for u in users})==len({u['attributes']['uid'][0] for u in users})==2,'Native principals alias a uid')
    entries=read(folder/'transcript.json');require(len(entries)==8 and all(e['runId']==run for e in entries),'Native transcript scope differs')
    by_id={e['id']:e for e in entries};require(len(by_id)==8,'Duplicate transcript')
    for row in read(folder/'decoded-manifest.json'):
        raw=(folder/row['file']).read_bytes();require(row['id'] in by_id and sha(raw)==row['sha256'] and len(raw)==by_id[row['id']]['decodedSamlBytes'],'Original decoded bytes differ')
    require(read(folder/'operation-counts.json')==dict(productConfigurationWriteAttempts=8,configurationApplyWrites=4,restorationWrites=4,
        nativeParserInvocations=1,normalFlowsAttempted=4,nativeSignedProducerInvocations=4,runCreations=1,productRestarts=0,humanOperations=0,restored=True),'Operation counts differ')
    native_replay=read(folder/'independent-native-producer-replay.json');require(native_replay['privateKeyExported'] is False
        and native_replay['nativeSignedProducerInvocations']==4 and len(native_replay['controls'])==4,'Independent native producer controls missing')
    for row in native_replay['controls']:require(row['bytesIdentical'] is True and row['sha256']==sha((folder/(row['kind']+'.xml')).read_bytes()),'Native producer replay changed')
    recorded=read(folder/'production-reader-replay.json');require(replay(folder)==recorded,'Production replay changed')
    require(recorded['outcome']=='SATISFIED' and len(recorded['checks'])==20 and recorded['nativeSignedSemanticControlsVerified']==4
        and recorded['privateKeyExported'] is False and recorded['credentialsPersisted'] is False,'Production controls incomplete')
    evaluation=folder/'evaluation';result=read(evaluation/'result.json');row=case(result)
    require((row['outcome'],row['verdict'],row['reason_code'],row['attested'])==('SATISFIED','PASS','saml.subject-principal.native-resolved',False),'Formal native outcome differs')
    require(result['run']['id']==run and result['target']['metadata_digest']=='sha256:'+sha((folder/'target-metadata.xml').read_bytes()),'Formal Run/target differs')
    require(read(evaluation/'transcript.json')==entries,'Formal evaluation changed transcript')
    require({e['reference'] for e in row['evidence']}=={e['reference'] for e in recorded['evidence']},'Formal evidence refs differ')
    if live:
        for label,path in [('hosted','metadata/saml20-idp-hosted.php'),('remote','metadata/saml20-sp-remote.php'),('salt','config/config-override.php'),('authsource','config/authsources.php')]:
            current=subprocess.check_output(['docker','exec','samlscope-reference-ssp','cat','/var/simplesamlphp/'+path]);require(sha(current)==restoration[label]['nativeFinalSha256'],'Live native restore differs')
        for name,path in [('persistent-filter','modules/saml/src/Auth/Process/PersistentNameID.php'),('base-generator','modules/saml/src/BaseNameIDGenerator.php'),('userpass','modules/exampleauth/src/Auth/Source/UserPass.php'),('xml-signer','vendor/simplesamlphp/saml2-legacy/src/SAML2/Utils.php')]:
            require(subprocess.check_output(['docker','exec','samlscope-reference-ssp','cat','/var/simplesamlphp/'+path])==(folder/('native-'+name+'.php')).read_bytes(),'Native executable source differs')
        for suffix in ['result.json','transcript']:
            with urllib.request.urlopen('http://localhost:18080/api/runs/'+run+'/'+suffix,timeout=30) as response:value=json.load(response)
            require(case(value)==row if suffix=='result.json' else value==entries,'Live formal native proof differs')
    return evaluation/'result.json',{CASE:row}

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('root',type=Path);p.add_argument('--capture-runtime',action='store_true');p.add_argument('--record-replay',action='store_true');p.add_argument('--capture-native-producer-replay',action='store_true');p.add_argument('--live',action='store_true');args=p.parse_args();folder=locate(args.root)
    if args.capture_native_producer_replay:capture_native_producer_replay(folder)
    if args.capture_runtime:capture_runtime(folder)
    if args.record_replay:
        file=folder/'production-reader-replay.json';require(not file.exists(),'Refusing replay replacement');file.write_text(json.dumps(replay(folder),indent=2)+'\n')
    if not any([args.capture_runtime,args.record_replay,args.capture_native_producer_replay]):
        path,rows=verify(args.root,args.live);print(json.dumps(dict(result=str(path),cases={k:v['verdict'] for k,v in rows.items()},verified=True),indent=2))
