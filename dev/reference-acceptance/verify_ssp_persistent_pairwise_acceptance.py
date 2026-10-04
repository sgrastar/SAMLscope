#!/usr/bin/env python3
"""Native two-peer proof, exact restoration, all attempts and immutable production replay."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import urllib.request
import xml.etree.ElementTree as ET
import zipfile

REPO=Path(__file__).resolve().parents[2]
FOLDER='ssp-native-persistent-pairwise-v166-r3'
MUTANT='ssp-native-persistent-pairwise-same-value-mutant-v166-r2'
CASE='IIP-SSO05-a3-idp-01'
SUITE='samlscope-reference-suite'
JARS=('runner','core','saml','store')
CLASSES=('com/samlscope/runner/cases/SimpleSamlPhpPersistentPairwiseEvidence.class',
    'com/samlscope/runner/cases/IdpExecutableBrowserFixtureScenarioTestCase.class',
    'com/samlscope/runner/cases/VerifiedResponseAssertion.class')
HELPER='VerifySspPersistentPairwiseEvidence'
TARGET='http://localhost:18380/idp'
S='{urn:oasis:names:tc:SAML:2.0:assertion}'
P='{urn:oasis:names:tc:SAML:2.0:protocol}'
FORMAT='urn:oasis:names:tc:SAML:2.0:nameid-format:persistent'

def sha(raw):return hashlib.sha256(raw).hexdigest()
def read(path):return json.loads(path.read_bytes())
def require(value,detail):
    if not value:raise ValueError(detail)
def case(result):return next(c for req in result['requirements'] for c in req['cases'] if c['id']==CASE)

def capture_runtime(folder):
    runtime=folder/'runtime';runtime.mkdir(exist_ok=False);pins=dict(jars={},classes={})
    for name in JARS:
        file=runtime/(name+'.jar')
        subprocess.run(['docker','cp',SUITE+':/opt/samlscope/lib/'+name+'-0.1.0.jar',str(file)],check=True,capture_output=True)
        pins['jars'][name]=sha(file.read_bytes())
    with zipfile.ZipFile(runtime/'runner.jar') as archive:pins['classes']={name:sha(archive.read(name)) for name in CLASSES}
    helper=Path(__file__).with_name(HELPER+'.java').read_bytes();(runtime/(HELPER+'.java')).write_bytes(helper);pins['helperSha256']=sha(helper)
    pins['suiteImageId']=subprocess.check_output(['docker','inspect','--format','{{.Image}}',SUITE]).decode().strip()
    (runtime/'pins.json').write_text(json.dumps(pins,indent=2)+'\n')

def replay(folder,mutant):
    pins=read(folder/'runtime/pins.json')
    require(set(pins['jars'])==set(JARS),'Archived runtime JAR set differs')
    for name in JARS:require(sha((folder/('runtime/'+name+'.jar')).read_bytes())==pins['jars'][name],'Runtime JAR changed')
    require(sha((folder/('runtime/'+HELPER+'.java')).read_bytes())==pins['helperSha256'],'Archived helper changed')
    with zipfile.ZipFile(folder/'runtime/runner.jar') as archive:
        require(pins['classes']=={name:sha(archive.read(name)) for name in CLASSES},'Production reader class changed')
    cp=':'.join(str(folder/('runtime/'+name+'.jar')) for name in JARS)+':'+Path('/private/tmp/samlscope-runner-runtime-classpath.txt').read_text().strip()
    with tempfile.TemporaryDirectory(prefix='ssp-persistent-pairwise-replay-') as temporary:
        temporary=Path(temporary);classes=temporary/'classes'
        result=subprocess.run(['javac','-sourcepath','','-cp',cp,'-d',str(classes),str(folder/('runtime/'+HELPER+'.java'))],capture_output=True,text=True)
        require(result.returncode==0,'Replay helper compile failed: '+result.stderr[-1200:])
        require(all(p.name.startswith(HELPER) for p in classes.rglob('*.class')),'Replay shadows a production class')
        result=subprocess.run(['java','-cp',str(classes)+':'+cp,'com.samlscope.runner.cases.'+HELPER,str(folder),str(mutant),str(temporary/'report.json')],capture_output=True,text=True,timeout=60)
        require(result.returncode==0,'Production reader replay failed: '+result.stderr[-1500:])
        return read(temporary/'report.json')

def campaign(folder,mutant=False):
    restoration=read(folder/'restoration.json')
    for label in ['hosted','remote','salt']:
        before=(folder/(label+'-original.php')).read_bytes();after=(folder/(label+'-final.php')).read_bytes()
        require(before==after and restoration[label]['restored'] is True
            and restoration[label]['original_sha256']==restoration[label]['final_sha256']==sha(before),'Native restoration differs')
    counts=read(folder/'operation-counts.json')
    require(counts==dict(productConfigurationWriteAttempts=6,configurationApplyWrites=3,restorationWrites=3,
        nativeParserInvocations=2,normalFlowsAttempted=4,runCreations=2,productRestarts=0,humanOperations=0,restored=True),'Native operation counts differ')
    require(read(folder/'campaign.json')['sameValueMutant'] is mutant,'Producer control identity differs')
    ops=read(folder/'operations.json');require(len(ops)==2 and all(r['status']=='recorded' and r['nativeParserReturncode']==0 and r['normalFlowsAttempted']==2 for r in ops),'Native campaign incomplete')
    remote=(folder/'remote-original.php').read_bytes()+b'\n'+b'\n'.join((folder/label/'parser.stdout').read_bytes() and read(folder/label/'parser.stdout')['php'].encode() for label in ['primary','secondary'])+b'\n'
    require(remote==(folder/'remote-configured.php').read_bytes(),'Native parser configuration derivation differs')
    names=[];uids=[];entities=[]
    for label in ['primary','secondary']:
        member=folder/label;created=read(member/'created.json')['run'];run=created['id'];entity='http://localhost:18080/p/'+created['planId'];entities.append(entity)
        require(read(member/'parser.stdout')['entity_id']==entity and read(member/'parser.stdout')['validate_authnrequest'] is True,'Native SP scope differs')
        metadata=ET.fromstring((member/'fixture.xml').read_bytes());require(metadata.get('entityID')==entity,'Original SP metadata differs')
        entries=read(member/'transcript.json');require(len(entries)==4 and all(e['runId']==run for e in entries),'Original two-flow transcript differs')
        by_id={e['id']:e for e in entries};originals={}
        for row in read(member/'decoded-manifest.json'):
            file=member/row['file'];raw=file.read_bytes();entry=by_id.get(row['id'])
            require(file.resolve().parent==(member/'decoded').resolve() and entry and sha(raw)==row['sha256'] and len(raw)==entry['decodedSamlBytes'],'Decoded original differs')
            originals[row['id']]=raw
        require(set(originals)==set(by_id),'Original manifest incomplete')
        peer_names=[]
        for entry in entries:
            if entry['direction']!='INBOUND':continue
            root=ET.fromstring(originals[entry['id']]);require(root.get('Destination')==entry['url'],'Native Response destination differs')
            assertions=root.findall(S+'Assertion');require(len(assertions)==1,'Native Assertion count differs')
            name=assertions[0].find(S+'Subject/'+S+'NameID');require(name is not None and name.get('Format')==FORMAT and name.get('SPNameQualifier')==entity and name.get('SPProvidedID') is None,'Native persistent qualifiers differ')
            identifying=[v.text for a in assertions[0].findall(S+'AttributeStatement/'+S+'Attribute') if a.get('Name')=='uid' for v in a.findall(S+'AttributeValue')]
            require(len(identifying)==1,'Native identifying uid differs');uids+=identifying;peer_names.append(name.text)
        require(len(peer_names)==2 and len(set(peer_names))==1,'Native within-peer pseudonym changed');names+=peer_names
    require(len(set(entities))==2 and len(set(uids))==1,'Two-peer same-uid precondition differs')
    require(len(set(names))==(1 if mutant else 2),'Actual native producer pairwise behavior differs')
    if mutant:require(set(names)==set(uids),'Native same-value control did not expose identifying uid')
    salt=None;auth=None
    for phase in ['primary-before','primary-after','secondary-before','secondary-after']:
        native=read(folder/phase/'native.json');value=native['saltSha256'];auth_value=native['authenticationSource']['originalSha256']
        require(salt in {None,value} and auth in {None,auth_value},'Native salt/authsource changed between peers');salt=value;auth=auth_value
        require(native['authenticationSource']['class']=='exampleauth:UserPass' and native['authenticationSource']['authproc'] is None,'Principal source differs')
        users=native['authenticationSource']['users'];require(all(set(u)=={'principal','uid'} for u in users),'Credential data persisted in native readback')
        principal_uid=[u['uid'][0] for u in users if len(u['uid'])==1];require(len(principal_uid)==len(users)==len(set(principal_uid)) and set(uids).issubset(set(principal_uid)),'Identifying uid aliases principals')
        for label in ['hosted','remote']:require((folder/phase/(label+'.php')).read_bytes()==(folder/(label+'-configured.php')).read_bytes(),'Native before/after config differed')
    return counts

def verify(root,live=False):
    root=Path(root).resolve();folder=root if root.name==FOLDER else root/FOLDER;mutant=folder.parent/MUTANT
    campaign(folder);campaign(mutant,True)
    recorded=read(folder/'production-reader-replay.json');require(replay(folder,mutant)==recorded,'Archived production replay differs')
    require(recorded['outcome']=='SATISFIED' and recorded['nativeSameValueProducerVerified'] is True
        and len(recorded['checks'])==21 and set(recorded['checks'].values())=={'SATISFIED','NOT_VERIFIED'},'Reader controls incomplete')
    evaluation=folder/'evaluation';result=read(evaluation/'result.json');row=case(result)
    require((row['outcome'],row['verdict'],row['reason_code'],row['attested'])==('SATISFIED','PASS','idp.persistent-pairwise.observed',False),'Formal production result differs')
    run=read(folder/'primary/created.json')['run']['id'];require(result['run']['id']==run
        and result['target']['metadata_digest']=='sha256:'+sha((folder/'primary/target-metadata.xml').read_bytes()),'Formal Run/target differs')
    require(read(evaluation/'transcript.json')==read(folder/'primary/transcript.json'),'Formal evaluation altered native transcript')
    refs={e['reference'] for e in recorded['evidence']};require({e['reference'] for e in row['evidence']}==refs,'Formal evidence references differ')
    if live:
        for label,path in [('hosted','metadata/saml20-idp-hosted.php'),('remote','metadata/saml20-sp-remote.php'),('salt','config/config-override.php')]:
            raw=subprocess.check_output(['docker','exec','samlscope-reference-ssp','cat','/var/simplesamlphp/'+path]);require(raw==(folder/(label+'-final.php')).read_bytes(),'Live native restoration differs')
        code=r'''require '/var/simplesamlphp/lib/_autoload.php';
$auth=\SimpleSAML\Configuration::getConfig('authsources.php')->getArray('example-userpass');
$users=[];foreach($auth['users']??[] as $key=>$attributes){$parts=explode(':',$key,2);if(count($parts)!==2)throw new \RuntimeException('Invalid native user key');$users[]=['principal'=>$parts[0],'uid'=>$attributes['uid']??null];}
echo json_encode(['id'=>'example-userpass','class'=>$auth[0]??null,'users'=>$users,'authproc'=>$auth['authproc']??null,'originalSha256'=>hash_file('sha256','/var/simplesamlphp/config/authsources.php')],JSON_THROW_ON_ERROR);'''
        native=json.loads(subprocess.check_output(['docker','exec','samlscope-reference-ssp','php','-r',code]))
        require(native==read(folder/'primary-before/native.json')['authenticationSource'],'Live unique principal source differs')
        for file,path in [('native-userpass.php','/var/simplesamlphp/modules/exampleauth/src/Auth/Source/UserPass.php'),
            ('native-persistent-filter.php','/var/simplesamlphp/modules/saml/src/Auth/Process/PersistentNameID.php'),
            ('native-base-generator.php','/var/simplesamlphp/modules/saml/src/BaseNameIDGenerator.php')]:
            require(subprocess.check_output(['docker','exec','samlscope-reference-ssp','cat',path])==(folder/file).read_bytes(),'Live native source differs')
        for suffix,filename in [('result.json','result.json'),('transcript','transcript.json')]:
            with urllib.request.urlopen('http://localhost:18080/api/runs/'+run+'/'+suffix,timeout=30) as response:value=json.load(response)
            require((case(value)==row if suffix=='result.json' else value==read(evaluation/filename)),'Live formal result/transcript differs')
    return evaluation/'result.json',{CASE:row}

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('root',type=Path);p.add_argument('--capture-runtime',action='store_true');p.add_argument('--record-replay',action='store_true');p.add_argument('--live',action='store_true');args=p.parse_args()
    folder=args.root if args.root.name==FOLDER else args.root/FOLDER
    if args.capture_runtime:capture_runtime(folder)
    if args.record_replay:
        report=replay(folder,folder.parent/MUTANT);file=folder/'production-reader-replay.json';require(not file.exists(),'Refusing replay replacement');file.write_text(json.dumps(report,indent=2)+'\n')
    if not args.capture_runtime and not args.record_replay:
        path,rows=verify(args.root,args.live);print(json.dumps(dict(result=str(path),cases={k:v['verdict'] for k,v in rows.items()},verified=True),indent=2))
