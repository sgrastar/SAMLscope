#!/usr/bin/env python3
"""Complete SSP retained-expiry adoption from immutable native originals and actual deployed code."""
import argparse,hashlib,json,subprocess,tempfile,urllib.request,zipfile
from pathlib import Path
from verify_shibboleth_native_ui_acceptance import dependency_classpath
from verify_terminal_http_acceptance import find_case

REPO=Path(__file__).resolve().parents[2];FOLDER='simplesamlphp-metadata-validity-r2';CASE='IIP-MD05-ar-idp-01'
RUNTIME='reader-v193';EVALUATION='evaluation-v193';JARS=('runner','core','saml','store')
HELPER='VerifySimpleSamlPhpMetadataValidity';STORED='ReadSimpleSamlPhpMetadataValidityStoredConclusion'
CLASSES=('SimpleSamlPhpMetadataValidityEvidence','MetadataValidityConfigurationTestCase','ApprovedConfigCaseRegistry')
PINS={'jars': {'runner': '5f6e92d264804680112ba17952876abfe330fc67bdbab475c7a676a8df91f548', 'core': '1d6e0020c915f50e78902554c06b61916a3f49e50de78d3bc23c6089d312babe', 'saml': 'd5dd36a15d7df8c164d406de5ebac9d180e371061a36ad31e3184dc56964cdb7', 'store': 'c4482cd06f9290a3592f0fceac2c9ec2d7603ea0557d1edc885e1c3d51bd8ece'}, 'classes': {'SimpleSamlPhpMetadataValidityEvidence': '71a1c29489b8006c67b127699945bf1bc37925c97dbee21689f7270fa3e0816b', 'MetadataValidityConfigurationTestCase': '02b24056a8f7d8ce4fae7430d3bcc48315091e98a4ff0e0db0e3b35d78153f53', 'ApprovedConfigCaseRegistry': '4f525772f16fe421608c778b06a8ca59d26294d373a398b726efd040f830a67a'}, 'VerifySimpleSamlPhpMetadataValiditySha256': 'a993d78ec1ce59d18b085b957e8cf99c2b8ba9f23592c32426154b7ce13abe80', 'ReadSimpleSamlPhpMetadataValidityStoredConclusionSha256': 'feb3771899351efa05344e9a9beb627d3be90e88f2d4d8a6d370775bd126351e', 'suiteImageId': 'sha256:b446b37ddf0884b10dee188abf64aa32c4400223859ec99e72941289381081b4'}
ORIGINALS={'receipt/manifest.json': 'cfb9ddf5cece049a11fff24f5edb7bab737b8af97c19b5fe493e319e2191cbd6', 'transcript.json': '0e4ce5be589896e8aead869dd81b1cff85ea0bf7770b9c45d47890db76f5b671', 'target-metadata.xml': 'fbe069ca8b0e1a28cba80039de40be8d88e18499ad04e1e07658467170e87685', 'created.json': 'ef228c21dc6417d77e33ab5baee6057bbf408a794dc30d30b27560f16d9743ff', 'plan.json': '01f34aa884b69b0eb60d1ae53241051a7d9c04d7de6b93f49e994c57b6bcfb81', 'decoded-manifest.json': 'e43252a1947c01f5e418bde032f442cc92ee1ee7601d0346277b3fea0a2bbe3d'}
CALIBRATION_ORIGINALS={'calibration-completion.json': '27bf1fe9a79aa078203ee6a9b43399819d03481637c9bc4fe204c15c7c37bf70', 'calibration/native-signer-source-readback.json': '5880f9a86661ced2d433f0511404b0fae10eda01e38264e51721a33f8f060512', 'calibration/calibration.json': '8bdfb0da5eafd2628a43b0d9fc1536470f1441decbf3f42fd9c9567e8104cd0f', 'calibration/producer.php': 'b737f6d50ac5321c758f93426b9b89f68280fca93fdb7accfcc46ee356e7ca0f', 'calibration/earlier-parent-expiry-ignore.xml': '39a8251d7052d250a74ba86e15e923edd534fcedea140c1b5473993ecf74a63d', 'calibration/native-saml2-utils.php': '5845e28158c7641d5ce1e6b9205e8005b6d9c090e1888ea46416abb8fdf0018d', 'calibration/native-xml-security-key.php': '6c89ac116aca2c05791712749450be474218fd97cd9a66b7aad9d2ba4e6cba17', 'calibration/native-xml-security-dsig.php': '79597160c501fbdbe19bdca12b6797c06c38c4eae7cad6d0d1dca89301a5734f', 'calibration-initial-issueinstant/calibration.json': '90aac12d1002e49018994642cd28d4b8116254149ca869bc403b4d7dd61ea3b3'}
CONTROLS={'wrong-run','wrong-target','wrong-adapter','wrong-case','wrong-campaign','wrong-peer','wrong-profile','missing-original','symlink-original','native-source-changed','native-after-changed','not-restored','restore-differs','retained-expire-changed','expired-not-crossed','expiry-error-unrelated','unrelated-http-body-recomputed-hash','foreign-request-hash','native-policy-signature-disabled','condition-missing','response-reference-changed','cost-underreported','duplicate-history','foreign-history','native-http-outside-readback-window','signature-control-after-normal','foreign-decoded-reference','calibration-signature-invalid'}
sha=lambda b:hashlib.sha256(b).hexdigest()
read=lambda p:json.loads(Path(p).read_bytes())
def require(value,message):
    if not value:raise ValueError(message)
def locate(root):
    root=Path(root).resolve();return root if root.name==FOLDER else root/FOLDER
def command(args):return subprocess.run(args,check=True,capture_output=True,timeout=90)
def capture_runtime(folder):
    archive=folder/RUNTIME;archive.mkdir(exist_ok=False);pins=dict(jars={},classes={})
    for name in JARS:
        file=archive/(name+'.jar');command(['docker','cp','samlscope-reference-suite:/opt/samlscope/lib/'+name+'-0.1.0.jar',str(file)]);pins['jars'][name]=sha(file.read_bytes())
    with zipfile.ZipFile(archive/'runner.jar') as z:pins['classes']={n:sha(z.read('com/samlscope/runner/cases/'+n+'.class')) for n in CLASSES}
    for name in [HELPER,STORED]:
        raw=Path(__file__).with_name(name+'.java').read_bytes();(archive/(name+'.java')).write_bytes(raw);pins[name+'Sha256']=sha(raw)
    pins['suiteImageId']=command(['docker','inspect','--format','{{.Image}}','samlscope-reference-suite']).stdout.decode().strip()
    (archive/'pins.json').write_text(json.dumps(pins,indent=2)+'\n');dependency_classpath(archive,True)
def runtime(folder):
    archive=folder/RUNTIME;actual=read(archive/'pins.json');require(PINS is not None and actual==PINS,'Actual deployed validity pins not finalized or changed')
    for name in JARS:require(sha((archive/(name+'.jar')).read_bytes())==PINS['jars'][name],'Archived production JAR changed')
    with zipfile.ZipFile(archive/'runner.jar') as z:require(actual['classes']=={n:sha(z.read('com/samlscope/runner/cases/'+n+'.class')) for n in CLASSES},'Archived operative Reader/wrapper changed')
    for name in [HELPER,STORED]:require(sha((archive/(name+'.java')).read_bytes())==PINS[name+'Sha256'],'Archived helper changed')
    return ':'.join(str((archive/(n+'.jar')).resolve()) for n in JARS)+':'+dependency_classpath(archive)
def compiled(folder,name,operation):
    cp=runtime(folder)
    with tempfile.TemporaryDirectory(prefix='ssp-validity-replay-') as directory:
        temp=Path(directory);classes=temp/'classes';command(['javac','-sourcepath','','-cp',cp,'-d',str(classes),str(folder/RUNTIME/(name+'.java'))]);require(all(p.name.startswith(name) for p in classes.rglob('*.class')),'Replay helper shadows production Reader')
        return operation(cp,classes,temp)
def replay(folder,retain=False):
    def execute(cp,classes,temp):
        result=subprocess.run(['java','-cp',cp+':'+str(classes),'com.samlscope.runner.cases.'+HELPER,str(folder),str(temp/'report.json')],capture_output=True,timeout=90)
        require(result.returncode==0,'Archived actual production replay failed: '+result.stderr.decode(errors='replace')[-1000:]);return read(temp/'report.json')
    value=compiled(folder,HELPER,execute);saved=folder/RUNTIME/'production-replay.json'
    if retain:require(not saved.exists(),'Production replay original immutable');saved.write_text(json.dumps(value,indent=2)+'\n')
    else:require(value==read(saved),'Actual archived Reader replay differs')
    require(value['production_outcome']['outcome']=='SATISFIED' and value['production_outcome']['reasonCode']=='metadata.validity.expiration-observed','Retained-expiry original outcome differs')
    require({k:v for k,v in value['controls'].items() if k in CONTROLS}==dict.fromkeys(CONTROLS,'NOT_VERIFIED') and set(value['controls'])==CONTROLS|{'native-signed-earlier-parent-expiry-ignore'} and value['controls']['native-signed-earlier-parent-expiry-ignore']=='VIOLATED','Invalid originals or approved expiry-ignore mutant accepted')
    require(value['wrapperLifecycle']==dict(start=True,ConfigConfirmed=True,TranscriptReady=True,Aborted=True,TimedOut=True,**{'status-ready':True,'recorded-not-verified':True,'recorded-conclusive':False,'incomplete-history':'NOT_VERIFIED'}) and value['privateMaterialExported'] is False,'Shared native lifecycle or privacy changed');return value
def stored(folder,label,capture=False):
    file=folder/EVALUATION/('stored-'+label+'.json');run=read(folder/'created.json')['run']['id']
    def execute(cp,classes,temp):
        if capture:
            require(not file.exists(),'Stored public conclusion immutable');remote='/tmp/'+temp.name;command(['docker','exec','samlscope-reference-suite','mkdir',remote])
            try:
                command(['docker','cp',str(classes),'samlscope-reference-suite:'+remote+'/classes']);raw=command(['docker','exec','samlscope-reference-suite','java','-cp',remote+'/classes:/opt/samlscope/lib/*','com.samlscope.runner.cases.'+STORED,'capture',run]).stdout;file.write_bytes(raw)
            finally:command(['docker','exec','-u','0','samlscope-reference-suite','rm','-rf',remote])
        raw=command(['java','-cp',cp+':'+str(classes),'com.samlscope.runner.cases.'+STORED,'offline',str(file)]).stdout;require(raw==file.read_bytes(),'Stored original differs from archived central Evaluator');return json.loads(raw)
    return compiled(folder,STORED,execute)
def install(folder):
    capture_before(folder)
    receipt=folder/'receipt';run=read(receipt/'manifest.json')['runId'];destination='/data/simplesamlphp-metadata-validity-evidence/'+run
    require(not (folder/'receipt-installation-v193.json').exists(),'Receipt installation audit immutable');command(['docker','exec','samlscope-reference-suite','mkdir','-p','/data/simplesamlphp-metadata-validity-evidence']);exists=subprocess.run(['docker','exec','samlscope-reference-suite','test','-e',destination],capture_output=True,timeout=90);require(exists.returncode==1,'Refusing to replace preexisting native receipt');command(['docker','cp',str(receipt),'samlscope-reference-suite:'+destination]);uid=command(['docker','exec','samlscope-reference-suite','id','-u']).stdout.decode().strip();command(['docker','exec','-u','0','samlscope-reference-suite','chown','-R',uid+':'+uid,destination]);records={}
    for file in receipt.iterdir():
        raw=command(['docker','exec','samlscope-reference-suite','cat',destination+'/'+file.name]).stdout;require(raw==file.read_bytes(),'Placed native original readback differs');records[file.name]=sha(raw)
    (folder/'receipt-installation-v193.json').write_text(json.dumps(dict(runId=run,path=destination,readBackVerified=True,records=records),indent=2)+'\n')
def api(run,suffix,data=None):
    body=None if data is None else json.dumps(data).encode();request=urllib.request.Request('http://localhost:18080/api/runs/'+run+'/'+suffix,data=body,headers={} if body is None else {'Content-Type':'application/json'})
    with urllib.request.urlopen(request,timeout=60) as response:return json.load(response)
def capture_before(folder):
    evaluation=folder/EVALUATION
    if evaluation.exists():
        require((evaluation/'stored-before.json').exists() and not (evaluation/'evaluate.json').exists(),'Formal lifecycle original already complete or incomplete');return
    evaluation.mkdir(exist_ok=False);run=read(folder/'created.json')['run']['id'];stored(folder,'before',True)
    for name,suffix in [('result-before.json','result.json'),('transcript-before.json','transcript')]: (evaluation/name).write_text(json.dumps(api(run,suffix),indent=2)+'\n')
def formal(folder):
    capture_before(folder);evaluation=folder/EVALUATION;run=read(folder/'created.json')['run']['id']
    (evaluation/'evaluate.json').write_text(json.dumps(api(run,'protocol-evidence/evaluate',{}),indent=2)+'\n')
    for name,suffix in [('result.json','result.json'),('transcript.json','transcript')]: (evaluation/name).write_text(json.dumps(api(run,suffix),indent=2)+'\n')
    stored(folder,'after',True)
def verify_adoption(root,live=False):
    folder=locate(root);require(all(sha((folder/name).read_bytes())==digest for name,digest in ORIGINALS.items()),'Accepted original corpus changed');receipt=folder/'receipt';manifest=read(receipt/'manifest.json');run=read(folder/'created.json')['run']['id'];report=replay(folder)
    require(run==manifest['runId']==report['runId'] and report['manifestSha256']==sha((receipt/'manifest.json').read_bytes()) and report['transcriptSha256']==sha((folder/'transcript.json').read_bytes()),'Original Run/receipt/transcript binding differs')
    require(set(manifest['originals'])=={p.name for p in receipt.iterdir() if p.name!='manifest.json'},'Native original inventory differs')
    for name,digest in manifest['originals'].items():require(sha((receipt/name).read_bytes())==digest,'Native original hash changed')
    original=(receipt/'original-configuration.php').read_bytes();require(original==(receipt/'final-configuration.php').read_bytes() and read(receipt/'restoration.json')['restored'] is True,'Expiry native restoration differs')
    recovery=folder/'baseline-recovery';require((recovery/'original-configuration.php').read_bytes()==(recovery/'final-configuration.php').read_bytes() and read(recovery/'restoration.json')['restored'] is True,'Initial baseline native restoration differs')
    audit=read(folder/'qualification-audit.json');require(audit['cumulative']==dict(protocolSubmissions=8,credentialPosts=2,productConfigurationWrites=6,restorationWrites=2,personOperations=0,productRestarts=0,restored=True) and audit['expiryPairsRepeated']==0 and audit['baselineProtocolCorrection']['originalCountsChanged'] is False,'All attempts/user effort not conserved')
    entries=read(folder/'transcript.json');by_id={e['id']:e for e in entries};require(len(by_id)==len(entries) and all(e['runId']==run for e in entries),'Foreign/duplicate history')
    corrected=audit['baselineProtocolCorrection'];rq=by_id[corrected['requestReference']];response=by_id[corrected['responseReference']];require(rq['direction']=='OUTBOUND' and rq['method']=='GET' and rq['samlSummary']['type']=='AuthnRequest' and response['direction']=='INBOUND' and response['samlSummary']['type']=='Response' and response['samlSummary']['inResponseTo']==rq['samlSummary']['id'] and response['samlSummary']['normalFlowAccepted'] is True,'Corrected baseline protocol operation not original')
    require(all(sha((folder/name).read_bytes())==digest for name,digest in CALIBRATION_ORIGINALS.items()),'Native calibration/source original changed');completion=read(folder/'calibration-completion.json');require(completion['nativeCliSignerInvocations']==2 and completion['protocolSubmissions']==completion['productConfigurationWrites']==completion['personOperations']==0 and completion['recordedIntoRun'] is completion['privateMaterialExported'] is False,'Calibration cost/scope differs')
    for name,digest in completion['attempts'].items():require(sha((folder/name/'calibration.json').read_bytes())==digest,'Calibration attempt hidden')
    calibration=read(folder/'calibration/calibration.json');require(calibration['purpose']=='diagnostic-oracle-calibration-only' and calibration['recordedIntoRun'] is False and calibration['signedXmlSha256']==sha((folder/'calibration/earlier-parent-expiry-ignore.xml').read_bytes()),'Synthetic calibration adopted as product behavior')
    installed=read(folder/'receipt-installation-v193.json');require(installed==dict(runId=run,path='/data/simplesamlphp-metadata-validity-evidence/'+run,readBackVerified=True,records=manifest['originals']|{'manifest.json':sha((receipt/'manifest.json').read_bytes())}),'Runtime native original placement not read back')
    evaluation=folder/EVALUATION;result=read(evaluation/'result.json');case=find_case(result,CASE);before=stored(folder,'before')['cases'][CASE];after=stored(folder,'after')['cases'][CASE];outcome=dict(after['outcome']);details=dict(outcome['details']);prior=details.pop('previous_recorded_evidence_result',None)
    if prior is not None:
        old=before['outcome'];require(prior['revision']==before['revision'] and {k:prior[k] for k in ['outcome','not_verified_reason','reason_code','reason_message_key','evidence','details']}==dict(outcome=old['outcome'],not_verified_reason=old['notVerifiedReason'],reason_code=old['reasonCode'],reason_message_key=old['reasonMessageKey'],evidence=old['evidence'],details=old['details']),'Previous original outcome history changed')
    outcome['details']=details;require(outcome==report['production_outcome'] and after['status']=='FINISHED' and after['verdict']=='PASS' and before['outboxCount']==after['outboxCount'],'Formal full stored outcome or outbox differs')
    require((case['outcome'],case['verdict'],case['reason_code'],case['attested'],case['evidence_class'])==('SATISFIED','PASS','metadata.validity.expiration-observed',False,'OPERATOR_ASSISTED') and case['evidence']==outcome['evidence'],'Formal central verdict/provenance differs')
    require(result['run']['id']==run and result['target']['metadata_digest']=='sha256:'+sha((folder/'target-metadata.xml').read_bytes()) and read(evaluation/'transcript-before.json')==read(evaluation/'transcript.json')==entries,'Formal re-evaluation changed originals')
    if live:
        require(command(['docker','exec','samlscope-reference-ssp','cat','/var/simplesamlphp/metadata/saml20-sp-remote.php']).stdout==original,'Live product configuration not restored')
        for suffix,value in [('result.json',result),('transcript',entries)]:require(find_case(api(run,suffix),CASE)==case if suffix=='result.json' else api(run,suffix)==value,'Live formal result/transcript differs')
    return evaluation/'result.json',{CASE:case}

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('root',type=Path);parser.add_argument('--capture-runtime',action='store_true');parser.add_argument('--retain-replay',action='store_true');parser.add_argument('--install',action='store_true');parser.add_argument('--formal',action='store_true');parser.add_argument('--live',action='store_true');args=parser.parse_args();folder=locate(args.root)
    if args.capture_runtime:capture_runtime(folder)
    if args.retain_replay:print('actual archived replay',replay(folder,True)['runId'])
    if args.install:install(folder)
    if args.formal:formal(folder)
    if not any([args.capture_runtime,args.retain_replay,args.install,args.formal]):print(verify_adoption(folder,args.live))
