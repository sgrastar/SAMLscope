#!/usr/bin/env python3
"""Independent archived deployed-reader replay, native parser regeneration, complete restoration and counts."""
import argparse,hashlib,json,subprocess,tempfile,urllib.request,zipfile
from pathlib import Path
from export_ssp_consent_ui import export,VARIANTS
FOLDER='ssp-native-consent-ui-v172-r6';CASE='IIP-MD05-fj-idp-01';HELPER='VerifySimpleSamlPhpConsentUi'
JARS=('runner','core','saml','store');CLASSES=('SimpleSamlPhpConsentUiEvidence','UiDisplayComparison','UiDisplayEvidenceFile','UiDisplayBrowserEvidenceTestCase','NativeUiFeatureAbsenceTestCase','ApprovedBrowserCaseRegistry')
RUNTIME='runtime-v174';EVALUATION='evaluation-v174';REPLAY='production-reader-replay-v174.json';INSTALLATION='receipt-installation-v174.json'
SOURCES={'consent-controller':'modules/consent/src/Controller/ConsentController.php','consent-filter':'modules/consent/src/Auth/Process/Consent.php','consent-template':'modules/consent/templates/consentform.twig','template':'src/SimpleSAML/XHTML/Template.php','parser':'src/SimpleSAML/Metadata/SAMLParser.php','auth-state':'src/SimpleSAML/Auth/State.php','base-template':'templates/base.twig','header-template':'templates/_header.twig'}
def sha(raw):return hashlib.sha256(raw).hexdigest()
def read(path):return json.loads(path.read_bytes())
def require(value,reason):
    if not value:raise ValueError(reason)
def locate(root):
    root=Path(root).resolve();return root if root.name==FOLDER else root/FOLDER
def case(result):return next(c for q in result['requirements'] for c in q['cases'] if c['id']==CASE)
def capture_runtime(folder,runtime_name=None):
    runtime=folder/(runtime_name or RUNTIME);runtime.mkdir(exist_ok=False);pins=dict(jars={},classes={})
    for name in JARS:
        p=runtime/(name+'.jar');subprocess.run(['docker','cp','samlscope-reference-suite:/opt/samlscope/lib/'+name+'-0.1.0.jar',str(p)],capture_output=True,check=True);pins['jars'][name]=sha(p.read_bytes())
    with zipfile.ZipFile(runtime/'runner.jar') as z:pins['classes']={n:sha(z.read('com/samlscope/runner/cases/'+n+'.class')) for n in CLASSES}
    helper=Path(__file__).with_name(HELPER+'.java').read_bytes();(runtime/(HELPER+'.java')).write_bytes(helper);pins['helperSha256']=sha(helper)
    pins['suiteImageId']=subprocess.check_output(['docker','inspect','--format','{{.Image}}','samlscope-reference-suite']).decode().strip()
    (runtime/'pins.json').write_text(json.dumps(pins,indent=2)+'\n')
def replay(folder,runtime_name=None):
    runtime=folder/(runtime_name or RUNTIME);pins=read(runtime/'pins.json');require(set(pins['jars'])==set(JARS),'Archived JAR set differs')
    for name in JARS:require(sha((runtime/(name+'.jar')).read_bytes())==pins['jars'][name],'Archived JAR changed')
    with zipfile.ZipFile(runtime/'runner.jar') as z:require(pins['classes']=={n:sha(z.read('com/samlscope/runner/cases/'+n+'.class')) for n in CLASSES},'Archived production classes changed')
    require(sha((runtime/(HELPER+'.java')).read_bytes())==pins['helperSha256'],'Archived helper changed')
    cp=':'.join(str(runtime/(n+'.jar')) for n in JARS)+':'+Path('/private/tmp/samlscope-runner-runtime-classpath.txt').read_text().strip()
    with tempfile.TemporaryDirectory(prefix='ssp-native-ui-replay-') as name:
        temporary=Path(name);classes=temporary/'classes';compile=subprocess.run(['javac','-sourcepath','','-cp',cp,'-d',str(classes),str(runtime/(HELPER+'.java'))],capture_output=True,text=True)
        require(compile.returncode==0,'Replay compile failed: '+compile.stderr[-1000:]);require(all(p.name.startswith(HELPER) for p in classes.rglob('*.class')),'Helper shadows production class')
        result=subprocess.run(['java','-cp',str(classes)+':'+cp,'com.samlscope.runner.cases.'+HELPER,str(folder),str(temporary/'report.json')],capture_output=True,text=True,timeout=90)
        require(result.returncode==0,'Production replay failed: '+result.stderr[-1600:]);return read(temporary/'report.json')
def capture_native_parser(folder):
    require(not (folder/'independent-native-parser-replay.json').exists(),'Refusing parser replay replacement');rows=[];entity='http://localhost:18080/p/'+read(folder/'created.json')['run']['planId'];command=(folder/'native-parser-command.php').read_text()
    for variant in ['control']+VARIANTS:
        raw=(folder/variant/'fixture.xml').read_bytes();result=subprocess.run(['docker','exec','-i','samlscope-reference-ssp','php','-r',command,entity,'default'],input=raw,capture_output=True,timeout=30)
        require(result.returncode==0 and result.stdout==(folder/variant/'parser.stdout').read_bytes(),'Actual native parser output differs');rows.append(dict(variant=variant,fixtureSha256=sha(raw),parserSha256=sha(result.stdout),bytesIdentical=True))
    (folder/'independent-native-parser-replay.json').write_text(json.dumps(dict(records=rows,nativeParserInvocations=4,productConfigurationWrites=0,protocolSends=0,humanOperations=0),indent=2)+'\n')
def verify(root,live=False):
    folder=locate(root);manifest=read(folder/'originals/manifest.json');run=read(folder/'created.json')['run']['id'];require(manifest['runId']==run,'Run differs')
    with tempfile.TemporaryDirectory(prefix='ssp-native-ui-export-') as name:
        regenerated=Path(name)/'originals';export(folder,regenerated);require({p.name for p in regenerated.iterdir()}=={p.name for p in (folder/'originals').iterdir()},'Exported original set differs')
        for p in regenerated.iterdir():require(p.read_bytes()==(folder/'originals'/p.name).read_bytes(),'Export regenerated bytes differ')
    for name,digest in manifest['files'].items():require(sha((folder/'originals'/name).read_bytes())==digest,'Original hash differs')
    restore=read(folder/'restoration.json')
    for label in ['remote','hosted','override']:
        before=(folder/(label+'-original.php')).read_bytes();require(before==(folder/(label+'-final.php')).read_bytes() and restore[label]['restored'] and restore[label]['original_sha256']==restore[label]['final_sha256']==sha(before),'Native configuration restore differs')
    recorded=read(folder/REPLAY);require(replay(folder)==recorded,'Archived production replay differs')
    require(recorded['production_outcome']['outcome']=='SATISFIED' and len(recorded['negative_controls'])==16 and set(recorded['negative_controls'].values())=={'NOT_VERIFIED'},'Controls or complete outcome differ')
    require(recorded['normalization_controls']==dict(actual_variants_only_change_approved_fields=True,uncontrolled_metadata_change_preserved=True),'Structural normalization controls incomplete')
    require(recorded['wrapper_readiness_and_reevaluation'] is True,'Actual wrapper integration unproven')
    require(read(folder/'independent-native-parser-replay.json')['nativeParserInvocations']==4,'Native parser controls incomplete')
    privacy=folder/'privacy-projection-v176/projection.json'
    if privacy.exists():
        projection=read(privacy);require(projection['caseOutcomeIdentical'] and projection['originalDecodedSamlAndTranscriptUnchanged'] and projection['formalCaseManifestHashAbsent'],'Native privacy projection lacks semantic proof')
        require(projection['newManifestSha256']==sha((folder/'originals/manifest.json').read_bytes()),'Native privacy projection manifest changed')
        projected=read(folder/'production-reader-replay-privacy-v176.json');require(replay(folder,'runtime-privacy-v176')==projected,'Actual deployed Reader projection replay differs')
        require(projected['production_outcome']==recorded['production_outcome'] and projected['negative_controls']==recorded['negative_controls'],'Native privacy projection changes case meaning/controls')
        for name,digest in projection['protectedFiles'].items():require(sha((folder/name).read_bytes())==digest,'Privacy projection alters signed/raw/formal proof')
        for row in projection['files']:
            path=folder.parent/row['file'];require(sha(path.read_bytes())==row['afterSha256'],'Projected HTML changed')
            import re
            require(re.search(r'_[0-9a-f]{40}',path.read_text(),re.I) is None,'Native auth-state nonce remains in HTML')
    installed=read(folder/INSTALLATION);require(installed['readBackVerified'] and {r['file']:r['sha256'] for r in installed['records']}==manifest['files']|{'manifest.json':sha((folder/'originals/manifest.json').read_bytes())},'Runtime installation readback differs')
    evaluation=folder/EVALUATION;result=read(evaluation/'result.json');actual=case(result);require((actual['outcome'],actual['verdict'],actual['reason_code'],actual['attested'])==('SATISFIED','PASS','browser.ui-display.precedence-observed',False),'Formal outcome differs')
    require({e['reference'] for e in actual['evidence']}=={e['reference'] for e in recorded['production_outcome']['evidence']},'Formal outcome references differ')
    transcript=read(folder/'transcript.json');require(read(evaluation/'transcript-before.json')==read(evaluation/'transcript.json')==transcript,'Formal evaluation changed transcript')
    history=read(folder/'formal-attempt-history.json');require(history['reason']=='v173 native UI absence wrapper did not forward delegate reevaluation' and history['adoptionMaintained'] is False,'Failed formal attempt not documented')
    for name,digest in history['files'].items():require(sha((folder/name).read_bytes())==digest,'Failed formal attempt overwritten')
    require(case(read(folder/'evaluation/result.json'))['outcome']=='NOT_VERIFIED' and read(folder/'evaluation/transcript.json')==transcript,'Historical failed attempt changed')
    attempts=[]
    for index in range(1,7):
        attempt=folder.parent/('ssp-native-consent-ui-v172-r'+str(index));counts=read(attempt/'operation-counts.json');require(counts['restored'] and counts['humanOperations']==counts['productRestarts']==0,'Unrestored/unaccounted diagnostic attempt');attempts.append(counts)
        if index>1:
            for label,state in read(attempt/'restoration.json').items():require(state['restored'] and state['original_sha256']==state['final_sha256'],'Diagnostic restoration incomplete')
    summary=read(folder/'batch-summary.json')
    for key in ['productConfigurationWriteAttempts','configurationApplyWrites','restorationWrites','protocolOperationsAttempted','runCreations']:require(summary[key]==sum(a[key] for a in attempts),'Batch attempt counts differ: '+key)
    require(summary['nativeParserInvocations']==sum(a['nativeParserInvocations'] for a in attempts)+4 and summary['productRestarts']==summary['humanOperations']==0,'Parser/control counts differ')
    if live:
        for label,path in [('remote','metadata/saml20-sp-remote.php'),('hosted','metadata/saml20-idp-hosted.php'),('override','config/config-override.php')]:require(subprocess.check_output(['docker','exec','samlscope-reference-ssp','cat','/var/simplesamlphp/'+path])==(folder/(label+'-original.php')).read_bytes(),'Live product configuration not restored')
        for name,path in SOURCES.items():require(subprocess.check_output(['docker','exec','samlscope-reference-ssp','cat','/var/simplesamlphp/'+path])==(folder/('native-'+name+'.txt')).read_bytes(),'Live native source differs')
        for suffix in ['result.json','transcript']:
            with urllib.request.urlopen('http://localhost:18080/api/runs/'+run+'/'+suffix,timeout=30) as response:value=json.load(response)
            require(case(value)==actual if suffix=='result.json' else value==transcript,'Live formal proof differs')
    return evaluation/'result.json',{CASE:actual}
if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('root',type=Path);p.add_argument('--capture-runtime',action='store_true');p.add_argument('--record-replay',action='store_true');p.add_argument('--native-parser-replay',action='store_true');p.add_argument('--live',action='store_true');a=p.parse_args();folder=locate(a.root)
    if a.capture_runtime:capture_runtime(folder)
    if a.native_parser_replay:capture_native_parser(folder)
    if a.record_replay:
        file=folder/REPLAY;require(not file.exists(),'Refusing replay replacement');file.write_text(json.dumps(replay(folder),indent=2)+'\n')
    if not any([a.capture_runtime,a.record_replay,a.native_parser_replay]):
        path,outcomes=verify(a.root,a.live);print(json.dumps(dict(result=str(path),case=CASE,verdict=outcomes[CASE]['verdict'],verified=True),indent=2))
