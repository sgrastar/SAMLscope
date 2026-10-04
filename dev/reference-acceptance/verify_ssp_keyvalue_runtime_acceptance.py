#!/usr/bin/env python3
"""Independent actual deployed reader replay, native parser regeneration, formal adoption."""
import argparse,hashlib,importlib.util,json,subprocess,tempfile,urllib.request,zipfile
from pathlib import Path
from export_ssp_keyvalue_runtime_receipt import export,VARIANTS
REPO=Path(__file__).resolve().parents[2]
FOLDER='ssp-native-keyvalue-runtime-v170-r3'
CASES={'IIP-MD05-cd-idp-01','IIP-MD06-a5-idp-01','IIP-MD06-a7-idp-01'}
JARS=('runner','core','saml','store');HELPER='VerifySimpleSamlPhpKeyValueRuntime'
CLASSES=('SimpleSamlPhpKeyValueRuntimeEvidence','MetadataKeySelectionEvidenceFile','MetadataKeySelectionComparison','MetadataKeySelectionConfigurationTestCase','ApprovedConfigCaseRegistry')
SOURCES={'parser':'src/SimpleSAML/Metadata/SAMLParser.php','message':'modules/saml/src/Message.php',
    'configuration':'src/SimpleSAML/Configuration.php','idp-saml2':'modules/saml/src/IdP/SAML2.php','web-browser-sso':'modules/saml/src/Controller/WebBrowserSingleSignOn.php'}
def sha(raw):return hashlib.sha256(raw).hexdigest()
def read(path):return json.loads(path.read_bytes())
def require(condition,detail):
    if not condition:raise ValueError(detail)
def locate(root):
    root=Path(root).resolve();return root if root.name==FOLDER else root/FOLDER
def rows(result):return {c['id']:c for q in result['requirements'] for c in q['cases'] if c['id'] in CASES}
def verify_privacy_projection(folder,manifest,recorded,installed,actual):
    directory=folder/'privacy-projection'
    if not directory.exists():return
    followup=folder/'privacy-projection-v176';latest=None;intermediate=manifest;next_files={}
    if followup.exists():
        latest=read(followup/'projection.json');intermediate=read(followup/'original-manifest.json')
        require(latest['oldManifestSha256']==sha((followup/'original-manifest.json').read_bytes())
            and latest['newManifestSha256']==sha((folder/'originals/manifest.json').read_bytes()),'Second privacy projection manifest chain differs')
        require(set(intermediate['files'])==set(manifest['files']) and set(latest['changedManifestFiles'])=={r['exportedFile'] for r in latest['files'] if 'exportedFile' in r},'Second projection scope differs')
        changed2=set(latest['changedManifestFiles'])
        require(all(name in changed2 or digest==manifest['files'][name] for name,digest in intermediate['files'].items()),'Second projection changes used originals')
        import sys
        sys.path.insert(0,str(REPO/'dev/simplesamlphp'))
        from native_ui_privacy import contains_state_secret
        for row in latest['files']:
            path=folder.parent/row['file'];raw=path.read_bytes();next_files[row['file']]=row
            require(sha(raw)==row['afterSha256'] and not contains_state_secret(raw.decode()),'Second projection retains native state or differs')
            if 'exportedFile' in row:
                name=row['exportedFile'];require(intermediate['files'][name]==row['beforeSha256'] and manifest['files'][name]==row['afterSha256'],'Second exported privacy projection differs')
        require(all(sha((folder/name).read_bytes())==digest for name,digest in latest['protectedFiles'].items()),'Second projection changes protected proof')
        require(latest['caseOutcomesIdentical'] and latest['formalRowsUnchanged'] and latest['runtimeProjectionReadBack']
            and latest['productConfigurationWrites']==latest['protocolSends']==latest['humanOperations']==0,'Second projection proof incomplete')
        current=read(folder/'production-reader-replay-privacy-v176.json');require(replay(folder,'runtime-privacy-v176')==current==recorded,'Actual deployed privacy replay differs')
        require(rows(read(folder/'evaluation-privacy-v176/result.json'))==actual
            and read(folder/'evaluation-privacy-v176/transcript.json')==read(folder/'transcript.json'),'Second formal evaluation differs')
    projection=read(directory/'projection.json');old_manifest=read(directory/'original-manifest.json')
    old_replay=read(directory/'original-production-reader-replay.json');old_install=read(directory/'original-receipt-installation.json')
    require(projection['schema']=='samlscope-unused-login-privacy-projection-v1'
        and projection['oldManifestSha256']==sha((directory/'original-manifest.json').read_bytes())
        and projection['newManifestSha256']==(latest['oldManifestSha256'] if latest else sha((folder/'originals/manifest.json').read_bytes())),'Privacy projection manifest relationship differs')
    changed=set(projection['changedManifestFiles']);require(len(changed)==2 and set(old_manifest['files'])==set(manifest['files']),'Privacy projection scope differs')
    for name,digest in old_manifest['files'].items():require(name in changed or digest==intermediate['files'][name],'Privacy projection changes used original')
    require({k:v for k,v in old_replay.items() if k!='manifestSha256'}=={k:v for k,v in recorded.items() if k!='manifestSha256'},'Privacy projection changes production replay')
    require(all(projection['oldManifestSha256'] not in json.dumps(row) for row in actual.values()),'Formal CaseExecution has stale manifest hash')
    require(all(sha((folder/name).read_bytes())==digest for name,digest in projection['protectedFiles'].items()),'Privacy projection changes formal proof')
    require(len(projection['files'])==9 and projection['runtimeProjectionWrites']==3 and projection['runtimeProjectionReadBack']
        and projection['usedOriginalsUnchanged'] and projection['formalOutcomeAndReferencesUnchanged'],'Privacy projection counts or outcome relationship differs')
    from html.parser import HTMLParser
    class Tokens(HTMLParser):
        def __init__(self):super().__init__();self.values=[]
        def handle_starttag(self,tag,attrs):
            value=dict(attrs)
            if tag=='input' and value.get('name')=='AuthState':self.values.append(value.get('value'))
    for row in projection['files']:
        raw=(folder.parent/row['file']).read_bytes();expected=next_files.get(row['file']);require((expected['beforeSha256']==row['afterSha256'] and expected['afterSha256']==sha(raw) if expected else sha(raw)==row['afterSha256']) and row['beforeSha256']!=row['afterSha256'],'Privacy projection file differs')
        tokens=Tokens();tokens.feed(raw.decode());require(tokens.values==['[REDACTED-AUTHSTATE]'],'Native login state retained')
        if 'exportedFile' in row:
            name=row['exportedFile'];require(name in changed and old_manifest['files'][name]==row['beforeSha256'] and intermediate['files'][name]==row['afterSha256'],'Exported privacy projection differs')
    require({v['file']:v['sha256'] for v in old_install['records']}==old_manifest['files']|{'manifest.json':projection['oldManifestSha256']},'Archived original runtime installation differs')
    require(installed.get('privacyProjection') is True,'Projected runtime installation not identified')
def capture_runtime(folder,runtime_name='runtime'):
    runtime=folder/runtime_name;runtime.mkdir(exist_ok=False);pins=dict(jars={},classes={})
    for name in JARS:
        path=runtime/(name+'.jar');subprocess.run(['docker','cp','samlscope-reference-suite:/opt/samlscope/lib/'+name+'-0.1.0.jar',str(path)],check=True,capture_output=True)
        pins['jars'][name]=sha(path.read_bytes())
    with zipfile.ZipFile(runtime/'runner.jar') as archive:pins['classes']={n:sha(archive.read('com/samlscope/runner/cases/'+n+'.class')) for n in CLASSES}
    source=Path(__file__).with_name(HELPER+'.java').read_bytes();(runtime/(HELPER+'.java')).write_bytes(source);pins['helperSha256']=sha(source)
    pins['suiteImageId']=subprocess.check_output(['docker','inspect','--format','{{.Image}}','samlscope-reference-suite']).decode().strip()
    (runtime/'pins.json').write_text(json.dumps(pins,indent=2)+'\n')
def replay(folder,runtime_name='runtime'):
    runtime=folder/runtime_name;pins=read(runtime/'pins.json');require(set(pins['jars'])==set(JARS),'Archived JAR set differs')
    for name in JARS:require(sha((runtime/(name+'.jar')).read_bytes())==pins['jars'][name],'Archived JAR changed')
    require(sha((runtime/(HELPER+'.java')).read_bytes())==pins['helperSha256'],'Archived helper changed')
    with zipfile.ZipFile(runtime/'runner.jar') as archive:require(pins['classes']=={n:sha(archive.read('com/samlscope/runner/cases/'+n+'.class')) for n in CLASSES},'Production classes changed')
    cp=':'.join(str(runtime/(n+'.jar')) for n in JARS)+':'+Path('/private/tmp/samlscope-runner-runtime-classpath.txt').read_text().strip()
    with tempfile.TemporaryDirectory(prefix='ssp-keyvalue-replay-') as name:
        temporary=Path(name);classes=temporary/'classes'
        result=subprocess.run(['javac','-sourcepath','','-cp',cp,'-d',str(classes),str(runtime/(HELPER+'.java'))],capture_output=True,text=True)
        require(result.returncode==0,'Helper compile failed: '+result.stderr[-1200:]);require(all(p.name.startswith(HELPER) for p in classes.rglob('*.class')),'Helper shadows production class')
        result=subprocess.run(['java','-cp',str(classes)+':'+cp,'com.samlscope.runner.cases.'+HELPER,str(folder),str(temporary/'report.json')],capture_output=True,text=True,timeout=90)
        require(result.returncode==0,'Production replay failed: '+result.stderr[-1200:]);return read(temporary/'report.json')
def native_parser_replay(folder):
    command=(folder/'native-parser-command.php').read_text();entity=read(folder/'originals/manifest.json')['spEntityId'];records=[]
    for variant in ['control']+VARIANTS:
        result=subprocess.run(['docker','exec','-i','samlscope-reference-ssp','php','-r',command,entity,'default'],input=(folder/variant/'fixture.xml').read_bytes(),capture_output=True,timeout=40)
        require(result.returncode==0 and result.stdout==(folder/variant/'parser.stdout').read_bytes(),'Installed native parser regeneration differs')
        records.append(dict(variant=variant,returncode=0,fixtureSha256=sha((folder/variant/'fixture.xml').read_bytes()),parserSha256=sha(result.stdout),bytesIdentical=True))
    path=folder/'independent-native-parser-replay.json';require(not path.exists(),'Refusing parser replay replacement')
    path.write_text(json.dumps(dict(commandSha256=sha(command.encode()),records=records,nativeParserInvocations=5,productConfigurationWrites=0,protocolSends=0,humanOperations=0),indent=2)+'\n')
def verify(root,live=False):
    folder=locate(root);manifest=read(folder/'originals/manifest.json');run=read(folder/'created.json')['run']['id'];require(manifest['runId']==run,'Run differs')
    with tempfile.TemporaryDirectory(prefix='ssp-keyvalue-export-') as name:
        regenerated=Path(name)/'originals';export(folder,regenerated)
        require({p.name for p in regenerated.iterdir()}=={p.name for p in (folder/'originals').iterdir()},'Regenerated original set differs')
        for p in regenerated.iterdir():require(p.read_bytes()==(folder/'originals'/p.name).read_bytes(),'Original export differs: '+p.name)
    for name,digest in manifest['files'].items():require(sha((folder/'originals'/name).read_bytes())==digest,'Native original changed')
    require((folder/'original-sp-config.php').read_bytes()==(folder/'final-sp-config.php').read_bytes(),'Configuration restore bytes differ')
    restore=read(folder/'restoration.json');require(restore['restored'] and restore['original_sha256']==restore['final_sha256']==sha((folder/'original-sp-config.php').read_bytes()),'Restore hashes differ')
    require(read(folder/'operation-counts.json')==dict(productConfigurationWriteAttempts=6,configurationApplyWrites=5,restorationWrites=1,nativeParserInvocations=5,protocolOperationsAttempted=10,runCreations=1,productRestarts=0,humanOperations=0,restored=True),'Collection counts differ')
    native=read(folder/'independent-native-parser-replay.json');require(native['nativeParserInvocations']==5 and len(native['records'])==5 and all(v['bytesIdentical'] for v in native['records']),'Native parser controls incomplete')
    for row in native['records']:require(row['parserSha256']==sha((folder/row['variant']/'parser.stdout').read_bytes()),'Native parser replay changed')
    for label in ['before','after']:
        identity=read(folder/('native-inspect-'+label+'.json'));require(set(identity)=={'containerId','imageId','image','startedAt','running'},'Unsafe native identity projection')
    recorded=read(folder/'production-reader-replay.json');require(replay(folder)==recorded,'Production replay differs')
    require(set(recorded['production_outcomes'])==CASES and all(v['outcome']=='VIOLATED' for v in recorded['production_outcomes'].values())
        and len(recorded['negative_controls'])==21 and set(recorded['negative_controls'].values())=={'NOT_VERIFIED'},'Production counterexamples/controls incomplete')
    evaluation=folder/'evaluation';result=read(evaluation/'result.json');actual=rows(result);require(set(actual)==CASES,'Formal case set differs')
    for id,row in actual.items():
        require((row['outcome'],row['verdict'],row['reason_code'],row['attested'])==('VIOLATED','FAIL','metadata.keys.keyvalue-runtime-unavailable',False),'Formal outcome differs: '+id)
        require({e['reference'] for e in row['evidence']}=={e['reference'] for e in recorded['production_outcomes'][id]['evidence']},'Formal evidence refs differ')
    entries=read(folder/'transcript.json');require(read(evaluation/'transcript.json')==read(evaluation/'transcript-before.json')==entries,'Formal evaluation changed transcript')
    require(result['run']['id']==run and result['target']['metadata_digest']=='sha256:'+sha((folder/'target-metadata.xml').read_bytes()),'Formal Run target differs')
    installed=read(folder/'receipt-installation.json');require(installed['readBackVerified'] is True and set(v['file'] for v in installed['records'])==set(manifest['files'])|{'manifest.json'},'Runtime originals readback incomplete')
    for row in installed['records']:require(row['sha256']==sha((folder/'originals'/row['file']).read_bytes()),'Runtime readback hash differs')
    verify_privacy_projection(folder,manifest,recorded,installed,actual)
    attempts=[]
    for index in [1,2,3]:
        attempt=folder.parent/('ssp-native-keyvalue-runtime-v170-r'+str(index));counts=read(attempt/'operation-counts.json');restoration=read(attempt/'restoration.json')
        require(restoration['restored'] and counts['restored'] and counts['productConfigurationWriteAttempts']==6,'Attempt not accounted/restored');attempts.append(counts)
    summary=read(folder/'batch-summary.json');require(summary['productConfigurationWriteAttempts']==sum(a['productConfigurationWriteAttempts'] for a in attempts)
        and summary['configurationApplyWrites']==15 and summary['restorationWrites']==3 and summary['protocolOperationsAttempted']==30
        and summary['runCreations']==3 and summary['nativeParserInvocations']==20 and summary['productRestarts']==summary['humanOperations']==0,'Batch attempt counts differ')
    if live:
        current=subprocess.check_output(['docker','exec','samlscope-reference-ssp','cat','/var/simplesamlphp/metadata/saml20-sp-remote.php']);require(current==(folder/'original-sp-config.php').read_bytes(),'Live product restore differs')
        for name,path in SOURCES.items():require(subprocess.check_output(['docker','exec','samlscope-reference-ssp','cat','/var/simplesamlphp/'+path])==(folder/('native-'+name+'.php')).read_bytes(),'Native executable source differs')
        for suffix in ['result.json','transcript']:
            with urllib.request.urlopen('http://localhost:18080/api/runs/'+run+'/'+suffix,timeout=30) as response:value=json.load(response)
            require(rows(value)==actual if suffix=='result.json' else value==entries,'Live formal result/transcript differs')
    return evaluation/'result.json',actual
if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('root',type=Path);p.add_argument('--capture-runtime',action='store_true');p.add_argument('--record-replay',action='store_true');p.add_argument('--capture-native-parser-replay',action='store_true');p.add_argument('--live',action='store_true');a=p.parse_args();folder=locate(a.root)
    if a.capture_runtime:capture_runtime(folder)
    if a.capture_native_parser_replay:native_parser_replay(folder)
    if a.record_replay:
        file=folder/'production-reader-replay.json';require(not file.exists(),'Refusing replay replacement');file.write_text(json.dumps(replay(folder),indent=2)+'\n')
    if not any([a.capture_runtime,a.record_replay,a.capture_native_parser_replay]):
        path,outcomes=verify(a.root,a.live);print(json.dumps(dict(result=str(path),cases={k:v['verdict'] for k,v in outcomes.items()},verified=True),indent=2))
