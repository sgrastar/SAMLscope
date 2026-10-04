#!/usr/bin/env python3
"""Adopt grouped Shibboleth UI cases from native originals and archived production replay."""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import xml.etree.ElementTree as ET
import yaml

from verify_terminal_http_acceptance import _verify_target_runtime,_verify_suite_runtime,find_case,parsed_time

REPO=Path(__file__).resolve().parents[2]
FOLDER='shibboleth-native-ui-v176-r3'
APPEND='shibboleth-native-ui-v176-https-append'
CASES=['IIP-MD05-'+part+'-idp-01' for part in ['fb','fg','fh','fj']]
VARIANTS={'control','full-ui-info',*['ui-consumer-display-'+part for part in ['all','service','entity']],
    *['ui-url-'+element+'-'+scheme for element in ['logo','information','privacy'] for scheme in ['http','https','data','javascript','file']],
    'ui-safety-logo-data','ui-safety-information-javascript','ui-safety-privacy-javascript'}
CONTROLS={'missing-variant','missing-fg-javascript','wrong-run','foreign-run-entry','duplicate-entry','wrong-target','wrong-runtime','missing-native-class','wrong-getter-source',
    'wrong-restoration','missing-readback','late-before','wrong-browser-request','populated-hidden-token','dom-assignment-only','missing-slot-control','wrong-slot-control',
    'unknown-dialog','target-response-bad-signature','unsigned-request','discovery-flow-enabled','incomplete-transcript','non-target-case','correlated-metadata-probe-execution'}
HELPER='61346778d460ec9f19692864e9677194f772438a02de95abeff23766f5830a38'
GETTER='054d049bffc049369703fbeebd3e49748fff155f29388e8a18f699ae47f908b6'
COMPILED_GETTER='f2c236e168ab5e7023efed5a433bfaf79abd51502017e209a7b475cc137b1ecd'
STORED_EXPORTER='e38a4e0786df1665e0efa2d224caecf606dc97ecfce3c7aa36b4d67c9bcd6ec2'
COVERAGE_SHA256='2bee3db74c9be9908710bbe18935c73454f1ed4c5c0f06bdab1cf18deaef843c'
# Filled from actual v177 deployment before first adoption. Never infer a production pin from
# a submitted receipt alone.
PINS={'image_id':'sha256:443dac0bc8eede8ace5c6cd62085c3fe0f3e82c18174a895e0f36d3b59bfe147','jars':{
    'core':'1d6e0020c915f50e78902554c06b61916a3f49e50de78d3bc23c6089d312babe',
    'runner':'397586d7de60d058a7ae78a932bd01cad232aecbe0f1970c97154458a6d3130b',
    'saml':'20981403f9b5125ea5ca5bc25e2a464e37918b88870d930561d69c9d4d71df1c'}}
STORE_SHA256='c4482cd06f9290a3592f0fceac2c9ec2d7603ea0557d1edc885e1c3d51bd8ece'
SHA=lambda raw:hashlib.sha256(raw).hexdigest()
READ=lambda path:json.loads(Path(path).read_text())
MD='{urn:oasis:names:tc:SAML:2.0:metadata}';UI='{urn:oasis:names:tc:SAML:metadata:ui}'
def require(value,detail):
    if not value:raise ValueError(detail)

def dependency_classpath(archive,seed=False):
    # Archived project JARs always precede these third-party dependencies. Avoid a fresh Gradle
    # configuration/build for every generator gate; the installed dependency files are retained.
    excluded={'core-0.1.0.jar','runner-0.1.0.jar','saml-0.1.0.jar','store-0.1.0.jar','api-0.1.0.jar','peer-0.1.0.jar','auth-0.1.0.jar'}
    original=archive/'verification-dependencies.json'
    if not original.exists():
        require(seed,'Archived verification dependency originals missing')
        # Dependency discovery is performed once. Every subsequent historic replay verifies
        # these original third-party bytes, without running Gradle or reading live products.
        captured=Path('/private/tmp/samlscope-runner-runtime-classpath.txt')
        require(captured.exists(),'Verification dependency discovery unavailable')
        files=[Path(value) for value in captured.read_text().strip().split(':') if value.endswith('.jar') and Path(value).name not in excluded]
        require(files and all(path.is_file() for path in files),'Captured verification dependencies unavailable')
        original.write_text(json.dumps([dict(path=str(path),sha256=SHA(path.read_bytes())) for path in files],indent=2)+'\n')
    rows=READ(original)
    require(SHA(original.read_bytes())=='972d47e354b99210c79dd2b720d440f3b44a870ce197359879dbcd88967c5a57','Archived dependency inventory changed')
    require(rows and len({row['path'] for row in rows})==len(rows),'Dependency inventory invalid')
    for row in rows:require(Path(row['path']).name not in excluded and SHA(Path(row['path']).read_bytes())==row['sha256'],'Historic verification dependency changed')
    return ':'.join(row['path'] for row in rows)

def replay(folder,retain=False):
    folder=Path(folder);archive=folder/'reader-v177';receipt=folder/'receipt'
    runtime=READ(archive/'suite-runtime-terminal-http.json');store=READ(archive/'store-runtime.json');helper=archive/'replay-helper-v2.java'
    require(PINS is not None,'Actual production pins not finalized')
    require(SHA(helper.read_bytes())==HELPER==READ(archive/'replay-helper-v2.json')['sha256'],'Archived helper changed')
    jars=[archive/runtime['jars'][name]['file'] for name in ['runner','core','saml']]
    require(all(SHA((archive/runtime['jars'][name]['file']).read_bytes())==digest for name,digest in PINS['jars'].items()),'Archived production JAR changed')
    require(SHA((archive/store['file']).read_bytes())==store['sha256']==STORE_SHA256,'Archived Store changed');jars.append(archive/store['file'])
    with tempfile.TemporaryDirectory(prefix='samlscope-native-ui-replay-') as temporary:
        temporary=Path(temporary);source=temporary/'VerifyShibbolethNativeUiEvidence.java';source.write_bytes(helper.read_bytes());classes=temporary/'classes';classes.mkdir()
        classpath=':'.join(map(str,jars))+':'+dependency_classpath(archive,retain)
        subprocess.run(['javac','-cp',classpath,'-d',str(classes),str(source)],check=True,capture_output=True)
        require(all(p.name.startswith('VerifyShibbolethNativeUiEvidence') for p in classes.rglob('*.class')),'Helper shadows production class')
        report=temporary/'report.json';executed=subprocess.run(['java','-cp',':'.join(map(str,jars))+':'+str(classes)+':'+dependency_classpath(archive),
            'com.samlscope.runner.cases.VerifyShibbolethNativeUiEvidence',str(receipt.resolve()),str(report)],capture_output=True)
        require(executed.returncode==0,'Archived production Reader replay failed: '+executed.stderr.decode(errors='replace')[-1800:]);regenerated=report.read_bytes()
    saved=archive/'production-replay-v2.json'
    if retain:
        require(not saved.exists(),'Refusing to overwrite actual replay');saved.write_bytes(regenerated)
    else:require(saved.read_bytes()==regenerated,'Actual archived Reader replay differs')
    report=json.loads(regenerated)
    require(set(report['cases'])==set(CASES) and set(report['controls'])==CONTROLS,'Production/control inventory differs')
    require(all(value==('VIOLATED' if key=='correlated-metadata-probe-execution' else 'NOT_VERIFIED') for key,value in report['controls'].items()),'Invalid control accepted')
    require(report['privateCredentialsUsed'] is False and report['productOperations']==0,'Replay performed product operations')
    return report

def stored_conclusions(archive):
    source=archive/'stored-readback-source.java';original=archive/'stored-case-conclusions.json';provenance=READ(archive/'stored-readback-provenance.json')
    require(SHA(source.read_bytes())==STORED_EXPORTER==provenance['sourceSha256'] and SHA(original.read_bytes())==provenance['sha256']
        and provenance['readonly'] is True and provenance['caseStateExported'] is provenance['privateCredentialsExported'] is False
        and provenance['productOperations']==0 and set(provenance['selectedCases'])==set(CASES),'Narrow stored outcome original changed')
    coverage=(archive/'approved-coverage-original.yaml').read_bytes();require(SHA(coverage)==COVERAGE_SHA256,'Approved coverage original changed')
    def levels(value):
        if isinstance(value,dict):
            if 'key' in value and 'level' in value:yield value['key'],value['level']
            for child in value.values():yield from levels(child)
        elif isinstance(value,list):
            for child in value:yield from levels(child)
    approved=dict(levels(yaml.safe_load(coverage)))
    require({key:approved[key] for key in ['IIP-MD05.fb','IIP-MD05.fg','IIP-MD05.fh','IIP-MD05.fj']}
        =={'IIP-MD05.fb':'SHOULD_NOT','IIP-MD05.fg':'MUST','IIP-MD05.fh':'SHOULD_NOT','IIP-MD05.fj':'SHOULD'},'Central levels differ from approved source')
    runtime=READ(archive/'suite-runtime-terminal-http.json');jars=[archive/runtime['jars'][name]['file'] for name in ['runner','core','saml']]+[archive/'suite-store-0.1.0.jar']
    with tempfile.TemporaryDirectory(prefix='samlscope-native-ui-conclusion-replay-') as temporary:
        temporary=Path(temporary);named=temporary/'ReadShibbolethUiStoredConclusions.java';named.write_bytes(source.read_bytes());classes=temporary/'classes';classes.mkdir()
        classpath=':'.join(map(str,jars))+':'+dependency_classpath(archive)
        subprocess.run(['javac','-cp',classpath,'-d',str(classes),str(named)],check=True,capture_output=True)
        require(all(p.name.startswith('ReadShibbolethUiStoredConclusions') for p in classes.rglob('*.class')),'Stored helper shadows production class')
        executed=subprocess.run(['java','-cp',':'.join(map(str,jars))+':'+str(classes)+':'+dependency_classpath(archive),
            'com.samlscope.runner.cases.ReadShibbolethUiStoredConclusions','offline',str(original.resolve())],check=True,capture_output=True)
        require(executed.stdout==original.read_bytes(),'Archived central Evaluator disagrees with stored conclusions')
    return READ(original)

def verify(root):
    root=Path(root);folder=root/FOLDER;append=root/APPEND;receipt=folder/'receipt';archive=folder/'reader-v177'
    manifest=READ(receipt/'manifest.json');run=READ(folder/'created.json')['run']['id'];require(manifest['runId']==run,'Mixed receipt Run')
    originals=READ(folder/'receipt-originals.json')
    require({str(p.relative_to(receipt)):SHA(p.read_bytes()) for p in receipt.rglob('*') if p.is_file()}==originals,'Receipt originals changed')
    require(READ(folder/'receipt-installation.json')==dict(runId=run,readBackMatched=True,files=originals),'Runtime placement was not read back')
    transcript=READ(receipt/'transcript.json');by_id={entry['id']:entry for entry in transcript}
    require(len(by_id)==len(transcript) and all(e['runId']==run for e in transcript),'Foreign/duplicate Recorder original')
    require(READ(append/'transcript.json')==transcript,'Run export differs from final append')
    for original in READ(receipt/'decoded-manifest.json'):
        entry=by_id.get(original['id']);raw=(receipt/original['file']).read_bytes()
        require(entry is not None and entry['decodedSamlBytes']==len(raw) and SHA(raw)==original['sha256'],'Decoded Recorder original changed')
    require(set(row['variant'] for row in manifest['observations'])==VARIANTS and len(manifest['observations'])==len(VARIANTS),'Required native conditions incomplete')
    for observation in manifest['observations']:
        variant=observation['variant'];child=receipt/variant;prepared=by_id[observation['metadataReference']]
        raw=(child/'fixture.xml').read_bytes()
        require(raw==(receipt/'decoded'/(prepared['id']+'.xml')).read_bytes() and SHA(raw)==observation['fixtureSha256'],'Fixture is not Recorder original')
        metadata=ET.fromstring(raw);role=metadata.find(MD+'SPSSODescriptor');require(role is not None,'SP role missing')
        if variant.startswith('ui-url-'):
            _,_,element,scheme=variant.split('-');name={'logo':'Logo','information':'InformationURL','privacy':'PrivacyStatementURL'}[element]
            nodes=role.findall('.//'+UI+name);require(len(nodes)==1 and nodes[0].text.startswith(scheme+':'),'URL condition mislabeled '+variant)
        elif variant=='ui-consumer-display-all':
            require(role.find('.//'+UI+'DisplayName').text=='SAMLscope UI display candidate' and role.find('.//'+MD+'ServiceName').text=='SAMLscope service candidate','Display positive absent')
        elif variant=='ui-consumer-display-service':require(role.find('.//'+UI+'DisplayName') is None and role.find('.//'+MD+'ServiceName').text=='SAMLscope service candidate','Service fallback absent')
        elif variant=='ui-consumer-display-entity':require(role.find('.//'+UI+'DisplayName') is None and role.find('.//'+MD+'ServiceName') is None,'Entity fallback precondition absent')
        elif variant.startswith('ui-safety-'):
            element='Logo' if 'logo' in variant else 'InformationURL' if 'information' in variant else 'PrivacyStatementURL';nodes=role.findall('.//'+UI+element)
            require(len(nodes)==1,'Safety URL absent')
            if element=='Logo':
                require(nodes[0].text.startswith('data:image/svg+xml;base64,'),'Script SVG absent');svg=base64.b64decode(nodes[0].text.split(',',1)[1])
                require(svg==b'<svg xmlns="http://www.w3.org/2000/svg" width="180" height="48"><rect width="180" height="48" fill="#1d4ed8"/><script>alert(\'SAMLscope-UI-safety-v1\')</script></svg>','SVG script condition altered')
            else:require(nodes[0].text=="javascript:alert('SAMLscope-UI-safety-v1')",'Javascript condition altered')
    # Every attempt, including both failed collection attempts, is conserved. Do not hide the
    # old DOM-only HTTPS original or count replay/evaluation as a new product test.
    trial_counts=[]
    for trial in ['shibboleth-native-ui-v176-r1','shibboleth-native-ui-v176-r2',FOLDER,APPEND]:
        candidate=root/trial;restoration=READ(candidate/'restoration.json');operations=READ(candidate/'operations.json')
        require(restoration['restored'] is True and restoration['temporaryRemoved'] is True
            and (candidate/'original-providers.xml').read_bytes()==(candidate/'final-providers.xml').read_bytes(),'Attempt not restored '+trial)
        require(all(row['unchanged'] for row in restoration['configurationFiles']),'Native UI settings not restored')
        require(all(row.get('readBack') is True for row in operations if row['operation']=='product-config-write')
            and all(row['completed'] is True for row in operations if row['operation']=='product-reload'),'Operation read-back incomplete')
        counts=READ(candidate/('operation-counts-delta.json' if trial==APPEND else 'operation-counts.json'))
        require(counts['productConfigurationWrites']==sum(row['operation']=='product-config-write' for row in operations)
            and counts['productReloads']==sum(row['operation']=='product-reload' for row in operations)
            and counts['productRestarts']==counts['humanOperations']==0,'Operation counts mismatch');trial_counts.append(counts)
        _verify_target_runtime(candidate,'shibboleth',float(READ(candidate/'created.json')['run']['createdAt']))
    require(SHA((receipt/'native-getter-v3-source.java').read_bytes())==GETTER and SHA((receipt/'native-getter-v3-compiled.class').read_bytes())==COMPILED_GETTER
        and (receipt/'native-getter-v3-compiler-version.txt').read_text().strip()=='javac 17.0.20.1','Native getter/compiler original changed')
    getter_ops=READ(receipt/'native-getter-v3-operations.json');require(getter_ops['sourceUnchanged'] is True
        and all(row['exitCode']==0 for row in getter_ops['operations']) and getter_ops['productConfigurationWrites']==getter_ops['productRestarts']==getter_ops['humanOperations']==0,'Getter capture failed')
    formal=READ(archive/'formal-native-ui-evaluation.json');result_path=archive/'evaluation-terminal-http-v1/result.json';result=READ(result_path)
    require(formal['runId']==run and formal['transcriptUnchanged'] is True and formal['productWrites']==formal['productRestarts']==formal['protocolSends']==formal['humanOperations']==0,'Formal performed new product work')
    require(READ(archive/'evaluation-terminal-http-v1/transcript-before.json')==READ(archive/'evaluation-terminal-http-v1/transcript.json')==transcript,'Formal changed Recorder')
    _verify_suite_runtime(archive,run,parsed_time(formal['startedAt']),PINS)
    cases={id:find_case(result,id) for id in CASES};require(cases==formal['cases'],'Formal case original changed')
    require(result['run']['id']==run and result['target']['metadata_digest']=='sha256:'+manifest['targetMetadataSha256'],
        'Formal Run or fixed target metadata differs')
    replayed=replay(folder);require(replayed['runId']==run,'Archived replay Run differs');stored=stored_conclusions(archive)
    require(stored['runId']==run and set(stored['cases'])==set(CASES),'Stored outcomes have another Run/case')
    for id,case in cases.items():
        require(case['attested'] is False and case['verdict']=='WARNING'
            and case['outcome']==('VIOLATED' if '-fj-' in id else 'SATISFIED_WITH_NOTE'),'Wrong formal conclusion')
        actual=replayed['cases'][id]
        require(actual['outcome']==case['outcome'] and actual['reasonCode']==case['reason_code'] and actual['evidence']==case['evidence'],'Formal and archived Reader differ')
        observed=dict(stored['cases'][id]['outcome']);details=dict(observed['details'])
        previous=details.pop('previous_recorded_evidence_result',None)
        # CaseExecutionService attaches the previous NOT_VERIFIED revision to a recorded
        # re-evaluation. This is an audit envelope, not a new Reader determination. Preserve
        # its captured original and validate its narrow shape; compare every actual conclusion
        # field, including all other details/evidence, byte-semantically to production replay.
        previous_reason={'fb':'browser.oracle-unavailable','fh':'browser.ui-url.evidence-incomplete',
            'fj':'browser.ui-display.evidence-incomplete'}.get(id.split('-')[2])
        if previous_reason is None:require(previous is None,'Unexpected reevaluation audit envelope')
        else:
            require(previous is not None and set(previous)=={'revision','updated_at','outcome','not_verified_reason','reason_code','reason_message_key','evidence','details'}
                and previous['revision']==0 and previous['outcome']=='NOT_VERIFIED' and previous['evidence']==[]
                and previous['reason_code']==previous['reason_message_key']==previous_reason
                and isinstance(previous['details'],dict) and isinstance(previous['not_verified_reason'],str)
                and parsed_time(result['run']['started_at'])<=parsed_time(previous['updated_at'])<parsed_time(formal['startedAt']),
                'Invalid prior NOT_VERIFIED reevaluation audit envelope')
        observed['details']=details
        require(observed==actual and stored['cases'][id]['verdict']==case['verdict'],
            'Stored CaseOutcome details/evidence or central verdict differs')
    return result_path,cases

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('root',type=Path);parser.add_argument('--retain-replay',action='store_true')
    args=parser.parse_args()
    if args.retain_replay:print(replay(args.root/FOLDER,True)['runId'],'archived production reader controls passed')
    else:
        path,cases=verify(args.root);print(path,{id:case['verdict'] for id,case in cases.items()})
