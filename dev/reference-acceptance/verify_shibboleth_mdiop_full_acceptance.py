#!/usr/bin/env python3
"""Adopt MD05.c only after all current native representations and signature controls.

The old partial campaign remains historical, unadoptable evidence. This gate replays the
archived production factory against a fresh complete campaign and reads every native original.
It makes no judgment about runtime key interpretation obligations in MD06.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import xml.etree.ElementTree as ET

from verify_mdiop_acceptance import REQUIRED_FIXTURES
from verify_shibboleth_metadata_refresh_acceptance import decoded_originals
from verify_shibboleth_persistent_pairwise_acceptance import runtime_classpath
from verify_terminal_http_acceptance import _verify_target_runtime, _verify_suite_runtime, find_case, parsed_time

REPO=Path(__file__).resolve().parents[2]
FOLDER='shibboleth-mdiop-full-v172-r2'
CASE='IIP-MD05-c-idp-01'
LEGACY_PINS={'image_id': 'sha256:c7d63f33732c837aec60407b0bcdc9127f0ed1d72e39dbaa81aa1db4c9b6b6b7', 'jars': {'core': '1d6e0020c915f50e78902554c06b61916a3f49e50de78d3bc23c6089d312babe', 'runner': 'df1b998fb90968a90c9cf6f80b6ce2a5333b991330db9b1e0d3df35d8f5646da', 'saml': '5d4e309378ebbb835f99e16d17eeff5221302146822df6809ce751093544a228'}}
PINS={'image_id': 'sha256:26bf9614c251e750b85d7c0c51543abd010f6ec36fdbb26a8b8aa53a5cf78dff', 'jars': {'core': '1d6e0020c915f50e78902554c06b61916a3f49e50de78d3bc23c6089d312babe', 'runner': 'f4d841508e04679a85f3ded38bfed7c327ae210efceb3e7b01bf13973bd36c5c', 'saml': '5d4e309378ebbb835f99e16d17eeff5221302146822df6809ce751093544a228'}}

HELPER_SHA256='075d7517b6393892464dfefbfbd5f060c6ee938be2d224901b69b8551d83e546'
STORE_SHA256='c4482cd06f9290a3592f0fceac2c9ec2d7603ea0557d1edc885e1c3d51bd8ece'
CATALOG_SHA256='431d9aa863d5d882d37266667a8fd20547d1fe6d037274b8d59ff66347f5ecd4'
MD='{urn:oasis:names:tc:SAML:2.0:metadata}'
SHA=lambda raw:hashlib.sha256(raw).hexdigest()
READ=lambda path:json.loads(Path(path).read_text())


def require(value,detail):
    if not value:raise ValueError(detail)


def catalog_projection(raw):
    # Use the existing locked validator environment, without installing dependencies.
    source='import sys,json,yaml; print(json.dumps(yaml.safe_load(sys.stdin.read()),sort_keys=True))'
    result=subprocess.run([str(REPO/'.venv/bin/python'),'-c',source],input=raw,capture_output=True,check=True)
    return json.loads(result.stdout)


def replay(folder,retain=False):
    folder=Path(folder);archive=folder/'strict-reader-v173'
    runtime=READ(archive/'suite-runtime-terminal-http.json');store=READ(archive/'store-runtime.json')
    helper=archive/'replay-helper-original.java';provenance=READ(archive/'replay-helper-original.json')
    require(SHA(helper.read_bytes())==HELPER_SHA256==provenance['sha256'] and provenance['file']==helper.name,'Archived helper changed')
    catalog=(folder/'approved-cases-original.yaml').read_bytes()
    require(SHA(catalog)==CATALOG_SHA256 and READ(folder/'approved-cases-projection.json')==catalog_projection(catalog),
            'Approved catalog projection differs from its signed original')
    jars=[archive/runtime['jars'][name]['file'] for name in ('runner','core','saml')]
    require(all(SHA((archive/runtime['jars'][name]['file']).read_bytes())==digest for name,digest in PINS['jars'].items())
            and store['path']=='/opt/samlscope/lib/store-0.1.0.jar'
            and SHA((archive/store['file']).read_bytes())==store['sha256']==STORE_SHA256,'Archived production runtime changed')
    jars.append(archive/store['file'])
    legacy_runtime=READ(folder/'suite-runtime-terminal-http.json');legacy_store=READ(folder/'store-runtime.json')
    legacy_jars=[folder/legacy_runtime['jars'][name]['file'] for name in ('runner','core','saml')]
    require(all(SHA((folder/legacy_runtime['jars'][name]['file']).read_bytes())==digest
                for name,digest in LEGACY_PINS['jars'].items()),'Historical v172 Reader changed')
    require(SHA((folder/legacy_store['file']).read_bytes())==legacy_store['sha256']==STORE_SHA256,'Historical Store archive changed')
    legacy_jars.append(folder/legacy_store['file'])
    with tempfile.TemporaryDirectory(prefix='samlscope-mdiop-full-replay-') as temporary:
        temp=Path(temporary);named=temp/'VerifyShibbolethMdiopFullEvidence.java';named.write_bytes(helper.read_bytes())
        classes=temp/'classes';classes.mkdir();classpath=':'.join(map(str,jars))+':'+runtime_classpath()
        subprocess.run(['javac','-cp',classpath,'-d',str(classes),str(named)],check=True,capture_output=True)
        require(all(p.name.startswith('VerifyShibbolethMdiopFullEvidence') for p in classes.rglob('*.class')),
                'Helper would shadow a production class')
        report=temp/'report.json';executed=subprocess.run(['java','-cp',':'.join(map(str,jars))+':'+str(classes)+':'+runtime_classpath(),
            'com.samlscope.runner.cases.VerifyShibbolethMdiopFullEvidence',str(folder.resolve()),str(report)],capture_output=True)
        require(executed.returncode==0,'Archived production replay failed: '+executed.stderr.decode(errors='replace')[-2000:])
        regenerated=report.read_bytes()
        baseline=temp/'historical-baseline.json'
        historical=subprocess.run(['java','-cp',':'.join(map(str,legacy_jars))+':'+str(classes)+':'+runtime_classpath(),
            'com.samlscope.runner.cases.VerifyShibbolethMdiopFullEvidence',str(folder.resolve()),str(baseline),'historical-baseline'],capture_output=True)
        require(historical.returncode==0,'Actual v172 baseline replay failed: '+historical.stderr.decode(errors='replace')[-1500:])
        historical_bytes=baseline.read_bytes()
    retained=archive/'production-replay-v173.json';historical_path=archive/'historical-production-baseline-v172.json'
    if retain:
        require(not retained.exists() and not historical_path.exists(),'Refusing to replace archived replay')
        retained.write_bytes(regenerated);historical_path.write_bytes(historical_bytes)
    else:require(retained.read_bytes()==regenerated and historical_path.read_bytes()==historical_bytes,'Actual archived Reader replay differs')
    parsed=json.loads(regenerated)
    require(parsed['runId']==READ(folder/'created.json')['run']['id'] and parsed['caseId']==CASE
            and parsed['productionOutcome']=='SATISFIED' and parsed['runtimeKeyInterpretationProven'] is False
            and set(parsed['representations'])==REQUIRED_FIXTURES|{'control'}
            and all(set(value.values())=={True} for value in parsed['representations'].values())
            and set(parsed['controls'])=={'missing-positive:'+v for v in REQUIRED_FIXTURES|{'control'}}|{'foreign-run','duplicate-recorder-id'}
            and set(parsed['controls'].values())=={'NOT_VERIFIED'},'Representation/control inventory incomplete')
    require(parsed['productionCaseOutcome']==json.loads(historical_bytes)['productionCaseOutcome'],
            'Strict v173 changed historical outcome/evidence/details')
    formal=READ(folder/'formal-mdiop-evaluation.json')['case'];observed=parsed['productionCaseOutcome']
    require(observed['outcome']==formal['outcome'] and observed['reasonCode']==formal['reason_code']
            and observed['evidence']==formal['evidence']
            and all(sorted(set(observed['details'][key]))==value for key,value in formal['diagnostics'].items()),
            'Actual strict Reader differs from immutable formal v172 case')
    return parsed


def entity(metadata):
    if metadata.tag==MD+'EntityDescriptor':return metadata
    values=metadata.findall(MD+'EntityDescriptor')
    require(len(values)==1,'Native fixture entity ambiguous');return values[0]


def semantic(node):
    return (node.tag,tuple(sorted(node.attrib.items())),''.join((node.text or '').split()),tuple(semantic(c) for c in node))


def verify(root):
    folder=Path(root)/FOLDER;result_path=folder/'evaluation-terminal-http-v1/result.json'
    result=READ(result_path);run=READ(folder/'created.json')['run']['id'];case=find_case(result,CASE)
    require((case['outcome'],case['verdict'],case['reason_code'],case['attested'])
            ==('SATISFIED','PASS','metadata.fixture-probe.satisfied',False),'Formal whole-obligation result differs')
    original=READ(folder/'transcript.json');entries={e['id']:e for e in original}
    require(len(entries)==len(original) and all(e['runId']==run for e in original),'Mixed Recorder originals')
    bodies=decoded_originals(folder,original)
    restored=READ(folder/'restoration.json')
    require(restored['restored'] is restored['temporary_file_removed'] is True
            and restored['original_sha256']==restored['final_sha256']==SHA((folder/'original-providers.xml').read_bytes())
            and (folder/'original-providers.xml').read_bytes()==(folder/'final-providers.xml').read_bytes(),
            'Native filesystem provider not exactly restored')
    configured=(folder/'configured-providers.xml').read_bytes()
    require(configured==(folder/'configured-providers-readback.xml').read_bytes(),'Provider apply read-back differs')
    config=ET.fromstring(configured);native_path='/opt/reference-idp/metadata/algorithm-'+run+'.xml'
    providers=[n for n in config if n.get('metadataFile')==native_path]
    require(len(providers)==1 and providers[0].get('{http://www.w3.org/2001/XMLSchema-instance}type')=='FilesystemMetadataProvider',
            'Native import does not use the original fixture file')
    operations=READ(folder/'operations.json');native_operations=READ(folder/'native-operations.json');counts=READ(folder/'operation-counts.json')
    require({row['variant'] for row in operations}==REQUIRED_FIXTURES|{'control'} and len(operations)==19
            and counts['restored'] is True and counts['human_operations']==counts['product_restarts']==0
            and counts['metadata_fixture_writes']==19 and counts['provider_apply_writes']==counts['restoration_writes']==1
            and counts['reloads']==20 and counts['protocol_roundtrips']==19
            and sum(row['operation']=='write' and row['label'].startswith('fixture-') for row in native_operations)==19
            and all(row.get('completed') is True for row in native_operations if row['operation']=='reload'),
            'Native operation counts differ')
    for variant in ['control',*sorted(REQUIRED_FIXTURES)]:
        child=folder/variant;record=READ(child/'import.json');flow=READ(child/'flow.json')
        fixture=(child/'fixture.xml').read_bytes()
        require(record['product']=='shibboleth' and record['run']==run and record['variant']==variant
                and record['status']=='success' and record['import_path']=='native-filesystem-provider'
                and record['configuration_read_back'] is record['provider_reloaded'] is record['restored'] is True
                and record['fixture_sha256']==SHA(fixture) and fixture==(child/'fixture-readback.xml').read_bytes(),
                'Original fixture import differs: '+variant)
        metadata=ET.fromstring(fixture);prepared=[e for e in original if e['direction']=='OUTBOUND'
            and e.get('samlSummary',{}).get('type')=='MetadataPrepared' and e['samlSummary'].get('variant')==variant]
        require(len(prepared)==1 and bodies[prepared[0]['id']]==fixture,'Prepared Recorder fixture differs: '+variant)
        native=READ(child/'native-effective-sp-metadata-read.json');native_bytes=(child/'native-effective-sp-metadata.xml').read_bytes()
        require(native['container']=='samlscope-reference-shibboleth' and native['runId']==run and native['variant']==variant
                and native['entityId']==entity(metadata).get('entityID')==record['entity_id']
                and native['command']==['/opt/reference-idp/bin/mdquery.sh','-u','http://localhost:8080/idp','-e',record['entity_id']]
                and native['exitCode']==0 and native['sha256']==SHA(native_bytes),'Native effective resolver original differs')
        effective=entity(ET.fromstring(native_bytes));sp=entity(metadata).find(MD+'SPSSODescriptor');actual=effective.find(MD+'SPSSODescriptor')
        require(effective.get('entityID')==entity(metadata).get('entityID') and sp is not None and actual is not None
                and semantic(sp)==semantic(actual),'Native resolver retained a different representation: '+variant)
        require(flow['run']==run and flow['variant']==variant and flow['correlated_success'] is True
                and flow['positive_exchange']['success'] is True and flow['negative_control']['source']=='suite'
                and flow['negative_control']['correlated_success'] is False,'Native controls differ')
    created=READ(folder/'created.json')['run'];_verify_target_runtime(folder,'shibboleth',float(created['createdAt']))
    formal=READ(folder/'formal-mdiop-evaluation.json')
    _verify_suite_runtime(folder,run,parsed_time(formal['startedAt']),LEGACY_PINS)
    archive=folder/'strict-reader-v173';archival=READ(archive/'archival-verification.json')
    _verify_suite_runtime(archive,run,parsed_time(archival['startedAt']),PINS)
    require(archival['sourceFormalResultSha256']==SHA(result_path.read_bytes())
            and archival['sourceTranscriptSha256']==SHA((folder/'transcript.json').read_bytes())
            and archival['productWrites']==archival['productRestarts']==archival['protocolSends']==archival['humanOperations']==0
            and archival['transcriptUnchanged'] is True
            and READ(archive/'evaluation-terminal-http-v1/transcript.json')==original,
            'Strict archival replay changed native originals or operated the product')
    require(formal['runId']==run and formal['transcriptUnchanged'] is True and formal['case']==case
            and READ(folder/'evaluation-terminal-http-v1/transcript-before.json')
            ==READ(folder/'evaluation-terminal-http-v1/transcript.json')==original,'Formal evaluation changed Recorder')
    for ref in case['evidence']:
        require(ref['kind']=='transcript' and ref['reference'].removeprefix('transcript:') in entries,'Case references another source')
    replay(folder)
    return result_path,{CASE:case}


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('root',type=Path);parser.add_argument('--retain-replay',action='store_true')
    args=parser.parse_args()
    if args.retain_replay:
        report=replay(args.root/FOLDER,retain=True);print(report['runId'],report['caseId'],report['productionOutcome'],len(report['controls']),'negative controls')
    else:
        path,cases=verify(args.root);print(path,{name:case['verdict'] for name,case in cases.items()})
