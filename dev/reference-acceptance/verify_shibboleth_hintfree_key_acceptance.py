#!/usr/bin/env python3
"""Adopt the selected native hint-free representation pair through an archived Reader."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

from export_shibboleth_metadata_key_receipt import export
from verify_metadata_key_acceptance import CONTROLS
from verify_shibboleth_metadata_refresh_acceptance import decoded_originals
from verify_shibboleth_persistent_pairwise_acceptance import runtime_classpath
from verify_terminal_http_acceptance import _verify_suite_runtime,find_case,parsed_time

REPO=Path(__file__).resolve().parents[2]
FOLDER='shibboleth-hintfree-keys-v172-r2'
CASE='IIP-MD05-cd-idp-01'
PINS={'image_id': 'sha256:26bf9614c251e750b85d7c0c51543abd010f6ec36fdbb26a8b8aa53a5cf78dff', 'jars': {'core': '1d6e0020c915f50e78902554c06b61916a3f49e50de78d3bc23c6089d312babe', 'runner': 'f4d841508e04679a85f3ded38bfed7c327ae210efceb3e7b01bf13973bd36c5c', 'saml': '5d4e309378ebbb835f99e16d17eeff5221302146822df6809ce751093544a228'}}
HELPER_SHA256='e27adcba28bf734eaa4d5e0e8444aca6c045bb44b3d8359f613855b3e598b2dc'
STORE_SHA256='c4482cd06f9290a3592f0fceac2c9ec2d7603ea0557d1edc885e1c3d51bd8ece'
SOURCE_RECEIPT_SHA256='852b352c3a48f8885f1a99b9e904414050aa9329c49b22cc435fa1310bde92e3'
SHA=lambda raw:hashlib.sha256(raw).hexdigest()
READ=lambda path:json.loads(Path(path).read_text())


def require(value,detail):
    if not value:raise ValueError(detail)


def replay(folder,retain=False):
    folder=Path(folder);child=folder/'metadata_idp';runtime=READ(child/'suite-runtime-terminal-http.json');store=READ(child/'store-runtime.json')
    helper=folder/'replay-helper-original.java';provenance=READ(folder/'replay-helper-original.json')
    require(SHA(helper.read_bytes())==HELPER_SHA256==provenance['sha256'] and provenance['file']==helper.name,'Archived helper changed')
    jars=[child/runtime['jars'][name]['file'] for name in ('runner','core','saml')]
    require(all(SHA((child/runtime['jars'][name]['file']).read_bytes())==digest for name,digest in PINS['jars'].items())
            and store['path']=='/opt/samlscope/lib/store-0.1.0.jar' and SHA((child/store['file']).read_bytes())==store['sha256']==STORE_SHA256,'Archived production JAR changed')
    jars.append(child/store['file'])
    with tempfile.TemporaryDirectory(prefix='samlscope-shib-hintfree-replay-') as temporary:
        temp=Path(temporary);named=temp/'VerifyShibbolethHintFreeKeyEvidence.java';named.write_bytes(helper.read_bytes())
        classes=temp/'classes';classes.mkdir();dependencies=runtime_classpath()
        subprocess.run(['javac','-cp',':'.join(map(str,jars))+':'+dependencies,'-d',str(classes),str(named)],check=True,capture_output=True)
        require(all(p.name.startswith('VerifyShibbolethHintFreeKeyEvidence') for p in classes.rglob('*.class')),'Helper would shadow production Reader')
        report=temp/'report.json';result=subprocess.run(['java','-cp',':'.join(map(str,jars))+':'+str(classes)+':'+dependencies,
            'com.samlscope.runner.cases.VerifyShibbolethHintFreeKeyEvidence',str(child.resolve()),str(report)],capture_output=True)
        require(result.returncode==0,'Archived actual Reader replay failed: '+result.stderr.decode(errors='replace')[-2000:])
        regenerated=report.read_bytes()
    retained=folder/'production-replay-v173.json'
    if retain:
        require(not retained.exists(),'Refusing to replace historical replay');retained.write_bytes(regenerated)
    else:require(regenerated==retained.read_bytes(),'Actual archived Reader replay differs')
    parsed=json.loads(regenerated);observed=parsed['production_comparison'][CASE]
    require(parsed['qualified_cases']==[CASE] and parsed['receipt_sha256']==SOURCE_RECEIPT_SHA256
            and parsed['transcript_sha256']==SHA((child/'transcript.json').read_bytes())
            and observed['outcome']=='SATISFIED' and observed['reasonCode']=='metadata.keys.selection-observed'
            and observed['details']['missing_variants']==observed['details']['evidence_issues']==[]
            and set(parsed['negative_controls'])=={CASE+':'+name for name in CONTROLS}
            and set(parsed['negative_controls'].values())=={'NOT_VERIFIED'},'Hint-free controls incomplete')
    return parsed


def verify(root):
    folder=Path(root)/FOLDER;child=folder/'metadata_idp';raw=(child/'qualified-metadata-key-receipt.json').read_bytes();receipt=json.loads(raw)
    require(SHA(raw)==SOURCE_RECEIPT_SHA256 and export(child.resolve())==receipt,'Native original export changed')
    matrix=READ(folder/'matrix.json');variants={'control','entity-root','keyvalue-only'}
    require(matrix['matrix']=='keys' and matrix['variants']==['control','entity-root','keyvalue-only']
            and {r['variant'] for r in receipt['conditions']}==variants-{'control'},'Native selected group differs')
    entries=READ(child/'transcript.json');decoded_originals(child,entries)
    requests={e['samlSummary'].get('id') for e in entries if e['direction']=='OUTBOUND'
            and e['samlSummary'].get('type')=='AuthnRequest'}
    audit=READ(child/'native-signature-audit.json')
    require(len(requests)==6 and len(audit['rows'])==6
            and {r['request_id'] for r in audit['rows']}==requests and audit['run']==receipt['runId'],
            'Native grouped actual sends/audit correlation differs')
    require(receipt['runId']==READ(child/'created.json')['run']['id'] and receipt['evidenceAdapter']=='shibboleth-audit'
            and receipt['restored'] is True and not any(i['variant'] in variants for i in receipt['conditionIssues']),
            'Required native conditions missing')
    for base in (folder,child):
        restoration=READ(base/'restoration.json')
        require(restoration['restored'] is True and restoration['original_sha256']==restoration['final_sha256'],'Historical native restoration differs')
    from signature_audit_format import signature_audit,FORMAT
    require((folder/'original-audit.xml').read_bytes()==(folder/'final-audit.xml').read_bytes()
            and signature_audit((folder/'original-audit.xml').read_bytes())==(folder/'configured-audit.xml').read_bytes()
            and receipt['auditFormat']==FORMAT,'Native audit restoration/observer source differs')
    require((child/'original-providers.xml').read_bytes()==(child/'final-providers.xml').read_bytes(),
            'Native provider byte restoration differs')
    outer=READ(folder/'operation-counts.json');inner=READ(child/'operation-counts.json')
    require(outer['human_operations']==inner['human_operations']==0 and outer['product_restarts']==2
            and outer['configuration_write_attempts']==2 and inner['metadata_fixture_writes']==3
            and inner['provider_apply_writes']==inner['restoration_writes']==1 and inner['reloads']==4
            and inner['product_restarts']==0 and inner['protocol_roundtrips']==3,'Native grouped operation counts differ')
    for variant in variants:
        flow=READ(child/variant/'flow.json');imported=READ(child/variant/'import.json')
        require(flow['correlated_success'] is True and flow['positive_exchange']['success'] is True
                and flow['negative_control']['source']=='suite' and flow['negative_control']['correlated_success'] is False
                and imported['configuration_read_back'] is imported['provider_reloaded'] is imported['restored'] is True
                and SHA((child/variant/'fixture.xml').read_bytes())==imported['fixture_sha256'],
                'Native grouped fixture/control incomplete: '+variant)
    installation=READ(folder/'receipt-placement-readback.json')
    require(installation['runId']==receipt['runId'] and installation['sha256']==SHA(raw) and installation['readBackMatched'] is True,'Receipt placement changed')
    formal=READ(child/'formal-hintfree-key-evaluation.json');_verify_suite_runtime(child,receipt['runId'],parsed_time(formal['startedAt']),PINS)
    evaluation=child/'evaluation-terminal-http-v1';result_path=evaluation/'result.json';result=READ(result_path);case=find_case(result,CASE)
    require((case['outcome'],case['verdict'],case['reason_code'],case['attested'])==('SATISFIED','PASS','metadata.keys.selection-observed',False)
            and formal['case']==case and formal['runId']==receipt['runId'] and formal['transcriptUnchanged'] is True
            and READ(evaluation/'transcript-before.json')==READ(evaluation/'transcript.json')==entries,'Formal original result differs')
    proof=replay(folder);observed=proof['production_comparison'][CASE]
    require({(r['kind'],r['reference']) for r in observed['evidence']}=={(r['kind'],r['reference']) for r in case['evidence']},'Formal reference set differs')
    return result_path,{CASE:case}


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('root',type=Path);parser.add_argument('--retain-replay',action='store_true')
    args=parser.parse_args()
    if args.retain_replay:
        report=replay(args.root/FOLDER,retain=True);print(report['run'],report['qualified_cases'],len(report['negative_controls']),'negative controls')
    else:
        path,cases=verify(args.root);print(path,{name:case['verdict'] for name,case in cases.items()})
