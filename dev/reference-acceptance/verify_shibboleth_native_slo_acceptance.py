#!/usr/bin/env python3
"""Strict adoption of Shibboleth native same-flow SLO failure and all-success control."""
import argparse
import hashlib
import json
from pathlib import Path
import secrets
import subprocess
import tempfile
import xml.etree.ElementTree as ET
import yaml
from verify_terminal_http_acceptance import _verify_target_runtime,_verify_suite_runtime,find_case,parsed_time
from verify_shibboleth_native_ui_acceptance import dependency_classpath

REPO=Path(__file__).resolve().parents[2]
FOLDER='shibboleth-native-slo-v178-r7';CASE='IIP-IDP17-s-idp-01';SUITE='samlscope-reference-suite'
CONTROLS={'proper-partial-logout','wrong-final-destination','wrong-final-correlation','wrong-session-index','wrong-name-format','wrong-name-qualifier','wrong-sp-qualifier',
    'foreign-run-entry','duplicate-entry','foreign-content-reference','wrong-content-size','multiple-origin-processing','missing-final-response','post-logout-authentication','wrong-target',
    'wrong-control-run','wrong-browser-plan','ambient-cookie','wrong-native-scope','mixed-native-flow','missing-participant','wrong-native-session-key','missing-native-source','wrong-native-source',
    'wrong-restoration','missing-readback','late-before-readback','early-after-readback','missing-500-response','failure-before-origin','failure-after-browser','missing-native-json',
    'native-json-failure','missing-suite-reply','wrong-accepted-reply','unknown-http-delivery','wrong-counterexample-signature','incomplete-transcript','non-target-case','asynchronous-origin','forged-native-context'}
# Actual deployed v180 includes the real M3 registry seam; v179 diagnostics remain history.
PINS={'image_id':'sha256:b526bfd1de8562ed17b50241da6a5c73bff368d76a58d3fd0ee602200af4a460','jars':{'core':'1d6e0020c915f50e78902554c06b61916a3f49e50de78d3bc23c6089d312babe','runner':'e11b3be6e6d2c53aa1353670e064753d769cc765a6535a69a514dd0324fd0635','saml':'20981403f9b5125ea5ca5bc25e2a464e37918b88870d930561d69c9d4d71df1c'}}
STORE_SHA256='c4482cd06f9290a3592f0fceac2c9ec2d7603ea0557d1edc885e1c3d51bd8ece'
HELPER='0b0f82ee9412a5a70a8a03b97d34f404ca75c255c899f9e4f2daaebf826ddba0'
STORED_HELPER='f203333f2092832d5ff732c495c3b0e6937f404754d81dd2bb3156dfe311a044'
COVERAGE_SHA256='2bee3db74c9be9908710bbe18935c73454f1ed4c5c0f06bdab1cf18deaef843c'
SHA=lambda raw:hashlib.sha256(raw).hexdigest()
READ=lambda path:json.loads(Path(path).read_text())
def require(value,detail):
    if not value:raise ValueError(detail)
def command(args):return subprocess.run(args,check=True,capture_output=True)

def jars(archive):
    require(PINS is not None,'Actual production pin not finalized')
    runtime=READ(archive/'suite-runtime-terminal-http.json');store=READ(archive/'store-runtime.json')
    result=[archive/runtime['jars'][name]['file'] for name in ['runner','core','saml']]
    require(all(SHA((archive/runtime['jars'][name]['file']).read_bytes())==digest for name,digest in PINS['jars'].items()),'Archived production JAR changed')
    require(SHA((archive/store['file']).read_bytes())==store['sha256']==STORE_SHA256,'Archived Store JAR changed');return result+[archive/store['file']]

def replay(folder,retain=False):
    folder=Path(folder);archive=folder/'reader-v180';receipt=folder/'receipt';helper=archive/'replay-helper.java'
    require(SHA(helper.read_bytes())==HELPER==READ(archive/'replay-helper.json')['sha256'],'Archived SLO helper changed')
    project=jars(archive)
    with tempfile.TemporaryDirectory(prefix='samlscope-native-slo-verify-') as temporary:
        temporary=Path(temporary);source=temporary/'VerifyShibbolethNativeSloEvidence.java';source.write_bytes(helper.read_bytes());classes=temporary/'classes';classes.mkdir()
        dependency=dependency_classpath(archive,retain)
        command(['javac','-cp',':'.join(map(str,project))+':'+dependency,'-d',str(classes),str(source)])
        require(all(path.name.startswith('VerifyShibbolethNativeSloEvidence') for path in classes.rglob('*.class')),'Helper shadows production Reader')
        remote='/tmp/samlscope-native-slo-verify-'+secrets.token_hex(6);uid=command(['docker','exec',SUITE,'id','-u']).stdout.decode().strip()
        command(['docker','exec','--user','0',SUITE,'mkdir',remote])
        try:
            command(['docker','cp',str(receipt),SUITE+':'+remote+'/receipt']);command(['docker','cp',str(classes),SUITE+':'+remote+'/classes'])
            for jar in project:command(['docker','cp',str(jar),SUITE+':'+remote+'/'+jar.name])
            command(['docker','exec','--user','0',SUITE,'chown','-R',uid+':'+uid,remote])
            # Project JARs FIRST: current deployed Runner code never decides historic results.
            classpath=':'.join(remote+'/'+jar.name for jar in project)+':'+remote+'/classes:/opt/samlscope/lib/*'
            executed=subprocess.run(['docker','exec',SUITE,'java','-cp',classpath,'com.samlscope.runner.cases.VerifyShibbolethNativeSloEvidence',remote+'/receipt',remote+'/report.json'],capture_output=True)
            require(executed.returncode==0,'Archived native SLO production replay failed: '+executed.stderr.decode(errors='replace')[-1500:])
            command(['docker','cp',SUITE+':'+remote+'/report.json',str(temporary/'report.json')]);regenerated=(temporary/'report.json').read_bytes()
        finally:command(['docker','exec','--user','0',SUITE,'rm','-rf',remote])
    saved=archive/'production-replay.json'
    if retain:require(not saved.exists(),'Refusing to overwrite production replay');saved.write_bytes(regenerated)
    else:require(saved.read_bytes()==regenerated,'Archived production replay differs')
    result=json.loads(regenerated);require(set(result['controls'])==CONTROLS,'Control inventory changed')
    require(all(value==('SATISFIED' if key=='proper-partial-logout' else 'NOT_VERIFIED') for key,value in result['controls'].items()),'Invalid SLO control accepted')
    require(result['privateCredentialsUsed'] is True and result['privateCredentialsPersisted'] is False and result['productOperations']==0,'Replay performed product operations or persisted credentials')
    return result

def stored_conclusion(archive):
    source=archive/'stored-readback-source.java';original=archive/'stored-case-conclusions.json';provenance=READ(archive/'stored-readback-provenance.json')
    require(SHA(source.read_bytes())==STORED_HELPER==provenance['sourceSha256'] and SHA(original.read_bytes())==provenance['sha256']
        and provenance['readonly'] is True and provenance['caseStateExported'] is provenance['privateCredentialsExported'] is False and provenance['productOperations']==0,'Stored outcome original changed')
    coverage=(archive/'approved-coverage-original.yaml').read_bytes();require(SHA(coverage)==COVERAGE_SHA256,'Approved level original changed')
    def levels(node):
        if isinstance(node,dict):
            if 'key' in node and 'level' in node:yield node['key'],node['level']
            for child in node.values():yield from levels(child)
        elif isinstance(node,list):
            for child in node:yield from levels(child)
    require(dict(levels(yaml.safe_load(coverage)))['IIP-IDP17.s']=='MUST','Central MUST level differs')
    with tempfile.TemporaryDirectory(prefix='samlscope-native-slo-conclusion-') as temporary:
        temporary=Path(temporary);named=temporary/'ReadShibbolethSloStoredConclusion.java';named.write_bytes(source.read_bytes());classes=temporary/'classes';classes.mkdir()
        cp=':'.join(map(str,jars(archive)))+':'+dependency_classpath(archive)
        command(['javac','-cp',cp,'-d',str(classes),str(named)])
        require(all(p.name.startswith('ReadShibbolethSloStoredConclusion') for p in classes.rglob('*.class')),'Stored exporter shadows production')
        executed=command(['java','-cp',cp+':'+str(classes),'com.samlscope.runner.cases.ReadShibbolethSloStoredConclusion','offline',str(original.resolve())])
        require(executed.stdout==original.read_bytes(),'Archived central Evaluator differs')
    return READ(original)

def captured_timestamp(archive, instant):
    """Reproduce the archived exporter's numeric tree conversion exactly, without a tolerance.

    The pre-formal helper used JsonCodec.readTree on a decimal Instant. Its DoubleNode
    cannot retain all nanoseconds. The audit envelope retains the original Instant; this
    round trip proves that it produces exactly the captured value using those archived JARs.
    """
    source='''import com.samlscope.store.JsonCodec;
public final class CanonicalShibbolethStoredTimestamp {
 public static void main(String[] args) throws Exception {
  var mapper=new JsonCodec().mapper();
  var encoded=mapper.writeValueAsBytes(java.time.Instant.parse(args[0]));
  System.out.print(mapper.treeToValue(mapper.readTree(encoded),java.time.Instant.class));
 }
}'''
    with tempfile.TemporaryDirectory(prefix='samlscope-stored-timestamp-') as temporary:
        temporary=Path(temporary);file=temporary/'CanonicalShibbolethStoredTimestamp.java';file.write_text(source)
        cp=':'.join(map(str,jars(archive)))+':'+dependency_classpath(archive)
        command(['javac','-cp',cp,'-d',str(temporary),str(file)])
        require({p.name for p in temporary.glob('*.class')}=={'CanonicalShibbolethStoredTimestamp.class'},'Timestamp helper shadows production')
        return command(['java','-cp',cp+':'+str(temporary),'CanonicalShibbolethStoredTimestamp',instant]).stdout.decode()

def verify(root):
    root=Path(root);folder=root/FOLDER;receipt=folder/'receipt';archive=folder/'reader-v180';manifest=READ(receipt/'manifest.json');run=manifest['runId'];control=manifest['controlRunId']
    require(run!=control and READ(receipt/'failure/created.json')['run']['id']==run and READ(receipt/'all-success/created.json')['run']['id']==control,'Wrong Run pair')
    originals=READ(folder/'receipt-originals.json');require({str(p.relative_to(receipt)):SHA(p.read_bytes()) for p in receipt.rglob('*') if p.is_file()}==originals,'Receipt originals changed')
    require(READ(folder/'receipt-installation.json')==dict(runId=run,readBackMatched=True,files=originals),'Receipt placement not read back')
    require(SHA((receipt/'manifest.json').read_bytes())==originals['manifest.json'],'Manifest changed')
    for file,digest in manifest['originals'].items():require(SHA((receipt/file).read_bytes())==digest,'Original changed '+file)
    for label,expected in [('failure',run),('all-success',control)]:
        transcript=READ(receipt/label/'transcript.json');by_id={entry['id']:entry for entry in transcript}
        require(len(by_id)==len(transcript) and all(e['runId']==expected for e in transcript),'Foreign/duplicate Recorder entry')
        require(READ(receipt/label/'transcript-final.json')==transcript,'Campaign changed transcript during re-evaluation')
        require(SHA((receipt/label/'target-metadata.xml').read_bytes())==manifest['targetMetadataSha256'],'Mixed fixed target metadata')
        for original in READ(receipt/label/'decoded-manifest.json'):
            entry=by_id[original['id']];raw=(receipt/label/original['file']).read_bytes()
            require(entry['decodedSamlRef']=='transcripts/'+expected+'/'+entry['id']+'.saml.xml' and entry['decodedSamlBytes']==len(raw) and SHA(raw)==original['sha256'],'Decoded Recorder original changed')
        browser=READ(receipt/label/'browser-original.json');require(browser['initialCookieCount']==0 and browser['runId']==expected and browser['planId']==manifest['planId'],'Fresh same-Plan native flow missing')
    # Preserve every trial, including native local logout, wrong Redirect endpoint, and failed
    # capture/sanitization attempts. Prepared-only Outbox records do not count as target sends.
    totals={key:0 for key in ['productConfigurationWrites','productReloads','productRestarts','humanOperations','outboundRecordedMessages','preparedAndSkippedMessages','outboundProtocolMessages']}
    trials=[root/('shibboleth-native-slo-v177-r'+str(i)) for i in range(1,7)]+[folder]
    for trial in trials:
        restoration=READ(trial/'restoration.json');operations=READ(trial/'operations.json');counts=READ(trial/'operation-counts-corrected.json')
        require(restoration['restored'] is True and restoration['temporaryRemoved'] is True and all(row['unchanged'] for row in restoration['configurationFiles'])
            and (trial/'original-providers.xml').read_bytes()==(trial/'final-providers.xml').read_bytes(),'Attempt restoration incomplete')
        require(counts['previousOperationCountsSha256']==SHA((trial/'operation-counts.json').read_bytes()),'Original counts correction changed')
        require(counts['productConfigurationWrites']==sum(r['operation']=='write' for r in operations) and counts['productReloads']==sum(r['operation']=='reload' for r in operations)
            and counts['productRestarts']==counts['humanOperations']==0,'Product operation counts differ')
        recorded=prepared=0
        for label in ['failure','all-success']:
            unsent={r['actionId'] for r in READ(trial/label/'skipped.json') if r.get('prepared') is True and r.get('sentToTarget') is False}
            for entry in READ(trial/label/'transcript.json'):
                if entry['direction']=='OUTBOUND' and entry.get('samlSummary',{}).get('type') in ['AuthnRequest','LogoutRequest','LogoutResponse']:
                    recorded+=1;prepared+=entry['samlSummary'].get('action_id') in unsent
        require((counts['outboundRecordedMessages'],counts['preparedAndSkippedMessages'],counts['outboundProtocolMessages'])==(recorded,prepared,recorded-prepared),'Prepared/actual send counts differ')
        for key in totals:totals[key]+=counts[key]
        _verify_target_runtime(trial,'shibboleth',float(READ(trial/'failure/created.json')['run']['createdAt']))
    require(READ(root/'shibboleth-native-slo-operation-summary.json')['totals']==totals,'Operation summary lost a failed attempt')
    formal=READ(archive/'formal-native-slo-evaluation.json');result_path=archive/'evaluation-terminal-http-v1/result.json';result=READ(result_path)
    require(formal['runId']==run and formal['transcriptUnchanged'] is True and formal['productWrites']==formal['productRestarts']==formal['protocolSends']==formal['humanOperations']==0,'Formal performed product operations')
    require(READ(archive/'evaluation-terminal-http-v1/transcript-before.json')==READ(archive/'evaluation-terminal-http-v1/transcript.json')==READ(receipt/'failure/transcript.json'),'Formal changed transcript')
    _verify_suite_runtime(archive,run,parsed_time(formal['startedAt']),PINS)
    case=find_case(result,CASE);require(result['run']['id']==run and result['target']['metadata_digest']=='sha256:'+manifest['targetMetadataSha256'],'Formal Run/target mismatch')
    require(case==formal['case'] and case['attested'] is False and case['verdict']=='FAIL' and case['outcome']=='VIOLATED','Wrong formal outcome/verdict')
    replayed=replay(folder);actual=replayed['outcome'];require(replayed['runId']==run and actual['outcome']==case['outcome'] and actual['reasonCode']==case['reason_code'] and actual['evidence']==case['evidence'],'Formal differs from archived Reader')
    stored=stored_conclusion(archive);require(stored['runId']==run and set(stored['cases'])=={CASE},'Stored outcome mixed')
    observed=dict(stored['cases'][CASE]['outcome']);details=dict(observed['details']);previous=details.pop('previous_recorded_evidence_result',None)
    prior=READ(archive/'previous-stored-case-conclusions.json');old=prior['cases'][CASE];old_outcome=old['outcome']
    require(prior['runId']==run and old['verdict']=='NOT_VERIFIED' and old_outcome['outcome']=='NOT_VERIFIED'
        and previous is not None and set(previous)=={'revision','updated_at','outcome','not_verified_reason','reason_code','reason_message_key','evidence','details'}
        and previous['revision']==old['revision'] and captured_timestamp(archive,previous['updated_at'])==old['updatedAt']
        and all(previous[left]==old_outcome[right] for left,right in [('outcome','outcome'),('not_verified_reason','notVerifiedReason'),('reason_code','reasonCode'),
            ('reason_message_key','reasonMessageKey'),('evidence','evidence'),('details','details')])
        and parsed_time(result['run']['started_at'])<=parsed_time(previous['updated_at'])<parsed_time(formal['startedAt']),'Prior NV audit envelope differs from captured CaseOutcome')
    observed['details']=details;require(observed==actual and stored['cases'][CASE]['verdict']==case['verdict'],'Stored CaseOutcome/central verdict differs')
    return result_path,{CASE:case}

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('root',type=Path);parser.add_argument('--retain-replay',action='store_true');args=parser.parse_args()
    if args.retain_replay:print(replay(args.root/FOLDER,True)['runId'],'archived production controls passed')
    else:
        path,cases=verify(args.root);print(path,{id:case['verdict'] for id,case in cases.items()})
