"""Narrow original read-back of public CaseOutcome; no CaseState or database export."""
import hashlib,json,subprocess,tempfile
from pathlib import Path
HELPER='ReadSimpleSamlPhpUiStoredConclusions'
sha=lambda raw:hashlib.sha256(raw).hexdigest()
def capture(folder,runtime_name,name,run,case):
    folder=Path(folder);runtime=folder/runtime_name;output=folder/name
    if output.exists():raise ValueError('Stored public outcome original is immutable')
    source=Path(__file__).with_name(HELPER+'.java').read_bytes();cp=':'.join(str((runtime/(n+'.jar')).resolve()) for n in ['runner','core','saml','store'])+':'+Path('/private/tmp/samlscope-runner-runtime-classpath.txt').read_text().strip()
    with tempfile.TemporaryDirectory(prefix='ssp-ui-stored-readback-') as name:
        temporary=Path(name);src=temporary/(HELPER+'.java');src.write_bytes(source);classes=temporary/'classes'
        subprocess.run(['javac','-sourcepath','','-cp',cp,'-d',str(classes),str(src)],check=True,capture_output=True)
        if not all(p.name.startswith(HELPER) for p in classes.rglob('*.class')):raise ValueError('Readback helper shadows production')
        remote='/tmp/'+temporary.name
        subprocess.run(['docker','exec','samlscope-reference-suite','mkdir','-p',remote],check=True,capture_output=True)
        try:
            subprocess.run(['docker','cp',str(classes),'samlscope-reference-suite:'+remote+'/classes'],check=True,capture_output=True)
            raw=subprocess.check_output(['docker','exec','samlscope-reference-suite','java','-cp',remote+'/classes:/opt/samlscope/lib/*','com.samlscope.runner.cases.'+HELPER,'capture',run,case],timeout=30)
        finally:subprocess.run(['docker','exec','--user','0','samlscope-reference-suite','rm','-rf',remote],check=True,capture_output=True)
    value=json.loads(raw)
    if value['runId']!=run or set(value['cases'])!={case}:raise ValueError('Stored readback selected foreign conclusion')
    output.write_bytes(raw);(output.with_suffix('.source.java')).write_bytes(source)
    output.with_suffix('.provenance.json').write_text(json.dumps(dict(sourceSha256=sha(source),sha256=sha(raw),readonly=True,selectedCases=[case],caseStateExported=False,privateCredentialsExported=False,productOperations=0,suiteHelperPlacements=1),indent=2)+'\n')
    return value

def verify(folder,runtime_name,name,run,case):
    folder=Path(folder);runtime=folder/runtime_name;original=folder/name;source=original.with_suffix('.source.java');proof=json.loads(original.with_suffix('.provenance.json').read_bytes());value=json.loads(original.read_bytes())
    if proof!=dict(sourceSha256=sha(source.read_bytes()),sha256=sha(original.read_bytes()),readonly=True,selectedCases=[case],caseStateExported=False,privateCredentialsExported=False,productOperations=0,suiteHelperPlacements=1):raise ValueError('Stored readback provenance changed')
    cp=':'.join(str((runtime/(n+'.jar')).resolve()) for n in ['runner','core','saml','store'])+':'+Path('/private/tmp/samlscope-runner-runtime-classpath.txt').read_text().strip()
    with tempfile.TemporaryDirectory(prefix='ssp-ui-stored-offline-') as name:
        temporary=Path(name);src=temporary/(HELPER+'.java');src.write_bytes(source.read_bytes());classes=temporary/'classes'
        subprocess.run(['javac','-sourcepath','','-cp',cp,'-d',str(classes),str(src)],check=True,capture_output=True)
        if not all(p.name.startswith(HELPER) for p in classes.rglob('*.class')):raise ValueError('Readback helper shadows production')
        raw=subprocess.check_output(['java','-cp',str(classes)+':'+cp,'com.samlscope.runner.cases.'+HELPER,'offline',str(original.resolve())],timeout=30)
    if json.loads(raw)!=value or value['runId']!=run or set(value['cases'])!={case}:raise ValueError('Archived central Evaluator disagrees with stored original')
    return value['cases'][case]

def compare_stored(folder,runtime_name,case,proof,before_name='evaluation/stored-before.json',after_name='evaluation/stored-after.json'):
    folder=Path(folder);run=json.loads((folder/'created.json').read_bytes())['run']['id'];before=verify(folder,runtime_name,before_name,run,case);after=verify(folder,runtime_name,after_name,run,case)
    if after['status']!='FINISHED' or before['outboxCount']!=after['outboxCount']:raise ValueError('Native formal completion manufactured a browser action')
    outcome=dict(after['outcome']);details=dict(outcome['details']);previous=details.pop('previous_recorded_evidence_result',None)
    if previous is not None:
        old=before['outcome']
        if set(previous)!={'revision','updated_at','outcome','not_verified_reason','reason_code','reason_message_key','evidence','details'} or previous['revision']!=before['revision'] or old is None:raise ValueError('Invalid previous-result audit envelope')
        if {k:previous[k] for k in ['outcome','not_verified_reason','reason_code','reason_message_key','evidence','details']}!=dict(outcome=old['outcome'],not_verified_reason=old['notVerifiedReason'],reason_code=old['reasonCode'],reason_message_key=old['reasonMessageKey'],evidence=old['evidence'],details=old['details']):raise ValueError('Prior outcome audit envelope changed')
    outcome['details']=details
    if outcome!=proof:raise ValueError('Stored production CaseOutcome differs from archived Reader')
    return after
