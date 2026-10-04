#!/usr/bin/env python3
"""Two genuine native OpenSAML model executions; diagnostic controls are never installed."""
import argparse,datetime,hashlib,json,pathlib,secrets,subprocess,sys
REPO=pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0,str(REPO/'dev/shibboleth'))
from full_ui_metadata_campaign import runtime,CONTAINER
SHA=lambda b:hashlib.sha256(b).hexdigest()
NOW=lambda:datetime.datetime.now(datetime.timezone.utc).isoformat()
def save(path,value):path.write_text(json.dumps(value,indent=2)+'\n')
def command(args,data=None):return subprocess.run(args,input=data,capture_output=True,timeout=60,check=True)
def calibrate(folder):
    folder=pathlib.Path(folder).resolve();out=folder/'calibration';out.mkdir(exist_ok=False)
    manifest=json.loads((folder/'receipt/manifest.json').read_bytes());run=manifest['runId']
    source=REPO/'dev/shibboleth/FullUiNativeModelControl.java';raw=source.read_bytes()
    if SHA(raw)!='a59228b9daabf838ca5975c1ffcc6f8cd74a72bb2ef7c11308d838c18796639a':raise ValueError('Native detector source changed')
    original=folder/'receipt/full-ui-info-native-output.xml';before=runtime()
    prefix='/tmp/full-ui-native-model-'+secrets.token_hex(6);ops=[];nativecp=prefix+':/usr/local/tomcat/webapps/idp/WEB-INF/lib/*'
    (out/'FullUiNativeModelControl.java').write_bytes(raw);(out/'input.xml').write_bytes(original.read_bytes())
    # Isolated model JVM only: route OpenSAML diagnostics away from its XML stdout.
    # This file is copied and hashed as a diagnostic logging configuration, not a
    # product renderer/MetadataResolver setting.
    logging=b'<configuration><appender name="STDERR" class="ch.qos.logback.core.ConsoleAppender"><target>System.err</target><encoder><pattern>%level %logger - %msg%n</pattern></encoder></appender><root level="WARN"><appender-ref ref="STDERR"/></root></configuration>'
    (out/'logback.xml').write_bytes(logging)
    command(['docker','exec',CONTAINER,'mkdir',prefix])
    try:
        for name in ['FullUiNativeModelControl.java','input.xml','logback.xml']:command(['docker','cp',str(out/name),CONTAINER+':'+prefix+'/'+name])
        compilation=['javac','-cp','/usr/local/tomcat/webapps/idp/WEB-INF/lib/*','-d',prefix,prefix+'/FullUiNativeModelControl.java']
        started=NOW();r=command(['docker','exec',CONTAINER,*compilation]);finished=NOW()
        (out/'compiler-stdout.txt').write_bytes(r.stdout);(out/'compiler-stderr.txt').write_bytes(r.stderr)
        compiler=dict(command=compilation,producerSha256=SHA(raw),exitCode=r.returncode,startedAt=started,finishedAt=finished)
        for mode in ['stock','ignore-full-ui']:
            argv=['java','-cp',nativecp,'FullUiNativeModelControl',mode,prefix+'/input.xml'];started=NOW()
            r=command(['docker','exec',CONTAINER,*argv]);finished=NOW()
            (out/(mode+'-output.xml')).write_bytes(r.stdout);(out/(mode+'-stderr.txt')).write_bytes(r.stderr)
            ops.append(dict(mode=mode,command=argv,exitCode=r.returncode,inputSha256=SHA(original.read_bytes()),
                outputSha256=SHA(r.stdout),producerSha256=SHA(raw),startedAt=started,finishedAt=finished,
                stderrFile=mode+'-stderr.txt',stderrSha256=SHA(r.stderr)))
    finally:command(['docker','exec',CONTAINER,'rm','-rf',prefix])
    after=runtime()
    if before!=after:raise ValueError('Native detector runtime changed')
    save(out/'operations.json',dict(schema='samlscope-full-ui-model-calibration-v1',runId=run,counterfactualCalibrationOnly=True,
        compiler=compiler,invocations=ops,nativeRuntimeBefore=before,nativeRuntimeAfter=after,
        isolatedLoggingConfigFile='logback.xml',isolatedLoggingConfigSha256=SHA(logging),productLoggingChanged=False,
        nativeCompilations=1,nativeModelExecutions=2,productSettings=0,saml=0,credentials=0,personOperations=0,controlsAdopted=False))
    selected=['FullUiNativeModelControl.java','input.xml','stock-output.xml','ignore-full-ui-output.xml','operations.json','stock-stderr.txt','ignore-full-ui-stderr.txt','logback.xml']
    save(out/'receipt-calibration.json',dict(calibration=dict(counterfactualCalibrationOnly=True,inputFile='input.xml',
        stockOutputFile='stock-output.xml',mutantOutputFile='ignore-full-ui-output.xml',operationsFile='operations.json',
        producerFile='FullUiNativeModelControl.java',producerSha256=SHA(raw)),files={n:SHA((out/n).read_bytes()) for n in selected}))
    print(run,'native whole-extension-ignore control complete; no product finding')
if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('campaign',type=pathlib.Path);calibrate(p.parse_args().campaign)
