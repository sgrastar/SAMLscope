#!/usr/bin/env python3
"""Execute public selector control inputs; keep all outputs diagnostic and out of Recorder."""
import argparse, base64, hashlib, json, pathlib, secrets, subprocess
from metadata_application_selection import CONTAINER, SOURCE as STOCK_SOURCE, NOW, SHA, save, inspect
SOURCE = pathlib.Path(__file__).with_name('ShibbolethMetadataApplicationCalibration.java')
MODES = ('stock-native-consumer', 'drop-accepted-b-secondary-acs', 'retain-conflicting-old-a-acs')
def call(args):
    return subprocess.run(args, capture_output=True, timeout=60)
def checked(args):
    result = call(args)
    if result.returncode: raise RuntimeError('Public diagnostic operation failed')
    return result
def capture(folder, output):
    folder, output = folder.absolute(), output.absolute()
    assert not output.exists() and not any(p.is_symlink() for p in [folder, output, *folder.parents, *output.parents])
    receipt = folder/'receipt'; manifest = json.loads((receipt/'manifest.json').read_bytes())
    assert json.loads((receipt/'restoration.json').read_bytes())['restored'] is True
    stock = (receipt/'native-selection-input.json').read_bytes()
    epoch = json.loads((receipt/'native-originals/control-before.json').read_bytes())
    old = (receipt/'native'/epoch['cacheFile']).read_bytes()
    assert SHA(old) == epoch['cacheSha256'] and SHA(STOCK_SOURCE.read_bytes()) == '752445cbb28082a252d8903a9ca58b9c6fdc0253cb8562f7b874164fd0973883'
    output.mkdir(); (output/'calibration-source.java').write_bytes(SOURCE.read_bytes()); (output/'stock-source.java').write_bytes(STOCK_SOURCE.read_bytes())
    (output/'logback.xml').write_bytes(b'<configuration><root level="OFF"/></configuration>\n')
    for mode in MODES:
        save(output/(mode+'.input.json'), dict(schema='samlscope-native-metadata-application-calibration-input-v1',
          purpose='public-native-consumer-calibration-only', selectedConsumer=mode, runId=manifest['runId'],
          stockSelectionInputBase64=base64.b64encode(stock).decode(), stockSelectionInputSha256=SHA(stock),
          oldMetadataBase64=base64.b64encode(old).decode(), oldMetadataSha256=SHA(old)))
    temp='/tmp/shib-application-calibration-'+secrets.token_hex(6)
    native_paths=['/usr/local/tomcat/webapps/idp/WEB-INF/lib/'+name+'-5.2.3.jar' for name in ('idp-conf-impl','idp-saml-impl','opensaml-saml-impl','opensaml-saml-api')]
    before=inspect(); commands=[]; compiler=java=0; removed=False
    def native(*args):return checked(['docker','exec',CONTAINER,*args])
    def operation(command, kind, prefix):
        started=NOW(); result=call(command)
        (output/(prefix+'.stdout')).write_bytes(result.stdout); (output/(prefix+'.stderr')).write_bytes(result.stderr)
        row=dict(operation=kind,command=command,startedAt=started,completedAt=NOW(),exitCode=result.returncode,
                 stdoutSha256=SHA(result.stdout),stderrSha256=SHA(result.stderr))
        commands.append(row)
        if result.returncode:raise RuntimeError('Public diagnostic operation failed; preserved diagnostic output')
        return result,row
    try:
        raw=native('sha256sum',*native_paths).stdout; (output/'native-jars-before.sha256').write_bytes(raw)
        native('mkdir',temp)
        names={'calibration-source.java':SOURCE.name,'stock-source.java':STOCK_SOURCE.name,'logback.xml':'logback.xml'}
        names.update({mode+'.input.json':mode+'.input.json' for mode in MODES})
        for local,remote in names.items():checked(['docker','cp',str(output/local),CONTAINER+':'+temp+'/'+remote])
        compiler+=1
        operation(['docker','exec',CONTAINER,'javac','-cp','/usr/local/tomcat/webapps/idp/WEB-INF/lib/*','-d',temp,temp+'/'+STOCK_SOURCE.name,temp+'/'+SOURCE.name],'native-public-compile','compile')
        for mode in MODES:
            java+=1
            command=['docker','exec',CONTAINER,'java','-Dlogback.configurationFile='+temp+'/logback.xml','-cp',temp+':/usr/local/tomcat/webapps/idp/WEB-INF/lib/*',SOURCE.stem,temp+'/'+mode+'.input.json',temp+'/'+SOURCE.name,temp+'/'+STOCK_SOURCE.name]
            result,row=operation(command,'native-public-java',mode)
            (output/(mode+'.output.json')).write_bytes(result.stdout)
            save(output/(mode+'.invocation.json'),dict(schema='samlscope-native-metadata-application-calibration-invocation-v1',
              purpose='public-native-consumer-calibration-only',selectedConsumer=mode,sourceSha256=SHA(SOURCE.read_bytes()),
              stockSourceSha256=SHA(STOCK_SOURCE.read_bytes()),inputSha256=SHA((output/(mode+'.input.json')).read_bytes()),
              outputSha256=SHA(result.stdout),**row))
        after=native('sha256sum',*native_paths).stdout; (output/'native-jars-after.sha256').write_bytes(after)
        assert raw==after and before==inspect()
    finally:
        native('rm','-rf',temp); removed=True
        save(output/'operations.json',dict(commands=commands,nativeContainerBefore=before,nativeContainerAfter=inspect(),
          nativeCompilerCalls=compiler,nativePublicJavaCalls=java,temporarySourceRemoved=removed,
          productSettings=0,protocolOperations=0,credentialPosts=0,productRestarts=0,personOperations=0))
    return output
if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__); p.add_argument('folder',type=pathlib.Path); p.add_argument('output',type=pathlib.Path)
    a=p.parse_args(); print(capture(a.folder,a.output))
