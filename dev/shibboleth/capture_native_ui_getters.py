#!/usr/bin/env python3
"""Capture pinned native getter stdout from public native-effective metadata originals.

Supplemental only: adoption also requires each actual signed SAML request, fresh native
challenge, native rendered view and unchanged settings. This helper modifies no settings.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

CONTAINER='samlscope-reference-shibboleth'
SHA=lambda raw:hashlib.sha256(raw).hexdigest()
JAR='/usr/local/tomcat/webapps/idp/WEB-INF/lib/idp-ui-5.2.3.jar'
CLASS='net/shibboleth/idp/ui/context/RelyingPartyUIContext.class'


def capture(folder,revision='v1'):
    if revision not in {'v1','v2','v3'}:raise ValueError('Unsupported getter capture revision')
    prefix='native-getter' if revision=='v1' else 'native-getter-'+revision
    folder=Path(folder).resolve();destination=folder/(prefix+'-stdout.txt')
    if destination.exists():raise ValueError('Refusing to overwrite native stdout')
    operations=[];temporary=None
    run=json.loads((folder/'created.json').read_text())['run']['id']
    source=Path(__file__).with_name('NativeUiConsumerValues.java').read_bytes()
    (folder/(prefix+'-source.java')).write_bytes(source)
    command=lambda *args:subprocess.check_output(['docker','exec',CONTAINER,*args],timeout=90)
    native_before=command('unzip','-p',JAR,CLASS);(folder/(prefix+'-before.class')).write_bytes(native_before)
    try:
        temporary=command('mktemp','-d','/tmp/samlscope-ui-public-XXXXXXXX').decode().strip()
        if not temporary.startswith('/tmp/samlscope-ui-public-') or not temporary[len('/tmp/'):].replace('-','').isalnum():raise ValueError('Unsafe temporary path')
        with tempfile.TemporaryDirectory(prefix='samlscope-public-ui-') as local:
            local=Path(local);(local/'NativeUiConsumerValues.java').write_bytes(source)
            for row in json.loads((folder/'observations.json').read_text()):
                name=row['variant'];child=local/name;child.mkdir()
                raw=(folder/name/'native-effective-metadata.xml').read_bytes()
                if SHA(raw)!=row['nativeMetadataSha256']:raise ValueError('Changed native metadata original')
                (child/'native-effective-metadata.xml').write_bytes(raw)
            subprocess.run(['docker','cp',str(local)+'/.',CONTAINER+':'+temporary],check=True,capture_output=True)
        cp='/usr/local/tomcat/webapps/idp/WEB-INF/lib/*'
        (folder/(prefix+'-compiler-version.txt')).write_bytes(command('javac','-version'))
        compiled=subprocess.run(['docker','exec',CONTAINER,'javac','-cp',cp,'-d',temporary,temporary+'/NativeUiConsumerValues.java'],capture_output=True,timeout=90)
        (folder/(prefix+'-compile.stdout')).write_bytes(compiled.stdout)
        (folder/(prefix+'-compile.stderr')).write_bytes(compiled.stderr)
        operations.append(dict(operation='compile-public-native-getter',exitCode=compiled.returncode))
        if compiled.returncode:
            raise RuntimeError('Native getter compilation failed')
        (folder/(prefix+'-compiled.class')).write_bytes(command('cat',temporary+'/NativeUiConsumerValues.class'))
        executed=subprocess.run(['docker','exec',CONTAINER,'java','-cp',temporary+':'+cp,'NativeUiConsumerValues',temporary],capture_output=True,timeout=90)
        operations.append(dict(operation='native-getter-read',exitCode=executed.returncode))
        # The only input is public fixture XML. Full native stdout remains an original;
        # it never processes environment secrets, private keys or login form values.
        destination.write_bytes(executed.stdout)
        if executed.returncode:
            (folder/(prefix+'-stderr')).write_bytes(executed.stderr);raise RuntimeError('Native getter execution failed')
        rows=[]
        for line in executed.stdout.decode().splitlines():
            if not line.startswith('SAMLSCOPE_NATIVE_UI\t'):continue
            _,variant,digest,name,logo,jar_hash=line.split('\t')
            rows.append(dict(runId=run,variant=variant,nativeMetadataSha256=digest,serviceName=name,logo=logo,nativeJarSha256=jar_hash))
        expected={row['variant'] for row in json.loads((folder/'observations.json').read_text())}
        if len(rows)!=len(expected) or {row['variant'] for row in rows}!=expected:raise RuntimeError('Incomplete native getter output')
        for row in rows:
            part=folder/row['variant'];(part/('native-values.json' if revision=='v1' else 'native-values-'+revision+'.json')).write_text(json.dumps(row,indent=2)+'\n')
        (folder/(prefix+'-output.json')).write_text(json.dumps(dict(runId=run,rows=rows,sourceSha256=SHA(source),stdoutSha256=SHA(executed.stdout)),indent=2)+'\n')
        return rows
    finally:
        if temporary:
            result=subprocess.run(['docker','exec',CONTAINER,'rm','-rf','--',temporary],capture_output=True)
            operations.append(dict(operation='delete-public-getter-temporary',exitCode=result.returncode))
            if result.returncode:raise RuntimeError('Native public getter cleanup failed')
        native_after=command('unzip','-p',JAR,CLASS);(folder/(prefix+'-after.class')).write_bytes(native_after)
        (folder/(prefix+'-operations.json')).write_text(json.dumps(dict(operations=operations,
            sourceUnchanged=native_before==native_after,productConfigurationWrites=0,productRestarts=0,humanOperations=0),indent=2)+'\n')
        if native_after!=native_before:raise RuntimeError('Native consumer class changed')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--evidence',type=Path,required=True)
    parser.add_argument('--revision',choices=['v1','v2','v3'],default='v1');args=parser.parse_args()
    capture(args.evidence,args.revision)
