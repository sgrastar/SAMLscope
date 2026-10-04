#!/usr/bin/env python3
"""Bind one current original native campaign to isolated producer/selected-form evidence."""
import argparse, datetime, hashlib, json, pathlib, secrets, shutil, subprocess, tempfile
REPO=pathlib.Path(__file__).resolve().parents[2]
NATIVE='samlscope-reference-keycloak'
HELPER='ProbeKeycloakForceAuthnMechanism'
sha=lambda raw:hashlib.sha256(raw).hexdigest()
load=lambda p:json.loads(p.read_bytes())
def require(value,why):
    if not value:raise ValueError(why)
def command(args):return subprocess.run([str(a) for a in args],check=True,capture_output=True,timeout=90)
def native_probe(folder,prefix="native"):
    inventory=(folder/'originals/before.native-classpath.txt').read_bytes()
    require(inventory==(folder/'originals/after.native-classpath.txt').read_bytes(),'Native epoch changed')
    rows=[dict(sha256=line.split()[0],path=line.split()[-1]) for line in inventory.decode().splitlines()]
    require(len(rows)==471 and len({r['path'] for r in rows})==471,'Whole native classpath incomplete')
    jars=[]
    for row in rows:
        path=folder/'native-complete'/row['path'].removeprefix('/opt/keycloak/lib/')
        require(path.is_file() and path.stat().st_nlink==1 and sha(path.read_bytes())==row['sha256'],'Native immutable archive differs')
        jars.append(path)
    helper=REPO/'dev/reference-acceptance'/(HELPER+'.java')
    require(not (folder/(prefix+'-trace.json')).exists(),'Native trace is immutable')
    archived_helper=folder/'native-helper.java'
    if archived_helper.exists():require(archived_helper.read_bytes()==helper.read_bytes(),'Native helper archive changed')
    else:archived_helper.write_bytes(helper.read_bytes())
    java=pathlib.Path('/Library/Java/JavaVirtualMachines/jdk-21.jdk/Contents/Home/bin')
    with tempfile.TemporaryDirectory(prefix='kc-native-mechanism-compile-') as temporary:
        classes=pathlib.Path(temporary)/'classes'
        command([java/'javac','-sourcepath','','-cp',':'.join(map(str,jars)),'-d',classes,helper])
        require(all(p.name.startswith(HELPER) for p in classes.rglob('*.class')),'Native helper shadows product classes')
        remote='/tmp/kc-native-mechanism-'+secrets.token_hex(6)
        command(['docker','exec',NATIVE,'mkdir',remote])
        try:
            command(['docker','cp',classes,NATIVE+':'+remote+'/classes'])
            command(['docker','cp',folder/'inputs',NATIVE+':'+remote+'/inputs'])
            command(['docker','exec',NATIVE,'mkdir',remote+'/originals'])
            for name in ['native-client-before.json','flow-executions-before.json','flow-creation.json','native-realm-before.json']:
                command(['docker','cp',folder/'originals'/name,NATIVE+':'+remote+'/originals/'+name])
            actual={line.split()[1]:line.split()[0] for line in command(['docker','exec',NATIVE,'sha256sum',*[r['path'] for r in rows]]).stdout.decode().splitlines()}
            require(actual=={r['path']:r['sha256'] for r in rows},'Complete installed native runtime differs')
            started=datetime.datetime.now(datetime.timezone.utc).isoformat().replace('+00:00','Z')
            result=subprocess.run(['docker','exec',NATIVE,'java','-cp',remote+'/classes:'+':'.join(r['path'] for r in rows),HELPER,remote,remote+'/inputs/omitted.xml',remote+'/inputs/true.xml',remote+'/trace.json'],capture_output=True,timeout=60)
            (folder/(prefix+'-process.stderr')).write_bytes(result.stderr);(folder/(prefix+'-process.stdout')).write_bytes(result.stdout)
            require(result.returncode==0,'Native selected mechanism did not execute: '+result.stderr.decode(errors='replace')[-2000:])
            command(['docker','cp',NATIVE+':'+remote+'/trace.json',folder/(prefix+'-trace.json')])
            after={line.split()[1]:line.split()[0] for line in command(['docker','exec',NATIVE,'sha256sum',*[r['path'] for r in rows]]).stdout.decode().splitlines()}
            require(after==actual,'Native code changed during probe')
            (folder/(prefix+'-process.json')).write_text(json.dumps(dict(exitCode=0,startedAt=started,finishedAt=datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00","Z"),nativeClasspathSha256=sha(inventory),helperSha256=sha(helper.read_bytes()),isolatedInfrastructure=True,productSettingWrites=0,protocolSubmissions=0,credentialPosts=0),indent=2)+'\n')
        finally:command(['docker','exec','-u','0',NATIVE,'rm','-rf','--',remote])
    trace=load(folder/(prefix+'-trace.json'))
    require(len(trace['classes'])==15 and len(trace['traces'])==5 and trace['trueLivePasswordUiExecutionClaimed'] is False,'Native proof scope differs')
    for origin in trace['classes']:
        require(actual[origin['jarPath']]==origin['jarSha256'],'Actual loaded native class origin differs')
    return trace
if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('folder',type=pathlib.Path);parser.add_argument('--prefix',default='native');args=parser.parse_args();native_probe(args.folder.resolve(),args.prefix);print('Native producer and selected mechanism controls PASS')
