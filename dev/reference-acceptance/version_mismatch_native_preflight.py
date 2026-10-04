#!/usr/bin/env python3
"""Read-only native qualification before an SSO01.ep login; never a verdict."""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import subprocess

REPO = Path(__file__).resolve().parents[2]
SHA = lambda value: hashlib.sha256(value).hexdigest()
SSP_SOURCES = {
    'Message.php': ('/var/simplesamlphp/vendor/simplesamlphp/saml2-legacy/src/SAML2/Message.php', '42334f0f2d0590a82371552bccea01ffc5bb73cc8fe3849a190d62f0809d481e'),
    'Utils.php': ('/var/simplesamlphp/vendor/simplesamlphp/saml2-legacy/src/SAML2/Utils.php', '5845e28158c7641d5ce1e6b9205e8005b6d9c090e1888ea46416abb8fdf0018d'),
}
REFLECTION = r'''
require '/var/simplesamlphp/lib/_autoload.php';
$out=[];foreach(['messageClass'=>\SAML2\Message::class,'utilsClass'=>\SAML2\Utils::class] as $name=>$class){
 $reflection=new \ReflectionClass($class);$file=$reflection->getFileName();
 $out[$name.'File']=$file;$out[$name.'SourceSha256']=hash_file('sha256',$file);
}echo json_encode($out,JSON_THROW_ON_ERROR);
'''


def qualify_facts(product, runtime, reflection, sources):
    result = dict(schema='samlscope-version-native-preflight-v1', product=product,
        caseId='IIP-SSO01-ep-idp-01', readiness='blocked', reasons=[],
        genuineSamlResponsePathAvailable=True, nativeHttpTerminalAdapterQualified=False,
        productSettings=0, protocolSubmissions=0, credentialPosts=0, personOperations=0,
        outcomeDerived=False, guaranteedReduction=0)
    if product != 'simplesamlphp':
        result['reasons'] = ['native-http-terminal-adapter-unqualified']
        return result
    if (runtime.get('running') is not True or not isinstance(runtime.get('mounts'), list)
            or not isinstance(runtime.get('containerId'), str)
            or len(runtime['containerId']) != 64 or not isinstance(runtime.get('imageId'), str)
            or not runtime['imageId'].startswith('sha256:')):
        result['reasons'] = ['native-runtime-boundary-unqualified']
        return result
    destinations=set()
    for mount in runtime['mounts']:
        destination=mount.get('Destination')
        if (not isinstance(destination,str) or not destination.startswith('/') or destination in destinations
                or not isinstance(mount.get('RW'),bool) or not isinstance(mount.get('Source'),str)
                or not mount['Source'].startswith('/') or not all(isinstance(mount.get(k),str) for k in ('Type','Mode','Propagation'))
                or any(path==destination or path.startswith(destination.rstrip('/')+'/') for path,_ in SSP_SOURCES.values())):
            result['reasons']=['native-source-mount-boundary-unqualified'];return result
        destinations.add(destination)
    for name, (path, expected) in SSP_SOURCES.items():
        prefix = 'messageClass' if name == 'Message.php' else 'utilsClass'
        if (reflection.get(prefix+'File') != path or reflection.get(prefix+'SourceSha256') != expected
                or SHA(sources.get(name, b'')) != expected):
            result['reasons'] = ['native-parser-source-binding-unqualified']
            return result
    result.update(readiness='qualified-for-version-campaign', nativeHttpTerminalAdapterQualified=True,
                  adapter='simplesamlphp-native-message-version',
                  requiredFixtures=['baseline-success', 'invalid-issue-instant', 'version-1-1'],
                  sourceSha256={name: SHA(raw) for name, raw in sources.items()},
                  nativeFailureCauses=['Unsupported version: 1.1',
                    'Invalid SAML2 timestamp passed to xsDateTimeToTimestamp: not-a-saml-timestamp'])
    return result


def inspect(container):
    command = ['docker','inspect','--format',
        '{"containerId":{{json .Id}},"imageId":{{json .Image}},"running":{{json .State.Running}},"mounts":{{json .Mounts}}}',container]
    result=json.loads(subprocess.run(command,check=True,capture_output=True,timeout=20).stdout)
    result["mounts"]=sorted(result["mounts"],key=lambda row:row["Destination"])
    return result


def capture(output, product='simplesamlphp'):
    output = Path(output).resolve();output.mkdir(parents=True,exist_ok=False)
    if product != 'simplesamlphp':
        report = qualify_facts(product, {}, {}, {})
        (output/'qualification.json').write_text(json.dumps(report,indent=2)+'\n')
        return report
    container='samlscope-reference-ssp';before=inspect(container);source={};calls=[]
    for name, (path, _) in SSP_SOURCES.items():
        started=datetime.datetime.now(datetime.timezone.utc).isoformat()
        command=['docker','exec',container,'cat',path]
        result=subprocess.run(command,check=True,capture_output=True,timeout=20)
        source[name]=result.stdout;(output/name).write_bytes(result.stdout)
        calls.append(dict(executable='cat',publicPath=path,startedAt=started,
                          completedAt=datetime.datetime.now(datetime.timezone.utc).isoformat(),exitCode=0))
    result=subprocess.run(['docker','exec',container,'php','-r',REFLECTION],check=True,capture_output=True,timeout=20)
    reflection=json.loads(result.stdout);after=inspect(container)
    facts={**before,**reflection};(output/'runtime-before.json').write_text(json.dumps(facts,sort_keys=True)+'\n')
    (output/'runtime-after.json').write_text(json.dumps({**after,**reflection},sort_keys=True)+'\n')
    (output/'reflection-command.php').write_text(REFLECTION)
    report=qualify_facts(product,before,reflection,source)
    if before != after:report.update(readiness='blocked',nativeHttpTerminalAdapterQualified=False,reasons=['native-runtime-changed'])
    report['nativeReadOnlyCommands']={'dockerInspect':2,'cat':len(calls),'php':1}
    report['sourceReflectionCommandSha256']=SHA(REFLECTION.encode())
    (output/'command-counts.json').write_text(json.dumps(calls,indent=2)+'\n')
    (output/'qualification.json').write_text(json.dumps(report,indent=2)+'\n')
    return report


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',required=True,type=Path)
    parser.add_argument('--product',choices=['simplesamlphp','shibboleth','keycloak'],default='simplesamlphp')
    args=parser.parse_args();report=capture(args.output,args.product)
    print(json.dumps(report,sort_keys=True));return 0 if report['readiness']=='qualified-for-version-campaign' else 1
if __name__ == '__main__':raise SystemExit(main())
