#!/usr/bin/env python3
"""One native CONFIG capability observation; no authentication or SAML dispatch.

The diagnostic capability-removal class exists only in an isolated helper PHP
process. Product configuration and native temporary files restore in finally.
"""
import argparse
import base64
import hashlib
import io
import json
from pathlib import Path
import re
import secrets
import subprocess
import sys
from datetime import datetime, timezone
import urllib.request
import zipfile

sys.dont_write_bytecode = True
from transient_allow_create_campaign import REPO, CONTAINER, IDP, PREFIX, BASE, api, save, batch, settled, raw, native
from encrypted_logout_native_campaign import GENERATE
from capture_run_originals import capture

CASE = 'IIP-IDP19-b-idp-01'
DIGEST = 'sha256:f0804b19a640f8dc668635a12630d2ac5dbb50193f04bed346a0e4afcc2ab9a8'
SCHEMA = 'samlscope-simplesamlphp-multiple-decryption-keys-v1'
IMAGE = 'sha256:9ae050473c68ce13c5451839cb64257eaa17be3a4d2c9a3f87996bbe0cebb0aa'
SHA = lambda b: hashlib.sha256(b).hexdigest()
NOW = lambda: datetime.now(timezone.utc).isoformat()


def require(value, reason):
    if not value:
        raise ValueError(reason)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    folder = args.output.resolve()
    require(folder.is_relative_to(REPO/'build/acceptance') and not folder.exists(), 'Fresh ignored acceptance folder required')
    folder.mkdir(parents=True)
    require(subprocess.run(['git','check-ignore','--quiet',str(folder)],cwd=REPO).returncode == 0, 'Acceptance folder must be ignored')
    operations = []
    save(folder/'operations.json', operations)
    original_run=subprocess.run

    def implicit_run(command, *arguments, **options):
        if not isinstance(command,(list,tuple)) or command[0]!='docker':
            return original_run(command,*arguments,**options)
        label='implicit-'+str(sum(x['label'].startswith('implicit-') for x in operations))
        row=dict(label=label,kind='native-implicit',command=list(command),startedAt=NOW(),stdinSha256=SHA(options.get('input') or b''))
        operations.append(row);save(folder/'operations.json',operations)
        if not any(k in options for k in ('stdout','stderr','capture_output')):options['capture_output']=True
        try:
            result=original_run(command,*arguments,**options)
            row.update(finishedAt=NOW(),exitCode=result.returncode,stdoutSha256=SHA(result.stdout or b''),stderrSha256=SHA(result.stderr or b''))
            if result.stdout is not None:
                row['stdoutFile']=label+'.stdout';(folder/row['stdoutFile']).write_bytes(result.stdout)
            if result.stderr is not None:
                row['stderrFile']=label+'.stderr';(folder/row['stderrFile']).write_bytes(result.stderr)
            return result
        except subprocess.CalledProcessError as failure:
            row.update(finishedAt=NOW(),exitCode=failure.returncode,stdoutSha256=SHA(failure.stdout or b''),stderrSha256=SHA(failure.stderr or b''))
            raise
        finally:
            save(folder/'operations.json',operations)
    subprocess.run=implicit_run

    def execute(label, command, payload=None, kind='native-read'):
        row = dict(label=label, kind=kind, command=command, startedAt=NOW(), stdinSha256=SHA(payload or b''))
        operations.append(row); save(folder/'operations.json', operations)
        try:
            result = original_run(command, input=payload, capture_output=True, timeout=40)
            row.update(finishedAt=NOW(), exitCode=result.returncode, stdoutSha256=SHA(result.stdout), stderrSha256=SHA(result.stderr),
                       stdoutFile=label+'.stdout', stderrFile=label+'.stderr')
            (folder/row['stdoutFile']).write_bytes(result.stdout)
            (folder/row['stderrFile']).write_bytes(result.stderr)
            save(folder/'operations.json', operations)
            require(result.returncode == 0, 'Native operation failed: '+label)
            return result.stdout
        except BaseException:
            row.setdefault('finishedAt', NOW()); row.setdefault('exitCode', -1)
            save(folder/'operations.json', operations)
            raise

    def identity(label):
        command=['docker','inspect','--format','{"containerId":{{json .Id}},"imageId":{{json .Image}},"startedAt":{{json .State.StartedAt}},"running":{{json .State.Running}}}',CONTAINER]
        value=json.loads(execute(label,command));require(value['imageId']==IMAGE and value['running'] is True,'Native runtime scope changed')
        save(folder/(label+'.json'),value);return value

    # Read actual installed resources before any target writes or native files.
    api_jar=execute('deployed-api', ['docker','exec','samlscope-reference-suite','cat','/opt/samlscope/lib/api-0.1.0.jar'])
    with zipfile.ZipFile(io.BytesIO(api_jar)) as archive:
        profile=archive.read('profiles/single_logout_idp.json')
        pins=archive.read('profiles/release-pins.properties')
    (folder/'profile.json').write_bytes(profile);(folder/'release-pins.properties').write_bytes(pins)
    definition=json.loads(profile)
    cases={x['id']:x['digest'] for x in definition['cases']}
    require(cases.get(CASE)==DIGEST and {'IIP-IDP19-a-idp-01','IIP-IDP19-c-idp-01'}<=cases.keys(),'Actual approved full-SLO membership missing')
    require(('single_logout_idp=sha256:'+SHA(profile)) in pins.decode(),'Installed profile digest is not release-pinned')
    save(folder/'scope.json',dict(caseId=CASE,caseDigest=DIGEST,profile='single_logout_idp',profileSha256=SHA(profile),deployedApiSha256=SHA(api_jar),
                                plannedCases={k:cases[k] for k in ['IIP-IDP19-a-idp-01',CASE,'IIP-IDP19-c-idp-01']}))
    before_identity=identity('runtime-before')
    worker_text=execute('native-web-workers',['docker','exec',CONTAINER,'ps','-eo','uid,comm']).decode()
    worker_uids={line.split()[0] for line in worker_text.splitlines() if line.strip().endswith('apache2') and line.split()[0]!='0'}
    require(worker_uids=={'33'},'Unsupported actual web worker UID')
    helper=Path(__file__).with_name('multiple_decryption_keys_probe.php').read_bytes()
    (folder/'native-probe.php').write_bytes(helper);(folder/'collector.py').write_bytes(Path(__file__).read_bytes())
    remote=batch('saml20-sp-remote.php');hosted=batch('saml20-idp-hosted.php')
    configs={'remote':remote,'hosted':hosted}
    for name,c in configs.items():
        (folder/(name+'-original.php')).write_bytes(settled(c.container_path,c.original))
    (folder/'override-original.php').write_bytes(raw('/var/simplesamlphp/config/config-override.php'))
    token=secrets.token_hex(12);prefix='/tmp/samlscope-decryption-config-'+token
    key_path=prefix+'.key.pem';cert_path=prefix+'.cert.pem';helper_path=prefix+'.php'
    paths=[key_path,cert_path,helper_path]
    run=None;key_attempted=False;helper_attempted=False;native_input=None
    try:
        execute('native-paths-before',['docker','exec',CONTAINER,'php','-r',
            'foreach(array_slice($argv,1) as $p)if(file_exists($p)||is_link($p))throw new RuntimeException("Owned path already exists");',*paths])
        key_attempted=True
        certificate=execute('native-key-generation',['docker','exec','--user','33',CONTAINER,'php','-r',GENERATE,key_path,cert_path],kind='native-key-write')
        (folder/'new-public-certificate.pem').write_bytes(certificate)
        helper_attempted=True
        execute('native-helper-write',['docker','exec','--user','33','-i',CONTAINER,'sh','-c','cat > "$1"','sh',helper_path],helper,kind='native-helper-write')
        require(execute('native-helper-readback',['docker','exec',CONTAINER,'cat',helper_path])==helper,'Native helper bytes changed')
        hosted.apply(("$metadata['"+IDP+"']['new_privatekey']='"+key_path+"';\n$metadata['"+IDP+"']['new_certificate']='"+cert_path+"';").encode())
        (folder/'hosted-configured.php').write_bytes(settled(hosted.container_path,hosted.expected))
        plan=api('/api/plans',dict(name='Native two-decryption-key CONFIG capability',profile='single_logout_idp',targetKind='IDP',targetEntityId=IDP,
            metadataSourceKind='URL',metadataSourceLocation='http://samlscope-reference-ssp/simplesaml/module.php/saml/idp/metadata',
            suiteMetadataDelivery='HTTP_URL',declaredFeatures={},parameters=dict(clockSkewToleranceSeconds=180,metadataRefreshWaitSeconds=300,requestSigningMode='REQUIRED'),
            interaction=dict(allowBrowserSteps=False,allowAttestation=False,preset='quick'),authorizedTarget=True))
        save(folder/'plan.json',plan);pid=plan['plan']['plan']['id'];require(re.fullmatch(r'plan_[0-9A-HJKMNP-TV-Z]{26}',pid),'Invalid actual Plan identity')
        created=api('/api/plans/'+pid+'/runs',{});save(folder/'created.json',created);run=created['run']['id']
        require(re.fullmatch(r'run_[0-9A-HJKMNP-TV-Z]{26}',run),'Invalid actual Run identity')
        entity=BASE+'/p/'+pid;save(folder/'preflight.json',api('/api/runs/'+run+'/preflight',{}))
        capture(folder,run,api('/api/runs/'+run+'/transcript'))
        target=(folder/'target-metadata.xml').read_bytes()
        # This is a real native metadata parser fetch, recorded by the Suite.
        parser_command=native.PHP.replace("$xml=stream_get_contents(STDIN);", "$xml=file_get_contents($argv[3]);")
        parser_command=parser_command.replace("echo json_encode(['entity_id'", "echo json_encode(['inputXmlBase64'=>base64_encode($xml),'inputSha256'=>hash('sha256',$xml),'entity_id'")
        require(parser_command!=native.PHP,'Supported native parser input route changed')
        (folder/'native-parser-command.php').write_text(parser_command)
        native_url='http://samlscope-reference-suite:8080/p/'+pid+'/metadata/live?run='+run
        parsed=execute('native-peer-parser',['docker','exec','--user','33',CONTAINER,'php','-r',parser_command,entity,'default',native_url])
        projection=json.loads(parsed);require(projection['entity_id']==entity,'Native parser selected another peer')
        remote.apply(projection['php'].encode());(folder/'remote-configured.php').write_bytes(settled(remote.container_path,remote.expected))
        native_input=dict(runId=run,caseDigest=DIGEST,targetEntityId=IDP,peerEntityId=entity,targetMetadataSha256=SHA(target))
        input_bytes=json.dumps(native_input,separators=(',',':')).encode();(folder/'native-input.json').write_bytes(input_bytes)
        for phase in ['before','after']:
            result=execute('native-'+phase,['docker','exec','--user','33','-i',CONTAINER,'php',helper_path],input_bytes,kind='native-configuration-observation')
            envelope=json.loads(result);observation=json.loads(base64.b64decode(envelope['payloadBase64'],validate=True));save(folder/('native-'+phase+'.json'),observation)
            require(len(observation['baselineKeys'])==2 and len({x['spkiSha256'] for x in observation['baselineKeys']})==2,'Actual native two-key capability not observed')
            require(len(observation['control']['keys'])==1,'Native capability-removal control failed')
        first=json.loads((folder/'native-before.json').read_bytes());last=json.loads((folder/'native-after.json').read_bytes())
        require(first['loadedClasses']==last['loadedClasses'] and first['dependencies']==last['dependencies'] and first['settingsSha256']==last['settingsSha256'],
                'Native source/configuration changed within observation')
        deps=folder/'native-dependencies';deps.mkdir();require(len(first['dependencies'])<=256,'Native dependency closure exceeded budget')
        total=0
        for index,row in enumerate(first['dependencies']):
            path=row['file'];require(re.fullmatch(r'/var/simplesamlphp/(src|vendor|modules|lib)/[A-Za-z0-9_./-]+\.php',path) and '/..' not in path,'Unsafe native dependency path')
            value=execute('dependency-'+str(index),['docker','exec',CONTAINER,'cat',path]);require(SHA(value)==row['sha256'] and len(value)==row['bytes'] and len(value)<=1048576,'Native dependency changed')
            total+=len(value);require(total<=16777216,'Native dependency byte budget exceeded');(deps/(row['sha256']+'.php')).write_bytes(value)
        save(folder/'tests-start.json',api('/api/runs/'+run+'/tests/start',{}))
        save(folder/'transcript.json',api('/api/runs/'+run+'/transcript'));capture(folder,run,json.loads((folder/'transcript.json').read_bytes()))
        save(folder/'result-before.json',api('/api/runs/'+run+'/result.json'))
        require(any(x.get('samlSummary',{}).get('type')=='MetadataPrepared' for x in json.loads((folder/'transcript.json').read_bytes())),
                'Genuine own-Run metadata transcript is missing')
    finally:
        restorations={};restore_failures=[]
        for name,c in reversed(list(configs.items())):
            try:
                restorations[name]=c.restore();(folder/(name+'-final.php')).write_bytes(settled(c.container_path,c.original))
            except BaseException as failure:
                restore_failures.append(dict(operation='restore-'+name,errorClass=type(failure).__name__))
        save(folder/'restoration.json',restorations)
        try:
            require(raw('/var/simplesamlphp/config/config-override.php')==(folder/'override-original.php').read_bytes(),'Unrelated native override changed')
            if native_input is not None and not restore_failures:
                restore_input=json.dumps({**native_input,'mode':'restored'},separators=(',',':')).encode()
                (folder/'native-restored-input.json').write_bytes(restore_input)
                result=execute('native-restored',['docker','exec','--user','33','-i',CONTAINER,'php',helper_path],restore_input,kind='native-restoration-observation')
                envelope=json.loads(result);restored=json.loads(base64.b64decode(envelope['payloadBase64'],validate=True));save(folder/'native-restored.json',restored)
                require(restored['newPrivateKey'] is None and len(restored['keys'])==1,'Native factory did not restore its original one-key configuration')
        except BaseException as failure:
            restore_failures.append(dict(operation='native-restoration-readback',errorClass=type(failure).__name__))
        if key_attempted or helper_attempted:
            try:
                execute('native-files-remove',['docker','exec','--user','33',CONTAINER,'php','-r',
                    'foreach(array_slice($argv,1) as $p){if(is_link($p))throw new RuntimeException("Unexpected link");if(file_exists($p)&&!unlink($p))throw new RuntimeException("Removal failed");}',*paths],kind='native-file-remove')
                execute('native-paths-after',['docker','exec',CONTAINER,'php','-r',
                    'foreach(array_slice($argv,1) as $p)if(file_exists($p)||is_link($p))throw new RuntimeException("Cleanup incomplete");',*paths])
            except BaseException as failure:
                restore_failures.append(dict(operation='native-file-cleanup',errorClass=type(failure).__name__))
        try:
            after_identity=identity('runtime-after');require(before_identity==after_identity,'Native runtime identity changed')
        except BaseException as failure:
            restore_failures.append(dict(operation='native-runtime-readback',errorClass=type(failure).__name__))
        counts=dict(productConfigurationWriteAttempts=sum(c.write_count for c in configs.values()),
            successfulHostWrites=sum(c.write_count for c in configs.values()),nativeApplications=sum(c.applied_count for c in configs.values()),
            restorationWrites=sum(c.restoration_writes for c in configs.values()),nativeObservationInvocations=sum(x['kind']=='native-configuration-observation' for x in operations),
            dockerCommandsAttempted=len(operations),failedDockerCommands=sum(x.get('exitCode',-1)!=0 for x in operations),
            nativeEphemeralFilesCreated=3 if key_attempted and helper_attempted else 0,nativeEphemeralFilesRemoved=3 if key_attempted and helper_attempted else 0,
            runCreations=int(run is not None),credentialPosts=0,samlProtocolOperations=0,productRestarts=0,humanOperations=0,
            restored=not restore_failures and len(restorations)==2 and all(x['restored'] for x in restorations.values()),
            restorationFailures=restore_failures)
        save(folder/'operation-counts.json',counts)
        subprocess.run=original_run
        require(not restore_failures,'Native restoration failed; see bounded operation ledger')
    files={str(p.relative_to(folder)):SHA(p.read_bytes()) for p in folder.rglob('*') if p.is_file() and p.name!='manifest.json'}
    save(folder/'manifest.json',dict(schema=SCHEMA,campaignId='native-multiple-decryption-keys',runId=run,caseId=CASE,caseDigest=DIGEST,
        targetEntityId=IDP,targetMetadataSha256=SHA((folder/'target-metadata.xml').read_bytes()),nativeHelperPath=helper_path,newPrivateKeyPath=key_path,
        newCertificatePath=cert_path,files=files,outcomeAssigned=False))
    print(run,'native CONFIG originals captured; no verdict adopted; restored')


if __name__=='__main__':
    main()
