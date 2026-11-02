#!/usr/bin/env python3
"""Collect native simultaneous metadata sources; never submit a product verdict.

Dry run is pure and does not import product helpers, read configuration, create a
Run, invoke Docker, open a socket, or create an output directory.
"""
import argparse
import datetime
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import urllib.request

CASES = {
    'IIP-MD05-a1-idp-01': 'sha256:308f52da818fe17f173314127627e15084ab297b72ea504d27077f86df4af72d',
    'IIP-MD05-a2-idp-01': 'sha256:f175ab21c50fdf5861980473955f0d5f4ba17d7e4b064ad06beeca0cf4b3d4ca',
}
ADAPTER = 'simplesamlphp-native-metadata-entity-identity-v1'
TARGET = 'http://localhost:18380/idp'
CONTAINER = 'samlscope-reference-ssp'
REMOTE = '/var/simplesamlphp/config/config-override.php'
NATIVE_FILES = {
    'handler.php': '/var/simplesamlphp/src/SimpleSAML/Metadata/MetaDataStorageHandler.php',
    'source.php': '/var/simplesamlphp/src/SimpleSAML/Metadata/MetaDataStorageSource.php',
    'flatfile.php': '/var/simplesamlphp/src/SimpleSAML/Metadata/MetaDataStorageHandlerFlatFile.php',
    'parser.php': '/var/simplesamlphp/src/SimpleSAML/Metadata/SAMLParser.php',
    'configuration.php': '/var/simplesamlphp/src/SimpleSAML/Configuration.php',
}
SHA = lambda b: hashlib.sha256(b).hexdigest()
NOW = lambda: datetime.datetime.now(datetime.timezone.utc).isoformat().replace('+00:00', 'Z')

# Only public metadata is projected. The installed native source and handler do
# the lookup; including a PHP array ourselves would not prove native adoption.
READBACK = r'''
require '/var/simplesamlphp/lib/_autoload.php';
$input=json_decode(stream_get_contents(STDIN),true,512,JSON_THROW_ON_ERROR);
function project(array $m): array {
 $keys=[];
 foreach (($m['keys']??[]) as $k) {
  if (($k['type']??null)!=='X509Certificate' || ($k['signing']??false)!==true) continue;
  $der=base64_decode(preg_replace('/\s/','',$k['X509Certificate']),true);
  if ($der===false || openssl_x509_read("-----BEGIN CERTIFICATE-----\n".chunk_split(base64_encode($der),64,"\n")."-----END CERTIFICATE-----\n")===false)
   throw new RuntimeException('Native certificate unavailable');
  $keys[]=hash('sha256',$der);
 }
 $keys=array_values(array_unique($keys));sort($keys);
 $acs=[];foreach(($m['AssertionConsumerService']??[]) as $a) $acs[]=$a['Location'];
 $acs=array_values(array_unique($acs));sort($acs);
 if (!$keys || !$acs) throw new RuntimeException('Native identity projection incomplete');
 return ['entityId'=>$m['entityid'],'keys'=>$keys,'endpoints'=>$acs];
}
$global=\SimpleSAML\Configuration::getInstance();
$sources=$global->getArray('metadata.sources');
$handler=\SimpleSAML\Metadata\MetaDataStorageHandler::getMetadataHandler();
if ($input['phase']==='restored') {
 $list=$handler->getList('saml20-sp-remote');$absent=true;
 foreach($input['entities'] as $entity) if (isset($list[$entity])) $absent=false;
 echo json_encode(['sources'=>$sources,'ownedPeersAbsent'=>$absent],JSON_THROW_ON_ERROR);exit;
}
if (count($sources)!==3 || $sources[0]!==['type'=>'flatfile']) throw new RuntimeException('Native source configuration differs');
$rows=[];
foreach([1,2] as $index) {
 $source=\SimpleSAML\Metadata\MetaDataStorageSource::getSource($sources[$index]);$items=[];
 foreach($input[$index===1?'entities':'duplicateEntities'] as $entity) {
  $m=$source->getMetaData($entity,'saml20-sp-remote');
  if (!is_array($m)) throw new RuntimeException('Native source did not retain the offered reference');
  $items[]=project($m);
 }
 $rows[]=$items;
}
$effective=[];foreach($input['entities'] as $entity) $effective[]=project($handler->getMetaData($entity,'saml20-sp-remote'));
$hashes=[];foreach($input['sourcePaths'] as $name=>$path) $hashes[$name]=hash_file('sha256',$path);
// Read the installed distribution's version constant, not a caller label.
$version=\SimpleSAML\Configuration::VERSION;
echo json_encode(['version'=>$version,'sources'=>$sources,'sourceA'=>$rows[0],'sourceB'=>$rows[1],
 'effective'=>$effective,'sourceHashes'=>$hashes,'configurationSha256'=>hash_file('sha256','/var/simplesamlphp/config/config-override.php')],JSON_THROW_ON_ERROR);
'''


def require(condition, message):
    if not condition:
        raise ValueError(message)


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()


def reject_sensitive(value):
    if isinstance(value, dict):
        for key, item in value.items():
            require(not re.search(r'password|secret|credential|token|cookie|authorization|privatekey', key, re.I),
                    'Sensitive field refused before persistence')
            reject_sensitive(item)
    elif isinstance(value, list):
        for item in value:
            reject_sensitive(item)


def dry_plan():
    return dict(adapter=ADAPTER, profile='metadata_idp', product='SimpleSAMLphp 2.5.0',
        cases=CASES, operation='simultaneous-sources',
        fixtures=[dict(source='A', entity='primary', signingKeys=['primary-key'], endpoints=['primary-acs']),
                  dict(source='A', entity='secondary', signingKeys=['secondary-key'], endpoints=['secondary-acs']),
                  dict(source='B', entity='primary', signingKeys=['primary-key', 'rollover-key'], endpoints=['duplicate-acs'])],
        controls=dict(positive='idp-core-no-ecp: two signed, correlated peer flows',
                      negative=['mut-iip-md05-a1-idp', 'mut-iip-md05-a2-idp'],
                      calibration='Archived reader: merged identities must be detected; source precedence stays unverified'),
        steps=['Verify approved profile and both saved Run inventories before configuration',
               'Parse three original Suite metadata fixtures with the installed native parser',
               'Create two isolated flatfile sources; append one metadata.sources overlay',
               'Read each native source and effective handler before and after two normal controls',
               'Restore once, verify original digest and native source list, remove temporary sources',
               'Export original transcripts and pin a receipt; replay before any adoption'],
        plannedCounts=dict(runCreations=2, nativeParserInvocations=3, configurationApplyWrites=1,
            restorationWrites=1, configurationWriteAttempts=2, successfulHostWrites=2,
            nativeApplications=1, fixtureFileWrites=2, fixtureRemovalOperations=1,
            normalFlowsAttempted=2, protocolSubmissions=2, humanOperations=0, productRestarts=0),
        executedCounts=dict(docker=0, network=0, productWrites=0, protocolSubmissions=0),
        limitations=['Archived native source supports directory-scoped flatfiles; active deployment still requires readback',
                     'No qualified stock 2.5.0 duplicate-conflict diagnostic; shadowing cannot be adopted'])


def approved_profile(profile):
    require(profile['profile'] == 'metadata_idp', 'Wrong adoption profile')
    rows = profile['cases']
    require(len({row['id'] for row in rows}) == len(rows), 'Duplicate profile case')
    by = {row['id']: row['digest'] for row in rows}
    require(all(by.get(case) == digest for case, digest in CASES.items()), 'Approved profile cases differ')


def inventory(result):
    rows = [case for requirement in result['requirements'] for case in requirement['cases']]
    by = {}
    for row in rows:
        require(row['id'] not in by, 'Duplicate result case')
        by[row['id']] = row
    require(set(CASES) <= set(by), 'Run does not contain both approved cases')
    return dict(CASES)


def overlay(root):
    require(re.fullmatch(r'/tmp/samlscope-md05-run_[0-9A-HJKMNP-TV-Z]{26}', root), 'Unsafe source directory')
    sources = [dict(type='flatfile'), dict(type='flatfile', directory=root+'/a'), dict(type='flatfile', directory=root+'/b')]
    code = ("$config['metadata.sources'] = [['type'=>'flatfile'],"
            "['type'=>'flatfile','directory'=>'"+root+"/a'],"
            "['type'=>'flatfile','directory'=>'"+root+"/b']];")
    return sources, code.encode()


def load_helpers(repo):
    # Imports are deliberately deferred until after the dry-run branch.
    sys.path[:0] = [str(repo/'dev/simplesamlphp'), str(repo/'dev/keycloak'), str(repo/'dev/reference-acceptance')]
    from configuration_batch import ConfigurationBatch
    from reference_flow import Client
    from capture_run_originals import capture
    from algorithm_preference_campaign import recorded
    spec = importlib.util.spec_from_file_location('ssp_md05_parser', repo/'dev/simplesamlphp/import_metadata_batch.py')
    parser = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(parser)
    return ConfigurationBatch, Client, capture, recorded, parser


def live(args):
    repo = args.repo.resolve()
    username = os.environ.get('REFERENCE_USERNAME', 'samlscope-m0-user')
    password = os.environ.get('REFERENCE_PASSWORD')
    require(password is not None, 'Live collection requires REFERENCE_PASSWORD in memory')
    ConfigurationBatch, Client, capture, recorded, parser = load_helpers(repo)
    api, save, base = parser.api, parser.save, parser.BASE
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    receipt = out/'receipt'
    receipt.mkdir()
    (receipt/'collector-source.py').write_bytes(Path(__file__).read_bytes())
    (receipt/'native-readback-command.php').write_text('<?php\n'+READBACK)
    commands, peers, originals = [], [], {}
    counts = {k: 0 for k in dry_plan()['plannedCounts']}
    restoration = dict(restored=False)
    batch = None
    root = None
    root_owned = False
    runtime_before = None
    native_applications = 0
    host_writes = 0

    def docker(*argv, data=None):
        row = dict(arguments=list(argv), startedAt=NOW(), exitCode=None)
        commands.append(row)
        save(receipt/'native-commands.json', commands)
        p = subprocess.run(['docker', 'exec', '-i', CONTAINER, *argv], input=data, capture_output=True, timeout=45)
        row.update(finishedAt=NOW(), exitCode=p.returncode)
        save(receipt/'native-commands.json', commands)
        require(p.returncode == 0, 'Native command failed; stderr is not persisted')
        return p.stdout

    def runtime():
        fmt = '{"id":{{json .Id}},"image":{{json .Image}},"running":{{json .State.Running}},"startedAt":{{json .State.StartedAt}}}'
        raw = subprocess.run(['docker', 'inspect', '--format', fmt, CONTAINER], check=True, capture_output=True, timeout=30).stdout
        value = json.loads(raw)
        require(value['running'] is True, 'Product must already be running')
        return value

    def record(kind, **values):
        data = dict(schema='samlscope-ssp-metadata-entity-identity-original-v1', kind=kind,
                    runId=peers[0]['runId'], campaignId='native-metadata-entity-identity',
                    targetMetadataSha256=SHA((receipt/'target-metadata.xml').read_bytes()), recordedAt=NOW(), **values)
        reject_sensitive(data)
        originals[kind] = recorded(receipt, peers[0]['created'], data, kind)

    class CountingClient(Client):
        def __init__(self):
            super().__init__()
            self.login_posts = 0

        def request(self, url, fields=None):
            login = fields and any(k in fields for k in ('password', 'j_password'))
            if login:
                counts['loginFormPostAttempts'] = counts.get('loginFormPostAttempts', 0) + 1
            result = super().request(url, fields)
            if login:
                self.login_posts += 1
                counts['loginFormPosts'] = self.login_posts
            return result

    try:
        # Neither a profile name alone nor an invented inventory proves that a
        # saved Run contains a case. Verify actual result membership first.
        import yaml
        approved_profile(json.loads((repo/'profiles/metadata_idp.json').read_bytes()))
        catalog = yaml.safe_load((repo/'tests/cases.yaml').read_bytes())
        definitions = catalog['cases'] if isinstance(catalog, dict) else catalog
        for case, digest in CASES.items():
            selected = [row for row in definitions if row['id'] == case]
            require(len(selected) == 1 and selected[0]['case_digest'] == digest, 'Approved case digest changed')
        runtime_before = runtime()
        for label in ('primary', 'secondary'):
            folder = receipt/label
            folder.mkdir()
            plan = api('/api/plans', dict(name='SimpleSAMLphp native entity identity '+label, profile='metadata_idp',
                targetKind='IDP', targetEntityId=TARGET, metadataSourceKind='URL',
                metadataSourceLocation='http://samlscope-reference-ssp/simplesaml/module.php/saml/idp/metadata',
                suiteMetadataDelivery='HTTP_URL', declaredFeatures={}, parameters=dict(clockSkewToleranceSeconds=180,
                    metadataRefreshWaitSeconds=300, testUserHint='samlscope-m0-user', requestSigningMode='REQUIRED'),
                interaction=dict(allowBrowserSteps=True, allowAttestation=False, preset='quick'), authorizedTarget=True))
            pid = plan['plan']['plan']['id']
            created = api('/api/plans/'+pid+'/runs', {})
            run = created['run']['id']
            counts['runCreations'] += 1
            save(folder/'plan.json', plan)
            save(folder/'created.json', created)
            save(folder/'case-inventory.json', inventory(api('/api/runs/'+run+'/result.json')))
            save(folder/'preflight.json', api('/api/runs/'+run+'/preflight', {}))
            entity = base+'/p/'+pid
            with urllib.request.urlopen(entity+'/metadata', timeout=30) as r:
                (folder/'fixture.xml').write_bytes(r.read())
            peers.append(dict(label=label, planId=pid, runId=run, entity=entity, created=created))
            capture(folder, run, api('/api/runs/'+run+'/transcript'))
        target_raw = (receipt/'primary/target-metadata.xml').read_bytes()
        require(target_raw == (receipt/'secondary/target-metadata.xml').read_bytes(), 'Peer targets differ')
        (receipt/'target-metadata.xml').write_bytes(target_raw)
        run = peers[0]['runId']
        root = '/tmp/samlscope-md05-'+run
        sources, code = overlay(root)
        save(out/'duplicate-campaign.json', api('/api/runs/'+run+'/metadata-lab/automatic-polling',
                                              dict(variants=['multiple-signing-keys'], pollingDelaySeconds=0)))
        lab = api('/api/runs/'+run+'/metadata-lab')
        with urllib.request.urlopen(lab['automaticStartUrl'], timeout=30) as r:
            require(r.status == 202, 'Fixture fetch gate unavailable')
        with urllib.request.urlopen(lab['metadataUrl'], timeout=30) as r:
            (receipt/'duplicate-fixture.xml').write_bytes(r.read())
        parsed = []
        for name, entity in [('primary/fixture.xml', peers[0]['entity']), ('secondary/fixture.xml', peers[1]['entity']),
                             ('duplicate-fixture.xml', peers[0]['entity'])]:
            counts['nativeParserInvocations'] += 1
            data = json.loads(docker('php', '-r', parser.PHP, entity, 'default', data=(receipt/name).read_bytes()))
            reject_sensitive(data)
            require(data['entity_id'] == entity and data['validate_authnrequest'] is True, 'Native parser prerequisite failed')
            parsed.append(data)
        # Configuration bytes may contain unrelated secrets. Keep the original
        # only in ConfigurationBatch memory; persist its digest, never its text.
        batch = ConfigurationBatch(args.configuration)
        batch.container_path = REMOTE
        require(b'?>' not in batch.original and docker('cat', REMOTE) == batch.original, 'Configuration baseline mismatch')
        require(json.loads(docker('php', '-r', "require '/var/simplesamlphp/lib/_autoload.php'; echo json_encode(\\SimpleSAML\\Configuration::getInstance()->getArray('metadata.sources'));")) == [{'type': 'flatfile'}], 'Stock source list required')
        baseline = json.loads(docker('php', '-r', READBACK, data=canonical(dict(phase='restored', entities=[p['entity'] for p in peers]))))
        require(baseline['ownedPeersAbsent'], 'Refusing an existing peer')
        # mkdir is exclusive. Never delete a pre-existing directory in finally.
        docker('mkdir', root)
        root_owned = True
        docker('mkdir', root+'/a', root+'/b')
        for directory, payload in [('a', '\n'.join(p['php'] for p in parsed[:2])), ('b', parsed[2]['php'])]:
            body = ('<?php\n'+payload+'\n').encode()
            counts['fixtureFileWrites'] += 1
            docker('php', '-r', '$p=$argv[1];$b=stream_get_contents(STDIN);if(file_put_contents($p,$b)!==strlen($b))exit(1);', root+'/'+directory+'/saml20-sp-remote.php', data=body)
            require(docker('cat', root+'/'+directory+'/saml20-sp-remote.php') == body, 'Fixture file readback differs')
        batch.apply(code)
        host_writes += 1
        require(docker('cat', REMOTE) == batch.expected, 'Native configuration bytes remain stale')
        # No sleep assumes that Apache applied the file. The two signed normal
        # controls below are the native application proof; CLI readback alone is not.
        (receipt/'native-runtime').mkdir()
        source_hashes = {}
        for name, path in NATIVE_FILES.items():
            raw = docker('cat', path)
            (receipt/'native-runtime'/name).write_bytes(raw)
            source_hashes[name] = SHA(raw)
        read_input = dict(phase='active', entities=[p['entity'] for p in peers], duplicateEntities=[peers[0]['entity']], sourcePaths=NATIVE_FILES)
        def state(kind):
            started = NOW()
            value = json.loads(docker('php', '-r', READBACK, data=canonical(read_input)))
            require(value['sources'] == sources and value['version'] == '2.5.0' and value['sourceHashes'] == source_hashes,
                    'Native sources/version/runtime changed')
            require(value['configurationSha256'] == SHA(batch.expected), 'Effective configuration differs')
            record(kind, native=value, runtime=runtime(), observedStartedAt=started, observedFinishedAt=NOW(), originalSha256=SHA(batch.original))
        state('before')
        client = CountingClient()
        for peer in peers:
            previous = {e['id'] for e in api('/api/runs/'+peer['runId']+'/transcript')}
            counts['normalFlowsAttempted'] += 1
            result = client.flow(peer['entity']+'/start/m0-roundtrip?run='+peer['runId'], None,
                                 username, password)
            rows = [e for e in api('/api/runs/'+peer['runId']+'/transcript') if e['id'] not in previous]
            rq = [e for e in rows if e['direction'] == 'OUTBOUND' and e['samlSummary'].get('type') == 'AuthnRequest']
            rs = [e for e in rows if e['direction'] == 'INBOUND' and e['samlSummary'].get('normalFlowAccepted') is True]
            counts['protocolSubmissions'] += len(rq)
            require(result == 'recorded' and len(rq) == len(rs) == 1 and rs[0]['samlSummary']['inResponseTo'] == rq[0]['samlSummary']['id'], 'Normal control incomplete; no repeated action')
            peer['normal'] = dict(requestReference=rq[0]['id'], responseReference=rs[0]['id'])
        native_applications = 1
        counts['loginFormPosts'] = client.login_posts
        state('after')
        for peer in peers:
            save(out/(peer['label']+'-tests-start.json'), api('/api/runs/'+peer['runId']+'/tests/start', {}))
    finally:
        if batch is not None:
            try:
                restore = batch.restore()
                if restore['restoration_write_attempts']:
                    host_writes += 1
                final = docker('cat', REMOTE)
                require(final == batch.original, 'Native configuration restoration differs')
                restored_state = json.loads(docker('php', '-r', READBACK, data=canonical(dict(phase='restored', entities=[p['entity'] for p in peers]))))
                require(restored_state == dict(sources=[dict(type='flatfile')], ownedPeersAbsent=True), 'Native restoration remains ambiguous')
                if root_owned:
                    docker('rm', '-r', '--', root)
                    counts['fixtureRemovalOperations'] += 1
                    root_owned = False
                    docker('php', '-r', 'if (file_exists($argv[1])) exit(1);', root)
                require(runtime() == runtime_before, 'Product runtime changed')
                restoration = dict(restored=True, originalSha256=SHA(batch.original), finalSha256=SHA(final),
                    temporarySourcesRemoved=not root_owned, **restored_state)
                record('restoration', runtime=runtime(), **restoration)
            except Exception as error:
                restoration = dict(restored=False, reason=type(error).__name__)
            counts.update(configurationApplyWrites=batch.applied_count, restorationWrites=batch.restoration_writes,
                          configurationWriteAttempts=batch.write_count)
        counts.update(successfulHostWrites=host_writes, nativeApplications=native_applications, nativeCommandAttempts=len(commands), restored=restoration['restored'])
        save(receipt/'restoration.json', restoration)
        save(receipt/'operation-counts.json', counts)
        for peer in peers:
            folder = receipt/peer['label']
            rows = api('/api/runs/'+peer['runId']+'/transcript')
            # capture validates and exports only original Run-scoped public SAML.
            save(folder/'transcript.json', rows)
            capture(folder, peer['runId'], rows)
            save(folder/'result-before.json', api('/api/runs/'+peer['runId']+'/result.json'))
        if peers:
            manifest = dict(schema='samlscope-ssp-metadata-entity-identity-v1', adapter=ADAPTER,
                campaignId='native-metadata-entity-identity', profile='metadata_idp', caseDigests=CASES,
                runId=peers[0]['runId'], planId=peers[0]['planId'], targetEntityId=TARGET,
                targetMetadataSha256=SHA((receipt/'target-metadata.xml').read_bytes()),
                operation='simultaneous-sources', peers=[{k: v for k, v in p.items() if k != 'created'} for p in peers],
                originals=originals, sources=locals().get('sources', []), sourceHashes=locals().get('source_hashes', {}))
            manifest['files'] = {str(p.relative_to(receipt)): SHA(p.read_bytes()) for p in receipt.rglob('*') if p.is_file()}
            save(receipt/'manifest.json', manifest)
        require(restoration['restored'], 'Restoration unproven; adoption forbidden')
    print('Native observations exported; replay and qualification required; no result adopted')


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--dry-run', action='store_true')
    p.add_argument('--repo', type=Path)
    p.add_argument('--output', type=Path)
    p.add_argument('--configuration', type=Path, help='Host config-override.php bound to the reference product')
    args = p.parse_args(argv)
    if args.dry_run:
        print(json.dumps(dry_plan(), indent=2))
        return
    if any(value is None for value in (args.repo, args.output, args.configuration)):
        p.error('Live collection requires --repo, --output and --configuration')
    live(args)


if __name__ == '__main__':
    main()
