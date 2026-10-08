"""Count recorded messages and queued actions; never infer zero dispatches from intent."""
import hashlib
import json
import re
import secrets
import subprocess
from pathlib import Path

SCHEMA = 'samlscope-run-protocol-operations-v1'
STATUSES = {'PENDING', 'SENDING', 'UNKNOWN_DELIVERY', 'BLOCKED_ON_CREDENTIAL', 'SENT'}

def require(value, reason):
    if not value:
        raise ValueError(reason)

def validate(snapshot):
    require(snapshot.get('schema') == SCHEMA, 'Unknown operation snapshot')
    require(re.fullmatch(r'run_[0-9A-HJKMNP-TV-Z]{26}', snapshot.get('runId', '')), 'Foreign Run')
    require(re.fullmatch(r'plan_[0-9A-HJKMNP-TV-Z]{26}', snapshot.get('planId', '')), 'Foreign Plan')
    require(snapshot.get('runStatus') in {'CREATED', 'PREFLIGHT', 'RUNNING', 'COMPLETED', 'ABORTED'}, 'Unknown Run state')
    for name, identity, digest in [('transcriptEntries', 'id', 'entrySha256'),
                                   ('outboxActions', 'actionId', 'actionSha256'),
                                   ('caseExecutions', 'caseId', 'documentSha256')]:
        rows = snapshot.get(name)
        require(isinstance(rows, list) and len(rows) <= 20_000, 'Missing bounded ' + name)
        require(len({r.get(identity) for r in rows}) == len(rows), 'Duplicate ' + name)
        for row in rows:
            require(isinstance(row.get(identity), str) and row[identity], 'Missing operation identity')
            require(re.fullmatch(r'[0-9a-f]{64}', row.get(digest, '')), 'Missing original digest')
    for row in snapshot['outboxActions']:
        require(row.get('status') in STATUSES, 'Unknown delivery state')
    return snapshot

def difference(before, after):
    validate(before); validate(after)
    require((before['runId'], before['planId']) == (after['runId'], after['planId']), 'Foreign operation scope')
    old_transcripts = {r['id']: r for r in before['transcriptEntries']}
    new_transcripts = {r['id']: r for r in after['transcriptEntries']}
    require(all(new_transcripts.get(k) == v for k, v in old_transcripts.items()), 'Original transcript changed')
    old_actions = {r['actionId']: r for r in before['outboxActions']}
    new_actions = {r['actionId']: r for r in after['outboxActions']}
    require(all(k in new_actions and new_actions[k]['actionSha256'] == v['actionSha256']
                for k, v in old_actions.items()), 'Original action changed')
    entries = [r for k, r in new_transcripts.items() if k not in old_transcripts]
    # Metadata preparation is observable HTTP work, but is not a SAML protocol message.
    outbound = [r for r in entries if r.get('direction') == 'OUTBOUND'
                and (r.get('type', '').endswith(('Request', 'Response')) or r.get('type') == 'SoapFault')]
    actions = [r for k, r in new_actions.items() if k not in old_actions]
    old_cases = {r['caseId'] for r in before['caseExecutions']}
    return {
        'outboundProtocolMessagesRecorded': len(outbound),
        'outboundProtocolTranscriptIds': [r['id'] for r in outbound],
        'outboxActionsCreated': len(actions),
        'outboxActionIdsCreated': [r['actionId'] for r in actions],
        'outboxDeliveryStatesAfter': {s: sum(r['status'] == s for r in after['outboxActions']) for s in sorted(STATUSES)},
        'caseExecutionsCreated': sum(r['caseId'] not in old_cases for r in after['caseExecutions']),
        'networkAttemptCount': None,
        'networkAttemptCountBasis': 'Snapshots measure recorded messages and action states, not unrecorded network retries.',
    }


class OperationSnapshots:
    """Compile once for this capture and read only the actual Suite database."""
    def __init__(self, repository, output, run, container='samlscope-reference-suite'):
        self.repository = Path(repository)
        self.output = Path(output)
        self.run = run
        self.container = container
        self.remote = '/tmp/samlscope-protocol-counts-' + secrets.token_hex(12)
        self.installed = False

    @staticmethod
    def command(args):
        return subprocess.run(list(map(str, args)), check=True, capture_output=True, timeout=120)

    def __enter__(self):
        require(re.fullmatch(r'run_[0-9A-HJKMNP-TV-Z]{26}', self.run), 'Foreign actual Run')
        source = self.repository/'dev/reference-acceptance/ReadRunProtocolOperations.java'
        jars = sorted((self.repository/'api/build/install/samlscope/lib').glob('*.jar'))
        require(jars, 'Qualified host runtime classpath required')
        digest = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
        hashes = {p.name: digest(p) for p in jars}
        live = self.command(['docker', 'exec', self.container, 'sha256sum',
                             *['/opt/samlscope/lib/' + p.name for p in jars]]).stdout.decode()
        actual = {line.split()[1].rsplit('/', 1)[-1]: line.split()[0] for line in live.splitlines()}
        require(actual == hashes, 'Counter compiler inputs differ from actual runtime')
        classes = self.output/'protocol-counter-classes'
        classes.mkdir()
        java = Path('/Library/Java/JavaVirtualMachines/jdk-21.jdk/Contents/Home/bin/javac')
        self.command([java, '-sourcepath', '', '-cp', ':'.join(map(str, jars)), '-d', classes, source])
        require(hashes == {p.name: digest(p) for p in jars}, 'Counter inputs changed during compilation')
        compiled = {str(p.relative_to(classes)): digest(p) for p in classes.rglob('*.class')}
        require(set(compiled) == {'com/samlscope/runner/cases/ReadRunProtocolOperations.class'}, 'Counter shadows production code')
        (self.output/'protocol-counter-generation.json').write_text(json.dumps({
            'sourceSha256': digest(source), 'runtimeClasspathSha256': hashes,
            'classesSha256': compiled, 'compilations': 1, 'outcomeCache': False,
        }, sort_keys=True, indent=2) + '\n')
        self.command(['docker', 'exec', self.container, 'mkdir', self.remote])
        self.installed = True
        try:
            self.command(['docker', 'cp', classes, self.container + ':' + self.remote + '/classes'])
        except BaseException:
            self.__exit__(None, None, None)
            raise
        return self

    def capture(self, stage):
        require(stage in {'before-initial', 'before-profile-start', 'after-profile-start'}, 'Unknown counter stage')
        path = self.output/(stage + '-operations.json')
        require(not path.exists(), 'Counter original already exists')
        remote_output = self.remote + '/' + stage + '.json'
        self.command(['docker', 'exec', self.container, 'java', '-cp',
                      '/opt/samlscope/lib/*:' + self.remote + '/classes',
                      'com.samlscope.runner.cases.ReadRunProtocolOperations',
                      '/data', self.run, remote_output])
        self.command(['docker', 'cp', self.container + ':' + remote_output, path])
        snapshot = validate(json.loads(path.read_bytes()))
        require(snapshot['runId'] == self.run, 'Foreign captured Run')
        return snapshot

    def __exit__(self, *ignored):
        if self.installed:
            require(re.fullmatch(r'/tmp/samlscope-protocol-counts-[0-9a-f]{24}', self.remote), 'Foreign counter cleanup')
            # docker cp preserves host ownership; remove only this owned generation as root.
            self.command(['docker', 'exec', '-u', '0', self.container, 'rm', '-rf', self.remote])
            self.installed = False
