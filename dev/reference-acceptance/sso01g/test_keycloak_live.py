"""Native REST lifecycle fixtures, never product conformance evidence."""
import copy
import io
import json
from pathlib import Path
import socket
import tempfile
import unittest
from unittest.mock import patch
import urllib.error
import urllib.parse as urls

from keycloak_live import (BASE, CONDITION, EVIDENCE, JOB, MAPPER, REALM, InvestigationError,
                           KeycloakLive, LocalAdmin, NoRedirect, local_base, main, output_dir, public)


class NativeApiFixture:
    """Models generated IDs, nested executions, and orphaned authenticator configs."""
    def __init__(self, fail_at=None, after=False):
        self.roots = {'browser': dict(id='shared-browser', alias='browser', description='Shared',
                        providerId='basic-flow', topLevel=True, builtIn=True)}
        self.execs = {'browser': []}
        self.configs = {}
        self.clients = {}
        self.events = []
        self.token = 'memory-only-test-token'
        self.serial = 0
        self.writes = 0
        self.fail_at, self.after = fail_at, after
        self.read_failure = False

    def identifier(self):
        self.serial += 1
        return 'native-' + str(self.serial)

    def flattened(self, alias):
        result = []
        for row in self.execs[alias]:
            result.append(copy.deepcopy(row))
            if row.get('authenticationFlow'):
                result.extend(self.flattened(row['displayName']))
        for i, row in enumerate(result):
            row['index'] = i
        return result

    def get(self, path, *, missing=False):
        if self.read_failure:
            self.read_failure = False
            raise InvestigationError('Transient fixture read failure')
        return copy.deepcopy(self._get(path, missing))

    def _get(self, path, missing):
        if path == '/admin/serverinfo':
            return dict(systemInfo=dict(version='26.7.2'), features=[dict(name='STEP_UP_AUTHENTICATION_SAML', enabled=True)],
                        protocolMapperTypes=dict(saml=[dict(id=MAPPER, properties=[])]))
        if path.endswith('/descriptor'):
            return b'<EntityDescriptor/>'
        if path == REALM:
            return dict(realm='samlscope', browserFlow='browser')
        if path.endswith('/authenticator-providers'):
            return [dict(id=p) for p in (CONDITION, 'auth-username-form', 'auth-password-form')]
        if '/config-description/' in path:
            return dict(providerId=CONDITION, properties=[])
        if path == REALM + '/authentication/flows':
            return list(self.roots.values())
        if path.startswith(REALM + '/clients?'):
            query = urls.parse_qs(urls.urlsplit(path).query)
            if 'clientId' in query:
                return [v for v in self.clients.values() if v['clientId'] == query['clientId'][0]]
            start = int(query.get('first', [0])[0])
            return list(self.clients.values())[start:start + 100]
        if path.startswith(REALM + '/clients/'):
            return self.clients[path.rsplit('/', 1)[-1]]
        if path.startswith(REALM + '/authentication/flows/') and path.count('/') == 6:
            identifier = path.rsplit('/', 1)[-1]
            for rows in self.execs.values():
                for row in rows:
                    if row.get('flowId') == identifier:
                        return dict(id=identifier, alias=row['displayName'], providerId='basic-flow')
            return None
        if path.endswith('/executions'):
            return self.flattened(urls.unquote(path.split('/')[-2]))
        if '/authentication/config/' in path:
            cfg = self.configs.get(path.rsplit('/', 1)[-1])
            if cfg is None and not missing:
                raise InvestigationError('Missing fixture config')
            return cfg
        raise AssertionError('Unexpected GET ' + path)

    def write(self, path, method, body=None):
        self.writes += 1
        self.events.append(dict(method=method, path=path, status=None))
        fail = self.writes == self.fail_at
        if fail and not self.after:
            raise InvestigationError('Native write rejected')
        self._write(path, method, copy.deepcopy(body))
        if fail:
            raise InvestigationError('Native write acknowledgment lost')
        self.events[-1]['status'] = 204

    def _write(self, path, method, body):
        if path == REALM + '/authentication/flows' and method == 'POST':
            self.roots[body['alias']] = dict(body, id=self.identifier())
            self.execs[body['alias']] = []
        elif path.endswith('/executions/flow') and method == 'POST':
            parent = path.split('/')[-3]
            self.execs[body['alias']] = []
            self.execs[parent].append(dict(id=self.identifier(), flowId=self.identifier(), displayName=body['alias'],
                 authenticationFlow=True, requirement='DISABLED'))
        elif path.endswith('/executions/execution') and method == 'POST':
            parent = path.split('/')[-3]
            self.execs[parent].append(dict(id=self.identifier(), providerId=body['provider'],
                   requirement='DISABLED', authenticationFlow=False))
        elif path.endswith('/executions') and method == 'PUT':
            row = next(r for rows in self.execs.values() for r in rows if r['id'] == body['id'])
            row['requirement'] = body['requirement']
        elif '/authentication/executions/' in path and path.endswith('/config') and method == 'POST':
            row = next(r for rows in self.execs.values() for r in rows if r['id'] == path.split('/')[-2])
            identifier = self.identifier()
            self.configs[identifier] = dict(body, id=identifier)
            row['authenticationConfig'] = identifier
            row['alias'] = body['alias']
        elif path == REALM + '/clients' and method == 'POST':
            identifier = self.identifier()
            self.clients[identifier] = dict(body, id=identifier, secret='never-persist-this-native-generated-value')
            self.clients[identifier]['attributes']['saml.signing.private.key'] = 'never-persist-this-native-generated-value'
            self.clients[identifier]['attributes']['saml.signing.certificate'] = 'public fixture certificate'
        elif path.endswith('/protocol-mappers/models') and method == 'POST':
            client = self.clients[path.split('/')[-3]]
            client.setdefault('protocolMappers', []).append(dict(body, id=self.identifier()))
        elif '/clients/' in path and method == 'DELETE':
            del self.clients[path.rsplit('/', 1)[-1]]
        elif '/authentication/flows/' in path and method == 'DELETE':
            name = next(k for k, v in self.roots.items() if v['id'] == path.rsplit('/', 1)[-1])
            for key in list(self.execs):
                if key.startswith(name):
                    del self.execs[key]
            del self.roots[name]
        elif '/authentication/config/' in path and method == 'DELETE':
            del self.configs[path.rsplit('/', 1)[-1]]
        else:
            raise AssertionError('Unexpected write ' + path)


class LiveLifecycleTest(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory(dir=JOB)
        self.addCleanup(self.folder.cleanup)
        self.api = NativeApiFixture()
        self.driver = KeycloakLive(self.api, Path(self.folder.name))

    def test_complete_configuration_roundtrip_and_exact_restoration(self):
        result = self.driver.run()
        self.assertEqual([], result['errors'])
        self.assertEqual('configuration-roundtrip-complete', result['status'])
        self.assertTrue(result['restored'])
        self.assertTrue(result['allCasesHeld'])
        self.assertEqual(['normal', 'maximum'], result['modes'])
        self.assertEqual(2, result['managementReadbackConfirmations'])
        self.assertEqual(0, result['nativeAuthenticationExecutionsObserved'])
        self.assertEqual(0, result['counts']['host_write_successes'])
        self.assertEqual(0, result['counts']['product_effective_applications'])
        self.assertEqual(0, result['counts']['product_effective_restorations'])
        self.assertEqual(27, result['counts']['setting_write_attempts'] - result['counts']['restoration_write_attempts'])
        self.assertEqual(5, result['counts']['restoration_write_attempts'])
        restored = json.loads((self.driver.out / 'restoration.json').read_text())
        self.assertEqual(restored['original'], restored['restored'])
        for path in self.driver.out.glob('*.json'):
            text = path.read_text()
            self.assertNotIn('never-persist-this-native-generated-value', text)
            self.assertNotIn('memory-only-test-token', text)
        self.assertNotIn('outcome', result)
        self.assertNotIn('verdict', result)

    def test_rejected_write_and_lost_ack_at_every_configuration_write_restore(self):
        for after in (False, True):
            for number in range(1, 28):
                with self.subTest(after=after, write=number), tempfile.TemporaryDirectory(dir=JOB) as out:
                    api = NativeApiFixture(fail_at=number, after=after)
                    result = KeycloakLive(api, Path(out)).run()
                    self.assertEqual('incomplete', result['status'])
                    self.assertTrue(result['restored'], result['errors'])
                    self.assertEqual({'browser'}, set(api.roots))
                    self.assertFalse(api.clients)
                    self.assertFalse(api.configs)
                    self.assertEqual(result['counts']['setting_write_attempts'] - 1,
                                     result['counts']['native_write_successes'])

    def test_read_failure_after_applied_write_reconciles_before_cleanup(self):
        original = self.api.write
        def write(*args, **kwargs):
            original(*args, **kwargs)
            if self.api.writes == 10:
                self.api.read_failure = True
        self.api.write = write
        result = self.driver.run()
        self.assertEqual('incomplete', result['status'])
        self.assertTrue(result['restored'], result['errors'])

    def test_existing_namespace_refused_without_write_or_cleanup(self):
        self.api.roots[self.driver.name] = dict(self.api.roots['browser'], alias=self.driver.name)
        result = self.driver.run()
        self.assertEqual(0, self.api.writes)
        self.assertFalse(result['restored'])
        self.assertIn(self.driver.name, self.api.roots)

    def test_concurrent_owned_edit_is_preserved(self):
        self.driver.capture()
        self.driver.configure()
        self.api.clients[self.driver.expected['client']['id']]['name'] = 'operator changed'
        writes = self.api.writes
        with self.assertRaises(InvestigationError):
            self.driver.restore()
        self.assertEqual(writes, self.api.writes)
        # Test fixture cleanup only, never an instruction to overwrite a native edit.

    def test_unrelated_change_during_pending_write_not_accepted_for_cleanup(self):
        self.driver.capture()
        self.driver.configure()
        self.driver.pending = dict(path=REALM + '/authentication/flows/' + self.driver.name + '/executions',
                                   method='PUT', body=dict(id='nonexistent', requirement='DISABLED'))
        self.api.clients[self.driver.expected['client']['id']]['name'] = 'operator changed'
        with self.assertRaises(InvestigationError):
            self.driver.restore()

    def test_original_shared_flow_drift_blocks_restoration_confirmation(self):
        self.driver.capture()
        self.driver.configure()
        self.api.roots['browser']['description'] = 'External edit'
        with self.assertRaises(InvestigationError):
            self.driver.restore()
        self.assertFalse(self.driver.report['restored'])
        self.assertEqual('External edit', self.api.roots['browser']['description'])

    def test_journal_precedes_every_write(self):
        original = self.api.write
        def check(path, method, body=None):
            journal = json.loads((self.driver.out / 'journal.json').read_text())
            self.assertEqual(path, journal['pending']['path'])
            self.assertEqual(method, journal['pending']['method'])
            self.assertEqual(self.driver.expected, journal['expected'])
            return original(path, method, body)
        self.api.write = check
        result = self.driver.run()
        self.assertTrue(result['restored'], result['errors'])

    def test_mapper_absence_holds_before_writes(self):
        original = self.api.get
        def get(path, **kwargs):
            value = original(path, **kwargs)
            if path == '/admin/serverinfo':
                value['protocolMapperTypes']['saml'] = []
            return value
        self.api.get = get
        result = self.driver.run()
        self.assertTrue(result['allCasesHeld'])
        self.assertEqual(0, self.api.writes)

    def test_recovery_handles_lost_delete_ack_and_preserves_ack_counts(self):
        # Normal setup + maximum is 27 writes. Client deletion is write 28.
        api = NativeApiFixture(fail_at=28, after=True)
        driver = KeycloakLive(api, self.driver.out)
        report = driver.run()
        self.assertFalse(report['restored'])
        api.token = 'memory-only-test-token'
        api.events = []  # A restarted transport has its own operation history.
        recovered = KeycloakLive(api, self.driver.out).recover()
        self.assertTrue(recovered['restored'], recovered['errors'])
        self.assertEqual('configuration-restored-after-interruption', recovered['status'])
        self.assertEqual(32, recovered['counts']['setting_write_attempts'])
        self.assertEqual(31, recovered['counts']['native_write_successes'])
        self.assertEqual(5, recovered['counts']['restoration_write_attempts'])
        self.assertFalse(api.clients)
        self.assertFalse(api.configs)

    def test_process_restart_recovers_unacknowledged_config_write_from_journal(self):
        self.driver.capture()
        self.api.fail_at, self.api.after = 8, True
        with self.assertRaises(InvestigationError):
            self.driver.configure()
        restarted = KeycloakLive(self.api, self.driver.out)
        result = restarted.recover()
        self.assertTrue(result['restored'], result['errors'])
        self.assertEqual(7, result['counts']['native_write_successes'] - result['counts']['restoration_native_write_successes'])

    def test_live_driver_rejects_shared_writes_before_native_write(self):
        self.driver.capture()
        for path, method, body in (
            (REALM, 'PUT', {'browserFlow': 'replaced'}),
            (REALM + '/authentication/flows/browser/executions', 'PUT', {'id': 'shared', 'requirement': 'DISABLED'}),
            (REALM + '/clients/shared-client', 'DELETE', None),
            (REALM + '/authentication/config/shared-config', 'DELETE', None),
        ):
            with self.subTest(path=path), self.assertRaises(InvestigationError):
                self.driver.mutate(path, method, body)
        self.assertEqual(0, self.api.writes)

    def test_recovery_does_not_accept_wrong_namespace(self):
        self.driver.capture()
        with self.assertRaises(InvestigationError):
            KeycloakLive(self.api, self.driver.out, 'other').recover()



class TransportBoundaryTest(unittest.TestCase):
    def test_only_literal_authorized_loopback_endpoint(self):
        for url in ('http://localhost:18180', 'http://127.1:18180', 'http://[::1]:18180',
                    'http://127.0.0.1:18180@outside.invalid', 'https://127.0.0.1:18180',
                    'http://127.0.0.1:18181', BASE + '/admin', BASE + '?x=1', BASE + '#x'):
            with self.subTest(url=url), patch('keycloak_live.fixture_credentials', side_effect=AssertionError('credentials')):
                with self.assertRaises(ValueError):
                    LocalAdmin(url)
        self.assertEqual(BASE, local_base(BASE))

    def test_redirects_and_proxies_disabled_and_no_cookie_processor(self):
        api = LocalAdmin()
        self.assertEqual({}, next(h for h in api.opener.handlers if h.__class__.__name__ == 'ProxyHandler').proxies
                         if any(h.__class__.__name__ == 'ProxyHandler' for h in api.opener.handlers) else {})
        self.assertIsNone(NoRedirect().redirect_request(None, None, None, None, None, None))
        self.assertFalse(any(h.__class__.__name__ == 'HTTPCookieProcessor' for h in api.opener.handlers))

    def test_no_authnrequest_or_arbitrary_url_path(self):
        api = LocalAdmin()
        with patch.object(api.opener, 'open', side_effect=AssertionError('network')):
            for path in ('http://outside.invalid', '//outside.invalid', '/realms/samlscope/protocol/saml',
                         '/admin/serverinfo#x', '/admin/realms/other/clients'):
                with self.subTest(path=path), self.assertRaises(ValueError):
                    api.get(path)

    def test_redirect_error_and_body_are_not_persisted(self):
        api = LocalAdmin()
        api.token = 'sensitive-fixture-token'
        error = urllib.error.HTTPError(BASE + '/admin/serverinfo', 302, 'sensitive-fixture-body',
                                        {'Location': 'https://outside.invalid'}, io.BytesIO(b'sensitive-fixture-body'))
        with patch.object(api.opener, 'open', side_effect=error), self.assertRaises(InvestigationError) as result:
            api.get('/admin/serverinfo')
        self.assertNotIn('sensitive-fixture', str(result.exception))
        self.assertEqual([dict(method='GET', path='/admin/serverinfo', status=302)], api.events)

    def test_public_projection_strips_generated_native_credentials_and_rejects_headers(self):
        self.assertEqual(dict(a=1), public(dict(a=1, secret='discard', registrationAccessToken='discard')))
        for key in ('Cookie', 'Set-Cookie', 'Authorization', 'password', 'saml.signing.private.key'):
            with self.subTest(key=key), self.assertRaises(InvestigationError):
                public({key: 'must not persist'})

    def test_output_symlink_and_outside_root_rejected(self):
        with tempfile.TemporaryDirectory(dir=JOB) as directory:
            p = Path(directory)
            (p / 'alias').symlink_to('/tmp', target_is_directory=True)
            with self.assertRaises(ValueError):
                output_dir(p / 'alias' / 'x')
        with self.assertRaises(ValueError):
            output_dir(ROOT_FOR_TEST / 'docs' / 'forbidden')

    def test_dry_run_and_explicit_mode_without_socket_or_credentials(self):
        with tempfile.TemporaryDirectory(dir=JOB) as directory, \
             patch.object(socket, 'socket', side_effect=AssertionError('network')), \
             patch('keycloak_live.fixture_credentials', side_effect=AssertionError('credentials')), \
             patch('sys.stdout', new_callable=io.StringIO):
            self.assertEqual(0, main(['--dry-run', '--out', directory]))
            with self.assertRaises(ValueError):
                main(['--dry-run', '--out', directory])
        with patch('sys.stderr', new_callable=io.StringIO):
            for flags in ([], ['--dry-run', '--live']):
                with self.assertRaises(SystemExit):
                    main(flags + ['--out', str(JOB / 'unused')])


ROOT_FOR_TEST = EVIDENCE.parents[3]
if __name__ == '__main__':
    unittest.main()
