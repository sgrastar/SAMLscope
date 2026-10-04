import base64
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET

path = Path(__file__).with_name('registered_signer_campaign.py')
spec = importlib.util.spec_from_file_location('shib_registered_signer_campaign_tested', path)
collector = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = collector
spec.loader.exec_module(collector)


def audit(value):
    return ('<beans xmlns="http://www.springframework.org/schema/beans" '
            'xmlns:util="http://www.springframework.org/schema/util"><util:map '
            'id="shibboleth.AuditFormattingMap"><entry key="Shibboleth-Audit" '
            'value="' + value + '"/></util:map></beans>').encode()


def fixture(entity, key):
    return ('<md:EntityDescriptor xmlns:md="' + collector.MD + '" xmlns:ds="' + collector.DS +
            '" entityID="' + entity + '"><ds:Signature/><md:SPSSODescriptor AuthnRequestsSigned="true">'
            '<md:KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>' +
            base64.b64encode(key).decode() + '</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>'
            '<md:AssertionConsumerService index="0" Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" '
            'Location="' + entity + '/sp/acs/0"/></md:SPSSODescriptor></md:EntityDescriptor>').encode()


class CampaignTests(unittest.TestCase):
    def test_capacity_guard_precedes_configuration_and_login(self):
        with patch.object(sys, 'argv', ['campaign', '--output', '/private/tmp/unused-shib-signers']), \
             patch.object(collector.os, 'statvfs', return_value=SimpleNamespace(f_bavail=0, f_frsize=4096)), \
             patch.object(collector, 'api') as api, patch.object(collector, 'SharedClient') as client, \
             patch.object(collector.Path, 'mkdir') as mkdir:
            with self.assertRaises(SystemExit) as result:
                collector.main()
        self.assertEqual(result.exception.code, 2)
        api.assert_not_called(); client.assert_not_called(); mkdir.assert_not_called()

    def test_already_usable_native_audit_preserves_original_bytes(self):
        raw = audit(collector.FORMAT)
        with patch.object(collector, 'signature_audit') as rewrite:
            self.assertEqual(collector.audit_configuration(raw), raw)
        rewrite.assert_not_called()

    def test_ambiguous_audit_stops_before_any_write(self):
        raw = audit(collector.FORMAT).replace(b'</util:map>', b'<entry key="Shibboleth-Audit" value="another"/></util:map>')
        with self.assertRaises(ValueError): collector.audit_configuration(raw)

    def test_new_providers_preserve_existing_chain_and_separate_peers(self):
        old = ('<MetadataProvider xmlns="' + collector.N + '" xmlns:xsi="' + collector.XSI +
               '" xsi:type="ChainingMetadataProvider" id="original"><MetadataProvider '
               'xsi:type="FilesystemMetadataProvider" id="retained" metadataFile="/old.xml"/></MetadataProvider>').encode()
        runs = ['run_' + '0' * 25 + '1', 'run_' + '0' * 25 + '2']
        peers = [dict(runId=run, sourcePath='/opt/reference-idp/metadata/registered-signer-' + run + '.xml') for run in runs]
        root = ET.fromstring(collector.provider_configuration(old, peers))
        self.assertEqual([n.get('id') for n in root], ['RegisteredSigner' + runs[0], 'RegisteredSigner' + runs[1], 'retained'])
        self.assertEqual(root[-1].get('metadataFile'), '/old.xml')
        with self.assertRaises(ValueError): collector.provider_configuration(old, [dict(runId=runs[0], sourcePath='/tmp/../unsafe')])

    def test_public_fixture_rejects_foreign_acs_or_unsigned_mode(self):
        entity = 'http://localhost:18080/p/plan_' + '0' * 26
        raw = fixture(entity, b'public-DER')
        self.assertEqual(collector.public_fixture(raw, entity), collector.SHA(b'public-DER'))
        for value in (raw.replace(b'AuthnRequestsSigned="true"', b'AuthnRequestsSigned="false"'),
                      raw.replace((entity + '/sp/acs/0').encode(), b'https://external.invalid/acs')):
            with self.assertRaises(ValueError): collector.public_fixture(value, entity)

    def test_second_credentials_are_blocked_before_transport_without_values(self):
        records = []; client = collector.SharedClient(records)
        with patch.object(collector.Client, 'request', return_value=('http://localhost:18280/login', '', 200)) as transport:
            client.request('http://localhost:18280/login', {'j_password': 'memory-only'})
            with self.assertRaises(ValueError): client.request('http://localhost:18280/login', {'j_password': 'memory-only'})
        self.assertEqual(transport.call_count, 1)
        self.assertEqual((client.credential_posts, client.credential_attempts), (1, 2))
        self.assertNotIn('memory-only', repr(client.__dict__))
        self.assertEqual(records, [])

    def test_shared_jar_never_confirms_fresh_session(self):
        with patch.object(collector.Client, 'request') as transport:
            with self.assertRaises(ValueError): collector.SharedClient([]).request('http://localhost:18080/probe', {'freshSessionConfirmed': 'true'})
        transport.assert_not_called()

    def test_nonordinary_requests_do_not_reuse_authentication_or_send(self):
        for attribute in ('ForceAuthn', 'IsPassive'):
            for value in ('true', '1', 'TRUE', ''):
                request = '<AuthnRequest ID="_request" ' + attribute + '="' + value + '"/>'
                fields = {'SAMLRequest': base64.b64encode(request.encode()).decode()}
                client = collector.SharedClient([])
                with patch.object(collector.Client, 'request') as transport:
                    with self.assertRaises(ValueError): client.request('http://localhost:18280/idp/profile/SAML2/POST/SSO', fields)
                transport.assert_not_called(); self.assertEqual(client.native_post_attempts, 0)

    def test_redirect_attempt_counts_preserve_raw_signed_query(self):
        client = collector.SharedClient([])
        handlers = [h for h in client.op.handlers if isinstance(h, collector.urllib.request.HTTPRedirectHandler)]
        query = 'SAMLRequest=raw%2Bbytes&RelayState=a%252Bb&Signature=raw%2Fsignature'
        result = handlers[0].redirect_request(collector.urllib.request.Request('http://localhost:18080/start'), None,
            302, '', {}, 'http://localhost:18280/idp?'+query)
        self.assertEqual(result.full_url, 'http://localhost:18280/idp?'+query)
        self.assertEqual(client.native_redirect_attempts, 1)
        self.assertNotIn(query, repr(client.__dict__))

    def test_native_public_error_has_actual_http_hash_and_aliases(self):
        records = []; client = collector.SharedClient(records)
        raw = b'<AuthnRequest xmlns="urn:oasis:names:tc:SAML:2.0:protocol" ID="_request"/>'
        page = '<h1>Message Security Error</h1>'
        with patch.object(collector.Client, 'request', return_value=('http://localhost:18280/idp', page, 400)):
            client.request('http://localhost:18280/idp', {'SAMLRequest': base64.b64encode(raw).decode()})
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]['requestSha256'], collector.SHA(raw))
        self.assertEqual(records[0]['responseBodySha256'], collector.SHA(page.encode()))
        self.assertEqual(records[0]['responseBodyBytes'], len(page.encode()))
        self.assertEqual(records[0]['finishedAt'], records[0]['completedAt'])
        self.assertEqual(records[0]['method'], 'POST')
        self.assertEqual(client.native_post_attempts, 1)

    def test_terminal_and_native_records_reject_private_material(self):
        self.assertTrue(collector.public_terminal('<h1>Public error</h1>'))
        for page in ('<INPUT name="password">', '< input value="csrf">', 'SAMLResponse', 'Cookie: private',
                     'Authorization: private', 'x' * 262145):
            self.assertFalse(collector.public_terminal(page))
        for key in ('password', 'private_key', 'Authorization', 'set-cookie', 'access_token'):
            with self.assertRaises(ValueError): collector.reject_sensitive({'nested': [{key: 'no-export'}]})
        collector.reject_sensitive({'credentialPosts': 1, 'credentialValuesPersisted': False, 'X509Certificate': 'public'})

    def test_partial_provider_write_is_restored_and_login_never_started(self):
        """Exercise main's actual finally after a native write fails after modifying its file."""
        providers = ('<MetadataProvider xmlns="' + collector.N + '" xmlns:xsi="' + collector.XSI +
                     '" xsi:type="ChainingMetadataProvider" id="original"/>').encode()
        audit_raw = audit(collector.FORMAT)
        store = {collector.PROVIDERS: providers, collector.AUDIT: audit_raw}
        target = b'<EntityDescriptor entityID="http://localhost:18280/idp/shibboleth"/>'
        run_ids = ['run_' + '0' * 25 + '1', 'run_' + '0' * 25 + '2']
        plan_ids = ['plan_' + '0' * 25 + '1', 'plan_' + '0' * 25 + '2']
        plans = []; failed = False
        def api(path, body=None):
            if path == '/api/plans':
                plan = plan_ids[len(plans)]; plans.append(plan); return {'plan': {'plan': {'id': plan}}}
            if path.endswith('/runs'):
                index = plan_ids.index(path.split('/')[3]); return {'run': {'id': run_ids[index], 'planId': plan_ids[index]}}
            if path.endswith('/preflight'): return {'status': 'OK'}
            raise AssertionError('Unexpected API before partial write: '+path)
        def command(args, **kwargs):
            nonlocal failed
            if args[:2] == ['docker', 'inspect']:
                return subprocess.CompletedProcess(args, 0, json.dumps({'id':'a'*64, 'image':'sha256:'+'b'*64,
                    'running':True, 'startedAt':'2026-10-02T00:00:00Z', 'mounts':[]}).encode(), b'')
            if args[:2] == ['docker', 'cp']:
                Path(args[-1]).write_bytes(target); return subprocess.CompletedProcess(args, 0, b'', b'')
            self.assertEqual(args[:4], ['docker', 'exec', '-i', collector.CONTAINER])
            native = args[4:]; stdout = b''; code = 0
            if native[0] == 'cat': stdout = store[native[1]]
            elif native[:2] == ['sh', '-c'] and native[2].startswith('test -e '):
                field = native[2].split()[2]; stdout = b'exists\n' if field in store else b''
            elif native[:2] == ['sh', '-c'] and native[2].startswith('cat > '):
                field = native[2][6:]; store[field] = kwargs['input']
                if field == collector.PROVIDERS and not failed:
                    failed = True; code = 1
            elif native[0] == 'rm': store.pop(native[-1], None)
            elif native[0].endswith('reload-service.sh'): stdout = b'reloaded'
            else: raise AssertionError('Unexpected native command: '+repr(native))
            return subprocess.CompletedProcess(args, code, stdout, b'')
        def urlopen(url, **kwargs):
            entity = url.removesuffix('/metadata'); index = plan_ids.index(entity.rsplit('/', 1)[1])
            raw = fixture(entity, ('public-'+str(index)).encode())
            response = SimpleNamespace(read=lambda: raw)
            response.__enter__ = lambda self: self
            class Response:
                def __enter__(self): return response
                def __exit__(self, *unused): pass
            return Response()
        with tempfile.TemporaryDirectory(prefix='shib-signer-restoration-test-') as temp:
            out = Path(temp)/'attempt'
            with patch.object(sys, 'argv', ['campaign', '--output', str(out)]), \
                 patch.object(collector, 'api', side_effect=api), patch.object(collector.subprocess, 'run', side_effect=command), \
                 patch.object(collector.urllib.request, 'urlopen', side_effect=urlopen), \
                 patch.object(collector, 'recorded', return_value={'reference':'tx_mock','sha256':'0'*64}), \
                 patch.object(collector.SharedClient, 'flow') as flow:
                with self.assertRaisesRegex(ValueError, 'Native command failed'): collector.main()
            flow.assert_not_called()
            counts = json.loads((out/'operation-counts.json').read_bytes())
            restoration = json.loads((out/'restoration.json').read_bytes())
            self.assertTrue(failed); self.assertTrue(restoration['restored'])
            self.assertEqual(store, {collector.PROVIDERS: providers, collector.AUDIT: audit_raw})
            self.assertEqual(counts['nativeConfigurationWrites'], 4)
            self.assertEqual(counts['restorationWrites'], 1)
            self.assertEqual(counts['protocolSubmissions'], 0)
            self.assertEqual(counts['credentialPosts'], 0)
            self.assertEqual(len(restoration['temporarySourcesRemoved']), 2)
            writes = [row for row in json.loads((out/'operations.json').read_bytes()) if row['operation'] == 'write']
            self.assertFalse(next(row for row in writes if row['label']=='prepare-native-providers')['readBack'])
            self.assertTrue(next(row for row in writes if row['label']=='restore-metadata-providers.xml')['readBack'])


if __name__ == '__main__': unittest.main()
