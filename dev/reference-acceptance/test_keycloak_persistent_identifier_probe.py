"""Offline native producer QA. Synthetic originals here are never adoption evidence."""
import base64
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[2]
HELPER = Path(__file__).with_name('ProbeKeycloakPersistentIdentifier.java')
NATIVE = REPO / 'build/acceptance/reference-20261004/keycloak-forceauthn-mechanism-r2/receipt/native-complete'
JAVA = Path('/Library/Java/JavaVirtualMachines/jdk-21.jdk/Contents/Home/bin')
CLIENT = 'http://localhost:18080/p/plan_00000000000000000000000000'
ATTRIBUTE = 'saml.persistent.name.id.for.' + CLIENT
VALUE = 'G-72ea1487-e8bd-412b-b152-3c2f485b316a'
PRINCIPAL = 'owned-probe-principal'
FORMAT = 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent'


def record(value):
    raw = json.dumps(value, separators=(',', ':')).encode()
    return dict(method='GET', url='http://localhost:18180/admin/realms/local-test/native-model',
                status=200, recordedAt='2026-10-04T10:00:00Z', response_sha256=hashlib.sha256(raw).hexdigest(),
                response_base64=base64.b64encode(raw).decode())


def request(identifier, issuer=CLIENT):
    return f'''<p:AuthnRequest xmlns:p="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:s="urn:oasis:names:tc:SAML:2.0:assertion" ID="{identifier}" Version="2.0" IssueInstant="2026-10-04T10:00:00Z"><s:Issuer>{issuer}</s:Issuer><p:NameIDPolicy Format="{FORMAT}" AllowCreate="true"/></p:AuthnRequest>'''


def response(identifier, value, request_id):
    return f'''<p:Response xmlns:p="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:s="urn:oasis:names:tc:SAML:2.0:assertion" ID="{identifier}" Version="2.0" IssueInstant="2026-10-04T10:00:00Z" InResponseTo="{request_id}"><s:Issuer>http://localhost:18180/realms/local-test</s:Issuer><p:Status><p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></p:Status><s:Assertion ID="{identifier}_assertion" Version="2.0" IssueInstant="2026-10-04T10:00:00Z"><s:Issuer>http://localhost:18180/realms/local-test</s:Issuer><s:Subject><s:NameID Format="{FORMAT}">{value}</s:NameID></s:Subject></s:Assertion></p:Response>'''


class NativePersistentProbeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='native-persistent-probe-tests-')
        cls.root = Path(cls.temp.name).resolve()
        if not NATIVE.is_dir():
            cls.temp.cleanup()
            raise unittest.SkipTest('Independent archived native runtime is unavailable')
        jars = sorted(NATIVE.rglob('*.jar'))
        if len(jars) != 471:
            raise RuntimeError('Complete independent archived native runtime required')
        cls.cp = ':'.join(str(p.resolve()) for p in jars)
        cls.classes = cls.root / 'classes'
        cls.classes.mkdir()
        run = subprocess.run([str(JAVA / 'javac'), '-sourcepath', '', '-cp', cls.cp, '-d',
                              str(cls.classes), str(HELPER)], capture_output=True, text=True, timeout=45)
        if run.returncode:
            raise RuntimeError(run.stderr)
        if any(not p.name.startswith('ProbeKeycloakPersistentIdentifier') for p in cls.classes.rglob('*.class')):
            raise RuntimeError('Probe shadows product class')

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def fixture(self):
        client = dict(id='captured-client-id', clientId=CLIENT, protocol='saml', attributes={
            'saml_name_id_format': 'persistent', 'saml_force_name_id_format': 'true'}, protocolMappers=[])
        user = dict(id='captured-user-id', username=PRINCIPAL, attributes={})
        after = copy.deepcopy(user)
        after['attributes'] = {ATTRIBUTE: [VALUE]}
        mutant = copy.deepcopy(user)
        mutant['attributes'] = {ATTRIBUTE: [PRINCIPAL]}
        return {'native-client-before.json': client, 'native-client-after.json': copy.deepcopy(client),
                'native-user-before.json': user, 'native-user-after.json': after,
                'native-user-mutant-before.json': mutant, 'client-scopes-before.json': [],
                'client-scopes-after.json': [], 'user-profile-visible.json': dict(unmanagedAttributePolicy='ADMIN_EDIT')}

    def run_probe(self, change=None, xml_change=None, bad_digest=False):
        with tempfile.TemporaryDirectory(dir=self.root) as tmp:
            folder = Path(tmp)
            originals = folder / 'originals'
            originals.mkdir()
            values = self.fixture()
            if change:
                change(values)
            for name, value in values.items():
                row = record(value)
                if bad_digest and name == 'native-user-after.json':
                    row['response_sha256'] = '0' * 64
                (originals / name).write_text(json.dumps(row))
            xml = [request('_normal'), response('_normal_reply', VALUE, '_normal'),
                   request('_mutant'), response('_mutant_reply', PRINCIPAL, '_mutant')]
            if xml_change:
                xml_change(xml)
            inputs = []
            for i, raw in enumerate(xml):
                path = folder / f'original-{i}.xml'
                path.write_text(raw)
                inputs.append(str(path))
            output = folder / 'report.json'
            run = subprocess.run([str(JAVA / 'java'), '-Xmx512m', '-Dsamlscope.probe.source=' + str(HELPER),
                                  '-cp', str(self.classes) + ':' + self.cp, 'ProbeKeycloakPersistentIdentifier',
                                  str(folder), *inputs, str(output)], capture_output=True, text=True,
                                 cwd=REPO, timeout=30)
            return run, json.loads(output.read_text()) if output.exists() else None

    def rejected(self, reason, **kwargs):
        run, report = self.run_probe(**kwargs)
        self.assertNotEqual(run.returncode, 0)
        self.assertIsNone(report)
        self.assertIn(reason, run.stderr)

    def test_unchanged_native_uuid_creation_and_exact_saved_reuse(self):
        run, report = self.run_probe()
        self.assertEqual(run.returncode, 0, run.stderr)
        construction, reuse, mutant = report['traces']
        self.assertEqual(construction['attributesBefore'], {})
        self.assertEqual(construction['attributesAfter'], {ATTRIBUTE: [construction['nativeValue']]})
        self.assertEqual(construction['setSingleAttributeEffects'],
                         [dict(attribute=ATTRIBUTE, value=construction['nativeValue'])])
        self.assertEqual(reuse['nativeValue'], VALUE)
        self.assertEqual(reuse['setSingleAttributeEffects'], [])
        self.assertEqual(mutant['nativeValue'], PRINCIPAL)
        self.assertTrue(mutant['diagnosticOnly'])
        self.assertTrue(mutant['equalsDeclaredPrincipal'])
        self.assertFalse(construction['equalsDeclaredPrincipal'])
        self.assertTrue(any(x['samlNameIdMapper'] for x in report['mapperClosure']['factories']))
        self.assertFalse(report['randomnessSeededOrReplaced'])
        self.assertFalse(report['signatureValidationPerformed'])
        self.assertFalse(report['verdictAdopted'])

    def test_nonempty_construction_state_cannot_claim_uuid_creation(self):
        self.rejected('Construction baseline has native attributes',
                      change=lambda v: v['native-user-before.json']['attributes'].update({ATTRIBUTE: [VALUE]}))

    def test_global_attribute_cannot_substitute_native_uuid_constructor(self):
        self.rejected('Construction baseline has native attributes',
                      change=lambda v: v['native-user-before.json']['attributes'].update(
            {'saml.persistent.name.id.for.*': [VALUE]}))

    def test_saved_native_attribute_must_equal_original_response(self):
        self.rejected('Saved original attribute and signed NameID differ',
                      change=lambda v: v['native-user-after.json']['attributes'].update({ATTRIBUTE: ['different']}))

    def test_principal_control_must_match_actual_native_attribute(self):
        self.rejected('Original native principal-valued control is not bound',
                      change=lambda v: v['native-user-mutant-before.json']['attributes'].update({ATTRIBUTE: [VALUE]}))

    def test_response_must_bind_original_request(self):
        self.rejected('Response request mismatch',
                      xml_change=lambda xml: xml.__setitem__(1, response('_normal_reply', VALUE, '_unrelated')))

    def test_foreign_client_request_is_rejected(self):
        self.rejected('Foreign request client',
                      xml_change=lambda xml: xml.__setitem__(0, request('_normal', 'http://foreign.example')))

    def test_original_native_get_digest_is_checked(self):
        self.rejected('Original native response digest mismatch', bad_digest=True)

    def test_actual_native_nameid_mapper_bypass_is_rejected(self):
        def change(v):
            mapper = dict(id='mapper', protocol='saml', protocolMapper='saml-user-attribute-nameid-mapper')
            for name in ['native-client-before.json', 'native-client-after.json']:
                v[name]['protocolMappers'] = [mapper]
        self.rejected('Native NameID mapper bypasses selected producer', change=change)

    def test_nameid_mapper_in_any_captured_saml_scope_is_rejected(self):
        def change(v):
            scope = dict(id='saml-scope', protocol='saml', protocolMappers=[dict(
                id='mapper', protocol='saml', protocolMapper='saml-user-attribute-nameid-mapper')])
            for name in ['client-scopes-before.json', 'client-scopes-after.json']:
                v[name] = [scope]
        self.rejected('Native NameID mapper bypasses selected producer', change=change)

    def test_unknown_mapper_cannot_be_assumed_not_to_override_nameid(self):
        def change(v):
            mapper = dict(id='mapper', protocol='saml', protocolMapper='unknown-native-mapper')
            for name in ['native-client-before.json', 'native-client-after.json']:
                v[name]['protocolMappers'] = [mapper]
        self.rejected('Unknown native SAML mapper provider', change=change)

    def test_changed_scope_inventory_is_rejected(self):
        self.rejected('Complete native client scope inventory changed', change=lambda v:
                      v['client-scopes-after.json'].append(dict(id='new-scope', protocol='saml')))

    def test_native_omitted_empty_attributes_requires_visible_native_profile(self):
        run, report = self.run_probe(change=lambda v: v['native-user-before.json'].pop('attributes'))
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(report['traces'][0]['attributesBefore'], {})

    def test_hidden_unmanaged_attributes_cannot_be_treated_as_empty(self):
        self.rejected('Actual native ADMIN_EDIT attribute visibility required', change=lambda v:
                      v['user-profile-visible.json'].update(unmanagedAttributePolicy='DISABLED'))


if __name__ == '__main__':
    unittest.main()
