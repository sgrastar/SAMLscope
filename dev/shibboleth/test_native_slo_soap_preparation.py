"""Host-only SOAP preparation contracts; no Docker, network, login, or target writes."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
import xml.etree.ElementTree as ET

p = Path(__file__).with_name('native_slo_soap_preparation.py')
spec = importlib.util.spec_from_file_location('tested_soap_preparation', p)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
PLAN = 'plan_' + '0' * 26
RUN = 'run_' + '1' * 26
ENTITY = 'http://localhost:18080/p/' + PLAN
PRIMARY = ('<md:EntityDescriptor xmlns:md="' + m.MD + '" entityID="' + ENTITY + '">'
           '<md:SPSSODescriptor protocolSupportEnumeration="' + m.SAML + '">'
           '<md:KeyDescriptor use="signing"><public>actual-public-key</public></md:KeyDescriptor>'
           '<md:KeyDescriptor use="encryption"><public>other-public-key</public></md:KeyDescriptor>'
           '<md:SingleLogoutService Binding="' + m.SOAP_BINDING + '" Location="' + ENTITY + '/sp/slo/soap?mdv=control"/>'
           '<md:SingleLogoutService Binding="post" Location="' + ENTITY + '/sp/slo"/>'
           '<md:AssertionConsumerService Binding="post" Location="' + ENTITY + '/sp/acs/0" index="0"/>'
           '<md:AssertionConsumerService Binding="paos" Location="' + ENTITY + '/sp/paos" index="1"/>'
           '</md:SPSSODescriptor><md:IDPSSODescriptor protocolSupportEnumeration="' + m.SAML + '"/>'
           '</md:EntityDescriptor>').encode()
PROVIDERS = ('<MetadataProvider xmlns="' + m.PROVIDER + '" id="existing"><MetadataProvider id="old" metadataFile="/original.xml"/></MetadataProvider>').encode()
FLOW = Path(__file__).resolve().parents[2] / 'build/acceptance/reference-20261003/shibboleth-metadata-key-cluster-preflight-r1/native-slo-source/slo-back-flow.xml'


class SoapPreparationTests(unittest.TestCase):
    def test_all_four_entities_advertise_soap_without_changing_original_keys_acs_or_other_role(self):
        raw, peers = m.soap_metadata(PRIMARY, PLAN, RUN, 'failure')
        entities = ET.fromstring(raw).findall('{' + m.MD + '}EntityDescriptor')
        self.assertEqual(len(entities), 4)
        self.assertEqual(len(peers), 3)
        self.assertIsNotNone(entities[0].find('{' + m.MD + '}IDPSSODescriptor'))
        original_sp = ET.fromstring(PRIMARY).find('{' + m.MD + '}SPSSODescriptor')
        for entity in entities:
            sp = entity.find('{' + m.MD + '}SPSSODescriptor')
            self.assertEqual([ET.tostring(n) for n in sp.findall('{' + m.MD + '}KeyDescriptor')],
                             [ET.tostring(n) for n in original_sp.findall('{' + m.MD + '}KeyDescriptor')])
            self.assertEqual([ET.tostring(n) for n in sp.findall('{' + m.MD + '}AssertionConsumerService')],
                             [ET.tostring(n) for n in original_sp.findall('{' + m.MD + '}AssertionConsumerService')])
            endpoints = sp.findall('{' + m.MD + '}SingleLogoutService')
            self.assertEqual(len(endpoints), 1)
            self.assertEqual(endpoints[0].get('Binding'), m.SOAP_BINDING)
            self.assertIn('run=' + RUN, endpoints[0].get('Location'))
        self.assertIn('mdv=control', entities[0].find('.//{' + m.MD + '}SingleLogoutService').get('Location'))

    def test_only_failure_peer_uses_failure_route_and_remaining_routes_are_distinct(self):
        _, rows = m.soap_metadata(PRIMARY, PLAN, RUN, 'failure')
        self.assertTrue(rows[0]['soapEndpoint'].split('?')[0].endswith('/sp/slo-fail'))
        self.assertTrue(rows[1]['soapEndpoint'].split('?')[0].endswith('/sp/slo/soap'))
        self.assertTrue(rows[2]['soapEndpoint'].split('?')[0].endswith('/idp/slo/soap'))
        self.assertEqual(len({r['soapEndpoint'] for r in rows}), 3)

    def test_all_success_control_changes_only_failing_endpoint_not_keys_entities_or_acs(self):
        failure, _ = m.soap_metadata(PRIMARY, PLAN, RUN, 'failure')
        success, _ = m.soap_metadata(PRIMARY, PLAN, RUN, 'all-success')
        a, b = ET.fromstring(failure), ET.fromstring(success)
        endpoint = a[1].find('.//{' + m.MD + '}SingleLogoutService')
        endpoint.set('Location', b[1].find('.//{' + m.MD + '}SingleLogoutService').get('Location'))
        self.assertEqual(ET.tostring(a), ET.tostring(b))

    def test_foreign_plan_run_and_missing_primary_soap_are_rejected(self):
        for raw in (PRIMARY.replace(PLAN.encode(), ('plan_' + '2' * 26).encode()),
                    PRIMARY.replace(m.SOAP_BINDING.encode(), b'not-soap'),
                    PRIMARY.replace(b'mdv=control', ('run=' + 'run_' + '2' * 26).encode())):
            with self.assertRaises(ValueError):
                m.soap_metadata(raw, PLAN, RUN, 'failure')
        with self.assertRaises(ValueError):
            m.soap_metadata(PRIMARY, PLAN, 'invalid', 'failure')

    def test_capability_and_duplicate_run_queries_never_enter_public_fixture(self):
        for query in ('AuthState=private', 'execution=e1s1', 'SessionKey=private', 'run=' + RUN + '&amp;run=' + RUN):
            raw = PRIMARY.replace(b'mdv=control', query.encode())
            with self.assertRaises(ValueError):
                m.soap_metadata(raw, PLAN, RUN, 'failure')

    def test_provider_addition_preserves_old_entries_and_has_unique_owned_source(self):
        configured, source = m.provider_configuration(PROVIDERS, RUN)
        root = ET.fromstring(configured)
        self.assertEqual(root[1].get('id'), 'old')
        self.assertEqual(root[1].get('metadataFile'), '/original.xml')
        self.assertEqual(root[0].get('metadataFile'), source)
        with self.assertRaises(ValueError):
            m.provider_configuration(configured, RUN)

    def test_real_stock_backflow_failure_transition_is_sequential_but_frontflow_is_not(self):
        raw = FLOW.read_bytes()
        self.assertTrue(m.sequential_flow_contract(raw)['sequentialSubflowTransition'])
        for mutated in (raw.replace(b'<transition to="PopulateNextLogoutPropagationContext" />',
                                    b'<transition on="proceed" to="PopulateNextLogoutPropagationContext" />'),
                        raw.replace(b'id="BuildResponse"', b'id="OtherResponse"'),
                        FLOW.with_name('slo-front-abstract-flow.xml').read_bytes()):
            with self.assertRaises(ValueError):
                m.sequential_flow_contract(mutated)

    def test_raw_soap_is_preserved_and_body_confusion_is_rejected(self):
        raw = ('<S:Envelope xmlns:S="' + m.SOAP + '"><S:Body><p:LogoutRequest xmlns:p="' + m.SAML + '" ID="_actual"/></S:Body></S:Envelope>').encode()
        self.assertEqual(m.soap_message(raw, 'LogoutRequest').get('ID'), '_actual')
        for bad in (b'<LogoutRequest/>', raw.replace(b'</S:Body>', b'<extra/></S:Body>'),
                    raw.replace(b'LogoutRequest', b'LogoutResponse')):
            with self.assertRaises(ValueError):
                m.soap_message(bad, 'LogoutRequest')

    def test_preparation_is_new_attempt_public_only_and_not_runtime_readiness(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / 'fresh-soap-attempt'
            manifest = m.write_preparation(output, PRIMARY, PROVIDERS, FLOW.read_bytes(), PLAN, RUN, 'failure')
            self.assertEqual(manifest['status'], 'prepared-not-applied')
            self.assertFalse(manifest['affectsVerdict'])
            self.assertTrue(all(v == 0 for v in manifest['actualOperations'].values()))
            for name, row in manifest['files'].items():
                self.assertEqual(m.sha((output / name).read_bytes()), row['sha256'])
            with self.assertRaises(FileExistsError):
                m.write_preparation(output, PRIMARY, PROVIDERS, FLOW.read_bytes(), PLAN, RUN, 'failure')


if __name__ == '__main__':
    unittest.main()
