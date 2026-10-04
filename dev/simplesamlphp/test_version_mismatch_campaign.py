import copy
import importlib.util
from pathlib import Path
import sys
import base64,zlib,urllib.parse
import json
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('version_campaign',HERE/'version_mismatch_campaign.py');campaign=importlib.util.module_from_spec(spec);spec.loader.exec_module(campaign)
preflight=sys.modules['version_mismatch_native_preflight']

class VersionCampaignTests(unittest.TestCase):
    def setUp(self):
        self.sources={name:(campaign.REPO/'runner/src/test/resources/version-mismatch'/('ssp-'+name)).read_bytes() for name in preflight.SSP_SOURCES}
        self.reflection={}
        for name,(path,sha) in preflight.SSP_SOURCES.items():
            prefix='messageClass' if name=='Message.php' else 'utilsClass';self.reflection[prefix+'File']=path;self.reflection[prefix+'SourceSha256']=sha
        self.runtime=dict(containerId='a'*64,imageId='sha256:'+'b'*64,running=True,mounts=[dict(Destination='/var/simplesamlphp/config/config-override.php',Source='/host/config.php',Type='bind',RW=False,Mode='ro',Propagation='rprivate')])
    def xml(self,fixture,action='action_test',issuer='https://suite.example/sp',acs='https://suite.example/acs',endpoint='https://target.example/sso'):
        version='1.1' if fixture=='version-1-1' else '2.0';at='not-a-saml-timestamp' if fixture=='invalid-issue-instant' else '2026-10-03T19:00:00Z'
        return (f'<p:AuthnRequest xmlns:p="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:s="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:d="http://www.w3.org/2000/09/xmldsig#" ID="_{action}" Version="{version}" IssueInstant="{at}" Destination="{endpoint}" AssertionConsumerServiceURL="{acs}"><s:Issuer>{issuer}</s:Issuer><d:Signature/></p:AuthnRequest>').encode()
    def shape(self,raw,fixture):return campaign.request_shape(raw,fixture,'action_test','https://suite.example/sp','https://suite.example/acs','https://target.example/sso')
    def test_three_exact_fields_preserve_nonversion_distinction(self):
        for fixture in campaign.FIXTURES:self.assertEqual('_action_test',self.shape(self.xml(fixture),fixture))
        with self.assertRaises(ValueError):self.shape(self.xml('version-1-1'),'invalid-issue-instant')
    def test_foreign_id_endpoint_issuer_unsigned_and_forceauthn_are_rejected(self):
        valid=self.xml('version-1-1')
        for raw in [valid.replace(b'_action_test',b'_foreign'),valid.replace(b'https://target.example/sso',b'https://other.example/sso'),valid.replace(b'https://suite.example/sp',b'https://other.example/sp'),valid.replace(b'<d:Signature/>',b''),valid.replace(b' ID=',b' ForceAuthn="true" ID=')]:
            with self.assertRaises(ValueError):self.shape(raw,'version-1-1')
    def test_existing_configuration_mount_is_allowed_without_count_assumptions(self):
        self.assertTrue(preflight.qualify_facts('simplesamlphp',self.runtime,self.reflection,self.sources)['nativeHttpTerminalAdapterQualified'])
    def test_source_covering_mount_and_wrong_source_hash_block_before_login(self):
        runtime=copy.deepcopy(self.runtime);runtime['mounts'][0]['Destination']='/var/simplesamlphp/vendor'
        self.assertFalse(preflight.qualify_facts('simplesamlphp',runtime,self.reflection,self.sources)['nativeHttpTerminalAdapterQualified'])
        sources=dict(self.sources);sources['Message.php']+=b'\n'
        self.assertFalse(preflight.qualify_facts('simplesamlphp',self.runtime,self.reflection,sources)['nativeHttpTerminalAdapterQualified'])
    def test_other_products_retain_genuine_saml_path_but_cannot_borrow_ssp_http_proof(self):
        for product in ('shibboleth','keycloak'):
            result=preflight.qualify_facts(product,self.runtime,self.reflection,self.sources);self.assertFalse(result['nativeHttpTerminalAdapterQualified']);self.assertTrue(result['genuineSamlResponsePathAvailable'])
    def test_second_credential_is_blocked_before_request_and_cookies_not_serialized(self):
        client=campaign.SharedClient();client.credential_posts=1
        with patch.object(campaign.Client,'request',side_effect=AssertionError('must not send')):
            with self.assertRaises(ValueError):client.request('http://localhost:18380/login',dict(username='public-test-user',password='memory-only'))
        self.assertEqual(1,client.credential_posts);self.assertEqual(1,client.credential_attempts);self.assertEqual([],client.protocol_posts)
    def test_fresh_session_confirmation_is_blocked_before_request(self):
        client=campaign.SharedClient()
        with patch.object(campaign.Client,'request',side_effect=AssertionError('must not send')):
            with self.assertRaises(ValueError):client.request('http://localhost:18080/probe',dict(freshSessionConfirmed='true'))
    def test_private_form_and_bare_saml_form_are_not_public_terminal_originals(self):
        self.assertTrue(campaign.public_terminal('<html>Unsupported version: 1.1</html>'))
        for page in ['<input name="password">','SAMLResponse=private','Cookie: session=private','<a href="/login?AuthState=host-only-fixture">login</a>']:
            self.assertFalse(campaign.public_terminal(page))
    def test_actual_redirect_baseline_is_counted_without_reconstructing_signed_query(self):
        client=campaign.SharedClient();raw=self.xml('baseline-success');compressor=zlib.compressobj(wbits=-15);data=compressor.compress(raw)+compressor.flush()
        query='SAMLRequest='+urllib.parse.quote(base64.b64encode(data).decode(),safe='')+'&RelayState=public-run&SigAlg=exact%2Bbytes&Signature=public%2Bsignature'
        client.observed_redirect('http://localhost:18380/sso?'+query)
        self.assertEqual(1,len(client.protocol_gets));self.assertEqual(campaign.SHA(raw),client.protocol_gets[0]['requestSha256']);self.assertEqual(campaign.SHA(query.encode()),client.protocol_gets[0]['rawQuerySha256']);self.assertEqual('http://localhost:18380/sso',client.protocol_gets[0]['requestUrl'])
    def test_unqualified_redirect_forceauthn_is_blocked_before_transport(self):
        client=campaign.SharedClient();raw=self.xml('baseline-success').replace(b' ID=',b' ForceAuthn="true" ID=');c=zlib.compressobj(wbits=-15);data=c.compress(raw)+c.flush()
        with self.assertRaises(ValueError):client.observed_redirect('http://localhost:18380/sso?SAMLRequest='+urllib.parse.quote(base64.b64encode(data).decode(),safe=''))
        self.assertEqual([],client.protocol_gets)
    def test_exact_public_language_navigation_is_inspected_without_changing_original(self):
        menu='<form id="language-form" class="pure-form" method="get"><div id="languageform"><select aria-label="Language" class="pure-input-1-4 language-menu" name="language" id="language-selector"><option value="en" selected="selected">English</option></select><noscript><button type="submit" class="pure-button"><i class="fa fa-arrow-right"></i></button></noscript></div></form>'
        body='<h1>Unsupported version: 1.1</h1>'+menu
        self.assertTrue(campaign.public_terminal(body));self.assertEqual(body,'<h1>Unsupported version: 1.1</h1>'+menu)
        for raw in (menu.replace('method="get"','method="post"'),menu.replace('name="language"','name="csrf"'),menu+menu,'<select name="capability"><option value="private">hidden</option></select>','<form action="/auth"></form>'):
            self.assertFalse(campaign.public_terminal(raw))
    def test_normal_timestamp_missing_and_invalid_are_not_relabelled_as_control(self):
        for raw in (self.xml('baseline-success').replace(b' IssueInstant="2026-10-03T19:00:00Z"',b''),self.xml('baseline-success').replace(b'2026-10-03T19:00:00Z',b'not-a-saml-timestamp')):
            with self.assertRaises(ValueError):self.shape(raw,'baseline-success')
    def test_capability_final_url_is_projected_before_operation_ledger_serialization(self):
        client=campaign.SharedClient();memory_only='host-only-fixture-value'
        final='http://localhost:18380/login?AuthState='+memory_only
        with patch.object(campaign.Client,'request',return_value=(final,'<input name="password">',200)):
            self.assertEqual(final,client.request('http://localhost:18380/sso',dict(SAMLRequest=base64.b64encode(self.xml('baseline-success')).decode()))[0])
        ledger=json.dumps(client.protocol_posts)
        self.assertNotIn(memory_only,ledger);self.assertNotIn('AuthState',ledger)
        row=client.protocol_posts[0];self.assertTrue(row['responseUrlRedacted']);self.assertEqual('http://localhost:18380/login',row['responseUrl']);self.assertEqual(campaign.SHA(final.encode()),row['responseUrlOriginalSha256'])
        with self.assertRaises(ValueError):campaign.public_terminal_url(final)
    def test_public_terminal_urls_remain_exact_and_signed_query_is_not_reconstructed(self):
        for url in ('http://localhost:18380/sso','http://localhost:18380/sso?language=en','http://localhost:18080/sp/acs?mdv=control&run=run_0123456789ABCDEFGHJKMNPQRS'):
            self.assertEqual(url,campaign.public_terminal_url(url))
        raw='http://localhost:18380/sso?SAMLResponse=exact%2Bbytes&SigAlg=public&Signature=unreconstructed%2Bsignature'
        projected=campaign.public_url_projection(raw)
        self.assertTrue(projected['redacted']);self.assertEqual(campaign.SHA(raw.encode()),projected['originalSha256']);self.assertEqual('http://localhost:18380/sso',projected['url'])
        for key in ('AuthState','execution','csrf','session_code','unknown'):
            with self.assertRaises(ValueError):campaign.public_terminal_url('http://localhost:18380/sso?'+key+'=host-only-fixture')

if __name__=='__main__':unittest.main()
