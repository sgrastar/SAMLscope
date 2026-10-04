"""Native SLO collector privacy, selected-profile and exact restoration controls; no Docker."""
import base64
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

path=Path(__file__).with_name('slo_registered_signer_campaign.py')
spec=importlib.util.spec_from_file_location('shib_slo_product_tested',path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
import registered_signer_common as common

class Response:
    def __init__(self,body,url,status=200,location=None):self.body,self.url,self.status,self.headers=body,url,status,{} if location is None else {'Location':location}
    def read(self,*args):return self.body
    def geturl(self):return self.url
    def close(self):pass

class ProductTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.out=Path(self.temp.name);self.receipt=self.out/'receipt';self.receipt.mkdir();self.p=m.ShibbolethProduct();self.p.create_client(self.receipt);self.p.bind(self.out,self.receipt)
    def tearDown(self):self.temp.cleanup()
    def test_real_slo_completion_is_shared_parser_navigation_not_a_second_saml_or_login(self):
        target=m.ShibSloClient('http://localhost:18280',self.receipt);url='http://localhost:18280/idp/profile/SAML2/POST/SLO'
        request=b'<p:LogoutRequest xmlns:p="urn:oasis:names:tc:SAML:2.0:protocol" ID="_selected"/>'
        iframe=b'<iframe src="?execution=memory-only&amp;_eventId=proceed"></iframe>'
        reply=b'<LogoutResponse/>';terminal='<form method="post" action="http://localhost:18080/sp/slo"><input name="SAMLResponse" value="'+base64.b64encode(reply).decode()+'"></form>'
        with patch.object(target.slo_op,'open',side_effect=[Response(iframe,url),Response(terminal.encode(),url+'?execution=memory-only&_eventId=proceed')]) as navigation:
            target.request(url,{'SAMLRequest':base64.b64encode(request).decode()})
        self.assertEqual(navigation.call_count,2);self.assertEqual((target.protocol_posts,target.credential_posts),(1,0));self.assertEqual(len(target.records),1)
        self.assertEqual(target.records[0]['responseSamlSha256'],common.SHA(reply));self.assertTrue(target.records[0]['responseUrlQueryRedacted'])
        self.assertEqual(target.records[0]['nativeInitialResponseBodySha256'],common.SHA(iframe));self.assertEqual(len(target.completions),1)
        self.assertNotIn('memory-only',json.dumps(target.records)+''.join(p.read_text() for p in self.receipt.iterdir()))
    def test_foreign_or_wrong_event_completion_never_reaches_transport_or_public_storage(self):
        client=m.ShibSloClient('http://localhost:18280',self.receipt)
        for page in (b'<iframe src="http://foreign.invalid/idp/profile/SAML2/POST/SLO?execution=secret&amp;_eventId=proceed">',b'<iframe src="?execution=secret&amp;_eventId=other">'):
            with patch.object(client.slo_op,'open') as transport:
                with self.assertRaises(ValueError):client.complete_native_redirect('http://localhost:18280/idp/profile/SAML2/POST/SLO',page,200,None,'_actual')
            transport.assert_not_called()
        self.assertEqual(list(self.receipt.iterdir()),[])
    def test_failed_completion_get_retains_actual_attempt_without_token_or_saml_retry(self):
        client=m.ShibSloClient('http://localhost:18280',self.receipt);page=b'<iframe src="?execution=memory-only&amp;_eventId=proceed"></iframe>'
        with patch.object(client.slo_op,'open',side_effect=TimeoutError('Timeout')):
            with self.assertRaises(TimeoutError):client.complete_native_redirect('http://localhost:18280/idp/profile/SAML2/POST/SLO',page,200,None,'_actual')
        self.assertEqual(len(client.completions),1);self.assertFalse(client.completions[0]['completed']);self.assertEqual(client.completions[0]['exceptionClass'],'TimeoutError')
        raw=(self.out/'native-logout-completion-attempts.json').read_text();self.assertNotIn('memory-only',raw);self.assertEqual(client.protocol_posts,0)
    def test_execution_redirect_then_same_flow_iframe_preserves_terminal_public_location(self):
        client=m.ShibSloClient('http://localhost:18280',self.receipt);url=client.target_origin+'/idp/profile/SAML2/POST/SLO'
        import zlib,urllib.parse
        request=b'<p:LogoutRequest xmlns:p="urn:oasis:names:tc:SAML:2.0:protocol" ID="_selected"/>'
        reply=b'<LogoutResponse/>';compressed=zlib.compress(reply)[2:-4]
        location='http://localhost:18080/sp/slo?SAMLResponse='+urllib.parse.quote(base64.b64encode(compressed).decode(),safe='')+'&SigAlg=public&Signature=public'
        page=b'<iframe src="?execution=e1s1&amp;_eventId=proceed"></iframe>'
        responses=[Response(b'',url,302,'?execution=e1s1'),Response(page,url+'?execution=e1s1'),
                   Response(b'',url+'?execution=e1s1&_eventId=proceed',302,location)]
        with patch.object(client.slo_op,'open',side_effect=responses) as transport,patch.object(common.Client,'request',return_value=(location,'Response recorded',200)) as callback:
            client.request(url,{'SAMLRequest':base64.b64encode(request).decode()})
        self.assertEqual(transport.call_count,3);self.assertEqual(len(client.completions),2);self.assertEqual(client.protocol_posts,1);self.assertEqual(client.credential_posts,0)
        self.assertEqual(client.records[0]['responseSamlSha256'],common.SHA(reply));callback.assert_called_once_with(location,None)
        self.assertEqual((self.receipt/'native-location-_selected.txt').read_text(),location)
        exported=json.dumps(client.records)+''.join(p.read_text() for p in self.out.rglob('*') if p.is_file())
        self.assertNotIn('e1s1',exported);self.assertNotIn('_eventId',exported)
    def test_execution_redirect_rejects_foreign_endpoint_private_fields_and_old_execution_before_transport(self):
        client=m.ShibSloClient('http://localhost:18280',self.receipt);url=client.target_origin+'/idp/profile/SAML2/POST/SLO'
        for location in ('http://foreign.invalid/idp/profile/SAML2/POST/SLO?execution=e1s1',
                         '/idp/profile/Login?execution=e1s1','?execution=e1s1&AuthState=private',
                         '?execution=e1s1&execution=e2s1','?execution=e1s1#fragment','http://user:private@localhost:18280/idp/profile/SAML2/POST/SLO?execution=e1s1'):
            with patch.object(client.slo_op,'open') as transport:
                with self.assertRaises(ValueError):client.complete_native_redirect(url,b'',302,location,'_selected')
                transport.assert_not_called()
        with self.assertRaises(ValueError):client._execution_redirect(url+'?execution=e2s1','?execution=e1s1')
        self.assertEqual(client._execution_redirect(url,'?execution=e1s1'),url+'?execution=e1s1')
        with self.assertRaises(ValueError):client._execution_redirect(url,'?execution=e1s1')
        self.assertEqual(list(self.receipt.iterdir()),[])
    def test_navigation_does_not_save_login_no_saml_repeated_redirect_or_over_limit_page(self):
        url='http://localhost:18280/idp/profile/SAML2/POST/SLO'
        results=[Response(b'<form><input name="password" value="private"></form>',url+'?execution=e1s1'),
                 Response(b'<p>Logged out</p>',url+'?execution=e1s1'),
                 Response(b'',url+'?execution=e1s1',302,'?execution=e2s1'),
                 Response(b'<iframe src="?execution=e2s1&amp;_eventId=proceed"></iframe>',url+'?execution=e1s1')]
        for response in results:
            client=m.ShibSloClient('http://localhost:18280',self.receipt)
            with patch.object(client.slo_op,'open',return_value=response):
                with self.assertRaises(ValueError):client.complete_native_redirect(url,b'',302,'?execution=e1s1','_selected')
        client=m.ShibSloClient('http://localhost:18280',self.receipt);page=b'<iframe src="?execution=e1s1&amp;_eventId=proceed"></iframe>'
        with patch.object(client.slo_op,'open',side_effect=[Response(page,url+'?execution=e1s1'),Response(page,url+'?execution=e1s1&_eventId=proceed'),Response(page,url+'?execution=e1s1&_eventId=proceed')]):
            with self.assertRaisesRegex(ValueError,'hop limit'):client.complete_native_redirect(url,b'',302,'?execution=e1s1','_selected')
        self.assertEqual(list(self.receipt.iterdir()),[])
        exported=(self.out/'native-logout-completion-attempts.json').read_text();self.assertNotIn('e1s1',exported);self.assertNotIn('private',exported)
    def test_failed_execution_redirect_get_is_counted_before_transport_and_records_no_capability(self):
        client=m.ShibSloClient('http://localhost:18280',self.receipt);url=client.target_origin+'/idp/profile/SAML2/POST/SLO'
        with patch.object(client.slo_op,'open',side_effect=TimeoutError('not exported')):
            with self.assertRaises(TimeoutError):client.complete_native_redirect(url,b'',302,'?execution=e1s1','_selected')
        self.assertEqual(len(client.completions),1);self.assertFalse(client.completions[0]['completed'])
        self.assertEqual(client.completions[0]['exceptionClass'],'TimeoutError');self.assertEqual(client.protocol_posts,0)
        self.assertNotIn('e1s1',(self.out/'native-logout-completion-attempts.json').read_text())
    def test_even_terminal_saml_page_cannot_export_authentication_or_execution_capability(self):
        url='http://localhost:18280/idp/profile/SAML2/POST/SLO'
        terminal=b'<form method="post" action="http://localhost:18080/sp/slo"><input name="SAMLResponse" value="cHVibGlj"></form>'
        for capability in (b'<a href="?execution=e1s1">private</a>',b'<a href="?AuthState=private">private</a>',b'<p>Cookie: private</p>',b'<form><input name="csrf" value="private"></form>'):
            client=m.ShibSloClient('http://localhost:18280',self.receipt)
            with patch.object(client.slo_op,'open',side_effect=[Response(b'',url,302,'?execution=e1s1'),Response(terminal+capability,url+'?execution=e1s1')]):
                request=b'<p:LogoutRequest xmlns:p="urn:oasis:names:tc:SAML:2.0:protocol" ID="_selected"/>'
                with self.assertRaises(ValueError):client.request(url,{'SAMLRequest':base64.b64encode(request).decode()})
            self.assertEqual(len(client.records),0);self.assertEqual(list(self.receipt.iterdir()),[])
        self.assertNotIn('private',(self.out/'native-logout-completion-attempts.json').read_text())
    def test_slo_scope_uses_actual_selected_logout_profile_and_fixed_engine(self):
        directory=self.receipt/'native-source';directory.mkdir();profile={'RelyingPartyConfiguration':{'securityConfiguration':'shibboleth.DefaultSecurityConfiguration'},'ProfileConfiguration':{'id':m.PROFILE,'ignoreRequestSignatures':False}}
        def capture(folder,label,entity):
            self.assertEqual(m.TRUST.PROFILE,m.PROFILE);(folder/('trust-'+label+'-selected-properties.json')).write_text(json.dumps({'idp.trust.signatures':'shibboleth.ExplicitKeySignatureTrustEngine'}))
        with patch.object(self.p,'command',return_value=json.dumps(profile).encode()) as cmd,patch.object(m.TRUST,'capture',side_effect=capture):
            result=self.p.scope('before-primary','http://localhost:18080/p/actual')
        self.assertEqual(cmd.call_args.args[-2:],('-P',m.PROFILE));self.assertEqual(result['profileId'],m.PROFILE)
        profile['ProfileConfiguration']['id']='http://shibboleth.net/ns/profiles/saml2/sso/browser'
        with patch.object(self.p,'command',return_value=json.dumps(profile).encode()),patch.object(m.TRUST,'capture') as capture:
            with self.assertRaises(ValueError):self.p.scope('before-primary','http://localhost:18080/p/actual')
            capture.assert_not_called()
    def test_sensitive_profile_field_is_refused_before_source_capture(self):
        with patch.object(self.p,'command',return_value=b'{"password":"memory-only"}'),patch.object(m.TRUST,'capture') as capture:
            with self.assertRaises(ValueError):self.p.scope('before','http://localhost:18080/p/actual')
        capture.assert_not_called();self.assertEqual(list(self.receipt.iterdir()),[])
    def test_public_config_supports_native_metadata_urls_but_refuses_credential_values(self):
        self.assertEqual(m.public_configuration(b'<MetadataProvider metadataFile="/public.xml" metadataURL="http://localhost/p/metadata"/>'),b'<MetadataProvider metadataFile="/public.xml" metadataURL="http://localhost/p/metadata"/>')
        for raw in (b'<MetadataProvider password="memory-only"/>',b'<MetadataProvider metadataURL="http://user:memory-only@localhost/metadata"/>',b'<MetadataProvider metadataURL="http://localhost/metadata?token=memory-only"/>',b'<property name="password" value="memory-only"/>'):
            with self.assertRaises(ValueError):m.public_configuration(raw)
    def test_partial_provider_write_restores_configs_and_removes_only_owned_sources_without_restart(self):
        initial=b'<original/>';configured=b'<configured/>';source=m.ROOT+'/metadata/registered-signer-run_'+'0'*26+'.xml';store={m.PROVIDERS:configured,m.AUDIT:initial,source:b'<metadata/>'}
        self.p.original={m.PROVIDERS:initial,m.AUDIT:initial};self.p.expected={m.PROVIDERS:configured,m.AUDIT:initial,source:b'<metadata/>'};self.p.owned_sources={source:b'<metadata/>'}
        def command(*argv,data=None,allow_failure=False):
            if argv[0]=='cat':return store[argv[1]]
            if argv[0]=='sh':store[argv[-1].split('cat > ')[1]]=data;return b''
            if argv[0]=='test':return subprocess.CompletedProcess([],0 if argv[-1] in store else 1,b'',b'')
            if argv[0]=='rm':del store[argv[-1]];return b''
            raise AssertionError(argv)
        with patch.object(self.p,'command',side_effect=command),patch.object(self.p,'activate') as activation:
            self.assertTrue(self.p.restore([]));activation.assert_not_called()
        self.assertEqual(store,{m.PROVIDERS:initial,m.AUDIT:initial});self.assertTrue(json.loads((self.out/'native-restoration.json').read_bytes())['restored'])
    def test_unexpected_external_config_is_not_overwritten_and_other_owned_state_still_restores(self):
        initial=b'<original/>';configured=b'<configured/>';self.p.original={m.PROVIDERS:initial,m.AUDIT:initial};self.p.expected={m.PROVIDERS:configured,m.AUDIT:configured};store={m.PROVIDERS:b'<external/>',m.AUDIT:configured}
        def command(*argv,data=None,allow_failure=False):
            if argv[0]=='cat':return store[argv[1]]
            if argv[0]=='sh':store[argv[-1].split('cat > ')[1]]=data;return b''
            raise AssertionError(argv)
        with patch.object(self.p,'command',side_effect=command):self.assertFalse(self.p.restore([]))
        self.assertEqual(store,{m.PROVIDERS:b'<external/>',m.AUDIT:initial})
    def test_duplicate_request_audit_is_not_native_refusal_evidence(self):
        self.p.client.records=[{'requestId':'_selected'}]
        line='SAMLscope-signature-v1|_selected|peer|endpoint|status|MessageSecurityError|POST|'+m.PROFILE+'|2026-10-03T18:00:00Z\n'
        with patch.object(self.p,'command',side_effect=[b'2026-10-03T18:00:01Z', (line+line).encode()]):
            with self.assertRaisesRegex(ValueError,'unique request-bound'):self.p.after_http('2026-10-03T17:59:59Z')
        self.assertEqual(list(self.receipt.iterdir()),[])
    def test_nonzero_or_unrecognized_metadata_query_does_not_claim_absent_peers(self):
        peers=[{'label':'primary','entity':'http://localhost:18080/p/actual'}];(self.receipt/'native-source').mkdir()
        for result in (subprocess.CompletedProcess([],1,b'',b'failure'),subprocess.CompletedProcess([],0,b'<html>missing route</html>\n404',b''),subprocess.CompletedProcess([],0,b'Forbidden\n403',b'')):
            with patch.object(self.p,'command',return_value=result):
                with self.assertRaises(ValueError):self.p.state('initial',peers)
        self.assertEqual(list(self.receipt.iterdir()),[self.receipt/'native-source'])

if __name__=='__main__':unittest.main()
