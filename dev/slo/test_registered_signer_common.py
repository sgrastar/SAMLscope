import base64
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
import urllib.parse
import urllib.request

sys.path.insert(0, str(Path(__file__).resolve().parent))
import registered_signer_common as common


class Response(io.BytesIO):
    def __init__(self, body, url, status=200, headers=None):
        super().__init__(body); self.url=url; self.status=status; self.headers=headers or {}
    def geturl(self):
        return self.url
    def __enter__(self):
        return self
    def __exit__(self, *args):
        self.close()


class CommonTest(unittest.TestCase):
    def test_exact_public_language_navigation_preserves_original_and_rejects_capability_forms(self):
        navigation='<form id="language-form" class="pure-form" method="get"><div id="languageform"><select aria-label="Language" class="pure-input-1-4 language-menu" name="language" id="language-selector"><option value="en" selected="selected">English</option><option value="ja">日本語</option></select><noscript><button type="submit" class="pure-button"><i class="fa fa-arrow-right"></i></button></noscript></div></form>'
        raw=(navigation+'<p>Native signature rejected</p>').encode();self.assertEqual(common.safe_body(raw),raw)
        for changed in (navigation.replace('method="get"','method="post"'),navigation.replace('method="get"','method="get" action="/auth"'),navigation.replace('name="language"','name="csrf"'),navigation.replace('</form>','<input name="password" value="secret"></form>'),navigation.replace('</form>','<input name="session_code" value="secret"></form>'),navigation.replace('value="ja"','value="secret/capability"'),navigation+navigation,navigation+'<form><input name="token" value="secret"></form>'):
            with self.assertRaises(ValueError):common.safe_body(changed.encode())

    def test_privacy_failure_after_native_post_keeps_actual_outbox_attempt_cost_without_body(self):
        request=b'<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_action"/>';target='http://localhost:18380/slo'
        with tempfile.TemporaryDirectory() as name:
            directory=Path(name)/'receipt';directory.mkdir();client=common.SharedSloClient('http://localhost:18380',directory)
            with patch.object(client.slo_op,'open',return_value=Response(b'<form><input name="password" value="secret"></form>',target,500)):
                with self.assertRaises(ValueError):client.request(target,{'SAMLRequest':base64.b64encode(request).decode()})
            self.assertEqual((client.protocol_posts,client.outbox_attempts,len(client.records)),(1,1,0));self.assertEqual(list(directory.iterdir()),[])
            ledger=json.loads((Path(name)/'native-slo-attempts.json').read_bytes());self.assertEqual(ledger['attempts'],1);self.assertFalse(ledger['unknownDeliveryIsProductFailure']);self.assertNotIn('secret',json.dumps(ledger))

    def test_mount_capture_ignores_only_order_and_rejects_duplicate_or_changed_attributes(self):
        mounts = [dict(Type='bind', Source='/public/'+name, Destination='/native/'+name,
                       Mode='ro', RW=False, Propagation='rprivate') for name in ('b','a')]
        allowed={m['Destination']:dict(source=Path(m['Source']),rw=False) for m in mounts}
        value=dict(id='public-id', image='public-image', running=True, startedAt='public-time', mounts=mounts)
        with patch.object(common,'docker',return_value=json.dumps(value).encode()):
            first=common.runtime('mock',allowed)
        with patch.object(common,'docker',return_value=json.dumps(dict(value,mounts=mounts[::-1])).encode()):
            self.assertEqual(first,common.runtime('mock',allowed))
        self.assertEqual([m['Destination'] for m in first['mounts']],['/native/a','/native/b'])
        for invalid in ([mounts[0],mounts[0]], [dict(mounts[0],RW=True),mounts[1]],
                        [dict(mounts[0],Source='/foreign'),mounts[1]]):
            with patch.object(common,'docker',return_value=json.dumps(dict(value,mounts=invalid)).encode()):
                with self.assertRaises(ValueError):common.runtime('mock',allowed)

    def test_repeated_credentials_and_unknown_fresh_boundary_never_reach_transport(self):
        with tempfile.TemporaryDirectory() as name:
            client = common.SharedSloClient('http://localhost:18180', name)
            with patch.object(common.Client, 'request', return_value=('http://localhost:18180/auth','done',200)) as transport:
                client.request('http://localhost:18180/auth', {'username':'memory-only','password':'memory-only'})
                with self.assertRaises(ValueError):
                    client.request('http://localhost:18180/auth', {'username':'memory-only','password':'memory-only'})
                with self.assertRaises(ValueError):
                    client.request('http://localhost:18080/probe', {'freshSessionConfirmed':'true'})
                self.assertEqual(transport.call_count, 1)
                self.assertEqual(client.credential_posts, 1)
                self.assertEqual(list(Path(name).iterdir()), [])

    def test_native_response_is_captured_before_suite_response_delivery(self):
        request_xml = b'<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_action"/>'
        response_xml = b'<LogoutResponse ID="response"/>'
        target='http://localhost:18180/slo'; suite='http://localhost:18080/sp/slo'
        html = ('<form method="post" action="'+suite+'"><input name="SAMLResponse" value="'+base64.b64encode(response_xml).decode()+'"></form>').encode()
        with tempfile.TemporaryDirectory() as name:
            client=common.SharedSloClient('http://localhost:18180', name)
            with patch.object(client.slo_op, 'open', return_value=Response(html,target)):
                final, page, code=client.request(target, {'SAMLRequest':base64.b64encode(request_xml).decode()})
            self.assertEqual((final,code),(target,200))
            self.assertEqual(client.records[0]['responseSamlEndpoint'],suite)
            self.assertEqual(client.records[0]['responseSamlSha256'],common.SHA(response_xml))
            self.assertEqual(client.records[0]['responseBodyFile'],'native-body-_action.html')
            self.assertEqual((Path(name)/client.records[0]['responseBodyFile']).read_bytes(),html)

    def test_real_redirect_location_is_kept_without_reconstruction(self):
        import zlib
        request_xml=b'<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_action"/>'
        compressor=zlib.compressobj(wbits=-15);reply=b'<LogoutResponse ID="actual"/>'
        packed=compressor.compress(reply)+compressor.flush()
        location='/sp%20name/slo?SAMLResponse='+urllib.parse.quote(base64.b64encode(packed).decode(),safe='')+'&SigAlg=raw&Signature=raw'
        target='http://localhost:18180/slo'
        # A real SAML Location points to Suite. Keep its exact percent encodings and parameter order.
        location='http://localhost:18080'+location
        with tempfile.TemporaryDirectory() as name:
            client=common.SharedSloClient('http://localhost:18180',name)
            with patch.object(client.slo_op,'open',return_value=Response(b'',target,302,{'Location':location})),patch.object(common.Client,'request',return_value=('http://localhost:18080/sp%20name/slo','SAML Response recorded',200)):
                client.request(target,{'SAMLRequest':base64.b64encode(request_xml).decode()})
            row=client.records[0]
            self.assertEqual((Path(name)/row['responseLocationFile']).read_bytes(),location.encode())
            self.assertEqual(row['responseSamlEndpoint'],'http://localhost:18080/sp%20name/slo')
            self.assertEqual(row['responseSamlSha256'],common.SHA(reply))

    def test_authentication_capabilities_are_refused_before_any_body_export(self):
        for raw in (b'<form><input name="password" value="sensitive"></form>',b'<a href="/auth?session_code=sensitive">continue</a>',b'<div>Cookie: sensitive</div>',b'<input name="password" value="sensitive">',b'<a href="/simplesaml/module.php/core/logout-resume?id=_abcdef">continue</a>'):
            with self.assertRaises(ValueError):
                common.safe_body(raw)
        self.assertEqual(common.safe_body(b'<html>Invalid requester</html>'),b'<html>Invalid requester</html>')
        for value in ({'Cookie':'sensitive'},{'nested':[{'privateKey':'sensitive'}]},{'Authorization':'sensitive'}):
            with self.assertRaises(ValueError):
                common.public_json(value)

    def test_unsafe_redirect_location_is_refused_before_persistence(self):
        request=b'<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_action"/>'
        for location in ('http://localhost:18180/auth?session_code=memory-only','http://user:memory-only@localhost:18180/slo?SAMLResponse=unused','http://localhost:18080/slo?SAMLResponse=unused&tab_id=memory-only'):
            with tempfile.TemporaryDirectory() as name:
                client=common.SharedSloClient('http://localhost:18180',name)
                with patch.object(client.slo_op,'open',return_value=Response(b'<a href="/auth?session_code=memory-only">redirect</a>','http://localhost:18180/slo',302,{'Location':location})):
                    with self.assertRaises(ValueError):
                        client.request('http://localhost:18180/slo',{'SAMLRequest':base64.b64encode(request).decode()})
                self.assertFalse(any('location' in p.name for p in Path(name).iterdir()))
                self.assertEqual(list(Path(name).iterdir()),[])
                self.assertEqual(client.records,[])

    def test_partial_setup_and_restoration_query_failure_still_persist_actual_costs(self):
        class Product:
            name='mock';origin='http://localhost:18180';target=origin+'/idp';metadata_source='http://mock/metadata';adapter='mock'
            restored=False;writes=0
            def bind(self,out,receipt):self.out,self.receipt=out,receipt
            def preflight(self):pass
            def state(self,label,peers):
                if label=='restoration':raise ValueError('Query transport failed; absence unproven')
                return {'phase':label,'peers':peers}
            def prepare(self,peers):self.writes+=1;raise ValueError('Simulated failure after owned native write')
            def restore(self,peers):self.restored=True;return True
            def counts(self):return dict(nativeConfigurationWrites=self.writes,restorationWrites=1,productRestarts=0)
        product=Product(); counter={'plan':0,'run':0}
        def api(path,body=None):
            if path=='/api/plans':
                counter['plan']+=1;return {'plan':{'plan':{'id':'plan_'+str(counter['plan'])*26}}}
            if path.endswith('/runs'):
                counter['run']+=1;return {'run':{'id':'run_'+str(counter['run'])*26,'planId':path.split('/')[3]}}
            if path.endswith('/preflight'):return {}
            raise AssertionError('No flow/target submission is authorized in this failure test')
        def cp(*args,**kwargs):
            if args[0]=='cp':Path(args[2]).write_bytes(b'<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="http://localhost:18180/idp"/>')
            return b''
        def metadata(request,**kwargs):
            entity=str(request).removesuffix('/metadata')
            return Response(('<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="'+entity+'"/>').encode(),str(request))
        with tempfile.TemporaryDirectory() as name,patch.object(common,'api',side_effect=api),patch.object(common,'docker',side_effect=cp),patch.object(common.urllib.request,'urlopen',side_effect=metadata),patch.object(common,'recorded',return_value={'reference':'tx_mock','sha256':'a'*64}),patch.object(common.SharedSloClient,'flow') as flow:
            out=Path(name)/'campaign'
            with self.assertRaisesRegex(ValueError,'Simulated failure'):
                common.collect(product,out,min_free_mib=1)
            self.assertTrue(product.restored);flow.assert_not_called()
            counts=json.loads((out/'operation-counts.json').read_bytes())
            self.assertEqual((counts['credentialPosts'],counts['protocolSubmissions']),(0,0))
            self.assertTrue(counts['restored']);self.assertFalse((out/'receipt/manifest.json').exists())
            failure=json.loads((out/'restoration-proof-failure.json').read_bytes());self.assertTrue(failure['physicalRestored']);self.assertFalse(failure['productVerdictAdopted'])
            self.assertEqual(counts['nativeConfigurationWrites'],1)

    def test_installed_native_predicate_failure_stops_before_the_first_login(self):
        class Product:
            name='mock';origin='http://localhost:18180';target=origin+'/idp';metadata_source='http://mock/metadata';adapter='mock'
            restored=False
            def bind(self,out,receipt):pass
            def preflight(self):pass
            def state(self,label,peers):return {'phase':label,'peers':peers}
            def prepare(self,peers):pass
            def restore(self,peers):self.restored=True;return True
            def counts(self):return dict(nativeConfigurationWrites=2,restorationWrites=1,productRestarts=0)
        product=Product();counter={'plan':0,'run':0}
        def api(path,body=None):
            if path=='/api/plans':counter['plan']+=1;return {'plan':{'plan':{'id':'plan_'+str(counter['plan'])*26}}}
            if path.endswith('/runs'):counter['run']+=1;return {'run':{'id':'run_'+str(counter['run'])*26,'planId':path.split('/')[3]}}
            if path.endswith('/preflight'):return {}
            raise AssertionError('No login, SLO, or formal evaluation after an unproven native predicate')
        def cp(*args,**kwargs):
            if args[0]=='cp':Path(args[2]).write_bytes(b'<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="http://localhost:18180/idp"/>')
            return b''
        def metadata(request,**kwargs):
            entity=str(request).removesuffix('/metadata')
            return Response(('<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="'+entity+'"/>').encode(),str(request))
        with tempfile.TemporaryDirectory() as name,patch.object(common,'api',side_effect=api),patch.object(common,'docker',side_effect=cp),patch.object(common.urllib.request,'urlopen',side_effect=metadata),patch.object(common,'recorded',return_value={'reference':'tx_mock','sha256':'a'*64}),patch.object(common,'preparation_qualification',side_effect=ValueError('Native predicate unproven')) as predicate,patch.object(common.SharedSloClient,'flow') as flow:
            out=Path(name)/'campaign'
            with self.assertRaisesRegex(ValueError,'Native predicate'):common.collect(product,out,min_free_mib=1)
            self.assertEqual(predicate.call_args.args[2],'native');flow.assert_not_called();self.assertTrue(product.restored)
            counts=json.loads((out/'operation-counts.json').read_bytes());self.assertEqual((counts['credentialPosts'],counts['protocolSubmissions']),(0,0));self.assertTrue(counts['restored'])

    def test_publisher_is_configured_before_first_target_snapshot_and_failed_predicate_restores_without_login(self):
        self._publisher_failure(False)

    def test_partial_publisher_write_failure_restores_before_any_target_snapshot_or_login(self):
        self._publisher_failure(True)

    def _publisher_failure(self,partial):
        class Product:
            name='mock';origin='http://localhost:18380';target=origin+'/idp';metadata_source='http://mock/metadata';adapter='mock'
            configured=False;restored=False
            def bind(self,out,receipt):pass
            def preflight(self):pass
            def state(self,label,peers):return {'phase':label,'publisherConfigured':self.configured,'peers':peers}
            def configure_publisher(self):
                self.configured=True
                if partial:raise ValueError('Partial publisher failure')
            def prepare(self,peers):pass
            def restore(self,peers):self.configured=False;self.restored=True;return True
            def counts(self):return dict(nativeConfigurationWrites=2,restorationWrites=1,productRestarts=0)
        product=Product();counter={'plan':0,'run':0,'preflight':0}
        def api(path,body=None):
            if path=='/api/plans':counter['plan']+=1;return {'plan':{'plan':{'id':'plan_'+str(counter['plan'])*26}}}
            if path.endswith('/runs'):counter['run']+=1;return {'run':{'id':'run_'+str(counter['run'])*26,'planId':path.split('/')[3]}}
            if path.endswith('/preflight'):
                self.assertTrue(product.configured);counter['preflight']+=1;return {}
            raise AssertionError('No authenticated operation in this prelogin failure')
        def cp(*args,**kwargs):
            if args[0]=='cp':Path(args[2]).write_bytes(b'<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="http://localhost:18380/idp"/>')
            return b''
        def metadata(request,**kwargs):
            entity=str(request).removesuffix('/metadata');return Response(('<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="'+entity+'"/>').encode(),str(request))
        with tempfile.TemporaryDirectory() as name,patch.object(common,'api',side_effect=api),patch.object(common,'docker',side_effect=cp),patch.object(common.urllib.request,'urlopen',side_effect=metadata),patch.object(common,'recorded',return_value={'reference':'tx_mock','sha256':'a'*64}),patch.object(common,'preparation_qualification',side_effect=ValueError('Native predicate unproven')),patch.object(common.SharedSloClient,'flow') as flow:
            out=Path(name)/'campaign'
            with self.assertRaisesRegex(ValueError,'Partial publisher' if partial else 'Native predicate'):common.collect(product,out,min_free_mib=1)
            flow.assert_not_called();self.assertTrue(product.restored);self.assertEqual(counter['preflight'],0 if partial else 2)
            initial=json.loads((out/'deferred-initial-native-observation.json').read_bytes());self.assertFalse(initial['readback']['publisherConfigured'])
            if partial:self.assertTrue((out/'restoration-before-snapshot.json').exists())
            else:
                self.assertEqual(json.loads((out/'receipt/native-readbacks/initial.json').read_bytes()),initial['readback'])
            counts=json.loads((out/'operation-counts.json').read_bytes());self.assertTrue(counts['restored']);self.assertEqual((counts['credentialPosts'],counts['protocolSubmissions']),(0,0));self.assertFalse((out/'receipt/manifest.json').exists())


if __name__=='__main__':
    unittest.main()
