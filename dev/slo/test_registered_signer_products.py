"""Product ownership, restoration and credential redaction mocks; no Docker, login or SAML."""
import importlib.util
import io
import json
import base64
import zlib
import urllib.parse
from pathlib import Path
import sys
import tempfile
import unittest
import urllib.error
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(REPO / 'dev/slo'),str(REPO / 'dev/keycloak'),str(REPO / 'dev/reference-acceptance')]


def module(name,path):
    spec=importlib.util.spec_from_file_location(name,REPO/path);value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value


KC=module('slo_product_test_kc','dev/keycloak/slo_registered_signer_campaign.py')
SSP=module('slo_product_test_ssp','dev/simplesamlphp/slo_registered_signer_campaign.py')
ADOPT=module('slo_product_test_adopter','dev/reference-acceptance/verify_slo_registered_signer_acceptance.py')


class Response:
    def __init__(self,value,status=200,headers=None):
        self.raw=json.dumps(value).encode() if value is not None else b'';self.status=status;self.headers=headers or {}
    def read(self,*args):return self.raw
    def close(self):pass


class ProductTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.out=Path(self.tmp.name);self.receipt=self.out/'receipt';self.receipt.mkdir();self.kc=KC.KeycloakProduct();self.kc.bind(self.out,self.receipt)
    def tearDown(self):self.tmp.cleanup()

    def test_native_401_refresh_is_memory_only_separate_attempts(self):
        error=urllib.error.HTTPError('http://localhost:18180/admin/realms/samlscope/clients',401,'Expired',{},io.BytesIO(b'{}'))
        with patch.object(KC,'product_token',side_effect=['first-secret-value','second-secret-value']) as tokens,patch.object(KC.urllib.request,'urlopen',side_effect=[error,Response([])]) as transport:
            value,row,_=self.kc.native('/clients');self.assertEqual(value,[]);self.assertEqual(tokens.call_count,2);self.assertEqual(transport.call_count,2)
            self.assertEqual([o['status'] for o in self.kc.operations],[401,200]);public=(self.out/'native-operations.json').read_text();self.assertNotIn('secret-value',public);self.assertNotIn('Authorization',public)

    def test_native_private_client_fields_removed_before_return_or_save(self):
        data=dict(id='test',protocol='saml',secret='private',registrationAccessToken='private',attributes={'client.secret.creation.time':'private','saml.client.signature':'true'})
        with patch.object(KC,'product_token',return_value='memory'),patch.object(KC.urllib.request,'urlopen',return_value=Response(data)):
            value,row,_=self.kc.native('/clients/test')
        self.assertNotIn('secret',value);self.assertNotIn('registrationAccessToken',value);self.assertNotIn('client.secret.creation.time',value['attributes']);self.assertNotIn('private',json.dumps(row));self.assertTrue(row['removedFieldNames'])

    def test_native_brief_lookup_list_removes_only_generation_timestamp(self):
        value=[dict(id='test',protocol='saml',attributes={'client.secret.creation.time':'not-persisted','saml.signing.certificate':'public-certificate','saml.client.signature':'true'})]
        with patch.object(KC,'product_token',return_value='memory'),patch.object(KC.urllib.request,'urlopen',return_value=Response(value)):
            cleaned,row,_=self.kc.native('/clients?briefRepresentation=true')
        self.assertEqual(cleaned[0]['attributes'],{'saml.signing.certificate':'public-certificate','saml.client.signature':'true'})
        self.assertEqual(row['removedFieldNames'],['/0/attributes/client.secret.creation.time'])
        self.assertNotIn('not-persisted',json.dumps(row))

    def test_unrecognized_sensitive_field_fails_before_public_response_export(self):
        with patch.object(KC,'product_token',return_value='memory'),patch.object(KC.urllib.request,'urlopen',return_value=Response({'unexpected_password':'private'})):
            with self.assertRaisesRegex(ValueError,'Sensitive'):self.kc.native('/clients/test')
        self.assertNotIn('private',(self.out/'native-operations.json').read_text())

    def test_fresh_client_is_owned_immediately_even_if_second_creation_fails(self):
        peers=[dict(entity='http://localhost:18080/p/primary',label='primary'),dict(entity='http://localhost:18080/p/secondary',label='secondary')]
        for peer in peers:(self.receipt/peer['label']).mkdir();(self.receipt/peer['label']/'fixture.xml').write_bytes(b'<metadata/>')
        identity='11111111-1111-1111-1111-111111111111'
        def native(path,method='GET',data=None,xml=False,**kwargs):
            if path=='/client-description-converter':return dict(clientId=peers[0]['entity'],protocol='saml',attributes={'saml.client.signature':'true'}),dict(status=200),None
            if path=='/clients':return None,dict(status=201),'http://localhost:18180/admin/realms/samlscope/clients/'+identity
            raise AssertionError(path)
        with patch.object(self.kc,'lookup',side_effect=[([],{}),ValueError('second-precondition')]),patch.object(self.kc,'native',side_effect=native):
            with self.assertRaises(ValueError):self.kc.prepare(peers)
        self.assertEqual(self.kc.clients,{peers[0]['entity']:identity});self.assertEqual(json.loads((self.out/'created-native-clients.json').read_bytes()),self.kc.clients)

    def test_restore_deletes_only_owned_clients_and_preserves_original_policy(self):
        self.kc.clients={'first':'111','second':'222'};self.kc.original_policy={'policies':{'policies':[]},'profiles':{'profiles':[]}}
        with patch.object(self.kc,'native',return_value=(None,{'status':204},None)) as transport,patch.object(self.kc,'lookup',return_value=([],{})),patch.object(self.kc,'policy',return_value=self.kc.original_policy):
            self.assertTrue(self.kc.restore([{},{}]))
        self.assertEqual([c.args[0] for c in transport.call_args_list],['/clients/222','/clients/111']);self.assertEqual([c.args[1] for c in transport.call_args_list],['DELETE','DELETE'])

    def test_ssp_parser_prepare_failure_restores_exact_original_without_login(self):
        product=SSP.SimpleSamlPhpProduct();product.bind(self.out,self.receipt)
        class Batch:
            original=b'<?php\n$metadata=[];\n';expected=None;restoration_writes=0;write_count=0
            def apply(self,raw):self.expected=self.original+raw;self.write_count+=1;raise ValueError('partially-applied')
            def restore(self):self.restoration_writes+=1;self.write_count+=1;return {'restored':True}
        product.batch=Batch();peer=dict(entity='http://localhost:18080/p/fresh',label='primary');(self.receipt/'primary').mkdir();(self.receipt/'primary/fixture.xml').write_bytes(b'<metadata/>')
        def command(*argv,**kwargs):
            if argv[0]=='cat':return product.batch.original
            return json.dumps(dict(entityId=peer['entity'],validateAuthnRequest=True,php='$metadata["fresh"]=[];')).encode()
        with patch.object(product,'command',side_effect=command):
            with self.assertRaisesRegex(ValueError,'partially-applied'):product.prepare([peer])
            self.assertTrue(product.restore([peer]))
        self.assertEqual(product.batch.write_count,2);self.assertEqual(product.batch.restoration_writes,1);self.assertIn(b"['validate.logout'] = true",product.batch.expected)

    def test_ssp_native_logout_resume_is_memory_only_then_actual_saml_redirect_is_preserved(self):
        origin='http://localhost:18380';target=origin+'/slo';state='_abcdef123456';resume=origin+'/simplesaml/module.php/core/logout-resume?id='+state
        xml=b'<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_action"/>';reply=b'<LogoutResponse ID="reply"/>'
        compressor=zlib.compressobj(wbits=-15);packed=compressor.compress(reply)+compressor.flush()
        location='http://localhost:18080/sp%20name/slo?SAMLResponse='+urllib.parse.quote(base64.b64encode(packed).decode(),safe='')+'&SigAlg=raw&Signature=raw'
        class Native(io.BytesIO):
            def __init__(self,body,url,status,location):super().__init__(body);self.url=url;self.status=status;self.headers={'Location':location}
            def geturl(self):return self.url
        client=SSP.SimpleSamlPhpSloClient(origin,self.receipt)
        initial=('<a href="'+resume+'">redirect</a>').encode()
        with patch.object(client.slo_op,'open',side_effect=[Native(initial,target,302,resume),Native(b'',resume,302,location)]) as transport,patch.object(SSP.SharedSloClient.__bases__[0],'request',return_value=('http://localhost:18080/sp%20name/slo','SAML Response recorded',200)):
            client.request(target,{'SAMLRequest':base64.b64encode(xml).decode()})
        self.assertEqual(transport.call_count,2);self.assertEqual(transport.call_args_list[1].args[0].method,'GET')
        self.assertEqual((client.protocol_posts,client.outbox_attempts,client.credential_posts,len(client.completions)),(1,1,0,1))
        row=client.records[0];self.assertTrue(row['responseUrlQueryRedacted']);self.assertEqual(row['responseSamlSha256'],SSP.SHA(reply));self.assertEqual((self.receipt/row['responseLocationFile']).read_text(),location)
        public=b''.join(p.read_bytes() for p in self.out.rglob('*') if p.is_file());self.assertNotIn(state.encode(),public);self.assertNotIn(initial,public)

    def test_ssp_before_login_requires_native_selected_outgoing_signature_and_published_certificate(self):
        certificate=b'public DER fixture';digest=SSP.SHA(certificate)
        metadata=('<md:EntityDescriptor xmlns:md="'+SSP.MD+'" xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><md:IDPSSODescriptor><md:KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>'+base64.b64encode(certificate).decode()+'</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor></md:IDPSSODescriptor></md:EntityDescriptor>').encode()
        observed=dict(resolvedMetadata={'sign.logout':True},logoutResponseSigning=dict(selectedSigningKeyAvailable=True,certificateSha256=[digest]))
        SSP.require_response_signing(observed,metadata)
        for changed in ({'sign.logout':False},{'sign.logout':None}):
            bad=json.loads(json.dumps(observed));bad['resolvedMetadata']=changed
            with self.assertRaisesRegex(ValueError,'stop before login'):SSP.require_response_signing(bad,metadata)
        for changed in (dict(selectedSigningKeyAvailable=False,certificateSha256=[digest]),dict(selectedSigningKeyAvailable=True,certificateSha256=['0'*64]),dict(selectedSigningKeyAvailable=True,certificateSha256=[])):
            bad=json.loads(json.dumps(observed));bad['logoutResponseSigning']=changed
            with self.assertRaisesRegex(ValueError,'stop before login'):SSP.require_response_signing(bad,metadata)

    def test_ssp_logout_resume_rejects_foreign_duplicate_return_url_and_counts_failed_get(self):
        origin='http://localhost:18380';path='/simplesaml/module.php/core/logout-resume';client=SSP.SimpleSamlPhpSloClient(origin,self.receipt)
        for url in ('http://localhost:18180'+path+'?id=_abcdef',origin+path+'?id=_abcdef&id=_123456',origin+path+'?id=_abcdef&AuthState=private',origin+path+'?id=_abcdef%3Ahttp%3A%2F%2Fforeign'):
            with patch.object(client.slo_op,'open') as transport:
                with self.assertRaises(ValueError):client.complete_native_redirect(origin+'/slo',b'',302,url,'_action')
                transport.assert_not_called()
        with patch.object(client.slo_op,'open',side_effect=TimeoutError('transport failed')):
            with self.assertRaises(TimeoutError):client.complete_native_redirect(origin+'/slo',b'public',302,origin+path+'?id=_abcdef','_action')
        self.assertEqual(len(client.completions),1);self.assertFalse(client.completions[0]['completed']);self.assertEqual(client.completions[0]['exceptionClass'],'TimeoutError')
        self.assertNotIn('_abcdef',(self.out/'native-logout-completion-attempts.json').read_text())

    def test_ssp_continuation_preflight_requires_actual_stock_class_files_before_setup(self):
        raw=b'<?php /* public mocked native class source */'
        sources={name:(path,SSP.SHA(raw),cls) for name,(path,digest,cls) in SSP.CONTINUATION_SOURCE.items()}
        expected={cls:dict(sourceFile=path,sha256=digest) for path,digest,cls in sources.values()}
        for wrong in (False,True):
            folder=self.out/('changed' if wrong else 'stock');folder.mkdir();product=SSP.SimpleSamlPhpProduct();product.bind(folder,self.receipt)
            def command(*args,**kwargs):
                if args[0]=='cat':
                    self.assertTrue(any(row[0]==args[1] for row in sources.values()));return raw
                observed=json.loads(json.dumps(expected))
                if wrong:next(iter(observed.values()))['sourceFile']='/unselected/foreign.php'
                return json.dumps(observed).encode()
            with patch.object(SSP,'CONTINUATION_SOURCE',sources),patch.object(product,'command',side_effect=command):
                if wrong:
                    with self.assertRaisesRegex(ValueError,'class selection differs'):product.continuation_preflight()
                else:product.continuation_preflight();self.assertTrue((folder/'native-continuation-source/qualification.json').is_file())

    def test_ssp_partial_hosted_publisher_failure_restores_both_exact_files(self):
        product=SSP.SimpleSamlPhpProduct();product.bind(self.out,self.receipt)
        remote=self.out/'remote.php';hosted=self.out/'hosted.php';remote.write_bytes(b'<?php\n$metadata=[];\n');hosted.write_bytes(b'<?php\n$metadata["public"]=[];\n')
        product.batch=SSP.ConfigurationBatch(remote);product.hosted_batch=SSP.ConfigurationBatch(hosted)
        original=hosted.read_bytes();remote_original=remote.read_bytes()
        with patch.object(product,'wait_hosted',side_effect=[ValueError('Native publisher readback failed'),None]),patch.object(product,'command',return_value=remote_original):
            with self.assertRaisesRegex(ValueError,'publisher readback'):product.configure_publisher()
            self.assertTrue(product.restore([]))
        self.assertEqual(hosted.read_bytes(),original);self.assertEqual(remote.read_bytes(),remote_original)
        self.assertEqual(product.counts()['nativeConfigurationWrites'],2);self.assertEqual(product.counts()['restorationWrites'],1)

    def test_ssp_hosted_restoration_still_runs_when_remote_restoration_is_blocked(self):
        product=SSP.SimpleSamlPhpProduct();product.bind(self.out,self.receipt)
        class Remote:
            def restore(self):raise RuntimeError('External remote configuration change')
        product.batch=Remote();path=self.out/'hosted.php';original=b'<?php\n$metadata=[];\n';path.write_bytes(original)
        product.hosted_batch=SSP.ConfigurationBatch(path);product.hosted_batch.apply(b'$metadata["public"]=[];')
        with patch.object(product,'wait_hosted'):
            with self.assertRaisesRegex(ValueError,'both owned files'):product.restore([])
        self.assertEqual(path.read_bytes(),original)
        self.assertFalse(json.loads((self.out/'native-restoration.json').read_bytes())['restored'])

    def test_not_ready_preflight_never_posts(self):
        ev=self.out/ADOPT.EVALUATION;ev.mkdir()
        with patch.object(ADOPT,'api',return_value={'cases':[{'caseId':ADOPT.CASE,'ready':False}]}) as transport:
            with self.assertRaisesRegex(ValueError,'POST skipped'):ADOPT.formal_preflight(self.out,'run_test')
        self.assertEqual(transport.call_count,1);self.assertEqual(transport.call_args.args,('/api/runs/run_test/protocol-evidence',))

    def test_missing_formal_slot_unconclusive_never_posts(self):
        (self.out/ADOPT.EVALUATION).mkdir()
        with patch.object(ADOPT,'api',side_effect=[{'cases':[]},{'requirements':[{'cases':[{'id':ADOPT.CASE,'outcome':'NOT_VERIFIED'}]}]}]) as transport:
            with self.assertRaisesRegex(ValueError,'POST skipped'):ADOPT.formal_preflight(self.out,'run_test')
        self.assertTrue(all(len(c.args)==1 for c in transport.call_args_list))

    def test_stored_helper_import_does_not_mutate_shared_global(self):
        import keycloak_registered_signer_stored_outcome as shared
        original=shared.HELPER;isolated=ADOPT.stored_helpers();self.assertEqual(isolated.HELPER,ADOPT.STORED_HELPER);self.assertEqual(shared.HELPER,original);self.assertIsNot(isolated,shared)

    def test_only_memory_oracle_generated_hashes_vary_between_replays(self):
        saved=dict(production_outcome=dict(outcome='SATISFIED_WITH_NOTE',evidence=['stock-original']),
                   wholeReaderCalibration=dict(counterfactualCalibrationOnly=True,actualProductFinding=False,outcome='VIOLATED',
                    model=dict(ephemeralSigningKeyMemoryOnly=True,nativeProductOperationExecuted=False,
                               signedCrossSuccessSha256='a'*64,derivedTargetMetadataSha256='b'*64,signedBaselineSha256='c'*64)))
        actual=json.loads(json.dumps(saved));actual['wholeReaderCalibration']['model']['signedCrossSuccessSha256']='d'*64
        self.assertTrue(ADOPT.replay_agrees(actual,saved))
        actual['production_outcome']['evidence']=['changed-stock-original'];self.assertFalse(ADOPT.replay_agrees(actual,saved))
        actual=json.loads(json.dumps(saved));actual['wholeReaderCalibration']['outcome']='NOT_VERIFIED';self.assertFalse(ADOPT.replay_agrees(actual,saved))


if __name__=='__main__':unittest.main()
