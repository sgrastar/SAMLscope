import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET

spec=importlib.util.spec_from_file_location('soap_continuation_collector',Path(__file__).with_name('soap_slo_propagation_campaign.py'))
C=importlib.util.module_from_spec(spec);spec.loader.exec_module(C)

def hosted():
    return ('<md:EntityDescriptor xmlns:md="'+C.MD+'" entityID="http://localhost:18280/idp/shibboleth"><md:IDPSSODescriptor protocolSupportEnumeration="'+C.P+'"><md:SingleLogoutService Binding="post" Location="http://localhost:18280/idp/profile/SAML2/POST/SLO"/></md:IDPSSODescriptor></md:EntityDescriptor>').encode()

def prepared(plan='plan_test',run='run_test',trial='failure'):
    nodes=[]
    for label in C.LABELS:
        entity=C.BASE+'/p/'+plan+(''if label=='primary'else '/sp-'+label)
        query=''if label=='primary'else '?run='+run+'&amp;propagation=error-v2&amp;participant='+label+'&amp;trial='+trial+'&amp;mode='+('first-arrival'if trial=='failure'else'all-success')
        nodes.append('<md:EntityDescriptor entityID="'+entity+'"><md:SPSSODescriptor><md:SingleLogoutService Binding="'+C.SOAP+'" Location="http://host.docker.internal:18080/p/'+plan+'/sp/slo/soap'+query+'"/></md:SPSSODescriptor></md:EntityDescriptor>')
    return ('<md:EntitiesDescriptor xmlns:md="'+C.MD+'">'+''.join(nodes)+'</md:EntitiesDescriptor>').encode()

def origin(run='run_test',trial='failure'):
    chosen=C.action(run,trial,'logout')
    req=dict(id='request',direction='OUTBOUND',correlationId=chosen,samlSummary=dict(type='LogoutRequest',action_id=chosen,probe_transport='direct-soap'))
    rsp=dict(id='response',direction='INBOUND',correlationId=chosen,samlSummary=dict(type='SloProbeHttpResponse',saml_message='LogoutResponse',probe_transport='direct-soap',request_transcript='request'))
    return [req,rsp]

class CollectorTests(unittest.TestCase):
    def test_prior_failed_campaign_retains_original_failure_refs(self):
        with tempfile.TemporaryDirectory()as temporary:
            folder=Path(temporary)
            for name in ('created.json','operation-counts.json','native-restoration.json','failure.json'):(folder/name).write_bytes(b'original')
            self.assertEqual(set(C.prior_original_refs(folder,'run_test')),{'created.json','operation-counts.json','native-restoration.json','failure.json'})
    def test_complete_unadopted_prior_requires_own_order_original(self):
        with tempfile.TemporaryDirectory()as temporary,patch.object(C,'REPO',Path(temporary)):
            folder=Path(temporary)/'prior';folder.mkdir();(folder/'diagnosis').mkdir()
            for name in ('created.json','operation-counts.json','native-restoration.json','transcript-final.json'):(folder/name).write_bytes(b'original')
            diagnosis=dict(schema='samlscope-soap-first-error-order-diagnosis-v1',runId='run_test',adoptionAllowed=False,originalsChanged=False,
                sourceFile='prior/transcript-final.json',sourceSha256=C.SHA(b'original'))
            name='diagnosis/first-arrival-order-unqualified.json';(folder/name).write_text(json.dumps(diagnosis))
            self.assertEqual(set(C.prior_original_refs(folder,'run_test')),{'created.json','operation-counts.json','native-restoration.json','transcript-final.json',name})
            for field,value in [('runId','run_foreign'),('sourceSha256','0'*64),('sourceFile','foreign/transcript-final.json'),('adoptionAllowed',True)]:
                wrong=dict(diagnosis);wrong[field]=value;(folder/name).write_text(json.dumps(wrong))
                with self.assertRaises(ValueError):C.prior_original_refs(folder,'run_test')
    def test_exact_stock_authn_flow_bytes_are_qualified(self):
        originals={C.ROOT+'/flows/authn/conditions/'+x:('<flow id="'+x+'"/>').encode()for x in C.AUTHN_FLOWS}
        class Jar:
            def read(self,path):return originals[C.ROOT+'/flows/authn/conditions/'+path.removeprefix('net/shibboleth/idp/module/flows/authn/conditions/')]
        inventory=('\n'.join(originals)+'\n'+C.ROOT+'/views/logout.vm\n').encode();C.validate_flow_inventory(inventory,originals,Jar())
        altered=dict(originals);altered[next(iter(altered))]=b'<different-flow/>'
        with self.assertRaises(ValueError):C.validate_flow_inventory(inventory,altered,Jar())
    def test_unknown_slo_and_authn_flow_override_still_refused(self):
        originals={C.ROOT+'/flows/authn/conditions/'+x:b'<stock-flow/>'for x in C.AUTHN_FLOWS}
        class Jar:
            def read(self,path):return b'<stock-flow/>'
        for extra in ('flows/saml/saml2/slo-back-flow.xml','flows/authn/conditions/unknown.xml','views/override.class'):
            inventory=('\n'.join(originals)+'\n'+C.ROOT+'/'+extra+'\n').encode()
            with self.assertRaises(ValueError):C.validate_flow_inventory(inventory,originals,Jar())
    def test_selection_activation_configuration_has_no_browser_send_or_skip(self):
        answers=[[],dict(state='UNAVAILABLE'),[dict(caseId=C.CASE,kind='CONFIGURATION')]]
        with tempfile.TemporaryDirectory()as temporary,patch.object(C,'api',side_effect=answers),patch.object(C,'prepare_and_skip')as skip:
            steps=[];C.select_configuration('run_test',Path(temporary),steps);self.assertEqual(steps,[]);skip.assert_not_called()
    def test_advertisement_preserves_original_and_known_endpoints(self):
        raw=hosted();before=raw[:];new=C.soap_advertisement(raw,'http://localhost:18280/idp/shibboleth');self.assertEqual(raw,before)
        nodes=ET.fromstring(new).findall('.//{'+C.MD+'}SingleLogoutService');self.assertEqual(len(nodes),2)
        self.assertEqual(nodes[-1].attrib,dict(Binding=C.SOAP,Location='http://localhost:18280/idp/profile/SAML2/SOAP/SLO'))
    def test_signed_or_foreign_hosted_metadata_refused(self):
        for raw in (hosted().replace(b'<md:IDP',b'<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"/><md:IDP'),hosted().replace(b'idp/shibboleth',b'idp/foreign')):
            with self.assertRaises(ValueError):C.soap_advertisement(raw,'http://localhost:18280/idp/shibboleth')
    def test_prepared_original_four_entities(self):
        self.assertEqual([p['label']for p in C.prepared_peers(prepared(),'plan_test','run_test','failure')],list(C.LABELS))
    def test_foreign_run_or_callback_or_path_refused(self):
        for raw in (prepared().replace(b'run_test',b'run_foreign'),prepared().replace(b'host.docker.internal',b'foreign.invalid'),prepared().replace(b'/sp/slo/soap?',b'/other?')):
            with self.assertRaises(ValueError):C.prepared_peers(raw,'plan_test','run_test','failure')
    def test_duplicate_and_wrong_trial_marker_refused(self):
        for raw in (prepared().replace(b'run=run_test',b'run=run_test&amp;run=run_test'),prepared().replace(b'trial=failure',b'trial=all-success'),prepared().replace(b'mode=first-arrival',b'mode=all-success'),prepared().replace(b'error-v2',b'error-v1')):
            with self.assertRaises(ValueError):C.prepared_peers(raw,'plan_test','run_test','failure')
    def test_actual_sender_schema_matches_and_unissued_does_not(self):
        rows=origin();self.assertEqual(C.origin_final(rows,'run_test','failure'),tuple(rows))
        self.assertIsNone(C.origin_final(rows,'run_other','failure'));self.assertIsNone(C.origin_final(rows[:1],'run_test','failure'))
        rows[1]['samlSummary']['type']='LogoutResponse';self.assertIsNone(C.origin_final(rows,'run_test','failure'))
    def test_duplicate_origin_and_final_refused(self):
        for rows in (origin()+[origin()[0]],origin()+[origin()[1]]):
            with self.assertRaises(ValueError):C.origin_final(rows,'run_test','failure')
    def test_trial_baseline_uses_exact_action_correlation(self):
        rows=origin()
        for label in C.LABELS:
            rows.append(dict(id='baseline-'+label,direction='INBOUND',correlationId='_'+C.action('run_test','failure','login',label),samlSummary={'type':'Response'}))
            if label!='primary':
                for direction,kind in (('INBOUND','LogoutRequest'),('OUTBOUND','LogoutResponse')):
                    rows.append(dict(id=kind+'-'+label,direction=direction,samlSummary=dict(type=kind,propagationTrial='failure',propagationParticipant=label)))
        peers={label:label+'.xml'for label in C.LABELS}
        result=C.build_trial('run_test','failure',{'id':'prepared'},rows,'before','after',peers);self.assertEqual(len(result['baselines']),4)
        rows.append(dict(rows[2],id='foreign-duplicate'))
        with self.assertRaises(ValueError):C.build_trial('run_test','failure',{'id':'prepared'},rows,'before','after',peers)
    def test_credentials_memory_only_and_fourth_transport_refused(self):
        with tempfile.TemporaryDirectory()as temporary:
            client=C.PropagationClient(Path(temporary))
            with patch.object(C.Client,'request',return_value=('http://localhost:18280/idp/profile/SAML2/POST/SSO','private AuthState=capability',200))as request:
                for _ in range(3):client.request('http://localhost:18280/idp/auth',{'j_password':'never-export','j_username':'user'})
                with self.assertRaises(ValueError):client.request('http://localhost:18280/idp/auth',{'j_password':'never-export'})
                self.assertEqual(request.call_count,3)
            saved=(Path(temporary)/'credential-boundaries.json').read_text();self.assertNotIn('never-export',saved);self.assertNotIn('capability',saved)
    def test_failed_credential_attempt_is_counted_before_transport(self):
        with tempfile.TemporaryDirectory()as temporary:
            client=C.PropagationClient(Path(temporary))
            with patch.object(C.Client,'request',side_effect=TimeoutError()):
                with self.assertRaises(TimeoutError):client.request('http://localhost:18280/idp/auth',{'j_password':'never-export'})
            self.assertEqual(len(client.auth),1);self.assertFalse(client.auth[0]['completed']);self.assertEqual(client.auth[0]['failureClass'],'TimeoutError')
    def test_partial_write_reload_failure_restores_exact_and_removes_owned(self):
        class Fake(C.Product):
            def command(self,*argv,data=None,allow_failure=False):
                if argv[0]=='cat':return self.store[argv[1]]
                if argv[:2]==('test','-e'):
                    class R:returncode=0 if argv[2]in self.store else 1
                    return R()
                if argv[0]=='rm':self.store.pop(argv[1]);return b''
                if argv[:2]==('sh','-c')and argv[2].startswith('cat > '):self.store[argv[2][6:]]=data;return b''
                raise AssertionError(argv)
            def activate(self,label):
                self.activation_attempted=True
                if label!='restore':raise TimeoutError()
        with tempfile.TemporaryDirectory()as temporary:
            folder=Path(temporary);product=Fake();product.bind(folder,folder);product.store={C.PUBLIC:b'original-md',C.PROVIDERS:b'original-provider',C.AUDIT:b'original-audit'}
            product.original=dict(product.store);product.expected=dict(product.store);path=C.ROOT+'/metadata/owned.xml';product.owned_sources[path]=b'fixture'
            product.write(C.PUBLIC,b'configured-md','advertise');product.write(path,b'fixture','source')
            with self.assertRaises(TimeoutError):product.activate('prepare')
            self.assertTrue(product.restore([]));self.assertEqual(product.store,product.original);self.assertEqual(sum(r['label'].startswith('restore')for r in product.operations),1)

if __name__=='__main__':unittest.main()
