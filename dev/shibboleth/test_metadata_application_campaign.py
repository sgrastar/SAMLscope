import base64, importlib.util, json, pathlib, subprocess, sys, tempfile, unittest
from unittest.mock import patch
HERE=pathlib.Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('native_application_campaign',HERE/'metadata_application_campaign.py');c=importlib.util.module_from_spec(spec);spec.loader.exec_module(c)
PLAN='plan_0123456789ABCDEFGHJKMNPQRS';RUN='run_0123456789ABCDEFGHJKMNPQRS';ENTITY=c.BASE+'/p/'+PLAN

def fixture(run=RUN):
 return ('<md:EntityDescriptor xmlns:md="'+c.MD+'" xmlns:ds="'+c.DS+'" entityID="'+ENTITY+'"><ds:Signature/><md:SPSSODescriptor protocolSupportEnumeration="'+c.P+'">'+''.join('<md:AssertionConsumerService Binding="'+binding+'" Location="'+ENTITY+'/sp/'+('paos' if index==2 else 'acs/'+str(index))+'?mdv=no-valid-until&amp;run='+run+'" index="'+str(index)+'"/>' for index,binding in [(0,c.POST),(1,c.POST),(2,c.PAOS),(3,'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect')])+'</md:SPSSODescriptor></md:EntityDescriptor>').encode()

class CampaignPreflightTest(unittest.TestCase):
 def test_full_original_descriptor_retains_redirect_negative_advertisement(self):
  root=c.preflight_fixture(fixture(),ENTITY,'no-valid-until',RUN);self.assertEqual(4,len(root.findall('.//{'+c.MD+'}AssertionConsumerService')))
 def test_foreign_run_or_plan_is_rejected_before_native_setup(self):
  for raw,entity in [(fixture('run_1123456789ABCDEFGHJKMNPQRS'),ENTITY),(fixture(),ENTITY+'other')]:
   with self.assertRaises(ValueError):c.preflight_fixture(raw,entity,'no-valid-until',RUN)
 def test_missing_binding_or_false_variant_is_rejected(self):
  for raw,variant in [(fixture().replace(c.PAOS.encode(),c.POST.encode()),'no-valid-until'),(fixture(),'control')]:
   with self.assertRaises(ValueError):c.preflight_fixture(raw,ENTITY,variant,RUN)
 def test_soap_addition_preserves_native_roles_and_original_endpoints(self):
  raw=('<md:EntityDescriptor xmlns:md="'+c.MD+'" entityID="'+c.TARGET+'"><md:IDPSSODescriptor><md:SingleSignOnService Binding="'+c.POST+'" Location="http://localhost:18280/idp/profile/SAML2/POST/SSO"/></md:IDPSSODescriptor></md:EntityDescriptor>').encode();changed=c.E.fromstring(c.soap_metadata(raw));services=changed.findall('.//{'+c.MD+'}SingleSignOnService');self.assertEqual([(c.POST,'http://localhost:18280/idp/profile/SAML2/POST/SSO'),(c.SOAP,c.ECP)],[(n.get('Binding'),n.get('Location')) for n in services])
 def test_signed_published_metadata_is_never_silently_modified(self):
  raw=('<md:EntityDescriptor xmlns:md="'+c.MD+'" xmlns:ds="'+c.DS+'" entityID="'+c.TARGET+'"><ds:Signature/><md:IDPSSODescriptor/></md:EntityDescriptor>').encode()
  with self.assertRaises(ValueError):c.soap_metadata(raw)
 def test_actual_slot_preflight_rejects_other_profile_run_digest_and_missing_case(self):
  good=dict(run=dict(id=RUN),profile=dict(id='metadata-idp'),target=dict(metadata_digest='sha256:'+'a'*64),requirements=[dict(cases=[dict(id=case) for case in c.CASES])]);self.assertEqual(set(c.CASES),set(c.actual_slots(good,RUN,'a'*64)))
  for changed in [dict(profile=dict(id='browser-sso-idp')),dict(run=dict(id='foreign')),dict(target=dict(metadata_digest='sha256:'+'b'*64)),dict(requirements=[dict(cases=[dict(id=c.CASES[0])])])]:
   with self.assertRaises(ValueError):c.actual_slots({**good,**changed},RUN,'a'*64)
 def test_login_values_are_never_recorded_and_second_authentication_is_blocked(self):
  client=c.SharedClient([],HERE)
  with patch.object(c.MetadataNativeClient,'request',return_value=('http://localhost:18280/login','public',200)):
   client.request('http://localhost:18280/login',dict(j_password='memory',j_username='user'));self.assertEqual(1,client.credential_posts);self.assertEqual([],client.records)
   with self.assertRaises(ValueError):client.request('http://localhost:18280/login',dict(j_password='memory',j_username='user'))
 def test_public_terminal_never_persists_authentication_or_saml_forms(self):
  for page in ['<input name="password" value="private">','SAMLResponse','Cookie: private','Authorization: Basic private']:
   self.assertFalse(c.public_terminal(page))
  self.assertTrue(c.public_terminal('<h1>Message Security Error</h1>'))
 def test_unknown_existing_provider_is_blocked_without_native_reads(self):
  raw=('<MetadataProvider xmlns="'+c.N+'" xmlns:xsi="'+c.XSI+'" xsi:type="ChainingMetadataProvider"><MetadataProvider id="unknown" xsi:type="DynamicHTTPMetadataProvider" metadataURL="https://outside.invalid/"/></MetadataProvider>').encode()
  with patch.object(c,'docker') as native,tempfile.TemporaryDirectory() as folder:
   with self.assertRaises(ValueError):c.existing_sources(raw,ENTITY,pathlib.Path(folder))
   native.assert_not_called()
 def test_existing_peer_identity_prevents_setup_before_any_write(self):
  raw=('<MetadataProvider xmlns="'+c.N+'" xmlns:xsi="'+c.XSI+'" xsi:type="ChainingMetadataProvider"><MetadataProvider id="existing" xsi:type="FilesystemMetadataProvider" metadataFile="%{idp.home}/metadata/existing.xml"/></MetadataProvider>').encode()
  with patch.object(c,'docker',return_value=fixture()) as native,tempfile.TemporaryDirectory() as folder:
   with self.assertRaises(ValueError):c.existing_sources(raw,ENTITY,pathlib.Path(folder))
   native.assert_called_once_with('cat','/opt/reference-idp/metadata/existing.xml')
 def test_slo_route_uses_public_logout_response_without_authn_only_observer(self):
  request=('<p:LogoutRequest xmlns:p="'+c.P+'" ID="_slo"/>').encode();response=('<p:LogoutResponse xmlns:p="'+c.P+'" InResponseTo="_slo"/>').encode()
  page='<form action="http://localhost:18080/slo"><input name="SAMLResponse" value="'+base64.b64encode(response).decode()+'"></form>'
  with tempfile.TemporaryDirectory() as folder:
   client=c.SharedClient([],folder)
   with patch.object(c.Client,'request',return_value=('http://localhost:18280/idp/profile/SAML2/POST/SLO',page,200)) as transport:
    client.request('http://localhost:18280/idp/profile/SAML2/POST/SLO',{'SAMLRequest':base64.b64encode(request).decode()})
   self.assertEqual(transport.call_count,1);self.assertEqual(client.credential_posts,0)
   self.assertEqual(client.records[0]['requestSha256'],c.SHA(request));self.assertEqual(client.records[0]['responseSamlSha256'],c.SHA(response))
   self.assertNotIn('SAMLResponse',json.dumps(client.records))
 def test_redirect_transport_keeps_the_received_query_bytes(self):
  raw=('<p:LogoutResponse xmlns:p="'+c.P+'" InResponseTo="_slo"/>').encode();compress=c.zlib.compressobj(wbits=-15);encoded=base64.b64encode(compress.compress(raw)+compress.flush()).decode()
  query='SAMLResponse='+c.urllib.parse.quote(encoded,safe='')+'&SigAlg=literal%2Bvalue&Signature=unmodified%2Bvalue'
  client=c.SharedClient([],HERE);handler=next(h for h in client.op.handlers if h.__class__.__name__=='NativeResponseRedirect')
  req=c.urllib.request.Request('http://localhost:18280/idp/profile/SAML2/POST/SLO',data=b'public')
  result=handler.redirect_request(req,None,302,'Found',{},'http://localhost:18080/slo?'+query)
  self.assertEqual(result.full_url,'http://localhost:18080/slo?'+query)
  self.assertEqual(client.redirect_responses['_slo']['responseRawQuerySha256'],c.SHA(query.encode()))
  with self.assertRaises(ValueError):handler.redirect_request(req,None,302,'Found',{},'https://outside.invalid/')
 def test_resume_requires_current_own_case_slots_and_zero_dispatched_outbox(self):
  good=dict(runId=RUN,cases={case:dict(status='RUNNING',phase='runner-queued-front-channel',outcome=None,outboxCount=0) for case in c.CASES})
  c.resume_case_preflight(good,RUN)
  for change in [dict(status='FINISHED'),dict(phase='await-fixture-new-key-explicit-acs'),dict(outcome=dict(outcome='NOT_VERIFIED')),dict(outboxCount=1)]:
   altered=json.loads(json.dumps(good));altered['cases'][c.CASES[0]].update(change)
   with self.assertRaises(ValueError):c.resume_case_preflight(altered,RUN)
  with self.assertRaises(ValueError):c.resume_case_preflight({**good,'runId':'foreign'},RUN)

 def prepared_pair(self,index,at,agent='Shibboleth/5.2.3',run=RUN,source='http://native-source/'):
  fetch=dict(id='fetch'+str(index),runId=run,url=source,timestamp=at-.01,headers={'User-Agent':[agent]},samlSummary={'type':'MetadataFetch'})
  prepared=dict(id='prepared'+str(index),runId=run,timestamp=at,samlSummary=dict(type='MetadataPrepared',feed='live',variant='no-valid-until',metadataSha256='a'*64,fetchTranscriptId=fetch['id']))
  return [fetch,prepared]

 def test_identical_bytes_choose_latest_native_fetch_in_publication_window(self):
  entries=self.prepared_pair(0,1)+self.prepared_pair(1,6,'Python-urllib/3.14')+self.prepared_pair(2,7)+self.prepared_pair(3,8)
  prepared,fetch,selection=c.select_native_prepared(entries,RUN,'no-valid-until','a'*64,'http://native-source/',5,9)
  self.assertEqual('prepared3',prepared['id']);self.assertEqual('fetch3',fetch['id']);self.assertEqual(['prepared2','prepared3'],selection['candidatePreparedReferences'])

 def test_foreign_history_wrong_source_future_fetch_or_tied_latest_is_not_proof(self):
  variants=[self.prepared_pair(0,7,run='foreign'),self.prepared_pair(0,7,source='http://other/'),self.prepared_pair(0,10),self.prepared_pair(0,7)+self.prepared_pair(1,7)]
  for entries in variants:
   with self.assertRaises(ValueError):c.select_native_prepared(entries,RUN,'no-valid-until','a'*64,'http://native-source/',5,9)

 def test_partial_attempt_native_audit_is_filtered_by_actual_original_request_id(self):
  raw=('<p:AuthnRequest xmlns:p="'+c.P+'" ID="_own"/>').encode()
  audit='SAMLscope-application-v1|_own||||||||||2026-01-01T00:00:00Z\nSAMLscope-application-v1|_foreign||||||||||2026-01-01T00:00:00Z\n'
  with tempfile.TemporaryDirectory() as folder:
   path=pathlib.Path(folder);(path/'request.xml').write_bytes(raw)
   with patch.object(c,'docker',return_value=audit.encode()):c.collect_native_audit(path,[dict(id='tx-own',direction='OUTBOUND')],[dict(id='tx-own',file='request.xml')],path)
   result=(path/'native-application-audit.log').read_text();self.assertIn('_own',result);self.assertNotIn('_foreign',result)

class CampaignRestorationTest(unittest.TestCase):
 def simulate(self,changed,fail_write=False,fail_query=False):
  originals={c.PROVIDERS:b'<providers/>',c.AUDIT:b'<audit/>',c.PUBLIC:b'<public/>'};state=dict(originals);writes=[];restarts=[]
  for path in changed:state[path]=b'<changed/>'
  def native(*args,**kwargs):
   if args[0]=='cat':return state[args[1]]
   if args[0]=='rm':state.pop(args[2],None);return b''
   if args[0]=='sh':return b''
   self.fail(args)
  def write(path,raw,label):
   writes.append(label);state[path]=raw
   if fail_write and path==c.PROVIDERS:raise OSError('Write completed before readback failure')
  def query(*args,**kwargs):
   self.assertEqual(kwargs['timeout'],40)
   if fail_query:raise subprocess.TimeoutExpired(args[0],40)
   return subprocess.CompletedProcess(args[0],0,b'<md:EntitiesDescriptor xmlns:md="'+c.MD.encode()+b'"/>',b'')
  with tempfile.TemporaryDirectory() as folder:
   receipt=pathlib.Path(folder);native_dir=receipt/'native';native_dir.mkdir()
   with patch.object(c,'docker',side_effect=native),patch.object(c.subprocess,'run',side_effect=query),patch.object(c,'native_runtime',return_value=dict(running=True)):
    result=c.restore_native(originals,changed,[],'/owned-cache.xml',ENTITY,native_dir,receipt,write,restarts.append)
  return result,state,originals,writes,restarts
 def test_native_write_then_readback_failure_still_restores_all_owned_paths(self):
  result,state,originals,writes,restarts=self.simulate(set((c.PROVIDERS,c.AUDIT,c.PUBLIC)),fail_write=True)
  self.assertEqual(state,originals);self.assertEqual(writes,['restore-providers','restore-audit','restore-public-metadata'])
  self.assertEqual(restarts,['restore-application-audit']);self.assertFalse(result['restored']);self.assertEqual(result['failures'][0]['path'],c.PROVIDERS)
 def test_query_timeout_is_retained_after_config_cleanup_without_hiding_costs(self):
  result,state,originals,writes,restarts=self.simulate(set((c.PROVIDERS,c.AUDIT,c.PUBLIC)),fail_query=True)
  self.assertEqual(state,originals);self.assertEqual(len(writes),3);self.assertEqual(len(restarts),1)
  self.assertFalse(result['restored']);self.assertIn('restored-peer-query',[row.get('operation') for row in result['failures']])
 def test_no_native_write_before_precondition_failure_adds_no_restore_write_or_restart(self):
  result,state,originals,writes,restarts=self.simulate(set())
  self.assertTrue(result['restored']);self.assertEqual(state,originals);self.assertEqual(writes,[]);self.assertEqual(restarts,[])

if __name__=='__main__':unittest.main()
