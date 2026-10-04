"""No target operations: prove slot/fixture preflight and bounded shared-login behavior."""
import contextlib
import io
import pathlib
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parent))
import metadata_role_key_campaign as c
from signature_audit_format import FORMAT

RUN='run_00000000000000000000000001';PLAN='plan_00000000000000000000000001';ENTITY=c.BASE+'/p/'+PLAN
MD='urn:oasis:names:tc:SAML:2.0:metadata';DS='http://www.w3.org/2000/09/xmldsig#'

def result():
 return dict(run=dict(id=RUN),profile=dict(id='metadata-idp'),target=dict(entity_id='http://localhost:18280/idp/shibboleth',metadata_digest='sha256:'+'a'*64),requirements=[dict(cases=[dict(id=c.CASE),dict(id='IIP-MD06-c-idp-01')])])

def fixture(v):
 def role(name):
  use=['signing','encryption'] if 'explicit' in v else ['']
  key=''.join('<KeyDescriptor'+(' use="'+x+'"' if x else '')+'><ds:KeyInfo><ds:X509Data><ds:X509Certificate>AQID</ds:X509Certificate></ds:X509Data></ds:KeyInfo></KeyDescriptor>' for x in use)
  acs='<AssertionConsumerService index="0" Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="'+ENTITY+'/sp/acs/0"/>' if name=='SPSSODescriptor' else ''
  return '<'+name+'>'+key+acs+'</'+name+'>'
 names=['IDPSSODescriptor','SPSSODescriptor'] if 'idp-first' in v else ['SPSSODescriptor','IDPSSODescriptor']
 return ('<EntityDescriptor xmlns="'+MD+'" xmlns:ds="'+DS+'" entityID="'+ENTITY+'"><ds:Signature/>'+''.join(role(n) for n in names)+'</EntityDescriptor>').encode()

class PreflightTest(unittest.TestCase):
 def test_actual_case_slots_required(self):
  self.assertEqual(set(c.preflight_slots(result(),RUN)),{c.CASE,'IIP-MD06-c-idp-01'})
  for field in ['run','profile','cases']:
   r=result()
   if field=='run':r['run']['id']='run_00000000000000000000000002'
   elif field=='profile':r['profile']['id']='browser-sso-idp'
   else:r['requirements'][0]['cases'].pop()
   with self.assertRaises(AssertionError):c.preflight_slots(r,RUN)
 def test_all_four_structures_checked_before_native_write(self):
  for v in c.VARIANTS:c.preflight_fixture(fixture(v),ENTITY,v)
  with self.assertRaises(AssertionError):c.preflight_fixture(fixture(c.VARIANTS[1]),ENTITY,c.VARIANTS[0])
  with self.assertRaises(AssertionError):c.preflight_fixture(fixture(c.VARIANTS[0]),ENTITY,c.VARIANTS[2])
 def test_foreign_entity_and_wrong_acs_rejected(self):
  raw=fixture(c.VARIANTS[0])
  with self.assertRaises(AssertionError):c.preflight_fixture(raw,ENTITY+'/foreign',c.VARIANTS[0])
  with self.assertRaises(AssertionError):c.preflight_fixture(raw.replace((ENTITY+'/sp/acs/0').encode(),b'http://foreign.invalid/acs'),ENTITY,c.VARIANTS[0])
 def test_preflight_failure_does_not_reach_product_writes_or_login(self):
  audit=('<beans xmlns="http://www.springframework.org/schema/beans" xmlns:util="http://www.springframework.org/schema/util"><util:map id="shibboleth.AuditFormattingMap"><entry key="Shibboleth-Audit" value="'+FORMAT+'"/></util:map></beans>').encode()
  providers=b'<MetadataProvider xmlns="urn:mace:shibboleth:2.0:metadata"/>'
  calls=[];index=[0]
  def docker(*args,data=None):
   calls.append(args)
   if args==('cat',c.AUDIT):return audit
   if args==('cat',c.PROVIDERS):return providers
   return b''
  def api(path,data=None):
   if path=='/api/plans':return dict(plan=dict(plan=dict(id=PLAN)))
   if path.endswith('/runs'):return dict(run=dict(id=RUN,planId=PLAN))
   if path.endswith('/preflight'):return {}
   if path.endswith('/automatic-polling'):index[0]+=1;return {}
   if path.endswith('/metadata-lab'):return dict(automaticStartUrl='http://localhost:18080/prepare',metadataUrl='http://localhost:18080/metadata')
   if path.endswith('/result.json'):
    r=result();r['requirements'][0]['cases'].pop();return r
   if path.endswith('/transcript'):return []
   raise AssertionError(path)
  class Response(io.BytesIO):
   status=202
   def __enter__(self):return self
   def __exit__(self,*args):self.close()
  def urlopen(url,timeout=None):return Response(fixture(c.VARIANTS[index[0]-1]))
  with tempfile.TemporaryDirectory() as tmp,patch.object(c,'docker',side_effect=docker),patch.object(c,'api',side_effect=api),patch.object(c,'baseline') as baseline,patch.object(c,'capture'),patch.object(c,'trust_runtime',return_value=dict(running=True)),patch.object(c.urllib.request,'urlopen',side_effect=urlopen):
   with self.assertRaises(AssertionError):c.collect(pathlib.Path(tmp)/'attempt',capture_trust=True)
   baseline.assert_not_called()
  self.assertFalse(any(a[:2]==('sh','-c') and a[2].startswith('cat >') for a in calls))
  self.assertFalse(any('reload-service.sh' in str(a) for a in calls))

if __name__=='__main__':unittest.main()
