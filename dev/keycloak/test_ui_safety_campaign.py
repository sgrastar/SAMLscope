"""Native cleanup owns only new campaign clients and never conceals failed writes."""
import unittest
from ui_safety_campaign import restore_clients
class RestoreNativeUiSafety(unittest.TestCase):
 def test_partial_apply_then_exception_recovers_only_owned_client(self):
  data=[dict(id='owned',clientId='peer',protocol='saml')];ops=[]
  def read(_):return list(data)
  def write(path,method):
   self.assertEqual((path,method),('/clients/owned','DELETE'));data.clear();return 204,b'',{}
  def record(kind,**kw):row=dict(kind=kind,**kw);ops.append(row);return row
  self.assertEqual([],restore_clients(read,write,'lookup','peer',[],record));self.assertEqual(ops[0]['status'],204)
 def test_foreign_client_never_deleted(self):
  writes=[]
  with self.assertRaises(ValueError):restore_clients(lambda _:[dict(id='other',clientId='foreign',protocol='saml')],lambda *a,**kw:writes.append(a),'lookup','peer',[],lambda *a,**kw:{})
  self.assertEqual([],writes)
 def test_failed_recovery_not_called_restored(self):
  ops=[]
  def record(kind,**kw):row=dict(kind=kind,**kw);ops.append(row);return row
  with self.assertRaises(ValueError):restore_clients(lambda _:[dict(id='owned',clientId='peer',protocol='saml')],lambda *a,**kw:(500,b'',{}),'lookup','peer',[],record)
  self.assertEqual(500,ops[0]['status'])
if __name__=='__main__':unittest.main()
