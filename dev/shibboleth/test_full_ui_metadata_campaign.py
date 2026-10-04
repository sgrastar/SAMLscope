import importlib.util
import pathlib
import subprocess
import unittest
from unittest.mock import patch

spec=importlib.util.spec_from_file_location('full_ui_metadata_campaign',pathlib.Path(__file__).with_name('full_ui_metadata_campaign.py'))
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

class FullUiCampaignTest(unittest.TestCase):
    def test_write_reached_native_then_failed_can_restore_exactly(self):
        original=b'<old/>';configured=b'<configured/>';temporary='/owned-source.xml'
        state={m.PROVIDERS:configured,temporary:b'<fixture/>'};writes=[];reloads=[]
        def native(*args,**kwargs):
            if args[0]=='cat':return subprocess.CompletedProcess(args,0,state[args[1]],b'')
            if args[0]=='rm':state.pop(args[2]);return subprocess.CompletedProcess(args,0,b'',b'')
            path=args[2].split()[-1]; exists=path in state
            code=int(exists if 'test ! -e' in args[2] else not exists)
            return subprocess.CompletedProcess(args,code,b'',b'')
        def write(path,raw,label):writes.append(label);state[path]=raw
        m.restore(write,reloads.append,native,original,configured,temporary,True,True)
        self.assertEqual(state,{m.PROVIDERS:original});self.assertEqual(writes,['restore-providers']);self.assertEqual(reloads,['restore-providers'])
    def test_failed_before_native_write_needs_no_extra_mutation(self):
        state={m.PROVIDERS:b'<old/>'};calls=[]
        def native(*args,**kwargs):
            if args[0]=='cat':return subprocess.CompletedProcess(args,0,state[args[1]],b'')
            return subprocess.CompletedProcess(args,0 if 'test ! -e' in args[2] else 1,b'',b'')
        m.restore(lambda *a:calls.append(a),lambda *a:calls.append(a),native,b'<old/>',b'<new/>','/owned.xml',True,True)
        self.assertEqual(calls,[])
    def test_external_provider_change_is_never_overwritten(self):
        def native(*args,**kwargs):return subprocess.CompletedProcess(args,0,b'<external/>',b'')
        with self.assertRaises(ValueError):m.restore(lambda *a:self.fail('write'),lambda *a:self.fail('reload'),native,b'<old/>',b'<ours/>','/owned.xml',True,True)
    def test_private_xml_and_auth_header_keys_are_rejected_before_export(self):
        for raw in [b'<r><PrivateKey/></r>',b'<r password="x"/>',b'<r><Cookie/></r>',b'<r><Authorization/></r>']:
            with self.assertRaises(ValueError):m.public_xml(raw)
        self.assertEqual(m.public_xml(b'<r><X509Certificate>public</X509Certificate></r>'),b'<r><X509Certificate>public</X509Certificate></r>')
    def test_second_credential_is_blocked_before_transport(self):
        client=m.M0Client()
        with patch.object(m.reference_flow.Client,'request',return_value=('https://public.example/','',200)) as native:
            client.request('http://localhost:18280/idp/profile/Login',{'j_password':'memory-only'})
            with self.assertRaises(ValueError):client.request('http://localhost:18280/idp/profile/Login',{'j_password':'memory-only'})
            self.assertEqual(native.call_count,1)
        self.assertEqual(client.credential_posts,1)
    def test_native_query_uses_real_running_service_and_clean_cli_environment(self):
        command=m.query_command('http://suite.example/p/plan_00000000000000000000000000')
        self.assertEqual(command[0:7],['env','-u','CLASSPATH','-u','JAVA_OPTS','-u','SHIB_OPTS'])
        self.assertEqual(command[-4:],['-u','http://localhost:8080/idp','-e','http://suite.example/p/plan_00000000000000000000000000'])

if __name__=='__main__':unittest.main()
