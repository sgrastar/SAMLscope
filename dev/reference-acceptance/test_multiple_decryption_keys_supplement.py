"""Local data-only controls for the initial-login prerequisite's receipt binding."""
import importlib.util,json,pathlib,sys,tempfile,unittest
sys.dont_write_bytecode=True
spec=importlib.util.spec_from_file_location('key_config_acceptance',pathlib.Path(__file__).with_name('verify_simplesamlphp_multiple_decryption_keys_acceptance.py'))
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)

class SupplementBindingTest(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.folder=pathlib.Path(self.temp.name);self.initial=self.folder/'initial-roundtrip';self.initial.mkdir()
        self.run='run_00000000000000000000000000';self.plan='plan_00000000000000000000000000';self.original=b'<?php // local diagnostic fixture\n'
        self.write(self.folder/'created.json',{'run':{'id':self.run,'planId':self.plan}})
        self.write(self.initial/'run-after.json',{'id':self.run,'planId':self.plan,'status':'COMPLETED'})
        for path in [self.folder/'remote-original.php',self.initial/'remote-original.php',self.initial/'remote-final.php']:path.write_bytes(self.original)
        self.write(self.initial/'restoration.json',{'restored':True,'original_sha256':module.SHA(self.original),'final_sha256':module.SHA(self.original)})
        self.write(self.folder/'native-peer-parser.stdout',{'php':'// same native peer fixture'})
        (self.initial/'remote-configured.php').write_bytes(self.original+b'\n// same native peer fixture\n')
        base=dict(restored=True,credentialPosts=0,samlProtocolOperations=0,productConfigurationWriteAttempts=4,successfulHostWrites=4,nativeApplications=2,restorationWrites=2,nativeObservationInvocations=2,nativeEphemeralFilesCreated=3,nativeEphemeralFilesRemoved=3,dockerCommandsAttempted=2,failedDockerCommands=0,humanOperations=0)
        more=dict(restored=True,credentialPosts=1,initialNormalProtocolOperationsAttempted=1,profileTestProtocolDispatches=0,productConfigurationWriteAttempts=2,successfulHostWrites=2,nativeApplications=1,restorationWrites=1,dockerCommandsAttempted=2,failedDockerCommands=0,humanOperations=0)
        self.write(self.folder/'operation-counts.json',base);self.write(self.initial/'operation-counts.json',more)
        self.write(self.folder/'operations.json',[{},{}]);self.write(self.initial/'operations.json',[{},{}])
    def tearDown(self):self.temp.cleanup()
    @staticmethod
    def write(path,value):path.write_text(json.dumps(value))
    def test_same_run_and_native_configuration_sum_without_rewriting_history(self):
        before=(self.folder/'operation-counts.json').read_bytes();result=module.verify_initial_supplement(self.folder)
        self.assertEqual(6,result['productConfigurationWriteAttempts']);self.assertEqual(3,result['restorationWrites']);self.assertEqual(1,result['credentialPosts'])
        self.assertEqual(before,(self.folder/'operation-counts.json').read_bytes())
    def test_foreign_run_completion_cannot_satisfy_prerequisite(self):
        self.write(self.initial/'run-after.json',{'id':'run_00000000000000000000000001','planId':self.plan,'status':'COMPLETED'})
        with self.assertRaises(ValueError):module.verify_initial_supplement(self.folder)
    def test_restoration_claim_cannot_hide_changed_native_bytes(self):
        (self.initial/'remote-final.php').write_bytes(b'changed')
        with self.assertRaises(ValueError):module.verify_initial_supplement(self.folder)
    def test_another_peer_import_cannot_satisfy_prerequisite(self):
        (self.initial/'remote-configured.php').write_bytes(self.original+b'\n// foreign peer\n')
        with self.assertRaises(ValueError):module.verify_initial_supplement(self.folder)
    def test_coherently_lowered_original_burden_is_rejected(self):
        value=json.loads((self.folder/'operation-counts.json').read_bytes());value['productConfigurationWriteAttempts']=0;self.write(self.folder/'operation-counts.json',value)
        with self.assertRaises(ValueError):module.verify_initial_supplement(self.folder)

if __name__=='__main__':unittest.main()
