"""Strict separately recorded recovery controls; no Docker/product operations."""
import copy,importlib.util,json,pathlib,sys,tempfile,unittest
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parent))
from keycloak_registered_signer_runtime_recovery import runtime_recovery_proof,NAME
REPO=pathlib.Path(__file__).resolve().parents[2]
SOURCE=REPO/'build/acceptance/reference-20261002/docker-maintenance'
CAMPAIGN=REPO/'build/acceptance/reference-20261002/keycloak-registered-signer-r1'

class RuntimeRecoveryTest(unittest.TestCase):
    def setUp(self):
        self.before=json.loads((SOURCE/'pre-recovery-containers.json').read_bytes())
        self.after=json.loads((SOURCE/'post-recovery-containers.json').read_bytes())
        self.recovery=json.loads((SOURCE/'desktop-recovery.json').read_bytes())
        self.expected=json.loads((CAMPAIGN/'restoration.json').read_bytes())['after_runtime']
        self.current=next(r for r in self.after if r['Name']==NAME)
        self.actual=copy.deepcopy(self.expected);self.actual['startedAt']=self.current['StartedAt']
    def check(self):
        with tempfile.TemporaryDirectory(dir='/private/tmp') as name:
            root=pathlib.Path(name);maintenance=root/'docker-maintenance';maintenance.mkdir();folder=root/'campaign';folder.mkdir()
            for filename,value in [('pre-recovery-containers.json',self.before),('post-recovery-containers.json',self.after),('desktop-recovery.json',self.recovery)]:
                (maintenance/filename).write_text(json.dumps(value))
            return runtime_recovery_proof(folder,self.expected,self.actual,current_inspect=self.current)
    def test_exact_existing_runtime_needs_no_recovery_exception(self):
        self.assertIsNone(runtime_recovery_proof(CAMPAIGN,self.expected,self.expected))
    def test_same_containers_images_mounts_and_recorded_epochs_are_qualified(self):
        proof=self.check();self.assertTrue(proof['originalCampaignProofUnchanged']);self.assertEqual(proof['globalRecoveryCosts']['settingsWrites'],0)
    def test_changed_historical_or_current_epoch_cannot_alias_recovery(self):
        self.expected['startedAt']='2026-10-02T05:00:00Z'
        with self.assertRaisesRegex(ValueError,'epochs do not bind'):self.check()
        self.setUp();self.actual['startedAt']='2026-10-02T09:06:20Z'
        with self.assertRaisesRegex(ValueError,'epochs do not bind'):self.check()
    def test_any_native_runtime_field_change_is_rejected(self):
        self.actual['version']='other'
        with self.assertRaisesRegex(ValueError,'beyond its epoch'):self.check()
    def test_modified_image_mount_or_container_identity_is_rejected(self):
        self.current['Image']='sha256:other'
        with self.assertRaisesRegex(ValueError,'container/image/mount'):self.check()
        self.setUp();self.current['Mounts'][0]['RW']=True
        with self.assertRaisesRegex(ValueError,'container/image/mount'):self.check()
    def test_recovery_cannot_hide_settings_or_protocol_operations(self):
        self.recovery['settingsWrites']=1
        with self.assertRaisesRegex(ValueError,'actions or deployed-runtime'):self.check()
        self.setUp();self.recovery['protocolSubmissions']=1
        with self.assertRaisesRegex(ValueError,'actions or deployed-runtime'):self.check()
    def test_current_inspect_requires_the_exact_post_recovery_original(self):
        original=copy.deepcopy(self.current);self.current['Running']=False
        with self.assertRaises(ValueError):self.check()
    def test_mount_order_has_no_effect_but_duplicate_destination_is_ambiguous(self):
        row=next(r for r in self.after if r['Name']=='/samlscope-reference-ssp')
        row['Mounts'].reverse();self.assertTrue(self.check()['originalCampaignProofUnchanged'])
        row['Mounts'].append(copy.deepcopy(row['Mounts'][0]))
        with self.assertRaisesRegex(ValueError,'Ambiguous native mount'):self.check()

if __name__=='__main__':unittest.main()
