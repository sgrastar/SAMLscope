import copy, importlib.util, json, pathlib, tempfile, unittest

HERE=pathlib.Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('publisher_campaign',HERE/'publisher_key_inventory_campaign.py')
campaign=importlib.util.module_from_spec(spec);spec.loader.exec_module(campaign)

class PublisherPreparationTest(unittest.TestCase):
    def result(self):
        return dict(run={'id':campaign.DEFAULT_RUN},target={'role':'IDP'},requirements=[{'cases':[dict(id=x,mode='CONFIG') for x in campaign.CASES]}])
    def state(self):
        return dict(schema='samlscope-ssp-public-publisher-state-v1',entityId=campaign.TARGET,
            loadedClasses=[dict(logicalFile=k,sha256=v[1]) for k,v in campaign.SOURCES.items()],metadataSources=[dict(type='flatfile')],
            roleFeatureFlags={'saml20.ecp':False,'saml20.hok.assertion':False,'saml20.sendartifact':False,'metadata.sign.enable':False},
            currentCredentials=[dict(prefix='',publicCertificatePresent=True)],remotePeers=[],publicNativeMetadata={
                'SingleSignOnService':[dict(Binding='urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',Location='http://localhost:18380/sso')],
                'SingleLogoutService':[dict(Binding='urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',Location='http://localhost:18380/slo')]})
    def test_real_config_slots_required_before_native_writes(self):
        self.assertEqual(set(campaign.slots(self.result(),campaign.DEFAULT_RUN)),set(campaign.CASES))
        for kind in ('missing-case','wrong-run','wrong-role','attested-instead-of-config'):
            n=self.result()
            if kind=='missing-case':n['requirements'][0]['cases'].pop()
            elif kind=='wrong-run':n['run']['id']='run_00000000000000000000000000'
            elif kind=='wrong-role':n['target']['role']='SP'
            else:n['requirements'][0]['cases'][0]['mode']='ATTESTED'
            with self.assertRaises(ValueError):campaign.slots(n,campaign.DEFAULT_RUN)
    def test_native_core_browser_epoch_has_no_extra_scope_gap(self):
        self.assertEqual(campaign.native_gaps(self.state()),[])
    def test_ecp_requires_explicit_epoch_and_not_capability_waiver(self):
        n=self.state();n['roleFeatureFlags']['saml20.ecp']=True
        n['publicNativeMetadata']['SingleSignOnService'].append(dict(Binding='urn:oasis:names:tc:SAML:2.0:bindings:SOAP',Location='http://localhost:18380/soap'))
        self.assertEqual(campaign.native_gaps(n),['additional-endpoint-binding-transport-scope-unproven','additional-role-protocol-transport-scope-unproven'])
    def test_unknown_role_source_and_flag_shape_stop_before_writes(self):
        for kind in ('duplicate-source','unknown-source','nonbool-flag','second-storage'):
            n=self.state()
            if kind=='duplicate-source':n['loadedClasses'][1]=n['loadedClasses'][0]
            elif kind=='unknown-source':n['loadedClasses'][0]['sha256']='0'*64
            elif kind=='nonbool-flag':n['roleFeatureFlags']['saml20.ecp']='false'
            else:n['metadataSources'].append(dict(type='pdo'))
            with self.assertRaises(ValueError):campaign.native_gaps(n)
    def test_new_or_peer_credentials_do_not_become_current_keys_by_label(self):
        n=self.state();n['currentCredentials'].append(dict(prefix='new_',publicCertificatePresent=True))
        n['remotePeers'].append(dict(signatureOverridePresent=True,sharedEncryptionOverridePresent=False))
        self.assertEqual(campaign.native_gaps(n),['additional-current-purpose-unproven:new_','peer-override-current-purpose-unproven'])
    def test_https_role_transport_is_unproven_not_missing_key_failure(self):
        n=self.state();n['publicNativeMetadata']['SingleSignOnService'][0]['Location']='https://localhost/sso'
        self.assertEqual(campaign.native_gaps(n),['endpoint-transport-authentication-scope-unproven'])
    def test_public_projection_privacy_is_recursive(self):
        for key in ('Authorization','Cookie','password','nested.private-key','credentialTokens'):
            with self.assertRaises(ValueError):campaign.reject_sensitive(dict(nested=[{key:'never-export'}]))
        campaign.reject_sensitive(dict(currentCredentials=[dict(privateCredentialPresent=True,nativePrivateCredentialPublicSpkiPem='-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----')]))
        with self.assertRaises(ValueError):campaign.reject_sensitive(dict(value='-----BEGIN RSA PRIVATE KEY-----'))

class MountedConfigurationTest(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(dir='/private/tmp');self.path=pathlib.Path(self.temp.name)/'hosted.php';self.path.write_bytes(b'original public fixture')
        self.mount=dict(Type='bind',Source=str(self.path.resolve()),Destination=campaign.REMOTE,RW=False)
    def tearDown(self):self.temp.cleanup()
    def batch(self,rows=None,hashes=None):
        return campaign.MountedPublisherConfigurationBatch(self.path,lambda:rows or [self.mount],hashes or (lambda:campaign.SHA(self.path.read_bytes())))
    def test_readonly_mount_uses_host_inode_and_restores_exact_bytes(self):
        inode=self.path.stat().st_ino;b=self.batch();b.apply(b'public overlay');self.assertEqual(self.path.stat().st_ino,inode)
        self.assertEqual(b.write_count,1);self.assertTrue(b.restore()['restored']);self.assertEqual(b.write_count,2);self.assertEqual(b.restoration_writes,1)
        self.assertEqual(self.path.read_bytes(),b'original public fixture');self.assertEqual(len(b.native_readbacks),5)
    def test_foreign_mount_source_destination_type_rw_and_duplicate_rejected(self):
        for field,value in [('Type','volume'),('Source','/different/hosted.php'),('Destination','/different/native.php'),('RW',True),('RW','false')]:
            m=self.mount|{field:value}
            with self.assertRaises(ValueError):self.batch([m])
            self.assertEqual(self.path.read_bytes(),b'original public fixture')
        with self.assertRaises(ValueError):self.batch([self.mount,self.mount])
    def test_stale_native_readback_fails_and_host_restoration_remains_possible(self):
        reads=iter([campaign.SHA(self.path.read_bytes()),campaign.SHA(self.path.read_bytes()),'0'*64])
        b=self.batch(hashes=lambda:next(reads))
        with self.assertRaises(ValueError):b.apply(b'public overlay')
        b.hash_reader=lambda:campaign.SHA(self.path.read_bytes())
        self.assertTrue(b.restore()['restored']);self.assertEqual(b.write_count,2)
    def test_known_original_native_stale_allows_exact_owned_host_restoration(self):
        original=campaign.SHA(self.path.read_bytes());b=self.batch(hashes=lambda:original)
        with self.assertRaises(ValueError):b.apply(b'public overlay')
        self.assertTrue(b.restore()['restored']);self.assertEqual(self.path.read_bytes(),b.original)
    def test_unknown_native_bytes_never_authorize_host_restoration(self):
        b=self.batch();b.apply(b'public overlay');configured=self.path.read_bytes();b.hash_reader=lambda:'0'*64
        with self.assertRaises(ValueError):b.restore()
        self.assertEqual(self.path.read_bytes(),configured)
    def test_changed_mount_before_write_is_rejected_without_modifying_host(self):
        b=self.batch();self.mount['Source']='/foreign'
        with self.assertRaises(ValueError):b.apply(b'public overlay')
        self.assertEqual(self.path.read_bytes(),b'original public fixture')

if __name__=='__main__':unittest.main()
