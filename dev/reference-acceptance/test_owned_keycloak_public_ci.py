"""Pure ownership, retention and command guards. Never contacts any product."""
import importlib.util, pathlib, tempfile, unittest
from unittest.mock import patch
P=pathlib.Path(__file__).with_name('owned_keycloak_public_ci.py')
SPEC=importlib.util.spec_from_file_location('owned_keycloak_public_ci',P)
M=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(M)

class Guards(unittest.TestCase):
    def inspect_fake(self,changes=None):
        identifier='a'*64;image='sha256:'+'b'*64
        facts={'.Id':identifier,'.Name':'/'+M.name('owned'),'.Image':image,'.Config.Labels':M.labels('owned'),'.NetworkSettings.Ports':{'8080/tcp':[{'HostIp':'127.0.0.1','HostPort':'28080'}]},
               '.State.StartedAt':'2026-10-08T00:00:00Z','.State.Running':False,'.Mounts':[{'Type':'bind','Source':str(M.ROOT/M.SEED),'Destination':'/opt/keycloak/data/import/realm-samlscope.json','RW':False}],'.HostConfig.Tmpfs':{'/opt/keycloak/data':'rw','/tmp':'rw'}}
        facts.update(changes or {})
        def controlled(args,env=None):
            field=next(a for a in args if a.startswith('{{json '))[7:-2]
            value=([M.IMAGE] if field=='.RepoDigests' else image if field=='.Id' else facts[field]) if args[0]=='image' else facts[field]
            return M.json.dumps(value).encode()
        return controlled

    def test_stopped_owned_container_remains_cleanable_but_not_usable(self):
        with patch.object(M,'docker',side_effect=self.inspect_fake()):
            with self.assertRaises(ValueError):M.inspect_owned('owned','a'*64)
            self.assertFalse(M.inspect_owned('owned','a'*64,require_running=False)['running'])

    def test_spoofed_image_mount_labels_and_extra_ports_fail_closed(self):
        for changes in [{'.Image':'sha256:'+'c'*64},{'.Config.Labels':{M.LABEL:'foreign'}},{'.Mounts':[{'Type':'volume','Destination':'/opt/keycloak/data'}]},
                        {'.NetworkSettings.Ports':{'8080/tcp':[{'HostIp':'127.0.0.1','HostPort':'28080'}],'9000/tcp':[{'HostIp':'0.0.0.0','HostPort':'29000'}]}}]:
            with patch.object(M,'docker',side_effect=self.inspect_fake(changes)):
                with self.assertRaises(ValueError):M.inspect_owned('owned','a'*64,require_running=False)

    def test_only_fixed_public_seed_and_image_feed_start_command(self):
        facts=M.source_seed();self.assertEqual(facts,{'sha256':M.SEED_SHA,'gitBlob':M.SEED_BLOB})
        args=M.run_args('20261008-nameid-r1');self.assertIn(M.IMAGE,args);self.assertIn('127.0.0.1:28080:8080',args)
        self.assertEqual(args.count('--mount'),1);self.assertIn('readonly',args[args.index('--mount')+1]);self.assertEqual(args.count('--tmpfs'),2)
        self.assertIn('--pull=never',args);self.assertIn('none',args);self.assertNotIn('--privileged',args)
        self.assertTrue(all('KC_BOOTSTRAP_ADMIN_PASSWORD=' not in a for a in args))

    def test_generation_cannot_escape_into_command_or_other_container(self):
        for value in ['', '../reference', 'fixture;rm', '$(secret)', '-reference','UPPER', 'x'*37]:
            with self.assertRaises(ValueError): M.run_args(value)
        self.assertEqual(M.labels('safe')['com.samlscope.owned.acceptance'],'keycloak-public-ci-nameid-v2')

    def test_process_env_does_not_clone_reference_credentials(self):
        with patch.dict(M.os.environ,{'REFERENCE_NATIVE_SECRET':'do-not-forward'}):
            environment=M.bootstrap_environment()
            self.assertEqual(set(environment),{'PATH','KC_BOOTSTRAP_ADMIN_USERNAME','KC_BOOTSTRAP_ADMIN_PASSWORD'})
            self.assertNotIn('REFERENCE_NATIVE_SECRET',environment)

    def test_public_projection_closes_nested_or_case_varied_secrets(self):
        self.assertEqual(M.public({'readbackStatus':404,'credentialValuesExported':False}),{'readbackStatus':404,'credentialValuesExported':False})
        for key in ['Authorization','cOoKiE','access_token','client-secret','private_key','managementUrl','secret']:
            with self.assertRaises(ValueError):M.public({'nested':[{key:'unexportable'}]})

    def test_native_client_conversion_is_bound_to_saml_and_suite_entity(self):
        issuer=M.SUITE+'/p/plan_0123456789ABCDEFGHJKMNPQRS'
        source={'clientId':issuer,'protocol':'saml','attributes':{'saml.signing.certificate':'public-placeholder'}}
        client=M.native_client(source,issuer,'owned')
        self.assertEqual(client['attributes']['saml_force_name_id_format'],'false');self.assertEqual(source['attributes'],{'saml.signing.certificate':'public-placeholder'})
        self.assertTrue(all(client['attributes'][k]==v for k,v in M.ATTRIBUTES.items()))
        for wrong in [{'clientId':'other','protocol':'saml'},{'clientId':issuer,'protocol':'openid-connect'}]:
            with self.assertRaises(ValueError):M.native_client(wrong,issuer,'owned')

    def test_private_client_representation_is_not_exported(self):
        client={'id':'own-db-id','clientId':'public-issuer','protocol':'saml','name':'Owned','secret':'do-not-export','attributes':{'saml.signing.private.key':'do-not-export',**M.ATTRIBUTES}}
        result=M.client_projection(client);M.public(result)
        self.assertNotIn('secret',result);self.assertNotIn('saml.signing.private.key',result['attributes']);self.assertNotIn('do-not-export',str(result))

    def test_unowned_url_or_admin_authority_never_reaches_network(self):
        with patch.object(M.urllib.request,'build_opener',side_effect=AssertionError('Network reached')):
            for url in ['http://reference:28080/','http://localhost:28081/','http://localhost:28080@foreign/','https://localhost:28080/','http://localhost:28080/#foreign']:
                with self.assertRaises(ValueError):M.request(url)
            with self.assertRaises(ValueError):M.request(M.SUITE+'/api/plans',token='RAM-only-placeholder')
            with self.assertRaises(ValueError):M.request(M.ORIGIN+'/realms/samlscope',token='RAM-only-placeholder')

    def test_wrong_container_id_fails_before_docker(self):
        with patch.object(M,'docker',side_effect=AssertionError('Docker reached')):
            for value in ['', 'short', 'a'*63, 'b'*64+';foreign']:
                with self.assertRaises(ValueError):M.inspect_owned('owned',value)

    def test_wx_evidence_cannot_replace_prior_attempt(self):
        with tempfile.TemporaryDirectory() as directory:
            path=pathlib.Path(directory);M.write(path,'attempt.json',{'status':'public'})
            with self.assertRaises(FileExistsError):M.write(path,'attempt.json',{'status':'changed'})
            self.assertIn('public',(path/'attempt.json').read_text())

    def test_failed_start_removes_only_newly_created_id_and_records_attempt(self):
        identifier='a'*64;calls=[]
        def controlled(args,env=None):
            calls.append(args);return identifier.encode() if args[0]=='run' else b''
        with tempfile.TemporaryDirectory() as directory,patch.object(M,'docker',side_effect=controlled),patch.object(M,'inspect_owned',side_effect=ValueError('Ownership validation failed')):
            with self.assertRaises(ValueError):M.start('owned',pathlib.Path(directory))
            self.assertEqual(calls[-1],['rm','--force',identifier])
            facts=M.json.loads((pathlib.Path(directory)/'start-operation-counts.json').read_text())
            self.assertEqual(facts['failedStartCleanups'],1);self.assertEqual(facts['containersCreated'],1)

    def test_restore_never_deletes_foreign_native_client(self):
        document={'generation':'owned','ownedContainerId':'a'*64,'clientDbId':'a'*8+'-'+('b'*4+'-')*3+'c'*12,'planId':'plan_0123456789ABCDEFGHJKMNPQRS'}
        calls=[]
        def controlled(url,method='GET',**kwargs):calls.append(method);return 200,b'{"clientId":"foreign","name":"foreign","attributes":{}}',{}
        with tempfile.TemporaryDirectory() as directory,patch.object(M,'inspect_owned',return_value={}),patch.object(M,'admin_token',return_value='RAM-only-placeholder'),patch.object(M,'request',side_effect=controlled):
            with self.assertRaises(ValueError):M.restore(document,pathlib.Path(directory))
            self.assertEqual(calls,['GET'])

    def test_failed_native_readback_restores_created_client_before_any_run(self):
        plan_id='plan_0123456789ABCDEFGHJKMNPQRS';dbid='aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee';issuer=M.SUITE+'/p/'+plan_id;calls=[];readbacks=0
        identity={'profile':'browser_sso_idp','version':'functional-case-v2-nameid','digest':'sha256:05558838bf997f81d5be63d423df254b547ffe7c0600683157b6dadd566b7448'}
        def controlled(url,method='GET',body=None,token=None,content_type=None,statuses=(200,)):
            nonlocal readbacks
            calls.append((url,method))
            if url==M.SUITE+'/api/plans':return 200,M.json.dumps({'plan':{'plan':{'id':plan_id,'definitionIdentity':identity}}}).encode(),{}
            if url==issuer+'/metadata':return 200,b'<public-metadata/>',{}
            if url.endswith('/client-description-converter'):return 200,M.json.dumps({'clientId':issuer,'protocol':'saml'}).encode(),{}
            if url.endswith('/clients') and method=='POST':return 201,b'',{'Location':M.ORIGIN+'/admin/realms/samlscope/clients/'+dbid}
            if url.endswith('/'+dbid):
                if method=='DELETE':return 204,b'',{}
                readbacks+=1
                if readbacks==3:return 404,b'',{}
                value={'id':dbid,'clientId':issuer,'name':'SAMLscope Owned CI NameID owned','attributes':{'samlscope.owned.generation':'owned'}}
                return 200,M.json.dumps(value).encode(),{}
            raise AssertionError('Unexpected operation')
        with tempfile.TemporaryDirectory() as directory,patch.object(M,'inspect_owned',return_value={}),patch.object(M,'admin_token',return_value='RAM-only-placeholder'),patch.object(M,'client_state',return_value='f'*64),patch.object(M,'request',side_effect=controlled):
            output=pathlib.Path(directory)
            with self.assertRaises(ValueError):M.setup('owned','a'*64,output)
            self.assertEqual(sum(method=='DELETE' for _,method in calls),1);self.assertFalse(any('/runs' in url for url,_ in calls))
            self.assertTrue(M.json.loads((output/'failed-setup-restoration.json').read_text())['restored'])
            self.assertEqual(M.json.loads((output/'setup-operation-counts.json').read_text())['failedSetupRestorations'],1)

if __name__=='__main__':unittest.main()
