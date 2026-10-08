import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

PATH=Path(__file__).with_name('verify_simplesamlphp_multiple_decryption_keys_source_run_acceptance.py')
spec=importlib.util.spec_from_file_location('archived_native_source_acceptance',PATH)
MODULE=importlib.util.module_from_spec(spec);spec.loader.exec_module(MODULE)


class ArchivedStateContractTest(unittest.TestCase):
    def setUp(self):
        self.root='/tmp/ssp-config-source-archive-state-'+'a'*24
        self.pins={'archiveSha256':{n+'-0.1.0.jar':format(i+1,'064x') for i,n in enumerate(MODULE.MODULES)}}
        self.state={'schema':'samlscope-independent-configuration-source-state-v1','sourceRunId':'source',
            'recipientRunId':'recipient','fence':{'sourceHistory':'original','recipientOtherExecutions':'original'},
            'sourceExecutions':{},'executions':{MODULE.CASE:'original','other':'unchanged'},
            'caseExecution':{'runId':'recipient','caseId':MODULE.CASE,'revision':1,'outcome':{'outcome':'SATISFIED'},
                'state':{'phase':'await-configuration'},'waitCondition':None},'verdict':'PASS',
            'caseDocumentSha256':'original','caseStateSha256':'original','caseWaitSha256':'original','caseUpdatedAt':'original'}
        self.original=dict(self.state,actualModuleCodeSources={n:dict(path='/opt/samlscope/lib/'+n+'-0.1.0.jar',
            sha256=self.pins['archiveSha256'][n+'-0.1.0.jar'],**{'class':MODULE.MODULE_CLASSES[n]}) for n in MODULE.MODULES})
        self.report={'schema':'samlscope-archived-native-configuration-state-v1',
            'authority':'qualified-historical-project-archive','installedRuntimeClaimed':False,'targetOperations':0,
            'storedState':copy.deepcopy(self.state),'archivedModuleCodeSources':{n:dict(path=self.root+'/'+n+'-0.1.0.jar',
            sha256=self.pins['archiveSha256'][n+'-0.1.0.jar'],**{'class':MODULE.MODULE_CLASSES[n]}) for n in MODULE.MODULES}}
    def verify(self,report=None,original=None,root=None):
        return MODULE.archived_state_payload(report or self.report,original or self.original,self.pins,root or self.root)
    def test_distinct_archived_authority_and_unchanged_actual_state_are_accepted(self):
        old=copy.deepcopy(self.original)
        self.assertEqual(self.verify(),self.state)
        self.assertEqual(self.original,old)
        self.assertNotEqual(self.report['archivedModuleCodeSources'],self.original['actualModuleCodeSources'])
    def test_archived_authority_cannot_claim_installed_runtime_or_target_operations(self):
        for key,value in [('schema','foreign'),('authority','installed'),('installedRuntimeClaimed',True),('targetOperations',1)]:
            with self.subTest(key=key):
                report=copy.deepcopy(self.report);report[key]=value
                with self.assertRaises(ValueError):self.verify(report)
    def test_origin_module_set_path_class_and_byte_pins_are_mandatory(self):
        for name in ['missing','extra','path','class','sha256']:
            with self.subTest(name=name):
                report=copy.deepcopy(self.report);origins=report['archivedModuleCodeSources']
                if name=='missing':origins.pop('api')
                elif name=='extra':origins['other']=origins['api']
                else:origins['api'][name]='foreign'
                with self.assertRaises(ValueError):self.verify(report)
    def test_old_installed_origins_are_verified_instead_of_relabelled(self):
        for name in ['missing','path','class','sha256']:
            with self.subTest(name=name):
                original=copy.deepcopy(self.original)
                if name=='missing':original['actualModuleCodeSources'].pop('api')
                else:original['actualModuleCodeSources']['api'][name]='foreign'
                with self.assertRaises(ValueError):self.verify(original=original)
    def test_every_actual_stored_state_field_must_equal_the_sealed_state(self):
        changes={
            'foreign-run':lambda s:s.update(recipientRunId='foreign'),
            'foreign-source':lambda s:s.update(sourceRunId='foreign'),
            'history':lambda s:s['fence'].update(sourceHistory='changed'),
            'other-case':lambda s:s['executions'].update(other='changed'),
            'new-source-case':lambda s:s['sourceExecutions'].update(fake='inserted'),
            'outcome':lambda s:s['caseExecution']['outcome'].update(outcome='NOT_VERIFIED'),
            'revision':lambda s:s['caseExecution'].update(revision=2),
            'state':lambda s:s['caseExecution']['state'].update(phase='changed'),
            'wait':lambda s:s['caseExecution'].update(waitCondition={'kind':'CONFIG'}),
            'document':lambda s:s.update(caseDocumentSha256='changed'),
            'verdict':lambda s:s.update(verdict='FAIL'),
        }
        for name,change in changes.items():
            with self.subTest(name=name):
                report=copy.deepcopy(self.report);change(report['storedState'])
                with self.assertRaises(ValueError):self.verify(report)
    def test_missing_extra_or_installed_origin_fields_are_not_silently_discarded(self):
        for mode in ['missing','extra','installed-origins']:
            with self.subTest(mode=mode):
                report=copy.deepcopy(self.report)
                if mode=='missing':report['storedState'].pop('caseExecution')
                elif mode=='extra':report['storedState']['fake']='added'
                else:report['storedState']['actualModuleCodeSources']=self.original['actualModuleCodeSources']
                with self.assertRaises(ValueError):self.verify(report)
    def test_archive_root_cannot_escape_or_alias_installed_paths(self):
        for root in ['/opt/samlscope/lib','/tmp/ssp-config-source-archive-state-'+('a'*23),self.root+'/../other',
                     '/tmp/ssp-config-source-archive-state-'+('g'*24)]:
            with self.subTest(root=root):
                with self.assertRaises(ValueError):self.verify(root=root)
    def test_compiler_output_inventory_preserves_paths_and_rejects_links(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);(root/'package').mkdir();p=root/'package/helper.class';p.write_bytes(b'class')
            self.assertEqual(set(MODULE.files_unowned(root)),{'package/helper.class'})
            (root/'bad.class').symlink_to(p)
            with self.assertRaises(ValueError):MODULE.files_unowned(root)
    def test_real_sealed_six_origin_records_match_the_pinned_historical_archive(self):
        folder=MODULE.REPO/'build/acceptance/reference-20261008/ssp-configuration-source-run-r1/adoption'
        selected,pins=MODULE.reader(folder)
        for name in ['state-before.json','state-final.json','state-transition.json','actual-registry-final.json']:
            original=MODULE.READ(folder/name)
            payload=MODULE.historical_state_payload(original,pins)
            self.assertNotIn('actualModuleCodeSources',payload)
            self.assertEqual(original,MODULE.READ(folder/name))


if __name__=='__main__':unittest.main()
