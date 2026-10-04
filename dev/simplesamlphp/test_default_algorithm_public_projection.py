#!/usr/bin/env python3
"""Execute public projections with synthetic configuration; never load product files."""
import argparse
import json
from pathlib import Path
import shutil
import subprocess
import unittest

PHP_COMMAND = None
SOURCE = Path(__file__).with_name('default_algorithm_scope.php')

class PublicProjectionTest(unittest.TestCase):
    def run_php(self, body):
        prefix = SOURCE.read_text().split('// Native collection starts here.', 1)[0]
        result = subprocess.run(PHP_COMMAND, input=(prefix + body).encode(), capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        return json.loads(result.stdout)

    def test_credentials_and_unknown_nested_settings_never_leave_projection(self):
        row = self.run_php('''
$secret='SYNTHETIC_CREDENTIAL_SENTINEL';
$public=samlscope_public_peer_metadata(['entityid'=>'urn:test:sp','validate.authnrequest'=>false,
 'password'=>$secret,'sharedkey'=>$secret,'privatekey'=>$secret,'authproc'=>[['password'=>$secret]],
 'AssertionConsumerService'=>[['Binding'=>'urn:test:binding','Location'=>'https://example.test/acs','password'=>$secret]]]);
echo json_encode($public,JSON_THROW_ON_ERROR);
''')
        self.assertEqual(row, {'entityid': 'urn:test:sp', 'validate.authnrequest': False,
                              'AssertionConsumerService': [{'Binding': 'urn:test:binding', 'Location': 'https://example.test/acs'}]})
        self.assertNotIn('SYNTHETIC_CREDENTIAL_SENTINEL', json.dumps(row))

    def test_metadata_sources_publish_only_known_types(self):
        row = self.run_php('''
$secret='SYNTHETIC_SOURCE_PASSWORD';
echo json_encode(samlscope_public_metadata_sources([['type'=>'flatfile','password'=>$secret],
 ['type'=>'pdo','dsn'=>$secret,'username'=>$secret]]),JSON_THROW_ON_ERROR);
''')
        self.assertEqual(row, [{'type': 'flatfile'}, {'type': 'pdo'}])

    def test_native_dedicated_factory_public_fields_remain_exact(self):
        row = self.run_php('''
echo json_encode(samlscope_public_peer_metadata(['contacts'=>[],'expire'=>1791200000,
 'saml20.sign.assertion'=>true]),JSON_THROW_ON_ERROR);
''')
        self.assertEqual(row, {'contacts': [], 'expire': 1791200000, 'saml20.sign.assertion': True})

    def test_malformed_public_values_and_private_key_forms_fail_closed(self):
        row = self.run_php('''
$rejected=[];
foreach ([['validate.authnrequest'=>'SYNTHETIC_SECRET'],['keys'=>[['type'=>'privatekey','PEM'=>'SYNTHETIC_SECRET']]],
 ['AssertionConsumerService'=>[['Location'=>['password'=>'SYNTHETIC_SECRET']]]]] as $value) {
 try {samlscope_public_peer_metadata($value);$rejected[]=false;} catch (Throwable $e) {$rejected[]=true;}
}
try {samlscope_public_metadata_sources([['type'=>'SYNTHETIC_SECRET']]);$rejected[]=false;}
catch (Throwable $e) {$rejected[]=true;}
echo json_encode($rejected,JSON_THROW_ON_ERROR);
''')
        self.assertEqual(row, [True, True, True, True])

    def test_public_certificate_and_key_uses_remain_intact(self):
        row = self.run_php('''
$key=openssl_pkey_new(['private_key_bits'=>2048,'private_key_type'=>OPENSSL_KEYTYPE_RSA]);
$csr=openssl_csr_new(['commonName'=>'synthetic-projection-test'],$key);
$certificate=openssl_csr_sign($csr,null,$key,1);openssl_x509_export($certificate,$pem);
$der=preg_replace('/-----[^-]+-----|\\s/','',$pem);
$public=samlscope_public_peer_metadata(['keys'=>[['type'=>'X509Certificate','X509Certificate'=>$der,
 'signing'=>true,'encryption'=>false,'privatekey'=>'SYNTHETIC_KEY_SENTINEL']]]);
echo json_encode(['certificateUnchanged'=>$public['keys'][0]['X509Certificate']===$der,
 'keys'=>$public['keys']],JSON_THROW_ON_ERROR);
''')
        self.assertTrue(row['certificateUnchanged'])
        self.assertEqual(set(row['keys'][0]), {'type', 'X509Certificate', 'signing', 'encryption'})
        self.assertNotIn('SYNTHETIC_KEY_SENTINEL', json.dumps(row))

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--php-container', help='Existing container used only as a PHP interpreter; no native files are loaded')
    args, remaining = parser.parse_known_args()
    if args.php_container:
        PHP_COMMAND = ['docker', 'exec', '-i', args.php_container, 'php']
    elif shutil.which('php'):
        PHP_COMMAND = ['php']
    else:
        raise SystemExit('PHP interpreter unavailable; projection tests were not executed')
    unittest.main(argv=[__file__] + remaining)
