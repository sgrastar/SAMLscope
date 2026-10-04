"""Real two-origin HTTP checks for correlation and pre-persistence credential removal."""
import base64
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import sys
import tempfile
import threading
import unittest
import urllib.parse
import zlib

REPO=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(REPO/'dev/keycloak'))
sys.path.insert(0,str(Path(__file__).resolve().parent))
import authentication_challenge_capture as capture


class ChallengeCaptureTest(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory()
        self.output=Path(self.temporary.name)/'challenge'
        self.native_requests=[];self.password='memory-only-password';self.token='memory-only-token'
        self.populated=False
        owner=self
        class Native(BaseHTTPRequestHandler):
            def log_message(self,*args):pass
            def do_GET(self):
                owner.native_requests.append(('GET',self.path))
                action='/idp/profile/SAML2/Redirect/SSO?execution=e1s1'
                password=' value="'+owner.password+'"' if owner.populated else ''
                body=('<form method="post" action="'+action+'">'
                      '<input name="j_username" value="">'
                      '<input'+password+' type="password" name="j_password">'
                      '<input value="'+owner.token+'" name="csrf_token" type="hidden">'
                      '<input type=hidden name=token value='+owner.token+'></form>').encode()
                self.send_response(200);self.end_headers();self.wfile.write(body)
            def do_POST(self):
                # The server sees actual credentials; neither response nor capture logs them.
                owner.native_requests.append(('POST',self.path))
                length=int(self.headers['Content-Length']);data=self.rfile.read(length)
                owner.submitted=urllib.parse.parse_qs(data.decode())
                self.send_response(200);self.end_headers();self.wfile.write(b'authenticated')
        self.native=ThreadingHTTPServer(('127.0.0.1',0),Native)
        self.native_url='http://localhost:'+str(self.native.server_port)
        self.previous_target=capture.TARGET;capture.TARGET='localhost:'+str(self.native.server_port)
        raw=b'<p:AuthnRequest xmlns:p="urn:oasis:names:tc:SAML:2.0:protocol" ID="_native-request"/>'
        compressor=zlib.compressobj(wbits=-15);encoded=base64.b64encode(compressor.compress(raw)+compressor.flush()).decode()
        self.request_raw=raw
        self.redirect=self.native_url+'/idp/profile/SAML2/Redirect/SSO?'+urllib.parse.urlencode({'SAMLRequest':encoded,'SigAlg':'urn:example','Signature':'test'})
        class Suite(BaseHTTPRequestHandler):
            def log_message(self,*args):pass
            def do_GET(self):
                self.send_response(302);self.send_header('Location',owner.redirect);self.end_headers()
        self.suite=ThreadingHTTPServer(('127.0.0.1',0),Suite)
        self.suite_url='http://localhost:'+str(self.suite.server_port)
        self.threads=[threading.Thread(target=server.serve_forever,daemon=True) for server in (self.native,self.suite)]
        for thread in self.threads:thread.start()

    def tearDown(self):
        capture.TARGET=self.previous_target
        for server in (self.native,self.suite):server.shutdown();server.server_close()
        for thread in self.threads:thread.join()
        self.temporary.cleanup()

    def test_observed_request_challenge_and_submission_never_persist_credentials(self):
        client=capture.ChallengeClient(self.output)
        client.request(self.suite_url)
        client.request(self.native_url+'/idp/profile/SAML2/Redirect/SSO?execution=e1s1',
            {'j_username':'memory-only-user','j_password':self.password,'csrf_token':self.token})
        client.finish()
        report=json.loads((self.output/'native-challenge.json').read_text())
        self.assertEqual(report['request']['requestId'],'_native-request')
        self.assertEqual(report['request']['requestSha256'],capture.SHA(self.request_raw))
        self.assertEqual(len(report['credentialSubmissions']),1)
        self.assertEqual(self.submitted['j_password'],[self.password])
        stored=b''.join(path.read_bytes() for path in self.output.iterdir())
        for secret in (self.password,self.token,'memory-only-user'):
            self.assertNotIn(secret.encode(),stored)
        self.assertIn(b'[REDACTED]',stored)

    def test_challenge_without_observed_saml_request_is_not_persisted(self):
        client=capture.ChallengeClient(self.output)
        with self.assertRaisesRegex(ValueError,'no observed SAML request'):
            client.request(self.native_url+'/idp/profile/SAML2/Redirect/SSO?execution=e1s1')
        self.assertEqual(list(self.output.iterdir()),[])

    def test_populated_login_input_is_rejected_before_persistence_regardless_of_attribute_order(self):
        self.populated=True;client=capture.ChallengeClient(self.output)
        with self.assertRaisesRegex(ValueError,'populated login input'):
            client.request(self.suite_url)
        self.assertEqual(list(self.output.iterdir()),[])


if __name__=='__main__':unittest.main()
