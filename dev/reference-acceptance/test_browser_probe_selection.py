"""HTTP tests protecting the prepare-only optimization from target submissions."""
import contextlib
import http.server
import threading
import unittest
import urllib.error

from browser_probe_selection import prepare_and_skip, selected_cases


CASE = 'IIP-SSO05-a3-idp-01'


@contextlib.contextmanager
def server(reply):
    requests = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            body = self.rfile.read(int(self.headers.get('Content-Length', '0')))
            requests.append((self.command, self.path, body))
            reply(self)

        def do_GET(self):
            requests.append((self.command, self.path, b''))
            reply(self)

        def log_message(self, *_):
            pass

    instance = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    worker = threading.Thread(target=instance.serve_forever, kwargs={'poll_interval': .02}, daemon=True)
    worker.start()
    try:
        yield 'http://127.0.0.1:' + str(instance.server_port), requests
    finally:
        instance.shutdown()
        instance.server_close()
        worker.join(timeout=2)


def reply(code=200, location=None, body=b'fixture'):
    def send(handler):
        handler.send_response(code)
        if location is not None:
            handler.send_header('Location', location)
        handler.end_headers()
        handler.wfile.write(body)
    return send


class SelectionTest(unittest.TestCase):
    def api(self, calls, **change):
        def request(path, *body):
            calls.append((path, body))
            if not body:
                return dict(state='AWAITING_RESPONSE', caseId=CASE, actionId='action-1', **change)
            return {'state': 'READY'}
        return request

    def status(self, base):
        return dict(state='READY', caseId=CASE, actionId='action-1',
                    startUrl=base + '/p/plan-1/probe/action-1?run=run-1')

    def test_each_redirect_stops_before_target(self):
        with server(reply()) as (target, target_requests):
            for code in [301, 302, 303, 307, 308]:
                with self.subTest(code=code), server(reply(code, target + '/saml')) as (suite, suite_requests):
                    calls = []
                    result = prepare_and_skip(suite, 'run-1', self.status(suite), self.api(calls))
                    self.assertFalse(result['sentToTarget'])
                    self.assertEqual(code, result['preparedHttpStatus'])
                    self.assertEqual([('POST', '/p/plan-1/probe/action-1?run=run-1',
                                       b'freshSessionConfirmed=true')], suite_requests)
                    self.assertEqual(['/api/runs/run-1/active-probe', '/api/runs/run-1/active-probe/abort'],
                                     [path for path, _ in calls])
            self.assertEqual([], target_requests)

    def test_html_form_and_script_do_not_submit(self):
        with server(reply()) as (target, target_requests):
            html = ('<form action="' + target + '/saml"><input name="SAMLRequest"></form>'
                    '<script>document.forms[0].submit()</script>').encode()
            with server(reply(body=html)) as (suite, _):
                result = prepare_and_skip(suite, 'run-1', self.status(suite), self.api([]))
                self.assertFalse(result['sentToTarget'])
            self.assertEqual([], target_requests)

    def test_foreign_origin_rejected_before_get_or_abort(self):
        with server(reply()) as (target, requests):
            calls = []
            with self.assertRaises(ValueError):
                prepare_and_skip('http://127.0.0.1:1', 'run-1', self.status(target), self.api(calls))
            self.assertEqual([], requests)
            self.assertEqual([], calls)

    def test_server_failure_never_aborts(self):
        with server(reply(code=500)) as (suite, _):
            calls = []
            with self.assertRaises(urllib.error.HTTPError):
                prepare_and_skip(suite, 'run-1', self.status(suite), self.api(calls))
            self.assertEqual([], calls)

    def test_changed_action_or_case_never_aborts(self):
        for field, value in [('actionId', 'other-action'), ('caseId', 'other-case'), ('state', 'READY')]:
            with self.subTest(field=field), server(reply()) as (suite, _):
                calls = []

                def changed(path, *body):
                    calls.append((path, body))
                    return {**dict(state='AWAITING_RESPONSE', caseId=CASE, actionId='action-1'), field: value}

                with self.assertRaises(RuntimeError):
                    prepare_and_skip(suite, 'run-1', self.status(suite), changed)
                self.assertEqual(['/api/runs/run-1/active-probe'], [path for path, _ in calls])

    def test_invalid_selection_fails_before_configuration(self):
        self.assertIsNone(selected_cases(None))
        self.assertEqual({CASE}, selected_cases(CASE + ', ' + CASE))
        for value in ['', CASE + ',', 'unknown', CASE + ',../other']:
            with self.subTest(value=value), self.assertRaises(ValueError):
                selected_cases(value)


if __name__ == '__main__':
    unittest.main()
