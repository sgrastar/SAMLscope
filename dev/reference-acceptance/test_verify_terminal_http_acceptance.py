import unittest

import verify_terminal_http_acceptance as verifier


class TerminalHttpVerifierTest(unittest.TestCase):
    def entry(self, status=400, url="http://example.test/error", correlation="action_a"):
        return {
            "direction": "INBOUND",
            "method": "BROWSER",
            "status": status,
            "url": url,
            "correlationId": correlation,
            "decodedSamlRef": None,
            "decodedSamlBytes": 0,
            "bodyBytes": 4,
            "samlSummary": {
                "failure_indicated": True,
                "type": "BrowserResponseObservation",
                "http_status": status,
                "url": url,
            },
        }

    def test_effective_default_port_is_same_origin(self):
        self.assertEqual(verifier.origin("http://example.test/path"),
                         verifier.origin("http://EXAMPLE.test:80/other"))
        self.assertEqual(verifier.origin("https://example.test/path"),
                         verifier.origin("https://example.test:443/other"))

    def test_browser_accepts_only_same_origin_400_through_599(self):
        for status in (400, 500, 599):
            entry = self.entry(status)
            self.assertEqual("browser", verifier._verify_browser(
                entry, b"body", "action_a", "http://example.test/sso"))
        for status in (399, 600, 999):
            with self.assertRaises(ValueError):
                verifier._verify_browser(
                    self.entry(status), b"body", "action_a", "http://example.test/sso")

    def test_browser_rejects_cross_origin_and_wrong_action(self):
        with self.assertRaises(ValueError):
            verifier._verify_browser(self.entry(url="https://example.test/error"), b"body",
                                     "action_a", "http://example.test/sso")
        with self.assertRaises(ValueError):
            verifier._verify_browser(self.entry(url="http://example.test:81/error"), b"body",
                                     "action_a", "http://example.test/sso")
        with self.assertRaises(ValueError):
            verifier._verify_browser(self.entry(correlation="action_old"), b"body",
                                     "action_a", "http://example.test/sso")

    def test_terminal_semantics_match_the_three_approved_cases(self):
        self.assertEqual("satisfied", verifier._observation(
            "IIP-SSO01-em-idp-01", "version-1-1", "browser"))
        self.assertEqual("violated", verifier._observation(
            "IIP-SSO01-ak-idp-01", "bad-signature-value", "browser"))
        self.assertEqual("violated", verifier._observation(
            "IIP-SSO01-d-idp-01", "unrecognized-subject", "browser"))
        self.assertEqual("control_failed", verifier._observation(
            "IIP-SSO01-em-idp-01", "baseline-success", "browser"))

    def test_response_controls_and_negative_paths(self):
        self.assertEqual("satisfied", verifier._observation(
            "IIP-SSO01-ak-idp-01", "valid", "response", (True, True)))
        self.assertEqual("control_failed", verifier._observation(
            "IIP-SSO01-ak-idp-01", "valid", "response", (False, False)))
        self.assertEqual("violated", verifier._observation(
            "IIP-SSO01-ak-idp-01", "tampered-acs", "response", (True, True)))
        self.assertEqual("satisfied", verifier._observation(
            "IIP-SSO01-ak-idp-01", "bad-reference", "response", (False, False)))
        self.assertEqual("violated", verifier._observation(
            "IIP-SSO01-d-idp-01", "unrecognized-subject", "response", (True, False)))
        self.assertEqual("violated", verifier._observation(
            "IIP-SSO01-d-idp-01", "unrecognized-subject", "response", (True, True)))
        self.assertEqual("satisfied", verifier._observation(
            "IIP-SSO01-d-idp-01", "unrecognized-subject", "response", (False, False)))
        self.assertEqual("violated", verifier._observation(
            "IIP-SSO01-d-idp-01", "unrecognized-subject", "response", (False, True)))


if __name__ == "__main__":
    unittest.main()
