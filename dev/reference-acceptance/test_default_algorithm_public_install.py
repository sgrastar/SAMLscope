"""Host-only tests for bound SDK auxiliary installation; no Docker or target calls."""
import copy
import json
import pathlib
import tempfile
import unittest

import verify_shibboleth_default_algorithm_acceptance as adoption


class PublicInstallTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="default-public-install-test-")
        self.receipt = pathlib.Path(self.temporary.name).resolve()
        self.run = "run_00000000000000000000000000"
        self.manifest = {"runId": self.run, "counterfactualCalibrationOnly": False,
                         "files": {}, "observations": [{"fixtureId": "rsa-md5"}]}
        self.use = {"auditMode": "pre-audit-decoder-rejection", "diagnosticOnly": False,
                    "counterfactualCalibrationOnly": False,
                    "unmarshallerInvocationFile": "stock-unmarshaller-invocation.json"}
        self.call = {"schema": "samlscope-shibboleth-stock-unmarshaller-invocation-v1",
                     "runId": self.run, "exitCode": 0,
                     "stderrFile": "stock-unmarshaller.stderr",
                     "stderrSha256": adoption.SHA(b""),
                     "compileInvocationFile": "stock-unmarshaller-compile-invocation.json"}
        self.compiled = {"exitCode": 0, "stdoutSha256": adoption.SHA(b""),
                         "stderrSha256": adoption.SHA(b"")}
        self.write_json("rsa-md5-native-use.json", self.use)
        self.write_json("stock-unmarshaller-invocation.json", self.call)
        self.write_json("stock-unmarshaller-compile-invocation.json", self.compiled)
        for name in ["stock-unmarshaller.stderr", "stock-unmarshaller-compile.stdout",
                     "stock-unmarshaller-compile.stderr"]:
            (self.receipt / name).write_bytes(b"")
        self.write_manifest()

    def tearDown(self):
        self.temporary.cleanup()

    def write_json(self, name, value):
        raw = (json.dumps(value, sort_keys=True) + "\n").encode()
        (self.receipt / name).write_bytes(raw)
        self.manifest["files"][name] = adoption.SHA(raw)

    def write_manifest(self):
        (self.receipt / "manifest.json").write_text(json.dumps(self.manifest), encoding="utf-8")

    def assets(self):
        self.write_manifest()
        return adoption.public_install_assets(self.receipt, self.manifest)

    def test_bound_actual_empty_auxiliaries_are_copied_without_changing_manifest(self):
        before = copy.deepcopy(self.manifest)
        assets = self.assets()
        self.assertEqual(before, self.manifest)
        self.assertEqual(3, sum(raw == b"" for raw in assets.values()))
        self.assertEqual(adoption.SHA(b""), adoption.SHA(assets["stock-unmarshaller.stderr"]))
        self.assertNotIn("stock-unmarshaller.stderr", self.manifest["files"])

    def test_unlisted_nonempty_file_cannot_replace_empty_auxiliary(self):
        (self.receipt / "stock-unmarshaller.stderr").write_bytes(b"unexpected native error")
        with self.assertRaisesRegex(ValueError, "bound empty original"):
            self.assets()

    def test_missing_empty_original_cannot_be_reconstructed_from_empty_hash(self):
        (self.receipt / "stock-unmarshaller-compile.stdout").unlink()
        with self.assertRaisesRegex(ValueError, "Missing"):
            self.assets()

    def test_false_empty_digest_is_rejected(self):
        self.compiled["stderrSha256"] = "0" * 64
        self.write_json("stock-unmarshaller-compile-invocation.json", self.compiled)
        with self.assertRaisesRegex(ValueError, "bound empty original"):
            self.assets()

    def test_foreign_run_or_unknown_stderr_path_is_rejected(self):
        for key, value in [("runId", "run_11111111111111111111111111"),
                           ("stderrFile", "other-empty.stderr")]:
            with self.subTest(key=key):
                altered = dict(self.call, **{key: value})
                self.write_json("stock-unmarshaller-invocation.json", altered)
                with self.assertRaisesRegex(ValueError, "Invalid SDK"):
                    self.assets()

    def test_symlink_auxiliary_is_rejected(self):
        path = self.receipt / "stock-unmarshaller.stderr"
        path.unlink()
        elsewhere = self.receipt / "elsewhere"
        elsewhere.write_bytes(b"")
        path.symlink_to(elsewhere)
        with self.assertRaisesRegex(ValueError, "symlink"):
            self.assets()

    def test_counterfactual_native_use_is_not_installable(self):
        self.use["counterfactualCalibrationOnly"] = True
        self.write_json("rsa-md5-native-use.json", self.use)
        with self.assertRaisesRegex(ValueError, "Counterfactual"):
            self.assets()

    def test_unbound_empty_files_are_not_copied(self):
        (self.receipt / "arbitrary-private-like-empty-file").write_bytes(b"")
        self.assertNotIn("arbitrary-private-like-empty-file", self.assets())


if __name__ == "__main__":
    unittest.main()
