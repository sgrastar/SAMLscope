import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

MODULE_PATH = Path(__file__).with_name("preflight_observation_adoption.py")
spec = importlib.util.spec_from_file_location("observation_preflight", MODULE_PATH)
preflight = importlib.util.module_from_spec(spec)
spec.loader.exec_module(preflight)

CASE = "IIP-MD06-c-idp-01"
RUN = "run_4FFJTY56TCQY9AKRA0BR0CC5K8"


class ObservationScopePreflightTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        # macOS /var can be a symlink; production parent checks stay strict.
        self.root = Path(self.tmp.name).resolve()
        self.original = {
            "schema_version": "1",
            "run": {"id": RUN},
            "target": {"entity_id": "redacted:internal-target", "role": "IDP",
                       "kind": "IDP", "metadata_digest": "sha256:" + "1" * 64},
            "profile": {"id": "metadata-idp"},
            "requirements": [{"id": "IIP-MD06",
                "obligations": [{"key": "IIP-MD06.c", "role": "IDP"}],
                "cases": [{"id": CASE, "obligation": "IIP-MD06.c",
                           "mode": "ATTESTED", "outcome": "NOT_VERIFIED"}]}],
            "private_unrelated_payload": "NEVER_OUTPUT_THIS_SENTINEL",
        }

    def write(self, name, value):
        path = self.root / name
        path.write_text(json.dumps(value))
        return path

    def check(self, target=None, source=None):
        target_path = self.write("target.json", target or self.original)
        source_path = None if source is None else self.write("source.json", source)
        return preflight.scope_preflight(CASE, target_path, source_path)

    def test_unique_approved_same_run_slot_is_only_scope_ready(self):
        source = copy.deepcopy(self.original)
        # Auxiliary source evidence need not contain the destination case slot.
        source["requirements"] = []
        result = self.check(source=source)
        self.assertTrue(result["scope_ready"])
        self.assertEqual("ready-for-evidence-implementation", result["readiness"])
        self.assertFalse(result["native_evidence_verified"])
        self.assertNotIn("verdict", result)
        self.assertNotIn("outcome", result)
        self.assertNotIn("NEVER_OUTPUT_THIS_SENTINEL", json.dumps(result))
        self.assertNotIn("redacted:internal-target", json.dumps(result))

    def test_missing_case_stops_before_source_file_read(self):
        target = copy.deepcopy(self.original)
        target["requirements"][0]["cases"] = []
        result = preflight.scope_preflight(
            CASE, self.write("target.json", target), self.root / "missing-source.json")
        self.assertEqual(["target-case-slot-absent"], result["reasons"])
        self.assertNotIn("source_result_sha256", result)

    def test_duplicate_case_slot_is_not_implicitly_merged(self):
        target = copy.deepcopy(self.original)
        target["requirements"].append(copy.deepcopy(target["requirements"][0]))
        self.assertEqual(["target-case-slot-duplicate"], self.check(target)["reasons"])

    def test_cross_run_same_metadata_cannot_relabel_source(self):
        source = copy.deepcopy(self.original)
        source["run"]["id"] = "run_JKN1F8TWK7PN06HXRC848CKMGF"
        result = self.check(source=source)
        self.assertFalse(result["scope_ready"])
        self.assertEqual(["source-run-contract-unavailable"], result["reasons"])

    def test_same_run_target_hash_and_identity_must_agree(self):
        source = copy.deepcopy(self.original)
        source["target"]["metadata_digest"] = "sha256:" + "2" * 64
        self.assertEqual(["source-target-metadata-mismatch"], self.check(source=source)["reasons"])
        source = copy.deepcopy(self.original)
        source["target"]["entity_id"] = "https://other.example/idp"
        self.assertEqual(["source-target-identity-mismatch"], self.check(source=source)["reasons"])
        source = copy.deepcopy(self.original)
        source["profile"]["id"] = "browser-sso-idp"
        self.assertEqual(["source-profile-mismatch"], self.check(source=source)["reasons"])

    def test_role_mode_and_run_are_real_report_fields(self):
        for change, expected in [
            (lambda x: x["requirements"][0]["cases"][0].update(mode="CONFIG"), "case-mode-mismatch"),
            (lambda x: x["target"].update(role="SP", kind="SP"), "case-role-mismatch"),
            (lambda x: x["target"].update(role=[]), "target-role-invalid"),
            (lambda x: x["requirements"][0]["obligations"][0].update(role="SP"), "case-role-mismatch"),
            (lambda x: x["run"].update(id="run_alias"), "run-id-invalid"),
        ]:
            with self.subTest(expected=expected):
                target = copy.deepcopy(self.original)
                change(target)
                self.assertEqual([expected], self.check(target)["reasons"])

    def test_symlink_and_duplicate_json_keys_fail_closed(self):
        original = self.write("original.json", self.original)
        link = self.root / "link.json"
        link.symlink_to(original)
        self.assertEqual(["input-symlink"], preflight.scope_preflight(CASE, link)["reasons"])
        duplicate = self.root / "duplicate.json"
        duplicate.write_text('{"run":{},"run":{}}')
        self.assertEqual(["input-duplicate-json-key"],
                         preflight.scope_preflight(CASE, duplicate)["reasons"])


if __name__ == "__main__":
    unittest.main()
