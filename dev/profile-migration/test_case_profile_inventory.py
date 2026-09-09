import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location(
    "case_profile_inventory", Path(__file__).parent / "case_profile_inventory.py"
)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class CaseProfileInventoryTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.inventory = module.build_inventory(ROOT)

    def test_every_approved_case_is_accounted_for_once(self):
        import yaml

        approved = yaml.safe_load((ROOT / "tests/cases.yaml").read_text())["cases"]
        rows = self.inventory["cases"]
        self.assertEqual({case["id"] for case in approved}, {row["case_id"] for row in rows})
        self.assertEqual(len(approved), len(rows))

    def test_inventory_uses_approved_case_identity_without_copying_execution_detail(self):
        import yaml

        approved = {
            case["id"]: case
            for case in yaml.safe_load((ROOT / "tests/cases.yaml").read_text())["cases"]
        }
        for row in self.inventory["cases"]:
            source = approved[row["case_id"]]
            self.assertEqual(source["case_digest"], row["case_digest"])
            for field in ("variant_references", "variant_plan", "variant_groups", "controls", "requires"):
                self.assertNotIn(field, row)

    def test_membership_is_role_safe_and_complete(self):
        for row in self.inventory["cases"]:
            self.assertTrue(row["profiles"], row["case_id"])
            self.assertTrue(all(profile.endswith("_" + row["role"]) for profile in row["profiles"]))
        self.assertEqual(0, self.inventory["summary"]["by_classification"]["4"])

    def test_variant_membership_does_not_create_runtime_splits(self):
        split = {row["case_id"] for row in self.inventory["cases"] if row["classification"] == 3}
        self.assertEqual(set(), split)

    def test_approval_only_status_is_separate_from_case_reuse(self):
        self.assertEqual(set(module.PROFILES), set(self.inventory["approval_only_profile_candidates"]))
        self.assertNotIn("5", self.inventory["summary"]["by_classification"])

    def test_inventory_does_not_define_runtime_items(self):
        self.assertEqual("approved_case", self.inventory["execution_unit"])
        self.assertNotIn("items", self.inventory)
        self.assertNotIn("runtime_item_count", self.inventory["summary"])
        self.assertEqual(
            "dev/profile-migration/case-profile-membership-draft.json",
            self.inventory["membership_source"],
        )

    def test_non_observable_owners_remain_explicit_without_inventing_cases(self):
        self.assertEqual(
            {
                ("IIP-SSO05.a4", "idp", ("browser_sso_idp",)),
                ("IIP-SSO05.a4", "sp", ("browser_sso_sp",)),
            },
            {
                (row["obligation"], row["role"], tuple(row["profiles"]))
                for row in self.inventory["non_executable_obligations"]
            },
        )

    def test_release_candidates_are_case_sets_for_all_profiles(self):
        releases = module.profile_release_candidates(self.inventory, "functional-case-v1")
        self.assertEqual(set(module.PROFILES), set(releases))
        known = {row["case_id"] for row in self.inventory["cases"]}
        for profile, release in releases.items():
            self.assertEqual(profile, release["profile"])
            self.assertEqual("functional-case-v1", release["version"])
            self.assertTrue(release["cases"])
            self.assertTrue({row["id"] for row in release["cases"]} <= known)
            self.assertNotIn("items", release)
            self.assertNotIn("variants", release)

    def test_review_candidate_has_no_variant_execution_mapping(self):
        candidate = module.review_candidate(self.inventory)
        for case in candidate["cases"]:
            self.assertNotIn("variant_membership_overrides", case)


if __name__ == "__main__":
    unittest.main()
