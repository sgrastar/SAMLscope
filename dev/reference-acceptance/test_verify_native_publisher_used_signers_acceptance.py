"""Host-only proof boundaries for actual publisher signers from two Runs.

Fixtures contain public synthetic bytes. Every subprocess and Suite API entry
point is blocked so this module cannot invoke Docker, Java, or a native product.
"""
import copy
import importlib.util
import json
import pathlib
import tempfile
import unittest
from unittest.mock import patch


HERE = pathlib.Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "publisher_used_signers_acceptance", HERE / "verify_native_publisher_used_signers_acceptance.py"
)
verifier = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(verifier)

TARGET = "http://localhost:18380/idp"
BASE = "http://localhost:18080"
C1 = "IIP-MD05-c1-idp-01"
C3 = "IIP-MD05-c3-idp-01"


def identifier(prefix, number):
    return prefix + "_" + f"{number:026d}"


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True) + "\n")


def tree_bytes(root):
    return {str(p.relative_to(root)): p.read_bytes() for p in root.rglob("*") if p.is_file()}


class HostOnlyTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(dir="/private/tmp")
        self.addCleanup(temporary.cleanup)
        self.folder = pathlib.Path(temporary.name)
        self.receipt = self.folder / "receipt"
        self.receipt.mkdir()
        self.native = self.enterContext(patch.object(
            verifier.subprocess, "run", side_effect=AssertionError("Unexpected process invocation")
        ))
        self.native_read = self.enterContext(patch.object(
            verifier.subprocess, "check_output", side_effect=AssertionError("Unexpected process invocation")
        ))
        if hasattr(verifier, "api"):
            self.suite = self.enterContext(patch.object(
                verifier, "api", side_effect=AssertionError("Unexpected Suite API request")
            ))


class PublicReceiptInventoryTest(HostOnlyTest):
    def test_public_json_source_certificate_and_spki_inventory_is_read_only(self):
        write_json(self.receipt / "native.json", {
            "currentCredentials": [{"privateCredentialPresent": True, "certificateSha256": "a" * 64}],
            "remotePeers": [{"signatureOverridePublicSpkiPem": "-----BEGIN PUBLIC KEY-----\nAQID\n-----END PUBLIC KEY-----\n"}],
        })
        (self.receipt / "native-command.php").write_text("<?php // signature.privatekey is a configuration name\n")
        (self.receipt / "certificate.der").write_bytes(b"public synthetic certificate")
        (self.receipt / "public.pem").write_text("-----BEGIN PUBLIC KEY-----\nAQID\n-----END PUBLIC KEY-----\n")
        before = tree_bytes(self.receipt)
        expected = {name: verifier.sha(raw) for name, raw in before.items()}
        self.assertEqual(verifier.public_inventory(self.receipt), expected)
        self.assertEqual(tree_bytes(self.receipt), before)
        self.native.assert_not_called()
        self.native_read.assert_not_called()

    def test_nested_private_projection_fields_are_rejected_without_modifying_bytes(self):
        for key in ("password", "Authorization", "Cookie", "signature.privatekey", "secret", "token"):
            write_json(self.receipt / "native.json", {"remotePeers": [{"nested": {key: "synthetic forbidden value"}}]})
            before = tree_bytes(self.receipt)
            with self.subTest(key=key), self.assertRaises(ValueError):
                verifier.public_inventory(self.receipt)
            self.assertEqual(tree_bytes(self.receipt), before)

    def test_private_pem_marker_is_rejected_even_under_public_name(self):
        for kind in ("PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY", "ENCRYPTED PRIVATE KEY"):
            (self.receipt / "public.pem").write_text("-----BEGIN " + kind + "-----\nsynthetic forbidden marker\n")
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                verifier.public_inventory(self.receipt)

    def test_file_directory_and_root_symlinks_are_rejected(self):
        public = self.folder / "public.json"
        write_json(public, {"public": True})
        file_link = self.receipt / "linked.json"
        file_link.symlink_to(public)
        with self.assertRaises(ValueError):
            verifier.public_inventory(self.receipt)
        file_link.unlink()
        outside = self.folder / "outside"
        outside.mkdir()
        write_json(outside / "public.json", {"public": True})
        directory_link = self.receipt / "linked-directory"
        directory_link.symlink_to(outside, target_is_directory=True)
        with self.assertRaises(ValueError):
            verifier.public_inventory(self.receipt)
        directory_link.unlink()
        root_link = self.folder / "receipt-link"
        root_link.symlink_to(self.receipt, target_is_directory=True)
        with self.assertRaises(ValueError):
            verifier.public_inventory(root_link)


class UsedPeerManifestTest(HostOnlyTest):
    def setUp(self):
        super().setUp()
        self.target = (
            '<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="' + TARGET + '">'
            '<md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"/>'
            '</md:EntityDescriptor>'
        ).encode()
        self.manifest = {
            "runId": identifier("run", 1), "planId": identifier("plan", 1),
            "entityId": TARGET, "targetMetadataSha256": verifier.sha(self.target),
            "usedSigningPeers": [],
        }
        for index, label in enumerate(("primary", "secondary"), start=1):
            plan = identifier("plan", index)
            run = identifier("run", index)
            entity = BASE + "/p/" + plan
            peer = {
                "label": label, "runId": run, "planId": plan, "entityId": entity,
                "fixtureFile": label + "/fixture.xml", "createdFile": label + "/created.json",
                "planFile": label + "/plan.json", "requestReference": identifier("tx", index * 2),
                "responseReference": identifier("tx", index * 2 + 1), "signerUseOriginal": label + "-signer-use",
            }
            self.manifest["usedSigningPeers"].append(peer)
            write_json(self.receipt / peer["createdFile"], {"run": {"id": run, "planId": plan}})
            write_json(self.receipt / peer["planFile"], {
                "id": plan, "profile": "metadata_idp" if label == "primary" else "browser_sso_idp",
                "target": {"entityId": TARGET, "kind": "IDP"},
            })
            self.write_fixture(peer)
            (self.receipt / label / "target-metadata.xml").write_bytes(self.target)

    def write_fixture(self, peer, *, entity=None, role="SPSSODescriptor", duplicate=False):
        role_xml = '<md:' + role + ' protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"/>'
        raw = (
            '<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="' +
            (entity or peer["entityId"]) + '">' + role_xml + (role_xml if duplicate else "") + '</md:EntityDescriptor>'
        ).encode()
        (self.receipt / peer["fixtureFile"]).write_bytes(raw)

    def validate(self):
        return verifier.validate_used_peers(self.manifest, self.receipt)

    def test_real_primary_and_secondary_bindings_validate_without_relabeling(self):
        original = copy.deepcopy(self.manifest)
        before = tree_bytes(self.receipt)
        self.assertEqual(self.validate(), self.manifest["usedSigningPeers"])
        self.assertEqual(self.manifest, original)
        self.assertEqual(tree_bytes(self.receipt), before)

    def test_primary_manifest_run_and_plan_cannot_be_swapped_to_secondary(self):
        for field in ("runId", "planId"):
            manifest = copy.deepcopy(self.manifest)
            self.manifest[field] = self.manifest["usedSigningPeers"][1][field]
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.validate()
            self.manifest = manifest

    def test_two_ordered_distinct_peer_identities_are_required(self):
        original = copy.deepcopy(self.manifest)
        for change in ("missing", "reversed", "label", "runId", "planId", "entityId"):
            self.manifest = copy.deepcopy(original)
            rows = self.manifest["usedSigningPeers"]
            if change == "missing":
                rows.pop()
            elif change == "reversed":
                rows.reverse()
            else:
                rows[1][change] = rows[0][change]
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.validate()

    def test_created_run_and_plan_target_profile_are_immutable_bindings(self):
        peer = self.manifest["usedSigningPeers"][1]
        for file, field, value in (
            ("createdFile", "run.id", identifier("run", 3)),
            ("createdFile", "run.planId", identifier("plan", 3)),
            ("planFile", "id", identifier("plan", 3)),
            ("planFile", "profile", "metadata_idp"),
            ("planFile", "target.entityId", "http://foreign/idp"),
        ):
            path = self.receipt / peer[file]
            original = path.read_bytes()
            changed = json.loads(original)
            owner = changed
            parts = field.split(".")
            for part in parts[:-1]:
                owner = owner[part]
            owner[parts[-1]] = value
            write_json(path, changed)
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.validate()
            path.write_bytes(original)

    def test_foreign_ambiguous_or_idp_fixture_cannot_supply_sp_peer(self):
        peer = self.manifest["usedSigningPeers"][1]
        for options in ({"entity": "http://foreign/peer"}, {"role": "IDPSSODescriptor"}, {"duplicate": True}):
            self.write_fixture(peer, **options)
            with self.subTest(options=options), self.assertRaises(ValueError):
                self.validate()

    def test_each_peer_target_snapshot_must_equal_manifest_digest(self):
        for label in ("primary", "secondary"):
            path = self.receipt / label / "target-metadata.xml"
            path.write_bytes(self.target + b"\n")
            with self.subTest(label=label), self.assertRaises(ValueError):
                self.validate()
            path.write_bytes(self.target)

    def test_traversal_absolute_or_other_label_evidence_path_is_rejected(self):
        original = copy.deepcopy(self.manifest)
        for field, value in (
            ("fixtureFile", "secondary/../secondary/fixture.xml"),
            ("fixtureFile", "../fixture.xml"), ("createdFile", "primary/created.json"),
            ("planFile", str((self.receipt / "secondary/plan.json").resolve())),
        ):
            self.manifest = copy.deepcopy(original)
            self.manifest["usedSigningPeers"][1][field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                self.validate()

    def test_unsafe_or_reused_request_response_references_are_rejected(self):
        original = copy.deepcopy(self.manifest)
        for field, value in (
            ("requestReference", "../tx"), ("responseReference", "tx_not-ulid"),
            ("requestReference", original["usedSigningPeers"][0]["requestReference"]),
            ("responseReference", original["usedSigningPeers"][0]["responseReference"]),
            ("responseReference", original["usedSigningPeers"][0]["requestReference"]),
        ):
            self.manifest = copy.deepcopy(original)
            self.manifest["usedSigningPeers"][1][field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                self.validate()

    def test_peer_signer_use_original_cannot_be_relabelled(self):
        self.manifest["usedSigningPeers"][1]["signerUseOriginal"] = "primary-signer-use"
        with self.assertRaises(ValueError):
            self.validate()


class ActualCampaignCostTest(HostOnlyTest):
    COUNTS = {
        "productSettings": 2, "configurationRestorations": 1, "nativePublicCalls": 10,
        "credentialPosts": 1, "samlSubmissions": 3, "personOperations": 0,
        "nativeEphemeralKeyCreations": 1, "nativeEphemeralKeyRemovals": 1,
        "initialBaselineSubmissions": 1, "selectedSignerSubmissions": 2,
        "guestWriteAttempts": 2, "successfulHostWrites": 2, "successfulGuestWrites": 2,
        "nativePeerApplications": 1, "nativePeerRestorations": 1, "productRestarts": 0,
    }

    def test_exact_success_restoration_and_three_sso_costs_are_read_only(self):
        counts = copy.deepcopy(self.COUNTS)
        verifier.validate_costs(counts)
        self.assertEqual(counts, self.COUNTS)

    def test_missing_or_extra_operation_cannot_be_hidden_by_aggregate_success(self):
        for field, expected in self.COUNTS.items():
            changed = self.COUNTS | {field: expected + 1}
            with self.subTest(field=field), self.assertRaises(ValueError):
                verifier.validate_costs(changed)
            changed = self.COUNTS.copy()
            del changed[field]
            with self.subTest(missing=field), self.assertRaises(ValueError):
                verifier.validate_costs(changed)

    def test_boolean_float_string_and_integer_subclass_are_not_actual_counts(self):
        class IntegerLike(int):
            pass

        for field, expected in self.COUNTS.items():
            for value in (True, False, float(expected), str(expected), IntegerLike(expected)):
                with self.subTest(field=field, kind=type(value).__name__), self.assertRaises(ValueError):
                    verifier.validate_costs(self.COUNTS | {field: value})

    def test_failed_guest_push_or_unproven_key_removal_is_not_complete(self):
        for field, value in (("successfulGuestWrites", 1), ("nativePeerApplications", 0),
                             ("nativePeerRestorations", 0), ("nativeEphemeralKeyRemovals", 0)):
            with self.subTest(field=field), self.assertRaises(ValueError):
                verifier.validate_costs(self.COUNTS | {field: value})

    def test_unaccounted_operation_category_cannot_be_dropped(self):
        with self.assertRaises(ValueError):
            verifier.validate_costs(self.COUNTS | {"unaccountedProductOperations": 1})


class ExactNativeRestorationTest(HostOnlyTest):
    def setUp(self):
        super().setUp()
        original_digest = "a" * 64
        overlay_digest = "b" * 64
        restored = {
            "restored": True, "original_sha256": original_digest, "final_sha256": original_digest,
            "configuration_write_attempts": 2, "applied_conditions": 1,
            "restoration_write_attempts": 1, "errors": [],
        }
        rows = []
        for index, (phase, digest) in enumerate((
            ("initial", original_digest), ("before-host-write", original_digest),
            ("after-native-write", overlay_digest), ("before-host-write", overlay_digest),
            ("after-native-write", original_digest),
        )):
            rows.append({
                "phase": phase, "sha256": digest, "expectedSha256": digest,
                "startedAt": f"2026-10-04T00:00:{index * 2:02d}Z",
                "finishedAt": f"2026-10-04T00:00:{index * 2 + 1:02d}Z",
            })
        mounted = {
            "mount": {
                "Type": "bind",
                "Source": str(verifier.REPO / "build/acceptance/reference-20260914/ssp-config/saml20-sp-remote.php"),
                "Destination": verifier.PEER_REMOTE, "RW": True,
            },
            "guestWriteAttempts": 2, "successfulHostWrites": 2, "successfulGuestWrites": 2,
            "readbacks": rows,
        }
        write_json(self.folder / "restoration-write.json", restored)
        write_json(self.folder / "restoration.json", restored)
        write_json(self.folder / "native-mounted-configuration-readbacks.json", mounted)
        write_json(self.folder / "ephemeral-removal.json", {
            "removed": True, "absent": True, "createAttempts": 1, "removeAttempts": 1,
        })

    def verify(self):
        return verifier.verify_restoration(self.folder, ActualCampaignCostTest.COUNTS)

    def test_restoration_proves_owned_mount_original_hash_and_removed_material_read_only(self):
        before = tree_bytes(self.folder)
        restored = self.verify()
        self.assertTrue(restored["restored"])
        self.assertEqual(restored["original_sha256"], restored["final_sha256"])
        self.assertEqual(tree_bytes(self.folder), before)

    def test_host_success_does_not_cover_native_hash_or_mount_failure(self):
        path = self.folder / "native-mounted-configuration-readbacks.json"
        original = json.loads(path.read_bytes())
        for field, value in (("Source", "/foreign/remote.php"), ("Destination", "/foreign/guest.php"),
                             ("Type", "volume"), ("RW", False), ("RW", 1)):
            changed = copy.deepcopy(original)
            changed["mount"][field] = value
            write_json(path, changed)
            with self.subTest(mount_field=field, value=value), self.assertRaises(ValueError):
                self.verify()
        for change in ("unknown-hash", "missing-final", "unchanged-overlay", "reversed-window"):
            changed = copy.deepcopy(original)
            rows = changed["readbacks"]
            if change == "unknown-hash":
                rows[2]["sha256"] = "c" * 64
            elif change == "missing-final":
                rows.pop()
            elif change == "unchanged-overlay":
                for row in rows:
                    row["sha256"] = row["expectedSha256"] = "a" * 64
            else:
                rows[2]["finishedAt"] = "2026-10-04T00:00:00Z"
            write_json(path, changed)
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.verify()

    def test_restoration_projection_counts_cannot_be_booleans_or_floats(self):
        write_path = self.folder / "restoration-write.json"
        snapshot_path = self.folder / "restoration.json"
        original = json.loads(write_path.read_bytes())
        for field, value in (("configuration_write_attempts", 2.0), ("applied_conditions", True),
                             ("restoration_write_attempts", True)):
            changed = original | {field: value}
            write_json(write_path, changed)
            write_json(snapshot_path, changed)
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.verify()

    def test_native_mounted_write_success_counts_must_be_integers(self):
        path = self.folder / "native-mounted-configuration-readbacks.json"
        original = json.loads(path.read_bytes())
        for field in ("guestWriteAttempts", "successfulHostWrites", "successfulGuestWrites"):
            write_json(path, original | {field: 2.0})
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.verify()

    def test_partial_restoration_removal_or_different_snapshot_remains_unqualified(self):
        path = self.folder / "ephemeral-removal.json"
        original = json.loads(path.read_bytes())
        for field, value in (("removed", False), ("removed", 1), ("absent", False), ("absent", 1),
                             ("createAttempts", 0), ("createAttempts", True), ("removeAttempts", 0), ("removeAttempts", True)):
            write_json(path, original | {field: value})
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                self.verify()
        write_json(path, original)
        restored = json.loads((self.folder / "restoration.json").read_bytes())
        write_json(self.folder / "restoration.json", restored | {"final_sha256": "c" * 64})
        with self.assertRaises(ValueError):
            self.verify()


class FormalPreservationTest(HostOnlyTest):
    def fixtures(self):
        old = {"id": C1, "mode": "CONFIG", "outcome": "NOT_VERIFIED", "verdict": "NOT_VERIFIED"}
        before = {
            "run": {"id": identifier("run", 1)},
            "target": {"role": "IDP", "entityId": TARGET, "metadata_digest": "sha256:" + "a" * 64},
            "requirements": [{"id": "MD05", "cases": [old, old | {"id": C3}, {
                "id": "IIP-MD05-c5-idp-01", "outcome": "NOT_VERIFIED", "details": {"original": True},
            }]}],
        }
        proofs = {
            case: {"outcome": "VIOLATED", "reasonCode": "metadata.publisher.role-description-incomplete",
                   "evidence": [{"kind": "transcript", "reference": identifier("tx", n)}]}
            for n, case in enumerate((C1, C3), start=1)
        }
        after = copy.deepcopy(before)
        for case in after["requirements"][0]["cases"][:2]:
            case.update({
                "outcome": "VIOLATED", "verdict": "FAIL", "evidence_class": "OPERATOR_ASSISTED",
                "attested": False, "reason_code": proofs[case["id"]]["reasonCode"],
                "evidence": copy.deepcopy(proofs[case["id"]]["evidence"]),
            })
        return before, after, proofs

    def test_both_conclusions_and_unrelated_cases_preserved_without_mutation(self):
        fixtures = self.fixtures()
        original = copy.deepcopy(fixtures)
        cases = verifier.verify_preservation(*fixtures)
        self.assertEqual(set(cases), {C1, C3})
        self.assertEqual(fixtures, original)

    def test_foreign_run_or_metadata_target_is_rejected(self):
        for field, value in (("run", {"id": identifier("run", 2)}),
                             ("target", {"role": "IDP", "entityId": TARGET, "metadata_digest": "sha256:" + "b" * 64})):
            fixtures = self.fixtures()
            fixtures[1][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                verifier.verify_preservation(*fixtures)

    def test_missing_added_duplicate_or_changed_unrelated_case_is_rejected(self):
        for change in ("missing", "added", "duplicate", "changed"):
            fixtures = self.fixtures()
            cases = fixtures[1]["requirements"][0]["cases"]
            if change == "missing":
                cases.pop()
            elif change == "added":
                cases.append({"id": "IIP-new", "outcome": "NOT_VERIFIED"})
            elif change == "duplicate":
                cases.append(copy.deepcopy(cases[0]))
            else:
                cases[-1]["details"]["original"] = False
            with self.subTest(change=change), self.assertRaises(ValueError):
                verifier.verify_preservation(*fixtures)

    def test_each_selected_case_requires_native_violation_and_exact_proof_evidence(self):
        for index in (0, 1):
            for field, value in (("outcome", "SATISFIED"), ("verdict", "PASS"),
                                 ("evidence_class", "ATTESTED"), ("attested", True), ("attested", 0),
                                 ("reason_code", "case.pending-interaction"),
                                 ("evidence", [{"kind": "transcript", "reference": identifier("tx", 9)}])):
                fixtures = self.fixtures()
                fixtures[1]["requirements"][0]["cases"][index][field] = value
                with self.subTest(index=index, field=field, value=value), self.assertRaises(ValueError):
                    verifier.verify_preservation(*fixtures)

    def test_one_case_proof_cannot_adopt_both_slots(self):
        fixtures = self.fixtures()
        del fixtures[2][C3]
        with self.assertRaises(ValueError):
            verifier.verify_preservation(*fixtures)


class IndependentArchivePinsTest(HostOnlyTest):
    def runtime_fixture(self):
        runtime = self.folder / "runtime"
        runtime.mkdir()
        pins = {}
        for name in verifier.JARS:
            raw = ("public synthetic archive " + name).encode()
            (runtime / (name + ".jar")).write_bytes(raw)
            pins[name] = verifier.sha(raw)
        for name in (verifier.HELPER, verifier.STORED, verifier.OUTBOX):
            raw = ("// public synthetic helper " + name + "\n").encode()
            (runtime / (name + ".java")).write_bytes(raw)
            pins[name] = verifier.sha(raw)
        dependencies = runtime / "dependencies"
        dependencies.mkdir()
        rows = []
        for name in ("first.jar", "second.jar"):
            raw = ("public synthetic dependency " + name).encode()
            (dependencies / name).write_bytes(raw)
            rows.append({"file": "dependencies/" + name, "sha256": verifier.sha(raw)})
        write_json(runtime / "dependency-priority.json", {
            "schema": "samlscope-publisher-replay-dependencies-v1",
            "qualifiedSource": "public-synthetic-deployment/isolated-test-overlay.json",
            "qualifiedSourceSha256": verifier.sha(b"public synthetic deployment qualification"),
            "mutableProjectEntriesExcluded": True, "entries": rows,
        })
        pins["dependencyPrioritySha256"] = verifier.sha((runtime / "dependency-priority.json").read_bytes())
        write_json(runtime / "archive-provenance.json", {
            "actualDeployedByteCopy": True, "mutableProjectHardlinks": False, "productOperations": 0,
        })
        write_json(runtime / "pins.json", pins)
        return runtime, pins

    def qualified(self, runtime, pins):
        with patch.object(verifier, "PINS", pins):
            return verifier.independently_pinned(runtime)

    def test_independently_pinned_public_byte_copies_validate_read_only(self):
        runtime, pins = self.runtime_fixture()
        before = tree_bytes(runtime)
        self.assertEqual(self.qualified(runtime, pins), pins)
        self.assertEqual(tree_bytes(runtime), before)
        self.native.assert_not_called()
        self.native_read.assert_not_called()

    def test_changed_project_helper_or_qualified_priority_bytes_are_rejected(self):
        runtime, pins = self.runtime_fixture()
        names = [name + ".jar" for name in verifier.JARS]
        names += [name + ".java" for name in (verifier.HELPER, verifier.STORED, verifier.OUTBOX)]
        names += ["dependency-priority.json"]
        for name in names:
            path = runtime / name
            original = path.read_bytes()
            path.write_bytes(original + b"public replacement")
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.qualified(runtime, pins)
            path.write_bytes(original)

    def test_third_party_dependency_hash_change_is_rejected_after_matching_pins(self):
        runtime, pins = self.runtime_fixture()
        (runtime / "dependencies/second.jar").write_bytes(b"different public dependency")
        with self.assertRaises(ValueError):
            self.qualified(runtime, pins)

    def test_qualified_classpath_rejects_foreign_duplicate_or_mutable_entries(self):
        runtime, pins = self.runtime_fixture()
        path = runtime / "dependency-priority.json"
        original = json.loads(path.read_bytes())
        for change in ("foreign", "duplicate", "mutable"):
            priority = copy.deepcopy(original)
            if change == "foreign":
                priority["entries"][0]["file"] = "../outside.jar"
            elif change == "duplicate":
                priority["entries"].append(copy.deepcopy(priority["entries"][0]))
            else:
                priority["mutableProjectEntriesExcluded"] = False
            write_json(path, priority)
            updated_pins = pins | {"dependencyPrioritySha256": verifier.sha(path.read_bytes())}
            write_json(runtime / "pins.json", updated_pins)
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.qualified(runtime, updated_pins)

    def test_hardlinked_project_archive_cannot_count_as_independent_byte_copy(self):
        runtime, pins = self.runtime_fixture()
        (self.folder / "mutable-runner.jar").hardlink_to(runtime / "runner.jar")
        with self.assertRaises(ValueError):
            self.qualified(runtime, pins)

    def test_project_or_helper_symlink_and_false_archive_provenance_are_rejected(self):
        runtime, pins = self.runtime_fixture()
        for name in ("runner.jar", verifier.HELPER + ".java"):
            path = runtime / name
            original = path.read_bytes()
            outside = self.folder / ("outside-" + name)
            outside.write_bytes(original)
            path.unlink()
            path.symlink_to(outside)
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.qualified(runtime, pins)
            path.unlink()
            path.write_bytes(original)
        write_json(runtime / "archive-provenance.json", {
            "actualDeployedByteCopy": False, "mutableProjectHardlinks": False, "productOperations": 0,
        })
        with self.assertRaises(ValueError):
            self.qualified(runtime, pins)

    def test_dependency_directory_cannot_escape_archive_through_symlink(self):
        runtime, pins = self.runtime_fixture()
        external = self.folder / "mutable-external-dependencies"
        (runtime / "dependencies").rename(external)
        (runtime / "dependencies").symlink_to(external, target_is_directory=True)
        with self.assertRaises(ValueError):
            self.qualified(runtime, pins)

    def test_unavailable_independent_pins_fail_before_any_process(self):
        runtime = self.folder / "runtime"
        runtime.mkdir()
        write_json(runtime / "pins.json", {"runner": "a" * 64})
        with patch.object(verifier, "PINS", {}), self.assertRaises(ValueError):
            verifier.independently_pinned(runtime)
        self.native.assert_not_called()
        self.native_read.assert_not_called()

    def test_archive_self_pins_cannot_replace_independent_qualification(self):
        runtime = self.folder / "runtime"
        runtime.mkdir()
        write_json(runtime / "pins.json", {"runner": "b" * 64})
        with patch.object(verifier, "PINS", {"runner": "a" * 64}), self.assertRaises(ValueError):
            verifier.independently_pinned(runtime)
        self.native.assert_not_called()
        self.native_read.assert_not_called()


class NativeTranscriptRedactionTest(HostOnlyTest):
    def test_exact_recorder_header_markers_are_preserved(self):
        entries = [{"headers": {"Cookie": ["SESSION=<redacted: 32 bytes>; PEER=<redacted: 16 bytes>"],
                                  "Authorization": ["<redacted: Basic, 48 bytes>"], "Content-Type": ["application/json"]}}]
        write_json(self.receipt / "primary/transcript.json", entries)
        before = tree_bytes(self.receipt)
        verifier.public_inventory(self.receipt)
        self.assertEqual(tree_bytes(self.receipt), before)
        self.native.assert_not_called()

    def test_unredacted_or_non_native_headers_and_other_secret_fields_are_rejected(self):
        for key, values in (("Cookie", ["SESSION=synthetic-plaintext"]), ("Cookie", ["[REDACTED]"]),
                            ("Cookie", ["SESSION=<redacted: 32 bytes>; EXTRA=plaintext"]),
                            ("Authorization", ["Basic synthetic-plaintext"]), ("Cookie", [])):
            with self.subTest(key=key, values=values), self.assertRaises(ValueError):
                verifier.validate_transcript_privacy([{"headers": {key: values}}])
        with self.assertRaises(ValueError):
            verifier.validate_transcript_privacy([{"headers": {}, "password": "synthetic"}])


class ReplayProductionGateTest(HostOnlyTest):
    def fixtures(self):
        manifest = {"runId": identifier("run", 1), "targetMetadataSha256": "a" * 64,
                    "usedSigningPeers": [{"runId": identifier("run", 1)}, {"runId": identifier("run", 2)}]}
        observed = {"runId": manifest["runId"], "targetMetadataSha256": manifest["targetMetadataSha256"],
                    "caseOutcomes": {c: {"outcome": "VIOLATED"} for c in (C1, C3)},
                    "negativeControls": {c: "NOT_VERIFIED" for c in verifier.CONTROLS},
                    "approvedMutants": {c: {"production": {"outcome": "NOT_VERIFIED"},
                                            "offline": {"outcome": "VIOLATED"}} for c in (C1, C3)},
                    "wrapperLifecycle": {c: True for c in verifier.LIFECYCLE},
                    "counterfactualAdopted": False, "sourceRunIds": [identifier("run", 2)],
                    "additionalSettings": 0, "additionalSaml": 0, "additionalCredentials": 0}
        return manifest, observed

    def test_all_controls_and_both_violation_lifecycles_are_required_without_mutation(self):
        manifest, report = self.fixtures(); before = copy.deepcopy((manifest, report))
        self.assertEqual(verifier.validate_replay(manifest, report), report["caseOutcomes"])
        self.assertEqual((manifest, report), before)
        for field in ("negativeControls", "wrapperLifecycle", "approvedMutants"):
            damaged = copy.deepcopy(report); damaged[field].pop(next(iter(damaged[field])))
            with self.subTest(field=field), self.assertRaises(ValueError): verifier.validate_replay(manifest, damaged)
        damaged = copy.deepcopy(report); damaged["caseOutcomes"][C3]["outcome"] = "SATISFIED"
        with self.assertRaises(ValueError): verifier.validate_replay(manifest, damaged)
        damaged = copy.deepcopy(report); damaged["approvedMutants"][C1]["production"]["outcome"] = "VIOLATED"
        with self.assertRaises(ValueError): verifier.validate_replay(manifest, damaged)

    def test_calibration_source_relabel_and_additional_operations_cannot_be_adopted(self):
        manifest, report = self.fixtures()
        for key, value in (("counterfactualAdopted", True), ("sourceRunIds", [identifier("run", 1)]),
                           ("additionalSettings", 1), ("additionalSaml", True), ("additionalCredentials", 0.0)):
            with self.subTest(key=key), self.assertRaises(ValueError): verifier.validate_replay(manifest, report | {key: value})


class EntireRunOutboxTest(HostOnlyTest):
    def test_exact_public_identity_rows_and_empty_outbox_are_read_only(self):
        run = identifier("run", 1)
        value = {"schema": "samlscope-used-signers-run-outbox-v1", "runId": run,
                 "readonly": True, "rows": [], "count": 0}
        self.assertEqual(verifier.validate_outbox(value, run), value)
        row = {"run_id": run, "case_id": C1, "action_id": "action_" + "a" * 32, "status": "PENDING",
               "transcript_entry_id": None, "created_at": "2026-10-04T00:00:00Z", "updated_at": "2026-10-04T00:00:00Z"}
        value.update(rows=[row], count=1); before = copy.deepcopy(value)
        verifier.validate_outbox(value, run); self.assertEqual(value, before)
        for damaged in (value | {"count": True}, value | {"rows": [row, row], "count": 2},
                        value | {"rows": [row | {"run_id": identifier("run", 2)}]},
                        value | {"rows": [row | {"action_json": "synthetic-private-payload"}]}):
            with self.assertRaises(ValueError): verifier.validate_outbox(damaged, run)


if __name__ == "__main__":
    unittest.main()
