"""Public-proof and restoration boundaries for the per-peer publisher campaign.

All native interactions use injected callbacks. No Docker process, SSO request,
credential submission, or private-key read is performed by this module.
"""
import base64
import copy
import importlib.util
import json
import pathlib
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch


HERE = pathlib.Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "publisher_used_signers_campaign", HERE / "publisher_key_inventory_campaign.py"
)
campaign = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(campaign)


class PeerConfigurationRestorationTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(dir="/private/tmp")
        self.addCleanup(temporary.cleanup)
        self.path = pathlib.Path(temporary.name) / "remote.php"
        self.original = b"<?php\n$metadata = [];\n"
        self.path.write_bytes(self.original)
        self.mount = {
            "Type": "bind",
            "Source": str(self.path.resolve()),
            "Destination": campaign.PEER_REMOTE,
            "RW": True,
        }

    def batch(self, *, mounts=None, hashes=None, writer=None):
        return campaign.MountedPeerConfigurationBatch(
            self.path,
            mount_reader=lambda: [self.mount] if mounts is None else mounts,
            hash_reader=hashes or (lambda: campaign.SHA(self.path.read_bytes())),
            guest_writer=writer or Mock(),
        )

    def test_one_two_peer_overlay_restores_exact_host_inode_and_guest_bytes(self):
        writer = Mock()
        inode = self.path.stat().st_ino
        batch = self.batch(writer=writer)
        overlay = b"$metadata['primary'] = [];\n$metadata['secondary'] = [];"
        batch.apply(overlay)
        configured = self.path.read_bytes()
        self.assertEqual(configured, self.original + b"\n" + overlay + b"\n")
        result = batch.restore()
        self.assertTrue(result["restored"])
        self.assertEqual(self.path.read_bytes(), self.original)
        self.assertEqual(self.path.stat().st_ino, inode)
        self.assertEqual([call.args[0] for call in writer.call_args_list], [configured, self.original])
        self.assertEqual(batch.guest_write_attempts, 2)
        self.assertEqual(batch.successful_host_writes, 2)
        self.assertEqual(batch.successful_guest_writes, 2)
        self.assertEqual(batch.write_count, 2)
        self.assertEqual(batch.restoration_writes, 1)
        batch.restore()
        self.assertEqual(writer.call_count, 2, "An already restored epoch must not write again")

    def test_failed_guest_push_preserves_owned_host_state_for_finally_restoration(self):
        writer = Mock(side_effect=[subprocess.CalledProcessError(1, "mock-guest-push"), None])
        batch = self.batch(writer=writer)
        with self.assertRaises(subprocess.CalledProcessError):
            batch.apply(b"$metadata['temporary-peer'] = [];")
        self.assertEqual(batch.expected, self.path.read_bytes())
        self.assertNotEqual(batch.expected, self.original)
        self.assertTrue(batch.restore()["restored"])
        self.assertEqual(self.path.read_bytes(), self.original)
        self.assertEqual(batch.guest_write_attempts, 2)
        self.assertEqual(batch.successful_host_writes, 2)
        self.assertEqual(batch.successful_guest_writes, 1)
        self.assertEqual(batch.applied_count, 0)
        self.assertEqual(batch.restoration_writes, 1)

    def test_known_original_guest_after_failed_push_allows_owned_host_restoration(self):
        original_digest = campaign.SHA(self.original)
        writer = Mock(side_effect=[subprocess.CalledProcessError(1, "mock-guest-push"), None])
        batch = self.batch(hashes=lambda: original_digest, writer=writer)
        with self.assertRaises(subprocess.CalledProcessError):
            batch.apply(b"public peer overlay")
        self.assertTrue(batch.restore()["restored"])
        self.assertEqual(self.path.read_bytes(), self.original)

    def test_external_edit_after_failed_push_is_preserved(self):
        writer = Mock(side_effect=subprocess.CalledProcessError(1, "mock-guest-push"))
        batch = self.batch(writer=writer)
        with self.assertRaises(subprocess.CalledProcessError):
            batch.apply(b"owned overlay")
        operator_bytes = b"<?php\n// independent operator edit\n"
        self.path.write_bytes(operator_bytes)
        with self.assertRaisesRegex(RuntimeError, "outside this batch"):
            batch.restore()
        self.assertEqual(self.path.read_bytes(), operator_bytes)
        self.assertEqual(writer.call_count, 1)

    def test_foreign_or_readonly_mount_rejected_before_any_write(self):
        for field, value in (
            ("Type", "volume"),
            ("Source", "/foreign/remote.php"),
            ("Destination", "/foreign/guest.php"),
            ("RW", False),
            ("RW", "true"),
        ):
            with self.subTest(field=field):
                writer = Mock()
                with self.assertRaises(ValueError):
                    self.batch(mounts=[self.mount | {field: value}], writer=writer)
                writer.assert_not_called()
                self.assertEqual(self.path.read_bytes(), self.original)
        with self.assertRaises(ValueError):
            self.batch(mounts=[self.mount, self.mount])

    def test_changed_mount_and_unknown_native_bytes_stop_before_owned_write(self):
        writer = Mock()
        batch = self.batch(writer=writer)
        self.mount["Source"] = "/foreign/rebound.php"
        with self.assertRaises(ValueError):
            batch.apply(b"overlay")
        writer.assert_not_called()
        self.assertEqual(self.path.read_bytes(), self.original)
        self.mount["Source"] = str(self.path.resolve())
        batch.hash_reader = lambda: "0" * 64
        with self.assertRaises(ValueError):
            batch.apply(b"overlay")
        writer.assert_not_called()
        self.assertEqual(self.path.read_bytes(), self.original)


class UsedSignerEpochTest(unittest.TestCase):
    DIGEST = "a" * 64

    def test_planned_deployed_profile_is_not_misreported_as_formal_slots(self):
        raw=json.dumps({'cases':[{'id':case,'digest':'sha256:'+self.DIGEST} for case in campaign.CASES]}).encode()
        plan={'id':'plan_'+'0'*26,'profile':'metadata_idp','target':{'entityId':campaign.TARGET}}
        scope=campaign.planned_publisher_scope(raw,plan)
        self.assertFalse(scope['formalSlotsConfirmed'])
        self.assertEqual(set(scope['caseDigests']),set(campaign.CASES))
        self.assertEqual(scope['profileSha256'],campaign.SHA(raw))

    def test_wrong_profile_target_or_missing_approved_case_stops_planned_scope(self):
        complete=[{'id':case,'digest':'sha256:'+self.DIGEST} for case in campaign.CASES]
        plan={'id':'plan_'+'0'*26,'profile':'metadata_idp','target':{'entityId':campaign.TARGET}}
        for changed,cases in [(plan|{'profile':'browser_sso_idp'},complete),
                              (plan|{'target':{'entityId':'http://foreign/idp'}},complete),
                              (plan,complete[:1]),(plan,[complete[0],complete[1]|{'digest':'unknown'}])]:
            with self.subTest(changed=changed,cases=cases),self.assertRaises(ValueError):
                campaign.planned_publisher_scope(json.dumps({'cases':cases}).encode(),changed)

    def fixtures(self):
        state = {
            "configurationHashes": [
                {"file": campaign.REMOTE, "sha256": "b" * 64},
                {"file": campaign.PEER_REMOTE, "sha256": "c" * 64},
            ],
            "roleFeatureFlags": {
                "saml20.ecp": True,
                "saml20.hok.assertion": False,
                "saml20.sendartifact": False,
                "metadata.sign.enable": False,
            },
            "loadedClasses": [{"logicalFile": "native-message.php", "sha256": "d" * 64}],
            "metadataSources": [{"type": "flatfile", "configurationHash": "e" * 64}],
            "currentCredentials": [{
                "prefix": "", "certificateSha256": "1" * 64,
                "publicSpkiPemSha256": "2" * 64,
            }],
            "remotePeers": [{
                "entityId": campaign.BASE + "/p/plan_" + f"{2:026d}",
                "signatureOverridePresent": True,
                "signatureOverrideCertificateDerBase64": "AQID",
                "signatureOverridePublicSpkiPem": "-----BEGIN PUBLIC KEY-----\nAQID\n-----END PUBLIC KEY-----\n",
            }],
            "publicNativeMetadata": {
                "entityid": campaign.TARGET,
                "SingleSignOnService": [{
                    "Binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
                    "Location": "http://localhost:18380/sso",
                }],
            },
            "publicRequestContext": {
                "requestUri": "/simplesaml/module.php/saml/idp/metadata",
                "scheme": "http", "host": "localhost:18380",
            },
            "nativeProducedMetadataSha256": self.DIGEST,
        }
        peers = []
        flows = []
        for index, label in enumerate(("primary", "secondary"), start=1):
            run = "run_" + f"{index:026d}"
            plan = "plan_" + f"{index:026d}"
            peers.append({
                "label": label,
                "runId": run,
                "planId": plan,
                "entityId": campaign.BASE + "/p/" + plan,
                "fixtureFile": label + "/fixture.xml",
                "createdFile": label + "/created.json",
                "planFile": label + "/plan.json",
            })
            flows.append({
                "label": label,
                "runId": run,
                "requestReference": "tx_" + f"{index * 2:026d}",
                "responseReference": "tx_" + f"{index * 2 + 1:026d}",
                "startedAt": f"2026-10-04T00:00:0{index * 2}Z",
                "finishedAt": f"2026-10-04T00:00:0{index * 2 + 1}Z",
            })
        return state, copy.deepcopy(state), peers, flows

    def evaluate(self, fixtures):
        return campaign.validate_used_signer_epoch(*fixtures, self.DIGEST)

    def test_two_unique_real_peer_bindings_share_stable_ecp_enabled_epoch(self):
        fixtures = self.fixtures()
        original = copy.deepcopy(fixtures)
        rows = self.evaluate(fixtures)
        self.assertEqual(len(rows), 2)
        self.assertEqual({row["label"] for row in rows}, {"primary", "secondary"})
        self.assertEqual(fixtures, original, "Validation must not relabel saved Run or public state")
        self.assertTrue(fixtures[0]["roleFeatureFlags"]["saml20.ecp"])

    def test_configuration_source_flag_or_publication_drift_is_rejected(self):
        for field in ("configurationHashes", "roleFeatureFlags", "loadedClasses", "metadataSources",
                      "currentCredentials", "remotePeers", "publicNativeMetadata", "publicRequestContext"):
            fixtures = self.fixtures()
            after = fixtures[1]
            after[field] = [] if isinstance(after[field], list) else {}
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.evaluate(fixtures)
        for side in (0, 1):
            fixtures = self.fixtures()
            fixtures[side]["nativeProducedMetadataSha256"] = "f" * 64
            with self.subTest(side=side), self.assertRaises(ValueError):
                self.evaluate(fixtures)

    def test_one_peer_or_one_flow_cannot_stand_in_for_two_used_signers(self):
        for position in (2, 3):
            fixtures = self.fixtures()
            fixtures[position].pop()
            with self.subTest(position=position), self.assertRaises(ValueError):
                self.evaluate(fixtures)

    def test_duplicate_run_entity_label_and_response_do_not_count_twice(self):
        for field in ("label", "runId", "planId", "entityId"):
            fixtures = self.fixtures()
            fixtures[2][1][field] = fixtures[2][0][field]
            with self.subTest(peer_field=field), self.assertRaises(ValueError):
                self.evaluate(fixtures)
        fixtures = self.fixtures()
        fixtures[3][1]["responseReference"] = fixtures[3][0]["responseReference"]
        with self.assertRaises(ValueError):
            self.evaluate(fixtures)

    def test_foreign_run_or_reversed_operation_cannot_be_bound_by_label(self):
        fixtures = self.fixtures()
        fixtures[3][1]["runId"] = fixtures[3][0]["runId"]
        with self.assertRaises(ValueError):
            self.evaluate(fixtures)
        fixtures = self.fixtures()
        fixtures[3][1]["finishedAt"] = "2026-10-04T00:00:00Z"
        with self.assertRaises(ValueError):
            self.evaluate(fixtures)


    def test_request_response_overlap_and_foreign_evidence_paths_are_rejected(self):
        fixtures = self.fixtures()
        fixtures[3][1]["requestReference"] = fixtures[3][0]["requestReference"]
        with self.assertRaises(ValueError):
            self.evaluate(fixtures)
        fixtures = self.fixtures()
        fixtures[3][1]["responseReference"] = fixtures[3][0]["requestReference"]
        with self.assertRaises(ValueError):
            self.evaluate(fixtures)
        for field, value in (("fixtureFile", "../fixture.xml"),
                             ("createdFile", "primary/created.json"),
                             ("planFile", "/absolute/plan.json")):
            fixtures = self.fixtures()
            fixtures[2][1][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.evaluate(fixtures)


class UsedSignerBudgetAndPrivacyTest(unittest.TestCase):
    def test_three_sso_operations_share_one_credential_submission(self):
        counts = {"samlSubmissions": 3, "credentialPosts": 1, "personOperations": 0}
        campaign.validate_flow_budget(counts)
        for field, value in (("samlSubmissions", 2), ("samlSubmissions", 4),
                             ("credentialPosts", 0), ("credentialPosts", 2),
                             ("personOperations", 1)):
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                campaign.validate_flow_budget(counts | {field: value})

    def test_operation_counts_must_be_exact_integer_values(self):
        class IntegerLike(int):
            pass

        counts = {"samlSubmissions": 3, "credentialPosts": 1, "personOperations": 0}
        for field, expected in counts.items():
            for value in (float(expected), str(expected), None, True, False, IntegerLike(expected)):
                with self.subTest(field=field, value=value, kind=type(value).__name__), \
                        self.assertRaises(ValueError):
                    campaign.validate_flow_budget(counts | {field: value})
            missing = counts.copy()
            del missing[field]
            with self.subTest(missing=field), self.assertRaises(ValueError):
                campaign.validate_flow_budget(missing)

    def test_peer_signer_public_projection_rejects_secret_fields_and_key_bytes(self):
        safe = {
            "remotePeers": [{
                "entityId": "http://localhost/peer",
                "signatureOverridePresent": True,
                "signatureOverridePublicSpkiPem": "-----BEGIN PUBLIC KEY-----\nAQID\n-----END PUBLIC KEY-----",
                "signatureOverrideCertificateDerBase64": "AQID",
            }]
        }
        campaign.reject_sensitive(safe)
        for field in ("signature.privatekey", "private-key", "Authorization", "Cookie", "password"):
            unsafe = copy.deepcopy(safe)
            unsafe["remotePeers"][0][field] = "never-record-this"
            with self.subTest(field=field), self.assertRaises(ValueError):
                campaign.reject_sensitive(unsafe)
        for kind in ("PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY", "ENCRYPTED PRIVATE KEY"):
            unsafe = copy.deepcopy(safe)
            unsafe["remotePeers"][0]["signatureOverridePublicSpkiPem"] = f"-----BEGIN {kind}-----"
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                campaign.reject_sensitive(unsafe)


class ResponseSignerIdentityTest(unittest.TestCase):
    DIRECT_CERTIFICATE = b"public direct Response certificate fixture"
    CHILD_CERTIFICATE = b"public Assertion certificate fixture"
    SPKI = b"public SubjectPublicKeyInfo fixture"

    def signature(self, certificates):
        values = "".join(
            "<ds:X509Certificate>\n" + base64.b64encode(value).decode() +
            "\n</ds:X509Certificate>" for value in certificates
        )
        return "<ds:Signature><ds:KeyInfo><ds:X509Data>" + values + "</ds:X509Data></ds:KeyInfo></ds:Signature>"

    def response(self, direct="", child="", root="samlp:Response"):
        return (
            "<" + root + ' xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"'
            ' xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"'
            ' xmlns:ds="http://www.w3.org/2000/09/xmldsig#">' + direct +
            "<saml:Assertion>" + child + "</saml:Assertion></" + root + ">"
        ).encode()

    def public_key_output(self):
        return b"-----BEGIN PUBLIC KEY-----\n" + base64.b64encode(self.SPKI) + b"\n-----END PUBLIC KEY-----\n"

    def test_direct_response_certificate_selected_even_with_different_child_hint(self):
        raw = self.response(self.signature([self.DIRECT_CERTIFICATE]), self.signature([self.CHILD_CERTIFICATE]))
        with patch.object(campaign.subprocess, "run", return_value=Mock(stdout=self.public_key_output())) as run:
            identity = campaign.response_signer_identity(raw)
        self.assertEqual(identity, {
            "certificateSha256": campaign.SHA(self.DIRECT_CERTIFICATE),
            "responseCertificateSpkiSha256": campaign.SHA(self.SPKI),
        })
        run.assert_called_once_with(
            ["openssl", "x509", "-inform", "DER", "-pubkey", "-noout"],
            input=self.DIRECT_CERTIFICATE, capture_output=True, check=True, timeout=20,
        )

    def test_child_only_or_multiple_direct_signatures_stop_before_public_key_command(self):
        signature = self.signature([self.DIRECT_CERTIFICATE])
        for raw in (self.response(child=signature), self.response(signature + signature)):
            with self.subTest(raw=raw), \
                    patch.object(campaign.subprocess, "run", side_effect=AssertionError("Unexpected public-key command")) as run, \
                    self.assertRaisesRegex(ValueError, "one direct signature"):
                campaign.response_signer_identity(raw)
            run.assert_not_called()

    def test_ambiguous_or_missing_direct_certificate_stops_before_public_key_command(self):
        for certificates in ([], [self.DIRECT_CERTIFICATE, self.CHILD_CERTIFICATE]):
            raw = self.response(self.signature(certificates))
            with self.subTest(certificates=len(certificates)), \
                    patch.object(campaign.subprocess, "run", side_effect=AssertionError("Unexpected public-key command")) as run, \
                    self.assertRaisesRegex(ValueError, "ambiguous"):
                campaign.response_signer_identity(raw)
            run.assert_not_called()

    def test_foreign_root_with_signature_cannot_be_called_an_actual_response(self):
        raw = self.response(self.signature([self.DIRECT_CERTIFICATE]), root="saml:Assertion")
        with patch.object(campaign.subprocess, "run", side_effect=AssertionError("Unexpected public-key command")) as run, \
                self.assertRaises(ValueError):
            campaign.response_signer_identity(raw)
        run.assert_not_called()

    def test_non_public_key_output_is_rejected(self):
        raw = self.response(self.signature([self.DIRECT_CERTIFICATE]))
        with patch.object(campaign.subprocess, "run", return_value=Mock(stdout=b"no public key")), \
                self.assertRaisesRegex(ValueError, "no public key"):
            campaign.response_signer_identity(raw)


class NativeEphemeralSignerTest(unittest.TestCase):
    DIRECTORY = "/tmp/samlscope-publisher-signers-" + "a" * 24
    OWNER = "b" * 64

    def public_result(self):
        # Deliberately public fixture bytes, never a generated/private credential.
        certificate = b"public certificate fixture"
        spki = "-----BEGIN PUBLIC KEY-----\nAQID\n-----END PUBLIC KEY-----\n"
        return {
            "created": True,
            "certificateDerBase64": base64.b64encode(certificate).decode(),
            "certificateSha256": campaign.SHA(certificate),
            "publicSpkiPem": spki,
            "publicSpkiPemSha256": campaign.SHA(spki.encode()),
        }

    def signer(self, runner):
        return campaign.NativeEphemeralSigner(self.DIRECTORY, self.OWNER, runner)

    def test_generation_exposes_only_bound_public_certificate_and_spki(self):
        public = self.public_result()
        runner = Mock(side_effect=[json.dumps(public).encode(), b'{"removed":true,"absent":true}'])
        signer = self.signer(runner)
        self.assertEqual(signer.create(), public)
        self.assertEqual(signer.cleanup(), {"removed": True, "absent": True})
        self.assertEqual((signer.creations, signer.removals), (1, 1))
        self.assertEqual((signer.create_attempts, signer.remove_attempts), (1, 1))
        self.assertEqual(
            [call.kwargs["operation"] for call in runner.call_args_list],
            ["native-ephemeral-public-material-create", "native-ephemeral-public-material-remove"],
        )
        for call in runner.call_args_list:
            self.assertEqual(call.kwargs["arguments"], (self.DIRECTORY, self.OWNER))
        self.assertNotIn(signer.private_path, json.dumps(public))
        self.assertNotIn(signer.certificate_path, json.dumps(public))

    def test_failed_create_still_attempts_owned_cleanup_without_claiming_creation(self):
        runner = Mock(side_effect=[
            subprocess.CalledProcessError(1, "mock-native-generation"),
            b'{"removed":true,"absent":true}',
        ])
        signer = self.signer(runner)
        with self.assertRaises(subprocess.CalledProcessError):
            signer.create()
        self.assertEqual(signer.creations, 0)
        self.assertTrue(signer.cleanup()["absent"])
        self.assertEqual((signer.create_attempts, signer.remove_attempts), (1, 1))
        self.assertEqual(signer.removals, 1)

    def test_public_identity_mismatch_is_not_adopted_and_still_cleans_up(self):
        for field in ("certificateSha256", "publicSpkiPemSha256"):
            public = self.public_result() | {field: "0" * 64}
            runner = Mock(side_effect=[json.dumps(public).encode(), b'{"removed":true,"absent":true}'])
            signer = self.signer(runner)
            with self.subTest(field=field), self.assertRaises(ValueError):
                signer.create()
            self.assertEqual(signer.creations, 0)
            self.assertTrue(signer.cleanup()["absent"])

    def test_private_output_is_rejected_before_a_public_material_success(self):
        for field, value in (
            ("privatekey", "never-export"),
            ("publicSpkiPem", "-----BEGIN RSA PRIVATE KEY-----\nnever-export"),
            ("certificateDerBase64", {"nested": {"Authorization": "never-export"}}),
        ):
            public = self.public_result() | {field: value}
            runner = Mock(side_effect=[json.dumps(public).encode(), b'{"removed":true,"absent":true}'])
            signer = self.signer(runner)
            with self.subTest(field=field), self.assertRaises(ValueError):
                signer.create()
            self.assertEqual(signer.creations, 0)
            self.assertTrue(signer.cleanup()["absent"])

    def test_protocol_failure_removes_owned_native_material_in_finally(self):
        runner = Mock(side_effect=[json.dumps(self.public_result()).encode(), b'{"removed":true,"absent":true}'])
        signer = self.signer(runner)
        with self.assertRaisesRegex(ValueError, "mock SSO failed"):
            try:
                signer.create()
                raise ValueError("mock SSO failed")
            finally:
                self.assertTrue(signer.cleanup()["absent"])
        self.assertEqual(signer.removals, 1)
        self.assertEqual(runner.call_count, 2)

    def test_unconfirmed_cleanup_is_a_failure_not_successful_restoration(self):
        runner = Mock(side_effect=[json.dumps(self.public_result()).encode(), b'{"removed":true,"absent":false}'])
        signer = self.signer(runner)
        signer.create()
        with self.assertRaisesRegex(ValueError, "removal unproven"):
            signer.cleanup()
        self.assertEqual(signer.removals, 0)
        self.assertEqual(signer.remove_attempts, 1)

    def test_no_creation_attempt_leaves_native_runner_untouched(self):
        runner = Mock()
        signer = self.signer(runner)
        self.assertEqual(signer.cleanup(), {"removed": False, "absent": True})
        runner.assert_not_called()
        self.assertEqual(signer.remove_attempts, 0)

    def test_unsafe_directory_or_owner_is_rejected_before_native_invocation(self):
        runner = Mock()
        for directory, owner in (
            ("/tmp/foreign-signers", self.OWNER),
            (self.DIRECTORY + "/../other", self.OWNER),
            (self.DIRECTORY, "not-an-owner-digest"),
            (self.DIRECTORY, "g" * 64),
        ):
            with self.subTest(directory=directory, owner=owner), self.assertRaises(ValueError):
                campaign.NativeEphemeralSigner(directory, owner, runner)
        runner.assert_not_called()


class ExistingPublisherModeTest(unittest.TestCase):
    def test_readonly_hosted_mode_keeps_its_no_guest_write_contract(self):
        with tempfile.TemporaryDirectory(dir="/private/tmp") as directory:
            path = pathlib.Path(directory) / "hosted.php"
            original = b"<?php\n$metadata = [];\n"
            path.write_bytes(original)
            mount = {"Type": "bind", "Source": str(path.resolve()), "Destination": campaign.REMOTE, "RW": False}
            with patch.object(campaign.subprocess, "run", side_effect=AssertionError("Unexpected native call")), \
                    patch.object(campaign.subprocess, "check_output", side_effect=AssertionError("Unexpected native call")):
                batch = campaign.MountedPublisherConfigurationBatch(
                    path, mount_reader=lambda: [mount], hash_reader=lambda: campaign.SHA(path.read_bytes())
                )
                batch.apply(b"public hosted overlay")
                self.assertTrue(batch.restore()["restored"])
            self.assertEqual(path.read_bytes(), original)
            self.assertEqual(batch.restoration_writes, 1)


class PublisherCliDispatchTest(unittest.TestCase):
    def test_per_peer_signers_dispatches_without_old_mode_or_native_calls(self):
        with tempfile.TemporaryDirectory(dir="/private/tmp") as directory:
            output = pathlib.Path(directory) / "receipt"
            result = object()
            with patch.object(campaign.sys, "argv", ["publisher", "--output", str(output), "--per-peer-signers"]), \
                    patch.object(campaign, "collect_used_signers", return_value=result) as collect, \
                    patch.object(campaign, "api", side_effect=AssertionError("Unexpected Suite request")) as api, \
                    patch.object(campaign.subprocess, "run", side_effect=AssertionError("Unexpected native call")) as run, \
                    patch.object(campaign.subprocess, "check_output", side_effect=AssertionError("Unexpected native call")) as read:
                self.assertIs(campaign.main(), result)
            collect.assert_called_once()
            arguments = collect.call_args.args[0]
            self.assertTrue(arguments.per_peer_signers)
            self.assertFalse(arguments.browser_epoch)
            self.assertFalse(arguments.preflight_only)
            self.assertEqual(arguments.output, output)
            self.assertFalse(output.exists(), "Dispatch must not perform legacy output setup")
            api.assert_not_called()
            run.assert_not_called()
            read.assert_not_called()

    def test_per_peer_conflicts_fail_before_dispatch_output_or_native_calls(self):
        for conflicting in (["--browser-epoch"], ["--preflight-only"], ["--browser-epoch", "--preflight-only"]):
            with self.subTest(conflicting=conflicting), tempfile.TemporaryDirectory(dir="/private/tmp") as directory:
                output = pathlib.Path(directory) / "receipt"
                with patch.object(campaign.sys, "argv", ["publisher", "--output", str(output), "--per-peer-signers", *conflicting]), \
                        patch.object(campaign, "collect_used_signers") as collect, \
                        patch.object(campaign, "api", side_effect=AssertionError("Unexpected Suite request")) as api, \
                        patch.object(campaign.subprocess, "run", side_effect=AssertionError("Unexpected native call")) as run, \
                        patch.object(campaign.subprocess, "check_output", side_effect=AssertionError("Unexpected native call")) as read, \
                        self.assertRaisesRegex(ValueError, "own explicit native operation mode"):
                    campaign.main()
                self.assertFalse(output.exists())
                collect.assert_not_called()
                api.assert_not_called()
                run.assert_not_called()
                read.assert_not_called()

    def test_legacy_modes_keep_immutable_run_checkpoint_before_native_work(self):
        class SuiteCheckpoint(RuntimeError):
            pass

        for mode in ([], ["--browser-epoch"], ["--preflight-only"]):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory(dir="/private/tmp") as directory:
                output = pathlib.Path(directory) / "receipt"
                with patch.object(campaign.sys, "argv", ["publisher", "--output", str(output), *mode]), \
                        patch.object(campaign, "collect_used_signers") as collect, \
                        patch.object(campaign, "api", side_effect=SuiteCheckpoint("Immutable Run checkpoint")) as api, \
                        patch.object(campaign.subprocess, "run", side_effect=AssertionError("Unexpected native call")) as run, \
                        patch.object(campaign.subprocess, "check_output", side_effect=AssertionError("Unexpected native call")) as read, \
                        self.assertRaises(SuiteCheckpoint):
                    campaign.main()
                api.assert_called_once_with("/api/runs/" + campaign.DEFAULT_RUN + "/result.json")
                self.assertTrue((output / "collector-source.py").is_file())
                collect.assert_not_called()
                run.assert_not_called()
                read.assert_not_called()

    def test_legacy_invalid_run_stops_before_any_output_or_native_calls(self):
        with tempfile.TemporaryDirectory(dir="/private/tmp") as directory:
            output = pathlib.Path(directory) / "receipt"
            with patch.object(campaign.sys, "argv", ["publisher", "--output", str(output), "--run", "../foreign"]), \
                    patch.object(campaign, "collect_used_signers") as collect, \
                    patch.object(campaign, "api", side_effect=AssertionError("Unexpected Suite request")) as api, \
                    patch.object(campaign.subprocess, "run", side_effect=AssertionError("Unexpected native call")) as run, \
                    self.assertRaisesRegex(ValueError, "Invalid Run"):
                campaign.main()
            self.assertFalse(output.exists())
            collect.assert_not_called()
            api.assert_not_called()
            run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
