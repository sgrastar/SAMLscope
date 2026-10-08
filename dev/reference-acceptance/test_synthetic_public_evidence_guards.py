#!/usr/bin/env python3
"""Owned-temp and captured-public-byte controls; never starts a Run or calls HTTP."""
import copy
import hashlib
import json
import shutil
import tempfile
from pathlib import Path
from synthetic_public_evidence_guards import (assert_public_json, persist_public_json,
                                               public_json_document, validate_selected_export)

CAPTURE = Path("build/acceptance/reference-20261008/v236-synthetic-artifact-runtime-r1")
OUTPUT = Path("build/acceptance/reference-20261008/v236-synthetic-harness-postreview-guards-r1")


def rejected(action):
    try:
        action()
    except ValueError:
        return
    raise AssertionError("Unsafe synthetic evidence accepted")


def main():
    OUTPUT.mkdir(parents=True, exist_ok=True)
    checks = []
    positive = {}
    with tempfile.TemporaryDirectory(prefix="samlscope-public-evidence-guards-") as temporary:
        owner = Path(temporary).resolve()
        for index, document in enumerate([
                {"managementUrl": "owned-test-sensitive-sentinel"},
                {"plan": {"initialRun": {"managementUrl": "owned-test-sensitive-sentinel"}}},
                {"nested": [{"access_token": "owned-test-sensitive-sentinel"}]},
                {"nested": {"privateKey": "owned-test-sensitive-sentinel"}},
                {"nested": {"Authorization": "owned-test-sensitive-sentinel"}},
                {"nested": {"Cookie": "owned-test-sensitive-sentinel"}},
                {"nested": {"client-secret": "owned-test-sensitive-sentinel"}}]):
            raw = json.dumps(document).encode()
            for suffix in (".response.body", ".response.json", "created.json"):
                target = owner / "api-operations" / (str(index) + suffix)
                rejected(lambda: persist_public_json(raw, target))
                assert not target.exists()
            rejected(lambda: assert_public_json(document))
            checks.append("non-public-field-rejected-before-raw-and-created-save-" + str(index))
        for index, raw in enumerate([b"<html>owned private sentinel</html>", b'{"managementUrl":null,"managementUrl":"sentinel"}', b'{"value":NaN}', b'not-json', b'"owned private scalar"']):
            target = owner / "malformed" / (str(index) + ".response.body")
            rejected(lambda: persist_public_json(raw, target))
            assert not target.exists()
            checks.append("malformed-html-or-scalar-response-not-saved-" + str(index))
        public = b'{"run":{"id":"owned-public-run"},"managementUrl":null}'
        assert persist_public_json(public, owner / "public.response.body")["managementUrl"] is None
        assert (owner / "public.response.body").read_bytes() == public
        checks.append("null-management-url-public-json-byte-preservation")

        for mode in ("signed", "unsigned"):
            native = json.loads((CAPTURE / mode / "native-before-result-api.json").read_text())
            folder = owner / mode
            shutil.copytree(CAPTURE / mode / "originals", folder / "originals")
            gate = validate_selected_export(native, folder)
            assert len(gate["requiredOriginals"]) == 12 and gate["requiredSelectedOriginalsExported"]
            assert gate["globalOriginalExportComplete"] is False and gate["wholeRunExportClaimed"] is False
            positive[mode] = {"requiredOriginalReferences": [e["reference"] for e in gate["requiredOriginals"]],
                              "portableBytesAndHashesVerified": True, "unselectedDtdStillGlobalExportIncomplete": True}
            checks.append(mode + "-actual-selected-twelve-portable-originals")
            case_refs = set(gate["caseEvidenceReferences"])
            b_response = next(e for e in native["transcriptOriginals"] if e["id"] in case_refs and e["direction"] == "INBOUND" and e["summary"].get("type") == "Response")
            reference = b_response["id"]
            bad = copy.deepcopy(native)
            bad["transcriptOriginals"] = [e for e in bad["transcriptOriginals"] if e["id"] != reference]
            assert bad["runtimeProofVerified"] is True
            rejected(lambda: validate_selected_export(bad, folder))
            checks.append(mode + "-missing-B-original-despite-A-and-M0-proof-rejected")
            bad = copy.deepcopy(native)
            bad["caseExecution"]["outcome"]["evidence"] = bad["caseExecution"]["outcome"]["evidence"][:-1]
            rejected(lambda: validate_selected_export(bad, folder))
            checks.append(mode + "-nine-case-evidence-refs-rejected")
            bad = copy.deepcopy(native)
            bad["caseExecution"]["outcome"]["evidence"][1] = bad["caseExecution"]["outcome"]["evidence"][0]
            rejected(lambda: validate_selected_export(bad, folder))
            checks.append(mode + "-duplicate-case-reference-rejected")
            bad = copy.deepcopy(native)
            bad["caseExecution"]["outcome"]["details"]["completed_binding_fixtures"] = ["post-binding-control", "artifact-binding"]
            rejected(lambda: validate_selected_export(bad, folder))
            checks.append(mode + "-missing-approved-B-fixtures-rejected")
            for name in ("decodedSamlBytes", "computedDecodedSha256", "storedBodySha256"):
                bad = copy.deepcopy(native)
                changed = next(e for e in bad["transcriptOriginals"] if e["id"] == reference)
                changed[name] = changed[name] + 1 if name == "decodedSamlBytes" else "0" * 64
                rejected(lambda: validate_selected_export(bad, folder))
                checks.append(mode + "-declared-" + name + "-mismatch-rejected")
            path = folder / "originals" / (reference + ".saml.xml")
            original = path.read_bytes()
            path.unlink()
            rejected(lambda: validate_selected_export(native, folder))
            path.write_bytes(original)
            checks.append(mode + "-missing-physical-B-file-rejected")
            path.write_bytes(original + b" ")
            rejected(lambda: validate_selected_export(native, folder))
            path.write_bytes(original)
            checks.append(mode + "-physical-B-size-mismatch-rejected")
            changed_bytes = bytearray(original)
            changed_bytes[-1] ^= 1
            path.write_bytes(changed_bytes)
            rejected(lambda: validate_selected_export(native, folder))
            path.write_bytes(original)
            checks.append(mode + "-physical-B-byte-tamper-rejected")
            saved = owner / (mode + "-owned-original")
            path.rename(saved)
            path.symlink_to(saved)
            rejected(lambda: validate_selected_export(native, folder))
            path.unlink()
            saved.rename(path)
            checks.append(mode + "-portable-leaf-symlink-rejected")
            directory = folder / "originals"
            moved = owner / (mode + "-owned-originals")
            directory.rename(moved)
            directory.symlink_to(moved)
            rejected(lambda: validate_selected_export(native, folder))
            directory.unlink()
            moved.rename(directory)
            checks.append(mode + "-portable-parent-symlink-rejected")
            # An unselected DTD exclusion is outside the exact twelve-ref gate.
            assert validate_selected_export(native, folder)["globalOriginalExportComplete"] is False

    folders = [Path("build/acceptance/reference-20261008") / name for name in
               ("v236-synthetic-additional-r1", "v236-synthetic-additional-negative-r1", "v236-synthetic-artifact-runtime-r1")]
    privacy = {"jsonDocumentsInspected": 0, "nullManagementUrlFields": 0,
               "nonNullManagementUrlFields": 0, "nonNullExplicitCredentialFields": 0,
               "capturedActualRuns": 7, "valuesOrUrlsRecorded": False}
    def count_management(value):
        if isinstance(value, dict):
            for key, child in value.items():
                if key.replace("_", "").replace("-", "").lower() == "managementurl":
                    privacy["nullManagementUrlFields" if child is None else "nonNullManagementUrlFields"] += 1
                count_management(child)
        elif isinstance(value, list):
            for child in value:
                count_management(child)
    for folder in folders:
        for path in folder.rglob("*"):
            if path.is_file() and (path.suffix == ".json" or path.name.endswith(".response.body")):
                try:
                    document = json.loads(path.read_bytes())
                except (ValueError, UnicodeError):
                    continue
                privacy["jsonDocumentsInspected"] += 1
                count_management(document)
                assert_public_json(document)
    assert privacy["nonNullManagementUrlFields"] == 0
    helper_sources = [Path(__file__), Path(__file__).with_name("synthetic_public_evidence_guards.py"),
                      Path(__file__).with_name("synthetic_additional_runtime_smoke.py"),
                      Path(__file__).with_name("synthetic_artifact_runtime_smoke.py")]
    report = {"schema": "synthetic-harness-postreview-public-and-export-guards-v1", "checksPassed": len(checks), "checks": checks,
              "selectedArtifactReplay": positive, "capturedLocalPrivacyCounts": privacy,
              "httpOperations": 0, "databaseReads": 0, "privateKeyReads": 0, "newRuns": 0,
              "changesActualCaseOutcome": False, "actualProductProof": False,
              "sourceSha256": {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in helper_sources}}
    (OUTPUT / "collector-public-and-selected-export-guards.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"checksPassed": len(checks), "actualSelectedOriginalsPerMode": 12,
                      "oldCapturePrivacyViolationCount": 0, "httpOperations": 0, "newRuns": 0,
                      "report": str(OUTPUT / "collector-public-and-selected-export-guards.json")}))


if __name__ == "__main__":
    main()
