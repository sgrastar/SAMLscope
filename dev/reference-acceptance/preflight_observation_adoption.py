#!/usr/bin/env python3
"""Read-only case/Run scope check before evidence implementation.

This is not an adoption verifier. It neither checks native evidence nor derives
an outcome/verdict. Cross-Run reuse has no supported contract here and fails
closed, even for reports with identical metadata digests.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import stat
import sys

MAX_FILE_BYTES = 10 * 1024 * 1024
RUN_ID = re.compile(r"run_[0-9A-HJKMNP-TV-Z]{26}\Z")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
CASE_ID = re.compile(r"[A-Za-z0-9_.-]{1,160}\Z")
PROFILE_ID = re.compile(r"[A-Za-z0-9_.-]{1,80}\Z")
REPO_ROOT = Path(__file__).resolve().parents[2]


class Blocked(Exception):
    def __init__(self, reason: str):
        self.reason = reason


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise Blocked(reason)


def strict_bytes(path: Path) -> bytes:
    """Reject symlinks (including parents), non-files, and oversized input."""
    path = Path(path).absolute()
    try:
        for ancestor in (*reversed(path.parents), path):
            require(not stat.S_ISLNK(ancestor.lstat().st_mode), "input-symlink")
        before = path.lstat()
        require(stat.S_ISREG(before.st_mode), "input-not-regular-file")
        require(0 < before.st_size <= MAX_FILE_BYTES, "input-size-invalid")
        # O_NOFOLLOW protects the final path against a concurrent replacement.
        import os
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, "rb") as stream:
            opened = os.fstat(stream.fileno())
            require((opened.st_dev, opened.st_ino) == (before.st_dev, before.st_ino),
                    "input-changed-during-read")
            data = stream.read(MAX_FILE_BYTES + 1)
            after = os.fstat(stream.fileno())
        require(len(data) == before.st_size and
                (after.st_size, after.st_mtime_ns) == (before.st_size, before.st_mtime_ns),
                "input-changed-during-read")
        return data
    except OSError:
        raise Blocked("input-unavailable") from None


def json_file(path: Path) -> tuple[dict, str]:
    raw = strict_bytes(path)
    try:
        def unique_object(pairs):
            result = {}
            for key, value in pairs:
                require(key not in result, "input-duplicate-json-key")
                result[key] = value
            return result
        def reject_constant(_value):
            raise Blocked("input-json-invalid")
        value = json.loads(raw, object_pairs_hook=unique_object,
                           parse_constant=reject_constant)
    except (ValueError, UnicodeError, RecursionError):
        raise Blocked("input-json-invalid") from None
    require(isinstance(value, dict), "result-structure-invalid")
    return value, hashlib.sha256(raw).hexdigest()


def approved_case(case_id: str, repo: Path) -> tuple[dict, dict]:
    try:
        import yaml
    except ImportError:
        raise Blocked("approved-catalog-reader-unavailable") from None
    original = strict_bytes(repo / "tests/cases.yaml")
    try:
        catalog = yaml.safe_load(original)
    except (ValueError, yaml.YAMLError):
        raise Blocked("approved-catalog-invalid") from None
    require(isinstance(catalog, dict) and isinstance(catalog.get("cases"), list),
            "approved-catalog-invalid")
    candidates = [row for row in catalog["cases"]
                  if isinstance(row, dict) and row.get("id") == case_id]
    require(len(candidates) == 1, "approved-case-not-unique")
    case = candidates[0]
    require(isinstance(case.get("role"), str) and case["role"] in {"idp", "sp"} and
            isinstance(case.get("mode"), str) and
            case["mode"] in {"AUTOMATED", "BROWSER", "CONFIG", "ATTESTED"} and
            isinstance(case.get("obligation"), str), "approved-case-contract-invalid")
    digests = {"cases_sha256": hashlib.sha256(original).hexdigest()}
    for name in ("coverage", "specs"):
        digests[f"{name}_sha256"] = hashlib.sha256(
            strict_bytes(repo / f"tests/{name}.yaml")).hexdigest()
    return case, digests


def result_scope(value: dict) -> dict:
    require(value.get("schema_version") == "1", "result-schema-unsupported")
    run = value.get("run")
    require(isinstance(run, dict) and isinstance(run.get("id"), str) and
            RUN_ID.fullmatch(run["id"]) is not None, "run-id-invalid")
    target = value.get("target")
    require(isinstance(target, dict), "target-contract-unavailable")
    role = target.get("role")
    require(isinstance(role, str) and role in {"IDP", "SP"} and target.get("kind", role) == role,
            "target-role-invalid")
    entity = target.get("entity_id")
    require(isinstance(entity, str) and 0 < len(entity) <= 16384,
            "target-entity-unavailable")
    digest = target.get("metadata_digest")
    require(isinstance(digest, str) and DIGEST.fullmatch(digest) is not None,
            "target-metadata-digest-invalid")
    profile = value.get("profile")
    require(isinstance(profile, dict) and isinstance(profile.get("id"), str) and
            PROFILE_ID.fullmatch(profile["id"]) is not None,
            "profile-id-invalid")
    return {"run_id": run["id"], "target_role": role,
            "target_entity_field_sha256": hashlib.sha256(entity.encode()).hexdigest(),
            "target_metadata_sha256": digest.removeprefix("sha256:"),
            "profile_id": profile["id"]}


def scope_preflight(case_id: str, target_result: Path,
                    source_result: Path | None = None,
                    *, repo: Path = REPO_ROOT) -> dict:
    report = {"schema": "samlscope-observation-scope-preflight-v1",
              "scope_ready": False, "readiness": "blocked", "reasons": [],
              "scope_only": True, "native_evidence_verified": False,
              "cross_run_reuse_supported": False}
    try:
        require(isinstance(case_id, str) and CASE_ID.fullmatch(case_id) is not None,
                "case-id-invalid")
        report["case_id"] = case_id
        approved, spec = approved_case(case_id, repo)
        report["approved_contract"] = {"role": approved["role"],
                                       "mode": approved["mode"],
                                       "obligation": approved["obligation"]}
        report["specification_digests"] = spec
        target, target_sha = json_file(target_result)
        report["target_result_sha256"] = target_sha
        requirements = target.get("requirements")
        require(isinstance(requirements, list), "case-slot-contract-unavailable")
        slots = []
        for requirement in requirements:
            require(isinstance(requirement, dict) and
                    isinstance(requirement.get("cases"), list),
                    "case-slot-contract-unavailable")
            slots.extend((slot, requirement) for slot in requirement["cases"]
                         if isinstance(slot, dict) and slot.get("id") == case_id)
        require(len(slots) > 0, "target-case-slot-absent")
        require(len(slots) == 1, "target-case-slot-duplicate")
        slot, requirement = slots[0]
        require(slot.get("mode") == approved["mode"], "case-mode-mismatch")
        require(slot.get("obligation") == approved["obligation"],
                "case-obligation-mismatch")
        scope = result_scope(target)
        report["target_scope"] = scope
        require(scope["target_role"] == approved["role"].upper(), "case-role-mismatch")
        owners = requirement.get("obligations")
        require(isinstance(owners, list), "obligation-role-contract-unavailable")
        owners = [row for row in owners if isinstance(row, dict) and
                  row.get("key") == approved["obligation"]]
        require(len(owners) == 1 and owners[0].get("role") == scope["target_role"],
                "case-role-mismatch")
        if source_result is not None:
            source, source_sha = json_file(source_result)
            report["source_result_sha256"] = source_sha
            source_scope = result_scope(source)
            report["source_scope"] = source_scope
            require(source_scope["run_id"] == scope["run_id"],
                    "source-run-contract-unavailable")
            require(source_scope["target_metadata_sha256"] == scope["target_metadata_sha256"],
                    "source-target-metadata-mismatch")
            require(source_scope["target_entity_field_sha256"] == scope["target_entity_field_sha256"] and
                    source_scope["target_role"] == scope["target_role"],
                    "source-target-identity-mismatch")
            require(source_scope["profile_id"] == scope["profile_id"],
                    "source-profile-mismatch")
        report["scope_ready"] = True
        report["readiness"] = "ready-for-evidence-implementation"
    except Blocked as error:
        report["reasons"] = [error.reason]
    return report


class MachineParser(argparse.ArgumentParser):
    def error(self, _message):
        raise Blocked("cli-arguments-invalid")


def main(argv=None) -> int:
    parser = MachineParser(description=__doc__)
    parser.add_argument("--case-id", required=True)
    parser.add_argument("--target-result", type=Path, required=True)
    parser.add_argument("--source-result", type=Path)
    try:
        args = parser.parse_args(argv)
        report = scope_preflight(args.case_id, args.target_result, args.source_result)
    except Blocked as error:
        report = {"schema": "samlscope-observation-scope-preflight-v1",
                  "scope_ready": False, "readiness": "blocked", "scope_only": True,
                  "native_evidence_verified": False, "cross_run_reuse_supported": False,
                  "reasons": [error.reason]}
    print(json.dumps(report, sort_keys=True))
    return 0 if report["scope_ready"] else 1


if __name__ == "__main__":
    sys.exit(main())
