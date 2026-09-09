#!/usr/bin/env python3
"""Build the functional-profile migration inventory at approved-case granularity.

The historical item drafts are read only as membership review evidence.  They do
not become execution units and their row count is deliberately omitted.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
PROFILES = (
    "browser_sso_idp",
    "browser_sso_sp",
    "metadata_idp",
    "metadata_sp",
    "single_logout_idp",
    "single_logout_sp",
    "ecp_idp",
)
PROFILE_ROLES = {profile: profile.rsplit("_", 1)[1] for profile in PROFILES}
SOURCES = ("tests/coverage.yaml", "tests/cases.yaml", "tests/predicates.yaml")
LEGACY_REVIEW_DRAFTS = {"ext01-items-draft.json"}
MEMBERSHIP_DRAFT = "dev/profile-migration/case-profile-membership-draft.json"


def draft_paths(root: Path) -> list[Path]:
    return sorted(
        path
        for path in (root / "dev/profile-migration").glob("*-items-draft.json")
        if path.name not in LEGACY_REVIEW_DRAFTS
    )


def source_digest(root: Path, path: str) -> str:
    return "sha256:" + hashlib.sha256((root / path).read_bytes()).hexdigest()


def _case_reference_profiles(drafts: list[dict]) -> dict[str, dict[str | None, set[str]]]:
    result: dict[str, dict[str | None, set[str]]] = defaultdict(lambda: defaultdict(set))
    for draft in drafts:
        for item in draft.get("items", []):
            case_ids = item.get("case_ids")
            if case_ids is None:
                case_ids = [item["source_case"]] if item.get("source_case") else []
            reference = item.get("variant_reference")
            for case_id in case_ids:
                result[case_id][reference].update(item.get("profiles", []))
    return result


def _load_membership_evidence(root: Path, expected_sources: dict[str, str], by_id: dict[str, dict]):
    candidate_path = root / MEMBERSHIP_DRAFT
    if candidate_path.exists():
        candidate = json.loads(candidate_path.read_text())
        if candidate.get("schema_version") != 1 or candidate.get("source_digests") != expected_sources:
            raise ValueError("Case membership draft is stale or has an unsupported schema")
        entries = candidate.get("cases")
        if not isinstance(entries, list) or {entry.get("case_id") for entry in entries} != set(by_id):
            raise ValueError("Case membership draft must account for every approved case exactly once")
        result = defaultdict(lambda: defaultdict(set))
        for entry in entries:
            case = by_id[entry["case_id"]]
            if entry.get("case_digest") != case["case_digest"] or entry.get("role") != case["role"]:
                raise ValueError(f"Case membership source identity changed: {entry['case_id']}")
            profiles = entry.get("profiles")
            if not isinstance(profiles, list) or not profiles:
                raise ValueError(f"Missing case membership: {entry['case_id']}")
            references = case.get("covers_variants") or [None]
            for reference in references:
                result[entry["case_id"]][reference].update(profiles)
        return result, [candidate_path]

    paths = draft_paths(root)
    if not paths:
        raise ValueError("No reviewed membership drafts found")
    drafts = [json.loads(path.read_text()) for path in paths]
    for path, draft in zip(paths, drafts):
        if draft.get("source_digests") != expected_sources:
            raise ValueError(f"Stale source digests in {path.relative_to(root)}")
    return _case_reference_profiles(drafts), paths


def build_inventory(root: Path = ROOT) -> dict:
    coverage_document = yaml.safe_load((root / "tests/coverage.yaml").read_text())
    cases_document = yaml.safe_load((root / "tests/cases.yaml").read_text())
    cases = cases_document["cases"]
    by_id = {case["id"]: case for case in cases}
    if len(by_id) != len(cases):
        raise ValueError("Duplicate approved case ID")

    expected_sources = {path: source_digest(root, path) for path in SOURCES}
    reference_profiles, membership_sources = _load_membership_evidence(root, expected_sources, by_id)
    unknown_cases = sorted(set(reference_profiles) - set(by_id))
    if unknown_cases:
        raise ValueError(f"Membership evidence references unknown cases: {unknown_cases[:3]}")

    rows = []
    for case in cases:
        case_id = case["id"]
        by_reference = reference_profiles.get(case_id, {})
        expected_references = set(case.get("covers_variants") or [None])
        actual_references = set(by_reference)
        missing_references = sorted(
            ("<owner>" if value is None else value)
            for value in expected_references - actual_references
        )
        extra_references = sorted(
            ("<owner>" if value is None else value)
            for value in actual_references - expected_references
        )
        profiles = sorted({profile for values in by_reference.values() for profile in values})
        invalid_profiles = sorted(set(profiles) - set(PROFILES))
        role_mismatches = sorted(profile for profile in profiles if PROFILE_ROLES.get(profile) != case["role"])

        if missing_references or extra_references or invalid_profiles or role_mismatches or not profiles:
            classification = 4
            reason = "Membership evidence is missing or invalid; the case cannot yet enter a complete profile."
        elif len(profiles) > 1:
            classification = 2
            reason = "Reuse the unchanged approved case in multiple functional profiles."
        else:
            classification = 1
            reason = "Reuse the unchanged approved case in its single functional profile."

        rows.append({
            "case_id": case_id,
            "obligation": case["obligation"],
            "role": case["role"],
            "level_source": "tests/coverage.yaml",
            "mode": case["mode"],
            "milestone": case["milestone"],
            "profiles": profiles,
            "classification": classification,
            "classification_reason": reason,
            "implementation_status": "APPROVED_CASE_REGISTRY_IMPLEMENTATION",
            "approval_status": "PROFILE_MEMBERSHIP_REVIEW_REQUIRED",
            "variant_references": list(case.get("covers_variants") or []),
            "variant_plan": case.get("variant_plan") or [],
            "variant_groups": case.get("variant_groups") or [],
            "controls": case.get("controls") or [],
            "requires": case.get("requires") or {},
            "case_digest": case["case_digest"],
            "missing_membership_references": missing_references,
            "extra_membership_references": extra_references,
        })

    counts = Counter(row["classification"] for row in rows)
    by_profile = {profile: sum(profile in row["profiles"] for row in rows) for profile in PROFILES}
    case_owners = {(case["obligation"], case["role"]) for case in cases}
    non_executable = []
    for requirement in coverage_document["requirements"]:
        for obligation in requirement["obligations"]:
            for role in obligation["roles"]:
                if (obligation["key"], role) in case_owners:
                    continue
                if obligation["testability"] != "NOT_OBSERVABLE":
                    raise ValueError(f"Observable owner has no approved case: {obligation['key']}#{role}")
                section = str(requirement["section"])
                if section != "2.3":
                    raise ValueError(f"Non-executable profile membership needs review: {obligation['key']}#{role}")
                non_executable.append({
                    "obligation": obligation["key"],
                    "role": role,
                    "profiles": [f"browser_sso_{role}"],
                    "review_disposition": "PENDING",
                })

    return {
        "schema_version": 1,
        "status": "CASE_LEVEL_MIGRATION_INVENTORY_PENDING_INDEPENDENT_MEMBERSHIP_REVIEW",
        "execution_unit": "approved_case",
        "profile_semantics": "profile_is_a_set_of_approved_cases",
        "source_digests": expected_sources,
        "membership_sources": [str(path.relative_to(root)) for path in membership_sources],
        "implementation_evidence": [
            "api/src/test/java/com/samlscope/api/CatalogDocumentsTest.java",
            "runner/src/test/java/com/samlscope/runner/cases/AutomatedCaseRegistryTest.java",
        ],
        "classification_legend": {
            "1": "unchanged case reuse in one profile",
            "2": "unchanged case reuse in multiple profiles; membership/UI work only",
            "3": "case split proven necessary under the stated criteria",
            "4": "genuinely missing or invalid case membership/implementation input",
            "5": "implementation complete; independent approval only",
        },
        "summary": {
            "approved_cases": len(rows),
            "by_classification": {str(key): counts.get(key, 0) for key in range(1, 6)},
            "case_memberships_by_profile": by_profile,
            "runtime_item_count": None,
        },
        "cases": rows,
        "non_executable_obligations": non_executable,
    }


def review_candidate(inventory: dict) -> dict:
    """Compact replacement for the historical per-variant item proposals."""
    return {
        "schema_version": 1,
        "status": "PENDING_INDEPENDENT_CASE_MEMBERSHIP_REVIEW_NOT_EXECUTABLE",
        "execution_unit": "approved_case",
        "source_digests": inventory["source_digests"],
        "review_rules": [
            "A functional profile is a set of approved cases.",
            "Variants, controls, conditions and alternative groups remain inside their approved case.",
            "A case split requires an incompatible target configuration or flow, an independent verdict or user-visible function, or evidence that the existing case cannot attribute correctly.",
            "This draft does not authorize production execution until independently approved and release-pinned.",
        ],
        "cases": [
            {
                "case_id": row["case_id"],
                "case_digest": row["case_digest"],
                "obligation": row["obligation"],
                "role": row["role"],
                "profiles": row["profiles"],
                "classification": row["classification"],
                "review_disposition": "PENDING",
            }
            for row in inventory["cases"]
        ],
        "non_executable_obligations": inventory["non_executable_obligations"],
    }


def profile_release_candidates(inventory: dict, version: str = "functional-case-v1-draft") -> dict[str, dict]:
    """Create loader-shaped review candidates without granting release approval."""
    releases = {}
    for profile in PROFILES:
        releases[profile] = {
            "schema_version": 1,
            "version": version,
            "profile": profile,
            "source_digests": inventory["source_digests"],
            "cases": [
                {"id": row["case_id"], "digest": row["case_digest"]}
                for row in inventory["cases"]
                if profile in row["profiles"]
            ],
            "non_executable_obligations": [
                row["obligation"]
                for row in inventory["non_executable_obligations"]
                if profile in row["profiles"]
            ],
        }
    return releases


def render_markdown(inventory: dict) -> str:
    summary = inventory["summary"]
    lines = [
        "# Case-level functional profile migration inventory",
        "",
        f"Status: `{inventory['status']}`",
        "",
        "The approved case is the execution unit. A functional profile is a set of cases. "
        "Variants, controls and alternative groups remain inside their approved case.",
        "",
        "## Classification",
        "",
        "| Class | Meaning | Cases |",
        "|---:|---|---:|",
    ]
    for key, meaning in inventory["classification_legend"].items():
        lines.append(f"| {key} | {meaning} | {summary['by_classification'][key]} |")
    lines.extend([
        "",
        "Class 5 is intentionally empty until a production case-set definition is frozen and only "
        "independent approval remains. The current membership proposals do not constitute approval.",
        "",
        "## Profile membership candidates",
        "",
        "| Profile | Approved cases |",
        "|---|---:|",
    ])
    for profile, count in summary["case_memberships_by_profile"].items():
        lines.append(f"| `{profile}` | {count} |")
    lines.extend([
        "",
        "These are case memberships, not variant/item counts and not completion claims.",
        "",
        "## Cases requiring a split decision",
        "",
        "A split is not automatic. It is permitted only for incompatible target configuration, a "
        "different communication/browser flow, an independently required verdict, a separate "
        "user-visible function, or evidence that cannot be attributed correctly by the existing case.",
        "",
        "| Case | Owner | Role | Proposed case memberships | Why a split is necessary |",
        "|---|---|---|---|---|",
    ])
    for row in inventory["cases"]:
        if row["classification"] == 3:
            profiles = ", ".join(f"`{profile}`" for profile in row["profiles"])
            lines.append(
                f"| `{row['case_id']}` | `{row['obligation']}` | `{row['role']}` | "
                f"{profiles} | existing case cannot preserve an unambiguous execution or verdict |"
            )
    lines.extend([
        "",
        "The machine-readable JSON retains each case's variant plan, alternative groups, controls, "
        "prerequisites and case digest. It omits an item count because item rows are not runtime tests.",
        "",
    ])
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--json-output", type=Path)
    parser.add_argument("--markdown-output", type=Path)
    parser.add_argument("--write-review-candidate", type=Path)
    parser.add_argument("--release-candidates-dir", type=Path)
    parser.add_argument("--release-version", default="functional-case-v1-draft")
    args = parser.parse_args()
    inventory = build_inventory(args.root)
    json_output = args.json_output or args.root / "build/case-profile-inventory.json"
    markdown_output = args.markdown_output or args.root / "build/case-profile-inventory.md"
    json_output.parent.mkdir(parents=True, exist_ok=True)
    markdown_output.parent.mkdir(parents=True, exist_ok=True)
    json_output.write_text(json.dumps(inventory, indent=2) + "\n")
    markdown_output.write_text(render_markdown(inventory))
    if args.write_review_candidate:
        args.write_review_candidate.parent.mkdir(parents=True, exist_ok=True)
        args.write_review_candidate.write_text(json.dumps(review_candidate(inventory), indent=2) + "\n")
    if args.release_candidates_dir:
        args.release_candidates_dir.mkdir(parents=True, exist_ok=True)
        for profile, document in profile_release_candidates(inventory, args.release_version).items():
            (args.release_candidates_dir / f"{profile}.json").write_text(
                json.dumps(document, indent=2) + "\n"
            )
    print(json.dumps(inventory["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
