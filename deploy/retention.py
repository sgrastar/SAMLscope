#!/usr/bin/env python3
"""Offline hosted retention. Preview by default; apply only to a stopped service.

Non-anonymous private Runs expire from creation; published Transcript entries expire individually
from recording. Published results and reusable Plans are retained.
"""
import argparse
import datetime as dt
import json
from pathlib import Path
import re
import shutil
import sqlite3

SUPPORTED_SCHEMA_VERSION = 14
SUPPORTED_MIGRATIONS = (1, 2, 3, 4, 5, 6, 7, 8, 11, 12, 13, 14)


def validate_schema(db):
    versions = tuple(row[0] for row in db.execute("SELECT version FROM schema_migrations ORDER BY version"))
    if versions != SUPPORTED_MIGRATIONS:
        raise ValueError("Unsupported database schema; migrate with the matching application first")
    # These inputs belong to a Run, including published Runs. Deleting their parent
    # must remove them; expiring only published Transcripts must preserve them.
    for table, value in (("supplemental_decryption_keys", "document_json"),
                         ("run_shared_key_commitments", "key_sha256")):
        db.execute(f"SELECT run_id, {value} FROM {table} LIMIT 0")
        foreign_keys = db.execute(f"PRAGMA foreign_key_list({table})").fetchall()
        if len(foreign_keys) != 1 or foreign_keys[0][2:5] != ("runs", "run_id", "id") \
                or foreign_keys[0][6] != "CASCADE":
            raise ValueError("Unsupported Run input ownership; cascade deletion required")


def instant(value):
    result = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    if result.tzinfo is None:
        raise ValueError("Retention timestamps must include a timezone")
    return result


def run_id(value):
    if not re.fullmatch(r"run_[0-9A-HJKMNP-TV-Z]{26}", value):
        raise ValueError("Invalid Run identifier")
    return value


def safe_path(root, relative):
    path = root / relative
    if Path(relative).is_absolute() or ".." in Path(relative).parts:
        raise ValueError("Unsafe evidence reference")
    current = root
    for part in Path(relative).parts:
        current = current / part
        if current.is_symlink():
            raise ValueError("Symlink in evidence path")
    if not path.resolve().is_relative_to(root):
        raise ValueError("Evidence path escapes data directory")
    return path


def maintain(data_directory, now, *, apply=False, service_stopped=False, anonymous_confirmations=()):
    if apply and not service_stopped:
        raise ValueError("Apply requires a stopped service and --service-stopped")
    if now.tzinfo is None:
        raise ValueError("Retention clock must include a timezone")
    root = Path(data_directory).resolve(strict=True)
    database = root / "samlscope.db"
    if not database.exists():
        database = root / "samlier.db"
    if not database.is_file() or database.is_symlink():
        raise ValueError("Existing regular SQLite database required")
    mode = "rw" if apply else "ro"
    with sqlite3.connect(database.as_uri() + "?mode=" + mode, uri=True) as db:
        db.execute("PRAGMA foreign_keys = ON")
        db.execute("BEGIN IMMEDIATE" if apply else "BEGIN")
        validate_schema(db)
        db.execute("SELECT run_id, entry_count, stored_bytes FROM transcript_usage LIMIT 0")
        db.execute("SELECT singleton, entry_count, stored_bytes FROM transcript_global_usage LIMIT 0")
        # A current provider check must be supplied by a trusted operator/integration.
        # No confirmation means candidate reporting only, never destructive expiry.
        candidates = []
        for identifier, role, status, created, last_used, version in db.execute(
                "SELECT id, role, status, created_at, last_used_at, version FROM application_users"):
            if role == "ANONYMOUS" and status == "ACTIVE" and instant(last_used or created) <= now - dt.timedelta(days=30):
                candidates.append({"id": identifier, "version": version, "lastUsedAt": last_used,
                                   "expiresAt": (instant(last_used or created) + dt.timedelta(days=30)).isoformat()})
        by_id = {row["id"]: row for row in candidates}
        expired_users = []
        for confirmation in anonymous_confirmations:
            candidate = by_id.get(confirmation.get("id"))
            if candidate is None or confirmation.get("isAnonymous") is not True:
                raise ValueError("Anonymous expiry confirmation does not match a current candidate")
            if confirmation.get("version") != candidate["version"] or confirmation.get("lastUsedAt") != candidate["lastUsedAt"]:
                raise ValueError("Account changed since expiry confirmation")
            verified = instant(confirmation["verifiedAt"])
            if not now - dt.timedelta(minutes=5) <= verified <= now:
                raise ValueError("A fresh account-state verification is required")
            if candidate["id"] in expired_users:
                raise ValueError("Duplicate account-state confirmation")
            expired_users.append(candidate["id"])
        expired_plans = []
        expired_runs = []
        for user in expired_users:
            expired_plans.extend(row[0] for row in db.execute(
                "SELECT plan_id FROM hosted_plan_owners WHERE owner_id = ?", (user,)))
        for plan in expired_plans:
            if not re.fullmatch(r"plan_[0-9A-HJKMNP-TV-Z]{26}", plan):
                raise ValueError("Invalid Plan identifier")
            expired_runs.extend(run_id(row[0]) for row in db.execute("SELECT id FROM runs WHERE plan_id = ?", (plan,)))
        private = [run_id(row[0]) for row in db.execute(
            "SELECT r.id, r.created_at FROM runs r LEFT JOIN published_runs p "
            "ON p.run_id = r.id LEFT JOIN hosted_plan_owners o ON o.plan_id = r.plan_id "
            "LEFT JOIN application_users u ON u.id = o.owner_id "
            "WHERE p.run_id IS NULL AND COALESCE(u.role, '') <> 'ANONYMOUS'")
            if instant(row[1]) <= now - dt.timedelta(days=30)]
        entries = []
        paths = set()
        for plan in expired_plans:
            paths.update((f"keys/{plan}", f"target-metadata/{plan}.xml"))
        for identifier in set(private + expired_runs):
            paths.update((f"transcripts/{identifier}", f"results/{identifier}",
                          f"target-metadata/{identifier}.xml"))
        for identifier, owner, recorded, document in db.execute(
                "SELECT t.id, t.run_id, t.timestamp, t.document_json FROM transcript_entries t "
                "JOIN published_runs p ON p.run_id = t.run_id"):
            if instant(recorded) > now - dt.timedelta(days=90):
                continue
            owner = run_id(owner)
            value = json.loads(document)
            for field in ("bodyRef", "decodedSamlRef"):
                reference = value.get(field)
                if reference:
                    if not re.fullmatch(
                            rf"transcripts/{owner}/tx_[0-9A-HJKMNP-TV-Z]{{26}}\.(body|saml\.xml)", reference):
                        raise ValueError("Unexpected Transcript reference")
                    paths.add(reference)
            entries.append(identifier)
        # Validate the whole deletion set before touching any files.
        resolved = [safe_path(root, relative) for relative in sorted(paths)]
        for path in resolved:
            if path.is_dir() and any(child.is_symlink() for child in path.rglob("*")):
                raise ValueError("Symlink inside evidence directory")
        summary = {"mode": "apply" if apply else "preview", "asOf": now.isoformat(),
                   "privateRuns": private, "publishedTranscriptEntries": entries,
                   "paths": sorted(paths), "anonymousExpiryCandidates": candidates,
                   "expiredAnonymousUsers": expired_users, "expiredAnonymousPlans": expired_plans,
                   "anonymousExpiry": "verified-confirmations-only"}
        if apply:
            # Keep rows until file deletion succeeds. On failure leave the service
            # stopped and retry; removed expired files are intentionally not restored.
            for path in resolved:
                if path.is_dir():
                    shutil.rmtree(path)
                else:
                    path.unlink(missing_ok=True)
            db.executemany("DELETE FROM plans WHERE id = ?", [(value,) for value in expired_plans])
            for user in expired_users:
                db.execute("DELETE FROM target_metadata_revisions WHERE connection_id IN "
                           "(SELECT id FROM target_connections WHERE owner_id = ?)", (user,))
                db.execute("DELETE FROM target_connections WHERE owner_id = ?", (user,))
                db.execute("DELETE FROM application_users WHERE id = ?", (user,))
            db.executemany("DELETE FROM runs WHERE id = ?", [(value,) for value in private])
            db.executemany("DELETE FROM transcript_entries WHERE id = ?", [(value,) for value in entries])
            db.execute("""UPDATE transcript_usage SET
                entry_count = (SELECT COUNT(*) FROM transcript_entries t WHERE t.run_id = transcript_usage.run_id),
                stored_bytes = (SELECT COALESCE(SUM(
                    COALESCE(json_extract(t.document_json, '$.bodyBytes'), 0) +
                    COALESCE(json_extract(t.document_json, '$.decodedSamlBytes'), 0)), 0)
                    FROM transcript_entries t WHERE t.run_id = transcript_usage.run_id)""")
            db.execute("""UPDATE transcript_global_usage SET
                entry_count = (SELECT COUNT(*) FROM transcript_entries),
                stored_bytes = (SELECT COALESCE(SUM(
                    COALESCE(json_extract(document_json, '$.bodyBytes'), 0) +
                    COALESCE(json_extract(document_json, '$.decodedSamlBytes'), 0)), 0)
                    FROM transcript_entries) WHERE singleton = 1""")
            if db.execute("PRAGMA foreign_key_check").fetchall():
                raise ValueError("Foreign key check failed; keep service stopped")
        else:
            db.rollback()
        return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", required=True)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--service-stopped", action="store_true")
    parser.add_argument("--anonymous-confirmations", type=Path,
                        help="Trusted current provider-state confirmations; omitted while UserInfo integration is pending")
    args = parser.parse_args()
    confirmations = json.loads(args.anonymous_confirmations.read_text()) if args.anonymous_confirmations else []
    result = maintain(args.data_dir, dt.datetime.now(dt.timezone.utc),
                      apply=args.apply, service_stopped=args.service_stopped, anonymous_confirmations=confirmations)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
