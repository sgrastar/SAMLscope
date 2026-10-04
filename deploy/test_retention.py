import datetime as dt
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch
import shutil
from retention import SUPPORTED_SCHEMA_VERSION, maintain


NOW = dt.datetime(2026, 9, 7, tzinfo=dt.timezone.utc)


class RetentionTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.database = self.root / "samlscope.db"
        self.old, self.fresh, self.published = ["run_" + letter * 26 for letter in "ABC"]
        with self.connect() as db:
            for migration in sorted((Path(__file__).resolve().parents[1] /
                    "store/src/main/resources/db/migration").glob("*.sql")):
                db.executescript(migration.read_text())
                db.execute("INSERT INTO schema_migrations VALUES (?, ?)",
                           (int(migration.name[1:4]), NOW.isoformat()))
            db.execute("INSERT INTO plans VALUES (?, '{}', ?, ?)",
                       ("plan_" + "A" * 26, NOW.isoformat(), NOW.isoformat()))
            for run, age in ((self.old, 30), (self.fresh, 29), (self.published, 100)):
                created = (NOW - dt.timedelta(days=age)).isoformat()
                db.execute("INSERT INTO runs VALUES (?, ?, 'COMPLETED', '{}', ?, ?)",
                           (run, "plan_" + "A" * 26, created, created))
                for ref in (f"results/{run}/result.json", f"target-metadata/{run}.xml"):
                    self.write(ref)
                db.execute("INSERT INTO supplemental_decryption_keys VALUES (?, ?)",
                           (run, json.dumps({"fixture": run})))
                db.execute("INSERT INTO run_shared_key_commitments VALUES (?, ?)", (run, "a" * 64))
            db.execute("INSERT INTO published_runs VALUES (?, ?)", (self.published, NOW.isoformat()))
            for letter, run, age in (("A", self.old, 30), ("B", self.fresh, 1),
                                     ("C", self.published, 90), ("D", self.published, 1)):
                identifier = "tx_" + letter * 26
                reference = f"transcripts/{run}/{identifier}.body"
                self.write(reference)
                db.execute("INSERT INTO transcript_entries VALUES (?, ?, ?, ?)",
                           (identifier, run, (NOW - dt.timedelta(days=age)).isoformat(),
                            json.dumps({"bodyRef": reference, "bodyBytes": 7, "decodedSamlBytes": 0})))
            db.execute("INSERT INTO transcript_usage(run_id, entry_count, stored_bytes) "
                       "SELECT run_id, count(*), count(*) * 7 FROM transcript_entries GROUP BY run_id")
            db.execute("UPDATE transcript_global_usage SET entry_count=4, stored_bytes=28")

    def connect(self):
        db = sqlite3.connect(self.database)
        db.execute("PRAGMA foreign_keys=ON")
        return db

    def write(self, reference):
        path = self.root / reference
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"fixture")

    def snapshot(self):
        return {str(p.relative_to(self.root)): p.read_bytes()
                for p in self.root.rglob("*") if p.is_file()}

    def anonymous(self, days=31):
        identifier = "oidc:" + "a" * 64
        used = (NOW - dt.timedelta(days=days)).isoformat()
        with self.connect() as db:
            db.execute("INSERT INTO application_users(id, role, created_at, last_used_at, enrolled) "
                       "VALUES (?, 'ANONYMOUS', ?, ?, 1)", (identifier, used, used))
            for (plan,) in db.execute("SELECT id FROM plans").fetchall():
                db.execute("INSERT OR REPLACE INTO hosted_plan_owners(plan_id, owner_id) VALUES (?, ?)", (plan, identifier))
                self.write(f"keys/{plan}/private.pem")
                self.write(f"target-metadata/{plan}.xml")
            db.execute("INSERT INTO target_connections VALUES ('target', ?, '{}')", (identifier,))
            db.execute("INSERT INTO target_metadata_revisions VALUES ('target', 'revision', '{}', '{}')")
        return {"id": identifier, "version": 0, "lastUsedAt": used,
                "isAnonymous": True, "verifiedAt": NOW.isoformat()}

    def test_anonymous_expiry_without_provider_confirmation_is_preview_only(self):
        self.anonymous()
        report = maintain(self.root, NOW, apply=True, service_stopped=True)
        self.assertEqual(1, len(report["anonymousExpiryCandidates"]))
        self.assertEqual([], report["expiredAnonymousUsers"])
        self.assertEqual([], report["privateRuns"])
        self.assertTrue((self.root / "results" / self.old).exists())
        self.assertTrue((self.root / "results" / self.published).exists())

    def test_confirmed_expiry_removes_entire_account_including_public_reports(self):
        confirmation = self.anonymous()
        report = maintain(self.root, NOW, apply=True, service_stopped=True,
                          anonymous_confirmations=[confirmation])
        self.assertEqual([confirmation["id"]], report["expiredAnonymousUsers"])
        with self.connect() as db:
            for table in ("application_users", "plans", "runs", "published_runs", "transcript_entries",
                          "target_connections", "target_metadata_revisions", "hosted_plan_owners",
                          "supplemental_decryption_keys", "run_shared_key_commitments"):
                self.assertEqual(0, db.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0], table)
            self.assertEqual([], db.execute("PRAGMA foreign_key_check").fetchall())
        self.assertFalse((self.root / "results" / self.published).exists())
        self.assertFalse(any((self.root / "keys").glob("*/private.pem")))

    def test_expiry_rejects_stale_state_upgrade_activity_and_unverified_status(self):
        confirmation = self.anonymous()
        for bad in ({**confirmation, "verifiedAt": (NOW - dt.timedelta(minutes=6)).isoformat()},
                    {**confirmation, "version": 1}, {**confirmation, "isAnonymous": False},
                    {**confirmation, "lastUsedAt": NOW.isoformat()}):
            before = self.snapshot()
            with self.assertRaises(ValueError):
                maintain(self.root, NOW, apply=True, service_stopped=True, anonymous_confirmations=[bad])
            self.assertEqual(before, self.snapshot())
        with self.connect() as db:
            db.execute("UPDATE application_users SET role='USER', version=1")
        with self.assertRaises(ValueError):
            maintain(self.root, NOW, apply=True, service_stopped=True, anonymous_confirmations=[confirmation])
        with self.connect() as db:
            db.execute("UPDATE application_users SET role='ANONYMOUS', version=0, last_used_at=?", (NOW.isoformat(),))
        with self.assertRaises(ValueError):
            maintain(self.root, NOW, apply=True, service_stopped=True, anonymous_confirmations=[confirmation])

    def test_preview_does_not_modify_data(self):
        before = self.snapshot()
        report = maintain(self.root, NOW)
        self.assertEqual([self.old], report["privateRuns"])
        self.assertEqual(["tx_" + "C" * 26], report["publishedTranscriptEntries"])
        self.assertEqual(before, self.snapshot())

    def test_apply_preserves_new_evidence_and_published_results(self):
        maintain(self.root, NOW, apply=True, service_stopped=True)
        self.assertFalse((self.root / "results" / self.old).exists())
        self.assertFalse((self.root / "target-metadata" / (self.old + ".xml")).exists())
        self.assertTrue((self.root / "results" / self.published / "result.json").exists())
        self.assertTrue((self.root / "results" / self.fresh / "result.json").exists())
        with self.connect() as db:
            self.assertEqual(2, db.execute("SELECT count(*) FROM runs").fetchone()[0])
            self.assertEqual((2, 14), db.execute(
                "SELECT entry_count, stored_bytes FROM transcript_global_usage").fetchone())
            self.assertEqual((1, 7), db.execute(
                "SELECT entry_count, stored_bytes FROM transcript_usage WHERE run_id=?",
                (self.published,)).fetchone())
            for table in ("supplemental_decryption_keys", "run_shared_key_commitments"):
                self.assertEqual({self.fresh, self.published},
                                 {row[0] for row in db.execute(f"SELECT run_id FROM {table}")}, table)
            self.assertEqual([], db.execute("PRAGMA foreign_key_check").fetchall())
        second = maintain(self.root, NOW, apply=True, service_stopped=True)
        self.assertEqual([], second["privateRuns"])
        self.assertEqual([], second["publishedTranscriptEntries"])

    def test_apply_requires_explicit_stop_confirmation(self):
        with self.assertRaises(ValueError):
            maintain(self.root, NOW, apply=True)

    def test_unknown_schema_is_rejected_before_file_deletion(self):
        with self.connect() as db:
            next_version = db.execute("SELECT MAX(version) + 1 FROM schema_migrations").fetchone()[0]
            db.execute("INSERT INTO schema_migrations VALUES (?, ?)",
                       (next_version, NOW.isoformat()))
        before = self.snapshot()
        with self.assertRaises(ValueError):
            maintain(self.root, NOW, apply=True, service_stopped=True)
        self.assertEqual(before, self.snapshot())

    def test_supported_schema_matches_the_current_application_migrations(self):
        with self.connect() as db:
            self.assertEqual(SUPPORTED_SCHEMA_VERSION,
                             db.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0])
        maintain(self.root, NOW)

    def test_missing_or_unknown_earlier_migration_is_rejected(self):
        for sql in ("DELETE FROM schema_migrations WHERE version=13",
                    "INSERT INTO schema_migrations VALUES (9, '2026-09-07T00:00:00Z')"):
            with self.connect() as db:
                db.execute(sql)
            before = self.snapshot()
            with self.assertRaises(ValueError):
                maintain(self.root, NOW, apply=True, service_stopped=True)
            self.assertEqual(before, self.snapshot())
            with self.connect() as db:
                db.execute("INSERT OR IGNORE INTO schema_migrations VALUES (13, ?)", (NOW.isoformat(),))
                db.execute("DELETE FROM schema_migrations WHERE version=9")

    def test_run_input_without_cascade_is_rejected_before_deleting_files(self):
        with self.connect() as db:
            db.execute("DROP TABLE supplemental_decryption_keys")
            db.execute("CREATE TABLE supplemental_decryption_keys ("
                       "run_id TEXT PRIMARY KEY REFERENCES runs(id), document_json TEXT NOT NULL)")
        before = self.snapshot()
        with self.assertRaises(ValueError):
            maintain(self.root, NOW, apply=True, service_stopped=True)
        self.assertEqual(before, self.snapshot())

    def test_retention_keeps_administrator_account_and_its_published_inputs(self):
        identifier = "oidc:" + "b" * 64
        with self.connect() as db:
            db.execute("INSERT INTO application_users(id, role, created_at, enrolled, version) "
                       "VALUES (?, 'ADMIN', ?, 1, 4)", (identifier, (NOW - dt.timedelta(days=100)).isoformat()))
            db.execute("INSERT INTO hosted_plan_owners VALUES (?, ?)", ("plan_" + "A" * 26, identifier))
        report = maintain(self.root, NOW, apply=True, service_stopped=True)
        self.assertEqual([], report["expiredAnonymousUsers"])
        self.assertEqual([], report["anonymousExpiryCandidates"])
        with self.connect() as db:
            self.assertEqual(("ADMIN", "ACTIVE", 1, 4), db.execute(
                "SELECT role, status, enrolled, version FROM application_users WHERE id=?", (identifier,)).fetchone())
            for table in ("supplemental_decryption_keys", "run_shared_key_commitments"):
                self.assertEqual(1, db.execute(f"SELECT COUNT(*) FROM {table} WHERE run_id=?",
                                             (self.published,)).fetchone()[0])

    def test_unsafe_reference_aborts_before_any_deletion(self):
        with self.connect() as db:
            db.execute("UPDATE transcript_entries SET document_json=? WHERE id=?",
                       (json.dumps({"bodyRef": "../outside"}), "tx_" + "C" * 26))
        before = self.snapshot()
        with self.assertRaises(ValueError):
            maintain(self.root, NOW, apply=True, service_stopped=True)
        self.assertEqual(before, self.snapshot())

    def test_symlink_aborts_before_any_deletion(self):
        link = self.root / "results" / self.old / "linked"
        link.symlink_to(self.root / "results" / self.fresh, target_is_directory=True)
        with self.assertRaises(ValueError):
            maintain(self.root, NOW, apply=True, service_stopped=True)
        self.assertTrue((self.root / "results" / self.old / "result.json").exists())

    def test_interrupted_file_cleanup_keeps_rows_for_retry(self):
        original = shutil.rmtree

        def fail_transcript_removal(path, *args, **kwargs):
            if Path(path).resolve() == (self.root / "transcripts" / self.old).resolve():
                raise OSError("Simulated storage failure")
            return original(path, *args, **kwargs)

        with patch("retention.shutil.rmtree", side_effect=fail_transcript_removal):
            with self.assertRaises(OSError):
                maintain(self.root, NOW, apply=True, service_stopped=True)
        with self.connect() as db:
            self.assertEqual(1, db.execute("SELECT count(*) FROM runs WHERE id=?",
                                         (self.old,)).fetchone()[0])
        self.assertTrue((self.root / "results" / self.fresh / "result.json").exists())
        maintain(self.root, NOW, apply=True, service_stopped=True)
        with self.connect() as db:
            self.assertEqual(0, db.execute("SELECT count(*) FROM runs WHERE id=?",
                                         (self.old,)).fetchone()[0])


if __name__ == "__main__":
    unittest.main()
