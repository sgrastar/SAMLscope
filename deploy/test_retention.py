import datetime as dt
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch
import shutil
from retention import maintain


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
            self.assertEqual([], db.execute("PRAGMA foreign_key_check").fetchall())
        second = maintain(self.root, NOW, apply=True, service_stopped=True)
        self.assertEqual([], second["privateRuns"])
        self.assertEqual([], second["publishedTranscriptEntries"])

    def test_apply_requires_explicit_stop_confirmation(self):
        with self.assertRaises(ValueError):
            maintain(self.root, NOW, apply=True)

    def test_unknown_schema_is_rejected_before_file_deletion(self):
        with self.connect() as db:
            db.execute("INSERT INTO schema_migrations VALUES (8, ?)", (NOW.isoformat(),))
        before = self.snapshot()
        with self.assertRaises(ValueError):
            maintain(self.root, NOW, apply=True, service_stopped=True)
        self.assertEqual(before, self.snapshot())

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
