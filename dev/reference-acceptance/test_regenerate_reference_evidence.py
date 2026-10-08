import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import urllib.parse
import zipfile

import regenerate_reference_evidence as bridge


class ScopedBridgeTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='public-generation-bridge-test-')
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.repo = self.base / 'repo'; self.repo.mkdir()
        (self.repo / 'settings.gradle.kts').write_text('include("runner", "api")')
        self.qualification = self.base / 'qualified'; self.qualification.mkdir()
        self.deps = self.qualification / 'isolated-compile/dependencies/runtime'; self.deps.mkdir(parents=True)
        self.external = self.base / 'dependencies'; self.external.mkdir()
        for name in ('one.jar', 'two.jar'):
            (self.external / name).write_bytes(name.encode())
            (self.deps / name).write_bytes(name.encode())
        self.project = self.repo / 'runner-0.1.0.jar'; self.project.write_bytes(b'public project original')
        self.project_deps = self.qualification / 'runtime-built'; self.project_deps.mkdir()
        for name in sorted(bridge.PROJECTS):
            (self.project_deps / name).write_bytes(('qualified foundation ' + name).encode())
        sources = self.qualification / 'isolated-compile/sources/runner/main'; sources.mkdir(parents=True)
        (sources / 'Foundation.java').write_bytes(b'public class Foundation {}')
        self.source_proof = {
            'schema': 'samlscope-project-isolated-overlay-qualification-v1',
            'projectJars': {p.name: bridge.sha(p.read_bytes()) for p in self.project_deps.iterdir()},
            'runtimeDependencySha256': {p.name: bridge.sha(p.read_bytes()) for p in self.deps.iterdir()},
            'testCount': 1, 'packagedReplayExitCode': 0, 'archiveUnchangedAfterTesting': True,
            'mainClassSourcesBoundToArchive': True, 'signedProtectedSourcesIncluded': False,
            'unrelatedWorktreeSourcesIncluded': False, 'allArchiveLinkCountsOne': True,
            'sourceSha256': {'runner/src/main/java/Foundation.java': bridge.sha((sources / 'Foundation.java').read_bytes())},
            'sourceSnapshotSha256': {'runner/main/Foundation.java': bridge.sha((sources / 'Foundation.java').read_bytes())}}
        self.source_proof['testedArchiveSha256'] = self.source_proof['projectJars'].copy()
        self.source_proof['parentRuntimeDependencySha256'] = self.source_proof['runtimeDependencySha256'].copy()
        self.proof = {'healthStatus': 200, 'liveMatchesIndependentArchive': True,
                      'liveMatchesHostDistribution': True, 'liveDependenciesMatchQualifiedParent': True,
                      'projectJars': self.source_proof['projectJars'].copy(),
                      'runtimeDependencySha256': {p.name: bridge.sha(p.read_bytes()) for p in self.deps.iterdir()}}
        self.write_proofs()
        self.legacy = self.base / 'classpath.txt'
        def discover(repo, project, configuration):
            paths = [self.external / 'one.jar', self.project]
            if project == ':api': paths.insert(1, self.external / 'two.jar')
            return ':'.join(map(str, paths))
        self.calls = patch.object(bridge.discovery, '_discover', side_effect=discover).start()
        self.addCleanup(patch.stopall)

    def guard(self):
        return bridge.LegacyBridge(self.repo, self.qualification, self.legacy)

    def write_proofs(self):
        (self.qualification / 'runtime-live-verification.json').write_text(json.dumps(self.proof))
        (self.qualification / 'isolated-test-overlay.json').write_text(json.dumps(self.source_proof))

    def test_many_reads_are_checked_two_discoveries_archived_foundation_cleanup(self):
        with bridge.discovery.dependency_discovery_scope():
            guard = self.guard()
            with guard.active():
                for _ in range(4):
                    paths = self.legacy.read_text().strip().split(':')
                    self.assertEqual(paths, [str(p.resolve()) for p in sorted(self.deps.iterdir())]
                                     + [str(p.resolve()) for p in sorted(self.project_deps.iterdir())])
                    self.assertNotIn(str(self.project), paths)
                self.assertEqual(str(self.external / 'one.jar') + ':' + str(self.project),
                                 bridge.discovery.runtime_classpath(self.repo))
                self.assertEqual(2, self.calls.call_count)
                self.assertEqual(4, guard.legacy_reads)
            self.assertFalse(self.legacy.exists())
            self.assertIsNotNone(bridge.discovery._SCOPE.get())
        self.assertIsNone(bridge.discovery._SCOPE.get())

    def test_exception_also_removes_own_unmodified_bridge(self):
        with bridge.discovery.dependency_discovery_scope():
            with self.assertRaisesRegex(RuntimeError, 'normal verifier failed'):
                with self.guard().active(): raise RuntimeError('normal verifier failed')
        self.assertFalse(self.legacy.exists())

    def test_existing_or_symlink_bridge_is_never_replaced_or_removed(self):
        for symlink in (False, True):
            if symlink: self.legacy.symlink_to(self.external / 'one.jar')
            else: self.legacy.write_bytes(b'foreign original')
            original = self.legacy.read_bytes()
            with bridge.discovery.dependency_discovery_scope():
                with self.assertRaises(FileExistsError):
                    with self.guard().active(): self.fail('not reached')
            self.assertEqual(original, self.legacy.read_bytes())
            self.legacy.unlink()

    def test_altered_compatibility_payload_is_preserved_and_fails(self):
        with bridge.discovery.dependency_discovery_scope():
            with self.assertRaisesRegex(ValueError, 'altered legacy bridge'):
                with self.guard().active():
                    self.legacy.write_bytes(b'altered public path fixture')
                    self.legacy.read_text()
        self.assertEqual(b'altered public path fixture', self.legacy.read_bytes())

    def test_changed_gradle_input_is_rejected_before_legacy_use(self):
        with bridge.discovery.dependency_discovery_scope():
            with self.assertRaisesRegex(ValueError, 'Gradle inputs changed'):
                with self.guard().active():
                    (self.repo / 'settings.gradle.kts').write_text('include("different")')
                    self.legacy.read_text()
        self.assertFalse(self.legacy.exists())

    def test_changed_discovered_or_qualified_dependency_is_rejected(self):
        for folder in (self.external, self.deps):
            with bridge.discovery.dependency_discovery_scope():
                with self.assertRaises(ValueError):
                    with self.guard().active():
                        (folder / 'one.jar').write_bytes(b'changed public dependency')
                        self.legacy.read_text()
            self.assertFalse(self.legacy.exists())
            (folder / 'one.jar').write_bytes(b'one.jar')

    def test_qualification_changed_is_rejected(self):
        with bridge.discovery.dependency_discovery_scope():
            with self.assertRaisesRegex(ValueError, 'Qualification changed'):
                with self.guard().active():
                    (self.qualification / 'runtime-live-verification.json').write_text('{}')
                    self.legacy.read_text()
        self.assertFalse(self.legacy.exists())

    def test_wrong_deployed_dependency_version_stops_before_file_creation(self):
        (self.external / 'two.jar').write_bytes(b'wrong version')
        with bridge.discovery.dependency_discovery_scope():
            with self.assertRaisesRegex(ValueError, 'differs from qualified runtime'):
                with self.guard().active(): self.fail('not reached')
        self.assertFalse(self.legacy.exists())

    def test_missing_complete_api_member_stops_before_file_creation(self):
        self.calls.side_effect = lambda *_: str(self.external / 'one.jar') + ':' + str(self.project)
        with bridge.discovery.dependency_discovery_scope():
            with self.assertRaisesRegex(ValueError, 'Complete API graph differs'):
                with self.guard().active(): self.fail('not reached')
        self.assertFalse(self.legacy.exists())

    def test_runner_standalone_version_is_not_added_to_deployed_api_replay(self):
        older = self.external / 'one-older.jar'
        older.write_bytes(b'older transitive logging dependency')
        def discover(repo, project, configuration):
            values = [older, self.project] if project == ':runner' else [
                self.external / 'one.jar', self.external / 'two.jar', self.project]
            return ':'.join(map(str, values))
        self.calls.side_effect = discover
        with bridge.discovery.dependency_discovery_scope():
            with self.guard().active():
                supplied = self.legacy.read_text().strip().split(':')
                self.assertNotIn(str(older), supplied)
                self.assertEqual(set(supplied), {str(p.resolve()) for folder in (self.deps, self.project_deps)
                                               for p in folder.iterdir()})
                self.assertIn(str(older), bridge.discovery.runtime_classpath(self.repo))
        self.assertFalse(self.legacy.exists())

    def test_runner_standalone_file_drift_still_rejects_generation(self):
        older = self.external / 'one-older.jar'
        older.write_bytes(b'older transitive logging dependency')
        original = self.calls.side_effect
        self.calls.side_effect = lambda repo, project, configuration: (
            str(older) + ':' + str(self.project) if project == ':runner' else
            original(repo, project, configuration))
        with bridge.discovery.dependency_discovery_scope():
            with self.assertRaises(ValueError):
                with self.guard().active():
                    older.write_bytes(b'changed standalone dependency')
                    self.legacy.read_text()
        self.assertFalse(self.legacy.exists())

    def test_foreign_inode_substitution_is_retained(self):
        with bridge.discovery.dependency_discovery_scope():
            with self.assertRaisesRegex(ValueError, 'foreign or altered legacy bridge'):
                with self.guard().active():
                    replacement = self.base / 'replacement.txt'
                    replacement.write_bytes(b'foreign replacement')
                    replacement.replace(self.legacy)
                    self.legacy.read_text()
        self.assertEqual(b'foreign replacement', self.legacy.read_bytes())

    def test_unqualified_project_hash_or_incomplete_inventory_is_rejected(self):
        self.source_proof['testedArchiveSha256']['core-0.1.0.jar'] = '0' * 64
        self.write_proofs()
        with self.assertRaisesRegex(ValueError, 'packaged source qualification'):
            self.guard()
        self.source_proof['testedArchiveSha256'] = self.source_proof['projectJars'].copy()
        self.proof['projectJars'].pop('core-0.1.0.jar')
        self.write_proofs()
        with self.assertRaisesRegex(ValueError, 'project inventory differs'):
            self.guard()
        self.assertFalse(self.legacy.exists())

    def test_changed_project_archive_or_source_snapshot_is_rejected_on_each_read(self):
        for path in (self.project_deps / 'core-0.1.0.jar',
                     self.qualification / 'isolated-compile/sources/runner/main/Foundation.java'):
            raw = path.read_bytes()
            with bridge.discovery.dependency_discovery_scope():
                with self.assertRaises(ValueError):
                    with self.guard().active():
                        path.write_bytes(b'changed public qualified fixture')
                        self.legacy.read_text()
            self.assertFalse(self.legacy.exists())
            path.write_bytes(raw)

    def test_hardlinked_or_symlink_project_archive_is_rejected(self):
        path = self.project_deps / 'core-0.1.0.jar'
        original = path.read_bytes()
        other = self.base / 'shared-core.jar'; other.write_bytes(original)
        path.unlink(); os.link(other, path)
        with self.assertRaisesRegex(ValueError, 'independent'):
            self.guard()
        path.unlink(); path.symlink_to(other)
        with self.assertRaisesRegex(ValueError, 'regular original'):
            self.guard()
        self.assertFalse(self.legacy.exists())

    def test_source_qualification_replacement_is_rejected_on_each_read(self):
        with bridge.discovery.dependency_discovery_scope():
            with self.assertRaisesRegex(ValueError, 'Source qualification changed'):
                with self.guard().active():
                    (self.qualification / 'isolated-test-overlay.json').write_text('{}')
                    self.legacy.read_text()
        self.assertFalse(self.legacy.exists())

    def test_old_reader_prefix_wins_and_missing_foundation_compiles_and_runs(self):
        # Real javac/java resolution demonstrates both requirements together:
        # a duplicate Reader in the new foundation cannot shadow the old one,
        # while a type absent from the old archive is supplied by the foundation.
        def jar(name, source, target):
            folder = self.base / (name + '-' + target.stem); folder.mkdir()
            path = folder / (name + '.java'); path.write_text(source)
            subprocess.run(['javac', '-d', str(folder), str(path)], check=True, capture_output=True)
            with zipfile.ZipFile(target, 'w') as archive:
                archive.write(folder / (name + '.class'), name + '.class')
        old = self.base / 'old-runner.jar'
        jar('OldReader', 'public class OldReader { public static String oldOnly() { return "old"; } }', old)
        newer = self.base / 'new-reader.jar'
        jar('OldReader', 'public class OldReader { public static String value() { return "new"; } }', newer)
        (self.project_deps / 'runner-0.1.0.jar').write_bytes(newer.read_bytes())
        jar('Foundation', 'public class Foundation { public static String value() { return "foundation"; } }',
            self.project_deps / 'core-0.1.0.jar')
        for folder in (self.deps, self.project_deps):
            for path in folder.iterdir():
                if path.name not in ('runner-0.1.0.jar', 'core-0.1.0.jar'):
                    with zipfile.ZipFile(path, 'w') as archive: pass
        self.source_proof['projectJars'] = {p.name: bridge.sha(p.read_bytes()) for p in self.project_deps.iterdir()}
        self.source_proof['testedArchiveSha256'] = self.source_proof['projectJars'].copy()
        self.proof['projectJars'] = self.source_proof['projectJars'].copy()
        self.proof['runtimeDependencySha256'] = {p.name: bridge.sha(p.read_bytes()) for p in self.deps.iterdir()}
        self.source_proof['runtimeDependencySha256'] = self.proof['runtimeDependencySha256'].copy()
        self.source_proof['parentRuntimeDependencySha256'] = self.proof['runtimeDependencySha256'].copy()
        for path in self.external.iterdir(): path.write_bytes((self.deps / path.name).read_bytes())
        self.write_proofs()
        helper = self.base / 'CheckPrefix.java'
        helper.write_text('public class CheckPrefix { public static void main(String[] x) { '
                          'System.out.println(OldReader.oldOnly() + ":" + Foundation.value()); '
                          'System.out.println(OldReader.class.getProtectionDomain().getCodeSource().getLocation()); '
                          'System.out.print(Foundation.class.getProtectionDomain().getCodeSource().getLocation()); } }')
        with bridge.discovery.dependency_discovery_scope():
            with self.guard().active():
                classpath = str(old) + ':' + self.legacy.read_text().strip()
                subprocess.run(['javac', '-cp', classpath, '-d', str(self.base), str(helper)],
                               check=True, capture_output=True)
                result = subprocess.run(['java', '-cp', str(self.base) + ':' + classpath, 'CheckPrefix'],
                                        check=True, capture_output=True, text=True)
                values = result.stdout.splitlines()
                self.assertEqual('old:foundation', values[0])
                self.assertEqual([old.resolve(), (self.project_deps / 'core-0.1.0.jar').resolve()],
                                 [Path(urllib.parse.urlparse(value).path).resolve() for value in values[1:]])
        self.assertFalse(self.legacy.exists())

    def test_extra_project_or_unbound_source_is_rejected_before_bridge_creation(self):
        extra = self.project_deps / 'unexpected-project.jar'; extra.write_bytes(b'extra fixture')
        with self.assertRaisesRegex(ValueError, 'project directory differs'):
            self.guard()
        extra.unlink()
        self.source_proof['sourceSnapshotSha256']['runner/main/Unbound.java'] = '0' * 64
        self.write_proofs()
        with self.assertRaisesRegex(ValueError, 'source snapshot binding differs'):
            self.guard()
        self.assertFalse(self.legacy.exists())


if __name__ == '__main__': unittest.main()
