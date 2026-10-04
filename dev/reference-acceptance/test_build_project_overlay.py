"""Host-only tests for immutable project-overlay qualification inputs."""

import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest

import build_project_overlay as overlay


def digest(data):
    return hashlib.sha256(data).hexdigest()


class OverlayGuardTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def write(self, relative, data=b"public fixture"):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path

    def pins(self, parent, **fields):
        parent.mkdir(parents=True, exist_ok=True)
        (parent / "isolated-test-overlay.json").write_text(json.dumps(fields))

    def dependency_fixture(self, suffix=""):
        parent = self.root / ("parent" + suffix)
        lib = self.root / ("runtime-lib" + suffix)
        dependencies = [self.write(lib.relative_to(self.root) / "alpha.jar", b"alpha"),
                        self.write(lib.relative_to(self.root) / "beta.jar", b"beta")]
        for name in overlay.PROJECT_JARS:
            self.write(lib.relative_to(self.root) / name, name.encode())
        expected = {str(path): digest(path.read_bytes()) for path in dependencies}
        # JUnit pins share the legacy record but are not runtime dependencies.
        expected[str(self.root / "unavailable-gradle-cache" / "junit.jar")] = digest(b"junit")
        self.pins(parent, dependencySha256=expected)
        runtime = {"imageId": "sha256:" + "a" * 64, "suiteContainerId": "b" * 64}
        runtime_file = parent / "runtime-live-verification.json"
        runtime_file.write_text(json.dumps(runtime))
        proof = {"schema": "samlscope-runtime-third-party-verification-v1",
                 **runtime,
                 "parentRuntimeVerificationSha256": overlay.sha(runtime_file),
                 "thirdPartyJars": {path.name: digest(path.read_bytes()) for path in dependencies},
                 "liveEqualsHostAndQualifiedParent": True}
        (parent / "runtime-third-party-verification.json").write_text(json.dumps(proof))
        return parent, lib, dependencies, expected

    def archive_fixture(self, suffix=""):
        archive = self.root / ("archive" + suffix)
        for name in overlay.PROJECT_JARS:
            self.write(archive.relative_to(self.root) / name, ("original:" + name).encode())
        return archive


class QualifiedRuntimeDependenciesTest(OverlayGuardTest):
    def test_legacy_pins_select_exact_runtime_inventory_and_ignore_project_and_junit_jars(self):
        parent, lib, dependencies, _ = self.dependency_fixture()

        actual = overlay.qualified_runtime_dependencies(parent, lib)

        self.assertEqual(set(dependencies), set(actual))
        self.assertEqual(len(dependencies), len(actual))
        self.assertTrue(all(path.parent == lib for path in actual))

    def test_changed_missing_or_extra_runtime_dependency_is_rejected(self):
        for mutation in ("changed", "missing", "extra"):
            with self.subTest(mutation=mutation):
                parent, lib, dependencies, _ = self.dependency_fixture("-" + mutation)
                if mutation == "changed":
                    dependencies[0].write_bytes(b"different version")
                elif mutation == "missing":
                    dependencies[0].unlink()
                else:
                    self.write(lib.relative_to(self.root) / "unqualified.jar", b"extra")

                with self.assertRaises((RuntimeError, ValueError, OSError)):
                    overlay.qualified_runtime_dependencies(parent, lib)

    def test_duplicate_direct_runtime_basename_is_rejected_even_with_equal_digest(self):
        parent, lib, dependencies, expected = self.dependency_fixture()
        # Distinct JSON keys normalize to the same direct runtime dependency.
        expected[str(lib) + "/./" + dependencies[0].name] = digest(dependencies[0].read_bytes())
        self.pins(parent, dependencySha256=expected)

        with self.assertRaises((RuntimeError, ValueError, OSError)):
            overlay.qualified_runtime_dependencies(parent, lib)

    def test_modern_basename_pins_match_legacy_and_actual_runtime_proof(self):
        parent, lib, dependencies, legacy = self.dependency_fixture()
        modern = {path.name: digest(path.read_bytes()) for path in dependencies}
        self.pins(parent, dependencySha256=legacy, runtimeDependencySha256=modern)

        self.assertEqual(set(dependencies), set(overlay.qualified_runtime_dependencies(parent, lib)))

    def test_modern_and_legacy_pin_conflict_is_rejected(self):
        parent, lib, dependencies, legacy = self.dependency_fixture()
        modern = {path.name: digest(path.read_bytes()) for path in dependencies}
        legacy[str(dependencies[0])] = digest(b"stale legacy entry")
        self.pins(parent, dependencySha256=legacy, runtimeDependencySha256=modern)

        with self.assertRaises((RuntimeError, ValueError, OSError)):
            overlay.qualified_runtime_dependencies(parent, lib)

    def test_missing_or_mismatched_parent_runtime_proof_is_rejected(self):
        for mutation in ("missing-proof", "missing-runtime", "schema", "hash", "image", "container",
                         "jar-bytes", "missing-jar", "extra-jar", "not-bound"):
            with self.subTest(mutation=mutation):
                parent, lib, dependencies, _ = self.dependency_fixture("-proof-" + mutation)
                proof_file = parent / "runtime-third-party-verification.json"
                proof = json.loads(proof_file.read_text())
                if mutation == "missing-proof":
                    proof_file.unlink()
                elif mutation == "missing-runtime":
                    (parent / "runtime-live-verification.json").unlink()
                else:
                    if mutation == "schema":
                        proof["schema"] = "foreign-proof-schema"
                    elif mutation == "hash":
                        proof["parentRuntimeVerificationSha256"] = digest(b"different runtime proof")
                    elif mutation == "image":
                        proof["imageId"] = "sha256:" + "c" * 64
                    elif mutation == "container":
                        proof["suiteContainerId"] = "d" * 64
                    elif mutation == "jar-bytes":
                        proof["thirdPartyJars"][dependencies[0].name] = digest(b"different native JAR")
                    elif mutation == "missing-jar":
                        proof["thirdPartyJars"].pop(dependencies[0].name)
                    elif mutation == "extra-jar":
                        proof["thirdPartyJars"]["foreign.jar"] = digest(b"foreign native JAR")
                    else:
                        proof["liveEqualsHostAndQualifiedParent"] = False
                    proof_file.write_text(json.dumps(proof))

                with self.assertRaises((RuntimeError, ValueError, OSError)):
                    overlay.qualified_runtime_dependencies(parent, lib)

    def test_parent_runtime_proof_digest_binds_raw_bytes_not_only_parsed_fields(self):
        parent, lib, _, _ = self.dependency_fixture()
        runtime_file = parent / "runtime-live-verification.json"
        original_fields = json.loads(runtime_file.read_text())
        runtime_file.write_bytes(runtime_file.read_bytes() + b"\n")
        self.assertEqual(original_fields, json.loads(runtime_file.read_text()))

        with self.assertRaises((RuntimeError, ValueError, OSError)):
            overlay.qualified_runtime_dependencies(parent, lib)

    def test_modern_pins_reject_path_keys_and_incorrect_digest(self):
        for mutation in ("path-key", "digest"):
            with self.subTest(mutation=mutation):
                parent, lib, dependencies, legacy = self.dependency_fixture("-modern-" + mutation)
                modern = {path.name: digest(path.read_bytes()) for path in dependencies}
                if mutation == "path-key":
                    modern["nested/" + dependencies[0].name] = modern.pop(dependencies[0].name)
                else:
                    modern[dependencies[0].name] = digest(b"wrong pinned bytes")
                self.pins(parent, dependencySha256=legacy, runtimeDependencySha256=modern)

                with self.assertRaises((RuntimeError, ValueError, OSError)):
                    overlay.qualified_runtime_dependencies(parent, lib)


class IndependentSnapshotCopyTest(OverlayGuardTest):
    def test_copy_preserves_pinned_bytes_and_is_independent_of_hardlinked_source(self):
        source = self.write("source/input.jar", b"pinned input")
        alias = source.with_name("input-alias.jar")
        os.link(source, alias)
        target = self.root / "snapshot/input.jar"
        target.parent.mkdir()

        actual = overlay.copy_independent_snapshot(source, target, digest(b"pinned input"))

        self.assertEqual(target, actual)
        self.assertEqual(b"pinned input", target.read_bytes())
        self.assertEqual(1, target.stat().st_nlink)
        self.assertFalse(target.is_symlink())
        self.assertFalse(os.path.samefile(source, target))
        source.write_bytes(b"later mutable source")
        self.assertEqual(b"pinned input", target.read_bytes())

    def test_wrong_source_hash_and_symbolic_source_are_rejected(self):
        source = self.write("source/input.jar", b"pinned input")
        symbolic = source.with_name("symbolic.jar")
        symbolic.symlink_to(source)
        for selected, expected in ((source, digest(b"wrong input")),
                                   (symbolic, digest(b"pinned input"))):
            with self.subTest(source=selected.name):
                target = self.root / ("snapshot-" + selected.name)
                with self.assertRaises((RuntimeError, ValueError, OSError)):
                    overlay.copy_independent_snapshot(selected, target, expected)

    def test_existing_regular_symbolic_and_hardlinked_targets_are_preserved(self):
        source = self.write("source/input.jar", b"new input")
        for kind in ("regular", "symbolic", "hardlinked"):
            with self.subTest(kind=kind):
                sentinel = self.write("existing-" + kind + "/sentinel.jar", b"existing bytes")
                target = sentinel.with_name("target.jar")
                if kind == "regular":
                    target.write_bytes(b"existing bytes")
                elif kind == "symbolic":
                    target.symlink_to(sentinel)
                else:
                    os.link(sentinel, target)

                with self.assertRaises((RuntimeError, ValueError, OSError)):
                    overlay.copy_independent_snapshot(source, target, digest(b"new input"))

                self.assertEqual(b"existing bytes", sentinel.read_bytes())
                self.assertEqual(b"existing bytes", target.read_bytes())


class TestResourceSnapshotTest(OverlayGuardTest):
    def test_same_named_resource_roots_keep_complete_independent_trees(self):
        source_roots = []
        for module in ("runner", "saml"):
            resource = self.root / module / "src/test/resources"
            self.write(resource.relative_to(self.root) / "nested/fixture.json", module.encode())
            self.write(resource.relative_to(self.root) / ".hidden", b"")
            (resource / "empty-directory").mkdir()
            source_roots.append(resource)
        target = self.root / "resource-snapshot"

        copies, expected = overlay.snapshot_test_resources(source_roots, target)

        self.assertEqual(2, len(copies))
        self.assertEqual(2, len(set(copies)))
        self.assertEqual({b"runner", b"saml"},
                         {(copy / "nested/fixture.json").read_bytes() for copy in copies})
        for copy in copies:
            self.assertTrue(copy.is_relative_to(target))
            self.assertEqual(b"", (copy / ".hidden").read_bytes())
            self.assertTrue((copy / "empty-directory").is_dir())
        actual_files = {str(path.relative_to(target)): digest(path.read_bytes())
                        for path in target.rglob("*") if path.is_file()}
        self.assertEqual(actual_files, expected)
        self.assertTrue(all((target / relative).stat().st_nlink == 1 for relative in expected))
        source_roots[0].joinpath("nested/fixture.json").write_bytes(b"changed source")
        self.write(source_roots[0].relative_to(self.root) / "later.json", b"new source file")
        overlay.require_snapshot_unchanged(target, expected)
        self.assertEqual({b"runner", b"saml"},
                         {(copy / "nested/fixture.json").read_bytes() for copy in copies})

    def test_absent_resource_roots_are_skipped(self):
        absent = self.root / "peer/src/test/resources"
        source = self.write("runner/src/test/resources/fixture.json", b"fixture").parent
        target = self.root / "resource-snapshot"

        copies, expected = overlay.snapshot_test_resources([absent, source], target)

        self.assertEqual(1, len(copies))
        self.assertEqual(b"fixture", (copies[0] / "fixture.json").read_bytes())
        self.assertEqual(1, len(expected))
        overlay.require_snapshot_unchanged(target, expected)

    def test_symbolic_resource_files_and_directories_are_rejected(self):
        outside = self.write("outside/fixture.json", b"outside")
        for kind in ("file", "directory"):
            with self.subTest(kind=kind):
                source = self.root / ("resources-" + kind)
                source.mkdir()
                (source / "linked").symlink_to(outside if kind == "file" else outside.parent,
                                              target_is_directory=kind == "directory")
                with self.assertRaises((RuntimeError, ValueError, OSError)):
                    overlay.snapshot_test_resources([source], self.root / ("snapshot-" + kind))

    def test_snapshot_changes_additions_removals_links_and_renames_are_rejected(self):
        for mutation in ("changed", "added", "removed", "renamed", "symlink", "directory-symlink", "hardlink"):
            with self.subTest(mutation=mutation):
                root = self.root / ("snapshot-" + mutation)
                file = self.write(root.relative_to(self.root) / "nested/fixture.json", b"original")
                expected = {"nested/fixture.json": digest(b"original")}
                overlay.require_snapshot_unchanged(root, expected)
                if mutation == "changed":
                    file.write_bytes(b"changed")
                elif mutation == "added":
                    self.write(root.relative_to(self.root) / "unrecorded.json", b"added")
                elif mutation == "removed":
                    file.unlink()
                elif mutation == "renamed":
                    file.rename(file.with_name("renamed.json"))
                elif mutation == "symlink":
                    outside = self.write("outside-" + mutation + "/fixture.json", b"original")
                    file.unlink()
                    file.symlink_to(outside)
                elif mutation == "directory-symlink":
                    outside = self.root / "empty-outside"
                    outside.mkdir()
                    (root / "unrecorded-directory").symlink_to(outside, target_is_directory=True)
                else:
                    # Keep the file inventory unchanged so only the link guard detects this.
                    os.link(file, self.root / "outside-resource-alias.json")

                with self.assertRaises((RuntimeError, ValueError, OSError)):
                    overlay.require_snapshot_unchanged(root, expected)
                self.assertEqual({"nested/fixture.json": digest(b"original")}, expected)


class ProjectArchiveGuardTest(OverlayGuardTest):
    def test_exact_six_independent_project_jars_are_hashed(self):
        archive = self.archive_fixture()

        actual = overlay.archive_hashes(archive)

        expected = {name: digest(("original:" + name).encode()) for name in overlay.PROJECT_JARS}
        self.assertEqual(expected, actual)
        overlay.require_archive_unchanged(archive, actual)

    def test_archive_inventory_and_file_aliases_are_rejected(self):
        for mutation in ("missing", "extra", "symlink", "hardlink"):
            with self.subTest(mutation=mutation):
                archive = self.archive_fixture("-" + mutation)
                file = archive / overlay.PROJECT_JARS[0]
                if mutation == "missing":
                    file.unlink()
                elif mutation == "extra":
                    self.write(archive.relative_to(self.root) / "unqualified.jar", b"extra")
                elif mutation == "symlink":
                    outside = self.write("archive-outside/" + file.name, file.read_bytes())
                    file.unlink()
                    file.symlink_to(outside)
                else:
                    os.link(file, self.root / "outside-alias.jar")

                with self.assertRaises((RuntimeError, ValueError, OSError)):
                    overlay.archive_hashes(archive)

    def test_archive_bytes_and_inventory_must_remain_equal_to_validated_hashes(self):
        for mutation in ("changed", "missing", "extra"):
            with self.subTest(mutation=mutation):
                archive = self.archive_fixture("-replay-" + mutation)
                expected = overlay.archive_hashes(archive)
                file = archive / overlay.PROJECT_JARS[-1]
                if mutation == "changed":
                    file.write_bytes(b"changed during replay")
                elif mutation == "missing":
                    file.unlink()
                else:
                    self.write(archive.relative_to(self.root) / "unexpected.jar", b"new during replay")

                with self.assertRaises((RuntimeError, ValueError, OSError)):
                    overlay.require_archive_unchanged(archive, expected)

    def test_incomplete_or_extra_expected_archive_inventory_is_rejected(self):
        archive = self.archive_fixture()
        original = overlay.archive_hashes(archive)
        for mutation in ("missing", "extra"):
            with self.subTest(mutation=mutation):
                expected = dict(original)
                if mutation == "missing":
                    expected.pop(overlay.PROJECT_JARS[0])
                else:
                    expected["foreign.jar"] = digest(b"foreign")
                with self.assertRaises((RuntimeError, ValueError, OSError)):
                    overlay.require_archive_unchanged(archive, expected)


class DockerfileParentBindingTest(unittest.TestCase):
    def test_qualified_tag_is_used_and_actual_image_id_is_kept_as_a_comment(self):
        runtime = {"image": "samlscope:qualified-parent", "imageId": "sha256:" + "a" * 64}
        actual = overlay.dockerfile_for_qualified_parent(runtime, ["runner-0.1.0.jar"])

        self.assertIn("# Qualified parent image ID: " + runtime["imageId"] + "\n", actual)
        self.assertIn("requires exact image-ID verification", actual)
        self.assertIn("\nFROM samlscope:qualified-parent\n", actual)
        self.assertNotIn("FROM sha256:", actual)
        self.assertTrue(actual.endswith("COPY runner-0.1.0.jar /opt/samlscope/lib/\n"))

    def test_raw_image_id_cannot_be_misrepresented_as_a_parent_tag(self):
        runtime = {"image": "sha256:" + "a" * 64, "imageId": "sha256:" + "a" * 64}
        with self.assertRaises(RuntimeError):
            overlay.dockerfile_for_qualified_parent(runtime, ["runner-0.1.0.jar"])

    def test_missing_or_multiline_parent_reference_is_rejected(self):
        for value in ({"imageId": "sha256:" + "a" * 64},
                      {"image": "samlscope:parent\nRUN false", "imageId": "sha256:" + "a" * 64},
                      {"image": "samlscope:parent", "imageId": "unqualified"}):
            with self.subTest(value=value):
                with self.assertRaises(RuntimeError):
                    overlay.dockerfile_for_qualified_parent(value, ["runner-0.1.0.jar"])


if __name__ == "__main__":
    unittest.main()
