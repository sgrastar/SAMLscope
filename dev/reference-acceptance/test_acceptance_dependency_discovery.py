from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


sys.path.insert(0, str(Path(__file__).parent))
import acceptance_dependency_discovery as discovery


class DependencyDiscoveryTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="dependency-discovery-test-")
        self.addCleanup(self.temporary.cleanup)
        self.repo = Path(self.temporary.name)
        (self.repo / "runner").mkdir()
        (self.repo / "settings.gradle.kts").write_text('include("runner")')
        (self.repo / "runner/build.gradle.kts").write_text('plugins { `java-library` }')
        self.jar = self.repo / "dependency.jar"
        self.jar.write_bytes(b"public test dependency")
        self.calls = patch.object(discovery, "_discover", return_value=str(self.jar)).start()
        self.addCleanup(patch.stopall)

    def test_eight_requests_discover_once_but_scope_outside_remains_fresh(self):
        with discovery.dependency_discovery_scope():
            for _ in range(8):
                self.assertEqual(str(self.jar), discovery.runtime_classpath(self.repo))
            self.assertEqual(1, self.calls.call_count)
        discovery.runtime_classpath(self.repo)
        discovery.runtime_classpath(self.repo)
        self.assertEqual(3, self.calls.call_count)
        with discovery.dependency_discovery_scope():
            discovery.runtime_classpath(self.repo)
        self.assertEqual(4, self.calls.call_count)

    def test_input_change_refuses_reuse_without_new_discovery(self):
        with discovery.dependency_discovery_scope():
            discovery.runtime_classpath(self.repo)
            (self.repo / "runner/build.gradle.kts").write_text('plugins { `application` }')
            with self.assertRaisesRegex(ValueError, "inputs changed"):
                discovery.runtime_classpath(self.repo)
        self.assertEqual(1, self.calls.call_count)

    def test_new_input_and_environment_change_refuse_reuse(self):
        with discovery.dependency_discovery_scope():
            discovery.runtime_classpath(self.repo)
            (self.repo / "gradle.properties").write_text("publicFlag=true")
            with self.assertRaisesRegex(ValueError, "inputs changed"):
                discovery.runtime_classpath(self.repo)
        with discovery.dependency_discovery_scope():
            discovery.runtime_classpath(self.repo)
            with patch.dict("os.environ", {"JAVA_TOOL_OPTIONS": "-Dpublic.test=true"}):
                with self.assertRaisesRegex(ValueError, "inputs changed"):
                    discovery.runtime_classpath(self.repo)

    def test_dependency_file_change_refuses_reuse(self):
        with discovery.dependency_discovery_scope():
            discovery.runtime_classpath(self.repo)
            self.jar.write_bytes(b"changed public dependency")
            with self.assertRaisesRegex(ValueError, "files changed"):
                discovery.runtime_classpath(self.repo)
        self.assertEqual(1, self.calls.call_count)

    def test_exception_discards_scope_and_nested_scope_restores_outer(self):
        with self.assertRaisesRegex(RuntimeError, "test failure"):
            with discovery.dependency_discovery_scope():
                discovery.runtime_classpath(self.repo)
                raise RuntimeError("test failure")
        self.assertIsNone(discovery._SCOPE.get())
        discovery.runtime_classpath(self.repo)
        with discovery.dependency_discovery_scope():
            discovery.runtime_classpath(self.repo)
            with discovery.dependency_discovery_scope():
                discovery.runtime_classpath(self.repo)
            discovery.runtime_classpath(self.repo)
        self.assertEqual(4, self.calls.call_count)

    def test_failed_discovery_is_never_reused(self):
        self.calls.side_effect = [subprocess.CalledProcessError(1, "gradle"), str(self.jar)]
        with discovery.dependency_discovery_scope():
            with self.assertRaises(subprocess.CalledProcessError):
                discovery.runtime_classpath(self.repo)
            self.assertEqual(str(self.jar), discovery.runtime_classpath(self.repo))
        self.assertEqual(2, self.calls.call_count)

    def test_distinct_project_configuration_never_borrows_classpath(self):
        with discovery.dependency_discovery_scope():
            discovery.runtime_classpath(self.repo)
            discovery.runtime_classpath(self.repo, ":api")
            discovery.runtime_classpath(self.repo, configuration="compileClasspath")
        self.assertEqual(3, self.calls.call_count)

    def test_input_change_during_discovery_is_rejected(self):
        def changing(*_):
            (self.repo / "settings.gradle.kts").write_text('include("runner", "api")')
            return str(self.jar)
        self.calls.side_effect = changing
        with discovery.dependency_discovery_scope():
            with self.assertRaisesRegex(ValueError, "during discovery"):
                discovery.runtime_classpath(self.repo)
        self.assertIsNone(discovery._SCOPE.get())

    def test_gradle_user_properties_init_addition_and_removal_refuse_reuse(self):
        with tempfile.TemporaryDirectory(prefix="public-gradle-user-input-") as user:
            home = Path(user)
            for name in ("gradle.properties", "init.gradle", "init.gradle.kts", "init.d/public.gradle", "init.d/public.gradle.kts"):
                path = home / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("// public mock configuration")
            with patch.dict("os.environ", {"GRADLE_USER_HOME": str(home)}):
                with discovery.dependency_discovery_scope():
                    discovery.runtime_classpath(self.repo)
                    (home / "gradle.properties").write_text("// changed public configuration")
                    with self.assertRaisesRegex(ValueError, "inputs changed"):
                        discovery.runtime_classpath(self.repo)
                with discovery.dependency_discovery_scope():
                    discovery.runtime_classpath(self.repo)
                    (home / "init.d/new.gradle.kts").write_text("// new public initialization")
                    with self.assertRaisesRegex(ValueError, "inputs changed"):
                        discovery.runtime_classpath(self.repo)
                with discovery.dependency_discovery_scope():
                    discovery.runtime_classpath(self.repo)
                    (home / "init.gradle").unlink()
                    with self.assertRaisesRegex(ValueError, "inputs changed"):
                        discovery.runtime_classpath(self.repo)


if __name__ == "__main__":
    unittest.main()
