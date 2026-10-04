"""Check discovery sharing without replacing any signature helper execution."""
from pathlib import Path
import json
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


sys.path.insert(0, str(Path(__file__).parent))
import acceptance_dependency_discovery as discovery
import verify_ssp_metadata_signature_acceptance as signature
import verify_ssp_metadata_signature_consumer_acceptance as consumer


class SspSignatureDependencyWiringTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="ssp-discovery-wiring-")
        self.addCleanup(self.temporary.cleanup)
        self.repo = Path(self.temporary.name).resolve()
        source = self.repo / "dev/reference-acceptance"
        source.mkdir(parents=True)
        (self.repo / "settings.gradle.kts").write_text('include("runner", "api")')
        for project in ("runner", "api"):
            (self.repo / project).mkdir()
            (self.repo / project / "build.gradle.kts").write_text('plugins { `java-library` }')
        self.dependencies = {}
        for project in (":runner", ":api"):
            jar = self.repo / (project[1:] + "-dependency.jar")
            jar.write_bytes((project + " public test dependency").encode())
            self.dependencies[project] = str(jar)
        self.folder = self.repo / "campaign"
        self.folder.mkdir()
        self.runtime = self.folder / "runtime"
        self.runtime.mkdir()
        (self.runtime / "runtime-runner.jar").write_bytes(b"captured Runner archive")
        self.replays = {
            "VerifyMetadataSignatureEvidence": ("metadata-signature-replay.json", b'{"proof":"signature"}\n'),
            "VerifyMetadataSignatureRejections": ("native-signature-rejection-replay.json", b'{"proof":"rejections"}\n'),
            "VerifyMetadataSignatureCampaign": ("production-case-replay.json", b'{"proof":"cases"}\n'),
        }
        for helper, (filename, raw) in self.replays.items():
            (source / (helper + ".java")).write_text("// Public wiring-test source\n")
            (self.folder / filename).write_bytes(raw)
        (self.repo / "tests").mkdir()
        (self.repo / "tests/cases.yaml").write_text("cases: []\n")
        self.addCleanup(patch.stopall)
        patch.object(signature, "__file__", str(source / "verify_ssp_metadata_signature_acceptance.py")).start()
        patch.object(consumer, "__file__", str(source / "verify_ssp_metadata_signature_consumer_acceptance.py")).start()
        self.discoveries = patch.object(discovery, "_discover", side_effect=self.discover).start()
        self.commands = []
        # Both modules use the same subprocess module; patch its one command seam.
        self.process = patch.object(subprocess, "run", side_effect=self.execute).start()

    def discover(self, repository, project, configuration):
        self.assertEqual(self.repo, repository)
        self.assertEqual("runtimeClasspath", configuration)
        return self.dependencies[project]

    def execute(self, argv, **kwargs):
        self.commands.append((list(argv), kwargs))
        self.assertEqual(self.repo, kwargs["cwd"])
        self.assertTrue(kwargs["check"])
        self.assertTrue(kwargs["capture_output"])
        if argv[0] == "javac":
            self.assertTrue(all(Path(item).is_file() for item in argv if str(item).endswith(".java")))
        elif argv[0] == "java":
            helper = argv[3].rsplit(".", 1)[-1]
            self.assertEqual(str(self.folder), argv[4])
            Path(argv[5]).write_bytes(self.replays[helper][1])
            if helper == "VerifyMetadataSignatureCampaign":
                self.assertEqual(str(self.repo / "tests/cases.yaml"), argv[6])
            else:
                self.assertEqual(6, len(argv))
        else:
            self.fail("Unexpected command: " + argv[0])
        return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

    def gate(self):
        return signature.replay_production_reader(self.folder, self.runtime)

    def helpers(self):
        return consumer.replay_helpers(self.folder, self.runtime)

    def test_scope_shares_runner_but_keeps_api_distinct_and_executes_all_helpers(self):
        with discovery.dependency_discovery_scope():
            # Existing generator users may discover runner before these SSP callers.
            discovery.runtime_classpath(self.repo, project=":runner")
            self.gate()
            self.gate()
            self.helpers()
        self.assertIsNone(discovery._SCOPE.get())
        self.assertEqual([":runner", ":api"], [call.args[1] for call in self.discoveries.call_args_list])
        compiles = [argv for argv, _ in self.commands if argv[0] == "javac"]
        executions = [argv for argv, _ in self.commands if argv[0] == "java"]
        self.assertEqual(3, len(compiles))
        self.assertEqual([
            "VerifyMetadataSignatureEvidence", "VerifyMetadataSignatureEvidence",
            "VerifyMetadataSignatureRejections", "VerifyMetadataSignatureCampaign",
        ], [argv[3].rsplit(".", 1)[-1] for argv in executions])
        runner = str(self.runtime / "runtime-runner.jar")
        for index, argv in enumerate(compiles):
            project = ":runner" if index < 2 else ":api"
            self.assertEqual(runner + ":" + self.dependencies[project], argv[2])
        for index, argv in enumerate(executions):
            project = ":runner" if index < 2 else ":api"
            self.assertTrue(argv[2].endswith(":" + runner + ":" + self.dependencies[project]))
        self.assertEqual([
            "VerifyMetadataSignatureRejections.java", "VerifyMetadataSignatureCampaign.java",
        ], [Path(item).name for item in compiles[-1] if str(item).endswith(".java")])

    def test_standalone_calls_discover_fresh_and_reexecute(self):
        self.gate()
        self.gate()
        self.helpers()
        self.helpers()
        self.assertEqual([":runner", ":runner", ":api", ":api"],
                         [call.args[1] for call in self.discoveries.call_args_list])
        self.assertEqual(4, sum(argv[0] == "javac" for argv, _ in self.commands))
        self.assertEqual(6, sum(argv[0] == "java" for argv, _ in self.commands))

    def test_new_generation_does_not_keep_dependency_or_replay_results(self):
        for _ in range(2):
            with discovery.dependency_discovery_scope():
                self.gate()
                self.gate()
        self.assertEqual(2, self.discoveries.call_count)
        self.assertEqual(4, sum(argv[0] == "java" for argv, _ in self.commands))

    def test_signature_gate_requires_identical_retained_bytes(self):
        filename, raw = self.replays["VerifyMetadataSignatureEvidence"]
        (self.folder / filename).write_text(json.dumps(json.loads(raw), indent=2))
        with self.assertRaisesRegex(AssertionError, "retained replay differs"):
            self.gate()

    def test_each_consumer_helper_requires_identical_retained_bytes(self):
        for helper in ("VerifyMetadataSignatureRejections", "VerifyMetadataSignatureCampaign"):
            with self.subTest(helper=helper):
                filename, raw = self.replays[helper]
                (self.folder / filename).write_text(json.dumps(json.loads(raw), indent=2))
                with self.assertRaisesRegex(AssertionError, "retained production replay differs: " + filename):
                    self.helpers()
                (self.folder / filename).write_bytes(raw)

    def test_discovery_failure_propagates_before_compile_and_can_retry(self):
        failure = subprocess.CalledProcessError(1, "gradle")
        self.discoveries.side_effect = failure
        with discovery.dependency_discovery_scope():
            for replay in (self.gate, self.helpers):
                with self.assertRaises(subprocess.CalledProcessError) as caught:
                    replay()
                self.assertIs(failure, caught.exception)
            self.assertEqual([], self.commands)
            self.discoveries.side_effect = self.discover
            self.gate()
            self.helpers()
        self.assertEqual(4, self.discoveries.call_count)

    def test_compile_failure_propagates_without_running_java(self):
        failure = subprocess.CalledProcessError(1, "javac")
        for replay in (self.gate, self.helpers):
            with self.subTest(replay=replay.__name__):
                self.process.reset_mock()
                self.process.side_effect = failure
                with self.assertRaises(subprocess.CalledProcessError) as caught:
                    replay()
                self.assertIs(failure, caught.exception)
                self.assertEqual(1, self.process.call_count)
                self.assertEqual("javac", self.process.call_args.args[0][0])

    def test_java_failure_propagates_without_substituting_retained_result(self):
        failure = subprocess.CalledProcessError(1, "java")

        def fail_java(argv, **kwargs):
            if argv[0] == "java":
                raise failure
            return self.execute(argv, **kwargs)

        self.process.side_effect = fail_java
        for replay in (self.gate, self.helpers):
            with self.subTest(replay=replay.__name__):
                with self.assertRaises(subprocess.CalledProcessError) as caught:
                    replay()
                self.assertIs(failure, caught.exception)


if __name__ == "__main__":
    unittest.main()
