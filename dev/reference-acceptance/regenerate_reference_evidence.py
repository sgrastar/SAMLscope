#!/usr/bin/env python3
"""Generation-scoped legacy dependency bridge; never caches evidence or outcomes."""
import argparse
from contextlib import contextmanager
import hashlib
import importlib
import json
import os
from pathlib import Path
import stat
import sys
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / 'dev/reference-acceptance'))
import acceptance_dependency_discovery as discovery

LEGACY = Path('/private/tmp/samlscope-runner-runtime-classpath.txt')
PROJECTS = {name + '-0.1.0.jar' for name in ('api', 'core', 'peer', 'runner', 'saml', 'store')}
sha = lambda raw: hashlib.sha256(raw).hexdigest()


def require(value, message):
    if not value:
        raise ValueError(message)


def public_file(path, independent=False):
    value = path.lstat()
    require(stat.S_ISREG(value.st_mode) and not path.is_symlink(), 'Dependency must be a regular original file')
    require(not independent or value.st_nlink == 1, 'Qualified dependency must be independent')
    raw = path.read_bytes()
    require(len(raw) == value.st_size, 'Dependency changed while hashing')
    return sha(raw)


class LegacyBridge:
    def __init__(self, repository, qualification, legacy=LEGACY):
        self.repository = Path(repository).resolve(strict=True)
        self.qualification = Path(qualification).resolve(strict=True)
        self.legacy = Path(legacy)
        self.original_runtime = discovery.runtime_classpath
        self.original_read_text = Path.read_text
        self.graphs = {}
        self.legacy_reads = 0
        self.scoped_calls = 0
        self.descriptor = None
        self.identity = None
        self.input_snapshot = discovery._input_snapshot(self.repository)
        self.qualification_file = self.qualification / 'runtime-live-verification.json'
        self.qualification_bytes = self.qualification_file.read_bytes()
        proof = json.loads(self.qualification_bytes)
        require(proof['healthStatus'] == 200 and proof['liveMatchesIndependentArchive'] is True
                and proof['liveMatchesHostDistribution'] is True
                and proof['liveDependenciesMatchQualifiedParent'] is True,
                'Runtime qualification is incomplete')
        self.expected = proof['runtimeDependencySha256']
        require(isinstance(self.expected, dict) and self.expected, 'Qualified dependencies unavailable')
        self.expected_projects = proof['projectJars']
        require(set(self.expected_projects) == PROJECTS, 'Qualified project inventory differs')
        self.source_qualification_file = self.qualification / 'isolated-test-overlay.json'
        self.source_qualification_bytes = self.source_qualification_file.read_bytes()
        source_proof = json.loads(self.source_qualification_bytes)
        require(source_proof['schema'] == 'samlscope-project-isolated-overlay-qualification-v1'
                and source_proof['projectJars'] == source_proof['testedArchiveSha256'] == self.expected_projects
                and source_proof['runtimeDependencySha256'] == source_proof['parentRuntimeDependencySha256'] == self.expected
                and source_proof['testCount'] > 0 and source_proof['packagedReplayExitCode'] == 0
                and source_proof['archiveUnchangedAfterTesting'] is True
                and source_proof['mainClassSourcesBoundToArchive'] is True
                and source_proof['signedProtectedSourcesIncluded'] is False
                and source_proof['unrelatedWorktreeSourcesIncluded'] is False
                and source_proof['allArchiveLinkCountsOne'] is True,
                'Project foundation lacks packaged source qualification')
        self.expected_sources = source_proof['sourceSnapshotSha256']
        require(isinstance(self.expected_sources, dict) and self.expected_sources,
                'Qualified source snapshots unavailable')
        bound_sources = {}
        for name, digest in source_proof['sourceSha256'].items():
            path = Path(name)
            require(not path.is_absolute() and '..' not in path.parts
                    and len(path.parts) > 4 and path.parts[1] == 'src'
                    and path.parts[2] in ('main', 'test') and path.parts[3] == 'java',
                    'Unexpected qualified project source path')
            snapshot = path.parts[0] + '/' + path.parts[2] + '/' + path.name
            require(snapshot not in bound_sources, 'Ambiguous qualified project source snapshot')
            bound_sources[snapshot] = digest
        require(bound_sources == self.expected_sources, 'Qualified source snapshot binding differs')
        self.qualified = self.qualification / 'isolated-compile/dependencies/runtime'
        self.project_directory = self.qualification / 'runtime-built'
        self.project_paths = [self.project_directory / name for name in sorted(self.expected_projects)]
        self.external_paths = [self.qualified / name for name in sorted(self.expected)]
        # Each legacy caller prepends its own archived project JARs. These
        # independently qualified project archives only supply missing modules;
        # they never precede or replace that caller's immutable Reader prefix.
        self.paths = self.external_paths + self.project_paths
        require(set(p.name for p in self.qualified.iterdir()) == set(self.expected), 'Qualified dependency directory differs')
        require(set(p.name for p in self.project_directory.iterdir()) == PROJECTS, 'Qualified project directory differs')
        self.payload = (os.pathsep.join(str(p) for p in self.paths) + '\n').encode()
        self.validate_qualified()

    def validate_qualified(self):
        require(self.qualification_file.read_bytes() == self.qualification_bytes, 'Qualification changed during generation')
        require(self.source_qualification_file.read_bytes() == self.source_qualification_bytes,
                'Source qualification changed during generation')
        require(discovery._input_snapshot(self.repository) == self.input_snapshot, 'Gradle inputs changed during generation')
        for path in self.external_paths:
            require(public_file(path, independent=True) == self.expected[path.name], 'Qualified dependency bytes changed')
        for path in self.project_paths:
            require(public_file(path, independent=True) == self.expected_projects[path.name],
                    'Qualified project foundation bytes changed')
        for name, digest in self.expected_sources.items():
            require(public_file(self.qualification / 'isolated-compile/sources' / name, independent=True) == digest,
                    'Qualified source snapshot bytes changed')

    def graph(self, project, configuration='runtimeClasspath'):
        value = self.original_runtime(self.repository, project=project, configuration=configuration)
        paths = [Path(item) for item in value.split(os.pathsep)]
        hashes = {}
        for path in paths:
            digest = public_file(path)
            require(str(path) not in hashes, 'Duplicate discovered dependency path')
            hashes[str(path)] = digest
            if project == ':api' and path.name not in PROJECTS:
                require(self.expected.get(path.name) == digest, 'Discovered dependency differs from qualified runtime')
        key = (project, configuration)
        if key in self.graphs:
            require(self.graphs[key] == hashes, 'Discovered dependency bytes changed during generation')
        else:
            self.graphs[key] = hashes
        return value

    def initialize(self):
        # The deployed Suite resolves the API graph. A lower transitive version
        # in Runner's standalone graph is not part of that production classpath.
        # Both discoveries remain pinned for drift detection; only the complete
        # API graph supplies the qualified legacy replay external dependencies.
        # Project foundations come exclusively from the source-qualified archive,
        # never from the mutable Gradle project paths observed in these graphs.
        complete = {}
        for project in (':runner', ':api'):
            for item in self.graph(project).split(os.pathsep):
                path = Path(item)
                if project == ':api' and path.name not in PROJECTS:
                    digest = public_file(path)
                    require(path.name not in complete or complete[path.name] == digest, 'Duplicate dependency name has differing bytes')
                    complete[path.name] = digest
        require(complete == self.expected, 'Complete API graph differs from qualified dependency inventory')
        flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, 'O_NOFOLLOW', 0)
        descriptor = os.open(self.legacy, flags, 0o600)
        try:
            with os.fdopen(descriptor, 'wb') as handle:
                handle.write(self.payload)
                handle.flush()
                os.fsync(handle.fileno())
            value = self.legacy.lstat()
            self.identity = value.st_dev, value.st_ino
            self.validate()
        except BaseException:
            if self.identity is None:
                value = self.legacy.lstat()
                self.identity = value.st_dev, value.st_ino
            self.cleanup()
            raise

    def validate(self):
        self.validate_qualified()
        for project, configuration in list(self.graphs):
            self.graph(project, configuration)
        value = self.legacy.lstat()
        require(stat.S_ISREG(value.st_mode) and value.st_nlink == 1
                and (value.st_dev, value.st_ino) == self.identity, 'Legacy bridge ownership changed')
        require(self.legacy.read_bytes() == self.payload, 'Legacy bridge content changed')

    def runtime(self, repository, project=':runner', configuration='runtimeClasspath'):
        require(Path(repository).resolve(strict=True) == self.repository, 'Foreign dependency repository')
        self.scoped_calls += 1
        self.validate()
        return self.graph(project, configuration)

    def read_text(self, path, *args, **kwargs):
        if Path(path) == self.legacy:
            self.legacy_reads += 1
            self.validate()
            value = self.original_read_text(path, *args, **kwargs)
            require(value == self.payload.decode('utf-8'), 'Actual legacy classpath read changed')
            return value
        return self.original_read_text(path, *args, **kwargs)

    def cleanup(self):
        if self.identity is None:
            return
        value = self.legacy.lstat()
        require(stat.S_ISREG(value.st_mode) and not self.legacy.is_symlink()
                and (value.st_dev, value.st_ino) == self.identity
                and self.legacy.read_bytes() == self.payload, 'Refuse removal of foreign or altered legacy bridge')
        self.legacy.unlink()
        self.identity = None

    @contextmanager
    def active(self):
        self.initialize()
        try:
            reader = lambda path, *args, **kwargs: self.read_text(path, *args, **kwargs)
            with patch.object(Path, 'read_text', reader), patch.object(discovery, 'runtime_classpath', self.runtime):
                yield self
            self.validate()
        finally:
            self.cleanup()

    def report(self):
        return {'schema': 'samlscope-generation-scoped-legacy-dependencies-v1',
                'qualificationSha256': sha(self.qualification_bytes),
                'projectSourceQualificationSha256': sha(self.source_qualification_bytes),
                'gradleInputSnapshotSha256': sha(repr(self.input_snapshot).encode()),
                'externalDependencies': self.expected, 'qualifiedCount': len(self.expected),
                'projectFoundationSha256': self.expected_projects,
                'qualifiedProjectSourceSnapshotSha256': self.expected_sources,
                'projectFoundationAuthority': 'independent source-qualified runtime-built archive bound to live project hashes',
                'legacyArchivedProjectPrefixPreserved': True,
                'mutableGradleProjectPathsSupplied': False,
                'dependencyAuthority': 'complete deployed API graph; Runner standalone graph checked separately for drift',
                'discoveryKeys': [{'project': p, 'configuration': c, 'files': len(files)}
                                  for (p, c), files in sorted(self.graphs.items())],
                'legacyReadsChecked': self.legacy_reads, 'scopedDiscoveryRequests': self.scoped_calls,
                'legacyClasspathPayloadSha256': sha(self.payload),
                'temporaryBridgeRemoved': not self.legacy.exists(),
                'evidenceOutcomeCache': False, 'allNormalVerifiersExecuted': True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--generator', choices=('remaining', 'comparison'), required=True)
    parser.add_argument('--evidence-root', type=Path, required=True)
    parser.add_argument('--qualification', type=Path, required=True)
    parser.add_argument('--report', type=Path, required=True)
    parser.add_argument('--definitions', type=Path, default=REPO / 'tests/cases.yaml')
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    module = importlib.import_module('generate_remaining_audit' if args.generator == 'remaining' else 'generate_comparison')
    report = args.report.resolve()
    require(report.is_relative_to(REPO / 'build/acceptance') and not report.exists(), 'Fresh ignored report path required')
    with discovery.dependency_discovery_scope():
        bridge = LegacyBridge(REPO, args.qualification)
        try:
            with bridge.active():
                if args.generator == 'remaining':
                    module.render(args.evidence_root, args.definitions,
                                  args.output or REPO / 'docs/26-unverified-case-inventory.md')
                else:
                    module.render(args.evidence_root,
                                  args.output or REPO / 'docs/23-reference-test-comparison.md')
        except BaseException as error:
            report.write_text(json.dumps({**bridge.report(), 'generationPassed': False,
                              'allNormalVerifiersExecuted': False, 'errorType': type(error).__name__}, indent=2) + '\n')
            raise
        report.write_text(json.dumps({**bridge.report(), 'generationPassed': True}, indent=2) + '\n')


if __name__ == '__main__':
    main()
