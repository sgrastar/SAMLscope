#!/usr/bin/env python3
"""Build selected unprotected sources together against an immutable runtime.

Only explicit Runner, SAML and Peer class families enter the overlay. Tests run
against the actual resulting JARs, not mutable Gradle main outputs.
"""
import argparse
import ast
import datetime
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import zipfile

ROOT = Path(__file__).resolve().parents[2]
JAVA = Path('/Library/Java/JavaVirtualMachines/jdk-21.jdk/Contents/Home/bin')
MODULES = ('runner', 'saml', 'peer')
PROJECT_JARS = tuple(n + '-0.1.0.jar' for n in ('api', 'core', 'peer', 'runner', 'saml', 'store'))


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def require(value, message):
    if not value:
        raise RuntimeError(message)


def qualified_runtime_dependencies(parent: Path, runtime_lib: Path) -> list[Path]:
    """Resolve the host runtime only after matching the qualified parent's bytes."""
    record = json.loads((parent / 'isolated-test-overlay.json').read_text())
    expected = record.get('runtimeDependencySha256')
    legacy = {}
    for value, digest in record.get('dependencySha256', {}).items():
        path = Path(value)
        if path.parent.resolve() != runtime_lib.resolve():
            continue  # The parent also records its test-only JUnit dependencies.
        require(path.name not in legacy and path.name not in PROJECT_JARS,
                'Duplicate or project dependency in parent qualification')
        require('..' not in path.parts, 'Aliased dependency in parent qualification')
        legacy[path.name] = digest
    if expected is None:
        expected = legacy
    else:
        require(isinstance(expected, dict) and (not legacy or legacy == expected),
                'Parent dependency inventories disagree')
    require(expected and all(Path(name).name == name and name.endswith('.jar')
                            and name not in PROJECT_JARS
                            and isinstance(digest, str) and re.fullmatch(r'[0-9a-f]{64}', digest)
                            for name, digest in expected.items()), 'Invalid parent runtime dependencies')
    runtime_path = parent / 'runtime-live-verification.json'
    runtime = json.loads(runtime_path.read_text())
    native = json.loads((parent / 'runtime-third-party-verification.json').read_text())
    require(native.get('schema') == 'samlscope-runtime-third-party-verification-v1'
            and native.get('parentRuntimeVerificationSha256') == sha(runtime_path)
            and re.fullmatch(r'sha256:[0-9a-f]{64}', runtime.get('imageId', ''))
            and native.get('imageId') == runtime['imageId']
            and native.get('suiteContainerId') == runtime.get('suiteContainerId')
            and isinstance(runtime.get('suiteContainerId'), str) and runtime['suiteContainerId']
            and native.get('liveEqualsHostAndQualifiedParent') is True
            and native.get('thirdPartyJars') == expected,
            'Parent native runtime dependency proof differs from qualification')
    require(runtime_lib.is_dir() and not runtime_lib.is_symlink(), 'Invalid host runtime library')
    actual = {p.name: p for p in runtime_lib.glob('*.jar') if p.name not in PROJECT_JARS}
    require(set(actual) == set(expected), 'Host runtime dependency inventory differs from parent')
    for name, path in actual.items():
        require(path.is_file() and not path.is_symlink() and sha(path) == expected[name],
                'Host runtime dependency differs from parent: ' + name)
    return [actual[name] for name in sorted(actual)]


def copy_independent_snapshot(source: Path, target: Path, expected_sha: str) -> Path:
    """Copy a pinned input without sharing an inode or overwriting an alias."""
    require(source.is_file() and not source.is_symlink(), 'Invalid snapshot source')
    require(not target.exists() and not target.is_symlink(), 'Snapshot target already exists')
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, target)
    require(target.stat().st_nlink == 1 and sha(target) == expected_sha,
            'Snapshot copy differs from pinned source')
    target.chmod(0o444)
    return target


def tree_inventory(root: Path, *, independent: bool = False) -> dict[str, str]:
    require(root.is_dir() and not root.is_symlink(), 'Invalid snapshot directory')
    inventory = {}
    for path in sorted(root.rglob('*')):
        require(not path.is_symlink() and (path.is_dir() or path.is_file()), 'Invalid snapshot entry')
        if path.is_file():
            require(not independent or path.stat().st_nlink == 1, 'Snapshot input shares an inode')
            inventory[str(path.relative_to(root))] = sha(path)
    return inventory


def snapshot_test_resources(resource_roots: list[Path], target_root: Path) -> tuple[list[Path], dict[str, str]]:
    require(not target_root.exists() and not target_root.is_symlink(), 'Resource snapshot already exists')
    target_root.mkdir(parents=True)
    snapshots = []
    for index, source in enumerate(resource_roots):
        require(not source.is_symlink(), 'Symbolic test resource directory')
        if not source.exists():
            continue
        originals = tree_inventory(source)
        target = target_root / str(index)
        target.mkdir()
        for directory in sorted(p for p in source.rglob('*') if p.is_dir()):
            (target / directory.relative_to(source)).mkdir(parents=True, exist_ok=True)
        for name, digest in originals.items():
            copy_independent_snapshot(source / name, target / name, digest)
        require(tree_inventory(source) == originals, 'Test resource source changed during capture')
        snapshots.append(target)
    return snapshots, tree_inventory(target_root, independent=True)


def require_snapshot_unchanged(root: Path, expected: dict[str, str]) -> None:
    require(tree_inventory(root, independent=True) == expected, 'Snapshot inventory or bytes changed')


def archive_hashes(archive: Path) -> dict[str, str]:
    require(archive.is_dir() and not archive.is_symlink()
            and {p.name for p in archive.iterdir()} == set(PROJECT_JARS), 'Invalid six-JAR archive inventory')
    for name in PROJECT_JARS:
        path = archive / name
        require(path.is_file() and not path.is_symlink() and path.stat().st_nlink == 1,
                'Archive JAR is not independent: ' + name)
    return {name: sha(archive / name) for name in PROJECT_JARS}


def require_archive_unchanged(archive: Path, expected: dict[str, str]) -> None:
    require(archive_hashes(archive) == expected, 'Packaged archive changed during testing')


def dockerfile_for_qualified_parent(runtime: dict, changed_jars: list[str]) -> str:
    image, image_id = runtime.get('image'), runtime.get('imageId')
    require(isinstance(image, str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.:/-]*', image)
            and not image.startswith('sha256:')
            and isinstance(image_id, str) and re.fullmatch(r'sha256:[0-9a-f]{64}', image_id),
            'Qualified parent tag or image ID unavailable')
    # A Docker image ID is not a registry distribution digest accepted by FROM.
    # The deployer must verify this tag or an owned local alias against image_id.
    return ('# Qualified parent image ID: ' + image_id + '\n'
            '# Parent tag requires exact image-ID verification before build.\n'
            'FROM ' + image + '\nCOPY ' + ' '.join(changed_jars) + ' /opt/samlscope/lib/\n')


def protected_sources():
    tree = ast.parse((ROOT / 'tools/g2_validate.py').read_text())
    constants = {}
    for node in tree.body:
        if not isinstance(node, ast.Assign) or len(node.targets) != 1 or not isinstance(node.targets[0], ast.Name):
            continue
        name = node.targets[0].id
        if isinstance(node.value, ast.Constant):
            constants[name] = node.value.value
        elif name in ('STATIC_PROTECTED_PATHS', 'PROTECTED_PREFIXES'):
            values = []
            for value in node.value.elts:
                values.append(constants[value.id] if isinstance(value, ast.Name) else ast.literal_eval(value))
            constants[name] = values
    require('STATIC_PROTECTED_PATHS' in constants and 'PROTECTED_PREFIXES' in constants,
            'Cannot identify the signed protected boundary')
    return set(constants['STATIC_PROTECTED_PATHS']), tuple(constants['PROTECTED_PREFIXES'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--parent', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--parent-image', required=True)
    parser.add_argument('--main-source', required=True, action='append', type=Path)
    parser.add_argument('--test-source', required=True, action='append', type=Path)
    parser.add_argument('--resource-source', action='append', type=Path, default=[])
    parser.add_argument('--selector', required=True, action='append')
    parser.add_argument('--bound-class', action='append', default=[])
    parser.add_argument('--expected-tests', required=True, type=int)
    args = parser.parse_args()
    require(args.expected_tests > 0, 'No packaged tests selected')
    parent, output = args.parent.resolve(), args.output.resolve()
    require(output.is_relative_to(ROOT / 'build/acceptance') and not output.is_symlink(), 'Unsafe output')
    require(not (output / 'isolated-compile').exists() and not (output / 'runtime-built').exists(), 'Frozen output exists')
    protected, prefixes = protected_sources()
    sources = []
    for kind, values in [('main', args.main_source), ('test', args.test_source)]:
        for value in values:
            source = value.absolute()
            require('..' not in source.parts, 'Parent traversal in source path')
            require(not any(p.is_symlink() for p in (source, *source.parents)), 'Symbolic source')
            relative = str(source.relative_to(ROOT))
            module = source.relative_to(ROOT).parts[0]
            require(module in MODULES and source.is_relative_to(ROOT / module / 'src' / kind / 'java'), 'Unexpected source')
            require(relative not in protected and not relative.startswith(prefixes), 'Signed protected source selected')
            require(source.is_file(), 'Missing source')
            sources.append((kind, module, source))
    resources = []
    for value in args.resource_source:
        source = value.absolute()
        require('..' not in source.parts, 'Parent traversal in resource path')
        require(not any(p.is_symlink() for p in (source, *source.parents)), 'Symbolic resource')
        relative = str(source.relative_to(ROOT))
        module = source.relative_to(ROOT).parts[0]
        base = ROOT / module / 'src/main/resources'
        require(module in MODULES and source.is_relative_to(base)
                and relative not in protected and not relative.startswith(prefixes), 'Unexpected or protected resource')
        require(source.is_file() and source.suffix == '.json' and source.stat().st_size <= 1_048_576,
                'Only bounded public JSON resources are accepted')
        jar_name = str(source.relative_to(base))
        require(jar_name.startswith('com/samlscope/' + module + '/') and '..' not in Path(jar_name).parts,
                'Resource outside its module namespace')
        resources.append((module, source, jar_name))
    parent_runtime = json.loads((parent / 'runtime-live-verification.json').read_text())
    baseline = parent_runtime['projectJars']
    require(args.parent_image in (parent_runtime.get('image'), parent_runtime.get('imageId')),
            'Parent image argument differs from qualified runtime')
    archive = parent / 'runtime-built'
    require(archive_hashes(archive) == baseline, 'Parent archive differs')
    parent_qualification = json.loads((parent / 'isolated-test-overlay.json').read_text())
    require(parent_qualification.get('projectJars') == baseline
            and parent_qualification.get('packagedReplayExitCode') == 0,
            'Parent dependency qualification is not bound to its runtime')
    work = output / 'isolated-compile'
    work.mkdir(parents=True)
    builder = work / 'builder-source.py'
    builder.write_bytes(Path(__file__).read_bytes())
    parent_proof_names = ('runtime-live-verification.json', 'isolated-test-overlay.json',
                          'runtime-third-party-verification.json')
    parent_proof_hashes = {name: sha(parent / name) for name in parent_proof_names}
    for name, digest in parent_proof_hashes.items():
        copy_independent_snapshot(parent / name, work / 'parent-proof' / name, digest)
    require(json.loads((work / 'parent-proof/runtime-live-verification.json').read_text()) == parent_runtime
            and json.loads((work / 'parent-proof/isolated-test-overlay.json').read_text()) == parent_qualification,
            'Parent qualification changed during capture')
    source_hashes, families, mains, tests = {}, {}, [], []
    for kind, module, source in sources:
        target = work / 'sources' / module / kind / source.name
        target.parent.mkdir(parents=True, exist_ok=True)
        require(not target.exists(), 'Duplicate source')
        copy_independent_snapshot(source, target, sha(source))
        source_hashes[str(source.relative_to(ROOT))] = sha(target)
        (mains if kind == 'main' else tests).append(target)
        if kind == 'main':
            match = re.search(r'^package\s+([\w.]+)\s*;', target.read_text(), re.M)
            require(match is not None and match.group(1).startswith('com.samlscope.' + module + '.'), 'Module/package mismatch')
            family = match.group(1).replace('.', '/') + '/' + source.stem
            require(family not in families, 'Duplicate main class family')
            families[family] = module + '-0.1.0.jar'
    resource_bytes = {}
    for module, source, jar_name in resources:
        target = work / 'resources' / module / jar_name
        target.parent.mkdir(parents=True, exist_ok=True)
        require(not target.exists(), 'Duplicate resource')
        copy_independent_snapshot(source, target, sha(source))
        source_hashes[str(source.relative_to(ROOT))] = sha(target)
        key = (module + '-0.1.0.jar', jar_name)
        require(key not in resource_bytes and jar_name not in families, 'Duplicate resource family')
        resource_bytes[key] = target.read_bytes()
    dependency_sources = qualified_runtime_dependencies(work / 'parent-proof', ROOT / 'api/build/install/samlscope/lib')
    cache = Path.home() / '.gradle/caches/modules-2/files-2.1'
    junit = []
    for group, version in [('org.junit.jupiter', '6.1.3'), ('org.junit.platform', '6.1.3'),
                           ('org.apiguardian', '1.1.2'), ('org.opentest4j', '1.3.0')]:
        junit.extend(p for p in (cache / group).rglob('*.jar') if version in p.parts)
    junit = sorted(junit)
    require(junit and len({p.name for p in junit}) == len(junit), 'JUnit unavailable or ambiguous')
    dependency_hashes = {str(p): sha(p) for p in dependency_sources + junit}
    runtime_dependency_hashes = {p.name: dependency_hashes[str(p)] for p in dependency_sources}
    dependencies = [copy_independent_snapshot(p, work / 'dependencies/runtime' / p.name, dependency_hashes[str(p)])
                    for p in dependency_sources]
    junit = [copy_independent_snapshot(p, work / 'dependencies/junit' / p.name, dependency_hashes[str(p)])
             for p in junit]
    dependency_snapshot_hashes = tree_inventory(work / 'dependencies', independent=True)
    source_snapshot_hashes = tree_inventory(work / 'sources', independent=True)
    main_resource_snapshot_hashes = tree_inventory(work / 'resources', independent=True) if resources else {}
    resource_roots = [ROOT / m / 'src/test/resources' for m in MODULES]
    test_resource_source_hashes = {str(root): tree_inventory(root) for root in resource_roots if root.exists()}
    test_resource_paths, test_resource_hashes = snapshot_test_resources(resource_roots, work / 'test-resources')
    support, support_hashes = [], {}
    for module in MODULES:
        source = ROOT / module / 'build/classes/java/test'
        if source.is_dir():
            dest = work / 'test-support' / module
            shutil.copytree(source, dest, symlinks=False)
            support.append(dest)
            support_hashes.update({str(p.relative_to(work)): sha(p) for p in dest.rglob('*.class')})
    classes, test_classes = work / 'classes', work / 'test-classes'
    classes.mkdir(); test_classes.mkdir()

    def execute(stage, argv):
        print(stage, flush=True)
        with (work / (stage + '.stdout')).open('wb') as stdout, (work / (stage + '.stderr')).open('wb') as stderr:
            result = subprocess.run(argv, cwd=ROOT, stdout=stdout, stderr=stderr)
        if result.returncode:
            print((work / (stage + '.stderr')).read_text(errors='replace')[-4000:])
            print((work / (stage + '.stdout')).read_text(errors='replace')[-4000:])
        require(result.returncode == 0, stage + ' failed; originals retained')

    parent_cp = ':'.join(map(str, [*(archive / n for n in PROJECT_JARS), *dependencies]))
    execute('main-compile', [str(JAVA / 'javac'), '--release', '21', '-sourcepath', '', '-cp', parent_cp,
                             '-d', str(classes), *map(str, mains)])
    replacements = {str(p.relative_to(classes)): p.read_bytes() for p in classes.rglob('*.class')}
    require(replacements and all(any(n == f + '.class' or n.startswith(f + '$') for f in families)
                                for n in replacements), 'Unexpected compiled main class')
    runtime = output / 'runtime-built'
    runtime.mkdir()
    differences = {}
    for name in PROJECT_JARS:
        scoped = {f for f, jar in families.items() if jar == name}
        scoped_resources = {n: raw for (jar, n), raw in resource_bytes.items() if jar == name}
        if not scoped and not scoped_resources:
            shutil.copyfile(archive / name, runtime / name)
            differences[name] = {'changed': [], 'added': [], 'removed': []}
            continue
        selected = {n: raw for n, raw in replacements.items()
                    if any(n == f + '.class' or n.startswith(f + '$') for f in scoped)}
        require(not set(selected).intersection(scoped_resources), 'Resource collides with compiled class')
        selected.update(scoped_resources)
        with zipfile.ZipFile(archive / name) as before, zipfile.ZipFile(runtime / name, 'w') as after:
            prior = {n for n in before.namelist() if any(n == f + '.class' or n.startswith(f + '$') for f in scoped)}
            require(prior.issubset(selected), 'Class family member removed; full build required')
            for info in before.infolist():
                after.writestr(info, selected.pop(info.filename, before.read(info.filename)))
            for n, raw in selected.items():
                after.writestr(n, raw, compress_type=zipfile.ZIP_DEFLATED)
        with zipfile.ZipFile(archive / name) as before, zipfile.ZipFile(runtime / name) as after:
            a, b = set(before.namelist()), set(after.namelist())
            changed = sorted(n for n in a & b if before.read(n) != after.read(n))
            added, removed = sorted(b - a), sorted(a - b)
            require(not removed and all(n in scoped_resources or any(n == f + '.class' or n.startswith(f + '$') for f in scoped)
                                       for n in changed + added), 'Unexpected JAR differences')
            differences[name] = {'changed': changed, 'added': added, 'removed': removed}
    tested_archive_hashes = archive_hashes(runtime)
    cp = ':'.join(map(str, [*(runtime / n for n in PROJECT_JARS), *dependencies, *junit]))
    test_cp = ':'.join(map(str, [test_classes, *support])) + ':' + cp + ':' + ':'.join(map(str, test_resource_paths))
    execute('test-compile', [str(JAVA / 'javac'), '--release', '21', '-sourcepath', '', '-cp', test_cp,
                             '-d', str(test_classes), *map(str, tests)])
    bound = {f.replace('/', '.'): jar for f, jar in families.items()}
    for name in args.bound_class:
        module = name.split('.')[2]
        require(module in MODULES, 'Bound class outside overlay modules')
        bound[name] = module + '-0.1.0.jar'
    launcher = work / 'RunPackagedProjectTests.java'
    rows = ','.join('new String[]{' + json.dumps(n) + ',' + json.dumps(j) + '}' for n, j in sorted(bound.items()))
    selectors = ','.join('selectClass(' + json.dumps(n) + ')' for n in args.selector)
    launcher.write_text('''import org.junit.platform.launcher.core.*;
import org.junit.platform.launcher.listeners.*;
import static org.junit.platform.engine.discovery.DiscoverySelectors.*;
import java.nio.file.*;
public final class RunPackagedProjectTests {
 public static void main(String[] args) throws Exception {
  Path root=Path.of(args[0]).toRealPath();
  for(String[] row:new String[][]{BOUND}) {
   Path actual=Path.of(Class.forName(row[0]).getProtectionDomain().getCodeSource().getLocation().toURI()).toRealPath();
   if(!root.resolve(row[1]).equals(actual))throw new IllegalStateException("Wrong packaged class source: "+row[0]);
  }
  var listener=new SummaryGeneratingListener();
  LauncherFactory.create().execute(LauncherDiscoveryRequestBuilder.request().selectors(SELECTORS).build(),listener);
  var result=listener.getSummary();result.printTo(new java.io.PrintWriter(System.out,true));
  if(result.getTestsFoundCount()!=COUNT || result.getTestsSucceededCount()!=COUNT || result.getTestsFailedCount()!=0 || result.getTestsSkippedCount()!=0) {
   result.printFailuresTo(new java.io.PrintWriter(System.out,true));throw new IllegalStateException("Packaged test failure");
  }
  System.out.println("PACKAGED PROJECT COUNT/COUNT PASS");
 }
}
'''.replace('BOUND', rows).replace('SELECTORS', selectors).replace('COUNT', str(args.expected_tests)))
    execute('launcher-compile', [str(JAVA / 'javac'), '--release', '21', '-cp', test_cp, '-d', str(work), str(launcher)])
    execute('packaged-replay', [str(JAVA / 'java'), '-Xmx384m', '-cp', str(work) + ':' + test_cp,
                               'RunPackagedProjectTests', str(runtime)])
    require(all(sha(Path(p)) == expected for p, expected in dependency_hashes.items()), 'Dependency changed')
    require(all(sha(ROOT / p) == expected for p, expected in source_hashes.items()), 'Source changed')
    require_snapshot_unchanged(work / 'dependencies', dependency_snapshot_hashes)
    require_snapshot_unchanged(work / 'sources', source_snapshot_hashes)
    if resources:
        require_snapshot_unchanged(work / 'resources', main_resource_snapshot_hashes)
    require_snapshot_unchanged(work / 'test-resources', test_resource_hashes)
    require({str(root): tree_inventory(root) for root in resource_roots if root.exists()}
            == test_resource_source_hashes, 'Test resource source changed during testing')
    require_archive_unchanged(runtime, tested_archive_hashes)
    require_archive_unchanged(archive, baseline)
    require_snapshot_unchanged(work / 'parent-proof', parent_proof_hashes)
    require(all(sha(parent / name) == digest for name, digest in parent_proof_hashes.items()),
            'Parent qualification changed during testing')
    hashes = tested_archive_hashes
    context = output / 'docker-context'
    context.mkdir()
    changed_jars = [n for n in PROJECT_JARS if hashes[n] != baseline[n]]
    require(changed_jars and 'api-0.1.0.jar' not in changed_jars, 'Protected API changed or empty overlay')
    (context / 'Dockerfile').write_text(dockerfile_for_qualified_parent(parent_runtime, changed_jars))
    for n in changed_jars:
        shutil.copyfile(runtime / n, context / n)
        require(sha(context / n) == hashes[n], 'Docker context copy differs from tested archive')
    require_archive_unchanged(runtime, tested_archive_hashes)
    record = {'schema': 'samlscope-project-isolated-overlay-qualification-v1',
              'recordedAt': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'parent': str(parent.relative_to(ROOT)), 'sourceSha256': source_hashes,
              'parentImageId': parent_runtime['imageId'], 'parentProofSha256': parent_proof_hashes,
              'DockerfileParentTagRequiresIdVerification': True,
              'builderSha256': sha(builder), 'testSupportSha256': support_hashes,
              'dependencySha256': dependency_hashes, 'testCount': args.expected_tests,
              'runtimeDependencySha256': runtime_dependency_hashes,
              'parentRuntimeDependencySha256': runtime_dependency_hashes,
              'dependencySnapshotSha256': dependency_snapshot_hashes,
              'dependencyPriority': [str(p.relative_to(work)) for p in dependencies + junit],
              'testResourceSourceSha256': test_resource_source_hashes,
              'testResourceSnapshotSha256': test_resource_hashes,
              'testResourcePriority': [str(p.relative_to(work)) for p in test_resource_paths],
              'sourceSnapshotSha256': source_snapshot_hashes,
              'mainResourceSnapshotSha256': main_resource_snapshot_hashes,
              'testedArchiveSha256': tested_archive_hashes, 'archiveUnchangedAfterTesting': True,
              'packagedReplayExitCode': 0, 'projectJars': hashes, 'jarDifferences': differences,
              'changedProjectJars': changed_jars, 'mainClassSourcesBoundToArchive': True,
              'resourceSources': [str(source.relative_to(ROOT)) for _, source, _ in resources],
              'signedProtectedSourcesIncluded': False, 'unrelatedWorktreeSourcesIncluded': False,
              'allArchiveLinkCountsOne': True, 'personOperations': 0, 'productSettings': 0,
              'runtimeDeployed': False}
    (output / 'isolated-test-overlay.json').write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps({k: v for k, v in record.items() if k != 'testSupportSha256'}))


if __name__ == '__main__':
    main()
