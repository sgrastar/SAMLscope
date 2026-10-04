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
            require(not any(p.is_symlink() for p in (source, *source.parents)), 'Symbolic source')
            relative = str(source.relative_to(ROOT))
            module = source.relative_to(ROOT).parts[0]
            require(module in MODULES and source.is_relative_to(ROOT / module / 'src' / kind / 'java'), 'Unexpected source')
            require(relative not in protected and not relative.startswith(prefixes), 'Signed protected source selected')
            require(source.is_file(), 'Missing source')
            sources.append((kind, module, source))
    baseline = json.loads((parent / 'runtime-live-verification.json').read_text())['projectJars']
    archive = parent / 'runtime-built'
    for name in PROJECT_JARS:
        require((archive / name).stat().st_nlink == 1 and sha(archive / name) == baseline[name], 'Parent archive differs')
    work = output / 'isolated-compile'
    work.mkdir(parents=True)
    builder = work / 'builder-source.py'
    builder.write_bytes(Path(__file__).read_bytes())
    source_hashes, families, mains, tests = {}, {}, [], []
    for kind, module, source in sources:
        target = work / 'sources' / module / kind / source.name
        target.parent.mkdir(parents=True, exist_ok=True)
        require(not target.exists(), 'Duplicate source')
        shutil.copyfile(source, target)
        source_hashes[str(source.relative_to(ROOT))] = sha(target)
        (mains if kind == 'main' else tests).append(target)
        if kind == 'main':
            match = re.search(r'^package\s+([\w.]+)\s*;', target.read_text(), re.M)
            require(match is not None and match.group(1).startswith('com.samlscope.' + module + '.'), 'Module/package mismatch')
            family = match.group(1).replace('.', '/') + '/' + source.stem
            require(family not in families, 'Duplicate main class family')
            families[family] = module + '-0.1.0.jar'
    dependencies = sorted(p for p in (ROOT / 'api/build/install/samlscope/lib').glob('*.jar') if p.name not in PROJECT_JARS)
    cache = Path.home() / '.gradle/caches/modules-2/files-2.1'
    junit = []
    for group, version in [('org.junit.jupiter', '6.1.3'), ('org.junit.platform', '6.1.3'),
                           ('org.apiguardian', '1.1.2'), ('org.opentest4j', '1.3.0')]:
        junit.extend(p for p in (cache / group).rglob('*.jar') if version in p.parts)
    require(junit, 'JUnit unavailable')
    dependency_hashes = {str(p): sha(p) for p in dependencies + junit}
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
        if not scoped:
            shutil.copyfile(archive / name, runtime / name)
            differences[name] = {'changed': [], 'added': [], 'removed': []}
            continue
        selected = {n: raw for n, raw in replacements.items()
                    if any(n == f + '.class' or n.startswith(f + '$') for f in scoped)}
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
            require(not removed and all(any(n == f + '.class' or n.startswith(f + '$') for f in scoped)
                                       for n in changed + added), 'Unexpected JAR differences')
            differences[name] = {'changed': changed, 'added': added, 'removed': removed}
    cp = ':'.join(map(str, [*(runtime / n for n in PROJECT_JARS), *dependencies, *junit]))
    resources = [ROOT / m / 'src/test/resources' for m in MODULES]
    test_cp = ':'.join(map(str, [test_classes, *support])) + ':' + cp + ':' + ':'.join(map(str, resources))
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
    hashes = {n: sha(runtime / n) for n in PROJECT_JARS}
    require(all((runtime / n).stat().st_nlink == 1 for n in PROJECT_JARS), 'Archive not independent')
    context = output / 'docker-context'
    context.mkdir()
    changed_jars = [n for n in PROJECT_JARS if hashes[n] != baseline[n]]
    require(changed_jars and 'api-0.1.0.jar' not in changed_jars, 'Protected API changed or empty overlay')
    (context / 'Dockerfile').write_text('FROM ' + args.parent_image + '\nCOPY ' + ' '.join(changed_jars) + ' /opt/samlscope/lib/\n')
    for n in changed_jars:
        shutil.copyfile(runtime / n, context / n)
    record = {'schema': 'samlscope-project-isolated-overlay-qualification-v1',
              'recordedAt': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'parent': str(parent.relative_to(ROOT)), 'sourceSha256': source_hashes,
              'builderSha256': sha(builder), 'testSupportSha256': support_hashes,
              'dependencySha256': dependency_hashes, 'testCount': args.expected_tests,
              'packagedReplayExitCode': 0, 'projectJars': hashes, 'jarDifferences': differences,
              'changedProjectJars': changed_jars, 'mainClassSourcesBoundToArchive': True,
              'signedProtectedSourcesIncluded': False, 'unrelatedWorktreeSourcesIncluded': False,
              'allArchiveLinkCountsOne': True, 'personOperations': 0, 'productSettings': 0,
              'runtimeDeployed': False}
    (output / 'isolated-test-overlay.json').write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps({k: v for k, v in record.items() if k != 'testSupportSha256'}))


if __name__ == '__main__':
    main()
