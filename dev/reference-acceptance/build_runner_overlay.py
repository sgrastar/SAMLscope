#!/usr/bin/env python3
"""Compile selected Runner sources against an immutable runtime, then test the actual JAR.

This never loads mutable main Gradle classes or incorporates unrelated working-tree sources.
All inputs and test helpers are copied before compilation. An existing output is not replaced.
"""
import argparse
import datetime
import hashlib
import json
import pathlib
import re
import shutil
import subprocess
import zipfile

ROOT = pathlib.Path(__file__).resolve().parents[2]
JAVA = pathlib.Path('/Library/Java/JavaVirtualMachines/jdk-21.jdk/Contents/Home/bin')
PROJECT_JARS = tuple(name + '-0.1.0.jar' for name in ('api', 'core', 'peer', 'runner', 'saml', 'store'))


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def check(value, message):
    if not value:
        raise RuntimeError(message)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--parent', required=True, type=pathlib.Path)
    parser.add_argument('--output', required=True, type=pathlib.Path)
    parser.add_argument('--main-source', required=True, action='append', type=pathlib.Path)
    parser.add_argument('--test-source', required=True, action='append', type=pathlib.Path)
    parser.add_argument('--selector', required=True, action='append')
    parser.add_argument('--bound-class', action='append', default=[])
    parser.add_argument('--expected-tests', required=True, type=int)
    parser.add_argument('--parent-image', required=True)
    args = parser.parse_args()
    parent = args.parent.resolve()
    output = args.output.resolve()
    check(output.is_relative_to(ROOT / 'build/acceptance'), 'Output must be in acceptance artifacts')
    check(not (output / 'isolated-compile').exists() and not (output / 'runtime-built').exists(),
          'Output already has frozen build artifacts; select a new attempt directory')
    baseline = json.loads((parent / 'runtime-live-verification.json').read_text())['projectJars']
    archive = parent / 'runtime-built'
    for name in PROJECT_JARS:
        check((archive / name).stat().st_nlink == 1 and sha(archive / name) == baseline[name],
              'Parent archive changed: ' + name)
    work = output / 'isolated-compile'
    work.mkdir(parents=True)
    builder_source = work / 'builder-source.py'
    builder_source.write_bytes(pathlib.Path(__file__).read_bytes())
    frozen = work / 'sources'
    frozen.mkdir()
    mains, tests, source_hashes, families = [], [], {}, []
    for kind, inputs, destination in [('main', args.main_source, mains), ('test', args.test_source, tests)]:
        for source in inputs:
            source = source.resolve()
            check(source.is_relative_to(ROOT / 'runner/src') and not source.is_symlink(), 'Unexpected source')
            target = frozen / kind / source.name
            target.parent.mkdir(exist_ok=True)
            check(not target.exists(), 'Duplicate source name')
            shutil.copyfile(source, target)
            source_hashes[str(source.relative_to(ROOT))] = sha(target)
            destination.append(target)
            if kind == 'main':
                package = re.search(r'^package\s+([\w.]+)\s*;', target.read_text(), re.M)
                check(package is not None, 'Missing source package')
                families.append(package.group(1).replace('.', '/') + '/' + source.stem)
    classes, test_classes = work / 'classes', work / 'test-classes'
    classes.mkdir()
    test_classes.mkdir()
    support = work / 'test-support'
    shutil.copytree(ROOT / 'runner/build/classes/java/test', support, symlinks=False)
    support_hashes = {str(p.relative_to(support)): sha(p) for p in sorted(support.rglob('*.class'))}
    dependencies = sorted(p for p in (ROOT / 'api/build/install/samlscope/lib').glob('*.jar')
                          if p.name not in PROJECT_JARS)
    cache = pathlib.Path.home() / '.gradle/caches/modules-2/files-2.1'
    junit = []
    for group, version in [('org.junit.jupiter', '6.1.3'), ('org.junit.platform', '6.1.3'),
                           ('org.apiguardian', '1.1.2'), ('org.opentest4j', '1.3.0')]:
        junit += [p for p in (cache / group).rglob('*.jar') if version in p.parts]
    check(junit, 'JUnit runtime unavailable')
    dependency_hashes = {str(p): sha(p) for p in dependencies + junit}

    def execute(stage, argv):
        print(stage, flush=True)
        with (work / (stage + '.stdout')).open('wb') as stdout, (work / (stage + '.stderr')).open('wb') as stderr:
            result = subprocess.run(argv, cwd=ROOT, stdout=stdout, stderr=stderr)
        if result.returncode:
            print((work / (stage + '.stdout')).read_text(errors='replace')[-4000:])
            print((work / (stage + '.stderr')).read_text(errors='replace')[-4000:])
        check(result.returncode == 0, stage + ' failed; frozen logs retained')

    cp = ':'.join(str(p) for p in [*(archive / n for n in PROJECT_JARS), *dependencies])
    execute('main-compile', [str(JAVA / 'javac'), '--release', '21', '-cp', cp, '-d', str(classes),
                             *map(str, mains)])
    runtime = output / 'runtime-built'
    runtime.mkdir()
    replacements = {str(p.relative_to(classes)): p.read_bytes() for p in classes.rglob('*.class')}
    check(replacements and all(any(name == f + '.class' or name.startswith(f + '$') for f in families)
                               for name in replacements), 'Compiler produced an unexpected class family')
    with zipfile.ZipFile(archive / 'runner-0.1.0.jar') as before, zipfile.ZipFile(runtime / 'runner-0.1.0.jar', 'w') as after:
        old_family = {name for name in before.namelist()
                      if any(name == f + '.class' or name.startswith(f + '$') for f in families)}
        check(old_family.issubset(replacements), 'A class family member was removed; use an explicit full rebuild')
        for info in before.infolist():
            after.writestr(info, replacements.pop(info.filename, before.read(info.filename)))
        for name, data in replacements.items():
            after.writestr(name, data, compress_type=zipfile.ZIP_DEFLATED)
    for name in PROJECT_JARS:
        if name != 'runner-0.1.0.jar':
            shutil.copyfile(archive / name, runtime / name)
    cp = ':'.join(str(p) for p in [*(runtime / n for n in PROJECT_JARS), *dependencies, *junit])
    test_cp = ':'.join([str(test_classes), str(support), cp, str(ROOT / 'runner/src/test/resources')])
    execute('test-compile', [str(JAVA / 'javac'), '--release', '21', '-cp', test_cp,
                             '-d', str(test_classes), *map(str, tests)])
    bound = sorted(set(args.bound_class + [f.replace('/', '.') for f in families]))
    selectors = ','.join('selectClass(' + json.dumps(name) + ')' for name in args.selector)
    launcher = work / 'RunPackagedRunnerTests.java'
    launcher.write_text('''import org.junit.platform.launcher.core.*;
import org.junit.platform.launcher.listeners.*;
import static org.junit.platform.engine.discovery.DiscoverySelectors.*;
import java.nio.file.*;
public final class RunPackagedRunnerTests {
 public static void main(String[] args) throws Exception {
  Path expected=Path.of(args[0]).toRealPath();
  for(String name:new String[]{BOUND}) {
   Class<?> type=Class.forName(name);
   Path actual=Path.of(type.getProtectionDomain().getCodeSource().getLocation().toURI()).toRealPath();
   if(!expected.equals(actual))throw new IllegalStateException("Wrong packaged class source: "+name);
  }
  var request=LauncherDiscoveryRequestBuilder.request().selectors(SELECTORS).build();
  var listener=new SummaryGeneratingListener();LauncherFactory.create().execute(request,listener);
  var summary=listener.getSummary();summary.printTo(new java.io.PrintWriter(System.out,true));
  if(summary.getTestsFoundCount()!=COUNT || summary.getTestsSucceededCount()!=COUNT || summary.getTestsFailedCount()!=0 || summary.getTestsSkippedCount()!=0) {
   summary.printFailuresTo(new java.io.PrintWriter(System.out,true));throw new IllegalStateException("Packaged test failure");
  }
  System.out.println("PACKAGED RUNNER COUNT/COUNT PASS; selected main classes use the qualified Runner archive");
 }
}
'''.replace('BOUND', ','.join(json.dumps(name) for name in bound)).replace('SELECTORS', selectors)
        .replace('COUNT', str(args.expected_tests)))
    execute('launcher-compile', [str(JAVA / 'javac'), '--release', '21', '-cp', test_cp, '-d', str(work), str(launcher)])
    execute('packaged-replay', [str(JAVA / 'java'), '-Xmx256m', '-cp', str(work) + ':' + test_cp,
                               'RunPackagedRunnerTests', str(runtime / 'runner-0.1.0.jar')])
    check(all(sha(pathlib.Path(path)) == expected for path, expected in dependency_hashes.items()),
          'A dependency changed during qualification')
    for kind, inputs in [('main', args.main_source), ('test', args.test_source)]:
        for source in inputs:
            check(sha(source.resolve()) == source_hashes[str(source.resolve().relative_to(ROOT))], 'Source changed during qualification')
    with zipfile.ZipFile(archive / 'runner-0.1.0.jar') as before, zipfile.ZipFile(runtime / 'runner-0.1.0.jar') as after:
        a, b = set(before.namelist()), set(after.namelist())
        changed = sorted(name for name in a & b if before.read(name) != after.read(name))
        added, removed = sorted(b - a), sorted(a - b)
        check(not removed and all(any(name == f + '.class' or name.startswith(f + '$') for f in families)
                                 for name in changed + added), 'Unexpected JAR entry difference')
    hashes = {name: sha(runtime / name) for name in PROJECT_JARS}
    check(all((runtime / name).stat().st_nlink == 1 for name in PROJECT_JARS), 'Archive is not independent')
    context = output / 'docker-context'
    context.mkdir()
    (context / 'Dockerfile').write_text('FROM ' + args.parent_image + '\nCOPY runner-0.1.0.jar /opt/samlscope/lib/\n')
    shutil.copyfile(runtime / 'runner-0.1.0.jar', context / 'runner-0.1.0.jar')
    record = {'schema': 'samlscope-runner-isolated-overlay-qualification-v1',
              'recordedAt': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'parent': str(parent.relative_to(ROOT)), 'sourceSha256': source_hashes,
              'builderSha256': sha(builder_source), 'testSupportSha256': support_hashes,
              'dependencySha256': dependency_hashes,
              'testCount': args.expected_tests, 'packagedReplayExitCode': 0,
              'projectJars': hashes, 'changedEntries': changed, 'addedEntries': added,
              'removedEntries': removed, 'mainClassSourcesBoundToArchive': True,
              'unrelatedWorktreeSourcesIncluded': False, 'allArchiveLinkCountsOne': True,
              'personOperations': 0, 'productSettings': 0, 'runtimeDeployed': False}
    (output / 'isolated-test-overlay.json').write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps({key: value for key, value in record.items() if key != 'testSupportSha256'}))


if __name__ == '__main__':
    main()
