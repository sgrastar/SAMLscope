#!/usr/bin/env python3
"""Compile/run the identical JUnit suite locally, without Gradle sockets or resolution."""
import hashlib
import json
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[3]
SOURCE = Path(__file__).resolve().parent
OUT = ROOT / 'build/acceptance/reference-20261031/slo'
JAVA = Path('/Library/Java/JavaVirtualMachines/jdk-21.jdk/Contents/Home/bin')


def main():
    lib = ROOT / 'api/build/install/samlscope/lib'
    deps = [lib / 'core-0.1.0.jar']
    for name in ('jackson-core', 'jackson-databind', 'jackson-annotations'):
        found = list(lib.glob(name + '-*.jar'))
        if len(found) != 1:
            raise ValueError('Ambiguous installed dependency')
        deps.extend(found)
    cache = Path.home() / '.gradle/caches/modules-2/files-2.1'
    for name in ('org.junit.jupiter/junit-jupiter-api/6.1.3', 'org.junit.jupiter/junit-jupiter-engine/6.1.3',
                 'org.junit.platform/junit-platform-launcher/6.1.3', 'org.junit.platform/junit-platform-engine/6.1.3',
                 'org.junit.platform/junit-platform-commons/6.1.3', 'org.opentest4j/opentest4j/1.3.0',
                 'org.apiguardian/apiguardian-api/1.1.2'):
        found = list((cache / name).glob('*/*.jar'))
        if len(found) != 1:
            raise ValueError('Missing or ambiguous cached JUnit dependency')
        deps.extend(found)
    pins = {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in deps}
    dest = OUT / 'javac-classes'
    dest.mkdir(exist_ok=True)
    cp = os.pathsep.join(map(str, deps))
    commands = [[str(JAVA / 'javac'), '-encoding', 'UTF-8', '-sourcepath', '', '-cp', cp, '-d', str(dest),
                 str(SOURCE / 'ReadSloStoredEvidence.java'), *map(str, sorted((SOURCE / 'test').glob('*.java')))],
                [str(JAVA / 'java'), '-Dslo.repo=' + str(ROOT), '-Djava.io.tmpdir=' + str(OUT / 'test-tmp'),
                 '-cp', str(dest) + os.pathsep + cp, 'com.samlscope.runner.cases.RunOfflineSloChecks']]
    (OUT / 'test-tmp').mkdir(exist_ok=True)
    logs = []
    for command in commands:
        p = subprocess.run(command, cwd=ROOT, text=True, capture_output=True)
        logs.append({'command': command, 'exitCode': p.returncode, 'stdout': p.stdout, 'stderr': p.stderr})
        (OUT / 'java-junit-checks.json').write_text(json.dumps(logs, indent=2) + '\n')
        if p.returncode:
            print(p.stdout + p.stderr)
            raise SystemExit(p.returncode)
    (OUT / 'java-dependency-pins.json').write_text(json.dumps(pins, indent=2) + '\n')
    print(logs[-1]['stdout'])
    return dest, cp


if __name__ == '__main__':
    main()
