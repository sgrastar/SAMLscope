#!/usr/bin/env python3
"""Diagnose installed native UI getters against original fixtures; never change product verdicts."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

SHA = lambda raw: hashlib.sha256(raw).hexdigest()
CONDITIONS = ['ui-url-'+element+'-'+scheme for element in ['logo','information','privacy']
              for scheme in ['http','https','data','javascript','file']]
CONTAINER = 'samlscope-reference-shibboleth'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--fixtures', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists(): raise ValueError('Refusing to overwrite evidence')
    hashes = {c: SHA((args.fixtures/c/'fixture.xml').read_bytes()) for c in CONDITIONS}
    args.output.mkdir(parents=True)
    source = Path(__file__).with_name('NativeUiUrlProbe.java')
    source_raw = source.read_bytes()
    # Only public fixture XML and probe source are copied; no native configuration is changed.
    temporary = subprocess.check_output(['docker','exec',CONTAINER,'mktemp','-d','/tmp/samlscope-ui-probe-XXXXXXXX'],text=True).strip()
    if not temporary.startswith('/tmp/samlscope-ui-probe-') or not temporary[len('/tmp/'):].replace('-','').isalnum():
        raise ValueError('Unexpected native temporary path')
    operations = []; records = []; cleaned = False
    try:
        with tempfile.TemporaryDirectory(prefix='samlscope-public-ui-fixtures-') as local:
            local = Path(local)
            for condition in CONDITIONS:
                dest = local/condition;dest.mkdir()
                raw = (args.fixtures/condition/'fixture.xml').read_bytes()
                if SHA(raw) != hashes[condition]:raise ValueError('Fixture changed while staging')
                (dest/'fixture.xml').write_bytes(raw)
            (local/'NativeUiUrlProbe.java').write_bytes(source_raw)
            subprocess.run(['docker','cp',str(local)+'/.',CONTAINER+':'+temporary],check=True,capture_output=True)
        command = ['docker','exec',CONTAINER]
        cp = '/usr/local/tomcat/webapps/idp/WEB-INF/lib/*'
        compiled = subprocess.run(command+['javac','-cp',cp,'-d',temporary,temporary+'/NativeUiUrlProbe.java'],capture_output=True,timeout=60)
        operations.append(dict(operation='compile',exit_code=compiled.returncode))
        if compiled.returncode:
            (args.output/'compile.stderr').write_bytes(compiled.stderr)
            raise RuntimeError('Native probe compilation failed')
        result = subprocess.run(command+['java','-cp',temporary+':'+cp,'NativeUiUrlProbe',temporary],capture_output=True,timeout=90)
        operations.append(dict(operation='native-getter-probe',exit_code=result.returncode))
        # Discard generic framework logs, including values mentioned in product warning messages.
        for line in result.stdout.decode().splitlines():
            if not line.startswith('SAMLSCOPE_UI_PROBE\t'):continue
            _, condition, digest, status, jar_hash = line.split('\t')
            if condition not in hashes or digest != hashes[condition] or status not in ['null','candidate-returned','different-value']:
                raise ValueError('Unbound native observation')
            if len(jar_hash)!=64 or any(c not in '0123456789abcdef' for c in jar_hash):raise ValueError('Invalid native source hash')
            records.append(dict(condition=condition,fixture_sha256=digest,native_return=status,ui_jar_sha256=jar_hash))
        if result.returncode or len(records)!=len(CONDITIONS) or {r['condition'] for r in records}!=set(CONDITIONS):
            raise RuntimeError('Native probe incomplete')
        for row in records:print(row['condition'],row['native_return'],flush=True)
    finally:
        cleanup = subprocess.run(['docker','exec',CONTAINER,'rm','-rf','--',temporary],capture_output=True)
        cleaned = cleanup.returncode == 0
        report = dict(schema='samlscope-native-ui-getter-diagnosis-v1',scope='isolated-native-getter',
            browser_execution_verified=False,request_bound_nonuse_verified=False,verdict_adopted=False,
            probe_source_sha256=SHA(source_raw),records=records,operations=operations,
            temporary_removed=cleaned,product_configuration_writes=0,product_restarts=0,human_operations=0)
        (args.output/'observations.json').write_text(json.dumps(report,indent=2)+'\n')
        if not cleaned:raise RuntimeError('Native probe cleanup failed')


if __name__ == '__main__':main()
