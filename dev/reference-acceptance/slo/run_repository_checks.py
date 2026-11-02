#!/usr/bin/env python3
"""Run unchanged offline validators, relocating ONLY their report writes to this task.

Use python -I -B. The validation logic, repository root and signed inputs are unchanged.
The caller's write boundary forbids the validators' usual build/*.json destinations.
"""
import builtins
import contextlib
import io
import json
import os
from pathlib import Path
import runpy
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[3]
OUT = ROOT / 'build/acceptance/reference-20261031/slo'
REPORTS = {ROOT / 'build/spec-reconcile-report.json': OUT / 'spec-reconcile-report.json',
           ROOT / 'build/g2-report.json': OUT / 'g2-report.json'}
OPEN = builtins.open
IO_OPEN = io.open


def relocated_open(opener, file, mode='r', *args, **kwargs):
    if not isinstance(file, int) and any(x in mode for x in 'wax+'):
        path = Path(file).absolute()
        path = REPORTS.get(path, path)
        if not path.is_relative_to(OUT):
            raise PermissionError('Validator attempted an out-of-scope write')
        file = path
    return opener(file, mode, *args, **kwargs)


def main():
    if not sys.flags.isolated or not sys.dont_write_bytecode:
        raise ValueError('Invoke with .venv/bin/python -I -B')
    temp = OUT / 'check-tmp'
    temp.mkdir(exist_ok=True)
    tempfile.tempdir = str(temp)
    os.environ['TMPDIR'] = str(temp)
    summaries = []
    for name, args in [('g1_docgen.py', ['--check']), ('g1_validate.py', ['--structural-only']), ('g2_validate.py', [])]:
        log = io.StringIO()
        sys.argv = [str(ROOT / 'tools' / name), *args]
        builtins.open = lambda f, mode='r', *a, **kw: relocated_open(OPEN, f, mode, *a, **kw)
        io.open = lambda f, mode='r', *a, **kw: relocated_open(IO_OPEN, f, mode, *a, **kw)
        try:
            with contextlib.redirect_stdout(log), contextlib.redirect_stderr(log):
                try:
                    runpy.run_path(sys.argv[0], run_name='__main__')
                    code = 0
                except SystemExit as e:
                    code = e.code or 0
        finally:
            builtins.open = OPEN
            io.open = IO_OPEN
        summaries.append({'validator': name, 'args': args, 'exitCode': code, 'output': log.getvalue(),
                          'reportWritesRelocatedOnly': True})
        print(name, code, log.getvalue().strip())
    (OUT / 'repository-checks.json').write_text(json.dumps(summaries, indent=2) + '\n')
    return int(any(x['exitCode'] for x in summaries))


if __name__ == '__main__':
    raise SystemExit(main())
