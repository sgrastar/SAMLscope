#!/usr/bin/env python3
"""Offline public-result discovery. Never runs a campaign or reads native secrets."""
import hashlib
import json
from pathlib import Path
import subprocess
import yaml

ROOT = Path(__file__).resolve().parents[3]
OUT = ROOT / 'build/acceptance/reference-20261031/slo'
IDS = {'IIP-' + x + '-idp-01' for x in (
    'IDP17-c', 'IDP17-r', 'IDP17-s', 'IDP17-b2', 'IDP18-c', 'IDP18-d', 'IDP19-a', 'IDP19-c')}


def digest(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def load(p):
    return json.loads(p.read_text())


def save(name, obj):
    (OUT / name).write_text(json.dumps(obj, ensure_ascii=False, indent=2) + '\n')


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    inventory = ROOT / 'build/acceptance/reference-20260914/remaining-audit/inventory.json'
    cases_file = ROOT / 'tests/cases.yaml'
    coverage_file = ROOT / 'tests/coverage.yaml'
    cases = {x['id']: x for x in yaml.safe_load(cases_file.read_text())['cases']}
    obligations = {o['key']: o for r in yaml.safe_load(coverage_file.read_text())['requirements']
                   for o in r['obligations']}
    definitions = {i: {'case': cases[i], 'obligation': obligations[cases[i]['obligation']]}
                   for i in sorted(IDS)}
    save('approved-definitions.json', definitions)
    selected = [x for x in load(inventory) if x['profile'] == 'single_logout_idp' and x['case'] in IDS]
    rows = []
    for x in selected:
        folder = Path(x['evidence_folder'])
        if not folder.is_absolute():
            folder = ROOT / folder if str(folder).startswith('build/') else inventory.parent.parent / folder
        result = folder / 'result.json'
        obj = load(result)
        matches = [c for r in obj['requirements'] for c in r['cases'] if c['id'] == x['case']]
        rows.append({'inventory': x, 'resultPath': str(result.relative_to(ROOT)),
                     'resultSha256': digest(result), 'ledgerDigestMatches': digest(result) == x['result_sha256'],
                     'runMatches': obj['run']['id'] == x['run'], 'profile': obj['profile']['id'],
                     'membershipCount': len(matches), 'savedCase': matches[0] if len(matches) == 1 else None})
    save('ledger-observations.json', rows)
    # File names only. No broad content search in native configuration, private/, .env, or keys.
    names = subprocess.run(['rg', '--files', '--hidden', '--no-ignore', 'build/acceptance'], cwd=ROOT,
                           capture_output=True, check=True, text=True).stdout.splitlines()
    found = []
    for name in names:
        p = ROOT / name
        if p.name != 'result.json' or OUT in p.parents or any(s in p.parts for s in ('private', '.git', 'source')):
            continue
        if p.is_symlink():
            continue
        try:
            obj = load(p)
        except (ValueError, UnicodeError):
            continue
        if not isinstance(obj, dict) or obj.get('profile', {}).get('id') != 'single-logout-idp':
            continue
        chosen = [{k: c.get(k) for k in ('id', 'outcome', 'verdict', 'reason_code', 'evidence', 'diagnostics')}
                  for r in obj.get('requirements', []) for c in r.get('cases', []) if c['id'] in IDS]
        found.append({'path': name, 'sha256': digest(p), 'run': obj['run']['id'], 'cases': chosen})
    save('saved-result-candidates.json', sorted(found, key=lambda x: x['path']))
    runs = {x['run'] for x in selected}
    transcripts = []
    for name in names:
        p = ROOT / name
        if ('transcript' not in p.name or p.suffix != '.json' or OUT in p.parents
                or any(s in p.parts for s in ('private', '.git', 'source')) or p.is_symlink()):
            continue
        try:
            obj = load(p)
        except (ValueError, UnicodeError):
            continue
        if isinstance(obj, list):
            matches = {e.get('runId') for e in obj if isinstance(e, dict)} & runs
            if matches:
                transcripts.append({'path': name, 'sha256': digest(p), 'runs': sorted(matches), 'entries': len(obj)})
    save('ledger-transcript-index.json', sorted(transcripts, key=lambda x: x['path']))
    save('input-pins.json', {str(p.relative_to(ROOT)): digest(p)
                            for p in (inventory, cases_file, coverage_file)})
    print(json.dumps({'observations': len(rows), 'ledgerDigestsMatch': all(x['ledgerDigestMatches'] for x in rows),
                      'membershipMatches': all(x['membershipCount'] == 1 and x['runMatches'] for x in rows),
                      'savedResultsInspected': len(found)}))


if __name__ == '__main__':
    main()
