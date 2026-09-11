#!/usr/bin/env python3
"""Generate source membership for result notices without modifying signed catalogs."""
import argparse
import hashlib
import json
import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
INPUTS = ['tests/specs.yaml', 'tests/coverage.yaml', 'tests/cases.yaml', 'tests/predicates.yaml']


def generate():
    specs = yaml.safe_load((ROOT / INPUTS[0]).read_text())['specs']
    coverage = yaml.safe_load((ROOT / INPUTS[1]).read_text())
    cases = yaml.safe_load((ROOT / INPUTS[2]).read_text())['cases']
    predicates = yaml.safe_load((ROOT / INPUTS[3]).read_text())
    def ids(value):
        text = json.dumps(value, default=str)
        return {key for key in specs if re.search(r'(?<![A-Za-z0-9_-])' + re.escape(key) + r'(?![A-Za-z0-9_-])', text)}
    obligations = {o['key']: o for r in coverage['requirements'] for o in r['obligations']}
    membership = {key: ids(o) for key, o in obligations.items()}
    case_sources = {}
    for case in cases:
        for key in set(re.findall(r'IIP-[A-Z0-9]+\.[a-z][a-z0-9]*', json.dumps(case, default=str))):
            case_sources.setdefault(key, set()).update(ids(case))
    # Include test instructions and predicate definitions, not just the primary specification.
    for key, o in obligations.items():
        predicate = (o.get('condition') or {}).get('predicate')
        if predicate:
            membership[key] |= ids(predicates.get('predicates', {}).get(predicate, {}))
        membership[key] |= case_sources.get(key, set())
    # Links can import variants transitively. Attribution does not change coverage ownership.
    changed = True
    while changed:
        changed = False
        for key, o in obligations.items():
            linked = json.dumps(o.get('linked_obligations', []))
            before = len(membership[key])
            for other in re.findall(r'IIP-[A-Z0-9]+\.[a-z][a-z0-9]*', linked):
                membership[key] |= membership.get(other, set())
            changed |= before != len(membership[key])
    by_case = {}
    for case in cases:
        selected = ids(case)
        for key in re.findall(r'IIP-[A-Z0-9]+\.[a-z][a-z0-9]*', json.dumps(case, default=str)):
            selected |= membership.get(key, set())
        by_case[case['id']] = sorted(selected)
    profiles = sorted((ROOT / 'profiles').glob('*.json'))
    by_profile = {}
    for path in profiles:
        profile = json.loads(path.read_text())
        selected = set()
        for case in profile['cases']:
            selected.update(by_case[case['id']])
        for key in profile.get('non_executable_obligations', []):
            selected.update(membership[key])
        by_profile[profile['profile']] = sorted(selected)
    return {
        'schema_version': 1,
        'scope': 'Source references of selected obligation definitions, tests and imported variants; this is attribution, not evaluation coverage or legal clearance.',
        'input_sha256': {p: hashlib.sha256((ROOT / p).read_bytes()).hexdigest() for p in INPUTS + [str(p.relative_to(ROOT)) for p in profiles]},
        'case_sources': by_case,
        'profile_sources': by_profile,
        'obligation_sources': {k: sorted(v) for k, v in sorted(membership.items())},
        'sources': {k: {f: str(v[f]) for f in ['title', 'publisher', 'version', 'url']} for k, v in specs.items()},
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    path = ROOT / 'LICENSES/material-index.json'
    index = generate()
    content = json.dumps(index, ensure_ascii=False, indent=2) + '\n'
    if args.check:
        if not path.exists() or path.read_text() != content:
            raise SystemExit('Material index is stale: run dev/licensing/materials.py')
    else:
        path.write_text(content)
    public_path = ROOT / 'web/public/licenses/source-membership.json'
    public = json.dumps({k: index[k] for k in ['case_sources', 'profile_sources', 'obligation_sources']}, ensure_ascii=False, indent=2) + '\n'
    if args.check:
        if not public_path.exists() or public_path.read_text() != public:
            raise SystemExit('Public source membership is stale: run dev/licensing/materials.py')
    else:
        public_path.parent.mkdir(parents=True, exist_ok=True)
        public_path.write_text(public)
    registry = json.loads((ROOT / 'LICENSES/source-notices.json').read_text())
    for source in registry['sources']:
        assert hashlib.sha256(source['notice_text'].encode()).hexdigest() == source['notice_text_sha256'], source['id']
    assert registry['original_content']['license_text'] == (ROOT / 'LICENSES/CC-BY-SA-4.0.txt').read_text()
    print('Material index, original-content license and retained notice hashes match')


if __name__ == '__main__':
    main()
