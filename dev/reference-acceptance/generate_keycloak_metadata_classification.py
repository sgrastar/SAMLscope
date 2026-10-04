#!/usr/bin/env python3
"""Generate the Keycloak metadata classification table from the unique ledger rows."""
import argparse
import json
import yaml
from collections import Counter
from pathlib import Path

START = '<!--keycloak-metadata:start-->'
END = '<!--keycloak-metadata:end-->'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inventory', type=Path,
                        default=Path('build/acceptance/reference-20260914/remaining-audit/inventory.json'))
    parser.add_argument('--definitions', type=Path, default=Path('tests/cases.yaml'))
    parser.add_argument('--output', type=Path, default=Path('docs/33-keycloak-metadata-observation.md'))
    args = parser.parse_args()
    rows = [r for r in json.loads(args.inventory.read_text())
            if r['product'] == 'keycloak' and r['profile'] == 'metadata_idp']
    definitions = {c['id']: c for c in yaml.safe_load(args.definitions.read_text())['cases']}
    cases = sorted({r['case'] for r in rows})
    if len(cases) != len(rows):
        raise ValueError(f'duplicate Keycloak metadata rows: {len(rows)} rows / {len(cases)} ids')
    classified = {}
    for row in rows:
        classified.setdefault(row['case'], set()).add(row['capability_diagnosis'])
    conflicting = {case: value for case, value in classified.items() if len(value) > 1}
    if conflicting:
        raise ValueError(f'case classified twice: {conflicting}')
    missing = [case for case in cases if not classified[case]]
    if missing:
        raise ValueError(f'unclassified Keycloak metadata cases: {missing}')
    counts = Counter(next(iter(value)) for value in classified.values())
    lines = [
        START,
        f'Unique scope: {len(cases)} case IDs ({len(rows)} Keycloak metadata_idp ledger observations, without duplicates).',
        '',
        '| # | Case | Obligation | Classification | Reason code |',
        '|---:|---|---|---|---|',
    ]
    for index, case in enumerate(cases, 1):
        row = next(r for r in rows if r['case'] == case)
        obligation = definitions.get(case, {}).get('obligation', '')
        lines.append(f"| {index} | `{case}` | {obligation} | `{row['capability_diagnosis']}` | `{row['reason_code']}` |")
    lines += [
        '',
        'Classification totals: ' + ' / '.join(f"`{key}` {counts[key]}" for key in sorted(counts)) + f" = {sum(counts.values())}.",
        '',
        f"Metadata classification totals are `suite-observation-gap` {counts.get('suite-observation-gap', 0)} + "
        f"`operator-attestation-available` {counts.get('operator-attestation-available', 0)} + "
        f"`feature-absent` {counts.get('feature-absent', 0)} = "
        f"{counts.get('suite-observation-gap', 0) + counts.get('operator-attestation-available', 0) + counts.get('feature-absent', 0)}. "
        f"The remaining {counts.get('role-inapplicable', 0) + counts.get('evidence-form-mismatch', 0)} observations are "
        f"non-metadata cases in the same profile (`role-inapplicable` {counts.get('role-inapplicable', 0)} = `IIP-EXT01-b/c`, "
        f"`evidence-form-mismatch` {counts.get('evidence-form-mismatch', 0)} = `IIP-ALG01/02`).",
        '',
        'The 61 cases whose absence was unconfirmed were moved to `suite-observation-gap` (`absence_basis=not-confirmed-investigated-path`). '
        'The 7 `feature-absent` cases concern published mdui elements; absence was confirmed from target public metadata fetched by the Suite. '
        '`IIP-MD05.aw` belongs only to import observation (`suite-observation-gap`), resolving the previous classification overlap.',
        END,
    ]
    document = args.output.read_text()
    if START not in document or END not in document:
        raise ValueError('docs/33 is missing the classification markers')
    before, remainder = document.split(START, 1)
    _, after = remainder.split(END, 1)
    args.output.write_text(before + '\n'.join(lines) + after)
    print(f'classified {len(cases)} cases: {dict(counts)}')


if __name__ == '__main__':
    main()
