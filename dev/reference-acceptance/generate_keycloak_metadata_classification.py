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
        f'対象一意一覧: {len(cases)}ケースID（台帳のKeycloak metadata_idpは{len(rows)}観測、重複なし）。',
        '',
        '| # | ケース | 義務 | 分類 | 理由コード |',
        '|---:|---|---|---|---|',
    ]
    for index, case in enumerate(cases, 1):
        row = next(r for r in rows if r['case'] == case)
        obligation = definitions.get(case, {}).get('obligation', '')
        lines.append(f"| {index} | `{case}` | {obligation} | `{row['capability_diagnosis']}` | `{row['reason_code']}` |")
    lines += [
        '',
        '分類の合計: ' + ' / '.join(f"`{key}` {counts[key]}" for key in sorted(counts)) + f" = {sum(counts.values())}。",
        '',
        f"メタデータ分類の合計は `suite-observation-gap` {counts.get('suite-observation-gap', 0)} + "
        f"`operator-attestation-available` {counts.get('operator-attestation-available', 0)} + "
        f"`feature-absent` {counts.get('feature-absent', 0)} = "
        f"{counts.get('suite-observation-gap', 0) + counts.get('operator-attestation-available', 0) + counts.get('feature-absent', 0)}で、"
        f"残り{counts.get('role-inapplicable', 0) + counts.get('evidence-form-mismatch', 0)}件は同プロファイル内の"
        f"非メタデータケース（`role-inapplicable` {counts.get('role-inapplicable', 0)} = `IIP-EXT01-b/c`、"
        f"`evidence-form-mismatch` {counts.get('evidence-form-mismatch', 0)} = `IIP-ALG01/02`）です。",
        '',
        '不存在が未確認の61ケースは`suite-observation-gap`へ移しました（`absence_basis=not-confirmed-investigated-path`）。'
        '`feature-absent`の7件はmdui公開要素で、Suite自身が取得した対象公開メタデータで不存在を確認済みです。'
        '`IIP-MD05.aw`は取込観測側（`suite-observation-gap`）にのみ属し、旧分類の重複は解消しています。',
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
