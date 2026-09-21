"""Cross-check every unresolved observation against approved case contracts and actual result bytes.

This audit proves inventory integrity, never implementation completeness or a target verdict.
"""
import argparse
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path
import yaml


def digest(data):
    return hashlib.sha256(data).hexdigest()


def audit(root, catalog_path):
    inventory_path = root / 'remaining-audit/inventory.json'
    inventory_raw = inventory_path.read_bytes()
    catalog_raw = catalog_path.read_bytes()
    catalog = yaml.safe_load(catalog_raw)
    definitions = {case['id']: case for case in catalog['cases']}
    if len(definitions) != len(catalog['cases']):
        raise ValueError('Duplicate case IDs in catalog')
    observations = json.loads(inventory_raw)
    groups = defaultdict(list)
    errors = []
    seen = set()
    cache = {}
    for row in observations:
        identity = (row['product'], row['profile'], row['case'])
        if identity in seen:
            errors.append({'observation': identity, 'error': 'duplicate observation'})
        seen.add(identity)
        definition = definitions.get(row['case'])
        if definition is None:
            errors.append({'observation': identity, 'error': 'case absent from approved catalog'})
            continue
        variants = definition['variant_plan']
        if row['variant_references'] != [v['reference'] for v in variants]:
            errors.append({'observation': identity, 'error': 'variant references differ from approved contract'})
        if row['variant_instructions'] != [v['instruction_en'] for v in variants]:
            errors.append({'observation': identity, 'error': 'variant instructions differ from approved contract'})
        controls = [{k: c[k] for k in ('id', 'kind', 'fixture')} for c in definition['controls']]
        if row['controls'] != controls:
            errors.append({'observation': identity, 'error': 'controls differ from approved contract'})
        folder = Path(row['evidence_folder'])
        if not folder.is_absolute() and not folder.is_dir():
            folder = root / folder
        path = folder / 'result.json'
        try:
            if path not in cache:
                raw = path.read_bytes()
                result = json.loads(raw)
                cache[path] = (digest(raw), result)
            actual_digest, result = cache[path]
            if actual_digest != row['result_sha256']:
                raise ValueError('result digest differs from selected evidence')
            if result['run']['id'] != row['run']:
                raise ValueError('result belongs to another Run')
            cases = [c for req in result['requirements'] for c in req['cases'] if c['id'] == row['case']]
            if len(cases) != 1:
                raise ValueError('case missing or duplicated in selected result')
            if row.get('reason_code') == 'audit.algorithm-verification-controls-unproven':
                from audit_algorithm_verification_evidence import withdrawals
                qualified = [r for r in withdrawals(root)
                             if (r['product'], r['profile'], r['case']) == tuple(identity)]
                if len(qualified) != 1 or any(row.get(k) != v for k, v in qualified[0].items()):
                    raise ValueError('algorithm audit qualification differs from verified source')
            else:
                if cases[0]['verdict'] != 'NOT_VERIFIED':
                    raise ValueError('resolved result remains in unresolved inventory')
                if cases[0]['reason_code'] != row['reason_code']:
                    raise ValueError('diagnostic differs from selected result')
        except (OSError, KeyError, ValueError) as error:
            errors.append({'observation': identity, 'error': str(error), 'result': str(path)})
        groups[row['case']].append({k: row[k] for k in ('product', 'profile', 'run', 'category', 'reason_code', 'result_sha256', 'evidence_folder')})
    contracts = []
    for case_id, rows in sorted(groups.items()):
        definition = definitions[case_id]
        contracts.append({'case': case_id, 'obligation': definition['obligation'], 'role': definition['role'],
                          'mode': definition['mode'], 'milestone': definition['milestone'],
                          'variant_plan': definition['variant_plan'], 'variant_groups': definition['variant_groups'],
                          'controls': definition['controls'], 'requires': definition.get('requires', {}),
                          'interpretation_constraints': definition.get('interpretation_constraints', []),
                          'counterexample_en': definition['counterexample_en'],
                          'observations': rows, 'completion': 'not_proven'})
    return {'inventory_sha256': digest(inventory_raw), 'catalog_sha256': digest(catalog_raw),
            'observation_count': len(observations), 'case_count': len(contracts),
            'variant_count': sum(len(c['variant_plan']) for c in contracts),
            'control_count': sum(len(c['controls']) for c in contracts),
            'category_counts': dict(Counter(row['category'] for row in observations)),
            'errors': errors, 'contracts': contracts}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence-root', type=Path, required=True)
    parser.add_argument('--catalog', type=Path, default=Path('tests/cases.yaml'))
    args = parser.parse_args()
    report = audit(args.evidence_root, args.catalog)
    output = args.evidence_root / 'remaining-audit/unresolved-contract-audit.json'
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps({k: v for k, v in report.items() if k not in ('contracts',)}, ensure_ascii=False))
    if report['errors']:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
