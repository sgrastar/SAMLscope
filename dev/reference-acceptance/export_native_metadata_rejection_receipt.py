#!/usr/bin/env python3
"""Bind a product's native metadata rejection to the Run's fetched original fixture.

The Runner only accepts a rejection that is tied to the transcript entry the Suite actually
delivered for the reject variant, to the pinned public target metadata, and to the product's own
rejection record. This exporter refuses to fabricate any of those links. With several reject
fixtures it pairs product rejection records to fixtures by delivery order, never by assertion.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess


SHA = lambda raw: hashlib.sha256(raw).hexdigest()
ADAPTERS = {'shibboleth-resolver', 'simplesamlphp-parser', 'keycloak-import', 'shibboleth-idp'}


def read(path):
    return json.loads(Path(path).read_text())


def log_bytes(args):
    if args.log_file is not None:
        return Path(args.log_file).read_bytes()
    if args.container is None or args.log_path is None:
        raise ValueError('resolver log source is required')
    return subprocess.check_output(['docker', 'exec', args.container, 'cat', args.log_path], timeout=60)


def rejection_lines(args):
    """Product rejection records for this Run, in log order. Level filter avoids stack traces."""
    marker = args.marker.encode('utf-8')
    run = args.run.encode('utf-8')
    level = (b' - ' + args.level.encode('utf-8') + b' [') if args.level else None
    return [line for line in log_bytes(args).split(b'\n')
            if marker in line and run in line and line.strip() and (level is None or level in line)]


def export(args):
    folder = Path(args.campaign_dir).resolve()
    variants = args.variants.split(',') if args.variants else [args.variant]
    if len(set(variants)) != len(variants):
        raise ValueError('Duplicate reject variant')
    transcript = read(folder / 'transcript.json')
    manifest = read(folder / 'decoded-manifest.json')
    if not transcript or not manifest:
        raise ValueError('Campaign evidence is incomplete')
    runs = {entry['runId'] for entry in transcript}
    if runs != {args.run}:
        raise ValueError('Transcript does not belong to a single Run')
    entries = {entry['id']: entry for entry in transcript}
    if len(entries) != len(transcript):
        raise ValueError('Duplicate transcript identity')
    raw_evidence = []
    seen = set()
    for row in manifest:
        source = folder / row['file']
        path = source.resolve()
        if path.parent != (folder / 'decoded').resolve() or source.is_symlink():
            raise ValueError('Invalid original path')
        raw = path.read_bytes()
        if SHA(raw) != row['sha256'] or row['id'] in seen or row['id'] not in entries:
            raise ValueError('Original identity mismatch')
        seen.add(row['id'])
        raw_evidence.append(dict(reference=row['id'], sha256=row['sha256']))
    if not raw_evidence:
        raise ValueError('No Run originals captured')
    restoration = read(folder / 'restoration.json')
    if restoration.get('restored') is not True:
        raise ValueError('Product configuration was not restored')
    delivered = []
    for variant in variants:
        fixture = (folder / variant / 'fixture.xml').read_bytes()
        fixture_sha = SHA(fixture)
        prepared = [entry for entry in transcript
                    if entry['direction'] == 'OUTBOUND'
                    and entry['samlSummary'].get('type') == 'MetadataPrepared'
                    and entry['samlSummary'].get('variant') == variant]
        if len(prepared) != 1:
            raise ValueError('Reject variant delivery is ambiguous: ' + variant)
        original_sha = next(row['sha256'] for row in raw_evidence if row['reference'] == prepared[0]['id'])
        if original_sha != fixture_sha:
            raise ValueError('Reject fixture differs from the Run original the Suite delivered: ' + variant)
        delivered.append((prepared[0]['timestamp'], variant, fixture_sha))
    lines = rejection_lines(args)
    # Identical product records carry no variant identity, so map them by delivery order. The log
    # may also contain rejections for variants outside this receipt (e.g. an informational probe).
    order = (args.rejected_order or ','.join(variants)).split(',')
    if len(lines) != len(order) or set(variants) - set(order):
        raise ValueError(f'Expected {len(order)} product rejection records for {order}, found {len(lines)}')
    positions = [order.index(variant) for variant in variants]
    if positions != sorted(positions):
        raise ValueError('Reject variants are not in delivery order')
    line_by_variant = dict(zip(order, lines))
    fixture_by_variant = {variant: fixture_sha for _, variant, fixture_sha in delivered}
    rejections = [dict(
        variant=variant,
        fixtureSha256=fixture_by_variant[variant],
        nativeRejection=dict(source=args.adapter, detailSha256=SHA(line_by_variant[variant]),
                             logRef=args.log_ref or args.log_path or str(args.log_file)))
        for variant in variants]
    if args.adapter not in ADAPTERS:
        raise ValueError('Unsupported evidence adapter')
    return dict(
        schema='samlscope-native-metadata-rejection-receipt-v1',
        runId=args.run,
        targetMetadataSha256=SHA((folder / 'target-metadata.xml').read_bytes()),
        restored=True,
        evidenceAdapter=args.adapter,
        rawEvidence=raw_evidence,
        rejections=rejections,
        conditionIssues=[])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--campaign-dir', type=Path, required=True)
    parser.add_argument('--run', required=True)
    parser.add_argument('--variant')
    parser.add_argument('--variants', help='Comma-separated reject fixtures delivered in this Run')
    parser.add_argument('--rejected-order',
                        help='All fixtures whose product records appear in the log, in order')
    parser.add_argument('--adapter', required=True, choices=sorted(ADAPTERS))
    parser.add_argument('--marker', required=True,
                        help='Substring that identifies the product rejection record')
    parser.add_argument('--level', help='Log level token (e.g. ERROR or WARN) to exclude stack traces')
    parser.add_argument('--container', help='Container holding the resolver log')
    parser.add_argument('--log-path', help='Resolver log path inside the container')
    parser.add_argument('--log-file', type=Path, help='Local copy of the resolver log')
    parser.add_argument('--log-ref', help='Stable reference recorded in the receipt (defaults to the log source)')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if (args.variant is None) == (args.variants is None):
        parser.error('Provide exactly one of --variant or --variants')
    if (args.container is None) == (args.log_file is None) and args.log_path is None:
        parser.error('Provide either --container with --log-path or --log-file')
    receipt = export(args)
    args.output.write_text(json.dumps(receipt, indent=2) + '\n')
    print('Wrote', args.output)


if __name__ == '__main__':
    main()
