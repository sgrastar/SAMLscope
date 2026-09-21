#!/usr/bin/env python3
"""Capture and bind a completed native key campaign after observer restoration, without adopting verdicts."""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
from capture_run_originals import capture
from export_metadata_key_receipt import export


def prepare(campaign):
    campaign = Path(campaign).resolve()
    batch = campaign / 'observations'
    restoration = json.loads((campaign / 'observer/restoration.json').read_text())
    if not all(restoration.get(k) for k in ('provider_removed','realm_configuration_restored','product_restart_verified')):
        raise ValueError('Restore product before preparing acceptance evidence')
    matrix = json.loads((batch / 'matrix.json').read_text())
    if matrix['matrix'] != 'keys':
        raise ValueError('This exporter requires the metadata key matrix')
    report = dict(started_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        product_configuration_writes=0, protocol_requests=0, verdict_adopted=False, profiles=[])
    for folder in sorted(batch.iterdir()):
        if not folder.is_dir() or not (folder / 'created.json').is_file():
            continue
        record = dict(profile=folder.name, status='started')
        report['profiles'].append(record)
        try:
            created = json.loads((folder / 'created.json').read_text())
            run = created['run']['id']
            entries = json.loads((folder / 'transcript.json').read_text())
            manifest = folder / 'decoded-manifest.json'
            if manifest.exists():
                raise ValueError('Existing original snapshot; refusing to overwrite')
            captured = capture(folder,run,entries)
            record.update(run=run,originals_captured=len(captured))
            receipt = export(folder)
            raw = (json.dumps(receipt,indent=2)+'\n').encode()
            path = folder / 'qualified-metadata-key-receipt.json'
            with path.open('xb') as stream:
                stream.write(raw)
            record.update(status='receipt-prepared',receipt_sha256=hashlib.sha256(raw).hexdigest(),
                conditions_prepared=len(receipt['conditions']),condition_issues=receipt.get('conditionIssues',[]),
                original_signature_replay='required',runtime_adoption='not-performed')
        except Exception as error:
            record.update(status='incomplete',error_type=type(error).__name__,reason=str(error))
    report['finished_at'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    with (batch / 'key-evidence-preparation.json').open('x') as stream:
        json.dump(report,stream,indent=2)
        stream.write('\n')
    if not report['profiles'] or any(r['status']!='receipt-prepared' for r in report['profiles']):
        raise RuntimeError('Key evidence preparation incomplete; inspect key-evidence-preparation.json')
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--campaign',type=Path,required=True)
    args = parser.parse_args()
    result = prepare(args.campaign)
    print('Prepared receipts for',len(result['profiles']),'profiles; signature replay and formal evaluation still required')
