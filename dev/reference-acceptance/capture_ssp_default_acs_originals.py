#!/usr/bin/env python3
"""Capture immutable Run originals for the existing SimpleSAMLphp default-ACS campaign."""
import argparse
import hashlib
import json
from pathlib import Path

from capture_run_originals import capture


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('folder', type=Path)
    args = parser.parse_args()
    folder = args.folder.resolve()
    run = json.loads((folder / 'created.json').read_text())['run']['id']
    transcript = json.loads((folder / 'transcript.json').read_text())
    manifest = capture(folder, run, transcript)
    target = folder / 'target-metadata.xml'
    record = {'run': run, 'originals': len(manifest),
              'target_metadata_sha256': hashlib.sha256(target.read_bytes()).hexdigest()}
    (folder / 'original-capture.json').write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps(record, sort_keys=True))


if __name__ == '__main__':
    main()
