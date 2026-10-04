#!/usr/bin/env python3
"""Compile and run the metadata-rejection replay verifier against a campaign folder.

The replay loads only the Run originals, the target metadata and the receipt, then proves the real
receipt binds the rejection and that every temporary mutation fails to. It adopts no verdict.
"""
import argparse
import json
from pathlib import Path
import shutil
import subprocess
import tempfile

CONTAINER = 'samlscope-reference-suite'
CLASS = 'com.samlscope.runner.cases.VerifyMetadataRejectionEvidence'
SOURCE = Path(__file__).resolve().parent / 'VerifyMetadataRejectionEvidence.java'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--campaign-dir', type=Path, required=True)
    parser.add_argument('--variant')
    parser.add_argument('--adapter', required=True)
    parser.add_argument('--variants', help='Comma-separated reject fixtures (overrides --variant for multi-variant receipts)')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    folder = args.campaign_dir.resolve()
    if args.output.exists():
        raise ValueError('Refusing to overwrite an existing proof')
    work = Path(tempfile.mkdtemp(prefix='samlscope-rejection-replay-'))
    try:
        library = work / 'lib'
        subprocess.run(['docker', 'cp', CONTAINER + ':/opt/samlscope/lib', str(library)],
                       check=True, capture_output=True, timeout=120)
        classes = work / 'classes'
        classes.mkdir()
        classpath = str(library / '*')
        subprocess.run(['javac', '-cp', classpath, '-d', str(classes), str(SOURCE)],
                       check=True, capture_output=True, timeout=300)
        run = json.loads((folder / 'created.json').read_text())['run']['id']
        result = subprocess.run(['java', '-cp', str(classes) + ':' + classpath, CLASS,
                                 str(folder), str(args.output.resolve()),
                                 args.variants or args.variant, args.adapter],
                                check=True, capture_output=True, text=True, timeout=300)
        print(result.stdout.strip())
    finally:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == '__main__':
    main()
