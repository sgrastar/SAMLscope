#!/usr/bin/env python3
"""Compile and run the native ECDSA evidence replay against one campaign profile.

The replay reads only saved originals and a receipt, generates disposable negative controls, and
does not change a target product or assign a product verdict.
"""
import argparse
from pathlib import Path
import json
import shutil
import subprocess
import tempfile


CONTAINER = 'samlscope-reference-suite'
CLASS = 'com.samlscope.runner.cases.VerifyNativeEcProtocol'
SOURCE = Path(__file__).resolve().parent / 'VerifyNativeEcProtocol.java'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--campaign-dir', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    folder = args.campaign_dir.resolve()
    output = args.output.resolve()
    if output.exists():
        raise ValueError('Refusing to overwrite an existing proof')
    run = json.loads((folder / 'created.json').read_text())['run']['id']
    receipt = folder / 'preparation-receipts' / f'{run}.json'
    if not receipt.is_file():
        raise ValueError('Missing native ECDSA receipt')
    work = Path(tempfile.mkdtemp(prefix='samlscope-native-ec-replay-'))
    try:
        library = work / 'lib'
        subprocess.run(['docker', 'cp', CONTAINER + ':/opt/samlscope/lib', str(library)],
                       check=True, capture_output=True, timeout=120)
        classes = work / 'classes'
        classes.mkdir()
        classpath = str(library / '*')
        subprocess.run(['javac', '-cp', classpath, '-d', str(classes), str(SOURCE)],
                       check=True, capture_output=True, timeout=300)
        result = subprocess.run(['java', '-cp', str(classes) + ':' + classpath, CLASS,
                                 str(folder), str(receipt.parent), str(output)],
                                check=True, capture_output=True, text=True, timeout=300)
        print(result.stdout.strip())
    finally:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == '__main__':
    main()
