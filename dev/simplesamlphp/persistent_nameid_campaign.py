#!/usr/bin/env python3
"""Exercise persistent NameID generation with an exact, temporary reference-IdP setting."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import urllib.request

REPO = Path(__file__).resolve().parents[2]
HOSTED = REPO / 'build/acceptance/reference-20260914/ssp-config/saml20-idp-hosted.php'
CONTAINER = 'samlscope-reference-ssp'
PROBE = '/var/simplesamlphp/public/samlscope-apcu-clear.php'


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def reload_product():
    subprocess.run(['docker', 'exec', CONTAINER, 'apache2ctl', 'graceful'], check=True, timeout=60)
    source = ("<?php require '/var/simplesamlphp/lib/_autoload.php';"
              "if (function_exists('apcu_clear_cache')) apcu_clear_cache(); echo 'CLEARED';")
    subprocess.run(['docker', 'exec', '-i', CONTAINER, 'sh', '-c', 'cat > ' + PROBE],
                   input=source.encode(), check=True, timeout=30)
    try:
        with urllib.request.urlopen('http://localhost:18380/simplesaml/samlscope-apcu-clear.php', timeout=30) as response:
            if response.read() != b'CLEARED':
                raise RuntimeError('APCu cache clear did not complete')
    finally:
        subprocess.run(['docker', 'exec', CONTAINER, 'rm', '-f', PROBE], check=True, timeout=30)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    out = args.output.resolve()
    if out.exists() and any(out.iterdir()):
        raise ValueError('Evidence directory must be empty')
    out.mkdir(parents=True, exist_ok=True)
    original = HOSTED.read_bytes()
    marker = b"$metadata['http://localhost:18380/idp']['authproc']"
    if marker in original or b'?>' in original:
        raise ValueError('Reference hosted metadata has unexpected content')
    configured = original + (
        b"\n$metadata['http://localhost:18380/idp']['authproc'] = [20 => "
        b"['class' => 'saml:PersistentNameID', 'identifyingAttribute' => 'uid']];\n"
    )
    record = {'original_sha256': digest(original), 'configured_sha256': digest(configured),
              'configuration_write_attempts': 0, 'product_reloads': 0, 'human_operations': 0}
    try:
        HOSTED.write_bytes(configured)
        record['configuration_write_attempts'] += 1
        if HOSTED.read_bytes() != configured:
            raise RuntimeError('Configured file read-back mismatch')
        reload_product()
        record['product_reloads'] += 1
        child = out / 'browser-chain'
        process = subprocess.run([sys.executable, str(REPO / 'dev/simplesamlphp/browser_chain_campaign.py'),
                                  '--output', str(child), '--stop-after-case', 'IIP-IDP10-d-idp-01'],
                                 stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=1800)
        (out / 'campaign.log').write_text(process.stdout)
        record['campaign_exit_code'] = process.returncode
    finally:
        HOSTED.write_bytes(original)
        record['configuration_write_attempts'] += 1
        record['final_sha256'] = digest(HOSTED.read_bytes())
        record['restored'] = record['final_sha256'] == record['original_sha256']
        try:
            reload_product()
            record['product_reloads'] += 1
        finally:
            (out / 'hosted-configuration.json').write_text(json.dumps(record, indent=2) + '\n')
        if not record['restored']:
            raise RuntimeError('Hosted metadata restore failed')
    if record.get('campaign_exit_code') != 0:
        raise RuntimeError('Browser campaign failed; inspect campaign.log')


if __name__ == '__main__':
    main()
