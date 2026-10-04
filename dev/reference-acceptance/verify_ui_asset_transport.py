#!/usr/bin/env python3
"""Verify real HTTP and certificate-validated HTTPS return the exact same public fixture."""
import argparse
import hashlib
import json
from pathlib import Path
import ssl
import urllib.request


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--asset', type=Path, required=True)
    parser.add_argument('--certificate', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--http-port', type=int, default=18480)
    parser.add_argument('--https-port', type=int, default=18443)
    args = parser.parse_args()
    if args.output.exists(): raise ValueError('Refusing to overwrite transport evidence')
    if not all(1024 <= p <= 65535 for p in [args.http_port, args.https_port]): raise ValueError('Invalid port')
    expected = args.asset.read_bytes()
    digest = hashlib.sha256(expected).hexdigest()
    context = ssl.create_default_context(cafile=str(args.certificate))
    records = []
    for scheme, port in [('http', args.http_port), ('https', args.https_port)]:
        url = f'{scheme}://localhost:{port}/metadata-lab/ui-fixture.svg'
        with urllib.request.urlopen(url, context=context if scheme == 'https' else None, timeout=15) as response:
            actual = response.read(65537)
            if response.status != 200 or response.geturl() != url or actual != expected:
                raise ValueError('Fixture transport did not return the exact original')
            if response.headers.get_content_type() != 'image/svg+xml': raise ValueError('Unexpected media type')
            records.append(dict(url=url, status=response.status, sha256=hashlib.sha256(actual).hexdigest(), bytes=len(actual)))
    report = dict(schema='samlscope-ui-asset-transport-v1', asset_sha256=digest,
        certificate_sha256=hashlib.sha256(args.certificate.read_bytes()).hexdigest(),
        tls_validation='provided-certificate-and-hostname', observations=records,
        product_verdict_adopted=False)
    with args.output.open('x') as output: json.dump(report, output, indent=2)
    print('HTTP and certificate-validated HTTPS returned identical fixture bytes')


if __name__ == '__main__': main()
