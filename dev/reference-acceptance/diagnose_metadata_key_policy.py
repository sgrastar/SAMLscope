#!/usr/bin/env python3
"""Explain native import-policy gaps from bound originals, without assigning a product outcome."""
import argparse
import hashlib
import json
from pathlib import Path
import xml.etree.ElementTree as ET
from export_metadata_key_receipt import export


def diagnose(folder):
    receipt=export(folder.resolve())
    original=json.loads((folder/'qualified-metadata-key-receipt.json').read_text())
    if receipt!=original:
        raise ValueError('Native source changed since receipt capture')
    rows=[]
    for condition in receipt['conditions']:
        variant=condition['variant']
        fixture=(folder/variant/'fixture.xml').read_bytes()
        role=ET.fromstring(fixture).find('{urn:oasis:names:tc:SAML:2.0:metadata}SPSSODescriptor')
        if role is None:
            raise ValueError('Missing SP role')
        attrs=condition['nativeClient']['attributes']
        enabled=attrs.get('saml.client.signature')=='true'
        rows.append(dict(variant=variant,fixture_sha256=hashlib.sha256(fixture).hexdigest(),
            advertised_authn_requests_signed=role.get('AuthnRequestsSigned'),
            native_client_signature_enabled=enabled,
            native_signing_certificate_present=bool(attrs.get('saml.signing.certificate')),
            diagnosis='native-signature-policy-enabled' if enabled else 'native-signature-policy-disabled-after-import',
            positive_response_recorded=bool(condition['positive'].get('responseReference')),
            negative_response_recorded=bool(condition['negative'].get('responseReference')),
            response_signature_verified_by_this_diagnostic=False,
            affects_verdict=False))
    return dict(run=receipt['runId'],conditions=rows,verdict_adopted=False,
        limitation='Import policy and response presence only; response signatures and product conformance are not inferred.')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();report=diagnose(args.evidence)
    with args.output.open('x') as stream:
        json.dump(report,stream,indent=2);stream.write('\n')
    for row in report['conditions']:
        if not row['native_client_signature_enabled']:print(row['variant'],row['diagnosis'])
