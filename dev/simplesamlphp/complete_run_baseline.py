#!/usr/bin/env python3
"""Complete an existing reference Run's normal login with one native import and exact restore."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import time
import urllib.request
from attribute_name_capability import native, api, save, BASE, Client, ConfigurationBatch, REPO


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if not re.fullmatch(r'run_[0-9A-HJKMNP-TV-Z]{26}', args.run): raise ValueError('Invalid Run')
    out = args.output.resolve(); out.mkdir(parents=True, exist_ok=False)
    run = api('/api/runs/' + args.run); plan = run['planId']
    if not re.fullmatch(r'plan_[0-9A-HJKMNP-TV-Z]{26}', plan): raise ValueError('Invalid Plan')
    entity = BASE + '/p/' + plan
    configuration = ConfigurationBatch(REPO / 'build/acceptance/reference-20260914/ssp-config/saml20-sp-remote.php')
    if entity.encode() in configuration.original or b'?>' in configuration.original: raise ValueError('Ambiguous overlay')
    with urllib.request.urlopen(entity + '/metadata',timeout=30) as response: fixture=response.read()
    (out/'fixture.xml').write_bytes(fixture)
    parsed=subprocess.run(['docker','exec','-i','samlscope-reference-ssp','php','-r',native.PHP,entity,'default'],
        input=fixture,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=40)
    if parsed.returncode: raise RuntimeError('Native baseline parser failed before configuration')
    (out/'parser-output.json').write_bytes(parsed.stdout)
    data=json.loads(parsed.stdout)
    if data['entity_id']!=entity or data['validate_authnrequest'] is not True: raise ValueError('Unusable baseline import')
    operations=[]
    try:
        fingerprint=configuration.apply(data['php'].encode())
        operations.append(dict(operation='write',configuration_sha256=fingerprint,read_back=True))
        time.sleep(3)
        receipt=Client().flow(entity+'/start/m0-roundtrip?run='+args.run,None,
            os.environ.get('REFERENCE_USERNAME','samlscope-m0-user'),os.environ.get('REFERENCE_PASSWORD','samlscope-m0-password'))
        save(out/'flow.json',receipt)
        operations.append(dict(operation='ordinary-login',status=receipt))
        if receipt!='recorded': raise RuntimeError('Ordinary login not recorded')
    finally:
        restored=configuration.restore()
        save(out/'operations.json',dict(run=args.run,operations=operations,**restored,configuration_settle_seconds=3,human_operations=0))
        save(out/'run-after.json',api('/api/runs/'+args.run))
    print('Ordinary login recorded; native configuration restored')


if __name__=='__main__':main()
