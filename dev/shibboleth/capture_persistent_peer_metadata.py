#!/usr/bin/env python3
"""Read an already resolved SP entity through the native Shibboleth metadata-query endpoint."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import xml.etree.ElementTree as ET


def capture(folder):
    folder = Path(folder)
    created = json.loads((folder / 'created.json').read_text())['run']
    entity = 'http://localhost:18080/p/' + created['planId']
    command = ['/opt/reference-idp/bin/mdquery.sh', '-u', 'http://localhost:8080/idp', '-e', entity]
    started = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
    completed = subprocess.run(['docker', 'exec', 'samlscope-reference-shibboleth', *command],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=45)
    (folder / 'native-effective-peer-metadata.xml').write_bytes(completed.stdout)
    (folder / 'native-mdquery.stderr').write_bytes(completed.stderr)
    root = ET.fromstring(completed.stdout)
    if completed.returncode != 0 or root.tag != '{urn:oasis:names:tc:SAML:2.0:metadata}EntityDescriptor' or root.get('entityID') != entity:
        raise RuntimeError('Native effective peer metadata read-back failed')
    record = dict(operation='native-admin-metadata-read', command=command, container='samlscope-reference-shibboleth',
                  entityId=entity, runId=created['id'], startedAt=started,
                  completedAt=datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
                  exitCode=completed.returncode, bytes=len(completed.stdout),
                  sha256=hashlib.sha256(completed.stdout).hexdigest())
    (folder / 'native-mdquery-operation.json').write_text(json.dumps(record, indent=2) + '\n')
    return record


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('folder', type=Path)
    print(json.dumps(capture(parser.parse_args().folder), indent=2))
