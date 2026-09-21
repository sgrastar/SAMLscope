"""Capture only Run-scoped SAML originals and the pinned public target metadata from the reference Suite."""
import hashlib
import json
from pathlib import Path
import re
import subprocess


def capture(folder, run, entries):
    folder = Path(folder)
    if not re.fullmatch(r'run_[0-9A-HJKMNP-TV-Z]{26}', run):
        raise ValueError('Invalid Run')
    originals = folder/'decoded'; originals.mkdir(exist_ok=True)
    manifest = []; seen = set()
    for entry in entries:
        if entry.get('runId') != run or entry['id'] in seen:
            raise ValueError('Mixed or duplicate transcript')
        seen.add(entry['id'])
        if not entry.get('decodedSamlRef'): continue
        if not re.fullmatch(r'tx_[0-9A-HJKMNP-TV-Z]{26}', entry['id']):
            raise ValueError('Invalid transcript identity')
        source = 'transcripts/'+run+'/'+entry['id']+'.saml.xml'
        if entry['decodedSamlRef'] != source:
            raise ValueError('Unexpected transcript content path')
        destination = originals/(entry['id']+'.xml')
        subprocess.run(['docker','cp','samlscope-reference-suite:/data/'+source,str(destination)],
                       check=True,capture_output=True,timeout=30)
        manifest.append(dict(id=entry['id'],file=str(destination.relative_to(folder)),
            sha256=hashlib.sha256(destination.read_bytes()).hexdigest()))
    (folder/'decoded-manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    subprocess.run(['docker','cp','samlscope-reference-suite:/data/target-metadata/'+run+'.xml',
                    str(folder/'target-metadata.xml')],check=True,capture_output=True,timeout=30)
    return manifest
