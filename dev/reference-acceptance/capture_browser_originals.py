"""Export Recorder-owned browser response bodies without interpreting them."""

import hashlib
import json
import re
import subprocess
from pathlib import Path


def capture(output, entries, container='samlscope-reference-suite'):
    output = Path(output)
    destination = output / 'browser-originals'
    destination.mkdir(exist_ok=True)
    manifest = []
    for entry in entries:
        if entry.get('method') != 'BROWSER':
            continue
        entry_id = entry.get('id', '')
        body_ref = entry.get('bodyRef', '')
        if re.fullmatch(r'tx_[0-9A-HJKMNP-TV-Z]{26}', entry_id) is None:
            raise ValueError('Unsafe browser transcript identifier')
        if re.fullmatch(r'transcripts/run_[0-9A-HJKMNP-TV-Z]{26}/tx_[0-9A-HJKMNP-TV-Z]{26}\.body', body_ref) is None:
            raise ValueError('Unsafe browser body reference')
        target = destination / (entry_id + '.body')
        subprocess.run(
            ['docker', 'cp', container + ':/data/' + body_ref, str(target)],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        raw = target.read_bytes()
        if len(raw) != entry.get('bodyBytes'):
            raise RuntimeError('Browser body byte count differs from the Recorder entry')
        manifest.append({
            'id': entry_id,
            'file': 'browser-originals/' + target.name,
            'sha256': hashlib.sha256(raw).hexdigest(),
            'bytes': len(raw),
        })
    (output / 'browser-originals-manifest.json').write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + '\n')
    return manifest

