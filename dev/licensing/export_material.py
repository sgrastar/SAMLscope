#!/usr/bin/env python3
"""Export public catalog/doc material with in-file notices, preserving approved inputs."""
import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def sha(data):
    return hashlib.sha256(data).hexdigest()


def attribution(path, payload):
    index = json.loads((ROOT / 'LICENSES/material-index.json').read_text())
    for name, digest in index['input_sha256'].items():
        if sha((ROOT / name).read_bytes()) != digest:
            raise ValueError('Material index is stale; regenerate it before exporting')
    registry_bytes = (ROOT / 'LICENSES/source-notices.json').read_bytes()
    registry = json.loads(registry_bytes)
    text = payload.decode('utf-8')
    ids = {key for key, spec in index['sources'].items()
           if re.search(r'(?<![A-Za-z0-9_-])' + re.escape(key) + r'(?![A-Za-z0-9_-])', text)
           or spec['url'] in text}
    # Profile payloads name case IDs, not obligation keys; never infer ownership from
    # a case ID prefix because one requirement can contain several distinct sources.
    for case in re.findall(r'IIP-[A-Z0-9]+-[a-z][a-z0-9]*-(?:idp|sp)-[0-9]+', text):
        ids.update(index.get('case_sources', {}).get(case, []))
    keys = set(re.findall(r'IIP-[A-Z0-9]+\.[a-z][a-z0-9]*', text))
    for key in keys:
        ids.update(index['obligation_sources'].get(key, []))
    # A document naming a whole requirement also references its constituent definitions.
    for requirement in set(re.findall(r'IIP-[A-Z]+[0-9]+(?![A-Za-z0-9.\-])', text)):
        for key, sources in index['obligation_sources'].items():
            if key.startswith(requirement + '.'):
                ids.update(sources)
    sources = {s['id']: s for s in registry['sources']}
    for s in sources.values():
        if sha(s['notice_text'].encode()) != s['notice_text_sha256']:
            raise ValueError('Source notice hash mismatch: ' + s['id'])
    return {
        'format': 'samlscope-material-export-1',
        'source_path': path,
        'source_sha256': sha(payload),
        'source_registry_sha256': sha(registry_bytes),
        'scope': registry['original_content']['scope'],
        'original_content': registry['original_content'],
        'modifications': 'A notice wrapper has been added for redistribution. The original payload is preserved; this exported file is not itself a signed approval artifact.',
        'review_status': 'Notice membership is derived from explicit references, not a legal clearance. Unmarked quotations, adaptations and code examples still require material review.',
        'sources': [sources[k] for k in sorted(ids) if k in sources],
        'unresolved_sources': [{'id': k, 'reference': index['sources'][k]} for k in sorted(ids) if k not in sources],
    }


def render(path, payload):
    meta = attribution(path, payload)
    suffix = Path(path).suffix
    if suffix in ['.yaml', '.yml']:
        # Comments are valid before a YAML directive and leave parsed data unchanged.
        notice = json.dumps(meta, ensure_ascii=False, indent=2)
        header = '# SAMLscope redistribution metadata (original bytes follow END marker)\n'
        header += '\n'.join('# ' + line for line in notice.splitlines()) + '\n# END SAMLSCOPE ATTRIBUTION\n'
        return header.encode() + payload
    if suffix == '.json':
        # Do not add unknown fields to the approved JSON schema. Use an explicit export envelope.
        return (json.dumps({'attribution': meta, 'content': json.loads(payload),
                            'original_utf8': payload.decode('utf-8')}, ensure_ascii=False, indent=2) + '\n').encode()
    if suffix == '.md':
        # Indent each line rather than interpolating third-party HTML into Markdown.
        notice = json.dumps(meta, ensure_ascii=False, indent=2)
        return payload + b'\n\n## Redistribution notices\n\n' + ('\n'.join('    ' + line for line in notice.splitlines()) + '\n').encode()
    raise ValueError('Supported public materials: YAML, JSON and Markdown')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('source', help='Tracked public path under tests/, profiles/ or docs/')
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    path = (ROOT / args.source).resolve()
    relative = path.relative_to(ROOT).as_posix()
    tracked = subprocess.check_output(['git', '-C', str(ROOT), 'ls-files', '-z']).decode().split('\0')
    if relative not in tracked or relative.split('/')[0] not in {'tests', 'profiles', 'docs'} or path.is_symlink():
        raise ValueError('Only tracked public tests/profile/document files can be exported')
    output = args.output.resolve()
    # Do not overwrite any approved input or project source, even under another name.
    output.relative_to(ROOT / 'build')
    if output == path:
        raise ValueError('Export cannot overwrite its source')
    result = render(relative, path.read_bytes())
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(result)
    print(f'Wrote {output.relative_to(ROOT)}; original source unchanged')


if __name__ == '__main__':
    main()
