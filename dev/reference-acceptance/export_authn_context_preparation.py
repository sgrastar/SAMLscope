#!/usr/bin/env python3
"""Bind verified native configuration and original exchanges, never an operator supplied verdict."""
import argparse
import hashlib
import json
from pathlib import Path
import sys
import xml.etree.ElementTree as ET
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'shibboleth'))
from authn_context_preparation import configure, reference, inputs

SHA = lambda raw: hashlib.sha256(raw).hexdigest()


def export(folder, output, case, controls):
    if case not in ['ga', 'gb', 'gc', 'gj']:
        raise ValueError('Unsupported case')
    read = lambda name: json.loads((folder / name).read_text())
    run = read('created.json')['run']['id']
    prepared, restored = read('preparation.json'), read('restoration.json')
    if prepared['run'] != run or prepared['login_provenance'] != 'fixed-in-memory-driver-input' \
            or prepared.get('active_authentication_flows') != 'Password':
        raise ValueError('Native scope unproven')
    if not restored['restored'] or restored['failures'] or not restored['temporary_removed'] \
            or restored['original_sha256'] != restored['final_sha256']:
        raise ValueError('Restoration unproven')
    comparison = (folder / 'original-authn-authn-comparison').read_bytes()
    properties = (folder / 'original-authn-authn-properties').read_bytes()
    maximum = case == 'gc'
    configured = configure(comparison, properties, maximum)
    mode = 'maximum' if maximum else 'normal'
    expected = dict(prepared['native'])
    for name, value in zip(['authn/authn-comparison', 'authn/authn-properties'], configured):
        if value != (folder / (mode + '-' + name.replace('/', '-') + '.xml')).read_bytes():
            raise ValueError('Native configuration derivation changed')
        expected[name] = SHA(value)
    for name, value in [('authn/authn-comparison', comparison), ('authn/authn-properties', properties)]:
        if restored['original_sha256'][name] != SHA(value):
            raise ValueError('Original configuration binding differs')
    input_record = read('inputs.json')
    if input_record['inputs'] != inputs() or input_record['runId'] != run:
        raise ValueError('Comparison input plan changed')
    protocol = read('protocol-observation.json')
    if protocol['run'] != run or protocol['issues'] or protocol['transcript_sha256'] != SHA((folder / 'transcript.json').read_bytes()) \
            or protocol['target_metadata_sha256'] != SHA((folder / 'target-metadata.xml').read_bytes()):
        raise ValueError('Verified protocol scope changed')
    entries = {row['id']: row for row in read('transcript.json')}
    originals = {}
    for row in read('decoded-manifest.json'):
        path = (folder / row['file']).resolve()
        if path.parent != (folder / 'decoded').resolve() or row['id'] in originals:
            raise ValueError('Ambiguous original')
        raw = path.read_bytes()
        if SHA(raw) != row['sha256'] or entries[row['id']]['runId'] != run or len(raw) != entries[row['id']]['decodedSamlBytes']:
            raise ValueError('Original digest mismatch')
        originals[row['id']] = raw
    verified = {row['evidence'][2]['reference']: row for row in protocol['observations']}
    exchanges, metadata_hashes, request_hashes, control_refs = [], set(), set(), []
    control_exchanges = []
    candidates = [row for row in read('observations.json') if row['condition'].startswith(case + '-')]
    if len(candidates) != 4:
        raise ValueError('Native conditions incomplete')
    def observation(row):
        if row['before'] != expected or row['after'] != expected or row['login_input_binding'] != prepared['login_input_binding']:
            raise ValueError('Native state or login input changed')
        ids = row['new_transcript_ids']
        selected = [verified[key] for key in ids if key in verified]
        if len(selected) != 1:
            raise ValueError('Original exchange missing')
        value = selected[0]
        refs = [e['reference'] for e in value['evidence']]
        if set(refs[2:]) != set(ids) or value['entity_id'] != prepared['entity_id'] \
                or originals[refs[1]] != (folder / 'fixture.xml').read_bytes():
            raise ValueError('Original exchange scope differs')
        if entries[refs[2]]['samlSummary'].get('authn_context_inputs_sha256') != SHA((folder / 'inputs.json').read_bytes()):
            raise ValueError('Sent input plan differs')
        metadata_hashes.add(value['metadata_sha256']);request_hashes.add(value['request_fingerprint'])
        return value, refs
    for row in candidates:
        value, refs = observation(row)
        exchanges.append(dict(condition=row['condition'].split('-', 1)[1], metadataReference=refs[1], requestReference=refs[2], responseReference=refs[3]))
    if maximum:
        controls_native = [row for row in read('observations.json') if row['condition'].startswith('control-')]
        if len(controls_native) != 4:
            raise ValueError('Availability controls incomplete')
        for row in controls_native:
            value, refs = observation(row)
            _, kind_name, rank = row['condition'].split('-')
            kind = 'CLASS' if kind_name == 'class' else 'DECLARATION'
            returned = value['class_reference'] if kind == 'CLASS' else value['declaration_reference']
            if value['response_kind'] != 'SUCCESS' or returned != reference(kind, rank) \
                    or value['request'] != dict(comparison='EXACT', kind=kind, references=[reference(kind, rank)]):
                raise ValueError('Native candidate not actually available')
            control_refs.extend(refs)
            control_exchanges.append(dict(condition=row['condition'].split('-', 1)[1], metadataReference=refs[1], requestReference=refs[2], responseReference=refs[3]))
    if len(metadata_hashes) != 1 or len(request_hashes) != 1:
        raise ValueError('Uncontrolled request inputs differ')
    # A separate verified control runner binds its result to this exact protocol output.
    check = json.loads(controls.read_text())
    if check['protocol_sha256'] != SHA((folder / 'protocol-observation.json').read_bytes()) or case not in check['verified_cases']:
        raise ValueError('Detection controls unavailable')
    contexts = {}
    for kind in ['CLASS', 'DECLARATION']:
        references = {name: reference(kind, name) for name in ['low', 'medium', 'high', 'unavailable']}
        ranks = {references[name]: rank for rank, name in enumerate(['low', 'medium', 'high'])}
        ranks[references['unavailable']] = -1 if maximum else 3
        available = [references[name] for name in (['low', 'medium'] if maximum else ['low', 'medium', 'high'])]
        contexts[kind] = dict(references=references, ordering=dict(ranks=ranks, available=available, availabilityComplete=maximum),
                              satisfiable=available, provenUnachievable=[references['unavailable']])
    target = (folder / 'target-metadata.xml').read_bytes()
    case_id = 'IIP-SSO01-' + case + '-idp-01'
    receipt = dict(schema='samlscope-native-authn-context-receipt-v1', runId=run,
        targetEntityId=ET.fromstring(target).get('entityID'), targetMetadataSha256=SHA(target),
        preparation=dict(runId=run, caseId=case_id, nativeContext=dict(experiment='native-authn-context-' + run + '-' + case,
            entityId=prepared['entity_id'], loginFingerprint=prepared['login_input_binding'],
            configurationFingerprint=SHA(json.dumps(expected, sort_keys=True).encode()), contexts=contexts, controls='VERIFIED'), exchanges=exchanges, availabilityControls=control_exchanges),
        rawEvidence=[dict(reference=row['id'], sha256=row['sha256']) for row in read('decoded-manifest.json')],
        availabilityControlReferences=sorted(set(control_refs)), controlsSha256=SHA(controls.read_bytes()))
    raw = (json.dumps(receipt, indent=2) + '\n').encode()
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists():
        if output.is_symlink() or output.read_bytes() != raw: raise ValueError('Receipt is immutable')
    else:
        with output.open('xb') as stream:
            stream.write(raw)
    return receipt


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--case', required=True)
    parser.add_argument('--controls', type=Path, required=True)
    args = parser.parse_args()
    export(args.evidence.resolve(), args.output.resolve(), args.case, args.controls.resolve())
