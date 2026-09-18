#!/usr/bin/env python3
"""Bind native UI observations to exact original metadata and browser-sent requests; no verdict."""
import argparse
from datetime import datetime
import hashlib
import json
from pathlib import Path
import xml.etree.ElementTree as ET

SHA = lambda raw: hashlib.sha256(raw).hexdigest()
MD = 'urn:oasis:names:tc:SAML:2.0:metadata'
SAML = 'urn:oasis:names:tc:SAML:2.0:assertion'
PROTOCOL = 'urn:oasis:names:tc:SAML:2.0:protocol'
CONDITIONS = ['ui-consumer-display-all', 'ui-consumer-display-service', 'ui-consumer-display-entity',
              'ui-consumer-logo-localized', 'ui-consumer-logo-fallback']


def logo_comparison(folder, bound, restoration):
    """Diagnostic comparison only; native runtime setting proof and formal controls remain separate."""
    path = folder / 'ui-language-preparation.json'
    if not path.exists():
        return dict(status='not-observed', reason='native-language-preparation-missing')
    language = json.loads(path.read_text())
    if not restoration.get('language_settings_unchanged'):
        return dict(status='not-observed', reason='native-language-configuration-changed')
    preferred = language['preferred_language'].split('-')[0].lower()
    fallback = {value.split('-')[0].lower() for value in language['fallback_languages']}
    observed = {row['condition']: row for row in bound}
    inputs = []
    for condition in ['ui-consumer-logo-localized', 'ui-consumer-logo-fallback']:
        root = ET.fromstring((folder / condition / 'fixture.xml').read_bytes())
        info = root.findall('./{' + MD + '}SPSSODescriptor/{' + MD + '}Extensions/'
                            '{urn:oasis:names:tc:SAML:metadata:ui}UIInfo')
        if len(info) != 1:
            return dict(status='not-observed', reason='ui-input-ambiguous')
        logos = info[0].findall('{urn:oasis:names:tc:SAML:metadata:ui}Logo')
        default = [logo for logo in logos if '{http://www.w3.org/XML/1998/namespace}lang' not in logo.attrib]
        localized = [logo for logo in logos if '{http://www.w3.org/XML/1998/namespace}lang' in logo.attrib]
        if len(logos) != 2 or len(default) != 1 or len(localized) != 1:
            return dict(status='not-observed', reason='logo-candidates-ambiguous')
        inputs.append((default[0], localized[0]))
    for position in [0, 1]:
        left, right = inputs[0][position], inputs[1][position]
        attrs = lambda node: {k: v for k, v in node.attrib.items() if k != '{http://www.w3.org/XML/1998/namespace}lang'}
        if left.text != right.text or attrs(left) != attrs(right):
            return dict(status='not-observed', reason='logo-inputs-not-held-fixed')
    if inputs[0][0].text == inputs[0][1].text:
        return dict(status='not-observed', reason='logo-controls-indistinguishable')
    languages = [pair[1].get('{http://www.w3.org/XML/1998/namespace}lang').split('-')[0].lower() for pair in inputs]
    if languages[0] != preferred or languages[1] in fallback | {preferred}:
        return dict(status='not-observed', reason='logo-language-condition-unmet')
    for condition, selected in [('ui-consumer-logo-localized', 'localized'), ('ui-consumer-logo-fallback', 'default')]:
        row = observed[condition]
        if row['accept_language'] != language['preferred_language'] or row['status'] != 'observed':
            return dict(status='not-observed', reason='logo-browser-observation-unavailable')
        if row['selected_candidate'] != selected:
            return dict(status='difference-not-observed', reason='logo-selection-difference-unconfirmed')
    return dict(status='difference-observed', preparation_sha256=SHA(path.read_bytes()),
        native_runtime_setting_verified=language['runtime_effective_setting_verified'], verdict_adopted=False)



def url_comparison(bound):
    """Diagnostic matrix; DOM assignment is neither rendering nor product-wide nonuse."""
    by_condition = {row['condition']: row for row in bound}
    elements = []
    for element in ['logo', 'information', 'privacy']:
        observations = []
        for scheme in ['http', 'https', 'data', 'javascript', 'file']:
            row = by_condition['ui-url-' + element + '-' + scheme]
            assignment = row.get('url_assignment') or {}
            observations.append(dict(scheme=scheme, rendering=row['status'],
                assignment=assignment.get('status', 'not-recorded'),
                selector_scope=row.get('url_selector_scope', 'not-recorded'),
                observation_sha256=row['observation_sha256']))
        allowed = observations[:3]
        forbidden = observations[3:]
        positive = all(row['rendering'] == 'observed' and row['assignment'] == 'candidate-assigned' for row in allowed)
        elements.append(dict(element=element, allowed_rendering_control_observed=positive,
            forbidden_candidate_assigned=any(row['assignment'] == 'candidate-assigned' for row in forbidden),
            forbidden_nodes_absent_at_sample=all(row['assignment'] == 'absent-at-sample' for row in forbidden),
            reason='formal-consumer-oracle-unavailable' if positive else 'usable-positive-control-unavailable',
            observations=observations))
    return dict(status='diagnostic-only', reason='url-element-consumption-scope-unproven',
                absence_is_nonuse_proof=False, verdict_adopted=False, elements=elements)

def bind(folder, url_schemes=False):
    def read(name):
        return json.loads((folder / name).read_text())

    run = read('created.json')['run']['id']
    restoration = read('restoration.json')
    if not restoration['restored'] or not restoration['temporary_removed'] or restoration['failures']:
        raise ValueError('Native restoration incomplete')
    if restoration['original_sha256'] != restoration['final_sha256']:
        raise ValueError('Native restoration hash mismatch')
    operations = read('operations.json')
    if operations['run'] != run or not operations['restored']:
        raise ValueError('Operations belong to another or unrestored Run')
    entries = read('transcript.json')
    if len({e['id'] for e in entries}) != len(entries) or any(e['runId'] != run for e in entries):
        raise ValueError('Ambiguous or mixed Run transcripts')
    by_id = {e['id']: e for e in entries}
    originals = {}
    for row in read('decoded-manifest.json'):
        path = folder / row['file']
        if path.resolve().parent != (folder / 'decoded').resolve() or row['id'] in originals:
            raise ValueError('Invalid original evidence path or duplicate')
        raw = path.read_bytes()
        if SHA(raw) != row['sha256'] or row['id'] not in by_id:
            raise ValueError('Original evidence mismatch')
        if by_id[row['id']]['decodedSamlBytes'] != len(raw):
            raise ValueError('Original evidence length mismatch')
        originals[row['id']] = raw
    bound = []
    used_requests = set()
    conditions = (['ui-url-' + element + '-' + scheme
        for element in ['logo', 'information', 'privacy']
        for scheme in ['http', 'https', 'data', 'javascript', 'file']] if url_schemes else CONDITIONS)
    for condition in conditions:
        observation = read(condition + '/browser-observation.json')
        receipt_raw = (folder / condition / 'native-import.json').read_bytes()
        receipt = json.loads(receipt_raw)
        fixture = (folder / condition / 'fixture.xml').read_bytes()
        if url_schemes:
            element = {'logo': 'Logo', 'information': 'InformationURL', 'privacy': 'PrivacyStatementURL'}[condition.split('-')[2]]
            nodes = ET.fromstring(fixture).findall('./{' + MD + '}SPSSODescriptor/{' + MD + '}Extensions/'
                '{urn:oasis:names:tc:SAML:metadata:ui}UIInfo/{urn:oasis:names:tc:SAML:metadata:ui}' + element)
            supplied = read(condition + '/browser-input.json')['observation']
            if len(nodes) != 1 or supplied['candidates'] != {'probe': nodes[0].text}:
                raise ValueError('URL candidate differs from original fixture')
            if not nodes[0].text.startswith(condition.split('-')[-1] + ':'):
                raise ValueError('URL scheme differs from condition')
            expected_kind = 'logo' if element == 'Logo' else 'link'
            if observation['kind'] != expected_kind or supplied['kind'] != expected_kind:
                raise ValueError('URL observation kind mismatch')
            if observation.get('page_anchor', {}).get('selected_candidate') != 'control' or observation['page_anchor']['status'] != 'observed':
                raise ValueError('Target login page anchor unavailable')
            assignment = observation.get('url_assignment')
            if assignment is not None:
                if assignment.get('nonuse_proven') is not False:
                    raise ValueError('DOM assignment cannot prove nonuse')
                if assignment['status'] not in {'unavailable', 'absent-at-sample', 'ambiguous', 'candidate-assigned', 'unrecognized-assignment'}:
                    raise ValueError('Unknown URL assignment status')
                if assignment['status'] == 'candidate-assigned' and assignment.get('selected_candidate') != 'probe':
                    raise ValueError('Unexpected assigned candidate')
                if assignment['status'] != 'unavailable':
                    if datetime.fromisoformat(assignment['sampled_at']) < datetime.fromisoformat(observation['observed_at']):
                        raise ValueError('URL assignment chronology mismatch')
                expected_scope = 'native-logo-slot' if element == 'Logo' else 'candidate-matching-anchor'
                if observation.get('url_selector_scope') != expected_scope:
                    raise ValueError('Unknown native URL selector scope')
            if observation.get('url_absence_is_nonuse_proof') is not False:
                raise ValueError('URL absence must remain diagnostic')
        if observation['run_id'] != run or observation['condition'] != condition or receipt['run'] != run:
            raise ValueError('Observation Run/condition mismatch')
        if observation['fixture_sha256'] != SHA(fixture) or receipt['fixture_sha256'] != SHA(fixture):
            raise ValueError('Fixture mismatch')
        if observation['import_receipt_sha256'] != SHA(receipt_raw):
            raise ValueError('Import receipt mismatch')
        if receipt['native_path'] != 'FilesystemMetadataProvider' or not receipt['file_read_back'] or not receipt['resolver_reload_completed']:
            raise ValueError('Native preparation unproven')
        for kind, label in [('write', condition), ('reload', condition), ('write', 'metadata-providers')]:
            matches = [o for o in operations['operations'] if o['operation'] == kind and o['label'] == label]
            if len(matches) != 1 or not matches[0].get('read_back' if kind == 'write' else 'completed'):
                raise ValueError('Native operation incomplete or ambiguous')
            if kind == 'write' and matches[0]['sha256'] != (SHA(fixture) if label == condition else receipt['provider_sha256']):
                raise ValueError('Native read-back mismatch')
        browser = observation['browser_request']
        if browser['status'] != 'captured':
            raise ValueError('Browser request missing or ambiguous')
        candidates = [e for e in entries if e['direction'] == 'OUTBOUND'
            and e.get('samlSummary', {}).get('type') == 'AuthnRequest'
            and e.get('samlSummary', {}).get('variant') == condition
            and e['id'] in originals and SHA(originals[e['id']]) == browser['decoded_sha256']]
        if len(candidates) != 1 or candidates[0]['id'] in used_requests:
            raise ValueError('Browser request has no unique original')
        request = candidates[0]
        used_requests.add(request['id'])
        xml = ET.fromstring(originals[request['id']])
        metadata = ET.fromstring(fixture)
        if xml.tag != '{' + PROTOCOL + '}AuthnRequest' or metadata.tag != '{' + MD + '}EntityDescriptor':
            raise ValueError('Unexpected XML root')
        issuer = xml.find('{' + SAML + '}Issuer')
        if issuer is None or issuer.text != metadata.attrib['entityID'] or xml.get('ID') != request['samlSummary']['id']:
            raise ValueError('Request identity mismatch')
        if xml.get('Destination') != request['url'] or request['url'] != observation['expected_origin'] + browser['endpoint_path']:
            raise ValueError('Request endpoint mismatch')
        if observation['expected_path'] != browser['endpoint_path']:
            raise ValueError('Observed page differs from the request endpoint')
        if request['method'] != browser['method'] or len(originals[request['id']]) != browser['decoded_bytes']:
            raise ValueError('Browser request method/length mismatch')
        prepared = [e for e in entries if e['direction'] == 'OUTBOUND'
            and e.get('samlSummary', {}).get('type') == 'MetadataPrepared'
            and e.get('samlSummary', {}).get('variant') == condition
            and e['id'] in originals and originals[e['id']] == fixture]
        if len(prepared) != 1:
            raise ValueError('Prepared fixture missing or ambiguous')
        prepared = prepared[0]
        fetched = by_id[prepared['samlSummary']['fetchTranscriptId']]
        if fetched['direction'] != 'INBOUND' or fetched['samlSummary']['type'] != 'MetadataFetch' or fetched['samlSummary']['variant'] != condition:
            raise ValueError('Metadata fetch mismatch')
        observed_at = datetime.fromisoformat(observation['observed_at'].replace('Z', '+00:00')).timestamp()
        if not fetched['timestamp'] <= prepared['timestamp'] <= request['timestamp'] <= observed_at:
            raise ValueError('Evidence chronology mismatch')
        bound.append(dict(condition=condition, fixture_sha256=SHA(fixture), request_reference=request['id'],
            metadata_reference=prepared['id'], fetch_reference=fetched['id'],
            observation_sha256=SHA((folder / condition / 'browser-observation.json').read_bytes()),
            status=observation['status'], selected_candidate=observation.get('selected_candidate'),
            reason=observation.get('reason'), accept_language=browser['accept_language'],
            document_language=observation.get('document_language'),
            **({'url_assignment': observation.get('url_assignment'),
                'url_selector_scope': observation.get('url_selector_scope')} if url_schemes else {})))
    return dict(schema='samlscope-ui-evidence-binding-v1', run=run, originals_bound=True,
        native_readback_bound=True, native_receipt_trust='local-adapter', verdict_adopted=False, observations=bound,
        **({'url_comparison': url_comparison(bound)} if url_schemes
           else {'logo_comparison': logo_comparison(folder, bound, restoration)}))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence', type=Path, required=True)
    parser.add_argument('--url-schemes', action='store_true')
    args = parser.parse_args()
    result = bind(args.evidence.resolve(), args.url_schemes)
    with (args.evidence / 'ui-evidence-binding.json').open('x') as output:
        json.dump(result, output, indent=2)
        output.write('\n')
    print('Bound', len(result['observations']), 'observations; no verdict assigned')
