"""Generate operation-cost and result deltas from the recorded local follow-up evidence."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re

PRODUCTS = ('keycloak', 'shibboleth', 'simplesamlphp')
NAMES = dict(zip(PRODUCTS, ('Keycloak', 'Shibboleth', 'SimpleSAMLphp')))
DESCRIPTION_TRANSLATIONS = json.loads(
    Path(__file__).with_name('operation-descriptions-en.json').read_text())
JAPANESE = re.compile(r'[\u3040-\u30ff\u31f0-\u31ff\u3400-\u4dbf\u4e00-\u9fff\uf900-\ufaff]')


def description_en(description):
    """Translate display text without changing the immutable operation ledger."""
    digest = hashlib.sha256(description.encode('utf-8')).hexdigest()
    translated = DESCRIPTION_TRANSLATIONS.get(digest, description)
    if JAPANESE.search(translated):
        raise ValueError('Operation description needs an English presentation translation: ' + digest)
    return translated

def cases(path):
    return {c['id']: c for r in json.loads(path.read_text())['requirements'] for c in r['cases']}

def render(root, output, date='2026-09-14', focus=(), notes=None):
    operations = [json.loads(line) for line in (root / 'operations.jsonl').read_text().splitlines() if line]
    totals = {p: Counter() for p in PRODUCTS}
    transitions = []
    for before in sorted((root / 'before').glob('*/*/result.json')):
        product, profile = before.parent.parent.name, before.parent.name
        after = root / 'after' / product / profile / 'result.json'
        old, new = cases(before), cases(after if after.exists() else before)
        if old.keys() != new.keys():
            raise ValueError('Case set changed: compare equivalent definitions first')
        for key, case in new.items():
            if focus and key not in focus:
                continue
            totals[product]['before'] += old[key]['verdict'] == 'NOT_VERIFIED'
            totals[product]['after'] += case['verdict'] == 'NOT_VERIFIED'
            if old[key]['verdict'] != case['verdict']:
                transitions.append((product, profile, key, old[key]['verdict'], case['verdict'], case['reason_code']))
    lines = ['# Follow-up tests and configuration and operation costs', '',
             f'This record measures only follow-up tests on {date}. Earlier environment setup and attempts have unmeasured counts and durations, which are not treated as zero. Additional evidence is collected for existing Runs and conclusion deltas are compared under the same case definitions.' + (' This before/after comparison is limited to the selected cases.' if focus else ''), '',
             'Human user actions, agent browser actions on behalf of the user, and API/file configuration changes are counted separately. Each configuration write, including restoration, counts once; service reloads are separate. Opening a page, entering a field, clicking, and manual continuation each count as one browser action; automatic redirects do not. Scripted execution does not eliminate the configuration work itself.', '',
             '## Changes in conclusions', '', '| Product | Not verified: before | After | Reduction |', '|---|---:|---:|---:|']
    for p in PRODUCTS:
        t=totals[p]; lines.append(f"| {NAMES[p]} | {t['before']} | {t['after']} | {t['before']-t['after']} |")
    if focus:
        lines += ['', 'The deltas above cover only the selected cases. Conclusions for other cases are unchanged. See the [complete inventory](26-unverified-case-inventory.md) for all unverified counts and retest results by product.', '', 'These counts are observations per product, profile, and case. They are distinct from operation and configuration counts.', '',]
    else:
        lines += ['', 'The deltas above record the first follow-up tests. A later complete audit retested common cases in separate Runs and confirmed 5 additional Success observations. Subsequent retests after additional implementation are reflected in the current unverified counts in the complete inventory ([implementation record](27-additional-implementation.md)). See the [complete inventory](26-unverified-case-inventory.md) for details and retest results by product. The workload and details below include these retests and unsuccessful attempts to require signatures.', '', 'These counts are observations per product, profile, and case. They are distinct from operation and configuration counts.', '',]
    lines += ['## Workload', '', '| Product | Configuration writes (including restoration) | Service reloads | Agent browser actions | Human user actions |', '|---|---:|---:|---:|---:|']
    for p in PRODUCTS:
        rows=[r for r in operations if r['product']==p]
        counts=[sum(r.get(k,0) for r in rows) for k in ('configuration_writes','service_reloads','browser_actions','human_actions')]
        lines.append('| '+NAMES[p]+' | '+' | '.join(map(str,counts))+' |')
    lines += ['', f"Auxiliary connection containers were started {sum(r.get('environment_helper_starts',0) for r in operations)} times. Configuration retries caused by temporary script errors are retained in the ledger and are not classified as product defects."]
    lines += ['', f"The local Suite verification environment was restarted {sum(r.get('suite_restarts',0) for r in operations)} times, and forwarding containers {sum(r.get('forward_restarts',0) for r in operations)} times. These are counted separately from product configuration operations.", '', 'Operation durations are measured tool-call durations or script elapsed times. They exclude investigation, decisions, code authoring, and time between calls, and do not estimate human manual effort. Unmeasured durations are shown as an em dash.', '',
              '## Operation details', '', '| # | Product | Operation | Execution method | Configuration writes | Reloads | Browser actions | Measured seconds |', '|---:|---|---|---|---:|---:|---:|---:|']
    for i,r in enumerate(operations,1):
        duration=r.get('duration_seconds')
        if r.get('duration_seconds_measured') is False: duration=None
        seconds='—' if duration is None else f'{duration:.1f}'
        lines.append(f"| {i} | {NAMES.get(r['product'],r['product'])} | {description_en(r['description']).replace('|','/')} | {r.get('execution','—')} | {r.get('configuration_writes',0)} | {r.get('service_reloads',0)} | {r.get('browser_actions',0)} | {seconds} | <!--g1-literal-->")
    lines += ['', '## Cases with changed conclusions', '', '| Product | Profile | Test | Before | After | Reason code |', '|---|---|---|---|---|---|']
    for product,profile,key,old,new,reason in transitions:
        lines.append(f'| {NAMES[product]} | {profile} | `{key}` | {old} | {new} | `{reason}` |')
    if notes is not None:
        output.write_text('\n'.join(lines) + '\n' + notes.read_text())
        (root/'result-delta.json').write_text(json.dumps({'totals':totals,'transitions':transitions},ensure_ascii=False,indent=2)+'\n')
        return
    lines += ['', '## Issues directly affecting workload', '',
              '| Priority | Issue | Observed in this follow-up | Proposed improvement |', '|---|---|---|---|',
              '| High | Unevaluable items appear to be waiting for operations | BrowserEvidenceTestCase returns oracle-unavailable after completion; some CONFIG cases proceed to attestation | Show automated evaluation, evidence verification, and unimplemented paths before startup; do not request configuration work that cannot be evaluated |',
              '| High | Ordering while waiting for metadata fetch | Even with native HTTP fetching active, a response arriving before the post-start fetch causes the Suite to stop with 400 | Let the Suite enforce start, confirmed fetch, then request transmission; avoid fixed delays |',
              '| High | Manual metadata import evidence does not reach evaluation | Responses follow batch import, but manual download is not counted as fetched evidence | Bind the imported file digest to target import records using an evidence kind distinct from HTTP fetch |',
              '| High | Key mismatch after redirect | A redirect from a stable URL without a token returns the normal key, mismatching the polling request signature | Continue testing with an explicit token in the fetch URL; preserve the mode correctly in the Suite to remove extra configuration |',
              '| Medium | localhost means different hosts on the host and in containers | The redirect target was unreachable, requiring auxiliary forwarding | Use a verification configuration with a hostname reachable by the browser, product, and Suite |',
              '| Medium | Intermediate errors stop consecutive tests | SimpleSAMLphp stopped on KeyValue-only; continuing subsequent tests required one intervention | Save error evidence and allow independent subsequent tests to resume |',
              '| Fixed | Switching metadata modes prioritizes an old request ID | The Suite incorrectly rejected a valid response as uncorrelated during HTTP update after batch import | Corrected issued-request correlation, deployed the verification image after regression tests, and completed continuation in the same Run |',
              '| Medium | Repeated positive tests and configuration round trips | Additional SSO advances repeated Audience observations and signature checks of unencrypted Assertions | Include required positive controls in the initial execution plan; use product adapters for configuration snapshots and restoration |',
              '| Medium | IdP-initiated SSO cannot be received | Normal reception requires InResponseTo to match an existing AuthnRequest | Design an explicitly permitted Run-specific IdP-initiated reception path with positive and negative controls |', '',
              'The Shibboleth HTTP fetch path was checked against the [official FileBackedHTTPMetadataProvider documentation](https://shibboleth.atlassian.net/wiki/spaces/IDP5/pages/3199506865). Except for request-ID correlation explicitly marked Fixed, these improvements are proposals based on measurements and source inspection in this follow-up.', '',
              '## Verification and remaining scope', '',
              'Product configuration changes from this follow-up were restored. The request-ID correlation fix was verified with a SpPeerRoundTripTest regression covering the same variant in both modes and deployed to the local verification image. Case definitions and judgment levels are unchanged. HTML/JSON equality before and after execution and the existence of Transcripts referenced by new PASS conclusions were also verified.', '',
              'Unverified observations remain, including missing automated evaluation that operations alone cannot resolve, tests with insufficient rejection evidence, and attestations requiring operational or configuration support. Completing additional attempts does not establish completion of all tests or whole-product conformance.', '',
              '## Evidence and regeneration', '',
              'The operation ledger, configuration backups, before/after result.json files, and test scripts are stored locally in `build/acceptance/reference-20260914/interaction-followup/`. Configuration backups are excluded from publication and commits.', '',
              'Regenerate: `.venv/bin/python dev/reference-acceptance/generate_interaction_report.py --evidence-root build/acceptance/reference-20260914/interaction-followup`.', '']
    output.write_text('\n'.join(lines))
    (root/'result-delta.json').write_text(json.dumps({'totals':totals,'transitions':transitions},ensure_ascii=False,indent=2)+'\n')

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence-root',type=Path,required=True)
    parser.add_argument('--output',type=Path,default=Path('docs/25-interaction-execution-cost.md'))
    parser.add_argument('--date',default='2026-09-14')
    parser.add_argument('--focus-cases',default='',help='comma-separated case IDs to include in deltas and transitions')
    parser.add_argument('--notes-file',type=Path,default=None,help='markdown sections appended after the operation detail table')
    args=parser.parse_args();render(args.evidence_root,args.output,args.date,tuple(x for x in args.focus_cases.split(',') if x),args.notes_file)
