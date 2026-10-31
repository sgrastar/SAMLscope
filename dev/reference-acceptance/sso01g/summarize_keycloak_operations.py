#!/usr/bin/env python3
"""Summarize retained management status records, including failed attempts/recovery.

No outcome, product execution claim or conformance evaluation is produced.
"""
import argparse
import json
from pathlib import Path
from keycloak_live import REALM, output_dir, save


def events(report):
    yield from report.get('apiOperations', [])
    if report.get('priorInvestigation'):
        yield from events(report['priorInvestigation'])


def summarize(paths):
    rows = []
    for path in paths:
        report = json.loads(path.read_text())
        operations = list(events(report))
        writes = [r for r in operations if r['path'].startswith(REALM + '/')
                  and r['method'] in ('POST', 'PUT', 'DELETE')]
        acknowledgments = [r for r in writes if r['status'] is not None and 200 <= r['status'] < 300]
        rows.append(dict(report=str(path), status=report['status'], restored=report['restored'],
                         settingWriteAttempts=len(writes), nativeAcknowledgments=len(acknowledgments),
                         restorationWriteAttempts=sum(r['method'] == 'DELETE' for r in writes),
                         restorationAcknowledgments=sum(r['method'] == 'DELETE' for r in acknowledgments),
                         managementGetAttempts=sum(r['method'] == 'GET' for r in operations),
                         managementGetSuccesses=sum(r['method'] == 'GET' and r['status'] is not None
                                                   and 200 <= r['status'] < 300 for r in operations),
                         adminTokenRequests=sum(r['path'].endswith('/openid-connect/token') for r in operations),
                         configurationGroupReadbacks=report.get('managementReadbackConfirmations', 0),
                         humanInteractions=report['humanInteractions'], samlRequests=report['samlRequests'],
                         nativeAuthenticationExecutionsObserved=report['nativeAuthenticationExecutionsObserved']))
    keys = ('settingWriteAttempts', 'nativeAcknowledgments', 'restorationWriteAttempts', 'restorationAcknowledgments',
            'managementGetAttempts', 'managementGetSuccesses', 'adminTokenRequests',
            'configurationGroupReadbacks', 'humanInteractions', 'samlRequests', 'nativeAuthenticationExecutionsObserved')
    return dict(schema='samlscope-keycloak-investigation-operation-totals-v1', attempts=rows,
                totals={k: sum(row[k] for row in rows) for k in keys}, hostConfigurationWrites=0,
                evidenceStatus='supplemental-unadopted', allCasesHeld=True,
                notes=['Counts cover the supplied instrumented reports only; preliminary discovery and diagnostic GETs are separate.',
                       'Native acknowledgments are HTTP success, not authentication-flow execution.',
                       'All DELETEs in this driver restore the fresh owned resources.',
                       'First recovery counters in live-r1 predated acknowledgment persistence correction; HTTP status records retain the acknowledgments.'])


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--out', type=Path, required=True)
    p.add_argument('reports', nargs='+', type=Path)
    a = p.parse_args()
    out = output_dir(a.out)
    if out.exists():
        raise ValueError('Summary already exists')
    save(out, summarize(a.reports))


if __name__ == '__main__':
    main()
