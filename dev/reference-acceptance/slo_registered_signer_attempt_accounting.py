"""Bind qualified and failed campaign costs to unchanged original files, separately from verdict proof."""
import hashlib
import json
from pathlib import Path

FIELDS = ('protocolSubmissions', 'outboxProtocolSubmissions', 'credentialPosts',
          'credentialPostAttempts', 'nativeConfigurationWrites', 'restorationWrites',
          'productRestarts', 'personOperations', 'nativeHttpAttempts',
          'nativeConverterAttempts', 'nativeCliExecutions')
ATTEMPTS = {'keycloak': ('keycloak-slo-registered-signer', 5),
            'simplesamlphp': ('simplesamlphp-slo-registered-signer', 6),
            'shibboleth': ('shibboleth-slo-registered-signer', 2)}


def require(value, message):
    if not value:
        raise ValueError(message)


def read(path):
    require(path.is_file() and not any(p.is_symlink() for p in [path, *path.parents]),
            'Unsafe or absent accounting original')
    raw = path.read_bytes()
    require(len(raw) <= 1024 * 1024, 'Oversize accounting original')
    return json.loads(raw), hashlib.sha256(raw).hexdigest()


def costs(row):
    values = {name: row.get(name, 0) for name in FIELDS}
    require(all(type(n) is int and n >= 0 for n in values.values()), 'Invalid actual operation count')
    require(values['restorationWrites'] <= values['nativeConfigurationWrites']
            and values['credentialPosts'] <= values['credentialPostAttempts']
            and values['outboxProtocolSubmissions'] <= values['protocolSubmissions'],
            'Inconsistent actual operation counts')
    return values


def summary(folder, product):
    folder = Path(folder).absolute()
    require(product in ATTEMPTS, 'Unknown accounting scope')
    stem, count = ATTEMPTS[product]
    require(folder.name == stem + '-r' + str(count), 'Qualified attempt identity differs')
    failed = {field: 0 for field in FIELDS}
    rows = []
    for index in range(1, count + 1):
        attempt = folder.parent / (stem + '-r' + str(index))
        native, counts_sha = read(attempt / 'operation-counts.json')
        values = costs(native)
        hashes = {'operation-counts.json': counts_sha}
        qualified = index == count
        if qualified:
            require(not (attempt / 'failure.json').exists() and native.get('restored') is True,
                    'Qualified batch failed or was not restored')
            receipt_counts, receipt_sha = read(attempt / 'receipt/operation-counts.json')
            require(receipt_counts == native, 'Qualified receipt accounting differs')
            hashes['receipt/operation-counts.json'] = receipt_sha
        else:
            failure, hashes['failure.json'] = read(attempt / 'failure.json')
            require(failure.get('productVerdictAdopted') is False, 'Failed attempt claimed a product verdict')
        if values['nativeConfigurationWrites']:
            restoration, hashes['native-restoration.json'] = read(attempt / 'native-restoration.json')
            require(native.get('restored') is True and restoration.get('restored') is True,
                    'An operated attempt lacks native restoration')
            if product == 'keycloak':
                require(restoration.get('newPeerEntitiesAbsent') is True
                        and restoration.get('originalPoliciesUnchanged') is True,
                        'Failed/qualified Keycloak native data was not restored')
            elif product == 'simplesamlphp':
                require(restoration.get('original_sha256') == restoration.get('final_sha256')
                        and isinstance(restoration.get('original_sha256'), str)
                        and len(restoration['original_sha256']) == 64,
                        'Failed/qualified SSP native bytes were not restored')
                if 'hostedOriginalSha256' in restoration:
                    require(restoration.get('hostedRestored') is True
                            and restoration.get('hostedOriginalSha256') == restoration.get('hostedFinalSha256'),
                            'SSP hosted metadata publisher was not restored')
        if (attempt / 'created.json').exists():
            created, hashes['created.json'] = read(attempt / 'created.json')
            run = created['run']['id']
        else:
            require(not qualified and all(v == 0 for v in values.values()),
                    'Unscoped attempt performed operations')
            run = None
        if not qualified:
            for key in FIELDS:
                failed[key] += values[key]
        row=dict(folder=attempt.name, runId=run, qualified=qualified,counts=values, originalHashes=hashes)
        if product=='shibboleth':
            require(restoration.get('original')==restoration.get('final') and restoration.get('temporarySourcesAbsent') is True,
                    'Shibboleth configuration/source restoration differs')
            for name in ('metadataReloads','nativeLogoutCompletionGets'):
                observed_count=native.get(name,0);require(type(observed_count) is int and observed_count>=0,'Invalid Shibboleth navigation/reload count');row[name]=observed_count
            if row['nativeLogoutCompletionGets']:
                navigation,hashes['native-logout-completion-attempts.json']=read(attempt/'native-logout-completion-attempts.json')
                require(isinstance(navigation,list) and len(navigation)==row['nativeLogoutCompletionGets']
                        and all(n.get('method')=='GET' and n.get('executionValueExported') is False for n in navigation),
                        'Unsafe or incomplete Shibboleth navigation accounting')
            check_path=attempt/'root-restoration-check.json'
            if check_path.exists():
                check,hashes['root-restoration-check.json']=read(check_path);checks=check.get('checks')
                require(check.get('exactRestored') is True and type(check.get('nativeReadbacks')) is int
                        and isinstance(checks,list) and check['nativeReadbacks']==len(checks)
                        and len({n.get('path') for n in checks})==len(checks)
                        and {n.get('path'):n.get('expectedSha256') for n in checks}==restoration['original']
                        and all(n.get('expectedSha256')==n.get('nativeSha256') for n in checks)
                        and all(check.get(k)==0 for k in ('settingWrites','samlSubmissions','credentialPosts','personOperations')),
                        'Independent Shibboleth restoration readback differs')
                row['independentRestorationReadbacks']=check['nativeReadbacks']
        if product == 'simplesamlphp':
            # Old failed collectors counted completed public HTTP records as outbox
            # submissions. Preserve those original numbers and separately derive actual
            # SLO attempts from the native protocol counter and sole successful baseline.
            baseline_count=0
            if (attempt/'baseline.json').exists():
                baseline,hashes['baseline.json']=read(attempt/'baseline.json')
                require(set(baseline)=={'requestReference','responseReference'} and all(isinstance(v,str) and v.startswith('tx_') for v in baseline.values()),'Unqualified baseline accounting')
                baseline_count=1
            actual=values['protocolSubmissions']-baseline_count
            require(actual>=0 and values['outboxProtocolSubmissions']<=actual,'Native protocol/baseline accounting inconsistent')
            if values['outboxProtocolSubmissions']!=actual:
                require(not qualified and index==3 and values['protocolSubmissions']==2 and baseline_count==1 and values['outboxProtocolSubmissions']==0
                        and failure.get('reason')=='ValueError: Authentication/confirmation form refused before public recording',
                        'Unexplained historical outbox accounting discrepancy')
                source=attempt/'common-collector-source.py';raw=source.read_bytes();hashes['common-collector-source.py']=hashlib.sha256(raw).hexdigest()
                require(b'outboxProtocolSubmissions=sum(1 for r in client.records)' in raw and b'safe_body(body)' in raw,'Historical collector accounting source differs')
                row['historicalCompletedHttpRecords']=values['outboxProtocolSubmissions']
            row['derivedNativeSloAttempts']=actual
            row['baselineProtocolSubmissions']=baseline_count
            completions=native.get('nativeLogoutCompletionGets',0)
            require(type(completions) is int and completions>=0,'Invalid actual native completion count')
            row['nativeLogoutCompletionGets']=completions
            if completions:
                navigation,hashes['native-logout-completion-attempts.json']=read(attempt/'native-logout-completion-attempts.json')
                require(isinstance(navigation,list) and len(navigation)==completions,'Native completion attempt ledger differs')
                require(all(n.get('method')=='GET' and n.get('executionValueExported') is False for n in navigation),'Unsafe native completion ledger')
        rows.append(row)
    qualified_cost = rows[-1]['counts']
    result=dict(schema='samlscope-slo-attempt-accounting-v1', product=product,
                qualifiedFolder=folder.name, attempts=rows, failed=failed,
                qualified=qualified_cost,
                cumulative={key: failed[key] + qualified_cost[key] for key in FIELDS},
                failedAttemptsAdoptedAsProductFindings=False,
                measurementCostsAffectVerdict=False)
    if product=='simplesamlphp':
        result['derivedNativeSloAttempts']=sum(r['derivedNativeSloAttempts'] for r in rows)
        result['historicalReportedCountsUnchanged']=True
        result['nativeLogoutCompletionGets']=sum(r['nativeLogoutCompletionGets'] for r in rows)
    if product=='shibboleth':
        result['metadataReloads']=sum(r['metadataReloads'] for r in rows)
        result['nativeLogoutCompletionGets']=sum(r['nativeLogoutCompletionGets'] for r in rows)
        result['independentRestorationReadbacks']=sum(r.get('independentRestorationReadbacks',0) for r in rows)
    return result


def record(folder, product):
    output = Path(folder) / 'attempt-accounting.json'
    require(not output.exists(), 'Accounting snapshot is already immutable')
    output.write_text(json.dumps(summary(folder, product), indent=2) + '\n')


def verify(folder, product):
    saved, _ = read(Path(folder) / 'attempt-accounting.json')
    require(saved == summary(folder, product), 'Cumulative costs or their original hashes changed')
    return saved
