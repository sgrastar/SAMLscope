#!/usr/bin/env python3
"""Archive, replay and adopt stock SLO signer originals; isolated models never enter production."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.parse
import urllib.request

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / 'dev/slo'))
sys.path.insert(0, str(Path(__file__).parent))
import slo_registered_signer_attempt_accounting as accounting
from registered_signer_common import CASE, CAMPAIGN, FIXTURES, SUITE, api, install_public, public_json, runtime, save, mounted_hashes
HELPER = 'VerifySloRegisteredSignerEvidence'
STORED_HELPER = 'ReadSloRegisteredSignerStoredConclusions'
JARS = ('runner', 'core', 'saml', 'store')
RUNTIME = 'runtime-actual'
EVALUATION = 'evaluation-actual'
SHIB_RUNTIME = 'runtime-evaluation-v224-r2'
SHIB_EVALUATION = 'evaluation-v224-r2'
PRODUCTS = {
    'keycloak': ('keycloak-slo-registered-signer-r5', 'keycloak-native-slo-issuer-key-v1', 'samlscope-reference-keycloak'),
    'simplesamlphp': ('simplesamlphp-slo-registered-signer-r6', 'simplesamlphp-native-slo-issuer-key-v1', 'samlscope-reference-ssp'),
    'shibboleth': ('shibboleth-slo-registered-signer-r2', 'shibboleth-native-slo-issuer-key-v1', 'samlscope-reference-shibboleth'),
}
# Filled only from the completed deployed-runtime readback, before adoption.
PINS = {'runner': 'db6f80bbecbfd64165e769261f802310ec69bfae6995a74204e8362a2af0f99c', 'core': '1d6e0020c915f50e78902554c06b61916a3f49e50de78d3bc23c6089d312babe', 'saml': 'd8ea9ebf6048f82ba9773850d8302cca00b19751fa0aac4eca675506c8c737ca', 'store': 'c4482cd06f9290a3592f0fceac2c9ec2d7603ea0557d1edc885e1c3d51bd8ece', 'VerifySloRegisteredSignerEvidence': 'f354380cf7b9d7afd73dc35f129459b5fe6971e98d578a0ffce45d596035f18b', 'ReadSloRegisteredSignerStoredConclusions': '73782a66848d5a28b59d0770188d02a574b5e096a2dfe7b85f678e979e5bed7b'}
# Preserve the already adopted Keycloak runtime. Future product pins are filled only
# from that product's completed deployed archive, never by updating historical pins.
PRODUCT_PINS = {'keycloak': dict(PINS), 'simplesamlphp': {'runner': 'c7da08eed81f996e56d0d5008163528a747dad91f3100a60c65410ae1a504537', 'core': '1d6e0020c915f50e78902554c06b61916a3f49e50de78d3bc23c6089d312babe', 'saml': 'd8ea9ebf6048f82ba9773850d8302cca00b19751fa0aac4eca675506c8c737ca', 'store': 'c4482cd06f9290a3592f0fceac2c9ec2d7603ea0557d1edc885e1c3d51bd8ece', 'VerifySloRegisteredSignerEvidence': 'f354380cf7b9d7afd73dc35f129459b5fe6971e98d578a0ffce45d596035f18b', 'ReadSloRegisteredSignerStoredConclusions': '73782a66848d5a28b59d0770188d02a574b5e096a2dfe7b85f678e979e5bed7b'}, 'shibboleth': {'runner': '5543bb1afb6ce41e98992c8e3b572d9c7580c300d6d8706c72dc70581f79edf4', 'core': '1d6e0020c915f50e78902554c06b61916a3f49e50de78d3bc23c6089d312babe', 'saml': 'd8ea9ebf6048f82ba9773850d8302cca00b19751fa0aac4eca675506c8c737ca', 'store': 'c4482cd06f9290a3592f0fceac2c9ec2d7603ea0557d1edc885e1c3d51bd8ece', 'VerifySloRegisteredSignerEvidence': 'f354380cf7b9d7afd73dc35f129459b5fe6971e98d578a0ffce45d596035f18b', 'ReadSloRegisteredSignerStoredConclusions': '73782a66848d5a28b59d0770188d02a574b5e096a2dfe7b85f678e979e5bed7b'}}
CONTROLS = {'wrong-run','wrong-adapter','wrong-target','wrong-campaign','foreign-plan','foreign-key','duplicate-history','foreign-decoded-ref','missing-normal','duplicate-outbound-action','altered-session-index','missing-restoration','restoration-flag-only','negative-operation-count','too-few-outbox-count','optional-consumer-label-only','public-counterfactual','unrelated-native-http','foreign-native-request-hash','foreign-native-body-hash','native-epoch-changed','private-native-readback','missing-native-peer','foreign-hosted-identity','hosted-label-only','generic-http-rejection'}
MODEL_CONTROLS = {'public-calibrated-consumer','calibration-label-only','calibration-source-run','calibration-session-mismatch','calibration-order-mismatch'}
sha = lambda raw: hashlib.sha256(raw).hexdigest()
load = lambda path: json.loads(Path(path).read_bytes())


def require(value, message):
    if not value:
        raise ValueError(message)


def locate(root, product):
    root = Path(root).absolute()
    require(not any(p.is_symlink() for p in [root, *root.parents]), 'Unsafe adoption root')
    root = root.resolve()
    require(product in PRODUCTS, 'Unknown product scope')
    return root if (root / 'receipt/manifest.json').is_file() else root / PRODUCTS[product][0]


def stored_helpers():
    # An isolated module instance prevents HELPER overrides leaking to other adoption verifiers.
    path = Path(__file__).with_name('keycloak_registered_signer_stored_outcome.py')
    spec = importlib.util.spec_from_file_location('slo_signer_stored_isolated', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.HELPER = STORED_HELPER
    return module


def runtime_archive(folder):
    return SHIB_RUNTIME if Path(folder).name == PRODUCTS['shibboleth'][0] else RUNTIME


def evaluation_archive(folder):
    return SHIB_EVALUATION if Path(folder).name == PRODUCTS['shibboleth'][0] else EVALUATION


def capture_runtime(folder):
    dest = folder / runtime_archive(folder)
    dest.mkdir(exist_ok=False)
    actual = {}
    for name in JARS:
        matches = list((REPO / 'api/build/install/samlscope/lib').glob(name + '-*.jar'))
        require(len(matches) == 1, 'Ambiguous distribution JAR')
        host = matches[0]
        deployed = subprocess.check_output(['docker','exec',SUITE,'sha256sum','/opt/samlscope/lib/' + host.name], timeout=40).decode().split()[0]
        require(sha(host.read_bytes()) == deployed, 'Distribution differs from actual deployed JAR')
        # Independent copies avoid mutable build outputs sharing inodes with proof archives.
        shutil.copyfile(host, dest / (name + '.jar'))
        actual[name] = deployed
    for name in (HELPER, STORED_HELPER):
        raw = Path(__file__).with_name(name + '.java').read_bytes()
        (dest / (name + '.java')).write_bytes(raw)
        actual[name] = sha(raw)
    save(dest / 'pins.json', actual)
    save(dest / 'archive-placement.json', dict(mode='independent-copy', mutableDistributionLinked=False, deployedBytesReadBack=True))
    return actual


def replay(folder):
    archived = folder / runtime_archive(folder)
    pins = load(archived / 'pins.json')
    product = next((p for p, (name, _, _) in PRODUCTS.items() if folder.name == name), None)
    expected = PRODUCT_PINS.get(product)
    require(expected and pins == expected, 'Actual runtime is not independently pinned')
    for name in JARS:
        require(sha((archived / (name + '.jar')).read_bytes()) == pins[name], 'Archived JAR changed')
    require(sha((archived / (HELPER + '.java')).read_bytes()) == pins[HELPER], 'Archived helper changed')
    cp = ':'.join(str((archived / (name + '.jar')).resolve()) for name in JARS) + ':' + Path('/private/tmp/samlscope-runner-runtime-classpath.txt').read_text().strip()
    with tempfile.TemporaryDirectory(prefix='slo-signer-actual-replay-') as name:
        temporary = Path(name)
        classes = temporary / 'classes'
        subprocess.run(['javac','-sourcepath','','-cp',cp,'-d',str(classes),str(archived / (HELPER + '.java'))], check=True, capture_output=True, timeout=60)
        require(all(p.name.startswith(HELPER) for p in classes.rglob('*.class')), 'Helper shadows production classes')
        remote = '/tmp/' + temporary.name
        subprocess.run(['docker','exec',SUITE,'mkdir','-p',remote], check=True, capture_output=True, timeout=40)
        try:
            # Separate public staging copies; immutable archive permissions remain untouched.
            for source, label in ((classes,'classes'),(folder / 'receipt','receipt'),(archived,'runtime')):
                stage = temporary / ('stage-' + label)
                shutil.copytree(source, stage)
                for p in stage.rglob('*'):
                    p.chmod(0o755 if p.is_dir() else 0o644)
                stage.chmod(0o755)
                subprocess.run(['docker','cp',str(stage),SUITE + ':' + remote + '/' + label], check=True, capture_output=True, timeout=90)
            remote_cp = ':'.join(remote + '/runtime/' + n + '.jar' for n in JARS) + ':/opt/samlscope/lib/*:' + remote + '/classes'
            result = subprocess.run(['docker','exec',SUITE,'java','-cp',remote_cp,'com.samlscope.runner.cases.' + HELPER,remote + '/receipt','/data',remote + '/replay.json'], capture_output=True, text=True, timeout=120)
            require(result.returncode == 0, 'Archived production replay failed: ' + result.stderr[-1800:])
            subprocess.run(['docker','cp',SUITE + ':' + remote + '/replay.json',str(temporary / 'replay.json')], check=True, capture_output=True, timeout=40)
            return load(temporary / 'replay.json')
        finally:
            subprocess.run(['docker','exec','--user','0',SUITE,'rm','-rf',remote], check=True, capture_output=True, timeout=60)


def install(folder):
    m = load(folder / 'receipt/manifest.json')
    require(m['counterfactualCalibrationOnly'] is False and m['schema'] == 'samlscope-slo-registered-signer-v1' and 'calibrationProvenance' not in m
            and not any(p.startswith('calibration/') for p in m['files']), 'Only stock originals may be installed')
    run = m['runId']
    archive,evaluation=runtime_archive(folder),evaluation_archive(folder)
    ev = folder / evaluation
    ev.mkdir(exist_ok=False)
    stored_helpers().capture(folder,archive,evaluation + '/stored-before.json',run,CASE)
    save(ev / 'result-before.json', api('/api/runs/' + run + '/result.json'))
    save(ev / 'transcript-before.json', api('/api/runs/' + run + '/transcript'))
    target = '/data/slo-registered-signer-evidence/' + run + '/manifest.json'
    exists = subprocess.run(['docker','exec',SUITE,'test','-e',target], capture_output=True, timeout=40)
    require(exists.returncode == 1, 'Final proof already installed; do not overwrite adoption history')
    installed = install_public(folder / 'receipt', run)
    installed.update(productSettingWrites=0,protocolSubmissions=0,credentialPosts=0,stockOnly=True,counterfactualInstalled=False)
    save(folder / 'receipt-installation.json', installed)


def formal_preflight(folder, run):
    ev = folder / evaluation_archive(folder)
    status = api('/api/runs/' + run + '/protocol-evidence')
    save(ev / 'protocol-evidence-before.json', status)
    require(isinstance(status,dict) and isinstance(status.get('cases'),list), 'Suite path gap: invalid readiness; evaluation POST skipped')
    selected = [r for r in status['cases'] if r.get('caseId') == CASE]
    if selected:
        require(len(selected) == 1 and selected[0].get('ready') is True, 'Suite path gap: SLO proof not ready; evaluation POST skipped')
        return True
    report = api('/api/runs/' + run + '/result.json')
    save(ev / 'already-conclusive-result.json', report)
    cases = [c for requirement in report['requirements'] for c in requirement['cases'] if c['id'] == CASE]
    require(len(cases) == 1 and cases[0].get('outcome') in {'SATISFIED','SATISFIED_WITH_NOTE','VIOLATED'}, 'Suite path gap: case absent without conclusive history; evaluation POST skipped')
    return False


def formal(folder):
    archive,evaluation=runtime_archive(folder),evaluation_archive(folder)
    ev = folder / evaluation
    require((ev / 'stored-before.json').is_file() and (folder / 'receipt-installation.json').is_file(), 'Capture previous history and read back stock receipt before evaluation')
    require(not (ev / 'result.json').exists() and not (ev / 'evaluate.json').exists(), 'Formal history is immutable; no repeated POST')
    run = load(folder / 'receipt/manifest.json')['runId']
    if formal_preflight(folder, run):
        save(ev / 'evaluate.json', api('/api/runs/' + run + '/protocol-evidence/evaluate', {}))
    save(ev / 'result.json', api('/api/runs/' + run + '/result.json'))
    save(ev / 'transcript.json', api('/api/runs/' + run + '/transcript'))
    stored_helpers().capture(folder,archive,evaluation + '/stored-after.json',run,CASE)


def original_inventory(receipt, m):
    require({str(p.relative_to(receipt)) for p in receipt.rglob('*') if p.is_file()} == set(m['files']) | {'manifest.json'}, 'Native file inventory changed')
    for name, digest in m['files'].items():
        p = receipt / name
        require(p.resolve().is_relative_to(receipt.resolve()) and p.is_file() and not any(x.is_symlink() for x in [p,*p.parents]) and sha(p.read_bytes()) == digest, 'Original modified or escaped')
    for peer in m['peers']:
        child = receipt / peer['label']
        entries = load(child / 'transcript.json')
        by = {e['id']:e for e in entries}
        require(len(by) == len(entries) and all(e['runId'] == peer['runId'] for e in entries), 'Foreign or duplicate transcript')
        decoded = set()
        for row in load(child / 'decoded-manifest.json'):
            p = child / row['file']; e = by[row['id']]
            require(p.parent == child / 'decoded' and row['id'] not in decoded and e['decodedSamlRef'] == 'transcripts/' + peer['runId'] + '/' + row['id'] + '.saml.xml' and sha(p.read_bytes()) == row['sha256'] and len(p.read_bytes()) == e['decodedSamlBytes'], 'Decoded original differs')
            decoded.add(row['id'])
        require(decoded == {e['id'] for e in entries if e.get('decodedSamlRef')}, 'Decoded originals incomplete')
        for row in load(child / 'browser-originals-manifest.json'):
            p = child / row['file']; e = by[row['id']]
            require(p.parent == child / 'browser-originals' and e['bodyRef'] == row['reference'] == 'transcripts/' + peer['runId'] + '/' + row['id'] + '.body' and len(p.read_bytes()) == row['bytes'] == e['bodyBytes'] and sha(p.read_bytes()) == row['sha256'], 'Native browser original differs')


def live_restoration(folder, product, m):
    receipt = folder / 'receipt'
    state = load(receipt / 'native-readbacks/restoration.json')
    allowed={mount['Destination']:dict(source=Path(mount['Source']),rw=mount['RW']) for mount in state['runtime']['mounts']}
    now = runtime(PRODUCTS[product][2],allowed if allowed else None)
    require(mounted_hashes(PRODUCTS[product][2],now)==state.get('mountedFileHashes',{}),'Live mounted byte hashes changed')
    require(now == state['runtime'], 'Native restored runtime epoch changed')
    if product == 'keycloak':
        sys.path.insert(0, str(REPO / 'dev/keycloak'))
        from attribute_policy_capability_absence import product_token
        token = product_token()
        def native(path):
            request = urllib.request.Request('http://localhost:18180/admin/realms/samlscope' + path, headers={'Authorization':'Bearer ' + token})
            with urllib.request.urlopen(request,timeout=40) as response: return json.load(response)
        for peer in m['peers']:
            require(native('/clients?clientId=' + urllib.parse.quote(peer['entity'],safe='') + '&briefRepresentation=true') == [], 'Temporary native peer remains')
        require({name:native('/client-policies/' + name) for name in ('policies','profiles')} == load(receipt / 'original-configuration/policies.json'), 'Live native policy changed')
    elif product == 'simplesamlphp':
        for name in ('saml20-sp-remote.php','saml20-idp-hosted.php'):
            current = subprocess.check_output(['docker','exec',PRODUCTS[product][2],'cat','/var/simplesamlphp/metadata/' + name],timeout=40)
            require(current == (receipt / 'original-configuration' / name).read_bytes(), 'Live SSP metadata restoration differs')
    else:
        for name in state['configurationFiles']:
            current = subprocess.check_output(['docker','exec',PRODUCTS[product][2],'cat','/opt/reference-idp/conf/' + name],timeout=40)
            require(current == (receipt / 'original-configuration' / name).read_bytes(), 'Live Shib configuration restoration differs')
    for peer in m['peers']:
        require(api('/api/runs/' + peer['runId'] + '/transcript') == load(receipt / peer['label'] / 'transcript.json'), 'Live transcript changed')


def replay_agrees(actual, saved):
    # The diagnostic oracle generates a new memory-only signing key each replay. Only these
    # three derived byte hashes vary; all stock outcomes, evidence, source bindings and controls
    # still compare exactly. Each replay's helper verifies its own generated crypto material.
    values=[]
    for report in (actual,saved):
        copy=json.loads(json.dumps(report));model=copy['wholeReaderCalibration'];generated=model['model']
        require(model['counterfactualCalibrationOnly'] is True and model['actualProductFinding'] is False
                and generated['ephemeralSigningKeyMemoryOnly'] is True
                and generated['nativeProductOperationExecuted'] is False,'Invalid diagnostic replay provenance')
        for field in ('signedCrossSuccessSha256','derivedTargetMetadataSha256','signedBaselineSha256'):
            require(re.fullmatch(r'[0-9a-f]{64}',generated[field]) is not None,'Invalid generated diagnostic hash')
            del generated[field]
        values.append(copy)
    return values[0] == values[1]


def verify_adoption(root, product, live=False):
    folder = locate(root, product); receipt = folder / 'receipt'; m = load(receipt / 'manifest.json'); run = m['runId']
    accounting.verify(folder,product)
    require(m['schema'] == 'samlscope-slo-registered-signer-v1' and m['campaignId'] == CAMPAIGN and m['caseId'] == CASE and m['adapter'] == PRODUCTS[product][1] and m['counterfactualCalibrationOnly'] is False and 'calibrationProvenance' not in m and not any(p.startswith('calibration/') for p in m['files']), 'Stock product scope differs')
    require(run == load(folder / 'created.json')['run']['id'] and m['targetMetadataSha256'] == sha((receipt / 'target-metadata.xml').read_bytes()) and m['peers'][0]['runId'] == run and [p['label'] for p in m['peers']] == ['primary','secondary'], 'Run/target/aggregate owner differs')
    slot = load(folder / 'formal-slot.json')
    require(slot['formalSlotVerified'] is True and slot['runId'] == run and slot['case']['id'] == CASE and slot['case']['mode'] == 'ATTESTED' and slot['profile'] == 'single_logout_idp', 'Approved formal slot was not established')
    original_inventory(receipt, m)
    observed = load(folder / 'native-reader-replay.json')
    require(replay_agrees(replay(folder),observed) and set(observed['checks']) == CONTROLS and observed['shared_native_lifecycle'] is True and observed['privateMaterialExported'] is False and observed['additionalProductOperations'] == 0, 'Actual archived replay differs')
    require(all((c['outcome'],c['centralVerdict']) == ('NOT_VERIFIED','NOT_VERIFIED') for c in observed['checks'].values()), 'Invalid originals did not fail closed')
    model = observed['wholeReaderCalibration']
    require(model['counterfactualCalibrationOnly'] is True and model['actualProductFinding'] is False and (model['outcome'],model['centralVerdict']) == ('VIOLATED','WARNING') and set(model['checks']) == MODEL_CONTROLS and all(c['outcome'] == 'NOT_VERIFIED' for c in model['checks'].values()) and model['model']['ephemeralSigningKeyMemoryOnly'] is True and model['model']['nativeProductOperationExecuted'] is False, 'Isolated whole-reader detection or production exclusion missing')
    counts = load(receipt / 'operation-counts.json')
    require(counts == load(folder / 'operation-counts.json') and counts['restored'] is True and counts['outboxProtocolSubmissions'] == 3 and counts['protocolSubmissions'] >= 4 and counts['credentialPosts'] == counts['credentialPostAttempts'] == 1 and counts['personOperations'] == 0 and counts['normalControlEndsSession'] is True, 'Actual batch accounting differs')
    require(load(folder / 'restoration.json') == dict(restored=True,additionalSamlForRestoration=0,credentialsPersisted=False,cookieValuesPersisted=False), 'Native restoration missing')
    installed = load(folder / 'receipt-installation.json')
    require(installed['readBackVerified'] is True and installed['records'] == m['files'] | {'manifest.json':sha((receipt / 'manifest.json').read_bytes())} and installed['stockOnly'] is True and installed['counterfactualInstalled'] is False, 'Stock sidecar installation differs')
    archive,evaluation=runtime_archive(folder),evaluation_archive(folder)
    ev = folder / evaluation
    require(load(ev / 'transcript-before.json') == load(ev / 'transcript.json') == load(receipt / 'primary/transcript.json'), 'Formal evaluation changed original transcript')
    result = load(ev / 'result.json'); by = {c['id']:c for q in result['requirements'] for c in q['cases']}; proof = observed['production_outcome']
    require(result['run']['id'] == run and result['target']['metadata_digest'] == 'sha256:' + m['targetMetadataSha256'], 'Formal target differs')
    stored = stored_helpers().compare_stored(folder,archive,CASE,proof,before_name=evaluation + '/stored-before.json',after_name=evaluation + '/stored-after.json')
    case = by[CASE]
    require(proof['outcome'] == 'SATISFIED_WITH_NOTE' and (case['outcome'],case['verdict'],case['attested'],case['evidence_class']) == ('SATISFIED_WITH_NOTE','WARNING',False,'OPERATOR_ASSISTED') and case['evidence'] == proof['evidence'] and case['reason_code'] == proof['reasonCode'] and stored['verdict'] == 'WARNING' and stored['outboxCount'] == 3, 'Full stored/central outcome or provenance differs')
    if live:
        live_restoration(folder,product,m)
        require(next(c for q in api('/api/runs/' + run + '/result.json')['requirements'] for c in q['cases'] if c['id'] == CASE) == case, 'Live formal result differs')
    return ev / 'result.json', {CASE:case}


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__); p.add_argument('root',type=Path);p.add_argument('--product',choices=PRODUCTS,required=True)
    for flag in ('capture-runtime','record-replay','record-accounting','install','formal','live'):p.add_argument('--' + flag,action='store_true')
    args = p.parse_args(); folder = locate(args.root,args.product)
    if args.capture_runtime:print(json.dumps(capture_runtime(folder),indent=2))
    if args.record_replay:
        require(not (folder / 'native-reader-replay.json').exists(), 'Replay original immutable');save(folder / 'native-reader-replay.json', replay(folder))
    if args.record_accounting:accounting.record(folder,args.product)
    if args.install:install(folder)
    if args.formal:formal(folder)
    if not any((args.capture_runtime,args.record_replay,args.record_accounting,args.install,args.formal)):
        verify_adoption(folder,args.product,args.live);print(args.product + ' SLO registered signer adoption verified: one observation')
