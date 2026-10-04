#!/usr/bin/env python3
"""Adopt the real SSP per-peer signing-key omission from immutable public originals."""
import argparse
import base64
import hashlib
import json
import math
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.request
import xml.etree.ElementTree as ET
from decimal import Decimal

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import verify_native_publisher_key_inventory_acceptance as stock
import native_publisher_stored_outcome as stored

REPO = stock.REPO
FOLDER = 'simplesamlphp-publisher-used-signers-r2'
SUITE = stock.SUITE
HELPER = 'VerifyNativePublisherUsedSignersEvidence'
STORED = stock.STORED
OUTBOX = 'ReadNativePublisherUsedSignersRunOutbox'
RUNTIME = 'runtime-actual'
EVALUATION = 'evaluation-actual'
JARS = stock.JARS
C1, C3 = stock.C1, stock.C3
TARGET = 'http://localhost:18380/idp'
PUBLICATION = 'http://localhost:18380/simplesaml/module.php/saml/idp/metadata'
PEER_REMOTE = '/var/simplesamlphp/metadata/saml20-sp-remote.php'
PINS = {  # Actual copied bytes agreed independently with deployment-v230 qualification.
    'runner':'c66778bafc59968b4676fdae9868075c2ce30235621404836f92c6837e2e5092',
    'core':'1d6e0020c915f50e78902554c06b61916a3f49e50de78d3bc23c6089d312babe',
    'saml':'db9f6e715f87b965020311507b56e9a990d30741d5047e8fab35d85aa1de3ab5',
    'store':'c4482cd06f9290a3592f0fceac2c9ec2d7603ea0557d1edc885e1c3d51bd8ece',
    'peer':'133703391229d9ce4247af5bb3d39a1853b9caa816307fe56a17148ff4a3242c',
    'api':'24cb469496204e912e496ec317e4066fa434d0270a951617277f0b349259de8b',
    'dependencyPrioritySha256':'ebd03c2b2a66b7c678b8c43f4d8d13ba2f4529c457c05496db1b6aa8770a9678',
    HELPER:'4d8641229835b142687eefe38bae8a7012a5feedb527deb9ad160544eaa237ff',
    STORED:'b4887c7dd1137ea02b7c75d3bf7405e5669e56f0f4971de26ca80a66b8b593fd',
    OUTBOX:'886f24e12742ed6847a8d835f4126b216b7890d06a18b31e36efcb36d74ce0d9'}
QUALIFIED_DEPENDENCIES = 'deployment-v230/isolated-test-overlay.json'
CONTROLS = stock.CONTROLS | {
    'missing-signing-peer', 'foreign-signing-run', 'duplicate-signing-run', 'wrong-signing-plan',
    'wrong-signing-request', 'wrong-signing-response', 'missing-source-history', 'foreign-source-history',
    'source-target-mismatch', 'signer-certificate-replaced', 'native-signer-use-unbound', 'material-not-removed'}
LIFECYCLE = {'start-violated', 'status-ready', 'recorded-nv-reevaluation', 'conclusive-unchanged',
             'config-unavailable-preserved', 'c3-real-key-omission', 'c3-recorded-nv-reevaluation',
             'c3-conclusive-unchanged', 'c3-config-unavailable-preserved'}
EXPECTED_COSTS = dict(productSettings=2, configurationRestorations=1, nativePublicCalls=10,
    credentialPosts=1, samlSubmissions=3, personOperations=0, nativeEphemeralKeyCreations=1,
    nativeEphemeralKeyRemovals=1, initialBaselineSubmissions=1, selectedSignerSubmissions=2,
    guestWriteAttempts=2, successfulHostWrites=2, successfulGuestWrites=2,
    nativePeerApplications=1, nativePeerRestorations=1, productRestarts=0)
ORIGINAL_KINDS = {
    'initial':'native-role-inventory', 'signers-before':'native-role-inventory',
    'signers-after':'native-role-inventory', 'restored':'native-role-inventory',
    'signers-publication':'native-publication', 'signers-transition':'native-configuration-transition',
    'restoration':'native-publisher-restoration', 'controls':'native-publisher-detector-control',
    'ephemeral-material':'native-public-signing-material', 'ephemeral-removal':'native-public-signing-material-removal',
    'primary-signer-use':'native-signer-use', 'secondary-signer-use':'native-signer-use'}
sha, load, require, save, api, public_cases = stock.sha, stock.load, stock.require, stock.save, stock.api, stock.public_cases
RUN = r'run_[0-9A-HJKMNP-TV-Z]{26}'
PLAN = r'plan_[0-9A-HJKMNP-TV-Z]{26}'
TX = r'tx_[0-9A-HJKMNP-TV-Z]{26}'
MD = 'urn:oasis:names:tc:SAML:2.0:metadata'
DS = 'http://www.w3.org/2000/09/xmldsig#'

OUTBOX_SOURCE = r'''package com.samlscope.runner.cases;
import com.samlscope.store.JsonCodec;
import java.sql.DriverManager;
import java.util.*;
/** Entire selected Run public outbox identity/status only; no payload or credentials. */
public final class ReadNativePublisherUsedSignersRunOutbox {
 public static void main(String[] args)throws Exception {
  if(args.length!=1||!args[0].matches("run_[0-9A-HJKMNP-TV-Z]{26}"))throw new IllegalArgumentException("Unsafe Run");
  var rows=new ArrayList<Map<String,Object>>();
  try(var connection=DriverManager.getConnection("jdbc:sqlite:file:/data/samlscope.db?mode=ro");
      var statement=connection.prepareStatement("SELECT run_id,case_id,action_id,status,transcript_entry_id,created_at,updated_at FROM outbox_actions WHERE run_id=? ORDER BY created_at,action_id")) {
   statement.setString(1,args[0]);try(var result=statement.executeQuery()) {while(result.next()) {
    var row=new TreeMap<String,Object>();for(var field:List.of("run_id","case_id","action_id","status","transcript_entry_id","created_at","updated_at"))row.put(field,result.getString(field));rows.add(row);
   }}
  }
  var json=new JsonCodec();json.mapper().enable(com.fasterxml.jackson.databind.SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS);
  System.out.println(json.mapper().writerWithDefaultPrettyPrinter().writeValueAsString(Map.of("schema","samlscope-used-signers-run-outbox-v1","runId",args[0],"readonly",true,"rows",rows,"count",rows.size())));
 }
}
'''

def locate(root, product='simplesamlphp'):
    require(product == 'simplesamlphp', 'Unimplemented product adapter remains NOT_VERIFIED')
    root = pathlib.Path(root).absolute()
    require(not any(p.is_symlink() for p in [root, *root.parents]), 'Unsafe evidence root')
    folder = root if (root/'receipt/manifest.json').is_file() else root/FOLDER
    require(folder.is_dir() and not any(p.is_symlink() for p in [folder, *folder.parents]), 'Unsafe attempt folder')
    return folder

def relative_file(root, name):
    require(isinstance(name, str) and name and '\\' not in name and '\x00' not in name, 'Unsafe public file name')
    parts = pathlib.PurePosixPath(name)
    require(not parts.is_absolute() and str(parts) == name and all(p not in ('', '.', '..') for p in parts.parts), 'Foreign public file path')
    path = root.joinpath(*parts.parts)
    require(not any(p.is_symlink() for p in [path, *path.parents]) and path.is_file(), 'Public file is missing or a symlink')
    return path

def reject_sensitive(value):
    if isinstance(value, dict):
        for name, item in value.items():
            key = re.sub(r'[-_.]', '', name.lower())
            require(not any(x in key for x in ('cookie','authorization','password','passwd','secret','token','privatekey'))
                and not ('credentials' in key and key != 'currentcredentials'), 'Private public projection refused')
            reject_sensitive(item)
    elif isinstance(value, list):
        for item in value: reject_sensitive(item)
    elif isinstance(value, str):
        require(re.search(r'-----BEGIN (?:RSA |EC |ENCRYPTED )?PRIVATE KEY-----', value) is None, 'Private bytes refused')

def public_inventory(receipt):
    receipt = pathlib.Path(receipt)
    require(receipt.is_dir() and not any(p.is_symlink() for p in [receipt, *receipt.parents]), 'Unsafe public receipt')
    result = {}
    for path in receipt.rglob('*'):
        require(not path.is_symlink(), 'Symlink in public receipt')
        if not path.is_file():
            require(path.is_dir(), 'Special file in public receipt'); continue
        name = str(path.relative_to(receipt)); relative_file(receipt, name)
        raw = path.read_bytes()
        require(re.search(rb'-----BEGIN (?:RSA |EC |ENCRYPTED )?PRIVATE KEY-----', raw) is None, 'Private material in public receipt')
        if path.suffix == '.json':
            value = json.loads(raw)
            if name in ('primary/transcript.json','secondary/transcript.json'): validate_transcript_privacy(value)
            else: reject_sensitive(value)
        result[name] = sha(raw)
    return result

def validate_transcript_privacy(entries):
    """Preserve Recorder bytes; accept only its irreversible header redaction grammar."""
    require(isinstance(entries,list), 'Public transcript is not a list')
    cookie = r"[!#$%&'*+.^_`|~0-9A-Za-z-]+=<redacted: [0-9]+ bytes>"
    for entry in entries:
        require(isinstance(entry,dict) and isinstance(entry.get('headers'),dict), 'Transcript headers unavailable')
        headers = dict(entry['headers'])
        for name, values in list(headers.items()):
            lower = name.lower()
            if lower not in ('cookie','set-cookie','authorization','proxy-authorization'): continue
            require(isinstance(values,list) and values and all(isinstance(v,str) for v in values), 'Ambiguous redacted headers')
            if lower in ('cookie','set-cookie'):
                require(all(re.fullmatch(cookie+r'(?:; '+cookie+r')*',v) for v in values), 'Unredacted cookie bytes refused')
            else:
                require(all(re.fullmatch(r'<redacted: [A-Za-z][A-Za-z0-9-]*, [0-9]+ bytes>',v) for v in values), 'Unredacted authorization refused')
            del headers[name]
        reject_sensitive(entry | {'headers':headers})

def validate_costs(counts):
    require(isinstance(counts, dict) and set(counts) == set(EXPECTED_COSTS)
            and all(type(counts[k]) is int and counts[k] == v for k, v in EXPECTED_COSTS.items()), 'Actual native operation costs differ')
    return counts

def validate_used_peers(manifest, receipt):
    peers = manifest.get('usedSigningPeers')
    require(isinstance(peers, list) and [p.get('label') for p in peers] == ['primary','secondary'], 'Two ordered signing peers required')
    seen = {k:set() for k in ('runId','planId','entityId','requestReference','responseReference')}
    for peer in peers:
        label = peer['label']
        require(re.fullmatch(RUN, peer.get('runId','')) and re.fullmatch(PLAN, peer.get('planId',''))
                and peer.get('entityId') == 'http://localhost:18080/p/'+peer['planId'], 'Foreign signing peer identity')
        for key in seen:
            require(peer.get(key) not in seen[key], 'Duplicate signing peer '+key); seen[key].add(peer.get(key))
        require(re.fullmatch(TX, peer.get('requestReference','')) and re.fullmatch(TX, peer.get('responseReference','')),
                'Foreign signing protocol references')
        require(peer.get('signerUseOriginal') == label+'-signer-use', 'Signer-use original is not owned by peer')
        for key, name in (('fixtureFile','fixture.xml'),('createdFile','created.json'),('planFile','plan.json')):
            require(peer.get(key) == label+'/'+name, 'Foreign peer evidence path')
        created = load(relative_file(receipt, peer['createdFile']))['run']
        plan = load(relative_file(receipt, peer['planFile']))
        require(created['id'] == peer['runId'] and created['planId'] == peer['planId'] and plan['id'] == peer['planId']
                and plan['profile'] == ('metadata_idp' if label == 'primary' else 'browser_sso_idp')
                and plan['target']['entityId'] == TARGET, 'Signing peer Plan/Run/profile differs')
        root = ET.fromstring(relative_file(receipt, peer['fixtureFile']).read_bytes())
        require(root.tag == '{'+MD+'}EntityDescriptor' and root.get('entityID') == peer['entityId']
                and len(root.findall('{'+MD+'}SPSSODescriptor')) == 1, 'Signing peer original metadata differs')
        require(sha(relative_file(receipt, label+'/target-metadata.xml').read_bytes()) == manifest['targetMetadataSha256'], 'Source target snapshot differs')
    require(peers[0]['runId'] == manifest['runId'] and peers[0]['planId'] == manifest['planId'], 'Primary peer is a foreign Run')
    require(not seen['requestReference'].intersection(seen['responseReference']), 'Request and response references overlap')
    return peers

def transcript_originals(folder, run):
    entries = load(relative_file(folder, 'transcript.json')); by = {}
    require(isinstance(entries, list), 'Transcript is not a list')
    for row in entries:
        require(row.get('runId') == run and re.fullmatch(TX, row.get('id','')) and row['id'] not in by, 'Foreign/duplicate transcript')
        by[row['id']] = row
    validate_transcript_privacy(entries)
    decoded = {}
    for row in load(relative_file(folder, 'decoded-manifest.json')):
        tx = row['id']; require(tx in by and tx not in decoded and row['file'] == 'decoded/'+tx+'.xml', 'Foreign decoded original')
        raw = relative_file(folder, row['file']).read_bytes(); entry = by[tx]
        require(entry['decodedSamlRef'] == 'transcripts/'+run+'/'+tx+'.saml.xml' and type(entry['decodedSamlBytes']) is int
                and entry['decodedSamlBytes'] == len(raw) and sha(raw) == row['sha256'], 'Decoded original differs')
        decoded[tx] = raw
    require(set(decoded) == {e['id'] for e in entries if e.get('decodedSamlRef')}, 'Incomplete decoded transcript')
    return entries, by, decoded

def at(value, field):
    instant = value[field]
    if type(instant) is int: return Decimal(instant)
    if type(instant) is float:
        require(math.isfinite(instant), 'Nonfinite public Instant')
        return Decimal(str(instant))
    return stored._instant_seconds(instant)

def verify_restoration(folder, counts):
    restored = load(relative_file(folder, 'restoration-write.json'))
    require(restored['restored'] is True and restored['original_sha256'] == restored['final_sha256']
            and all(type(restored[k]) is int for k in ('configuration_write_attempts','applied_conditions','restoration_write_attempts'))
            and restored['configuration_write_attempts'] == 2 and restored['applied_conditions'] == 1
            and restored['restoration_write_attempts'] == 1 and not restored.get('errors'), 'Exact remote restoration missing')
    mounted = load(relative_file(folder, 'native-mounted-configuration-readbacks.json'))
    require(mounted['mount']['RW'] is True and mounted['mount'] == dict(Type='bind', Source=str(REPO/'build/acceptance/reference-20260914/ssp-config/saml20-sp-remote.php'),
            Destination=PEER_REMOTE, RW=True) and mounted['guestWriteAttempts'] == mounted['successfulHostWrites'] == mounted['successfulGuestWrites'] == 2,
            'Mounted remote configuration costs differ')
    require(all(type(mounted[k]) is int for k in ('guestWriteAttempts','successfulHostWrites','successfulGuestWrites')), 'Mounted write counts must be integers')
    rows = mounted['readbacks']
    require([r['phase'] for r in rows] == ['initial','before-host-write','after-native-write','before-host-write','after-native-write']
            and all(r['sha256'] == r['expectedSha256'] and at(r,'startedAt') <= at(r,'finishedAt') for r in rows)
            and rows[0]['sha256'] == rows[1]['sha256'] == rows[4]['sha256'] == restored['original_sha256']
            and rows[2]['sha256'] == rows[3]['sha256'] != rows[0]['sha256'], 'Native mounted epoch proof differs')
    removed = load(relative_file(folder, 'ephemeral-removal.json'))
    require(removed.get('removed') is True and removed.get('absent') is True
            and type(removed.get('createAttempts')) is int and type(removed.get('removeAttempts')) is int
            and removed == dict(removed=True, absent=True, createAttempts=1, removeAttempts=1), 'Owned ephemeral material was not removed exactly once')
    require(load(relative_file(folder, 'restoration.json')) == restored, 'Restoration snapshots differ')
    return restored

def verify_files(folder):
    folder = pathlib.Path(folder); receipt = folder/'receipt'; m = load(relative_file(receipt, 'manifest.json'))
    require(re.fullmatch(RUN, m.get('runId','')) and re.fullmatch(PLAN, m.get('planId',''))
            and re.fullmatch('[0-9a-f]{64}', m.get('targetMetadataSha256','')), 'Unsafe primary Run/Plan/digest')
    require(m['schema'] == 'samlscope-native-metadata-publisher-key-inventory-v1'
            and m['campaignId'] == 'native-metadata-publisher-key-inventory' and m['adapter'] == 'simplesamlphp-stock-publisher-inventory-v1'
            and m['selectedPath'] == 'stock-current-role' and m['counterfactualCalibrationOnly'] is False and m['entityId'] == TARGET,
            'Real stock publisher proof required')
    require(public_inventory(receipt) == m['files'] | {'manifest.json':sha((receipt/'manifest.json').read_bytes())}, 'Receipt inventory differs')
    for name in m['files']: relative_file(receipt, name)
    target = relative_file(folder, 'target-metadata.xml').read_bytes()
    require(target == relative_file(receipt, 'target-metadata.xml').read_bytes() and sha(target) == m['targetMetadataSha256'], 'Primary fixed snapshot changed')
    peers = validate_used_peers(m, receipt); run = m['runId']
    plan = load(relative_file(folder, 'plan.json')); before = load(relative_file(folder, 'result-before.json')); cases = public_cases(before)
    require(plan == load(receipt/peers[0]['planFile']) and plan['profile'] == 'metadata_idp' and before['run']['id'] == run
            and before['target']['role'] == 'IDP' and before['target']['metadata_digest'] == 'sha256:'+m['targetMetadataSha256']
            and all(c in cases and cases[c]['mode'] == 'CONFIG' for c in (C1,C3)), 'Real approved primary CONFIG slots missing')
    entries, by, decoded = transcript_originals(folder, run)
    old = load(relative_file(folder, 'transcript-before-collection.json'))
    require([e for e in entries if e['id'] in {r['id'] for r in old}] == old, 'Primary prior transcript changed')
    require(set(m['originals']) == set(ORIGINAL_KINDS), 'Original inventory is incomplete or ambiguous')
    originals = {}; references = set()
    for label, kind in ORIGINAL_KINDS.items():
        ref = m['originals'][label]; tx = ref['reference']; require(tx in decoded and tx not in references, 'Original transcript missing or duplicated'); references.add(tx)
        require(ref['file'] == 'native-originals/'+label+'.json' and decoded[tx] == relative_file(receipt, ref['file']).read_bytes()
                and sha(decoded[tx]) == ref['sha256'] == m['files'][ref['file']], 'Native original is not an exact Recorder original')
        n = json.loads(decoded[tx]); reject_sensitive(n); entry = by[tx]
        require(n['schema'] == 'samlscope-native-publisher-original-v1' and n['runId'] == run and n['campaignId'] == m['campaignId']
                and n['targetMetadataSha256'] == m['targetMetadataSha256'] and n['kind'] == kind and at(n,'recordedAt') <= at(entry,'timestamp')
                and entry['direction'] == 'INBOUND' and entry['method'] == 'POST' and entry['status'] == 204
                and entry['contentType'] == 'application/json' and entry['url'] == m['recorderUrl'] == 'http://localhost:18080/p/'+m['planId']+'/sp/paos?run='+run,
                'Native original Run/transport binding differs')
        originals[label] = n
    epochs = m['epochs']; require(len(epochs) == 1, 'One unchanged signer epoch required'); epoch = epochs[0]
    require(epoch['id'] == 'peer-signers' and epoch['transition'] == 'explicit-native-peer-signers'
            and epoch['beforeOriginal'] == 'signers-before' and epoch['afterOriginal'] == 'signers-after'
            and epoch['publicationOriginal'] == 'signers-publication' and epoch['transitionOriginal'] == 'signers-transition'
            and at(originals['signers-before'],'nativeFinishedAt') < at(epoch,'startedAt') < at(epoch,'finishedAt') < at(originals['signers-after'],'nativeStartedAt'), 'Signer epoch is unbound')
    require(relative_file(receipt, epoch['publicationFile']).read_bytes() == target, 'Current publication differs from immutable target')
    secondary_entries = None
    for peer in peers:
        history, source_by, source_decoded = transcript_originals(receipt/peer['label'], peer['runId'])
        if peer['label'] == 'primary': require(history == entries and source_decoded == decoded, 'Primary peer export differs')
        else: secondary_entries = history
        req, rsp = peer['requestReference'], peer['responseReference']; use = originals[peer['signerUseOriginal']]
        require(req in source_decoded and rsp in source_decoded and source_by[req]['direction'] == 'OUTBOUND' and source_by[rsp]['direction'] == 'INBOUND'
                and use['observedRunId'] == peer['runId'] and use['requestReference'] == req and use['responseReference'] == rsp
                and use['requestSha256'] == sha(source_decoded[req]) and use['responseSha256'] == sha(source_decoded[rsp])
                and use['fixtureSha256'] == sha(relative_file(receipt, peer['fixtureFile']).read_bytes())
                and re.fullmatch('[0-9a-f]{64}', use['responseCertificateSpkiSha256'])
                and at(epoch,'startedAt') <= at(use,'nativeStartedAt') <= at(source_by[req],'timestamp') < at(source_by[rsp],'timestamp')
                <= at(use,'nativeFinishedAt') <= at(epoch,'finishedAt') < at(use,'recordedAt'), 'Actual signer use source Run is unbound')
    require(originals['primary-signer-use']['responseCertificateSpkiSha256'] != originals['secondary-signer-use']['responseCertificateSpkiSha256'], 'One signer cannot prove two current keys')
    material, removal = originals['ephemeral-material'], originals['ephemeral-removal']
    require(sha(relative_file(receipt, material['publicCertificateFile']).read_bytes()) == material['certificateSha256'] == removal['certificateSha256']
            and removal['absent'] is True and at(material,'nativeStartedAt') < at(material,'nativeFinishedAt') < at(epoch,'startedAt')
            and at(originals['signers-after'],'nativeFinishedAt') < at(removal,'nativeStartedAt') < at(removal,'nativeFinishedAt') < at(originals['restoration'],'recordedAt'), 'Ephemeral public material ownership/removal is unproven')
    counts = validate_costs(load(relative_file(folder, 'operation-counts.json'))); verify_restoration(folder, counts)
    require(originals['restoration']['operationCounts'] == counts, 'Restoration original costs differ')
    qualification = load(relative_file(folder, 'qualification.json'))
    require(qualification['adopted'] is False and qualification['initialTargetSnapshotUnchanged'] is True and qualification['settingsRestored'] is True
            and qualification['newSaml'] == 3 and qualification['newCredentials'] == 1 and qualification['personOperations'] == 0, 'Measurement/adoption separation missing')
    return m, run, entries

def cumulative_cost_projection(folder):
    records = []; totals = {}
    for name in (*stock.PRIOR_ATTEMPTS, stock.FOLDER, 'simplesamlphp-publisher-used-signers-r1'):
        prior = folder.parent/name; require(prior.is_dir() and not any(p.is_symlink() for p in [prior,*prior.rglob('*')]), 'Prior attempt missing or unsafe')
        inventory = {str(p.relative_to(prior)):sha(p.read_bytes()) for p in prior.rglob('*') if p.is_file()}
        snapshots = {}
        for name2 in ('operation-counts.json','failure-accounting.json','qualification.json','recovery-restoration.json','operations.json','public-read-operations.json','root-restoration-check.json'):
            path = prior/name2
            if path.is_file(): snapshots[name2] = dict(sha256=sha(path.read_bytes()), value=load(path))
        require(snapshots, 'Prior operation snapshot unavailable')
        if 'failure-accounting.json' in snapshots and 'costs' in snapshots['failure-accounting.json']['value']:
            costs = snapshots['failure-accounting.json']['value']['costs']
        elif prior.name == 'simplesamlphp-publisher-used-signers-r1':
            q = snapshots['failure-accounting.json']['value']
            require(q['schema'] == 'samlscope-publisher-used-signers-failure-v1' and q['stage'] == 'native-client-import-before-output'
                    and q['exceptionClass'] == 'ImportError' and q['restorationRequired'] is False and q['adopted'] is False
                    and all(type(q[k]) is int and q[k] == 0 for k in ('nativeSettings','nativeSaml','nativeCredentials','nativePublicCalls','personOperations','plans','runs')),
                    'Failed import attempt does not prove zero target/Run operations')
            costs = dict(productSettings=q['nativeSettings'], samlSubmissions=q['nativeSaml'], credentialPosts=q['nativeCredentials'],
                         nativePublicCalls=q['nativePublicCalls'], personOperations=q['personOperations'], plans=q['plans'], runs=q['runs'])
        elif 'operation-counts.json' in snapshots: costs = snapshots['operation-counts.json']['value']
        else:
            q = snapshots['qualification.json']['value']; costs = dict(productSettings=q['settings'], samlSubmissions=q['saml'], credentialPosts=q['credentials'], personOperations=q['personOperations'], nativePublicCalls=q['nativePublicCalls'], metadataGets=q['metadataGets'])
        costs = dict(costs)
        if 'public-read-operations.json' in snapshots:
            http = snapshots['public-read-operations.json']['value']; require(isinstance(http,list), 'Prior public HTTP ledger is not a list')
            require(all(r['method'] == 'GET' and r['url'] == PUBLICATION and type(r['responseStatus']) is int and r['responseStatus'] == 200
                    and re.fullmatch('[0-9a-f]{64}',r['responseSha256']) for r in http), 'Prior public HTTP reads are unbound')
            if 'metadataGets' not in costs: costs['metadataGets'] = len(http)
        elif 'metadataGets' not in costs:
            # The oldest stopped CLI attempt has a single saved GET original but
            # predates the HTTP ledger. Retain its bound original as a cost only.
            publications = list((prior/'receipt/native-publications').glob('*.xml'))
            if publications:
                snapshots['public-publication-originals'] = {str(p.relative_to(prior)):sha(p.read_bytes()) for p in publications}
                costs['metadataGets'] = len(publications)
        verification_costs = {}
        if 'root-restoration-check.json' in snapshots:
            root_check = snapshots['root-restoration-check.json']['value']
            require(root_check['exactRestored'] is True and root_check['adopted'] is False
                    and root_check['hostSha256'] == root_check['nativeSha256'] == root_check['expectedSha256']
                    and re.fullmatch('[0-9a-f]{64}',root_check['expectedSha256'])
                    and type(root_check['nativeReadbacks']) is int and root_check['nativeReadbacks'] == 1
                    and all(type(root_check[k]) is int and root_check[k] == 0 for k in ('settingWrites','samlSubmissions','credentialPosts','personOperations')), 'Independent old native restoration read is unbound')
            verification_costs = dict(nativePublicCalls=root_check['nativeReadbacks'], independentNativeHashReadbacks=root_check['nativeReadbacks'])
        require(all(type(v) is int and v >= 0 for v in costs.values()), 'Prior operation counts are not integer originals')
        for key, value in costs.items(): totals[key] = totals.get(key, 0)+value
        for key, value in verification_costs.items(): totals[key] = totals.get(key, 0)+value
        records.append(dict(folder=prior.name, files=inventory, boundSnapshots=snapshots, recordedCosts=costs, independentVerificationCosts=verification_costs))
    counts = validate_costs(load(folder/'operation-counts.json')); http = load(folder/'public-read-operations.json')
    require([r['label'] for r in http] == ['initial','peer-signers','restored'] and all(r['method'] == 'GET' and r['url'] == PUBLICATION
            and r['responseStatus'] == 200 and at(r,'startedAt') < at(r,'finishedAt') and r['responseSha256'] == sha((folder/'receipt/native-publications'/(r['label']+'.xml')).read_bytes()) for r in http), 'Actual public GET ledger differs')
    manifest = load(folder/'receipt/manifest.json'); peers = validate_used_peers(manifest, folder/'receipt')
    qualified = counts | dict(metadataGets=len(http), plans=len(peers), runs=len({p['runId'] for p in peers}))
    read_source = folder.parent/'publisher-used-signers-preflight-r1/public-native-source-read-costs.json'
    source_reads = load(relative_file(read_source.parent, read_source.name))
    require(source_reads['schema'] == 'samlscope-publisher-public-read-costs-v1' and source_reads['nativePublicReadCalls'] == 2
            and source_reads['sourceBytesPersisted'] is False
            and source_reads['commands'] == [['docker','exec','samlscope-reference-ssp','cat','/var/simplesamlphp/src/SimpleSAML/Utils/'+name+'.php'] for name in ('Config','System')]
            and all(type(source_reads[k]) is int and source_reads[k] == 0 for k in ('nativeSettings','nativeSaml','nativeCredentials','personOperations')), 'Prior public native resolver read ledger differs')
    totals['nativePublicCalls'] = totals.get('nativePublicCalls',0)+source_reads['nativePublicReadCalls']
    for key, value in qualified.items(): totals[key] = totals.get(key, 0)+value
    value = dict(schema='samlscope-used-signers-cumulative-costs-v1', priorAttempts=records, qualifiedAttempt=folder.name,
        qualifiedCosts=qualified, cumulativeRecordedCosts=totals, qualifiedCountsSha256=sha((folder/'operation-counts.json').read_bytes()),
        qualifiedHttpLedgerSha256=sha((folder/'public-read-operations.json').read_bytes()),
        additionalPublicNativeSourceReadLedger=dict(file=str(read_source.relative_to(folder.parent)),sha256=sha(read_source.read_bytes()),value=source_reads),
        suitePlanRunCountsDerivedFromPublicCreatedDocuments=True,
        priorProductSettingsAreRecordedWriteAttempts=True, priorAppliedChangesNotInferred=True, userInteractions=0)
    return value

def cumulative_operations(folder, write=False):
    value = cumulative_cost_projection(folder); path = folder/'cumulative-operation-audit.json'
    if write: save(path, value)
    else: require(load(path) == value, 'Bound failed-attempt lineage/cost audit changed')
    return value

def capture_runtime(folder, qualified_dependencies=None):
    selected = qualified_dependencies or QUALIFIED_DEPENDENCIES
    require(selected is not None, 'Independent qualified deployment path is not set')
    qualification = pathlib.Path(selected); qualification = qualification if qualification.is_absolute() else folder.parent/qualification
    require(qualification.is_file() and not any(p.is_symlink() for p in [qualification,*qualification.parents]), 'Unsafe qualified deployment source')
    qualified = load(qualification); require(os.statvfs(REPO).f_bavail*os.statvfs(REPO).f_frsize >= 48*1024*1024, 'Insufficient archive space')
    dest = folder/RUNTIME; dest.mkdir(exist_ok=False); pins = {}
    for name in JARS:
        remote = '/opt/samlscope/lib/'+name+'-0.1.0.jar'
        before = subprocess.check_output(['docker','exec',SUITE,'sha256sum',remote],timeout=30).decode().split()[0]
        subprocess.run(['docker','cp',SUITE+':'+remote,str(dest/(name+'.jar'))],check=True,capture_output=True,timeout=50)
        after = subprocess.check_output(['docker','exec',SUITE,'sha256sum',remote],timeout=30).decode().split()[0]
        require(before == after == sha((dest/(name+'.jar')).read_bytes()), 'Actual deployed bytes changed during capture'); pins[name] = before
    require(qualified['projectJars'] == {n+'-0.1.0.jar':pins[n] for n in JARS}, 'Captured runtime differs from qualified deployment')
    library = dest/'dependencies'; library.mkdir(); priority = []
    for name, digest in qualified['dependencySha256'].items():
        path = pathlib.Path(name)
        require(path.name not in {n+'-0.1.0.jar' for n in JARS} and path.is_file() and not path.is_symlink() and sha(path.read_bytes()) == digest, 'Qualified dependency differs')
        target = library/path.name; require(not target.exists(), 'Duplicate archived dependency name'); shutil.copyfile(path, target)
        priority.append(dict(file='dependencies/'+path.name, sha256=digest))
    save(dest/'dependency-priority.json', dict(schema='samlscope-publisher-replay-dependencies-v1', qualifiedSource=str(qualification.relative_to(folder.parent)),
        qualifiedSourceSha256=sha(qualification.read_bytes()), mutableProjectEntriesExcluded=True, entries=priority))
    pins['dependencyPrioritySha256'] = sha((dest/'dependency-priority.json').read_bytes())
    for name in (HELPER,STORED):
        raw = pathlib.Path(__file__).with_name(name+'.java').read_bytes(); (dest/(name+'.java')).write_bytes(raw); pins[name] = sha(raw)
    raw = OUTBOX_SOURCE.encode(); (dest/(OUTBOX+'.java')).write_bytes(raw); pins[OUTBOX] = sha(raw)
    save(dest/'pins.json', pins); save(dest/'archive-provenance.json', dict(actualDeployedByteCopy=True, mutableProjectHardlinks=False, productOperations=0))
    return pins

def independently_pinned(runtime):
    require(bool(PINS), 'Runtime/archive has no independent pins')
    runtime = pathlib.Path(runtime); pins = load(relative_file(runtime, 'pins.json'))
    require(pins == PINS and set(pins) == set(JARS) | {HELPER,STORED,OUTBOX,'dependencyPrioritySha256'}, 'Runtime/archive differs from independent pins')
    for name in JARS:
        path = relative_file(runtime, name+'.jar'); require(path.stat().st_nlink == 1 and sha(path.read_bytes()) == pins[name], 'Archived project JAR changed or is hardlinked')
    for name in (HELPER,STORED,OUTBOX): require(sha(relative_file(runtime, name+'.java').read_bytes()) == pins[name], 'Archived public helper changed')
    priority = relative_file(runtime, 'dependency-priority.json')
    require(sha(priority.read_bytes()) == pins['dependencyPrioritySha256'], 'Qualified dependency priority changed')
    provenance = load(relative_file(runtime, 'archive-provenance.json'))
    require(provenance == dict(actualDeployedByteCopy=True, mutableProjectHardlinks=False, productOperations=0), 'Archive provenance differs')
    for row in load(priority)['entries']: relative_file(runtime, row['file'])
    stock.archived_classpath(runtime)
    return pins

def validate_live_suite_runtime(folder):
    independently_pinned(folder/RUNTIME)
    for name in JARS:
        raw = subprocess.check_output(['docker','exec',SUITE,'sha256sum','/opt/samlscope/lib/'+name+'-0.1.0.jar'],timeout=30).decode().split()
        require(len(raw) == 2 and raw[0] == PINS[name] and raw[1] == '/opt/samlscope/lib/'+name+'-0.1.0.jar', 'Live Suite production runtime differs from actual archived qualification')

def replay(folder):
    runtime = folder/RUNTIME; independently_pinned(runtime); cp = stock.archived_classpath(runtime)
    with tempfile.TemporaryDirectory(prefix='used-signers-archived-replay-') as name:
        tmp = pathlib.Path(name); classes = tmp/'classes'
        subprocess.run(['javac','-sourcepath','','-cp',cp,'-d',str(classes),str(runtime/(HELPER+'.java'))],check=True,capture_output=True,timeout=60)
        require(all(p.name.startswith(HELPER) for p in classes.rglob('*.class')), 'Replay helper shadows production Reader')
        subprocess.run(['java','-cp',str(classes)+':'+cp,'com.samlscope.runner.cases.'+HELPER,str(folder.resolve()),str(tmp/'report.json')],check=True,capture_output=True,timeout=90)
        return load(tmp/'report.json')

def validate_replay(m, observed):
    require(observed['runId'] == m['runId'] and observed['targetMetadataSha256'] == m['targetMetadataSha256']
            and set(observed['caseOutcomes']) == {C1,C3} and all(o['outcome'] == 'VIOLATED' for o in observed['caseOutcomes'].values()), 'Actual current signer omission is not proven')
    require(set(observed['negativeControls']) == CONTROLS and set(observed['negativeControls'].values()) == {'NOT_VERIFIED'}
            and set(observed['approvedMutants']) == {C1,C3} and all(v['production']['outcome'] == 'NOT_VERIFIED' and v['offline']['outcome'] == 'VIOLATED' for v in observed['approvedMutants'].values())
            and set(observed['wrapperLifecycle']) == LIFECYCLE and all(v is True for v in observed['wrapperLifecycle'].values())
            and observed['counterfactualAdopted'] is False and set(observed['sourceRunIds']) == {m['usedSigningPeers'][1]['runId']}
            and all(type(observed[k]) is int and observed[k] == 0 for k in ('additionalSettings','additionalSaml','additionalCredentials')),
            'Meaningful production controls/full wrapper lifecycle incomplete')
    return observed['caseOutcomes']

def capture_outbox(folder, name, run):
    require(re.fullmatch(RUN, run), 'Unsafe public outbox Run'); runtime = folder/RUNTIME; independently_pinned(runtime)
    source = relative_file(runtime, OUTBOX+'.java'); cp = stock.archived_classpath(runtime); output = folder/name
    require(not output.exists(), 'Public outbox original already exists')
    with tempfile.TemporaryDirectory(prefix='used-signers-public-outbox-') as name2:
        tmp = pathlib.Path(name2); classes = tmp/'classes'
        subprocess.run(['javac','-sourcepath','','-cp',cp,'-d',str(classes),str(source)],check=True,capture_output=True,timeout=60)
        require(all(p.name.startswith(OUTBOX) for p in classes.rglob('*.class')), 'Outbox helper shadows production classes')
        remote = '/tmp/'+tmp.name
        subprocess.run(['docker','exec',SUITE,'mkdir','-p',remote],check=True,capture_output=True,timeout=30)
        try:
            subprocess.run(['docker','cp',str(classes),SUITE+':'+remote+'/classes'],check=True,capture_output=True,timeout=60)
            raw = subprocess.check_output(['docker','exec',SUITE,'java','-cp',remote+'/classes:/opt/samlscope/lib/*','com.samlscope.runner.cases.'+OUTBOX,run],timeout=30)
        finally: subprocess.run(['docker','exec','--user','0',SUITE,'rm','-rf',remote],check=True,capture_output=True,timeout=30)
    value = json.loads(raw); validate_outbox(value, run); output.write_bytes(raw)
    save(output.with_suffix('.provenance.json'), dict(sourceSha256=sha(source.read_bytes()), sha256=sha(raw), readonly=True, payloadExported=False, productOperations=0))
    return value

def read_live_outbox(folder, run):
    with tempfile.TemporaryDirectory(prefix='used-signers-live-public-outbox-') as name:
        return capture_outbox(folder, str(pathlib.Path(name)/'original.json'), run)

def validate_outbox(value, run):
    require(value['schema'] == 'samlscope-used-signers-run-outbox-v1' and value['runId'] == run and value['readonly'] is True
            and type(value['count']) is int and value['count'] == len(value['rows']), 'Foreign public outbox projection')
    seen = set()
    for row in value['rows']:
        require(set(row) == {'run_id','case_id','action_id','status','transcript_entry_id','created_at','updated_at'} and row['run_id'] == run
                and re.fullmatch(r'action_[0-9a-f]{32}', row['action_id']) and row['action_id'] not in seen, 'Outbox row is foreign, duplicated or private')
        seen.add(row['action_id']); at(row,'created_at'); at(row,'updated_at')
    return value

def verify_outbox_original(folder, name, run):
    path = relative_file(folder, name); value = load(path); validate_outbox(value, run)
    require(load(path.with_suffix('.provenance.json')) == dict(sourceSha256=PINS[OUTBOX], sha256=sha(path.read_bytes()), readonly=True, payloadExported=False, productOperations=0), 'Public outbox provenance changed')
    return value

def readback_inventory(path):
    require(re.fullmatch(r'/data/metadata-publisher-key-evidence/(?:\.stage-)?'+RUN, path), 'Unsafe public placement path')
    result = subprocess.run(['docker','exec',SUITE,'sh','-c','cd "$1" && test -z "$(find . -type l -print -quit)" && find . -type f -exec sha256sum {} +','publisher-readback',path],check=True,capture_output=True,timeout=50)
    rows = {}
    for line in result.stdout.decode().splitlines():
        digest, name = line.split('  ', 1); name = name[2:] if name.startswith('./') else ''
        require(re.fullmatch('[0-9a-f]{64}', digest) and name and not pathlib.PurePosixPath(name).is_absolute()
                and '..' not in pathlib.PurePosixPath(name).parts and name not in rows, 'Ambiguous public placement inventory')
        rows[name] = digest
    return rows

def install(folder):
    m, run, entries = verify_files(folder); observed = replay(folder); require(observed == load(folder/'native-reader-replay.json'), 'Actual archived replay must precede placement'); validate_replay(m, observed)
    ev = folder/EVALUATION; ev.mkdir(exist_ok=False)
    validate_live_suite_runtime(folder)
    # These direct database originals precede any result GET, which can reevaluate.
    for case, label in ((C1,'c1'),(C3,'c3')): stored.capture(folder, RUNTIME, EVALUATION+'/stored-before-'+label+'.json', run, case)
    for peer in m['usedSigningPeers']:
        label = peer['label']; source = folder/'receipt'/label
        capture_outbox(folder, EVALUATION+'/'+label+'-outbox-before.json', peer['runId'])
        history = api('/api/runs/'+peer['runId']+'/transcript'); require(history == load(source/'transcript.json'), 'Source history changed before placement'); save(ev/(label+'-transcript-before.json'), history)
    save(ev/'result-before.json', api('/api/runs/'+run+'/result.json'))
    base = '/data/metadata-publisher-key-evidence'; dest = base+'/'+run; stage = base+'/.stage-'+run
    for path in (dest, stage): require(subprocess.run(['docker','exec',SUITE,'test','-e',path],capture_output=True,timeout=20).returncode == 1, 'Existing public proof/stage must not be overwritten')
    inventory = public_inventory(folder/'receipt')
    with tempfile.TemporaryDirectory(prefix='used-signers-public-placement-') as name:
        copy = pathlib.Path(name)/'receipt'; shutil.copytree(folder/'receipt', copy)
        for p in [copy,*copy.rglob('*')]: p.chmod(0o755 if p.is_dir() else 0o644)
        subprocess.run(['docker','exec','--user','0',SUITE,'mkdir','-p',base],check=True,capture_output=True,timeout=30)
        subprocess.run(['docker','cp',str(copy),SUITE+':'+stage],check=True,capture_output=True,timeout=90)
        require(readback_inventory(stage) == inventory, 'Suite user cannot read the exact staged public inventory')
        subprocess.run(['docker','exec','--user','0',SUITE,'mv',stage,dest],check=True,capture_output=True,timeout=30)
    require(readback_inventory(dest) == inventory, 'Atomic public placement inventory differs')
    save(folder/'receipt-installation.json', dict(path=dest, readBackVerified=True, records=inventory, atomicSameDataFilesystem=True,
        publicFiles0644=True, publicDirectories0755=True, stockSelectedPath=True, productOperations=0))
    validate_live_suite_runtime(folder)

def formal(folder):
    m, run, entries = verify_files(folder); ev = folder/EVALUATION
    require(all((ev/('stored-before-'+label+'.json')).is_file() for label in ('c1','c3')), 'Both stored-before originals must precede placement')
    require(load(folder/'receipt-installation.json')['readBackVerified'] is True, 'Public receipt is not installed')
    validate_live_suite_runtime(folder)
    save(ev/'evaluate.json', api('/api/runs/'+run+'/protocol-evidence/evaluate', {})); save(ev/'result.json', api('/api/runs/'+run+'/result.json'))
    for case, label in ((C1,'c1'),(C3,'c3')): stored.capture(folder, RUNTIME, EVALUATION+'/stored-after-'+label+'.json', run, case)
    for peer in m['usedSigningPeers']:
        label = peer['label']; capture_outbox(folder, EVALUATION+'/'+label+'-outbox-after.json', peer['runId'])
        save(ev/(label+'-transcript-after.json'), api('/api/runs/'+peer['runId']+'/transcript'))
    validate_live_suite_runtime(folder)

def verify_preservation(before_result, after_result, adopted):
    require(set(adopted) == {C1,C3} and before_result['run']['id'] == after_result['run']['id']
            and before_result['target'] == after_result['target'], 'Formal primary Run/target differs')
    before, after = public_cases(before_result), public_cases(after_result)
    require(len(before) == sum(len(q['cases']) for q in before_result['requirements']) and len(after) == sum(len(q['cases']) for q in after_result['requirements'])
            and set(before) == set(after) and {k:v for k,v in before.items() if k not in adopted} == {k:v for k,v in after.items() if k not in adopted}, 'Unrelated case or case inventory changed')
    for case, proof in adopted.items():
        observed = after[case]
        require(proof['outcome'] == 'VIOLATED' and (observed['outcome'],observed['verdict'],observed['evidence_class'],observed['attested'])
                == ('VIOLATED','FAIL','OPERATOR_ASSISTED',False) and observed['attested'] is False
                and observed['reason_code'] == proof['reasonCode'] and observed['evidence'] == proof['evidence'], 'Full central native omission conclusion/provenance differs')
    return {c:after[c] for c in (C1,C3)}

def verify(root, product='simplesamlphp', live=False):
    folder = locate(root, product); m, run, entries = verify_files(folder); cumulative_operations(folder)
    observed = load(relative_file(folder, 'native-reader-replay.json')); require(replay(folder) == observed, 'Actual archived production replay differs'); outcomes = validate_replay(m, observed)
    installed = load(relative_file(folder, 'receipt-installation.json'))
    require(installed == dict(path='/data/metadata-publisher-key-evidence/'+run, readBackVerified=True, records=public_inventory(folder/'receipt'),
        atomicSameDataFilesystem=True, publicFiles0644=True, publicDirectories0755=True, stockSelectedPath=True, productOperations=0), 'Public receipt installation is not closed')
    ev = folder/EVALUATION; result = load(relative_file(ev, 'result.json')); before = load(relative_file(ev, 'result-before.json'))
    require(result['run']['id'] == run and result['target']['metadata_digest'] == 'sha256:'+m['targetMetadataSha256'], 'Formal target identity differs')
    selected = verify_preservation(before, result, outcomes)
    for case, label in ((C1,'c1'),(C3,'c3')):
        for when in ('before','after'):
            source = relative_file(ev, 'stored-'+when+'-'+label+'.source.java')
            require(sha(source.read_bytes()) == PINS[STORED], 'Stored original is not from the actual pinned shared helper')
        final = stored.compare_stored(folder, RUNTIME, case, outcomes[case], before_name=EVALUATION+'/stored-before-'+label+'.json', after_name=EVALUATION+'/stored-after-'+label+'.json')
        require(final['verdict'] == 'FAIL', 'Archived central Evaluator did not preserve MUST failure')
    for peer in m['usedSigningPeers']:
        label = peer['label']; history = load(folder/'receipt'/label/'transcript.json')
        require(load(ev/(label+'-transcript-before.json')) == load(ev/(label+'-transcript-after.json')) == history, 'Entire source Run transcript changed')
        require(verify_outbox_original(folder, EVALUATION+'/'+label+'-outbox-before.json', peer['runId'])
                == verify_outbox_original(folder, EVALUATION+'/'+label+'-outbox-after.json', peer['runId']), 'Entire source Run outbox changed')
    if live:
        validate_live_suite_runtime(folder)
        for peer in m['usedSigningPeers']:
            require(api('/api/runs/'+peer['runId']+'/transcript') == load(folder/'receipt'/peer['label']/'transcript.json'), 'Live source transcript differs')
            require(read_live_outbox(folder, peer['runId']) == verify_outbox_original(folder, EVALUATION+'/'+peer['label']+'-outbox-after.json', peer['runId']), 'Live entire source Run outbox differs')
        require({c:public_cases(api('/api/runs/'+run+'/result.json'))[c] for c in (C1,C3)} == selected, 'Live primary conclusions differ')
        initial = load(folder/'receipt/native-readbacks/initial.json'); program = (folder/'receipt/native-public-readback.php').read_bytes()
        raw = subprocess.check_output(['docker','exec','-i','samlscope-reference-ssp','php','-d','display_errors=0','-d','log_errors=0'],input=program,timeout=40); current = json.loads(raw); reject_sensitive(current)
        for field in ('publicRequestContext','publicNativeMetadata','currentCredentials','remotePeers','loadedClasses','metadataSources','configurationHashes','roleFeatureFlags','nativeProducedMetadataXmlBase64','nativeProducedMetadataSha256'):
            require(current[field] == initial[field], 'Live restored native public state differs')
        native = json.loads(subprocess.check_output(['docker','inspect','--format','{"id":{{json .Id}},"image":{{json .Image}},"running":{{json .State.Running}},"startedAt":{{json .State.StartedAt}},"mounts":{{json .Mounts}}}','samlscope-reference-ssp'],timeout=30))
        native['mounts'] = sorted(native['mounts'],key=lambda x:json.dumps(x,sort_keys=True,separators=(',',':'))+'\n')
        require(native == load(folder/'receipt'/m['originals']['initial']['file'])['runtime'], 'Live native runtime/mount epoch differs')
        with urllib.request.urlopen(PUBLICATION,timeout=30) as response: require(response.status == 200 and sha(response.read()) == m['targetMetadataSha256'], 'Live immutable publication differs')
        require(readback_inventory(installed['path']) == installed['records'], 'Live installed public proof differs')
        validate_live_suite_runtime(folder)
    return ev/'result.json', selected

if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__); p.add_argument('root', type=pathlib.Path); p.add_argument('--product', default='simplesamlphp')
    p.add_argument('--qualified-dependencies', type=pathlib.Path); p.add_argument('--live', action='store_true')
    actions = p.add_mutually_exclusive_group()
    for name in ('record-costs','capture-runtime','record-replay','install','formal'): actions.add_argument('--'+name, action='store_true')
    a = p.parse_args(); folder = locate(a.root, a.product)
    if a.record_costs: print(json.dumps(cumulative_operations(folder, True), indent=2))
    elif a.capture_runtime: print(json.dumps(capture_runtime(folder, a.qualified_dependencies), indent=2))
    elif a.record_replay: save(folder/'native-reader-replay.json', replay(folder)); print('Actual archived used-signer replay passed')
    elif a.install: install(folder); print('Public proof installed after both stored-before originals')
    elif a.formal: formal(folder); print('Both central conclusions and unchanged source histories captured')
    else:
        path, cases = verify(a.root, a.product, a.live)
        print(json.dumps(dict(result=str(path), cases=list(cases), additionalSaml=0, additionalCredentials=0,
            verificationOnlyNativePublicCalls=1 if a.live else 0, verificationOnlyMetadataGets=1 if a.live else 0)))
