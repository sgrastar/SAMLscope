"""Reference SLO campaign utilities. Credentials and authentication capabilities stay in memory."""
import base64
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
import zlib

REPO = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(REPO / 'dev/keycloak'), str(REPO / 'dev/reference-acceptance')]
from import_metadata_batch import api, save, BASE
from reference_flow import Client, parse_forms
from browser_probe_selection import prepare_and_skip
from capture_run_originals import capture

CASE = 'IIP-IDP17-ab-idp-01'
CAMPAIGN = 'native-slo-registered-signer'
FIXTURES = ('local-invalid-signature', 'local-other-signer', 'local-normal')
SUITE = 'samlscope-reference-suite'
MD = 'urn:oasis:names:tc:SAML:2.0:metadata'
SAML = 'urn:oasis:names:tc:SAML:2.0:protocol'
DS = 'http://www.w3.org/2000/09/xmldsig#'
SHA = lambda raw: hashlib.sha256(raw).hexdigest()
NOW = lambda: datetime.datetime.now(datetime.timezone.utc).isoformat().replace('+00:00', 'Z')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def public_json(value):
    if isinstance(value, dict):
        for key, member in value.items():
            require(re.search(r'(?i)password|passwd|private.?key|secret|authorization|cookie|(?:^|[-_.])token(?:$|[-_.])', key) is None,
                    'Sensitive field name refused before public recording: ' + key)
            public_json(member)
    elif isinstance(value, list):
        for member in value:
            public_json(member)


def local_url(url):
    p = urllib.parse.urlsplit(url)
    require(p.scheme in ('http', 'https') and p.hostname in ('localhost', '127.0.0.1')
            and p.username is None and p.password is None, 'Nonlocal or credential-bearing URL refused')
    return p


def endpoint(url):
    p = local_url(url)
    return urllib.parse.urlunsplit((p.scheme, p.netloc, p.path, '', ''))


# Exact stock SSP non-authentication navigation. Inspection removes it only in memory;
# the full native response bytes remain unchanged in the public original.
LANGUAGE_NAVIGATION = (r'<form\s+id="language-form"\s+class="pure-form"\s+method="get"\s*>\s*'
    r'<div\s+id="languageform"\s*>\s*<select\s+aria-label="Language"\s+class="pure-input-1-4 language-menu"\s+name="language"\s+id="language-selector"\s*>\s*'
    r'(?:<option\s+value="[A-Za-z][A-Za-z0-9_-]{0,15}"(?:\s+selected="selected")?\s*>[^<>]*</option>\s*)+'
    r'</select>\s*<noscript>\s*<button\s+type="submit"\s+class="pure-button"\s*>\s*<i\s+class="fa fa-arrow-right"\s*></i>\s*</button>\s*</noscript>\s*</div>\s*</form>')

def without_public_language_navigation(page):
    matches=list(re.finditer(r'(?is)<form\b[^>]*>.*?</form\s*>',page))
    language=[m for m in matches if re.match(r'<form\s+id="language-form"(?:\s|>)',m.group(),re.I)]
    require(len(language)<=1,'Duplicate public language navigation refused')
    for match in language:
        require(re.fullmatch(LANGUAGE_NAVIGATION,match.group(),re.I|re.S) is not None,
                'Unexpected language navigation structure refused before recording')
        page=page[:match.start()]+page[match.end():]
    return page


def safe_body(raw):
    require(len(raw) <= 1024 * 1024, 'Oversize native response refused')
    page = raw.decode('utf-8', errors='strict')
    require(re.search(r'(?i)logout-resume[^\s<>"\x27]*[?&](?:amp;)?id=', page) is None,
            'Native logout continuation capability refused before public recording')
    # SAML response forms are normal protocol evidence. Authentication forms are not exported.
    inspected=without_public_language_navigation(page)
    for form in parse_forms(inspected):
        require(set(form.fields).issubset({'SAMLResponse', 'RelayState'}) and 'SAMLResponse' in form.fields,
                'Authentication/confirmation form refused before public recording')
    remaining=re.sub(r'(?is)<form\b[^>]*>.*?</form\s*>','',inspected)
    require(re.search(r'(?i)<\s*(?:input|textarea|select)\b',remaining) is None,'Credential/control input outside a qualified form refused')
    require(re.search(r'(?i)session_code|tab_id|client_data|csrf|kc_action|auth_session_id|Authorization\s*:|Cookie\s*:', page) is None,
            'Authentication capability refused before public recording')
    return raw


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, location):
        return None


class SharedSloClient(Client):
    """One authenticated browser; capture target response before dispatching it to Suite."""
    def __init__(self, target_origin, directory):
        super().__init__()
        self.target_origin = target_origin
        self.directory = Path(directory)
        self.credential_posts = self.credential_attempts = self.protocol_posts = self.protocol_redirects = 0
        self.records = []; self.outbox_attempts = 0
        owner = self

        class Redirects(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, request, fp, code, message, headers, location):
                p = local_url(location)
                if p.scheme + '://' + p.netloc == owner.target_origin and 'SAMLRequest' in urllib.parse.parse_qs(p.query):
                    owner.protocol_redirects += 1
                return super().redirect_request(request, fp, code, message, headers, location)

        self.op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar), Redirects())
        self.slo_op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar), NoRedirect())

    def complete_native_response(self, final, body, code, request_id):
        """Default products have no extra native browser navigation."""
        return final, body, code, {}

    def complete_native_redirect(self, final, body, code, location, request_id):
        """Product-specific internal navigation stays in memory before public recording."""
        return final, body, code, location, {}

    def request(self, url, fields=None):
        local_url(url)
        if fields and 'freshSessionConfirmed' in fields:
            raise ValueError('Fresh-session confirmation refused for shared SLO controls')
        if fields and any(key in fields for key in ('password', 'j_password')):
            self.credential_attempts += 1
            require(self.credential_posts == 0, 'Second credential submission refused before transport')
            self.credential_posts += 1
        xml = raw = None
        if fields and 'SAMLRequest' in fields:
            raw = base64.b64decode(fields['SAMLRequest'], validate=True)
            xml = ET.fromstring(raw)
            require(xml.get('ForceAuthn') in (None, 'false', '0') and xml.get('IsPassive') in (None, 'false', '0'),
                    'Fresh authentication boundary refused before transport')
            if endpoint(url).startswith(self.target_origin + '/'):
                self.protocol_posts += 1
        if xml is None or xml.tag != '{' + SAML + '}LogoutRequest':
            return super().request(url, fields)
        require(endpoint(url).startswith(self.target_origin + '/'), 'SLO fixture has a foreign target')
        self.outbox_attempts += 1
        started = NOW()
        save(self.directory.parent/'native-slo-attempts.json',dict(attempts=self.outbox_attempts,latestRequestId=xml.get('ID'),latestRequestSha256=SHA(raw),startedAt=started,unknownDeliveryIsProductFailure=False))
        request = urllib.request.Request(url, data=urllib.parse.urlencode(fields).encode(), method='POST')
        try:
            response = self.slo_op.open(request, timeout=40)
        except urllib.error.HTTPError as error:
            # HTTPError is also the original response; no retry or different request is sent.
            response = error
        try:
            body = response.read(1024 * 1024 + 1)
            code, final, location = response.status, response.geturl(), response.headers.get('Location')
            finished = NOW()
        finally:
            response.close()
        final,body,code,location,redirect_completion=self.complete_native_redirect(final,body,code,location,xml.get('ID'))
        final,body,code,completion=self.complete_native_response(final,body,code,xml.get('ID'))
        completion.update(redirect_completion)
        if completion:finished=NOW()
        redirect=None
        if code in (301, 302, 303, 307, 308):
            require(location is not None, 'Redirect response lacks actual Location')
            raw_location=location;resolved=urllib.parse.urljoin(final,raw_location);p=local_url(resolved)
            values=urllib.parse.parse_qs(p.query,strict_parsing=True)
            require(set(values).issubset({'SAMLResponse','RelayState','SigAlg','Signature'}) and 'SAMLResponse' in values
                    and all(len(v)==1 for v in values.values()) and p.fragment=='',
                    'Non-SAML/authentication Location refused before recording')
            reply=zlib.decompress(base64.b64decode(values['SAMLResponse'][0],validate=True),-15)
            redirect=(raw_location,resolved,reply)
        safe_body(body)
        name = 'native-body-' + xml.get('ID', '') + '.html'
        require(re.fullmatch(r'native-body-_[A-Za-z0-9_-]+\.html', name), 'Unsafe native request identity')
        (self.directory / name).write_bytes(body)
        row = dict(method='POST', requestUrl=url, responseUrl=final, requestId=xml.get('ID'),
                   requestSha256=SHA(raw), startedAt=started, finishedAt=finished,
                   responseStatus=code, responseBodyFile=name, responseBodyBytes=len(body), responseBodySha256=SHA(body))
        row.update(completion)
        if code in (301, 302, 303, 307, 308):
            raw_location,location,reply=redirect
            row.update(responseSamlSha256=SHA(reply), responseSamlEndpoint=endpoint(location))
            location_name = 'native-location-' + xml.get('ID', '') + '.txt'
            (self.directory / location_name).write_bytes(raw_location.encode('utf-8'))
            row['responseLocationFile'] = location_name
            self.records.append(row)
            require(code in (301, 302, 303), 'Redirect preserving POST requires separate delivery handling')
            return self.request(location)
        replies = [form for form in parse_forms(body.decode()) if 'SAMLResponse' in form.fields]
        require(len(replies) <= 1, 'Ambiguous native response form')
        if replies:
            reply = base64.b64decode(replies[0].fields['SAMLResponse'], validate=True)
            row.update(responseSamlSha256=SHA(reply), responseSamlEndpoint=endpoint(urllib.parse.urljoin(final, replies[0].action)))
        self.records.append(row)
        return final, body.decode(), code


def docker(*arguments, timeout=60, data=None):
    return subprocess.run(['docker', *arguments], input=data, capture_output=True, check=True, timeout=timeout).stdout


def runtime(container, allowed_mounts=None):
    fmt = '{"id":{{json .Id}},"image":{{json .Image}},"running":{{json .State.Running}},"startedAt":{{json .State.StartedAt}},"mounts":{{json .Mounts}}}'
    value = json.loads(docker('inspect', '--format', fmt, container, timeout=20))
    require(value['running'] is True, 'Native runtime is stopped')
    mounts = value['mounts']
    if allowed_mounts is None:
        require(mounts == [], 'Runtime has an unqualified mounted override')
    else:
        require(isinstance(mounts,list) and len(mounts)==len(allowed_mounts), 'Native mount count differs')
        seen=set()
        for mount in mounts:
            destination=mount.get('Destination');expected=allowed_mounts.get(destination)
            require(destination not in seen and expected is not None and mount.get('Type')=='bind' and mount.get('RW') is expected['rw'] and mount.get('Source')==str(expected['source']) and mount.get('Propagation')=='rprivate' and mount.get('Mode') in (('', 'rw') if expected['rw'] else ('ro',)), 'Unknown native override/mount refused')
            seen.add(destination)
    # Docker exposes mounts from a map; presentation order may vary between inspections.
    # Preserve every actual attribute, while making future recorded snapshots deterministic.
    value['mounts'] = sorted(mounts, key=lambda mount: mount['Destination'])
    return value


def mounted_hashes(container, state):
    observed={}
    for mount in state['mounts']:
        source=Path(mount['Source']);require(source.is_file() and not source.is_symlink(), 'Mounted source is absent or symlinked')
        host=SHA(source.read_bytes());native=docker('exec',container,'sha256sum',mount['Destination']).decode().split()[0]
        require(host==native,'Host/native mounted bytes differ')
        observed[mount['Destination']]=dict(source=str(source),hostSha256=host,nativeSha256=native)
    return observed


def recorded(receipt, created, value, label):
    public_json(value)
    raw = (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()
    run, plan = created['run']['id'], created['run']['planId']
    before = {e['id'] for e in api('/api/runs/' + run + '/transcript')}
    request = urllib.request.Request(BASE + '/p/' + plan + '/sp/paos?run=' + run, data=raw, method='POST', headers={'Content-Type': 'application/json'})
    with urllib.request.urlopen(request, timeout=40) as response:
        require(response.status == 204, 'Recorder refused original bytes')
    entries = [e for e in api('/api/runs/' + run + '/transcript') if e['id'] not in before and e.get('decodedSamlRef')]
    require(len(entries) == 1 and entries[0]['decodedSamlBytes'] == len(raw), 'Recorder original identity ambiguous')
    path = receipt / 'native-originals' / (label + '.json'); path.parent.mkdir(exist_ok=True); path.write_bytes(raw)
    return dict(reference=entries[0]['id'], sha256=SHA(raw))


def file_hashes(receipt):
    return {str(p.relative_to(receipt)): SHA(p.read_bytes()) for p in receipt.rglob('*') if p.is_file() and p.name not in {'manifest.json', 'preparation.json'}}


def install_public(source, run):
    """Create a separate public staging copy; immutable archives are never chmodded or linked."""
    import tempfile
    source = Path(source)
    with tempfile.TemporaryDirectory(prefix='slo-public-stage-') as temporary:
        stage = Path(temporary) / 'public'; stage.mkdir(mode=0o755)
        records = {}
        for p in source.rglob('*'):
            require(not p.is_symlink(), 'Symlinked public sidecar refused')
            if not p.is_file():
                continue
            relative = p.relative_to(source)
            raw = p.read_bytes()
            if p.suffix in ('.json', '.xml', '.php', '.txt', '.html'):
                require(re.search(rb'-----BEGIN (?:RSA |EC |ENCRYPTED )?PRIVATE KEY-----', raw) is None, 'Private key refused')
            target = stage / relative; target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(raw); target.chmod(0o644); records[str(relative)] = SHA(raw)
        for directory in [stage, *[p for p in stage.rglob('*') if p.is_dir()]]:
            directory.chmod(0o755)
        destination = '/data/slo-registered-signer-evidence/' + run
        docker('exec', '--user', '0', SUITE, 'mkdir', '-p', destination)
        docker('exec', '--user', '0', SUITE, 'chmod', '0755', destination)
        docker('cp', str(stage) + '/.', SUITE + ':' + destination, timeout=90)
        for name, digest in records.items():
            actual = docker('exec', SUITE, 'sha256sum', destination + '/' + name).decode().split()[0]
            require(actual == digest, 'Suite-user public readback differs')
        return dict(path=destination, records=records, readBackVerified=True, modes={'files':'0644','directories':'0755'}, publicStagingCopy=True)


def preparation_qualification(receipt, frame, mode, out):
    """Actual installed native predicates before login; full session predicates before SLO.

    The temporary public frame is a diagnostic prerequisite, never an adopted receipt.
    Existing original files and permissions are left untouched.
    """
    import shutil
    import tempfile
    require(mode in ('native', 'prepared'), 'Unsupported prerequisite stage')
    helper = 'VerifySloRegisteredSignerPreparation'
    source = REPO / 'dev/reference-acceptance' / (helper + '.java')
    runner = REPO / 'api/build/install/samlscope/lib/runner-0.1.0.jar'
    deployed = docker('exec', SUITE, 'sha256sum', '/opt/samlscope/lib/' + runner.name).decode().split()[0]
    require(SHA(runner.read_bytes()) == deployed, 'Prerequisite compiler/runtime differs from deployed Runner')
    run = frame['runId']; require(re.fullmatch(r'run_[0-9A-HJKMNP-TV-Z]{26}', run), 'Unsafe prerequisite Run')
    with tempfile.TemporaryDirectory(prefix='slo-preparation-') as name:
        temporary = Path(name); stage = temporary / 'public'; stage.mkdir()
        shutil.copytree(receipt, stage / run)
        raw = (json.dumps(frame, sort_keys=True, separators=(',', ':')) + '\n').encode()
        # Preserve the exact prerequisite input even if the helper stops before M0.
        saved_input = out / (mode + '-preparation-input.json')
        require(not saved_input.exists(), 'Prerequisite input is already immutable')
        saved_input.write_bytes(raw)
        (stage / run / 'preparation.json').write_bytes(raw)
        classes = stage / 'classes'
        compiled = subprocess.run(['javac', '-sourcepath', '', '-cp', str(runner.parent / '*'), '-d', str(classes), str(source)],
                                  capture_output=True, timeout=60)
        require(compiled.returncode == 0, 'Native prerequisite helper did not compile')
        require(all(p.name.startswith(helper) for p in classes.rglob('*.class')), 'Prerequisite helper shadows production classes')
        for p in stage.rglob('*'):
            require(not p.is_symlink(), 'Symlinked prerequisite copy refused')
            p.chmod(0o755 if p.is_dir() else 0o644)
        stage.chmod(0o755)
        remote = '/tmp/' + temporary.name
        command = ['java', '-cp', remote + '/classes:/opt/samlscope/lib/*', 'com.samlscope.runner.cases.' + helper,
                   remote + '/' + run, '/data', remote + '/result.json', mode]
        started = NOW()
        try:
            # Parent belongs to the Suite user so the public diagnostic report can be written.
            docker('exec', SUITE, 'mkdir', '-m', '0755', remote)
            docker('cp', str(stage) + '/.', SUITE + ':' + remote, timeout=90)
            call = subprocess.run(['docker', 'exec', SUITE, *command], capture_output=True, timeout=90)
            destination = out / (mode + '-preparation-qualification.json')
            docker('cp', SUITE + ':' + remote + '/result.json', str(destination), timeout=40)
            report = json.loads(destination.read_bytes())
            save(out / (mode + '-preparation-invocation.json'), dict(
                schema='samlscope-slo-preparation-invocation-v1', runId=run, stage=mode, command=command,
                startedAt=started, completedAt=NOW(), exitCode=call.returncode, runnerSha256=deployed,
                helperSourceSha256=SHA(source.read_bytes()), preparationSha256=SHA(raw),
                reportSha256=SHA(destination.read_bytes()), productSettings=0, protocolSubmissions=0,
                credentialPosts=0, diagnosticOnly=True))
            require(call.returncode == 0 and report.get('ready') is True and report.get('runId') == run
                    and report.get('mode') == mode and report.get('preparationSha256') == SHA(raw)
                    and report.get('nativePreparationVerified') is True
                    and report.get('preloginFixtureExecutionVerified') == 3
                    and report.get('fixtureConstructionIsSessionEvidence') is False,
                    'Actual native preparation predicate is unproven; no additional login or SLO will be attempted')
            return report
        finally:
            docker('exec', '--user', '0', SUITE, 'rm', '-rf', remote)


def collect(product, output, max_suite_probes=500, min_free_mib=96):
    """Product adapter owns only setup/readback/restore; all SAML comes from Runner outbox."""
    free = os.statvfs(REPO)
    require(free.f_bavail * free.f_frsize >= min_free_mib * 1024 * 1024, 'Insufficient host space before native setup')
    out = Path(output).resolve(); out.mkdir(parents=True, exist_ok=False)
    receipt = out / 'receipt'; receipt.mkdir()
    (out / 'common-collector-source.py').write_bytes(Path(__file__).read_bytes())
    module = sys.modules.get(type(product).__module__)
    if module is not None and getattr(module,'__file__',None):
        (out / 'product-collector-source.py').write_bytes(Path(module.__file__).read_bytes())
    peers, references, probes, skips = [], {}, [], []
    primary = None; client = product.create_client(receipt) if hasattr(product,'create_client') else SharedSloClient(product.origin, receipt)
    error = None; restored = False; setup_started = False
    recorder_ready = False; deferred_initial = None
    defer_target_preflight = hasattr(product, 'configure_publisher')
    product.bind(out, receipt)
    try:
        product.preflight()
        for label in ('primary', 'secondary'):
            folder = receipt / label; folder.mkdir()
            plan = api('/api/plans', dict(name=product.name + ' SLO registered signer ' + label,
                profile='single_logout_idp', targetKind='IDP', targetEntityId=product.target,
                metadataSourceKind='URL', metadataSourceLocation=product.metadata_source,
                suiteMetadataDelivery='HTTP_URL', declaredFeatures={},
                parameters=dict(clockSkewToleranceSeconds=180, metadataRefreshWaitSeconds=30,
                                testUserHint='samlscope-m0-user', requestSigningMode='REQUIRED'),
                interaction=dict(allowBrowserSteps=True, allowAttestation=False, preset='quick'), authorizedTarget=True))
            save(out / (label + '-plan.json'), plan)
            plan_id = plan['plan']['plan']['id']
            created = api('/api/plans/' + plan_id + '/runs', {})
            save(folder / 'created.json', created)
            if not defer_target_preflight:
                save(out / (label + '-preflight.json'), api('/api/runs/' + created['run']['id'] + '/preflight', {}))
                docker('cp', SUITE + ':/data/target-metadata/' + created['run']['id'] + '.xml', str(folder / 'target-metadata.xml'), timeout=40)
            with urllib.request.urlopen(BASE + '/p/' + plan_id + '/metadata', timeout=30) as response:
                raw = response.read(1024 * 1024 + 1)
            xml = ET.fromstring(raw); entity = BASE + '/p/' + plan_id
            require(xml.tag == '{' + MD + '}EntityDescriptor' and xml.get('entityID') == entity,
                    'Actual Suite metadata has a different peer entity')
            (folder / 'fixture.xml').write_bytes(raw)
            peers.append(dict(label=label, runId=created['run']['id'], planId=plan_id, entity=entity))
            if label == 'primary':
                primary = created; save(out / 'created.json', created); save(out / 'plan.json', plan)
                if not defer_target_preflight:
                    (receipt / 'target-metadata.xml').write_bytes((folder / 'target-metadata.xml').read_bytes())
        if defer_target_preflight:
            # Capture the genuine original state before configuring the stock publisher. The
            # same fresh Runs obtain their FIRST immutable metadata snapshot after native POST
            # advertisement; no earlier Run snapshot or fixture is replaced.
            started=NOW();value=product.state('initial',peers);finished=NOW();public_json(value)
            deferred_initial=dict(nativeStartedAt=started,nativeFinishedAt=finished,readback=value)
            save(out/'deferred-initial-native-observation.json',deferred_initial)
            setup_started=True;product.configure_publisher()
            for peer in peers:
                save(out/(peer['label']+'-preflight.json'),api('/api/runs/'+peer['runId']+'/preflight',{}))
                docker('cp',SUITE+':/data/target-metadata/'+peer['runId']+'.xml',str(receipt/peer['label']/'target-metadata.xml'),timeout=40)
            (receipt/'target-metadata.xml').write_bytes((receipt/'primary/target-metadata.xml').read_bytes())
        require((receipt / 'primary/target-metadata.xml').read_bytes() == (receipt / 'secondary/target-metadata.xml').read_bytes(),
                'Two plans have a different pinned target snapshot')
        target_hash = SHA((receipt / 'target-metadata.xml').read_bytes())
        target_xml = ET.fromstring((receipt / 'target-metadata.xml').read_bytes())
        require(target_xml.get('entityID') == product.target, 'Pinned target differs from native product')
        save(out / 'planned-scope.json', dict(caseId=CASE, mode='ATTESTED', profile='single_logout_idp',
            runId=primary['run']['id'], targetMetadataSha256=target_hash, formalSlotVerified=False,
            plannedOnly=True, reason='Formal case slot becomes available only after the actual M0 prerequisite'))

        def original(name, kind, **values):
            record = dict(schema='samlscope-slo-registered-signer-original-v1', runId=primary['run']['id'],
                          campaignId=CAMPAIGN, targetMetadataSha256=target_hash, kind=kind, recordedAt=NOW(), **values)
            ref = recorded(receipt, primary, record, name); references[name] = ref
            save(out / 'native-original-references.json', references)
            return record

        def state(label):
            if label=='initial' and deferred_initial is not None:
                started=deferred_initial['nativeStartedAt'];finished=deferred_initial['nativeFinishedAt'];readback=deferred_initial['readback']
            else:
                started = NOW(); readback = product.state(label, peers); finished = NOW()
            public_json(readback)
            path = 'native-readbacks/' + label + '.json'; (receipt / 'native-readbacks').mkdir(exist_ok=True)
            save(receipt / path, readback)
            return original(label, 'native-slo-registered-peers', phase=label, nativeStartedAt=started,
                            nativeFinishedAt=finished, nativeReadbackFile=path,
                            nativeReadbackSha256=SHA((receipt / path).read_bytes()),
                            **({'restored': True} if label == 'restoration' else {}))

        recorder_ready=True;state('initial'); setup_started = True; product.prepare(peers)
        # Native scope is qualified by the installed product adapter before the only login.
        state('probes-before')
        frame = dict(schema='samlscope-slo-registered-signer-preparation-v1', caseId=CASE, campaignId=CAMPAIGN,
                     runId=primary['run']['id'], adapter=product.adapter, targetEntityId=product.target,
                     targetMetadataSha256=target_hash, counterfactualCalibrationOnly=False,
                     peers=peers, originals=dict(references), files=file_hashes(receipt))
        preparation_qualification(receipt, frame, 'native', out)
        user = os.environ.get('REFERENCE_USERNAME', 'samlscope-m0-user')
        password = os.environ.get('REFERENCE_PASSWORD', 'samlscope-m0-password')
        run = primary['run']['id']; old = {e['id'] for e in api('/api/runs/' + run + '/transcript')}
        result = client.flow(peers[0]['entity'] + '/start/m0-roundtrip?run=' + run, None, user, password)
        added = [e for e in api('/api/runs/' + run + '/transcript') if e['id'] not in old]
        requests = [e for e in added if e['direction'] == 'OUTBOUND' and e.get('samlSummary', {}).get('type') == 'AuthnRequest']
        responses = [e for e in added if e['direction'] == 'INBOUND' and e.get('samlSummary', {}).get('normalFlowAccepted') is True]
        require(result == 'recorded' and len(requests) == len(responses) == 1
                and responses[0]['samlSummary'].get('inResponseTo') == requests[0]['samlSummary'].get('id'),
                'Actual initial shared authentication prerequisite is incomplete; do not repeat login')
        baseline = dict(requestReference=requests[0]['id'], responseReference=responses[0]['id'])
        save(out / 'baseline.json', baseline)
        frame.update(baseline=baseline, originals=dict(references), files=file_hashes(receipt))
        save(receipt / 'preparation.json', frame)
        preparation_qualification(receipt, frame, 'prepared', out)
        save(out / 'preparation-installation.json', install_public(receipt, run))
        save(out / 'tests-start.json', api('/api/runs/' + run + '/tests/start', {}))
        report = api('/api/runs/' + run + '/result.json')
        slots = [c for requirement in report['requirements'] for c in requirement['cases'] if c['id'] == CASE]
        require(report['run']['id'] == run and report['target']['metadata_digest'] == 'sha256:' + target_hash
                and len(slots) == 1 and slots[0]['mode'] == 'ATTESTED', 'Formal case identity/profile/target differs; restore and do not adopt')
        save(out / 'formal-slot.json', dict(runId=run, case=slots[0], profile='single_logout_idp', targetMetadataSha256=target_hash, formalSlotVerified=True))
        for fixture in FIXTURES:
            for _ in range(max_suite_probes):
                status = api('/api/runs/' + run + '/active-probe')
                if status.get('caseId') == CASE:
                    require(status.get('state') == 'READY' and status.get('requiresFreshSession') is False,
                            'Selected SLO fixture is unavailable or requires a fresh session')
                    break
                require(status.get('state') == 'READY', 'SLO signer outbox is not reachable; no login retry')
                skips.append(prepare_and_skip(BASE, run, status, api)); save(out / 'suite-only-skips.json', skips)
            else:
                raise ValueError('Suite-only selection operational bound exceeded')
            action = status['actionId']; old = {e['id'] for e in api('/api/runs/' + run + '/transcript')}
            before_record = len(client.records)
            clock_before = product.before_http()

            def terminal(url, page, code, reason):
                require(len(client.records) == before_record + 1 and client.records[-1]['requestId'] == '_' + action,
                        'Terminal HTTP lacks a unique actual target SLO delivery')
                api('/api/runs/' + run + '/active-probe/browser-response', dict(actionId=action, status=code, url=url, body=page))

            result = client.flow(status['startUrl'], None, user, password, terminal_observer=terminal)
            clock_after = product.after_http(clock_before)
            added = [e for e in api('/api/runs/' + run + '/transcript') if e['id'] not in old]
            requests = [e for e in added if e['direction'] == 'OUTBOUND' and e.get('correlationId') == action
                        and e.get('samlSummary', {}).get('type') == 'LogoutRequest']
            responses = [e for e in added if e['direction'] == 'INBOUND'
                         and e.get('samlSummary', {}).get('inResponseTo') == '_' + action
                         and e.get('samlSummary', {}).get('type') == 'LogoutResponse']
            require(len(requests) == 1 and len(responses) <= 1 and len(client.records) == before_record + 1,
                    'SLO fixture has no unique native request/response original')
            native = dict(client.records[-1]); require(native['requestId'] == '_' + action, 'Native HTTP belongs to another action')
            native.update(clock_after)
            row = dict(fixture=fixture, runId=run, actionId=action, requestReference=requests[0]['id'],
                       nativeHttpOriginal=fixture + '-http')
            payload = dict(observedRunId=run, fixture=fixture, requestReference=requests[0]['id'], actionId=action, native=native)
            if responses:
                row['responseReference'] = payload['responseReference'] = responses[0]['id']
            original(row['nativeHttpOriginal'], 'native-slo-http-response', **payload)
            probes.append(row); save(out / 'probes.json', probes)
        state('probes-after')
        save(out / 'completed-probes.json', dict(fixtures=list(FIXTURES), normalControlEndsSession=True,
             incomingOptionalResponseConsumerObserved=False, productVerdictAdopted=False))
    except Exception as failure:
        error = type(failure).__name__ + ': ' + str(failure)
        save(out / 'failure.json', dict(stage='collector', reason=error, productVerdictAdopted=False))
    finally:
        if setup_started:
            try:
                restored = product.restore(peers)
                require(restored is True, 'Native restoration incomplete; preserve state and stop')
                if recorder_ready:state('restoration')
                else:save(out/'restoration-before-snapshot.json',product.state('restoration',peers))
            except Exception as failure:
                # Physical restoration and a qualified restoration readback are separate facts.
                # Always persist actual attempts, including when the final query itself fails.
                save(out/'restoration-proof-failure.json',dict(physicalRestored=restored,
                    exceptionClass=type(failure).__name__,productVerdictAdopted=False))
                if error is None:error='Native restoration/readback unproven: '+type(failure).__name__
        counts = dict(protocolSubmissions=client.protocol_posts + client.protocol_redirects,
            outboxProtocolSubmissions=client.outbox_attempts, credentialPosts=client.credential_posts,
            credentialPostAttempts=client.credential_attempts, personOperations=0, restored=restored,
            normalControlEndsSession=True, **product.counts())
        save(receipt / 'operation-counts.json', counts); save(out / 'operation-counts.json', counts)
    if error:
        raise ValueError(error)
    for peer in peers:
        entries = api('/api/runs/' + peer['runId'] + '/transcript'); save(receipt / peer['label'] / 'transcript.json', entries)
        child=receipt / peer['label'];capture(child, peer['runId'], entries)
        browser=[]
        for entry in entries:
            if entry.get('method')!='BROWSER':continue
            require(re.fullmatch(r'tx_[0-9A-HJKMNP-TV-Z]{26}',entry['id']) and entry.get('bodyRef')=='transcripts/'+peer['runId']+'/'+entry['id']+'.body' and type(entry.get('bodyBytes')) is int and 0<=entry['bodyBytes']<=1024*1024,'Foreign/oversize browser original')
            raw=docker('exec',SUITE,'cat','/data/'+entry['bodyRef']);require(len(raw)==entry['bodyBytes'],'Browser original length differs');safe_body(raw)
            directory=child/'browser-originals';directory.mkdir(exist_ok=True);name='browser-originals/'+entry['id']+'.body';(child/name).write_bytes(raw)
            browser.append(dict(id=entry['id'],reference=entry['bodyRef'],bytes=len(raw),file=name,sha256=SHA(raw)))
        save(child/'browser-originals-manifest.json',browser)
    manifest = dict(frame, schema='samlscope-slo-registered-signer-v1', probes=probes,
                    originals=references, optionalResponseConsumerObserved=False)
    manifest['files'] = file_hashes(receipt) | {'preparation.json': SHA((receipt / 'preparation.json').read_bytes())}
    save(receipt / 'manifest.json', manifest)
    save(out / 'restoration.json', dict(restored=True, additionalSamlForRestoration=0,
                                      credentialsPersisted=False, cookieValuesPersisted=False))
    return out
