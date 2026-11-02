#!/usr/bin/env python3
"""Loopback-only Keycloak configuration investigation. Never sends AuthnRequests.

Management GET is configuration evidence, not execution evidence. This adapter is
intentionally NOT the product-runtime driver accepted by run_campaign().
"""
import argparse
import ast
import copy
from dataclasses import asdict
import json
from pathlib import Path
import re
import signal
import urllib.error
import urllib.parse as urls
import urllib.request as http

from campaign import CASES, Counters, ROOT, digest, plan

HERE = Path(__file__).resolve().parent
EVIDENCE = ROOT / 'build/acceptance/reference-20261031/sso01g-keycloak'
JOB = Path('/Users/yuta/.claude/codex-jobs/20261031-154936-kc-g-impl')
BASE = 'http://127.0.0.1:18180'
REALM = '/admin/realms/samlscope'
MAPPER = 'saml-authn-context-class-ref-mapper'
CONDITION = 'conditional-level-of-authentication'
PREFIX = 'samlscope-sso01g-'
BINDINGS = ('realm', 'browserFlow', 'directGrantFlow', 'registrationFlow',
            'resetCredentialsFlow', 'clientAuthenticationFlow', 'firstBrokerLoginFlow')


class InvestigationError(RuntimeError):
    """Messages are fixed and contain no response bodies, tokens, or headers."""


def local_base(value):
    p = urls.urlsplit(value)
    if (p.scheme != 'http' or p.hostname != '127.0.0.1' or p.username or p.password
            or p.query or p.fragment or p.path not in ('', '/')
            or p.netloc != '127.0.0.1:18180'):
        raise ValueError('Only http://127.0.0.1:18180 is authorized')
    return BASE


def output_dir(value):
    p = Path(value).absolute()
    if p != p.resolve() or not any(p.is_relative_to(r) and p != r for r in (HERE, EVIDENCE, JOB)):
        raise ValueError('Output must be a non-symlink child of an authorized directory')
    return p


def public(value):
    """Only public API projections enter journals; unexpected sensitive fields stop.

    Client native generated credentials are irreversibly removed in memory before
    any journal/callback. No raw HTTP payloads, headers or exception text are logged.
    """
    if isinstance(value, dict):
        result = {}
        for key, child in value.items():
            if key in ('secret', 'registrationAccessToken'):
                continue
            if re.search(r'password|^credentials?$|private.?key|authorization|cookie|access.?token|refresh.?token', key, re.I):
                raise InvestigationError('Sensitive public projection rejected')
            result[key] = public(child)
        return result
    if isinstance(value, list):
        return [public(v) for v in value]
    return value


def save(path, value):
    # Parent already validated; reject a replaced path or symlink on every write.
    if path.is_symlink() or path.parent != path.parent.resolve():
        raise InvestigationError('Evidence path changed')
    tmp = path.with_suffix(path.suffix + '.tmp')
    if tmp.exists():
        raise InvestigationError('Journal temporary file already exists')
    with tmp.open('x', encoding='utf-8') as f:
        json.dump(public(value), f, ensure_ascii=False, indent=2, sort_keys=True)
        f.write('\n')
        f.flush()
        import os
        os.fsync(f.fileno())
    tmp.replace(path)


def fixture_credentials():
    """Read only literal dev-fixture admin_token kwargs; do not import that script."""
    tree = ast.parse((ROOT / 'dev/keycloak/browser_chain_campaign.py').read_text())
    func = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'admin_token')
    calls = [n for n in ast.walk(func) if isinstance(n, ast.Call)
             and isinstance(n.func, ast.Name) and n.func.id == 'dict']
    for call in calls:
        keys = {k.arg for k in call.keywords}
        if keys == {'client_id', 'username', 'password', 'grant_type'}:
            return {k.arg: ast.literal_eval(k.value) for k in call.keywords}
    raise InvestigationError('Local development credential fixture unavailable')


class NoRedirect(http.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


class LocalAdmin:
    def __init__(self, base=BASE):
        self.base = local_base(base)  # Validate before fixture reads or network.
        self.opener = http.build_opener(http.ProxyHandler({}), NoRedirect())
        self.token = None
        self.events = []

    def _request(self, path, method='GET', body=None, *, form=False, missing=False):
        if (not path.startswith('/') or path.startswith('//') or '\\' in path
                or any(c in path for c in ('\r', '\n', '#'))
                or not (path.startswith(REALM + '/') or path == REALM
                        or path in ('/admin/serverinfo', '/realms/master/protocol/openid-connect/token',
                                    '/realms/samlscope/protocol/saml/descriptor'))):
            raise ValueError('Management or public metadata path required')
        target = self.base + path
        if urls.urlsplit(target).netloc != '127.0.0.1:18180':
            raise ValueError('Non-loopback destination rejected')
        headers = {'Content-Type': 'application/x-www-form-urlencoded' if form else 'application/json'}
        if self.token and not form:
            headers['Authorization'] = 'Bearer ' + self.token
        data = None if body is None else (urls.urlencode(body).encode() if form else json.dumps(body).encode())
        event = dict(method=method, path=path, status=None)
        self.events.append(event)
        try:
            with self.opener.open(http.Request(target, data=data, headers=headers, method=method), timeout=15) as response:
                event['status'] = response.status
                raw = response.read(4 * 1024 * 1024 + 1)
                if len(raw) > 4 * 1024 * 1024:
                    raise InvestigationError('Management response limit exceeded')
                if path.endswith('/descriptor'):
                    return raw
                return json.loads(raw) if raw else None
        except urllib.error.HTTPError as error:
            event['status'] = error.code
            error.close()  # Never read or persist error body/headers, including Location.
            if missing and error.code == 404:
                return None
            raise InvestigationError('Management HTTP request rejected') from None
        except (OSError, ValueError):
            raise InvestigationError('Management delivery or response uncertain') from None

    def login(self):
        value = self._request('/realms/master/protocol/openid-connect/token', 'POST',
                              fixture_credentials(), form=True)
        self.token = value['access_token']

    def get(self, path, *, missing=False):
        return self._request(path, missing=missing)

    def write(self, path, method, body=None):
        # This class cannot write the realm or any resource other than owned
        # objects: KeycloakLive checks IDs and namespace before calling this.
        return self._request(path, method, body)


def ordered(rows):
    return sorted(rows, key=lambda x: json.dumps(x, sort_keys=True))


class KeycloakLive:
    """Own one temporary SAML client and one isolated native flow tree.

    Capture and mutation are journaled before every write. A failed/uncertain
    write is read back, never resent. Finally removes only the fresh owned tree.
    Concurrent edits detected between mutations block destructive cleanup.
    """
    def __init__(self, api, out, name='kc-20261031'):
        if not re.fullmatch(r'[a-z0-9][a-z0-9-]{0,47}', name):
            raise ValueError('Invalid investigation name')
        self.api, self.out = api, output_dir(out)
        self.name = PREFIX + name
        self.client_id = 'urn:samlscope:sso01g:' + name
        self.counts = Counters()
        self.readback_confirmations = 0
        self.expected = None
        self.original = None
        self.pending = None
        self.config_ids = set()
        self.subflow_ids = set()
        self.report = dict(schema='samlscope-keycloak-configuration-investigation-v1',
                           evidenceStatus='supplemental-unadopted', status='incomplete',
                           cases=list(CASES), allCasesHeld=True, restored=False,
                           samlRequests=0, browserLogins=0, humanInteractions=0,
                           errors=[], modes=[],
                           excludedNativeFields=['secret', 'registrationAccessToken',
                                                 'attributes.saml.signing.private.key',
                                                 'attributes.saml.encryption.private.key'])

    def journal(self):
        save(self.out / 'journal.json', dict(name=self.name, clientId=self.client_id,
             original=self.original, expected=self.expected, pending=self.pending,
             configIds=sorted(self.config_ids), subflowIds=sorted(self.subflow_ids), counts=asdict(self.counts)))

    def flows(self):
        return self.api.get(REALM + '/authentication/flows')

    def clients(self):
        rows, offset = [], 0
        while True:
            page = self.api.get(REALM + f'/clients?first={offset}&max=100')
            rows.extend({k: c.get(k) for k in ('id', 'clientId', 'protocol', 'enabled')}
                        for c in page)
            if len(page) < 100:
                return ordered(rows)
            offset += len(page)

    def find_client(self):
        rows = self.api.get(REALM + '/clients?clientId=' + urls.quote(self.client_id, safe=''))
        exact = [c for c in rows if c.get('clientId') == self.client_id]
        if len(exact) > 1:
            raise InvestigationError('Owned client identity ambiguous')
        if not exact:
            return None
        value = self.api.get(REALM + '/clients/' + exact[0]['id'])
        if value.get('id') != exact[0]['id'] or value.get('clientId') != self.client_id:
            raise InvestigationError('Owned client identity mismatch')
        # Keycloak generates a client signing private-key attribute even for a
        # new public SAML client. Remove it in memory before generic projection.
        attrs = value.get('attributes', {})
        for key in ('saml.signing.private.key', 'saml.encryption.private.key'):
            attrs.pop(key, None)
        return public(value)

    def observe(self):
        roots = [f for f in self.flows() if f['alias'] == self.name]
        if len(roots) > 1:
            raise InvestigationError('Owned flow identity ambiguous')
        root = ({k: roots[0].get(k) for k in ('id', 'alias', 'description', 'providerId', 'topLevel', 'builtIn')}
                if roots else None)
        executions, configs = [], {}
        if root:
            executions = public(self.api.get(REALM + '/authentication/flows/' + urls.quote(self.name, safe='') + '/executions'))
            for row in executions:
                if row.get('flowId'):
                    self.subflow_ids.add(row['flowId'])
                cfg = row.get('authenticationConfig')
                if cfg:
                    self.config_ids.add(cfg)
                    configs[cfg] = public(self.api.get(REALM + '/authentication/config/' + cfg))
        # Include orphaned config resources so deletion cascades are verified.
        for cfg in sorted(self.config_ids):
            if cfg not in configs:
                value = self.api.get(REALM + '/authentication/config/' + cfg, missing=True)
                if value is not None:
                    configs[cfg] = public(value)
        return dict(client=self.find_client(), flow=root, executions=executions, configs=configs)

    def snapshot_shared(self):
        # Avoid realm export, SMTP, users, credentials and shared SPI configs.
        realm = self.api.get(REALM)
        flows = public(self.flows())
        executions = {f['alias']: public(self.api.get(REALM + '/authentication/flows/' +
                      urls.quote(f['alias'], safe='') + '/executions')) for f in flows}
        return dict(bindings={k: realm.get(k) for k in BINDINGS}, flows=ordered(flows),
                    executions=executions, clientInventory=self.clients())

    def discover(self):
        info = self.api.get('/admin/serverinfo')
        mappers = info.get('protocolMapperTypes', {}).get('saml', [])
        providers = self.api.get(REALM + '/authentication/authenticator-providers')
        config = self.api.get(REALM + '/authentication/config-description/' + CONDITION)
        value = dict(version=info.get('systemInfo', {}).get('version'),
                     features=[f for f in info.get('features', []) if f['name'].startswith('STEP_UP')],
                     samlMappers=public(mappers), authenticators=public(providers), loaConfig=public(config))
        save(self.out / 'capabilities.json', value)
        feature = {f['name']: f.get('enabled') for f in value['features']}
        if (feature.get('STEP_UP_AUTHENTICATION_SAML') is not True
                or MAPPER not in {m['id'] for m in mappers}
                or not {CONDITION, 'auth-username-form', 'auth-password-form'}.issubset({p['id'] for p in providers})):
            raise InvestigationError('Native SAML step-up prerequisites absent')
        metadata = self.api.get('/realms/samlscope/protocol/saml/descriptor')
        # No URL in the descriptor is dereferenced.
        import hashlib
        save(self.out / 'metadata-summary.json', dict(bytes=len(metadata), sha256=hashlib.sha256(metadata).hexdigest(),
             responseAuthnContextObserved=False))
        return value

    def capture(self):
        if self.find_client() is not None or any(f['alias'].startswith(self.name) for f in self.flows()):
            raise InvestigationError('Investigation namespace already exists; refusing overwrite')
        self.original = self.snapshot_shared()
        self.expected = self.observe()
        self.journal()

    def guard(self):
        if self.observe() != self.expected:
            raise InvestigationError('Concurrent owned configuration edit; cleanup requires review')

    def transition_allowed(self, before, after, pending):
        """Recognize only the one journaled native mutation, including a lost ACK.

        Native-generated IDs/defaults are allowed only on newly created resources.
        Every existing resource must otherwise equal its preceding GET projection.
        """
        path, method, body = (pending[k] for k in ('path', 'method', 'body'))
        expected = copy.deepcopy(before)
        if method == 'DELETE':
            if '/clients/' in path:
                if not before['client'] or path.rsplit('/', 1)[-1] != before['client']['id']:
                    return False
                expected['client'] = None
            elif '/authentication/flows/' in path:
                if not before['flow'] or path.rsplit('/', 1)[-1] != before['flow']['id']:
                    return False
                expected['flow'], expected['executions'] = None, []
                # Keycloak versions differ in config deletion cascade behavior.
                expected['configs'] = {k: v for k, v in before['configs'].items() if k in after['configs']}
            elif '/authentication/config/' in path:
                expected['configs'].pop(path.rsplit('/', 1)[-1], None)
            else:
                return False
        elif method == 'PUT' and path.endswith('/executions'):
            row = next((r for r in expected['executions'] if r['id'] == body['id']), None)
            if row is None:
                return False
            row['requirement'] = body['requirement']
        elif method == 'POST' and path == REALM + '/authentication/flows':
            if before['flow'] is not None or not after['flow']:
                return False
            if any(after['flow'].get(k) != v for k, v in body.items()):
                return False
            expected['flow'] = after['flow']
        elif method == 'POST' and path.endswith(('/executions/flow', '/executions/execution')):
            old = {r['id'] for r in before['executions']}
            added = [r for r in after['executions'] if r['id'] not in old]
            if len(added) != 1:
                return False
            row = added[0]
            if path.endswith('/flow'):
                if row.get('displayName') != body['alias'] or not row.get('authenticationFlow'):
                    return False
            elif row.get('providerId') != body['provider']:
                return False
            expected['executions'] = before['executions'] + added
        elif method == 'POST' and '/authentication/executions/' in path and path.endswith('/config'):
            new_ids = set(after['configs']) - set(before['configs'])
            if len(new_ids) != 1:
                return False
            cfg = next(iter(new_ids))
            if any(after['configs'][cfg].get(k) != v for k, v in body.items()):
                return False
            identifier = path.split('/')[-2]
            row = next((r for r in expected['executions'] if r['id'] == identifier), None)
            if row is None:
                return False
            row['authenticationConfig'] = cfg
            row['alias'] = body['alias']
            expected['configs'][cfg] = after['configs'][cfg]
        elif method == 'POST' and path == REALM + '/clients':
            if before['client'] is not None or not after['client']:
                return False
            for key, value in body.items():
                if key == 'attributes':
                    if any(after['client'].get(key, {}).get(k) != v for k, v in value.items()):
                        return False
                elif after['client'].get(key) != value:
                    return False
            expected['client'] = after['client']
        elif method == 'POST' and path.endswith('/protocol-mappers/models'):
            old = before['client'].get('protocolMappers', [])
            ids = {r['id'] for r in old}
            added = [r for r in after['client'].get('protocolMappers', []) if r['id'] not in ids]
            if len(added) != 1 or any(added[0].get(k) != v for k, v in body.items()):
                return False
            expected['client']['protocolMappers'] = old + added
        else:
            return False
        # The flat execution list preserves native ordering, level, and priority.
        # Insertions in a nested flow may shift subsequent flattened indices only.
        def normalized(value):
            value = copy.deepcopy(value)
            value['executions'] = ordered([{k: v for k, v in r.items() if k != 'index'} for r in value['executions']])
            if value['client'] and 'protocolMappers' in value['client']:
                value['client']['protocolMappers'] = ordered(value['client']['protocolMappers'])
            return value
        return normalized(expected) == normalized(after)

    def reconcile(self):
        after = self.observe()
        if after != self.expected:
            if not self.pending or not self.transition_allowed(self.expected, after, self.pending):
                raise InvestigationError('Unrecognized native change; cleanup requires review')
            self.expected = after
        self.journal()

    def assert_owned_write(self, path, method, body):
        """No mutation may address a shared client, realm binding or shared flow."""
        state = self.expected
        aliases = {self.name, *(self.name + '-' + rank for rank in ('low', 'medium', 'high'))}
        allowed = False
        if method == 'POST' and path == REALM + '/authentication/flows':
            allowed = body.get('alias') == self.name and state['flow'] is None
        elif method == 'POST' and path == REALM + '/clients':
            allowed = body.get('clientId') == self.client_id and state['client'] is None
        elif method == 'DELETE' and state['client'] and path == REALM + '/clients/' + state['client']['id']:
            allowed = True
        elif method == 'POST' and state['client'] and path == REALM + '/clients/' + state['client']['id'] + '/protocol-mappers/models':
            allowed = body.get('protocolMapper') == MAPPER and body.get('protocol') == 'saml'
        elif method == 'DELETE' and state['flow'] and path == REALM + '/authentication/flows/' + state['flow']['id']:
            allowed = True
        elif method == 'DELETE' and path.startswith(REALM + '/authentication/config/'):
            cfg = state['configs'].get(path.rsplit('/', 1)[-1])
            allowed = cfg is not None and cfg['alias'].startswith(self.name + '-')
        elif method == 'POST' and path.startswith(REALM + '/authentication/executions/') and path.endswith('/config'):
            row = next((r for r in state['executions'] if r['id'] == path.split('/')[-2]), None)
            allowed = row is not None and row.get('providerId') == CONDITION and body['alias'].startswith(self.name + '-')
        else:
            for alias in aliases:
                base = REALM + '/authentication/flows/' + alias + '/executions'
                if method == 'PUT' and path == base:
                    allowed = any(r['id'] == body.get('id') for r in state['executions'])
                elif method == 'POST' and path == base + '/execution':
                    allowed = body.get('provider') in (CONDITION, 'auth-username-form', 'auth-password-form')
                elif method == 'POST' and path == base + '/flow':
                    allowed = alias == self.name and body.get('alias') in aliases - {self.name}
        if not allowed:
            raise InvestigationError('Write outside isolated investigation resources rejected')

    def mutate(self, path, method, body=None, *, restoring=False):
        self.assert_owned_write(path, method, body)
        self.guard()
        self.pending = dict(path=path, method=method, body=body)
        self.journal()  # Recovery intent is durable BEFORE a native write.
        def write():
            self.journal()  # Counters.write has now incremented the attempt.
            return self.api.write(path, method, body)
        self.counts.write(write, location='native', restoring=restoring)
        self.journal()  # Persist the acknowledged count even if GET validation stops.
        # If a response/read fails, pending remains for reconciliation in finally.
        after = self.observe()
        if not self.transition_allowed(self.expected, after, self.pending):
            raise InvestigationError('Native mutation read-back mismatch')
        self.expected = after
        self.pending = None
        self.journal()

    def executions(self, alias=None):
        return self.api.get(REALM + '/authentication/flows/' + urls.quote(alias or self.name, safe='') + '/executions')

    def require(self, alias, identifier, requirement):
        rows = self.executions(alias)
        row = next(r for r in rows if r['id'] == identifier)
        row['requirement'] = requirement
        self.mutate(REALM + '/authentication/flows/' + urls.quote(alias, safe='') + '/executions', 'PUT', row)
        if next(r for r in self.executions(alias) if r['id'] == identifier)['requirement'] != requirement:
            raise InvestigationError('Execution requirement read-back mismatch')

    def add_execution(self, alias, provider):
        old = {r['id'] for r in self.executions(alias)}
        self.mutate(REALM + '/authentication/flows/' + urls.quote(alias, safe='') + '/executions/execution',
                    'POST', dict(provider=provider))
        new = [r for r in self.executions(alias) if r['id'] not in old]
        if len(new) != 1 or new[0].get('providerId') != provider:
            raise InvestigationError('Native execution create read-back mismatch')
        self.require(alias, new[0]['id'], 'REQUIRED')
        return new[0]['id']

    def configure(self):
        self.mutate(REALM + '/authentication/flows', 'POST', dict(alias=self.name,
                    providerId='basic-flow', topLevel=True, builtIn=False, description='Temporary SSO01g native investigation'))
        if not self.expected['flow'] or self.expected['flow']['alias'] != self.name:
            raise InvestigationError('Native flow read-back mismatch')
        self.add_execution(self.name, 'auth-username-form')
        for level, rank in enumerate(('low', 'medium', 'high'), 1):
            alias = self.name + '-' + rank
            self.mutate(REALM + '/authentication/flows/' + self.name + '/executions/flow', 'POST',
                        dict(alias=alias, type='basic-flow', provider='basic-flow', description='Native LoA ' + rank))
            row = next(r for r in self.executions() if r.get('displayName') == alias)
            self.require(self.name, row['id'], 'CONDITIONAL')
            condition = self.add_execution(alias, CONDITION)
            self.mutate(REALM + '/authentication/executions/' + condition + '/config', 'POST',
                        dict(alias=alias + '-config', config={'loa-condition-level': str(level), 'loa-max-age': '0'}))
            self.add_execution(alias, 'auth-password-form')
        flow_id = self.expected['flow']['id']
        mapping = {'urn:samlscope:reference:authn:class:' + r: n for n, r in enumerate(('low', 'medium', 'high'), 1)}
        self.mutate(REALM + '/clients', 'POST', dict(clientId=self.client_id, name=self.name,
                    protocol='saml', enabled=True, publicClient=True, redirectUris=[BASE + '/sso01g-unused-acs'],
                    attributes={'acr.loa.map': json.dumps(mapping, separators=(',', ':')),
                                'minimum.acr.value': 'urn:samlscope:reference:authn:class:low'},
                    authenticationFlowBindingOverrides={'browser': flow_id}))
        client = self.expected['client']
        if client is None:
            raise InvestigationError('Native client create read-back mismatch')
        self.mutate(REALM + '/clients/' + client['id'] + '/protocol-mappers/models', 'POST',
                    dict(name=self.name + '-classref', protocol='saml', protocolMapper=MAPPER, config={}))
        self.verify_mode('normal')

    def verify_mode(self, mode):
        self.guard()
        state = self.expected
        client = state['client']
        mapping = {'urn:samlscope:reference:authn:class:' + r: n for n, r in enumerate(('low', 'medium', 'high'), 1)}
        if (client.get('protocol') != 'saml' or json.loads(client.get('attributes', {}).get('acr.loa.map', '{}')) != mapping
                or client.get('authenticationFlowBindingOverrides', {}).get('browser') != state['flow']['id']
                or not any(m.get('protocolMapper') == MAPPER for m in client.get('protocolMappers', []))):
            raise InvestigationError('Native SAML client dependency read-back mismatch')
        for level, rank in enumerate(('low', 'medium', 'high'), 1):
            row = next(r for r in state['executions'] if r.get('displayName') == self.name + '-' + rank)
            wanted = 'DISABLED' if mode == 'maximum' and rank == 'high' else 'CONDITIONAL'
            if row['requirement'] != wanted:
                raise InvestigationError('Native LoA availability configuration mismatch')
            configs = [v for v in state['configs'].values() if v['alias'] == self.name + '-' + rank + '-config']
            if len(configs) != 1 or configs[0]['config'] != {'loa-condition-level': str(level), 'loa-max-age': '0'}:
                raise InvestigationError('Native LoA condition read-back mismatch')
        self.readback_confirmations += 1
        save(self.out / ('readback-' + mode + '.json'), dict(origin='product-management-api',
             executionObserved=False, mode=mode, state=state, sha256=digest(state)))
        self.report['modes'].append(mode)

    def apply(self, mode):
        if mode not in ('normal', 'maximum'):
            raise ValueError('Unknown mode')
        self.guard()
        row = next(r for r in self.executions() if r.get('displayName') == self.name + '-high')
        self.require(self.name, row['id'], 'DISABLED' if mode == 'maximum' else 'CONDITIONAL')
        self.verify_mode(mode)

    def restore(self):
        if self.pending:
            self.reconcile()
            self.pending = None
            self.journal()
        self.guard()
        if self.expected['client']:
            self.mutate(REALM + '/clients/' + self.expected['client']['id'], 'DELETE', restoring=True)
        if self.expected['flow']:
            self.mutate(REALM + '/authentication/flows/' + self.expected['flow']['id'], 'DELETE', restoring=True)
        # Keycloak can retain orphaned authenticator configs after flow deletion.
        for cfg in list(self.expected['configs']):
            self.mutate(REALM + '/authentication/config/' + cfg, 'DELETE', restoring=True)
        absent_subflows = {identifier: self.api.get(REALM + '/authentication/flows/' + identifier, missing=True) is None
                          for identifier in sorted(self.subflow_ids)}
        if not all(absent_subflows.values()):
            raise InvestigationError('Native subflow removal incomplete')
        empty = dict(client=None, flow=None, executions=[], configs={})
        restored = self.snapshot_shared()
        if self.observe() != empty or restored != self.original:
            raise InvestigationError('Restoration does not match original public configuration')
        self.report['managementRestorationConfirmations'] = 1
        self.report['restored'] = True
        save(self.out / 'restoration.json', dict(scope='public bindings, shared flow definitions/executions, client inventory and owned object absence',
             original=self.original, restored=restored, exactEquality=True,
             originalSha256=digest(self.original), restoredSha256=digest(restored), owned=empty,
             subflowsConfirmedAbsent=absent_subflows))
        self.journal()

    def recover(self):
        """Resume cleanup only; no interrupted configuration write is resent."""
        data = json.loads((self.out / 'journal.json').read_text())
        if data['name'] != self.name or data['clientId'] != self.client_id or not data['original']:
            raise InvestigationError('Recovery journal identity mismatch')
        public(data)  # Reject unexpected credential-bearing journal input.
        self.original, self.expected, self.pending = (data[k] for k in ('original', 'expected', 'pending'))
        self.config_ids = set(data['configIds'])
        self.subflow_ids = set(data.get('subflowIds', [])) | {r['flowId'] for r in (self.expected or {}).get('executions', []) if r.get('flowId')}
        prior_path = self.out / 'report.json'
        prior = json.loads(prior_path.read_text()) if prior_path.exists() else {}
        # Earlier interrupted journals can precede the last acknowledged count.
        # Reconcile only from our retained HTTP status records, never infer an ACK.
        totals = dict(setting_write_attempts=0, native_write_successes=0,
                      restoration_write_attempts=0, restoration_native_write_successes=0)
        def recorded(report):
            for event in report.get('apiOperations', []):
                if event['path'].startswith(REALM + '/') and event['method'] in ('POST', 'PUT', 'DELETE'):
                    totals['setting_write_attempts'] += 1
                    acknowledged = event.get('status') is not None and 200 <= event['status'] < 300
                    totals['native_write_successes'] += int(acknowledged)
                    if event['method'] == 'DELETE':
                        totals['restoration_write_attempts'] += 1
                        totals['restoration_native_write_successes'] += int(acknowledged)
            if report.get('priorInvestigation'):
                recorded(report['priorInvestigation'])
        recorded(prior)
        values = data['counts']
        for key, value in totals.items():
            values[key] = max(values[key], value)
        self.counts = Counters(**values)
        self.report['recoveredFromInterruptedInvestigation'] = True
        try:
            self.restore()
            self.report['status'] = 'configuration-restored-after-interruption'
        except Exception as error:
            self.report['errors'].append(dict(stage='restoration', type=type(error).__name__))
        finally:
            self.report.update(counts=asdict(self.counts), managementReadbackConfirmations=0,
                               nativeAuthenticationExecutionsObserved=0,
                               priorInvestigation=prior, apiOperations=self.api.events)
            save(prior_path, self.report)
            self.api.token = None
        return self.report

    def run(self):
        try:
            self.discover()
            self.capture()
            self.configure()
            self.apply('maximum')
            self.report['status'] = 'configuration-roundtrip-complete'
        except Exception as error:
            self.report['errors'].append(dict(stage='investigation', type=type(error).__name__))
        finally:
            if self.original is not None:
                try:
                    self.restore()
                except Exception as error:
                    self.report['errors'].append(dict(stage='restoration', type=type(error).__name__))
            if not self.report['restored'] or self.report['errors']:
                self.report['status'] = 'incomplete'
            self.report.update(counts=asdict(self.counts), managementReadbackConfirmations=self.readback_confirmations,
                               nativeAuthenticationExecutionsObserved=0,
                               apiOperations=self.api.events)
            save(self.out / 'report.json', self.report)
            self.api.token = None
        return self.report


def interrupted(signum, frame):
    raise InvestigationError('Investigation interrupted; restoring owned resources')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument('--dry-run', action='store_true')
    modes.add_argument('--live', action='store_true', help='Management configuration roundtrip only; no SAML or browser')
    parser.add_argument('--base-url', default=BASE)
    parser.add_argument('--name', default='kc-20261031')
    parser.add_argument('--recover', action='store_true', help='With --live: verify journal and remove owned objects only')
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args(argv)
    local_base(args.base_url)
    out = output_dir(args.out)
    if args.recover and (not args.live or not (out / 'journal.json').is_file()):
        raise ValueError('Recovery requires --live and an existing investigation journal')
    if not args.recover and out.exists() and any(out.iterdir()):
        raise ValueError('Use an empty investigation output directory')
    out.mkdir(parents=True, exist_ok=True)
    if args.dry_run:
        value = plan('keycloak')
        value['configurationInvestigationAvailable'] = True
        value['configurationOrigin'] = 'product-management-api; execution unverified'
        save(out / 'plan.json', value)
        print(json.dumps(dict(status='dry-run', networkRequests=0, allCasesHeld=True)))
        return 0
    # Install handlers before authentication or mutations. On a first termination
    # signal, restore without further signal interruption; SIGKILL needs journal review.
    old = {}
    def stop(signum, frame):
        for sig in old:
            signal.signal(sig, signal.SIG_IGN)
        interrupted(signum, frame)
    for sig in (signal.SIGTERM, signal.SIGINT):
        old[sig] = signal.signal(sig, stop)
    try:
        api = LocalAdmin(args.base_url)
        api.login()
        driver = KeycloakLive(api, out, args.name)
        result = driver.recover() if args.recover else driver.run()
    finally:
        for sig, handler in old.items():
            signal.signal(sig, handler)
    print(json.dumps({k: result[k] for k in ('status', 'restored', 'allCasesHeld', 'counts')}))
    return 0 if result['status'] in ('configuration-roundtrip-complete', 'configuration-restored-after-interruption') else 1


if __name__ == '__main__':
    raise SystemExit(main())
