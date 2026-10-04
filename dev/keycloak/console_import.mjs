#!/usr/bin/env node
/**
 * Drives the product's own Keycloak console metadata import and records one test record:
 * fixture identification, product import result, admin API read-back, optional follow-up flow,
 * and deletion/restore with read-back verification. Exit code is 0 only when every required
 * step is verified; a failure never prints or saves a success state.
 */
import { chromium } from 'playwright';
import crypto from 'crypto';
import fs from 'fs';

const CONSOLE = 'http://localhost:18180/admin/master/console/#/samlscope/clients';
const ADMIN = 'http://localhost:18180/admin/realms/samlscope';
const TOKEN_URL = 'http://localhost:18180/realms/master/protocol/openid-connect/token';

function arg(name, fallback) {
  const index = process.argv.indexOf(name);
  return index >= 0 ? process.argv[index + 1] : fallback;
}

const fixturePath = arg('--fixture');
const recordPath = arg('--record', 'import-record.json');
const verifyCommand = arg('--verify-command');
const expectedEntityId = arg('--entity-id');
const deleteAfter = process.argv.includes('--delete');
const verifyRequestSignatures = process.argv.includes('--verify-request-signatures');
const signingCapability = arg('--signing-capability');
const defaultSignatureSelector = process.argv.includes('--native-default-signature-selector');
const representationAdmissionOnly = process.argv.includes('--representation-admission-only');
const captureNativeAdmission = process.argv.includes('--capture-native-admission-originals');
const converterResponses = [];
if (representationAdmissionOnly && (signingCapability || verifyRequestSignatures || defaultSignatureSelector)) {
  console.error('Representation admission cannot be combined with signature-use/capability policies');
  process.exit(2);
}
if (defaultSignatureSelector && (signingCapability || verifyRequestSignatures)) {
  console.error('Native default selector cannot be combined with another policy mutation');
  process.exit(2);
}
if (signingCapability && (!['RSA_SHA256', 'RSA_SHA384', 'RSA_SHA512'].includes(signingCapability) || verifyRequestSignatures)) {
  console.error('Signing capability requires an explicit supported RSA SHA2 algorithm and unchanged imported encryption policy');
  process.exit(2);
}
if (!fixturePath) {
  console.error('usage: node console_import.mjs --fixture <xml> [--record <json>] [--verify-command <cmd>] [--delete]');
  process.exit(2);
}

const record = { status: 'running', steps: [], fixture: {}, client: {}, import: {}, flow: {}, cleanup: {} };
const fail = (step, detail) => {
  record.steps.push({ step, ok: false, detail });
  record.status = 'failure';
  record.failure_reason = `${step}: ${detail}`;
};
const pass = (step, detail) => record.steps.push({ step, ok: true, detail: detail ?? '' });

async function adminToken() {
  const body = new URLSearchParams({ client_id: 'admin-cli', username: 'admin', password: 'admin', grant_type: 'password' });
  const response = await fetch(TOKEN_URL, { method: 'POST', body });
  if (!response.ok) throw new Error(`token endpoint ${response.status}`);
  return (await response.json()).access_token;
}

async function readBack(token, clientId) {
  const response = await fetch(`${ADMIN}/clients?clientId=${encodeURIComponent(clientId)}`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!response.ok) throw new Error(`client lookup ${response.status}`);
  const clients = await response.json();
  if (!clients.length) return null;
  const detail = await fetch(`${ADMIN}/clients/${clients[0].id}`, { headers: { Authorization: `Bearer ${token}` } });
  if (!detail.ok) throw new Error(`client detail ${detail.status}`);
  return await detail.json();
}

let browser, page;
try {
  const bytes = fs.readFileSync(fixturePath);
  record.fixture = { path: fixturePath, sha256: crypto.createHash('sha256').update(bytes).digest('hex'), bytes: bytes.length };
  // The fixture's entityID is the clientId the product must derive by itself.
  const entityMatch = /entityID="([^"]+)"/.exec(bytes.toString('utf8'));
  if (!entityMatch) throw new Error('fixture has no entityID');
  const entityId = expectedEntityId ?? entityMatch[1];
  if (expectedEntityId && !Array.from(bytes.toString('utf8').matchAll(/entityID="([^"]+)"/g))
      .some(match => match[1] === expectedEntityId)) throw new Error('Expected entity is absent from the original fixture');
  record.fixture.entity_id = entityId;

  if (await readBack(await adminToken(), entityId)) throw new Error('Refusing to overwrite an existing client');
  browser = await chromium.launch({ channel: 'chrome', headless: true });
  page = await browser.newPage();
  if (captureNativeAdmission) page.on('response', response => {
    if (new URL(response.url()).pathname !== '/admin/realms/samlscope/client-description-converter') return;
    converterResponses.push((async () => {
      const raw = await response.body(); const native = JSON.parse(raw.toString('utf8'));
      if (native.secret || Object.keys(native.attributes ?? {}).some(key => /private|password/i.test(key) && native.attributes[key])) {
        throw new Error('Native converter contains credential/private-key data; no persistence');
      }
      const sent = response.request().postDataBuffer();
      return { url: response.url(), method: response.request().method(), status: response.status(),
        request_sha256: crypto.createHash('sha256').update(sent ?? Buffer.alloc(0)).digest('hex'),
        request_matches_original_fixture: Buffer.isBuffer(sent) && sent.equals(bytes),
        response_base64: raw.toString('base64'), response_sha256: crypto.createHash('sha256').update(raw).digest('hex') };
    })());
  });
  await page.goto(CONSOLE, { waitUntil: 'networkidle', timeout: 60000 });
  if (await page.locator('#username').count()) {
    await page.fill('#username', 'admin');
    await page.fill('#password', 'admin');
    await page.click('#kc-login');
    await page.waitForLoadState('networkidle');
  }
  await page.getByText('Import client', { exact: true }).click({ timeout: 30000 });
  await page.locator('input[type=file]').setInputFiles(fixturePath);
  pass('file-selected');
  // File selection completes before the console's asynchronous metadata parser.
  await page.waitForFunction(expected => Array.from(document.querySelectorAll('input'))
    .some(input => input.value === expected), entityId, { timeout: 30000 });
  pass('product-parsed-entity-id');
  await page.getByRole('button', { name: /^save$/i }).first().click({ timeout: 30000 });
  record.import.save_clicked = true;

  // Success signal: the console navigates to the created client settings page, or shows an error alert.
  let uiStatus = 'timeout';
  try {
    await page.waitForURL(/\/clients\/[0-9a-f-]+\/settings/, { timeout: 30000 });
    uiStatus = 'client-settings-page';
  } catch {
    const alert = await page.locator('[role=alert], .pf-v5-c-alert, .kc-feedback-text').first().innerText().catch(() => '');
    uiStatus = alert ? `error-display: ${alert.slice(0, 200)}` : 'no-success-signal';
  }
  record.import.ui_status = uiStatus;
  const idMatch = /\/clients\/([0-9a-f-]+)\/settings/.exec(page.url());
  record.client.database_id = idMatch ? idMatch[1] : null;
  record.import.final_url = page.url();
  if (!idMatch) {
    await page.screenshot({ path: recordPath.replace(/\.json$/, '.png'), fullPage: true });
    record.import.page_text = (await page.locator('body').innerText()).slice(0, 2500);
  }
  if (!idMatch) throw new Error(`import did not reach the client settings page (${uiStatus})`);
  pass('product-import-signal', uiStatus);

  // Read back through the admin API; the record only claims what the product's state contains.
  const token = await adminToken();
  let created = await readBack(token, entityId);
  if (!created || created.id !== record.client.database_id) {
    throw new Error('admin read-back did not find the imported client');
  }
  if (captureNativeAdmission) {
    const converters = await Promise.all(converterResponses);
    if (converters.length !== 1 || converters[0].status !== 200 || !converters[0].request_matches_original_fixture) {
      throw new Error('Native converter response/fixture binding is incomplete');
    }
    record.import.native_converter_original = converters[0];
    const nativeResponse = await fetch(`${ADMIN}/clients/${created.id}`, { headers: { Authorization: `Bearer ${token}` } });
    const raw = Buffer.from(await nativeResponse.arrayBuffer()); const saved = JSON.parse(raw.toString('utf8'));
    if (nativeResponse.status !== 200 || saved.id !== created.id || saved.clientId !== entityId
        || Object.keys(saved.attributes ?? {}).some(key => /private|password/i.test(key) && saved.attributes[key])) {
      throw new Error('Native saved readback or public key configuration unavailable');
    }
    // Credentials are removed before writing a file or submitting anything to Recorder.
    const redacted = { ...saved }; const redactions = [];
    for (const key of ['secret', 'registrationAccessToken']) if (Object.hasOwn(redacted, key)) { delete redacted[key]; redactions.push(key); }
    const publicOriginal = Buffer.from(JSON.stringify(redacted));
    record.import.native_saved_original = { url: `${ADMIN}/clients/${created.id}`, method: 'GET', status: nativeResponse.status,
      redactions, response_base64: publicOriginal.toString('base64'), response_sha256: crypto.createHash('sha256').update(publicOriginal).digest('hex') };
    fs.writeFileSync(recordPath.replace(/\.json$/, '.admission-originals.json'), JSON.stringify({ converter: record.import.native_converter_original, saved: record.import.native_saved_original }, null, 2));
    pass('native-converter-and-persisted-originals-before-policy');
  }
  if (verifyRequestSignatures) {
    const before = created.attributes ?? {};
    record.import.request_signature_policy = {
      original_value: before['saml.client.signature'] ?? null,
      original_signing_certificate: before['saml.signing.certificate'] ?? null,
      original_encryption_policy: before['saml.encrypt'] ?? null,
      key_material_modified: false, write_attempts: 0,
      purpose: 'Native verification and unencrypted response policy only; metadata keys are not supplied by the Suite',
    };
    if (before['saml.client.signature'] !== 'true' || before['saml.encrypt'] !== 'false') {
      const wanted = { ...created, attributes: { ...before, 'saml.client.signature': 'true', 'saml.encrypt': 'false' } };
      record.import.request_signature_policy.write_attempts++;
      const applied = await fetch(`${ADMIN}/clients/${created.id}`, {
        method: 'PUT', headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
        body: JSON.stringify(wanted),
      });
      record.import.request_signature_policy.write_status = applied.status;
      if (applied.status !== 204) throw new Error('Native signature policy could not be enabled');
      created = await readBack(token, entityId);
      if (!created || created.attributes?.['saml.client.signature'] !== 'true'
          || created.attributes?.['saml.encrypt'] !== 'false'
          || (created.attributes?.['saml.signing.certificate'] ?? null) !== (before['saml.signing.certificate'] ?? null)) {
        throw new Error('Native signature-policy read-back or imported key preservation failed');
      }
    }
    record.import.request_signature_policy.enabled_read_back = true;
    pass('native-signature-policy-with-original-imported-keys');
  }
  if (signingCapability) {
    const samlOnly = attrs => Object.fromEntries(Object.entries(attrs ?? {}).filter(([key]) => key.startsWith('saml')));
    const before = samlOnly(created.attributes);
    record.import.signing_capability_policy = {
      requested_algorithm: signingCapability, original_saml_attributes: before,
      write_attempts: 0, key_material_modified: false,
      purpose: 'Separate native signing capability control; not evidence of metadata algorithm preference or local policy',
    };
    if (before['saml.encrypt'] !== 'true' || before['saml.client.signature'] !== 'true') {
      throw new Error('Capability control requires unchanged imported encryption and request verification');
    }
    if (before['saml.signature.algorithm'] !== signingCapability) {
      record.import.signing_capability_policy.write_attempts++;
      const applied = await fetch(`${ADMIN}/clients/${created.id}`, {
        method: 'PUT', headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ ...created, attributes: { ...created.attributes, 'saml.signature.algorithm': signingCapability } }),
      });
      record.import.signing_capability_policy.write_status = applied.status;
      if (applied.status !== 204) throw new Error('Native signing capability setting failed');
      created = await readBack(token, entityId);
    }
    const after = samlOnly(created?.attributes);
    const wanted = { ...before, 'saml.signature.algorithm': signingCapability };
    if (Object.keys(after).length !== Object.keys(wanted).length || Object.entries(wanted).some(([key, value]) => after[key] !== value)) {
      throw new Error('Native signing capability read-back changed imported keys or another policy');
    }
    record.import.signing_capability_policy.read_back_verified = true;
    pass('native-signing-capability-only');
  }
  if (defaultSignatureSelector) {
    const before = { ...created.attributes };
    const wanted = { ...before };
    delete wanted['saml.signature.algorithm'];
    record.import.native_default_signature_selector = {
      original_saml_attributes: Object.fromEntries(Object.entries(before).filter(([key]) => key.startsWith('saml'))),
      write_attempts: 0, key_material_modified: false,
      purpose: 'Remove explicit native signature selection; this is not an algorithm prohibition or conformance result',
    };
    if (Object.hasOwn(before, 'saml.signature.algorithm')) {
      record.import.native_default_signature_selector.write_attempts++;
      const applied = await fetch(`${ADMIN}/clients/${created.id}`, {
        method: 'PUT', headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ ...created, attributes: wanted }),
      });
      record.import.native_default_signature_selector.write_status = applied.status;
      if (applied.status !== 204) throw new Error('Native explicit signature selection removal failed');
      created = await readBack(token, entityId);
    }
    const after = created?.attributes ?? {};
    if (Object.keys(after).length !== Object.keys(wanted).length || Object.entries(wanted).some(([key, value]) => after[key] !== value)) {
      throw new Error('Native default selector read-back changed another imported setting');
    }
    record.import.native_default_signature_selector.read_back_verified = true;
    pass('native-default-signature-selector-with-original-keys');
  }
  if (representationAdmissionOnly) {
    const before = { ...created.attributes };
    if (Object.keys(before).some(key => key.startsWith('saml') && /private|secret|credential|password/i.test(key))) {
      throw new Error('Refusing to persist native secret/private-key attributes');
    }
    record.import.representation_admission_only = {
      original_saml_attributes: Object.fromEntries(Object.entries(before).filter(([key]) => key.startsWith('saml'))),
      write_attempts: 0, key_material_modified: false,
      purpose: 'MD05.c structural acceptance only; signature use is deliberately outside this evidence scope',
    };
    const wanted = { ...before, 'saml.client.signature': 'false' };
    if (before['saml.client.signature'] !== 'false') {
      record.import.representation_admission_only.write_attempts++;
      const applied = await fetch(`${ADMIN}/clients/${created.id}`, {
        method: 'PUT', headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ ...created, attributes: wanted }),
      });
      record.import.representation_admission_only.write_status = applied.status;
      if (applied.status !== 204) throw new Error('Native admission-only policy failed');
      created = await readBack(token, entityId);
    }
    const after = created?.attributes ?? {};
    if (Object.keys(after).length !== Object.keys(wanted).length || Object.entries(wanted).some(([key, value]) => after[key] !== value)) {
      throw new Error('Native admission-only policy changed imported keys or another attribute');
    }
    record.import.representation_admission_only.read_back_verified = true;
    pass('native-structural-admission-policy-with-original-imported-keys');
  }
  const finalAttributes = created.attributes ?? {};
  record.import.read_back = {
    client_id: created.clientId,
    saml_attributes: Object.fromEntries(Object.entries(finalAttributes).filter(([key]) => key.startsWith('saml'))),
    has_signing_certificate: Boolean(finalAttributes['saml.signing.certificate']),
    has_encryption_certificate: Boolean(finalAttributes['saml.encryption.certificate']),
  };
  pass('admin-read-back', created.clientId);

  if (verifyCommand) {
    const { execSync } = await import('node:child_process');
    try {
      record.flow = { command: verifyCommand, output: execSync(verifyCommand, { encoding: 'utf8', timeout: 300000 }).slice(-2000), ok: true };
      pass('follow-up-flow');
    } catch (error) {
      record.flow = { command: verifyCommand, output: String(error).slice(0, 1000), ok: false };
      fail('follow-up-flow', 'command failed');
    }
  }

  if (deleteAfter) {
    const deleted = await fetch(`${ADMIN}/clients/${created.id}`, { method: 'DELETE', headers: { Authorization: `Bearer ${token}` } });
    const remaining = await readBack(token, entityId);
    record.cleanup = { deleted_status: deleted.status, read_back_absent: remaining === null };
    if (deleted.status !== 204 || remaining !== null) throw new Error('cleanup verification failed');
    pass('cleanup-delete-verified');
  }
  if (record.status === 'running') record.status = 'success';
} catch (error) {
  fail('import-run', String(error).slice(0, 600));
  if (deleteAfter && record.client.database_id && record.fixture.entity_id && !record.cleanup.read_back_absent) {
    try {
      const token = await adminToken();
      const own = await readBack(token, record.fixture.entity_id);
      if (own?.id === record.client.database_id) {
        const deleted = await fetch(`${ADMIN}/clients/${own.id}`, { method: 'DELETE', headers: { Authorization: `Bearer ${token}` } });
        record.cleanup = { deleted_status: deleted.status, read_back_absent: (await readBack(token, record.fixture.entity_id)) === null, after_failure: true };
      }
    } catch { record.cleanup.failure_cleanup_verified = false; }
  }
  if (deleteAfter && record.fixture.entity_id && !record.import.save_clicked) {
    try { record.cleanup = { no_save_attempted: true, read_back_absent: (await readBack(await adminToken(), record.fixture.entity_id)) === null }; } catch {}
  }
  try { await page?.screenshot({ path: recordPath.replace(/\.json$/, '.png'), fullPage: true }); } catch {}
} finally {
  await browser?.close();
}
fs.writeFileSync(recordPath, JSON.stringify(record, null, 2));
if (record.status === 'success') {
  console.log(`IMPORT VERIFIED client=${record.client.database_id}`);
  process.exit(0);
}
console.error(`IMPORT FAILED: ${record.failure_reason}`);
process.exit(1);
