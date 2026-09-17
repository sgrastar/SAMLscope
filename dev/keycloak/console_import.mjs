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
  const created = await readBack(token, entityId);
  if (!created || created.id !== record.client.database_id) {
    throw new Error('admin read-back did not find the imported client');
  }
  const attributes = created.attributes ?? {};
  record.import.read_back = {
    client_id: created.clientId,
    saml_attributes: Object.fromEntries(Object.entries(attributes).filter(([key]) => key.startsWith('saml'))),
    has_signing_certificate: Boolean(attributes['saml.signing.certificate']),
    has_encryption_certificate: Boolean(attributes['saml.encryption.certificate']),
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
