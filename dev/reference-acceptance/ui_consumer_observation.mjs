/**
 * Read-only Playwright observation for a product-specific, already identified UI element.
 * No browser creation, navigation, login, import, verdict, screenshots, or DOM dump here.
 * Native adapters must separately prove import/Run/fixture association before adoption.
 */
import crypto from 'node:crypto';
import fs from 'node:fs';

const sha256 = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
const normalize = value => value.trim().replace(/\s+/gu, ' ');

/** Only these public candidate values may leave the browser. Unknown content is discarded. */
export async function observeUiConsumer(page, {
  runId, condition, fixturePath, importReceiptPath, expectedOrigin, expectedPath,
  preferredLanguage, elementSelector, kind, candidates,
}) {
  if (!/^run_[0-9A-HJKMNP-TV-Z]{26}$/.test(runId)
      || !/^[a-z][a-z0-9-]{0,79}$/.test(condition)
      || !['display-name', 'logo', 'link'].includes(kind)
      || !preferredLanguage || !elementSelector
      || !expectedPath?.startsWith('/') || expectedPath.includes('?') || expectedPath.includes('#')) {
    throw new Error('Invalid UI observation identity');
  }
  const origin = new URL(expectedOrigin);
  if (!['http:', 'https:'].includes(origin.protocol) || origin.origin !== expectedOrigin) {
    throw new Error('Expected origin must be an HTTP(S) origin');
  }
  const entries = Object.entries(candidates ?? {});
  if (!entries.length || entries.length > 8 || entries.some(([token, value]) =>
    !/^[a-z][a-z0-9-]{0,39}$/.test(token) || typeof value !== 'string' || !value.length)) {
    throw new Error('Invalid public candidate mapping');
  }
  const values = entries.map(([, value]) => kind === 'display-name' ? normalize(value) : value);
  if (new Set(values).size !== values.length) throw new Error('Ambiguous candidate values');
  const fixture = fs.readFileSync(fixturePath);
  const receipt = fs.readFileSync(importReceiptPath);
  const record = {
    schema: 'samlscope-ui-consumer-observation-v1', run_id: runId, condition, kind,
    fixture_sha256: sha256(fixture), import_receipt_sha256: sha256(receipt),
    // A hash reference is not a claim that the native import receipt has been validated.
    import_binding_verified: false, verdict_adopted: false,
    expected_origin: expectedOrigin, expected_path: expectedPath,
    preferred_language: preferredLanguage, selector: elementSelector,
    observed_at: new Date().toISOString(), status: 'not-observed',
  };
  try {
    const actual = new URL(page.url());
    if (actual.origin !== expectedOrigin || actual.pathname !== expectedPath) {
      return { ...record, reason: 'unexpected-product-page' };
    }
    const languageMatches = await page.evaluate(expected =>
      navigator.language.toLowerCase() === expected.toLowerCase()
        && navigator.languages[0]?.toLowerCase() === expected.toLowerCase(), preferredLanguage);
    if (!languageMatches) return { ...record, reason: 'browser-language-mismatch' };
    const locator = page.locator(elementSelector);
    if (await locator.count() !== 1) return { ...record, reason: 'element-missing-or-ambiguous' };
    if (!await locator.isVisible()) return { ...record, reason: 'element-not-visible' };
    // Do not read arbitrary form values, page text, cookies, storage, headers, or request bodies.
    const sample = await locator.evaluate((element, args) => {
      const { kind, entries } = args;
      if (element.matches('input, textarea, select, [contenteditable]')
          || element.querySelector('input, textarea, select, [contenteditable]')) {
        return { reason: 'form-element-rejected' };
      }
      for (let ancestor = element; ancestor; ancestor = ancestor.parentElement) {
        const style = getComputedStyle(ancestor);
        if (ancestor.hidden || ancestor.getAttribute('aria-hidden') === 'true'
            || style.display === 'none' || style.visibility !== 'visible' || Number(style.opacity) === 0) {
          return { reason: 'element-hidden' };
        }
      }
      const rect = element.getBoundingClientRect();
      if (rect.width <= 0 || rect.height <= 0 || rect.bottom <= 0 || rect.right <= 0
          || rect.top >= innerHeight || rect.left >= innerWidth) return { reason: 'element-outside-viewport' };
      const x = Math.max(0, Math.min(innerWidth - 1, rect.left + rect.width / 2));
      const y = Math.max(0, Math.min(innerHeight - 1, rect.top + rect.height / 2));
      const top = document.elementFromPoint(x, y);
      if (!top || !(top === element || element.contains(top))) return { reason: 'element-occluded' };
      let value;
      if (kind === 'logo') {
        if (!(element instanceof HTMLImageElement)) return { reason: 'not-an-image' };
        if (!element.complete || element.naturalWidth <= 0 || element.naturalHeight <= 0) {
          return { reason: 'image-not-loaded' };
        }
        value = element.currentSrc;
      } else if (kind === 'link') {
        if (!(element instanceof HTMLAnchorElement)) return { reason: 'not-a-link' };
        // Observe the rendered destination without following it or executing a scheme handler.
        value = element.href;
      } else {
        if (!(element instanceof HTMLElement)) return { reason: 'not-a-text-element' };
        value = element.innerText.trim().replace(/\s+/gu, ' ');
      }
      const matches = entries.filter(([, candidate]) => candidate === value);
      return matches.length === 1 ? { selected_candidate: matches[0][0] } : { reason: 'unknown-candidate' };
    }, { kind, entries: entries.map(([token], index) => [token, values[index]]) });
    // A navigation during sampling makes the page association uncertain.
    const after = new URL(page.url());
    if (after.origin !== expectedOrigin || after.pathname !== expectedPath) {
      return { ...record, reason: 'page-changed-during-observation' };
    }
    return sample.reason ? { ...record, reason: sample.reason }
      : { ...record, status: 'observed', selected_candidate: sample.selected_candidate };
  } catch {
    // Playwright errors can embed DOM excerpts and URLs containing protocol parameters.
    return { ...record, reason: 'browser-observation-unavailable' };
  }
}

export function saveUiConsumerObservation(path, record) {
  // Never replace previously captured evidence with a newer observation.
  fs.writeFileSync(path, JSON.stringify(record, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
}

/**
 * Retain a bounded URL-assignment diagnostic independently of successful rendering.
 * An unloaded or hidden image can still contain the supplied URL. Conversely, the
 * absence of a matching node is not proof of product-wide nonuse or rejection.
 * This does not navigate, click, execute a URL, or return arbitrary DOM attributes.
 */
export async function observeUiUrlConsumer(page, options) {
  if (!['logo', 'link'].includes(options.kind)) throw new Error('URL observation requires image or link');
  const record = await observeUiConsumer(page, options);
  const assignment = { status: 'unavailable', nonuse_proven: false };
  const expectedPage = () => {
    const actual = new URL(page.url());
    return actual.origin === options.expectedOrigin && actual.pathname === options.expectedPath;
  };
  try {
    if (!expectedPage()) return { ...record, url_assignment: { ...assignment, reason: 'unexpected-product-page' } };
    const locator = page.locator(options.elementSelector);
    const count = await locator.count();
    let sample;
    if (count === 0) sample = { status: 'absent-at-sample', matched_nodes: 0 };
    else if (count !== 1) sample = { status: 'ambiguous', matched_nodes: count };
    else sample = await locator.evaluate((element, args) => {
      const isImage = args.kind === 'logo';
      if (!(isImage ? element instanceof HTMLImageElement : element instanceof HTMLAnchorElement)) {
        return { status: 'unavailable', reason: 'unexpected-element-type' };
      }
      // Attribute assignment is deliberately separate from load/visibility/currentSrc.
      const value = element.getAttribute(isImage ? 'src' : 'href');
      const matches = args.entries.filter(([, candidate]) => candidate === value);
      return matches.length === 1
        ? { status: 'candidate-assigned', selected_candidate: matches[0][0], matched_nodes: 1 }
        : { status: 'unrecognized-assignment', matched_nodes: 1 };
    }, { kind: options.kind, entries: Object.entries(options.candidates) });
    if (!expectedPage()) return { ...record, url_assignment: { ...assignment, reason: 'page-changed-during-observation' } };
    return { ...record, url_assignment: { ...assignment, ...sample, sampled_at: new Date().toISOString() } };
  } catch {
    return { ...record, url_assignment: { ...assignment, reason: 'browser-observation-unavailable' } };
  }
}
