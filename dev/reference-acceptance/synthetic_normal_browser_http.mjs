/** Node fetch Response boundary for the owned synthetic smoke; no raw non-public retention. */
import { publicJson } from './generic_browser_campaign.mjs';
const fail = () => { throw new Error('Malformed or non-public API body omitted'); };

export function fetchStatus(response) {
  if (!(response instanceof Response) || !Number.isInteger(response.status) || response.status < 100 || response.status > 599
      || typeof response.ok !== 'boolean' || response.ok !== (response.status >= 200 && response.status < 300)) fail();
  return { status: response.status, ok: response.ok, contentType: response.headers.get('content-type') ?? '' };
}

// Validate grammar and duplicate keys before JSON.parse; raw bytes could contain
// an earlier bearer value hidden by a later duplicate null field.
export function publicDocument(raw) {
  let text; try { text = new TextDecoder('utf-8', { fatal: true }).decode(raw); } catch { fail(); } let offset = 0;
  const space = () => { while (/\s/.test(text[offset] ?? '') && offset < text.length) offset++; };
  const string = () => {
    if (text[offset] !== '"') fail(); const start = offset++;
    while (offset < text.length) {
      const character = text[offset++];
      if (character === '\\') { offset++; continue; }
      if (character === '"') { try { return JSON.parse(text.slice(start, offset)); } catch { fail(); } }
    }
    fail();
  };
  const value = () => {
    space(); const first = text[offset];
    if (first === '{') {
      offset++; space(); const keys = new Set(); if (text[offset] === '}') { offset++; return; }
      while (true) {
        space(); const key = string(); if (keys.has(key)) fail(); keys.add(key); space(); if (text[offset++] !== ':') fail(); value(); space();
        const next = text[offset++]; if (next === '}') return; if (next !== ',') fail();
      }
    }
    if (first === '[') {
      offset++; space(); if (text[offset] === ']') { offset++; return; }
      while (true) { value(); space(); const next = text[offset++]; if (next === ']') return; if (next !== ',') fail(); }
    }
    if (first === '"') { string(); return; }
    const primitive = /^(?:null|true|false|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)/.exec(text.slice(offset));
    if (!primitive || (/[0-9]/.test(primitive[0][0]) || primitive[0][0] === '-') && !Number.isFinite(Number(primitive[0]))) fail();
    offset += primitive[0].length;
  };
  value(); space(); if (offset !== text.length) fail();
  let parsed; try { parsed = JSON.parse(text); } catch { fail(); }
  if (parsed === null || typeof parsed !== 'object') fail();
  return publicJson(parsed);
}

export async function readPublicResponse(response, retainStatus, retainRaw) {
  const facts = fetchStatus(response); await retainStatus({ status: facts.status, bodyOmittedUntilPublicValidation: true });
  if (!/^application\/json(?:;|$)/i.test(facts.contentType)) throw new Error(`Owned Suite API status ${facts.status}; body omitted`);
  const reader = response.body?.getReader(), chunks = []; let length = 0;
  if (reader) while (true) {
    const next = await reader.read(); if (next.done) break;
    length += next.value.length; if (length > 6 * 1024 * 1024) { await reader.cancel(); fail(); }
    chunks.push(next.value);
  }
  const raw = Buffer.concat(chunks), value = publicDocument(raw);
  await retainRaw(raw); // All recursive credential checks precede physical writes.
  if (!facts.ok) throw new Error(`Owned Suite API status ${facts.status}`);
  return value;
}
