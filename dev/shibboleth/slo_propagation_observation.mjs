/** Transport/UI completeness only. This never decides a SAML case outcome. */
export function propagationObservation(record, suiteOrigin = 'http://localhost:18080') {
  const incomplete = reason => ({ settled: false, reason, affectsVerdict: false });
  if (!['failure', 'all-success'].includes(record.trial)) return incomplete('unknown-trial');
  const context = record.nativePropagationContext;
  const peers = context?.participants;
  if (!Array.isArray(peers) || peers.length !== 3 ||
      new Set(peers.map(p => p.entityId)).size !== 3 ||
      new Set(peers.map(p => p.sessionKeySha256)).size !== 3 ||
      peers.some(p => !/^[0-9a-f]{64}$/.test(p.sessionKeySha256 ?? '')))
    return incomplete('participant-context-incomplete');
  if (!record.nativeFlowScopes?.includes(context.flowScopeSha256))
    return incomplete('native-flow-context-unbound');
  const dom = record.nativeDom?.participants;
  if (!Array.isArray(dom) || dom.length !== peers.length ||
      new Set(dom.map(p => p.entityId)).size !== peers.length)
    return incomplete('participant-dom-incomplete');
  const resources = record.nativeResources ?? [];
  const expectedKeys = new Set(peers.map(p => p.sessionKeySha256));
  if (resources.some(r => r.sessionKeySha256 && !expectedKeys.has(r.sessionKeySha256)))
    return incomplete('foreign-participant-resource');
  const ids = new Set();
  let observedFailures = 0;
  for (const peer of peers) {
    const views = dom.filter(p => p.entityId === peer.entityId);
    if (views.length !== 1) return incomplete('participant-dom-unbound');
    const classes = views[0].classes ?? [];
    const success = classes.includes('success'), failure = classes.includes('failure');
    if (success === failure || classes.includes('pending')) return incomplete('native-participant-pending');
    const key = peer.sessionKeySha256;
    const generated = resources.filter(r => r.origin === 'http://localhost:18280' &&
        r.path === '/idp/profile/PropagateLogout' && r.status === 200 &&
        r.sessionKeySha256 === key && r.generatedRequest);
    const sent = resources.filter(r => r.origin === suiteOrigin &&
        r.sessionKeySha256 === key && r.samlRequest);
    if (generated.length !== 1 || sent.length !== 1 ||
        generated[0].generatedRequest.id !== sent[0].samlRequest.id ||
        generated[0].generatedRequest.sha256 !== sent[0].samlRequest.sha256 ||
        !sent[0].samlRequest.id || !/^[0-9a-f]{64}$/.test(sent[0].samlRequest.sha256 ?? '') ||
        ids.has(sent[0].samlRequest.id))
      return incomplete('generated-request-transport-unbound');
    ids.add(sent[0].samlRequest.id);
    const results = resources.filter(r => r.origin === 'http://localhost:18280' &&
        r.sessionKeySha256 === key && r.nativeResult && r.status === 200);
    if (success && (sent[0].status !== 200 || results.length !== 1 || results[0].nativeResult !== 'Success'))
      return incomplete('native-success-response-unavailable');
    if (failure) {
      // This is an observed HTTP error, not its issuance time or native knowledge time.
      if (record.trial !== 'failure' || sent[0].status !== 500 || results.length > 1 ||
          results.some(r => r.nativeResult !== 'Failure'))
        return incomplete('native-failure-response-unavailable');
      observedFailures++;
    }
  }
  if ((record.trial === 'failure' && observedFailures !== 1) ||
      (record.trial === 'all-success' && observedFailures !== 0))
    return incomplete('trial-participant-outcomes-incomplete');
  return { settled: true, reason: 'participant-transports-and-native-outcomes-observed',
    participants: peers.length, observedHttpFailures: observedFailures,
    nativeDomCompleted: record.nativeDom?.completed === true, affectsVerdict: false };
}

/** Wait for already-started observer promises, including responses added during draining. */
export async function settlePending(pending, start = 0) {
  let cursor = start;
  while (cursor < pending.length) {
    const end = pending.length;
    await Promise.all(pending.slice(cursor, end));
    cursor = end;
  }
  return cursor;
}
