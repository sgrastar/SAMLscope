const names: Record<string, string> = {
  public_base_https: 'Secure Test Peer URL', target_metadata: 'IdP / SP metadata',
  target_to_suite: 'Return connection to SAMLscope',
}
export function PreflightSummary({ report, roundTripComplete = false }: { report: Record<string, unknown> | undefined; roundTripComplete?: boolean }) {
  if (!report || !Array.isArray(report.checks)) return null
  const checks = report.checks.filter((value): value is { code: string; status: string; message: string } =>
    value && typeof value.code === 'string' && typeof value.status === 'string' && typeof value.message === 'string')
  const failed = checks.some(check => check.status === 'FAIL')
  const ready = !failed && checks.some(check => check.code === 'target_metadata' && check.status === 'PASS')
  return <section className="preflight-summary" aria-label="Preflight results">
    <h3>{failed ? 'Setup needs attention' : ready ? 'Setup checks completed' : 'Setup checks are incomplete'}</h3>
    <p>{ready ? `Metadata is ready. ${roundTripComplete ? 'Select Start or resume tests.' : 'Continue with the login step below.'} These setup checks are not a SAML conformance verdict.`
      : 'Resolve the items below, then run preflight again. Do not start the round trip yet.'}</p>
    <ul>{checks.map((check, index) => <li key={`${check.code}-${index}`}>
      <strong>{names[check.code] ?? check.code}</strong>
      <span>{check.status === 'PASS' ? 'Ready' : check.status === 'FAIL' ? 'Needs attention'
        : check.status === 'WARNING' ? 'Not yet verified' : 'Not checked'}</span>
      <p>{check.code === 'target_to_suite' && check.status === 'WARNING'
        ? (roundTripComplete ? 'This setup check did not verify the return connection. A round trip has since been recorded; review its evidence in this Run.' : 'This setup check has not verified a response from the target. This is expected before the first round trip; continue with login.')
        : check.message}</p>
    </li>)}</ul>
    <details><summary>Technical details</summary><pre>{JSON.stringify(report, null, 2)}</pre></details>
  </section>
}
