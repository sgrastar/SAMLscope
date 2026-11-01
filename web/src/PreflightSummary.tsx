import { t } from './i18n'
const checkNames = (): Record<string, string> => ({
  public_base_https: t('Secure Test Peer URL'), target_metadata: t('IdP / SP metadata'),
  target_to_suite: t('Return connection to SAMLscope'),
})
export function PreflightSummary({ report, roundTripComplete = false }: { report: Record<string, unknown> | undefined; roundTripComplete?: boolean }) {
  if (!report || !Array.isArray(report.checks)) return null
  const checks = report.checks.filter((value): value is { code: string; status: string; message: string } =>
    value && typeof value.code === 'string' && typeof value.status === 'string' && typeof value.message === 'string')
  const failed = checks.some(check => check.status === 'FAIL')
  const ready = !failed && checks.some(check => check.code === 'target_metadata' && check.status === 'PASS')
  return <section className="preflight-summary" aria-label={t('Preflight results')}>
    <h3>{failed ? t('Setup needs attention') : ready ? t('Setup checks completed') : t('Setup checks are incomplete')}</h3>
    <p>{ready ? (roundTripComplete
      ? t('Metadata is ready. Select Start or resume tests. These setup checks are not a SAML conformance verdict.')
      : t('Metadata is ready. Continue with the login step below. These setup checks are not a SAML conformance verdict.'))
      : t('Resolve the items below, then run preflight again. Do not start the round trip yet.')}</p>
    <ul>{checks.map((check, index) => <li key={`${check.code}-${index}`}>
      <strong>{checkNames()[check.code] ?? check.code}</strong>
      <span>{check.status === 'PASS' ? t('Ready') : check.status === 'FAIL' ? t('Needs attention')
        : check.status === 'WARNING' ? t('Not yet verified') : t('Not checked')}</span>
      <p>{check.code === 'target_to_suite' && check.status === 'WARNING'
        ? (roundTripComplete ? t('This setup check did not verify the return connection. A round trip has since been recorded; review its evidence in this Run.') : t('This setup check has not verified a response from the target. This is expected before the first round trip; continue with login.'))
        : check.message}</p>
    </li>)}</ul>
    <details><summary>{t('Technical details')}</summary><pre>{JSON.stringify(report, null, 2)}</pre></details>
  </section>
}
