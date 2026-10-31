import { t } from './i18n'
import { SourceNoticeLink } from './SourceNoticeLink'
import { Fragment, useEffect, useMemo, useState } from 'react'
import { AppShell } from './AppShell'
import { api, type PublicResult } from './api'
import { humanize } from './format'
import { profileLabel } from './profiles'

export function ResultReport({ runId }: { runId: string }) {
  const [result, setResult] = useState<PublicResult>()
  const [error, setError] = useState('')
  const [filter, setFilter] = useState('ALL')

  useEffect(() => {
    void api.result(runId).then(setResult).catch(cause => setError((cause as Error).message))
  }, [runId])

  const requirements = useMemo(() => result?.requirements.filter(requirement =>
    filter === 'ALL' || requirement.verdict === filter) ?? [], [result, filter])

  if (error) return <AppShell current="report" runId={runId}><main className="shell gate-page">
    <section className="gate-card error-state"><p className="eyebrow">{t('SAMLscope result')}</p><h1>{t('Result unavailable')}</h1>
      <div className="notice notice-error" role="alert">{error}</div><a className="button button-secondary" href={`/manage/${runId}`}>{t('Return to Run workspace')}</a>
    </section></main></AppShell>
  if (!result) return <AppShell current="report" runId={runId}><main className="shell page-main">
    <div className="report-skeleton" role="status" aria-label={t('Loading authoritative result')}><span /><span /><span /><span /></div>
  </main></AppShell>

  const ratio = Math.round(result.coverage.verifiedRatio * 1000) / 10
  const verdictCounts = result.summary.requirements.verdicts
  const filterOptions = ['ALL', ...Object.keys(verdictCounts).map(value => value.toUpperCase())]
  return <AppShell current="report" runId={runId} mode={result.suite.executionMode === 'hosted' ? 'hosted' : 'selfhosted'}>
    <section className="report-hero"><div className="shell report-hero-inner">
      <div><p className="eyebrow">{t('SAMLscope conformance result')}</p><h1>{humanize(result.run.conformance)}</h1><p>{result.conformanceStatement}</p></div>
      <div className={`verdict-card verdict-${result.run.conformance.toLowerCase()}`}><span>{t('Completeness')}</span><strong>{humanize(result.run.completeness)}</strong></div>
    </div></section>
    <main className="shell report-main">
      <section className="metrics" aria-label={t('Result coverage')}>
        <Metric label={t('Verified MUST')} value={`${result.coverage.mustResolved}/${result.coverage.mustObservable}`} />
        <Metric label={t('Applicable obligations')} value={`${result.coverage.obligationsApplicable}/${result.coverage.obligationsTotal}`} />
        <Metric label={t('Verified ratio')} value={`${ratio}%`} />
        <Metric label={t('Unresolved MUST')} value={String(result.coverage.mustUnresolved)} />
      </section>

      <section className="panel report-section provenance-panel">
        <p className="eyebrow">{t('Evidence sources')}</p><h2>{t('Evidence provenance')}</h2>
        <p className="section-copy">{t('Externally verified and self-attested evidence are reported separately. Self-attestation is never presented as external verification.')}</p>
        <div className="provenance-strip">
          <EvidenceMetric kind="observed" label={t('Externally verified')} value={result.evidenceSummary.externallyVerified} />
          <EvidenceMetric kind="attested" label={t('Self-attested')} value={result.evidenceSummary.selfAttested} />
          <EvidenceMetric kind="unverified" label={t('Not verified')} value={result.evidenceSummary.notVerified} />
        </div>
      </section>

      <section className="report-grid">
        <section className="panel"><h2>{t('Target and provenance')}</h2><dl className="key-values">
          <dt>{t('Product')}</dt><dd>{result.target.declaredProduct} <small>{t('(declared)')}</small></dd>
          <dt>{t('Entity ID')}</dt><dd><code>{result.target.entityId}</code></dd>
          <dt>{t('Role')}</dt><dd>{targetRole(result.target.role, result.target.kind)}</dd>
          <dt>{t('Profile')}</dt><dd>{profileLabel(result.profile.id)}</dd>
          <dt>{t('Request signing')}</dt><dd>{result.configuration?.parameters?.requestSigningMode ? humanize(result.configuration.parameters.requestSigningMode) : t('Not recorded')}</dd>
          <dt>{t('Suite')}</dt><dd>{result.suite.name} {result.suite.version}</dd>
          <dt>{t('Evaluation bundle')}</dt><dd><code>{shortDigest(result.evaluationBundle.digest)}</code></dd>
          <dt>{t('Run')}</dt><dd><code>{result.run.id}</code></dd>
        </dl></section>

        <section className="panel"><h2>{t('Resolution status')}</h2>
          {result.unresolved.length === 0 ? <p className="quiet-success">{t('No unresolved obligations.')}</p> : <ul className="finding-list">{result.unresolved.map(item => <li key={item.obligation}>
            <strong>{item.obligation}: {humanize(item.verdict)}</strong><span>{item.howToResolve}</span>
          </li>)}</ul>}
          {result.notObservable.map(item => <div className="notice notice-neutral" key={item.obligation}><strong>{item.obligation}</strong>{item.reason}</div>)}
        </section>
      </section>

      {(result.advisories.length > 0 || result.suiteIncidents.length > 0) && <section className="panel report-section">
        <h2>{t('Advisories and Suite incidents')}</h2><ul className="finding-list">
          {result.advisories.map(item => <li key={`${item.code}-${item.obligation}`}><strong>{item.code}</strong><span>{item.messageEn} {t('It does not affect the verdict.')}</span></li>)}
          {result.suiteIncidents.map((item, index) => <li key={`${item.kind}-${index}`}><strong>{item.kind}</strong><span>{item.note}</span></li>)}
        </ul>
      </section>}

      <section className="requirements-section">
        <div className="section-heading"><div><p className="eyebrow">{t('Traceable detail')}</p><h2>{t('Requirements')}</h2></div>
          <div className="requirement-filters" aria-label={t('Filter requirements')}>{filterOptions.map(option => <button
            className={filter === option ? 'active' : ''} type="button" key={option} aria-pressed={filter === option}
            onClick={() => setFilter(option)}>{humanize(option)} {option === 'ALL' ? result.summary.requirements.total : countForVerdict(verdictCounts, option)}</button>)}</div>
        </div>
        {requirements.length === 0 ? <div className="empty-state compact"><h3>{t('No requirements match this filter')}</h3></div>
          : <div className="requirements">{requirements.map(requirement => <details key={requirement.id} className="requirement">
            <summary><span>{requirement.id}</span><strong className={`badge badge-${requirement.verdict.toLowerCase()}`}>{humanize(requirement.verdict)}</strong></summary>
            <div className="requirement-body"><a href={requirement.specUrl}>{t('Source requirement')}</a> · <SourceNoticeLink kind="requirement" id={requirement.id} />
              <ul>{requirement.obligations.map(item => <li key={item.key}><code>{item.key}</code><span>{item.level} / {humanize(item.verdict)}</span></li>)}</ul>
              {requirement.cases.map(test => <details key={test.id} className="case-observations">
                <summary><code>{test.id}</code> · {humanize(test.verdict)}</summary>
                <p>{humanize(test.reason.replaceAll('.', ' '))}</p>
                {test.diagnostics && Object.keys(test.diagnostics).length > 0 && <>
                  <p>{t('Partial observations are supporting detail. The case verdict above remains authoritative.')}</p>
                  <dl className="key-values">{Object.entries(test.diagnostics).map(([name, values]) => <Fragment key={name}>
                    <dt>{humanize(name.replace(/([a-z])([A-Z])/g, '$1_$2'))}</dt>
                    <dd>{values.map(value => <div key={value}><code>{value}</code></div>)}</dd>
                  </Fragment>)}</dl>
                </>}
              </details>)}
            </div>
          </details>)}</div>}
      </section>

      <section className="panel report-section export-panel"><h2>{t('Export')}</h2><div className="row-actions">
        <a className="button" href={`/api/runs/${runId}/result.json`} download>{t('Download result.json')}</a>
        <a className="button button-secondary" href={`/api/runs/${runId}/report.html`} download>{t('Download static report.html')}</a>
      </div></section>
      <footer className="legal disclaimer">{t('This is a test result, not a certification. Target product details are declarations and are not independently verified.')} <a href="/licenses">{t('Licenses and sources')}</a></footer>
    </main>
  </AppShell>
}

function targetRole(role: string, kind: string) {
  const readableRole = humanize(role)
  const readableKind = humanize(kind)
  return readableRole.toLowerCase() === readableKind.toLowerCase()
    ? readableRole
    : `${readableRole} / ${readableKind}`
}

function Metric({ label, value }: { label: string; value: string }) {
  return <div><span>{label}</span><strong>{value}</strong></div>
}

function EvidenceMetric({ kind, label, value }: { kind: string; label: string; value: number }) {
  return <div><span className={`semantic-dot evidence-${kind}`} /><span>{label}</span><strong>{value}</strong><small>{t('cases')}</small></div>
}

function shortDigest(value: string) {
  return `${value.slice(0, 19)}…${value.slice(-8)}`
}

function countForVerdict(counts: Record<string, number>, verdict: string) {
  const match = Object.entries(counts).find(([key]) => key.toUpperCase() === verdict)
  return match?.[1] ?? 0
}
