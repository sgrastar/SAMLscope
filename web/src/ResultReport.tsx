import { useEffect, useMemo, useState } from 'react'
import { AppShell } from './AppShell'
import { api, type PublicResult } from './api'
import { humanize } from './format'

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
    <section className="gate-card error-state"><p className="eyebrow">SAMLscope result</p><h1>Result unavailable</h1>
      <div className="notice notice-error" role="alert">{error}</div><a className="button button-secondary" href={`/manage/${runId}`}>Return to Run workspace</a>
    </section></main></AppShell>
  if (!result) return <AppShell current="report" runId={runId}><main className="shell page-main">
    <div className="report-skeleton" role="status" aria-label="Loading authoritative result"><span /><span /><span /><span /></div>
  </main></AppShell>

  const ratio = Math.round(result.coverage.verifiedRatio * 1000) / 10
  const verdictCounts = result.summary.requirements.verdicts
  const filterOptions = ['ALL', ...Object.keys(verdictCounts).map(value => value.toUpperCase())]
  return <AppShell current="report" runId={runId} mode={result.suite.executionMode === 'hosted' ? 'hosted' : 'selfhosted'}>
    <section className="report-hero"><div className="shell report-hero-inner">
      <div><p className="eyebrow">SAMLscope conformance result</p><h1>{humanize(result.run.conformance)}</h1><p>{result.conformanceStatement}</p></div>
      <div className={`verdict-card verdict-${result.run.conformance.toLowerCase()}`}><span>Completeness</span><strong>{humanize(result.run.completeness)}</strong></div>
    </div></section>
    <main className="shell report-main">
      <section className="metrics" aria-label="Result coverage">
        <Metric label="Verified MUST" value={`${result.coverage.mustResolved}/${result.coverage.mustObservable}`} />
        <Metric label="Applicable obligations" value={`${result.coverage.obligationsApplicable}/${result.coverage.obligationsTotal}`} />
        <Metric label="Verified ratio" value={`${ratio}%`} />
        <Metric label="Unresolved MUST" value={String(result.coverage.mustUnresolved)} />
      </section>

      <section className="panel report-section provenance-panel">
        <p className="eyebrow">Evidence sources</p><h2>Evidence provenance</h2>
        <p className="section-copy">Externally verified and self-attested evidence are reported separately. Self-attestation is never presented as external verification.</p>
        <div className="provenance-strip">
          <EvidenceMetric kind="observed" label="Externally verified" value={result.evidenceSummary.externallyVerified} />
          <EvidenceMetric kind="attested" label="Self-attested" value={result.evidenceSummary.selfAttested} />
          <EvidenceMetric kind="unverified" label="Not verified" value={result.evidenceSummary.notVerified} />
        </div>
      </section>

      <section className="report-grid">
        <section className="panel"><h2>Target and provenance</h2><dl className="key-values">
          <dt>Product</dt><dd>{result.target.declaredProduct} <small>(declared)</small></dd>
          <dt>Entity ID</dt><dd><code>{result.target.entityId}</code></dd>
          <dt>Role</dt><dd>{targetRole(result.target.role, result.target.kind)}</dd>
          <dt>Profile</dt><dd>{result.profile.id}</dd>
          <dt>Request signing</dt><dd>{humanize(result.configuration?.parameters?.requestSigningMode ?? 'Not recorded')}</dd>
          <dt>Suite</dt><dd>{result.suite.name} {result.suite.version}</dd>
          <dt>Evaluation bundle</dt><dd><code>{shortDigest(result.evaluationBundle.digest)}</code></dd>
          <dt>Run</dt><dd><code>{result.run.id}</code></dd>
        </dl></section>

        <section className="panel"><h2>Resolution status</h2>
          {result.unresolved.length === 0 ? <p className="quiet-success">No unresolved obligations.</p> : <ul className="finding-list">{result.unresolved.map(item => <li key={item.obligation}>
            <strong>{item.obligation}: {humanize(item.verdict)}</strong><span>{item.howToResolve}</span>
          </li>)}</ul>}
          {result.notObservable.map(item => <div className="notice notice-neutral" key={item.obligation}><strong>{item.obligation}</strong>{item.reason}</div>)}
        </section>
      </section>

      {(result.advisories.length > 0 || result.suiteIncidents.length > 0) && <section className="panel report-section">
        <h2>Advisories and Suite incidents</h2><ul className="finding-list">
          {result.advisories.map(item => <li key={`${item.code}-${item.obligation}`}><strong>{item.code}</strong><span>{item.messageEn} It does not affect the verdict.</span></li>)}
          {result.suiteIncidents.map((item, index) => <li key={`${item.kind}-${index}`}><strong>{item.kind}</strong><span>{item.note}</span></li>)}
        </ul>
      </section>}

      <section className="requirements-section">
        <div className="section-heading"><div><p className="eyebrow">Traceable detail</p><h2>Requirements</h2></div>
          <div className="requirement-filters" aria-label="Filter requirements">{filterOptions.map(option => <button
            className={filter === option ? 'active' : ''} type="button" key={option} aria-pressed={filter === option}
            onClick={() => setFilter(option)}>{humanize(option)} {option === 'ALL' ? result.summary.requirements.total : countForVerdict(verdictCounts, option)}</button>)}</div>
        </div>
        {requirements.length === 0 ? <div className="empty-state compact"><h3>No requirements match this filter</h3></div>
          : <div className="requirements">{requirements.map(requirement => <details key={requirement.id} className="requirement">
            <summary><span>{requirement.id}</span><strong className={`badge badge-${requirement.verdict.toLowerCase()}`}>{humanize(requirement.verdict)}</strong></summary>
            <div className="requirement-body"><a href={requirement.specUrl}>Source requirement</a>
              <ul>{requirement.obligations.map(item => <li key={item.key}><code>{item.key}</code><span>{item.level} / {humanize(item.verdict)}</span></li>)}</ul>
            </div>
          </details>)}</div>}
      </section>

      <section className="panel report-section export-panel"><h2>Export</h2><div className="row-actions">
        <a className="button" href={`/api/runs/${runId}/result.json`} download>Download result.json</a>
        <a className="button button-secondary" href={`/api/runs/${runId}/report.html`} download>Download static report.html</a>
      </div></section>
      <footer className="legal disclaimer">This is a test result, not a certification. Target product details are declarations and are not independently verified.</footer>
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
  return <div><span className={`semantic-dot evidence-${kind}`} /><span>{label}</span><strong>{value}</strong><small>cases</small></div>
}

function shortDigest(value: string) {
  return `${value.slice(0, 19)}…${value.slice(-8)}`
}

function countForVerdict(counts: Record<string, number>, verdict: string) {
  const match = Object.entries(counts).find(([key]) => key.toUpperCase() === verdict)
  return match?.[1] ?? 0
}
