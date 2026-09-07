import { FormEvent, useEffect, useMemo, useState } from 'react'
import { AppShell } from './AppShell'
import { api, type Plan, type PlanInput, type Profile, type Run } from './api'
import { ResultReport } from './ResultReport'
import { ManagementBootstrap } from './ManagementBootstrap'
import { RunManagement } from './RunManagement'
import { formatDate, humanize } from './format'

const initialInput: PlanInput = {
  name: '',
  profile: 'IDP_CORE',
  targetKind: 'IDP',
  targetEntityId: '',
  metadataSourceKind: 'URL',
  metadataSourceLocation: '',
  suiteMetadataDelivery: 'MANUAL',
  declaredFeatures: {},
  parameters: { clockSkewToleranceSeconds: 180, metadataRefreshWaitSeconds: 300, testUserHint: '' },
  interaction: { allowBrowserSteps: true, allowAttestation: true },
  authorizedTarget: false,
}

export function App() {
  const reportRunId = window.location.pathname.match(/^\/reports\/(run_[0-9A-HJKMNP-TV-Z]{26})$/)?.[1]
  if (reportRunId) return <ResultReport runId={reportRunId} />
  const manageRunId = window.location.pathname.match(/^\/manage\/(run_[0-9A-HJKMNP-TV-Z]{26})$/)?.[1]
  if (manageRunId) return <ManagementBootstrap runId={manageRunId} />
  const browserMatch = window.location.pathname.match(/^\/browser\/(run_[0-9A-HJKMNP-TV-Z]{26})\/([A-Za-z0-9-]+)$/)
  const browserRunId = browserMatch?.[1]
  if (browserRunId) return <AppShell current="run" runId={browserRunId}>
    <main className="shell page-main"><RunManagement
      runId={browserRunId}
      focusCaseId={browserMatch?.[2]}
      csrfToken={window.sessionStorage.getItem(`samlscope.csrf.${browserRunId}`) ?? undefined}
    /></main>
  </AppShell>

  return <PlanWorkspace />
}

function PlanWorkspace() {
  const initialLocation = planLocation()
  const [plans, setPlans] = useState<Plan[]>([])
  const [selectedId, setSelectedId] = useState<string | undefined>(initialLocation.planId)
  const [runs, setRuns] = useState<Run[]>([])
  const [planRuns, setPlanRuns] = useState<Record<string, PlanRunHistory>>({})
  const [input, setInput] = useState(initialInput)
  const [message, setMessage] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(true)
  const [mode, setMode] = useState<'selfhosted' | 'hosted'>('selfhosted')
  const [managementUrl, setManagementUrl] = useState<string>()
  const [view, setView] = useState<'list' | 'new' | 'detail'>(initialLocation.view)
  const selected = useMemo(() => plans.find(plan => plan.plan.id === selectedId), [plans, selectedId])

  const refreshPlans = async () => {
    const value = await api.plans()
    setPlans(value)
    const histories = await Promise.all(value.map(async plan => {
      try {
        return [plan.plan.id, { state: 'loaded', runs: await api.runs(plan.plan.id) } satisfies PlanRunHistory] as const
      } catch (cause) {
        return [plan.plan.id, {
          state: 'error',
          message: cause instanceof Error ? cause.message : 'Run history could not be loaded.',
        } satisfies PlanRunHistory] as const
      }
    }))
    setPlanRuns(Object.fromEntries(histories))
    if (selectedId && !value.some(plan => plan.plan.id === selectedId)) {
      setSelectedId(undefined)
      setView('list')
      window.history.replaceState(null, '', '/')
    }
  }

  useEffect(() => {
    void api.health().then(async health => {
      setMode(health.mode)
      try { await refreshPlans() } catch (cause) {
        if (health.mode === 'selfhosted') throw cause
      }
    }).catch(cause => setError((cause as Error).message)).finally(() => setLoading(false))
  }, [])

  useEffect(() => {
    const restoreLocation = () => {
      const location = planLocation()
      setView(location.view)
      setSelectedId(location.planId)
      window.scrollTo({ top: 0, behavior: 'auto' })
    }
    window.addEventListener('popstate', restoreLocation)
    return () => window.removeEventListener('popstate', restoreLocation)
  }, [])

  useEffect(() => {
    if (!selectedId || view !== 'detail') return
    void api.runs(selectedId).then(value => {
      setRuns(value)
      setPlanRuns(current => ({ ...current, [selectedId]: { state: 'loaded', runs: value } }))
    }).catch(cause => setError((cause as Error).message))
  }, [selectedId, view])

  const show = (next: 'list' | 'new' | 'detail', planId?: string) => {
    setView(next)
    setSelectedId(planId)
    const query = next === 'new' ? '?new=1' : next === 'detail' && planId ? `?plan=${encodeURIComponent(planId)}` : '/'
    window.history.pushState(null, '', query)
    window.scrollTo({ top: 0, behavior: 'smooth' })
  }

  const create = async (event: FormEvent) => {
    event.preventDefault()
    setError('')
    try {
      const created = await api.createPlan(input)
      setPlans(current => [created.plan, ...current])
      setSelectedId(created.plan.plan.id)
      setRuns(created.initialRun ? [created.initialRun.run] : [])
      setPlanRuns(current => ({
        ...current,
        [created.plan.plan.id]: { state: 'loaded', runs: created.initialRun ? [created.initialRun.run] : [] },
      }))
      setManagementUrl(created.initialRun?.managementUrl ?? undefined)
      setInput(initialInput)
      setView('detail')
      window.history.pushState(null, '', `?plan=${encodeURIComponent(created.plan.plan.id)}`)
      setMessage(created.initialRun?.managementUrl
        ? 'Test Plan and initial Run created. Save the protected management link below.'
        : 'Test Plan created. Register the Test Peer metadata in the target before starting a Run.')
    } catch (cause) { setError((cause as Error).message) }
  }

  const createRun = async () => {
    if (!selected) return
    setError('')
    try {
      const csrfToken = runs.map(run => window.sessionStorage.getItem(`samlscope.csrf.${run.id}`)).find(Boolean) ?? undefined
      const created = await api.createRun(selected.plan.id, csrfToken)
      setRuns(current => [created.run, ...current])
      setPlanRuns(current => {
        const history = current[selected.plan.id]
        return {
          ...current,
          [selected.plan.id]: {
            state: 'loaded',
            runs: [created.run, ...(history?.state === 'loaded' ? history.runs : [])],
          },
        }
      })
      setManagementUrl(created.managementUrl ?? undefined)
      if (created.managementUrl) setMessage('Run created. Save the protected management link below.')
      else {
        await api.preflight(created.run.id)
        setMessage('Run created and preflight completed.')
        const refreshedRuns = await api.runs(selected.plan.id)
        setRuns(refreshedRuns)
        setPlanRuns(current => ({ ...current, [selected.plan.id]: { state: 'loaded', runs: refreshedRuns } }))
      }
    } catch (cause) { setError((cause as Error).message) }
  }

  return <AppShell current="plans" mode={mode}>
    <main className="shell page-main">
      {error && <div className="notice notice-error" role="alert"><strong>Unable to continue</strong>{error}</div>}
      {message && <div className="notice notice-success" role="status">{message}</div>}
      {managementUrl && <ManagementLink url={managementUrl} />}
      {loading ? <PlanSkeleton /> : view === 'new' ? <NewPlan input={input} setInput={setInput} create={create} cancel={() => show('list')} />
        : view === 'detail' && selected ? <PlanDetail plan={selected} runs={runs} createRun={createRun} canCreateRun={mode === 'selfhosted'} back={() => show('list')} />
          : <PlanList plans={plans} runs={planRuns} open={id => show('detail', id)} create={() => show('new')}
            refresh={() => void refreshPlans().catch(cause => setError((cause as Error).message))} />}
      <footer className="legal">Operational quick checks remain separate from conformance results. Creating a Test Plan requires authorization to test the declared target.</footer>
    </main>
  </AppShell>
}

type PlanRunHistory = { state: 'loaded'; runs: Run[] } | { state: 'error'; message: string }

function PlanList({ plans, runs, open, create, refresh }: {
  plans: Plan[]
  runs: Record<string, PlanRunHistory>
  open: (id: string) => void
  create: () => void
  refresh: () => void
}) {
  return <>
    <header className="page-head plan-index-head">
      <div><p className="eyebrow">SAML Conformance Test Suite</p><h1>Test Plans</h1>
        <p>Run evidence-backed SAML interoperability checks, resolve incomplete evidence, and export a traceable result.</p></div>
      <div className="row-actions"><button className="button-secondary" onClick={refresh}>Refresh</button>
        <button onClick={create}>New Test Plan</button></div>
    </header>
    {plans.length === 0 ? <section className="empty-state">
      <h2>No Test Plans yet</h2><p>Register an IdP or SP to create its stable Test Peer metadata and first Run.</p>
      <button onClick={create}>Register a target</button>
    </section> : <section className="plan-list" aria-label="Test Plans">{plans.map(plan => {
      const history = runs[plan.plan.id]
      const planHistory = history?.state === 'loaded' ? history.runs : undefined
      const latest = planHistory?.[0]
      return <button className="plan-row" key={plan.plan.id} onClick={() => open(plan.plan.id)}>
        <span><strong>{plan.plan.name}</strong><small>{plan.plan.target.entityId}</small></span>
        <span className={`profile-badge profile-${plan.plan.profile.toLowerCase()}`}>{humanize(plan.plan.profile)}</span>
        <span className="plan-run-summary">
          {history?.state === 'error' ? <><strong>Run history unavailable</strong><small>Refresh to retry</small></>
            : planHistory ? <><strong>{planHistory.length} Run{planHistory.length === 1 ? '' : 's'}</strong>
              <small>{latest ? `${humanize(latest.status)}${latest.updatedAt ? ` · ${formatDate(latest.updatedAt)}` : ''}` : 'Not started'}</small></>
              : <><strong>Loading Run history</strong><small>Please wait</small></>}
        </span>
        <span aria-hidden="true">View</span>
      </button>
    })}</section>}
  </>
}

function NewPlan({ input, setInput, create, cancel }: {
  input: PlanInput
  setInput: (value: PlanInput) => void
  create: (event: FormEvent) => void
  cancel: () => void
}) {
  const profiles: Array<{ id: Profile; title: string; description: string }> = [
    { id: 'IDP_CORE', title: 'IdP Core', description: 'Baseline SSO and SLO obligations for an Identity Provider.' },
    { id: 'IDP_FULL', title: 'IdP Full', description: 'Core plus ECP, channel binding, and extended evidence.' },
    { id: 'SP_CORE', title: 'SP Core', description: 'Baseline SSO and SLO obligations for a Service Provider.' },
    { id: 'SP_FULL', title: 'SP Full', description: 'Core plus extended evidence for a Service Provider.' },
  ]
  return <section className="form-wrap">
    <button className="text-button back-link" onClick={cancel}>Back to Test Plans</button>
    <header className="page-head compact"><p className="eyebrow">New Test Plan</p><h1>Register a target</h1>
      <p>Choose the profile and tell SAMLscope how the target can be reached.</p></header>
    <form onSubmit={create}>
      <fieldset className="field-group"><legend>Profile</legend><p>Choose the conformance profile for this Test Plan.</p>
        <div className="profile-grid">{profiles.map(profile => <label className={`profile-option${input.profile === profile.id ? ' selected' : ''}`} key={profile.id}>
          <input type="radio" name="profile" value={profile.id} checked={input.profile === profile.id} onChange={() => setInput({
            ...input, profile: profile.id, targetKind: profile.id.startsWith('IDP') ? 'IDP' : 'SP',
          })} />
          <strong>{profile.title}</strong><span>{profile.description}</span>
        </label>)}</div>
      </fieldset>
      <fieldset className="field-group"><legend>Target</legend>
        <label>Plan name<input required value={input.name} onChange={event => setInput({ ...input, name: event.target.value })} /></label>
        <label>Target SAML Entity ID<input required type="url" value={input.targetEntityId} onChange={event => setInput({ ...input, targetEntityId: event.target.value })} /></label>
        <label>Target metadata URL<input required type="url" value={input.metadataSourceLocation} onChange={event => setInput({ ...input, metadataSourceLocation: event.target.value })} /></label>
      </fieldset>
      <fieldset className="field-group"><legend>Suite metadata delivery</legend>
        <p>How the target retrieves SAMLscope's metadata. This never grants SAMLscope access to a vendor administration API.</p>
        <div className="choice-grid">{(['MANUAL', 'HTTP_URL', 'MDQ'] as const).map(value => <label className={`choice-option${input.suiteMetadataDelivery === value ? ' selected' : ''}`} key={value}>
          <input type="radio" name="delivery" value={value} checked={input.suiteMetadataDelivery === value} onChange={() => setInput({ ...input, suiteMetadataDelivery: value })} />
          {humanize(value)}
        </label>)}</div>
      </fieldset>
      <fieldset className="field-group"><legend>Authorization</legend><label className="checkbox-row">
        <input required type="checkbox" checked={input.authorizedTarget} onChange={event => setInput({ ...input, authorizedTarget: event.target.checked })} />
        I own or am authorized to test this target.
      </label></fieldset>
      <div className="form-actions"><button type="submit">Create plan</button><button className="button-secondary" type="button" onClick={cancel}>Cancel</button></div>
    </form>
  </section>
}

function PlanDetail({ plan, runs, createRun, canCreateRun, back }: {
  plan: Plan
  runs: Run[]
  createRun: () => void
  canCreateRun: boolean
  back: () => void
}) {
  return <>
    <button className="text-button back-link" onClick={back}>Back to Test Plans</button>
    <header className="plan-detail-head"><div><p className="eyebrow">Test Plan / {humanize(plan.plan.profile)}</p><h1>{plan.plan.name}</h1></div>
      <span className="authorization-state"><span className="semantic-dot status-live" />Authorized target</span></header>
    <section className="panel peer-panel"><p className="eyebrow">Test Peer registration</p><h2>Where the target reaches SAMLscope</h2>
      <dl className="key-values">
        <dt>Entity ID</dt><dd><code>{plan.entityId}</code></dd>
        <dt>Metadata</dt><dd><a href={plan.metadataUrl}>{plan.metadataUrl}</a></dd>
        <dt>MDQ</dt><dd><code>{plan.mdqUrl}</code></dd>
        <dt>Secondary IdP entity ID</dt><dd><code>{plan.secondaryIdpEntityId}</code></dd>
        <dt>Secondary IdP metadata</dt><dd><a href={plan.secondaryIdpMetadataUrl}>{plan.secondaryIdpMetadataUrl}</a></dd>
      </dl>{canCreateRun && <button onClick={createRun}>Create Run and preflight</button>}
    </section>
    <section className="runs-section"><div className="section-heading"><h2>Runs</h2><span>{runs.length} total</span></div>
      {runs.length === 0 ? <div className="empty-state compact"><h3>No Runs yet</h3><p>Create the first Run after registering the Test Peer metadata.</p></div>
        : <div className="run-list">{runs.map(run => <article className="run-row" key={run.id}>
          <div><span className={`run-status status-${run.status.toLowerCase()}`}>{humanize(run.status)}</span><code>{run.id}</code></div>
          <span>Suite to target reachability: {humanize(run.targetToSuiteReachability)}</span>
          <div className="row-actions">
            {plan.plan.profile.startsWith('IDP') && run.status !== 'COMPLETED' && <a className="button" href={`/p/${plan.plan.id}/start/m0-roundtrip?run=${run.id}`}>Start IdP round trip</a>}
            <a className="button button-secondary" href={`/manage/${run.id}`}>{run.status === 'COMPLETED' ? 'Manage evidence' : 'Open Run workspace'}</a>
            {run.status === 'COMPLETED' && <a className="button" href={`/reports/${run.id}`}>Open result</a>}
          </div>
        </article>)}</div>}
    </section>
  </>
}

function ManagementLink({ url }: { url: string }) {
  return <aside className="management-link notice notice-success" role="status"><strong>One-time management link. Save it now.</strong>
    <p>The secret fragment is removed from browser history when it is exchanged for a protected session.</p>
    <code>{url.replace(/#t=.*/, '#t=••••••••••••••••')}</code><a className="button" href={url}>Open protected Run</a>
  </aside>
}

function PlanSkeleton() {
  return <div className="skeleton-page" role="status" aria-label="Loading Test Plans"><span /><span /><span /></div>
}

function planLocation(): { view: 'list' | 'new' | 'detail'; planId?: string } {
  const query = new URLSearchParams(window.location.search)
  if (query.has('new')) return { view: 'new' }
  const planId = query.get('plan') ?? undefined
  return planId ? { view: 'detail', planId } : { view: 'list' }
}
