import { FormEvent, useEffect, useMemo, useState } from 'react'
import { AppShell } from './AppShell'
import { api, type AuthSession, type Plan, type PlanInput, type Profile, type Run, type TargetConnection } from './api'
import { ResultReport } from './ResultReport'
import { ManagementBootstrap } from './ManagementBootstrap'
import { RunManagement } from './RunManagement'
import { formatDate, humanize } from './format'
import { idpRoundTripReady, idpRoundTripUrl } from './peerUrls'
import { PeerRegistration } from './PeerRegistration'
import { RoundTripLink } from './RoundTripLink'
import { profileCatalog, profileLabel, profileRole } from './profiles'
import { Licenses } from './Licenses'

const initialInput: PlanInput = {
  name: '',
  profile: 'browser_sso_idp',
  targetKind: 'IDP',
  targetEntityId: '',
  metadataSourceKind: 'URL',
  metadataSourceLocation: '',
  suiteMetadataDelivery: 'MANUAL',
  declaredFeatures: {},
  parameters: { clockSkewToleranceSeconds: 180, metadataRefreshWaitSeconds: 300, testUserHint: '', requestSigningMode: 'OPTIONAL' },
  interaction: { allowBrowserSteps: true, allowAttestation: false, preset: 'quick' },
  authorizedTarget: false,
}

export function App() {
  if (window.location.pathname === '/licenses') return <Licenses />
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
  const [targets, setTargets] = useState<TargetConnection[]>([])
  const [installedProfiles, setInstalledProfiles] = useState<Profile[]>([])
  const [plans, setPlans] = useState<Plan[]>([])
  const [selectedId, setSelectedId] = useState<string | undefined>(initialLocation.planId)
  const [runs, setRuns] = useState<Run[]>([])
  const [planRuns, setPlanRuns] = useState<Record<string, PlanRunHistory>>({})
  const [input, setInput] = useState(initialInput)
  const [message, setMessage] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(true)
  const [mode, setMode] = useState<'selfhosted' | 'hosted'>('selfhosted')
  const [auth, setAuth] = useState<AuthSession>()
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
      const session = health.oidcEnabled ? await api.authSession() : undefined
      if (session) setAuth(session)
      setInstalledProfiles(await api.profiles())
      if (health.mode === 'selfhosted' || session?.authenticated) setTargets(await api.targets())
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
    if (next === 'new' && auth?.enabled && !auth.authenticated && auth.accessPolicy !== 'optional') {
      window.location.assign('/auth/login')
      return
    }
    setSelectedId(planId)
    const query = next === 'new' ? '?new=1' : next === 'detail' && planId ? `?plan=${encodeURIComponent(planId)}` : '/'
    window.history.pushState(null, '', query)
    window.scrollTo({ top: 0, behavior: 'smooth' })
  }

  const create = async (event: FormEvent) => {
    event.preventDefault()
    setError('')
    try {
      let planInput = input
      if (!input.targetConnectionId) {
        const target = await api.registerTarget({
          name: input.name,
          entityId: input.targetEntityId,
          metadataUrl: input.metadataSourceLocation,
          authorizedTarget: input.authorizedTarget,
        })
        setTargets(current => [target, ...current])
        planInput = {
          ...input,
          targetConnectionId: target.id,
          targetRevisionId: target.revisions[0].id,
        }
      }
      const created = await api.createPlan(planInput)
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

  const mustSignIn = auth?.enabled && !auth.authenticated && auth.accessPolicy !== 'optional'
  return <AppShell current="plans" mode={mode}>
    <main className="shell page-main">
      {error && <div className="notice notice-error" role="alert"><strong>Unable to continue</strong>{error}</div>}
      {message && <div className="notice notice-success" role="status">{message}</div>}
      {managementUrl && <ManagementLink url={managementUrl} />}
      {loading ? <PlanSkeleton /> : view === 'new' && mustSignIn ? <section className="panel">
        <h1>Sign in to create a Test Plan</h1>
        <p>Your Plans and Runs will be available when you return.</p>
        <a className="button" href="/auth/login">Continue to sign in</a>
      </section> : view === 'new' ? <NewPlan input={input} setInput={setInput} create={create} cancel={() => show('list')}
        targets={targets} installedProfiles={installedProfiles} />
        : view === 'detail' && selected ? <PlanDetail plan={selected} runs={runs} createRun={createRun} canCreateRun={mode === 'selfhosted' || auth?.authenticated === true} back={() => show('list')} />
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
        <span><strong>{plan.plan.name}</strong><small>{plan.plan.target.entityId}</small>
          {profileRole(plan.plan.profile) === 'IDP' && <small>Request signing: {humanize(plan.plan.requestSigningMode ?? 'OPTIONAL')}</small>}</span>
        <span className={`profile-badge profile-${plan.plan.profile.toLowerCase()}`}>{profileLabel(plan.plan.profile)}</span>
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

function NewPlan({ input, setInput, create, cancel, targets, installedProfiles }: {
  input: PlanInput
  setInput: (value: PlanInput) => void
  create: (event: FormEvent) => void
  cancel: () => void
  targets: TargetConnection[]
  installedProfiles: Profile[]
}) {
  const profiles = profileCatalog.filter(profile => installedProfiles.includes(profile.id))
  const role = profileRole(input.profile)
  const compatibleTargets = targets.filter(target => target.revisions[0]?.roles.includes(role))

  useEffect(() => {
    if (profiles.length > 0 && !installedProfiles.includes(input.profile)) chooseProfile(profiles[0].id)
  }, [installedProfiles.join(',')])

  const chooseProfile = (profile: Profile) => {
    const nextRole = profileRole(profile)
    const selected = targets.find(target => target.id === input.targetConnectionId)
    const retainTarget = selected?.revisions.some(revision =>
      revision.id === input.targetRevisionId && revision.roles.includes(nextRole)) === true
    setInput({
      ...input,
      profile,
      targetKind: nextRole,
      targetConnectionId: retainTarget ? input.targetConnectionId : undefined,
      targetRevisionId: retainTarget ? input.targetRevisionId : undefined,
      targetEntityId: retainTarget ? input.targetEntityId : '',
      metadataSourceLocation: retainTarget ? input.metadataSourceLocation : '',
      parameters: {
        ...input.parameters,
        requestSigningMode: nextRole === 'IDP' ? input.parameters.requestSigningMode : 'OPTIONAL',
      },
    })
  }

  const chooseTarget = (id: string) => {
    const target = compatibleTargets.find(candidate => candidate.id === id)
    const revision = target?.revisions.find(candidate => candidate.roles.includes(role))
    setInput({
      ...input,
      targetConnectionId: target?.id,
      targetRevisionId: revision?.id,
      targetEntityId: target?.entityId ?? '',
      metadataSourceLocation: '',
      name: input.name || target?.name || '',
    })
  }

  return <section className="form-wrap">
    <button className="text-button back-link" onClick={cancel}>Back to Test Plans</button>
    <header className="page-head compact"><p className="eyebrow">New Test Plan</p><h1>Create Test Plan</h1>
      <p>Choose a functional profile and reuse registered metadata or add a target once.</p></header>
    <form onSubmit={create}>
      <fieldset className="field-group"><legend>Profile</legend><p>Choose the conformance profile for this Test Plan.</p>
        {profiles.length === 0 ? <p role="status">No approved functional profile definitions are installed.</p> :
        <div className="profile-grid">{profiles.map(profile => <label className={`profile-option${input.profile === profile.id ? ' selected' : ''}`} key={profile.id}>
          <input type="radio" name="profile" value={profile.id} checked={input.profile === profile.id} onChange={() => chooseProfile(profile.id)} />
          <strong>{profile.title}</strong><span>{profile.description}</span>
        </label>)}</div>}
      </fieldset>
      <fieldset className="field-group"><legend>Target</legend>
        <label>Plan name<input required value={input.name} onChange={event => setInput({ ...input, name: event.target.value })} /></label>
        {compatibleTargets.length > 0 && <label>Saved target<select value={input.targetConnectionId ?? ''} onChange={event => chooseTarget(event.target.value)}>
          <option value="">Register a new target</option>
          {compatibleTargets.map(target => <option key={target.id} value={target.id}>{target.name} — {target.entityId}</option>)}
        </select></label>}
        {input.targetConnectionId ? <p>Using the saved metadata snapshot for <strong>{input.targetEntityId}</strong>. The same target can be reused by other compatible profiles.</p> : <>
        <label>Target SAML Entity ID<input required type="url" value={input.targetEntityId} onChange={event => setInput({ ...input, targetEntityId: event.target.value })} /></label>
        <label>Target metadata URL<input required type="url" value={input.metadataSourceLocation} onChange={event => setInput({ ...input, metadataSourceLocation: event.target.value })} /></label>
        </>}
      </fieldset>
      <label>Execution assistance<select value={input.interaction.preset ?? 'quick'} onChange={event => {
        const preset = event.target.value as NonNullable<PlanInput['interaction']['preset']>
        setInput({ ...input, interaction: { ...input.interaction, preset, allowAttestation: preset === 'assisted_with_attestation' } })
      }}>
        <option value="quick">Quick</option>
        <option value="assisted">Assisted</option>
        <option value="assisted_with_attestation">Assisted + attestation</option>
      </select><small>Checks without the selected evidence method remain not verified.</small></label>
      {['browser_sso_idp', 'metadata_idp'].includes(input.profile) && <fieldset className="field-group"><legend>Request signing</legend>
        <p>Keep the target's signature requirement fixed for this Plan. Use a separate Plan to test the other setting.</p>
        <label>Target requires signed requests<select value={input.parameters.requestSigningMode ?? 'OPTIONAL'}
          onChange={event => setInput({ ...input, parameters: { ...input.parameters,
            requestSigningMode: event.target.value as 'REQUIRED' | 'OPTIONAL' } })}>
          <option value="OPTIONAL">Optional — normal requests are unsigned</option>
          <option value="REQUIRED">Required — normal requests are signed</option>
        </select></label>
        <p>Signature tests retain their intentionally invalid signatures in both settings.</p>
      </fieldset>}
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
      <div className="form-actions"><button type="submit" disabled={profiles.length === 0}>Create plan</button><button className="button-secondary" type="button" onClick={cancel}>Cancel</button></div>
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
    <header className="plan-detail-head"><div><p className="eyebrow">Test Plan / {profileLabel(plan.plan.profile)}</p><h1>{plan.plan.name}</h1>{profileRole(plan.plan.profile) === 'IDP' && <p>Request signing: {humanize(plan.plan.requestSigningMode ?? 'OPTIONAL')} · fixed for this Plan</p>}</div>
      <span className="authorization-state"><span className="semantic-dot status-live" />Authorized target</span></header>
    <PeerRegistration plan={plan} />
    {canCreateRun && <button onClick={createRun}>Create Run and preflight</button>}
    <section className="runs-section"><div className="section-heading"><h2>Runs</h2><span>{runs.length} total</span></div>
      {runs.length === 0 ? <div className="empty-state compact"><h3>No Runs yet</h3><p>Create the first Run after registering the Test Peer metadata.</p></div>
        : <div className="run-list">{runs.map(run => <article className="run-row" key={run.id}>
          <div><span className={`run-status status-${run.status.toLowerCase()}`}>{humanize(run.status)}</span><code>{run.id}</code></div>
          <span>Suite to target reachability: {humanize(run.targetToSuiteReachability)}</span>
          <div className="row-actions">
            {profileRole(plan.plan.profile) === 'IDP' && run.status !== 'COMPLETED' && (idpRoundTripReady(run)
              ? <RoundTripLink href={idpRoundTripUrl(plan, run.id)} />
              : <span>Open Run workspace and run preflight before starting SAML.</span>)}
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
