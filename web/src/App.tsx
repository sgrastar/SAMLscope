import { SourceNoticeLink } from './SourceNoticeLink'
import { FormEvent, useEffect, useMemo, useRef, useState } from 'react'
import { AppShell } from './AppShell'
import { api, type AuthSession, type Plan, type PlanInput, type Profile, type Run, type RunCreated, type TargetConnection } from './api'
import { ResultReport } from './ResultReport'
import { ManagementBootstrap } from './ManagementBootstrap'
import { RunManagement } from './RunManagement'
import { formatDate, humanize } from './format'
import { profileCatalog, profileLabel, profileRole } from './profiles'
import { Admin } from './Admin'
import { Licenses } from './Licenses'

/** Everything the form does not ask for is fixed here; users only configure the product. */
const initialInput: PlanInput = {
  name: '',
  profile: 'browser_sso_idp',
  targetKind: 'IDP',
  targetEntityId: '',
  metadataSourceKind: 'URL',
  metadataSourceLocation: '',
  suiteMetadataDelivery: 'HTTP_URL',
  declaredFeatures: {},
  parameters: { clockSkewToleranceSeconds: 180, metadataRefreshWaitSeconds: 300, testUserHint: '', requestSigningMode: 'OPTIONAL' },
  interaction: { allowBrowserSteps: true, allowAttestation: false, preset: 'assisted' },
  authorizedTarget: false,
}

/** Seam so navigation can be observed in tests. */
export const navigation = { go: (url: string) => window.location.assign(url) }

const signingProfiles: Profile[] = ['browser_sso_idp', 'metadata_idp']

function planName(entityId: string, profile: Profile): string {
  let host = entityId
  try { host = new URL(entityId).hostname } catch { /* keep the raw value */ }
  return `${host} ${profileLabel(profile)}`
}

export function App() {
  if (window.location.pathname === '/admin') return <Admin />
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
  const [planRuns, setPlanRuns] = useState<Record<string, PlanRunHistory>>({})
  const [input, setInput] = useState(initialInput)
  const [error, setError] = useState('')
  const [creating, setCreating] = useState(false)
  const errorRef = useRef<HTMLDivElement>(null)
  const [loading, setLoading] = useState(true)
  const [mode, setMode] = useState<'selfhosted' | 'hosted'>('selfhosted')
  const [auth, setAuth] = useState<AuthSession>()
  const [adminOwners, setAdminOwners] = useState<Record<string, string | null>>({})
  const [managementUrl, setManagementUrl] = useState<string>()
  const [view, setView] = useState<'list' | 'new' | 'detail'>(initialLocation.view)
  const selected = useMemo(() => plans.find(plan => plan.plan.id === selectedId), [plans, selectedId])
  const history = selectedId ? planRuns[selectedId] : undefined

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
      if (session?.role === 'ADMIN') {
        const all = await api.adminPlans()
        setAdminOwners(Object.fromEntries(all.map(row => [row.plan.plan.id, row.ownerId])))
      }
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
    if (!selectedId || view !== 'detail' || history?.state === 'loaded') return
    void api.runs(selectedId).then(value => {
      setPlanRuns(current => ({ ...current, [selectedId]: { state: 'loaded', runs: value } }))
    }).catch(cause => setError((cause as Error).message))
  }, [selectedId, view])

  useEffect(() => {
    if (!error) return
    errorRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' })
    errorRef.current?.focus({ preventScroll: true })
  }, [error])

  const show = (next: 'list' | 'new' | 'detail', planId?: string) => {
    setView(next)
    if (next === 'new' && auth?.enabled && !auth.authenticated && auth.accessPolicy !== 'optional') {
      navigation.go('/auth/login')
      return
    }
    setSelectedId(planId)
    const query = next === 'new' ? '?new=1' : next === 'detail' && planId ? `?plan=${encodeURIComponent(planId)}` : '/'
    window.history.pushState(null, '', query)
    window.scrollTo({ top: 0, behavior: 'smooth' })
  }

  /** Go straight to the Run page; only a hosted one-time secret link needs a deliberate click. */
  const openRun = (planId: string, created: RunCreated) => {
    setPlanRuns(current => {
      const known = current[planId]
      return { ...current, [planId]: { state: 'loaded',
        runs: [created.run, ...(known?.state === 'loaded' ? known.runs : [])] } }
    })
    const target = created.managementUrl ?? `/manage/${created.run.id}`
    if (mode === 'selfhosted' || auth?.enabled || !created.managementUrl) navigation.go(target)
    else setManagementUrl(created.managementUrl)
  }

  const create = async (event: FormEvent) => {
    event.preventDefault()
    if (creating) return
    setError('')
    setCreating(true)
    try {
      const name = planName(input.targetEntityId, input.profile)
      let planInput: PlanInput = { ...input, name }
      if (!input.targetConnectionId) {
        const target = await api.registerTarget({
          name,
          entityId: input.targetEntityId,
          metadataUrl: input.metadataSourceLocation,
          authorizedTarget: input.authorizedTarget,
          expectedRole: profileRole(input.profile),
        })
        setTargets(current => [target, ...current])
        planInput = { ...planInput, targetConnectionId: target.id, targetRevisionId: target.revisions[0].id }
      }
      const created = await api.createPlan(planInput)
      const planId = created.plan.plan.id
      if (auth?.userId) setAdminOwners(current => ({ ...current, [planId]: auth.userId! }))
      setPlans(current => [created.plan, ...current])
      setSelectedId(planId)
      setInput(initialInput)
      const initial = created.initialRun ?? await api.createRun(planId)
      setView('detail')
      window.history.pushState(null, '', `?plan=${encodeURIComponent(planId)}`)
      openRun(planId, initial)
    } catch (cause) { setError(planCreationError(cause, input.profile)) }
    finally { setCreating(false) }
  }

  const createRun = async () => {
    if (!selected) return
    setError('')
    try {
      const known = planRuns[selected.plan.id]
      const csrfToken = (known?.state === 'loaded' ? known.runs : [])
        .map(run => window.sessionStorage.getItem(`samlscope.csrf.${run.id}`)).find(Boolean) ?? undefined
      openRun(selected.plan.id, await api.createRun(selected.plan.id, csrfToken))
    } catch (cause) { setError((cause as Error).message) }
  }

  const mustSignIn = auth?.enabled && !auth.authenticated && auth.accessPolicy !== 'optional'
  const canCreateRun = !!selected && (mode === 'selfhosted' || auth?.authenticated === true)
    && (auth?.role !== 'ADMIN' || adminOwners[selected.plan.id] === auth.userId)
  return <AppShell current="plans" mode={mode}>
    <main className="shell page-main">
      {error && <div ref={errorRef} className="notice notice-error workspace-error" role="alert" tabIndex={-1}><strong>Unable to continue</strong>{error}</div>}
      {managementUrl && <ManagementLink url={managementUrl} />}
      {loading ? <PlanSkeleton /> : view === 'new' && mustSignIn ? <section className="card">
        <h1>Sign in to create a test</h1>
        <p>Your tests and runs will be available when you return.</p>
        <a className="button" href="/auth/login">Continue to sign in</a>
      </section> : view === 'new' ? <NewPlan input={input} setInput={setInput} create={create} cancel={() => show('list')}
        targets={targets} installedProfiles={installedProfiles} creating={creating} />
        : view === 'detail' && selected ? <PlanDetail plan={selected} history={history} createRun={createRun}
          canCreateRun={canCreateRun} back={() => show('list')} />
          : <PlanList plans={plans} runs={planRuns} open={id => show('detail', id)} create={() => show('new')} />}
      <footer className="legal">Operational quick checks remain separate from conformance results. Creating a Test Plan requires authorization to test the declared target.</footer>
    </main>
  </AppShell>
}

type PlanRunHistory = { state: 'loaded'; runs: Run[] } | { state: 'error'; message: string }

function PlanList({ plans, runs, open, create }: {
  plans: Plan[]
  runs: Record<string, PlanRunHistory>
  open: (id: string) => void
  create: () => void
}) {
  return <>
    <header className="page-head">
      <h1>Test Plans</h1>
      <button onClick={create}>New test</button>
    </header>
    {plans.length === 0 ? <section className="card">
      <h2>No tests yet</h2><p>Register an IdP or SP to start.</p>
    </section> : <section className="plan-list" aria-label="Test Plans">{plans.map(plan => {
      const history = runs[plan.plan.id]
      const latest = history?.state === 'loaded' ? history.runs[0] : undefined
      return <button className="plan-row" key={plan.plan.id} onClick={() => open(plan.plan.id)}>
        <span><strong>{plan.plan.name}</strong><small>{profileLabel(plan.plan.profile)}</small></span>
        <span className="plan-run-summary">
          {history?.state === 'error' ? <strong>Run history unavailable</strong>
            : history ? <strong>{latest ? `${humanize(latest.status)}${latest.updatedAt ? ` · ${formatDate(latest.updatedAt)}` : ''}` : 'Not started'}</strong>
              : <strong>Loading…</strong>}
        </span>
      </button>
    })}</section>}
  </>
}

function NewPlan({ input, setInput, create, cancel, targets, installedProfiles, creating }: {
  input: PlanInput
  setInput: (value: PlanInput) => void
  create: (event: FormEvent) => void
  cancel: () => void
  targets: TargetConnection[]
  installedProfiles: Profile[]
  creating: boolean
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
        requestSigningMode: signingProfiles.includes(profile) ? input.parameters.requestSigningMode : 'OPTIONAL',
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
    })
  }

  return <section className="form-wrap">
    <button className="text-button back-link" onClick={cancel}>Back to Test Plans</button>
    <h1>New test</h1>
    <form onSubmit={create}>
      <fieldset className="field-group"><legend>Profile</legend>
        {profiles.length === 0 ? <p role="status">No approved functional profile definitions are installed.</p> :
        <div className="profile-grid">{profiles.map(profile => <label className={`profile-option${input.profile === profile.id ? ' selected' : ''}`} key={profile.id}>
          <input type="radio" name="profile" value={profile.id} checked={input.profile === profile.id} onChange={() => chooseProfile(profile.id)} />
          <strong>{profile.title}</strong><span>{profile.description}</span>
        </label>)}</div>}
      </fieldset>
      <fieldset className="field-group"><legend>Your product</legend>
        {compatibleTargets.length > 0 && <label>Saved target<select value={input.targetConnectionId ?? ''} onChange={event => chooseTarget(event.target.value)}>
          <option value="">Register a new target</option>
          {compatibleTargets.map(target => <option key={target.id} value={target.id}>{target.name} — {target.entityId}</option>)}
        </select></label>}
        {input.targetConnectionId ? <p>Using the saved metadata for <strong>{input.targetEntityId}</strong>.</p> : <>
        <label>Target SAML Entity ID<input required type="url" value={input.targetEntityId} onChange={event => setInput({ ...input, targetEntityId: event.target.value })} /></label>
        <label>Target metadata URL<input required type="url" value={input.metadataSourceLocation} onChange={event => setInput({ ...input, metadataSourceLocation: event.target.value })} /></label>
        </>}
        {signingProfiles.includes(input.profile) && <label className="checkbox-row">
          <input type="checkbox" checked={input.parameters.requestSigningMode === 'REQUIRED'}
            onChange={event => setInput({ ...input, parameters: { ...input.parameters,
              requestSigningMode: event.target.checked ? 'REQUIRED' : 'OPTIONAL' } })} />
          My IdP requires signed requests
        </label>}
      </fieldset>
      <label className="checkbox-row">
        <input required type="checkbox" checked={input.authorizedTarget} onChange={event => setInput({ ...input, authorizedTarget: event.target.checked })} />
        I own or am authorized to test this target.
      </label>
      <div className="actions"><button type="submit" disabled={profiles.length === 0 || creating} aria-busy={creating}>
        {creating ? 'Creating plan…' : 'Create plan'}
      </button><button className="button-secondary" type="button" onClick={cancel} disabled={creating}>Cancel</button></div>
    </form>
  </section>
}

function PlanDetail({ plan, history, createRun, canCreateRun, back }: {
  plan: Plan
  history: PlanRunHistory | undefined
  createRun: () => void
  canCreateRun: boolean
  back: () => void
}) {
  const latest = history?.state === 'loaded' ? history.runs[0] : undefined
  return <>
    <button className="text-button back-link" onClick={back}>Back to Test Plans</button>
    <header className="page-head">
      <div><h1>{plan.plan.name}</h1><p className="muted">{profileLabel(plan.plan.profile)}</p>
        <SourceNoticeLink kind="profile" id={plan.plan.profile} /></div>
      {canCreateRun && <button onClick={createRun}>New run</button>}
    </header>
    <section className="card" aria-label="Latest run">
      {history?.state === 'error' ? <p>Run history unavailable.</p>
        : !latest ? <p>{history ? 'No runs yet.' : 'Loading…'}</p>
          : <>
              <h2>Latest run</h2>
              <p><strong>{humanize(latest.status)}</strong>{latest.updatedAt ? ` · ${formatDate(latest.updatedAt)}` : ''}</p>
              <div className="actions">
                <a className="button" href={`/manage/${latest.id}`}>Open</a>
                {latest.status === 'COMPLETED' && <a className="button button-secondary" href={`/reports/${latest.id}`}>Results</a>}
              </div>
            </>}
    </section>
  </>
}

function ManagementLink({ url }: { url: string }) {
  return <aside className="card notice notice-success" role="status"><strong>One-time management link. Save it now.</strong>
    <p>The secret fragment is removed from browser history when it is exchanged for a protected session.</p>
    <code>{url.replace(/#t=.*/, '#t=••••••••••••••••')}</code>
    <a className="button" href={url}>Open protected Run</a>
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

function planCreationError(cause: unknown, profile: Profile): string {
  const message = cause instanceof Error ? cause.message : 'The Test Plan could not be created.'
  const role = profileRole(profile)
  const descriptor = role === 'SP' ? 'SPSSODescriptor' : 'IDPSSODescriptor'
  const roleName = role === 'SP' ? 'Service Provider' : 'Identity Provider'
  const roleLabel = role === 'SP' ? 'SP' : 'IdP'
  const otherRole = role === 'SP' ? 'IdP' : 'SP'

  if (message.includes('Target does not have the selected role')) {
    return `This profile requires ${roleName} metadata, but the selected entity does not include a SAML 2.0 ${descriptor}. Use metadata for an ${roleLabel}, or choose an ${otherRole} profile.`
  }
  if (message.includes('Selected entityID is absent from metadata')) {
    return 'The entered Entity ID was not found in the downloaded metadata. Copy the exact entityID value from the metadata document.'
  }
  if (message.includes('Expected SAML metadata document')) {
    return 'The URL did not return a SAML metadata document. Check that it points directly to an EntityDescriptor or EntitiesDescriptor XML document.'
  }
  if (message.includes('Selected entity has no SAML 2.0 IdP or SP role')) {
    return 'The selected entity does not declare a SAML 2.0 IdP or SP role. Its metadata needs an IDPSSODescriptor or SPSSODescriptor with SAML 2.0 protocol support.'
  }
  if (message.includes('Target metadata could not be retrieved')) {
    return 'The metadata URL could not be fetched. Check that it is publicly reachable over HTTP(S), does not require sign-in, and returns metadata directly.'
  }
  if (message.includes('Target metadata could not be parsed')) {
    return 'The downloaded content could not be parsed as valid SAML metadata. Check the XML, certificate data, and Entity ID.'
  }
  if (message.includes('Target metadata unavailable') || message.includes('Target unavailable')) {
    return 'The saved target or metadata revision is no longer available. Register the target metadata again.'
  }
  if (message.includes('Select a target and metadata revision')) {
    return 'Select a saved target with a compatible metadata revision, or register a new target.'
  }
  if (message.includes('Another Run against this target is already active')) {
    return 'This target already has an active Run. Open or complete that Run before creating another Plan for the same target.'
  }
  if (message.includes('Too many hosted requests') || message.includes('Too many hosted request identities')) {
    return 'Plan creation is temporarily rate limited. Wait a few minutes, then try again.'
  }
  if (message.includes('Authorization to test the target is required') || message.includes('Confirm that you own or are authorized')) {
    return 'Confirm the authorization checkbox before creating the Test Plan.'
  }
  if (message === 'Access denied') {
    return 'The server did not authorize this action. Reload the page and try again.'
  }
  if (message === 'Failed to fetch' || message.includes('NetworkError')) {
    return 'SAMLscope could not reach the server. Check your connection and try again.'
  }
  if (message === 'The request could not be completed') {
    return 'SAMLscope could not complete the request. Try again; if it continues, report the time and selected profile.'
  }
  return message
}
