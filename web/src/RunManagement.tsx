import { FormEvent, ReactNode, useEffect, useRef, useState } from 'react'
import {
  api, type ActiveProbeStatus, type CampaignReport, type MetadataLab, type PendingInteraction, type Plan,
  type ProtocolEvidenceStatus, type Run, type SupplementalDecryptionKeyStatus, type TargetInitiatedIntent,
  type DefinitionAvailability, type StoredHistoricalState,
} from './api'
import { humanize } from './format'
import { InteractionCard, resolvePrompt } from './InteractionCards'
import { MetadataCampaign, metadataCampaignOpen } from './MetadataCampaign'
import { idpRoundTripReady, idpRoundTripUrl } from './peerUrls'
import { PeerRegistration } from './PeerRegistration'
import { RoundTripLink } from './RoundTripLink'
import { PreflightSummary } from './PreflightSummary'
import { SupplementalDecryptionKeyPanel } from './SupplementalDecryptionKeyPanel'

export { metadataFixtureWork } from './MetadataCampaign'

/** One Run on one page: a single "what to do now" card, then the remaining steps. */
export function RunManagement({ runId, csrfToken, focusCaseId }: {
  runId: string
  csrfToken?: string
  focusCaseId?: string
}) {
  const [interactions, setInteractions] = useState<PendingInteraction[]>([])
  const [activeProbe, setActiveProbe] = useState<ActiveProbeStatus>()
  const [protocolEvidence, setProtocolEvidence] = useState<ProtocolEvidenceStatus>()
  const [campaigns, setCampaigns] = useState<CampaignReport | null>(null)
  const [lab, setLab] = useState<MetadataLab>()
  const [plan, setPlan] = useState<Plan>()
  const [run, setRun] = useState<Run>()
  const [preflightReport, setPreflightReport] = useState<Record<string, unknown>>()
  const [mode, setMode] = useState<'selfhosted' | 'hosted'>('selfhosted')
  const [targetInitiated, setTargetInitiated] = useState<TargetInitiatedIntent | null>(null)
  const [supplementalKeys, setSupplementalKeys] = useState<SupplementalDecryptionKeyStatus>()
  const [supplementalKeysError, setSupplementalKeysError] = useState('')
  const [availability, setAvailability] = useState<DefinitionAvailability>()
  const [stored, setStored] = useState<StoredHistoricalState>()
  const [ecpDelivery, setEcpDelivery] = useState<string[]>([])
  const [started, setStarted] = useState(false)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const [busy, setBusy] = useState('')
  const [loaded, setLoaded] = useState(false)
  const evaluatedState = useRef('')
  const refreshSeq = useRef(0)
  const actSeq = useRef(0)

  const profile = plan?.plan.profile ?? ''
  const isIdp = profile.endsWith('_idp')

  const refresh = async () => {
    const seq = ++refreshSeq.current
    const [workspace, nextRun, plans, health] = await Promise.all([
      api.workspaceEvidence(runId), api.run(runId), api.plans(), api.health(),
    ])
    if (seq !== refreshSeq.current) return // a newer refresh started; do not overwrite it with stale data
    const readOnly = workspace.definitionAvailability?.readOnlyStored === true
      || workspace.definitionAvailability?.definitionAvailable === false
      || workspace.definitionAvailability?.liveEvaluationAvailable === false
    const nextPlan = plans.find(value => value.plan.id === nextRun.planId)
    setAvailability(workspace.definitionAvailability)
    setStored(workspace.storedHistoricalState?.runId === runId ? workspace.storedHistoricalState : undefined)
    setInteractions(workspace.interactions)
    setActiveProbe(workspace.activeProbe)
    setProtocolEvidence(workspace.protocolEvidence)
    setCampaigns(workspace.campaigns)
    setRun(nextRun)
    setPlan(nextPlan)
    setMode(health.mode)
    const eligible = workspace.protocolEvidence?.eligibleCases > 0
    setLab(!readOnly && eligible ? await api.metadataLab(runId).catch(() => undefined) : undefined)
    if (!readOnly && nextPlan?.plan.profile === 'single_logout_idp') {
      try {
        setSupplementalKeys(await api.supplementalDecryptionKeys(runId))
        setSupplementalKeysError('')
      } catch (cause) {
        setSupplementalKeys(undefined)
        setSupplementalKeysError((cause as Error).message)
      }
    } else {
      setSupplementalKeys(undefined)
      setSupplementalKeysError('')
    }
    const supportsTargetInitiated = nextPlan?.plan.profile === 'browser_sso_idp' || nextPlan?.plan.profile === 'single_logout_idp'
    setTargetInitiated(!readOnly && supportsTargetInitiated ? await api.targetInitiated(runId).catch(() => null) : null)
  }
  const refreshQuietly = () => refresh().catch(cause => setError((cause as Error).message))

  useEffect(() => {
    setLoaded(false)
    setError('')
    setNotice('')
    evaluatedState.current = ''
    void refresh().then(() => setLoaded(true)).catch(cause => setError((cause as Error).message))
  }, [runId])

  // Returning from the target's login tab should show the next step without a manual reload.
  useEffect(() => {
    window.addEventListener('focus', refreshQuietly)
    return () => window.removeEventListener('focus', refreshQuietly)
  }, [runId])

  const probeWaiting = activeProbe?.state === 'AWAITING_RESPONSE'
  const waitingForTraffic = probeWaiting || interactions.some(value => value.completionMode === 'TRANSCRIPT')
    || (lab?.ingestionMode === 'AUTOMATIC_POLLING' && !lab.campaignComplete)
  useEffect(() => {
    if (!waitingForTraffic) return
    const timer = setInterval(() => void refreshQuietly(), 5000)
    return () => clearInterval(timer)
  }, [waitingForTraffic, runId])

  const act = async (key: string, work: () => Promise<void>) => {
    const seq = ++actSeq.current
    setBusy(key)
    setError('')
    try { await work() } catch (cause) { setError((cause as Error).message) } finally {
      if (seq === actSeq.current) setBusy('')
    }
  }

  // Evaluate recorded metadata evidence once per distinct state; never in a loop.
  useEffect(() => {
    if (!lab || !protocolEvidence) return
    if (!lab.campaignComplete && protocolEvidence.readyCases === 0) return
    const state = `${lab.campaignComplete}|${protocolEvidence.readyCases}|${lab.campaignIndex}`
    if (evaluatedState.current === state) return
    evaluatedState.current = state
    void act('evaluate', async () => {
      await api.evaluateProtocolEvidence(runId, csrfToken)
      await refresh()
    })
  }, [lab, protocolEvidence])

  const checkSetup = () => act('preflight', async () => {
    setPreflightReport(await api.preflight(runId, csrfToken))
    setNotice('')
    await refresh()
  })

  const startTests = () => act('start-tests', async () => {
    const result = await api.startTests(runId, csrfToken)
    setStarted(true)
    setNotice(result.ecpProbesRequired ? 'Next: run the sign-in check below.' : '')
    await refresh()
  })

  const complete = (interaction: PendingInteraction) => act(interaction.caseId, async () => {
    await api.completeBrowser(runId, interaction.caseId, csrfToken)
    await refresh()
  })

  const answer = (event: FormEvent<HTMLFormElement>, interaction: PendingInteraction) => {
    event.preventDefault()
    const data = new FormData(event.currentTarget)
    const value = String(data.get('value') ?? '')
    const note = String(data.get('note') ?? '')
    return act(interaction.caseId, async () => {
      if (interaction.kind === 'CONFIGURATION') {
        await api.configure(runId, interaction.caseId, value, value === 'confirmed' ? '' : note, csrfToken)
      } else {
        await api.attest(runId, interaction.caseId, value, note, csrfToken)
      }
      await refresh()
    })
  }

  const completeShared = (campaignId: string, actionId: string) => act(`shared-${actionId}`, async () => {
    await api.completeCampaignAction(runId, campaignId, actionId, csrfToken)
    await refresh()
  })

  const prepareTargetInitiated = (kind: TargetInitiatedIntent['kind']) => act('target-initiated', async () => {
    setTargetInitiated(await api.prepareTargetInitiated(runId, kind, csrfToken))
  })

  const probeAction = (kind: 'abort' | 'retry') => act(`probe-${kind}`, async () => {
    if (kind === 'abort') await api.abortActiveProbe(runId, csrfToken)
    else await api.retryActiveProbe(runId, csrfToken)
    await refresh()
  })

  const ecpProbe = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    const form = event.currentTarget
    const data = new FormData(form)
    return act('ecp-probe', async () => {
      const probes = await api.ecpProbe(runId, String(data.get('username') ?? ''), String(data.get('password') ?? ''), csrfToken)
      setEcpDelivery(probes.map(probe => probe.outboxStatus === 'UNKNOWN_DELIVERY'
        ? 'Delivery unknown (not counted as a product failure)' : humanize(probe.outboxStatus)))
      form.reset()
      await api.startTests(runId, csrfToken)
      await refresh()
    })
  }

  const submitKeys = (sourceUri: string, publicKeysSpkiBase64: string[]) => act('supplemental-keys', async () => {
    if (!supplementalKeys) return
    await api.submitSupplementalDecryptionKeys(runId, {
      targetEntityId: supplementalKeys.targetEntityId,
      metadataSha256: supplementalKeys.metadataSha256,
      sourceUri, publicKeysSpkiBase64,
    }, csrfToken)
    await refresh()
  })

  const publish = () => act('publish', async () => {
    const result = await api.publish(runId, csrfToken)
    setNotice(`Published at ${result.publicUrl}`)
  })

  if (!loaded) return error
    ? <section className="page-state" role="alert">
        <h1>Run unavailable</h1>
        <p>{error}</p>
        <button type="button" onClick={() => {
          setError('')
          void refresh().then(() => setLoaded(true)).catch(cause => setError((cause as Error).message))
        }}>Retry</button>
      </section>
    : <section className="page-state" aria-busy="true"><p>Loading…</p></section>

  const encodedRun = encodeURIComponent(runId)
  if (availability?.readOnlyStored || availability?.definitionAvailable === false
    || availability?.liveEvaluationAvailable === false) {
    return <section className="run-page">
      <h1>{plan?.plan.name ?? 'Saved run'}</h1>
      <p className="lead">This run was saved with an earlier test definition and is read-only.
        {' '}No new determination has been made. Start a new test to run again.</p>
      <div className="actions">
        <a className="button" href={`/reports/${encodedRun}`}>Open saved result</a>
        <a className="button button-secondary" href="/">New test</a>
      </div>
      {error && <p className="notice notice-error" role="alert">{error}</p>}
      {stored && stored.slots.length > 0 && <details><summary>{stored.slots.length} saved records</summary>
        <table><thead><tr><th>Case</th><th>Outcome</th></tr></thead>
          <tbody>{stored.slots.map(slot => <tr key={slot.caseId}>
            <td><code>{slot.caseId}</code></td>
            <td>{slot.storedOutcome ? humanize(slot.storedOutcome) : humanize(slot.status)}</td>
          </tr>)}</tbody></table>
      </details>}
    </section>
  }

  const completed = run?.status === 'COMPLETED'
  const setupReady = idpRoundTripReady(run)
  const probeReady = activeProbe?.state === 'READY' && !!activeProbe.startUrl
  const planId = plan?.plan.id ?? ''
  const shown = focusCaseId ? interactions.filter(value => value.caseId === focusCaseId) : interactions

  // Only login/logout-style browser steps may be the primary card. Capability answers and
  // attestations can change or soften a determination, so they stay in collapsed sections.
  const probeCaseId = activeProbe?.state === 'READY' || activeProbe?.state === 'AWAITING_RESPONSE' ? activeProbe.caseId : null
  const browserSteps = shown.filter(value => value.kind === 'BROWSER' && value.caseId !== probeCaseId)
  const capability = shown.filter(value => value.kind === 'CONFIGURATION' && value.completionMode === 'TRANSCRIPT_OR_OPERATOR')
  const operatorSettings = shown.filter(value => value.kind === 'CONFIGURATION' && value.completionMode !== 'TRANSCRIPT_OR_OPERATOR')
  const attestations = shown.filter(value => value.kind === 'ATTESTATION')
  const [firstStep, ...laterSteps] = browserSteps

  const claimed = new Set<string>()
  const sharedActions: Array<{ campaign: CampaignReport['campaigns'][number]; action: CampaignReport['campaigns'][number]['actions'][number]; cases: PendingInteraction[] }> = []
  for (const campaign of (campaigns?.campaigns ?? []).filter(value => value.actionKind === 'CONFIGURATION')) {
    for (const action of campaign.actions.filter(value => value.remainingCaseIds.length > 1)) {
      const cases = operatorSettings.filter(value => action.remainingCaseIds.includes(value.caseId) && !claimed.has(value.caseId))
      if (cases.length < 2) continue
      cases.forEach(value => claimed.add(value.caseId))
      sharedActions.push({ campaign, action, cases })
    }
  }
  const individualSettings = operatorSettings.filter(value => !claimed.has(value.caseId))

  const classifications = campaigns?.classifications ?? []
  const unresolved = classifications.filter(value => !value.resolved).length
  const hasSummary = completed && typeof campaigns?.cases === 'number'
  const metadataOpen = metadataCampaignOpen(lab, protocolEvidence)
  const showMetadata = !!protocolEvidence && (protocolEvidence.eligibleCases > 0 || capability.length > 0)
  const nothingToAsk = !firstStep && !probeReady && !probeWaiting
  const ranBefore = started || classifications.some(value => value.resolved)
  const resultsLink = <a href={`/reports/${encodedRun}`}>See why</a>

  // Exactly one step is promoted to the primary card.
  let primary: ReactNode
  if (focusCaseId && shown.length === 0) {
    primary = <>
      <h2>No action needed for this case</h2>
      <p><a href={`/manage/${encodedRun}`}>Back to the run</a></p>
    </>
  } else if (!setupReady && !completed) {
    primary = <>
      <h2>1. Connect your product</h2>
      <p>Register SAMLscope in your {isIdp ? 'IdP' : 'SP'} using the values below, then check the setup.</p>
      <button disabled={busy !== ''} aria-busy={busy === 'preflight'} onClick={() => void checkSetup()}>
        {busy === 'preflight' ? 'Checking…' : 'Check setup'}
      </button>
    </>
  } else if (!completed) {
    primary = isIdp && plan
      ? <>
          <h2>2. Sign in once</h2>
          <p>Open your IdP, sign in with the test user, then come back to this page.</p>
          <RoundTripLink href={idpRoundTripUrl(plan, runId)} />
        </>
      : <>
          <h2>2. Sign in once</h2>
          <p>Start a login at your SP. This page updates when the response is recorded.</p>
        </>
  } else if (probeReady) {
    primary = <>
      <h2>Open the browser check</h2>
      <p>{activeProbe?.instructionsEn}</p>
      {activeProbe?.requiresFreshSession && <p>Use a private window with no active session at your product.</p>}
      <a className="button" href={activeProbe?.startUrl ?? undefined} target="_blank" rel="noreferrer">Open browser check</a>
    </>
  } else if (probeWaiting) {
    primary = <>
      <h2>Finish in the other tab</h2>
      <p>Complete the sign-in there only if it asks for it. This page continues automatically.</p>
      <div className="actions">
        <button className="button-secondary" disabled={busy !== ''} onClick={() => void probeAction('retry')}>Open again</button>
        <button className="button-secondary" disabled={busy !== ''} onClick={() => void probeAction('abort')}>Nothing came back</button>
      </div>
    </>
  } else if (firstStep) {
    primary = <InteractionCard interaction={firstStep} planId={planId} runId={runId} busy={busy === firstStep.caseId}
      onComplete={complete} onAnswer={answer} lead />
  } else if (campaigns && classifications.length > 0 && ranBefore && unresolved === 0) {
    primary = <>
      <h2>All tests finished</h2>
      <p>Every test has a recorded result. Open the results page for the details.</p>
      <a className="button" href={`/reports/${encodedRun}`}>Results</a>
    </>
  } else if (campaigns && classifications.length > 0 && ranBefore && metadataOpen) {
    primary = <>
      <h2>Metadata refresh tests</h2>
      <p>Start them in the card below. They resolve more tests.</p>
    </>
  } else if (campaigns && classifications.length > 0 && ranBefore) {
    primary = <>
      <h2>Nothing more to ask</h2>
      <p>{unresolved} could not be verified automatically (they stay not verified and count in the total).</p>
      <a className="button" href={`/reports/${encodedRun}`}>Open results</a>
    </>
  } else {
    primary = <>
      <h2>Run the tests</h2>
      <p>Runs every test that can be checked automatically. You are only asked to act when needed.</p>
      <button disabled={busy !== ''} aria-busy={busy === 'start-tests'} onClick={() => void startTests()}>
        {busy === 'start-tests' ? 'Running…' : 'Run tests'}
      </button>
    </>
  }

  const cardProps = (value: PendingInteraction) => ({
    interaction: value, planId, runId, busy: busy === value.caseId, onComplete: complete, onAnswer: answer,
  })
  const opened = !!focusCaseId
  const optionalSettings = sharedActions.length + individualSettings.length

  return <section className="run-page">
    <header className="run-head">
      <div>
        <h1>{plan?.plan.name ?? 'Run'}</h1>
        <p className="muted">{plan ? humanize(plan.plan.profile) : ''}</p>
      </div>
      <a className="button button-secondary" href={`/reports/${encodedRun}`}>Results</a>
    </header>
    {error && <p className="notice notice-error" role="alert">{error}</p>}
    {notice && <p className="notice notice-success" role="status">{notice}</p>}
    <section className="next-step" aria-label="What to do now">{primary}</section>
    {hasSummary && <p className="summary-line" role="status">
      Verified automatically {campaigns.externallyVerifiedCases} · Self-attested {campaigns.selfAttestedCases}
      {' '}· Not verified {campaigns.notVerifiedCases} of {campaigns.cases} {resultsLink}
    </p>}
    {completed && nothingToAsk && ranBefore && <div className="actions">
      <button className="button-secondary" disabled={busy !== ''} onClick={() => void startTests()}>Continue tests</button>
      <p className="muted">Press after you changed your product's settings.</p>
    </div>}
    {laterSteps.length > 0 && <details className="more-steps"><summary>
      {laterSteps.length} more step{laterSteps.length === 1 ? '' : 's'} after this
    </summary>
      <div className="interaction-list">{laterSteps.map(value =>
        <InteractionCard key={value.caseId} {...cardProps(value)} />)}</div>
    </details>}
    {completed && showMetadata && protocolEvidence && <MetadataCampaign runId={runId} planId={planId} csrfToken={csrfToken}
      status={protocolEvidence} lab={lab} setLab={setLab} capability={capability} busy={busy} act={act}
      refresh={refresh} setNotice={setNotice} onAnswer={answer} forceOpen={opened} />}
    {optionalSettings > 0 && <details className="more-steps" open={opened}>
      <summary>Tests that need a product setting change ({optionalSettings}, optional)</summary>
      <div className="interaction-list">
        {sharedActions.map(({ campaign, action, cases }) => <article className="card" key={action.id}>
          <h3>{campaign.title}</h3>
          {cases[0].promptEn && <p className="prompt">{resolvePrompt(cases[0].promptEn, planId, runId)}</p>}
          <p className="muted">{cases.length} tests: {cases.map(value => value.caseId).join(', ')}</p>
          <button disabled={busy !== ''} onClick={() => void completeShared(campaign.id, action.id)}>I made this setting change</button>
          <p className="muted">This only records that you did it; without recorded traffic the cases stay not verified.</p>
        </article>)}
        {individualSettings.map(value => <InteractionCard key={value.caseId} {...cardProps(value)} />)}
      </div>
    </details>}
    {completed && profile === 'ecp_idp' && <form className="card" onSubmit={event => void ecpProbe(event)}>
      <fieldset disabled={busy !== ''}>
        <legend>Sign-in check for ECP</legend>
        <p>Enter your test account. It is kept in memory for this check only and is never stored.</p>
        <label>Username<input required name="username" autoComplete="username" /></label>
        <label>Password<input required name="password" type="password" autoComplete="current-password" /></label>
        <button type="submit">Run check</button>
        {ecpDelivery.length > 0 && <p role="status">{ecpDelivery.join(' · ')}</p>}
      </fieldset>
    </form>}
    {completed && profile === 'browser_sso_idp' && <div className="card">
      <h3>IdP-initiated sign-in</h3>
      {targetInitiated
        ? <p>Waiting for one IdP-initiated sign-in. Use this RelayState: <code>{targetInitiated.runId}</code></p>
        : <><p>Optional check. Prepare it, then start sign-in from your IdP.</p>
            <button className="button-secondary" disabled={busy !== ''} onClick={() => void prepareTargetInitiated('UNSOLICITED_SSO')}>Prepare</button></>}
    </div>}
    {completed && profile === 'single_logout_idp' && <div className="card">
      <h3>Logout from your product</h3>
      {targetInitiated
        ? <p>Waiting for one logout request. Sign out at your product in the same session.</p>
        : <><p>Optional check. Prepare it, then sign out at your product.</p>
            <button className="button-secondary" disabled={busy !== ''} onClick={() => void prepareTargetInitiated('TARGET_LOGOUT')}>Prepare</button></>}
    </div>}
    {supplementalKeys
      ? <SupplementalDecryptionKeyPanel status={supplementalKeys} busy={busy === 'supplemental-keys'}
          error={supplementalKeysError} onSubmit={submitKeys} />
      : profile === 'single_logout_idp' && supplementalKeysError
        ? <p className="notice notice-error" role="alert">{supplementalKeysError}</p> : null}
    <PreflightSummary roundTripComplete={completed}
      report={preflightReport ?? run?.context?.preflight as Record<string, unknown> | undefined} />
    {plan && <details className="setup-details" open={!setupReady && !completed}>
      <summary>Connection details</summary>
      <PeerRegistration plan={plan} />
    </details>}
    {attestations.length > 0 && <details className="more-steps" open={opened}>
      <summary>Self-attestation ({attestations.length}, optional)</summary>
      <div className="interaction-list">{attestations.map(value =>
        <InteractionCard key={value.caseId} {...cardProps(value)} />)}</div>
    </details>}
    {mode === 'hosted' && <div className="actions">
      <button className="button-secondary" disabled={busy === 'publish'} onClick={() => void publish()}>Publish result</button>
    </div>}
  </section>
}
