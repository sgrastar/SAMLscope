import { FormEvent, useEffect, useMemo, useRef, useState } from 'react'
import { createPortal } from 'react-dom'
import {
  api, type ActiveProbeStatus, type BootstrapContract, type MetadataLab, type PendingInteraction, type Plan,
  type ProtocolEvidenceStatus, type CampaignReport, type Run,
} from './api'
import { formatDate, humanize } from './format'
import { idpRoundTripReady, idpRoundTripUrl } from './peerUrls'
import { PeerRegistration } from './PeerRegistration'
import { RoundTripLink } from './RoundTripLink'
import { PreflightSummary } from './PreflightSummary'

export function RunManagement({ runId, csrfToken, focusCaseId, navigateTo }: {
  runId: string
  csrfToken?: string
  focusCaseId?: string
  navigateTo?: (url: string) => void
}) {
  const launch = navigateTo ?? ((url: string) => window.location.assign(url))
  const [interactions, setInteractions] = useState<PendingInteraction[]>([])
  const [bootstrapContracts, setBootstrapContracts] = useState<BootstrapContract[]>([])
  const [metadataLab, setMetadataLab] = useState<MetadataLab>()
  const [protocolEvidence, setProtocolEvidence] = useState<ProtocolEvidenceStatus>()
  const [activeProbe, setActiveProbe] = useState<ActiveProbeStatus>()
  const [campaigns, setCampaigns] = useState<CampaignReport>()
  const [error, setError] = useState('')
  const [initialLoadComplete, setInitialLoadComplete] = useState(false)
  const [busy, setBusy] = useState('')
  const [planId, setPlanId] = useState('')
  const [profile, setProfile] = useState('')
  const [plan, setPlan] = useState<Plan>()
  const [runSummary, setRunSummary] = useState<Run>()
  const [notice, setNotice] = useState('')
  const [preflightReport, setPreflightReport] = useState<Record<string, unknown>>()
  const [mode, setMode] = useState<'selfhosted' | 'hosted'>('selfhosted')
  const [pollingDelaySeconds, setPollingDelaySeconds] = useState(15)
  const [sectionCaseChoices, setSectionCaseChoices] = useState<Record<string, string>>({})
  const [caseQuery, setCaseQuery] = useState('')
  const [caseScope, setCaseScope] = useState<'attention' | 'all' | 'not_verified'>('attention')
  const [planFilter, setPlanFilter] = useState<'ALL' | 'QUICK' | 'STANDARD' | 'FULL'>('ALL')
  const [evidenceFilters, setEvidenceFilters] = useState<Record<EvidenceClass, boolean>>({
    PROTOCOL_OBSERVED: true,
    OPERATOR_ASSISTED: true,
    SELF_ATTESTED: true,
  })
  const [selectedCaseId, setSelectedCaseId] = useState<string>()
  const [caseDrawerOpen, setCaseDrawerOpen] = useState(false)
  const caseDrawerRef = useRef<HTMLElement | null>(null)
  const caseDrawerCloseRef = useRef<HTMLButtonElement>(null)
  const lastCaseTriggerRef = useRef<HTMLButtonElement | null>(null)
  const selfCheckSections = !focusCaseId && campaigns
    ? campaigns.campaigns.filter(campaign => campaign.evidenceClass === 'SELF_ATTESTED')
      .map(campaign => ({
        campaign,
        interactions: interactions.filter(interaction => campaign.remainingCaseIds.includes(interaction.caseId)),
      }))
      .filter(section => section.interactions.length > 0)
    : []
  const groupedSelfCheckCases = new Set(selfCheckSections.flatMap(section =>
    section.interactions.map(interaction => interaction.caseId)))
  const sharedOperatorActions = !focusCaseId && campaigns
    ? campaigns.campaigns.filter(campaign => campaign.actionKind === 'CONFIGURATION')
      .flatMap(campaign => campaign.actions
        .filter(action => action.remainingCaseIds.length > 1)
        .map(action => ({
          campaign,
          action,
          interactions: interactions.filter(interaction => action.remainingCaseIds.includes(interaction.caseId)),
        })))
      .filter(section => section.interactions.length > 1)
    : []
  const groupedOperatorCases = new Set(sharedOperatorActions.flatMap(section =>
    section.interactions.map(interaction => interaction.caseId)))
  const bootstrapCases = new Set(bootstrapContracts.flatMap(contract => contract.caseIds))
  const activeProbeCaseId = activeProbe?.state === 'READY' || activeProbe?.state === 'AWAITING_RESPONSE'
    ? activeProbe.caseId
    : undefined
  const visibleInteractions = focusCaseId
    ? interactions.filter(interaction => interaction.caseId === focusCaseId)
    : interactions.filter(interaction => !groupedSelfCheckCases.has(interaction.caseId)
      && !groupedOperatorCases.has(interaction.caseId)
      && !(interaction.kind === 'CONFIGURATION' && bootstrapCases.has(interaction.caseId))
      && interaction.caseId !== activeProbeCaseId)
  const configurationInteractions = interactions.filter(interaction => interaction.kind === 'CONFIGURATION')
  const metadataWork = metadataFixtureWork(protocolEvidence)
  const interactionText = useMemo(() => new Map(interactions.map(interaction => [interaction.caseId,
    [interaction.promptEn, ...(interaction.answerValues ?? [])].filter(Boolean).join(' ')])), [interactions])
  const caseWorkspace = useMemo(() => campaignWorkspace(campaigns, {
    query: caseQuery,
    scope: caseScope,
    plan: planFilter,
    evidence: evidenceFilters,
  }, interactionText), [campaigns, caseQuery, caseScope, planFilter, evidenceFilters, interactionText])
  const caseWorkspaceCount = caseWorkspace.reduce((count, group) => count + group.cases.length, 0)
  const selectedCaseIsVisible = caseWorkspace.some(group => group.cases.some(value => value.caseId === selectedCaseId))
  const selectedCase = selectedCaseIsVisible
    ? campaigns?.classifications?.find(value => value.caseId === selectedCaseId)
    : undefined
  const selectedCaseCampaign = campaigns?.campaigns.find(value => value.id === selectedCase?.campaignId)
  const selectedInteraction = interactions.find(value => value.caseId === selectedCase?.caseId)
  const hasActiveProbe = activeProbe?.state === 'READY' || activeProbe?.state === 'AWAITING_RESPONSE'

  const refresh = async () => {
    // Hosted evidence reads share one lock and one rate-limit admission.
    const [workspace, lab, run, plans, health] = await Promise.all([
      api.workspaceEvidence(runId), api.metadataLab(runId),
      api.run(runId), api.plans(), api.health(),
    ])
    const { interactions: nextInteractions, bootstrapContracts: contracts,
      protocolEvidence: evidence, activeProbe: probe, campaigns: campaignReport } = workspace
    setInteractions(nextInteractions)
    setBootstrapContracts(contracts)
    setMetadataLab(lab)
    setProtocolEvidence(evidence)
    setActiveProbe(probe)
    if (Array.isArray(campaignReport?.plans)) setCampaigns(campaignReport)
    setRunSummary(run)
    setPlanId(run.planId)
    const selectedPlan = plans.find(value => value.plan.id === run.planId)
    setPlan(selectedPlan)
    setProfile(selectedPlan?.plan.profile ?? '')
    setMode(health.mode)
  }

  useEffect(() => {
    setInitialLoadComplete(false)
    setError('')
    void refresh().then(() => setInitialLoadComplete(true)).catch(cause => setError((cause as Error).message))
  }, [runId])

  useEffect(() => {
    if (!caseDrawerOpen) return
    const previousOverflow = document.body.style.overflow
    const workspaceRoot = document.querySelector<HTMLElement>('.management.workspace')
    document.body.style.overflow = 'hidden'
    workspaceRoot?.setAttribute('inert', '')
    const closeOnEscape = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        setCaseDrawerOpen(false)
        requestAnimationFrame(() => lastCaseTriggerRef.current?.focus())
        return
      }
      if (event.key === 'Tab') {
        const focusable = [...(caseDrawerRef.current?.querySelectorAll<HTMLElement>(
          'a[href], button:not(:disabled), input:not(:disabled), select:not(:disabled), textarea:not(:disabled), [tabindex]:not([tabindex="-1"])',
        ) ?? [])].filter(value => value.getAttribute('aria-hidden') !== 'true')
        if (focusable.length === 0) return
        const first = focusable[0]
        const last = focusable[focusable.length - 1]
        if (event.shiftKey && document.activeElement === first) {
          event.preventDefault()
          last.focus()
        } else if (!event.shiftKey && document.activeElement === last) {
          event.preventDefault()
          first.focus()
        }
      }
    }
    document.addEventListener('keydown', closeOnEscape)
    requestAnimationFrame(() => caseDrawerCloseRef.current?.focus())
    return () => {
      document.body.style.overflow = previousOverflow
      workspaceRoot?.removeAttribute('inert')
      document.removeEventListener('keydown', closeOnEscape)
    }
  }, [caseDrawerOpen])

  useEffect(() => {
    if (caseDrawerOpen && !selectedCase) {
      setCaseDrawerOpen(false)
      requestAnimationFrame(() => lastCaseTriggerRef.current?.focus())
    }
  }, [caseDrawerOpen, selectedCase])

  const retryInitialLoad = async () => {
    setError('')
    try {
      await refresh()
      setInitialLoadComplete(true)
    } catch (cause) {
      setError((cause as Error).message)
    }
  }

  const closeCaseDrawer = () => {
    setCaseDrawerOpen(false)
    requestAnimationFrame(() => lastCaseTriggerRef.current?.focus())
  }

  const attest = async (event: FormEvent<HTMLFormElement>, interaction: PendingInteraction) => {
    event.preventDefault()
    const data = new FormData(event.currentTarget)
    const value = String(data.get('value') ?? '')
    const note = String(data.get('note') ?? '')
    setBusy(interaction.caseId)
    setError('')
    try {
      await api.attest(runId, interaction.caseId, value, note, csrfToken)
      await refresh()
    } catch (cause) {
      setError((cause as Error).message)
    } finally {
      setBusy('')
    }
  }

  const configure = async (event: FormEvent<HTMLFormElement>, interaction: PendingInteraction) => {
    event.preventDefault()
    const data = new FormData(event.currentTarget)
    const value = String(data.get('value') ?? '')
    const note = value === 'confirmed' ? '' : String(data.get('note') ?? '')
    setBusy(interaction.caseId)
    setError('')
    try {
      await api.configure(runId, interaction.caseId, value, note, csrfToken)
      await refresh()
    } catch (cause) {
      setError((cause as Error).message)
    } finally {
      setBusy('')
    }
  }

  const completeBrowser = async (interaction: PendingInteraction) => {
    setBusy(interaction.caseId)
    setError('')
    try {
      await api.completeBrowser(runId, interaction.caseId, csrfToken)
      await refresh()
    } catch (cause) {
      setError((cause as Error).message)
    } finally {
      setBusy('')
    }
  }

  const completeSharedOperatorAction = async (
    campaignId: string, actionId: string, caseCount: number,
  ) => {
    const key = `${campaignId}:${actionId}`
    setBusy(key)
    setError('')
    try {
      await api.completeCampaignAction(runId, campaignId, actionId, csrfToken)
      setNotice(`Recorded one shared target operation for ${caseCount} cases. No target outcome was supplied; cases without external evidence remain not verified.`)
      await refresh()
    } catch (cause) {
      setError((cause as Error).message)
    } finally {
      setBusy('')
    }
  }

  const submitSelfCheckSection = async (
    event: FormEvent<HTMLFormElement>,
    section: (typeof selfCheckSections)[number],
  ) => {
    event.preventDefault()
    const data = new FormData(event.currentTarget)
    const note = String(data.get('shared-note') ?? '')
    const sectionConclusion = String(data.get('section-conclusion') ?? '')
    if (!sectionConclusion) {
      setError(`Choose one evidence conclusion for ${section.campaign.title}.`)
      return
    }
    if (sectionConclusion !== 'unable_to_verify' && !note.trim()) {
      setError(`Identify the shared evidence for ${section.campaign.title}.`)
      return
    }
    setBusy(section.campaign.id)
    setError('')
    try {
      for (const interaction of section.interactions) {
        const conclusion = String(data.get(`override:${interaction.caseId}`) ?? '') || sectionConclusion
        if (interaction.kind === 'CONFIGURATION') {
          const configuration = conclusion === 'unable_to_verify' ? 'capability_undetermined' : 'confirmed'
          await api.configure(runId, interaction.caseId, configuration,
            configuration === 'confirmed' ? '' : note, csrfToken)
          if (configuration === 'confirmed') {
            await api.attest(runId, interaction.caseId,
              conclusion === 'satisfied' ? 'evidence_satisfies' : 'evidence_violates', note, csrfToken)
          }
        } else if (interaction.kind === 'ATTESTATION') {
          await api.attest(runId, interaction.caseId, attestationValue(interaction, conclusion), note, csrfToken)
        }
      }
      setNotice(`Recorded the ${section.campaign.title} evidence section. Each case retained its own server-defined outcome mapping.`)
      await refresh()
    } catch (cause) {
      setError((cause as Error).message)
      await refresh().catch(() => undefined)
    } finally {
      setBusy('')
    }
  }

  const startM1 = async () => {
    setBusy('quick-check')
    setError('')
    try {
      await api.quickCheck(runId, csrfToken)
      await refresh()
    } catch (cause) {
      setError((cause as Error).message)
    } finally {
      setBusy('')
    }
  }

  const abortActiveProbe = async () => {
    setBusy('active-probe-abort')
    setError('')
    try {
      await api.abortActiveProbe(runId, csrfToken)
      setNotice('No correlated SAML Response was returned. This fixture was marked unavailable, never as a target failure; any remaining scenario controls will continue.')
      await refresh()
    } catch (cause) {
      setError((cause as Error).message)
    } finally {
      setBusy('')
    }
  }

  const retryActiveProbe = async () => {
    setBusy('active-probe-retry')
    setError('')
    try {
      await api.retryActiveProbe(runId, csrfToken)
      setNotice('A new one-time fixture was issued. The uncertain prior delivery remains recorded and is not replayed.')
      await refresh()
    } catch (cause) {
      setError((cause as Error).message)
    } finally {
      setBusy('')
    }
  }

  const runPreflight = async () => {
    setBusy('preflight')
    setError('')
    try {
      const report = await api.preflight(runId, csrfToken)
      setPreflightReport(report)
      setNotice('Setup checks finished. Review the preflight results below for the next step.')
      await refresh()
    } catch (cause) {
      setError((cause as Error).message)
    } finally {
      setBusy('')
    }
  }

  const startMilestone = async (milestone: 'M2' | 'M3') => {
    setBusy(milestone)
    setError('')
    try {
      await api.startMilestone(runId, milestone, csrfToken)
      await refresh()
    } catch (cause) {
      setError((cause as Error).message)
    } finally {
      setBusy('')
    }
  }

  const runEcpProbe = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    const form = event.currentTarget
    const data = new FormData(form)
    setBusy('ecp-probe')
    setError('')
    setNotice('')
    try {
      await api.ecpProbe(runId, String(data.get('username') ?? ''), String(data.get('password') ?? ''), csrfToken)
      form.reset()
      setNotice('The baseline ECP exchange, five channel-binding controls, and the SAML-EC session-key probe were recorded. M3 can now evaluate the transcript.')
    } catch (cause) {
      setError((cause as Error).message)
    } finally {
      setBusy('')
    }
  }

  const publish = async () => {
    setBusy('publish')
    setError('')
    try {
      const result = await api.publish(runId, csrfToken)
      setNotice(`Published at ${result.publicUrl}`)
    } catch (cause) {
      setError((cause as Error).message)
    } finally {
      setBusy('')
    }
  }

  const selectMetadataVariant = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    const variant = String(new FormData(event.currentTarget).get('variant') ?? '')
    setBusy('metadata-variant')
    setError('')
    try {
      const selected = await api.selectMetadataVariant(runId, variant, csrfToken)
      setMetadataLab(selected)
      setNotice(`Metadata fixture selected: ${selected.selectedVariant}. The stable metadata URL did not change.`)
    } catch (cause) {
      setError((cause as Error).message)
    } finally {
      setBusy('')
    }
  }

  const selectNextMetadataFixture = async () => {
    if (!metadataWork.nextVariant) return
    setBusy('metadata-next')
    setError('')
    try {
      const selected = await api.selectMetadataVariant(runId, metadataWork.nextVariant, csrfToken)
      setMetadataLab(selected)
      setNotice(`Next incomplete metadata fixture selected: ${selected.selectedVariant}. Trigger the target's normal refresh or re-import, then attempt the required SAML flow.`)
    } catch (cause) {
      setError((cause as Error).message)
    } finally {
      setBusy('')
    }
  }

  const startAutomaticMetadataPolling = async () => {
    if (metadataWork.pendingVariants.length === 0) return
    setBusy('metadata-auto')
    setError('')
    try {
      const selected = await api.startAutomaticMetadataPolling(
        runId, metadataWork.pendingVariants, pollingDelaySeconds, csrfToken)
      setMetadataLab(selected)
      if (!selected.automaticStartUrl) throw new Error('The automatic metadata campaign did not return a start URL.')
      setNotice(`Automatic metadata polling armed with ${selected.campaignVariants.length} fixtures. Opening the first signed browser flow now; leave the stable metadata URL configured.`)
      launch(selected.automaticStartUrl)
    } catch (cause) {
      setError((cause as Error).message)
    } finally {
      setBusy('')
    }
  }

  const startPreloadedMetadataCampaign = async () => {
    setBusy('metadata-preloaded')
    setError('')
    try {
      const selected = await api.startPreloadedMetadataCampaign(runId, csrfToken)
      setMetadataLab(selected)
      setNotice(`Preloaded aggregate prepared with ${selected.preloadedVariants.length} compatible positive fixtures. Import its URL once, then return here to run the correlated browser sequence.`)
    } catch (cause) {
      setError((cause as Error).message)
    } finally {
      setBusy('')
    }
  }

  const useManualMetadataRefresh = async () => {
    setBusy('metadata-manual')
    setError('')
    try {
      const selected = await api.useManualMetadataRefresh(runId, csrfToken)
      setMetadataLab(selected)
      setNotice('Manual metadata refresh restored. Select each remaining fixture only when the target cannot poll the stable URL.')
      await refresh()
    } catch (cause) {
      setError((cause as Error).message)
    } finally {
      setBusy('')
    }
  }

  const evaluateProtocolEvidence = async () => {
    setBusy('protocol-evidence')
    setError('')
    try {
      const evaluation = await api.evaluateProtocolEvidence(runId, csrfToken)
      const completed = evaluation.completed.map(value => `${value.caseId}: ${value.outcome}`)
      setNotice(completed.length > 0
        ? `Evaluated recorded protocol evidence: ${completed.join(', ')}.`
        : 'No evidence-driven case is ready. Complete the listed fixture fetches and correlated SAML attempts first.')
      await refresh()
    } catch (cause) {
      setError((cause as Error).message)
    } finally {
      setBusy('')
    }
  }

  const confirmProtocolEvidenceAttempts = async () => {
    setBusy('protocol-attempts')
    setError('')
    try {
      const evaluation = await api.confirmProtocolEvidenceAttempts(runId, csrfToken)
      const completed = evaluation.completed.map(value => `${value.caseId}: ${value.outcome}`)
      setNotice(completed.length > 0
        ? `Completed the metadata campaign from recorded evidence: ${completed.join(', ')}.`
        : 'No pending metadata campaign cases were found.')
      await refresh()
    } catch (cause) {
      setError((cause as Error).message)
    } finally {
      setBusy('')
    }
  }

  const interactionCard = (interaction: PendingInteraction) => <article key={interaction.caseId} className="interaction">
    <header><strong>{interaction.caseId}</strong><span>{interaction.kind}</span></header>
    {interaction.promptEn && <pre>{resolvePrompt(interaction.promptEn, planId, runId)}</pre>}
    {interaction.kind === 'BROWSER' && <div className="actions">
      {interaction.startUrl && <a className="button" href={interaction.startUrl}>Open focused browser step</a>}
      {interaction.completionMode === 'TRANSCRIPT'
        ? <p>Waiting for the required correlated Transcript evidence. No completion answer is needed.</p>
        : <button disabled={busy === interaction.caseId} onClick={() => void completeBrowser(interaction)}>
            Browser steps completed
          </button>}
    </div>}
    {interaction.kind === 'ATTESTATION' && <form onSubmit={event => void attest(event, interaction)}>
      <fieldset disabled={busy === interaction.caseId}>
        <legend>Evidence conclusion</legend>
        {interaction.answerValues.map(value => <label className="radio" key={value}>
          <input required type="radio" name="value" value={value} />{humanize(value)}
        </label>)}
        <label>Evidence note<textarea name="note" maxLength={4000} placeholder="Identify the observed UI, log, trace, or other evidence." /></label>
        <button type="submit">Record attestation</button>
      </fieldset>
    </form>}
    {interaction.kind === 'CONFIGURATION' && <form onSubmit={event => void configure(event, interaction)}>
      <fieldset disabled={busy === interaction.caseId}>
        <legend>{interaction.completionMode === 'TRANSCRIPT_OR_OPERATOR'
          ? 'Automatic protocol evidence with manual unavailability fallback'
          : 'Manual configuration input'}</legend>
        {interaction.completionMode === 'TRANSCRIPT_OR_OPERATOR' && <p>
          This case completes automatically when all required correlated Transcript evidence is present.
          Use the answers below only when the target capability or required setup cannot be exercised.
        </p>}
        {interaction.answerValues.map(value => <label className="radio" key={value}>
          <input required type="radio" name="value" value={value} />{humanize(value)}
        </label>)}
        <label>Unavailability note<textarea name="note" maxLength={4000} placeholder="Required unless the configuration was confirmed." /></label>
        <button type="submit">Continue case</button>
      </fieldset>
    </form>}
    <small>Expires {formatDate(interaction.expiresAt, 'Unknown')}</small>
  </article>

  const activeProbePanel = activeProbe?.state === 'READY' && activeProbe.startUrl
    ? <article className="interaction active-probe">
        <header><strong>{activeProbe.caseId ?? 'Browser-assisted SAML scenario'}</strong><span>AUTOMATED ORACLE</span></header>
        <p>{activeProbe.instructionsEn}</p>
        {activeProbe.requiresFreshSession && <p>The first IsPassive probe must start in a private browser context with no active target session.</p>}
        <a className="button" href={activeProbe.startUrl}>Open scenario</a>
      </article>
    : activeProbe?.state === 'AWAITING_RESPONSE'
      ? <article className="interaction active-probe">
          <header><strong>{activeProbe.caseId ?? 'Browser-assisted SAML scenario'}</strong><span>WAITING</span></header>
          <p>The request was dispatched. Complete target login or consent in that browser. SAMLscope will continue automatically after a correlated SAML Response.</p>
          <button disabled={busy === 'active-probe-retry'} onClick={() => void retryActiveProbe()}>
            Reissue this one-time fixture
          </button>
          <button disabled={busy === 'active-probe-abort'} onClick={() => void abortActiveProbe()}>
            No SAML Response was returned
          </button>
        </article>
      : null

  if (!initialLoadComplete) return error ? <section className="run-load-state" role="alert">
    <p className="eyebrow">Run workspace</p>
    <h1>Run unavailable</h1>
    <p>SAMLscope could not load the complete Run state. No Run actions are available until all required data loads successfully.</p>
    <pre>{error}</pre>
    <button type="button" onClick={() => void retryInitialLoad()}>Retry loading Run</button>
  </section> : <section className="report-skeleton run-workspace-skeleton" aria-label="Loading Run workspace" aria-busy="true">
    <span /><span /><span /><span />
  </section>

  return <section className="management workspace">
    <header className="workspace-masthead">
      <div>
        <p className="eyebrow">Run workspace</p>
        <h1>{plan?.plan.name ?? 'Loading Run'}</h1>
        <p className="workspace-context">
          {plan && <a href={`/?plan=${encodeURIComponent(plan.plan.id)}`}>{humanize(plan.plan.profile)}</a>}
          <code>{runId}</code>
        </p>
      </div>
      <div className="workspace-state">
        <div><span className={`run-status status-${(runSummary?.status ?? 'created').toLowerCase()}`}>
          {humanize(runSummary?.status ?? 'CREATED')}
        </span></div>
        <span>{interactions.length} pending interaction{interactions.length === 1 ? '' : 's'}</span>
        {campaigns && <div className="workspace-evidence-summary" aria-label="Evidence summary">
          <span className="evidence-observed-text"><strong>{campaigns.externallyVerifiedCases}</strong> externally verified</span>
          <span className="evidence-attested-text"><strong>{campaigns.selfAttestedCases}</strong> self-attested</span>
          <span className="evidence-unverified-text"><strong>{campaigns.notVerifiedCases}</strong> not verified</span>
        </div>}
        <details className="export-menu"><summary>Export / report</summary><div>
          <a href={`/api/runs/${runId}/result.json`} download>Download result.json</a>
          <a href={`/api/runs/${runId}/report.html`} download>Download report.html</a>
          <a href={`/reports/${runId}`}>Open current result</a>
        </div></details>
      </div>
    </header>
    {campaigns && <nav className="plan-progress" aria-label="Filter cases by evidence plan">
      <button type="button" className={`plan-progress-card${planFilter === 'ALL' ? ' selected' : ''}`}
        aria-pressed={planFilter === 'ALL'} onClick={() => setPlanFilter('ALL')}>
        <span>All plans</span><strong>{campaigns.cases}</strong><small>approved cases</small>
      </button>
      {campaigns.plans.map(value =>
      <button type="button" className={`plan-progress-card plan-${value.plan.toLowerCase()}${planFilter === value.plan ? ' selected' : ''}`}
        aria-pressed={planFilter === value.plan} onClick={() => setPlanFilter(value.plan)} key={value.plan}>
        <span>{humanize(value.plan)}</span><strong>{value.remainingUserActions}</strong>
        <small>actions remaining · {value.estimatedMinutesMin}-{value.estimatedMinutesMax} min</small>
        <progress max={Math.max(value.deliberateUserActions, 1)}
          value={Math.max(value.deliberateUserActions - value.remainingUserActions, 0)} />
      </button>)}</nav>}
    <section className="run-next-step" aria-label="Run setup steps">
      <h2>What to do next</h2>
      <ol>
        <li><strong>Register the Test Peer.</strong> Follow the registration guide below in your target product.</li>
        <li><strong>Run preflight.</strong> Check that SAMLscope can retrieve the target metadata.</li>
        <li><strong>Complete one login.</strong> {profile.startsWith('IDP') ? 'Open the IdP, sign in with a test user, then return to this Run.' : 'Start login at your target SP and return to this Run after the response is recorded.'}</li>
        <li><strong>Run the initial checks (M1).</strong> Then follow Pending interactions. M2 and M3 are additional test stages, not setup buttons.</li>
      </ol>
      <p className="notice">{runSummary?.status === 'COMPLETED'
        ? 'Next: run the initial checks (M1), then complete the pending interactions. A recorded response is not a conformance PASS.'
        : idpRoundTripReady(runSummary)
          ? 'Next: complete the login round trip. If you already opened the IdP, finish that login before starting another.'
          : 'Next: register the metadata below, then select Run preflight.'}</p>
    </section>
    <PreflightSummary roundTripComplete={runSummary?.status === 'COMPLETED'} report={preflightReport ?? runSummary?.context?.preflight as Record<string, unknown> | undefined} />
    <div className="workspace-actionbar">
      <div className="actions">
        <button disabled={busy !== ''} aria-busy={busy === 'preflight'} onClick={() => void runPreflight()}>
          {busy === 'preflight' && <span className="button-spinner" aria-hidden="true" />}Run preflight</button>
        {plan && profile.startsWith('IDP') && idpRoundTripReady(runSummary) && runSummary?.status !== 'COMPLETED'
          && <RoundTripLink href={idpRoundTripUrl(plan, runId)} />}
        <button disabled={busy !== '' || runSummary?.status !== 'COMPLETED'} onClick={() => void startM1()}>Start or resume M1</button>
        <details className="additional-stages"><summary>Additional test stages (M2 / M3)</summary>
          <p>Continue here after the initial round trip and M1. Follow each stage’s prerequisites and pending instructions.</p>
          <button disabled={busy !== ''} onClick={() => void startMilestone('M2')}>Start or resume M2</button>
          <button disabled={busy !== ''} onClick={() => void startMilestone('M3')}>Start or resume M3</button>
        </details>
      </div>
      <div className="actions">
        <button className="button-secondary" onClick={() => void refresh()}>Refresh</button>
        <a className="button button-secondary" href={`/reports/${runId}`}>Open current result</a>
      </div>
    </div>
    {activeProbePanel}
    {error && <aside className="notice notice-error" role="alert">{error}</aside>}
    {notice && <aside className="notice notice-success" role="status">{notice}</aside>}
    {plan && <PeerRegistration plan={plan} />}
    {!focusCaseId && bootstrapContracts.length > 0 && <section className="bootstrap-contracts">
      <p className="eyebrow">One-time environment bootstrap</p>
      <h2>Shared setup contracts</h2>
      <p>These contracts replace repeated product-specific setup questions. SAMLscope uses standard SAML metadata and protocol traffic; it does not call a vendor Admin API.</p>
      <div className="contract-list">{bootstrapContracts.map(contract => <article className="contract" key={contract.id}>
        <header><div><strong>{contract.title}</strong><p>{contract.description}</p></div><span>{humanize(contract.readiness)}</span></header>
        <p>{contract.setupInstruction}</p>
        {contract.setupUrl && <dl><dt>Stable setup URL</dt><dd><code>{contract.setupUrl}</code></dd></dl>}
        {contract.kind === 'STANDARD_METADATA' && metadataLab && <form className="fixture-selector" onSubmit={selectMetadataVariant}>
          <label>Suite metadata fixture<select name="variant" value={metadataLab.selectedVariant}
            onChange={event => setMetadataLab(current => current
              ? { ...current, selectedVariant: event.target.value } : current)}>
            {metadataLab.availableVariants.map(variant => <option key={variant} value={variant}>{humanize(variant)}</option>)}
          </select></label>
          <button disabled={busy === 'metadata-variant'} type="submit">Select behind stable URL</button>
        </form>}
        {contract.kind === 'STANDARD_METADATA' && protocolEvidence && protocolEvidence.eligibleCases > 0 && <div className="protocol-evidence">
          <p><strong>{protocolEvidence.eligibleCases}</strong> currently implemented case{protocolEvidence.eligibleCases === 1 ? '' : 's'} can derive outcomes directly from metadata fetches and correlated SAML traffic; <strong>{protocolEvidence.readyCases}</strong> ready now.</p>
          <p>SAMLscope normally evaluates these cases automatically as Transcript evidence arrives. Because a public metadata fetch does not identify its caller, use the recovery action only after you triggered the target's normal refresh or re-import and attempted the listed SAML flows.</p>
          <div className="standard-work-queue">
            <p><strong>Standard work queue:</strong> {metadataWork.completedFixtures}/{metadataWork.totalFixtures} fixture fetches recorded.</p>
            {metadataLab?.ingestionMode === 'AUTOMATIC_POLLING' ? <>
              <p><strong>Automatic polling:</strong> {metadataLab.campaignIndex}/{metadataLab.campaignVariants.length} fixtures completed{metadataLab.campaignComplete ? '. Campaign complete.' : `; currently serving ${humanize(metadataLab.selectedVariant)}.`}</p>
              <p><strong>Operator continuations:</strong> {metadataLab.operatorContinuationActions}</p>
              <p><small>SAMLscope waits {metadataLab.pollingDelaySeconds} seconds between successful fixtures so the target's ordinary metadata-key refresh window can elapse. The delay changes orchestration only, never the outcome.</small></p>
              {!metadataLab.campaignComplete && metadataLab.automaticStartUrl && <a
                className="button" href={metadataLab.automaticStartUrl} target="_blank" rel="noreferrer">
                Start or resume the signed metadata campaign
              </a>}
              {metadataLab.automaticContinueUrl && <>
                <form action={metadataLab.automaticContinueUrl} method="post" target="_blank">
                  <button type="submit">Continue after the Target displayed its result</button>
                </form>
                <p><small>This only advances orchestration after the browser attempt. It does not claim that the Target fetched or used metadata and does not mark the Target satisfied or violated; missing observations remain not verified.</small></p>
              </>}
              <p><small>The fixture uses a distinct test signing key. A target that refreshes its configured metadata URL on an unknown key can fetch and validate without repeated imports. SAMLscope holds the document stable across duplicate fetches and advances after the correlated browser result. A target that does not refresh remains unresolved and can use the aggregate or manual queue.</small></p>
              <button disabled={busy === 'metadata-manual'} onClick={() => void useManualMetadataRefresh()}>
                Return to manual refresh
              </button>
            </> : metadataLab?.ingestionMode === 'PRELOADED_AGGREGATE' ? <>
              <p><strong>One-time positive aggregate:</strong> {metadataLab.preloadedVariants.length} compatible fixtures in one signed metadata document.</p>
              {metadataLab.preloadedMetadataUrl && <>
                <dl><dt>Import once</dt><dd><code>{metadataLab.preloadedMetadataUrl}</code></dd></dl>
              </>}
              {metadataLab.preloadedDownloadUrl && <a className="button"
                href={metadataLab.preloadedDownloadUrl} download="samlscope-metadata-campaign.xml">
                  Download signed aggregate XML
              </a>}
              <p>{metadataLab.preloadedFetched
                ? 'A Target fetch of the aggregate URL was recorded. Run the browser sequence; SAMLscope reuses the session and advances through the imported entities automatically.'
                : 'Import the downloaded file or let the Target fetch the URL through its ordinary metadata interface. Downloading is not counted as a Target fetch; correlated SAML responses prove actual use.'}</p>
              {metadataLab.preloadedStartUrl && <a className="button" href={metadataLab.preloadedStartUrl} target="_blank" rel="noreferrer">
                Run {metadataLab.preloadedVariants.length} preloaded SAML flows
              </a>}
              <button disabled={busy === 'metadata-manual'} onClick={() => void useManualMetadataRefresh()}>
                Return to manual refresh
              </button>
            </> : metadataWork.pendingVariants.length > 0 && <>
              <button disabled={busy === 'metadata-preloaded'} onClick={() => void startPreloadedMetadataCampaign()}>
                Prepare one-time aggregate for compatible positive fixtures
              </button>
              <p><small>Use this for static-import products that accept an EntitiesDescriptor containing multiple SP entities. Incompatible root, redirect, duplicate, expired, unsigned, and bad-signature fixtures remain separate.</small></p>
              <button disabled={busy === 'metadata-auto'} onClick={() => void startAutomaticMetadataPolling()}>
                Arm automatic polling for {metadataWork.pendingVariants.length} fixtures
              </button>
              <label>Seconds between signed fixtures
                <input type="number" min="0" max="900" value={pollingDelaySeconds}
                  onChange={event => setPollingDelaySeconds(Number(event.target.value))} />
              </label>
              <p><small>Use this when the target periodically retrieves the same metadata URL or refreshes it when a new signing key is encountered. Configure the displayed stable URL once, then start one browser campaign; correlated fetches and browser results advance automatically and remain Transcript evidence.</small></p>
            </>}
            {metadataWork.nextVariant && <button
              disabled={metadataLab?.ingestionMode !== 'MANUAL_REFRESH'
                || busy === 'metadata-next' || metadataLab?.selectedVariant === metadataWork.nextVariant}
              onClick={() => void selectNextMetadataFixture()}>
              {metadataLab?.selectedVariant === metadataWork.nextVariant
                ? `Next fixture selected: ${humanize(metadataWork.nextVariant)}`
                : `Select next incomplete fixture: ${humanize(metadataWork.nextVariant)}`}
            </button>}
            {!metadataWork.nextVariant && metadataWork.nextOperation && <p>
              All required fixtures were fetched. Next observation: <code>{metadataWork.nextOperation}</code>.
            </p>}
            <p><small>Each click changes only the Suite-controlled document behind the stable URL. SAMLscope never calls the target's administration API; perform the target's ordinary refresh/re-import and protocol flow before advancing.</small></p>
          </div>
          <button disabled={busy === 'protocol-evidence' || protocolEvidence.readyCases === 0}
            onClick={() => void evaluateProtocolEvidence()}>
            Re-evaluate recorded evidence
          </button>
          <button disabled={busy === 'protocol-attempts'}
            onClick={() => void confirmProtocolEvidenceAttempts()}>
            Confirm all listed refreshes and flows were attempted
          </button>
          <p><small>This confirms only that you performed the listed operations. It is not a verdict questionnaire; SAMLscope derives every outcome from the recorded fetches and SAML traffic.</small></p>
          <details><summary>Protocol observation progress</summary><ul>
            {protocolEvidence.cases.map(value => <li key={value.caseId}>
              <code>{value.caseId}</code>: {value.completedObservations.length}/{value.requiredObservations.length} required observations
            </li>)}
          </ul></details>
        </div>}
        <details><summary>{contract.pendingCases} cases share this environment</summary>
          <p>Open an individual case only when the standard protocol driver cannot obtain its evidence. Confirming setup is not itself a verdict.</p>
          <ul className="case-links">{contract.caseIds.map(caseId => <li key={caseId}>
            <a href={`/browser/${runId}/${caseId}`}>{caseId}</a>
          </li>)}</ul>
        </details>
      </article>)}</div>
    </section>}
    {!focusCaseId && campaigns && <section className="campaign-overview">
      <p className="eyebrow">Run plans</p>
      <h2>Choose evidence depth, not individual cases</h2>
      <p>Cases share Transcripts, metadata fetches, and configuration campaigns. Counts below are deliberate user actions, not case counts.</p>
      <div className="contract-list">{campaigns.plans.map(value => <article className="contract" key={value.plan}>
        <header><div><strong>{humanize(value.plan)}</strong><p>{planDescription(value.plan)}</p></div>
          <span>{value.budgetMet ? 'WITHIN BUDGET' : 'OVER BUDGET'}</span></header>
        <dl>
          <dt>Cases</dt><dd>{value.cases}</dd>
          <dt>Actions</dt><dd>{value.deliberateUserActions} total / {value.remainingUserActions} remaining (budget {value.actionBudget})</dd>
          <dt>Estimated time</dt><dd>{value.estimatedMinutesMin}-{value.estimatedMinutesMax} minutes</dd>
          <dt>Action mix</dt><dd>{value.loginActions} login, {value.configurationActions} configuration, {value.metadataRefreshActions} metadata refresh</dd>
          {value.plan === 'FULL' && <><dt>Self-check sections</dt><dd>{value.selfAttestationSections}</dd></>}
        </dl>
      </article>)}</div>
      <p><strong>Externally verified:</strong> {campaigns.externallyVerifiedCases} · <strong>Self-attested:</strong> {campaigns.selfAttestedCases} · <strong>Not verified:</strong> {campaigns.notVerifiedCases}</p>
      <details><summary>Evidence campaigns and shared cases</summary>
        <div className="contract-list">{campaigns.campaigns.map(campaign => <article
          className={`contract evidence-panel evidence-${campaign.evidenceClass.toLowerCase()}`} key={campaign.id}>
          <header><div><strong>{campaign.title}</strong><p>{humanize(campaign.evidenceClass)}</p></div><span>{campaign.remainingUserActions} action{campaign.remainingUserActions === 1 ? '' : 's'} remaining</span></header>
          {campaign.freshSessionRequired && <p>A fresh target session is required at the campaign boundary.</p>}
          {campaign.expectedTranscriptEvidence.length > 0 && <p>Expected evidence: {campaign.expectedTranscriptEvidence.join(', ')}</p>}
          <p>{campaign.caseIds.length} cases share this campaign; {campaign.remainingCaseIds.length} remain unresolved.</p>
        </article>)}</div>
      </details>
    </section>}
    {!focusCaseId && campaigns && <section className="case-workspace" aria-labelledby="case-workspace-title">
      <div className="section-heading case-workspace-heading"><div><h2 id="case-workspace-title">Case workspace</h2>
        <p>Find approved cases by campaign, evidence source, or approved operator instructions. This view does not change their approved outcome rules.</p></div>
        <label className="case-search">Search cases<input type="search" value={caseQuery}
          onChange={event => setCaseQuery(event.target.value)} placeholder="Case ID, campaign, action, prompt, or evidence" /></label>
      </div>
      <div className="case-filterbar">
        <div className="segmented-control" aria-label="Case resolution filter">
          <button type="button" className={caseScope === 'attention' ? 'active' : ''}
            aria-pressed={caseScope === 'attention'} onClick={() => setCaseScope('attention')}>Needs attention</button>
          <button type="button" className={caseScope === 'all' ? 'active' : ''}
            aria-pressed={caseScope === 'all'} onClick={() => setCaseScope('all')}>All cases</button>
          <button type="button" className={caseScope === 'not_verified' ? 'active' : ''}
            aria-pressed={caseScope === 'not_verified'} onClick={() => setCaseScope('not_verified')}>Not verified</button>
        </div>
        <div className="evidence-filterbar" aria-label="Evidence class filters">
          {(Object.keys(evidenceFilters) as EvidenceClass[]).map(value => <button type="button" key={value}
            className={`evidence-filter evidence-${value.toLowerCase()}${evidenceFilters[value] ? ' active' : ''}`}
            aria-pressed={evidenceFilters[value]} onClick={() => setEvidenceFilters(current => ({
              ...current, [value]: !current[value],
            }))}><span className={`semantic-dot evidence-${evidenceToken(value)}`} />{humanize(value)}</button>)}
        </div>
        <span className="case-result-count" aria-live="polite">{caseWorkspaceCount} case{caseWorkspaceCount === 1 ? '' : 's'} shown</span>
      </div>
      <div className="case-workspace-layout">
        <div className="case-groups" aria-live="polite">
          {caseWorkspace.length === 0 ? <div className="empty-state compact"><h3>No cases match these filters</h3>
            <p>Change the plan, evidence, resolution, or search filters.</p></div> : caseWorkspace.map(group =>
            <section className="case-group" key={group.campaign.id}>
              <header><div><strong>{group.campaign.title}</strong><small>{humanize(group.campaign.evidenceClass)}</small></div>
                <span>{group.cases.filter(value => !value.resolved).length} need attention</span></header>
              <div>{group.cases.map(value => <button type="button" className={`case-row${selectedCaseId === value.caseId ? ' selected' : ''}`}
                key={value.caseId} onClick={event => {
                  lastCaseTriggerRef.current = event.currentTarget
                  setSelectedCaseId(value.caseId)
                  setCaseDrawerOpen(true)
                }} aria-haspopup="dialog" aria-expanded={caseDrawerOpen && selectedCaseId === value.caseId}>
                <span className={`semantic-dot ${value.resolved ? 'evidence-observed' : 'evidence-unverified'}`} />
                <code>{value.caseId}</code><span>{humanize(value.actionKind)}</span>
                <strong>{value.outcome ? humanize(value.outcome) : value.resolved ? 'Resolved' : 'Needs attention'}</strong>
              </button>)}</div>
            </section>)}
        </div>
      </div>
    </section>}
    {caseDrawerOpen && selectedCase && selectedCaseCampaign && createPortal(<div className="case-drawer-layer">
      <div className="case-drawer-backdrop" aria-hidden="true" onClick={closeCaseDrawer} />
      <aside ref={caseDrawerRef} className="case-drawer" role="dialog" aria-modal="true" aria-labelledby="case-drawer-title">
        <header className="case-drawer-header"><div><p className="eyebrow">Case details</p>
          <h2 id="case-drawer-title">{selectedCase.caseId}</h2></div>
          <button ref={caseDrawerCloseRef} type="button" className="button-secondary" onClick={closeCaseDrawer}
            aria-label="Close case details">Close</button></header>
        <dl><dt>Campaign</dt><dd>{selectedCaseCampaign.title}</dd>
          <dt>Plan</dt><dd>{humanize(selectedCase.plan)}</dd>
          <dt>Evidence</dt><dd><span className={`evidence-label evidence-${selectedCase.evidenceClass.toLowerCase()}`}>
            {humanize(selectedCase.evidenceClass)}</span></dd>
          <dt>Outcome</dt><dd>{selectedCase.outcome ? humanize(selectedCase.outcome) : selectedCase.resolved ? 'Resolved' : 'Pending evidence'}</dd>
          <dt>User action</dt><dd>{humanize(selectedCase.actionKind)}</dd>
          <dt>Fresh session</dt><dd>{selectedCase.freshSessionRequired ? 'Required' : 'Not required'}</dd></dl>
        {selectedCase.expectedTranscriptEvidence.length > 0 && <><h3>Expected Transcript evidence</h3>
          <ul>{selectedCase.expectedTranscriptEvidence.map(value => <li key={value}><code>{value}</code></li>)}</ul></>}
        {selectedInteraction ? <div className="case-drawer-interaction">{interactionCard(selectedInteraction)}</div>
          : selectedCase.resolved ? <p className="quiet-success">This case already has a recorded outcome.</p>
            : <div className="notice"><strong>No direct input is requested</strong>
              <p>Continue its campaign or protocol fixture from the Run workspace. A missing observation remains not verified.</p>
              <a className="button button-secondary" href={`/browser/${runId}/${selectedCase.caseId}`}>Open focused case</a></div>}
      </aside>
    </div>, document.body)}
    {sharedOperatorActions.length > 0 && <section className="shared-operator-actions">
      <p className="eyebrow">Standard plan operations</p>
      <h2>Shared target policy changes</h2>
      <p>Perform each target-side policy change once. SAMLscope applies that operation to every listed case, but the operation itself is not evidence of conformance. Without a conclusive Transcript or other external evidence, those cases remain not verified.</p>
      <div className="interaction-list">{sharedOperatorActions.map(section => {
        const key = `${section.campaign.id}:${section.action.id}`
        return <article className="interaction" key={key}>
          <header><strong>{humanize(section.action.id)}</strong><span>{section.interactions.length} CASES</span></header>
          <details><summary>Approved operations covered by this policy state</summary>
            {section.interactions.map(interaction => <article key={interaction.caseId}>
              <strong>{interaction.caseId}</strong>
              {interaction.promptEn && <pre>{resolvePrompt(interaction.promptEn, planId, runId)}</pre>}
            </article>)}
          </details>
          <button disabled={busy === key} onClick={() => void completeSharedOperatorAction(
            section.campaign.id, section.action.id, section.interactions.length)}>
            Continue after applying this shared policy
          </button>
        </article>
      })}</div>
    </section>}
    {selfCheckSections.length > 0 && <section className="self-check-sections">
      <p className="eyebrow">Full plan evidence</p>
      <h2>Grouped self-check sections</h2>
      <p>These are the cases that cannot currently be proved from standard SAML, browser, metadata, or Transcript evidence. Record one evidence conclusion per section. Open case-specific overrides only when the shared evidence supports different conclusions.</p>
      <div className="interaction-list">{selfCheckSections.map(section =>
        <form className="interaction" key={section.campaign.id}
          onSubmit={event => void submitSelfCheckSection(event, section)}>
          <fieldset disabled={busy === section.campaign.id}>
            <legend>{section.campaign.title}</legend>
            <p>{section.interactions.length} approved cases reuse this evidence decision.</p>
            <label>Section evidence conclusion<select required name="section-conclusion" defaultValue="">
              <option value="">Choose…</option>
              <option value="satisfied">Evidence satisfies every listed case</option>
              <option value="violated">Evidence violates every listed case</option>
              <option value="unable_to_verify">Unable to verify this evidence section</option>
            </select></label>
            <details><summary>Case scope and optional overrides</summary>
              <p>Leave an override unset to reuse the section conclusion. An override changes only that case; it does not alter the approved verdict mapping.</p>
              {section.interactions.map(interaction => <article key={interaction.caseId}>
                <header><strong>{interaction.caseId}</strong><span>{interaction.kind}</span></header>
                {interaction.promptEn && <details><summary>Approved evidence instructions</summary>
                  <pre>{resolvePrompt(interaction.promptEn, planId, runId)}</pre>
                </details>}
                <label>Case-specific override<select name={`override:${interaction.caseId}`}
                  value={sectionCaseChoices[interaction.caseId] ?? ''}
                  onChange={event => setSectionCaseChoices(current => ({
                    ...current, [interaction.caseId]: event.target.value,
                  }))}>
                  <option value="">Use section conclusion</option>
                  <option value="satisfied">Evidence satisfies this case</option>
                  <option value="violated">Evidence violates this case</option>
                  <option value="unable_to_verify">Unable to verify this case</option>
                </select></label>
              </article>)}
            </details>
            <label>Shared evidence note<textarea name="shared-note" maxLength={4000}
              placeholder="Identify the shared configuration, trace, policy, or review evidence once for this section." /></label>
            <button type="submit">Record section</button>
          </fieldset>
        </form>)}</div>
    </section>}
    <div className="section-heading"><div><p className="eyebrow">Evidence workflow</p><h2>Pending interactions</h2></div></div>
    {profile === 'IDP_FULL' && <form className="interaction" onSubmit={event => void runEcpProbe(event)}>
      <fieldset disabled={busy === 'ecp-probe'}>
        <legend>ECP, channel-binding, and SAML-EC probes</legend>
        <p>Credentials are held in memory for this send only. They are never written to case state, the outbox, or the transcript.</p>
        <label>Username<input required name="username" autoComplete="username" /></label>
        <label>Password<input required name="password" type="password" autoComplete="current-password" /></label>
        <button type="submit">Run seven ECP probes before M3</button>
      </fieldset>
    </form>}
    {plan && profile.startsWith('SP') && <p>Start login at the target SP after importing the Test Peer metadata.</p>}
    {focusCaseId && <div className="actions"><a className="button" href={`/manage/${runId}`}>Back to Run management</a></div>}
    {visibleInteractions.length === 0 ? <p className="quiet-success">
      {focusCaseId ? `No pending interaction for ${focusCaseId}.`
        : configurationInteractions.length > 0
          ? 'Configuration prerequisites are available under the shared setup contracts above.'
          : hasActiveProbe
            ? 'No other pending interactions. Continue the active probe above.'
          : 'No pending interactions.'}
    </p> :
      <div className="interaction-list">{visibleInteractions.map(interactionCard)}</div>}
    {mode === 'hosted' && <div className="actions"><button disabled={busy === 'publish'} onClick={() => void publish()}>Publish hosted result</button></div>}
  </section>
}

type EvidenceClass = 'PROTOCOL_OBSERVED' | 'OPERATOR_ASSISTED' | 'SELF_ATTESTED'

function campaignWorkspace(campaigns: CampaignReport | undefined, filter: {
  query: string
  scope: 'attention' | 'all' | 'not_verified'
  plan: 'ALL' | 'QUICK' | 'STANDARD' | 'FULL'
  evidence: Record<EvidenceClass, boolean>
}, interactionText: Map<string, string>) {
  if (!campaigns) return []
  const query = filter.query.trim().toLowerCase()
  const campaignById = new Map(campaigns.campaigns.map(value => [value.id, value]))
  const visible = (campaigns.classifications ?? []).filter(value => {
    const campaign = campaignById.get(value.campaignId)
    const searchable = [
      value.caseId,
      campaign?.title,
      value.actionKind,
      value.evidenceClass,
      value.outcome,
      interactionText.get(value.caseId),
      ...(value.expectedTranscriptEvidence ?? []),
    ].filter(Boolean).join(' ').toLowerCase()
    return campaign
      && (filter.scope === 'all'
        || filter.scope === 'attention' && !value.resolved
        || filter.scope === 'not_verified' && value.outcome === 'NOT_VERIFIED')
      && (filter.plan === 'ALL' || value.plan === filter.plan)
      && filter.evidence[value.evidenceClass]
      && (!query || searchable.includes(query))
  })
  return campaigns.campaigns.map(campaign => ({
    campaign,
    cases: visible.filter(value => value.campaignId === campaign.id),
  })).filter(group => group.cases.length > 0)
}

function evidenceToken(value: EvidenceClass) {
  return value === 'PROTOCOL_OBSERVED' ? 'observed' : value === 'OPERATOR_ASSISTED' ? 'assisted' : 'attested'
}


export function metadataFixtureWork(status: ProtocolEvidenceStatus | undefined) {
  const required = new Set<string>()
  const completed = new Set<string>()
  status?.cases.forEach(value => {
    value.requiredObservations.forEach(observation => required.add(observation))
    value.completedObservations.forEach(observation => completed.add(observation))
  })
  // ProtocolEvidenceStatus preserves the case-defined observation order. Keep that order so the
  // positive control is fetched before abnormal fixtures; alphabetic sorting used to offer
  // bad-signature before control on a fresh campaign.
  const fixtureRequired = [...required].filter(value => value.startsWith('fetched:'))
  const fixtureCompleted = fixtureRequired.filter(value => completed.has(value))
  const nextFixture = fixtureRequired.find(value => !completed.has(value))
  const nextOperation = [...required].find(value => !completed.has(value))
  return {
    totalFixtures: fixtureRequired.length,
    completedFixtures: fixtureCompleted.length,
    pendingVariants: fixtureRequired.filter(value => !completed.has(value))
      .map(value => value.slice('fetched:'.length)),
    nextVariant: nextFixture?.slice('fetched:'.length) ?? null,
    nextOperation: nextOperation ?? null,
  }
}

function resolvePrompt(value: string, planId: string, runId: string) {
  return value.replaceAll('<plan-id>', planId || '<plan-id>').replaceAll('<run-id>', runId)
}

function planDescription(plan: 'QUICK' | 'STANDARD' | 'FULL') {
  if (plan === 'QUICK') return 'Protocol-observed evidence only.'
  if (plan === 'STANDARD') return 'Quick plus operator-assisted configuration and refresh actions.'
  return 'Standard plus grouped self-attested evidence that cannot be externally observed.'
}

function attestationValue(interaction: PendingInteraction, conclusion: string) {
  const candidates = conclusion === 'satisfied'
    ? ['satisfied', 'evidence_satisfies']
    : conclusion === 'violated'
      ? ['violated', 'evidence_violates']
      : ['unable_to_verify', 'unable']
  const value = candidates.find(candidate => interaction.answerValues.includes(candidate))
  if (!value) throw new Error(`The approved answer mapping for ${interaction.caseId} has no ${conclusion} option.`)
  return value
}
