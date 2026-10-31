import type { FormEvent } from 'react'
import { api, type MetadataLab, type PendingInteraction, type ProtocolEvidenceStatus } from './api'
import { humanize } from './format'
import { CapabilityEscape } from './InteractionCards'

export function metadataFixtureWork(status: ProtocolEvidenceStatus | undefined) {
  const required = new Set<string>()
  const completed = new Set<string>()
  status?.cases.forEach(value => {
    value.requiredObservations.forEach(observation => required.add(observation))
    value.completedObservations.forEach(observation => completed.add(observation))
  })
  // Keep the case-defined order so the positive control is fetched before abnormal fixtures.
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

export function metadataCampaignOpen(lab: MetadataLab | undefined, status: ProtocolEvidenceStatus | undefined) {
  if (!lab) return false
  return lab.ingestionMode === 'AUTOMATIC_POLLING'
    ? !lab.campaignComplete : metadataFixtureWork(status).pendingVariants.length > 0
}

export function MetadataCampaign({ runId, planId, csrfToken, status, lab, setLab, capability, busy, act, refresh, setNotice,
  onAnswer, forceOpen }: {
  runId: string
  planId: string
  csrfToken?: string
  status: ProtocolEvidenceStatus
  lab: MetadataLab | undefined
  setLab: (lab: MetadataLab) => void
  capability: PendingInteraction[]
  busy: string
  act: (key: string, work: () => Promise<void>) => Promise<void>
  refresh: () => Promise<void>
  setNotice: (value: string) => void
  onAnswer: (event: FormEvent<HTMLFormElement>, interaction: PendingInteraction) => void
  forceOpen: boolean
}) {
  const work = metadataFixtureWork(status)
  const disabled = busy !== ''
  const run = (key: string, call: () => Promise<MetadataLab>, after?: (value: MetadataLab) => void) =>
    act(key, async () => { const value = await call(); setLab(value); after?.(value) })
  const start = () => run('metadata-auto',
    () => api.startAutomaticMetadataPolling(runId, work.pendingVariants, 15, csrfToken),
    value => { if (!value.automaticStartUrl) throw new Error('The metadata tests did not return a start URL.') })
  const confirm = () => act('metadata-confirm', async () => {
    await api.confirmProtocolEvidenceAttempts(runId, csrfToken)
    setNotice('Attempts confirmed. Cases without evidence stay not verified.')
    await refresh()
  })
  const auto = lab?.ingestionMode === 'AUTOMATIC_POLLING'
  const preloaded = lab?.ingestionMode === 'PRELOADED_AGGREGATE'

  return <section className="card" aria-label="Metadata refresh tests">
    <h3>{status.eligibleCases > 0 ? `Metadata refresh tests (${status.eligibleCases})` : 'Tests your product may not support'}</h3>
    {lab && <>
      <p className="muted">{work.completedFixtures} / {work.totalFixtures} metadata fetches recorded.</p>
      {lab.ingestionMode === 'MANUAL_REFRESH' && work.pendingVariants.length > 0 && <div className="actions">
        <p>Your product loads SAMLscope metadata from the URL you registered. Start, then open the test link.</p>
        <button disabled={disabled} onClick={() => void start()}>Start</button>
      </div>}
      {auto && !lab.campaignComplete && <div className="actions">
        <p role="status">Progress: {lab.campaignIndex} / {lab.campaignVariants.length}</p>
      </div>}
      {auto && lab.automaticStartUrl && !lab.campaignComplete && <div className="actions">
        <a className="button" href={lab.automaticStartUrl} target="_blank" rel="noreferrer">Open the test link</a>
      </div>}
      {auto && lab.automaticContinueUrl && <form method="post" action={lab.automaticContinueUrl} target="_blank">
        <button className="button-secondary" type="submit">My product showed its result — continue</button>
        <p className="muted">Only advances the run; it is not a verdict.</p>
      </form>}
      {auto && lab.campaignComplete && <p>Metadata campaign complete.</p>}
    </>}
    <details open={forceOpen}>
      <summary>If your product doesn't re-fetch automatically</summary>
      {lab && <>
        {preloaded
          ? <dl>
              {lab.preloadedMetadataUrl && <><dt>Metadata URL</dt><dd><code>{lab.preloadedMetadataUrl}</code></dd></>}
              {lab.preloadedDownloadUrl && <><dt>Download</dt><dd><a href={lab.preloadedDownloadUrl}
                download="samlscope-metadata-campaign.xml">Download metadata file</a></dd></>}
              {lab.preloadedStartUrl && <><dt>Start</dt><dd><a href={lab.preloadedStartUrl} target="_blank"
                rel="noreferrer">Run preloaded sign-ins</a></dd></>}
            </dl>
          : <div className="actions"><button className="button-secondary" disabled={disabled}
              onClick={() => void run('metadata-preloaded', () => api.startPreloadedMetadataCampaign(runId, csrfToken))}>
              Use one combined metadata file</button></div>}
        {lab.ingestionMode !== 'MANUAL_REFRESH' && <div className="actions">
          <button className="button-secondary" disabled={disabled}
            onClick={() => void run('metadata-manual', () => api.useManualMetadataRefresh(runId, csrfToken))}>
            Refresh by hand</button></div>}
        {lab.ingestionMode === 'MANUAL_REFRESH' && work.nextVariant && <div className="actions">
          <p>Stable metadata URL: <code>{lab.metadataUrl}</code>. Current fixture: {humanize(lab.selectedVariant)}.</p>
          <button className="button-secondary" disabled={disabled || lab.selectedVariant === work.nextVariant}
            onClick={() => void run('metadata-next', () => api.selectMetadataVariant(runId, work.nextVariant!, csrfToken))}>
            Select next fixture ({humanize(work.nextVariant)})</button></div>}
      </>}
      <div className="actions">
        <button className="button-secondary" disabled={disabled} onClick={() => void confirm()}>I tried everything listed</button>
        <p className="muted">Cases without evidence stay not verified.</p>
      </div>
      <CapabilityEscape interactions={capability} planId={planId} runId={runId} busy={disabled}
        onAnswer={onAnswer} open={forceOpen} />
    </details>
  </section>
}
