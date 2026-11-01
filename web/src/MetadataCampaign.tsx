import { tx } from './i18nNodes'
import { t } from './i18n'
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
    value => { if (!value.automaticStartUrl) throw new Error(t('The metadata tests did not return a start URL.')) })
  const confirm = () => act('metadata-confirm', async () => {
    await api.confirmProtocolEvidenceAttempts(runId, csrfToken)
    setNotice(t('Attempts confirmed. Cases without evidence stay not verified.'))
    await refresh()
  })
  const auto = lab?.ingestionMode === 'AUTOMATIC_POLLING'
  const preloaded = lab?.ingestionMode === 'PRELOADED_AGGREGATE'

  return <section className="card" aria-label={t('Metadata refresh tests')}>
    <h3>{status.eligibleCases > 0 ? t('Metadata refresh tests ({n})', { n: status.eligibleCases }) : t('Tests your product may not support')}</h3>
    {lab && <>
      <p className="muted">{t('{done} / {total} metadata fetches recorded.', { done: work.completedFixtures, total: work.totalFixtures })}</p>
      {lab.ingestionMode === 'MANUAL_REFRESH' && work.pendingVariants.length > 0 && <div className="actions">
        <p>{t('Your product loads SAMLscope metadata from the URL you registered. Start, then open the test link.')}</p>
        <button disabled={disabled} onClick={() => void start()}>{t('Start')}</button>
      </div>}
      {auto && !lab.campaignComplete && <div className="actions">
        <p role="status">{t('Progress: {done} / {total}', { done: lab.campaignIndex, total: lab.campaignVariants.length })}</p>
      </div>}
      {auto && lab.automaticStartUrl && !lab.campaignComplete && <div className="actions">
        <a className="button" href={lab.automaticStartUrl} target="_blank" rel="noreferrer">{t('Open the test link')}</a>
      </div>}
      {auto && lab.automaticContinueUrl && <form method="post" action={lab.automaticContinueUrl} target="_blank">
        <button className="button-secondary" type="submit">{t('My product showed its result — continue')}</button>
        <p className="muted">{t('Only advances the run; it is not a verdict.')}</p>
      </form>}
      {auto && lab.campaignComplete && <p>{t('Metadata campaign complete.')}</p>}
    </>}
    <details open={forceOpen}>
      <summary>{t("If your product doesn't re-fetch automatically")}</summary>
      {lab && <>
        {preloaded
          ? <dl>
              {lab.preloadedMetadataUrl && <><dt>{t('Metadata URL')}</dt><dd><code>{lab.preloadedMetadataUrl}</code></dd></>}
              {lab.preloadedDownloadUrl && <><dt>{t('Download')}</dt><dd><a href={lab.preloadedDownloadUrl}
                download="samlscope-metadata-campaign.xml">{t('Download metadata file')}</a></dd></>}
              {lab.preloadedStartUrl && <><dt>{t('Start')}</dt><dd><a href={lab.preloadedStartUrl} target="_blank"
                rel="noreferrer">{t('Run preloaded sign-ins')}</a></dd></>}
            </dl>
          : <div className="actions"><button className="button-secondary" disabled={disabled}
              onClick={() => void run('metadata-preloaded', () => api.startPreloadedMetadataCampaign(runId, csrfToken))}>
              {t('Use one combined metadata file')}</button></div>}
        {lab.ingestionMode !== 'MANUAL_REFRESH' && <div className="actions">
          <button className="button-secondary" disabled={disabled}
            onClick={() => void run('metadata-manual', () => api.useManualMetadataRefresh(runId, csrfToken))}>
            {t('Refresh by hand')}</button></div>}
        {lab.ingestionMode === 'MANUAL_REFRESH' && work.nextVariant && <div className="actions">
          <p>{tx('Stable metadata URL: {url}. Current fixture: {fixture}.', { url: <code>{lab.metadataUrl}</code>, fixture: humanize(lab.selectedVariant) })}</p>
          <button className="button-secondary" disabled={disabled || lab.selectedVariant === work.nextVariant}
            onClick={() => void run('metadata-next', () => api.selectMetadataVariant(runId, work.nextVariant!, csrfToken))}>
            {t('Select next fixture ({fixture})', { fixture: humanize(work.nextVariant) })}</button></div>}
      </>}
      <div className="actions">
        <button className="button-secondary" disabled={disabled} onClick={() => void confirm()}>{t('I tried everything listed')}</button>
        <p className="muted">{t('Cases without evidence stay not verified.')}</p>
      </div>
      <CapabilityEscape interactions={capability} planId={planId} runId={runId} busy={disabled}
        onAnswer={onAnswer} open={forceOpen} />
    </details>
  </section>
}
