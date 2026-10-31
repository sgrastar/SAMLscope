import { t } from './i18n'
import type { FormEvent } from 'react'
import type { PendingInteraction } from './api'
import { humanize } from './format'

export function resolvePrompt(value: string, planId: string, runId: string) {
  return value.replaceAll('<plan-id>', planId || '<plan-id>').replaceAll('<run-id>', runId)
}

type Ids = { planId: string; runId: string }
type Handlers = {
  busy: boolean
  onComplete: (interaction: PendingInteraction) => void
  onAnswer: (event: FormEvent<HTMLFormElement>, interaction: PendingInteraction) => void
}

export function InteractionCard({ interaction, planId, runId, busy, onComplete, onAnswer, lead = false }:
  Ids & Handlers & { interaction: PendingInteraction; lead?: boolean }) {
  const Heading = lead ? 'h2' : 'h3'
  const title = interaction.kind === 'BROWSER' ? t('Do this in the browser')
    : interaction.kind === 'CONFIGURATION' ? t('Change a setting in your product') : t('Check your product')
  return <article className={lead ? 'step-body' : 'card'}>
    <Heading>{title}</Heading>
    {interaction.promptEn && <p className="prompt">{resolvePrompt(interaction.promptEn, planId, runId)}</p>}
    <p className="muted"><code>{interaction.caseId}</code></p>
    {interaction.kind === 'BROWSER' && <div className="actions">
      {interaction.startUrl && <a className="button" href={interaction.startUrl} target="_blank" rel="noreferrer">{t('Open')}</a>}
      {interaction.completionMode === 'TRANSCRIPT'
        ? <p className="muted">{t('This page continues on its own once the sign-in is recorded.')}</p>
        : <>
            <button className="button-secondary" disabled={busy} onClick={() => onComplete(interaction)}>{t('I did it')}</button>
            <p className="muted">{t('The result comes from recorded traffic. No record = not verified.')}</p>
          </>}
    </div>}
    {interaction.kind !== 'BROWSER' && <AnswerForm interaction={interaction} busy={busy} onAnswer={onAnswer}
      labels={undefined} />}
  </article>
}

function AnswerForm({ interaction, busy, onAnswer, labels }: {
  interaction: PendingInteraction
  busy: boolean
  onAnswer: Handlers['onAnswer']
  labels: Record<string, string> | undefined
}) {
  return <form onSubmit={event => onAnswer(event, interaction)}>
    <fieldset disabled={busy}>
      {interaction.answerValues.map(value => <label className="radio" key={value}>
        <input required type="radio" name="value" value={value} />{labels?.[value] ?? humanize(value)}
      </label>)}
      <label>{t('Note')}<textarea name="note" maxLength={4000} placeholder={t('What did you see or change?')} /></label>
      <button type="submit">{t('Continue')}</button>
    </fieldset>
  </form>
}

const capabilityLabels: Record<string, string> = {
  capability_absent: t('My product does not support this (can affect the result)'),
  target_config_unavailable: t("Can't change this in my environment"),
  capability_undetermined: t("Don't know"),
}

/** Escape hatch for tests that are judged from Transcript evidence; collapsed by default. */
export function CapabilityEscape({ interactions, planId, runId, busy, onAnswer, open }:
  Ids & { interactions: PendingInteraction[]; busy: boolean; onAnswer: Handlers['onAnswer']; open: boolean }) {
  if (interactions.length === 0) return null
  return <div>
    <p className="muted">{t('Normally judged automatically. Only choose if your product cannot do this.')}</p>
    {interactions.map(interaction => <details key={interaction.caseId} open={open}>
      <summary>{t("If this can't be run on your product:")} <code>{interaction.caseId}</code></summary>
      {interaction.promptEn && <p className="prompt">{resolvePrompt(interaction.promptEn, planId, runId)}</p>}
      <AnswerForm interaction={interaction} busy={busy} onAnswer={onAnswer} labels={capabilityLabels} />
    </details>)}
  </div>
}
