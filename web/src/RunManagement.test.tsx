import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { afterEach, expect, test, vi } from 'vitest'
import { metadataFixtureWork, RunManagement } from './RunManagement'
import type { CampaignReport, MetadataLab, PendingInteraction, ProtocolEvidenceStatus } from './api'

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
  window.localStorage.clear()
  window.sessionStorage.clear()
})

const RUN = 'run_0123456789ABCDEFGHJKMNPQRS'
const ready = { checks: [{ code: 'target_metadata', status: 'PASS', message: 'ok' }] }

function interaction(caseId: string, kind: PendingInteraction['kind'], extra: Partial<PendingInteraction> = {}): PendingInteraction {
  return { caseId, kind, promptKey: null, promptEn: `Prompt for ${caseId}`, startUrl: null, expiresAt: 0,
    answerValues: kind === 'CONFIGURATION' ? ['confirmed', 'capability_absent'] : ['satisfied', 'unable'], ...extra }
}

function report(parts: Partial<CampaignReport> = {}): CampaignReport {
  return { runId: RUN, cases: 10, casesByEvidenceClass: { PROTOCOL_OBSERVED: 0, OPERATOR_ASSISTED: 0, SELF_ATTESTED: 0 },
    externallyVerifiedCases: 6, selfAttestedCases: 1, notVerifiedCases: 3, plans: [], campaigns: [], classifications: [], ...parts }
}

const classification = (caseId: string, resolved: boolean) => ({
  caseId, plan: 'STANDARD' as const, evidenceClass: 'PROTOCOL_OBSERVED' as const, campaignId: 'c', actionKind: 'NONE' as const,
  freshSessionRequired: false, resolved, outcome: resolved ? 'SATISFIED' as const : null, expectedTranscriptEvidence: [],
})

function evidence(cases: Array<[string, string[], string[]]> = [], ready = 0): ProtocolEvidenceStatus {
  return { eligibleCases: cases.length, readyCases: ready,
    cases: cases.map(([caseId, requiredObservations, completedObservations]) =>
      ({ caseId, ready: false, requiredObservations, completedObservations, details: {} })) }
}

function lab(parts: Partial<MetadataLab> = {}): MetadataLab {
  return { runId: RUN, planId: 'plan', selectedVariant: 'control', metadataUrl: 'https://suite.example/metadata',
    availableVariants: ['control'], ingestionMode: 'MANUAL_REFRESH', campaignVariants: [], campaignIndex: 0,
    campaignComplete: false, pollingDelaySeconds: 15, operatorContinuationActions: 0, automaticStartUrl: null,
    automaticContinueUrl: null, preloadedMetadataUrl: null, preloadedDownloadUrl: null, preloadedStartUrl: null,
    preloadedVariants: [], preloadedFetched: false, ...parts }
}

type Setup = {
  interactions?: PendingInteraction[]
  protocolEvidence?: ProtocolEvidenceStatus
  campaigns?: CampaignReport | null
  activeProbe?: Record<string, unknown>
  lab?: MetadataLab
  profile?: string
  status?: string
  context?: Record<string, unknown>
  availability?: Record<string, unknown>
  post?: (url: string) => unknown
}

function setup(options: Setup = {}) {
  const calls: Array<{ url: string; method: string; body?: string }> = []
  vi.stubGlobal('fetch', vi.fn(async (url: string, init?: RequestInit) => {
    const method = init?.method ?? 'GET'
    calls.push({ url, method, body: init?.body as string | undefined })
    const json = (value: unknown) => new Response(JSON.stringify(value), { status: 200, headers: { 'content-type': 'application/json' } })
    if (method === 'POST') return json(options.post?.(url) ?? (url.endsWith('/metadata-lab/automatic-polling')
      ? { ...(options.lab ?? lab()), ingestionMode: 'AUTOMATIC_POLLING', automaticStartUrl: 'https://suite.example/start-auto' }
      : { ecpProbesRequired: false }))
    if (url.endsWith('/workspace-evidence')) return json({
      interactions: options.interactions ?? [], bootstrapContracts: [],
      protocolEvidence: options.protocolEvidence ?? evidence(), activeProbe: options.activeProbe ?? { state: 'NOT_STARTED' },
      campaigns: options.campaigns === undefined ? null : options.campaigns,
      definitionAvailability: options.availability,
    })
    if (url.endsWith('/metadata-lab')) return json(options.lab ?? lab())
    if (url === '/api/health') return json({ status: 'ok', version: 't', mode: 'selfhosted' })
    if (url === '/api/plans') return json([{ plan: { id: 'plan', name: 'My IdP', profile: options.profile ?? 'browser_sso_idp',
      target: { kind: 'IDP', entityId: 'https://idp.example' } }, entityId: 'e', metadataUrl: 'https://suite.example/p/plan/metadata',
      mdqUrl: '', secondaryIdpEntityId: '', secondaryIdpMetadataUrl: '' }])
    if (url === `/api/runs/${RUN}`) return json({ id: RUN, planId: 'plan', status: options.status ?? 'COMPLETED',
      targetToSuiteReachability: 'CONFIRMED', context: options.context ?? { preflight: ready } })
    if (url.includes('/target-initiated')) return json(null)
    return json([])
  }))
  return calls
}

const posts = (calls: ReturnType<typeof setup>) => calls.filter(call => call.method === 'POST')
const primary = async () => within(await screen.findByRole('region', { name: 'What to do now' }))

test('before preflight the only primary action is Check setup', async () => {
  setup({ status: 'CREATED', context: {} })
  render(<RunManagement runId={RUN} />)
  expect((await primary()).getByRole('button', { name: 'Check setup' })).toBeTruthy()
  expect(screen.getByText('Connection details').closest('details')?.open).toBe(true)
})

test('first browser step is the primary card; later steps and optional sections stay collapsed', async () => {
  setup({
    interactions: [
      interaction('b1', 'BROWSER', { startUrl: 'https://idp.example/go' }),
      interaction('b2', 'BROWSER'),
      interaction('att', 'ATTESTATION'),
      interaction('cfg', 'CONFIGURATION', { completionMode: 'OPERATOR' }),
    ],
  })
  render(<RunManagement runId={RUN} />)
  const card = await primary()
  expect(await card.findByText('Prompt for b1')).toBeTruthy()
  expect(card.queryByText('Prompt for att')).toBeNull()
  expect(card.queryByText('Prompt for cfg')).toBeNull()
  expect(card.getByRole('link', { name: 'Open' }).getAttribute('href')).toBe('https://idp.example/go')
  expect(screen.getByText('1 more step after this').closest('details')?.open).toBe(false)
  expect(screen.getByText(/Self-attestation \(1, optional\)/).closest('details')?.open).toBe(false)
  expect(screen.getByText(/product setting change \(1, optional\)/).closest('details')?.open).toBe(false)
})

test('prompts resolve plan and run placeholders', async () => {
  setup({ interactions: [interaction('b1', 'BROWSER', { promptEn: 'curl <plan-id> <run-id>', completionMode: 'OPERATOR' })] })
  render(<RunManagement runId={RUN} />)
  expect(await screen.findByText(`curl plan ${RUN}`)).toBeTruthy()
})

test('TRANSCRIPT_OR_OPERATOR configuration is never primary; its answers live in the collapsed metadata card', async () => {
  const calls = setup({
    interactions: [interaction('cap', 'CONFIGURATION', {
      completionMode: 'TRANSCRIPT_OR_OPERATOR', answerValues: ['capability_absent', 'target_config_unavailable', 'capability_undetermined'] })],
    campaigns: report({ classifications: [classification('cap', false)] }),
  })
  render(<RunManagement runId={RUN} />)
  await screen.findByText('Run the tests')
  expect((await primary()).queryByText('Prompt for cap')).toBeNull()
  expect(screen.queryByText(/product setting change/)).toBeNull()
  expect(screen.getByText('Normally judged automatically. Only choose if your product cannot do this.')).toBeTruthy()
  expect(screen.getByText(/If this can't be run on your product/).closest('details')?.open).toBe(false)
  fireEvent.click(screen.getByLabelText('My product does not support this (can affect the result)'))
  expect(screen.getByLabelText("Can't change this in my environment")).toBeTruthy()
  expect(screen.getByLabelText("Don't know")).toBeTruthy()
  fireEvent.click(screen.getByRole('button', { name: 'Continue' }))
  await waitFor(() => expect(posts(calls)).toHaveLength(1))
  expect(posts(calls)[0].url).toBe(`/api/runs/${RUN}/cases/cap/configure`)
  expect(JSON.parse(posts(calls)[0].body!)).toMatchObject({ value: 'capability_absent' })
})

test('always shows the not verified count, even when it is zero, and never claims everything passed', async () => {
  setup({ campaigns: report({ externallyVerifiedCases: 10, selfAttestedCases: 0, notVerifiedCases: 0,
    classifications: [classification('a', true)] }) })
  render(<RunManagement runId={RUN} />)
  expect(await screen.findByText('All tests finished')).toBeTruthy()
  const line = screen.getByText(/Verified automatically 10/)
  expect(line.textContent).toContain('Self-attested 0')
  expect(line.textContent).toContain('Not verified 0 of 10')
  expect(within(line).getByRole('link', { name: 'See why' }).getAttribute('href')).toBe(`/reports/${RUN}`)
  expect((await primary()).queryByText(/pass/i)).toBeNull()
  expect(line.textContent).not.toMatch(/pass|fail/i)
})

test('unresolved cases with nothing to ask are reported as not verified, with a way to continue', async () => {
  const calls = setup({ campaigns: report({ classifications: [classification('a', true), classification('b', false), classification('c', false)] }) })
  render(<RunManagement runId={RUN} />)
  expect(await screen.findByText(/2 could not be verified automatically/)).toBeTruthy()
  expect(screen.getByText(/Not verified 3 of 10/)).toBeTruthy()
  expect(screen.getByText("Press after you changed your product's settings.")).toBeTruthy()
  fireEvent.click(screen.getByRole('button', { name: 'Continue tests' }))
  await waitFor(() => expect(posts(calls).map(call => call.url)).toEqual([`/api/runs/${RUN}/tests/start`]))
})

test('metadata campaign is not requested or shown without eligible cases', async () => {
  const calls = setup()
  render(<RunManagement runId={RUN} />)
  await screen.findByText('Run the tests')
  expect(calls.some(call => call.url.endsWith('/metadata-lab'))).toBe(false)
  expect(screen.queryByText(/Metadata refresh tests/)).toBeNull()
})

test('metadata campaign starts with one button and links to the first test in a new tab', async () => {
  const calls = setup({ protocolEvidence: evidence([['m1', ['fetched:control', 'fetched:bad'], ['fetched:control']]]) })
  render(<RunManagement runId={RUN} csrfToken="csrf" />)
  expect(await screen.findByText('Metadata refresh tests (1)')).toBeTruthy()
  fireEvent.click(screen.getByRole('button', { name: 'Start' }))
  const open = await screen.findByRole('link', { name: 'Open the test link' })
  expect(open.getAttribute('href')).toBe('https://suite.example/start-auto')
  expect(open.getAttribute('target')).toBe('_blank')
  const start = posts(calls).find(call => call.url.endsWith('/metadata-lab/automatic-polling'))!
  expect(JSON.parse(start.body!)).toEqual({ variants: ['bad'], pollingDelaySeconds: 15 })
  expect(screen.queryByRole('button', { name: /Re-evaluate/ })).toBeNull()
})

test('automatic continuation only advances the run and recovery options are collapsed', async () => {
  const calls = setup({
    protocolEvidence: evidence([['m1', ['fetched:control', 'fetched:bad'], ['fetched:control']]]),
    lab: lab({ ingestionMode: 'AUTOMATIC_POLLING', campaignVariants: ['bad', 'x'], campaignIndex: 1,
      automaticStartUrl: 'https://suite.example/s', automaticContinueUrl: 'https://suite.example/c' }),
  })
  render(<RunManagement runId={RUN} csrfToken="csrf" />)
  expect(await screen.findByText('Progress: 1 / 2')).toBeTruthy()
  const form = screen.getByRole('button', { name: 'My product showed its result — continue' }).closest('form')!
  expect(form.getAttribute('action')).toBe('https://suite.example/c')
  expect(form.getAttribute('target')).toBe('_blank')
  expect(screen.getByText('Only advances the run; it is not a verdict.')).toBeTruthy()
  expect(screen.getByText("If your product doesn't re-fetch automatically").closest('details')?.open).toBe(false)
  fireEvent.click(screen.getByRole('button', { name: 'I tried everything listed' }))
  await waitFor(() => expect(posts(calls).some(call => call.url.endsWith('/protocol-evidence/confirm-attempts'))).toBe(true))
  expect(screen.getByText('Attempts confirmed. Cases without evidence stay not verified.')).toBeTruthy()
})

test('recorded metadata evidence is evaluated once without a loop', async () => {
  const calls = setup({ protocolEvidence: evidence([['m1', ['fetched:control'], ['fetched:control']]], 1) })
  render(<RunManagement runId={RUN} />)
  await waitFor(() => expect(posts(calls).filter(call => call.url.endsWith('/protocol-evidence/evaluate'))).toHaveLength(1))
  await new Promise(resolve => setTimeout(resolve, 100))
  expect(posts(calls).filter(call => call.url.endsWith('/protocol-evidence/evaluate'))).toHaveLength(1)
})

test('metadataFixtureWork keeps the case-defined order', () => {
  const work = metadataFixtureWork(evidence([['m1', ['fetched:control', 'fetched:bad-signature', 'other'], ['fetched:control']]]))
  expect(work).toMatchObject({ totalFixtures: 2, completedFixtures: 1, pendingVariants: ['bad-signature'], nextVariant: 'bad-signature' })
})

test('one shared setting change is recorded with a single action, not one button per case', async () => {
  const calls = setup({
    interactions: [interaction('s1', 'CONFIGURATION', { completionMode: 'OPERATOR' }),
      interaction('s2', 'CONFIGURATION', { completionMode: 'OPERATOR' })],
    campaigns: report({ campaigns: [{ id: 'camp', title: 'Disable signing', plan: 'STANDARD', evidenceClass: 'OPERATOR_ASSISTED',
      actionKind: 'CONFIGURATION', deliberateUserActions: 1, remainingUserActions: 1, freshSessionRequired: false,
      caseIds: ['s1', 's2'], remainingCaseIds: ['s1', 's2'], expectedTranscriptEvidence: [],
      actions: [{ id: 'act', caseIds: ['s1', 's2'], remainingCaseIds: ['s1', 's2'] }] }] }),
  })
  render(<RunManagement runId={RUN} csrfToken="csrf" />)
  const section = (await screen.findByText(/product setting change \(1, optional\)/)).closest('details')!
  expect(within(section).getAllByRole('button')).toHaveLength(1)
  expect(within(section).getByText(/without recorded traffic the cases stay not verified/)).toBeTruthy()
  fireEvent.click(within(section).getByRole('button', { name: 'I made this setting change' }))
  await waitFor(() => expect(posts(calls)).toHaveLength(1))
  expect(posts(calls)[0].url).toBe(`/api/runs/${RUN}/campaigns/camp/actions/act/complete`)
})

test('ECP credentials are used once, cleared and never stored; unknown delivery is not a product failure', async () => {
  const calls = setup({
    profile: 'ecp_idp',
    post: url => url.endsWith('/ecp-probe') ? [{ outboxStatus: 'UNKNOWN_DELIVERY' }] : { ecpProbesRequired: false },
  })
  render(<RunManagement runId={RUN} csrfToken="csrf" />)
  fireEvent.change(await screen.findByLabelText('Username'), { target: { value: 'alice' } })
  fireEvent.change(screen.getByLabelText('Password'), { target: { value: 'hunter2' } })
  fireEvent.click(screen.getByRole('button', { name: 'Run check' }))
  expect(await screen.findByText('Delivery unknown (not counted as a product failure)')).toBeTruthy()
  expect((screen.getByLabelText('Password') as HTMLInputElement).value).toBe('')
  expect((screen.getByLabelText('Username') as HTMLInputElement).value).toBe('')
  expect(JSON.stringify([...Object.entries(window.localStorage), ...Object.entries(window.sessionStorage)])).not.toContain('hunter2')
  expect(posts(calls).some(call => call.body?.includes('hunter2'))).toBe(true)
  expect(document.body.textContent).not.toContain('hunter2')
})

test('a focused case without a pending action says so instead of offering to run tests', async () => {
  setup({ interactions: [interaction('other', 'BROWSER')] })
  render(<RunManagement runId={RUN} focusCaseId="missing" />)
  expect(await screen.findByText('No action needed for this case')).toBeTruthy()
  expect(screen.queryByRole('button', { name: 'Run tests' })).toBeNull()
})

test('saved runs from an earlier definition are read only and make no writes or metadata requests', async () => {
  const calls = setup({
    availability: { code: 'retained', definitionAvailable: true, readOnlyStored: true, liveEvaluationAvailable: false, newRunRequired: true },
    protocolEvidence: evidence([['m1', ['fetched:control'], []]]),
    interactions: [interaction('b1', 'BROWSER')],
  })
  render(<RunManagement runId={RUN} />)
  expect(await screen.findByText(/saved with an earlier test definition and is read-only/)).toBeTruthy()
  expect(screen.getByRole('link', { name: 'Open saved result' }).getAttribute('href')).toBe(`/reports/${RUN}`)
  expect(screen.queryByRole('button')).toBeNull()
  expect(posts(calls)).toHaveLength(0)
  expect(calls.some(call => /metadata-lab|target-initiated|supplemental/.test(call.url))).toBe(false)
})

test('a failed load offers a retry', async () => {
  vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({ message: 'boom' }), { status: 500 })))
  render(<RunManagement runId={RUN} />)
  expect(await screen.findByRole('button', { name: 'Retry' })).toBeTruthy()
})
