import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { afterEach, expect, test, vi } from 'vitest'
import { metadataFixtureWork, RunManagement } from './RunManagement'
import type { MetadataLab } from './api'
import { stubWorkspaceFetch } from './workspaceTestFixture'

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
})

test('loads all evidence through one request without competing section reads', async () => {
  const calls: string[] = []
  vi.stubGlobal('fetch', vi.fn(async (url: string) => {
    calls.push(url)
    if (url.endsWith('/workspace-evidence')) return json({
      interactions: [], bootstrapContracts: [], protocolEvidence: protocolEvidence(),
      activeProbe: { state: 'NOT_STARTED' }, campaigns: [],
    })
    if (url.endsWith('/metadata-lab')) return json(metadataLab())
    if (url === '/api/health') return json({ mode: 'hosted' })
    if (url === '/api/plans') return json([])
    if (url === '/api/runs/run_test') return json({ id: 'run_test', planId: 'plan', context: {} })
    throw new Error(`Unexpected separate evidence request: ${url}`)
  }))
  render(<RunManagement runId="run_test" />)
  expect(await screen.findByText('Run preflight')).toBeTruthy()
  expect(calls.filter(url => url.endsWith('/workspace-evidence'))).toHaveLength(1)
  expect(calls).toHaveLength(5)
})

test.each([false, true])('starts the whole profile and explains ECP prerequisites (%s)', async (ecpProbesRequired) => {
  const posts: string[] = []
  vi.stubGlobal('fetch', vi.fn(async (url: string, init?: RequestInit) => {
    if (init?.method === 'POST') {
      posts.push(url)
      return json({ ecpProbesRequired })
    }
    if (url.endsWith('/workspace-evidence')) return json({
      interactions: [], bootstrapContracts: [], protocolEvidence: protocolEvidence(),
      activeProbe: { state: 'NOT_STARTED' }, campaigns: [],
    })
    if (url.endsWith('/metadata-lab')) return json(metadataLab())
    if (url === '/api/health') return json({ mode: 'selfhosted' })
    if (url === '/api/plans') return json([])
    if (url === '/api/runs/run_test') return json({ id: 'run_test', planId: 'plan', status: 'COMPLETED', context: {} })
    throw new Error(`Unexpected request: ${url}`)
  }))
  render(<RunManagement runId="run_test" />)
  fireEvent.click(await screen.findByRole('button', { name: 'Start or resume tests' }))
  expect(await screen.findByText(ecpProbesRequired
    ? /Next: run the ECP probes below/
    : /Profile tests started or resumed/)).toBeTruthy()
  expect(posts).toEqual(['/api/runs/run_test/tests/start'])
  expect(screen.queryByText(/M1|M2|M3/)).toBeNull()
})

test.each(['ready', 'partial', 'probe-error', 'resume-error', 'start-error'])(
  'handles profile continuation and refreshes partial progress: %s', async (scenario) => {
    const posts: string[] = []
    let evidenceReads = 0
    vi.stubGlobal('fetch', vi.fn(async (url: string, init?: RequestInit) => {
      if (init?.method === 'POST') {
        posts.push(url)
        if ((url.endsWith('/ecp-probe') && scenario === 'probe-error')
          || (url.endsWith('/tests/start') && ['resume-error', 'start-error'].includes(scenario))) {
          return new Response(JSON.stringify({ message: 'Temporary operation failure' }), {
            status: 503, headers: { 'content-type': 'application/json' },
          })
        }
        if (url.endsWith('/ecp-probe')) return json([
          { outboxStatus: 'SENT' }, { outboxStatus: scenario === 'partial' ? 'UNKNOWN_DELIVERY' : 'SENT' },
        ])
        return json({ ecpProbesRequired: scenario === 'partial' })
      }
      if (url.endsWith('/workspace-evidence')) {
        evidenceReads++
        return json({ interactions: [], bootstrapContracts: [], protocolEvidence: protocolEvidence(),
          activeProbe: { state: 'NOT_STARTED' }, campaigns: [] })
      }
      if (url.endsWith('/metadata-lab')) return json(metadataLab())
      if (url === '/api/health') return json({ mode: 'selfhosted' })
      if (url === '/api/plans') return json([{
        plan: { id: 'plan', profile: 'ecp_idp', name: 'ECP target', target: { kind: 'IDP', entityId: 'https://target.example' } },
        entityId: 'https://suite.example/p/plan', metadataUrl: 'https://suite.example/p/plan/metadata',
        mdqUrl: 'https://suite.example/mdq', secondaryIdpEntityId: 'https://suite.example/secondary',
        secondaryIdpMetadataUrl: 'https://suite.example/secondary/metadata',
      }])
      if (url === '/api/runs/run_test') return json({ id: 'run_test', planId: 'plan', status: 'COMPLETED', context: {} })
      throw new Error(`Unexpected request: ${url}`)
    }))
    render(<RunManagement runId="run_test" />)
    const start = await screen.findByRole('button', { name: 'Start or resume tests' })
    if (scenario === 'start-error') fireEvent.click(start)
    else {
      fireEvent.change(screen.getByLabelText('Username'), { target: { value: 'test-user' } })
      fireEvent.change(screen.getByLabelText('Password'), { target: { value: 'test-password' } })
      fireEvent.click(screen.getByRole('button', { name: 'Run ECP probes and continue tests' }))
    }
    await waitFor(() => expect(evidenceReads).toBe(2))
    expect(posts).toEqual(scenario === 'start-error' ? ['/api/runs/run_test/tests/start']
      : scenario === 'probe-error' ? ['/api/runs/run_test/ecp-probe']
      : ['/api/runs/run_test/ecp-probe', '/api/runs/run_test/tests/start'])
    if (scenario.endsWith('error')) expect(screen.getByRole('alert').textContent).toContain('Temporary operation failure')
    if (scenario === 'partial') {
      expect(screen.getByText('Delivery uncertain')).toBeTruthy()
      expect(screen.getByText(/Uncertain delivery is not a target failure/)).toBeTruthy()
    }
    if (scenario === 'ready') expect(screen.getByText(/ECP probes recorded and profile tests resumed/)).toBeTruthy()
    if (['ready', 'partial', 'resume-error'].includes(scenario)) {
      expect((screen.getByLabelText('Password') as HTMLInputElement).value).toBe('')
      expect(screen.getByLabelText('ECP probe delivery status')).toBeTruthy()
    }
  },
)

test('blocks Run actions until the complete initial state loads and supports retry', async () => {
  let unavailable = true
  stubWorkspaceFetch(vi.fn(async (url: string) => {
    if (unavailable) return new Response(JSON.stringify({ message: 'campaign projection unavailable' }), {
      status: 503, headers: { 'content-type': 'application/json' },
    })
    if (url.includes('/bootstrap-contracts')) return json([])
    if (url.includes('/metadata-lab')) return json(metadataLab())
    if (url.includes('/protocol-evidence')) return json(protocolEvidence())
    if (url.includes('/active-probe')) return json({ state: 'NOT_STARTED' })
    if (url.includes('/campaigns')) return json([])
    if (url.includes('/interactions')) return json([])
    if (url === '/api/health') return json({ status: 'ok', version: 'test', mode: 'selfhosted' })
    if (url.includes('/api/runs/')) return json({ id: 'run_0123456789ABCDEFGHJKMNPQRS', planId: 'plan' })
    if (url === '/api/plans') return json([])
    return json([])
  }))

  render(<RunManagement runId="run_0123456789ABCDEFGHJKMNPQRS" />)

  expect(await screen.findByRole('heading', { name: 'Run unavailable' })).toBeTruthy()
  expect(screen.queryByText('Run preflight')).toBeNull()
  expect(screen.queryByText('Start or resume tests')).toBeNull()

  unavailable = false
  fireEvent.click(screen.getByRole('button', { name: 'Retry loading Run' }))
  expect(await screen.findByText('Run preflight')).toBeTruthy()
})

test('shows approved instructions and submits only an option plus evidence note', async () => {
  const calls: Array<{ url: string; init?: RequestInit }> = []
  let pending = true
  stubWorkspaceFetch(vi.fn(async (url: string, init?: RequestInit) => {
    calls.push({ url, init })
    if (init?.method === 'POST') {
      pending = false
      return new Response(JSON.stringify({ status: 'FINISHED' }), {
        status: 200, headers: { 'content-type': 'application/json' },
      })
    }
    if (url.includes('/bootstrap-contracts')) return json([])
    if (url.includes('/metadata-lab')) return json(metadataLab())
    if (url.includes('/protocol-evidence')) return json(protocolEvidence())
    if (url === '/api/health') return json({ status: 'ok', version: 'test', mode: 'selfhosted' })
    if (url.includes('/interactions')) return json(pending ? [{
      caseId: 'IIP-G02-c-idp-01', kind: 'ATTESTATION', promptKey: 'case.g02',
      promptEn: 'Compare the complete value through the approved readback path.', startUrl: null,
      expiresAt: '2026-09-05T00:00:00Z', answerValues: ['satisfied', 'violated', 'unable_to_verify'],
    }] : [])
    if (url.includes('/api/runs/')) return json({ id: 'run_0123456789ABCDEFGHJKMNPQRS', planId: 'plan' })
    if (url === '/api/plans') return json([])
    return json([])
  }))

  render(<RunManagement runId="run_0123456789ABCDEFGHJKMNPQRS" csrfToken="csrf" />)
  expect(await screen.findByText(/approved readback path/)).toBeTruthy()
  fireEvent.click(screen.getByLabelText('Satisfied'))
  fireEvent.change(screen.getByLabelText('Evidence note'), { target: { value: 'Admin audit log entry 17' } })
  fireEvent.click(screen.getByText('Record attestation'))

  await waitFor(() => expect(screen.getByText('No pending interactions.')).toBeTruthy())
  const post = calls.find(call => call.init?.method === 'POST')!
  expect(post.init?.body).toBe(JSON.stringify({ value: 'satisfied', note: 'Admin audit log entry 17' }))
  expect(post.init?.headers).toEqual({ 'content-type': 'application/json', 'X-CSRF-Token': 'csrf' })
  expect(String(post.init?.body)).not.toContain('PASS')
})

test('keeps configuration status separate from the later evidence conclusion', async () => {
  const calls: Array<{ url: string; init?: RequestInit }> = []
  let stage = 'config'
  stubWorkspaceFetch(vi.fn(async (url: string, init?: RequestInit) => {
    calls.push({ url, init })
    if (init?.method === 'POST') {
      stage = 'evidence'
      return new Response(JSON.stringify({ status: 'WAITING_ATTESTATION' }), {
        status: 200, headers: { 'content-type': 'application/json' },
      })
    }
    if (url.includes('/bootstrap-contracts')) return json(stage === 'config' ? [{
      id: 'authentication-policy', title: 'Authentication and identifier policy', description: 'Shared setup.',
      kind: 'OPERATOR_POLICY', readiness: 'SETUP_REQUIRED', setupUrl: null,
      setupInstruction: 'Prepare this policy once.', pendingCases: 1, caseIds: ['IIP-SSO01-u-sp-01'],
    }] : [])
    if (url.includes('/metadata-lab')) return json(metadataLab())
    if (url.includes('/protocol-evidence')) return json(protocolEvidence())
    if (url === '/api/health') return json({ status: 'ok', version: 'test', mode: 'selfhosted' })
    if (url.includes('/interactions')) return json(stage === 'config' ? [{
      caseId: 'IIP-SSO01-u-sp-01', kind: 'CONFIGURATION', promptKey: 'case.config',
      promptEn: 'Activate the approved target configuration.', startUrl: null,
      expiresAt: '2026-09-05T00:00:00Z',
      answerValues: ['confirmed', 'capability_absent', 'target_config_unavailable', 'capability_undetermined'],
    }] : [{
      caseId: 'IIP-SSO01-u-sp-01', kind: 'ATTESTATION', promptKey: 'case.evidence',
      promptEn: 'Execute both approved controls.', startUrl: null,
      expiresAt: '2026-09-05T00:00:00Z',
      answerValues: ['evidence_satisfies', 'evidence_violates', 'unable_to_verify'],
    }])
    if (url.includes('/api/runs/')) return json({ id: 'run_0123456789ABCDEFGHJKMNPQRS', planId: 'plan' })
    if (url === '/api/plans') return json([])
    return json([])
  }))

  render(<RunManagement
    runId="run_0123456789ABCDEFGHJKMNPQRS"
    focusCaseId="IIP-SSO01-u-sp-01"
    csrfToken="csrf"
  />)
  expect(await screen.findByText(/approved target configuration/)).toBeTruthy()
  fireEvent.click(screen.getByLabelText('Confirmed'))
  fireEvent.click(screen.getByText('Continue case'))

  expect(await screen.findByText(/both approved controls/)).toBeTruthy()
  const post = calls.find(call => call.init?.method === 'POST')!
  expect(post.url).toContain('/configure')
  expect(post.init?.body).toBe(JSON.stringify({ value: 'confirmed', note: '' }))
})

test('a focused browser URL shows only the requested case', async () => {
  stubWorkspaceFetch(vi.fn(async (url: string) => {
    if (url.includes('/bootstrap-contracts')) return json([])
    if (url.includes('/metadata-lab')) return json(metadataLab())
    if (url.includes('/protocol-evidence')) return json(protocolEvidence())
    if (url === '/api/health') return json({ status: 'ok', version: 'test', mode: 'selfhosted' })
    if (url.includes('/interactions')) return json([
      {
        caseId: 'IIP-ALG01-a-idp-01', kind: 'BROWSER', promptKey: null,
        promptEn: 'Inspect the target DigestMethod.', startUrl: 'https://suite.example/browser/one',
        expiresAt: '2026-09-05T00:00:00Z', answerValues: ['completed'],
      },
      {
        caseId: 'IIP-ALG02-a-idp-01', kind: 'BROWSER', promptKey: null,
        promptEn: 'Inspect the target SignatureMethod.', startUrl: 'https://suite.example/browser/two',
        expiresAt: '2026-09-05T00:00:00Z', answerValues: ['completed'],
      },
    ])
    if (url.includes('/api/runs/')) return json({ id: 'run_0123456789ABCDEFGHJKMNPQRS', planId: 'plan' })
    if (url === '/api/plans') return json([])
    return json([])
  }))

  render(<RunManagement
    runId="run_0123456789ABCDEFGHJKMNPQRS"
    focusCaseId="IIP-ALG01-a-idp-01"
  />)

  expect(await screen.findByText(/target DigestMethod/)).toBeTruthy()
  expect(screen.queryByText(/target SignatureMethod/)).toBeNull()
  expect(screen.getByRole('link', { name: 'Back to Run management' }).getAttribute('href'))
    .toBe('/manage/run_0123456789ABCDEFGHJKMNPQRS')
})

test('evaluates only server-reported ready protocol evidence from the shared metadata contract', async () => {
  const calls: Array<{ url: string; init?: RequestInit }> = []
  let evaluated = false
  stubWorkspaceFetch(vi.fn(async (url: string, init?: RequestInit) => {
    calls.push({ url, init })
    if (url.includes('/protocol-evidence/evaluate')) {
      evaluated = true
      return json({
        completed: [{ caseId: 'IIP-MD05-an-idp-01', outcome: 'SATISFIED' }],
        remaining: { eligibleCases: 0, readyCases: 0, cases: [] },
      })
    }
    if (url.includes('/bootstrap-contracts')) return json([{
      id: 'metadata-feed', title: 'Suite-controlled metadata feed', description: 'Shared feed.',
      kind: 'STANDARD_METADATA', readiness: 'FETCH_OBSERVED', setupUrl: metadataLab().metadataUrl,
      setupInstruction: 'Use the stable URL.', pendingCases: evaluated ? 0 : 1,
      caseIds: evaluated ? [] : ['IIP-MD05-an-idp-01'],
    }])
    if (url.includes('/metadata-lab')) return json(metadataLab())
    if (url.includes('/protocol-evidence')) return json(evaluated ? protocolEvidence() : {
      eligibleCases: 1, readyCases: 1, cases: [{
        caseId: 'IIP-MD05-an-idp-01', ready: true,
        requiredObservations: ['fetched:control', 'used:control'],
        completedObservations: ['fetched:control', 'used:control'], details: {},
      }],
    })
    if (url.includes('/interactions')) return json(evaluated ? [] : [{
      caseId: 'IIP-MD05-an-idp-01', kind: 'CONFIGURATION', promptKey: 'metadata.probe',
      promptEn: 'Use the shared metadata feed.', startUrl: null,
      expiresAt: '2026-09-05T00:00:00Z', answerValues: ['target_config_unavailable'],
      completionMode: 'TRANSCRIPT_OR_OPERATOR',
    }])
    if (url === '/api/health') return json({ status: 'ok', version: 'test', mode: 'selfhosted' })
    if (url.includes('/api/runs/')) return json({ id: 'run_0123456789ABCDEFGHJKMNPQRS', planId: 'plan' })
    if (url === '/api/plans') return json([])
    return json([])
  }))

  render(<RunManagement runId="run_0123456789ABCDEFGHJKMNPQRS" csrfToken="csrf" />)
  const button = await screen.findByRole('button', {
    name: 'Re-evaluate recorded evidence',
  })
  expect(button.hasAttribute('disabled')).toBe(false)
  fireEvent.click(button)

  expect(await screen.findByText(/IIP-MD05-an-idp-01: SATISFIED/)).toBeTruthy()
  const post = calls.find(call => call.url.includes('/protocol-evidence/evaluate'))!
  expect(post.init?.method).toBe('POST')
  expect(post.init?.headers).toEqual({ 'content-type': 'application/json', 'X-CSRF-Token': 'csrf' })
})

test('confirms one metadata campaign operation without collecting per-case verdict answers', async () => {
  const calls: Array<{ url: string; init?: RequestInit }> = []
  stubWorkspaceFetch(vi.fn(async (url: string, init?: RequestInit) => {
    calls.push({ url, init })
    if (url.includes('/protocol-evidence/confirm-attempts')) return json({
      completed: [{ caseId: 'IIP-MD04-b-idp-01', outcome: 'SATISFIED' }],
      remaining: { eligibleCases: 0, readyCases: 0, cases: [] },
    })
    if (url.includes('/bootstrap-contracts')) return json([{
      id: 'metadata-feed', title: 'Suite-controlled metadata feed', description: 'Shared feed.',
      kind: 'STANDARD_METADATA', readiness: 'FETCH_OBSERVED', setupUrl: metadataLab().metadataUrl,
      setupInstruction: 'Use the stable URL.', pendingCases: 1,
      caseIds: ['IIP-MD04-b-idp-01'],
    }])
    if (url.includes('/metadata-lab')) return json(metadataLab())
    if (url.includes('/protocol-evidence')) return json({
      eligibleCases: 1, readyCases: 0, cases: [{
        caseId: 'IIP-MD04-b-idp-01', ready: false,
        requiredObservations: ['fetched:expired', 'conclusive-rejection:expired'],
        completedObservations: ['fetched:expired'], details: {},
      }],
    })
    if (url.includes('/interactions')) return json([])
    if (url === '/api/health') return json({ status: 'ok', version: 'test', mode: 'selfhosted' })
    if (url.includes('/api/runs/')) return json({ id: 'run_0123456789ABCDEFGHJKMNPQRS', planId: 'plan' })
    if (url === '/api/plans') return json([])
    return json([])
  }))

  render(<RunManagement runId="run_0123456789ABCDEFGHJKMNPQRS" csrfToken="csrf" />)
  fireEvent.click(await screen.findByRole('button', {
    name: 'Confirm all listed refreshes and flows were attempted',
  }))

  expect(await screen.findByText(/IIP-MD04-b-idp-01: SATISFIED/)).toBeTruthy()
  const post = calls.find(call => call.url.includes('/protocol-evidence/confirm-attempts'))!
  expect(post.init?.method).toBe('POST')
  expect(post.init?.headers).toEqual({ 'content-type': 'application/json', 'X-CSRF-Token': 'csrf' })
})

test('selects the next incomplete metadata fixture without asking for a verdict', async () => {
  const calls: Array<{ url: string; init?: RequestInit }> = []
  let selected = 'control'
  stubWorkspaceFetch(vi.fn(async (url: string, init?: RequestInit) => {
    calls.push({ url, init })
    if (url.includes('/metadata-lab/variant') && init?.method === 'POST') {
      selected = JSON.parse(String(init.body)).variant
      return json({ ...metadataLab(), selectedVariant: selected })
    }
    if (url.includes('/bootstrap-contracts')) return json([{
      id: 'metadata-feed', title: 'Suite-controlled metadata feed', description: 'Shared feed.',
      kind: 'STANDARD_METADATA', readiness: 'FETCH_OBSERVED', setupUrl: metadataLab().metadataUrl,
      setupInstruction: 'Use the stable URL.', pendingCases: 1, caseIds: ['IIP-MD04-b-idp-01'],
    }])
    if (url.includes('/metadata-lab')) return json({ ...metadataLab(), selectedVariant: selected })
    if (url.includes('/protocol-evidence')) return json({
      eligibleCases: 1, readyCases: 0, cases: [{
        caseId: 'IIP-MD04-b-idp-01', ready: false,
        requiredObservations: ['fetched:control', 'used:control', 'fetched:expired', 'conclusive-rejection:expired'],
        completedObservations: ['fetched:control', 'used:control'], details: {},
      }],
    })
    if (url.includes('/interactions')) return json([])
    if (url === '/api/health') return json({ status: 'ok', version: 'test', mode: 'selfhosted' })
    if (url.includes('/api/runs/')) return json({ id: 'run_0123456789ABCDEFGHJKMNPQRS', planId: 'plan' })
    if (url === '/api/plans') return json([])
    return json([])
  }))

  render(<RunManagement runId="run_0123456789ABCDEFGHJKMNPQRS" csrfToken="csrf" />)
  const button = await screen.findByRole('button', {
    name: 'Select next incomplete fixture: Expired',
  })
  fireEvent.click(button)

  expect(await screen.findByText(/Next incomplete metadata fixture selected: expired/)).toBeTruthy()
  const post = calls.find(call => call.url.includes('/metadata-lab/variant'))!
  expect(post.init?.body).toBe(JSON.stringify({ variant: 'expired' }))
  expect(String(post.init?.body)).not.toContain('verdict')
})

test('metadata fixture work queue deduplicates observations shared by several cases', () => {
  expect(metadataFixtureWork({
    eligibleCases: 2,
    readyCases: 0,
    cases: [
      { caseId: 'one', ready: false, requiredObservations: ['fetched:control', 'fetched:expired'],
        completedObservations: ['fetched:control'], details: {} },
      { caseId: 'two', ready: false, requiredObservations: ['fetched:control', 'fetched:expired', 'used:control'],
        completedObservations: ['fetched:control', 'used:control'], details: {} },
    ],
  })).toEqual({
    totalFixtures: 2,
    completedFixtures: 1,
    nextVariant: 'expired',
    nextOperation: 'fetched:expired',
    pendingVariants: ['expired'],
  })
})

test('metadata fixture work queue preserves the approved observation order and starts with control', () => {
  expect(metadataFixtureWork({
    eligibleCases: 1,
    readyCases: 0,
    cases: [{
      caseId: 'one', ready: false,
      requiredObservations: ['fetched:control', 'used:control', 'fetched:bad-signature'],
      completedObservations: [], details: {},
    }],
  })).toEqual({
    totalFixtures: 2,
    completedFixtures: 0,
    nextVariant: 'control',
    nextOperation: 'fetched:control',
    pendingVariants: ['control', 'bad-signature'],
  })
})

test('arms one automatic polling campaign without collecting target verdict answers', async () => {
  const calls: Array<{ url: string; init?: RequestInit }> = []
  const navigateTo = vi.fn()
  let lab: MetadataLab = metadataLab()
  stubWorkspaceFetch(vi.fn(async (url: string, init?: RequestInit) => {
    calls.push({ url, init })
    if (url.includes('/metadata-lab/automatic-polling') && init?.method === 'POST') {
      const variants = JSON.parse(String(init.body)).variants as string[]
      lab = { ...lab, ingestionMode: 'AUTOMATIC_POLLING', campaignVariants: variants,
        campaignIndex: 0, campaignComplete: false, selectedVariant: variants[0],
        pollingDelaySeconds: 15, operatorContinuationActions: 0,
        automaticStartUrl: 'https://suite.example/p/plan/start/metadata-polling/0?run=run&poll=token',
        automaticContinueUrl: null }
      return json(lab)
    }
    if (url.includes('/bootstrap-contracts')) return json([{
      id: 'metadata-feed', title: 'Suite-controlled metadata feed', description: 'Shared feed.',
      kind: 'STANDARD_METADATA', readiness: 'SETUP_REQUIRED', setupUrl: lab.metadataUrl,
      setupInstruction: 'Use the stable URL.', pendingCases: 1, caseIds: ['IIP-MD04-b-idp-01'],
    }])
    if (url.includes('/metadata-lab')) return json(lab)
    if (url.includes('/protocol-evidence')) return json({
      eligibleCases: 1, readyCases: 0, cases: [{
        caseId: 'IIP-MD04-b-idp-01', ready: false,
        requiredObservations: ['fetched:control', 'used:control', 'fetched:expired'],
        completedObservations: [], details: {},
      }],
    })
    if (url.includes('/interactions')) return json([])
    if (url === '/api/health') return json({ status: 'ok', version: 'test', mode: 'selfhosted' })
    if (url.includes('/api/runs/')) return json({ id: 'run_0123456789ABCDEFGHJKMNPQRS', planId: 'plan' })
    if (url === '/api/plans') return json([])
    return json([])
  }))

  render(<RunManagement runId="run_0123456789ABCDEFGHJKMNPQRS" csrfToken="csrf"
    navigateTo={navigateTo} />)
  fireEvent.click(await screen.findByRole('button', { name: 'Arm automatic polling for 2 fixtures' }))

  expect(await screen.findByText(/Automatic metadata polling armed with 2 fixtures/)).toBeTruthy()
  expect(await screen.findByText(/0\/2 fixtures completed/)).toBeTruthy()
  expect(screen.getByRole('link', { name: 'Start or resume the signed metadata campaign' })
    .getAttribute('href')).toContain('/start/metadata-polling/0')
  const post = calls.find(call => call.url.includes('/automatic-polling'))!
  expect(post.init?.body).toBe(JSON.stringify({
    variants: ['control', 'expired'], pollingDelaySeconds: 15,
  }))
  expect(String(post.init?.body)).not.toContain('verdict')
  expect(navigateTo).toHaveBeenCalledWith(
    'https://suite.example/p/plan/start/metadata-polling/0?run=run&poll=token')
})

test('offers one aggregate import for compatible positive metadata fixtures', async () => {
  const calls: Array<{ url: string; init?: RequestInit }> = []
  let lab: MetadataLab = metadataLab()
  stubWorkspaceFetch(vi.fn(async (url: string, init?: RequestInit) => {
    calls.push({ url, init })
    if (url.includes('/metadata-lab/preloaded') && init?.method === 'POST') {
      lab = { ...lab, ingestionMode: 'PRELOADED_AGGREGATE',
        automaticStartUrl: null, automaticContinueUrl: null,
        preloadedMetadataUrl: 'https://suite.example/p/plan/metadata/preloaded?run=run&preload=token',
        preloadedDownloadUrl: 'https://suite.example/p/plan/metadata/preloaded/download?run=run&preload=token',
        preloadedStartUrl: 'https://suite.example/p/plan/start/metadata-preloaded/0?run=run&preload=token',
        preloadedVariants: ['unknown-extension', 'certificate-expired'], preloadedFetched: false }
      return json(lab)
    }
    if (url.includes('/bootstrap-contracts')) return json([{
      id: 'metadata-feed', title: 'Suite-controlled metadata feed', description: 'Shared feed.',
      kind: 'STANDARD_METADATA', readiness: 'SETUP_REQUIRED', setupUrl: lab.metadataUrl,
      setupInstruction: 'Use the stable URL.', pendingCases: 1, caseIds: ['IIP-MD05-a3-idp-01'],
    }])
    if (url.includes('/metadata-lab')) return json(lab)
    if (url.includes('/protocol-evidence')) return json({
      eligibleCases: 1, readyCases: 0, cases: [{
        caseId: 'IIP-MD05-a3-idp-01', ready: false,
        requiredObservations: ['fetched:control', 'used:control', 'fetched:unknown-extension'],
        completedObservations: [], details: {},
      }],
    })
    if (url.includes('/interactions')) return json([])
    if (url === '/api/health') return json({ status: 'ok', version: 'test', mode: 'selfhosted' })
    if (url.includes('/api/runs/')) return json({ id: 'run_0123456789ABCDEFGHJKMNPQRS', planId: 'plan' })
    if (url === '/api/plans') return json([])
    return json([])
  }))

  render(<RunManagement runId="run_0123456789ABCDEFGHJKMNPQRS" csrfToken="csrf" />)
  fireEvent.click(await screen.findByRole('button', {
    name: 'Prepare one-time aggregate for compatible positive fixtures',
  }))

  expect(await screen.findByText(/Preloaded aggregate prepared with 2 compatible positive fixtures/)).toBeTruthy()
  expect(await screen.findByText(/metadata\/preloaded\?run=run&preload=token/)).toBeTruthy()
  expect(screen.getByRole('link', { name: 'Download signed aggregate XML' })
    .getAttribute('download')).toBe('samlscope-metadata-campaign.xml')
  const post = calls.find(call => call.url.includes('/metadata-lab/preloaded'))!
  expect(post.init?.body).toBe('{}')
  expect(String(post.init?.body)).not.toContain('verdict')
})

test('explains that protocol-driven configuration answers are only an unavailability fallback', async () => {
  stubWorkspaceFetch(vi.fn(async (url: string) => {
    if (url.includes('/active-probe')) return json({ state: 'NOT_STARTED' })
    if (url.includes('/bootstrap-contracts')) return json([])
    if (url.includes('/metadata-lab')) return json(metadataLab())
    if (url.includes('/protocol-evidence')) return json(protocolEvidence())
    if (url.includes('/interactions')) return json([{
      caseId: 'IIP-MD05-an-idp-01', kind: 'CONFIGURATION', promptKey: 'metadata.probe',
      promptEn: 'Use the shared metadata feed.', startUrl: null,
      expiresAt: '2026-09-05T00:00:00Z', answerValues: ['target_config_unavailable'],
      completionMode: 'TRANSCRIPT_OR_OPERATOR',
    }])
    if (url === '/api/health') return json({ status: 'ok', version: 'test', mode: 'selfhosted' })
    if (url.includes('/api/runs/')) return json({ id: 'run_0123456789ABCDEFGHJKMNPQRS', planId: 'plan' })
    if (url === '/api/plans') return json([])
    return json([])
  }))

  render(<RunManagement
    runId="run_0123456789ABCDEFGHJKMNPQRS"
    focusCaseId="IIP-MD05-an-idp-01"
  />)

  expect(await screen.findByText(/completes automatically when all required correlated Transcript evidence/))
    .toBeTruthy()
  expect(screen.getByText('Target config unavailable')).toBeTruthy()
})

test('does not offer completed for a transcript-driven browser case', async () => {
  stubWorkspaceFetch(vi.fn(async (url: string) => {
    if (url.includes('/active-probe')) return json({ state: 'NOT_STARTED' })
    if (url.includes('/bootstrap-contracts')) return json([])
    if (url.includes('/metadata-lab')) return json(metadataLab())
    if (url.includes('/protocol-evidence')) return json(protocolEvidence())
    if (url.includes('/interactions')) return json([{
      caseId: 'IIP-SSO03-a-idp-01', kind: 'BROWSER', promptKey: null,
      promptEn: 'Perform the ordinary SSO flow.', startUrl: 'https://suite.example/start',
      expiresAt: '2026-09-05T00:00:00Z', answerValues: [], completionMode: 'TRANSCRIPT',
    }])
    if (url === '/api/health') return json({ status: 'ok', version: 'test', mode: 'selfhosted' })
    if (url.includes('/api/runs/')) return json({ id: 'run_0123456789ABCDEFGHJKMNPQRS', planId: 'plan' })
    if (url === '/api/plans') return json([])
    return json([])
  }))

  render(<RunManagement runId="run_0123456789ABCDEFGHJKMNPQRS" />)

  expect(await screen.findByText(/No completion answer is needed/)).toBeTruthy()
  expect(screen.queryByRole('button', { name: 'Browser steps completed' })).toBeNull()
  expect(screen.getByRole('link', { name: 'Open focused browser step' }).getAttribute('target')).toBe('_blank')
  expect(screen.getByRole('link', { name: 'Open focused browser step' }).getAttribute('rel')).toBe('noreferrer')
})

test('offers the server-generated active probe launch URL and explains fresh-session isolation', async () => {
  stubWorkspaceFetch(vi.fn(async (url: string) => {
    if (url.includes('/active-probe')) return json({
      planId: 'plan', state: 'READY', actionId: 'action_probe',
      startUrl: 'https://peer.example/p/plan/probe/action_probe?run=run_0123456789ABCDEFGHJKMNPQRS',
      requiresFreshSession: true, outcome: null,
      caseId: 'IIP-IDP05-a-idp-01',
      instructionsEn: 'Run the positive control and approved abnormal AuthnRequest fixtures.',
    })
    if (url.includes('/bootstrap-contracts')) return json([])
    if (url.includes('/metadata-lab')) return json(metadataLab())
    if (url.includes('/protocol-evidence')) return json(protocolEvidence())
    if (url.includes('/interactions')) return json([{
      caseId: 'IIP-IDP05-a-idp-01', kind: 'BROWSER', promptKey: null,
      promptEn: 'Run the positive control and approved abnormal AuthnRequest fixtures.',
      startUrl: 'https://peer.example/p/plan/probe/action_probe?run=run_0123456789ABCDEFGHJKMNPQRS',
      expiresAt: '2026-09-05T00:00:00Z', answerValues: ['completed'], completionMode: 'OPERATOR',
    }])
    if (url === '/api/health') return json({ status: 'ok', version: 'test', mode: 'selfhosted' })
    if (url.includes('/api/runs/')) return json({ id: 'run_0123456789ABCDEFGHJKMNPQRS', planId: 'plan', context: {
      preflight: { checks: [{ code: 'target_metadata', status: 'PASS' }] },
    } })
    if (url === '/api/plans') return json([{
      plan: { id: 'plan', name: 'Target IdP', profile: 'browser_sso_idp', target: { kind: 'IDP', entityId: 'https://idp.example' } },
      entityId: 'https://suite.example/p/plan', metadataUrl: 'https://suite.example/p/plan/metadata',
      mdqUrl: 'https://suite.example/mdq/plan', secondaryIdpEntityId: 'https://suite.example/p/plan/idp/secondary',
      secondaryIdpMetadataUrl: 'https://suite.example/p/plan/idp/secondary/metadata',
    }])
    return json([])
  }))

  render(<RunManagement runId="run_0123456789ABCDEFGHJKMNPQRS" />)

  expect(await screen.findAllByText('IIP-IDP05-a-idp-01')).toHaveLength(1)
  expect(screen.getByText(/positive control/)).toBeTruthy()
  expect(screen.getByText(/private browser context/)).toBeTruthy()
  expect(screen.queryByRole('button', { name: 'Browser steps completed' })).toBeNull()
  expect(screen.getByRole('link', { name: 'Open one browser check' }).getAttribute('href'))
    .toContain('/probe/action_probe')
  expect(screen.getByRole('link', { name: 'Open one browser check' }).getAttribute('target')).toBe('_blank')
  expect(screen.getByRole('link', { name: 'Start IdP round trip' }).getAttribute('href'))
    .toBe('https://suite.example/p/plan/start/m0-roundtrip?run=run_0123456789ABCDEFGHJKMNPQRS')
  expect(screen.getByText('No other pending interactions. Continue the active probe above.')).toBeTruthy()
  expect(screen.queryByText('No pending interactions.')).toBeNull()
})

test('keeps an ungrouped configuration interaction in the main work queue', async () => {
  stubWorkspaceFetch(vi.fn(async (url: string) => {
    if (url.includes('/active-probe')) return json({ state: 'NOT_STARTED' })
    if (url.includes('/bootstrap-contracts')) return json([])
    if (url.includes('/metadata-lab')) return json(metadataLab())
    if (url.includes('/protocol-evidence')) return json(protocolEvidence())
    if (url.includes('/campaigns')) return json({
      runId: 'run_0123456789ABCDEFGHJKMNPQRS', cases: 1,
      casesByEvidenceClass: { PROTOCOL_OBSERVED: 0, OPERATOR_ASSISTED: 1, SELF_ATTESTED: 0 },
      externallyVerifiedCases: 0, selfAttestedCases: 0, notVerifiedCases: 1,
      plans: [], classifications: [], campaigns: [],
    })
    if (url.includes('/interactions')) return json([{
      caseId: 'IIP-SP01-a-sp-01', kind: 'CONFIGURATION', promptKey: 'case.config',
      promptEn: 'Configure the target policy.', startUrl: null,
      expiresAt: '2026-09-05T00:00:00Z', answerValues: ['confirmed', 'target_config_unavailable'],
      completionMode: 'OPERATOR',
    }])
    if (url === '/api/health') return json({ status: 'ok', version: 'test', mode: 'selfhosted' })
    if (url.includes('/api/runs/')) return json({ id: 'run_0123456789ABCDEFGHJKMNPQRS', planId: 'plan' })
    if (url === '/api/plans') return json([])
    return json([])
  }))

  render(<RunManagement runId="run_0123456789ABCDEFGHJKMNPQRS" />)

  expect(await screen.findByText('Manual configuration input')).toBeTruthy()
  expect(screen.getByText('Configure the target policy.')).toBeTruthy()
  expect(screen.queryByText(/available under the shared setup contracts/)).toBeNull()
})

test('filters the approved case workspace without changing case outcomes', async () => {
  stubWorkspaceFetch(vi.fn(async (url: string) => {
    if (url.includes('/campaigns')) return json({
      runId: 'run_0123456789ABCDEFGHJKMNPQRS', cases: 3,
      casesByEvidenceClass: { PROTOCOL_OBSERVED: 2, OPERATOR_ASSISTED: 1, SELF_ATTESTED: 0 },
      externallyVerifiedCases: 1, selfAttestedCases: 0, notVerifiedCases: 2,
      plans: [
        { plan: 'QUICK', cases: 2, deliberateUserActions: 1, remainingUserActions: 1,
          loginActions: 1, configurationActions: 0, metadataRefreshActions: 0,
          selfAttestationSections: 0, estimatedMinutesMin: 10, estimatedMinutesMax: 20,
          actionBudget: 15, budgetMet: true },
        { plan: 'STANDARD', cases: 1, deliberateUserActions: 1, remainingUserActions: 1,
          loginActions: 0, configurationActions: 1, metadataRefreshActions: 0,
          selfAttestationSections: 0, estimatedMinutesMin: 30, estimatedMinutesMax: 60,
          actionBudget: 35, budgetMet: true },
      ],
      campaigns: [
        { id: 'ordinary-sso', title: 'Ordinary SSO', plan: 'QUICK', evidenceClass: 'PROTOCOL_OBSERVED',
          actionKind: 'LOGIN', deliberateUserActions: 1, remainingUserActions: 1, freshSessionRequired: true,
          caseIds: ['IIP-SSO01-a-idp-01', 'IIP-SSO01-b-idp-01'], remainingCaseIds: ['IIP-SSO01-b-idp-01'],
          expectedTranscriptEvidence: ['AuthnRequest', 'Response'], actions: [] },
        { id: 'policy', title: 'Target policy', plan: 'STANDARD', evidenceClass: 'OPERATOR_ASSISTED',
          actionKind: 'CONFIGURATION', deliberateUserActions: 1, remainingUserActions: 1, freshSessionRequired: false,
          caseIds: ['IIP-ALG04-a-idp-01'], remainingCaseIds: ['IIP-ALG04-a-idp-01'],
          expectedTranscriptEvidence: ['EncryptedAssertion'], actions: [] },
      ],
      classifications: [
        { caseId: 'IIP-SSO01-a-idp-01', plan: 'QUICK', evidenceClass: 'PROTOCOL_OBSERVED',
          campaignId: 'ordinary-sso', actionKind: 'LOGIN', freshSessionRequired: true, resolved: true,
          outcome: 'SATISFIED',
          expectedTranscriptEvidence: ['AuthnRequest', 'Response'] },
        { caseId: 'IIP-SSO01-b-idp-01', plan: 'QUICK', evidenceClass: 'PROTOCOL_OBSERVED',
          campaignId: 'ordinary-sso', actionKind: 'LOGIN', freshSessionRequired: true, resolved: false,
          outcome: null,
          expectedTranscriptEvidence: ['AuthnRequest', 'Response'] },
        { caseId: 'IIP-ALG04-a-idp-01', plan: 'STANDARD', evidenceClass: 'OPERATOR_ASSISTED',
          campaignId: 'policy', actionKind: 'CONFIGURATION', freshSessionRequired: false, resolved: false,
          outcome: 'NOT_VERIFIED',
          expectedTranscriptEvidence: ['EncryptedAssertion'] },
      ],
    })
    if (url.includes('/active-probe')) return json({ state: 'NOT_STARTED' })
    if (url.includes('/bootstrap-contracts')) return json([])
    if (url.includes('/metadata-lab')) return json(metadataLab())
    if (url.includes('/protocol-evidence')) return json(protocolEvidence())
    if (url.includes('/interactions')) return json([{
      caseId: 'IIP-ALG04-a-idp-01', kind: 'CONFIGURATION', promptKey: 'case.config',
      promptEn: 'Apply the approved encryption policy, then continue.', startUrl: null,
      expiresAt: '2026-09-05T00:00:00Z',
      answerValues: ['confirmed', 'capability_absent', 'target_config_unavailable', 'capability_undetermined'],
      completionMode: 'OPERATOR',
    }])
    if (url === '/api/health') return json({ status: 'ok', version: 'test', mode: 'selfhosted' })
    if (url.includes('/api/runs/')) return json({ id: 'run_0123456789ABCDEFGHJKMNPQRS', planId: 'plan' })
    if (url === '/api/plans') return json([])
    return json([])
  }))

  render(<RunManagement runId="run_0123456789ABCDEFGHJKMNPQRS" />)

  expect(await screen.findByRole('heading', { name: 'Case workspace' })).toBeTruthy()
  expect(screen.queryByText('IIP-SSO01-a-idp-01')).toBeNull()
  expect(screen.getByText('IIP-SSO01-b-idp-01')).toBeTruthy()
  expect(screen.getByRole('button', { name: /IIP-ALG04-a-idp-01/ })).toBeTruthy()

  fireEvent.click(screen.getByRole('button', { name: 'Not verified' }))
  expect(screen.queryByText('IIP-SSO01-b-idp-01')).toBeNull()
  expect(screen.getByRole('button', { name: /IIP-ALG04-a-idp-01/ })).toBeTruthy()

  fireEvent.click(screen.getByRole('button', { name: 'All cases' }))
  expect(screen.getByText('IIP-SSO01-a-idp-01')).toBeTruthy()

  fireEvent.click(screen.getByRole('button', { name: 'Operator assisted' }))
  expect(screen.queryByRole('button', { name: /IIP-ALG04-a-idp-01/ })).toBeNull()

  fireEvent.change(screen.getByLabelText('Search cases'), { target: { value: 'ordinary' } })
  expect(screen.getByText('IIP-SSO01-a-idp-01')).toBeTruthy()
  expect(screen.getByText('IIP-SSO01-b-idp-01')).toBeTruthy()
  expect(screen.getByText('2 cases shown')).toBeTruthy()

  fireEvent.click(screen.getByRole('button', { name: 'Operator assisted' }))
  fireEvent.change(screen.getByLabelText('Search cases'), { target: { value: 'approved encryption policy' } })
  const caseButton = screen.getByRole('button', { name: /IIP-ALG04-a-idp-01/ })
  expect(screen.getByText('1 case shown')).toBeTruthy()
  fireEvent.click(caseButton)

  const dialog = screen.getByRole('dialog', { name: 'IIP-ALG04-a-idp-01' })
  expect(within(dialog).getByText(/approved encryption policy/)).toBeTruthy()
  const continueButton = within(dialog).getByRole('button', { name: 'Continue case' })
  const closeButton = within(dialog).getByRole('button', { name: 'Close case details' })
  await waitFor(() => expect(document.activeElement).toBe(closeButton))
  fireEvent.keyDown(document, { key: 'Tab', shiftKey: true })
  expect(document.activeElement).toBe(continueButton)
  fireEvent.click(closeButton)
  await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
  await waitFor(() => expect(document.activeElement).toBe(caseButton))

  fireEvent.click(caseButton)
  expect(screen.getByRole('dialog', { name: 'IIP-ALG04-a-idp-01' })).toBeTruthy()
  fireEvent.keyDown(document, { key: 'Escape' })
  await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
  await waitFor(() => expect(document.activeElement).toBe(caseButton))
})

test('reissues an uncertain one-time fixture without turning it into a target failure', async () => {
  const calls: Array<{ url: string; init?: RequestInit }> = []
  let retried = false
  stubWorkspaceFetch(vi.fn(async (url: string, init?: RequestInit) => {
    calls.push({ url, init })
    if (url.includes('/active-probe/retry') && init?.method === 'POST') {
      retried = true
      return json({ planId: 'plan', state: 'READY', actionId: 'action_retry',
        startUrl: '/p/plan/probe/action_retry?run=run', requiresFreshSession: false,
        caseId: 'IIP-IDP05-a-idp-01', instructionsEn: 'Retry the same fixture.' })
    }
    if (url.includes('/active-probe')) return json(retried
      ? { planId: 'plan', state: 'READY', actionId: 'action_retry',
          startUrl: '/p/plan/probe/action_retry?run=run', requiresFreshSession: false,
          caseId: 'IIP-IDP05-a-idp-01', instructionsEn: 'Retry the same fixture.' }
      : { planId: 'plan', state: 'AWAITING_RESPONSE', actionId: 'action_original',
          startUrl: null, requiresFreshSession: false,
          caseId: 'IIP-IDP05-a-idp-01', instructionsEn: 'Run the fixture.' })
    if (url.includes('/bootstrap-contracts')) return json([])
    if (url.includes('/metadata-lab')) return json(metadataLab())
    if (url.includes('/protocol-evidence')) return json(protocolEvidence())
    if (url.includes('/interactions')) return json([])
    if (url === '/api/health') return json({ status: 'ok', version: 'test', mode: 'selfhosted' })
    if (url.includes('/api/runs/')) return json({ id: 'run_0123456789ABCDEFGHJKMNPQRS', planId: 'plan' })
    if (url === '/api/plans') return json([])
    return json([])
  }))

  render(<RunManagement runId="run_0123456789ABCDEFGHJKMNPQRS" csrfToken="csrf" />)
  fireEvent.click(await screen.findByRole('button', { name: 'Reissue this one-time fixture' }))

  expect(await screen.findByRole('link', { name: 'Open one browser check' })).toBeTruthy()
  expect(await screen.findByText(/new one-time fixture was issued/)).toBeTruthy()
  const post = calls.find(call => call.url.includes('/active-probe/retry'))!
  expect(post.init?.headers).toEqual({ 'content-type': 'application/json', 'X-CSRF-Token': 'csrf' })
})

test('shows plan action budgets and keeps self-attested evidence separate', async () => {
  stubWorkspaceFetch(vi.fn(async (url: string) => {
    if (url.includes('/campaigns')) return json({
      runId: 'run_0123456789ABCDEFGHJKMNPQRS', cases: 220,
      casesByEvidenceClass: { PROTOCOL_OBSERVED: 143, OPERATOR_ASSISTED: 55, SELF_ATTESTED: 22 },
      externallyVerifiedCases: 120, selfAttestedCases: 4, notVerifiedCases: 96,
      plans: [
        { plan: 'QUICK', cases: 143, deliberateUserActions: 12, remainingUserActions: 3,
          loginActions: 5, configurationActions: 0, metadataRefreshActions: 0,
          selfAttestationSections: 0, estimatedMinutesMin: 10, estimatedMinutesMax: 20,
          actionBudget: 15, budgetMet: true },
        { plan: 'STANDARD', cases: 198, deliberateUserActions: 31, remainingUserActions: 9,
          loginActions: 9, configurationActions: 8, metadataRefreshActions: 2,
          selfAttestationSections: 0, estimatedMinutesMin: 30, estimatedMinutesMax: 60,
          actionBudget: 35, budgetMet: true },
        { plan: 'FULL', cases: 220, deliberateUserActions: 39, remainingUserActions: 12,
          loginActions: 9, configurationActions: 8, metadataRefreshActions: 2,
          selfAttestationSections: 8, estimatedMinutesMin: 60, estimatedMinutesMax: 90,
          actionBudget: 50, budgetMet: true },
      ],
      campaigns: [{
        id: 'self-processing', title: 'XML and implementation processing', plan: 'FULL',
        evidenceClass: 'SELF_ATTESTED', actionKind: 'SELF_CHECK', deliberateUserActions: 1,
        remainingUserActions: 1, freshSessionRequired: false,
        caseIds: ['IIP-G02-c-idp-01'], remainingCaseIds: ['IIP-G02-c-idp-01'],
        expectedTranscriptEvidence: [],
      }],
    })
    if (url.includes('/active-probe')) return json({ state: 'NOT_STARTED' })
    if (url.includes('/bootstrap-contracts')) return json([])
    if (url.includes('/metadata-lab')) return json(metadataLab())
    if (url.includes('/protocol-evidence')) return json(protocolEvidence())
    if (url.includes('/interactions')) return json([])
    if (url === '/api/health') return json({ status: 'ok', version: 'test', mode: 'selfhosted' })
    if (url.includes('/api/runs/')) return json({ id: 'run_0123456789ABCDEFGHJKMNPQRS', planId: 'plan' })
    if (url === '/api/plans') return json([])
    return json([])
  }))

  render(<RunManagement runId="run_0123456789ABCDEFGHJKMNPQRS" />)

  expect(await screen.findByText('Choose evidence depth, not individual cases')).toBeTruthy()
  expect(screen.getByText(/12 total \/ 3 remaining/)).toBeTruthy()
  expect(screen.getByText(/Externally verified:/)).toBeTruthy()
  expect(screen.getByText(/Self-attested:/)).toBeTruthy()
  expect(screen.getByText('8')).toBeTruthy()
})

test('completes one shared policy action without collecting a target verdict', async () => {
  const calls: Array<{ url: string; init?: RequestInit }> = []
  let completed = false
  stubWorkspaceFetch(vi.fn(async (url: string, init?: RequestInit) => {
    calls.push({ url, init })
    if (init?.method === 'POST' && url.includes('/campaigns/')) {
      completed = true
      return json({ runId: 'run_0123456789ABCDEFGHJKMNPQRS', completed: [] })
    }
    if (url.includes('/campaigns')) return json({
      runId: 'run_0123456789ABCDEFGHJKMNPQRS', cases: 2,
      casesByEvidenceClass: { PROTOCOL_OBSERVED: 0, OPERATOR_ASSISTED: 2, SELF_ATTESTED: 0 },
      externallyVerifiedCases: 0, selfAttestedCases: 0, notVerifiedCases: 2,
      plans: [], classifications: [],
      campaigns: [{
        id: 'operator_assisted-configuration-shared-crypto-policy',
        title: 'Cryptographic algorithm policy', plan: 'STANDARD',
        evidenceClass: 'OPERATOR_ASSISTED', actionKind: 'CONFIGURATION',
        deliberateUserActions: 1, remainingUserActions: completed ? 0 : 1,
        freshSessionRequired: false,
        caseIds: ['IIP-ALG04-a-idp-01', 'IIP-ALG04-b-idp-01'],
        remainingCaseIds: completed ? [] : ['IIP-ALG04-a-idp-01', 'IIP-ALG04-b-idp-01'],
        expectedTranscriptEvidence: [],
        actions: [{
          id: 'content-encryption-policy',
          caseIds: ['IIP-ALG04-a-idp-01', 'IIP-ALG04-b-idp-01'],
          remainingCaseIds: completed ? [] : ['IIP-ALG04-a-idp-01', 'IIP-ALG04-b-idp-01'],
        }],
      }],
    })
    if (url.includes('/interactions')) return json(completed ? [] : [
      { caseId: 'IIP-ALG04-a-idp-01', kind: 'BROWSER', promptEn: 'Observe AES128-GCM.',
        startUrl: '/browser/run/first', expiresAt: '2026-09-05T00:00:00Z',
        answerValues: ['completed'], completionMode: 'OPERATOR' },
      { caseId: 'IIP-ALG04-b-idp-01', kind: 'BROWSER', promptEn: 'Observe AES256-GCM.',
        startUrl: '/browser/run/second', expiresAt: '2026-09-05T00:00:00Z',
        answerValues: ['completed'], completionMode: 'OPERATOR' },
    ])
    if (url.includes('/active-probe')) return json({ state: 'NOT_STARTED' })
    if (url.includes('/bootstrap-contracts')) return json([])
    if (url.includes('/metadata-lab')) return json(metadataLab())
    if (url.includes('/protocol-evidence')) return json(protocolEvidence())
    if (url === '/api/health') return json({ status: 'ok', version: 'test', mode: 'selfhosted' })
    if (url.includes('/api/runs/')) return json({ id: 'run_0123456789ABCDEFGHJKMNPQRS', planId: 'plan' })
    if (url === '/api/plans') return json([])
    return json([])
  }))

  render(<RunManagement runId="run_0123456789ABCDEFGHJKMNPQRS" csrfToken="csrf" />)

  expect(await screen.findByText('Shared target policy changes')).toBeTruthy()
  expect(screen.getByText('2 CASES')).toBeTruthy()
  expect(screen.queryAllByText('Browser steps completed')).toHaveLength(0)
  fireEvent.click(screen.getByText('Continue after applying this shared policy'))

  await waitFor(() => expect(completed).toBe(true))
  const post = calls.find(call => call.init?.method === 'POST')
  expect(post?.url).toContain('/campaigns/operator_assisted-configuration-shared-crypto-policy/actions/content-encryption-policy/complete')
  expect(post?.init?.body).toBe('{}')
})

test('shares one section conclusion while preserving case-specific overrides', async () => {
  const calls: Array<{ url: string; init?: RequestInit }> = []
  let completed = false
  stubWorkspaceFetch(vi.fn(async (url: string, init?: RequestInit) => {
    calls.push({ url, init })
    if (init?.method === 'POST') {
      if (url.includes('/attest')) completed = true
      return json({ status: url.includes('/configure') ? 'WAITING_ATTESTATION' : 'FINISHED' })
    }
    if (url.includes('/campaigns')) return json({
      runId: 'run_0123456789ABCDEFGHJKMNPQRS', cases: 2,
      casesByEvidenceClass: { PROTOCOL_OBSERVED: 0, OPERATOR_ASSISTED: 0, SELF_ATTESTED: 2 },
      externallyVerifiedCases: 0, selfAttestedCases: completed ? 2 : 0, notVerifiedCases: completed ? 0 : 2,
      plans: [], classifications: [],
      campaigns: [{
        id: 'self_attested-self_check-shared-self-metadata-acquisition',
        title: 'Metadata acquisition, refresh, and trust', plan: 'FULL',
        evidenceClass: 'SELF_ATTESTED', actionKind: 'SELF_CHECK', deliberateUserActions: 1,
        remainingUserActions: completed ? 0 : 1, freshSessionRequired: false,
        caseIds: ['IIP-MD03-b-idp-01', 'IIP-MD03-c-idp-01'],
        remainingCaseIds: completed ? [] : ['IIP-MD03-b-idp-01', 'IIP-MD03-c-idp-01'],
        expectedTranscriptEvidence: [],
      }],
    })
    if (url.includes('/interactions')) return json(completed ? [] : [
      {
        caseId: 'IIP-MD03-b-idp-01', kind: 'CONFIGURATION', promptKey: 'case.config',
        promptEn: 'Configure an out-of-band metadata verification key.', startUrl: null,
        expiresAt: '2026-09-05T00:00:00Z',
        answerValues: ['confirmed', 'capability_absent', 'target_config_unavailable', 'capability_undetermined'],
        completionMode: 'OPERATOR',
      },
      {
        caseId: 'IIP-MD03-c-idp-01', kind: 'ATTESTATION', promptKey: 'case.attest',
        promptEn: 'Review the key-use isolation evidence.', startUrl: null,
        expiresAt: '2026-09-05T00:00:00Z',
        answerValues: ['evidence_satisfies', 'evidence_violates', 'unable'], completionMode: 'OPERATOR',
      },
    ])
    if (url.includes('/active-probe')) return json({ state: 'NOT_STARTED' })
    if (url.includes('/bootstrap-contracts')) return json([])
    if (url.includes('/metadata-lab')) return json(metadataLab())
    if (url.includes('/protocol-evidence')) return json(protocolEvidence())
    if (url === '/api/health') return json({ status: 'ok', version: 'test', mode: 'selfhosted' })
    if (url.includes('/api/runs/')) return json({ id: 'run_0123456789ABCDEFGHJKMNPQRS', planId: 'plan' })
    if (url === '/api/plans') return json([])
    return json([])
  }))

  render(<RunManagement runId="run_0123456789ABCDEFGHJKMNPQRS" csrfToken="csrf" />)

  expect(await screen.findByText('Grouped self-check sections')).toBeTruthy()
  fireEvent.change(screen.getByLabelText('Section evidence conclusion'), { target: { value: 'satisfied' } })
  fireEvent.change(screen.getAllByLabelText('Case-specific override')[1], { target: { value: 'violated' } })
  fireEvent.change(screen.getByLabelText('Shared evidence note'), { target: { value: 'Shared policy export' } })
  fireEvent.click(screen.getByText('Record section'))

  await waitFor(() => expect(completed).toBe(true))
  const posts = calls.filter(call => call.init?.method === 'POST')
  expect(posts).toHaveLength(3)
  expect(posts[0].url).toContain('/configure')
  expect(posts[1].url).toContain('/attest')
  expect(posts[1].init?.body).toBe(JSON.stringify({ value: 'evidence_satisfies', note: 'Shared policy export' }))
  expect(posts[2].url).toContain('/attest')
  expect(posts[2].init?.body).toBe(JSON.stringify({ value: 'evidence_violates', note: 'Shared policy export' }))
})

function metadataLab() {
  return {
    runId: 'run_0123456789ABCDEFGHJKMNPQRS', planId: 'plan', selectedVariant: 'control',
    metadataUrl: 'https://suite.example/p/plan/metadata/live?run=run_0123456789ABCDEFGHJKMNPQRS',
    availableVariants: ['control', 'no-key-info'],
    ingestionMode: 'MANUAL_REFRESH' as const, campaignVariants: [], campaignIndex: 0,
    campaignComplete: false, automaticStartUrl: null, automaticContinueUrl: null,
    pollingDelaySeconds: 15, operatorContinuationActions: 0,
    preloadedMetadataUrl: null, preloadedDownloadUrl: null, preloadedStartUrl: null,
    preloadedVariants: [], preloadedFetched: false,
  }
}

function protocolEvidence() {
  return { eligibleCases: 0, readyCases: 0, cases: [] }
}

function json(value: unknown) {
  return new Response(JSON.stringify(value), { status: 200, headers: { 'content-type': 'application/json' } })
}
