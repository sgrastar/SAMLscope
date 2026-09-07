import { cleanup, render, screen } from '@testing-library/react'
import { afterEach, expect, test, vi } from 'vitest'
import { ManagementBootstrap } from './ManagementBootstrap'
import { api } from './api'
import { stubWorkspaceFetch } from './workspaceTestFixture'

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
  window.history.replaceState(null, '', '/')
  window.sessionStorage.clear()
})

test('removes the fragment before exchanging it and keeps only the CSRF token in session storage', async () => {
  const runId = 'run_0123456789ABCDEFGHJKMNPQRS'
  const token = 'a'.repeat(43)
  window.history.replaceState(null, '', `/manage/${runId}#t=${token}`)
  const replace = vi.spyOn(window.history, 'replaceState')
  const fetchMock = vi.fn(async (url: string, init?: RequestInit) => {
    if (url.includes('/interactions')) return new Response(JSON.stringify([]), {
      status: 200, headers: { 'content-type': 'application/json' },
    })
    if (url.includes('/bootstrap-contracts')) return json([])
    if (url.includes('/metadata-lab')) return json({
      runId, planId: 'plan', selectedVariant: 'control', metadataUrl: 'https://suite.example/metadata',
      availableVariants: ['control'], ingestionMode: 'MANUAL_REFRESH', campaignVariants: [],
      campaignIndex: 0, campaignComplete: false, pollingDelaySeconds: 15, operatorContinuationActions: 0, automaticStartUrl: null, automaticContinueUrl: null, preloadedMetadataUrl: null, preloadedDownloadUrl: null,
      preloadedStartUrl: null, preloadedVariants: [], preloadedFetched: false,
    })
    if (url.includes('/protocol-evidence')) return json({ eligibleCases: 0, readyCases: 0, cases: [] })
    if (url.includes('/active-probe')) return json({ state: 'NOT_STARTED' })
    expect(window.location.hash).toBe('')
    expect(init?.body).toBe(JSON.stringify({ runId, token }))
    return new Response(JSON.stringify({ runId, csrfToken: 'c'.repeat(43) }), {
      status: 200, headers: { 'content-type': 'application/json' },
    })
  })
  stubWorkspaceFetch(fetchMock)

  render(<ManagementBootstrap runId={runId} />)

  expect(await screen.findByText('Run unlocked')).toBeTruthy()
  expect(replace).toHaveBeenCalledWith(null, '', `/manage/${runId}`)
  expect(window.sessionStorage.getItem(`samlscope.csrf.${runId}`)).toBe('c'.repeat(43))
  expect(document.body.textContent).not.toContain(token)
})

test('opens a self-hosted management page without a fragment secret', async () => {
  const runId = 'run_0123456789ABCDEFGHJKMNPQRS'
  window.history.replaceState(null, '', `/manage/${runId}`)
  stubWorkspaceFetch(vi.fn(async (url: string) => new Response(JSON.stringify(
    url === '/api/health' ? { status: 'ok', version: 'test', mode: 'selfhosted' }
      : url.includes('/metadata-lab') ? {
        runId, planId: 'plan', selectedVariant: 'control', metadataUrl: 'https://suite.example/metadata',
        availableVariants: ['control'], ingestionMode: 'MANUAL_REFRESH', campaignVariants: [],
        campaignIndex: 0, campaignComplete: false, pollingDelaySeconds: 15, operatorContinuationActions: 0, automaticStartUrl: null, automaticContinueUrl: null, preloadedMetadataUrl: null, preloadedDownloadUrl: null,
        preloadedStartUrl: null, preloadedVariants: [], preloadedFetched: false,
      } : url.includes('/protocol-evidence') ? { eligibleCases: 0, readyCases: 0, cases: [] } : [],
  ), { status: 200, headers: { 'content-type': 'application/json' } })))

  render(<ManagementBootstrap runId={runId} />)

  expect(await screen.findByText('Run unlocked')).toBeTruthy()
  expect(await screen.findByText('No pending interactions.')).toBeTruthy()
})

function json(value: unknown) {
  return new Response(JSON.stringify(value), { status: 200, headers: { 'content-type': 'application/json' } })
}

test('resumes a hosted cookie session without the original fragment or tab storage', async () => {
  const runId = 'run_0123456789ABCDEFGHJKMNPQRS'
  vi.spyOn(api, 'health').mockResolvedValue({ status: 'ok', version: 'test', mode: 'hosted', oidcEnabled: false })
  vi.spyOn(api, 'run').mockResolvedValue({ id: runId, planId: 'plan', status: 'CREATED',
    targetToSuiteReachability: 'UNKNOWN', context: {} })
  const resume = vi.spyOn(api, 'resumeManagementSession').mockResolvedValue({ runId, csrfToken: 'resumed-csrf' })
  stubWorkspaceFetch(vi.fn(async () => json([])))

  render(<ManagementBootstrap runId={runId} />)

  expect(await screen.findByText('Run unlocked')).toBeTruthy()
  expect(resume).toHaveBeenCalledWith(runId)
  expect(window.sessionStorage.getItem(`samlscope.csrf.${runId}`)).toBe('resumed-csrf')
  expect(screen.queryByRole('link', { name: 'Start IdP round trip' })).toBeNull()
})

test('does not unlock a hosted Run using stale tab storage when the server denies access', async () => {
    const runId = 'run_0123456789ABCDEFGHJKMNPQRS'
    window.sessionStorage.setItem(`samlscope.csrf.${runId}`, 'stale-csrf')
    vi.spyOn(api, 'health').mockResolvedValue({ status: 'ok', version: 'test', mode: 'hosted', oidcEnabled: false })
    vi.spyOn(api, 'run').mockRejectedValue(new Error('Management access denied'))
    const resume = vi.spyOn(api, 'resumeManagementSession')

    render(<ManagementBootstrap runId={runId} />)

    expect(await screen.findByText('Access denied')).toBeTruthy()
    expect(resume).not.toHaveBeenCalled()
    expect(screen.queryByText('Run unlocked')).toBeNull()
})

test('keeps OIDC account access without requiring a legacy Run cookie', async () => {
  const runId = 'run_0123456789ABCDEFGHJKMNPQRS'
  vi.spyOn(api, 'health').mockResolvedValue({ status: 'ok', version: 'test', mode: 'hosted', oidcEnabled: true })
  vi.spyOn(api, 'run').mockResolvedValue({ id: runId, planId: 'plan', status: 'CREATED',
    targetToSuiteReachability: 'UNKNOWN', context: {} })
  vi.spyOn(api, 'authSession').mockResolvedValue({ enabled: true, authenticated: true,
    accessPolicy: 'required', displayName: 'Owner', csrfToken: 'oidc-csrf' })
  const resume = vi.spyOn(api, 'resumeManagementSession')
  stubWorkspaceFetch(vi.fn(async () => json([])))

  render(<ManagementBootstrap runId={runId} />)

  expect(await screen.findByText('Run unlocked')).toBeTruthy()
  expect(resume).not.toHaveBeenCalled()
})
