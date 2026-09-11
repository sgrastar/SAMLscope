import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, expect, test, vi } from 'vitest'
import { App } from './App'
import { applyPreferredTheme } from './AppShell'
import { stubWorkspaceFetch } from './workspaceTestFixture'

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
  vi.unstubAllGlobals()
  window.localStorage.clear()
})

test('separates operational checks from conformance results', async () => {
  stubWorkspaceFetch(vi.fn(async (input: RequestInfo | URL) => new Response(JSON.stringify(
    String(input).endsWith('/api/health')
      ? { status: 'ok', version: '0.1.0', mode: 'selfhosted' }
      : [],
  ), {
    status: 200,
    headers: { 'content-type': 'application/json' },
  })))
  render(<App />)
  expect(screen.getByText(/Operational quick checks remain separate from conformance results/)).toBeTruthy()
})

test('does not offer local Run creation in hosted mode', async () => {
  window.history.replaceState(null, '', '/')
  vi.stubGlobal('scrollTo', vi.fn())
  stubWorkspaceFetch(vi.fn(async (input: RequestInfo | URL) => {
    const url = String(input)
    const body = url.endsWith('/api/health')
      ? { status: 'ok', version: '0.1.0', mode: 'hosted' }
      : url.endsWith('/api/plans')
        ? [{
            plan: { id: 'plan_0123456789ABCDEFGHJKMNPQRS', name: 'Hosted target', profile: 'browser_sso_idp', target: { kind: 'IDP', entityId: 'https://idp.example' } },
            entityId: 'https://suite.example/p/plan', metadataUrl: 'https://suite.example/p/plan/metadata',
            mdqUrl: 'https://suite.example/mdq/plan', secondaryIdpEntityId: 'https://suite.example/p/plan/idp/secondary',
            secondaryIdpMetadataUrl: 'https://suite.example/p/plan/idp/secondary/metadata',
          }]
        : []
    return new Response(JSON.stringify(body), { status: 200, headers: { 'content-type': 'application/json' } })
  }))

  render(<App />)
  fireEvent.click(await screen.findByRole('button', { name: /Hosted target/ }))

  expect(await screen.findByRole('heading', { name: 'Register SAMLscope as an SP in your IdP' })).toBeTruthy()
  expect(screen.queryByRole('button', { name: 'Create Run and preflight' })).toBeNull()
})

test('shows Run count and latest status in the Test Plan overview', async () => {
  window.history.replaceState(null, '', '/')
  stubWorkspaceFetch(vi.fn(async (input: RequestInfo | URL) => {
    const url = String(input)
    const body = url.endsWith('/api/health')
      ? { status: 'ok', version: '0.1.0', mode: 'selfhosted' }
      : url.endsWith('/api/plans')
        ? [{
            plan: { id: 'plan_0123456789ABCDEFGHJKMNPQRS', name: 'Production IdP', profile: 'browser_sso_idp', target: { kind: 'IDP', entityId: 'https://idp.example' } },
            entityId: 'https://suite.example/p/plan', metadataUrl: 'https://suite.example/p/plan/metadata',
            mdqUrl: 'https://suite.example/mdq/plan', secondaryIdpEntityId: 'https://suite.example/p/plan/idp/secondary',
            secondaryIdpMetadataUrl: 'https://suite.example/p/plan/idp/secondary/metadata',
          }]
        : url.includes('/api/plans/plan_0123456789ABCDEFGHJKMNPQRS/runs')
          ? [
              { id: 'run_1', planId: 'plan_0123456789ABCDEFGHJKMNPQRS', status: 'RUNNING', targetToSuiteReachability: 'CONFIRMED', context: { preflight: { checks: [{ code: 'target_metadata', status: 'PASS' }] } }, updatedAt: 1788750216.704 },
              { id: 'run_2', planId: 'plan_0123456789ABCDEFGHJKMNPQRS', status: 'COMPLETED', targetToSuiteReachability: 'CONFIRMED', context: {}, updatedAt: '2026-09-01T01:00:00Z' },
            ]
          : []
    return new Response(JSON.stringify(body), { status: 200, headers: { 'content-type': 'application/json' } })
  }))

  render(<App />)

  expect(await screen.findByText('2 Runs')).toBeTruthy()
  expect(screen.getByText(/Running/)).toBeTruthy()
  expect(screen.getByText(`Running · ${new Date('2026-09-07T03:03:36.704Z').toLocaleString()}`)).toBeTruthy()
  vi.stubGlobal('scrollTo', vi.fn())
  fireEvent.click(screen.getByRole('button', { name: /Production IdP/ }))
  expect((await screen.findByRole('link', { name: 'Start IdP round trip' })).getAttribute('href'))
    .toBe('https://suite.example/p/plan_0123456789ABCDEFGHJKMNPQRS/start/m0-roundtrip?run=run_1')
})

test('does not misreport a failed Run history request as zero Runs', async () => {
  window.history.replaceState(null, '', '/')
  stubWorkspaceFetch(vi.fn(async (input: RequestInfo | URL) => {
    const url = String(input)
    if (url.endsWith('/api/health')) return new Response(JSON.stringify({
      status: 'ok', version: '0.1.0', mode: 'selfhosted',
    }), { status: 200, headers: { 'content-type': 'application/json' } })
    if (url.endsWith('/api/plans')) return new Response(JSON.stringify([{
      plan: { id: 'plan_0123456789ABCDEFGHJKMNPQRS', name: 'Unavailable history', profile: 'browser_sso_idp',
        target: { kind: 'IDP', entityId: 'https://idp.example' } },
      entityId: 'https://suite.example/p/plan', metadataUrl: 'https://suite.example/p/plan/metadata',
      mdqUrl: 'https://suite.example/mdq/plan', secondaryIdpEntityId: 'https://suite.example/p/plan/idp/secondary',
      secondaryIdpMetadataUrl: 'https://suite.example/p/plan/idp/secondary/metadata',
    }]), { status: 200, headers: { 'content-type': 'application/json' } })
    if (url.includes('/runs')) return new Response(JSON.stringify({ message: 'history store unavailable' }), {
      status: 503, headers: { 'content-type': 'application/json' },
    })
    return new Response(JSON.stringify([]), { status: 200, headers: { 'content-type': 'application/json' } })
  }))

  render(<App />)

  expect(await screen.findByText('Run history unavailable')).toBeTruthy()
  expect(screen.getByText('Refresh to retry')).toBeTruthy()
  expect(screen.queryByText('0 Runs')).toBeNull()
  expect(screen.queryByText('Not started')).toBeNull()
})

test('restores plan navigation when browser history changes', async () => {
  window.history.replaceState(null, '', '/')
  vi.stubGlobal('scrollTo', vi.fn())
  const pushState = vi.spyOn(window.history, 'pushState')
  stubWorkspaceFetch(vi.fn(async (input: RequestInfo | URL) => new Response(JSON.stringify(
    String(input).endsWith('/api/health')
      ? { status: 'ok', version: '0.1.0', mode: 'selfhosted' }
      : [],
  ), { status: 200, headers: { 'content-type': 'application/json' } })))

  render(<App />)
  fireEvent.click(await screen.findByRole('button', { name: 'New Test Plan' }))
  expect(pushState).toHaveBeenCalledWith(null, '', '?new=1')
  expect(screen.getByRole('heading', { name: 'Create Test Plan' })).toBeTruthy()

  window.history.replaceState(null, '', '/')
  window.dispatchEvent(new PopStateEvent('popstate'))
  expect(await screen.findByRole('heading', { name: 'Test Plans' })).toBeTruthy()
})

test('applies the saved theme before the React shell renders', () => {
  window.localStorage.setItem('samlscope.theme', 'dark')
  delete document.documentElement.dataset.theme
  applyPreferredTheme()
  expect(document.documentElement.dataset.theme).toBe('dark')
})

test('reuses one saved metadata revision for a functional profile Plan', async () => {
  window.history.replaceState(null, '', '?new=1')
  vi.stubGlobal('scrollTo', vi.fn())
  let planRequest: Record<string, unknown> | undefined
  const fetch = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input)
    if (url.endsWith('/api/health')) return json({ status: 'ok', version: '0.1.0', mode: 'selfhosted' })
    if (url.endsWith('/api/profiles')) return json(['browser_sso_idp', 'metadata_idp'])
    if (url.endsWith('/api/targets')) return json([{
      id: 'target_saved', name: 'Reusable IdP', entityId: 'https://idp.example',
      revisions: [{ id: 'metadata_saved', roles: ['IDP'], sha256: 'a'.repeat(64), refreshable: true }],
    }])
    if (url.endsWith('/api/plans') && init?.method === 'POST') {
      planRequest = JSON.parse(String(init.body))
      return json({
        plan: {
          plan: { id: 'plan_0123456789ABCDEFGHJKMNPQRS', name: 'Reusable IdP', profile: 'metadata_idp', target: { kind: 'IDP', entityId: 'https://idp.example' } },
          entityId: 'https://suite.example/p/plan', metadataUrl: 'https://suite.example/p/plan/metadata',
          mdqUrl: 'https://suite.example/mdq/plan', secondaryIdpEntityId: 'https://suite.example/p/plan/idp/secondary',
          secondaryIdpMetadataUrl: 'https://suite.example/p/plan/idp/secondary/metadata',
        },
        initialRun: null,
      }, 201)
    }
    if (url.endsWith('/api/plans')) return json([])
    return json([])
  })
  stubWorkspaceFetch(fetch)

  render(<App />)
  fireEvent.click(await screen.findByRole('radio', { name: /Metadata — IdP/ }))
  fireEvent.change(screen.getByLabelText('Saved target'), { target: { value: 'target_saved' } })
  fireEvent.change(screen.getByLabelText('Plan name'), { target: { value: 'Metadata review' } })
  fireEvent.click(screen.getByLabelText('I own or am authorized to test this target.'))
  fireEvent.click(screen.getByRole('button', { name: 'Create plan' }))

  await waitFor(() => expect(planRequest).toBeTruthy())
  expect(planRequest).toMatchObject({
    profile: 'metadata_idp',
    targetConnectionId: 'target_saved',
    targetRevisionId: 'metadata_saved',
    targetEntityId: 'https://idp.example',
  })
  expect(fetch.mock.calls.some(([url, init]) => String(url).endsWith('/api/targets') && init?.method === 'POST')).toBe(false)
})

test('shows creation progress and moves focus to a returned error', async () => {
  window.history.replaceState(null, '', '?new=1')
  vi.stubGlobal('scrollTo', vi.fn())
  const originalScrollIntoView = Element.prototype.scrollIntoView
  const scrollIntoView = vi.fn()
  Element.prototype.scrollIntoView = scrollIntoView
  let finishTarget!: (response: Response) => void
  const targetResponse = new Promise<Response>(resolve => { finishTarget = resolve })
  stubWorkspaceFetch(vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input)
    if (url.endsWith('/api/health')) return json({ status: 'ok', version: '0.1.0', mode: 'hosted', oidcEnabled: false })
    if (url.endsWith('/api/profiles')) return json(['browser_sso_idp'])
    if (url.endsWith('/api/plans')) return json([])
    if (url.endsWith('/api/targets') && init?.method === 'POST') return targetResponse
    return json([])
  }))

  try {
    render(<App />)
    fireEvent.change(await screen.findByLabelText('Plan name'), { target: { value: 'MockIdP' } })
    fireEvent.change(screen.getByLabelText('Target SAML Entity ID'), { target: { value: 'https://mockidp.dev/entityid' } })
    fireEvent.change(screen.getByLabelText('Target metadata URL'), { target: { value: 'https://mockidp.dev/api/saml/metadata' } })
    fireEvent.click(screen.getByLabelText('I own or am authorized to test this target.'))
    fireEvent.click(screen.getByRole('button', { name: 'Create plan' }))

    const busy = await screen.findByRole('button', { name: 'Creating plan…' })
    expect((busy as HTMLButtonElement).disabled).toBe(true)
    expect(busy.getAttribute('aria-busy')).toBe('true')
    finishTarget(json({ message: 'Access denied' }, 403))

    const alert = await screen.findByRole('alert')
    await waitFor(() => expect(document.activeElement).toBe(alert))
    expect(scrollIntoView).toHaveBeenCalledWith({ behavior: 'smooth', block: 'start' })
    expect((screen.getByRole('button', { name: 'Create plan' }) as HTMLButtonElement).disabled).toBe(false)
  } finally {
    Element.prototype.scrollIntoView = originalScrollIntoView
  }
})

test('explains how to fix metadata role and common metadata input errors', async () => {
  window.history.replaceState(null, '', '?new=1')
  vi.stubGlobal('scrollTo', vi.fn())
  const originalScrollIntoView = Element.prototype.scrollIntoView
  Element.prototype.scrollIntoView = vi.fn()
  const fetch = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input)
    if (url.endsWith('/api/health')) return json({ status: 'ok', version: '0.1.0', mode: 'hosted', oidcEnabled: false })
    if (url.endsWith('/api/profiles')) return json(['metadata_sp'])
    if (url.endsWith('/api/targets') && init?.method === 'POST') return json({
      id: 'target_mockidp', name: 'MockIdP', entityId: 'https://mockidp.dev/entityid',
      revisions: [{ id: 'metadata_mockidp', roles: ['IDP'], sha256: 'a'.repeat(64), refreshable: true }],
    }, 201)
    if (url.endsWith('/api/plans') && init?.method === 'POST') {
      return json({ message: 'Target does not have the selected role' }, 400)
    }
    if (url.endsWith('/api/plans')) return json([])
    return json([])
  })
  stubWorkspaceFetch(fetch)

  try {
    render(<App />)
    const profile = await screen.findByRole('radio', { name: /Metadata — SP/ })
    await waitFor(() => expect((profile as HTMLInputElement).checked).toBe(true))
    fireEvent.change(await screen.findByLabelText('Plan name'), { target: { value: 'MockIdP as SP' } })
    fireEvent.change(screen.getByLabelText('Target SAML Entity ID'), { target: { value: 'https://mockidp.dev/entityid' } })
    fireEvent.change(screen.getByLabelText('Target metadata URL'), { target: { value: 'https://mockidp.dev/api/saml/metadata' } })
    fireEvent.click(screen.getByLabelText('I own or am authorized to test this target.'))
    fireEvent.click(screen.getByRole('button', { name: 'Create plan' }))

    expect(await screen.findByText(/requires Service Provider metadata/)).toBeTruthy()
    expect(screen.getByText(/SPSSODescriptor/)).toBeTruthy()
    expect(screen.getByText(/choose an IdP profile/)).toBeTruthy()
    expect(fetch.mock.calls.find(([url, init]) => String(url).endsWith('/api/targets') && init?.method === 'POST')?.[1]?.body)
      .toContain('"expectedRole":"SP"')
  } finally {
    Element.prototype.scrollIntoView = originalScrollIntoView
  }
})

test('keeps the created Run visible without an unauthorized history reload', async () => {
  window.history.replaceState(null, '', '?new=1')
  vi.stubGlobal('scrollTo', vi.fn())
  const planId = 'plan_0123456789ABCDEFGHJKMNPQRS'
  const runId = 'run_0123456789ABCDEFGHJKMNPQRS'
  const fetch = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input)
    if (url.endsWith('/api/health')) return json({ status: 'ok', version: '0.1.0', mode: 'hosted', oidcEnabled: false })
    if (url.endsWith('/api/profiles')) return json(['browser_sso_idp'])
    if (url.endsWith('/api/targets') && init?.method === 'POST') return json({
      id: 'target_mockidp', name: 'MockIdP', entityId: 'https://mockidp.dev/entityid',
      revisions: [{ id: 'metadata_mockidp', roles: ['IDP'], sha256: 'a'.repeat(64), refreshable: true }],
    }, 201)
    if (url.endsWith('/api/plans') && init?.method === 'POST') return json({
      plan: {
        plan: { id: planId, name: 'MockIdP', profile: 'browser_sso_idp',
          target: { kind: 'IDP', entityId: 'https://mockidp.dev/entityid' } },
        entityId: `https://suite.example/p/${planId}`,
        metadataUrl: `https://suite.example/p/${planId}/metadata`,
        mdqUrl: `https://suite.example/mdq/${planId}`,
        secondaryIdpEntityId: `https://suite.example/p/${planId}/idp/secondary`,
        secondaryIdpMetadataUrl: `https://suite.example/p/${planId}/idp/secondary/metadata`,
      },
      initialRun: {
        run: { id: runId, planId, status: 'CREATED', targetToSuiteReachability: 'UNKNOWN', context: {} },
        managementUrl: `https://suite.example/manage/${runId}#t=${'a'.repeat(43)}`,
      },
    }, 201)
    if (url.endsWith('/api/plans')) return json([])
    if (url.endsWith(`/api/plans/${planId}/runs`)) return json({ message: 'Access denied' }, 403)
    return json([])
  })
  stubWorkspaceFetch(fetch)

  render(<App />)
  fireEvent.change(await screen.findByLabelText('Plan name'), { target: { value: 'MockIdP' } })
  fireEvent.change(screen.getByLabelText('Target SAML Entity ID'), { target: { value: 'https://mockidp.dev/entityid' } })
  fireEvent.change(screen.getByLabelText('Target metadata URL'), { target: { value: 'https://mockidp.dev/api/saml/metadata' } })
  fireEvent.click(screen.getByLabelText('I own or am authorized to test this target.'))
  fireEvent.click(screen.getByRole('button', { name: 'Create plan' }))

  expect(await screen.findByRole('heading', { name: 'MockIdP' })).toBeTruthy()
  expect(screen.getByText('1 total')).toBeTruthy()
  expect(screen.getByRole('link', { name: 'Open protected Run' })).toBeTruthy()
  expect(screen.queryByRole('alert')).toBeNull()
  expect(fetch.mock.calls.some(([url]) => String(url).endsWith(`/api/plans/${planId}/runs`))).toBe(false)
})

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } })
}
