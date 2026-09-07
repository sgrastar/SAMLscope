import { cleanup, fireEvent, render, screen } from '@testing-library/react'
import { afterEach, expect, test, vi } from 'vitest'
import { App } from './App'
import { applyPreferredTheme } from './AppShell'

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
  vi.unstubAllGlobals()
  window.localStorage.clear()
})

test('separates operational checks from conformance results', async () => {
  vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL) => new Response(JSON.stringify(
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
  vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL) => {
    const url = String(input)
    const body = url.endsWith('/api/health')
      ? { status: 'ok', version: '0.1.0', mode: 'hosted' }
      : url.endsWith('/api/plans')
        ? [{
            plan: { id: 'plan_0123456789ABCDEFGHJKMNPQRS', name: 'Hosted target', profile: 'IDP_CORE', target: { kind: 'IDP', entityId: 'https://idp.example' } },
            entityId: 'https://suite.example/p/plan', metadataUrl: 'https://suite.example/p/plan/metadata',
            mdqUrl: 'https://suite.example/mdq/plan', secondaryIdpEntityId: 'https://suite.example/p/plan/idp/secondary',
            secondaryIdpMetadataUrl: 'https://suite.example/p/plan/idp/secondary/metadata',
          }]
        : []
    return new Response(JSON.stringify(body), { status: 200, headers: { 'content-type': 'application/json' } })
  }))

  render(<App />)
  fireEvent.click(await screen.findByRole('button', { name: /Hosted target/ }))

  expect(await screen.findByRole('heading', { name: 'Where the target reaches SAMLscope' })).toBeTruthy()
  expect(screen.queryByRole('button', { name: 'Create Run and preflight' })).toBeNull()
})

test('shows Run count and latest status in the Test Plan overview', async () => {
  window.history.replaceState(null, '', '/')
  vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL) => {
    const url = String(input)
    const body = url.endsWith('/api/health')
      ? { status: 'ok', version: '0.1.0', mode: 'selfhosted' }
      : url.endsWith('/api/plans')
        ? [{
            plan: { id: 'plan_0123456789ABCDEFGHJKMNPQRS', name: 'Production IdP', profile: 'IDP_CORE', target: { kind: 'IDP', entityId: 'https://idp.example' } },
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
  vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL) => {
    const url = String(input)
    if (url.endsWith('/api/health')) return new Response(JSON.stringify({
      status: 'ok', version: '0.1.0', mode: 'selfhosted',
    }), { status: 200, headers: { 'content-type': 'application/json' } })
    if (url.endsWith('/api/plans')) return new Response(JSON.stringify([{
      plan: { id: 'plan_0123456789ABCDEFGHJKMNPQRS', name: 'Unavailable history', profile: 'IDP_CORE',
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
  vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL) => new Response(JSON.stringify(
    String(input).endsWith('/api/health')
      ? { status: 'ok', version: '0.1.0', mode: 'selfhosted' }
      : [],
  ), { status: 200, headers: { 'content-type': 'application/json' } })))

  render(<App />)
  fireEvent.click(await screen.findByRole('button', { name: 'New Test Plan' }))
  expect(pushState).toHaveBeenCalledWith(null, '', '?new=1')
  expect(screen.getByRole('heading', { name: 'Register a target' })).toBeTruthy()

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
