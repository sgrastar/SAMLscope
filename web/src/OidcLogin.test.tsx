import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, expect, test, vi } from 'vitest'
import { AppShell } from './AppShell'
import { App } from './App'
import { ManagementBootstrap } from './ManagementBootstrap'
import { api, type PlanInput } from './api'

vi.mock('./RunManagement', () => ({ RunManagement: () => <div>Authorized Run workspace</div> }))

afterEach(async () => {
  cleanup()
  window.history.replaceState(null, '', '/')
  window.sessionStorage.clear()
  vi.stubGlobal('fetch', vi.fn(async () => json({ enabled: false, authenticated: false, csrfToken: null })))
  await api.authSession()
  vi.restoreAllMocks()
})

test('shows sign in only when OIDC is enabled', async () => {
  vi.stubGlobal('fetch', vi.fn(async () => json({ enabled: true, authenticated: false, csrfToken: null })))
  render(<AppShell><p>Plans</p></AppShell>)
  expect((await screen.findByRole('link', { name: 'Sign in' })).getAttribute('href')).toBe('/auth/login')
})

test('uses a separate OIDC CSRF header for mutations and keeps an unsuccessful logout visible', async () => {
  const fetchMock = vi.fn(async (url: string, init?: RequestInit) => {
    if (url === '/auth/session') return json({ enabled: true, authenticated: true, displayName: 'Alice', csrfToken: 'oidc-csrf' })
    if (url === '/api/plans') return json({})
    if (url === '/auth/logout') {
      expect((init?.headers as Record<string, string>)['X-OIDC-CSRF-Token']).toBe('oidc-csrf')
      return new Response('{}', { status: 503 })
    }
    throw new Error(`Unexpected request ${url}`)
  })
  vi.stubGlobal('fetch', fetchMock)
  render(<AppShell><p>Plans</p></AppShell>)
  expect(await screen.findByText('Alice')).toBeTruthy()
  await api.createPlan({} as PlanInput)
  const mutation = fetchMock.mock.calls.find(([url]) => url === '/api/plans')
  expect((mutation?.[1]?.headers as Record<string, string>)['X-OIDC-CSRF-Token']).toBe('oidc-csrf')
  expect(window.sessionStorage.length).toBe(0)
  fireEvent.click(screen.getByRole('button', { name: 'Sign out' }))
  expect(await screen.findByRole('alert')).toHaveProperty('textContent', 'Sign out failed. Please try again.')
})

test('opens an owned Run without a secret fragment only after the API authorizes it', async () => {
  const fetchMock = vi.fn(async (url: string) => {
    if (url === '/api/health') return json({ mode: 'hosted', oidcEnabled: true })
    if (url === '/auth/session') return json({ enabled: true, authenticated: true, displayName: 'Alice', csrfToken: 'csrf' })
    if (url === '/api/runs/run_owned') return json({ id: 'run_owned' })
    throw new Error(`Unexpected request ${url}`)
  })
  vi.stubGlobal('fetch', fetchMock)
  render(<ManagementBootstrap runId="run_owned" />)
  expect(await screen.findByText('Authorized Run workspace')).toBeTruthy()
  expect(fetchMock.mock.calls.some(([url]) => url === '/api/runs/run_owned')).toBe(true)
  expect(fetchMock.mock.calls.some(([url]) => url === '/api/manage/session')).toBe(false)
})

test('does not open a Run merely because the user is authenticated', async () => {
  vi.stubGlobal('fetch', vi.fn(async (url: string) => {
    if (url === '/api/health') return json({ mode: 'hosted', oidcEnabled: true })
    if (url === '/auth/session') return json({ enabled: true, authenticated: true, displayName: 'Bob', csrfToken: 'csrf' })
    return new Response(JSON.stringify({ message: 'Access denied' }), { status: 403 })
  }))
  render(<ManagementBootstrap runId="run_not_owned" />)
  await waitFor(() => expect(screen.getByRole('heading', { name: 'Access denied' })).toBeTruthy())
  expect(screen.queryByText('Authorized Run workspace')).toBeNull()
})

test('direct new-plan navigation asks for login when deployment policy requires it', async () => {
  window.history.replaceState(null, '', '/?new=1')
  vi.stubGlobal('fetch', vi.fn(async (url: string) => {
    if (url === '/api/health') return json({ mode: 'hosted', oidcEnabled: true })
    if (url === '/auth/session') return json({ enabled: true, authenticated: false, accessPolicy: 'new_plans', csrfToken: null })
    return json([])
  }))
  render(<App />)
  expect(await screen.findByRole('heading', { name: 'Sign in to create a Test Plan' })).toBeTruthy()
  expect(screen.queryByRole('button', { name: 'Create plan' })).toBeNull()
})

function json(value: unknown) {
  return new Response(JSON.stringify(value), { status: 200, headers: { 'content-type': 'application/json' } })
}
