import { cleanup, fireEvent, render, screen } from '@testing-library/react'
import { afterEach, expect, test, vi } from 'vitest'
import type { Plan } from './api'
import { PeerRegistration } from './PeerRegistration'

const plan: Plan = { plan: { id: 'plan_test', name: 'Test IdP', profile: 'IDP_CORE',
  target: { kind: 'IDP', entityId: 'https://target.example' }, requestSigningMode: 'OPTIONAL' },
  entityId: 'https://peer.example/p/plan_test', metadataUrl: 'https://peer.example/p/plan_test/metadata',
  mdqUrl: 'https://peer.example/mdq/encoded', secondaryIdpEntityId: 'https://peer.example/p/plan_test/idp/secondary',
  secondaryIdpMetadataUrl: 'https://peer.example/p/plan_test/idp/secondary/metadata' }

afterEach(() => { cleanup(); vi.restoreAllMocks(); vi.unstubAllGlobals() })

test('explains registration, directional bindings, attributes, and unsigned requests', () => {
  render(<PeerRegistration plan={plan} />)
  expect(screen.getByRole('heading', { name: 'Register SAMLscope as an SP in your IdP' })).toBeTruthy()
  expect(screen.getByText(/Response to SAMLscope ACS/).textContent).toContain('HTTP-POST')
  expect(screen.getByText(/does not specify NameIDPolicy/)).toBeTruthy()
  expect(screen.getByText(/No named user attributes/)).toBeTruthy()
  expect(screen.getByText(/initial Redirect request is unsigned/)).toBeTruthy()
  expect(screen.getByText('https://peer.example/p/plan_test/sp/acs/0')).toBeTruthy()
})

test('copies every registration URL exactly and reports success', async () => {
  const writeText = vi.fn().mockResolvedValue(undefined)
  vi.stubGlobal('navigator', { clipboard: { writeText } })
  render(<PeerRegistration plan={plan} />)
  for (const button of screen.getAllByRole('button', { hidden: true })) {
    const value = button.closest('dd')!.querySelector('a, code')!.textContent
    fireEvent.click(button)
    expect(writeText).toHaveBeenLastCalledWith(value)
  }
  expect(await screen.findByText('Metadata URL copied')).toBeTruthy()
})

test('shows an accessible manual-copy fallback when clipboard is denied', async () => {
  vi.stubGlobal('navigator', { clipboard: { writeText: vi.fn().mockRejectedValue(new Error('denied')) } })
  render(<PeerRegistration plan={plan} />)
  fireEvent.click(screen.getByRole('button', { name: 'Copy Metadata URL' }))
  expect(await screen.findByText(/Could not copy Metadata URL/)).toBeTruthy()
  expect(screen.getByRole('link', { name: plan.metadataUrl }).getAttribute('href')).toBe(plan.metadataUrl)
})

test('distinguishes signed Plans and SP targets', () => {
  const { rerender } = render(<PeerRegistration plan={{ ...plan, plan: { ...plan.plan, requestSigningMode: 'REQUIRED' } }} />)
  expect(screen.getByText(/SAMLscope signs Redirect requests/)).toBeTruthy()
  expect(screen.queryByText(/initial Redirect request is unsigned/)).toBeNull()
  rerender(<PeerRegistration plan={{ ...plan, plan: { ...plan.plan, profile: 'SP_CORE' } }} />)
  expect(screen.getByRole('heading', { name: 'Register SAMLscope as an IdP in your SP' })).toBeTruthy()
  expect(screen.getByText('https://peer.example/p/plan_test/idp/sso')).toBeTruthy()
  expect(screen.queryByText('ACS URL / Reply URL')).toBeNull()
  expect(screen.getByText('urn:oasis:names:tc:SAML:2.0:nameid-format:transient')).toBeTruthy()
})
