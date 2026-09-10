import { cleanup, fireEvent, render, screen } from '@testing-library/react'
import { afterEach, expect, test } from 'vitest'
import { RoundTripLink } from './RoundTripLink'
import { PreflightSummary } from './PreflightSummary'

afterEach(cleanup)

test('round trip shows progress, blocks duplicate clicks and resets on return', () => {
  render(<RoundTripLink href="#idp" />)
  const link = screen.getByRole('link')
  expect(link.getAttribute('target')).toBe('_blank')
  expect(link.getAttribute('rel')).toBe('noreferrer')
  fireEvent.click(link)
  expect(link.textContent).toBe('Opening IdP…')
  expect(link.getAttribute('aria-busy')).toBe('true')
  expect(fireEvent.click(link)).toBe(false)
  fireEvent(window, new Event('pageshow'))
  expect(link.textContent).toBe('Start IdP round trip')
  expect(link.getAttribute('aria-busy')).toBe('false')
  fireEvent.click(link)
  fireEvent(window, new Event('focus'))
  expect(link.textContent).toBe('Start IdP round trip')
})

test('opening another tab preserves the original button', () => {
  render(<RoundTripLink href="#idp" />)
  fireEvent.click(screen.getByRole('link'), { ctrlKey: true })
  expect(screen.getByRole('link').textContent).toBe('Start IdP round trip')
})

test('preflight explains readiness without presenting a conformance verdict', () => {
  const report = { checks: [
    { code: 'target_metadata', status: 'PASS', message: 'Metadata parsed.' },
    { code: 'target_to_suite', status: 'WARNING', message: 'Asserted only.' },
  ] }
  const { rerender } = render(<PreflightSummary report={report} />)
  expect(screen.getByText('Setup checks completed')).toBeTruthy()
  expect(screen.getByText('Not yet verified')).toBeTruthy()
  expect(screen.getByText(/not a SAML conformance verdict/)).toBeTruthy()
  expect(screen.getByText('Technical details').closest('details')?.open).toBe(false)
  rerender(<PreflightSummary report={report} roundTripComplete />)
  expect(screen.getByText(/Continue with the initial checks/)).toBeTruthy()
  expect(screen.queryByText(/continue with login/)).toBeNull()
})

test('failed preflight tells the user to fix setup before login', () => {
  render(<PreflightSummary report={{ checks: [{ code: 'target_metadata', status: 'FAIL', message: 'Metadata unavailable.' }] }} />)
  expect(screen.getByText('Setup needs attention')).toBeTruthy()
  expect(screen.getByText(/Do not start the round trip yet/)).toBeTruthy()
  expect(screen.getByText('Metadata unavailable.')).toBeTruthy()
})
