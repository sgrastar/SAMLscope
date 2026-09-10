import { cleanup, fireEvent, render, screen } from '@testing-library/react'
import { afterEach, expect, test, vi } from 'vitest'
import { Licenses } from './Licenses'
import { api } from './api'

afterEach(() => { cleanup(); vi.restoreAllMocks(); vi.unstubAllGlobals() })
test('shows software scope and retained dependency notices as text', async () => {
  vi.spyOn(api, 'authSession').mockRejectedValue(new Error('No auth service'))
  vi.stubGlobal('fetch', vi.fn().mockImplementation((url: string) => Promise.resolve({ ok: true, json: async () => url.includes('source-notices') ? { sources: [{ id: 'example', title: 'Example source', source_url: 'https://example.org/source', edition: '1.0', date: '2020-01-01', notice_location: 'Copyright and license sections', license_url: 'https://creativecommons.org/licenses/by-sa/3.0/us/', notice_text: 'Original specification notice', catalog_correction_pending: true }] } : ({ packages: [
    { name: 'react', version: '19.2.8', license: 'MIT', notices: [{ file: 'LICENSE', text: 'Copyright example <script>notice text</script>' }] },
  ] }) })))
  render(<Licenses />)
  expect(screen.getByRole('heading', { name: 'Licenses and sources' })).toBeTruthy()
  fireEvent.click(screen.getByText('Apache License, Version 2.0'))
  expect(screen.getByText(/TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION/)).toBeTruthy()
  fireEvent.click(await screen.findByText('react 19.2.8 — MIT'))
  expect(screen.getByText('Copyright example <script>notice text</script>')).toBeTruthy()
  fireEvent.click(await screen.findByText('Example source — 1.0, 2020-01-01'))
  expect(screen.getByText('Original specification notice')).toBeTruthy()
  expect(screen.getByRole('link', { name: 'Original license terms' }).getAttribute('href')).toBe('https://creativecommons.org/licenses/by-sa/3.0/us/')
  expect(screen.queryByText(/Notice page undefined/)).toBeNull()
  expect(screen.getByText(/catalog correction is pending review/)).toBeTruthy()
  expect(document.querySelector('script')).toBeNull()
  expect(screen.getByText(/Source notices are included in browser and standalone outputs/)).toBeTruthy()
})
