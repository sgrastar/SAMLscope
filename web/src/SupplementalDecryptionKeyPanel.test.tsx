import { cleanup, fireEvent, render, screen } from '@testing-library/react'
import { afterEach, expect, test, vi } from 'vitest'
import { SupplementalDecryptionKeyPanel, parsePublicKeys } from './SupplementalDecryptionKeyPanel'
import type { SupplementalDecryptionKeyStatus } from './api'

afterEach(cleanup)

const status: SupplementalDecryptionKeyStatus = {
  targetEntityId: 'https://idp.example/entity',
  metadataSha256: 'a'.repeat(64),
  testsStarted: false,
  input: null,
}

test('parses PEM blocks and plain base64 values without accepting junk', () => {
  expect(parsePublicKeys('-----BEGIN PUBLIC KEY-----\nQUJD\nREVG\n-----END PUBLIC KEY-----'))
    .toEqual(['QUJDREVG'])
  expect(parsePublicKeys('QUJD\nREVG')).toEqual(['QUJD', 'REVG'])
  expect(parsePublicKeys('!!!')).toEqual([])
})

test('requires a source reference and at least one key before submitting', () => {
  const onSubmit = vi.fn()
  render(<SupplementalDecryptionKeyPanel status={status} busy={false} error="" onSubmit={onSubmit} />)
  fireEvent.click(screen.getByRole('button', { name: 'Fix decryption key input' }))
  expect(screen.getByRole('alert').textContent).toContain('HTTP(S) reference')
  fireEvent.change(screen.getByLabelText(/Public-key source/), { target: { value: 'https://idp.example/keys' } })
  fireEvent.change(screen.getByLabelText(/RSA public key/), { target: { value: '!!!' } })
  fireEvent.click(screen.getByRole('button', { name: 'Fix decryption key input' }))
  expect(screen.getByRole('alert').textContent).toContain('at least one RSA public key')
  fireEvent.change(screen.getByLabelText(/RSA public key/), { target: { value: 'QUJD\nREVG' } })
  fireEvent.click(screen.getByRole('button', { name: 'Fix decryption key input' }))
  expect(onSubmit).toHaveBeenCalledWith('https://idp.example/keys', ['QUJD', 'REVG'])
})

test('shows the fixed provenance instead of an editable form', () => {
  const fixed: SupplementalDecryptionKeyStatus = {
    ...status,
    testsStarted: true,
    input: {
      runId: 'run_test', targetEntityId: status.targetEntityId, metadataSha256: status.metadataSha256,
      sourceUri: 'https://idp.example/admin/keys', publicKeysSpkiBase64: ['QUJD', 'REVG'],
      recordedAt: '2026-09-15T00:00:00Z',
    },
  }
  render(<SupplementalDecryptionKeyPanel status={fixed} busy={false} error="" onSubmit={vi.fn()} />)
  expect(screen.getByText(/Fixed: 2 supplemental RSA key\(s\) from https:\/\/idp\.example\/admin\/keys/)).toBeTruthy()
  expect(screen.queryByRole('button', { name: 'Fix decryption key input' })).toBeNull()
})

test('marks a fixed absent input and disables new input after tests started', () => {
  const absent: SupplementalDecryptionKeyStatus = {
    ...status,
    testsStarted: true,
    input: {
      runId: 'run_test', targetEntityId: status.targetEntityId, metadataSha256: status.metadataSha256,
      sourceUri: null, publicKeysSpkiBase64: [], recordedAt: '2026-09-15T00:00:00Z',
    },
  }
  render(<SupplementalDecryptionKeyPanel status={absent} busy={false} error="" onSubmit={vi.fn()} />)
  expect(screen.getByText(/Fixed: this Run provides no supplemental decryption key/)).toBeTruthy()
  expect(screen.queryByRole('button', { name: 'Fix decryption key input' })).toBeNull()
})
