import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, expect, test, vi } from 'vitest'
import { Admin } from './Admin'
import { api } from './api'

const account = { enabled: true, authenticated: true, accessPolicy: 'required' as const, csrfToken: 'csrf', displayName: 'Operator', userId: 'oidc:admin', role: 'ADMIN' as const }
const user = { id: 'oidc:user', displayName: 'Example user', role: 'USER' as const, status: 'ACTIVE' as const, createdAt: '2026-09-01T00:00:00Z', lastUsedAt: null, version: 2 }
afterEach(() => { cleanup(); vi.restoreAllMocks() })
function setup() {
  vi.spyOn(api, 'health').mockResolvedValue({ status: 'ok', version: 'test', mode: 'hosted', oidcEnabled: true })
  vi.spyOn(api, 'authSession').mockResolvedValue(account)
  vi.spyOn(api, 'adminUsers').mockResolvedValue([{ user, expiresAt: null, expiryCandidate: false }])
  vi.spyOn(api, 'adminPlans').mockResolvedValue([])
}
test('general users never request admin data', async () => {
  setup(); vi.spyOn(api, 'authSession').mockResolvedValue({ ...account, role: 'USER' })
  render(<Admin />)
  expect(await screen.findByRole('heading', { name: 'Admin access required' })).toBeTruthy()
  expect(api.adminUsers).not.toHaveBeenCalled(); expect(api.adminPlans).not.toHaveBeenCalled()
})
test('admin edits a versioned local role and explicitly confirms account deletion', async () => {
  setup()
  const update = vi.spyOn(api, 'updateUser').mockResolvedValue(user)
  const remove = vi.spyOn(api, 'deleteUser').mockResolvedValue()
  render(<Admin />)
  await screen.findByText('Example user')
  fireEvent.click(screen.getByRole('button', { name: 'Edit' }))
  fireEvent.change(screen.getByLabelText('Display name'), { target: { value: 'Updated name' } })
  fireEvent.change(screen.getByLabelText('Role'), { target: { value: 'ANONYMOUS' } })
  fireEvent.click(screen.getByRole('button', { name: 'Save user' }))
  await waitFor(() => expect(update).toHaveBeenCalledWith({ ...user, displayName: 'Updated name', role: 'ANONYMOUS' }))
  await waitFor(() => expect(screen.queryByRole('button', { name: 'Save user' })).toBeNull())
  fireEvent.click(screen.getByRole('button', { name: 'Delete user' }))
  expect(remove).not.toHaveBeenCalled()
  expect(screen.getByRole('alertdialog')).toBeTruthy()
  fireEvent.click(screen.getByRole('button', { name: 'Confirm deletion' }))
  await waitFor(() => expect(remove).toHaveBeenCalledWith(user.id, user.version))
})
test('failed deletion remains visible with its retry controls', async () => {
  setup(); vi.spyOn(api, 'deleteUser').mockRejectedValue(new Error('At least one active admin must remain'))
  render(<Admin />); await screen.findByText('Example user')
  fireEvent.click(screen.getByRole('button', { name: 'Delete user' }))
  fireEvent.click(screen.getByRole('button', { name: 'Confirm deletion' }))
  expect(await screen.findByRole('alert')).toHaveProperty('textContent', 'At least one active admin must remain')
  expect(screen.getByRole('button', { name: 'Cancel' })).toBeTruthy()
})
