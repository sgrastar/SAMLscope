import { afterEach, expect, test, vi } from 'vitest'
import { api } from './api'

afterEach(() => {
  vi.useRealTimers()
  vi.unstubAllGlobals()
})

function busy(code = 'evidence_work_busy') {
  return new Response(JSON.stringify({ error: code, message: 'Evidence reconciliation is busy; retry later' }),
    { status: 503, headers: { 'content-type': 'application/json', 'Retry-After': '1' } })
}
function ok() {
  return new Response(JSON.stringify([]), { status: 200, headers: { 'content-type': 'application/json' } })
}

test('retries a busy 503 after Retry-After and then succeeds', async () => {
  vi.useFakeTimers()
  const fetchMock = vi.fn()
    .mockResolvedValueOnce(busy()).mockResolvedValueOnce(busy('generation_busy')).mockResolvedValueOnce(ok())
  vi.stubGlobal('fetch', fetchMock)
  const result = api.adminUsers()
  await vi.advanceTimersByTimeAsync(5000)
  await expect(result).resolves.toEqual([])
  expect(fetchMock).toHaveBeenCalledTimes(3)
})

test('gives up after a bounded number of attempts and shows the server message', async () => {
  vi.useFakeTimers()
  const fetchMock = vi.fn(async () => busy())
  vi.stubGlobal('fetch', fetchMock)
  const result = api.adminUsers()
  const assertion = expect(result).rejects.toThrow('Evidence reconciliation is busy; retry later')
  await vi.advanceTimersByTimeAsync(30000)
  await assertion
  expect(fetchMock).toHaveBeenCalledTimes(4)
})

test('does not retry other 503 responses or other errors', async () => {
  const fetchMock = vi.fn(async () => new Response(JSON.stringify({ error: 'other', message: 'down' }),
    { status: 503, headers: { 'content-type': 'application/json' } }))
  vi.stubGlobal('fetch', fetchMock)
  await expect(api.adminUsers()).rejects.toThrow('down')
  expect(fetchMock).toHaveBeenCalledTimes(1)
})
