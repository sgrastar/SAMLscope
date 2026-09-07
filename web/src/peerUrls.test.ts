import { expect, test } from 'vitest'
import type { Plan } from './api'
import { idpRoundTripUrl } from './peerUrls'

test.each(['https://peer.example', 'https://peer.example:8443', 'http://localhost:8080'])(
  'uses the configured metadata origin %s, including self-hosted ports', origin => {
    const plan = { plan: { id: 'plan_test' }, metadataUrl: `${origin}/p/plan_test/metadata` } as Plan
    expect(idpRoundTripUrl(plan, 'run_test')).toBe(`${origin}/p/plan_test/start/m0-roundtrip?run=run_test`)
  },
)

test('encodes identifiers instead of adding query parameters or path segments', () => {
  const plan = { plan: { id: 'plan/test' }, metadataUrl: 'https://peer.example/p/plan/metadata' } as Plan
  expect(idpRoundTripUrl(plan, 'run&other=value'))
    .toBe('https://peer.example/p/plan%2Ftest/start/m0-roundtrip?run=run%26other%3Dvalue')
})
