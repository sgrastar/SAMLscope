import { expect, test } from 'vitest'
import type { Plan, Run } from './api'
import { idpRoundTripReady, idpRoundTripUrl } from './peerUrls'

const run: Run = { id: 'run_test', planId: 'plan_test', status: 'CREATED',
  targetToSuiteReachability: 'UNKNOWN', context: {} }

test.each([undefined, {}, { preflight: { checks: [] } },
  { preflight: { checks: [{ code: 'target_metadata', status: 'FAIL' }] } },
  { preflight: { checks: [{ code: 'target_metadata', status: 'NOT_CHECKED' }] } },
  { preflight: { checks: [{ code: 'target_metadata', status: 'PASS' }, { code: 'public_base', status: 'FAIL' }] } },
])('does not start SAML with missing or failed preflight: %j', context => {
  expect(idpRoundTripReady({ ...run, context: context ?? {} })).toBe(false)
})

test('allows successful metadata preflight with an operational warning', () => {
  expect(idpRoundTripReady({ ...run, context: { preflight: { checks: [
    { code: 'target_metadata', status: 'PASS' }, { code: 'target_to_suite', status: 'WARNING' },
  ] } } })).toBe(true)
})

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
