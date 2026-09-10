import { render, screen } from '@testing-library/react'
import { afterEach, expect, test, vi } from 'vitest'
import { ResultReport } from './ResultReport'

afterEach(() => vi.restoreAllMocks())

test('renders the authoritative determination and its non-certification boundary', async () => {
  vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({
    schema_version: '1',
    run: { id: 'run_0123456789ABCDEFGHJKMNPQRS', started_at: '2026-08-29T00:00:00Z', finished_at: '2026-08-29T00:01:00Z', conformance: 'CONFORMANT_WITH_WARNINGS', completeness: 'COMPLETE', scope_qualifications: [] },
    suite: { name: 'SAMLscope', version: '0.1.0', image_digest: 'sha256:a', execution_mode: 'self-hosted' },
    evaluation_bundle: { digest: `sha256:${'b'.repeat(64)}` },
    profile: { id: 'browser-sso-idp', spec: { document: 'IIP', version: '1.1', date: '2019-12-18' }, level_definition_note: 'Functional case profile.' },
    target: { declared_product: 'Example IdP', declared_by: 'operator', verified: false, entity_id: 'https://idp.example/entity', metadata_digest: 'sha256:c', role: 'IDP', kind: 'IDP' },
    advisories: [], suite_incidents: [],
    summary: { requirements: { total: 1, verdicts: { pass: 1 } }, obligations: { total: 1, verdicts: { pass: 1 } }, cases: { total: 1, verdicts: { pass: 1 } } },
    evidenceSummary: { externallyVerified: 1, selfAttested: 0, notVerified: 0, externallyVerifiedRatio: 1, selfAttestedRatio: 0 },
    coverage: { obligations_total: 1, obligations_applicable: 1, must_applicable: 1, must_observable: 1, must_resolved: 1, must_unresolved: 0, must_not_observable: 0, verified_ratio: 1 },
    requirements: [{ id: 'IIP-G03', verdict: 'PASS', spec_url: 'https://example.test/spec', obligations: [{ key: 'IIP-G03.a', level: 'MUST_NOT', role: 'IDP', verdict: 'PASS' }], cases: [] }],
    unresolved: [], not_observable: [],
    conformance_statement: 'Conformance: CONFORMANT_WITH_WARNINGS. This is a test result, not a certification.',
  }), { status: 200, headers: { 'content-type': 'application/json' } })))

  render(<ResultReport runId="run_0123456789ABCDEFGHJKMNPQRS" />)

  expect(await screen.findByText('Conformant with warnings')).toBeTruthy()
  expect(screen.getByText('Example IdP', { exact: false })).toBeTruthy()
  expect(screen.getByText('Evidence provenance')).toBeTruthy()
  expect(screen.getByText('Externally verified')).toBeTruthy()
  expect(screen.getByText('Self-attested')).toBeTruthy()
  expect(screen.getByText('IdP')).toBeTruthy()
  expect(screen.queryByText('IDP / IDP')).toBeNull()
  expect(screen.getAllByText(/This is a test result, not a certification/)).toHaveLength(2)
  expect(screen.getByText('IIP-G03')).toBeTruthy()
})
