export type Profile = 'IDP_CORE' | 'IDP_FULL' | 'SP_CORE' | 'SP_FULL'

export interface Plan {
  plan: {
    id: string
    name: string
    profile: Profile
    target: { kind: 'IDP' | 'SP' | 'TOKEN_TRANSLATION_PROXY'; entityId: string }
  }
  entityId: string
  metadataUrl: string
  mdqUrl: string
  secondaryIdpEntityId: string
  secondaryIdpMetadataUrl: string
}

export interface Run {
  id: string
  planId: string
  status: string
  targetToSuiteReachability: string
  context: Record<string, unknown>
  createdAt?: string | number
  updatedAt?: string | number
}

export interface RunCreated {
  run: Run
  managementUrl: string | null
}

export interface PlanCreated {
  plan: Plan
  initialRun: RunCreated | null
}

export interface PublicResult {
  schemaVersion: '1'
  run: {
    id: string
    startedAt: string
    finishedAt: string
    conformance: string
    completeness: string
    scopeQualifications: Array<{
      kind: string
      predicate: string
      excludedObligations: string[]
      reason: string
      attestedBy: string
      attestedAt: string
      verified: false
    }>
  }
  suite: { name: string; version: string; imageDigest: string; executionMode: string }
  evaluationBundle: { digest: string }
  profile: { id: string; spec: { document: string; version: string; date: string }; levelDefinitionNote: string }
  target: {
    declaredProduct: string
    declaredBy: string
    verified: false
    entityId: string
    metadataDigest: string
    role: string
    kind: string
  }
  advisories: Array<{ code: string; obligation: string; severity: string; messageEn: string; affectsVerdict: false }>
  suiteIncidents: Array<{ kind: string; caseId?: string; actionId?: string; note: string }>
  summary: {
    requirements: ResultCount
    obligations: ResultCount
    cases: ResultCount
  }
  evidenceSummary: {
    externallyVerified: number
    selfAttested: number
    notVerified: number
    externallyVerifiedRatio: number
    selfAttestedRatio: number
  }
  coverage: {
    obligationsTotal: number
    obligationsApplicable: number
    mustApplicable: number
    mustObservable: number
    mustResolved: number
    mustUnresolved: number
    mustNotObservable: number
    verifiedRatio: number
  }
  requirements: Array<{
    id: string
    verdict: string
    specUrl: string
    obligations: Array<{ key: string; level: string; role: string; verdict: string }>
    cases: Array<{ id: string; obligation: string; outcome: string | null; verdict: string; mode: string; reason: string; evidenceClass: string }>
  }>
  unresolved: Array<{ obligation: string; level: string; verdict: string; reasons: string[]; howToResolve: string }>
  notObservable: Array<{ obligation: string; level: string; reason: string }>
  conformanceStatement: string
}

interface ResultCount {
  total: number
  verdicts: Record<string, number>
}

export interface PlanInput {
  name: string
  profile: Profile
  targetKind: 'IDP' | 'SP' | 'TOKEN_TRANSLATION_PROXY'
  targetEntityId: string
  metadataSourceKind: 'URL'
  metadataSourceLocation: string
  suiteMetadataDelivery: 'MANUAL' | 'HTTP_URL' | 'MDQ'
  declaredFeatures: Record<string, boolean>
  parameters: { clockSkewToleranceSeconds: number; metadataRefreshWaitSeconds: number; testUserHint: string }
  interaction: { allowBrowserSteps: boolean; allowAttestation: boolean }
  authorizedTarget: boolean
}

export interface ManagementSession {
  runId: string
  csrfToken: string
}

export interface PendingInteraction {
  caseId: string
  kind: 'BROWSER' | 'CONFIGURATION' | 'ATTESTATION'
  promptKey: string | null
  promptEn: string | null
  startUrl: string | null
  expiresAt: string | number
  answerValues: string[]
  completionMode?: 'OPERATOR' | 'TRANSCRIPT' | 'TRANSCRIPT_OR_OPERATOR'
}

export interface BootstrapContract {
  id: string
  title: string
  description: string
  kind: 'STANDARD_METADATA' | 'OPERATOR_POLICY'
  readiness: 'SETUP_REQUIRED' | 'FETCH_OBSERVED' | 'MANUAL_ONLY'
  setupUrl: string | null
  setupInstruction: string
  pendingCases: number
  caseIds: string[]
}

export interface MetadataLab {
  runId: string
  planId: string
  selectedVariant: string
  metadataUrl: string
  availableVariants: string[]
  ingestionMode: 'MANUAL_REFRESH' | 'AUTOMATIC_POLLING' | 'PRELOADED_AGGREGATE'
  campaignVariants: string[]
  campaignIndex: number
  campaignComplete: boolean
  pollingDelaySeconds: number
  operatorContinuationActions: number
  automaticStartUrl: string | null
  automaticContinueUrl: string | null
  preloadedMetadataUrl: string | null
  preloadedDownloadUrl: string | null
  preloadedStartUrl: string | null
  preloadedVariants: string[]
  preloadedFetched: boolean
}

export interface ProtocolEvidenceStatus {
  eligibleCases: number
  readyCases: number
  cases: Array<{
    caseId: string
    ready: boolean
    requiredObservations: string[]
    completedObservations: string[]
    details: Record<string, unknown>
  }>
}

export interface ProtocolEvidenceEvaluation {
  completed: Array<{ caseId: string; outcome: string }>
  remaining: ProtocolEvidenceStatus
}

export interface ActiveProbeStatus {
  planId: string
  state: 'NOT_STARTED' | 'READY' | 'AWAITING_RESPONSE' | 'FINISHED' | 'UNAVAILABLE'
  actionId: string | null
  startUrl: string | null
  requiresFreshSession: boolean
  outcome: string | null
  caseId: string | null
  instructionsEn: string | null
}

export interface CampaignReport {
  runId: string
  cases: number
  casesByEvidenceClass: Record<'PROTOCOL_OBSERVED' | 'OPERATOR_ASSISTED' | 'SELF_ATTESTED', number>
  externallyVerifiedCases: number
  selfAttestedCases: number
  notVerifiedCases: number
  plans: Array<{
    plan: 'QUICK' | 'STANDARD' | 'FULL'
    cases: number
    deliberateUserActions: number
    remainingUserActions: number
    loginActions: number
    configurationActions: number
    metadataRefreshActions: number
    selfAttestationSections: number
    estimatedMinutesMin: number
    estimatedMinutesMax: number
    actionBudget: number
    budgetMet: boolean
  }>
  campaigns: Array<{
    id: string
    title: string
    plan: 'QUICK' | 'STANDARD' | 'FULL'
    evidenceClass: 'PROTOCOL_OBSERVED' | 'OPERATOR_ASSISTED' | 'SELF_ATTESTED'
    actionKind: 'NONE' | 'LOGIN' | 'CONTINUE' | 'CONFIGURATION' | 'METADATA_REFRESH' | 'SELF_CHECK'
    deliberateUserActions: number
    remainingUserActions: number
    freshSessionRequired: boolean
    caseIds: string[]
    remainingCaseIds: string[]
    expectedTranscriptEvidence: string[]
    actions: Array<{
      id: string
      caseIds: string[]
      remainingCaseIds: string[]
    }>
  }>
  classifications: Array<{
    caseId: string
    plan: 'QUICK' | 'STANDARD' | 'FULL'
    evidenceClass: 'PROTOCOL_OBSERVED' | 'OPERATOR_ASSISTED' | 'SELF_ATTESTED'
    campaignId: string
    actionKind: 'NONE' | 'LOGIN' | 'CONTINUE' | 'CONFIGURATION' | 'METADATA_REFRESH' | 'SELF_CHECK'
    freshSessionRequired: boolean
    resolved: boolean
    outcome: 'SATISFIED' | 'SATISFIED_WITH_NOTE' | 'VIOLATED' | 'INDETERMINATE' | 'INCONSISTENT' | 'NOT_VERIFIED' | null
    expectedTranscriptEvidence: string[]
  }>
}

export interface Health { status: string; version: string; mode: 'selfhosted' | 'hosted' }

async function request<T>(url: string, init?: RequestInit): Promise<T> {
  const response = await fetch(url, {
    ...init,
    headers: { 'content-type': 'application/json', ...(init?.headers ?? {}) },
  })
  if (!response.ok) {
    const body = await response.json().catch(() => ({ message: response.statusText }))
    throw new Error(body.message ?? `HTTP ${response.status}`)
  }
  return response.status === 204 ? (undefined as T) : response.json()
}

function camelize(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(camelize)
  if (value !== null && typeof value === 'object') {
    return Object.fromEntries(Object.entries(value as Record<string, unknown>).map(([key, child]) => [
      key.replace(/_([a-z])/g, (_, letter: string) => letter.toUpperCase()),
      camelize(child),
    ]))
  }
  return value
}

export const api = {
  health: () => request<Health>('/api/health'),
  plans: () => request<Plan[]>('/api/plans'),
  createPlan: (input: PlanInput) => request<PlanCreated>('/api/plans', { method: 'POST', body: JSON.stringify(input) }),
  deletePlan: (id: string) => request<void>(`/api/plans/${id}`, { method: 'DELETE' }),
  runs: (planId: string) => request<Run[]>(`/api/plans/${planId}/runs`),
  run: (runId: string) => request<Run>(`/api/runs/${runId}`),
  createRun: (planId: string, csrfToken?: string) => request<RunCreated>(`/api/plans/${planId}/runs`, {
    method: 'POST', headers: csrfToken ? { 'X-CSRF-Token': csrfToken } : {},
  }),
  preflight: (runId: string, csrfToken?: string) => request<Record<string, unknown>>(`/api/runs/${runId}/preflight`, {
    method: 'POST', headers: csrfToken ? { 'X-CSRF-Token': csrfToken } : {},
  }),
  transcript: (runId: string) => request<unknown[]>(`/api/runs/${runId}/transcript`),
  quickCheck: (runId: string, csrfToken?: string) => request<unknown>(`/api/runs/${runId}/quick-check`, {
    method: 'POST', headers: csrfToken ? { 'X-CSRF-Token': csrfToken } : {},
  }),
  activeProbe: (runId: string) => request<ActiveProbeStatus>(`/api/runs/${runId}/active-probe`),
  abortActiveProbe: (runId: string, csrfToken?: string) =>
    request<ActiveProbeStatus>(`/api/runs/${runId}/active-probe/abort`, {
      method: 'POST', headers: csrfToken ? { 'X-CSRF-Token': csrfToken } : {},
    }),
  retryActiveProbe: (runId: string, csrfToken?: string) =>
    request<ActiveProbeStatus>(`/api/runs/${runId}/active-probe/retry`, {
      method: 'POST', headers: csrfToken ? { 'X-CSRF-Token': csrfToken } : {},
    }),
  result: async (runId: string) => camelize(
    await request<unknown>(`/api/runs/${runId}/result.json`),
  ) as PublicResult,
  managementSession: (runId: string, token: string) => request<ManagementSession>(
    '/api/manage/session', { method: 'POST', body: JSON.stringify({ runId, token }) },
  ),
  interactions: (runId: string) => request<PendingInteraction[]>(`/api/runs/${runId}/interactions`),
  campaigns: (runId: string) => request<CampaignReport>(`/api/runs/${runId}/campaigns`),
  bootstrapContracts: (runId: string) => request<BootstrapContract[]>(`/api/runs/${runId}/bootstrap-contracts`),
  metadataLab: (runId: string) => request<MetadataLab>(`/api/runs/${runId}/metadata-lab`),
  selectMetadataVariant: (runId: string, variant: string, csrfToken?: string) =>
    request<MetadataLab>(`/api/runs/${runId}/metadata-lab/variant`, {
      method: 'POST', body: JSON.stringify({ variant }),
      headers: csrfToken ? { 'X-CSRF-Token': csrfToken } : {},
    }),
  startAutomaticMetadataPolling: (runId: string, variants: string[], pollingDelaySeconds: number,
    csrfToken?: string) =>
    request<MetadataLab>(`/api/runs/${runId}/metadata-lab/automatic-polling`, {
      method: 'POST', body: JSON.stringify({ variants, pollingDelaySeconds }),
      headers: csrfToken ? { 'X-CSRF-Token': csrfToken } : {},
    }),
  startPreloadedMetadataCampaign: (runId: string, csrfToken?: string) =>
    request<MetadataLab>(`/api/runs/${runId}/metadata-lab/preloaded`, {
      method: 'POST', body: '{}', headers: csrfToken ? { 'X-CSRF-Token': csrfToken } : {},
    }),
  useManualMetadataRefresh: (runId: string, csrfToken?: string) =>
    request<MetadataLab>(`/api/runs/${runId}/metadata-lab/manual-refresh`, {
      method: 'POST', body: '{}', headers: csrfToken ? { 'X-CSRF-Token': csrfToken } : {},
    }),
  protocolEvidence: (runId: string) =>
    request<ProtocolEvidenceStatus>(`/api/runs/${runId}/protocol-evidence`),
  evaluateProtocolEvidence: (runId: string, csrfToken?: string) =>
    request<ProtocolEvidenceEvaluation>(`/api/runs/${runId}/protocol-evidence/evaluate`, {
      method: 'POST', body: '{}', headers: csrfToken ? { 'X-CSRF-Token': csrfToken } : {},
    }),
  confirmProtocolEvidenceAttempts: (runId: string, csrfToken?: string) =>
    request<ProtocolEvidenceEvaluation>(`/api/runs/${runId}/protocol-evidence/confirm-attempts`, {
      method: 'POST', body: '{}', headers: csrfToken ? { 'X-CSRF-Token': csrfToken } : {},
    }),
  attest: (runId: string, caseId: string, value: string, note: string, csrfToken?: string) =>
    request<unknown>(`/api/runs/${runId}/cases/${caseId}/attest`, {
      method: 'POST', body: JSON.stringify({ value, note }),
      headers: csrfToken ? { 'X-CSRF-Token': csrfToken } : {},
    }),
  configure: (runId: string, caseId: string, value: string, note: string, csrfToken?: string) =>
    request<unknown>(`/api/runs/${runId}/cases/${caseId}/configure`, {
      method: 'POST', body: JSON.stringify({ value, note }),
      headers: csrfToken ? { 'X-CSRF-Token': csrfToken } : {},
    }),
  completeBrowser: (runId: string, caseId: string, csrfToken?: string) =>
    request<unknown>(`/api/runs/${runId}/cases/${caseId}/browser-complete`, {
      method: 'POST', body: '{}', headers: csrfToken ? { 'X-CSRF-Token': csrfToken } : {},
    }),
  completeCampaignAction: (
    runId: string, campaignId: string, actionId: string, csrfToken?: string,
  ) => request<unknown>(`/api/runs/${runId}/campaigns/${encodeURIComponent(campaignId)}`
    + `/actions/${encodeURIComponent(actionId)}/complete`, {
    method: 'POST', body: '{}', headers: csrfToken ? { 'X-CSRF-Token': csrfToken } : {},
  }),
  startMilestone: (runId: string, milestone: 'M2' | 'M3', csrfToken?: string) =>
    request<unknown>(`/api/runs/${runId}/milestones/${milestone}/start`, {
      method: 'POST', headers: csrfToken ? { 'X-CSRF-Token': csrfToken } : {},
    }),
  ecpProbe: (runId: string, username: string, password: string, csrfToken?: string) =>
    request<unknown>(`/api/runs/${runId}/ecp-probe`, {
      method: 'POST', body: JSON.stringify({ username, password }),
      headers: csrfToken ? { 'X-CSRF-Token': csrfToken } : {},
    }),
  publish: (runId: string, csrfToken?: string) =>
    request<{ runId: string; publicUrl: string }>(`/api/runs/${runId}/publish`, {
      method: 'POST', headers: csrfToken ? { 'X-CSRF-Token': csrfToken } : {},
    }),
}
