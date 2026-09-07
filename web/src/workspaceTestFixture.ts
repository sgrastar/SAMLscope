import { vi } from 'vitest'

/** Assemble existing per-section fixtures into the single workspace response. */
export function stubWorkspaceFetch(handler: (input: string, init?: RequestInit) => Promise<Response>) {
  vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input)
    if (!url.endsWith('/workspace-evidence')) return handler(url, init)
    const base = url.slice(0, -'/workspace-evidence'.length)
    const sections = { interactions: 'interactions', bootstrapContracts: 'bootstrap-contracts',
      protocolEvidence: 'protocol-evidence', activeProbe: 'active-probe', campaigns: 'campaigns' }
    const result: Record<string, unknown> = {}
    for (const [key, path] of Object.entries(sections)) {
      const response = await handler(`${base}/${path}`, init)
      if (!response.ok) return response
      result[key] = await response.json()
    }
    return new Response(JSON.stringify(result), {
      status: 200, headers: { 'content-type': 'application/json' },
    })
  }))
}
