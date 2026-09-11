import { useEffect, useState } from 'react'
import { AppShell } from './AppShell'
import { softwareLicense, licensingScope, contentLicense } from 'virtual:samlscope-license'

type Dependency = { name: string; version: string; license: string; notices: { file: string; text: string }[] }
export function Licenses() {
  const [dependencies, setDependencies] = useState<Dependency[]>()
  const [error, setError] = useState('')
  useEffect(() => {
    const controller = new AbortController()
    void fetch('/licenses/browser-dependencies.json', { signal: controller.signal }).then(async response => {
      if (!response.ok) throw new Error('The bundled dependency notices could not be loaded.')
      const value = await response.json()
      if (!Array.isArray(value.packages)) throw new Error('The bundled dependency notices are unavailable.')
      setDependencies(value.packages)
    }).catch(cause => { if (!controller.signal.aborted) setError((cause as Error).message) })
    return () => controller.abort()
  }, [])
  return <AppShell current="licenses"><main className="shell page-main">
    <header className="page-head"><h1>Licenses and sources</h1>
      <p>Software, specification content and measured results have different licensing scopes.</p></header>
    <section><h2>Original software</h2><p>SAMLscope’s original software is licensed under Apache-2.0.</p>
      <details><summary>Apache License, Version 2.0</summary><pre className="license-text">{softwareLicense}</pre></details>
      <details><summary>Licensing scope and review status</summary><pre className="license-text">{licensingScope}</pre></details>
    </section>
    <section><h2>Browser dependencies</h2><p>These are the notices retained from packages included in this build’s browser JavaScript.</p>
      {error && <p role="alert">{error}</p>}
      {!error && !dependencies && <p>Loading notices…</p>}
      {dependencies?.map(pkg => <details key={`${pkg.name}@${pkg.version}`}>
        <summary>{pkg.name} {pkg.version} — {pkg.license}</summary>
        {pkg.notices.map(notice => <pre className="license-text" key={notice.file}>{notice.text}</pre>)}
      </details>)}
      <p><a href="/licenses/browser-dependencies.json" download>Download browser dependency notices</a></p>
    </section>
    <section><h2>Java runtime dependencies</h2>
      <p>The application distribution also includes Java libraries. Their original package and resource notices are preserved. Source code for EPL components is available under EPL-2.0 through the version-specific links in the inventory.</p>
      <JavaNotices />
      <p><a href="/licenses/java-dependencies.json" download>Download Java dependency notices and resource inventory</a></p>
    </section>
    <section><h2>Specification content</h2>
      <p>Requirement summaries, test instructions and profile mappings use external specifications. Their original terms apply to incorporated material. Source notices and modification credits are retained in browser and standalone outputs. Specification references are distinguished from copied material.</p>
      <p><a href="https://kantarainitiative.github.io/SAMLprofiles/fedinterop.html">Kantara SAML Implementation Profile</a> · <a href="https://docs.oasis-open.org/security/saml/v2.0/">OASIS SAML 2.0 specifications</a></p>
      <p>SAMLscope-owned original explanations and definitions are licensed under CC BY-SA 4.0; incorporated source material retains its original terms. Attribute original contributions to SAMLscope contributors and identify your changes.</p>
      <details><summary>CC BY-SA 4.0 — original content only</summary><pre className="license-text">{contentLicense}</pre></details>
      <SpecificationNotices />
      <p>Results do not imply certification, approval or endorsement by Kantara or OASIS.</p>
    </section>
  </main></AppShell>
}


type SourceNotice = { id: string; title: string; source_url: string; edition: string; date: string;
  notice_page?: number; notice_location?: string; license_url?: string; notice_text: string; catalog_correction_pending: boolean; terms_review_status?: string }
function SpecificationNotices() {
  const params = new URLSearchParams(window.location.search)
  const context = (['case', 'profile', 'requirement'] as const).find(kind => params.has(kind))
  const contextId = context ? params.get(context)! : ''
  const [selected, setSelected] = useState<string[]>()
  const [selectionError, setSelectionError] = useState('')
  useEffect(() => {
    if (!context) return
    const controller = new AbortController()
    void fetch('/licenses/source-membership.json', { signal: controller.signal }).then(async response => {
      if (!response.ok) throw new Error('Source membership could not be loaded.')
      const index = await response.json() as Record<string, Record<string, string[]>>
      const values = context === 'requirement'
        ? Object.entries(index.obligation_sources).filter(([key]) => key.startsWith(contextId + '.')).flatMap(([, ids]) => ids)
        : index[context + '_sources']?.[contextId]
      if (!values?.length) throw new Error('No source membership is available for this catalog item. View all specification notices below.')
      setSelected([...new Set(values)])
    }).catch(cause => { if (!controller.signal.aborted) setSelectionError((cause as Error).message) })
    return () => controller.abort()
  }, [context, contextId])
  const [sources, setSources] = useState<SourceNotice[]>()
  const [pending, setPending] = useState<string[]>([])
  const [error, setError] = useState('')
  useEffect(() => {
    const controller = new AbortController()
    void fetch('/licenses/source-notices.json', { signal: controller.signal }).then(async response => {
      if (!response.ok) throw new Error('The retained specification notices could not be loaded.')
      const value = await response.json()
      if (!Array.isArray(value.sources)) throw new Error('The retained specification notices are unavailable.')
      setSources(value.sources)
      setPending(value.unresolved_sources ?? [])
    }).catch(cause => { if (!controller.signal.aborted) setError((cause as Error).message) })
    return () => controller.abort()
  }, [])
  useEffect(() => {
    if (!sources) return
    const id = decodeURIComponent(window.location.hash.slice(1))
    const target = id ? document.getElementById(id) : null
    if (target instanceof HTMLDetailsElement) {
      target.open = true
      target.scrollIntoView({ block: 'start' })
    }
  }, [sources])
  return <>
    {error && <p role="alert">{error}</p>}
    {context && <p>Sources for {contextId}. <a href="/licenses">View all license notices</a></p>}
    {selectionError && <p role="alert">{selectionError}</p>}
    {context && !selected && !selectionError && <p>Loading source membership…</p>}
    {sources?.filter(source => !context || !!selectionError || selected?.includes(source.id)).map(source => <details key={source.id} id={`source-${source.id}`}>
      <summary>{source.title} — {source.edition}, {source.date}</summary>
      <p><a href={source.source_url}>Original document</a> · {source.notice_location ?? `Notice page ${source.notice_page}`}</p>
      {source.license_url && <p><a href={source.license_url}>Original license terms</a></p>}
      {source.catalog_correction_pending && <p>The stored document’s edition or date differs from the catalog entry. The catalog correction is pending review.</p>}
      {source.terms_review_status?.startsWith("PENDING") && <p>Supplemental historical permission terms remain under review.</p>}
      {source.notice_text && <pre className="license-text">{source.notice_text}</pre>}
    </details>)}
    {pending.length > 0 && <section><h3>Source notices still under review</h3><ul>{pending.filter(id => !context || !!selectionError || selected?.includes(id)).map(id => <li key={id} id={`source-${id}`}>{id} — notice review pending</li>)}</ul></section>}
    <p><a href="/licenses/source-notices.json" download>Download retained specification notices and source references</a></p>
  </>
}

function JavaNotices() {
  const [packages, setPackages] = useState<Array<{file: string; notices?: Array<{file: string; text: string}>; permission?: {
    supplemental_notices: Array<{license: string; text: string}>;
    source_availability?: {url: string; statement: string};
  }}>>()
  const [error, setError] = useState('')
  async function load(open: boolean) {
    if (!open || packages) return
    try {
      const response = await fetch('/licenses/java-dependencies.json')
      if (!response.ok) throw new Error('Java notices could not be loaded.')
      const data = await response.json()
      if (!Array.isArray(data.packages)) throw new Error('Java notices are unavailable.')
      setError('')
      setPackages(data.packages)
    } catch (cause) { setError((cause as Error).message) }
  }
  return <details onToggle={event => void load(event.currentTarget.open)}>
    <summary>Java copyright notices, license texts and source availability</summary>
    {error && <p role="alert">{error}</p>}
    {packages?.map(pkg => <details key={pkg.file}>
      <summary>{pkg.file}</summary>
      {pkg.notices?.map(notice => <pre className="license-text" key={notice.file}>{notice.text}</pre>)}
      {pkg.permission?.source_availability && <p>{pkg.permission.source_availability.statement} <a href={pkg.permission.source_availability.url}>Upstream source code</a></p>}
      {pkg.permission?.supplemental_notices.map((notice, index) => <pre className="license-text" key={index}>{notice.text}</pre>)}
    </details>)}
  </details>
}
