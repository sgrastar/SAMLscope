import { useEffect, useState } from 'react'
import { AppShell } from './AppShell'
import { softwareLicense, licensingScope } from 'virtual:samlscope-license'

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
    <section><h2>Specification content</h2>
      <p>Requirement summaries, test instructions and profile mappings use external specifications. Their original terms apply to incorporated material. Attribution review and output integration are still in progress.</p>
      <p><a href="https://kantarainitiative.github.io/SAMLprofiles/fedinterop.html">Kantara SAML Implementation Profile</a> · <a href="https://docs.oasis-open.org/security/saml/v2.0/">OASIS SAML 2.0 specifications</a></p>
      <SpecificationNotices />
      <p>Results do not imply certification, approval or endorsement by Kantara or OASIS.</p>
    </section>
  </main></AppShell>
}


type SourceNotice = { id: string; title: string; source_url: string; edition: string; date: string;
  notice_page?: number; notice_location?: string; license_url?: string; notice_text: string; catalog_correction_pending: boolean }
function SpecificationNotices() {
  const [sources, setSources] = useState<SourceNotice[]>()
  const [error, setError] = useState('')
  useEffect(() => {
    const controller = new AbortController()
    void fetch('/licenses/source-notices.json', { signal: controller.signal }).then(async response => {
      if (!response.ok) throw new Error('The retained specification notices could not be loaded.')
      const value = await response.json()
      if (!Array.isArray(value.sources)) throw new Error('The retained specification notices are unavailable.')
      setSources(value.sources)
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
    {sources?.map(source => <details key={source.id} id={`source-${source.id}`}>
      <summary>{source.title} — {source.edition}, {source.date}</summary>
      <p><a href={source.source_url}>Original document</a> · {source.notice_location ?? `Notice page ${source.notice_page}`}</p>
      {source.license_url && <p><a href={source.license_url}>Original license terms</a></p>}
      {source.catalog_correction_pending && <p>The stored document’s edition or date differs from the catalog entry. The catalog correction is pending review.</p>}
      <pre className="license-text">{source.notice_text}</pre>
    </details>)}
    <p><a href="/licenses/source-notices.json" download>Download retained specification notices and source references</a></p>
  </>
}
