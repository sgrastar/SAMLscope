import { readFileSync, readdirSync } from 'node:fs'
import { join } from 'node:path'

/** Retain the installed packages' actual notices in each distributed browser chunk. */
export function browserLicenseNotices() {
  const packages = new Map()
  function noticesForModules(ids) {
    const included = new Set()
    for (const id of ids) {
      const clean = id.replace(/^\0/, '')
      const marker = clean.lastIndexOf('/node_modules/')
      if (marker < 0) continue
      const rest = clean.slice(marker + '/node_modules/'.length).split('/')
      const name = rest[0].startsWith('@') ? rest.slice(0, 2).join('/') : rest[0]
      const directory = clean.slice(0, marker + '/node_modules/'.length) + name
      const metadata = JSON.parse(readFileSync(join(directory, 'package.json'), 'utf8'))
      const key = `${metadata.name}@${metadata.version}`
      if (!packages.has(key)) {
        const notices = readdirSync(directory).filter(file => /^(license|licence|notice|copying|copyright)(\.[\w-]+)?$/i.test(file))
          .sort().map(file => ({ file, text: readFileSync(join(directory, file), 'utf8') }))
        if (!notices.length) throw new Error(`No retained license notice for bundled package ${key}; review its terms before distribution`)
        packages.set(key, { name: metadata.name, version: metadata.version, license: metadata.license ?? 'UNSPECIFIED', notices })
      }
      included.add(key)
    }
    return [...included].sort().map(key => packages.get(key))
  }
  return {
    name: 'samlscope-browser-license-notices',
    apply: 'build',
    buildStart() { packages.clear() },
    augmentChunkHash(chunk) {
      return JSON.stringify(noticesForModules(Object.keys(chunk.modules)))
    },
    generateBundle(_options, bundle) {
      for (const chunk of Object.values(bundle)) {
        if (chunk.type !== 'chunk') continue
        const included = noticesForModules(Object.keys(chunk.modules))
        if (!included.length) continue
        const text = included.map(pkg => `${pkg.name}@${pkg.version}\n` + pkg.notices.map(n => `${n.file}\n${n.text}`).join('\n')).join('\n\n')
        // Run after minification. augmentChunkHash also accounts for notice-only changes.
        chunk.code = `/*! Third-party notices\n${text.replaceAll('*/', '* /')}\n*/\n${chunk.code}`
      }
      this.emitFile({ type: 'asset', fileName: 'licenses/source-notices.json',
        source: readFileSync(new URL('../LICENSES/source-notices.json', import.meta.url), 'utf8') })
      const included = [...packages.values()].sort((a, b) => `${a.name}@${a.version}`.localeCompare(`${b.name}@${b.version}`))
      this.emitFile({ type: 'asset', fileName: 'licenses/browser-dependencies.json', source: JSON.stringify({
        scope: 'Third-party packages included in browser JavaScript; these terms do not license specification content or measured results.',
        packages: included,
      }, null, 2) + '\n' })
    },
  }
}

export function softwareLicenseText() {
  return {
    name: 'samlscope-software-license-text',
    resolveId(id) { if (id === 'virtual:samlscope-license') return '\0samlscope-license' },
    load(id) {
      if (id !== '\0samlscope-license') return null
      const license = readFileSync(new URL('../LICENSE', import.meta.url), 'utf8')
      const scope = readFileSync(new URL('../LICENSING.md', import.meta.url), 'utf8')
      return `export const softwareLicense = ${JSON.stringify(license)}; export const licensingScope = ${JSON.stringify(scope)};`
    },
  }
}
