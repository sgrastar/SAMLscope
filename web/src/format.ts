const acronyms: Record<string, string> = {
  api: 'API',
  ecp: 'ECP',
  http: 'HTTP',
  idp: 'IdP',
  mdq: 'MDQ',
  saml: 'SAML',
  slo: 'SLO',
  sp: 'SP',
  sso: 'SSO',
  url: 'URL',
  xml: 'XML',
}

/** Jackson Instant values use epoch seconds; exported results use ISO strings. */
export function formatDate(value: string | number, fallback = 'Updated recently') {
  const date = new Date(typeof value === 'number' ? value * 1000 : value)
  return Number.isNaN(date.valueOf()) ? fallback : date.toLocaleString()
}

export function humanize(value: string) {
  const rendered = value.toLowerCase().split(/[_-]/).map(word => acronyms[word] ?? word).join(' ')
  return rendered.replace(/^./, first => first.toUpperCase())
}
