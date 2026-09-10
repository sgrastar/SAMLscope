import { useEffect, useState } from 'react'

export function RoundTripLink({ href }: { href: string }) {
  const [opening, setOpening] = useState(false)
  useEffect(() => {
    const reset = () => setOpening(false)
    window.addEventListener('pageshow', reset)
    window.addEventListener('focus', reset)
    return () => {
      window.removeEventListener('pageshow', reset)
      window.removeEventListener('focus', reset)
    }
  }, [])
  return <a className="button" href={href} target="_blank" rel="noreferrer"
    aria-busy={opening} aria-disabled={opening || undefined}
    onClick={event => {
      if (event.ctrlKey || event.metaKey || event.shiftKey || event.altKey || event.button !== 0) return
      if (opening) { event.preventDefault(); return }
      setOpening(true)
    }}>
    {opening && <span className="button-spinner" aria-hidden="true" />}
    {opening ? 'Opening IdP…' : 'Start IdP round trip'}
  </a>
}
