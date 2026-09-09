import { ReactNode, useEffect, useState } from 'react'
import { api, type AuthSession } from './api'

type CurrentSurface = 'plans' | 'run' | 'report' | 'access' | 'licenses'

export function AppShell({
  children,
  current = 'plans',
  mode = 'selfhosted',
  runId,
}: {
  children: ReactNode
  current?: CurrentSurface
  mode?: 'selfhosted' | 'hosted'
  runId?: string
}) {
  const [menuOpen, setMenuOpen] = useState(false)
  const [theme, setTheme] = useState<'light' | 'dark'>(() => preferredTheme())

  useEffect(() => {
    document.documentElement.dataset.theme = theme
    try { window.localStorage.setItem('samlscope.theme', theme) } catch { /* private mode */ }
  }, [theme])

  return <div className="app-frame">
    <header className="app-topbar">
      <a className="wordmark" href="/">SAMLscope <small>SAML CONFORMANCE</small></a>
      <button
        className="topbar-nav-toggle"
        type="button"
        aria-label="Toggle navigation"
        aria-expanded={menuOpen}
        onClick={() => setMenuOpen(open => !open)}
      >Menu</button>
      <nav className={`app-nav${menuOpen ? ' open' : ''}`} aria-label="Primary navigation">
        <a className={current === 'plans' ? 'current' : ''} href="/">Test Plans</a>
        {runId && <a className={current === 'run' ? 'current' : ''} href={`/manage/${runId}`}>Run Workspace</a>}
        {runId && <a className={current === 'report' ? 'current' : ''} href={`/reports/${runId}`}>Result Report</a>}
      </nav>
      <div className="app-topbar-spacer" />
      <LoginStatus />
      <span className="mode-chip"><span className="semantic-dot status-live" />{mode === 'hosted' ? 'Hosted' : 'Self-hosted'}</span>
      <button
        className="theme-toggle"
        type="button"
        onClick={() => setTheme(value => value === 'dark' ? 'light' : 'dark')}
        aria-label={`Switch to ${theme === 'dark' ? 'light' : 'dark'} theme`}
      >{theme === 'dark' ? 'Light' : 'Dark'}</button>
    </header>
    {children}
    <footer className="shell legal"><a href="/licenses">Licenses and sources</a></footer>
  </div>
}

export function preferredTheme(): 'light' | 'dark' {
  try {
    const saved = window.localStorage.getItem('samlscope.theme')
    if (saved === 'light' || saved === 'dark') return saved
  } catch { /* private mode */ }
  return window.matchMedia?.('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'
}

export function applyPreferredTheme() {
  document.documentElement.dataset.theme = preferredTheme()
}

function LoginStatus() {
  const [session, setSession] = useState<AuthSession>()
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  useEffect(() => {
    // Static exported reports have no live authentication service.
    if (window.location.protocol === 'file:') return
    queueMicrotask(() => { void api.authSession().then(setSession).catch(() => undefined) })
  }, [])
  if (!session?.enabled) return null
  const logout = async () => {
    setBusy(true)
    try {
      await api.logout()
      for (const key of Object.keys(window.sessionStorage)) {
        if (key.startsWith('samlscope.csrf.')) window.sessionStorage.removeItem(key)
      }
      window.location.assign('/')
    } catch {
      setError('Sign out failed. Please try again.')
      setBusy(false)
    }
  }
  return <div className="login-status">
    {session.authenticated ? <>
      <span className="login-name" title={session.displayName ?? undefined}>{session.displayName}</span>
      <button className="button-secondary" onClick={() => void logout()} disabled={busy}>Sign out</button>
    </> : <a className="button button-secondary" href="/auth/login">Sign in</a>}
    {error && <span role="alert">{error}</span>}
  </div>
}
