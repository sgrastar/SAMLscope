import { useEffect, useState } from 'react'
import { api } from './api'
import { AppShell } from './AppShell'
import { RunManagement } from './RunManagement'

/** Consumes the fragment locally, removes it before any network work, then exchanges it for a cookie. */
export function ManagementBootstrap({ runId }: { runId: string }) {
  const [state, setState] = useState<'exchanging' | 'ready' | 'error'>('exchanging')
  const [message, setMessage] = useState('')
  const [csrfToken, setCsrfToken] = useState<string>()
  const [mode, setMode] = useState<'selfhosted' | 'hosted'>('selfhosted')

  useEffect(() => {
    const token = new URLSearchParams(window.location.hash.slice(1)).get('t') ?? ''
    window.history.replaceState(null, '', `${window.location.pathname}${window.location.search}`)
    if (!token) {
      setCsrfToken(window.sessionStorage.getItem(`samlscope.csrf.${runId}`) ?? undefined)
      void api.health().then(async health => {
        setMode(health.mode)
        if (health.mode === 'selfhosted' && !health.oidcEnabled) {
          setState('ready')
          return
        }
        // The server must authorize this exact Run before the workspace is displayed.
        await api.run(runId)
        if (health.oidcEnabled) {
          const account = await api.authSession()
          if (account.authenticated) {
            setState('ready')
            return
          }
        }
        const session = await api.resumeManagementSession(runId)
        setCsrfToken(session.csrfToken)
        window.sessionStorage.setItem(`samlscope.csrf.${runId}`, session.csrfToken)
        setState('ready')
      }).catch(cause => {
        setState('error')
        setMessage((cause as Error).message)
      })
      return
    }
    void Promise.all([api.managementSession(runId, token), api.health().catch(() => undefined)]).then(([session, health]) => {
      if (health) setMode(health.mode)
      window.sessionStorage.setItem(`samlscope.csrf.${runId}`, session.csrfToken)
      setCsrfToken(session.csrfToken)
      setState('ready')
    }).catch(cause => {
      setState('error')
      setMessage((cause as Error).message)
    })
  }, [runId])

  return <AppShell current={state === 'ready' ? 'run' : 'access'} mode={mode} runId={state === 'ready' ? runId : undefined}>
    {state === 'exchanging' && <main className="shell gate-page">
      <section className="gate-card" aria-live="polite"><div className="activity-ring" aria-hidden="true" />
        <p className="eyebrow">Protected Run access</p><h1>Opening Run</h1>
        <p>Exchanging the one-time link for a protected browser session.</p>
        <ol className="gate-steps"><li>Consume the secret from the URL fragment.</li><li>Remove it from browser history before network access.</li><li>Exchange it once for a management cookie and CSRF token.</li></ol>
      </section>
    </main>}
    {state === 'ready' && <main className="shell page-main run-page">
      <div className="notice notice-success compact-notice" role="status"><strong>Run unlocked</strong>
        Access is ready. Evidence inputs remain separate from Suite verdict calculation.</div>
      <RunManagement runId={runId} csrfToken={csrfToken} />
    </main>}
    {state === 'error' && <main className="shell gate-page"><section className="gate-card error-state">
      <p className="eyebrow">Protected Run access</p><h1>Access denied</h1><div className="notice notice-error" role="alert">{message}</div>
      <a className="button button-secondary" href="/">Return to Test Plans</a>
    </section></main>}
  </AppShell>
}
