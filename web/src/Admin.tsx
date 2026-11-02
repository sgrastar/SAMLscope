import { t } from './i18n'
import { useEffect, useRef, useState } from 'react'
import { api, type AdminUser, type AdminPlan, type AuthSession, type UserRole } from './api'
import { AppShell } from './AppShell'
import { formatDate } from './format'

export function Admin() {
  const [session, setSession] = useState<AuthSession>()
  const [mode, setMode] = useState<'hosted' | 'selfhosted'>('hosted')
  const [users, setUsers] = useState<AdminUser[]>([])
  const [plans, setPlans] = useState<AdminPlan[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [message, setMessage] = useState('')
  const [busy, setBusy] = useState(false)
  const [tab, setTab] = useState<'users' | 'plans'>('users')
  const [query, setQuery] = useState('')
  const [editing, setEditing] = useState<AdminUser['user']>()
  const [deleting, setDeleting] = useState<{ kind: 'user' | 'plan'; id: string; name: string; version?: number }>()
  const editor = useRef<HTMLElement>(null)
  useEffect(() => {
    if (editing || deleting) { editor.current?.focus(); editor.current?.scrollIntoView?.({ block: 'nearest' }) }
  }, [editing?.id, deleting?.id])
  const refresh = async () => {
    const account = await api.authSession()
    setSession(account)
    if (account.role !== 'ADMIN') { setUsers([]); setPlans([]); return }
    const [accounts, allPlans] = await Promise.all([api.adminUsers(), api.adminPlans()])
    setUsers(accounts); setPlans(allPlans)
  }
  useEffect(() => {
    void api.health().then(health => { setMode(health.mode); return refresh() })
      .catch(cause => setError((cause as Error).message)).finally(() => setLoading(false))
  }, [])
  const action = async (work: () => Promise<unknown>, success: string) => {
    setBusy(true); setError(''); setMessage('')
    try { await work(); setEditing(undefined); setDeleting(undefined); setMessage(success); await refresh() }
    catch (cause) { setError((cause as Error).message) }
    finally { setBusy(false) }
  }
  const match = (value: string) => value.toLowerCase().includes(query.toLowerCase())
  return <AppShell current="admin" mode={mode}><main className="shell page-main admin-page">
    <h1>{t('Administration')}</h1>
    {error && <div className="notice notice-error" role="alert">{error}</div>}
    {message && <div className="notice notice-success" role="status">{message}</div>}
    {loading ? <p role="status">{t('Loading administration…')}</p> : session?.role !== 'ADMIN' ? <section>
      <h2>{t('Admin access required')}</h2><p>{t('Sign in with an administrator account to manage users and Test Plans.')}</p>
      <a className="button" href="/auth/login">{t('Sign in')}</a>
    </section> : <>
      <p>{t('Manage SAMLscope accounts and Test Plans. Account changes here do not change the identity provider.')}</p>
      <div className="actions">
        <button className={tab === 'users' ? '' : 'button-secondary'} aria-pressed={tab === 'users'} onClick={() => setTab('users')}>{t('Users ({n})', { n: users.length })}</button>
        <button className={tab === 'plans' ? '' : 'button-secondary'} aria-pressed={tab === 'plans'} onClick={() => setTab('plans')}>{t('Test Plans ({n})', { n: plans.length })}</button>
        <button className="button-secondary" disabled={busy} onClick={() => void action(refresh, t('Updated.'))}>{t('Refresh')}</button>
      </div>
      <label className="admin-search">{tab === 'users' ? t('Search users') : t('Search Test Plans')}<input value={query} onChange={event => setQuery(event.target.value)} placeholder={t('Name or identifier')} /></label>
      {tab === 'users' ? <>
        <p className="notice">{t('Anonymous accounts expire after 30 days without application use, including their published reports. Automatic account deletion is paused until current provider account status can be verified.')}</p>
        <div className="admin-table-wrap"><table><caption>{t('Application users')}</caption><thead><tr><th>{t('User')}</th><th>{t('Role')}</th><th>{t('Last application use')}</th><th>{t('Anonymous expiry')}</th><th>{t('Actions')}</th></tr></thead>
          <tbody>{users.filter(({ user }) => match(user.displayName + user.id + user.role)).map(({ user, expiresAt, expiryCandidate }) => <tr key={user.id}>
            <td><strong>{user.displayName || t('Unnamed user')}</strong>{session.userId === user.id && <span> {t('(you)')}</span>}<code>{user.id}</code>{user.status === 'DELETING' && <span>{t('Deletion incomplete — retry deletion')}</span>}</td>
            <td>{roleLabel(user.role)}</td><td>{user.lastUsedAt ? formatDate(user.lastUsedAt) : t('Not yet used')}</td>
            <td>{expiresAt ? <>{formatDate(expiresAt)}{expiryCandidate && <span>{t('Awaiting account-state verification')}</span>}</> : t('Not applicable')}</td>
            <td><div className="actions"><button className="button-secondary" disabled={busy || user.status !== 'ACTIVE'} onClick={() => { setDeleting(undefined); setEditing({ ...user }) }}>{t('Edit')}</button>
              <button className="button-secondary" disabled={busy} onClick={() => { setEditing(undefined); setDeleting({ kind: 'user', id: user.id, name: user.displayName || user.id, version: user.version }) }}>{t('Delete user')}</button></div></td>
          </tr>)}</tbody></table></div>
        {!users.some(({ user }) => match(user.displayName + user.id + user.role)) && <p>{t('No matching users.')}</p>}
      </> : <>
        <div className="admin-table-wrap"><table><caption>{t('All Test Plans')}</caption><thead><tr><th>{t('Test Plan')}</th><th>{t('Owner')}</th><th>{t('Created at')}</th><th>{t('Actions')}</th></tr></thead>
          <tbody>{plans.filter(({ plan, ownerId }) => match(plan.plan.name + plan.plan.id + (ownerId ?? ''))).map(({ plan, ownerId, createdAt }) => <tr key={plan.plan.id}>
            <td><strong>{plan.plan.name}</strong><code>{plan.plan.id}</code></td>
            <td>{users.find(({ user }) => user.id === ownerId)?.user.displayName || t('Legacy / unassigned')}<code>{ownerId}</code></td>
            <td>{formatDate(createdAt)}</td><td><div className="actions"><a href={`/?plan=${plan.plan.id}`}>{t('View Plan')}</a>
              <button className="button-secondary" disabled={busy} onClick={() => { setEditing(undefined); setDeleting({ kind: 'plan', id: plan.plan.id, name: plan.plan.name }) }}>{t('Delete Plan')}</button></div></td>
          </tr>)}</tbody></table></div>
        {!plans.some(({ plan, ownerId }) => match(plan.plan.name + plan.plan.id + (ownerId ?? ''))) && <p>{t('No matching Test Plans.')}</p>}
      </>}
      {editing && <section ref={editor} tabIndex={-1} className="admin-editor" aria-label={t('Edit user')}><h2>{t('Edit user')}</h2><form onSubmit={event => { event.preventDefault(); void action(() => api.updateUser(editing), t('User updated.')) }}>
        <label>{t('Display name')}<input maxLength={200} value={editing.displayName} onChange={event => setEditing({ ...editing, displayName: event.target.value })} /></label>
        <label>{t('Role')}<select value={editing.role} onChange={event => setEditing({ ...editing, role: event.target.value as UserRole })}><option value="ANONYMOUS">{t('Anonymous')}</option><option value="USER">{t('General user')}</option><option value="ADMIN">{t('Admin')}</option></select></label>
        <p>{t('Role changes apply immediately. The last active admin cannot be demoted or deleted.')}</p>
        <div className="actions"><button disabled={busy}>{t('Save user')}</button><button type="button" className="button-secondary" disabled={busy} onClick={() => setEditing(undefined)}>{t('Cancel')}</button></div>
      </form></section>}
      {deleting && <section ref={editor} tabIndex={-1} className="admin-editor" role="alertdialog" aria-labelledby="delete-title" aria-describedby="delete-detail"><h2 id="delete-title">{t('Delete {name}?', { name: deleting.name })}</h2>
        <p id="delete-detail">{deleting.kind === 'user' ? t('This deletes the SAMLscope account, its target connections, all owned Plans, Runs, evidence and published reports. This identity will be blocked from signing in again. The provider account remains unchanged. This cannot be undone.') : t('This deletes the Plan, its Runs, evidence, keys and published reports. This cannot be undone.')}</p>
        <div className="actions"><button disabled={busy} onClick={() => void action(() => deleting.kind === 'user' ? api.deleteUser(deleting.id, deleting.version!) : api.adminDeletePlan(deleting.id), t('Deleted.'))}>{t('Confirm deletion')}</button>
          <button className="button-secondary" disabled={busy} onClick={() => setDeleting(undefined)}>{t('Cancel')}</button></div>
      </section>}
    </>}
  </main></AppShell>
}
function roleLabel(role: UserRole) { return { ANONYMOUS: t('Anonymous'), USER: t('General user'), ADMIN: t('Admin') }[role] }
