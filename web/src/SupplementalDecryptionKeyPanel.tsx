import { FormEvent, useState } from 'react'
import { type SupplementalDecryptionKeyStatus } from './api'
import { formatDate } from './format'

/** Run input for IdP decryption tests when the target metadata does not publish an encryption key. */
export function SupplementalDecryptionKeyPanel({ status, busy, error, onSubmit }: {
  status: SupplementalDecryptionKeyStatus
  busy: boolean
  error: string
  onSubmit: (sourceUri: string, publicKeysSpkiBase64: string[]) => void
}) {
  const [sourceUri, setSourceUri] = useState('')
  const [keysText, setKeysText] = useState('')
  const [localError, setLocalError] = useState('')
  const fixed = status.input
  const helper = '-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY----- or the base64 SubjectPublicKeyInfo'

  const submit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    const keys = parsePublicKeys(keysText)
    if (!sourceUri.trim()) {
      setLocalError('Enter the HTTP(S) reference that the public key was read from.')
      return
    }
    if (keys.length === 0) {
      setLocalError('Enter at least one RSA public key.')
      return
    }
    setLocalError('')
    onSubmit(sourceUri.trim(), keys)
  }

  return <article className="interaction supplemental-decryption-keys">
    <header><strong>IdP decryption key input</strong><span>{fixed ? 'FIXED FOR THIS RUN' : 'BEFORE START'}</span></header>
    <p>The target metadata is used unchanged. When it publishes no encryption key, SAMLscope encrypts
      IIP-IDP19 identifiers with a key you provide here. The first input is fixed for the Run; submit
      before starting the profile tests. The source reference is recorded as provenance and never fetched.</p>
    <dl>
      <dt>Target entity</dt><dd><code>{status.targetEntityId}</code></dd>
      <dt>Run metadata SHA-256</dt><dd><code>{status.metadataSha256}</code></dd>
    </dl>
    {fixed
      ? <>
          <p className="notice">{fixed.publicKeysSpkiBase64.length > 0
            ? `Fixed: ${fixed.publicKeysSpkiBase64.length} supplemental RSA key(s) from ${fixed.sourceUri}.`
            : 'Fixed: this Run provides no supplemental decryption key.'}</p>
          <p><small>Recorded {formatDate(fixed.recordedAt, 'Unknown')}. A replacement requires a new Run.</small></p>
        </>
      : <form onSubmit={submit}>
          <label>Public-key source (HTTP or HTTPS, no credentials, query, or fragment)
            <input name="sourceUri" value={sourceUri}
              placeholder="https://idp.example/admin/keys"
              onChange={event => setSourceUri(event.target.value)} /></label>
          <label>RSA public key(s), one per PEM block or base64 line
            <textarea name="publicKeysSpkiBase64" rows={5} value={keysText}
              placeholder={helper}
              onChange={event => setKeysText(event.target.value)} /></label>
          <button disabled={busy || status.testsStarted}>Fix decryption key input</button>
          {status.testsStarted && <p><small>Tests have started; this Run cannot accept a new input.</small></p>}
        </form>}
    {localError && <aside className="notice notice-error" role="alert">{localError}</aside>}
    {error && <aside className="notice notice-error" role="alert">{error}</aside>}
  </article>
}

/** Accepts PEM-armored PUBLIC KEY blocks or plain base64 SubjectPublicKeyInfo values. */
export function parsePublicKeys(value: string): string[] {
  const blocks = [...value.matchAll(/-----BEGIN [^-]+-----\s*([A-Za-z0-9+/=\s]+?)\s*-----END [^-]+-----/g)]
    .map(match => match[1].replace(/\s+/g, ''))
    .filter(Boolean)
  const candidates = blocks.length > 0
    ? blocks
    : value.split(/[\s,;]+/).map(item => item.trim()).filter(Boolean)
  return candidates.filter(key => /^[A-Za-z0-9+/]+={0,2}$/.test(key))
}
