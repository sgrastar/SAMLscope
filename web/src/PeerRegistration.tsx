import { useState } from 'react'
import type { Plan } from './api'
import { profileRole } from './profiles'

function CopyValue({ label, value, link = false }: { label: string; value: string; link?: boolean }) {
  const [feedback, setFeedback] = useState('')
  async function copy() {
    try {
      await navigator.clipboard.writeText(value)
      setFeedback(`${label} copied`)
    } catch {
      setFeedback(`Could not copy ${label}. Select and copy the value manually.`)
    }
  }
  return <div className="registration-value">
    <dt>{label}</dt><dd>
      <div className="registration-copy">
        {link ? <a href={value}>{value}</a> : <code>{value}</code>}
        <button type="button" className="button-secondary" aria-label={`Copy ${label}`} onClick={() => void copy()}>Copy</button>
      </div>
      <span className="registration-feedback" role="status">{feedback}</span>
    </dd>
  </div>
}

/** Initial interoperability setup, not additional conformance requirements. */
export function PeerRegistration({ plan }: { plan: Plan }) {
  const testingIdp = profileRole(plan.plan.profile) === 'IDP'
  const signed = plan.plan.requestSigningMode === 'REQUIRED'
  const endpoint = (path: string) => new URL(`/p/${encodeURIComponent(plan.plan.id)}${path}`, plan.metadataUrl).toString()
  return <section className="panel peer-panel peer-registration registration-guide">
    <p className="eyebrow">Test Peer registration</p>
    <h2>{testingIdp ? 'Register SAMLscope as an SP in your IdP' : 'Register SAMLscope as an IdP in your SP'}</h2>
    <ol className="registration-steps">
      <li>{testingIdp ? 'Create a SAML application / service provider in the IdP you want to test.'
        : 'Create an identity provider connection in the SP you want to test.'}</li>
      <li>Import the metadata URL below. If URL import is unavailable, open it and import the XML file.
        Import the signing certificate from this metadata too; the HTTPS certificate is not the SAML signing certificate.</li>
      <li>{testingIdp ? 'Assign a dedicated test user to the application. Save the settings, then open Run workspace, run preflight, and start the IdP round trip.'
        : 'Save the connection, then start login from your target SP using a dedicated test account.'}</li>
    </ol>
    <dl className="registration-values">
      <CopyValue label="Metadata URL" value={plan.metadataUrl} link />
      <CopyValue label={testingIdp ? 'SP Entity ID / Audience' : 'IdP Entity ID / Issuer'} value={plan.entityId} />
      {testingIdp ? <CopyValue label="ACS URL / Reply URL" value={endpoint('/sp/acs/0')} />
        : <CopyValue label="SSO URL" value={endpoint('/idp/sso')} />}
      <CopyValue label="Logout URL (SLO)" value={endpoint(testingIdp ? '/sp/slo' : '/idp/slo')} />
    </dl>
    <h3>Initial settings for the ordinary browser round trip</h3>
    <p>These are setup instructions, not extra SAML conformance rules. Keep the metadata as the source of truth. Later test cases may request different settings.</p>
    <dl className="registration-settings">
      <dt>Allowed SAML bindings</dt><dd>{testingIdp
        ? <>AuthnRequest to your IdP: <strong>HTTP-Redirect</strong>. Response to SAMLscope ACS: <strong>HTTP-POST</strong>.
          If your product has one combined allowlist, enable both. Do not send the browser SAML Response using Redirect.</>
        : <>AuthnRequest to SAMLscope: <strong>HTTP-Redirect or HTTP-POST</strong>. Configure your SP to accept a <strong>HTTP-POST</strong> Response at its own registered ACS.</>}</dd>
      <dt>NameID format</dt><dd>{testingIdp
        ? <>The initial request does not specify NameIDPolicy, and the SP metadata does not restrict NameID formats. Use your IdP’s supported default for a test user. If an explicit selection is required, transient (<code>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</code>) is a starting option when supported, not a conformance requirement. Email format is not required. NameID is the subject identifier, not an email attribute.</>
        : <>The ordinary Test Peer response uses <code>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</code>. Allow transient NameID for this initial flow; do not require an email-shaped identifier.</>}</dd>
      <dt>Required user attributes</dt><dd>No named user attributes (such as email, given_name, or groups) are required by SAMLscope for the initial round trip.
        {testingIdp ? ' No AttributeStatement mapping is needed just to start. Use synthetic test data, not real personal information.'
          : ' The ordinary Test Peer response does not supply an AttributeStatement. If your SP requires provisioning attributes, resolve that prerequisite before testing.'}</dd>
      <dt>AuthnRequest signature</dt><dd>{testingIdp
        ? signed ? 'This Plan uses REQUIRED: SAMLscope signs Redirect requests. Import the SP signing certificate from the metadata.'
          : 'This Plan uses OPTIONAL: the initial Redirect request is unsigned. It will not work with an IdP connection that requires signed requests. If signing is required by your policy, create a REQUIRED-signing Plan and register its metadata instead of weakening the policy.'
        : 'The Test Peer metadata does not require signed AuthnRequests. Keep your SP signing policy and import its metadata into this Test Plan.'}</dd>
      <dt>Assertion signature</dt><dd>{testingIdp ? 'Enable assertion signing. SAMLscope SP metadata advertises WantAssertionsSigned=true.'
        : 'Import the Test Peer signing certificate from the metadata and verify signed assertions in your SP.'}</dd>
      <dt>Logout binding</dt><dd>HTTP-Redirect or HTTP-POST at the Logout URL above. Logout is not a prerequisite for the first login; additional endpoints are listed in metadata.</dd>
    </dl>
    <details className="registration-advanced"><summary>Additional test endpoints: MDQ and secondary IdP</summary>
      <p>Not needed for the initial round trip. MDQ is for metadata-query tests. Register the secondary IdP only when a proxy or multi-IdP case asks for it; it is not the primary SP Entity ID.</p>
      <dl className="registration-values">
        <CopyValue label="MDQ URL" value={plan.mdqUrl} />
        <CopyValue label="Secondary IdP entity ID" value={plan.secondaryIdpEntityId} />
        <CopyValue label="Secondary IdP metadata URL" value={plan.secondaryIdpMetadataUrl} link />
      </dl>
      {testingIdp && <p>The metadata also advertises a Redirect ACS for a negative test. Do not select it as the normal response endpoint; use the POST ACS above.</p>}
    </details>
  </section>
}
