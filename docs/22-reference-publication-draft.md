# Reference IdP executions — publication draft

Follow-up: [review-qualified per-test comparison and Suite fixes](23-reference-test-comparison.md). Historical raw results below remain unchanged.

**Local draft prepared; not published.** These are observations from configured
test fixtures, not product certifications or a ranking. Candidate dispositions
and unresolved interpretation questions are recorded; independent approval of
product findings has not been granted.
The [execution record](21-reference-execution-record.md) contains Run identifiers,
exact image digests, diagnostic attempts and evidence qualifications.

## What was exercised

The selected SAMLscope source is
`874ba19d1d7383f15dfbad3736bcc5c761a8f69e`. It was built from an isolated source
archive, excluding unrelated uncommitted application changes. The targets were
Keycloak 26.7.2, Shibboleth IdP 5.2.3 and SimpleSAMLphp 2.5.0. The SimpleSAMLphp
fixture used the Cirrus AMD64 image with PHP 8.4.19; this packaging choice is part
of the result's provenance.

All targets and the Suite ran on loopback HTTP endpoints with disposable test
identities. Consequently these results do not cover production TLS, an external
identity directory, a deployment's access controls or a public network path.

| Executed IdP scope | Evidence obtained | Important limit |
|---|---|---|
| Browser SSO | Baseline exchanges and the registered active probe chains; independent Run comparisons | Protocol-client form exchanges are separate from real-browser evidence. ForceAuthn has a Suite precision concern. |
| Metadata | Preloaded variants imported into the targets; subsequent authentication attempts and independent repeats | Explicit local import is not proof of automatic fetching, refresh or metadata trust validation. |
| ECP | Correlated SOAP responses after explicit target setup; independent repeats | Success at baseline does not prove support for every ECP extension. |
| Target-initiated logout | Real-browser login and logout; correlated LogoutRequests and Suite-generated LogoutResponses; repeats | Shibboleth displayed logout failure. Generating a response does not prove its delivery or acceptance. |

The recorded profiles remain **INCOMPLETE**. Pending interactions and unresolved
requirements are retained. A repeated result establishes reproducibility of the
executed scope; it does not establish full conformance. A Suite verified ratio
describes resolved verification work, not the quality of a product. SP and
broker behavior must not be inferred from these IdP executions.

## Reproduction conditions

Use the image digests and Suite revision from the execution record. Register
the generated Suite SP metadata in a dedicated target configuration. Each repeat
must use a new Run and a new authentication session; preserve the configuration
and target metadata digest with each result.

- **Browser SSO:** follow the registered probes and their fresh-session
  requirements. A passive request that displays a login form must not be turned
  into a successful authentication by entering credentials. Preserve terminal
  errors as unavailable-response evidence, rather than inventing a response.
- **ECP:** enable the target's ECP capability, advertise its SOAP endpoint and
  register the exact Suite PAOS URL including the Run query parameter. Send test
  Basic credentials only through the Suite's ephemeral credential path and
  outbox. For SimpleSAMLphp, allow the configured PHP metadata revalidation
  interval after changing its SP configuration.
- **Metadata:** import the Run's exported metadata using the native target
  mechanism. Keycloak's metadata-peer identifiers are stable across repeats, so
  update the matching existing test clients rather than interpreting duplicate
  creation errors as conformance failures. Record rejected variants and resume
  only the next independent variant.
- **Logout:** register the Run-correlated SLO endpoint before logging in. Use
  the IdP's native logout flow and inspect both browser completion and correlated
  protocol evidence. Shibboleth's default `__Host-` session cookie requires the
  Secure setting used in the corrected fixture. SimpleSAMLphp's loopback HTTP
  fixture uses SameSite=Lax. These local settings are not production guidance.

Retain result JSON, standalone HTML, Transcript references, interactions and
campaign state locally. Verify that the HTML embeds the same JSON and compare
outcomes, reasons, metadata digests and unresolved work across repeats. Raw
authentication responses, session material and fixture keys are excluded from
this publication draft.

## Concerns that affect interpretation

The following Suite concerns prevent treating every exported FAIL as a confirmed
product defect:

- **ForceAuthn precision:** SimpleSAMLphp advanced its authentication timestamp,
  but whole-second precision could make it appear earlier than a fractional
  request timestamp. The Suite then reported context reuse. Those observations
  do not prove reuse.
- **NameID qualifier omission:** Keycloak's same-SP qualifier request returned
  an identifier without the explicit qualifier, addressed only to that SP.
  The Suite's literal attribute comparison needs review against the format's
  permitted omission rules. Requests naming a different SP are a separate case.
- **Embedded logout response:** the Suite POST response has
  `frame-ancestors 'none'`, whereas Shibboleth propagates logout through an
  embedded flow. The observed failed completion requires investigation on the
  Suite side before attributing it to the IdP.
- **Unavailable ECP response:** the generated-key check can classify a missing
  SOAP response as a violation. Earlier redirect-only fixture attempts are
  diagnostic records, not evidence of a target's generated-key behavior.
- **Indexed ACS import:** Keycloak's native imported client omits the index-1
  endpoint present in the Suite metadata. The resulting ACS-selection FAIL
  does not isolate runtime index handling under a complete endpoint registration.
- **State and evidence presentation:** the preloaded metadata completion page
  left the Suite Run awaiting browser work; another baseline round trip was
  required before evaluation. The exported `attested` flag and coverage field
  describe catalog testability, not a count of operator answers.

Other candidate observations include missing logout expiry attributes,
unsigned logout requests, transient identifier lexical form, NameID policy and
authentication-context handling, ACS selection, signature transforms, and
the separately referenced SAML-EC extension. These require their individual
request/response pairs, controls and fixture settings. They must not be condensed
into claims that a product is generally insecure or nonconforming.

The required-signature Keycloak comparison changes ordinary signature mutation
outcomes while retaining the excluded-content XPath candidate; its independent
repeat agrees. SimpleSAMLphp's required-signature pair has the same
signature-case pattern and matching repeat results. Optional-signature and
required-signature results must remain separate.

## Publication status

The original raw evidence remains local and ignored by Git. No issue report,
external upload, deployment or publication has been performed. Before this draft
can be represented as independently approved reference results, resolve the
recorded candidate-review questions and agree any broader publication claims.
Carry forward all unresolved coverage explicitly. These executions do not establish completion of the
project's full release or Phase 1 acceptance criteria.
