# Native Response and Assertion signing configurations

The approved `IIP-SSO04-a-idp-01` case requires independent signing capability. The existing active browser fixture only exercised an ordinary successful flow and therefore deliberately remained `browser_fixture_partial`.

`SignatureModesObservation` now reads immutable Run originals, pins target signing keys to the Run metadata, and correlates requests with unique responses. It recognizes both signatures, Assertion-only signing, and Response-only signing. Every present signature must verify; a valid outer Response cannot hide an invalid Assertion signature. Assertion-only output must bind the request ID, ACS recipient, and SP audience inside the signed Assertion. A duplicate ID, ambiguous response, unrelated subject confirmation, unknown signing key, or incomplete mode set cannot establish capability. All observations must belong to the same target and SP in the same Run. Additional invalid or unrelated responses are diagnosed separately; they cannot contribute a missing configuration.

Clear assertions retain their original ancestor namespace context during verification. Moving them into a synthetic wrapper invalidated Keycloak signatures using inherited namespace context during initial development; verification now uses the original DOM. Encrypted assertions are decrypted with the Run key before examining the contained signature.

`SignatureModesBrowserTestCase` preserves the existing outbox scenario and adds a native-configuration campaign plus recorded-evidence reevaluation. The existing partial outcome cannot become success from configuration labels or a browser completion click. Missing modes remain NOT_VERIFIED; the observer does not claim that failure to observe a configuration proves the product lacks that capability. Comparison and cryptographic regression controls are authored for the next grouped validation.

## Native evidence collected before the next runtime update

The Keycloak producer adapter now has a signature matrix in addition to its existing encryption matrix. Its default encryption behavior remains available. A new SimpleSAMLphp adapter uses the product parser and native `saml20.sign.response` / `saml20.sign.assertion` settings; the installed IdP implementation was inspected to identify those settings. Each adapter uses a temporary SP and readbacks of native settings, restores configuration, and retains protocol originals.

- Keycloak: `keycloak-signature-modes`, Run `run_JZSXZVMX0H39NRW09RE6EKN0N3`.
- SimpleSAMLphp: `simplesamlphp-signature-modes`, Run `run_11H8SAH2SC5JGQAQ2W3R510HNB`.

<!--g1-literal--> Each Run contains 3 requests and 3 responses. The new production observation code recognizes all 3 signing configurations in each product. `VerifySignatureModesEvidence.java` rejects 18 original-message mutations per Run: bad signature values, wrong audience, wrong signed request correlation, wrong issuer, duplicate IDs, and missing responses. These are local production-code replays, not formal runtime verdicts. The running reference Suite still uses v60 and its older partial case.

The initial native Runs used ordinary SP metadata, which advertises `WantAssertionsSigned=true`. They establish what those native configurations generated, but are not adopted as the final capability campaign. To avoid requiring Assertion signing while requesting a Response-only experiment, `signature-modes-optional` now generates validly signed metadata with `WantAssertionsSigned=false`, retaining ordinary plan keys and ACS/SLO endpoints. It is served through the existing Run-bound metadata-variant endpoint and explicitly excluded from polling-key campaigns. Both adapters now require this fixture; it must be deployed before their next execution. The ordinary metadata contract remains unchanged.

Shibboleth's installed profile classes expose `setSignResponses(boolean)`, `setSignAssertions(boolean)`, and `setEncryptAssertions(boolean)`. The per-SP configuration campaign is still to be implemented and executed with the optional-signing metadata. No absence of capability is inferred from the unfinished campaign.

<!--g1-literal--> Recorded operations: Keycloak admin GET 12, client creation 1, configuration PUT 3, deletion 1, token requests 17; SimpleSAMLphp configuration writes 4 including restoration, native setting readbacks 3. Both initial campaigns completed without product restarts or human interaction. Their exact operation logs and restoration evidence are retained. No Suite rebuild/deployment was performed for this increment, no full test suite was repeated, and no commit was created.

<!--g1-literal--> The authoritative ledger remains 432 unresolved observations / 152 distinct case IDs. Pending work includes grouped regression execution, deployment, optional-signing fixture campaigns, Shibboleth's adapter, formal reevaluation, and evidence-qualified ledger selection. The approved G1/G2 definition files were not changed.

## Completed native batch and formal adoption

The optional-signing metadata and the common observer are deployed. Shibboleth now has `dev/shibboleth/signature_modes_campaign.py`, which adds an isolated filesystem metadata provider and a per-SP relying-party override, reloads the appropriate native services, exercises each signing configuration, and restores both original configuration files byte-for-byte. No global signature setting is changed. `capture_run_originals.py` provides Run-scoped public-original capture for the adapters.

The final optional-signing campaigns are:

| Product | Run | Evidence folder |
|---|---|---|
| Keycloak | `run_9XH0Y4Z7P4JFHJTYQ3ZJKE633N` | `keycloak-signature-modes-v61` |
| Shibboleth | `run_VQ1J5M9J2XCT0GS0PXBBV3XZMY` | `shibboleth-signature-modes-v61` |
| SimpleSAMLphp | `run_W9WFP7QB19V0Y15T0QVE7D8RHW` | `simplesamlphp-signature-modes-v61` |

The public-original verifier now also verifies the Suite metadata signature, original recorded preparation, optional Assertion-signing flag, and each outgoing request signature, including the exact Redirect query bytes. It then verifies the product signatures and signed assertion correlation. `verify_signature_modes_acceptance.py` checks the native phase/readback, every original hash, mutation results, configuration restoration, and formal evidence-reference equality before selecting any result for the ledger.

An integration gap initially kept these cases queued even though their evidence was complete. `QueuedProtocolEvidenceCase` is an explicit opt-in for pure observation. The protocol-evidence service now completes an opted-in, never-dispatched case only when the Run transcript is complete, no outbox entry exists for the case, readiness is established, and the resulting outcome is conclusive. It never calls the scenario's start/resume methods. An attempt-confirmation click cannot waive those conditions. Cases outside the evidence registry are skipped; the first integration attempt exposed that missing guard and was recorded as a Suite failure before evaluation. Existing dispatched cases keep their normal state transitions.

<!--g1-literal--> The final reference runtime is `samlscope:reference-queued-evidence-v63`. All 3 products now have formal `SATISFIED / PASS` for `IIP-SSO04-a-idp-01`, and the comparison table displays Success for each. Original transcripts are identical before and after adoption; reevaluation sent no new SAML traffic. The ledger moves from 432 / 152 to 429 unresolved observations / 151 distinct case IDs. The unresolved-contract audit reports no inventory/definition mismatch.

<!--g1-literal--> Validation was scoped to new or failed behavior: 5 signature-mode controls plus 1 metadata-fixture contract check passed; the state-transition integration checks passed, with 12 existing transition tests and 8 final protocol-evidence tests. The protocol-evidence subset was repeated after the observed registry-lookup failure. Native replay rejected 18 mutations per product, 54 total. No full Java/Web suite was repeated.

<!--g1-literal--> This batch's recorded operations include Docker builds 3, Suite/forwarding recreations 3 each, Run creation/preflight 3 each, native SSO requests/responses 9 each, initial protocol evaluations 3 and final evaluations 3, and the failed status lookup 1. Keycloak: admin reads 12, setting writes 3, temporary-client create/delete 1 each, token requests 17. SimpleSAMLphp: configuration writes 4 including restoration, native readbacks 3. Shibboleth: configuration writes 7 including restoration, service reloads 6, temporary metadata deletion 1. Product restarts and human operations remain 0. Earlier diagnostic campaigns are recorded separately, not merged into these counts. Runtime source hashes, executed checks, installed jar hashes, failed-attempt details, and operation totals are retained in the runtime evidence directories. No commit was created.
