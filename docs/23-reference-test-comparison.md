# Reference IdP test comparison and failure causes

Local verification on 2026-09-14, covering each product's IdP functionality. This is not whole-product conformance certification or a published defect report. See the [execution record](21-reference-execution-record.md) for configuration, version, and evidence details.

`dev/reference-acceptance/generate_comparison.py` generates this table from measured `result.json` files. Historical results and approved evaluation definitions are preserved, with Suite and configuration misclassifications shown separately.

- **Success**: The evaluation result is PASS. This does not merely mean a SAML Success response was returned; proper rejection of an abnormal request also counts as Success.
- **Failed (Product)**: In the configuration and test scope below, the product response differs from the required behavior because of product behavior or missing functionality. This does not establish the same behavior in every configuration or a security compromise.
- **Not verified (Suite / Configuration)**: Product failure has not been established. These observations are also excluded from Success counts.
- **Warning**: WARNING from the Evaluator. It is not converted to Failed, preserving the SHOULD/MAY distinction.
- **Not verified / Not observable / Indeterminate / Not run**: Unverified, unobservable, inconclusive, or absent from the Run, respectively. These are distinct from N/A.

## Cause attribution

| Target | Test or behavior | Cause and conclusion | Evidence |
|---|---|---|---|
| Keycloak, SimpleSAMLphp | `IIP-SSO01-fk` | Product: accepts XPath transforms excluding some or all signed content | Verified signature-required configuration, a valid-signature control, and each exclusion-transform request. This concerns HTTP-POST XML signatures, without outer Redirect signature protection. Signature-generation positive and negative controls were also rerun. Core §5.4.4. |
| Keycloak, SimpleSAMLphp | `IIP-SSO07-b` | Product: returns Success with an identifier different from the requested Subject | After a normal-request positive control, sent an explicit persistent Subject request. NameIDPolicy did not request a Format change, and request/response InResponseTo matched. Keycloak was checked after decryption. This violates strong match in Core §3.4.1.4 for the observed condition; it does not establish execution of every case condition. |
| Shibboleth | `IIP-SSO07-b` | Product: returns Success with an identifier different from the requested known Subject | Completed native auditing of the known principal and positive controls, then compared the identifier in the signed, decrypted response correlated to the same request. No different-NameIDPolicy exception applied, and qualifier omission alone was not a failure reason. This observed counterexample reuses saved G02 originals; it does not establish completion of every case condition or generalize to other configurations. |
| Keycloak | `IIP-MD05-b` | Product: native import rejects a schema-valid EndpointType extension | Submitted the original signed fixture to the product converter, observing rejection with a child in an external namespace and acceptance of an extension-free control with the same key and URL. Matched replay of the pinned native parser, normal import and signed SSO, a genuinely schema-invalid control, and configuration restoration. This violates the observed variant; it does not establish execution of every metadata type. |
| SimpleSAMLphp | `IIP-IDP04-b` | Product: accepted attribute-service selection is not reflected in actual responses | Verified two product-imported services with distinct requested attributes and a positive control returning both attributes. In the same authenticated session with fixed attribute configuration, signed requests switching indices 0, 1, and 0 returned only UID. This observed counterexample matched request/response signatures, native attribute-selection paths, configuration restoration, and runtime evaluator controls; missing import output alone did not establish Failed. |
| SimpleSAMLphp | `IIP-SSO01-ag` | Product: returns Success despite an XML Destination mismatch | Reproduced using requests changing the host, path, and IdP, alongside a correct-Destination control. The actual HTTP target remained the registered IdP. Core §3.2.1. |
| Shibboleth | `IIP-SSO05-b2` | Product: transient NameID does not satisfy XML ID lexical rules | Verified `+`, `/`, and `=` after decryption. The result includes the default CryptoTransientIdGenerator configuration. Core §§1.3.4, 8.3.8. Raw identifier values are not published. |
| SimpleSAMLphp | `IIP-SSO05-a`, `IIP-IDP10-d` | Product: returns transient for a persistent request | Direct comparison of requested Format with decrypted NameID Format. Reproduced with working positive controls. Core §3.4.1.4. |
| Keycloak, SimpleSAMLphp | `IIP-IDP10-b` | Product: accepts unknown alternate-SP qualifiers or similar values without an error | The requested alternate SP and the returned identifier scope differ. This is separate from same-SP qualifier omission [S1]. Core §3.4.1.1. |
| SimpleSAMLphp | `IIP-IDP05-a`, `IIP-IDP08-a` | Product: returns Success without satisfying an unsupported request or exact AuthnContext condition | Positive controls exist. Unknown NameID Format and authentication context requests receive defaults. This does not establish failure of every Passive subcase. Core §§3.3.2.2.1, 3.4.1.1, 3.4.1.4. |
| Keycloak, Shibboleth | `IIP-IDP17-t` | Product: LogoutRequest from a session authority lacks NotOnOrAfter | Inspected LogoutRequest attributes received through actual IdP-initiated browser operations. This observation is independent of subsequent browser completion display. Core §3.7.3.2. |
| SimpleSAMLphp | `IIP-IDP17-m` | Product: HTTP-POST LogoutRequest lacks a signature | Verified the actual reception binding and XML. NotOnOrAfter exists, distinguishing this from missing expiration. Core §3.7, Bindings §3.5. |
| Keycloak 26.7.2 | `IIP-MD05-av` | Product: does not select omitted default and uses metadata with duplicate AssertionConsumerService indices | Submitted 4 evaluative fixtures and a control through product Import client. control, explicit-first, and all-false reached the correct ACS, but omitted default after explicit-false reached ACS 0 instead of ACS 1, and the duplicate-index fixture returned Success after read-back. Container image, startup time, runtime VERSION at campaign start/end, temporary-client deletion read-back, original fixtures, requests/responses, and Suite runtime JAR are bound to the same Run. Metadata Interoperability §2.4.1. |
| Shibboleth IdP 5.2.3 | `IIP-MD05-av` | Product: does not select omitted default and uses metadata with duplicate AssertionConsumerService indices | Submitted 4 evaluative fixtures and a control through product FilesystemMetadataProvider. control, explicit-first, and all-false reached the correct ACS, but omitted default after explicit-false reached ACS 0 instead of ACS 1, and the duplicate-index fixture also returned Success. Container image, startup time, runtime VERSION at campaign start/end, byte-identical configuration restoration, original fixtures, requests/responses, and Suite runtime JAR are bound to the same Run. Metadata Interoperability §2.4.1. |
| SimpleSAMLphp 2.5.0 | `IIP-MD05-av` | Product: uses metadata with duplicate AssertionConsumerService indices under the same parent | Native MDQ sent 3 default-selection controls (explicit true, omission after explicit false, and all false) to the correct ACS, then fetched and used the duplicate-index control and returned Success. Container image, startup time, runtime VERSION at campaign start/end, and configuration restoration are bound to the same Run. Metadata Interoperability §2.4.1. |
| Keycloak, SimpleSAMLphp | `IIP-IDP15-a` | Product/profile: SAML-EC GeneratedKey is absent | Even after PAOS registration correction, SOAP Success for the SessionKey test lacks GeneratedKey. Shibboleth passed both key-copy and encryption checks in the same test. This is distinct from failure of normal ECP as a whole. SAML-EC §5.3.1 and approved IIP-IDP15.a. |
| Keycloak | `IIP-IDP10-d` [S1] | Suite: same-SP qualifier omission produces FAIL through string mismatch | Core §§8.3.7–8.3.8 define omission rules. Adopted Runs received a holding correction to NOT_VERIFIED. Source reconciliation, signed reapproval of variant `v-e2c03ed209`, and implementation permitting omission under limited conditions are complete on a dedicated branch. The table retains the hold because no actual Run under the new definition has been adopted. |
| SimpleSAMLphp | `IIP-IDP06-a/b` [S2] | Suite: incorrect FAIL caused by timestamp precision differences | Even when authentication time advanced, second-precision AuthnInstant was treated as earlier than fractional IssueInstant. Ordering within reported precision remains NOT_VERIFIED, verified with second/millisecond regression controls. No Suite-specific allowed-clock-skew threshold was added. |
| Keycloak | `IIP-IDP12-a` [C1] | Configuration: ACS index registration is incomplete | Input metadata contains index 1, but the native-imported client lacks its ACS URL. This is not evidence evaluating product index handling with complete registration, so the old FAIL is not a product failure. |
| All products | Waiting continues after metadata campaigns | Suite: remains WAITING_BROWSER despite a correlated response | Corrected waiting-state release on a correlated metadata response; uncorrelated responses do not release it. Shibboleth replay verified COMPLETED and tests/start success without an additional baseline. |
| ECP diagnosis | GeneratedKey violation when no SOAP response is available | Suite: treats a missing response as a violation | Corrected to NOT_VERIFIED, distinct from a missing key in an actually received response. The older SimpleSAMLphp diagnostic Run returning HTTP 303 is excluded from the comparison. |
| Shibboleth SLO | Suite relay POST cannot operate in an iframe | Suite: frame-ancestors 'none' | Permitted only registered IdP SLO response origins. After correction, Shibboleth audit records confirmed LogoutResponse and Success reception. Admin page embedding permissions are unchanged. |
| Shibboleth SLO | Logout failed remains visible after relay | **Unresolved: browser completion-display interoperability** | The IdP returns HTTP 200 and JSON Success, but the in-app browser iframe remains on the Suite URL. Chrome comparison is incomplete because the connection provider stopped automation. No extension UI was visible on the actual page, and the discrepancy between the stop reason and the page remains unresolved. This does not establish full SLO correction or Success. |

`IIP-SSO01-ai/aj` from the earlier optional-signature configuration show Success in the comparison with Keycloak and SimpleSAMLphp requiring signatures. This configuration difference is not classified as a Suite misjudgment or an unconditional defect across product signature verification.

References: [SAML Core](https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf), [SAML Bindings](https://docs.oasis-open.org/security/saml/v2.0/saml-bindings-2.0-os.pdf), and [SAML-EC draft v16](https://www.ietf.org/archive/id/draft-ietf-kitten-sasl-saml-ec-16.txt). SAML-EC results concern the approved profile referencing that draft version; they do not add a new MUST to normal SAML Core.

## Correction and verification status

Implemented ForceAuthn precision evaluation, ECP missing-response handling, metadata waiting-state release, SLO CSP restricted to target origins, and suppression of incorrect FAIL on NameID omission. Signature-generation and scenario positive/negative controls and Runner/Peer/API regression tests for the changed areas passed. ForceAuthn, NameID omission, metadata, and SLO response arrival were actually rerun with the corrected image.

Verification overlaid only the classes changed in this work onto the original verification image; separate OIDC/admin changes in the working tree were excluded. Source SHA-256, image digest, and adopted result.json SHA-256 are saved locally in `build/acceptance/reference-20260914/fix-verification/`.

**Approval boundary:** G1/G2 approval-record updates and signature verification are complete on the dedicated `nameid-suite-reapproval` branch under explicit user authorization. All G1/G2 checks using externally pinned verification tools passed. The normal working tree contains separate OIDC/admin changes and has not been integrated with that branch. This success covers only the dedicated branch approval target; it does not approve the full normal working tree or running image.

Unverified observations remain across the profiles. Table Success entries alone do not establish whole-product conformance.

Regenerate: `.venv/bin/python dev/reference-acceptance/generate_comparison.py --evidence-root build/acceptance/reference-20260914`.

## Reapproval progress (2026-09-14)

Explicit user authorization was received for NameID evaluation definitions, G2 reapproval, approval-record updates, and signed commits using the existing key. The following local commits were created.

- Definitions and implementation: `f4daa528174f9bffe7cccf9833b1e779001236bb`
- G1 signed approval: `37d88f14e4e9` (abbreviated SHA)
- G2 approval target: `e3896d8bfe4ec17323c2ff12d9deb9c500e3565e`
- G2 signed approval: `a26f511a6c05bddeb42fc3c35141dd6226afd7ba`

Externally pinned G1 source reconciliation/signature verification and G2 definition/signature verification all passed. Verification logs are saved locally in `build/acceptance/reference-20260914/fix-verification/reapproval/`. The earlier pending authorization for signing is resolved. The dedicated worktree is `/private/tmp/samlscope-nameid-reapproval`, on branch `nameid-suite-reapproval`. No publication or push was performed.

Positive and negative controls verified the implementation permitting NameID omission in limited responses to the same SP, but it is not deployed to the running image. The current comparison retains execution evidence from before reapproval and does not turn Not verified into Success merely because of reapproval.

## Additional configuration and operation tests

Executed additional actual-browser SSO, temporary configuration for signed unencrypted Assertions, batch metadata import, and Shibboleth native HTTP fetch tests. See [follow-up tests and configuration and operation costs](25-interaction-execution-cost.md) for configuration changes, restoration, agent-operation counts, and conclusion deltas. The normal working tree and new NameID definitions were not incorporated into the running image.


See the [additional implementation record](27-additional-implementation.md) for additional implementation and retests using an image limited to changed classes. † in the comparison indicates additional case-level evidence. The Warning for an unpublished public URL is not an HTTPS violation.

G02 adopts v10 follow-up evidence. All 3 products completed 37 round trips including positive controls, verifying 20 standard-string inputs and 16 extension-attribute inputs. Saved XML with literal TAB/LF was also checked. Remaining conditions concern persistent/transient NameID, Advice, and AttributeValue; overall Not verified is retained.

SimpleSAMLphp `IIP-IDP06-a` adopts Success from a new v10 Run verifying post-request reauthentication time without reported-precision ambiguity. Omission and false controls retained the existing session time; only true returned a new time. `IIP-IDP06-b` adopts similarly verified v9 success evidence, but the latest v10 attempt remained Not verified because of timestamp precision ambiguity. The table explicitly identifies prior-Run evidence. Earlier [S2] records the incorrect-FAIL correction history rather than a permanent Not verified hold. A timestamp-precision hold is not a reauthentication failure.

For Shibboleth `IIP-SSO01-fk/fu/gi`, pregenerated positive requests in v8 became Stale Request and ended with `control_failed`. After v9 changed request generation to case-selection time, positive and abnormal attempts executed successfully and reconfirmed Success. The table adopts v9 evidence. Invalid-signature attempts include client observations of a Message Security Error page without a SAML response; this does not mean every input produced a SAML error response. Transmission delays were checked against saved XML IssueInstant and Transcript transmission times.


## Limited counterexamples for accepted updated metadata and encrypted logout

The old SimpleSAMLphp `IIP-IDP06-b-idp-01` Success is withdrawn through audit. External reauthentication time alone does not prove the approved obligation that the authentication mechanism can access ForceAuthn internally. Original results and transcripts are preserved; a review qualification matching original hashes, Run, referenced response, and approved variant returns the observation to unverified. External reauthentication evaluation for `IIP-IDP06-a-idp-01` and internal-mechanism evidence in another Run are unchanged. `audit_force_authn_mechanism_evidence.py` verifies the withdrawal, which assigns no new product violation.

Keycloak `IIP-MD06-ab-idp-01` uses a shared campaign pinning original A→B metadata import, explicit acceptance, stored configuration, implementation source, and signed positive controls for the same entity/native client. Native `Invalid redirect uri` when requesting the second POST ACS advertised by accepted B, correctly signed with the same B key, was correlated with signed Success for the normal ACS and an invalid-signature control. This is a concrete counterexample to the actual-application obligation in approved `IIP-MD06.ab#v-7e4460130e`, evaluated as Failed by the central Evaluator, rather than Success satisfying every condition. It is not generalized to other bindings/profiles or absence of whole-product capability.

Actual requests in this Run remain the shared originals from `IIP-MD06-a-idp-01`; they are not relabeled as sent by AB. AB's prepared outbox remains PENDING without a transcript reference. The first saved v187 result had already been reevaluated from originals, so explicit evaluate produced the same conclusion before and after. This combination of a finished case and unsent outbox is recorded in separate original Suite diagnostics; status, case_id, and historical unknown delivery are unchanged.

SimpleSAMLphp `IIP-IDP19-c-idp-01` correlates normal logout, decryption with the registered second key, and encryption with an unregistered key to the same native session, request, and response. Product parser/decryption verification and implementation originals were matched. Native decryption rejected the unregistered-key ciphertext, while the same actual logout path returned a successful response. The central Evaluator classifies this limited counterexample as Failed. The older NOT_VERIFIED from failed generic browser observer controls remains as originally recorded; silence or an HTTP error alone does not establish rejection capability. This conclusion does not apply where the additional native originals are unavailable.

<!--g1-literal--> Formal adoption in this batch comprises 2 Failed observations, reducing unverified observations from 227 to 225 with 87 distinct case IDs unchanged. The v187 deployment passed 299 targeted tests, G1 structure 46/46, and G2 21/21; 125 runtime files matched the distribution. Remaining observations are Keycloak 86, Shibboleth 57, and SimpleSAMLphp 82. Product configuration writes, product restarts, SAML transmissions, Run creation, and human actions for formal reevaluation and adoption alone are each 0.

<!--g1-literal--> Keycloak shares 3 prior collection attempts, reusing 15 configuration operations, 45 SAML attempts, and 3 created Runs. These are not counted again for AB adoption. SimpleSAMLphp has 7 attempts including earlier failures, with 33 attempted configuration writes (19 applications and 14 restorations), 40 SAML attempts, 19 authentication inputs, 7 created Runs, 12 native parser executions, 4 decryptions, and 25 signature checks. Suite-only prepare/abort operations total 159, with 7 temporary keys, 14 temporary-file writes, and 14 deletions recorded. All configuration was restored and temporary keys deleted; product restarts and human actions are each 0. Native helper failures and earlier failed generic controls are retained; reader fixes required no additional product transmissions.

<!--g1-literal--> Runtime JAR replay preserved the 23 Keycloak controls and all Outcomes/controls of previously adopted a/c; all 38 SimpleSAMLphp malformed-original controls remained unverified. Independent verifiers are `verify_keycloak_supersession_counterexample_acceptance.py` and `verify_ssp_encrypted_logout_acceptance.py`. Originals, formal results, restoration, and operation counts are saved in `build/acceptance/reference-20261001/keycloak-native-supersession-counterexample-v187-r1/` and `ssp-encrypted-logout-native-v186-r7/`; inventory deltas, deployment, and independent verification logs are recorded in `progress-v187.json`. Comparison cause classification requires an exact case, profile, and reason match with these verifiers.


Additional results adopted in the inventory are included in the comparison after matching Run, SHA-256, and Verdict. `Failed (adopted in inventory; cause classification unconfirmed)` transcribes a saved conclusion; this update does not add approval of product cause attribution.

## Breakdown of Not verified observations

The table adopts 191 case-result observations. Cases marked † adopt additional evidence from new Runs; other existing evidence is retained. These counts do not represent a single Run or a complete rerun of all tests. Earlier FAIL results reclassified as configuration gaps in the comparison are excluded from this NOT_VERIFIED total.

| Reason | Keycloak | Shibboleth IdP | SimpleSAMLphp | Required follow-up |
|---|---:|---:|---:|---|
| `case.pending-interaction` | 34 | 13 | 30 | Includes configuration and reception waits as well as unimplemented evaluation paths. See the complete inventory |
| `attestation.interaction-disallowed` | 20 | 20 | 22 | Attestation is disabled. Do not submit an attestation without verification |
| `browser_fixture_partial` | 7 | 7 | 11 | Only some tests were executed; evidence for remaining variants is missing |
| `idp.acs-probe.inconclusive` | 1 | 2 | 1 | Further inspect the case response, target configuration, and positive controls |
| `metadata.algorithms.local-policy-unverified` | 2 | 0 | 2 | Further inspect the case response, target configuration, and positive controls |
| `slo.propagation.not-observed` | 2 | 0 | 1 | Further inspect the case response, target configuration, and positive controls |
| `audit.slo-async-session-failure-unproven` | 1 | 1 | 0 | Safely induce failure to terminate the IdP session and observe both successful termination and failure-notification controls |
| `idp.error-assertion.inconclusive` | 1 | 0 | 1 | Further inspect the case response, target configuration, and positive controls |
| `slo.redirect-response.not-observed` | 1 | 0 | 1 | Further inspect the case response, target configuration, and positive controls |
| `audit.force-authn-mechanism-access-unproven` | 0 | 0 | 1 | Further inspect the case response, target configuration, and positive controls |
| `audit.metadata-full-ui-controls-unproven` | 0 | 0 | 1 | Import correctly placed UIInfo and DiscoHints and verify values for every variant through the product UI or effective read-back |
| `idp.nameid-policy.inconclusive` | 1 | 0 | 0 | Further inspect the case response, target configuration, and positive controls |
| `slo.async.feedback.unrecognized` | 0 | 0 | 1 | Further inspect the case response, target configuration, and positive controls |
| `slo.encrypted-id.key-unavailable` | 1 | 0 | 0 | Further inspect the case response, target configuration, and positive controls |
| `slo.encrypted-id.multiple-keys.key-unavailable` | 1 | 0 | 0 | Further inspect the case response, target configuration, and positive controls |
| `slo.encrypted-id.negative-control-failed` | 0 | 0 | 1 | Further inspect the case response, target configuration, and positive controls |
| `slo.partial-logout.not-observed` | 1 | 0 | 0 | Further inspect the case response, target configuration, and positive controls |
| `slo.redirect-request.not-observed` | 1 | 0 | 0 | Further inspect the case response, target configuration, and positive controls |
| `slo.redirect-response.unavailable` | 0 | 1 | 0 | Further inspect the case response, target configuration, and positive controls |

Removing Chrome and approval blocks alone cannot resolve these observations. Missing automated evaluation and fixtures require Suite implementation. Configuration and attestation paths require supporting evidence. The [complete inventory](26-unverified-case-inventory.md) records causes and retests for each case.

## Comparison by test

### browser_sso_idp

| Test | Keycloak 26.7.2 | Shibboleth IdP 5.2.3 | SimpleSAMLphp 2.5.0 |
|---|---|---|---|
| `IIP-ALG01-a-idp-01` | Success † | Success † | Success † |
| `IIP-ALG02-a-idp-01` | Success † | Success † | Success † |
| `IIP-ALG03-a-idp-01` | Success † | Success † | Warning † |
| `IIP-ALG04-a-idp-01` | Success † | Success † | Success † |
| `IIP-ALG04-b-idp-01` | Success † | Success † | Success † |
| `IIP-ALG05-a-idp-01` | Warning | Warning | Warning |
| `IIP-ALG06-a-idp-01` | Success † | Success † | Success † |
| `IIP-ALG06-b-idp-01` | Success † | Success † | Not verified † |
| `IIP-ALG06-c-idp-01` | Success † | Success † | Not verified † |
| `IIP-ALG06-d-idp-01` | Not verified † | Not verified † | Not verified † |
| `IIP-ALG07-a-idp-01` | Not verified | Not verified | Not verified |
| `IIP-ALG08-a-idp-01` | Success † | Success † | Not verified |
| `IIP-ALG08-b-idp-01` | Success † | Success † | Not verified |
| `IIP-ALG08-c-idp-01` | Not verified | Success † | Not verified |
| `IIP-EXT01-a-idp-01` | Success | Success | Success |
| `IIP-EXT01-b-idp-01` | Success † | Success † | Success † |
| `IIP-EXT01-b1-idp-01` | Warning | Warning | Warning |
| `IIP-EXT01-c-idp-01` | Success † | Success † | Not verified |
| `IIP-EXT01-c1-idp-01` | Warning | Warning | Warning |
| `IIP-G01-a-idp-01` | Not verified | Not verified | Not verified |
| `IIP-G02-a-idp-01` | Success † | Success † | Success † |
| `IIP-G02-c-idp-01` | Not verified | Not verified | Not verified |
| `IIP-G03-a-idp-01` | Success | Success | Success |
| `IIP-G03-b-idp-01` | Success † | Success † | Success † |
| `IIP-IDP01-a-idp-01` | **Failed (Product)** † | Success † | Success † |
| `IIP-IDP02-a-idp-01` | Success † | Success † | Success † |
| `IIP-IDP03-a-idp-01` | **Failed (adopted in inventory; cause classification unconfirmed)** † | Success † | Success † |
| `IIP-IDP04-a-idp-01` | **Failed (adopted in inventory; cause classification unconfirmed)** † | Success † | Success † |
| `IIP-IDP04-b-idp-01` | Not verified | Success † | **Failed (Product)** † |
| `IIP-IDP05-a-idp-01` | **Failed (Product)** † | Success | **Failed (Product)** |
| `IIP-IDP06-a-idp-01` | Success † | Success † | Success † |
| `IIP-IDP06-b-idp-01` | Success † | Success † | Not verified † |
| `IIP-IDP06-c-idp-01` | Success | Success | Success |
| `IIP-IDP07-a-idp-01` | Success | Success | Success |
| `IIP-IDP08-a-idp-01` | **Failed (Product)** † | Success † | **Failed (Product)** |
| `IIP-IDP09-a-idp-01` | Success † | Success † | Success † |
| `IIP-IDP09-b-idp-01` | Warning | Warning | Warning |
| `IIP-IDP10-a-idp-01` | Success | Success | Success |
| `IIP-IDP10-b-idp-01` | **Failed (Product)** | Success | **Failed (Product)** |
| `IIP-IDP10-d-idp-01` | Not verified (Suite) [S1] | Success | **Failed (Product)** |
| `IIP-IDP11-a-idp-01` | **Failed (Product)** † | Success † | Not verified |
| `IIP-IDP12-a-idp-01` | Not verified (Configuration) [C1] | Success | Success |
| `IIP-IDP12-b-idp-01` | Success † | Success † | Success |
| `IIP-IDP12-c-idp-01` | **Failed (adopted in inventory; cause classification unconfirmed)** † | Success † | Success † |
| `IIP-IDP12-d-idp-01` | Success | Not verified | Success |
| `IIP-IDP12-e-idp-01` | Success † | Success | Success |
| `IIP-IDP12-f-idp-01` | Not verified | Not verified | Not verified |
| `IIP-SSO01-a-idp-01` | Success | Success | Success |
| `IIP-SSO01-ad-idp-01` | Warning | Warning | Warning |
| `IIP-SSO01-ae-idp-01` | Success † | Success † | Success † |
| `IIP-SSO01-ag-idp-01` | Success | Success | **Failed (Product)** |
| `IIP-SSO01-ah-idp-01` | Warning | Warning | Warning |
| `IIP-SSO01-ai-idp-01` | Success | Success | Success |
| `IIP-SSO01-aj-idp-01` | Success | Success | Success |
| `IIP-SSO01-ak-idp-01` | Warning † | Warning † | Warning † |
| `IIP-SSO01-al-idp-01` | Success † | Success † | Success † |
| `IIP-SSO01-an-idp-01` | Success † | Success | Success † |
| `IIP-SSO01-ao-idp-01` | Success | Success | Success |
| `IIP-SSO01-ap-idp-01` | Success | Success | Success |
| `IIP-SSO01-au-idp-01` | Warning | Warning | Warning |
| `IIP-SSO01-bk-idp-01` | Warning | Warning | Warning |
| `IIP-SSO01-cc-idp-01` | Success | Success | Success |
| `IIP-SSO01-ch-idp-01` | Success | Success | Success |
| `IIP-SSO01-ci-idp-01` | Warning | Warning | Warning |
| `IIP-SSO01-cj-idp-01` | Warning | Warning | Warning |
| `IIP-SSO01-ck-idp-01` | Warning | Warning | Warning |
| `IIP-SSO01-cl-idp-01` | Warning | Warning | Success |
| `IIP-SSO01-cm-idp-01` | Warning | Warning | Success |
| `IIP-SSO01-cn-idp-01` | Warning | Warning | Success |
| `IIP-SSO01-cy-idp-01` | Success | Success | Success |
| `IIP-SSO01-cz-idp-01` | Warning | Warning | Success † |
| `IIP-SSO01-d-idp-01` | **Failed (Product)** † | Success | **Failed (Product)** † |
| `IIP-SSO01-da-idp-01` | Warning | Warning | Warning |
| `IIP-SSO01-db-idp-01` | Warning | Warning | Success |
| `IIP-SSO01-dc-idp-01` | Warning | Warning | Warning |
| `IIP-SSO01-dd-idp-01` | Warning | Warning | Success |
| `IIP-SSO01-de-idp-01` | Not verified | Not verified | Not verified |
| `IIP-SSO01-dh-idp-01` | Warning | Warning | Success |
| `IIP-SSO01-di-idp-01` | Warning | Warning | Warning |
| `IIP-SSO01-dj-idp-01` | Warning | Warning | Warning |
| `IIP-SSO01-dk-idp-01` | Warning | Warning | Warning |
| `IIP-SSO01-dl-idp-01` | Warning | Warning | Warning |
| `IIP-SSO01-dm-idp-01` | Success | Success | Warning |
| `IIP-SSO01-dn-idp-01` | Success | Success | Warning |
| `IIP-SSO01-do-idp-01` | Success | Success | Warning |
| `IIP-SSO01-dp-idp-01` | Warning | Warning | Warning |
| `IIP-SSO01-dq-idp-01` | Warning | Success | Warning |
| `IIP-SSO01-ds-idp-01` | Warning | Warning | Warning |
| `IIP-SSO01-du-idp-01` | Warning | Warning | Warning |
| `IIP-SSO01-dv-idp-01` | Success | Success | Success |
| `IIP-SSO01-dw-idp-01` | Success | Success | Success |
| `IIP-SSO01-dy-idp-01` | Not verified | Not verified | Not verified |
| `IIP-SSO01-dz-idp-01` | Success | Success | Success |
| `IIP-SSO01-e-idp-01` | Not verified | Not verified | Not verified |
| `IIP-SSO01-ea-idp-01` | Not verified | Not verified | Not verified |
| `IIP-SSO01-eb-idp-01` | Not verified | Not verified | Not verified |
| `IIP-SSO01-ec-idp-01` | Not verified | Not verified | Not verified |
| `IIP-SSO01-ed-idp-01` | Not verified | Not verified | Not verified |
| `IIP-SSO01-ee-idp-01` | Not verified | Not verified | Not verified |
| `IIP-SSO01-ef-idp-01` | Success | Success | Success |
| `IIP-SSO01-eg-idp-01` | Success | Success | Success |
| `IIP-SSO01-eh-idp-01` | Success | Success | Success |
| `IIP-SSO01-ei-idp-01` | Success | Success | Success |
| `IIP-SSO01-ej-idp-01` | Warning | Warning | Success |
| `IIP-SSO01-em-idp-01` | Success † | Success † | Success † |
| `IIP-SSO01-en-idp-01` | Success | Success | Success |
| `IIP-SSO01-eo-idp-01` | Success | Success | Success |
| `IIP-SSO01-ep-idp-01` | Not verified | Not verified | Warning † |
| `IIP-SSO01-eq-idp-01` | Warning | Warning | Success |
| `IIP-SSO01-er-idp-01` | Success | Success | Success |
| `IIP-SSO01-es-idp-01` | Success | Success | Success |
| `IIP-SSO01-et-idp-01` | Success | Success | Success |
| `IIP-SSO01-eu-idp-01` | Success | Success | Success |
| `IIP-SSO01-ev-idp-01` | Success | Success | Success |
| `IIP-SSO01-ew-idp-01` | Success | Success | Success |
| `IIP-SSO01-ex-idp-01` | Success | Success | Success |
| `IIP-SSO01-ez-idp-01` | Success † | Success † | Warning † |
| `IIP-SSO01-f-idp-01` | Not verified | Success | Not verified |
| `IIP-SSO01-fd-idp-01` | Warning † | Warning † | Warning † |
| `IIP-SSO01-fe-idp-01` | Warning † | Warning † | Warning † |
| `IIP-SSO01-fk-idp-01` | **Failed (Product)** | Success † | **Failed (Product)** |
| `IIP-SSO01-fp-idp-01` | Success † | Success † | Success † |
| `IIP-SSO01-fr-idp-01` | Warning † | Warning † | Warning † |
| `IIP-SSO01-fs-idp-01` | Success | Success | Success |
| `IIP-SSO01-fu-idp-01` | Warning | Success † | Warning |
| `IIP-SSO01-fv-idp-01` | Warning | Warning | Warning |
| `IIP-SSO01-g-idp-01` | Success † | Success † | Success † |
| `IIP-SSO01-ga-idp-01` | Not verified | Success † | Not verified |
| `IIP-SSO01-gb-idp-01` | Not verified | Success † | Not verified |
| `IIP-SSO01-gc-idp-01` | Not verified | **Failed (Product)** † | Not verified |
| `IIP-SSO01-gd-idp-01` | Warning † | Warning † | Warning † |
| `IIP-SSO01-gi-idp-01` | Success † | Success † | Success † |
| `IIP-SSO01-gj-idp-01` | Not verified | Success † | Not verified |
| `IIP-SSO01-h-idp-01` | Success | Success | Success |
| `IIP-SSO01-h1-idp-01` | Success | Success | Success |
| `IIP-SSO01-i-idp-01` | Success | Success | Success |
| `IIP-SSO01-i1-idp-01` | Warning | Warning | Warning |
| `IIP-SSO01-i2-idp-01` | Not verified | Not verified | Not verified |
| `IIP-SSO01-j-idp-01` | Success | Success | Success |
| `IIP-SSO01-k-idp-01` | Success † | Success † | Success |
| `IIP-SSO01-k1-idp-01` | Success | Success | Success |
| `IIP-SSO01-k2-idp-01` | Success | Success | Success |
| `IIP-SSO01-l-idp-01` | Success | Success | Success |
| `IIP-SSO01-m-idp-01` | Success | Success | Success |
| `IIP-SSO01-v-idp-01` | Success | Success | Success |
| `IIP-SSO01-x-idp-01` | Success | Success | Success |
| `IIP-SSO01-z-idp-01` | Warning † | Warning † | Warning † |
| `IIP-SSO02-a-idp-01` | Success | Success | Success |
| `IIP-SSO03-a-idp-01` | Success | Success | Success |
| `IIP-SSO03-b-idp-01` | Success † | Success † | Success † |
| `IIP-SSO04-a-idp-01` | Success † | Success † | Success † |
| `IIP-SSO05-a-idp-01` | Success | Success † | **Failed (Product)** |
| `IIP-SSO05-a1-idp-01` | Success † | Not verified | Not verified |
| `IIP-SSO05-a2-idp-01` | Success | Success † | Success † |
| `IIP-SSO05-a3-idp-01` | Success † | Success † | Success † |
| `IIP-SSO05-a8-idp-01` | Success † | Not verified | Not verified |
| `IIP-SSO05-b-idp-01` | Success | Success | Success |
| `IIP-SSO05-b1-idp-01` | Success | Success | Success |
| `IIP-SSO05-b2-idp-01` | Success | **Failed (Product)** | Success |
| `IIP-SSO07-a-idp-01` | Success | Success | Success |
| `IIP-SSO07-b-idp-01` | **Failed (Product)** † | **Failed (Product)** † | **Failed (Product)** † |

### metadata_idp

| Test | Keycloak 26.7.2 | Shibboleth IdP 5.2.3 | SimpleSAMLphp 2.5.0 |
|---|---|---|---|
| `IIP-ALG01-a-idp-01` | Success † | Success † | Success † |
| `IIP-ALG02-a-idp-01` | Success † | Success † | Success † |
| `IIP-ALG03-a-idp-01` | Success † | Success † | Warning † |
| `IIP-ALG07-a-idp-01` | Not verified | Not verified | Not verified |
| `IIP-EXT01-a-idp-01` | Success | Success | Success |
| `IIP-EXT01-b-idp-01` | Success † | Success † | Success † |
| `IIP-EXT01-b1-idp-01` | Warning | Warning | Warning |
| `IIP-EXT01-c-idp-01` | Success † | Success † | Not verified |
| `IIP-EXT01-c1-idp-01` | Warning | Warning | Warning |
| `IIP-G01-a-idp-01` | Not verified | Not verified | Not verified |
| `IIP-IDP17-b4-idp-01` | Warning | Warning | Warning |
| `IIP-MD01-a-idp-01` | Success † | Success † | Success † |
| `IIP-MD02-a-idp-01` | Success † | Success † | Success † |
| `IIP-MD02-b-idp-01` | Success † | Success | Success † |
| `IIP-MD02-c-idp-01` | Success † | Success | Success † |
| `IIP-MD02-d-idp-01` | Not verified | Success | Success † |
| `IIP-MD03-a-idp-01` | **Failed (Product)** † | Success † | Success † |
| `IIP-MD03-b-idp-01` | **Failed (Product)** † | Success † | Success † |
| `IIP-MD03-c-idp-01` | **Failed (Product)** † | Success | Success † |
| `IIP-MD03-d-idp-01` | **Failed (Product)** † | Success † | Success † |
| `IIP-MD03-e-idp-01` | Warning | Warning | Warning |
| `IIP-MD04-a-idp-01` | **Failed (Product)** † | Success † | **Failed (Product)** † |
| `IIP-MD04-b-idp-01` | **Failed (Product)** † | Success † | Success † |
| `IIP-MD04-c-idp-01` | **Failed (Product)** † | Success † | **Failed (Product)** † |
| `IIP-MD05-a-idp-01` | Not verified | Not verified | Not verified |
| `IIP-MD05-a1-idp-01` | Success † | Success † | Not verified |
| `IIP-MD05-a2-idp-01` | Success † | Success † | Not verified |
| `IIP-MD05-a3-idp-01` | Not verified | Not verified | Not verified † |
| `IIP-MD05-a4-idp-01` | Success † | Success | Success † |
| `IIP-MD05-a5-idp-01` | Success † | Success | Success † |
| `IIP-MD05-a6-idp-01` | Success | Success | Success |
| `IIP-MD05-a7-idp-01` | Warning | Warning | Warning |
| `IIP-MD05-a8-idp-01` | Not verified | Not verified | Not verified |
| `IIP-MD05-a9-idp-01` | Success | Success | Success |
| `IIP-MD05-ab-idp-01` | Success | Success | Success |
| `IIP-MD05-ac-idp-01` | Not verified | Not verified | Not verified |
| `IIP-MD05-ad-idp-01` | Warning † | Success † | Success † |
| `IIP-MD05-ae-idp-01` | Warning † | Warning † | Warning † |
| `IIP-MD05-af-idp-01` | Warning † | Warning † | Warning † |
| `IIP-MD05-ag-idp-01` | Warning | Warning | Warning |
| `IIP-MD05-ah-idp-01` | Success † | Success † | Success † |
| `IIP-MD05-ai-idp-01` | Warning | Warning | Warning |
| `IIP-MD05-aj-idp-01` | Warning | Warning | Warning |
| `IIP-MD05-ak-idp-01` | Warning | Warning | Warning |
| `IIP-MD05-al-idp-01` | Warning | Warning | Warning |
| `IIP-MD05-am-idp-01` | Not verified | Warning † | Warning † |
| `IIP-MD05-an-idp-01` | Not verified | Success † | **Failed (adopted in inventory; cause classification unconfirmed)** † |
| `IIP-MD05-ao-idp-01` | Not verified | Success † | Success † |
| `IIP-MD05-ap-idp-01` | Not verified | Success † | Success † |
| `IIP-MD05-aq-idp-01` | Not verified | Success † | Success † |
| `IIP-MD05-ar-idp-01` | Not verified | Success † | Success † |
| `IIP-MD05-as-idp-01` | **Failed (Product)** † | Success † | Success † |
| `IIP-MD05-at-idp-01` | Warning | Warning | Warning |
| `IIP-MD05-au-idp-01` | Warning | Warning | Warning |
| `IIP-MD05-av-idp-01` | **Failed (Product)** † | **Failed (Product)** † | **Failed (Product)** † |
| `IIP-MD05-aw-idp-01` | Not verified | Not verified | Not verified |
| `IIP-MD05-b-idp-01` | **Failed (Product)** † | Success † | **Failed (adopted in inventory; cause classification unconfirmed)** † |
| `IIP-MD05-c-idp-01` | Success † | Success † | Success † |
| `IIP-MD05-c1-idp-01` | Not verified | **Failed (adopted in inventory; cause classification unconfirmed)** † | **Failed (adopted in inventory; cause classification unconfirmed)** † |
| `IIP-MD05-c2-idp-01` | Not verified | Success † | Success † |
| `IIP-MD05-c3-idp-01` | Not verified | Not verified | **Failed (adopted in inventory; cause classification unconfirmed)** † |
| `IIP-MD05-c4-idp-01` | Warning | Warning | Warning |
| `IIP-MD05-c5-idp-01` | Not verified | Not verified | Not verified |
| `IIP-MD05-c6-idp-01` | Not verified | Not verified | Not verified |
| `IIP-MD05-c7-idp-01` | Not verified | Not verified | Not verified |
| `IIP-MD05-c8-idp-01` | Success | Success | Success |
| `IIP-MD05-c9-idp-01` | Success | Success | Success |
| `IIP-MD05-ca-idp-01` | Success | Success | Success |
| `IIP-MD05-cb-idp-01` | Warning | Warning | Warning |
| `IIP-MD05-cc-idp-01` | Warning | Warning | Warning |
| `IIP-MD05-cd-idp-01` | **Failed (Product)** † | Success | **Failed (Product)** † |
| `IIP-MD05-ce-idp-01` | Success | Success | Success |
| `IIP-MD05-d-idp-01` | Success † | Success † | Success † |
| `IIP-MD05-d1-idp-01` | Not verified | Not verified | Not verified |
| `IIP-MD05-d2-idp-01` | Warning | Warning | Warning |
| `IIP-MD05-d3-idp-01` | Warning | Warning | Warning |
| `IIP-MD05-d4-idp-01` | Warning | Warning | Warning |
| `IIP-MD05-d5-idp-01` | Warning | Warning | Warning |
| `IIP-MD05-d6-idp-01` | Warning | Warning | Warning |
| `IIP-MD05-d7-idp-01` | Warning | Warning | Warning |
| `IIP-MD05-d8-idp-01` | Warning | Warning | Warning |
| `IIP-MD05-d9-idp-01` | Warning | Warning | Warning |
| `IIP-MD05-e-idp-01` | Success † | Success † | Success † |
| `IIP-MD05-e1-idp-01` | Warning | Warning | Warning |
| `IIP-MD05-e2-idp-01` | Warning | Warning | Warning |
| `IIP-MD05-e3-idp-01` | Warning | Warning | Warning |
| `IIP-MD05-e4-idp-01` | Warning | Warning | Warning |
| `IIP-MD05-e5-idp-01` | Success † | Success † | Success † |
| `IIP-MD05-e6-idp-01` | Warning | Warning | Warning |
| `IIP-MD05-e7-idp-01` | Not verified | Success † | Not verified |
| `IIP-MD05-e8-idp-01` | **Failed (adopted in inventory; cause classification unconfirmed)** † | Success † | **Failed (adopted in inventory; cause classification unconfirmed)** † |
| `IIP-MD05-e9-idp-01` | Not verified † | Success † | Not verified † |
| `IIP-MD05-ea-idp-01` | Not verified † | Success † | Not verified † |
| `IIP-MD05-eb-idp-01` | **Failed (adopted in inventory; cause classification unconfirmed)** † | Success † | **Failed (adopted in inventory; cause classification unconfirmed)** † |
| `IIP-MD05-ec-idp-01` | Warning | Warning | Warning |
| `IIP-MD05-ed-idp-01` | Warning | Warning | Warning |
| `IIP-MD05-f-idp-01` | Not verified | Success † | Not verified |
| `IIP-MD05-f1-idp-01` | Warning | Warning | Warning |
| `IIP-MD05-f2-idp-01` | Warning | Warning | Warning |
| `IIP-MD05-f3-idp-01` | Warning | Warning | Warning |
| `IIP-MD05-f4-idp-01` | Warning | Warning | Warning |
| `IIP-MD05-f5-idp-01` | Not verified | Not verified | Not verified |
| `IIP-MD05-f7-idp-01` | Warning † | Warning † | Warning † |
| `IIP-MD05-f8-idp-01` | Warning † | Warning † | Warning † |
| `IIP-MD05-f9-idp-01` | Success † | Success † | Warning † |
| `IIP-MD05-fa-idp-01` | Warning † | Warning † | Warning † |
| `IIP-MD05-fb-idp-01` | Warning † | Warning † | Warning † |
| `IIP-MD05-fc-idp-01` | Warning | Warning | Warning |
| `IIP-MD05-fd-idp-01` | Warning | Warning | Warning |
| `IIP-MD05-fe-idp-01` | Warning | Warning | Warning |
| `IIP-MD05-ff-idp-01` | Success † | Success † | Success † |
| `IIP-MD05-fg-idp-01` | Warning † | Warning † | Warning † |
| `IIP-MD05-fh-idp-01` | Warning † | Warning † | Warning † |
| `IIP-MD05-fi-idp-01` | Warning † | Warning † | Warning † |
| `IIP-MD05-fj-idp-01` | Warning † | Warning † | Success † |
| `IIP-MD05-fk-idp-01` | Warning | Warning | Warning |
| `IIP-MD05-g-idp-01` | Success † | Success | Success † |
| `IIP-MD06-a-idp-01` | **Failed (Product)** † | Success † | Not verified |
| `IIP-MD06-a1-idp-01` | Not verified | Success | Success † |
| `IIP-MD06-a2-idp-01` | Not verified | Success † | Success † |
| `IIP-MD06-a3-idp-01` | Warning † | Warning † | Not verified |
| `IIP-MD06-a4-idp-01` | Warning | Warning | Warning |
| `IIP-MD06-a5-idp-01` | **Failed (Product)** † | Success † | **Failed (Product)** † |
| `IIP-MD06-a6-idp-01` | Not verified | Success † | Success † |
| `IIP-MD06-a7-idp-01` | **Failed (Product)** † | Success † | **Failed (Product)** † |
| `IIP-MD06-a8-idp-01` | Success † | Success † | Success † |
| `IIP-MD06-a9-idp-01` | **Failed (Product)** † | Success † | Success † |
| `IIP-MD06-aa-idp-01` | Warning | Warning | Warning |
| `IIP-MD06-ab-idp-01` | **Failed (Product)** † | Success † | Not verified |
| `IIP-MD06-b-idp-01` | **Failed (Product)** † | Success † | Success † |
| `IIP-MD06-c-idp-01` | Success † | Success † | Success † |
| `IIP-MD07-a-idp-01` | **Failed (Product)** † | Success † | Success † |
| `IIP-MD07-b-idp-01` | Not verified | Success † | Success † |
| `IIP-MD09-a-idp-01` | Not verified | Not verified | Not verified |
| `IIP-MD09-b-idp-01` | Not verified | Not verified | Not verified |
| `IIP-MD11-a-idp-01` | Not verified | Not verified | Not verified |
| `IIP-MD12-a-idp-01` | Success † | Success | Success † |
| `IIP-MD12-b-idp-01` | **Failed (Product)** † | Success | Success † |
| `IIP-MD12-c-idp-01` | Success † | Success | Success † |
| `IIP-MD12-d-idp-01` | **Failed (Product)** † | Success | Success † |

### ecp_idp

| Test | Keycloak 26.7.2 | Shibboleth IdP 5.2.3 | SimpleSAMLphp 2.5.0 |
|---|---|---|---|
| `IIP-ALG01-a-idp-01` | Success † | Success † | Success † |
| `IIP-ALG02-a-idp-01` | Success † | Success † | Success † |
| `IIP-ALG03-a-idp-01` | Success † | Success † | Warning † |
| `IIP-ALG04-a-idp-01` | Success † | Success † | Success † |
| `IIP-ALG04-b-idp-01` | Success † | Success † | Success † |
| `IIP-ALG05-a-idp-01` | Warning | Warning | Warning |
| `IIP-ALG06-a-idp-01` | Success † | Success † | Success † |
| `IIP-ALG06-b-idp-01` | Success † | Success † | Not verified |
| `IIP-ALG06-c-idp-01` | Success † | Success † | Not verified |
| `IIP-ALG06-d-idp-01` | Not verified † | Not verified † | Not verified |
| `IIP-ALG07-a-idp-01` | Not verified | Not verified | Not verified |
| `IIP-ALG08-a-idp-01` | Success † | Success † | Not verified |
| `IIP-ALG08-b-idp-01` | Success † | Success † | Not verified |
| `IIP-ALG08-c-idp-01` | Not verified | Success † | Not verified |
| `IIP-EXT01-a-idp-01` | Success | Success | Success |
| `IIP-EXT01-b-idp-01` | Success † | Success † | Success † |
| `IIP-EXT01-b1-idp-01` | Warning | Warning | Warning |
| `IIP-EXT01-c-idp-01` | Success † | Success † | Not verified |
| `IIP-EXT01-c1-idp-01` | Warning | Warning | Warning |
| `IIP-G01-a-idp-01` | Not verified | Not verified | Not verified |
| `IIP-G03-a-idp-01` | Success | Success | Success |
| `IIP-IDP14-a-idp-01` | Success | Success | Success |
| `IIP-IDP14-b-idp-01` | Warning | Warning | Warning |
| `IIP-IDP15-a-idp-01` | **Failed (Product)** | Success | **Failed (Product)** |
| `IIP-IDP16-a-idp-01` | Not verified | Not verified | Not verified |

### single_logout_idp

| Test | Keycloak 26.7.2 | Shibboleth IdP 5.2.3 | SimpleSAMLphp 2.5.0 |
|---|---|---|---|
| `IIP-ALG01-a-idp-01` | Success † | Success † | Success † |
| `IIP-ALG02-a-idp-01` | Success † | Success † | Success † |
| `IIP-ALG03-a-idp-01` | Success † | Success † | Warning † |
| `IIP-ALG07-a-idp-01` | Not verified | Not verified | Not verified |
| `IIP-EXT01-a-idp-01` | Success † | Success † | Success † |
| `IIP-EXT01-b-idp-01` | Success † | Success † | Success † |
| `IIP-EXT01-b1-idp-01` | Warning | Warning | Warning |
| `IIP-EXT01-c-idp-01` | Success † | Success † | Not verified † |
| `IIP-EXT01-c1-idp-01` | Warning | Warning | Warning |
| `IIP-G01-a-idp-01` | Not verified † | Not verified † | Not verified † |
| `IIP-G03-a-idp-01` | Success | Success | Success |
| `IIP-IDP17-a-idp-01` | Success † | Success † | Success † |
| `IIP-IDP17-aa-idp-01` | Warning † | Warning † | Warning † |
| `IIP-IDP17-ab-idp-01` | Warning † | Warning † | Warning † |
| `IIP-IDP17-ac-idp-01` | Warning | Warning | Warning |
| `IIP-IDP17-ai-idp-01` | Success | Success | Success |
| `IIP-IDP17-aj-idp-01` | Success | Success | Success |
| `IIP-IDP17-ak-idp-01` | Success | Success | Success |
| `IIP-IDP17-al-idp-01` | **Failed (adopted in inventory; cause classification unconfirmed)** † | Success † | Success † |
| `IIP-IDP17-am-idp-01` | Success | Success | Success |
| `IIP-IDP17-an-idp-01` | Warning | Warning | Warning |
| `IIP-IDP17-b-idp-01` | Success † | Success † | **Failed (adopted in inventory; cause classification unconfirmed)** † |
| `IIP-IDP17-b1-idp-01` | **Failed (adopted in inventory; cause classification unconfirmed)** † | Success † | **Failed (adopted in inventory; cause classification unconfirmed)** † |
| `IIP-IDP17-b2-idp-01` | Not verified | Not verified | Not verified † |
| `IIP-IDP17-b3-idp-01` | Warning | Warning | Warning |
| `IIP-IDP17-b4-idp-01` | Warning | Warning | Warning |
| `IIP-IDP17-c-idp-01` | Not verified † | Warning † | Warning † |
| `IIP-IDP17-j-idp-01` | Success | Success † | Success |
| `IIP-IDP17-k-idp-01` | Success | Success † | Success |
| `IIP-IDP17-l-idp-01` | Success | Success † | Success |
| `IIP-IDP17-m-idp-01` | Success | Success † | **Failed (Product)** |
| `IIP-IDP17-n-idp-01` | Success † | Success † | Success |
| `IIP-IDP17-r-idp-01` | Not verified † | Success † | Not verified † |
| `IIP-IDP17-s-idp-01` | Not verified † | **Failed (adopted in inventory; cause classification unconfirmed)** † | Success † |
| `IIP-IDP17-t-idp-01` | **Failed (Product)** | **Failed (Product)** † | Success |
| `IIP-IDP17-u-idp-01` | Warning † | Warning † | Success |
| `IIP-IDP17-v-idp-01` | Success | Success | Success |
| `IIP-IDP17-x-idp-01` | Success † | Success † | **Failed (adopted in inventory; cause classification unconfirmed)** † |
| `IIP-IDP17-y-idp-01` | **Failed (adopted in inventory; cause classification unconfirmed)** † | Warning † | Warning † |
| `IIP-IDP17-z-idp-01` | **Failed (adopted in inventory; cause classification unconfirmed)** † | Warning † | Warning † |
| `IIP-IDP18-a-idp-01` | Success † | Success † | Success † |
| `IIP-IDP18-b-idp-01` | Success † | Success † | Success † |
| `IIP-IDP18-c-idp-01` | Not verified † | Success † | Success † |
| `IIP-IDP18-d-idp-01` | Not verified † | Not verified † | Not verified † |
| `IIP-IDP19-a-idp-01` | Not verified † | Success † | Not verified † |
| `IIP-IDP19-b-idp-01` | Not verified | Success † | Success † |
| `IIP-IDP19-c-idp-01` | Not verified † | Success † | **Failed (Product)** † |
| `IIP-IDP20-a-idp-01` | Not verified | Not verified | Not verified |
| `IIP-IDP21-a-idp-01` | Not verified | Not verified | Not verified |

## Adopted execution evidence

| Profile | Product | Run | Evidence directory |
|---|---|---|---|
| browser_sso_idp († listed supplemental cases only) | keycloak | `run_QKZYJCWA259NPF6KPASGVMJATM` | `additional-implementation/keycloak/browser_sso_idp` |
| browser_sso_idp († listed supplemental cases only) | keycloak | `run_AT0T8032SAJ8FETMM2JTMQGB7H` | `crypto-integrated-implementation/keycloak/browser_sso_idp` |
| browser_sso_idp († listed supplemental cases only) | keycloak | `run_1CV03TRVJZJA99QCCS80R7PHSJ` | `literal-integrated-implementation/keycloak/browser_sso_idp` |
| browser_sso_idp († listed supplemental cases only) | keycloak | `run_5X1B1RGKPNK7C7J3C1KT4B3EFM` | `build/acceptance/reference-20260915/algorithm-observation-batch/keycloak/browser_sso_idp` |
| browser_sso_idp († listed supplemental cases only) | keycloak | `run_6AD6T3VS8H87WQQBB1T2DEB3MX` | `build/acceptance/reference-20260915/algorithm-observation-batch/keycloak/browser_alg_combo` |
| browser_sso_idp († listed supplemental cases only) | keycloak | `run_9NSDTT181GXXKP6FRPZ719VHH9` | `build/acceptance/reference-20260928/browser-chain-keycloak-g02-v116-retry1` |
| browser_sso_idp († listed supplemental cases only) | keycloak | `run_RY1Y068ZYS585CFX48MKKYP722` | `build/acceptance/reference-20260930/keycloak-g03-v129` |
| browser_sso_idp († listed supplemental cases only) | keycloak | `run_7QRV9JKP9KFEDTJNESWFZX7MSY` | `build/acceptance/reference-20260930/terminal-http-keycloak-v151b/evaluation-terminal-http-v1` |
| browser_sso_idp († listed supplemental cases only) | keycloak | `run_6AD6T3VS8H87WQQBB1T2DEB3MX` | `build/acceptance/reference-20260915/algorithm-observation-batch/keycloak/browser_alg_combo` |
| browser_sso_idp († listed supplemental cases only) | keycloak | `run_3MZXNDWFZ62FNETRN75P79TVPT` | `build/acceptance/reference-20260930/ext01b-keycloak-v158/browser_sso_idp/evaluation-terminal-http-v1` |
| browser_sso_idp († listed supplemental cases only) | keycloak | `run_6AD6T3VS8H87WQQBB1T2DEB3MX` | `build/acceptance/reference-20260915/algorithm-observation-batch/keycloak/browser_alg_combo` |
| browser_sso_idp († listed supplemental cases only) | keycloak | `run_F02RXET295Z79JB4S3HHY459B4` | `build/acceptance/reference-20261002/keycloak-authentication-identity-r2/evaluation` |
| browser_sso_idp († listed supplemental cases only) | keycloak | `run_7QRV9JKP9KFEDTJNESWFZX7MSY` | `build/acceptance/reference-20260930/terminal-http-keycloak-v151b/evaluation-terminal-http-v1` |
| browser_sso_idp († listed supplemental cases only) | keycloak | `run_1G19EET7MAD89ABAG3BSJR316N` | `build/acceptance/reference-20261002/keycloak-registered-signer-r1/evaluation-actual` |
| browser_sso_idp († listed supplemental cases only) | keycloak | `run_FZY4Z3QD3NFN0CZSGFY73Y38ZD` | `build/acceptance/reference-20260918/keycloak-browser-chain-v71` |
| browser_sso_idp († listed supplemental cases only) | keycloak | `run_7QRV9JKP9KFEDTJNESWFZX7MSY` | `build/acceptance/reference-20260930/terminal-http-keycloak-v151b/evaluation-terminal-http-v1` |
| browser_sso_idp († listed supplemental cases only) | keycloak | `run_YNYN0RZPZJCSF9A36B0BTX60HG` | `build/acceptance/reference-20261001/keycloak-native-transient-allow-create-v185-r1/evaluation` |
| browser_sso_idp († listed supplemental cases only) | keycloak | `run_0536WQRK5ZEW9S20D06WDJFSWG` | `build/acceptance/reference-20261001/keycloak-native-subject-confirmation-v184-r1/evaluation` |
| browser_sso_idp († listed supplemental cases only) | keycloak | `run_0536WQRK5ZEW9S20D06WDJFSWG` | `build/acceptance/reference-20261001/keycloak-native-subject-confirmation-v184-r1/evaluation` |
| browser_sso_idp († listed supplemental cases only) | keycloak | `run_FZY4Z3QD3NFN0CZSGFY73Y38ZD` | `build/acceptance/reference-20260918/keycloak-browser-chain-v71` |
| browser_sso_idp († listed supplemental cases only) | keycloak | `run_EJYK4M640FX4PJAWT2YQW6STER` | `build/acceptance/reference-20260930/post-error-binding-keycloak-v173/evaluation` |
| browser_sso_idp († listed supplemental cases only) | keycloak | `run_9XH0Y4Z7P4JFHJTYQ3ZJKE633N` | `build/acceptance/reference-20260918/keycloak-signature-modes-v61/adoption` |
| browser_sso_idp († listed supplemental cases only) | keycloak | `run_5PVJ1E05DBMMMASJ9QTS45T3TM` | `build/acceptance/reference-20261004/keycloak-persistent-opaque-r1` |
| browser_sso_idp († listed supplemental cases only) | keycloak | `run_WGE123Q325NKQX590ZR0F1ZH9Y` | `build/acceptance/reference-20261001/keycloak-native-persistent-pairwise-v180-r4/evaluation` |
| browser_sso_idp († listed supplemental cases only) | keycloak | `run_5PVJ1E05DBMMMASJ9QTS45T3TM` | `build/acceptance/reference-20261004/keycloak-persistent-opaque-r1` |
| browser_sso_idp († listed supplemental cases only) | keycloak | `run_AT0T8032SAJ8FETMM2JTMQGB7H` | `build/acceptance/reference-20260914/crypto-integrated-implementation/keycloak/browser_sso_idp` |
| browser_sso_idp († listed supplemental cases only) | keycloak | `run_3MZXNDWFZ62FNETRN75P79TVPT` | `build/acceptance/reference-20260930/ext01b-keycloak-v158/browser_sso_idp/evaluation-terminal-http-v1` |
| browser_sso_idp († listed supplemental cases only) | keycloak | `run_PNTFR0MBDQX80WRN8HYPM094XM` | `build/acceptance/reference-20261004/keycloak-extension-attribute-parser-r2/evaluation-v230/browser_sso_idp` |
| browser_sso_idp († listed supplemental cases only) | keycloak | `run_QXEKAXFXVK2Y48CH9HJD7A5DW7` | `build/acceptance/reference-20260918/keycloak-native-ec-signature-v2/observations/browser_sso_idp/evaluation` |
| browser_sso_idp († listed supplemental cases only) | keycloak | `run_6AD6T3VS8H87WQQBB1T2DEB3MX` | `build/acceptance/reference-20260915/algorithm-observation-batch/keycloak/browser_alg_combo` |
| browser_sso_idp († listed supplemental cases only) | keycloak | `run_5X1B1RGKPNK7C7J3C1KT4B3EFM` | `build/acceptance/reference-20260915/algorithm-observation-batch/keycloak/browser_sso_idp` |
| browser_sso_idp († listed supplemental cases only) | keycloak | `run_6AD6T3VS8H87WQQBB1T2DEB3MX` | `build/acceptance/reference-20260915/algorithm-observation-batch/keycloak/browser_alg_combo` |
| browser_sso_idp († listed supplemental cases only) | keycloak | `run_5X1B1RGKPNK7C7J3C1KT4B3EFM` | `build/acceptance/reference-20260915/algorithm-observation-batch/keycloak/browser_sso_idp` |
| browser_sso_idp († listed supplemental cases only) | keycloak | `run_6AD6T3VS8H87WQQBB1T2DEB3MX` | `build/acceptance/reference-20260915/algorithm-observation-batch/keycloak/browser_alg_combo` |
| browser_sso_idp († listed supplemental cases only) | keycloak | `run_5X1B1RGKPNK7C7J3C1KT4B3EFM` | `build/acceptance/reference-20260915/algorithm-observation-batch/keycloak/browser_sso_idp` |
| browser_sso_idp († listed supplemental cases only) | keycloak | `run_G0J99F02Y5VAVJPWY78CNTGBJP` | `build/acceptance/reference-20260930/keycloak-alg08-native-policy-v163-r4` |
| browser_sso_idp († listed supplemental cases only) | keycloak | `run_G0J99F02Y5VAVJPWY78CNTGBJP` | `build/acceptance/reference-20260930/keycloak-alg08-native-policy-v163-r4` |
| browser_sso_idp († listed supplemental cases only) | keycloak | `run_8W6ESET9BX4VF2029FKW5JQEND` | `build/acceptance/reference-20260930/keycloak-attribute-name-capability-absence-v157` |
| browser_sso_idp († listed supplemental cases only) | keycloak | `run_EEAG5F4CFPVHYP90GGDZXB8VN4` | `build/acceptance/reference-20260918/keycloak-relying-party-attribute-evaluation` |
| browser_sso_idp († listed supplemental cases only) | keycloak | `run_T6YFS3EDNTS92F0RHS33WTZTRV` | `build/acceptance/reference-20260930/keycloak-attribute-policy-capability-absence-v159` |
| browser_sso_idp († listed supplemental cases only) | keycloak | `run_T6YFS3EDNTS92F0RHS33WTZTRV` | `build/acceptance/reference-20260930/keycloak-attribute-policy-capability-absence-v159` |
| browser_sso_idp († listed supplemental cases only) | keycloak | `run_E8R3MNZD0NM9S6QYGPVD3S215V` | `build/acceptance/reference-20260930/keycloak-idp05a-v127-retry1` |
| browser_sso_idp († listed supplemental cases only) | keycloak | `run_F9VD5CSM4XV01J1Q2X1BPJ6DG2` | `build/acceptance/reference-20260918/keycloak-browser-chain-v73` |
| browser_sso_idp († listed supplemental cases only) | keycloak | `run_8KJN2EHMVRDZVB4EM2CS1THHPG` | `build/acceptance/reference-20261004/keycloak-forceauthn-mechanism-r2` |
| browser_sso_idp († listed supplemental cases only) | keycloak | `run_JQTKB2M3V6887FKT0DF49G38QZ` | `build/acceptance/reference-20260918/keycloak-browser-chain-v75` |
| browser_sso_idp († listed supplemental cases only) | keycloak | `run_P57XA0ZDWHSVWX8PNW01MXSVT7` | `build/acceptance/reference-20260930/keycloak-nameid-omission-probe-v2` |
| browser_sso_idp († listed supplemental cases only) | keycloak | `run_YT60WQ4FCYBC6ET6HGTDZQT3RE` | `build/acceptance/reference-20260930/keycloak-idp12e-v145/evaluation-v139` |
| browser_sso_idp († listed supplemental cases only) | keycloak | `run_JZWZCDA4MJ6EZ617JXKRG383K8` | `build/acceptance/reference-20260930/idp12b-keycloak-v150` |
| browser_sso_idp († listed supplemental cases only) | keycloak | `run_ZZQH3B5136N955F9W1NAMJ4GSG` | `build/acceptance/reference-20260918/keycloak-default-acs` |
| browser_sso_idp († listed supplemental cases only) | keycloak | `run_R6M9V3HBVEX0C8TX0FRT0JJTVG` | `build/acceptance/reference-20260918/keycloak-native-signature-audit/browser_sso_idp/evaluation` |
| browser_sso_idp († listed supplemental cases only) | keycloak | `run_R6M9V3HBVEX0C8TX0FRT0JJTVG` | `build/acceptance/reference-20260918/keycloak-native-signature-audit/browser_sso_idp/evaluation` |
| browser_sso_idp | keycloak | `run_0WQJR9TGK0MC4TFTVT1AFKWDKP` | `interaction-followup/after/keycloak/browser_sso_idp` |
| browser_sso_idp († listed supplemental cases only) | shibboleth | `run_DMGDE6GB0DGZ8HTYRJPY3QY7QG` | `additional-implementation/shibboleth/browser_sso_idp` |
| browser_sso_idp († listed supplemental cases only) | shibboleth | `run_BD24PBN5E7QBPNGZH12KH08X39` | `crypto-integrated-implementation/shibboleth/browser_sso_idp` |
| browser_sso_idp († listed supplemental cases only) | shibboleth | `run_Q6KXSR2FM4MPTWZFCBAFQNQ18P` | `literal-integrated-implementation/shibboleth/browser_sso_idp` |
| browser_sso_idp († listed supplemental cases only) | shibboleth | `run_W01Y7Z2TC4N0BH3PBQZGD2RFBE` | `queue-integrated-implementation/shibboleth/browser_sso_idp` |
| browser_sso_idp († listed supplemental cases only) | shibboleth | `run_YVEJ7H1J1K1161V8GY4WM3NSXF` | `integrated-implementation/shibboleth/polling-bssso` |
| browser_sso_idp († listed supplemental cases only) | shibboleth | `run_7ZBVHFJ7RNAT5EDQ16NKM2H5K6` | `build/acceptance/reference-20260915/algorithm-observation-batch/shibboleth/browser_sso_idp` |
| browser_sso_idp († listed supplemental cases only) | shibboleth | `run_7ZBVHFJ7RNAT5EDQ16NKM2H5K6` | `build/acceptance/reference-20260915/algorithm-observation-batch/shibboleth/browser_sso_idp` |
| browser_sso_idp († listed supplemental cases only) | shibboleth | `run_77C08BXJSBJFG7E1G87QJ9YK6Q` | `build/acceptance/reference-20261001/shibboleth-g02-known-subject-v181-r1/reader-v181-predeployment/evaluation-terminal-http-v1` |
| browser_sso_idp († listed supplemental cases only) | shibboleth | `run_CMTJ8G2DXBWJC07QW9EBT3QA2E` | `build/acceptance/reference-20260930/shibboleth-g03-v130` |
| browser_sso_idp († listed supplemental cases only) | shibboleth | `run_7ZBVHFJ7RNAT5EDQ16NKM2H5K6` | `build/acceptance/reference-20260915/algorithm-observation-batch/shibboleth/browser_sso_idp` |
| browser_sso_idp († listed supplemental cases only) | shibboleth | `run_7ZBVHFJ7RNAT5EDQ16NKM2H5K6` | `build/acceptance/reference-20260915/algorithm-observation-batch/shibboleth/browser_sso_idp` |
| browser_sso_idp († listed supplemental cases only) | shibboleth | `run_7ZBVHFJ7RNAT5EDQ16NKM2H5K6` | `build/acceptance/reference-20260915/algorithm-observation-batch/shibboleth/browser_sso_idp` |
| browser_sso_idp († listed supplemental cases only) | shibboleth | `run_B7216J6NG10P449KERTB9WWV2T` | `build/acceptance/reference-20260930/shibboleth-identity-v170-r3/browser/evaluation-terminal-http-v1` |
| browser_sso_idp († listed supplemental cases only) | shibboleth | `run_0M6900RHXJTXKMMGJQGKAQXTRF` | `build/acceptance/reference-20260930/terminal-http-shibboleth-v151b/evaluation-terminal-http-v1` |
| browser_sso_idp († listed supplemental cases only) | shibboleth | `run_4RK6H7SCP540PGAAVVPRPP5YKZ` | `build/acceptance/reference-20261003/shibboleth-registered-signer-r1/evaluation-actual` |
| browser_sso_idp († listed supplemental cases only) | shibboleth | `run_0M6900RHXJTXKMMGJQGKAQXTRF` | `build/acceptance/reference-20260930/terminal-http-shibboleth-v151b/evaluation-terminal-http-v1` |
| browser_sso_idp († listed supplemental cases only) | shibboleth | `run_19E1TEPRGWZZACWS0BWFMHNFJH` | `build/acceptance/reference-20261001/shibboleth-transient-allow-create-v185-r1/reader-v186/evaluation-terminal-http-v1` |
| browser_sso_idp († listed supplemental cases only) | shibboleth | `run_CVMVSDGMG1ZT5K1T7F7CNCV5F5` | `build/acceptance/reference-20261001/shibboleth-subject-confirmation-v184-r4/reader-v185/evaluation-terminal-http-v1` |
| browser_sso_idp († listed supplemental cases only) | shibboleth | `run_FWMYG7PY9SWNNNMYQA39DS4B8D` | `build/acceptance/reference-20260918/shibboleth-authn-context-evaluation` |
| browser_sso_idp († listed supplemental cases only) | shibboleth | `run_FWMYG7PY9SWNNNMYQA39DS4B8D` | `build/acceptance/reference-20260918/shibboleth-authn-context-evaluation` |
| browser_sso_idp († listed supplemental cases only) | shibboleth | `run_FWMYG7PY9SWNNNMYQA39DS4B8D` | `build/acceptance/reference-20260918/shibboleth-authn-context-evaluation` |
| browser_sso_idp († listed supplemental cases only) | shibboleth | `run_CVMVSDGMG1ZT5K1T7F7CNCV5F5` | `build/acceptance/reference-20261001/shibboleth-subject-confirmation-v184-r4/reader-v185/evaluation-terminal-http-v1` |
| browser_sso_idp († listed supplemental cases only) | shibboleth | `run_FWMYG7PY9SWNNNMYQA39DS4B8D` | `build/acceptance/reference-20260918/shibboleth-authn-context-evaluation` |
| browser_sso_idp († listed supplemental cases only) | shibboleth | `run_VQ1J5M9J2XCT0GS0PXBBV3XZMY` | `build/acceptance/reference-20260918/shibboleth-signature-modes-v61/adoption` |
| browser_sso_idp († listed supplemental cases only) | shibboleth | `run_0DC6V5CZ0CM5G681HY8R3Y9RV9` | `build/acceptance/reference-20260930/shibboleth-persistent-pairwise-v165-r1/primary/evaluation-terminal-http-v1` |
| browser_sso_idp († listed supplemental cases only) | shibboleth | `run_0DC6V5CZ0CM5G681HY8R3Y9RV9` | `build/acceptance/reference-20260930/shibboleth-persistent-pairwise-v165-r1/primary/evaluation-terminal-http-v1` |
| browser_sso_idp († listed supplemental cases only) | shibboleth | `run_0DC6V5CZ0CM5G681HY8R3Y9RV9` | `build/acceptance/reference-20260930/shibboleth-persistent-pairwise-v165-r1/primary/evaluation-terminal-http-v1` |
| browser_sso_idp († listed supplemental cases only) | shibboleth | `run_77C08BXJSBJFG7E1G87QJ9YK6Q` | `build/acceptance/reference-20261001/shibboleth-g02-known-subject-v181-r1/subject-match-reader-v183/evaluation-terminal-http-v1` |
| browser_sso_idp († listed supplemental cases only) | shibboleth | `run_9WWCQTJR1M2ACYNYZ57HPYY48E` | `build/acceptance/reference-20260930/ext01b-shibboleth-v155/browser_sso_idp/evaluation-terminal-http-v1` |
| browser_sso_idp († listed supplemental cases only) | shibboleth | `run_AH3YZDK6HEGQPYHZA5DT23SK5E` | `build/acceptance/reference-20260930/ext01c-shibboleth-v158/browser_sso_idp/metadata/evaluation-terminal-http-v1` |
| browser_sso_idp († listed supplemental cases only) | shibboleth | `run_ZZKWFCJAMM46A877423CM5XP9E` | `build/acceptance/reference-20260918/shibboleth-ecdsa-native-audit/browser_sso_idp/evaluation` |
| browser_sso_idp († listed supplemental cases only) | shibboleth | `run_7ZBVHFJ7RNAT5EDQ16NKM2H5K6` | `build/acceptance/reference-20260915/algorithm-observation-batch/shibboleth/browser_sso_idp` |
| browser_sso_idp († listed supplemental cases only) | shibboleth | `run_0TMTHFWK5HEM14WFNJ10RD5D1X` | `build/acceptance/reference-20260918/shibboleth-producer-evaluation` |
| browser_sso_idp († listed supplemental cases only) | shibboleth | `run_7ZBVHFJ7RNAT5EDQ16NKM2H5K6` | `build/acceptance/reference-20260915/algorithm-observation-batch/shibboleth/browser_sso_idp` |
| browser_sso_idp († listed supplemental cases only) | shibboleth | `run_0TMTHFWK5HEM14WFNJ10RD5D1X` | `build/acceptance/reference-20260918/shibboleth-producer-evaluation` |
| browser_sso_idp († listed supplemental cases only) | shibboleth | `run_0TMTHFWK5HEM14WFNJ10RD5D1X` | `build/acceptance/reference-20260918/shibboleth-producer-evaluation` |
| browser_sso_idp († listed supplemental cases only) | shibboleth | `run_7ZBVHFJ7RNAT5EDQ16NKM2H5K6` | `build/acceptance/reference-20260915/algorithm-observation-batch/shibboleth/browser_sso_idp` |
| browser_sso_idp († listed supplemental cases only) | shibboleth | `run_Z1TGHQBNQRJNXRQ5VF7QB1F7QM` | `build/acceptance/reference-20260930/shibboleth-alg08-aes-v161` |
| browser_sso_idp († listed supplemental cases only) | shibboleth | `run_Z1TGHQBNQRJNXRQ5VF7QB1F7QM` | `build/acceptance/reference-20260930/shibboleth-alg08-aes-v161` |
| browser_sso_idp († listed supplemental cases only) | shibboleth | `run_K56H9VMXYGKZS1117Y0V66AHYQ` | `build/acceptance/reference-20261004/shibboleth-default-algorithm-r7/reader-v217/formal` |
| browser_sso_idp († listed supplemental cases only) | shibboleth | `run_8S5P9BVTX8CCQ770M2KHKXG5CM` | `build/acceptance/reference-20260918/shibboleth-attribute-name-capability-registry` |
| browser_sso_idp († listed supplemental cases only) | shibboleth | `run_Z43RFP9ZF0175WP18Y1FZD70P9` | `build/acceptance/reference-20260918/shibboleth-relying-party-attribute-evaluation` |
| browser_sso_idp († listed supplemental cases only) | shibboleth | `run_C97YCPR7F5KNWRMCMHWNPQ11N9` | `build/acceptance/reference-20260918/shibboleth-attribute-policy-evaluation` |
| browser_sso_idp († listed supplemental cases only) | shibboleth | `run_C97YCPR7F5KNWRMCMHWNPQ11N9` | `build/acceptance/reference-20260918/shibboleth-attribute-policy-evaluation` |
| browser_sso_idp († listed supplemental cases only) | shibboleth | `run_C97YCPR7F5KNWRMCMHWNPQ11N9` | `build/acceptance/reference-20260918/shibboleth-attribute-policy-evaluation` |
| browser_sso_idp († listed supplemental cases only) | shibboleth | `run_MC6DQMEQKWPQ66PPBEY45M5R36` | `build/acceptance/reference-20260918/shibboleth-browser-chain-v73` |
| browser_sso_idp († listed supplemental cases only) | shibboleth | `run_B7216J6NG10P449KERTB9WWV2T` | `build/acceptance/reference-20261001/shibboleth-forceauthn-mechanism-v186-r1/reader-v188/evaluation-terminal-http-v1` |
| browser_sso_idp († listed supplemental cases only) | shibboleth | `run_TY7ZVP2SPK02TT7TBC2TTZBPB7` | `build/acceptance/reference-20261002/shibboleth-authn-exact-r1/browser/evaluation-terminal-http-v1` |
| browser_sso_idp († listed supplemental cases only) | shibboleth | `run_J7YRDB4T4J8FXKSRXG4K7ZNJ3Q` | `build/acceptance/reference-20260918/shibboleth-nameid-omission-evaluation` |
| browser_sso_idp († listed supplemental cases only) | shibboleth | `run_2DDHMXNQ7J9HCAB19F8ZPVAPPZ` | `build/acceptance/reference-20260930/idp12bd-shibboleth-v150` |
| browser_sso_idp († listed supplemental cases only) | shibboleth | `run_YVEJ7H1J1K1161V8GY4WM3NSXF` | `build/acceptance/reference-20260914/integrated-implementation/shibboleth/polling-bssso` |
| browser_sso_idp († listed supplemental cases only) | shibboleth | `run_C51HJ7F92AH6C2HG33JKBHWHCG` | `build/acceptance/reference-20260918/shibboleth-native-signed-request-v2/browser_sso_idp/evaluation` |
| browser_sso_idp († listed supplemental cases only) | shibboleth | `run_C51HJ7F92AH6C2HG33JKBHWHCG` | `build/acceptance/reference-20260918/shibboleth-native-signed-request-v2/browser_sso_idp/evaluation` |
| browser_sso_idp († listed supplemental cases only) | shibboleth | `run_B7216J6NG10P449KERTB9WWV2T` | `build/acceptance/reference-20261001/shibboleth-post-error-binding-v179/evaluation-terminal-http-v1` |
| browser_sso_idp | shibboleth | `run_JGADJKCN6GBGKJ68D1WP0G3GMX` | `interaction-followup/after/shibboleth/browser_sso_idp` |
| browser_sso_idp († listed supplemental cases only) | simplesamlphp | `run_TS5JTACXSDMGB9PE8Z9ZS2MP5K` | `additional-implementation/simplesamlphp/browser_sso_idp` |
| browser_sso_idp († listed supplemental cases only) | simplesamlphp | `run_XA01CQ82M03JJQ5JNECA47XFFQ` | `crypto-integrated-implementation/simplesamlphp/browser_sso_idp` |
| browser_sso_idp († listed supplemental cases only) | simplesamlphp | `run_KXN09QNRGAKBGY31S8AHJZKHNA` | `literal-integrated-implementation/simplesamlphp/browser_sso_idp` |
| browser_sso_idp († listed supplemental cases only) | simplesamlphp | `run_J7Z6YANJCXYTHVJXX820D4NNPY` | `queue-integrated-implementation/simplesamlphp/browser_sso_idp` |
| browser_sso_idp († listed supplemental cases only) | simplesamlphp | `run_K811HY2DMZWV52HTT82251AVFZ` | `build/acceptance/reference-20260915/algorithm-observation-batch/simplesamlphp/browser_sso_idp` |
| browser_sso_idp († listed supplemental cases only) | simplesamlphp | `run_VRW5T0M31JGT71ZG6MR1JF92PJ` | `build/acceptance/reference-20260915/peer-intent/simplesamlphp/browser_alg_enc` |
| browser_sso_idp († listed supplemental cases only) | simplesamlphp | `run_2HC9SHR4PRST13WH08VNRCRZXR` | `build/acceptance/reference-20260929/browser-chain-ssp-g02-v116` |
| browser_sso_idp († listed supplemental cases only) | simplesamlphp | `run_2VQYH1JSEQSH0K2WQZ425MGS5D` | `build/acceptance/reference-20260930/ssp-g03-v129` |
| browser_sso_idp († listed supplemental cases only) | simplesamlphp | `run_MZ074RSFSCH0SHHZJ3QZJS3Y61` | `build/acceptance/reference-20260930/terminal-http-ssp-v151/evaluation-terminal-http-v1` |
| browser_sso_idp († listed supplemental cases only) | simplesamlphp | `run_DQBEG87V5F2GDW83JXDW40STPV` | `build/acceptance/reference-20260918/ssp-browser-chain-v2` |
| browser_sso_idp († listed supplemental cases only) | simplesamlphp | `run_DQBEG87V5F2GDW83JXDW40STPV` | `build/acceptance/reference-20260918/ssp-browser-chain-v2` |
| browser_sso_idp († listed supplemental cases only) | simplesamlphp | `run_7ZHAZEFYR3SQ2ZF1H93M5BYVWH` | `build/acceptance/reference-20261001/ssp-authentication-identity-v187-r1/evaluation` |
| browser_sso_idp († listed supplemental cases only) | simplesamlphp | `run_MZ074RSFSCH0SHHZJ3QZJS3Y61` | `build/acceptance/reference-20260930/terminal-http-ssp-v151/evaluation-terminal-http-v1` |
| browser_sso_idp († listed supplemental cases only) | simplesamlphp | `run_P0KQBXB1WE72FG0GP91FV4FSC8` | `build/acceptance/reference-20261002/simplesamlphp-registered-signer-r3/evaluation-actual` |
| browser_sso_idp († listed supplemental cases only) | simplesamlphp | `run_A8PH28JMJZYRD6KMJDJS5FG22B` | `build/acceptance/reference-20260918/simplesamlphp-browser-chain-v68` |
| browser_sso_idp († listed supplemental cases only) | simplesamlphp | `run_KE84Y9K3YPETNPD2WR3F4C694N` | `build/acceptance/reference-20261001/ssp-native-subject-principal-v168-r1/evaluation` |
| browser_sso_idp († listed supplemental cases only) | simplesamlphp | `run_MZ074RSFSCH0SHHZJ3QZJS3Y61` | `build/acceptance/reference-20260930/terminal-http-ssp-v151/evaluation-terminal-http-v1` |
| browser_sso_idp († listed supplemental cases only) | simplesamlphp | `run_06ZZ1WXNBV0BNEZJKHPPHN6AEB` | `build/acceptance/reference-20261004/simplesamlphp-version-mismatch-r2/evaluation-actual` |
| browser_sso_idp († listed supplemental cases only) | simplesamlphp | `run_A1ETYRSEPB9Q2M0TW9X90SHE06` | `build/acceptance/reference-20261001/ssp-transient-allow-create-v183-r1/evaluation` |
| browser_sso_idp († listed supplemental cases only) | simplesamlphp | `run_DNSXEDH66T55QVSQWMZVQZ4K1G` | `build/acceptance/reference-20261001/ssp-subject-confirmation-native-v178-r1/evaluation` |
| browser_sso_idp († listed supplemental cases only) | simplesamlphp | `run_DNSXEDH66T55QVSQWMZVQZ4K1G` | `build/acceptance/reference-20261001/ssp-subject-confirmation-native-v178-r1/evaluation` |
| browser_sso_idp († listed supplemental cases only) | simplesamlphp | `run_A8PH28JMJZYRD6KMJDJS5FG22B` | `build/acceptance/reference-20260918/simplesamlphp-browser-chain-v68` |
| browser_sso_idp († listed supplemental cases only) | simplesamlphp | `run_DQBEG87V5F2GDW83JXDW40STPV` | `build/acceptance/reference-20260930/post-error-binding-simplesamlphp-v173/evaluation` |
| browser_sso_idp († listed supplemental cases only) | simplesamlphp | `run_W9WFP7QB19V0Y15T0QVE7D8RHW` | `build/acceptance/reference-20260918/simplesamlphp-signature-modes-v61/adoption` |
| browser_sso_idp († listed supplemental cases only) | simplesamlphp | `run_T1KNFTYX3KNM9NX1PK0WQXP8MW` | `build/acceptance/reference-20260930/ssp-native-persistent-normal-v165-r6/browser_sso_idp` |
| browser_sso_idp († listed supplemental cases only) | simplesamlphp | `run_Z1JSR2SNB3CS7R1XHEB8MJCP7H` | `build/acceptance/reference-20261001/ssp-native-persistent-pairwise-v166-r3/evaluation` |
| browser_sso_idp († listed supplemental cases only) | simplesamlphp | `run_XA01CQ82M03JJQ5JNECA47XFFQ` | `build/acceptance/reference-20260914/crypto-integrated-implementation/simplesamlphp/browser_sso_idp` |
| browser_sso_idp († listed supplemental cases only) | simplesamlphp | `run_8W6B711ANVWTPPZSS0K05PBX1M` | `build/acceptance/reference-20260930/ext01b-simplesamlphp-v158/browser_sso_idp/evaluation-terminal-http-v1` |
| browser_sso_idp († listed supplemental cases only) | simplesamlphp | `run_TC481X3D92H47146REC8ZR44EH` | `build/acceptance/reference-20260930/ssp-native-ec-v133/browser_sso_idp/evaluation-v133` |
| browser_sso_idp († listed supplemental cases only) | simplesamlphp | `run_00MKHH590BSDDG411ST76J02AD` | `build/acceptance/reference-20260918/simplesamlphp-shared-gcm128` |
| browser_sso_idp († listed supplemental cases only) | simplesamlphp | `run_30QS0MMCHGS3Q02VGHJ5VYEP9J` | `build/acceptance/reference-20260918/simplesamlphp-shared-gcm256` |
| browser_sso_idp († listed supplemental cases only) | simplesamlphp | `run_VRW5T0M31JGT71ZG6MR1JF92PJ` | `build/acceptance/reference-20260915/peer-intent/simplesamlphp/browser_alg_enc` |
| browser_sso_idp († listed supplemental cases only) | simplesamlphp | `run_K811HY2DMZWV52HTT82251AVFZ` | `build/acceptance/reference-20260915/algorithm-observation-batch/simplesamlphp/browser_sso_idp` |
| browser_sso_idp († listed supplemental cases only) | simplesamlphp | `run_K811HY2DMZWV52HTT82251AVFZ` | `build/acceptance/reference-20260915/algorithm-observation-batch/simplesamlphp/browser_sso_idp` |
| browser_sso_idp († listed supplemental cases only) | simplesamlphp | `run_K811HY2DMZWV52HTT82251AVFZ` | `build/acceptance/reference-20260915/algorithm-observation-batch/simplesamlphp/browser_sso_idp` |
| browser_sso_idp († listed supplemental cases only) | simplesamlphp | `run_4GWY98RD670EAFJ3R8Q6V2MW52` | `build/acceptance/reference-20260918/simplesamlphp-attribute-name-capability` |
| browser_sso_idp († listed supplemental cases only) | simplesamlphp | `run_WNMZ106QK6JKRN8P6JFZQ0KNWG` | `build/acceptance/reference-20260918/simplesamlphp-relying-party-attribute-evaluation` |
| browser_sso_idp († listed supplemental cases only) | simplesamlphp | `run_0F3AC58K1P1MJGQJ1Q0BDVPR6M` | `build/acceptance/reference-20260930/simplesamlphp-attribute-policy-evaluation-v153` |
| browser_sso_idp († listed supplemental cases only) | simplesamlphp | `run_0F3AC58K1P1MJGQJ1Q0BDVPR6M` | `build/acceptance/reference-20260930/simplesamlphp-attribute-policy-evaluation-v153` |
| browser_sso_idp († listed supplemental cases only) | simplesamlphp | `run_69SHRHN3H4F7DJYZCFB42YGKVK` | `build/acceptance/reference-20261001/ssp-attribute-service-index-v184-r1/evaluation` |
| browser_sso_idp († listed supplemental cases only) | simplesamlphp | `run_KXN09QNRGAKBGY31S8AHJZKHNA` | `build/acceptance/reference-20260914/literal-integrated-implementation/simplesamlphp/browser_sso_idp` |
| browser_sso_idp († listed supplemental cases only) | simplesamlphp | `run_VRW5T0M31JGT71ZG6MR1JF92PJ` | `build/acceptance/reference-20260915/peer-intent/simplesamlphp/browser_alg_enc` |
| browser_sso_idp († listed supplemental cases only) | simplesamlphp | `run_XKNHNHTS27D8V15RGGVWPPNWX4` | `build/acceptance/reference-20260918/simplesamlphp-default-acs` |
| browser_sso_idp († listed supplemental cases only) | simplesamlphp | `run_BAYBZ159BPMKKVXCQWESKDGFAQ` | `build/acceptance/reference-20260918/simplesamlphp-native-signature-observation-v2/browser_sso_idp/evaluation` |
| browser_sso_idp († listed supplemental cases only) | simplesamlphp | `run_BAYBZ159BPMKKVXCQWESKDGFAQ` | `build/acceptance/reference-20260918/simplesamlphp-native-signature-observation-v2/browser_sso_idp/evaluation` |
| browser_sso_idp († listed supplemental cases only) | simplesamlphp | `run_TN5M4DR92CBYYSVVDTWZ48NVDV` | `build/acceptance/reference-20261004/ssp-forceauthn-mechanism-r3/evaluation` |
| browser_sso_idp († listed supplemental cases only) | simplesamlphp | `run_J7Z6YANJCXYTHVJXX820D4NNPY` | `build/acceptance/reference-20260914/queue-integrated-implementation/simplesamlphp/browser_sso_idp` |
| browser_sso_idp | simplesamlphp | `run_SJWWBQT1S24VSJGRZMSQ8TJYM4` | `interaction-followup/after/simplesamlphp/browser_sso_idp` |
| metadata_idp († listed supplemental cases only) | keycloak | `run_HRAC88P0KKA5WQX8MF75WD198X` | `additional-implementation/keycloak/metadata_idp` |
| metadata_idp († listed supplemental cases only) | keycloak | `run_CVF559MZJPR15Y499GZ76NFT18` | `build/acceptance/reference-20260930/keycloak-md01-native-url-v158-r7/evaluation` |
| metadata_idp († listed supplemental cases only) | keycloak | `run_YA47R73Z5BYNTC6AANT6SMJZCT` | `build/acceptance/reference-20260930/keycloak-md02-native-refresh-v158-r3/evaluation` |
| metadata_idp († listed supplemental cases only) | keycloak | `run_1TV53ZGRM98QM45SA90PSGA3QC` | `build/acceptance/reference-20260918/keycloak-md02b-v110` |
| metadata_idp († listed supplemental cases only) | keycloak | `run_J7HCGRMNJHC614BA103CNGMVZ5` | `build/acceptance/reference-20260917/keycloak-signature-control-3` |
| metadata_idp († listed supplemental cases only) | keycloak | `run_AWN1AQGHPZ0W0DMSZRTY07M5BW` | `build/acceptance/reference-20260930/keycloak-md03-signature-capability-v160` |
| metadata_idp († listed supplemental cases only) | keycloak | `run_AWN1AQGHPZ0W0DMSZRTY07M5BW` | `build/acceptance/reference-20260930/keycloak-md03-signature-capability-v160` |
| metadata_idp († listed supplemental cases only) | keycloak | `run_AWN1AQGHPZ0W0DMSZRTY07M5BW` | `build/acceptance/reference-20260930/keycloak-md03-signature-capability-v160` |
| metadata_idp († listed supplemental cases only) | keycloak | `run_Z0RC3P1PWXJFG4T4736TMBS6FV` | `build/acceptance/reference-20260930/keycloak-metadata-source-capability-absence-v158` |
| metadata_idp († listed supplemental cases only) | keycloak | `run_MNJ7HF037KJKSPXPM899S9EYSR` | `build/acceptance/reference-20260930/keycloak-validity-capability-v158` |
| metadata_idp († listed supplemental cases only) | keycloak | `run_MNJ7HF037KJKSPXPM899S9EYSR` | `build/acceptance/reference-20260930/keycloak-validity-capability-v158` |
| metadata_idp († listed supplemental cases only) | keycloak | `run_0FTCNNW469F5SD19BR6GT4EAAG` | `build/acceptance/reference-20260930/keycloak-validity-capability-v158/md04c-capability-conclusion-v1` |
| metadata_idp († listed supplemental cases only) | keycloak | `run_Y3QFVC9TC07YYDRBFR08AN3C3G` | `build/acceptance/reference-20261002/keycloak-metadata-entity-identity-r1/evaluation-v194` |
| metadata_idp († listed supplemental cases only) | keycloak | `run_Y3QFVC9TC07YYDRBFR08AN3C3G` | `build/acceptance/reference-20261002/keycloak-metadata-entity-identity-r1/evaluation-v194` |
| metadata_idp († listed supplemental cases only) | keycloak | `run_J7HCGRMNJHC614BA103CNGMVZ5` | `build/acceptance/reference-20260917/keycloak-signature-control-3` |
| metadata_idp († listed supplemental cases only) | keycloak | `run_J7HCGRMNJHC614BA103CNGMVZ5` | `build/acceptance/reference-20260917/keycloak-signature-control-3` |
| metadata_idp († listed supplemental cases only) | keycloak | `run_35NM1CKB4HMDVRG01X6NSXVQN7` | `build/acceptance/reference-20260930/keycloak-native-key-policy-v165-r3/observations/metadata_idp/evaluation` |
| metadata_idp († listed supplemental cases only) | keycloak | `run_J5EY454Z5ZD3J7Q89SWCFNJNHD` | `build/acceptance/reference-20260918/single-signing-key/keycloak` |
| metadata_idp († listed supplemental cases only) | keycloak | `run_E6QM9P3HYKM1Q40MQ1NQHS69W6` | `build/acceptance/reference-20260930/publisher-keycloak-v120/evaluation` |
| metadata_idp († listed supplemental cases only) | keycloak | `run_GF71YH0KWBTXP4ZM8C1TFEG7CS` | `build/acceptance/reference-20260930/keycloak-rsa-sha1-metadata-v152` |
| metadata_idp († listed supplemental cases only) | keycloak | `run_MNJ7HF037KJKSPXPM899S9EYSR` | `build/acceptance/reference-20260930/keycloak-validity-capability-v158` |
| metadata_idp († listed supplemental cases only) | keycloak | `run_HX2ZP96JPC1NN5XNPH1FEFZ9GG` | `build/acceptance/reference-20260930/keycloak-default-acs-v139/evaluation-v139` |
| metadata_idp († listed supplemental cases only) | keycloak | `run_ZDVRESFDXKV24NE5S29M2P5NVN` | `build/acceptance/reference-20261001/keycloak-native-schema-admission-v183-r1/evaluation` |
| metadata_idp († listed supplemental cases only) | keycloak | `run_5PS5A09N019JCV0BT8DQRMNZNN` | `build/acceptance/reference-20260930/keycloak-mdiop-representation-native-v171-r5/evaluation` |
| metadata_idp († listed supplemental cases only) | keycloak | `run_35NM1CKB4HMDVRG01X6NSXVQN7` | `build/acceptance/reference-20260930/keycloak-native-key-policy-v165-r3/observations/metadata_idp/evaluation` |
| metadata_idp († listed supplemental cases only) | keycloak | `run_CW996EM45SYJPJF4VGT54ZKTDA` | `build/acceptance/reference-20260918/keycloak-md05d-v104` |
| metadata_idp († listed supplemental cases only) | keycloak | `run_9HE4ZZB92JHW6ZP10K44K5X7BD` | `build/acceptance/reference-20260918/keycloak-md05e-v106` |
| metadata_idp († listed supplemental cases only) | keycloak | `run_SMA5VXA5EDP001PKPR37ZR2893` | `build/acceptance/reference-20260918/algorithm-followup/keycloak` |
| metadata_idp († listed supplemental cases only) | keycloak | `run_9VMW5N633947P63NVBARN5T2EG` | `build/acceptance/reference-20260930/keycloak-intersection-capability-sha512-v167/evaluation` |
| metadata_idp († listed supplemental cases only) | keycloak | `run_SMA5VXA5EDP001PKPR37ZR2893` | `build/acceptance/reference-20260918/algorithm-followup/keycloak` |
| metadata_idp († listed supplemental cases only) | keycloak | `run_SMA5VXA5EDP001PKPR37ZR2893` | `build/acceptance/reference-20260918/keycloak-algorithm-evaluation` |
| metadata_idp († listed supplemental cases only) | keycloak | `run_SMA5VXA5EDP001PKPR37ZR2893` | `build/acceptance/reference-20260918/keycloak-algorithm-evaluation` |
| metadata_idp († listed supplemental cases only) | keycloak | `run_J107HRR1BXY7GHBHTDDMY87308` | `build/acceptance/reference-20260918/publisher-ui-scoped/keycloak` |
| metadata_idp († listed supplemental cases only) | keycloak | `run_J107HRR1BXY7GHBHTDDMY87308` | `build/acceptance/reference-20260918/publisher-ui-scoped/keycloak` |
| metadata_idp († listed supplemental cases only) | keycloak | `run_82S5JH8MMJD83SPDNM6HSRTGEC` | `build/acceptance/reference-20261001/keycloak-native-ui-consumer-v178-r1/evaluation` |
| metadata_idp († listed supplemental cases only) | keycloak | `run_J107HRR1BXY7GHBHTDDMY87308` | `build/acceptance/reference-20260918/publisher-ui-scoped/keycloak` |
| metadata_idp († listed supplemental cases only) | keycloak | `run_6DYMRF586HQ41JC6HZZVBTHCG8` | `build/acceptance/reference-20260930/keycloak-ui-feature-absence-v155` |
| metadata_idp († listed supplemental cases only) | keycloak | `run_60VNZAT8Y5SMSS0HVRYWXAJ947` | `build/acceptance/reference-20260918/keycloak-md05ff-v99` |
| metadata_idp († listed supplemental cases only) | keycloak | `run_XH5YWJR5S0FX6CTTHFB3990WE1` | `build/acceptance/reference-20261003/keycloak-ui-safety-r1/evaluation-v204` |
| metadata_idp († listed supplemental cases only) | keycloak | `run_82S5JH8MMJD83SPDNM6HSRTGEC` | `build/acceptance/reference-20261001/keycloak-native-ui-consumer-v178-r1/evaluation` |
| metadata_idp († listed supplemental cases only) | keycloak | `run_HRAC88P0KKA5WQX8MF75WD198X` | `build/acceptance/reference-20260914/additional-implementation/keycloak/metadata_idp` |
| metadata_idp († listed supplemental cases only) | keycloak | `run_6DYMRF586HQ41JC6HZZVBTHCG8` | `build/acceptance/reference-20260930/keycloak-ui-feature-absence-v155` |
| metadata_idp († listed supplemental cases only) | keycloak | `run_J7HCGRMNJHC614BA103CNGMVZ5` | `build/acceptance/reference-20260917/keycloak-signature-control-3` |
| metadata_idp († listed supplemental cases only) | keycloak | `run_SKGSQ8QRTQV0ZH40K0VBFKMDWY` | `build/acceptance/reference-20261001/keycloak-native-supersession-v177-r3/evaluation` |
| metadata_idp († listed supplemental cases only) | keycloak | `run_35NM1CKB4HMDVRG01X6NSXVQN7` | `build/acceptance/reference-20260930/keycloak-native-key-policy-v165-r3/observations/metadata_idp/evaluation` |
| metadata_idp († listed supplemental cases only) | keycloak | `run_35NM1CKB4HMDVRG01X6NSXVQN7` | `build/acceptance/reference-20260930/keycloak-native-key-policy-v165-r3/observations/metadata_idp/evaluation` |
| metadata_idp († listed supplemental cases only) | keycloak | `run_35NM1CKB4HMDVRG01X6NSXVQN7` | `build/acceptance/reference-20260930/keycloak-native-key-policy-v165-r3/observations/metadata_idp/evaluation` |
| metadata_idp († listed supplemental cases only) | keycloak | `run_DVZK14WN1W3E0SZ393MHQD42SJ` | `build/acceptance/reference-20260918/keycloak-native-key-selection-v65/observations/metadata_idp/evaluation` |
| metadata_idp († listed supplemental cases only) | keycloak | `run_AX3ZB21BWSJM8S2HMPXRD8N7K6` | `build/acceptance/reference-20260918/keycloak-native-certificate-signature/observations/metadata_idp/evaluation-v64` |
| metadata_idp († listed supplemental cases only) | keycloak | `run_SKGSQ8QRTQV0ZH40K0VBFKMDWY` | `build/acceptance/reference-20261001/keycloak-native-supersession-counterexample-v187-r1/evaluation` |
| metadata_idp († listed supplemental cases only) | keycloak | `run_Z0RC3P1PWXJFG4T4736TMBS6FV` | `build/acceptance/reference-20260930/keycloak-metadata-source-capability-absence-v158` |
| metadata_idp († listed supplemental cases only) | keycloak | `run_SKGSQ8QRTQV0ZH40K0VBFKMDWY` | `build/acceptance/reference-20261001/keycloak-native-self-contained-trust-v178-r1/evaluation-v179` |
| metadata_idp († listed supplemental cases only) | keycloak | `run_DVZK14WN1W3E0SZ393MHQD42SJ` | `build/acceptance/reference-20260918/keycloak-native-key-selection-v65/observations/metadata_idp/evaluation` |
| metadata_idp († listed supplemental cases only) | keycloak | `run_J7HCGRMNJHC614BA103CNGMVZ5` | `build/acceptance/reference-20260917/keycloak-signature-control-3` |
| metadata_idp († listed supplemental cases only) | keycloak | `run_AX3ZB21BWSJM8S2HMPXRD8N7K6` | `build/acceptance/reference-20260918/keycloak-native-certificate-signature/observations/metadata_idp/evaluation` |
| metadata_idp († listed supplemental cases only) | keycloak | `run_J7HCGRMNJHC614BA103CNGMVZ5` | `build/acceptance/reference-20260917/keycloak-signature-control-3` |
| metadata_idp († listed supplemental cases only) | keycloak | `run_AX3ZB21BWSJM8S2HMPXRD8N7K6` | `build/acceptance/reference-20260918/keycloak-native-certificate-signature/observations/metadata_idp/evaluation` |
| metadata_idp († listed supplemental cases only) | keycloak | `run_MT4QSB65RGQRC6MZKXF15KCJMS` | `build/acceptance/reference-20260930/ext01b-keycloak-v158/metadata_idp/evaluation-terminal-http-v1` |
| metadata_idp († listed supplemental cases only) | keycloak | `run_FB6GSNKXQRGTFC36605PEA7GC0` | `build/acceptance/reference-20261004/keycloak-extension-attribute-parser-r2/evaluation-v230/metadata_idp` |
| metadata_idp († listed supplemental cases only) | keycloak | `run_YN5FBG6NPMGQZ5VYKEEHFSF6ZR` | `build/acceptance/reference-20260918/keycloak-native-signature-audit/metadata_idp/evaluation` |
| metadata_idp († listed supplemental cases only) | keycloak | `run_YN5FBG6NPMGQZ5VYKEEHFSF6ZR` | `build/acceptance/reference-20260918/keycloak-native-signature-audit/metadata_idp/evaluation` |
| metadata_idp († listed supplemental cases only) | keycloak | `run_ASRA03EB5GQ074VCME7HESPZ6G` | `build/acceptance/reference-20260918/keycloak-native-ec-signature-v3/observations/metadata_idp/evaluation` |
| metadata_idp | keycloak | `run_HEGZFSAG1WFGFCXX1XE6N1C52B` | `keycloak/metadata_idp/run2` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_WPY618QSZEMJKGGQ6W1ZZ5YWZ6` | `additional-implementation/shibboleth/metadata_idp` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_296ZHGM9XYDBAXHE3CP2XC3MC7` | `integrated-implementation/shibboleth/polling` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_2442PWPHNVJ2QDXD1TFVB1XMJ4` | `build/acceptance/reference-20260930/shibboleth-dynamic-mdq-v8/evaluation` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_6EZ54PE9MBPH0C78MC6VPQV5SV` | `build/acceptance/reference-20260930/shibboleth-native-refresh-v164-r1/evaluation-terminal-http-v1` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_N7X58HSBHWGGP8FRZFVYKNKN2F` | `build/acceptance/reference-20260918/shibboleth-md03-signature-v78/evaluation` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_29FRDNMD9ET5C0F9Z336Q6SFEH` | `build/acceptance/reference-20260918/shibboleth-md03b-signature-v78b` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_FFD6R6CVAPGKW17HESMFM1A68E` | `build/acceptance/reference-20260930/md03d-shibboleth-v158` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_YW7XT8SYF0K69PK3QN8GAH1GHF` | `build/acceptance/reference-20260918/shibboleth-md04a-required-validuntil-v84/evaluation` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_7CZRNH7GGYQ137ZEDB23X3T16R` | `build/acceptance/reference-20260918/shibboleth-md05as-rejection-v77/evaluation` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_KX65MPT7ZXPTDYZ5HMNXBQ6MZ5` | `build/acceptance/reference-20260918/shibboleth-md04c-boundary-v84/evaluation` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_0ENQCX5J2EN57TDX23AZ82Q6AF` | `build/acceptance/reference-20261001/shibboleth-entityid-uniqueness-v180-r1/reader-v181/evaluation-terminal-http-v1` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_EQ37Y4AX9F7H8KR0KRMPF069DP` | `build/acceptance/reference-20260918/shibboleth-md05-a1a2-v76/evaluation` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_296ZHGM9XYDBAXHE3CP2XC3MC7` | `build/acceptance/reference-20260914/integrated-implementation/shibboleth/polling` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_2893MAJ9X84M3TVFWRNY5CAPK4` | `build/acceptance/reference-20260918/single-signing-key/shibboleth` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_2442PWPHNVJ2QDXD1TFVB1XMJ4` | `build/acceptance/reference-20260930/publisher-shibboleth-v120b/evaluation` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_M53G1T57ZXF9Q0P2GEDHWPN0EA` | `build/acceptance/reference-20261001/shibboleth-rsa-sha1-metadata-v171-r5/evaluation` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_YXKGGJFH0SY9HR7Q519HT4RB4X` | `build/acceptance/reference-20260918/shibboleth-md05-consumer-sig-v81/evaluation-am` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_YXKGGJFH0SY9HR7Q519HT4RB4X` | `build/acceptance/reference-20260918/shibboleth-md05-consumer-sig-v81/evaluation` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_ZF0TJ2HDCN7C4SRCDDZAQPG860` | `build/acceptance/reference-20260918/shibboleth-md05-consumer-sig-v79` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_6KGY6JFP7CEAV5JNQ6NA3N4SGS` | `build/acceptance/reference-20260918/shibboleth-md05apaq-v111` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_6KGY6JFP7CEAV5JNQ6NA3N4SGS` | `build/acceptance/reference-20260918/shibboleth-md05apaq-v111` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_J43EG1E1PDSAGD7EXG3GYRNSHN` | `build/acceptance/reference-20261002/shibboleth-metadata-validity-r2/reader-v193/evaluation-terminal-http-v1` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_7CZRNH7GGYQ137ZEDB23X3T16R` | `build/acceptance/reference-20260918/shibboleth-md05as-rejection-v77/evaluation` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_VG6RYQ2RN6TMS2GMFVM1QHQJ36` | `build/acceptance/reference-20260930/shibboleth-default-acs-v138/evaluation-v138` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_P1KVNHQWPCRSGHZ8RN0ZXDQC3J` | `build/acceptance/reference-20260918/shibboleth-md05b-v110` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_J7GJGATXAXDTV916CXJN8RRK5Z` | `build/acceptance/reference-20260930/shibboleth-mdiop-full-v172-r2/evaluation-terminal-http-v1` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_MDNFTC368ZZ3FDCDAECD1SMSG4` | `build/acceptance/reference-20261004/shibboleth-publisher-endpoints-r3/evaluation-actual` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_MAS75FBV4PTEKZA2M1895RYPBS` | `build/acceptance/reference-20260918/shibboleth-md05c2-v105` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_WYXRSA1PEQ42W6KJ1X40697112` | `build/acceptance/reference-20260918/shibboleth-md05d-v104` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_SGXSMPF0H9GDB15P8JABPQQYEY` | `build/acceptance/reference-20260918/shibboleth-md05e-v106` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_XZ4CY23XHSV2NPFTDW2H0EVZCS` | `build/acceptance/reference-20260918/algorithm-followup/shibboleth` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_XG5TCTRKY859K6HKXVB7TT53E3` | `build/acceptance/reference-20260918/shibboleth-md05e7-order-v90` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_6E5BWBMYHJFZS31AKS9Q1WCP72` | `build/acceptance/reference-20260918/shibboleth-intersection-evaluation` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_XZ4CY23XHSV2NPFTDW2H0EVZCS` | `build/acceptance/reference-20260918/algorithm-followup/shibboleth` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_XZ4CY23XHSV2NPFTDW2H0EVZCS` | `build/acceptance/reference-20260918/shibboleth-algorithm-evaluation` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_XZ4CY23XHSV2NPFTDW2H0EVZCS` | `build/acceptance/reference-20260918/shibboleth-algorithm-evaluation` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_FSF0BPRS2Z5X9WD99AYCS7GZFM` | `build/acceptance/reference-20261003/shibboleth-full-ui-r2/evaluation-v206` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_G7RK00MQC0WZXS14JPFQPV8NKZ` | `build/acceptance/reference-20260918/publisher-ui-scoped/shibboleth` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_G7RK00MQC0WZXS14JPFQPV8NKZ` | `build/acceptance/reference-20260918/publisher-ui-scoped/shibboleth` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_GNBRVD9WSNFGHMXZEFN4BAH6NR` | `build/acceptance/reference-20260918/shibboleth-ui-logo-evaluation` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_G7RK00MQC0WZXS14JPFQPV8NKZ` | `build/acceptance/reference-20260918/publisher-ui-scoped/shibboleth` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_RR7HDP5GD9R7TMV8S1W7TCZSH8` | `build/acceptance/reference-20261001/shibboleth-native-ui-v176-r3/reader-v177/evaluation-terminal-http-v1` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_MJ4V11GPKFJZRTNAP8EPP3MASF` | `build/acceptance/reference-20260918/shibboleth-md05ff-v99` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_RR7HDP5GD9R7TMV8S1W7TCZSH8` | `build/acceptance/reference-20261001/shibboleth-native-ui-v176-r3/reader-v177/evaluation-terminal-http-v1` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_RR7HDP5GD9R7TMV8S1W7TCZSH8` | `build/acceptance/reference-20261001/shibboleth-native-ui-v176-r3/reader-v177/evaluation-terminal-http-v1` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_WPY618QSZEMJKGGQ6W1ZZ5YWZ6` | `build/acceptance/reference-20260914/additional-implementation/shibboleth/metadata_idp` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_RR7HDP5GD9R7TMV8S1W7TCZSH8` | `build/acceptance/reference-20261001/shibboleth-native-ui-v176-r3/reader-v177/evaluation-terminal-http-v1` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_JJPW4W8GACM9DT4PKH4CG0KWC7` | `build/acceptance/reference-20261003/shibboleth-metadata-application-qualified-r1/evaluation-v213` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_77SAYK1RNYTD9E3HPTS5FQ5Q09` | `build/acceptance/reference-20261002/shibboleth-role-keys-r1/reader-v195/evaluation-terminal-http-v1` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_2DMZGR4YBY1K2CHG4710SDP2BA` | `build/acceptance/reference-20260930/shibboleth-role-signing-http-v165-r1/refresh/evaluation-terminal-http-v1` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_296ZHGM9XYDBAXHE3CP2XC3MC7` | `build/acceptance/reference-20260914/integrated-implementation/shibboleth/polling` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_CTX8SZ9YSEJQCRQ12WF3PPH8XN` | `build/acceptance/reference-20261002/shibboleth-certificate-runtime-r1/reader-v197/evaluation-terminal-http-v1` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_296ZHGM9XYDBAXHE3CP2XC3MC7` | `build/acceptance/reference-20260914/integrated-implementation/shibboleth/polling` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_P3V3M5S01NCK0A8AX4DVR9V33M` | `build/acceptance/reference-20260918/shibboleth-native-key-selection-v67/metadata_idp/evaluation` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_296ZHGM9XYDBAXHE3CP2XC3MC7` | `build/acceptance/reference-20260914/integrated-implementation/shibboleth/polling` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_JJPW4W8GACM9DT4PKH4CG0KWC7` | `build/acceptance/reference-20261003/shibboleth-metadata-application-qualified-r1/evaluation-v213` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_DCXY3VQPEXQF0KPGMS53PEPQCW` | `build/acceptance/reference-20260930/md06b-shibboleth-v158-r3` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_4761GW37A6K0MAJ6T640MKSY50` | `build/acceptance/reference-20261003/shibboleth-role-self-contained-trust-r2/trust-proof/reader-v204/formal` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_296ZHGM9XYDBAXHE3CP2XC3MC7` | `build/acceptance/reference-20260914/integrated-implementation/shibboleth/polling` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_P3V3M5S01NCK0A8AX4DVR9V33M` | `build/acceptance/reference-20260918/shibboleth-native-key-selection-v67/metadata_idp/evaluation` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_FD05JGHS5BY07MT016TY4FADFM` | `build/acceptance/reference-20260930/ext01b-shibboleth-v155/metadata_idp/evaluation-terminal-http-v1` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_0HDWMFK58A4V5W9BPWYABRNDRA` | `build/acceptance/reference-20260930/ext01c-shibboleth-v158/metadata_idp/metadata/evaluation-terminal-http-v1` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_M11JND1WT0CYAZVW88NRC2KW5Q` | `build/acceptance/reference-20260918/shibboleth-ecdsa-native-audit-metadata/metadata_idp/evaluation` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_CQ34HFCGCQ2NFE0YQKT5ZD22CQ` | `build/acceptance/reference-20260918/shibboleth-native-signed-request-v2/metadata_idp/evaluation` |
| metadata_idp († listed supplemental cases only) | shibboleth | `run_CQ34HFCGCQ2NFE0YQKT5ZD22CQ` | `build/acceptance/reference-20260918/shibboleth-native-signed-request-v2/metadata_idp/evaluation` |
| metadata_idp | shibboleth | `run_BMEHBBM5QAAAV41HZZX1R70QXH` | `interaction-followup/after/shibboleth/metadata_idp` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_CPWMJEQVVQYFYRDSCYFQWEC755` | `additional-implementation/simplesamlphp/metadata_idp` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_4C0CTQG9ZE90CV3XD17XD4JGCJ` | `build/acceptance/reference-20260930/ssp-native-mdq-direct-v1/evaluation` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_GM1SB82C8169KJ8D2T88G2WJ5S` | `build/acceptance/reference-20260930/ssp-metadata-refresh-v153` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_A0ATSTDF4W6HFC1GCYTFRXRRMR` | `build/acceptance/reference-20260918/simplesamlphp-md02b-v110` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_KDFJDGNQQCVFANEG53YYWYS4A1` | `build/acceptance/reference-20260917/simplesamlphp-native-parser-3` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_47A3XNG2QG2D7E64BDWH6XW5S3` | `build/acceptance/reference-20260918/simplesamlphp-aggregate-import` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_RWNXDC2KCN6ABEDTBWF2K8R6B6` | `build/acceptance/reference-20260930/ssp-metadata-signature-consumer-v164/campaign-r3/evaluation-native-rejection` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_HF9TAH6VHXY7RQK03JGW27XTF8` | `build/acceptance/reference-20260930/ssp-metadata-signature-v162/campaign-v3/repair-invalid-control` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_HF9TAH6VHXY7RQK03JGW27XTF8` | `build/acceptance/reference-20260930/ssp-metadata-signature-v162/campaign-v3/repair-invalid-control` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_HQBWWJ98N8XV9X0DFE1DNWHF03` | `build/acceptance/reference-20260930/md03d-simplesamlphp-v158` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_35NQ5VQX5JZTEXMB4RVK37CZVY` | `build/acceptance/reference-20260930/ssp-validity-capability-v158` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_Z4F3PP7WE9PWP284YCG5YKWANF` | `build/acceptance/reference-20260930/ssp-native-mdq-fixtures-v1/evaluation-native-rejection` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_35NQ5VQX5JZTEXMB4RVK37CZVY` | `build/acceptance/reference-20260930/ssp-validity-capability-v158` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_NTB45B0333JF88W97SGWEMZD0D` | `build/acceptance/reference-20260918/simplesamlphp-extension-points-corrected` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_KDFJDGNQQCVFANEG53YYWYS4A1` | `build/acceptance/reference-20260917/simplesamlphp-native-parser-3` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_KDFJDGNQQCVFANEG53YYWYS4A1` | `build/acceptance/reference-20260917/simplesamlphp-native-parser-3` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_KDFJDGNQQCVFANEG53YYWYS4A1` | `build/acceptance/reference-20260917/simplesamlphp-native-parser-3` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_816C536YJ0JK4DB1KCMG2QQNH5` | `build/acceptance/reference-20260918/single-signing-key/simplesamlphp` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_3FR2PVDMJW35XQGGGZSSG7RA9Q` | `build/acceptance/reference-20260930/publisher-ssp-v120/evaluation` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_NQBNKXVWD27W94A9AGQHAP4B06` | `build/acceptance/reference-20260930/ssp-rsa-sha1-metadata-v151` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_RWNXDC2KCN6ABEDTBWF2K8R6B6` | `build/acceptance/reference-20260930/ssp-metadata-signature-consumer-v164/campaign-r3/evaluation-native-rejection` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_RWNXDC2KCN6ABEDTBWF2K8R6B6` | `build/acceptance/reference-20260930/ssp-metadata-signature-consumer-v164/campaign-r3/evaluation-native-rejection` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_RWNXDC2KCN6ABEDTBWF2K8R6B6` | `build/acceptance/reference-20260930/ssp-metadata-signature-consumer-v164/campaign-r3/evaluation-native-rejection` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_GMJJ74B3V9P264GE7CX8PTYAE3` | `build/acceptance/reference-20260918/simplesamlphp-md05apaq-v111` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_GMJJ74B3V9P264GE7CX8PTYAE3` | `build/acceptance/reference-20260918/simplesamlphp-md05apaq-v111` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_HWRD7P947XEAKED9VW9MS61BZ6` | `build/acceptance/reference-20261002/simplesamlphp-metadata-validity-r2/evaluation-v193` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_Z4F3PP7WE9PWP284YCG5YKWANF` | `build/acceptance/reference-20260930/ssp-native-mdq-fixtures-v1/evaluation-native-rejection` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_08Q5460F7J5MFDXQQMT0CTGDRR` | `build/acceptance/reference-20260930/ssp-default-acs-v136/evaluation-v136` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_A1G3DYBWJDCSPBZW71DZ38R69Q` | `build/acceptance/reference-20260930/ssp-native-mdq-schema-valid-v1/evaluation-native-positive-v125` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_C13B6TD29Y7SKNF0MTVFGFQ6W1` | `build/acceptance/reference-20261001/ssp-mdiop-native-admission-v175-r1/evaluation` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_XFE204ASYT3HEY5FWW02B3NYHZ` | `build/acceptance/reference-20261004/simplesamlphp-publisher-used-signers-r2/evaluation-actual` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_KVHNHP2ZPE93WW6A154P3FH09S` | `build/acceptance/reference-20260918/simplesamlphp-md05c2-v105` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_XFE204ASYT3HEY5FWW02B3NYHZ` | `build/acceptance/reference-20261004/simplesamlphp-publisher-used-signers-r2/evaluation-actual` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_AFVTMTVZ37FHCFGNHJ7PMGGVMC` | `build/acceptance/reference-20261001/ssp-native-keyvalue-runtime-v170-r3/evaluation` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_MS5HDK610FJXD19ZR4C1YADKYW` | `build/acceptance/reference-20260918/simplesamlphp-md05d-v104` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_JB9X92CZED5RV8H322VWSH1XGV` | `build/acceptance/reference-20260918/simplesamlphp-md05e-v106` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_ZTEB6PCRWXJM0CZ6QWCZRR966T` | `build/acceptance/reference-20260918/algorithm-followup/simplesamlphp` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_Z15GR24Z1AWTH8DX9ZFZYPQSEK` | `build/acceptance/reference-20260930/ssp-intersection-capability-v165-r1/evaluation` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_ZTEB6PCRWXJM0CZ6QWCZRR966T` | `build/acceptance/reference-20260918/algorithm-followup/simplesamlphp` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_ZTEB6PCRWXJM0CZ6QWCZRR966T` | `build/acceptance/reference-20260918/algorithm-oracle-evaluation` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_ZTEB6PCRWXJM0CZ6QWCZRR966T` | `build/acceptance/reference-20260918/algorithm-oracle-evaluation` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_HNDN6YMHP5NZ9AP1GHB21V3AQH` | `build/acceptance/reference-20260918/publisher-ui-scoped/simplesamlphp` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_HNDN6YMHP5NZ9AP1GHB21V3AQH` | `build/acceptance/reference-20260918/publisher-ui-scoped/simplesamlphp` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_VRZ5B5R8SE352EMPR4A785ZFAH` | `build/acceptance/reference-20261001/ssp-native-consent-logo-v176-r2/evaluation` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_HNDN6YMHP5NZ9AP1GHB21V3AQH` | `build/acceptance/reference-20260918/publisher-ui-scoped/simplesamlphp` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_7SZ5MMZBD5FE51KBAQP9RF772S` | `build/acceptance/reference-20261001/ssp-native-consent-uri-v181-r2/evaluation` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_JSTA0B0DZX6T5ATW912F55395N` | `build/acceptance/reference-20260918/simplesamlphp-md05ff-v99` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_4V2ENBJQ8C49GPVB7KJ2C28KHN` | `build/acceptance/reference-20261001/ssp-native-consent-safety-v177-r2/evaluation` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_7SZ5MMZBD5FE51KBAQP9RF772S` | `build/acceptance/reference-20261001/ssp-native-consent-uri-v181-r2/evaluation` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_CPWMJEQVVQYFYRDSCYFQWEC755` | `build/acceptance/reference-20260914/additional-implementation/simplesamlphp/metadata_idp` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_BZCE2YCRJ1J6B0S9D9KNA317F1` | `build/acceptance/reference-20261001/ssp-native-consent-ui-v172-r6/evaluation-v174` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_KDFJDGNQQCVFANEG53YYWYS4A1` | `build/acceptance/reference-20260917/simplesamlphp-native-parser-3` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_F6BGNRP76J1E734N9MRDC3YT2X` | `build/acceptance/reference-20260918/simplesamlphp-metadata-fixture-v67` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_4FFJTY56TCQY9AKRA0BR0CC5K8` | `build/acceptance/reference-20261002/simplesamlphp-role-keys-r1/reader-v202/formal` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_AFVTMTVZ37FHCFGNHJ7PMGGVMC` | `build/acceptance/reference-20261001/ssp-native-keyvalue-runtime-v170-r3/evaluation` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_JKN1F8TWK7PN06HXRC848CKMGF` | `build/acceptance/reference-20261002/simplesamlphp-certificate-runtime-r2/evaluation-v200` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_AFVTMTVZ37FHCFGNHJ7PMGGVMC` | `build/acceptance/reference-20261001/ssp-native-keyvalue-runtime-v170-r3/evaluation` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_JBGGPXXP5664SYBAP858P9FMKD` | `build/acceptance/reference-20260918/simplesamlphp-native-key-selection-v65/metadata_idp/evaluation` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_KDFJDGNQQCVFANEG53YYWYS4A1` | `build/acceptance/reference-20260917/simplesamlphp-native-parser-3` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_PXSFEVJYKVT9QFN5AMDZB2V7J5` | `build/acceptance/reference-20260930/md06b-simplesamlphp-v158` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_4FFJTY56TCQY9AKRA0BR0CC5K8` | `build/acceptance/reference-20261002/simplesamlphp-self-contained-trust-r3/reader-v203/formal` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_KDFJDGNQQCVFANEG53YYWYS4A1` | `build/acceptance/reference-20260917/simplesamlphp-native-parser-3` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_JBGGPXXP5664SYBAP858P9FMKD` | `build/acceptance/reference-20260918/simplesamlphp-native-key-selection-v65/metadata_idp/evaluation` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_KDFJDGNQQCVFANEG53YYWYS4A1` | `build/acceptance/reference-20260917/simplesamlphp-native-parser-3` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_KDFJDGNQQCVFANEG53YYWYS4A1` | `build/acceptance/reference-20260917/simplesamlphp-native-parser-3` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_KDFJDGNQQCVFANEG53YYWYS4A1` | `build/acceptance/reference-20260917/simplesamlphp-native-parser-3` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_KDFJDGNQQCVFANEG53YYWYS4A1` | `build/acceptance/reference-20260917/simplesamlphp-native-parser-3` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_QVPS2Y8MMRB22T1GW4YW5MN3K3` | `build/acceptance/reference-20260930/ext01b-simplesamlphp-v158/metadata_idp/evaluation-terminal-http-v1` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_6CDG7AA61Y087GZYRPPMANBZ1W` | `build/acceptance/reference-20260918/simplesamlphp-native-signature-observation-v2/metadata_idp/evaluation` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_6CDG7AA61Y087GZYRPPMANBZ1W` | `build/acceptance/reference-20260918/simplesamlphp-native-signature-observation-v2/metadata_idp/evaluation` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_S9WN5SH11YRETN614ZTYYYA0PT` | `build/acceptance/reference-20260930/ssp-native-ec-v133/metadata_idp/evaluation-v133` |
| metadata_idp († listed supplemental cases only) | simplesamlphp | `run_YHD2ZJ212CAQJHBN4QVZ129E1G` | `/Users/yuta/Documents/SAMLscope/build/acceptance/reference-20260918/simplesamlphp-md05f-v107` |
| metadata_idp | simplesamlphp | `run_YVZ8AB57K11T5XRZNEYVHMPQ1Z` | `interaction-followup/after/simplesamlphp/metadata_idp` |
| ecp_idp († listed supplemental cases only) | keycloak | `run_B5BVZPZHA77V8B2SV0AKJZDJYC` | `build/acceptance/reference-20260915/algorithm-observation-batch/keycloak/ecp_idp` |
| ecp_idp († listed supplemental cases only) | keycloak | `run_B05XBA5FYGXDV933K9PKA9X441` | `build/acceptance/reference-20260915/peer-intent/keycloak/ecp_alg` |
| ecp_idp († listed supplemental cases only) | keycloak | `run_VDEDAMN49X5D6DJHF4GPJ1CA9M` | `build/acceptance/reference-20260930/ext01b-keycloak-v158/ecp_idp/evaluation-terminal-http-v1` |
| ecp_idp († listed supplemental cases only) | keycloak | `run_H5HT1BGQ7DM7ED1VT0M502Y0BA` | `build/acceptance/reference-20261004/keycloak-extension-attribute-parser-r2/evaluation-v230/ecp_idp` |
| ecp_idp († listed supplemental cases only) | keycloak | `run_YWWTJMD3P4MQWVNNYPNJD559CK` | `build/acceptance/reference-20260918/keycloak-native-signature-audit/ecp_idp/evaluation` |
| ecp_idp († listed supplemental cases only) | keycloak | `run_YWWTJMD3P4MQWVNNYPNJD559CK` | `build/acceptance/reference-20260918/keycloak-native-signature-audit/ecp_idp/evaluation` |
| ecp_idp († listed supplemental cases only) | keycloak | `run_9CQ4T26CJT03AJ9A3ZT7XDM6AW` | `build/acceptance/reference-20260918/keycloak-native-ec-signature-v3/observations/ecp_idp/evaluation` |
| ecp_idp († listed supplemental cases only) | keycloak | `run_B05XBA5FYGXDV933K9PKA9X441` | `build/acceptance/reference-20260915/peer-intent/keycloak/ecp_alg` |
| ecp_idp († listed supplemental cases only) | keycloak | `run_B5BVZPZHA77V8B2SV0AKJZDJYC` | `build/acceptance/reference-20260915/algorithm-observation-batch/keycloak/ecp_idp` |
| ecp_idp († listed supplemental cases only) | keycloak | `run_B05XBA5FYGXDV933K9PKA9X441` | `build/acceptance/reference-20260915/peer-intent/keycloak/ecp_alg` |
| ecp_idp († listed supplemental cases only) | keycloak | `run_B5BVZPZHA77V8B2SV0AKJZDJYC` | `build/acceptance/reference-20260915/algorithm-observation-batch/keycloak/ecp_idp` |
| ecp_idp († listed supplemental cases only) | keycloak | `run_BCJDFCFSWYMHVSESDMZCMBNAKA` | `build/acceptance/reference-20260918/keycloak-producer-algorithms-ecp` |
| ecp_idp († listed supplemental cases only) | keycloak | `run_B5BVZPZHA77V8B2SV0AKJZDJYC` | `build/acceptance/reference-20260915/algorithm-observation-batch/keycloak/ecp_idp` |
| ecp_idp († listed supplemental cases only) | keycloak | `run_NZGX1PXRJSNF8EHNXYM2ADPGDP` | `build/acceptance/reference-20260930/keycloak-alg08-native-policy-ecp-v164` |
| ecp_idp († listed supplemental cases only) | keycloak | `run_NZGX1PXRJSNF8EHNXYM2ADPGDP` | `build/acceptance/reference-20260930/keycloak-alg08-native-policy-ecp-v164` |
| ecp_idp | keycloak | `run_H38KM96SRSD9ESW4B0JQ0RV5JC` | `keycloak/ecp_idp/run5` |
| ecp_idp († listed supplemental cases only) | shibboleth | `run_YNSFE9WE4CNTHHB57W2RFVVR3K` | `build/acceptance/reference-20260915/algorithm-observation-batch/shibboleth/ecp_idp` |
| ecp_idp († listed supplemental cases only) | shibboleth | `run_FSAM4VBZ8MDAFB8H24QMTWD1V9` | `build/acceptance/reference-20260930/ext01b-shibboleth-v155/ecp_idp/evaluation-terminal-http-v1` |
| ecp_idp († listed supplemental cases only) | shibboleth | `run_5GA1YPD1SAMWK27ARM4B0AP9AS` | `build/acceptance/reference-20260930/ext01c-shibboleth-v158/ecp_idp/metadata/evaluation-terminal-http-v1` |
| ecp_idp († listed supplemental cases only) | shibboleth | `run_HM0CRTNVGD9Q1PT31P112N28AQ` | `build/acceptance/reference-20260918/shibboleth-ecdsa-native-audit-additional/ecp_idp/evaluation` |
| ecp_idp († listed supplemental cases only) | shibboleth | `run_YNSFE9WE4CNTHHB57W2RFVVR3K` | `build/acceptance/reference-20260915/algorithm-observation-batch/shibboleth/ecp_idp` |
| ecp_idp († listed supplemental cases only) | shibboleth | `run_SSWFM7EX1V67WPRXPK975NW52B` | `build/acceptance/reference-20260918/shibboleth-producer-evaluation-ecp` |
| ecp_idp († listed supplemental cases only) | shibboleth | `run_YNSFE9WE4CNTHHB57W2RFVVR3K` | `build/acceptance/reference-20260915/algorithm-observation-batch/shibboleth/ecp_idp` |
| ecp_idp († listed supplemental cases only) | shibboleth | `run_SSWFM7EX1V67WPRXPK975NW52B` | `build/acceptance/reference-20260918/shibboleth-producer-evaluation-ecp` |
| ecp_idp († listed supplemental cases only) | shibboleth | `run_SSWFM7EX1V67WPRXPK975NW52B` | `build/acceptance/reference-20260918/shibboleth-producer-evaluation-ecp` |
| ecp_idp († listed supplemental cases only) | shibboleth | `run_YNSFE9WE4CNTHHB57W2RFVVR3K` | `build/acceptance/reference-20260915/algorithm-observation-batch/shibboleth/ecp_idp` |
| ecp_idp († listed supplemental cases only) | shibboleth | `run_E27G00G2FF6M2HGC2GT64CQ5KA` | `build/acceptance/reference-20260930/shibboleth-alg08-ecp-v162-relay-r2` |
| ecp_idp († listed supplemental cases only) | shibboleth | `run_E27G00G2FF6M2HGC2GT64CQ5KA` | `build/acceptance/reference-20260930/shibboleth-alg08-ecp-v162-relay-r2` |
| ecp_idp († listed supplemental cases only) | shibboleth | `run_3FME5QSED778KCFZ028413KC3P` | `build/acceptance/reference-20261004/shibboleth-default-algorithm-ecp-source-r1` |
| ecp_idp († listed supplemental cases only) | shibboleth | `run_GQ70KKEYFZFHR5PYTZS4M3YKSZ` | `build/acceptance/reference-20260918/shibboleth-native-signed-request-v2/ecp_idp/evaluation` |
| ecp_idp († listed supplemental cases only) | shibboleth | `run_GQ70KKEYFZFHR5PYTZS4M3YKSZ` | `build/acceptance/reference-20260918/shibboleth-native-signed-request-v2/ecp_idp/evaluation` |
| ecp_idp | shibboleth | `run_4E2YMVJR6DPW196YFMWX4V9DN3` | `shibboleth/ecp_idp/run4` |
| ecp_idp († listed supplemental cases only) | simplesamlphp | `run_6MFJ4KXD8JGR140MMFWPVM8D84` | `build/acceptance/reference-20260915/peer-intent/simplesamlphp/ecp_alg_enc` |
| ecp_idp († listed supplemental cases only) | simplesamlphp | `run_BJ2XCTNGK2RRGAAYGCQWQ1RVJT` | `build/acceptance/reference-20260930/ext01b-simplesamlphp-v158/ecp_idp/evaluation-terminal-http-v1` |
| ecp_idp († listed supplemental cases only) | simplesamlphp | `run_EQPZ1J1F02HFF25C5G0YA7D2B3` | `build/acceptance/reference-20260918/simplesamlphp-native-signature-observation-v2/ecp_idp/evaluation` |
| ecp_idp († listed supplemental cases only) | simplesamlphp | `run_EQPZ1J1F02HFF25C5G0YA7D2B3` | `build/acceptance/reference-20260918/simplesamlphp-native-signature-observation-v2/ecp_idp/evaluation` |
| ecp_idp († listed supplemental cases only) | simplesamlphp | `run_J3V08TCY6KS3NN5CJWWSS7KN2C` | `build/acceptance/reference-20260930/ssp-native-ec-v133/ecp_idp/evaluation-v133` |
| ecp_idp († listed supplemental cases only) | simplesamlphp | `run_K5VQKQQHY8PMVF144RYVAYKP8G` | `build/acceptance/reference-20260929/simplesamlphp-ecp-shared-gcm128` |
| ecp_idp († listed supplemental cases only) | simplesamlphp | `run_VGZMD4XDTKT0T1M125F68HEBNW` | `build/acceptance/reference-20260929/simplesamlphp-ecp-shared-gcm256` |
| ecp_idp († listed supplemental cases only) | simplesamlphp | `run_6MFJ4KXD8JGR140MMFWPVM8D84` | `build/acceptance/reference-20260915/peer-intent/simplesamlphp/ecp_alg_enc` |
| ecp_idp | simplesamlphp | `run_KNM1G6JW0H7MYS6RT0FQX69EK5` | `simplesamlphp/ecp_idp/run6` |
| single_logout_idp († listed supplemental cases only) | keycloak | `run_K6A6ZHJNKWDYARKT4E4ZJGHQHT` | `remaining-audit/keycloak/fresh_common` |
| single_logout_idp († listed supplemental cases only) | keycloak | `run_CERKQBAE027XYKQZ6284AGS3K5` | `slo-redirect-receiver-integrated/keycloak/single_logout_idp` |
| single_logout_idp († listed supplemental cases only) | keycloak | `run_XYJ8KKVM3KYAAMFQR6XSHHHR4T` | `slo-encrypted-id-integrated/keycloak/single_logout_idp` |
| single_logout_idp († listed supplemental cases only) | keycloak | `run_BNXG3E6VS9ZGCX3ZNXPV1TB973` | `slo-multiple-keys-integrated/keycloak/single_logout_idp` |
| single_logout_idp († listed supplemental cases only) | keycloak | `run_K6A6ZHJNKWDYARKT4E4ZJGHQHT` | `build/acceptance/reference-20260914/remaining-audit/keycloak/fresh_common` |
| single_logout_idp († listed supplemental cases only) | keycloak | `run_K6A6ZHJNKWDYARKT4E4ZJGHQHT` | `build/acceptance/reference-20260914/remaining-audit/keycloak/fresh_common` |
| single_logout_idp († listed supplemental cases only) | keycloak | `run_QX707K2D5QHG7VR68206H0FB72` | `build/acceptance/reference-20260930/ext01b-keycloak-v158/single_logout_idp/evaluation-terminal-http-v1` |
| single_logout_idp († listed supplemental cases only) | keycloak | `run_2KT95AZ1GYY8P50CAD9TW4FRBV` | `build/acceptance/reference-20261004/keycloak-extension-attribute-parser-r2/evaluation-v230/single_logout_idp` |
| single_logout_idp († listed supplemental cases only) | keycloak | `run_DVQNW0ZY3675WNFYAYCTQ81J4X` | `build/acceptance/reference-20260918/keycloak-native-signature-audit/single_logout_idp/evaluation` |
| single_logout_idp († listed supplemental cases only) | keycloak | `run_DVQNW0ZY3675WNFYAYCTQ81J4X` | `build/acceptance/reference-20260918/keycloak-native-signature-audit/single_logout_idp/evaluation` |
| single_logout_idp († listed supplemental cases only) | keycloak | `run_W2DFV6VZDAB4S8GN6GAYNQ45MM` | `build/acceptance/reference-20260918/keycloak-native-ec-signature-v3/observations/single_logout_idp/evaluation` |
| single_logout_idp († listed supplemental cases only) | keycloak | `run_CERKQBAE027XYKQZ6284AGS3K5` | `build/acceptance/reference-20260914/slo-redirect-receiver-integrated/keycloak/single_logout_idp` |
| single_logout_idp († listed supplemental cases only) | keycloak | `run_P9PEZYWNZW63V20ETYAP94H7KX` | `build/acceptance/reference-20260915/slo-oracle/keycloak/slo_probe_browser` |
| single_logout_idp († listed supplemental cases only) | keycloak | `run_P9PEZYWNZW63V20ETYAP94H7KX` | `build/acceptance/reference-20260915/slo-oracle/keycloak/slo_probe_browser` |
| single_logout_idp († listed supplemental cases only) | keycloak | `run_W9RJ2DKTGE5S5XX6HPE2F8FZE4` | `build/acceptance/reference-20260915/peer-intent/keycloak/slo_audit` |
| single_logout_idp († listed supplemental cases only) | keycloak | `run_ZMKVMNSWGR5Y84J1MZ0M3CJTMK` | `build/acceptance/reference-20260930/keycloak-target-logout-absence-v158-r7/evaluation-terminal-http-v1` |
| single_logout_idp († listed supplemental cases only) | keycloak | `run_W9RJ2DKTGE5S5XX6HPE2F8FZE4` | `build/acceptance/reference-20260915/peer-intent/keycloak/slo_audit` |
| single_logout_idp († listed supplemental cases only) | keycloak | `run_W9RJ2DKTGE5S5XX6HPE2F8FZE4` | `build/acceptance/reference-20260915/peer-intent/keycloak/slo_audit` |
| single_logout_idp († listed supplemental cases only) | keycloak | `run_ZMKVMNSWGR5Y84J1MZ0M3CJTMK` | `build/acceptance/reference-20260930/keycloak-target-logout-absence-v158-r7/evaluation-terminal-http-v1` |
| single_logout_idp († listed supplemental cases only) | keycloak | `run_P9PEZYWNZW63V20ETYAP94H7KX` | `build/acceptance/reference-20260915/slo-oracle/keycloak/slo_probe_browser` |
| single_logout_idp († listed supplemental cases only) | keycloak | `run_P9PEZYWNZW63V20ETYAP94H7KX` | `build/acceptance/reference-20260915/slo-oracle/keycloak/slo_probe_browser` |
| single_logout_idp († listed supplemental cases only) | keycloak | `run_P9PEZYWNZW63V20ETYAP94H7KX` | `build/acceptance/reference-20260915/slo-oracle/keycloak/slo_probe_browser` |
| single_logout_idp († listed supplemental cases only) | keycloak | `run_P9PEZYWNZW63V20ETYAP94H7KX` | `build/acceptance/reference-20260915/slo-oracle/keycloak/slo_probe_browser` |
| single_logout_idp († listed supplemental cases only) | keycloak | `run_MZ1VKMF44GK8TD3H67V3D7YM5S` | `build/acceptance/reference-20261004/keycloak-slo-registered-signer-r5/evaluation-actual` |
| single_logout_idp († listed supplemental cases only) | keycloak | `run_P9PEZYWNZW63V20ETYAP94H7KX` | `build/acceptance/reference-20260915/slo-oracle/keycloak/slo_probe_browser` |
| single_logout_idp († listed supplemental cases only) | keycloak | `run_CERKQBAE027XYKQZ6284AGS3K5` | `build/acceptance/reference-20260914/slo-redirect-receiver-integrated/keycloak/single_logout_idp` |
| single_logout_idp († listed supplemental cases only) | keycloak | `run_Z8TR4WMEEQS682CHEM598836MT` | `build/acceptance/reference-20260915/slo-oracle/keycloak/slo_18b` |
| single_logout_idp († listed supplemental cases only) | keycloak | `run_W9RJ2DKTGE5S5XX6HPE2F8FZE4` | `build/acceptance/reference-20260915/peer-intent/keycloak/slo_audit` |
| single_logout_idp († listed supplemental cases only) | keycloak | `run_W9RJ2DKTGE5S5XX6HPE2F8FZE4` | `build/acceptance/reference-20260915/peer-intent/keycloak/slo_audit` |
| single_logout_idp († listed supplemental cases only) | keycloak | `run_XYJ8KKVM3KYAAMFQR6XSHHHR4T` | `build/acceptance/reference-20260914/slo-encrypted-id-integrated/keycloak/single_logout_idp` |
| single_logout_idp († listed supplemental cases only) | keycloak | `run_BNXG3E6VS9ZGCX3ZNXPV1TB973` | `build/acceptance/reference-20260914/slo-multiple-keys-integrated/keycloak/single_logout_idp` |
| single_logout_idp († listed supplemental cases only) | keycloak | `run_P9PEZYWNZW63V20ETYAP94H7KX` | `/Users/yuta/Documents/SAMLscope/build/acceptance/reference-20260915/slo-oracle/keycloak/slo_probe_browser` |
| single_logout_idp | keycloak | `run_J5SM20CM8MH8BG894VXA2N4BFM` | `keycloak/single_logout_idp/browser2` |
| single_logout_idp († listed supplemental cases only) | shibboleth | `run_SGCAQNVM44RHF91FQH3SQD0HDH` | `remaining-audit/shibboleth/fresh_common` |
| single_logout_idp († listed supplemental cases only) | shibboleth | `run_P02Y6XV9YZE7R9D3Z6V1D32WHQ` | `slo-redirect-receiver-integrated/shibboleth/single_logout_idp` |
| single_logout_idp († listed supplemental cases only) | shibboleth | `run_MCZRYHMCFBJ227206Y8YC3XCST` | `slo-encrypted-id-integrated/shibboleth/single_logout_idp` |
| single_logout_idp († listed supplemental cases only) | shibboleth | `run_7NEJ4R0ZV980M9YJSQEXPADWKQ` | `slo-multiple-keys-integrated/shibboleth/single_logout_idp` |
| single_logout_idp († listed supplemental cases only) | shibboleth | `run_T8A6A9QZFF5QVYTCK1AFQJZ4RZ` | `key-capability-integrated/shibboleth/single_logout_idp` |
| single_logout_idp († listed supplemental cases only) | shibboleth | `run_PXFNTJDBJJR8GE88XWPKK0T0HC` | `build/acceptance/reference-20260915/peer-intent/shibboleth/slo_target_logout` |
| single_logout_idp († listed supplemental cases only) | shibboleth | `run_SGCAQNVM44RHF91FQH3SQD0HDH` | `build/acceptance/reference-20260914/remaining-audit/shibboleth/fresh_common` |
| single_logout_idp († listed supplemental cases only) | shibboleth | `run_SGCAQNVM44RHF91FQH3SQD0HDH` | `build/acceptance/reference-20260914/remaining-audit/shibboleth/fresh_common` |
| single_logout_idp († listed supplemental cases only) | shibboleth | `run_AFKPCME8CRTXMMGYVP46DNDQZN` | `build/acceptance/reference-20260930/ext01b-shibboleth-v155/single_logout_idp/evaluation-terminal-http-v1` |
| single_logout_idp († listed supplemental cases only) | shibboleth | `run_VN2C6S628XPQS8B549608ZQY87` | `build/acceptance/reference-20260930/ext01c-shibboleth-v158/single_logout_idp/metadata/evaluation-terminal-http-v1` |
| single_logout_idp († listed supplemental cases only) | shibboleth | `run_RJ0XT9P3SJ4FY20NSDDZB5DRD2` | `build/acceptance/reference-20260918/shibboleth-ecdsa-native-audit-additional/single_logout_idp/evaluation` |
| single_logout_idp († listed supplemental cases only) | shibboleth | `run_P02Y6XV9YZE7R9D3Z6V1D32WHQ` | `build/acceptance/reference-20260914/slo-redirect-receiver-integrated/shibboleth/single_logout_idp` |
| single_logout_idp († listed supplemental cases only) | shibboleth | `run_9KV70EB8T30AXEBZKCAK1C1WWE` | `build/acceptance/reference-20260915/slo-oracle/shibboleth/slo_probe_browser` |
| single_logout_idp († listed supplemental cases only) | shibboleth | `run_9KV70EB8T30AXEBZKCAK1C1WWE` | `build/acceptance/reference-20260915/slo-oracle/shibboleth/slo_probe_browser` |
| single_logout_idp († listed supplemental cases only) | shibboleth | `run_Z0PMNCN36CNTYCJX36VDYFZYHP` | `build/acceptance/reference-20260915/peer-intent/shibboleth/slo_audit` |
| single_logout_idp († listed supplemental cases only) | shibboleth | `run_S9G7V5DDY23C9RPE3PWYNYKWD2` | `build/acceptance/reference-20260918/shibboleth-slo-webflow-v101` |
| single_logout_idp († listed supplemental cases only) | shibboleth | `run_8N96KQNNSSG8NAK632QZRG5SCG` | `build/acceptance/reference-20261004/shibboleth-soap-slo-continuation-r5/evaluation-actual` |
| single_logout_idp († listed supplemental cases only) | shibboleth | `run_67RM713GH15DD3S2X1VJ0GETZ3` | `build/acceptance/reference-20261001/shibboleth-native-slo-v178-r7/reader-v180/evaluation-terminal-http-v1` |
| single_logout_idp († listed supplemental cases only) | shibboleth | `run_S9G7V5DDY23C9RPE3PWYNYKWD2` | `build/acceptance/reference-20260918/shibboleth-slo-webflow-v101` |
| single_logout_idp († listed supplemental cases only) | shibboleth | `run_9KV70EB8T30AXEBZKCAK1C1WWE` | `build/acceptance/reference-20260915/slo-oracle/shibboleth/slo_probe_browser` |
| single_logout_idp († listed supplemental cases only) | shibboleth | `run_9KV70EB8T30AXEBZKCAK1C1WWE` | `build/acceptance/reference-20260915/slo-oracle/shibboleth/slo_probe_browser` |
| single_logout_idp († listed supplemental cases only) | shibboleth | `run_9KV70EB8T30AXEBZKCAK1C1WWE` | `build/acceptance/reference-20260915/slo-oracle/shibboleth/slo_probe_browser` |
| single_logout_idp († listed supplemental cases only) | shibboleth | `run_9KV70EB8T30AXEBZKCAK1C1WWE` | `build/acceptance/reference-20260915/slo-oracle/shibboleth/slo_probe_browser` |
| single_logout_idp († listed supplemental cases only) | shibboleth | `run_564R50AACKHVYJ2KT3THAE5WYP` | `build/acceptance/reference-20261004/shibboleth-slo-registered-signer-r2/evaluation-v224-r2` |
| single_logout_idp († listed supplemental cases only) | shibboleth | `run_9KV70EB8T30AXEBZKCAK1C1WWE` | `build/acceptance/reference-20260915/slo-oracle/shibboleth/slo_probe_browser` |
| single_logout_idp († listed supplemental cases only) | shibboleth | `run_P02Y6XV9YZE7R9D3Z6V1D32WHQ` | `build/acceptance/reference-20260914/slo-redirect-receiver-integrated/shibboleth/single_logout_idp` |
| single_logout_idp († listed supplemental cases only) | shibboleth | `run_TRBVRX88B7VW14KRS3JFQ3RFKQ` | `build/acceptance/reference-20260915/slo-oracle/shibboleth/slo_18b` |
| single_logout_idp († listed supplemental cases only) | shibboleth | `run_Z0PMNCN36CNTYCJX36VDYFZYHP` | `build/acceptance/reference-20260915/peer-intent/shibboleth/slo_audit` |
| single_logout_idp († listed supplemental cases only) | shibboleth | `run_Z0PMNCN36CNTYCJX36VDYFZYHP` | `build/acceptance/reference-20260915/peer-intent/shibboleth/slo_audit` |
| single_logout_idp († listed supplemental cases only) | shibboleth | `run_MCZRYHMCFBJ227206Y8YC3XCST` | `build/acceptance/reference-20260914/slo-encrypted-id-integrated/shibboleth/single_logout_idp` |
| single_logout_idp († listed supplemental cases only) | shibboleth | `run_T8A6A9QZFF5QVYTCK1AFQJZ4RZ` | `build/acceptance/reference-20260914/key-capability-integrated/shibboleth/single_logout_idp` |
| single_logout_idp († listed supplemental cases only) | shibboleth | `run_7NEJ4R0ZV980M9YJSQEXPADWKQ` | `build/acceptance/reference-20260914/slo-multiple-keys-integrated/shibboleth/single_logout_idp` |
| single_logout_idp († listed supplemental cases only) | shibboleth | `run_0NKMWAVB7T7DF1RFMQH2VDPD82` | `build/acceptance/reference-20260918/shibboleth-native-signed-request-v2/single_logout_idp/evaluation` |
| single_logout_idp († listed supplemental cases only) | shibboleth | `run_0NKMWAVB7T7DF1RFMQH2VDPD82` | `build/acceptance/reference-20260918/shibboleth-native-signed-request-v2/single_logout_idp/evaluation` |
| single_logout_idp († listed supplemental cases only) | shibboleth | `run_9KV70EB8T30AXEBZKCAK1C1WWE` | `/Users/yuta/Documents/SAMLscope/build/acceptance/reference-20260915/slo-oracle/shibboleth/slo_probe_browser` |
| single_logout_idp | shibboleth | `run_23TFJH7Y8APXAWCX58004A9FGG` | `shibboleth/single_logout_idp/browser5` |
| single_logout_idp († listed supplemental cases only) | simplesamlphp | `run_FK4C7STWMF8RWG80J1TCB57SGX` | `remaining-audit/simplesamlphp/fresh_common` |
| single_logout_idp († listed supplemental cases only) | simplesamlphp | `run_W63NJD61TCBC56C5WHFNYFZRS4` | `slo-redirect-receiver-integrated/simplesamlphp/single_logout_idp` |
| single_logout_idp († listed supplemental cases only) | simplesamlphp | `run_45Q1TW5SXTWCH4WMZ7JFSXP5YA` | `slo-encrypted-id-integrated/simplesamlphp/single_logout_idp` |
| single_logout_idp († listed supplemental cases only) | simplesamlphp | `run_19PV7S56N3H0DDENCD1K6GGK61` | `slo-multiple-keys-integrated/simplesamlphp/single_logout_idp` |
| single_logout_idp († listed supplemental cases only) | simplesamlphp | `run_FK4C7STWMF8RWG80J1TCB57SGX` | `build/acceptance/reference-20260914/remaining-audit/simplesamlphp/fresh_common` |
| single_logout_idp († listed supplemental cases only) | simplesamlphp | `run_FK4C7STWMF8RWG80J1TCB57SGX` | `build/acceptance/reference-20260914/remaining-audit/simplesamlphp/fresh_common` |
| single_logout_idp († listed supplemental cases only) | simplesamlphp | `run_R3141MFT60HP3HFDQMXQ0K4P87` | `build/acceptance/reference-20260930/ext01b-simplesamlphp-v158/single_logout_idp/evaluation-terminal-http-v1` |
| single_logout_idp († listed supplemental cases only) | simplesamlphp | `run_FK4C7STWMF8RWG80J1TCB57SGX` | `build/acceptance/reference-20260914/remaining-audit/simplesamlphp/fresh_common` |
| single_logout_idp († listed supplemental cases only) | simplesamlphp | `run_GD556ATPJCZAXF3CSRQXE0GWYW` | `build/acceptance/reference-20260918/simplesamlphp-native-signature-observation-v2/single_logout_idp/evaluation` |
| single_logout_idp († listed supplemental cases only) | simplesamlphp | `run_GD556ATPJCZAXF3CSRQXE0GWYW` | `build/acceptance/reference-20260918/simplesamlphp-native-signature-observation-v2/single_logout_idp/evaluation` |
| single_logout_idp († listed supplemental cases only) | simplesamlphp | `run_HTX2M5N1Y5AF3W2ZQZV9BX3467` | `build/acceptance/reference-20260930/ssp-native-ec-v133/single_logout_idp/evaluation-v133` |
| single_logout_idp († listed supplemental cases only) | simplesamlphp | `run_W63NJD61TCBC56C5WHFNYFZRS4` | `build/acceptance/reference-20260914/slo-redirect-receiver-integrated/simplesamlphp/single_logout_idp` |
| single_logout_idp († listed supplemental cases only) | simplesamlphp | `run_KDKRQPF0XMGD57BKQMT252SV9V` | `build/acceptance/reference-20260915/slo-oracle/simplesamlphp/slo_probe_browser` |
| single_logout_idp († listed supplemental cases only) | simplesamlphp | `run_KDKRQPF0XMGD57BKQMT252SV9V` | `build/acceptance/reference-20260915/slo-oracle/simplesamlphp/slo_probe_browser` |
| single_logout_idp († listed supplemental cases only) | simplesamlphp | `run_KDKRQPF0XMGD57BKQMT252SV9V` | `build/acceptance/reference-20260915/slo-oracle/simplesamlphp/slo_probe_browser` |
| single_logout_idp († listed supplemental cases only) | simplesamlphp | `run_AYKGN0WFF79RMY2SZQ0TTFRV2R` | `build/acceptance/reference-20260918/ssp-slo-propagation-v3` |
| single_logout_idp († listed supplemental cases only) | simplesamlphp | `run_JFRMKZS33R0GXK8F1Q3KRY7GDT` | `build/acceptance/reference-20260915/peer-intent/simplesamlphp/slo_audit` |
| single_logout_idp († listed supplemental cases only) | simplesamlphp | `run_2671TXGC71MJ97JGK0AFJX3Y0D` | `build/acceptance/reference-20260930/ssp-slo-iframe-v131i` |
| single_logout_idp († listed supplemental cases only) | simplesamlphp | `run_KDKRQPF0XMGD57BKQMT252SV9V` | `build/acceptance/reference-20260915/slo-oracle/simplesamlphp/slo_probe_browser` |
| single_logout_idp († listed supplemental cases only) | simplesamlphp | `run_KDKRQPF0XMGD57BKQMT252SV9V` | `build/acceptance/reference-20260915/slo-oracle/simplesamlphp/slo_probe_browser` |
| single_logout_idp († listed supplemental cases only) | simplesamlphp | `run_KDKRQPF0XMGD57BKQMT252SV9V` | `build/acceptance/reference-20260915/slo-oracle/simplesamlphp/slo_probe_browser` |
| single_logout_idp († listed supplemental cases only) | simplesamlphp | `run_KDKRQPF0XMGD57BKQMT252SV9V` | `build/acceptance/reference-20260915/slo-oracle/simplesamlphp/slo_probe_browser` |
| single_logout_idp († listed supplemental cases only) | simplesamlphp | `run_5WJCN84233GZCN0DGBFM67TEWQ` | `build/acceptance/reference-20261004/simplesamlphp-slo-registered-signer-r6/evaluation-actual` |
| single_logout_idp († listed supplemental cases only) | simplesamlphp | `run_KDKRQPF0XMGD57BKQMT252SV9V` | `build/acceptance/reference-20260915/slo-oracle/simplesamlphp/slo_probe_browser` |
| single_logout_idp († listed supplemental cases only) | simplesamlphp | `run_W63NJD61TCBC56C5WHFNYFZRS4` | `build/acceptance/reference-20260914/slo-redirect-receiver-integrated/simplesamlphp/single_logout_idp` |
| single_logout_idp († listed supplemental cases only) | simplesamlphp | `run_KPBMMV9KFCC5438QRXT8MTZ2AA` | `build/acceptance/reference-20260915/slo-oracle/simplesamlphp/slo_18b` |
| single_logout_idp († listed supplemental cases only) | simplesamlphp | `run_AYKGN0WFF79RMY2SZQ0TTFRV2R` | `build/acceptance/reference-20260918/ssp-slo-propagation-v3` |
| single_logout_idp († listed supplemental cases only) | simplesamlphp | `run_JFRMKZS33R0GXK8F1Q3KRY7GDT` | `build/acceptance/reference-20260915/peer-intent/simplesamlphp/slo_audit` |
| single_logout_idp († listed supplemental cases only) | simplesamlphp | `run_45Q1TW5SXTWCH4WMZ7JFSXP5YA` | `build/acceptance/reference-20260914/slo-encrypted-id-integrated/simplesamlphp/single_logout_idp` |
| single_logout_idp († listed supplemental cases only) | simplesamlphp | `run_5WJCN84233GZCN0DGBFM67TEWQ` | `build/acceptance/reference-20261008/ssp-configuration-source-run-r1/adoption` |
| single_logout_idp († listed supplemental cases only) | simplesamlphp | `run_1E0KV60F7802V0EECYD52V7V92` | `build/acceptance/reference-20261001/ssp-encrypted-logout-native-v186-r7/evaluation` |
| single_logout_idp | simplesamlphp | `run_DVCVA0CEB6PRZGXWWMV4AKMR1K` | `simplesamlphp/single_logout_idp/browser2` |
