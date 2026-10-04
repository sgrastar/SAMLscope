# Implementation Plan for Common SLO Execution Infrastructure and Evaluation

Among the 546 unverified observations, the scope is the 42 observations that end with `browser.oracle-unavailable` because the SLO browser oracle is not implemented. For `single_logout_idp` across 3 products, implement the 14 common cases from active fixture delivery by the Suite through correlation, controls, evaluation, and display. `Evaluator` performs evaluation, and cases return only `outcome` (AGENTS.md 3). Delivery goes through the outbox (AGENTS.md 4).

## 1. Target Cases and Required Evidence

| Case | Required fixture | Facts to observe | Main interpretation constraints |
|---|---|---|---|
| `IIP-IDP17.b` | Asynchronous LogoutRequest (Destination mismatch / unknown SessionIndex) and positive control | No response is returned, and the request is not applied to the session | Session termination itself is SHOULD. Separate b/b1/b2/b3 |
| `IIP-IDP17.b1` | Trusted asynchronous LogoutRequest with a valid signature and authenticated sender | No samlp:LogoutResponse is returned (both front/back) | Include a synchronous positive control. HTTP feedback is the obligation in b2 |
| `IIP-IDP17.b2` | Successful / failed front-channel asynchronous requests | The user-facing HTTP response indicates success/failure | Pair success and failure to detect a fixed "success" page. If failure cannot be induced, use `not_verified(session_termination_failure_not_inducible)` |
| `IIP-IDP17.c` | (informational) Upstream authority and secondary_peer registration | Record whether propagation occurs as information. No Verdict | No propagation is NOT_SUPPORTED. Do not make it FAIL |
| `IIP-IDP17.r` | 3 participants, with the first timing out / returning an error | If propagation is implemented, attempt the remaining participants | With only 1 participant, confirmation equivalent to `satisfied_with_note` cannot be obtained. Unimplemented propagation is satisfied_with_note. A timeout alone must not produce FAIL |
| `IIP-IDP17.s` | A request that is not asynchronous + participant failure | Second-level StatusCode=PartialLogout | Do not require PartialLogout when all participants succeed. Do not make the top level an error |
| `IIP-IDP17.x` | LogoutRequest with a Destination mismatch (valid signature) + control with the correct Destination | The request is not applied to the session | Do not require acceptance when Destination is omitted |
| `IIP-IDP17.y` | LogoutRequest with a modified signature value / signed content | The request is not applied to the session | Redirect query signatures are out of scope. If the LogoutResponse direction is unobserved, use `satisfied_with_note` |
| `IIP-IDP17.z` | LogoutRequest with an invalid signature (and optional LogoutResponse) | The content is not relied upon | Separate from y. Do not justify response suppression by aslo |
| `IIP-IDP17.aa` | LogoutRequest with an invalid signature | If a response is returned, it is an error LogoutResponse. No response is WARNING | SHOULD_CLASS. Use not_verified if internal processing is unavailable. Use `satisfied_with_note` if the response direction is unobserved |
| `IIP-IDP17.al` | A transform that makes the signed content empty / a signature that excludes identifiers or other content | Rejection | Only acceptance is a violation. The Suite self-verifies the fixture's cryptographic validity and actual exclusions |
| `IIP-IDP18.b` | Suite SP advertises only a Redirect response endpoint + HTTP-Redirect LogoutRequest | IdP returns LogoutResponse via HTTP-Redirect | Do not force Redirect when both Redirect and POST are advertised |
| `IIP-IDP18.c` | Suite SLO request endpoints are restricted to Redirect, and IdP sends a Redirect LogoutRequest | The request can be received | Use `satisfied_with_note` if issuance by the IdP is unobserved |
| `IIP-IDP18.d` | IdP issues a normal LogoutRequest, and Suite returns LogoutResponse via Redirect | IdP consumes the response | An asynchronous-only Run is `satisfied_with_note` |

## 2. Common Infrastructure

### 2.1 Direct HTTP Delivery (Outbox Extension)

With front-channel browser delivery, a missing response cannot establish "no response" (because delivery itself is UNKNOWN; AGENTS.md 4). Asynchronous b/b1, invalid-signature z/aa, Destination-mismatch x, and transform-exclusion al require **delivery confirmation and observation of the HTTP response body**. Add a direct HTTP delivery kind to the outbox for this purpose.

- Add `OutboundKind.LOGOUT_PROBE` (Retry.UNSAFE).
- `HttpOutboundSender` handles `LOGOUT_PROBE`, sends via POST (`SAMLRequest` form) or GET (Deflate+Base64+signed query), and records the HTTP status, headers, and body (limit 1MiB) in an INBOUND transcript.
- If the response body contains a SAML LogoutResponse, treat it as an existing SAML parsing target; otherwise, record it as "HTTP response only."
- Connection failures and timeouts become exceptions → `UNKNOWN_DELIVERY` (do not make the product FAIL).
- Correlate the response by `actionId`. The case waits using `ScenarioActionId`.

### 2.2 ActiveProbeCoordinator Extension

The Suite executes direct-delivery outbox actions without an external user agent.

- In `status()`, if the waiting action kind is `LOGOUT_PROBE`, send it through `dispatcher.dispatch`, then route the recorded INBOUND entry through `InboundCaseRouter` to the waiting case as an `InboundMessage`.
- If delivery is `UNKNOWN_DELIVERY`, resume with `CaseEvent.InboundUnavailable("unknown-delivery")`; the case returns the equivalent of NOT_VERIFIED.
- `CaseTimeoutService` resumes the case with `TimedOut` when the waiting deadline expires. If a direct-delivery HTTP response has already been recorded, determine the result from the presence or absence of content in the response body rather than relying on `TimedOut`.
- Extend `Status` with a `directProbe` flag so that the driver and report can distinguish whether browser interaction is involved.

### 2.3 Session Survival Controls

Observe "not applied to the session" for x/y/z/al using the following controls.

1. Perform a normal browser login (the same procedure as the existing `IdpBasicLogoutScenarioTestCase`).
2. Deliver the malformed fixture directly and record the response (error LogoutResponse / no response / HTTP response only).
3. Deliver a LogoutRequest with the correct Destination and a valid signature directly, and confirm a Success LogoutResponse. If this succeeds, the malformed fixture did not destroy the session.
4. If a Success LogoutResponse was returned in 2, treat it as strong evidence that the request was applied to the session and return VIOLATED.

If 3 fails (session lost / error), return VIOLATED as evidence that 2 was applied. If delivery of 3 itself is unknown, return NOT_VERIFIED.

### 2.4 Fixture Generation

Extend `SamlLogoutRequestFactory` so that it can generate the following in sequence for the same session.

- Destination replacement (set before signing, so that the signature remains valid).
- Modification after signing (change 1 byte of the signature value / change the text of a signed element while retaining valid XML).
- A signature that excludes ID or SessionIndex from the signed content through an XPath transform (with self-verification).
- Addition of the asynchronous marker (`aslo:Asynchronous`).

Each fixture has a `fixture_id`; `ActionIds.derive` provides its deterministic `actionId`. `CaseState` manages the stages.

### 2.5 Evaluation and Display

- Extend the existing rules in `LogoutTranscriptProfileCase` to return the following for each `Rule`.
  - Presence or absence of a direct-delivery response, HTTP status, SAML message type, Destination, and signature verification result.
  - Success or failure of the control (correct Destination).
  - Success or failure of session survival.
- For display, extend `PublicCaseDiagnostics` with `fixture_id`, `probe_transport`, `response_kind`, and `control_outcome`.
- Define reason codes for each case and reflect them in `docs/26` and `docs/23` through the generators.

## 3. Items Requiring Interpretation Decisions (Risk of Incorrect Determinations Without Confirmation Before Implementation)

1. **HTTP response observation for b2**: Whether to treat the HTML body and HTTP status obtained through direct delivery as a "user-facing response." This is not identical to browser delivery, but differences in response bodies (success/failure) can be observed. The approved variant requires a "user-facing HTTP response," so the response from automated delivery is considered usable as evidence without modification.
2. **Multiple participants for r/s**: "3 participants" and "secondary_peer registration" require an operational action to register a 2nd SP on the target product. The Suite can expose a 2nd SP endpoint, but registration with the target IdP (Keycloak administration API, Shibboleth configuration, SimpleSAMLphp configuration) must be recorded as an operation. If only 1 participant can be registered, r cannot become `satisfied_with_note` (do not treat an incomplete test path as an optional feature not being invoked). Return NOT_VERIFIED (path not prepared) and implement multiple-participant registration.
3. **Advertisement condition for 18-c**: Add a fixture that restricts the SLO request endpoints in Suite SP metadata to Redirect to the existing metadata publication mechanism. Add it as a separate experimental Plan/endpoint without rewriting the existing published metadata.
4. **"No response" for b1**: Treat receipt of a direct-delivery HTTP response (any status) as delivery confirmation. If it contains no SAML LogoutResponse, return SATISFIED for "does not return LogoutResponse." If there is no HTTP response itself (connection interruption), return NOT_VERIFIED with UNKNOWN_DELIVERY.

## 4. Implementation Order

1. Support `OutboundKind.LOGOUT_PROBE` and `HttpOutboundSender`, session survival and modified fixtures, Coordinator extension, and `LogoutProbeScenarioTestCase` (x/y/z/aa/al/b/b1).
2. Execute x/y/z/aa/al/b/b1 against 3 real products and update the evidence and inventory.
3. 18-b (Redirect-only advertisement and binding observation), 18-c/d (Suite response binding fixture).
4. b2 (success/failure controls for HTTP response bodies), c (informational), r/s (multiple-participant registration).
5. Keycloak metadata observation path (classify and implement in a separate section).

## 5. Batch 1 Results (IIP-IDP17.x / y / z / aa / al)

Executed direct HTTP delivery (`LOGOUT_PROBE`) on the Suite side and session survival confirmation using a control LogoutRequest with the correct Destination against 3 products. If the control returns Success, the crafted request was not applied to the session.

| Case | Keycloak | Shibboleth | SimpleSAMLphp | Observed facts |
|---|---|---|---|---|
| `IIP-IDP17-x` | Success | Success | Success | The Destination-mismatched request was not applied, and the valid control request returned Success |
| `IIP-IDP17-y` | Warning | Warning | Warning | The modified signature was not applied. Use `satisfied_with_note` because the direction in which the IdP consumes a response was unobserved |
| `IIP-IDP17-z` | Warning | Warning | Warning | The content with an invalid signature was not relied upon (session preservation confirmed by the control). Same note as above |
| `IIP-IDP17-aa` | Warning | Warning | Warning | No SAML error response was returned for an invalid signature (equivalent to a SHOULD violation; no response is WARNING as specified by the variant) |
| `IIP-IDP17-al` | Success | Success | Success | A signature excluding SessionIndex from the signed content was not accepted |

- Unverified observations resolved through empirical evidence: 15 observations (546→531, distinct case IDs 179→174).
- Product configuration changes: 0. Checked the environment's SP metadata and confirmed that Keycloak's SLO URL and SimpleSAMLphp's SingleLogoutService point to the uncorrelated `/sp/slo`.
- Suite recreations: 3 (each implementation fix and redeployment). Run creations: 3 (one per product). Browser interactions by the user personally: 0 (automated by the protocol client).
- Identified environmental factor: Shibboleth SP-initiated SLO does not send LogoutResponse unless the hidden iframe (`_eventId=proceed`) on the logout completion page is followed. Updated the reference driver to follow the iframe (a real browser retrieves it automatically). This was outside the evaluation logic.

The next implementation targets are asynchronous SLO (b/b1/b2), HTTP-Redirect-only endpoints (18-b/c/d), and propagation (r/s and c).

## 6. Batch 2 Results (IIP-IDP17.b / b1 / b2 / x / y / z / aa / al)

Batch 1's direct HTTP probes **did not carry the browser's session Cookie**, so they bypassed session-dependent verification (SimpleSAMLphp redirects unauthenticated requests to login, so the x conclusion that "Destination mismatch is not applied" was actually unverified). Delivery was therefore changed to use an authenticated browser, replacing the approach with structured evidence recorded from browser-observed HTTP responses through the new `browser-response` API. For Keycloak's invalid-signature fixture, the IdP's LogoutResponse `InResponseTo` and the request Destination were compared from transcribed values, and the Suite verifier also confirmed that the signature was invalid.

| Case | Keycloak | Shibboleth | SimpleSAMLphp | Observed facts |
|---|---|---|---|---|
| `IIP-IDP17-b` | Success | Success | **Failed (Product)** | SSP returns LogoutResponse(Success) even for an asynchronous request with a Destination mismatch |
| `IIP-IDP17-b1` | **Failed (Product)** | Success | **Failed (Product)** | Keycloak/SSP return LogoutResponse(Success) for a trusted asynchronous request |
| `IIP-IDP17-b2` | Success | Success | Not verified | SSP did not return evidence that distinguishes success/failure pages (reason updated) |
| `IIP-IDP17-x` | Success | Success | **Failed (Product)** | SSP applies a synchronous request with a Destination mismatch and returns Success |
| `IIP-IDP17-y` | **Failed (Product)** | Warning | Warning | With `SAML Client Signature` disabled, Keycloak applies the presented invalid signature without verification |
| `IIP-IDP17-z` | **Failed (Product)** | Warning | Warning | Same as above (relies on the content) |
| `IIP-IDP17-aa` | Warning | Warning | Warning | None of the 3 products returns a SAML error response (equivalent to SHOULD) |
| `IIP-IDP17-al` | **Failed (Product)** | Success | Success | Keycloak accepts a signature that excludes SessionIndex from the signed content |

- Unverified observations resolved through empirical evidence: 23 observations (531→523, distinct case IDs 174→172). The remaining SSP observation for `IIP-IDP17.b2` remains Not verified because the meaning of the feedback page cannot be determined.
- Keycloak y/z/al were observed with the target client's `saml.client.signature=false` (default). Behavior may change if the configuration changes, so record the configuration together with the inventory's reason. The specification requires verification "if a consumed message has a signature," and this configuration does not conform to that obligation.
- Operations: product configuration changes 0, Suite recreations 4 (evidence API and delivery mechanism fixes), Run creations 3, browser interactions by the user personally 0.
- Verification: the Suite verifier returned `valid=false` for the Keycloak y request's signature, and the response was Success with a matching `InResponseTo`. The SSP x request's Destination was `https://samlscope.invalid/sp/slo`, and the response was Success.

The next implementation targets are HTTP-Redirect-only endpoints (18-b/c/d) and propagation (r/s and c).

## 7. Batch 3 Results (IIP-IDP18.b / c / d)

Created a configuration in which the Suite SP advertises only a Redirect response endpoint through target-product settings (Shibboleth: changed the SP SingleLogoutService in `suite.xml` to Redirect only and reloaded MetadataResolverService. Keycloak: removed the client attributes `post`/`soap` by setting them to empty strings, leaving only `redirect`. SimpleSAMLphp: already Redirect only). The Suite sends a signed Redirect (GET) LogoutRequest and determines the response binding from the transcript's HTTP method.

| Case | Keycloak | Shibboleth | SimpleSAMLphp | Observed facts |
|---|---|---|---|---|
| `IIP-IDP18.b` | Success | Success | Success | LogoutResponse is returned via HTTP-Redirect for a Redirect request |
| `IIP-IDP18.c` | Undetermined | Success | Undetermined | Shibboleth sends an IdP-initiated LogoutRequest via HTTP-Redirect |
| `IIP-IDP18.d` | Undetermined | Success | Undetermined | IdP consumes the LogoutResponse returned by Suite via Redirect (browser-observed 200, no failure display) |

- Unverified observations resolved through empirical evidence: 5 observations (523→518, distinct case IDs 172→171).
- The campaign cases for Keycloak/SimpleSAMLphp `IIP-IDP18.c/d` remain unstarted because the targets do not issue an IdP-initiated LogoutRequest (see `docs/31`). Applying the variant's "use `satisfied_with_note` if not issued" requires a path that records campaign completion (confirmation of non-issuance); record this as an unimplemented remaining task.
- Operations: Shibboleth SP metadata rewrite 1 and reload 1, Keycloak client attribute rewrite 1 (post/soap removal), Suite recreation 1, Run creations 4 (3 for 18-b, 1 for 18-c/d), user interactions 0.

## 8. Batch 4 Results (IIP-IDP17.c and Campaign Completion)

- `IIP-IDP17.c` (informational): Added a rule to record whether propagation occurs as information. Shibboleth sends an IdP-initiated LogoutRequest (`propagated=true`); Keycloak/SimpleSAMLphp do not (`propagated=false`). The Verdict is Warning for informational recording.
- Target-initiated logout campaigns waited indefinitely if the target did not issue a request. Added `POST /api/runs/{id}/target-initiated/conclude` to confirm non-issuance and record the rule's observation (`not-issued`). This provides a path to record confirmation of non-issuance as an operator/driver action, even when the Suite cannot itself observe "not issued."
- Unverified observations resolved through empirical evidence: 7 observations (518→511, distinct case IDs 171→168).

## 9. Batch 5 Results (IIP-IDP17.r / s)

| Case | Keycloak | Shibboleth | SimpleSAMLphp | Observed facts |
|---|---|---|---|---|
| `IIP-IDP17.r` | Warning | Undetermined | Warning | Keycloak/SimpleSAMLphp do not implement propagation itself, so use `satisfied_with_note` as specified by the variant (propagation not implemented). Shibboleth propagates, but a single participant cannot prove "continuation after failure" |
| `IIP-IDP17.s` | Warning | Undetermined | Warning | Same as above. Shibboleth has a single participant, so failure cannot be induced and there is no observation path for PartialLogout |

- Unverified observations resolved through empirical evidence: 4 observations (511→507). Refined the reasons for Shibboleth r/s to `slo.propagation.failure-induction-unavailable` / `slo.partial-logout.unobserved`, retaining the undetermined status.
- Implemented a **lightweight harness that registers additional SP participants only in IdP metadata** to determine Shibboleth's propagation continuation and PartialLogout (the Suite does not need to publish multiple SPs).
  - Additional participants: `sp-fail` (SLO always returns 500 at `/p/{plan}/sp/slo-fail`) and `sp-remain` (SLO at `/p/{plan}/sp/slo[/soap]?run={run}` correlates to the same Run).
  - Logging in to the primary SP + 2 participants in the same browser (Unsolicited SSO) adds 3 participants to the IdP session.
  - Confirmed progress: session establishment for 2 participants, arrival at the IdP's propagation UI (`PropagateLogout`), inducing 500 for the failing participant, and recording a propagation request to the remaining participant in the same Run.
  - Remaining blocker: Shibboleth's SLO Webflow completes through JS/subsequent transitions on the propagation page and sends LogoutResponse (PartialLogout) to the initiating SP. With a curl-equivalent driver, the snapshot expires after `_eventId=proceed`, preventing completion. JS execution equivalent to a real browser or identification of the correct continuation event is required.
  - The failure-induction endpoint `/p/{plan}/sp/slo-fail` (always 500, no evaluation) is implemented.

## 10. Audit of Determined Results (2026-09-15)

- Revised the rules so that campaign completion (`target-initiated/conclude`) alone does not produce Warning for "not issued" or "propagation not implemented." If evidence is absent, return to NOT_VERIFIED with a `not-observed` reason.
- Returned 18-d (IdP consumption of a Redirect response) to NOT_VERIFIED because observing a 200 page alone does not prove consumption, using `consumption-unobserved`/`unavailable` as the reasons.
- If the same Run contains multiple logout operations, a delayed request from a previous operation cannot be distinguished even if it reaches the same participant endpoint within the current window. Retain NOT_VERIFIED with `processing-ambiguous` for r until participant endpoints can identify individual operations (negative control tested).
- Reimplemented the Success condition for r (propagation continuation) using **correlation per execution**. Treat the window from the initiating request's recorded time to the correlated final response as 1 logout operation. Return Success only when the window contains (1) **a record of a 500 response issued** by the failing participant endpoint (the issued response rather than arrival time), (2) a subsequent request to a **different participant endpoint**, and (3) the Suite response to that request. Return NOT_VERIFIED with the corresponding reason for an event outside the window, overlapping windows, arrival only, no response, a retry to the same participant, unrelated PartialLogout, or different SessionIndex values between participants. Negative controls were verified in unit tests.
- Observations reverted by the audit: Keycloak/SimpleSAMLphp 17-c / 18-c/d / r/s (10 observations) and Shibboleth 18-d (1 observation). Retain Shibboleth 17-c (propagation measured) and 18-c (binding measured). The inventory changed from 507→518 observations.
- Metadata consumption principle: Do not use the Suite's XML→administration API attribute conversion as evidence of the product's metadata interpretation. Evaluate behavior after passing the original fixture through the product's own import path ([docs/33](33-keycloak-metadata-observation.md)).

## 11. Operation Cost Recording Policy

Record product configuration writes and restoration, administration API operations, Suite recreations, and Run counts for each batch, saving them in `docs/31` and each batch's `operations.json`. Include failed attempts.

## 12. Progress Categories

- Code implementation: Suite/core changes and tests.
- Connection to the real environment: Run creation, fixture delivery, response recording.
- Unverified observations resolved through empirical evidence: number of observations reaching Success/Failed/Warning.
- Diagnostic-only updates: number of observations whose reasons/classifications were updated without changing the Verdict.

## 13. Reference Product Remeasurement

SimpleSAMLphp's iframe logout required the Continue action on the product screen after a participant error. Added this action to the browser driver, but pressing the logout start button twice for the same action produced apparent Success for propagation continuation. In `ssp-slo-iframe-v131i`, which eliminated the duplicate click, PartialLogout was confirmed in the second-level StatusCode of the correlated final LogoutResponse, and only `IIP-IDP17.s` was adopted. `IIP-IDP17.r` remained NOT_VERIFIED because a continuation request to another participant could not be observed. Adoption verification in `dev/reference-acceptance/verify_ssp_iframe_partial_logout.py` checks the original SAML, failure response, single operation, and configuration restoration hashes.

For Shibboleth's IdP-initiated logout, rerecorded a request to another participant after the failure response and the correlated Suite response in `shibboleth-target-slo-v131`. This updates the evidence for the already adopted `IIP-IDP17.r` to a Run with byte-identical restoration of product metadata; it does not reduce the unverified count further. SP-initiated Webflow remeasurement in `shibboleth-webflow-v131` did not produce an attempt to the failing participant and did not determine `IIP-IDP17.s`.

## 14. Revocation Regarding Failure Induction for Asynchronous Logout

`IIP-IDP17-b2-idp-01` verifies user notification both for normal termination and for failure of the IdP's own session termination. Rejection of a request with an incorrect Destination is not evidence that a failure of the IdP's own session termination occurred. The approved definition uses the same failure induction as `IIP-IDP17.o` and retains unverified status if it cannot be induced safely.

<!--g1-literal--> The 2 former Success observations for Keycloak and Shibboleth relied on HTTP 400 for an incorrect Destination and HTTP 200 or a correlated LogoutResponse after a normal request. Independently examined these originals and revoked adoption because the approved condition for the failure side had not been proven. Without changing saved result.json or transcripts, `audit_async_feedback_failure_evidence.py` checks the pinned Run, original request, signature, asynchronous Extensions, correlation, and approved conditions, returning only the generator's adoption result to NOT_VERIFIED. This is not treated as a product violation.

The revised `LogoutAsyncScenarioTestCase` also does not determine this case from the previous incorrect-Destination test or differences in screens. Until implementation and evidence for inducing failure of the IdP's own session termination are available, it returns `slo.async.feedback.own-session-failure-unproven`. The conditions for synchronous logout and the other asynchronous cases are retained. Actual deployment is confirmed separately using the target Runner JAR's hash and deployment records.

The originals and independent audit are saved in `build/acceptance/reference-20261002/cross-cluster-audit/slo-async-feedback-adopted-boundary/`. No additional logins or product configuration changes were performed to investigate failure notification.

## 15. Execution and Adoption Conditions for SOAP Propagation Continuation

Use Shibboleth's SOAP logout path to execute a trial that returns a participant error and a control in which all participants succeed in the same Run. Apply the case-prepared signed metadata to the product and save each participant's login, the initiating request, propagation requests and responses, and the correlated final response as originals. The script changes, reads back, and restores the configuration, then compares the restored state with the state before the change.

The IdP's participant selection order does not necessarily match registration order. Do not adopt an attempt in which a fixed failing participant was selected midway, because it does not meet the approved condition that "the first participant fails." The failure fixture returns a signed Responder to the first genuine SOAP request bound to the Run, trial, and prepared metadata, then returns Success to subsequent participants. Do not reuse duplicate requests or requests from another scope as the first attempt.

The common evaluation process computes the propagation determination from the verified participant set, actual attempt order, signed responses, and sets at operation completion. Confirm satisfaction from originals showing attempts to the remaining participants after failure, and determine a violation when evidence of complete operation termination and unattempted participants are both present. Missing responses or insufficient completeness evidence retain unverified status.

The approved negative control performs actual HTTP/SAML execution against an isolated Suite-owned target. The normal target and the mutant target that stops after failure use the same prerequisites and evaluation process. Permission to access calibration originals must not become a condition that switches the evaluation result. Public receipt installation and adoption verification check product-origin originals so that calibration-target results are not adopted as reference-product results.

Formal adoption verifies agreement between the distributed JAR and the independently saved JAR, whole-case start/resume/evidence checks/reevaluation, the positive and negative controls, configuration restoration, and transcript/outbox immutability before and after reevaluation. Generate the comparison table and unverified inventory from saved results that passed this verification.

Real-product adoption is saved in `build/acceptance/reference-20261004/shibboleth-soap-slo-continuation-r5/`. The formal Run is `run_8N96KQNNSSG8NAK632QZRG5SCG`, and the target case is `IIP-IDP17-r-idp-01`. Confirmed the same whole-case results using the deployed JAR and independent archive: normal continuation was SATISFIED, and the isolated stop-after-error control was VIOLATED. Only the product-origin case was formally reevaluated, and Success was confirmed. Signed communication originals, configuration restoration, and transcript/outbox immutability before and after reevaluation were also checked.

`operation-counts.json` records the current attempt's costs; `failed-inclusive-operation-counts.json` records costs including preceding attempts. Scripts performed configuration changes, authentication, and protocol operations, with no interactions by the user personally and no product restarts. Originals from preceding interrupted attempts, nonconforming participant order, and failures of adoption helper processing are retained and are not counted as inventory reductions. Do not infer a violation for product behavior that still lacks completeness evidence from this stop-after-error control's result.
