# Product audit integration for shared signature tests

After returning historical results that treated no response as success to revalidation, Shibboleth shared signature tests were rerun using request originals and product audits. `NativeSignedRequestEvidence` connects to the formal browser registry and recorded-evidence reevaluation. Cases return Outcome; the existing Evaluator determines Verdict.

<!--g1-literal--> ALG01 (SHA-256 creation/verification) and ALG02 (RSA-SHA256 creation/verification) ran on browser_sso_idp / metadata_idp / ecp_idp / single_logout_idp, producing 8 formal PASS observations. The inventory decreased 468 → 460; distinct case IDs remain 156. These execute each profile's shared BROWSER case, not signatures specific to ECP SOAP or SLO messages.

## Originals and determination conditions

Existing outbox scenarios send VALID / TAMPERED_ACS / BAD_REFERENCE / BAD_SIGNATURE_VALUE unchanged. Collection tools do not create test messages; they execute Suite's active-probe path.

The verifier regenerates original fixtures from Run signing keys, request IDs, times, registered destinations, and ACS, then checks byte equality with Transcript originals. This avoids treating unrelated malformed XML as a corrupted-signature fixture and confirms the changed request component. It also correlates outbox action ID, case ID, and fixture ID.

Normal conditions verify the actual signature of the correlated successful response using the target metadata key and check the applicable DigestMethod or SignatureMethod. Abnormal conditions check Shibboleth `MessageAuthenticationError` matching each request ID, SP entityID, binding, profile, and time. No response alone, generic execution errors, or another request's audit records cannot yield success. Conflicting SAML responses also prevent adoption.

Local receipts bind target metadata, Run, case, and original hashes. Missing evidence is reported as receipt / originals / fixture / native-event / producer-signature diagnostics. Existing manual “no response” reports remain unverified. The scenario definition key was also updated to avoid confusing algorithm tests in progress under historical definitions with the new tests.

## Tests and collection fixes

<!--g1-literal--> Alongside request-matrix original verification, each observation checked 9 controls: wrong-run / wrong-case / wrong-request / wrong-event / wrong-metadata / missing-condition / duplicate-fixture / wrong-request-original / wrong-response. All 72 mismatch/missing-evidence controls returned NOT_VERIFIED. These replay native records and add no product observations.

Initial collection mistook `case.in-progress` for completion and stopped after normal login without running the request matrix. Receipt generation detected missing required originals and stopped before result adoption. The termination condition was changed to explicit status vocabulary and rerun with new Runs. Initial attempts are retained with verified configuration restoration.

This batch performed compilation, original replay and negative controls, formal API evaluation, and inventory consistency checks. The full Java/Web test suite was not repeated. No commit was made.

## Operations and evidence

<!--g1-literal--> Across initial and corrected attempts: Run creations 8, product file writes 28 (including audit-format changes/restoration), metadata service reloads 16, temporary metadata deletions 8, product restarts and Tomcat starts 4 each. Recorded AuthnRequests 44, Responses 20. Suite build, Suite recreation, and forwarder recreation 1 each; receipt installations 8; formal evaluation API calls 4. User interactions 0.

Audit-format changes were shared across all profiles to avoid case-specific restarts. Each Run's temporary provider was restored; the audit format was finally restored to original bytes. Operation records: `build/acceptance/reference-20260918/native-signed-request-runtime-v56/acceptance-operations.json`.

Adopted evidence: `build/acceptance/reference-20260918/shibboleth-native-signed-request-v2/<profile>/`. `verification/protocol-verification.json` contains originals and negative controls; `evaluation/result.json` contains formal results; `receipt-installation.json` contains installation/read-back. Initial unadopted attempts remain in sibling `shibboleth-native-signed-request/`.

Execution image: `samlscope:reference-native-signed-request-v56`. `verify_native_signed_acceptance.py` checks configuration restoration, originals, control results, installation, formal determinations, and matching evidence references. Only cases passing this check enter comparison and inventory tables. Historical returns to revalidation remain recorded; Keycloak and SimpleSAMLphp evidence gaps remain unverified.

```sh
.venv/bin/python dev/reference-acceptance/verify_native_signed_acceptance.py build/acceptance/reference-20260918
.venv/bin/python dev/reference-acceptance/generate_remaining_audit.py --evidence-root build/acceptance/reference-20260914/remaining-audit
.venv/bin/python dev/reference-acceptance/generate_comparison.py --evidence-root build/acceptance/reference-20260914
```
