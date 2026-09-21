# Native certificate acceptance diagnosis

## Pending batch: MDIOP runtime interpretation

The native certificate adapter now also covers `IIP-MD06-a9-idp-01`. Its approved interpretation explicitly permits sharing observations with MD12.d while requiring runtime use after metadata acceptance. The existing receipt reader binds the imported native certificate and enabled signature policy to subsequent signed requests and request-specific native decisions. The MDIOP comparison requires the complete certificate matrix, including expiration; MD12.d continues to exclude expiration from its required conditions. Missing conditions and unobserved runtime decisions remain unverified. A critical-extension rejection mutant and missing-condition controls were added to the comparison tests for the next grouped run.

The first implementation was held for grouped validation. It has now been deployed and formally evaluated as described below. The existing MD12 adoption remains unchanged. `VerifyNativeCertificateEvidence.java` includes the runtime case in a separate replay without overwriting earlier proof artifacts.

## MDIOP adoption with the accumulated configuration/UI batch

The certificate runtime adapter, attribute-policy reevaluation, UI URL comparison/receipt reader, and fixed URL-campaign trust key were built together in the isolated distribution and deployed as `samlscope:reference-config-ui-v64`. API, Runner, and SAML jar hashes were checked against the running container. The unrelated SOAP source change was excluded. The prior containers were retained for recovery.

<!--g1-literal--> The grouped certificate, attribute-policy, UI comparison/receipt-boundary and UI fixture checks passed 30 tests. The first attempt found a stale UI fixture test expecting excluded schemes to be absent from the preloaded input inventory. The earlier committed implementation already included those negative-control inputs, which are advertised without navigating or executing them. That assertion was corrected, and the affected SAML test was rerun; the successful Runner tests were not repeated.

The original certificate Run `run_AX3ZB21BWSJM8S2HMPXRD8N7K6` was replayed using the final production classes. `verified-native-certificate-v64.json` records the full runtime matrix and rejection of modified receipts. The normal control and request-specific invalid-signature controls remain required. MDIOP interpretation includes expiration as well as the not-yet-valid condition; the MD12.d exclusion is not reused.

The updated runtime reconciled the saved evidence during the protocol-evidence status read. Consequently, the later explicit evaluation POST had no newly completed cases. The formal result in `evaluation-v64/result.json` nevertheless contains the persisted `VIOLATED / FAIL` result for `IIP-MD06-a9-idp-01`, with the exact original transcript/native-event references. The adoption verifier compares that result with the production replay, fixed target metadata, complete condition set and unchanged transcripts. The observed native import/signature policy rejected valid requests with expired and future certificates after accepting their metadata; this is classified as a product result for this case, not a Suite delivery/setup failure.

<!--g1-literal--> The generated ledger decreased from 429 observations / 151 case IDs to 428 / 150. Existing MD12 results were not counted again. The contract audit reports no inconsistencies. Image digest: `sha256:2f7e66a117eb21377c862ee2e5694fa55362868ff19ed7818be0e9915b93e26a`.

<!--g1-literal--> Operations: Docker build 1; Suite and forwarding-container recreation 1 each; explicit formal evaluation POST 1, preceded by the reconciling status read. Product configuration writes, product restarts, new SAML requests, human operations and new receipt installations were 0. The existing receipt was reused. Build attempts, final checks, jar readbacks, source hashes and operations are retained in `config-ui-runtime-v64/`. No commit was created. UI request-bound nonuse collection remains incomplete; deployment does not turn that missing evidence into a verified result.

The native Keycloak signature observer is now connected to a certificate matrix as well as the existing RSA/EC campaigns. Original metadata goes through the product console. The collector retains request-specific HTTP facts and synchronous native `LOGIN_ERROR / invalid_signature` events. The observer, realm settings, and temporary clients are restored after the batch.

Run `run_AX3ZB21BWSJM8S2HMPXRD8N7K6` in `keycloak-native-certificate-signature/observations/metadata_idp` contains the original fixtures, requests, signed responses, import readbacks, and restoration evidence.

`VerifyNativeCertificateRequests.java` verifies each positive request against the exact advertised certificate, verifies that the paired malformed signature is invalid, and verifies signatures on any correlated Success responses using the pinned target metadata. `diagnose_native_certificate_requests.py` binds those proofs to the exact certificate saved by the product, enabled signature checking, request hashes, request time windows, and direct HTTP error responses. A generic error, silence, a stale event, or a certificate label is insufficient.

<!--g1-literal--> All 9 positive request signatures were cryptographically valid. All 9 negative requests had invalid signatures and matching native rejection events. The valid requests using expired and not-yet-valid certificates also received request-bound native signature rejection. The other 7 positive requests returned signed Success responses: the normal control, critical extension, non-critical extension, missing digitalSignature usage, unrelated extendedKeyUsage, empty subject, and unknown CA.

The certificate validity interval was compared with the actual request timestamp, and the native API certificate matched the original fixture bytes. These findings distinguish valid Suite requests rejected by the product from malformed Suite inputs. They do not yet assign a conformance outcome: the approved MD12 case adapter, complete native-evidence negative controls, and formal evaluation remain to be connected. The raw Run results and ledger have not been rewritten on the basis of this diagnostic.

<!--g1-literal--> Unresolved observations remain 434 / 154 distinct case IDs. The certificate cluster now has concrete request-bound evidence instead of only an inconclusive login result.

<!--g1-literal--> Operations: original fixture imports 9; temporary client creation/deletion 10 each including the ordinary baseline; realm event configuration writes 2; observer install/removal 1 each; product restarts 2. AuthnRequests 19 and Responses 8. Docker builds, Suite recreations, and human operations were 0. Individual UI clicks and all console management reads were not instrumented and are explicitly left unmeasured. Counts and source hashes are recorded in `operation-summary.json`.

The Java verifier compiled and ran over all retained public originals; the Python diagnostic completed with the evidence bindings above. No full Java/Web suite was repeated and no commit was created. The final observer-removal restart and realm/client restoration were confirmed.

## Native case adapter

`NativeCertificateConfigurationTestCase` now decorates the approved metadata CONFIG cases through `ApprovedConfigCaseRegistry` and the runtime's local `certificate-evidence` directory. A receipt cannot supply an outcome: the reader checks the immutable Run originals, exact imported certificate, native signature policy, every positive request signature and negative control, signed correlated responses, and request-bound native rejection events. An invalid present receipt prevents fallback acceptance. The existing metadata observation path remains available when there is no native receipt.

The native policy must match across conditions, except for the certificate inputs and the exact campaign marker in endpoints already advertised by each original fixture. Endpoint settings are checked against those fixtures before normalization. Unknown-CA issuer comparison uses the encoded X.500 name produced by the fixture builder, avoiding display-order ambiguity.

<!--g1-literal--> The production reader successfully replayed all 9 conditions from the retained Run. It rejected 15 receipt mutations covering changed target/Run/originals, incomplete restoration, missing or duplicate conditions, disabled signature checks, certificate mismatch, policy changes, wrong native event identity/time/issuer, generic HTTP errors, missing native errors, and unrelated responses. The internal comparison identifies the expired and future-certificate rejections for MD12.b and the future-certificate rejection for MD12.d; expiration is not added to MD12.d's approved variant list.

`export_native_certificate_receipt.py` exports only source-bound observations after the original diagnostic and restoration checks pass. `VerifyNativeCertificateEvidence.java` exercises the production reader against public originals without product changes or private-key export. The adapter records the receipt digest and rejects a receipt that changes during evaluation.

Formal runtime adoption is still pending. The comparison replay is not itself a ledger update. The new Java code and test sources compile; the full Java/Web suite has not been repeated for this increment. Comparison-unit controls were authored for the next grouped validation.

## Formal adoption on the reference runtime

The accumulated certificate, display-name, transport-observation, and Recorder-boundary changes are deployed as `samlscope:reference-native-certificate-v60`. The installed API, Runner, and SAML jar hashes match the isolated distribution. The unrelated local SOAP Fault edit was excluded from that distribution.

<!--g1-literal--> A grouped check ran 31 tests across the certificate comparison, display comparison, TLS observation, HTTP sender, and metadata generator; all passed. The first Gradle build exposed an unavailable transitive Bouncy Castle dependency in Runner. Issuer-name matching was changed to the equivalent standard Java X.500 principal, after checking the original certificate's RFC2253 issuer. No dependency was added. The production replay then repeated successfully against the final distribution, including all 15 invalid-evidence controls.

The original certificate Run was formally reevaluated through the protocol-evidence API. MD12.b and MD12.d return `VIOLATED`, centrally mapped to `FAIL`. The former records expired and not-yet-valid certificate rejections; the latter records the not-yet-valid rejection. These are failures of the observed native import/signature policy, not conclusions drawn from silent requests, generic HTTP errors, or setup failure. `verify_native_certificate_acceptance.py` requires native export/source agreement, receipt installation readback, mutation checks, exact formal evidence references, target metadata identity, and unchanged transcripts before either result enters the ledger. Every original request and response is retained.

<!--g1-literal--> The generated comparison and unresolved ledger now report 432 observations / 152 distinct case IDs, down from 434 / 154. Both reductions are Keycloak `metadata_idp` certificate cases. No other case is adopted from this Run.

<!--g1-literal--> Adoption operations: Docker build 1, Suite recreation 1, forwarding-container recreation 1, local receipt installation/readback 1 each, formal evidence evaluation 1. No new protocol requests, product configuration writes, product restarts, or human operations were needed for this replay. The previous containers remain available for recovery. Build sources, grouped checks, deployed hashes, and operation counts are recorded in `native-certificate-runtime-v60/`. No commit was created.
