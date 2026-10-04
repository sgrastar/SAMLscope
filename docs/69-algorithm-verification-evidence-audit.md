# Evidence audit for shared signature algorithm determinations

After EC signature evidence integration, inspection of shared signature tests found a remaining branch in `IdpSignedRequestScenarioTestCase.observeUnavailable` converting the operation report `operator-reported-no-saml-response` into successful algorithm verification. Absence of an observed response does not necessarily mean product signature rejection and cannot establish ALG01 / ALG02 receiver verification capability.

The case was changed to return `NOT_VERIFIED` for this event. The existing treatment also remains: accepting a corrupted request where signatures are optional does not prove lack of support. Paths containing normal responses and correlated rejection responses remain evaluable.

## Treatment of historical results

<!--g1-literal--> Revalidation targets comprise 12 observations for `IIP-ALG01-a-idp-01` and `IIP-ALG02-a-idp-01`: browser_sso_idp for every product, plus Shibboleth metadata_idp / ecp_idp / single_logout_idp. Each formal result is PASS with `attested=false`, but its evidence references contain only 1 normal successful response and no proof of corrupted-request rejection.

Original `result.json` files are unchanged. `audit_algorithm_verification_evidence.py` checks each original result's Run, hash, determination, evidence count, and successful response in referenced Transcripts, then treats it as `audit.algorithm-verification-controls-unproven` in inventory and comparison tables. Aggregate auditing permits differences between original results and inventory determinations only when every item exactly matches this specific revalidation target list. Arbitrary audit flags cannot bypass result checking.

<!--g1-literal--> EC signature demonstration resolved 2 observations in the same batch. Unverified observations: 458 before changes → 456 after EC adoption → 468 after historical-result auditing; distinct case IDs remain 156. This returns insufficient Suite evidence to revalidation and adds no product FAIL.

## Verification and operations

<!--g1-literal--> `IdpSignedRequestScenarioTestCaseTest` and `EcSignatureSupportTestCaseTest` ran together; 11 tests passed. The added negative control checks that after a normal SHA-256 / RSA-SHA256 response, treating every corrupted request as “no response” cannot yield a successful final result. The entire Java/Web test suite was not rerun.

`samlscope:reference-algorithm-evidence-guard-v55` was deployed and successful startup confirmed. Evidence and build/deployment records are in `build/acceptance/reference-20260918/algorithm-evidence-guard-v55/`. Separately from normal operation records, `deployment.json` records this audit's additional build and Suite/forwarder container recreations. No product configuration changes or manual interactions were added.

<!--g1-literal--> G1 generated-document consistency and structural checks passed 46/46. G2 is 20/21; existing G2-30 remains because protected implementation source differs from the signed approval commit. Release gates are not complete.

## Continuing implementation

Shibboleth reruns and formal adoption are recorded in [Product audit integration for shared signature tests](70-native-signed-request-acceptance.md). This section and the opening return-to-revalidation counts are audit history, separately from the current inventory.

Shared signature tests are being connected to request-specific product audit rejection records. The foundation is EC matching of normal requests, body digests, signature values, response signatures, and request-ID audit records; SHA-256 creation/verification and RSA-SHA256 creation/verification conditions must each be confirmed independently. EC PASS does not substitute for shared-algorithm PASS.

Other test branches handling the same no-response event still need auditing against approved conditional obligations and required observations. This fix does not complete an audit of all tests.
