# Complete inventory of unverified observations

This inventory covers NOT_VERIFIED observations remaining after the previous follow-up and their additional retests. Counts are observations per product, profile, and case. Only retested cases adopt evidence from new Runs; other existing evidence is retained. These counts do not represent a complete single Run or a conformance rate.

| Before retesting | Conclusive (Success / Failed / Warning) | Currently unverified | Distinct unverified case IDs |
|---:|---:|---:|---:|
| 594 | 391 | 203 | 81 |

## Breakdown

| Cause and current path | Count | Next scope |
|---|---:|---|
| No automated evaluation after browser completion | 0 | Suite implementation |
| Only some test conditions are implemented | 29 | Suite implementation |
| Evidence verification and attestation after configuration | 59 | Configuration and evidence |
| Attestation is disabled | 65 | Configuration and evidence |
| Additional metadata tests and observations are missing | 10 | Test-path investigation |
| Additional browser and SLO observations are missing | 12 | Test-path investigation |
| Old waiting results have expired by resume time | 0 | Retest in a new Run |
| Executed without a conclusive result | 28 | Individual diagnosis |

Classification uses result reason codes, interaction types, and Suite implementation. "Test-path investigation" does not guarantee that execution is possible. Configuration and evidence paths also cannot guarantee results merely by enabling attestation.

ECDSA cases retain browser waiting results from old Runs, but the currently registered class is EcSignatureSupportTestCase. Classification changed from missing automated evaluation to missing metadata retrieval and signature-control evidence. Verdicts and the total unverified count are unchanged. Current source and registration SHA-256 values are saved in implementation-audit.json.

Basic SP-initiated SLO IIP-IDP17-a and Redirect acceptance IIP-IDP18-a adopt evidence from product retests with dedicated implementations deployed. EncryptedID decryption IIP-IDP19-a was also retested, adopting Shibboleth success. Keycloak missing encryption keys and SimpleSAMLphp failed negative controls remain unverified with updated reasons.

## Correction to the explanation

The earlier explanation that "most required operations are incomplete" incorrectly grouped missing browser completion implementations, partial fixtures, and disabled evidence verification paths as incomplete operations. Unverified observations are not product failures, but neither do they establish that all tests are implemented and completed.

## Execution paths examined in this follow-up

Starting and resuming existing SLO Runs for all 3 products showed that common cases marked as waiting in old output had ended with delivery_or_response_unknown. active-probe FINISHED describes the state after this expiration. Positive controls and common tests were rerun in new Runs and additional evidence was saved. There were 5 additional Success observations; the remaining observations were 9 partially implemented cases and 4 pending signature evaluations. The start and resume APIs were each invoked once per product; one positive-control/common-test Run was created per product. Product configuration changes up to this point totaled 0. Signature-required configurations were then attempted for Keycloak and SimpleSAMLphp but failed at positive-control startup and were not adopted. Keycloak reception completion could not be confirmed, while the SimpleSAMLphp auxiliary client failed XML parsing. These are not classified as product FAIL. Each product incurred 2 configuration writes for changes and restoration, with restoration verified. Browser operations and human user operations were 0; execution used a protocol client.

Retests after additional implementation automatically confirmed unpublished-URL notes for all 3 products (Warning) and confirmed Subject mismatches for Keycloak and SimpleSAMLphp (Failed). These are not whole-product conformance conclusions. See the [additional implementation record](27-additional-implementation.md).

In Keycloak 26.7.2, IIP-MD05-av control, explicit-first, and all-false fixtures imported through the product Import client path reached the correct ACS. However, omitted default after explicit-false reached ACS 0 instead of ACS 1, and metadata with duplicate AssertionConsumerService indices under the same parent was also imported, read back, and used for a Success response. This FAIL is a limited measurement that correlated container images, startup times, runtime VERSION at campaign start and end, deletion read-back of each temporary client, original fixtures, request/response correlation, and the Suite runtime JAR within the same Run.

In Shibboleth IdP 5.2.3, IIP-MD05-av fixtures imported through the product FilesystemMetadataProvider path reached the correct ACS for control, explicit-first, and all-false. However, omitted default after explicit-false reached ACS 0 instead of ACS 1, and metadata with duplicate AssertionConsumerService indices under the same parent was also fetched and used for a Success response. This FAIL is a limited measurement correlating container images, startup times, runtime VERSION at campaign start and end, byte-identical restoration to the original configuration, original fixtures, request/response correlation, and the Suite runtime JAR within the same Run.

In SimpleSAMLphp 2.5.0, the 3 IIP-MD05-av default-selection controls reached the correct ACS. However, metadata with duplicate AssertionConsumerService indices under the same parent was also fetched and used for a Success response. This FAIL is a limited measurement correlating container images, startup times, runtime VERSION at campaign start and end, configuration restoration, native MDQ fetches, and request/response correlation within the same Run.

## Actions by cause

### No automated evaluation after browser completion

BrowserEvidenceTestCase returns browser.oracle-unavailable after completion. Implement the corresponding input generation, observations, and positive and negative controls.

### Only some test conditions are implemented

Implement input generation and observations for every approved variant. Additional logins alone cannot complete verification.

### Evidence verification and attestation after configuration

Execute every variant and control for the case and collect evidence supporting the result. Attestation is disabled in the current Plan. Checking configuration alone does not establish Success.

### Attestation is disabled

Review the target configuration, operations, and implementation documentation. Include only items supported by collected evidence in a test plan with evidence verification enabled.

### Additional metadata tests and observations are missing

Identify fixtures that have not been fetched or used, then run additional tests through the target import path. For rejection tests, silence alone does not establish success; determine how rejection can be proved.

### Additional browser and SLO observations are missing

Identify the required reception evidence. Check whether the Suite provides paths for IdP-initiated operations, alternate ACS endpoints, and additional Logout operations; implement missing paths.

### Old waiting results have expired by resume time

On resume, the cases ended with delivery_or_response_unknown. Execute positive controls and common tests in a new Run and save evidence separately from the original SLO results.

### Executed without a conclusive result

Inspect reason codes and positive controls to distinguish Suite, configuration, and product causes. Do not turn silence or insufficient evidence into a product FAIL.

## Additional retest results by product

| Test | Keycloak | Shibboleth | SimpleSAMLphp |
|---|---|---|---|
| `IIP-ALG01-a-idp-01` | Success | Success | Success |
| `IIP-ALG02-a-idp-01` | Success | Success | Success |
| `IIP-ALG03-a-idp-01` | Success | Success | Warning |
| `IIP-ALG04-a-idp-01` | Success | Success | Success |
| `IIP-ALG04-b-idp-01` | Success | Success | Success |
| `IIP-ALG06-a-idp-01` | Success | Success | Success |
| `IIP-ALG06-b-idp-01` | Success | Success | Not verified: case.pending-interaction |
| `IIP-ALG06-c-idp-01` | Success | Success | Not verified: case.pending-interaction |
| `IIP-ALG06-d-idp-01` | Not verified: case.pending-interaction | Not verified: case.pending-interaction | Not verified: case.pending-interaction |
| `IIP-ALG08-a-idp-01` | Success | Success | Not verified (outside this retest scope) |
| `IIP-ALG08-b-idp-01` | Success | Success | Not verified (outside this retest scope) |
| `IIP-ALG08-c-idp-01` | Not verified (outside this retest scope) | Success | Not verified (outside this retest scope) |
| `IIP-EXT01-a-idp-01` | Success | Success | Success |
| `IIP-EXT01-b-idp-01` | Success | Success | Success |
| `IIP-EXT01-c-idp-01` | Not verified: browser_fixture_partial | Success | Not verified: browser_fixture_partial |
| `IIP-G01-a-idp-01` | Not verified: browser_fixture_partial | Not verified: browser_fixture_partial | Not verified: browser_fixture_partial |
| `IIP-G02-a-idp-01` | Success | Success | Success |
| `IIP-G03-b-idp-01` | Success | Success | Success |
| `IIP-IDP01-a-idp-01` | Failed (Product) | Success | Success |
| `IIP-IDP02-a-idp-01` | Success | Success | Success |
| `IIP-IDP03-a-idp-01` | Failed (Product) | Success | Success |
| `IIP-IDP04-a-idp-01` | Failed (Product) | Success | Success |
| `IIP-IDP04-b-idp-01` | Not verified (outside this retest scope) | Success | Failed (Product) |
| `IIP-IDP05-a-idp-01` | Failed (Product) | Not verified (outside this retest scope) | Not verified (outside this retest scope) |
| `IIP-IDP06-a-idp-01` | Success | Success | Success |
| `IIP-IDP06-b-idp-01` | Not verified (outside this retest scope) | Success | Not verified: audit.force-authn-mechanism-access-unproven |
| `IIP-IDP08-a-idp-01` | Failed (Product) | Success | Not verified (outside this retest scope) |
| `IIP-IDP09-a-idp-01` | Not verified (outside this retest scope) | Not verified (outside this retest scope) | Success |
| `IIP-IDP11-a-idp-01` | Failed (Product) | Success | Not verified (outside this retest scope) |
| `IIP-IDP12-b-idp-01` | Success | Success | Not verified (outside this retest scope) |
| `IIP-IDP12-c-idp-01` | Failed (Product) | Success | Success |
| `IIP-IDP12-e-idp-01` | Success | Not verified (outside this retest scope) | Not verified (outside this retest scope) |
| `IIP-IDP17-a-idp-01` | Success | Success | Success |
| `IIP-IDP17-aa-idp-01` | Warning | Warning | Warning |
| `IIP-IDP17-ab-idp-01` | Warning | Warning | Warning |
| `IIP-IDP17-al-idp-01` | Failed (Product) | Success | Success |
| `IIP-IDP17-b-idp-01` | Success | Success | Failed (Product) |
| `IIP-IDP17-b1-idp-01` | Failed (Product) | Success | Failed (Product) |
| `IIP-IDP17-b2-idp-01` | Not verified: audit.slo-async-session-failure-unproven | Not verified: audit.slo-async-session-failure-unproven | Not verified: slo.async.feedback.unrecognized |
| `IIP-IDP17-c-idp-01` | Not verified: slo.propagation.not-observed | Warning | Warning |
| `IIP-IDP17-n-idp-01` | Success | Success | Not verified (outside this retest scope) |
| `IIP-IDP17-r-idp-01` | Not verified: slo.propagation.not-observed | Success | Not verified: slo.propagation.not-observed |
| `IIP-IDP17-s-idp-01` | Not verified: slo.partial-logout.not-observed | Failed (Product) | Success |
| `IIP-IDP17-u-idp-01` | Warning | Warning | Not verified (outside this retest scope) |
| `IIP-IDP17-x-idp-01` | Success | Success | Failed (Product) |
| `IIP-IDP17-y-idp-01` | Failed (Product) | Warning | Warning |
| `IIP-IDP17-z-idp-01` | Failed (Product) | Warning | Warning |
| `IIP-IDP18-a-idp-01` | Success | Success | Success |
| `IIP-IDP18-b-idp-01` | Success | Success | Success |
| `IIP-IDP18-c-idp-01` | Not verified: slo.redirect-request.not-observed | Success | Success |
| `IIP-IDP18-d-idp-01` | Not verified: slo.redirect-response.not-observed | Not verified: slo.redirect-response.unavailable | Not verified: slo.redirect-response.not-observed |
| `IIP-IDP19-a-idp-01` | Not verified: slo.encrypted-id.key-unavailable | Success | Not verified: slo.encrypted-id.negative-control-failed |
| `IIP-IDP19-b-idp-01` | Not verified (outside this retest scope) | Success | Not verified (outside this retest scope) |
| `IIP-IDP19-c-idp-01` | Not verified: slo.encrypted-id.multiple-keys.key-unavailable | Success | Failed (Product) |
| `IIP-MD01-a-idp-01` | Success | Success | Success |
| `IIP-MD02-a-idp-01` | Success | Success | Success |
| `IIP-MD02-b-idp-01` | Success | Not verified (outside this retest scope) | Success |
| `IIP-MD02-c-idp-01` | Success | Not verified (outside this retest scope) | Success |
| `IIP-MD02-d-idp-01` | Not verified (outside this retest scope) | Not verified (outside this retest scope) | Success |
| `IIP-MD03-a-idp-01` | Failed (Product) | Success | Success |
| `IIP-MD03-b-idp-01` | Failed (Product) | Success | Success |
| `IIP-MD03-c-idp-01` | Failed (Product) | Not verified (outside this retest scope) | Success |
| `IIP-MD03-d-idp-01` | Failed (Product) | Success | Success |
| `IIP-MD04-a-idp-01` | Failed (Product) | Success | Failed (Product) |
| `IIP-MD04-b-idp-01` | Failed (Product) | Success | Success |
| `IIP-MD04-c-idp-01` | Failed (Product) | Success | Failed (Product) |
| `IIP-MD05-a1-idp-01` | Success | Success | Not verified (outside this retest scope) |
| `IIP-MD05-a2-idp-01` | Success | Success | Not verified (outside this retest scope) |
| `IIP-MD05-a3-idp-01` | Not verified (outside this retest scope) | Not verified (outside this retest scope) | Not verified: case.pending-interaction |
| `IIP-MD05-a4-idp-01` | Success | Not verified (outside this retest scope) | Success |
| `IIP-MD05-a5-idp-01` | Success | Not verified (outside this retest scope) | Success |
| `IIP-MD05-ad-idp-01` | Warning | Success | Success |
| `IIP-MD05-ae-idp-01` | Warning | Warning | Warning |
| `IIP-MD05-af-idp-01` | Warning | Warning | Warning |
| `IIP-MD05-ah-idp-01` | Success | Success | Success |
| `IIP-MD05-am-idp-01` | Not verified (outside this retest scope) | Warning | Warning |
| `IIP-MD05-an-idp-01` | Not verified (outside this retest scope) | Success | Failed (Product) |
| `IIP-MD05-ao-idp-01` | Not verified (outside this retest scope) | Success | Success |
| `IIP-MD05-ap-idp-01` | Not verified (outside this retest scope) | Success | Success |
| `IIP-MD05-aq-idp-01` | Not verified (outside this retest scope) | Success | Success |
| `IIP-MD05-ar-idp-01` | Not verified (outside this retest scope) | Success | Success |
| `IIP-MD05-as-idp-01` | Failed (Product) | Success | Success |
| `IIP-MD05-av-idp-01` | Failed (Product) | Failed (Product) | Failed (Product) |
| `IIP-MD05-b-idp-01` | Failed (Product) | Success | Failed (Product) |
| `IIP-MD05-c-idp-01` | Success | Success | Success |
| `IIP-MD05-c2-idp-01` | Not verified (outside this retest scope) | Success | Success |
| `IIP-MD05-cd-idp-01` | Failed (Product) | Not verified (outside this retest scope) | Failed (Product) |
| `IIP-MD05-d-idp-01` | Success | Success | Success |
| `IIP-MD05-e-idp-01` | Success | Success | Success |
| `IIP-MD05-e5-idp-01` | Success | Success | Success |
| `IIP-MD05-e7-idp-01` | Not verified (outside this retest scope) | Success | Not verified (outside this retest scope) |
| `IIP-MD05-e8-idp-01` | Failed (Product) | Success | Failed (Product) |
| `IIP-MD05-e9-idp-01` | Not verified: metadata.algorithms.local-policy-unverified | Success | Not verified: metadata.algorithms.local-policy-unverified |
| `IIP-MD05-ea-idp-01` | Not verified: metadata.algorithms.local-policy-unverified | Success | Not verified: metadata.algorithms.local-policy-unverified |
| `IIP-MD05-eb-idp-01` | Failed (Product) | Success | Failed (Product) |
| `IIP-MD05-f-idp-01` | Not verified (outside this retest scope) | Success | Not verified: audit.metadata-full-ui-controls-unproven |
| `IIP-MD05-f7-idp-01` | Warning | Warning | Warning |
| `IIP-MD05-f8-idp-01` | Warning | Warning | Warning |
| `IIP-MD05-f9-idp-01` | Success | Success | Warning |
| `IIP-MD05-fa-idp-01` | Warning | Warning | Warning |
| `IIP-MD05-fb-idp-01` | Warning | Warning | Warning |
| `IIP-MD05-ff-idp-01` | Success | Success | Success |
| `IIP-MD05-fg-idp-01` | Warning | Warning | Warning |
| `IIP-MD05-fh-idp-01` | Warning | Warning | Warning |
| `IIP-MD05-fi-idp-01` | Warning | Warning | Warning |
| `IIP-MD05-fj-idp-01` | Warning | Warning | Success |
| `IIP-MD05-g-idp-01` | Success | Not verified (outside this retest scope) | Success |
| `IIP-MD06-a-idp-01` | Failed (Product) | Success | Not verified (outside this retest scope) |
| `IIP-MD06-a1-idp-01` | Not verified (outside this retest scope) | Not verified (outside this retest scope) | Success |
| `IIP-MD06-a2-idp-01` | Not verified (outside this retest scope) | Success | Success |
| `IIP-MD06-a3-idp-01` | Warning | Warning | Not verified (outside this retest scope) |
| `IIP-MD06-a5-idp-01` | Failed (Product) | Success | Failed (Product) |
| `IIP-MD06-a6-idp-01` | Not verified (outside this retest scope) | Success | Success |
| `IIP-MD06-a7-idp-01` | Failed (Product) | Success | Failed (Product) |
| `IIP-MD06-a8-idp-01` | Success | Success | Success |
| `IIP-MD06-a9-idp-01` | Failed (Product) | Success | Success |
| `IIP-MD06-ab-idp-01` | Failed (Product) | Success | Not verified (outside this retest scope) |
| `IIP-MD06-b-idp-01` | Failed (Product) | Success | Success |
| `IIP-MD06-c-idp-01` | Success | Success | Success |
| `IIP-MD07-a-idp-01` | Failed (Product) | Success | Success |
| `IIP-MD07-b-idp-01` | Not verified (outside this retest scope) | Success | Success |
| `IIP-MD12-a-idp-01` | Success | Not verified (outside this retest scope) | Success |
| `IIP-MD12-b-idp-01` | Failed (Product) | Not verified (outside this retest scope) | Success |
| `IIP-MD12-c-idp-01` | Success | Not verified (outside this retest scope) | Success |
| `IIP-MD12-d-idp-01` | Failed (Product) | Not verified (outside this retest scope) | Success |
| `IIP-SSO01-ae-idp-01` | Success | Success | Success |
| `IIP-SSO01-ak-idp-01` | Warning | Warning | Warning |
| `IIP-SSO01-al-idp-01` | Success | Success | Success |
| `IIP-SSO01-an-idp-01` | Success | Not verified (outside this retest scope) | Success |
| `IIP-SSO01-cz-idp-01` | Not verified (outside this retest scope) | Not verified (outside this retest scope) | Success |
| `IIP-SSO01-d-idp-01` | Failed (Product) | Not verified (outside this retest scope) | Failed (Product) |
| `IIP-SSO01-em-idp-01` | Success | Success | Success |
| `IIP-SSO01-ep-idp-01` | Not verified (outside this retest scope) | Not verified (outside this retest scope) | Warning |
| `IIP-SSO01-fp-idp-01` | Success | Success | Success |
| `IIP-SSO01-fr-idp-01` | Warning | Warning | Warning |
| `IIP-SSO01-g-idp-01` | Success | Success | Success |
| `IIP-SSO01-ga-idp-01` | Not verified (outside this retest scope) | Success | Not verified (outside this retest scope) |
| `IIP-SSO01-gb-idp-01` | Not verified (outside this retest scope) | Success | Not verified (outside this retest scope) |
| `IIP-SSO01-gc-idp-01` | Not verified (outside this retest scope) | Failed (Product) | Not verified (outside this retest scope) |
| `IIP-SSO01-gd-idp-01` | Warning | Warning | Warning |
| `IIP-SSO01-gi-idp-01` | Success | Not verified (outside this retest scope) | Success |
| `IIP-SSO01-gj-idp-01` | Not verified (outside this retest scope) | Success | Not verified (outside this retest scope) |
| `IIP-SSO01-k-idp-01` | Success | Success | Not verified (outside this retest scope) |
| `IIP-SSO01-z-idp-01` | Warning | Warning | Warning |
| `IIP-SSO03-b-idp-01` | Success | Not verified (outside this retest scope) | Success |
| `IIP-SSO04-a-idp-01` | Success | Success | Success |
| `IIP-SSO05-a-idp-01` | Not verified (outside this retest scope) | Success | Not verified (outside this retest scope) |
| `IIP-SSO05-a2-idp-01` | Not verified (outside this retest scope) | Success | Success |
| `IIP-SSO05-a3-idp-01` | Success | Success | Success |
| `IIP-SSO07-b-idp-01` | Failed (Product) | Failed (Product) | Failed (Product) |

## Case-level inventory

Product columns list profiles with remaining unverified observations. Where a case has several reasons, the cause column lists each. An em dash means absence from this unverified set; it does not establish whole-product PASS.

| Test | Keycloak | Shibboleth | SimpleSAMLphp | Cause |
|---|---|---|---|---|
| `IIP-ALG06-b-idp-01` | — | — | browser_sso_idp、ecp_idp | Additional browser and SLO observations are missing |
| `IIP-ALG06-c-idp-01` | — | — | browser_sso_idp、ecp_idp | Additional browser and SLO observations are missing |
| `IIP-ALG06-d-idp-01` | browser_sso_idp、ecp_idp | browser_sso_idp、ecp_idp | browser_sso_idp、ecp_idp | Additional browser and SLO observations are missing |
| `IIP-ALG07-a-idp-01` | browser_sso_idp、ecp_idp、metadata_idp、single_logout_idp | browser_sso_idp、ecp_idp、metadata_idp、single_logout_idp | browser_sso_idp、ecp_idp、metadata_idp、single_logout_idp | Attestation is disabled |
| `IIP-ALG08-a-idp-01` | — | — | browser_sso_idp、ecp_idp | Evidence verification and attestation after configuration |
| `IIP-ALG08-b-idp-01` | — | — | browser_sso_idp、ecp_idp | Evidence verification and attestation after configuration |
| `IIP-ALG08-c-idp-01` | browser_sso_idp、ecp_idp | ecp_idp | browser_sso_idp、ecp_idp | Attestation is disabled |
| `IIP-EXT01-c-idp-01` | browser_sso_idp、ecp_idp、metadata_idp、single_logout_idp | — | browser_sso_idp、ecp_idp、metadata_idp、single_logout_idp | Only some test conditions are implemented |
| `IIP-G01-a-idp-01` | browser_sso_idp、ecp_idp、metadata_idp、single_logout_idp | browser_sso_idp、ecp_idp、metadata_idp、single_logout_idp | browser_sso_idp、ecp_idp、metadata_idp、single_logout_idp | Only some test conditions are implemented |
| `IIP-G02-c-idp-01` | browser_sso_idp | browser_sso_idp | browser_sso_idp | Attestation is disabled |
| `IIP-IDP04-b-idp-01` | browser_sso_idp | — | — | Evidence verification and attestation after configuration |
| `IIP-IDP06-b-idp-01` | browser_sso_idp | — | browser_sso_idp | Executed without a conclusive result |
| `IIP-IDP10-d-idp-01` | browser_sso_idp | — | — | Executed without a conclusive result |
| `IIP-IDP11-a-idp-01` | — | — | browser_sso_idp | Evidence verification and attestation after configuration |
| `IIP-IDP12-d-idp-01` | — | browser_sso_idp | — | Executed without a conclusive result |
| `IIP-IDP12-f-idp-01` | browser_sso_idp | browser_sso_idp | browser_sso_idp | Executed without a conclusive result |
| `IIP-IDP16-a-idp-01` | ecp_idp | ecp_idp | ecp_idp | Evidence verification and attestation after configuration |
| `IIP-IDP17-b2-idp-01` | single_logout_idp | single_logout_idp | single_logout_idp | Executed without a conclusive result |
| `IIP-IDP17-c-idp-01` | single_logout_idp | — | — | Executed without a conclusive result |
| `IIP-IDP17-r-idp-01` | single_logout_idp | — | single_logout_idp | Executed without a conclusive result |
| `IIP-IDP17-s-idp-01` | single_logout_idp | — | — | Executed without a conclusive result |
| `IIP-IDP18-c-idp-01` | single_logout_idp | — | — | Executed without a conclusive result |
| `IIP-IDP18-d-idp-01` | single_logout_idp | single_logout_idp | single_logout_idp | Executed without a conclusive result |
| `IIP-IDP19-a-idp-01` | single_logout_idp | — | single_logout_idp | Executed without a conclusive result |
| `IIP-IDP19-b-idp-01` | single_logout_idp | — | single_logout_idp | Evidence verification and attestation after configuration |
| `IIP-IDP19-c-idp-01` | single_logout_idp | — | — | Executed without a conclusive result |
| `IIP-IDP20-a-idp-01` | single_logout_idp | single_logout_idp | single_logout_idp | Evidence verification and attestation after configuration |
| `IIP-IDP21-a-idp-01` | single_logout_idp | single_logout_idp | single_logout_idp | Attestation is disabled |
| `IIP-MD02-d-idp-01` | metadata_idp | — | — | Additional metadata tests and observations are missing |
| `IIP-MD05-a-idp-01` | metadata_idp | metadata_idp | metadata_idp | Evidence verification and attestation after configuration |
| `IIP-MD05-a1-idp-01` | — | — | metadata_idp | Additional metadata tests and observations are missing |
| `IIP-MD05-a2-idp-01` | — | — | metadata_idp | Additional metadata tests and observations are missing |
| `IIP-MD05-a3-idp-01` | metadata_idp | metadata_idp | metadata_idp | Additional metadata tests and observations are missing |
| `IIP-MD05-a8-idp-01` | metadata_idp | metadata_idp | metadata_idp | Evidence verification and attestation after configuration |
| `IIP-MD05-ac-idp-01` | metadata_idp | metadata_idp | metadata_idp | Evidence verification and attestation after configuration |
| `IIP-MD05-am-idp-01` | metadata_idp | — | — | Additional metadata tests and observations are missing |
| `IIP-MD05-an-idp-01` | metadata_idp | — | — | Additional metadata tests and observations are missing |
| `IIP-MD05-ao-idp-01` | metadata_idp | — | — | Additional metadata tests and observations are missing |
| `IIP-MD05-ap-idp-01` | metadata_idp | — | — | Evidence verification and attestation after configuration |
| `IIP-MD05-aq-idp-01` | metadata_idp | — | — | Evidence verification and attestation after configuration |
| `IIP-MD05-ar-idp-01` | metadata_idp | — | — | Evidence verification and attestation after configuration |
| `IIP-MD05-aw-idp-01` | metadata_idp | metadata_idp | metadata_idp | Evidence verification and attestation after configuration |
| `IIP-MD05-c1-idp-01` | metadata_idp | metadata_idp | metadata_idp | Evidence verification and attestation after configuration |
| `IIP-MD05-c2-idp-01` | metadata_idp | — | — | Evidence verification and attestation after configuration |
| `IIP-MD05-c3-idp-01` | metadata_idp | metadata_idp | metadata_idp | Evidence verification and attestation after configuration |
| `IIP-MD05-c5-idp-01` | metadata_idp | metadata_idp | metadata_idp | Attestation is disabled |
| `IIP-MD05-c6-idp-01` | metadata_idp | metadata_idp | metadata_idp | Attestation is disabled |
| `IIP-MD05-c7-idp-01` | metadata_idp | metadata_idp | metadata_idp | Attestation is disabled |
| `IIP-MD05-d1-idp-01` | metadata_idp | metadata_idp | metadata_idp | Evidence verification and attestation after configuration |
| `IIP-MD05-e7-idp-01` | metadata_idp | — | metadata_idp | Evidence verification and attestation after configuration |
| `IIP-MD05-e9-idp-01` | metadata_idp | — | metadata_idp | Executed without a conclusive result |
| `IIP-MD05-ea-idp-01` | metadata_idp | — | metadata_idp | Executed without a conclusive result |
| `IIP-MD05-f-idp-01` | metadata_idp | — | metadata_idp | Evidence verification and attestation after configuration / Executed without a conclusive result |
| `IIP-MD05-f5-idp-01` | metadata_idp | metadata_idp | metadata_idp | Only some test conditions are implemented |
| `IIP-MD06-a-idp-01` | — | — | metadata_idp | Evidence verification and attestation after configuration |
| `IIP-MD06-a1-idp-01` | metadata_idp | — | — | Additional metadata tests and observations are missing |
| `IIP-MD06-a2-idp-01` | metadata_idp | — | — | Evidence verification and attestation after configuration |
| `IIP-MD06-a3-idp-01` | — | — | metadata_idp | Evidence verification and attestation after configuration |
| `IIP-MD06-a6-idp-01` | metadata_idp | — | — | Evidence verification and attestation after configuration |
| `IIP-MD06-ab-idp-01` | — | — | metadata_idp | Evidence verification and attestation after configuration |
| `IIP-MD07-b-idp-01` | metadata_idp | — | — | Evidence verification and attestation after configuration |
| `IIP-MD09-a-idp-01` | metadata_idp | metadata_idp | metadata_idp | Attestation is disabled |
| `IIP-MD09-b-idp-01` | metadata_idp | metadata_idp | metadata_idp | Attestation is disabled |
| `IIP-MD11-a-idp-01` | metadata_idp | metadata_idp | metadata_idp | Evidence verification and attestation after configuration |
| `IIP-SSO01-de-idp-01` | browser_sso_idp | browser_sso_idp | browser_sso_idp | Attestation is disabled |
| `IIP-SSO01-dy-idp-01` | browser_sso_idp | browser_sso_idp | browser_sso_idp | Attestation is disabled |
| `IIP-SSO01-e-idp-01` | browser_sso_idp | browser_sso_idp | browser_sso_idp | Attestation is disabled |
| `IIP-SSO01-ea-idp-01` | browser_sso_idp | browser_sso_idp | browser_sso_idp | Attestation is disabled |
| `IIP-SSO01-eb-idp-01` | browser_sso_idp | browser_sso_idp | browser_sso_idp | Only some test conditions are implemented |
| `IIP-SSO01-ec-idp-01` | browser_sso_idp | browser_sso_idp | browser_sso_idp | Attestation is disabled |
| `IIP-SSO01-ed-idp-01` | browser_sso_idp | browser_sso_idp | browser_sso_idp | Attestation is disabled |
| `IIP-SSO01-ee-idp-01` | browser_sso_idp | browser_sso_idp | browser_sso_idp | Attestation is disabled |
| `IIP-SSO01-ep-idp-01` | browser_sso_idp | browser_sso_idp | — | Additional browser and SLO observations are missing |
| `IIP-SSO01-f-idp-01` | browser_sso_idp | — | browser_sso_idp | Executed without a conclusive result |
| `IIP-SSO01-ga-idp-01` | browser_sso_idp | — | browser_sso_idp | Evidence verification and attestation after configuration |
| `IIP-SSO01-gb-idp-01` | browser_sso_idp | — | browser_sso_idp | Evidence verification and attestation after configuration |
| `IIP-SSO01-gc-idp-01` | browser_sso_idp | — | browser_sso_idp | Evidence verification and attestation after configuration |
| `IIP-SSO01-gj-idp-01` | browser_sso_idp | — | browser_sso_idp | Evidence verification and attestation after configuration |
| `IIP-SSO01-i2-idp-01` | browser_sso_idp | browser_sso_idp | browser_sso_idp | Only some test conditions are implemented |
| `IIP-SSO05-a1-idp-01` | browser_sso_idp | browser_sso_idp | browser_sso_idp | Attestation is disabled |
| `IIP-SSO05-a8-idp-01` | browser_sso_idp | browser_sso_idp | browser_sso_idp | Attestation is disabled |

## Classification of inconclusive observations (diagnosis)

This classification describes unverified reasons without changing Verdicts. feature-absent means feature absence confirmed from public metadata or equivalent evidence; role-inapplicable means a variant is not consumed in the role; evidence-form-mismatch means mismatch with the approved evidence format; operator-attestation-available means verification through operator testimony is possible; suite-observation-gap means Suite implementation can resolve the gap.

| Diagnosis | Count | Meaning | Proposed display |
|---|---:|---|---|
| `suite-observation-gap` | 118 | The Suite observation or execution path is not connected | Not verified that can be resolved by implementing the Suite path |
| `operator-attestation-available` | 67 | Can be verified through attestation or operator testimony | Can be verified through operator testimony, with one answer per case. Attestation is disabled in the current Plan |
| `evidence-form-mismatch` | 10 | The product response does not match the evidence format required by the approved evaluation conditions | Not verified because the evidence format does not match the approved conditions; requirement interpretation needs review |
| `role-inapplicable` | 8 | A variant requests an artifact that the target does not consume in its role | The variant is not consumed in the IdP role and is outside the execution scope; inapplicability has been established |

### role-inapplicable

`IIP-EXT01-c-idp-01`


### evidence-form-mismatch

`IIP-IDP10-d-idp-01`, `IIP-IDP12-d-idp-01`, `IIP-IDP12-f-idp-01`, `IIP-IDP19-a-idp-01`, `IIP-IDP19-c-idp-01`, `IIP-SSO01-f-idp-01`


### operator-attestation-available

`IIP-ALG07-a-idp-01`, `IIP-ALG08-c-idp-01`, `IIP-G02-c-idp-01`, `IIP-IDP06-b-idp-01`, `IIP-IDP21-a-idp-01`, `IIP-MD05-c5-idp-01`, `IIP-MD05-c6-idp-01`, `IIP-MD05-c7-idp-01`, `IIP-MD09-a-idp-01`, `IIP-MD09-b-idp-01`, `IIP-SSO01-de-idp-01`, `IIP-SSO01-dy-idp-01`, `IIP-SSO01-e-idp-01`, `IIP-SSO01-ea-idp-01`, `IIP-SSO01-ec-idp-01`, `IIP-SSO01-ed-idp-01`, `IIP-SSO01-ee-idp-01`, `IIP-SSO05-a1-idp-01`, `IIP-SSO05-a8-idp-01`


### suite-observation-gap

`IIP-ALG06-b-idp-01`, `IIP-ALG06-c-idp-01`, `IIP-ALG06-d-idp-01`, `IIP-ALG08-a-idp-01`, `IIP-ALG08-b-idp-01`, `IIP-G01-a-idp-01`, `IIP-IDP04-b-idp-01`, `IIP-IDP11-a-idp-01`, `IIP-IDP16-a-idp-01`, `IIP-IDP17-b2-idp-01`, `IIP-IDP17-c-idp-01`, `IIP-IDP17-r-idp-01`, `IIP-IDP17-s-idp-01`, `IIP-IDP18-c-idp-01`, `IIP-IDP18-d-idp-01`, `IIP-IDP19-b-idp-01`, `IIP-IDP20-a-idp-01`, `IIP-MD02-d-idp-01`, `IIP-MD05-a-idp-01`, `IIP-MD05-a1-idp-01`, `IIP-MD05-a2-idp-01`, `IIP-MD05-a3-idp-01`, `IIP-MD05-a8-idp-01`, `IIP-MD05-ac-idp-01`, `IIP-MD05-am-idp-01`, `IIP-MD05-an-idp-01`, `IIP-MD05-ao-idp-01`, `IIP-MD05-ap-idp-01`, `IIP-MD05-aq-idp-01`, `IIP-MD05-ar-idp-01`, `IIP-MD05-aw-idp-01`, `IIP-MD05-c1-idp-01`, `IIP-MD05-c2-idp-01`, `IIP-MD05-c3-idp-01`, `IIP-MD05-d1-idp-01`, `IIP-MD05-e7-idp-01`, `IIP-MD05-e9-idp-01`, `IIP-MD05-ea-idp-01`, `IIP-MD05-f-idp-01`, `IIP-MD05-f5-idp-01`, `IIP-MD06-a-idp-01`, `IIP-MD06-a1-idp-01`, `IIP-MD06-a2-idp-01`, `IIP-MD06-a3-idp-01`, `IIP-MD06-a6-idp-01`, `IIP-MD06-ab-idp-01`, `IIP-MD07-b-idp-01`, `IIP-MD11-a-idp-01`, `IIP-SSO01-eb-idp-01`, `IIP-SSO01-ep-idp-01`, `IIP-SSO01-ga-idp-01`, `IIP-SSO01-gb-idp-01`, `IIP-SSO01-gc-idp-01`, `IIP-SSO01-gj-idp-01`, `IIP-SSO01-i2-idp-01`


## Evidence

The local `build/acceptance/reference-20260914/remaining-audit/inventory.json` records every current unverified observation with its Run, case ID, reason code, test conditions, controls, next action, and source result.json SHA-256. Complete additional retest results are in `retest-delta.json`; the earlier set is in `baseline.json`. Original results and approved case definitions are unchanged.

Implementation references: `BrowserEvidenceTestCase`, `IdpExecutableBrowserFixtureScenarioTestCase`, `ApprovedConfigCaseRegistry`, and `AttestedOutcomeTestCase`. Case conditions are taken from `tests/cases.yaml`.

Inventory generation compares every unverified observation against approved conditions, positive and negative controls, and the source result.json Run, SHA-256, Verdict, and reason code. Any mismatch fails generation. Complete case conditions, variant groups, prerequisites, and interpretation constraints are stored in `unresolved-contract-audit.json`. Passing this audit does not establish completed evaluation implementation.

Regenerate: `.venv/bin/python dev/reference-acceptance/generate_remaining_audit.py --evidence-root build/acceptance/reference-20260914/remaining-audit`.
