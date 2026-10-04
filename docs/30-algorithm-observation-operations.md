# Follow-up tests and configuration and operation costs

This record measures only follow-up tests on 2026-09-15. Earlier environment setup and attempts have unmeasured counts and durations, which are not treated as zero. Additional evidence is collected for existing Runs and conclusion deltas are compared under the same case definitions. This before/after comparison is limited to the selected cases.

Human user actions, agent browser actions on behalf of the user, and API/file configuration changes are counted separately. Each configuration write, including restoration, counts once; service reloads are separate. Opening a page, entering a field, clicking, and manual continuation each count as one browser action; automatic redirects do not. Scripted execution does not eliminate the configuration work itself.

## Changes in conclusions

| Product | Not verified: before | After | Reduction |
|---|---:|---:|---:|
| Keycloak | 12 | 8 | 4 |
| Shibboleth | 12 | 8 | 4 |
| SimpleSAMLphp | 6 | 6 | 0 |

The deltas above cover only the selected cases. Conclusions for other cases are unchanged. See the [complete inventory](26-unverified-case-inventory.md) for all unverified counts and retest results by product.

These counts are observations per product, profile, and case. They are distinct from operation and configuration counts.

## Workload

| Product | Configuration writes (including restoration) | Service reloads | Agent browser actions | Human user actions |
|---|---:|---:|---:|---:|
| Keycloak | 1 | 0 | 0 | 0 |
| Shibboleth | 1 | 1 | 0 | 0 |
| SimpleSAMLphp | 0 | 0 | 0 | 0 |

Auxiliary connection containers were started 0 times. Configuration retries caused by temporary script errors are retained in the ledger and are not classified as product defects.

The local Suite verification environment was restarted 1 times, and forwarding containers 1 times. These are counted separately from product configuration operations.

Operation durations are measured tool-call durations or script elapsed times. They exclude investigation, decisions, code authoring, and time between calls, and do not estimate human manual effort. Unmeasured durations are shown as an em dash.

## Operation details

| # | Product | Operation | Execution method | Configuration writes | Reloads | Browser actions | Measured seconds |
|---:|---|---|---|---:|---:|---:|---:|
| 1 | Keycloak | Observed target-generated EncryptedAssertion algorithms in new browser_sso_idp Runs | protocol_client | 0 | 0 | 0 | 832.6 | <!--g1-literal-->
| 2 | Shibboleth | Observed target-generated EncryptedAssertion algorithms in new browser_sso_idp Runs | protocol_client | 0 | 0 | 0 | 950.4 | <!--g1-literal-->
| 3 | SimpleSAMLphp | Checked whether encrypted Assertions were present in a new browser_sso_idp Run | protocol_client | 0 | 0 | 0 | 169.2 | <!--g1-literal-->
| 4 | Keycloak | Observed ECP response encryption algorithms in a new ecp_idp Run with PAOS destination registered | protocol_client | 1 | 0 | 0 | — | <!--g1-literal-->
| 5 | Keycloak | Failed ecp_idp probe attempt before positive-control login | protocol_client | 0 | 0 | 0 | 0.6 | <!--g1-literal-->
| 6 | Shibboleth | Observed ECP response encryption algorithms in a new ecp_idp Run with PAOS destination registered and reloaded | protocol_client | 1 | 1 | 0 | — | <!--g1-literal-->
| 7 | suite | Deployed implementation image v20 and recreated Suite and forwarding containers | docker | 0 | 0 | 0 | 6.0 | <!--g1-literal-->

## Cases with changed conclusions

| Product | Profile | Test | Before | After | Reason code |
|---|---|---|---|---|---|
| Keycloak | browser_sso_idp | `IIP-ALG04-b-idp-01` | NOT_VERIFIED | PASS | `browser.encryption.aes256-gcm.decrypted` |
| Keycloak | browser_sso_idp | `IIP-ALG06-b-idp-01` | NOT_VERIFIED | PASS | `browser.encryption.rsa-oaep.decrypted` |
| Keycloak | ecp_idp | `IIP-ALG04-b-idp-01` | NOT_VERIFIED | PASS | `browser.encryption.aes256-gcm.decrypted` |
| Keycloak | ecp_idp | `IIP-ALG06-b-idp-01` | NOT_VERIFIED | PASS | `browser.encryption.rsa-oaep.decrypted` |
| Shibboleth | browser_sso_idp | `IIP-ALG04-a-idp-01` | NOT_VERIFIED | PASS | `browser.encryption.aes128-gcm.decrypted` |
| Shibboleth | browser_sso_idp | `IIP-ALG06-a-idp-01` | NOT_VERIFIED | PASS | `browser.encryption.rsa-oaep-mgf1p.decrypted` |
| Shibboleth | ecp_idp | `IIP-ALG04-a-idp-01` | NOT_VERIFIED | PASS | `browser.encryption.aes128-gcm.decrypted` |
| Shibboleth | ecp_idp | `IIP-ALG06-a-idp-01` | NOT_VERIFIED | PASS | `browser.encryption.rsa-oaep-mgf1p.decrypted` |
## Scope and results

<!--g1-literal--> The scope comprises 6 IIP-ALG04 / IIP-ALG06 cases (Keycloak / Shibboleth / SimpleSAMLphp × browser_sso_idp / ecp_idp = 36 observations). In addition, 9 SSO/SLO cases lacking evidence through NormalFlow evaluation were investigated (SSO01-g/k/z/ep, SSO03-b, SSO05-a/a2, and IDP17-n/u).

The implemented common evaluator decrypts the EncryptedAssertion in a correctly correlated Response with the Suite Run key, then reads EncryptionMethod (block cipher), EncryptedKey EncryptionMethod (key transport), DigestMethod, and MGF. Algorithm names in public metadata alone do not establish Success. NOT_VERIFIED is retained if decryption fails, there is no encrypted Assertion, only algorithms different from those requested are observed, or only some of the 4 combinations are covered. ECP correlation through outbox actions was also completed, including cases using the AuthnRequest ID inside SOAP.

<!--g1-literal--> Actual execution established 8 Success observations.

- Keycloak: confirmed `IIP-ALG04-b` (AES256-GCM) and `IIP-ALG06-b` (rsa-oaep) in both browser_sso_idp and ecp_idp.
- Shibboleth: confirmed `IIP-ALG04-a` (AES128-GCM) and `IIP-ALG06-a` (rsa-oaep-mgf1p) in both browser_sso_idp and ecp_idp.
- SimpleSAMLphp: no conclusive results because there were 0 encrypted Assertions among 161 browser_sso_idp cases. ECP was not executed in this follow-up. <!--g1-literal-->

Reasons observations remain inconclusive:

- Keycloak did not generate AES128-GCM or rsa-oaep-mgf1p. `IIP-ALG06-d` explicitly specifies MGF1-SHA256, so it does not prove the default MGF1-SHA1 with MGF omitted. `IIP-ALG06-c` covers only 1 of 4 combinations. <!--g1-literal-->
- Shibboleth did not generate AES256-GCM or rsa-oaep (1.1). `IIP-ALG06-d` uses rsa-oaep-mgf1p and is outside scope; `IIP-ALG06-c` covers only 1 combination. <!--g1-literal-->
- SimpleSAMLphp did not generate encrypted Assertions.

## Product and Suite causes

- Product: inability to observe required algorithm generation with defaults remains unverified rather than FAIL. Whether algorithms can be selected through product configuration or metadata declarations is unconfirmed.
- Suite (resolved in this batch): ALG04/06 lacked evaluation code and returned `browser.oracle-unavailable`. Common generation-side evaluation was implemented, and missing ECP correlation was completed.
- Suite (remaining): requiring multiple algorithms within one Run, as in `IIP-ALG06-c`, needs a design for Suite SP metadata algorithm advertisement or input generation.

## SSO/SLO observation investigation

The cases and missing evidence are listed below. All have evaluation code, but actual products do not generate the required evidence, so conclusions before and after the follow-up are unchanged.

| Case ID | Product and profile | Missing evidence |
|---|---|---|
| `IIP-SSO01-g-idp-01`, `IIP-SSO01-z-idp-01` | 3 products / browser_sso_idp | IdP-initiated (unsolicited) successful Response. The Suite has no input-generation path. | <!--g1-literal-->
| `IIP-SSO01-ep-idp-01` | 3 products / browser_sso_idp | VersionMismatch SAML Response for major≠2. The current path ends with a non-SAML error. | <!--g1-literal-->
| `IIP-SSO01-k-idp-01` | 3 products / browser_sso_idp | Bearer confirmation for at least 2 distinct accepted ACS destinations. Keycloak IDP12-a is FAIL and ignores the requested index. | <!--g1-literal-->
| `IIP-SSO03-b-idp-01` | 3 products / browser_sso_idp | At least 2 kinds of POST error responses. is_passive is the only trigger producing a SAML error. | <!--g1-literal-->
| `IIP-SSO05-a-idp-01`, `IIP-SSO05-a2-idp-01` | Other than Keycloak | Persistent NameID requests/responses. Keycloak already has PASS. |
| `IIP-IDP17-n-idp-01`, `IIP-IDP17-u-idp-01` | 3 products / single_logout_idp | LogoutRequest issued by the target IdP. No target-initiated logout input path exists. | <!--g1-literal-->

The Suite can complete ECP correlation, which is implemented. Unsolicited SSO and target-initiated logout require initiating operations on the target product; existing code automatically evaluates the received evidence. Because initiation depends on product-specific URLs and UI, it is kept as a separate human user procedure. Additional unit-test conditions are not counted as resolution of unverified observations.

## Verification scope and evidence

Related Runner tests and API/Web tests were executed together locally and passed, including `EncryptionAlgorithmObservationTest`. G1 generated-document equality and structural checks were executed separately. Actual product evidence is saved under `build/acceptance/reference-20260915/algorithm-observation-batch/`, including Run result.json, report.html, transcripts, operation logs, and comparisons. This directory is outside Git tracking.

## Limitations

- Completing this batch does not mean 0 unverified observations. Remaining ALG04/06 conditions and missing SSO/SLO observations are unresolved. <!--g1-literal-->
- ECP Runs contain started but incomplete cases when the ALG cases become conclusive. Evaluation used only evidence from completed ALG cases.
- Shibboleth PAOS registration added changes to a local trust file with its signature removed; restoration was not performed. Keycloak only added client redirectUris.

Regenerate: `.venv/bin/python dev/reference-acceptance/generate_interaction_report.py --evidence-root build/acceptance/reference-20260915/algorithm-observation-batch/interaction --output docs/30-algorithm-observation-operations.md --date 2026-09-15 --focus-cases IIP-ALG04-a-idp-01,IIP-ALG04-b-idp-01,IIP-ALG06-a-idp-01,IIP-ALG06-b-idp-01,IIP-ALG06-c-idp-01,IIP-ALG06-d-idp-01 --notes-file dev/reference-acceptance/algorithm-observation-notes-en.md`.
