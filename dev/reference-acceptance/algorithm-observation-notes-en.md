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
