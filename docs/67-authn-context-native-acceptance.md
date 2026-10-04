# Native authentication context comparison and formal determination

<!--g1-literal--> Unverified observations decreased 462→458; distinct case IDs remain 156. Shibboleth browser_sso_idp formally adopted Success for minimum, better, and candidate preference, and Failed for maximum. These determinations do not extend to other products or profiles.

| Case | Result | Observation |
|---|---|---|
| IIP-SSO01.ga | Success | Successful ClassRef/DeclRef selections are at least the requested low. Unachievable requests receive signed errors. |
| IIP-SSO01.gb | Success | Both select medium, stronger than low. Unachievable requests receive signed errors. |
| IIP-SSO01.gc | Failed (Product) | ClassRef selects medium; DeclRef selects low. Subsequent exact medium succeeds with the same configuration, SP, and login input, demonstrating availability of the stronger candidate. |
| IIP-SSO01.gj | Success | For both reference types, reversing candidate order also changes the response selection to follow the first candidate. |

## Implementation and determination evidence

`AuthnContextCampaignInputs` binds local adapter inputs to the Run and target metadata hash and generates signed requests through the existing preloaded browser campaign. Inputs specify sending conditions; they are not confirmation of strength order or Verdict. Existing request signatures, RelayState, and ACS correlation are preserved. This uses the existing campaign request generation path and adds no case-side HTTP sending.

The campaign uses standard Shibboleth `shibboleth.AuthnComparisonRules` and Password-flow `supportedPrincipals`. ClassRef uses `saml2`; DeclRef uses the product's bundled `saml2declref` definition. Custom URNs identify comparison values, and the product's own comparison rules define their order. Suite does not determine the strength of real authentication methods. The maximum test makes only low/medium available and requests high as the upper bound. This is temporary test configuration for an isolated reference IdP, not a recommendation for general deployment.

Configuration was checked against [Shibboleth AuthenticationFlowSelection](https://shibboleth.atlassian.net/wiki/spaces/IDP5/pages/3199505253/AuthenticationFlowSelection) and bundled `authn-system.xml`. Original and applied configuration, read-back before and after each exchange, and restoration hashes are saved. Every read-back also verifies that Password is the only enabled authentication flow.

The original-evidence collector checks the same preloaded metadata, published ACS/destination, request ID and response, signature, decryption, Audience, and SubjectConfirmation. Request inputs other than RequestedAuthnContext are fixed by fingerprint. Preparation evidence is loaded from a local file and rechecked against original hashes and references. Formal maximum evaluation also verifies originals from availability controls; configuration labels alone do not establish candidate availability.

`AuthnContextConfigurationTestCase` is registered in the CONFIG registry. Cases return Outcome; Evaluator converts formal PASS/FAIL. All determinations here are `attested=false`. Missing responses, HTTP page appearance, or successful configuration saves alone are insufficient evidence.

## Evidence and verification

<!--g1-literal--> Formal Run: `run_FWMYG7PY9SWNNNMYQA39DS4B8D`. Signatures, decryption, and correlation passed for 20 round trips: 16 evaluation conditions + 4 availability controls. After original configuration restoration, 1 normal SSO prerequisite round trip was completed, cases were started, and the evidence was formally evaluated.

Evidence is in `build/acceptance/reference-20260918/shibboleth-authn-context-acceptance/`; formal results are in `shibboleth-authn-context-evaluation/`. `verify_authn_context_acceptance.py` checks equality with regenerated preparation evidence, installed-record read-back, positive and negative controls, the normal SSO prerequisite, formal results, and unchanged original references before inventory adoption. Original and local evidence retain their Git ignore settings.

<!--g1-literal--> Related targeted tests passed: SAML 2 + Runner 13. Aggregation checks executed 4 positive controls, 8 reference-specific negative controls, 4 missing-condition checks, and 4 unverified-control checks. Missing, duplicate, mismatched-response, and unverified-control mutations of observed evidence returned NOT_VERIFIED for every case. This does not mean the entire test suite ran.

<!--g1-literal--> G1 generated-document consistency and structural checks passed 46/46. Known G2 protected-implementation signature differences remain separately unresolved; this is not release readiness.

## Configuration and operation records

<!--g1-literal--> The initial attempt overlooked that the reference container's startup command was `sleep infinity`; Tomcat did not start after container restart. It ended with 0 protocol round trips. Configuration was restored byte-for-byte, Tomcat started, and metadata HTTP 200 verified. The next attempt observed 16 round trips; the final attempt with availability controls observed 20. Failed attempts are included in total operations.

<!--g1-literal--> Across this implementation batch: product file writes 28 (configuration 24, temporary metadata 4), product container restarts 8, explicit Tomcat starts 7, service reloads 2, temporary metadata deletions 4, protocol round trips 37. Suite input writes 3, preparation evidence installations 4. Image builds 2; Suite/forwarder container recreations 2 each. User interactions 0. Also recorded: 1 CONFIG API rejection for an extra note and 1 incorrect result retrieval URL; neither is a product operation.

The configuration count is substantial. The final campaign groups conditions sharing configuration and switches among normal comparison, maximum, and restoration. Initial startup failure and the retry to add controls are not part of the future routine procedure. Next improvements are sharing the normal SSO prerequisite import with campaign preparation and grouping execution by product to avoid additional small case-specific restarts.

<!--g1-literal--> Native image: `samlscope:reference-authn-context-v53`; digest: `sha256:10f435a8289e3ea733fb8b54a06c8513e7f9eeac70f3804997c6cf5a1bb75241`. Source hash: `authn-context-runtime-v53/source.json`. Unrelated existing SOAP changes were excluded from the isolated build. No separate fine-grained commits were created.
