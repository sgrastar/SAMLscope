# Additional implementation and retesting

2026-09-14. Phase 1 is not ready for release. This corrects earlier completion records that treated registration of every case ID as equivalent to implementation of input generation, observation, and evaluation for every condition.

## Implementation in this batch

| Target | Change | Verification and limits |
|---|---|---|
| Continuous metadata retrieval | Send the authentication request only after the current fixture has actually been fetched. Before retrieval, return a waiting page that checks again automatically | Fetching the previous fixture, using an incorrect token, or fetching only a redirect does not release the wait. This path targets periodic retrieval; implementations that fetch only after encountering an unknown signing key cannot advance through it |
| Metadata redirects | Select the key for the content response using the Run's retrieval mode and record retrieval of the final content | Verify the actual AuthnRequest signature with the certificate fetched from the URL without a token. Reject content URLs for an old variant |
| IIP-MD05.fi (IdP) | Automatically inspect the Target's published URLs: Logo, InformationURL, and PrivacyStatementURL | Restrict evidence to the target entityID and IdP role. For non-HTTPS URLs, pass a RECOMMENDED-violation outcome to Evaluator. Note URLs that are not published. Separate from consumer URL processing in IIP-MD05.fh |
| IIP-G02.a | Compare a normal control with string-length boundaries and detect error responses | Other character and type conditions have not been executed; passing the boundary alone does not produce Success |
| IIP-G03.b | After the normal control, detect a successful response to an AuthnRequest containing DOCTYPE | Silence is not successful rejection. Response-side conditions remain unimplemented. The Suite cannot yet sign DOCTYPE requests for Plans requiring signatures |
| IIP-SSO07.b | Compare the explicit Subject with the identifier in a successful response. Decrypt encrypted Assertions and EncryptedID with the Run key | Partial implementation detecting identifier mismatches. A failed normal control or inability to decrypt does not produce a product FAIL. Request encryption and all confirmation-method conditions remain unimplemented |
| CONFIG reevaluation after reception | Automatically evaluate IIP-IDP09.a and IIP-SSO01.ez/.fd/.fe after a new Transcript arrives | Exclude unconfirmed correlations and incomplete histories. Confirm encryption capability by decrypting ciphertext in a successful response with the Run key, rather than by observing an empty EncryptedAssertion |
| Browser paths without an automatic oracle | Return NOT_VERIFIED with `browser.oracle-unavailable` instead of requesting an invalid completion action | Exposes an implementation gap; it does not increase the number of confirmed conformance observations |

## Retesting real products

Tests used new Runs with existing Plans. The browser SSO profile executed the normal flow and registered active test sequence; the metadata profile inspected published metadata. Execution used a protocol client. This is not completion of a new real-browser acceptance test.

| Test | Keycloak | Shibboleth | SimpleSAMLphp |
|---|---|---|---|
| IIP-MD05.fi | Warning: target URLs not published | Warning: target URLs not published | Warning: target URLs not published |
| IIP-G02.a | Not verified: conditions remain | Not verified: conditions remain | Not verified: conditions remain |
| IIP-G03.b | Not verified: Suite request signing unsupported | Not verified: conditions remain | Not verified: Suite request signing unsupported |
| IIP-SSO07.b | Failed: Subject mismatch | Not verified: conditions remain | Failed: Subject mismatch |
| IIP-IDP09.a | Success: decryption confirmed | Success: decryption confirmed | Not verified: encrypted output not obtained |

The Subject violation was checked against the normal control, request/response correlation, and the absence of a NameIDPolicy instruction changing Format. Keycloak was also checked after decryption. Raw identifier values and private keys are not stored in the verification summary. This does not claim that the product as a whole is nonconforming.

Shibboleth's periodic HTTP retrieval completed the control and HTTP 301, 302, and 307 tests. The extra poll token on the configured URL and the fixed delay after sending the authentication request are no longer needed. The auxiliary connection container was started and stopped; product settings were restored and checked by readback.

The comparison table adopts new-Run evidence only for cases changed in this batch and retains other existing evidence. Unverified observations decreased from 589 to 584. The new conclusions are Subject violations and notes for unpublished URLs; they are not all counted as Success.

## Work performed

Product testing after this implementation required 2 configuration writes including restoration and 2 service reloads. Configuration changes were limited to Shibboleth HTTP retrieval. There were 6 new Runs, with 1 restart each of the verification Suite and forwarding container. User actions and delegated browser actions were 0. Cumulative counts and attempt details are integrated into the [operation record](25-interaction-execution-cost.md).

## Verification and approval boundaries

All Runner/API regression tests in the ordinary working tree passed, including the new positive and negative controls. Generated documents and G1 structural validation also passed. G2 detected differences from the approved API source and blocked at G2-30; it did not declare approval. Checks cover sending before retrieval, signing keys at redirect destinations, evidence from a different entity or role, string boundaries, DTDs, Subject mismatches, delayed reception, wrong keys, unconfirmed correlation, incomplete history, and failed normal controls.

The verification image is `samlscope:reference-additional-v5`. It preserves the active approved definitions and incorporates only classes changed in this batch. Unrelated OIDC and administration-UI changes are excluded. The previous container is retained in a stopped state.

In the independent NameID reapproval working tree, Runner and this batch's API regression tests passed, but some full API tests failed because of mismatched existing coverage digests and functional-profile references. This is not a successful release verification of that entire working tree. Updating G2 approval for these API source changes, and reconciling and integrating the NameID definitions and functional profiles, remain incomplete.

## Remaining release work

### Ongoing metadata implementation

The following changes are additional implementation in the development working tree. They are not yet included in the real-product retests or active image described above. Real-product unverified counts have not been updated.

| Target | Added inputs and observations | Remaining verification |
|---|---|---|
| IIP-MD05.ad | Signed requests using the first and 2nd keys, both with signing specified and with use omitted | Native product import and use. Shares signing fixtures with the stronger `MD07` obligation |
| IIP-MD07.a | Requests that actually use a single key and each position in a multiple-key list | Rejection or silence alone does not establish a product violation |
| IIP-MD06.a5 | Change metadata-certificate and runtime-certificate attributes while signing with the same public key | Additional diagnostics separate rejection before trust establishment from runtime key comparison |
| IIP-MD06.a7 | Observe KeyValue and X509Certificate independently | Success for only one representation does not complete the case |
| IIP-MD06.a9 | Connect existing validity-period, subject/issuer, extension, and KeyUsage/EKU inputs to runtime observations | Additional product execution |
| IIP-IDP12.c | Omit all ACS selection attributes before signing; observe explicit-default changes and implicit defaults | Execute after refetching the same entity. Exclude the preloaded path that uses a different entity |
| Common metadata observations | Require exact Run/fixture matching, reject duplicate parameters, and exclude old use evidence preceding retrieval. Report missing retrieval, missing use, and insufficient rejection proof separately | Stricter checks may also affect previously conclusive results; reevaluation is required |
| Evaluation after configuration completion | Remove paths that turn silence into successful rejection or a product violation solely because an operation completed | Keep NOT_VERIFIED unless evidence establishes rejection |

The implicit-default ACS fixture has matching document and index order. This implementation does not independently resolve the interpretation difference between the approved explanation's "minimum index" and another metadata rule.

This development batch involved no product configuration changes, reloads, or user actions. G2 approval still requires updating because the approved API source differs.

<!--g1-literal--> Batch verification passed 539 tests: SAML 57, Runner 397, and API 85. Generated-document consistency and G1 structural validation 46/46 also passed. G2 remains 20/21, with G2-30 caused by differences from the approved API source. A shutdown race discovered during the work was fixed, and a test confirms that storage is released only after automatic Transcript reevaluation finishes.

The current product comparison already shows Not verified for `IIP-MD05.am/.an/.ao` on every product. Correcting the silence-based determination therefore withdraws no current Success in the comparison. Verification logs and source identity are stored locally at `build/acceptance/reference-20260914/metadata-implementation-batch/verification.json`.

### Ongoing string-condition implementation

<!--g1-literal--> ProviderName inputs for `IIP-G02.a` were expanded from the existing Cyrillic characters to ASCII, CJK, combining characters, XML special characters, TAB references, LF references, and supplementary-plane characters. Each category has 255 and 256 code points, with 16 string conditions and a normal control executed in sequence. Across 3 products, this represents 51 observations including controls; it does not mean 51 unverified cases were resolved.

Length is defined by code points rather than Java UTF-16 length; isolated surrogates are not generated. Combining-character inputs change length when normalized. Tests distinguish TAB/LF character references preserved after XML parsing from literal replacements normalized to spaces.

Successful character conditions are recorded in `confirmed_character_fixtures`; conditions with observed violations are recorded in `violating_fixtures`. NameID, user-defined types, and paths sending literal TAB/LF remain in `remaining_conditions`. Passing every character category does not complete all approved type conditions, so the whole case remains Not verified.

This batch also changes only the development working tree. Product deployment, configuration changes, retesting, and human actions have not yet occurred.

<!--g1-literal--> Combined regressions passed 541 tests: SAML 58, Runner 398, and API 85. They detected simulated implementations that reject only each individual character category, maintained Not verified for unimplemented type conditions even when every category passed, and confirmed preservation of values and signatures on signature-required paths. The local record is `build/acceptance/reference-20260914/string-implementation-batch/verification.json`.

### Ongoing extension-attribute implementation

<!--g1-literal--> Elements whose declared types contain anyAttribute are extracted from the pinned SAML schemas. Independent fixtures add exactly one foreign-namespace attribute to each of 13 metadata elements. Generated results are checked against both the schema and XML signature, and the schema's target list is audited against the generated-element list. Elements such as AssertionConsumerService that only inherit the attribute through their type are not added without justification.

AffiliationDescriptor is generated as aggregate metadata for an entity distinct from the ordinary SP/IdP, preserving the normal SSO path. Each fixture supports preloaded and periodic-retrieval generation and is connected to the work list as a supplementary metadata operation for IIP-EXT01.c. Supplementary operations do not increase the case count or denominator, and reuse common retrieval operations with existing cases. The case is STANDARD work so required configuration operations are not hidden from the QUICK plan.

Browser-side observation of all SubjectConfirmationData and Attribute conditions remains incomplete. Final diagnostics record metadata retrieval/use and remaining protocol elements; they do not mark the whole case Success. New fixtures require refetching in a new campaign.

The added schema checks also detected invalid IdP service ordering in existing Suite metadata. SingleSignOnService now follows SingleLogoutService and NameIDFormat. The current comparison has no Failed IIP-MD rows, so this discovery alone requires no withdrawal of a product Failed. However, correcting the normal input requires rerunning product tests.

<!--g1-literal--> Combined regressions passed 543 tests: SAML 59, Runner 399, and API 85. Product deployment, configuration changes, retesting, and human actions have not occurred. The local record is `build/acceptance/reference-20260914/attribute-implementation-batch/verification.json`.

### Reevaluation of delayed metadata evidence

Reevaluation is implemented for cases finished with `metadata.fixture-probe.incomplete` or `metadata.consumer-probe.incomplete` when new Transcript evidence arrives. The case remains FINISHED; execution does not restart. No test requests, outbox actions, or login operations are added.

Updates require explicit reevaluation support by the case, complete history, a new Transcript reference, and a conclusive outcome under existing predicates. Already conclusive success, violation, or note results, aborted/expired cases, silence, and old evidence alone cannot trigger updates. The original unverified outcome, evidence, revision, and timestamp are retained in CaseState and result details, and optimistic locking advances the revision. Delayed proof of use of prohibited metadata can also establish a violation under the correct conditions.

<!--g1-literal--> Runner 403 and API 85 passed 488 tests. Checks cover SQLite persistence/readback, retention of the original result, no resend, duplicate-update prevention, protection of aborted results, and rejection of updates based on incomplete history or only existing evidence. Product deployment, configuration changes, retesting, and human actions have not occurred. The local record is `build/acceptance/reference-20260914/late-evidence-batch/verification.json`.

Unimplemented and partially implemented entries in the [complete inventory](26-unverified-case-inventory.md) still need completion. This batch does not complete all encryption-algorithm combinations, multiple-SP/IdP-initiated/asynchronous SLO, all character and schema conditions, or metadata-consumer rejection proof. API registration counts and the absence of a `not_implemented` reason code do not establish implementation completion.

Evidence, SHA-256 values of changed classes, configuration backups, retest Runs, Subject recheck scripts, and restoration records are stored locally at `build/acceptance/reference-20260914/additional-implementation/`. Backups that may contain secrets are excluded from commits and publication.

### Integrated deployment and additional real-product verification

<!--g1-literal--> The metadata, string, extension-attribute, and delayed-evidence reevaluation implementations above were incorporated into verification image `samlscope:reference-integrated-v6`. The 51 changed classes were checked against build-output SHA-256 values, and all library JARs matched before and after deployment. Embedded catalogs and approval records were unchanged. Each development batch's "not deployed" statement records its state at that batch's end.

<!--g1-literal--> New SSO sequences completed on Keycloak, Shibboleth, and SimpleSAMLphp. All 16 IIP-G02.a string inputs were confirmed per product, yielding 48 partial observations. Persistent/transient NameID, user-defined strings, and literal TAB/LF on the wire remain incomplete, so the whole case remains Not verified on all 3 products. This is not resolution of 48 cases.

| Additional test | Keycloak | Shibboleth | SimpleSAMLphp |
|---|---|---|---|
| IIP-G02.a partial string-input observations | Inputs confirmed / whole case Not verified | Inputs confirmed / whole case Not verified | Inputs confirmed / whole case Not verified |
| IIP-MD05.ad multiple keys and omitted use | Outside this retest | Success | Outside this retest |
| IIP-MD06.a5 runtime public-key comparison | Outside this retest | Success | Outside this retest |
| IIP-MD06.a7 KeyValue and X509Certificate | Outside this retest | Success | Outside this retest |
| IIP-MD06.a9 certificate attribute handling | Outside this retest | Success | Outside this retest |
| IIP-MD07.a each single/multiple-key position | Outside this retest | Success | Outside this retest |
| IIP-IDP12.c default ACS selection | Outside this retest | Success | Outside this retest |

<!--g1-literal--> Shibboleth native HTTP retrieval executed 46 inputs in the metadata Run and 17 inputs in the SSO Run. Requests were sent only after the Suite confirmed retrieval of the same URL, with no manual continuation after each input. Retrieval alone does not produce Success; the normal control and SAML responses bound to the Run/fixture were checked. Default ACS verification covers explicit-default changes and implicit defaults with matching document/index order.

<!--g1-literal--> Only the 6 newly conclusive cases adopted the latest evidence in the comparison. Unverified observations decreased from 584 to 578. Additional metadata-extension observations were not promoted to Success for the whole IIP-EXT01.c case, which still includes incomplete protocol elements.

<!--g1-literal--> Shibboleth configuration writes were 4 (2 preparation, 2 restoration), with 4 service reloads. Restored configuration matched the original file bytes. There were 4 test Runs, 1 Suite restart, 1 forwarding-container restart, and 2 starts/stops each of the auxiliary retrieval container. Intermediate continuation, browser actions, and user actions were all 0. Scripted configuration work is included in operation costs.

Final extension-attribute diagnostics were also corrected where supplementary metadata Transcript references were missing from the parent case result. Observation descriptions and references come from the same read, and references are retained without duplication in parent evidence. Incomplete protocol elements remain Not verified. This reference-retention fix is in the development working tree and is not yet included in the verification image above.

Evidence is stored locally at `build/acceptance/reference-20260914/integrated-implementation/`. `character-observations.json` records partial observations, `resolved-case-provenance.json` records conclusive cases, and `runtime-verification.json` records runtime-class/library comparisons. These records do not mean every test, reapproval of the approved source, or release acceptance is complete.

<!--g1-literal--> All 404 Runner tests passed after the reference-retention fix. Generated-document consistency and G1 structural validation 46/46 also passed. Because the signer file referenced by local Git configuration was missing, verification explicitly selected the existing CI signer file at runtime. Approval records were unchanged. G2 remains 20/21, with G2-30 caused by M1Runtime/SamlScopeApplication differences from the approved source. The 79 Transcript references in the 6 new Success cases were also verified to exist in their respective Runs.

### Added ECDSA inputs and capability verification

Suite key storage now supports EC P-256 in a directory separate from existing RSA keys. EC certificates are used for signing; metadata continues to advertise the existing RSA key for encryption. XML signing selects RSA-SHA256 or ECDSA-SHA256 from the actual private-key type and rejects other key types.

Inputs `ecdsa-sha256` and `ecdsa-sha256-invalid-signature` were added. The latter sends a request with only its signature value corrupted. Normal and invalid controls on the periodic-retrieval path use the same EC public key, avoiding confusion between rejection of an unregistered key and rejection of a signature value. The normal fixture is included in aggregate preloading; invalid requests remain separate controls. Input selection, including default ACS inputs, now uses the common Variant definitions.

`IIP-ALG03.a` moved from a configuration-guidance-only path to capability verification from recorded evidence. It requires RSA normal Success, EC normal Success, and an explicit SAML error for an invalid EC signature. Run/fixture/issued-request correlation and responses after retrieval are checked. Incomplete history, contradictory responses, or controls indicating unconditional acceptance or rejection retain Not verified. An error or silence for the normal EC request alone does not establish lack of product algorithm support. Finished cases with insufficient evidence can be reevaluated without resending only when new complete evidence is available.

<!--g1-literal--> Response absence, success, error, unknown Status combinations, and history completeness were checked across 128 conditions. Including foreign Runs, ambiguous queries, responses before retrieval, contradictory responses, and rejection of updates after abortion, all 407 Runner tests passed. Combined SAML tests also passed. In the full API suite, 2 fixed-registration-count audits out of 85 tests failed because the new implementation increased the count. Expectations were updated after explicitly checking registered classes and required control inputs; retests of 4 related API tests and 2 EC-input tests passed.

This change is in the development working tree. Product deployment, EC testing, and product configuration changes have not occurred. Existing product results are not updated merely because implementation was added; unverified counts remain those of the [complete inventory](26-unverified-case-inventory.md). Evidence is stored locally at `build/acceptance/reference-20260914/ec-signature-batch/`. Differences from the G2-approved API source remain unresolved.

### Displaying partial observations and remaining conditions in published results

An optional `diagnostics` field was added to case results because checking additional observations previously required reading SQL directly. Confirmed character inputs, remaining type conditions, metadata retrieval and use, missing inputs, and supplementary observations of extension attributes can now be inspected in result JSON, the UI, and static HTML. Existing results without diagnostics remain readable.

Only fixed diagnostic keys combined with Suite-defined condition names are published. Arbitrary strings, NameID values, configuration notes, Authorization, and free text stored in previous results are not copied directly into published results. Details outside the allowlist remain internal; public diagnostics are not a dump of all internal information. Displaying partial observations does not change the Verdict, aggregation, or conformance descriptions determined by Evaluator.

The UI lets users expand individual cases within a requirement to inspect reasons and observed conditions. Static HTML displays the same diagnostics per case, inserting strings through textContent rather than interpreting them as HTML. Cases without new diagnostics still display their reasons.

<!--g1-literal--> The combined Runner 410 and API 85 regression tests and the UI display tests passed. All defined metadata and protocol input names were checked as publication candidates, including exclusion of unknown values and free text and unchanged outcomes and aggregation before and after diagnostics were added. Existing golden results were unchanged. JSON containing diagnostics was checked against the result schema, and invalid scalar diagnostics were rejected. G1 structural validation passed 46/46. G2 remains at 20/21, with differences from the approved API source still outstanding.

This change is also in the development working tree and has not been deployed to the running image. No product tests or configuration changes were performed, and the unverified count was not updated. The local verification record is `build/acceptance/reference-20260914/public-diagnostics-batch/verification.json`.

### Common encryption input matrix and correction of the decryption target

Inputs for AES128-GCM/AES256-GCM, RSA-OAEP/RSA-OAEP 1.1, SHA-1/SHA-256 and the default Digest, and omitted/explicit MGF were consolidated into a common generator. The encrypted wrappers are EncryptedAssertion, EncryptedID, and EncryptedAttribute. Combinations that introduce an XML Encryption 1.1 MGF parameter into XML Encryption 1.0 OAEP are not generated. This component only generates ciphertext containing randomness; it neither sends requests nor returns Verdicts. When connecting it to Runner, the generated payload must remain in the outbox so ciphertext is not regenerated on retry.

The batch tests detected that the encryption library explicitly writes default parameters into XML. For omitted-parameter inputs, the actual cryptographic operation is fixed to SHA-1/MGF1-SHA1, then the corresponding optional XML elements are removed. Explicit and omitted inputs are distinguished by inspecting actual XML, rather than only their names. Namespaces declared on plaintext ancestors are also preserved so QName-valued attributes retain their meaning.

The existing decryption process searched descendants for EncryptedData and returned the first element after decryption. An unencrypted element preceding the ciphertext could therefore be returned as the decrypted result. Decryption now first checks the structure against the pinned SAML schema's EncryptedElementType, allowing only direct EncryptedData followed by EncryptedKey. Cases remain responsible for validating the type of the decrypted plaintext.

<!--g1-literal--> Decryption, failure with a wrong key, and failure after ciphertext tampering were checked for 24 algorithm combinations and 3 wrappers, totaling 72 inputs. Unencrypted preceding or following elements, nested or duplicate EncryptedData, extra text, and wrappers in another namespace are also rejected. The combined SAML 64, Runner 410, and API 85 tests passed, totaling 559 tests. SAML schema validation was then added for both normal plaintext and encrypted wrappers, and the 2 targeted tests also passed.

<!--g1-literal--> G1 structural validation passed 46/46, and generated documents matched. G2 remains at 20/21: SamlScopeApplication, M1Runtime, and ResultDocumentAssembler changed in the preceding batch still differ from the signed approval targets. This gate has not been resolved.

This generator provides shared inputs for future encryption and EncryptedID scenarios. Existing unverified cases have not been changed to Success based only on this internal matrix test. No running-image deployment, product sends, or configuration changes have been performed. The local record is `build/acceptance/reference-20260914/encryption-matrix-batch/verification.json`.

### Connecting EncryptedID requests to Subject comparison

A selector was added for RSA encryption keys belonging to the selected entity and SAML role in target metadata. It handles X509Certificate and RSAKeyValue in direct KeyDescriptor elements and uses them only when use is encryption or omitted. It does not select signing-only keys or keys in another role or Extensions. A duplicate or missing selected entity is treated as unavailable rather than selecting an arbitrary candidate. This is test key selection, not a conformance determination for the entire metadata document.

The public key obtained from the target metadata fixed for the Run is passed into the browser test's in-memory configuration. If it is unavailable, the ordinary normal control is retained, and `target-encryption-key` is recorded as a missing input in the Subject comparison diagnostics.

AuthnRequests replacing NameID with EncryptedID were added to the existing `IIP-SSO07.b` scenario. Requests containing ciphertext are returned as ordinary OutboundAction values and use Runner's signing and outbox path. Cases do not send HTTP directly. The algorithm and target public key are included in scenario identity so changed test conditions can be detected on resume.

<!--g1-literal--> For 24 encrypted inputs, both plaintext NameID responses and NameID responses encrypted with the Suite key were checked. Controls returning a different identifier for each individual input were also run and detected as mismatches. Even when every identifier matches, conditions such as SubjectConfirmation remain unverified, so the whole case remains Not verified. This boundary was checked in 50 scenarios, and request SAML schema validation was performed. This does not mean 50 unverified cases were resolved.

<!--g1-literal--> The batch tests detected that the new input names exceeded the existing length limit; they were shortened using `enc-subject-`. SAML 65, Runner 411, and API 85 regression checks passed. G1 structural validation passed 46/46, and generated documents matched. Differences from the G2 approval targets remain outstanding.

As of 2026-09-15, this connection is implemented in the development working tree. It has not been deployed to the running image, executed against products, or accompanied by product configuration changes. The unverified count is unchanged. Verification records are stored locally at `build/acceptance/reference-20260914/encrypted-subject-batch/verification.json`.

### Additional Subject checks and preparation of an integrated image

Treating decrypted Assertion/NameID elements by local name alone could classify elements from another namespace as SAML identifiers, so namespace checks were added. Ambiguous structures with duplicate Subject or identifier choices remain unverified for this semantic comparison. Decryption failures are also handled per Assertion so an earlier undecryptable Assertion does not hide a clearly observed identifier mismatch in a later Assertion.

<!--g1-literal--> The main working tree's 412 Runner tests passed. The added encryption, ECDSA, and public diagnostic changes were then combined in an independent verification working tree, where SAML 65, Runner 413, and 6 targeted API tests passed. This does not mean full API release verification passed: the API check was limited to SamlScopeApplicationTest.

<!--g1-literal--> The deployment scope was limited to 97 classes generated from 31 Java sources and the result schema, with SHA-256 recorded. API and M1Runtime changes were limited to necessary request generation and encryption-key selection; the catalog, approved definitions, and unrelated OIDC or administration UI work were not mixed in. The new UI bundle is not included in this image, while public JSON and static HTML diagnostics are included.

The local verification image `samlscope:reference-crypto-v7` was built. The running image remains `samlscope:reference-integrated-v6`; no switch, product configuration change, or product test with the new image has occurred. G1 structural validation and generated-document matching passed, but differences from the G2 approval targets remain. Build, class, and image comparison records are stored at `build/acceptance/reference-20260914/crypto-integrated-implementation/`.


### Switching to the integrated image and retesting products

On 2026-09-15, the verification environment was switched to `samlscope:reference-crypto-v7`. The following records describe work performed after the preceding section's undeployed state. The old containers are retained in a stopped state.

<!--g1-literal--> The running container's 97 classes and result schema were checked by SHA-256. Libraries, the embedded catalog, and approval records match their pre-switch versions. The UI bundle was not updated. Public JSON and static HTML diagnostics are included in the running version.

<!--g1-literal--> Each product completed its browser SSO sequence, and evidence for `IIP-SSO07-b-idp-01` and `IIP-G02-a-idp-01` was adopted into the comparison table. Existing evidence for other cases was retained. Subject comparison results are shown below. Send counts include normal controls.

| Product | Sends / recorded responses | Subject comparison result | Observations and limitations |
|---|---:|---|---|
<!--g1-literal--> | Keycloak | 2 / 2 | Failed (Product) | Plaintext identifier mismatch. Encrypted inputs were not executed because metadata contained no eligible encryption key |
<!--g1-literal--> | Shibboleth | 26 / 26 | Not verified | Evidence required for comparison is missing for plaintext and encrypted inputs |
<!--g1-literal--> | SimpleSAMLphp | 26 / 26 | Failed (Product) | Identifier mismatches observed for plaintext and encrypted inputs |

Receiving a response to encrypted input or detecting a mismatch alone is not treated as verification of encryption-algorithm support. Keycloak's signing-only key was not reused for encryption; the missing key remains in diagnostics.

<!--g1-literal--> Public diagnostics confirmed partial observations for 16 character conditions and 6 types of remaining conditions. Static HTML was retrieved and executed with jsdom, confirming that diagnostic display processing for 161 cases had no execution errors. This was not visual inspection in an actual browser.

In the Shibboleth ECDSA test, native HTTP metadata retrieval was temporarily configured, and successful RSA and ECDSA normal controls were recorded. The invalid ECDSA signature stopped at an HTTP 400 Message Security Error page. No correlated SAML error response was present, and history completeness was not established, so support verification was not changed to Success. Partial protocol-evidence API observations and the stop page were saved; the outcome was not finalized through self-attestation.

<!--g1-literal--> Product configuration writes comprised 2 Shibboleth writes for application and restoration, with 2 reloads. The auxiliary container was started and stopped 1 time each, and restoration to the original configuration bytes was verified. Product settings were not changed for the SSO retests. All operations used agent-driven HTTP; human manual and browser operations were 0. Restarts of the running Suite and forwarding container were also recorded in the operation ledger.

<!--g1-literal--> The full inventory remains at 578 unverified observations. Additional executed inputs were not converted into resolved-case counts. Differences from the G2 approved source remain, so release readiness has not been reached.

Execution evidence is stored locally at `build/acceptance/reference-20260914/crypto-integrated-implementation/`. Operation counts are recorded in [configuration and interaction costs](25-interaction-execution-cost.md), and product results in the [comparison table](23-reference-test-comparison.md).

### User-defined string types and NameID input matrix

The `SamlTypedStringFixtures` input-fragment generator was added for the approved G02 type conditions. It generates persistent/transient NameID, xs:string elements in Advice, AttributeValue with a user-defined xs:string-derived type, and xs:string attributes in Extensions. These are independent fragments for permitted message positions, not a mechanism for inserting Advice or similar content into arbitrary AuthnRequests.

<!--g1-literal--> The 5 positions combined with the existing 16 character conditions produce 80 inputs. They cover 255/256 code points, ASCII, Cyrillic, CJK, combining characters, XML special characters, TAB/LF character references, and supplementary-plane characters. This does not mean 80 unverified cases were resolved.

String types are identified from a fixed schema bundled with the Suite, rather than inferred from user-defined type names. Custom types are validated through an explicit dedicated method; arbitrary schema import was not added to normal target XML validation. Network retrieval of DTDs and schemas is disabled.

The matrix tests detected that existing string-type observation followed only restriction and did not recognize NameID's simpleContent extension. It now follows restriction/extension inheritance to xs:string. This allows the existing nonempty-string check to observe received NameID values as well.

Product delivery paths, preparation of registered NameID values, and observation that values are retained inside the target still require separate work. Ignoring a custom extension or returning a normal response is not treated as proof of string retention. This input foundation is a development working-tree change and has not been deployed or accompanied by product configuration changes. The unverified count is retained.

<!--g1-literal--> Combined regression tests after the type-inheritance fix passed for SAML 68 and Runner 412. Custom schemas were then loaded only on the first call to dedicated validation, and a regression condition passing NameID to the actual nonempty check was added. The final targeted SAML 3 and Runner 5 tests passed. Matrix checks covered type, character count, truncation detection, rejection of unknown custom types, and DOM independence. The 32 NameID inputs use normal values and empty or whitespace-only values as controls.

<!--g1-literal--> G1 structural validation passed 46/46, and generated documents matched. G2 remains at 20/21, with existing differences from the approved source. Source SHA-256 and verification logs are stored locally at `build/acceptance/reference-20260914/typed-string-batch/verification.json`.

### Connecting extension string inputs to browser tests and checking the inventory

<!--g1-literal--> The 16 user-defined xs:string attribute inputs in Extensions were connected to the G02 browser scenario. Following the ProviderName sequence, Extensions is inserted directly after Issuer in the default request. ProviderName is unchanged for these inputs, limiting the changed factor to the extension value. Requests are returned as ordinary OutboundAction values and sent through Runner's signing and outbox path. The definition key detecting input-sequence changes on resume was also updated.

Names of inputs that receive a normal correlated response with an Assertion are recorded in public diagnostics as `responded_extension_string_fixtures`. Ignored extensions can also produce normal responses, so this is not proof of internal value retention. The remaining condition `user-defined-extension-string-attribute` is retained. Error responses or responses without an Assertion are treated as missing supplementary observations, not product violations of the string requirement.

<!--g1-literal--> Combined verification covered 17 scenarios including rejection of each ProviderName condition, plus 34 scenarios including errors or missing Assertions for each extension string condition. Input XML schema conformance, values and character counts, and removal only of missing inputs from observed conditions were checked. Public diagnostics allow only fixed input IDs, not the values themselves. SAML 68 and Runner 415 combined regression tests passed.

<!--g1-literal--> The inventory audit found 12 ECDSA observations still classified as having no automatic oracle based on old browser-wait information. Current EcSignatureSupportTestCase and registration code were checked, and the classification was updated to additional metadata tests / observation gaps. Product outcomes and the total of 578 unverified observations were unchanged. Implementation and registration source hashes were saved in `remaining-audit/implementation-audit.json`, requiring reinspection when registration changes.

This connection is in the development working tree and has not been deployed or retested against products. No product configuration changes or user actions occurred. Verification records are stored locally at `build/acceptance/reference-20260914/extension-string-batch/verification.json`.


### Deploying the integrated string-test version to the live environment

<!--g1-literal--> String-input and NameID type-observation changes were combined in an independent working tree, passing the SAML 68 and Runner 416 batch tests. The 15 classes generated from 4 implementation sources and the fixed user-defined-type schema were added to the v7 image. Existing libraries, the embedded catalog, and approved definitions were unchanged.

The verification environment was switched to `samlscope:reference-string-v8`, and running classes and the fixed schema were checked by SHA-256. The old Suite and forwarding containers are retained in a stopped state. The UI bundle was not updated.

<!--g1-literal--> New Keycloak, Shibboleth, and SimpleSAMLphp Runs each sent 33 G02 requests and recorded responses for all of them. Public diagnostics display 16 ProviderName character conditions and 16 extension-string response conditions. Because this does not verify internal retention of extension values, G02 remains Not verified as a whole. Running results and observation counts are saved in `string-integrated-implementation/diagnostics-live-check.json`.

<!--g1-literal--> Suite and forwarding-container restarts were 1 each; product configuration changes, human manual operations, and browser operations were 0. Tests used protocol clients. Run creation and elapsed time will be added to the operation ledger after the sequences finish.


<!--g1-literal--> The 3 product SSO sequences subsequently reached FINISHED, and results were saved. Keycloak outcomes were unchanged from v7. SimpleSAMLphp newly confirmed 1 ForceAuthn case as Success. The 4 request/response Transcript pairs were compared: omitted/false normal controls retain the same authentication time, while true produces a new authentication time after the request. Check timestamps and XML SHA-256 are saved in `string-integrated-implementation/simplesamlphp/force-authn-evidence-check.json`.

<!--g1-literal--> Additional G02 observations and SimpleSAMLphp's ForceAuthn success were adopted into the comparison table, reducing the existing unverified set from 578 to 577. The operation ledger also records elapsed time per Run, automatic fixture starts and response counts, and automatic session initialization counts.

<!--g1-literal--> Shibboleth's 3 signature/correlation cases (SSO01-fk/fu/gi) encountered Stale Request in this normal control and became control_failed. Prior successful evidence was not deleted, but the relevant comparison cells explicitly state prior Run success / latest normal control unconfirmed. The 577 above is the size of the existing unverified set; it does not mean these 3 latest attempts need no recheck. Suite execution order will be investigated further, including whether generated requests become stale while queued. No new product FAIL was established.

### Correcting request-generation timing in long test sequences

<!--g1-literal--> Saved Transcripts for Shibboleth's SSO01-fk/fu/gi normal requests were read, comparing IssueInstant with recorded send time. Approximately 367, 374, and 383 seconds respectively elapsed between generation and sending. Code inspection also confirmed that the Suite started every browser case when starting a profile, generating later cases' requests, signatures, and response deadlines in advance. The record is `request-queue-batch/stale-request-evidence.json`.

After selecting target role, profile, and applicability, ApprovedCaseStarter now persists only a start reservation for BrowserFrontChannelScenario. Reserved cases have no payload, signature, or response deadline. ActiveProbeCoordinator starts the next selected case through CaseExecutionService using the clock at selection time and the normal signing and outbox path. A newly reserved case does not overtake a running case.

A case that finishes without generating a request because prerequisites are missing retains its result before advancing to the next reservation. Reservations and starts use the existing repository revision comparison; duplicate start requests return the existing state. Case Outcome, Evaluator Verdict conversion, and sent or unknown-delivery outbox payloads are unchanged.

<!--g1-literal--> Regression conditions reserved 50 cases and advanced the clock by 2 hours, confirming that no signatures, outbox entries, or response deadlines were created. The clock was then advanced by 10 minutes before each response, confirming that only the next selected case receives the current request time and deadline. Existing payload immutability and unchanged signing counts on duplicate queries or starts were also checked. Runner 416 and API 85 combined regression tests passed.

This change removes delays caused by waiting for other cases. It does not automatically refresh requests already selected but held unsent by a user, or old Runs that already contain payloads. Rewriting an existing payload's request time would change the meaning of signatures and delivery records. It has not yet been deployed to live v8 or verified against products in new Runs; the stopped cases have not been counted as resolved. There were no product configuration changes or human manual operations.

### Deploying start reservations to the verification environment

<!--g1-literal--> Start reservations and request generation on selection were combined in an independent working tree. Runner 417 and 6 targeted API tests passed. The targeted API was SamlScopeApplicationTest; this does not imply full API release verification. Only 8 classes generated from 3 implementation sources were added to the v8 image.

The verification environment was switched to `samlscope:reference-queue-v9`. Running class SHA-256 and unchanged existing libraries were checked. The catalog, approved definitions, and UI bundle were unchanged. Old Suite and forwarding containers are retained in a stopped state.

New Keycloak, Shibboleth, and SimpleSAMLphp Runs started their SSO sequences. Old Runs containing generated requests were not updated and remain available for comparison. Execution evidence and operation records are stored locally at `build/acceptance/reference-20260914/queue-integrated-implementation/`.

<!--g1-literal--> The 3 product sequences reached FINISHED, and results, operation ledgers, and all outcome differences were saved. Shibboleth's previously stopped normal requests had shorter queue delays, as shown below, allowing case Success to be reconfirmed. These times are not judgment thresholds; they are differences between recorded XML IssueInstant and Transcript send time.

| Shibboleth case | v8 delay after generation (seconds) | v9 delay after generation (seconds) | v9 result |
|---|---:|---:|---|
<!--g1-literal--> | IIP-SSO01-fk | 366.656 | 7.482 | Success |
<!--g1-literal--> | IIP-SSO01-fu | 374.271 | 5.916 | Success |
<!--g1-literal--> | IIP-SSO01-gi | 382.835 | 5.987 | Success |

Invalid-signature inputs include attempts where the client observed a Message Security Error page with no SAML response. This does not mean every input returned an explicit SAML error response. The records establish that normal-control Stale Request failures were resolved and that the existing cases completed their normal and abnormal attempts.

<!--g1-literal--> Keycloak outcomes were unchanged from v8. SimpleSAMLphp's IIP-IDP06-b became Success, and its 4 request/response stages were compared. Omitted/false retained authentication time; only true produced a reauthentication time after the request. The latest IIP-IDP06-a attempt was Not verified because of ambiguous timestamp precision. The comparison table explicitly identifies adoption of earlier successful evidence for that case and the latest attempt's pending status.

<!--g1-literal--> The existing unverified set decreased from 577 to 576. Shibboleth's 3 cases retained previous successful evidence and were not counted again in this reduction. Suite and forwarding-container restarts were 1 each; product configuration changes, human manual operations, and browser operations were 0. Automatic test starts, responses, session initialization counts, and elapsed times were recorded in the operation ledger.

Comparison evidence is in `queue-integrated-implementation/*/request-age-check.json`, `verdict-delta.json`, and SimpleSAMLphp's `force-authn-evidence-check.json`; live-environment checks are in `runtime-verification.json`. These are local execution records, not proof of release approval.

<!--g1-literal--> After deployment and record updates, G1 structural validation passed 46/46, and generated documents matched. G2 remains at 20/21, with ApprovedCaseStarter, M1Runtime, SamlScopeApplication, and ResultDocumentAssembler differing from the signed approval targets. ApprovedCaseStarter's reservation change is also subject to reapproval; the release gate has not passed.

### Correcting the separation of G02 acceptance and value-retention conditions

Rechecking IIP-G02.a in approved `tests/coverage.yaml` showed that the value-retention check previously added for extension strings was not a condition of this obligation. The definition treats completion of the flow without errors as acceptance evidence and explicitly allows G02.a to be verified even if an extension may have been ignored. Ignoring and truncation are handled separately by G02.b/c. The preceding explanation that G02.a extension-type conditions must remain because value retention was unverified is corrected here.

<!--g1-literal--> When all 16 extension-string inputs complete normally, `user-defined-extension-string-attribute` is now recorded in `confirmed_type_conditions` and removed from G02.a's `remaining_conditions`. Responding input names remain in public diagnostics. Separate NameID, Advice, AttributeValue, and literal TAB/LF conditions remain, so this alone does not make the whole case Success.

Explicit SAML errors for extension inputs are also treated as G02.a rejections, detecting implementations that reject only specific character classes or boundary values. Unknown or missing Status is treated as an observation gap for that input, not a definitive string-requirement violation. Type conditions are not confirmed when the normal control fails. The scenario definition key was also updated to avoid mixing definitions with running or stored cases.

<!--g1-literal--> Combined verification covered the existing 51 response scenarios plus 64 scenarios assigning unknown/missing Status to each of 32 standard and extension string inputs. Runner 418 and API 85 batch tests passed. Public diagnostics were also checked to allow only fixed type-condition IDs, excluding arbitrary type names and values.

Approved definitions were not changed; the implementation was aligned with them. This is currently a development working-tree change and has not been deployed to live v9, retested against products, or accompanied by configuration changes. Product unverified counts are unchanged. The supporting definition, changed-source SHA-256, and verification record are stored locally at `build/acceptance/reference-20260914/string-acceptance-batch/verification.json`.

### Delivery paths for literal TAB/LF and character references

<!--g1-literal--> 4 inputs sending literal TAB/LF in ProviderName at 255/256 code points were added, bringing standard string inputs to 20. XML parsing normalizes literal TAB/LF in attributes to spaces, while character references retain TAB/LF values, so their expected parsed values are distinguished. Literal input names are not merely reused in the custom-type matrix; existing typed inputs retain their character-reference conditions.

In signature-required mode, normal signing operates on the parsed XML value, then the original lexical representation is restored in ProviderName after signing. Before restoration, equality of the parsed attribute value is checked, rejecting any semantic change. Only the AuthnRequest root attribute is changed. Quote styles are distinguished, and XML declarations, comments, and processing instructions are skipped when locating the attribute, preventing changes to other attributes or similar strings inside comments. Already-signed inputs remain unchanged, without re-signing or reserialization.

<!--g1-literal--> Combined checks covered 32 combinations of quote style, namespace prefix, prolog, and numeric character reference, 20 standard string inputs, signature verification, and SQLite outbox storage. Stored payloads retain actual literal TAB/LF and verify signatures using the same parsed values as the receiver. SAML 70 tests and the Runner combined regression tests passed.

<!--g1-literal--> The 72 unknown/missing Status scenarios for 36 standard and extension G02 inputs were also checked. `literal-tab-and-lf-on-wire` is removed from remaining conditions only when both literals and character references are observed. Additional boundary checks preventing removal when either is missing passed in 9 targeted Runner tests.

These are development working-tree changes. They and the preceding G02 acceptance correction have not been deployed to live v9 or retested against products, and product unverified counts are unchanged. Verification logs and source SHA-256 are stored locally at `build/acceptance/reference-20260914/literal-whitespace-batch/verification.json`. There were no product configuration changes or human manual operations.

### Applying the integrated literal-string and acceptance-condition version to products

<!--g1-literal--> The preceding changes were combined in an isolated verification working tree, where SAML 70, Runner 419, and 6 targeted API tests passed. The targeted API was SamlScopeApplicationTest, not full API release verification. The 10 classes generated from 6 sources were included in the local test image `samlscope:reference-literal-v10`.

Running class SHA-256 and unchanged existing libraries were checked. Approved definitions were unchanged. The old Suite and forwarding containers were retained for recovery. Execution evidence is stored locally at `build/acceptance/reference-20260914/literal-integrated-implementation/`.

<!--g1-literal--> G02 in new Runs received successful SAML responses for all 37 exchanges on each of the 3 products: the normal control, 20 standard string inputs, and 16 extension-attribute inputs. Every response was correlated to an outbound action in the same Run and checked for inclusion in case evidence references. For the 4 literal TAB/LF inputs, recorded XML lexical forms, parsed code-point counts, and signature presence were recorded. Signatures themselves were verified in the preceding automated tests.

<!--g1-literal--> Public diagnostics' unconfirmed conditions decreased from 6 types to 4. Extension-attribute acceptance and literal-character conditions are confirmed; persistent NameID, transient NameID, Advice strings, and AttributeValue strings remain. G02 as a whole remains Not verified. Progress on conditions is not added to whole-case resolution counts. Checks are saved in each product's `string-evidence-check.json`.

<!--g1-literal--> The 3 product SSO sequences reached FINISHED, and all differences from v9 were checked. Keycloak and Shibboleth had no Verdict changes. SimpleSAMLphp's IDP06-a became Success, while IDP06-b became Not verified because of timestamp precision. All 4 request/response stages and authentication times were compared for both. The comparison table adopts IDP06-a's v10 success and retains IDP06-b's v9 success with the latest attempt explicitly pending. Evidence is in `verdict-delta.json` and SimpleSAMLphp's `force-authn-evidence-check.json`.

<!--g1-literal--> The total remains 576 unverified observations. Run IDs and SHA-256 were checked for 31 execution records in the comparison table. The full inventory also stores G02 public diagnostics and remaining conditions, identifying the next required inputs and observations. Diagnostics in JSON and static HTML were confirmed to match.

| Product | Automatic fixture starts | Recorded responses | Automatic session initializations | Elapsed time (seconds) |
|---|---:|---:|---:|---:|
<!--g1-literal--> | Keycloak | 131 | 105 | 6 | 511.070 |
<!--g1-literal--> | Shibboleth | 160 | 127 | 6 | 617.478 |
<!--g1-literal--> | SimpleSAMLphp | 161 | 140 | 6 | 124.221 |

<!--g1-literal--> Each Run has 1 initial normal exchange in addition to the table. Counts are per protocol fixture, not all HTTP operations including login pages and redirects. Suite and forwarding-container restarts were 1 each; product configuration changes, human manual operations, and browser operations were 0. These were recorded with elapsed times in the operation ledger.

<!--g1-literal--> G1 structural validation passed 46/46, and generated documents matched. G2 remains at 20/21, with differences from the approval targets for ApprovedCaseStarter, M1Runtime, SamlScopeApplication, and ResultDocumentAssembler. Completion of this retest is not a release-readiness determination.

### Checking evidence gaps and XML scope in the common SLO oracle

Reinspection of SLO implementation paths from the unverified inventory found that the existing common oracle excluded unreadable records and evaluated only the remainder, and selected the first LogoutRequest/LogoutResponse from arbitrary XML descendants. Both could create success from hidden read failures or evaluate messages outside the exchange. They were corrected before extending the oracle to additional SLO cases.

Run snapshots are checked for retrieval failure, foreign-Run records, duplicate record IDs, missing XML references, mismatches between recorded size and actual byte count, and read or parse failure. Incomplete evidence produces `slo.evidence.incomplete`, not a product violation. Evidence is not discarded to produce success; foreign-Run records are neither read nor included in result evidence references. This does not add cryptographic integrity verification of stored content.

XML selection uses a root SLO message or a single SLO message directly under SOAP Body. Arbitrary wrappers, messages appearing only in Header, multiple Bodies, and multiple body messages cannot support success. Positive and negative controls also verify that same-named SOAP Header messages are not treated as Body exchange messages.

Browser and passive evaluation both respect CaseContext's incomplete-history flag. History retrieval failures do not return to waiting for another browser action; Not verified and a fixed reason ID are displayed. Incomplete records are not counted as observation complete, and exception text, file paths, and arbitrary values are excluded from public diagnostics.

<!--g1-literal--> The 23 common oracle rules were checked against 207 scenarios covering 9 evidence-gap conditions, 207 scenarios covering 9 ambiguous-XML-scope conditions, and 4 SOAP Body positive/negative scenarios. Browser/passive integration and publication restrictions for 9 diagnostic types were also checked. The 423 Runner tests passed.

This is a development working-tree change, not deployed to live v10 or retested with product SLO. The unverified count is unchanged. No product configuration changes or human manual operations occurred. Source SHA-256 and verification logs are stored locally at `build/acceptance/reference-20260914/slo-evidence-integrity-batch/`.

### Request inputs for SP-initiated logout

The current SLO path centered on receiving messages and lacked reusable request generation for SP-initiated sequences. `SamlLogoutRequestFactory` was added to generate LogoutRequest from caller-specified stable request ID, destination, Issuer, NameID/EncryptedID, SessionIndex list, issue time, optional deadline, and asynchronous setting.

Omitted or multiple SessionIndex values, alternative identifiers or destinations, and past deadlines can be expressed as separate inputs. Generating these inputs does not itself determine conformance or violation. Asynchronous is placed directly under Extensions, preserving identifier content, qualifier attributes, and inherited namespaces. The source identifier DOM is unchanged.

EncryptedID uses the existing encryption inputs and the caller's selected public key. Signing occurs once, after Issuer; re-signing an already-signed input is rejected. Request generation performs neither HTTP sends nor case evaluation; Runner retains responsibility for delivery and retry. Existing Plan AuthnRequest-signing semantics are unchanged.

<!--g1-literal--> The 72 plaintext construction scenarios checked combinations of strings, name formats, SessionIndex lists, asynchronous settings, and deadlines. The 48 encryption scenarios combined 24 algorithms with 2 receiver keys, verifying decryption with the selected key and failure with another key. XSD structure, signature verification, detection of Destination changes after signing, and unchanged input DOM were also checked.

<!--g1-literal--> 3 requests with a normal signature, modified signature value, and modified signed content were stored through the actual SQLite outbox path. Even with existing AuthnRequest signing enabled, LogoutRequest bytes were retained without repair or re-signing, and LOGOUT_REQUEST retry classification remained UNSAFE. SAML 73 and Runner 424 batch tests passed.

This implements request inputs and storage. SP-initiated logout scenario registration, SLO reception/active-probe integration, and product evaluation remain incomplete. It has not been deployed to live v10 or accompanied by product configuration changes, and the unverified count was not reduced. Source SHA-256 and logs are stored locally at `build/acceptance/reference-20260914/slo-request-fixture-batch/`.

### Connecting SLO responses to active probes

Active-probe RelayState handling was added to SloPeerService. It checks that the correlated Run belongs to the endpoint's Plan, agrees with the URL's run parameter, and has no duplicate run parameter. Ordinary SLO reception retains the existing path.

Active probes save abnormal responses in Transcript before parsing, then pass the record ID and original XML to the waiting case. Cases determine InResponseTo and Status conformance; reception alone does not establish product Success. Pre-parse and post-parse records are distinguished, and the parsed result is confirmed to be stored before notification. Authorization and Cookie are removed before submission to Recorder.

SLO reception uses dedicated acceptLogout and accepts only LOGOUT_REQUEST outbox entries. The normal ACS accepts only AUTHN_REQUEST. Responses arriving through the wrong route are rejected before delivery-state checks or case resume. SLO response pages reuse the existing active-probe continuation page and trigger result generation when cases finish.

LOGOUT_REQUEST was added to the browser-send allowlist, with recorded message type LogoutRequest. Delivery path and retry safety remain separate: retries from UNKNOWN_DELIVERY are still forbidden. This does not add SLO-specific SOAP or HTTP-Redirect sending.

<!--g1-literal--> Reception tests covered 36 scenarios across POST/Redirect, URL run parameters, normal/error responses, correlation mismatch, wrong message types, and unparseable XML, plus 16 correlation-rejection scenarios. A test defect depending on same-time record sort order was corrected by comparing the notified evidence ID directly.

<!--g1-literal--> Browser delivery was checked with 50 cases mixing AuthnRequest and LogoutRequest: request generation on selection, immutable bytes after sending, duplicate-send rejection, and wrong reception-route rejection. Runner 424, Peer 11, and API 85 batch tests passed.

This connects communication and execution control. Product SLO case registration, product retesting, and deployment to live v10 remain unperformed; the unverified count is unchanged. No product configuration changes or human manual operations occurred. Source SHA-256 and logs are stored locally at `build/acceptance/reference-20260914/slo-active-routing-batch/`.

### Registering the basic SP-initiated logout case

`IdpBasicLogoutScenarioTestCase` was connected to M3 browser registration according to approved IIP-IDP17.a. It sends a signed AuthnRequest in a new session, obtains the identifier and SessionIndex from a normal Response whose signature can be verified, then returns a signed synchronous LogoutRequest to the outbox. Existing Runner paths perform actual HTTP delivery.

The normal control checks request correlation, ACS, SAML version, Status, XML structure, target Issuer, signature, identifier, and SessionIndex. EncryptedAssertion and EncryptedID are decrypted in memory, and decrypted Assertion structure is checked. No request is generated for multiple Assertions, indeterminate identifiers or SessionIndex, or unverifiable signatures or decryption. Decrypted identifiers and keys are not stored in CaseState; only normal-control evidence references are carried forward.

LogoutResponse is checked for target signature and Issuer before request-ID and Suite SLO-destination correlation. Correlation or destination mismatch is a violation; failed normal controls, no response, unknown delivery, incomplete history, and unverifiable signatures produce Not verified. Approved definitions assign session termination and Status branches separately to IIP-IDP17.e/o/q, so a correctly correlated error LogoutResponse is not a violation of this basic case.

Test prerequisites include target HTTP-POST SSO/SLO endpoints and signing certificates, plus Suite signing/decryption keys. Missing prerequisites retain Not verified with a reason, rather than N/A or product FAIL. This does not establish lack of support for targets providing only HTTP-Redirect.

<!--g1-literal--> Session inputs were verified across 48 combinations of NameID format, Assertion encryption, identifier encryption, signature placement, and SessionIndex count. Status, destination, correlation, and signature abnormalities covered 28 combinations; no response, expiry, and interruption covered 6 scenarios across stages. Missing normal controls, malformed decrypted structure, version mismatch, and incomplete history were also checked. Runner 428 and API 85 batch tests passed.

<!--g1-literal--> The full inventory reclassified IIP-IDP17-a for the 3 products from no automatic oracle to awaiting new implementation deployment / additional observations. Old Run evidence remains Not verified; the total of 576 is unchanged. Deployment to live v10 and product retesting have not occurred. There were no product configuration changes or human manual operations. Source SHA-256 and logs are stored locally at `build/acceptance/reference-20260914/basic-slo-case-batch/`.

### Runtime SLO retests and Status URI correction

SLO request generation, reception, and basic evaluation were deployed locally and retested against real products. A Suite bug constructed the normal-login Status URI from the protocol namespace. Test fixtures shared the mistake. Both were corrected to the standard Success URI, with negative controls rejecting the wrong namespace and Responder as normal success. This was not a product failure.

Keycloak then sent LogoutRequest, but the test client still had an old Run-specific SLO response URL. Suite's Run correlation rejected it. Correlation checks were preserved; response URLs were changed to Plan-fixed URLs. active-probe RelayState identifies the Run, removing per-Run configuration rewrites on this path.

<!--g1-literal--> Keycloak required 1 API update affecting 2 SLO response fields, with 0 human operations. 6 Run creation/execution attempts, interrupted trials, and Suite switches, including pre-fix attempts, were recorded. Interrupted trials were not counted as completed tests.

A fresh Keycloak Run produced `slo.basic.synchronous-response-observed` / PASS. LogoutRequest used the identifier and SessionIndex from a verified signed login, and a correlated LogoutResponse arrived. Result references matched Transcript Response/LogoutResponse evidence; static HTML embedded results matched JSON. Only this comparison case was updated. Other SLO obligations, including session termination, were not concluded.

Shibboleth's protocol client stopped on the product page after sending LogoutRequest; page content and further steps required investigation. SimpleSAMLphp's Run-fixed metadata advertised only HTTP-Redirect SLO, while the basic case assumed HTTP-POST. Suite needed a Redirect sender. Neither limitation was classified as product FAIL.

<!--g1-literal--> Runner 428 tests passed; G1 generated docs matched and G1 structure passed 46/46. G2 remained 20/21 with protected-source differences. Unverified observations fell from 576 to 575; this was neither a complete run nor release readiness.

Verified runtime was `samlscope:reference-slo-status-v12`. Existing libraries were checked unchanged and old containers retained for recovery. Evidence, source/class hashes, retests, and before/after settings are in local `build/acceptance/reference-20260914/slo-status-correction/`.

### Redirect SLO sending and automatic browser transitions

SimpleSAMLphp advertised only HTTP-Redirect SLO, so a signed Redirect encoder was added. Under [SAML Bindings §3.4.4.1](https://docs.oasis-open.org/security/saml/v2.0/saml-bindings-2.0-os.pdf), it removes only the direct protocol-message XML signature from a copy and retains embedded Assertion signatures. It applies raw DEFLATE, Base64, URL encoding, and RSA-SHA256 signatures over query values. Original outbox requests remain unchanged; actual outbound query/XML is recorded in Transcript. Destinations with reserved SAML parameters are rejected as Suite configuration errors.

BrowserFrontChannelScenario binding selection was connected to execution. Basic SLO selects POST when available, otherwise Redirect; the choice is stored in CaseState. Normal login remains POST. Existing callers default to POST; Runner's key provider signs Redirect requests for the browser. Delivery remains UNKNOWN_DELIVERY until a correlated response, and replaying the same request remains prohibited.

<!--g1-literal--> Across 120 combinations of message type, RelayState, destination query, and original XML signature, tests checked decompression, unchanged inputs, embedded-signature preservation, correct-key verification, and rejection of wrong keys or altered messages/RelayState. Both plain and encoded reserved parameters were rejected. 50 mixed POST/Redirect cases checked HTTP method, query, destination, signatures, outbox preservation, and replay refusal. SAML 75, Runner 429, and API 85 tests passed.

SimpleSAMLphp initially returned an unsigned LogoutResponse. sign.logout was enabled for this test SP without changing the unsigned result to product FAIL. Immediate read-back produced one PHP parsing error; repeat checks found matching host/container size and SHA-256, valid PHP syntax, and correct settings. No further setting write was made; the read-back retry was recorded.

Shibboleth stopped before responding because the protocol client did not execute a hidden iframe's automatic transition. Runtime page templates and actual pages were inspected. The client followed only the same-origin, same-path transition explicitly specified by the product page; this was not operator self-attestation.

<!--g1-literal--> 4 SLO Runs were created/executed, including interrupted trials and unsigned responses. New settings comprised 1 old Run-specific response-URL change each for Shibboleth and SimpleSAMLphp and 1 SimpleSAMLphp signature change: 3 writes affecting 3 fields. 1 Shibboleth metadata reload, 1 read-back retry, and 1 iframe transition were recorded. Human operations: 0. Fixed response URLs remove per-Run rewrites on this path.

<!--g1-literal--> Alongside existing Keycloak evidence, SimpleSAMLphp and Shibboleth basic SLO now passed in real exchanges. Response/LogoutResponse references, request correlation, static HTML/JSON equality, and XML reconstructed from the actual Redirect query matched. Only basic-case inventory/comparison entries changed; unresolved observations fell from 575 to 573. No other SLO obligations or complete campaign were claimed.

<!--g1-literal--> Runtime was `samlscope:reference-slo-redirect-v13`. 16 class hashes and unchanged libraries were checked; old containers were retained. G1 structure passed 46/46 and generated docs matched. G2 remained 20/21 with approved-source differences unresolved. Implementation continued; release readiness was not claimed.

Local evidence is in `build/acceptance/reference-20260914/slo-redirect-implementation/`. Adding Redirect sending does not establish automatic evaluation of every Redirect response. Successful SLO responses in this batch arrived by POST and their XML signatures were verified.

### Binding Redirect signatures to evaluated XML

The shared SLO verifier previously did not bind a valid Redirect-signed query to the stored XML being evaluated. It now verifies the original query signature, decompresses its message, and compares exact bytes with the evaluated XML. Decompression is bounded by expected XML length. Duplicate message parameters, invalid compression, and different XML are rejected.

A GET query/XML mismatch yields `slo.evidence.incomplete` with public diagnostic `redirect_message_mismatch`, not a product signature violation. A signed URL query on POST cannot stand in for the POST body's signature. Former positive Redirect tests used dummy compression values; they were replaced with actual decompressible messages.

Basic SLO can evaluate an XML-unsigned LogoutResponse only when its unique receipt ID identifies a same-Run INBOUND/GET entry and that original query verifies under target trust with identical XML. Another Run, OUTBOUND, POST, duplicate evidence IDs, missing records, mismatched XML, and bad signatures remain Not verified. Issuer, InResponseTo, Destination, and schema validation remain unchanged.

<!--g1-literal--> The 120 encoder combinations gained checks for identical XML, wrong keys, differing length/content, duplicate parameters, and bad compression. 23 shared SLO rules gained 69 scenarios covering 3 evidence mismatches; basic SLO gained 40 Status/evidence-state scenarios. SAML 75 and Runner 431 tests passed.

<!--g1-literal--> G1 generation matched and structure passed 46/46. G2 remained 20/21. These changes were in the working tree, not deployed to v13; real product Redirect-response trials were not yet run. Unverified observations remained 573. Product writes and human operations: zero. Source SHA-256 and logs are in local `build/acceptance/reference-20260914/slo-redirect-trust-batch/`.

### SOAP body scope and preserving rejection evidence

The SLO SOAP receiver previously selected the first LogoutRequest/LogoutResponse anywhere under Envelope. It now requires a SOAP 1.1 Envelope, one direct Body, and one direct LogoutRequest/LogoutResponse inside it. Header lookalikes are not selected. Multiple Bodies, multiple messages, arbitrary wrappers, different namespaces, and standalone SAML are rejected on this transport path.

The body copy passed to OpenSAML inherits ancestor namespace declarations; the original Envelope is stored unchanged. If invalid scope can still be bound through a URL Run belonging to the Plan, original bytes and fixed rejection `invalid-soap-message-scope` are recorded before rejection. Authorization/Cookie headers are removed before recording, and no SAML response is generated.

Shared SLO evaluation preserves receiver rejection so passive replay cannot turn rejected input into success. Recorded SOAP rejection yields `slo.evidence.incomplete` and `logout_message_scope_unresolved`, never product FAIL. This does not complete every SOAP rule or additional profile.

<!--g1-literal--> Tests covered 48 message-type/namespace-prefix/misplacement scenarios, 4 valid Body/Header-lookalike scenarios, and 46 rejection-preservation scenarios across 23 shared rules. Runner 432 and Peer 13 tests passed.

<!--g1-literal--> G1 generation matched and structure passed 46/46; G2 remained 20/21. This and the prior Redirect signature/XML fix stayed in the working tree, not deployed to v13. Unverified observations remained 573; product writes and human operations were zero. Source SHA-256 and logs are in local `build/acceptance/reference-20260914/slo-soap-scope-batch/`.

### Deploying reception fixes and verifying real Redirect responses

Redirect signature/XML binding and SOAP body-scope fixes were deployed together as `samlscope:reference-slo-receive-v14`. Verified source SHA-256 matched the working tree; runtime class hashes and unchanged libraries were checked. Old containers were retained for recovery.

SimpleSAMLphp's test-SP response binding was changed to HTTP-Redirect while retaining signatures, then a new Run executed. LogoutRequest was sent by GET after login; an XML-unsigned LogoutResponse arrived by GET. The basic case verified its original query signature and XML identity and passed. Independent OpenSSL verification also succeeded using the Run-fixed metadata public certificate. Reconstructed/stored XML, request correlation, and static HTML/JSON equality were verified.

Review found the preceding SimpleSAMLphp run also passed IIP-IDP18-a Redirect-request acceptance, but only basic SLO had been adopted. The approved definition covers reception of SP-initiated LogoutRequest; the new Run's evidence was adopted. Every old Not verified → new PASS transition in the profile was checked; other changes were already adopted shared-extension and basic-SLO cases.

<!--g1-literal--> Suite/forward switches: 1 each; product setting change: 1 write affecting 1 field; Run creation/execution: 1; human operations: 0. Setting-file read-back hashes matched before PHP value checks. Costs were recorded; unverified observations fell from 573 to 572. Original POST-response evidence was retained.

<!--g1-literal--> 14 deployed classes and unchanged libraries were checked. Prior successful SAML 75, Runner 432, and Peer 13 test records were retained; this batch added real transport validation. G1 generation matched, structure passed 46/46, and G2 remained 20/21. Remaining G2 approval-source differences and unverified cases prevent release-readiness claims. Real product SOAP reception was outside this batch.

Hashes, switches, settings, Runs, and OpenSSL verification are in local `build/acceptance/reference-20260914/slo-receive-integrated/`.

### Dedicated execution for Redirect-request acceptance

IIP-IDP18-a requires Redirect LogoutRequest reception, which basic SLO cannot demonstrate on products selecting POST. A dedicated Redirect execution path was registered in M3 using existing signature/session verification. Approved cases, levels, and variants were unchanged.

The acceptance case selects the Redirect SLO endpoint even when POST exists. Missing configuration yields Not verified, never fallback POST, success, or N/A. Normal-login signatures, identifiers, SessionIndex, decryption, and structure checks are shared with basic SLO. Sending stays outbox-only.

Case IDs are stored in state and request IDs derive per case. Another case's or old state cannot resume and mix evidence. Basic SLO observes a correlated response; Redirect acceptance evaluates reception, so verified error responses are handled according to that distinction. Signatures, Issuer, destination, correlation, and structure remain checked. Silence, unknown delivery, bad signatures, and failed normal controls are not product FAIL.

<!--g1-literal--> Tests covered 48 Redirect-only normal-session conditions, 28 Status/destination/correlation/signature conditions, request-ID separation, other-case-state rejection, and prohibition of POST fallback. Runner 435 and API 85 tests passed.

Automatic approval review initially rejected test addition/execution. Current instructions explicitly stated independent G2 approval and implementation completion; unchanged approved definitions/records were inspected and supplied for review. The same local validation was then allowed. Existing G2 source differences were neither cleared nor concealed, and approval records were unchanged.

<!--g1-literal--> G1 generation matched, structure passed 46/46, and G2 remained 20/21. The new path was in the working tree, not deployed to v14 or tested against products. Unverified observations remained 572; product writes and human operations were zero. Implementation details in the inventory and source SHA-256 hashes/logs in local `build/acceptance/reference-20260914/slo-redirect-receiver-batch/` were updated.

### Runtime confirmation of dedicated Redirect acceptance

The verified scenario was deployed as `samlscope:reference-slo-receiver-v15`. Source SHA-256 matched tested inputs; M1Runtime differences were limited to registration and endpoint selection. Runtime classes and unchanged libraries were verified; old containers were retained.

New Runs on existing Keycloak, Shibboleth, and SimpleSAMLphp Plans executed basic SLO then dedicated Redirect acceptance. Each case used a separate fresh login, request ID, and receipt. Every product returned a signature/correlation-verifiable LogoutResponse; both cases passed. Shibboleth iframe transitions used the previously added client processing.

<!--g1-literal--> Across 6 cases on 3 products, normal-login/LogoutResponse evidence, per-case correlation/separation, reconstructed Redirect XML versus Transcript, and static HTML/JSON equality were checked. Only these 2 comparison cases moved to the new Runs. Unverified observations fell from 572 to 570 with 180 distinct case IDs. This is not completion of a single Run or other SLO requirements.

<!--g1-literal--> Product writes and human operations: 0. Run creation/execution: 3; Suite/forward switches: 1 each; Shibboleth iframe transitions: 2. Per-case logins and protocol messages were counted.

<!--g1-literal--> 6 deployed classes and unchanged libraries were checked. Successful Runner 435/API 85 records were retained; this batch verified real product paths. G1 generation matched, structure passed 46/46, and G2 remained 20/21. Approved-source differences and unverified cases remained; release readiness was not claimed.

Source/class hashes, switches, Runs, and evidence comparisons are in local `build/acceptance/reference-20260914/slo-redirect-receiver-integrated/`.

### LogoutRequest EncryptedID decryption path

M3 gained an IIP-IDP19-a path encrypting the issued NameID in LogoutRequest under approved conditions. It selects an encryption-use RSA public key from Run-fixed target IdP metadata. Missing eligible keys or registration of Suite's control key prevent the control and yield Not verified.

After fresh login, a signed LogoutRequest encrypts the identifier under Suite's unregistered key. Only a rejection response with valid signature, Issuer, destination, correlation, and structure permits another fresh login. The registered-key trial then requires correlated Success to demonstrate decryption. Control Success, silence, bad signature, or bad correlation remains Not verified. After a valid negative control, rejection of correct registered-key input is a violation.

Inputs use AES128-GCM and rsa-oaep-mgf1p. Suite signs the encrypted request before outbox storage. Decrypted identifiers/private keys never enter CaseState. The rejected control session is not reused; normal trials use another login and request ID. This does not complete IIP-IDP19-c multiple-key traversal or other algorithms.

<!--g1-literal--> 48 combinations of identifier format, Assertion/NameID encryption, signature position, and SessionIndex count checked correct/control-key decryption, XML structure, signatures, and evidence propagation. Each normal input checked Success and 3 errors, plus 7 control signature/correlation conditions and 3 silence/interruption conditions. Runner 437/API 85 tests ultimately passed.

Initial API validation had a connection error in `OidcLoginIntegrationTest.checksResponseIssuerBeforeExchangingCode`. The log was retained; unchanged OIDC code passed on rerun. The rerun additionally verified controls against rejecting valid EncryptedID input.

<!--g1-literal--> G1 generation matched, structure passed 46/46, and G2 remained 20/21. The path was in the working tree, not deployed to v15 or tested with real products. Unverified observations remained 570; all 3 product entries were reclassified as implemented, awaiting additional evidence. Product writes/human operations were zero. SHA-256 hashes and logs are in local `build/acceptance/reference-20260914/slo-encrypted-id-batch/`.

### Runtime EncryptedID confirmation

The verified scenario was deployed as `samlscope:reference-slo-encrypted-v16`; SLO reran from existing product Plans. Runtime/source hashes and unchanged libraries matched.

| Item | Keycloak | Shibboleth | SimpleSAMLphp |
|---|---|---|---|
| Basic SLO | Success | Success | Success |
| Redirect acceptance | Success | Success | Success |
| EncryptedID decryption | Not verified: missing encryption key | Success | Not verified: negative control failed |

Shibboleth returned signed Responder for the unregistered-key control and signed Success under the registered key in a separate fresh session. Outbound LogoutRequests contained EncryptedID without plaintext NameID; request correlation and case ownership were checked.

Keycloak's Run metadata contained only signing keys, preventing encryption-key selection. This is a configuration/test-preparation limitation, not proof of unsupported encryption or product FAIL.

SimpleSAMLphp returned signed Success for an identifier encrypted under an unregistered key, so the control could not distinguish decryption. Installed `IdP/SAML2.php::receiveLogoutMessage` verifies signatures and delegates logout through the SP association; no NameID decryption was found in that entry branch. Source inspection corroborates that Success alone cannot prove decryption. No product-wide capability claim or product FAIL was added; investigated source was saved locally.

<!--g1-literal--> Only the 3 EncryptedID product entries adopted new evidence/reasons. Unverified observations fell from 570 to 569; 25 of the original 594 were concluded. This does not complete a single Run. Basic SLO and Redirect acceptance retained PASS across 6 retested cases.

<!--g1-literal--> Product writes: 0; human operations: 0; Run creation/execution: 3; Suite/forward switches: 1 each; Shibboleth automatic iframe transitions: 3. Session separation and message counts were recorded. Trials used the local protocol client, not the user's Chrome.

<!--g1-literal--> Successful Runner 437/API 85 records were retained; this batch checked real exchanges and static HTML/JSON equality. Remaining unverified cases and G2 approved-source differences prevented release readiness.

Evidence, Runs, source/runtime comparisons, and switches are in local `build/acceptance/reference-20260914/slo-encrypted-id-integrated/`.

### Multiple decryption-key EncryptedID path

IIP-IDP19-c gained an unregistered-key rejection control followed by decryption under the next distinct registered key in metadata order. Encryption/unspecified-use RSA keys are restricted to the target entity, IdP Role, and SAML protocol. Duplicate public keys are removed at retrieval, so repeating certificates cannot satisfy multiple-key prerequisites.

After a valid signed/correlated negative control, a separate fresh login supplies the next registered-key LogoutRequest. Control Success or silence yields Not verified; valid-input rejection after a proven control is a violation; signature/correlation/structure-verified Success satisfies the observation. No KeyName or other selection hints are added. This executes the approved external observation and does not claim to observe internal key-search order.

Missing distinct keys, a registered Suite control key, or unavailable corresponding keys stop sending with Not verified. Publishing keys alone does not satisfy IIP-IDP19-b configuration capability. Case IDs/state versions prevent reuse of another case or old execution evidence.

<!--g1-literal--> Single-key and multiple-key paths each covered 48 session combinations, 96 total. Every valid input checked Success/3 errors, each case checked 7 signature/correlation conditions and 3 interruption conditions, and 5 key absence/duplication/control-contamination conditions were checked. Inputs decrypt only under the selected key, not another registered or control key.

<!--g1-literal--> This was working-tree implementation, not deployed to v16; multiple-key product configuration/retests were unperformed. Product writes and human operations: 0. Unverified observations remained 569; inventory entries were updated to await additional evidence.

<!--g1-literal--> Runner 438/API 85 tests passed. G1 generation matched, structure passed 46/46, and G2 remained 20/21 with existing protected-source differences. SHA-256 hashes/logs are in local `build/acceptance/reference-20260914/slo-multiple-keys-batch/`.

### Runtime multiple-key verification and configuration rework

Verified classes were deployed as `samlscope:reference-slo-multiple-v17`; runtime SHA-256 and unchanged libraries were checked. An extra RSA key was added to Shibboleth's existing rollover configuration and published for encryption before a fresh Run. Private keys stayed inside the test container.

| Case | Keycloak | Shibboleth | SimpleSAMLphp |
|---|---|---|---|
| Basic SLO | Success | Success | Success |
| Redirect acceptance | Success | Success | Success |
| EncryptedID decryption | Not verified: missing encryption key | Success | Not verified: negative control failed |
| Multiple decryption keys | Not verified: missing encryption key | Success | Not verified: multiple-key configuration missing |

Shibboleth rejected the unregistered-key input and accepted extra-key input in separate sessions. Independent decryption of actual transmitted XML confirmed neither target key decrypts the control, while only the extra key decrypts valid input to NameID. Keys/plaintext were not saved; records retain XML hashes and successful key position only.

<!--g1-literal--> The 3 multiple-key product entries adopted new evidence. Unverified observations fell from 569 to 568; 26 of the baseline 594 were concluded. This was not single-Run completion or release readiness.

Initial writes targeted inactive `/opt/shibboleth-idp` instead of active `/opt/reference-idp`. They were restored from backup, then applied to the active home. Container restart did not restore manually started Tomcat: startup lacked test idp.home, and disabled shutdown ports left old processes alive. Startup was corrected to retain the test home; identified old processes were terminated. Published metadata confirmed the active extra key before testing.

<!--g1-literal--> Configuration-file writes: 10; human operations: 0. Breakdown: 3 wrong-home writes, 3 restorations, 3 active-home writes, 1 startup correction. Key generations: 2, including 1 wrong-home attempt. Suite/forward switches, 3 Run creation/execution attempts, product startup/recovery, termination of 2 identified old processes, and protocol counts were recorded. Rework was not disguised as successful automation or zero operations.

Future reruns must first match active home, startup command, and published metadata, then reuse existing extra-key configuration. IIP-IDP19-b configuration capability still lacked its required controls/evidence and was not automatically concluded.

<!--g1-literal--> Successful Runner 438/API 85 records were retained; this batch verified real exchanges, key selection, and static HTML/JSON equality. Evidence, configuration backups, switches, and verification scripts are in local `build/acceptance/reference-20260914/slo-multiple-keys-integrated/`.

### Auditing every unresolved contract during inventory generation

`audit_unresolved_contracts.py` checks unique product/profile/case observations, approved variant references/instructions, positive/negative controls, original result.json SHA-256, Run ID, case uniqueness, NOT_VERIFIED, and reason codes. Missing files, mixed Runs, or concluded results still present as unresolved fail the audit.

Per-case artifacts retain all variants, all_of/one_of groups, control details, prerequisites, interpretation limits, false-positive counterexamples, and product/profile observations. Completion remains `not_proven`. Class registration or some valid inputs do not prove implementation of every condition.

<!--g1-literal--> The audit matched 568 unresolved observations, 180 cases, 455 conditions, and 356 controls with no discrepancies. Conditions/controls are counted per case without duplication across products. Runtime unresolved counts were unchanged.

The inventory generator runs the audit before updating Markdown and stops on mismatch. Details are in local `build/acceptance/reference-20260914/remaining-audit/unresolved-contract-audit.json`. This proves inventory/evidence consistency, not completion of missing oracles.

<!--g1-literal--> Product writes and human operations: 0. Only ledger/audit processing changed; Java evaluators and product retests were unchanged.

### Shared validation of configuration protocol evidence

`AutoConfigurationTranscriptEvidenceTestCase` now validates complete Run history, Run ID, unique evidence IDs, content existence/byte count/XML structure, and Response namespace. Unreadable storage or failed history/decryption-key retrieval becomes Suite evidence insufficiency and Not verified rather than an uncaught exception.

Previously content-read exceptions escaped, and other Runs/duplicate IDs were not explicitly checked. Known evidence faults now return reasons rather than asking for reconfiguration. Losing history after confirmation or response arrival returns the same diagnostic Not verified. Valid-record automatic evaluation and guidance when evidence is not yet available remain supported.

Public diagnostics are limited to Suite-defined tokens `history_incomplete`, `history_unavailable`, `run_mismatch`, `ambiguous_entry_id`, `decoded_content_missing`, `decoded_content_size_mismatch`, `decoded_content_unreadable`, `decoded_content_invalid_xml`, `response_type_mismatch`, and `target-encryption-key`. Paths, exception messages, private keys, and plaintext are excluded. New XML/Response diagnostics were added to the report allowlist.

<!--g1-literal--> 4 Assertion-encryption capability/placement cases covered 14 history/evidence/key-retrieval faults, 56 conditions total. Initial validation found a missing CaseOutcome notVerifiedReason initialization; it was corrected and tests rerun. Failed logs were retained.

<!--g1-literal--> This shared checker was in the working tree, not deployed or retested against products. Unverified observations remained 568; product writes and human operations were 0. Validation records are in local `build/acceptance/reference-20260914/configuration-evidence-integrity-batch/`.

<!--g1-literal--> Runner 439 tests passed after correction. G1 generation matched and structure passed 46/46. Existing protected G2 source differences remained unresolved.

### Observing multiple-key configuration capability through exchanges

`MultipleDecryptionKeysConfigurationTestCase` was connected to IIP-IDP19-b. It uses same-Run IIP-IDP19-a and IIP-IDP19-c results, each passing an unregistered-key control followed by registered-key decryption. Automatic satisfaction requires evidence that distinct keys are actually configured and used.

Run-fixed target metadata must expose distinct encryption keys. Dependencies must be FINISHED/SATISFIED with dedicated reasons; all control-to-normal references must resolve to unique same-Run inbound records. Published keys, one success, self-attestation, other Runs, duplicate evidence, or failed controls do not prove capability. No automatic FAIL inferring capability absence was added.

Insufficient evidence retains the approved configuration/evidence-confirmation path. Later same-Run evidence can update Not verified through explicit recorded-evidence reevaluation without another configuration-complete response. Provenance separates self-attestation from protocol observation.

<!--g1-literal--> 6 faults across 4 references for each dependency gave 48 conditions, alongside missing/duplicate keys, absent/wrong-Run/wrong-case/wrong-reason/incomplete/self-attested/unsatisfied results. The first compile failed because a test helper's byte-count type differed from TranscriptEntry; it was corrected, the failed log retained, and tests rerun.

<!--g1-literal--> This path was added to the working tree, not deployed or verified in new product Runs. Unverified observations remained 568; product writes and human operations were 0. Inventory entries record implementation and needed observations.

<!--g1-literal--> Runner 442/API 85 tests passed. G1 generation matched, structure passed 46/46, and G2 remained 20/21. Source SHA-256/logs are in local `build/acceptance/reference-20260914/multiple-key-capability-batch/`.

### Deploying automatic multiple-key capability observation

Automatic capability observation and configuration-evidence integrity were deployed as `samlscope:reference-key-capability-v18`. Verified source/class SHA-256 hashes and unchanged libraries matched. Shibboleth reused the previously configured extra key and published metadata.

After single/multiple-key decryption cases, Shibboleth IIP-IDP19-b automatically became Success with `attested: false` and `evidence_class: PROTOCOL_OBSERVED`. Every capability reference matched dependent decryption evidence. Independent checks again confirmed neither target key decrypts the control and only the extra key decrypts normal input.

Keycloak lacked observable encryption keys; SimpleSAMLphp lacked a valid single-key control and multiple-key configuration. Their capability cases remained unverified. Basic SLO and Redirect acceptance retained Success for all products.

<!--g1-literal--> Only Shibboleth's capability comparison entry moved to the new Run. Unverified observations fell from 568 to 567; 27 of the baseline 594 were concluded. Capability reused 8 existing evidence entries with 0 extra protocol operations or configuration answers.

<!--g1-literal--> Product writes and human operations: 0; new Run creation/execution: 3; Suite/forward switches: 1 each. Case logins, messages, and browser transitions were counted. Trials used the local protocol client, not the user's Chrome.

<!--g1-literal--> 8 runtime classes were checked. Successful Runner 442/API 85 records were retained; this batch checked real SLO, capability provenance, and static HTML/JSON equality. Deployment of the integrity checker does not establish retesting of all CONFIG cases.

Evidence, switches, class/library comparisons, Runs, and scripts are in local `build/acceptance/reference-20260914/key-capability-integrated/`. Remaining unverified cases and approved-source differences prevented release-readiness claims.

### Diagnosing Keycloak encryption-key visibility

Administration API investigation found an existing RSA-OAEP encryption-key provider, while retrieved SAML metadata published only signing keys. The earlier missing-encryption-configuration diagnosis means Suite cannot obtain test encryption keys from Run metadata, not that no key exists inside the product.

<!--g1-literal--> Runtime services JAR 26.7.2 bytecode confirmed metadata generation selects SIG/RS256 keys, matching [official source for the same version](https://github.com/keycloak/keycloak/blob/26.7.2/services/src/main/java/org/keycloak/protocol/saml/SamlService.java). Adding another encryption provider alone cannot fix Suite's current retrieval path.

Next implementation was an explicit supplemental test-public-key input with frozen provenance and Run binding. Signing-only keys must not be silently reused, and unpublished KeyDescriptors must not be fabricated in target metadata. Supplemental input still requires unregistered-key rejection and normal-key responses; decryption capability was not yet proven.

<!--g1-literal--> Product writes/human operations: 0. Unverified observations remained 567 and Verdicts unchanged. Inventory next actions were updated to avoid repeated unnecessary key additions. Public administration fields, retrieved metadata, runtime JAR/source SHA-256 hashes, and diagnosis are in local `build/acceptance/reference-20260914/keycloak-decryption-keys/`. Tokens/private keys were not recorded.

### Supplemental public-key storage foundation

`SupplementalDecryptionKeys` and `SqliteSupplementalDecryptionKeys` store test public keys bound to Run, target entity, metadata SHA-256, source URI, and time without changing public metadata. Inputs are RSA SubjectPublicKeyInfo; duplicates after normalization are rejected. Private/non-RSA/malformed keys do not echo input or parser exceptions in errors.

Source URIs are references, not fetched. Only HTTP(S) is accepted; userinfo/query/fragment are rejected to avoid retaining credential-bearing URLs. Empty-key snapshots have no provenance.

A unique SQLite constraint permits only initial INSERT per Run, never update. First test access may freeze no supplemental keys, preventing later additions from changing prerequisites. Snapshots for another entity or metadata SHA-256 are rejected. Parent Run deletion removes inputs.

<!--g1-literal--> 60 rejected-input conditions plus normalization/order, duplicates, empty input, replacement prevention, reopen, target/hash mismatch, missing Run, cascade deletion, and 8 parallel initial-insert races were verified. Initial validation found missing handling of a relative URI's null scheme; it was fixed and rechecked.

<!--g1-literal--> Core 179/Store 39 tests then passed. Types/storage were in the working tree; API, execution, reporting, and deployment remained unfinished. Unverified observations remained 567; product writes and human operations were 0.

SHA-256 hashes and initial/rerun logs are in local `build/acceptance/reference-20260914/supplemental-key-input-batch/`.

### Supplemental-key freezing and combination service

`SupplementalDecryptionKeyService` compares submitted entity/SHA-256 with Run-resolved target metadata and saves only matching inputs. Read-only inspect does not freeze input merely because a user opens the panel.

Identical resubmission retains original time/provenance. Key, ordering, source, entity, or metadata-SHA-256 changes are rejected rather than overwritten. Legacy started Runs without snapshots freeze no supplemental keys and reject late registration.

Effective keys retain published order, then append supplemental keys without double-counting public keys. Neither metadata rewriting nor source-URI fetch occurs. Frozen inputs are rejected if target entity/hash no longer matches.

<!--g1-literal--> 4 published-key lists, 3 supplemental inputs, and 4 change types gave 48 combinations checking order, deduplication, identical resubmission, and change rejection. Tests also covered freezing absent input, late input on started legacy Runs, and target mismatch.

<!--g1-literal--> Run-scoped service processing was implemented; authorized HTTP registration, start-time freezing, encryption/result provenance, and UI integration remained necessary. Runtime was unchanged; unverified observations remained 567; product writes and human operations were 0.

<!--g1-literal--> Runner 444 tests passed. G1 generation matched and structure passed 46/46. SHA-256 hashes/logs are in local `build/acceptance/reference-20260914/supplemental-key-service-batch/`.

### Supplemental-key API, UI, and execution integration (2026-09-15)

The unfinished supplemental-public-key integration in `28-deepseek-handoff.md` was completed and retested against runtime. Baseline commit: `52e8feff9507b4bcae4e9f46152a6439ef94a4dd`.

- Runner: `SupplementalDecryptionKeyService.KeySet` freezes provenance `published-metadata` / `supplemental-input`. `TestInputFixed` extends `IllegalStateException` and maps to HTTP 409 Conflict. `keySet` freezes absent inputs before returning effective keys; SQLite's first INSERT determines concurrent start/submission outcomes.
- Encryption: `IdpBasicLogoutScenarioTestCase` excludes Suite control keys from effective registered keys. 19a uses the first key, 19c the 2nd. Results record `decryption_key_source`. Capability 19b uses the same frozen inputs and preserves exact evidence requirements: 4 per encryption case and 8 for 19b.
- API: `GET /api/runs/{id}/supplemental-decryption-keys` returns state/frozen input without freezing. `POST .../submit` uses shared Run authorization/CSRF. Reads do not return 409; before preflight they report metadata unavailable.
- UI: Run workspace adds “IdP decryption key input” with entity, metadata SHA-256, frozen state, provenance, and time. PEM/base64 public keys are accepted; frozen inputs cannot be edited.
- Result: `decryption_key_source` is an allowlisted diagnostic containing fixed tokens only. Arbitrary source URIs/key material are excluded from public results.

<!--g1-literal--> API/Runner tests covered authorization, legacy Runs, start races, and premature freezing. GET does not save; identical submission preserves time; replacement returns 409; starting retains prior input or freezes absence and prevents late additions. 20 concurrent freeze/submit trials stored exactly submitted-key or no-key state.

<!--g1-literal--> Core 179, SAML 75, Store 39, Runner 451, Peer 13, API 86, and Web 83 passed, 926 total. G1 generation matched and structure passed 46/46. G2 remained 20/21 with G2-30 protected-source signature differences; old G2 approval was not treated as independent approval of these changes.

Full-built `samlscope:reference-supplemental-v19`, digest `sha256:59a7760e2becec15c7f2854ad71011fd0a3c9bcab87a63bfe6d94f8c600bd878`, was deployed. Keycloak's SLO Run received 1 RSA-OAEP ENC public key from the administration API with provenance `http://localhost:18180/admin/realms/samlscope/keys` before start. Among 49 cases, `IIP-IDP19-a` changed `slo.encrypted-id.key-unavailable` → `slo.encrypted-id.negative-control-failed`; `IIP-IDP19-c` changed `...key-unavailable` → `...configuration-unavailable`. Both remained NOT_VERIFIED. Keycloak accepted the unregistered-key LogoutRequest control, so positive input was not sent. No product Failed was added.

Shibboleth had 0 Verdict differences across the same 49 cases. `IIP-IDP19-a`/`19-c` retained Success with 4 references; `19-b` used 8. Results added `decryption_key_source: ["published-metadata"]`. SimpleSAMLphp was not rerun because it already had `slo.encrypted-id.negative-control-failed`.

<!--g1-literal--> Unverified observations remained 567 with 180 distinct IDs. New evidence demonstrated supplemental-input application/provenance, not final Verdicts. Docker builds: 2, including an unadopted failed initial overlay; Suite/forwarder recreations: 2 each; product restarts: 0; product setting writes: 0; administration reads: 2; supplemental submissions: 1; new Runs: 2; protocol round trips: 46; browser automatic transitions: 4; direct user operations: 0. See [supplemental-key acceptance](29-supplemental-key-acceptance.md).

### Producer-algorithm evaluation and 8 conclusions (2026-09-15)

<!--g1-literal--> Among 567 unresolved observations, 6 IIP-ALG04/06 cases covered 3 products and 2 profiles, 36 observations. `ApprovedBrowserCaseRegistry` returned `browser.oracle-unavailable` because generated EncryptedAssertion algorithms lacked an evaluator.

`EncryptionAlgorithmObservation` and `EncryptionAlgorithmBrowserEvidenceTestCase` decrypt normally correlated Response EncryptedAssertions with Run keys before inspecting EncryptionMethod, EncryptedKey key transport, DigestMethod, and MGF. Metadata algorithm names alone cannot yield Success. Missing EncryptedAssertions, failed decryption, only other algorithms, or partial 4-combination coverage remain NOT_VERIFIED. ECP correlates through outbox actions with SOAP AuthnRequest IDs.

<!--g1-literal--> Runtime `samlscope:reference-alg-v20` was deployed and retested. Keycloak `IIP-ALG04-b` AES256-GCM and `IIP-ALG06-b` rsa-oaep, and Shibboleth `IIP-ALG04-a` AES128-GCM and `IIP-ALG06-a` rsa-oaep-mgf1p, became Success in browser_sso_idp and ecp_idp: 8 observations. SimpleSAMLphp had 0 EncryptedAssertions in 161 browser_sso_idp cases, so no conclusions. Unresolved conditions were algorithms not generated by the products (AES128/256-GCM, the other rsa-oaep family member, and default MGF1-SHA1), not product FAIL.

9 SSO/SLO NormalFlow cases were investigated: `IIP-SSO01-g/z` needs IdP-initiated success; `IIP-SSO01-ep` needs a VersionMismatch SAML Response; `IIP-SSO01-k` needs accepted alternative ACS; `IIP-SSO03-b` needs a 2nd SAML error type; `IIP-IDP17-n/u` needs target-initiated LogoutRequest. Only ECP correlation could be completed on Suite's side here; other evidence depended on target initiation or settings. Verdicts were unchanged.

<!--g1-literal--> Unverified observations fell from 567 to 559; distinct IDs remained 180. Unit conditions were not counted as resolutions. G2-30 remained unresolved; this was not independent approval. See [producer-algorithm acceptance and operations](30-algorithm-observation-operations.md).

### Target-message reception and 9 conclusions (2026-09-15)

<!--g1-literal--> Single-use preparation intents (`TargetInitiatedIntents`) were added for IdP-initiated SSO and target logout that Suite cannot directly initiate. ACS/SLO accept RelayState-free unsolicited Responses or LogoutRequests for the sole waiting Run in a Plan only when intent is prepared, validating Issuer, Destination, Success, and single use. Unprepared reception remains rejected.

`GET/POST /api/runs/{id}/target-initiated` and a workspace preparation panel show RelayState/waiting state. `LogoutBrowserEvidenceTestCase` can reevaluate completed NOT_VERIFIED with new Transcript evidence. SLO decrypts Assertion NameID/SessionIndex with Run keys before comparison. Adversarial outbound DOCTYPE inputs no longer halt all normal-flow observation; unparseable received responses remain uncertain.

<!--g1-literal--> Keycloak `IIP-SSO01-g` became Success and `IIP-SSO01-z` Warning. Shibboleth `IIP-SSO01-g` and `IIP-SSO01-k` became Success, `IIP-SSO01-z` Warning, `IDP17-j/k/l/m` Success, `IDP17-t` known Failed, and `IDP17-n/u` NOT_VERIFIED with specific reasons. Unverified observations fell from 559 to 550; distinct IDs remained 180. Keycloak/SimpleSAMLphp target LogoutRequests did not reach Suite and stayed unverified. See [target-message acceptance](31-peer-intent-acceptance.md).

### Diagnostic classification and SimpleSAMLphp encryption (2026-09-15)

<!--g1-literal--> Reasons for 548 unresolved observations were classified as `capability_diagnosis` without changing Verdict: suite-observation-gap 379, operator-attestation-available 77, evidence-form-mismatch 47, role-inapplicable 24, feature-absent 21. The key and fixed tokens were added to public diagnostics for future display, including OIDF Conformance skipped-equivalent presentation. Generated classification is in the [complete inventory](26-unverified-case-inventory.md).

<!--g1-literal--> SimpleSAMLphp Suite-SP metadata temporarily set `assertion.encryption=true`; browser_sso_idp/ecp_idp Runs returned EncryptedAssertions. RSA-OAEP-MGF1P satisfied `IIP-ALG06-a`; CBC content encryption left `IIP-ALG04.a` unresolved. Configuration was restored in place; after container restart PHP syntax and NULL value were verified. Unverified observations fell from 548 to 546.

### Reconciling saved evidence with the inventory (2026-09-17)

<!--g1-literal--> Saved result.json conclusions produced 24 candidates against the unresolved inventory. Only SimpleSAMLphp browser_sso_idp `IIP-IDP09-a-idp-01` Assertion-encryption capability was adopted as 1 observation. Unverified observations changed 518→517, distinct IDs 171→170, and baseline conclusions 76→77. No new product tests ran.

Adopted Run: `run_VRW5T0M31JGT71ZG6MR1JF92PJ`; source: `build/acceptance/reference-20260915/peer-intent/simplesamlphp/browser_alg_enc/result.json`; SHA-256: `503d257c71742219b1dac6574dc96ebf631cdc7642007c2c905b29e3cdc62b50`. `configuration.passive.assertion-encryption-capability` PASS was adopted. Decrypted EncryptedAssertion references `tx_5R7TGFK6S2CR86125YH70J5PQJ` and `tx_YTZYN207T7VA49N6WEY7N4EB5S` belong to the same Run and its already adopted ALG06.a evidence. The approved condition requires EncryptedAssertion returned for Suite metadata encryption keys; the evaluator verifies decryption under Run keys.

Old SLO nonissuance/unimplemented/consumption conclusions had been withdrawn by audit and were not readopted. SimpleSAMLphp SSO01.cz Warning had no evidence references and did not prove Subject evaluation inside an encrypted Assertion, so it was excluded. Old signature/error/NameID tests did not supply new evidence overcoming existing conclusions/reservations. Candidate decisions and source SHA-256 hashes are in `build/acceptance/reference-20260917/ledger-reconciliation/audit.json`.

Comparison generation now reads adopted Run/SHA-256/Verdict/reason from the inventory retest delta, preventing missing SLO adoption and redisplay of withdrawn results. A ledger-adopted FAIL absent from the comparison's product-cause confirmation list is labeled cause-classification-unconfirmed; this update does not newly authorize product attribution.

<!--g1-literal--> Product writes, restorations, browser operations, and user interactions: 0. Docker stayed stopped. This corrected missing adoption of historical evidence. The temporary allowed-signers file missing after restart was restored from the existing public signing key.

### Conclusions through SSO after native console import (2026-09-17)

<!--g1-literal--> Keycloak native metadata import and signed SSO automation concluded MD02.c, MD05.a4, MD05.a5, MD05.g, MD12.a, and MD12.c: 6 observations. Unverified changed 517→511; distinct IDs remained 170. It also exposed old PASS with signature verification disabled after KeyValue-only import; those 2 cases were not adopted. See [native console-import acceptance](34-native-metadata-import-acceptance.md) for prerequisites, settings, failed attempts, and evidence.
