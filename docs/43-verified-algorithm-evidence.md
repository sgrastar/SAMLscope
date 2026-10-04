# Signature-verified evidence for algorithm selection

## Shared verification and runtime evidence

`VerifiedSignatureAlgorithms` returns signature and digest algorithms and the verification key's SHA-256 only when a signature on the SAML Response or a direct child Assertion matches the expected Issuer, uses a Run trust key, and directly references the selected element. Message KeyInfo is never adopted as a trust anchor.

Duplicate IDs, another Issuer, wrong keys, modification after signing, changed SignatureMethod, and partial XPath signatures are excluded. An Assertion-only signature does not cover the whole Response. Failure to verify with permitted transforms is an observation limitation, not a product violation.

Saved SimpleSAMLphp Run `run_EF53BKR660XSH9Q27R8D4K1B41` was rechecked. Target metadata SHA-256 matched result.json metadata_digest. Only signing or unspecified-use certificates from the target entity's SAML IdP Role were trusted. Original XML hashes and request/response correlation were also checked.

<!--g1-literal--> Response and direct child Assertion signatures verified for all thirteen conditions; every condition used RSA-SHA256/SHA256. No additional product settings or SSO operations were performed: this was analysis of existing evidence.

`dev/reference-acceptance/VerifyMetadataAlgorithmSignatures.java` runs with the new SAML JAR and existing distribution dependencies on its classpath. Its `verified-algorithm-signatures.json` output covers only verified elements and their correlation; it does not directly change conformance verdicts.

## Comparison with advertised algorithms

`diagnose_metadata_algorithm_selection.py` compares verified algorithms with original fixture advertisements. Signature and digest selection are independent. A Role overrides Entity information only for the same advertised type. Missing declarations do not establish lack of support.

<!--g1-literal--> Counting signature and digest separately gave 26 observations: 4 without advertisements, 10 selecting the first algorithm, 6 selecting an unadvertised algorithm, and 6 selecting a later algorithm. These are not concluded-case counts. Later selection explicitly records unconfirmed local policy; all diagnostics set affects_verdict=false.

The additional Run, evidence paths, digests, and next actions were linked to SimpleSAMLphp MD05.ea/eb inventory entries. Original case-result Runs and Verdicts were not replaced.

## Remaining evaluation work

At this stage Suite MetadataFetch recorded variants but did not store delivered metadata XML as decodedSamlRef. External driver fixture originals and import records supplied that missing evidence. Internal automation must bind actual delivered XML, retrieval, native consumption, and the request/response for that same condition. Variant names alone cannot establish delivered contents.

Case implementation and registration still needed the approved MD05.ea local-policy exception, MD05.eb precedence per algorithm type, and positive/negative controls. Signature verification alone did not change results to Success/Failed.

## Validation and status

SAML regressions and additional negative controls were run. The first new test used a keystore Plan ID outside the permitted format; it was corrected to the existing format and the failed tests were rerun successfully. Runtime remained on v32; the new processing verified evidence offline.

<!--g1-literal--> The inventory remained at 483 unverified observations and 159 case IDs. Additional product configuration writes: 0; new Runs: 0; user interactions: 0. G1 generation matched, structural validation passed 46/46, and the inventory audit reported zero errors. The existing G2 signature difference remained unresolved; overall completion was not claimed.
