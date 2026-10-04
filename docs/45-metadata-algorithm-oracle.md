# Integrating and validating metadata algorithm-selection oracles

## Evaluation scope

`MetadataAlgorithmConfigurationTestCase` was connected to M2 MD05.ea/eb. Confirmation establishes only readiness of native import; saved evidence determines Outcome. Confirmation is not an input for Verdict. Before confirmation the case does not complete automatically even with evidence; after confirmation insufficient evidence still yields NOT_VERIFIED.

`MetadataAlgorithmEvidence` checks Run-fixed IdP signing keys, metadata-original SHA-256, retrieval records, AuthnRequest Issuer/ACS/ID, Response Destination/InResponseTo, and verified signatures. Missing conditions are not filled from other campaigns. Modified responses or originals, another Run, ambiguous request IDs, or missing retrieval correlation remain unverified.

`MetadataAlgorithmSelection` handles signature and digest independently. Only Role advertisements of the same type override Entity information. A Digest-only Role must not discard Entity signature information. Ordering respects the local-policy exception: order mismatch alone does not cause Warning or Failed. Cases return Outcome; Evaluator converts it to Verdict.

## Evaluating saved runtime evidence

Evidence from Run `run_ZTEB6PCRWXJM0CZ6QWCZRR966T` was reused. The target is SimpleSAMLphp's static metadata import through its native parser, not other import modes or product-wide conformance.

| Case | Result | Evidence and limits |
|---|---|---|
| IIP-MD05-eb-idp-01 | Failed | Verified signed responses used SHA256 when Role SigningMethod, DigestMethod, or both advertised SHA384 in conflict with Entity information. Reverse conflict with Role SHA256 and independent single-algorithm conditions were also executed. |
| IIP-MD05-ea-idp-01 | NOT_VERIFIED | Reversing advertisement order still selected SHA256, but SHA384 availability and local policy were unconfirmed. Order mismatch was not treated directly as a violation. |

Product source `modules/admin/src/Controller/Federation.php` confirmed `SAMLParser::parseDescriptorsString` → `getMetadata20SP`, followed by removal of `entityDescriptor`/`expire`, matched the native static conversion. Information lost through Suite-specific attribute conversion was not labeled a product failure. Original equality, read-back, and restoration were bound to the previous evidence.

<!--g1-literal--> The inventory changed from 483 to 482 unverified observations; distinct case IDs remained 159. Diagnostics and unit tests are not counted as resolved observations. The original baseline of 594 observations had 112 conclusions, not a complete test run.

Evidence is in `build/acceptance/reference-20260918/algorithm-oracle-evaluation/`; import originals and protocol evidence are in `simplesamlphp-algorithm-recorded-metadata/`. `verify_metadata_algorithm_outcomes.py` checks original hashes, preparation confirmation, import/restoration, signature verification, Outcome, and evidence references before generators adopt only eligible cases.

## Integration gaps and validation

Runtime integration exposed a missing Transcript dependency in the M2 registry and an existing manual-verdict guard blocking preparation confirmation. Both were fixed. Only cases explicitly declaring `requiresPreparationConfirmation` can confirm preparation. Manual confirmation remains prohibited for other Transcript-evaluated cases. PendingInteraction uses the same contract.

API integration tests verify the case exists in the release metadata profile and preparation confirmation through the API remains unverified without evidence. Runner tests cover signature-verified positive/negative controls, Roles advertising only one type, mixed campaigns, and modified responses/originals.

<!--g1-literal--> Runner: 493 tests; API: 88 tests; no failures or skips. G1 generation, structural validation, and inventory audit passed. The existing G2-30 signature difference remained unresolved; release approval was not complete.

## Operation cost

<!--g1-literal--> Thirteen saved conditions were reused. Product configuration writes: 0; native reimports: 0; new Runs: 0; preflight: 0; new protocol exchanges: 0; product restarts: 0; user interactions: 0. Preparation confirmations: 2 successful, 1 failed attempt. Including integration fixes, Docker builds: 3; Suite/forwarder recreations: 3 each. Previous import operations were not counted again.

Final runtime was `samlscope:reference-algorithm-oracle-v36`, digest `sha256:eb97a0ff7e3c0e9f870fe3eb61877695143a0f80b9a5f1890ade796e344409a2`. Unrelated API SOAP differences were excluded from deployment. Counts are in `operations.json` in the evidence directory above.
