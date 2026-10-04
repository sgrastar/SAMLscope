# Native Shibboleth loading and algorithm-selection validation

## Execution path

`dev/shibboleth/import_metadata_batch.py` writes original fixtures unchanged to a dedicated temporary file for Shibboleth's standard `FilesystemMetadataProvider`. No Suite XML-to-product-attribute conversion is involved. Each condition checks byte equality and service reload, then executes Suite-issued normal and invalid-signature controls.

The original `metadata-providers.xml` is restored byte for byte and reloaded on exit, and temporary files are deleted. Failure paths restore through `finally`. Existing SP metadata files are unchanged. This path can also serve later metadata campaigns.

## Runtime results

<!--g1-literal--> Run `run_XZ4CY23XHSV2NPFTDW2H0EVZCS` completed loading, normal SSO, and restoration for thirteen conditions. Suite originals matched product input XML, and Response signatures verified under the Run-fixed IdP key in every condition.

| Case | Result | Observation |
|---|---|---|
| IIP-MD05-ea-idp-01 | Success | Reversing Entity/Role advertisement order switched signature and digest selection to the first SHA256/SHA384 algorithms. Single-algorithm conditions were also verified. |
| IIP-MD05-eb-idp-01 | Success | Conflicts were resolved in favor of Role information for each type. A Role advertising only one type preserved Entity information for the other. Reverse conflicts were also verified. |

<!--g1-literal--> Unverified observations changed from 481 to 479; distinct case IDs changed from 159 to 158. MD05.eb now had measured conclusions for all three reference products. Of the original 594 observations, 115 were concluded; the remaining inventory was not completed.

The existing common evaluator correlated originals and verified signatures. Some invalid-signature controls reported `unhandled location` at the Suite ACS completion page; that UI output was not used to determine normal-request success. Correlated SAML Success responses were checked separately using saved request IDs.

## Evidence and validation

Original XML, flows, service reloads, and restoration are in `build/acceptance/reference-20260918/shibboleth-algorithm-metadata/`. Preparation confirmations and post-evaluation results are in `shibboleth-algorithm-evaluation/`; import-time results were preserved.

`native_algorithm_preparation.py` now checks FilesystemMetadataProvider read-back/reload, original configuration hashes, and temporary-file removal. `verify_metadata_algorithm_outcomes.py` compares originals, preparation, signature verification, and case evidence references before adoption. Product-specific expected results reside in acceptance audits, not product-name branches in the common evaluator.

The verified Java runtime was reused. Evidence audits, generated inventory consistency, G1 generation, and structural validation ran. The existing G2 signature difference remained unresolved.

## Operation counts

<!--g1-literal--> Metadata file writes: 13; provider application/restoration writes: 2; temporary-file deletion: 1 (16 product write operations); metadata-service reloads: 14. Normal SSO attempts: 13; invalid-signature controls: 13; Run creation: 1; preflight: 1; preparation confirmations: 2. Docker builds: 0; Suite recreations: 0; product restarts: 0; user interactions: 0.

Counts are in `shibboleth-algorithm-evaluation/operations.json`. Per-condition service reloads remain a target for reduction in future batched HTTP-refresh campaigns.
