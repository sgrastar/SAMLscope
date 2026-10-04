# Evaluating shared metadata algorithms and parameters

## Formal evaluation scope

`IIP-MD05-e8-idp-01` was connected to measured M2 CONFIG evaluation. `MetadataAlgorithmEvidence` supplies exchanges binding original metadata, retrieval records, outbound requests, and verified Responses. `MetadataIntersectionEvidence` checks approved encryption, signature, digest, key-size, and algorithm-specific parameter intersections.

Preparation confirmation establishes only that native import received the fixture. Confirmation or successful XML import alone cannot yield Success. Response signatures use Run-fixed target metadata keys; fixture decryption keys must match original SP public keys. Encrypted Assertions are actually decrypted, and contained signatures are verified if present. Neither private keys nor decrypted plaintext are stored in evidence.

<!--g1-literal--> Thirteen required conditions, including controls, cover SHA256/384 signatures and digests, AES128/256 GCM, CBC with explicit KeySize, old/new RSA-OAEP with SHA1/SHA256 and MGF, and signature-candidate exclusion through MaxKeySize in one campaign.

Partial evidence from different campaigns is not combined. Original mismatch, unverified signatures, unsuccessful decryption, missing conditions, or missing controls yield NOT_VERIFIED. Measured SHA256/384 generation capability is also required; unknown capability is not converted to product violation. Exclusion key sizes are test inputs, not Suite-defined security thresholds. Cases return Outcome; the existing Evaluator converts it to Verdict.

## Runtime results and inventory

Shibboleth Run `run_6E5BWBMYHJFZS31AKS9Q1WCP72`, Plan `plan_G5ZG6VA64WK6T2RTS6ACYCCT50`, passed original fixtures to a temporary FilesystemMetadataProvider and ran SSO per condition. Provider and configuration were restored; temporary-file absence and original configuration hashes were confirmed.

<!--g1-literal--> Originals, signatures, and correct-key decryption were confirmed for all thirteen conditions. Wrong-key decryption was rejected in all thirteen. Missing conditions, evidence problems, and selection mismatches were empty. MD05.e8 produced `SATISFIED / PASS`, reason `metadata.algorithms.intersection-observed`.

Evidence is in `build/acceptance/reference-20260918/shibboleth-intersection-metadata/`; formal results and preparation grounds are in adjacent `shibboleth-intersection-evaluation/`. Originals were preserved alongside before/after evaluations. `verify_metadata_intersection.py` checks hashes, native import/restoration, signatures, decryption, every condition, and result references before adoption.

<!--g1-literal--> Unverified observations changed from 475 to 474; distinct case IDs remained 157. Conditions and added tests are not resolved-observation counts. No new product FAIL was recorded.

## Validation and operator effort

Tests cover complete controls, a mutant ignoring key-size restrictions, missing conditions, mixed campaigns, corrupt inputs, wrong keys, and incorrect OAEP parameters. Existing signature-algorithm/Role-precedence regressions also ran. API tests verify M2 registration and that preparation confirmation without evidence cannot yield Success.

<!--g1-literal--> Product metadata writes: 13; provider application/restoration writes: 2; temporary-file deletion: 1; total write operations: 16. Service reloads: 14; normal SSO attempts: 13; invalid-signature attempts: 13. Run creation/preflight: 1 each. Docker builds: 1; Suite/forwarder recreations: 1 each; product restarts: 0; user interactions: 0. Decryption verification: 1; preparation confirmation POST: 1. One result-read request returned 404 because of an incorrect URL; that URL was corrected.

Runtime was `samlscope:reference-intersection-v39`, digest `sha256:17c47a45e48bcefde75e45b500a4f823248a41f124e39cb0428cab9d699ee31a`. Existing uncommitted SOAP changes were excluded from the image.

<!--g1-literal--> Targeted Runner tests: 12; API tests: 8; all passed. G1 generation matched and structural validation passed 46/46; the inventory audit reported no errors. G2 passed 20/21, with only the existing G2-30 signature difference outstanding.

## Continuing work

This evaluation covers the consumer's shared metadata algorithm selection. Full MD05.e extension coverage, other products, and ALG04/06 integration in applicable browser/ECP profiles were not considered resolved. The existing protected G2 source-signature difference remained outstanding; release readiness was not claimed.
