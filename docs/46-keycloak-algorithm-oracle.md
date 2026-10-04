# Extending algorithm-selection tests to Keycloak

## Execution and results

The common MD05.ea/eb evaluator was used with Keycloak's native console importer. Original fixtures were uploaded to `Import client`; successful save-page transitions were matched against administration API read-back before sending Suite-generated normal and invalid-signature controls. Each created client was deleted after its fixture and absence was read back. Suite did not convert XML to its own administration API attributes.

<!--g1-literal--> Run `run_SMA5VXA5EDP001PKPR37ZR2893` completed import, normal SSO, and cleanup for all thirteen conditions. Byte equality with Suite originals and Response signature verification under the Run-fixed IdP key were confirmed for all thirteen.

| Case | Result | Evidence and limits |
|---|---|---|
| IIP-MD05-eb-idp-01 | Failed | Verified responses used SHA256 when Role SigningMethod or DigestMethod advertised SHA384 in conflict with Entity information. Single-algorithm and reverse-conflict conditions were also executed. |
| IIP-MD05-ea-idp-01 | NOT_VERIFIED | Reversed order still selected SHA256, but local policy and SHA384 availability were unconfirmed. |

Conclusions are limited to the tested Keycloak reference environment's native console import path. The same original-byte, request/response-correlation, and signature-verified evaluator used for SimpleSAMLphp was reused without product-specific evaluation rules. Silence after invalid-signature requests or campaign termination alone was not evidence of violation.

<!--g1-literal--> Unverified observations changed from 482 to 481; distinct case IDs remained 159. Together with SimpleSAMLphp, the change was 483 to 481. Of the original 594 observations, 113 were concluded.

## Evidence and auditing

Evidence is in `build/acceptance/reference-20260918/keycloak-algorithm-metadata/`; preparation confirmation and evaluation are in `keycloak-algorithm-evaluation/`. Import-time results were preserved; post-evaluation results were saved separately.

`native_algorithm_preparation.py` adds common native-import auditing. Keycloak requires fixture SHA-256, successful-save UI and client DB ID, entityID read-back, a correlated normal flow, and post-deletion absence. SimpleSAMLphp retains parser-output hashes, read-back, and restoration checks. Only cases passing `verify_metadata_algorithm_outcomes.py` were adopted into generated inventory.

Previously verified Java code and runtime images were reused. Saved-evidence checks for both products, inventory auditing, G1 generation, and structural validation ran. The existing G2-30 signature difference remained unresolved; release completion was not claimed.

## Operation cost

<!--g1-literal--> Native UI imports: 13; client creations/deletions: 13 each (26 product configuration writes); normal SSO attempts: 13; invalid-signature controls: 13; Run creation: 1; preflight: 1; preparation confirmations: 2. Docker builds: 0; Suite recreations: 0; product restarts: 0; user interactions: 0. Automation ran in background Chrome. Post-deletion read-back confirmed absence for every client.

Counts are in `keycloak-algorithm-evaluation/operations.json`. Reusing the common evaluator avoided redeployment for the additional product.
