# Native SimpleSAMLphp encrypted response observations

`dev/simplesamlphp/producer_algorithm_campaign.py` was added. Using the same configuration restoration/read-back foundation as signature-mode comparison, it records unencrypted, encrypted, and repeated encrypted exchanges for a temporary SP whose normal original metadata is passed to the product's own parser. Standard `assertion.encryption` settings change while Response and Assertion signatures remain enabled. Suite does not replace the product's generation implementation.

## Originals and formal determination

Originals for Run `run_BTJPR0GYG7H7FMBJRCJ7Z699RK` remain in `build/acceptance/reference-20260918/simplesamlphp-native-producer-encryption-normal/`. Encrypted responses used `aes128-cbc`, key transport `rsa-oaep-mgf1p`, and SHA-1 with DigestMethod omitted. These observations do not imply AES-GCM or other OAEP support.

`VerifyNativeProducerAlgorithms.java` also supports SimpleSAMLphp comparison. Private keys are used within Suite's read-only volume and not exported. It checks original AuthnRequest Redirect signatures, Response signatures with the fixed target key, and decrypted Assertion signatures. It also verifies decryption failure with another private key and signature failure for altered Responses. Plaintext Assertions are not saved. Required condition counts for existing Keycloak comparison remain unchanged.

Formal protocol-evidence evaluation produced `SATISFIED / PASS / browser.encryption.rsa-oaep-mgf1p.decrypted` for `IIP-ALG06-a-idp-01`. `verify_ssp_producer_acceptance.py` matches original hashes, target/Run identity, configuration read-back, restoration, cryptographic verification results, and formal determination evidence references. Accepted settings or HTTP completion alone do not establish Success. However, the current generated inventory already resolved this case through another demonstration. This result remains additional evidence, adds no new resolution, and does not change the existing adoption source.

<!--g1-literal--> Unverified observations remain 429. Other algorithms are not determined from this observation. New unit-test groups or full tests were not run in this small batch and remain for combined verification of related implementation. Original verification for the additional demonstration was executed.

## Failed attempts and configuration work

The initial `simplesamlphp-native-producer-encryption/` attempt explicitly used Suite `variant=control`, putting ACS on the metadata-test path. Normal login therefore remained incomplete and the profile-start API rejected the request. This is not classified as product failure. The metadata URL was corrected to the normal path and a new Run executed; initial originals are retained.

Both attempts restored configuration to original bytes and verified matching hashes. Concurrent changes are not overwritten. Runtime settings were added only to a temporary SP; existing SP settings remained unchanged.

<!--g1-literal--> Including failed attempts: Run creation/preflight 2 each, product configuration writes 8 (including restoration 2), native read-backs 6, AuthnRequest/Response 6 each, profile-start attempts 2 (failed 1), formal evidence evaluation 1. Product restarts, Docker builds, Suite recreation, and user interactions 0. Temporary original-verification container executions 1. Recorded in `batch-operations.json`. No commit was made.

Earlier source changes for the MDIOP certificate adapter and attribute-policy reevaluation are not yet included in this running image. This determination uses existing encryption evaluation and does not validate those pending changes.
