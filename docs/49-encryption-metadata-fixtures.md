# Fixtures for encryption algorithms, OAEP parameters, and key sizes

## Implemented scope

`MetadataEncryptionAlgorithmFixtures` was connected to ordinary, polling, and preloaded generation. It adds `md:EncryptionMethod` to encryption or unspecified-use SP KeyDescriptors, excluding signing-only KeyDescriptors and IdP Roles.

<!--g1-literal--> Fifteen inputs cover AES128/256 CBC/GCM single advertisements, reversed GCM order, explicit KeySize, old/new RSA-OAEP with SHA1/SHA256, explicit/omitted MGF, and rejection of the first signature candidate by MaxKeySize.

Key-size exclusions deliberately create ineligible fixture candidates; they are not Suite-defined security thresholds. Later candidates have no extra restrictions. Omitted MGF differs from explicit MGF1-SHA1, and old RSA-OAEP has no MGF element added.

`dev/shibboleth/import_metadata_batch.py` gained an option to continue after an unobserved non-baseline condition. Configuration-load failures and baseline failures still stop execution. Advancing a campaign does not establish rejection or a Verdict.

## Runtime observations

Shibboleth Run `run_054AFN63J7RV1NZNFRYS65PDN7` passed original XML to the native FilesystemMetadataProvider.

<!--g1-literal--> All sixteen conditions, including controls, confirmed equality between original XML and Suite originals, normal SSO, Response signature verification under the Run-fixed IdP key, and configuration restoration.

Encrypted responses switched CBC/GCM according to single advertisements and followed reversed GCM order. RSA-OAEP responses matched advertised algorithms, digests, and MGF. The omitted-MGF advertisement produced an explicit MGF1-SHA1 response; it was not recorded as an omitted-MGF response.

`observe_metadata_encryption_batch.py` records encrypted headers inside signed responses and their advertisements. Headers do not establish successful decryption, so this diagnostic supplies no Verdict.

## Decryption and negative controls

`VerifyMetadataEncryptionDecryption.java` ran inside the Suite container. It matched original fixture encryption certificates to existing variant public keys, then decrypted original responses with the corresponding keys. The same ciphertext failed under another variant's key. Private keys stayed inside the container; plaintext was not saved. Results contain only condition IDs, evidence references, and facts such as successful decryption and wrong-key failure.

<!--g1-literal--> Correct-key Assertion decryption succeeded in all sixteen conditions; wrong-key controls failed in all sixteen. The first attempt computed results but could not save them because of evidence-directory ownership. Output was moved to a writable temporary file inside the container and verification reran. The failed output attempt was recorded and not adopted.

## Remaining integration and inventory

Existing ALG04/06 browser observations use normal SSO Run keys and exclude metadata campaign responses. These conditions use variant-specific keys, requiring explicit decryption-key supply and original/response correlation in the evaluation path. Keys must not be inferred merely from fixture advertisements.

Remaining work includes complete MD05.e/e8 conditions and controls and ALG04/06 integration in applicable profiles. This evidence was linked as additional observations to related Shibboleth unverified inventory entries.

<!--g1-literal--> The inventory remained at 475 unverified observations and 157 case IDs. Fifteen inputs, sixteen normal-flow conditions, and sixteen decryptions were not counted as newly concluded observations.

Evidence is in `build/acceptance/reference-20260918/shibboleth-encryption-metadata/`. `encryption-selection-observations.json` and `verified-encryption-decryption.json` save observations, decryption results, and original evidence hashes.

## Validation and operation cost

SAML regressions checked ordinary/polling algorithm order, KeySize, algorithm-specific parameters, and explicit versus omitted MGF. Existing signature verification across all variants also passed. G1 generation, structural validation, and inventory audit ran. The existing G2 signature difference remained unresolved.

<!--g1-literal--> Product metadata writes: 16; provider application/restoration writes: 2; temporary-file deletion: 1 (19 write operations); metadata-service reloads: 17. Normal SSO attempts: 16; invalid-signature controls: 16; Run creation: 1; preflight: 1. Docker builds: 1; Suite/forwarder recreations: 1 each; product restarts: 0; user interactions: 0. Decryption checks: 2, including the failed output attempt.

Runtime was `samlscope:reference-encryption-metadata-v38`, digest `sha256:07f31932ce130b97f6e93ae8a17bba1682a381e6318a1a9f6b984dce46c9cde8`. Only the SAML JAR changed.
