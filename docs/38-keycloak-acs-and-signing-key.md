# Keycloak default ACS evidence and unique signing-key observation

## Adopted results

<!--g1-literal--> Unverified observations 489→485; distinct IDs 161→159. Added Warning 3, Failed 1, Success 0. Concluded conformance observations are not the same as product successes.

| Case | Keycloak | Shibboleth | SimpleSAMLphp |
|---|---|---|---|
| IIP-MD05.ae: signing-key identification | Warning: unique signing key | Warning: unique signing key | Warning: unique signing key |
| IIP-IDP12.c: default ACS response | Failed in the investigated native import path | Existing result retained | Existing result retained |

## Unique signing-key branch

The approved definition explicitly makes identification trivial with one candidate. TargetMetadataObservation now implements this through the existing CONFIG path.

Inspect signing/use-omitted KeyDescriptors in the target IdP role of a single EntityDescriptor. Deduplicate actual certificate public-key values; encryption-only keys are excluded. Missing or multiple distinct keys, unknown representations, accompanying KeyValue, parsing failure or absent target role preserve the unresolved path. Matching real signatures to multiple candidates is outside this batch.

Original SHA-256, entityID, Run and result are checked. The adopter independently extracts certificate public keys with OpenSSL, rather than inferring uniqueness from names or certificate-object equality.

## Why the Keycloak difference is product behavior

The original fixture was imported by Keycloak Import client and saved settings read back. Suite then emitted a signed AuthnRequest with ACS URL, index and ProtocolBinding all omitted. Fixture SHA-256, temporary client, request ID, Response InResponseTo and actual reception URL are bound together.

| Input | Metadata-selected ACS index | Actual response index |
|---|---|---|
| First isDefault=true | 0 | 0 |
| Next ACS isDefault=true | 1 | 0 |
| All omitted | 0 | 0 |
| First false, next omitted | 1 | 0 |
| All false | 0 | 0 |
| Multiple true | 0 | 0 |

Normal controls succeed. Unique updated fixture URLs and signing keys were actually imported and valid signed requests answered, excluding stale configuration, failed import, silence and unreachable endpoints. The violation is the wrong response destination when the default index changes, not signature/configuration failure.

Running keycloak-services EntityDescriptorDescriptionConverter bytecode corroborates the measured location: getServiceURL selects the first matching-binding ACS Location without consulting isDefault. This matches imported saml_assertion_consumer_url_post and actual responses. Bytecode is corroboration, not the sole Verdict basis.

<!--g1-literal--> Scope is Keycloak 26.7.2, this console-native import path and reference configuration. Do not generalize to other versions, manual settings or import methods, or transfer the result to separate obligations such as IIP-MD05.av.

## Originals and operations

Root: build/acceptance/reference-20260918/.

| Trial | Run | Folder |
|---|---|---|
| Keycloak default ACS | run_ZZQH3B5136N955F9W1NAMJ4GSG | keycloak-default-acs |
| Keycloak signing key | run_J5EY454Z5ZD3J7Q89SWCFNJNHD | single-signing-key/keycloak |
| Shibboleth signing key | run_2893MAJ9X84M3TVFWRNY5CAPK4 | single-signing-key/shibboleth |
| SimpleSAMLphp signing key | run_816C536YJ0JK4DB1KCMG2QQNH5 | single-signing-key/simplesamlphp |

Fixture, UI success, API read-back, deletion, request/response originals, manifest and running JAR/class hashes are retained. Only results passing audit_keycloak_default_acs.py and verify_single_signing_key_batch.py are adopted by generators.

<!--g1-literal--> Costs: Keycloak imports 7; setting writes 14 (7 creates/7 deletes); Runs 4; preflight 4; Suite/forward recreations 1 each; docker build 1; user actions 0; product restarts 0. API absence verified for every deleted client. Passive key observation changed no product configuration.

Image: samlscope:reference-single-key-v28; digest sha256:1153608d19ca6901efaefd94f1fa6ce7d09ce860a3701a4c02b73d88a5750cae. Runner regression passed; G1 generation/structure verified. Existing G2 signed-source differences remained unresolved.
