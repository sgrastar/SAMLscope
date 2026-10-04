# Execution fixtures for metadata algorithm order and Role precedence

## Inputs and scope

The approved IIP-MD05.ea/eb definitions and the Metadata Consumers section of SAML2MetaAlgSup were reviewed before adding algorithm-selection inputs to the metadata campaign. Signature and digest algorithms are handled separately. A Role advertising only DigestMethod must not cause an implementation to discard the Entity-level SigningMethod.

<!--g1-literal--> Twelve fixtures were added. Together with the normal control, they provide thirteen batch conditions through both HTTP import and preloaded generation. They were not yet registered with an oracle at this stage; successful SSO alone does not establish these obligations.

| Fixture suffix (common prefix `algorithm-`) | Input |
|---|---|
| entity-sha256 / entity-sha384 | Single signature and digest algorithm controls |
| entity-order-256-384 / entity-order-384-256 | Reversed Entity-level algorithm order |
| role-order-256-384 / role-order-384-256 | Reversed SP Role-level algorithm order |
| role-signing-384 | Entity uses SHA256; Role overrides only the signature algorithm with SHA384 |
| role-digest-384 | Entity uses SHA256; Role overrides only the digest algorithm with SHA384 |
| role-both-384 / role-both-256 | Conflicting Entity and Role advertisements |
| unsupported-first | Unknown algorithm followed by supported SHA256 |
| absent | No advertisement of either type; absence does not establish lack of support |

SAML regression tests covered signature integrity for every existing variant, reversed order, overrides of only one algorithm type, and absent declarations. Approved G1 definitions were unchanged.

## Observation through the product's own importer

SimpleSAMLphp Run `run_EF53BKR660XSH9Q27R8D4K1B41` passed original fixtures to the native metadata parser. It recorded signature-required configuration read-back, Suite-issued signature controls, Responses correlated to normal AuthnRequests, and restoration of the original configuration.

<!--g1-literal--> All thirteen conditions produced correlated Success Responses. Both Response and Assertion SignedInfo advertised RSA-SHA256/SHA256 throughout, including conditions advertising SHA384 alone or only at Role level.

`dev/reference-acceptance/observe_metadata_algorithm_batch.py` saves original XML and hashes, verifies normal request-ID correlation, fixture hashes, import records and restoration, and compares Entity/SP Role advertisements with response SignedInfo. Responses to invalid-signature controls are excluded from normal observations. Its diagnostic output explicitly sets `signature_verified: false` and `affects_verdict: false`; it does not replace cryptographic verification or conformance evaluation.

Evidence is in `build/acceptance/reference-20260918/simplesamlphp-algorithm-metadata/`. These observations alone do not establish product-wide SHA384 absence, ordering violations, or Role-precedence violations. Ordering must respect the approved local-policy exception.

## Remaining oracle integration

- Verify Response/Assertion signatures using trust keys in the Run's target metadata before observing SignedInfo.
- Bind metadata retrieval and native import to the corresponding request/response evidence within one campaign.
- For MD05.ea, evaluate single-algorithm controls, reversed order, and local policy.
- For MD05.eb, evaluate signature and digest algorithms independently. Stop Entity inheritance only when the Role advertises that same type.
- These fixtures do not cover all MD05.e EncryptionMethod, KeySize, or algorithm-specific extensions; add those separately.

## Operation cost and status

<!--g1-literal--> Native imports: 13; Run creation: 1; preflight: 1; product configuration writes: 27 (each application/restoration plus final restoration); signature-control requests: 13; normal requests: 13; Docker builds: 1; Suite/forwarder recreations: 1 each; user interactions: 0; product restarts: 0. SHA-256 equality confirmed complete restoration.

The deployed image was `samlscope:reference-algorithm-metadata-v32`, digest `sha256:40595feb47f0d34de4cdfeffa4315f27700b78b93211f1d8d32836cbc051fc08`. Only the SAML JAR was overlaid onto the previous shared-key-input image. Deployment records are in `build/acceptance/reference-20260918/algorithm-metadata-runtime/`.

<!--g1-literal--> This batch adopted zero conclusions. The inventory remained at 483 unverified observations and 159 case IDs. G1 generation matched and structural validation passed 46/46. The existing G2 signature difference remained unresolved; this record is not release approval.
