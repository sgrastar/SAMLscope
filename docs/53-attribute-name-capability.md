# Evidence of attribute Name and NameFormat generation capability

Connected evaluation of product-generated attributes to the CONFIG path of approved `IIP-IDP01-a-idp-01`. Preparation confirmation alone does not pass: evaluation checks same-Run AuthnRequest/normal Response correlation, ACS, signature verification against certificates in fixed target metadata, and Assertion Issuer. Encrypted Assertions are decrypted with Run keys, and any enclosed signature is verified. Attribute values are not saved in diagnostics.

<!--g1-literal--> The 3 required conditions are a URN Name, a non-URI string Name, and an unknown NameFormat URI. Test names are `urn:samlscope:test:attribute-name` and `SAMLscope arbitrary attribute`; NameFormat is `urn:samlscope:test:attribute-name-format`. Tests require NOT_VERIFIED for missing conditions, modified signatures, request-correlation/ACS mismatches, incomplete history, duplicate records and preparation confirmation alone.

## Product results

| Product | Adopted Run | Result |
|---|---|---|
| SimpleSAMLphp | `run_4GWY98RD670EAFJ3R8Q6V2MW52` | Success |
| Shibboleth | `run_8S5P9BVTX8CCQ770M2KHKXG5CM` | Success |

<!--g1-literal--> For both products, all 3 conditions were unobserved in the ordinary-configuration control and observed after attribute settings restricted to the test SP. Original hashes, signatures, decryption results and restored configuration were independently checked before formal-result adoption. Unverified observations decreased 472→470; distinct case IDs remain 157. The Keycloak case remains unverified.

SimpleSAMLphp records native metadata-parser import separately from test-SP AttributeMap/NameFormat configuration. Shibboleth uses a temporary metadata provider, attribute-resolver encoders and a target-SP-only release policy. Original/restored configuration SHA-256 equality was verified.

The first Shibboleth Run, `run_GRQ3P0CQSEVDVKV84W0HTT10KE`, observed none of the conditions. It is retained as a failed attempt caused by missing attribute-registry reload. The [official AttributeEncoder configuration](https://shibboleth.atlassian.net/wiki/spaces/IDP5/pages/3199504645) also documents that adding/removing inline encoders requires registry reload. Added reloads on application/restoration and retested in a separate Run.

Evidence under `build/acceptance/reference-20260918/`: `simplesamlphp-attribute-name-capability/`, `shibboleth-attribute-name-capability/`, `shibboleth-attribute-name-capability-registry/`. `VerifyAttributeCapability.java` revalidates Response signatures using fixed metadata and extracts only attribute names/formats, keeping private keys in the container. `verify_attribute_name_capability.py` checks controls, original hashes, adopted results and restoration records before updating the inventory.

## Operations and validation

<!--g1-literal--> Product configuration and related writes total 19: SimpleSAMLphp 3, initial Shibboleth attempt 8, retest 8, including 2 temporary-file deletions. Service reloads 14; ordinary SSO 6; Run creation/preflight/preparation confirmation 3 each. Docker build 1; Suite/forwarder recreations 1 each; product restarts 0; user interactions 0. Initial-failure costs are included.

<!--g1-literal--> 16 targeted Runner tests and the API distribution build passed. G1 generated-document consistency/structural checks 46/46; no inventory-audit errors. G2 remains 20/21 because of existing protected-implementation signed-source difference G2-30; this is not reapproval.

Running image: `samlscope:reference-attribute-name-v41`; digest: `sha256:2cd23990e237f2ff8225e36254d8b953f58e68d973771209c49cd11ca0a7045a`. Only this campaign's Runner artifact was overlaid on the preceding image; unrelated API working-tree changes were excluded.
