# Published UI notes and aggregate-metadata retest

## Concluded scope

<!--g1-literal--> Unverified observations 500→490; distinct case IDs 164→161. Added Success 1, Warning 9, Failed 0. This is not full completion or release approval.

| Case | Keycloak | Shibboleth | SimpleSAMLphp | Evidence |
|---|---|---|---|---|
| IIP-MD05.f7 | Warning | Warning | Warning | Target IdP publishes no Description |
| IIP-MD05.f8 | Warning | Warning | Warning | Target IdP publishes no Logo |
| IIP-MD05.fa | Warning | Warning | Warning | Target IdP publishes no InformationURL |
| IIP-MD02.d | Outside this batch | Outside this batch | Success | All specified aggregate child counts parsed natively; signed SSO observed at imported ACS |

Absence notes use the approved interpretation_constraints satisfied_with_note branch, not inferred lack of a consumer UI or NOT_APPLICABLE. Published text usefulness, image background and URL-content comparisons are not automatically satisfied.

## Implementation and evidence

AutoBrowserMetadataEvidenceTestCase is connected through withPublishedMetadata. Passive inspection requires Run-fixed metadata to be one EntityDescriptor matching the Plan entityID. Missing/different entities, aggregate roots or parsing failure retain existing unresolved paths. Separately emitted invalid-signature controls are excluded from normal-flow readers.

Evidence root: build/acceptance/reference-20260918/. verify_publisher_ui_batch.py checks original metadata SHA-256, target entity, absence, Run and outcome before adoption. Aggregate import uses the existing native-import verifier for original fixture, parser output, restored settings and signed-response correlation.

| Product/trial | Run | Folder |
|---|---|---|
| Keycloak published UI | run_J107HRR1BXY7GHBHTDDMY87308 | publisher-ui-scoped/keycloak |
| Shibboleth published UI | run_G7RK00MQC0WZXS14JPFQPV8NKZ | publisher-ui-scoped/shibboleth |
| SimpleSAMLphp published UI | run_HNDN6YMHP5NZ9AP1GHB21V3AQH | publisher-ui-scoped/simplesamlphp |
| SimpleSAMLphp aggregate import | run_47A3XNG2QG2D7E64BDWH6XW5S3 | simplesamlphp-aggregate-import |

Image: samlscope:reference-publisher-ui-v26; digest sha256:d91fa5493d44486d3fccba02bcd632651ed778aa23afc3c1fa120525af0486c6.

## Non-adoption and remaining work

MD06.a1 is not adopted despite raw PASS: endpoints/keys were not used for every nested entity. The driver installs only the selected entity from parser output. A complete entity-use harness and stronger oracle evidence conditions remain necessary.

The initial UI retest remained unresolved because of missing execution wiring. The first connected image then failed startup because it rejected existing UnavailableBrowserOracleTestCase. Corrected the type constraint, recovered, added target-entity matching and adopted only final fresh Runs. Failed evidence is retained.

## Costs and verification

<!--g1-literal--> Docker builds 3; Suite/forward recreations 3 each including one failed startup; Run creation 7; preflight 8; tests/start attempts 8 including one rejection before initial login. Published-UI setting writes 0; aggregate imports 6; configuration writes 13 (12 install/restores plus final restoration); direct user actions 0; product restarts 0. Restoration matched original SHA-256.

<!--g1-literal--> Runner regression passed, followed by target-entity matching and incomplete-type wiring tests. G1 generation/structure passed 46/46. G2 remained 20/21 due to protected-source G2-30; no renewed approval is claimed. Inventory audit was consistent at 490 observations / 161 case IDs.
