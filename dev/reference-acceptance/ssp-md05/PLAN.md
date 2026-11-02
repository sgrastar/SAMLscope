# SimpleSAMLphp MD05 campaign plan (a1, a2, e7)

Status: plan only. No product, Docker, network or configuration action has been taken, and the ledger is not updated.
Target: `metadata_idp` / SimpleSAMLphp 2.5.0, cases `IIP-MD05-a1-idp-01`, `IIP-MD05-a2-idp-01`, `IIP-MD05-e7-idp-01`.
Current state (docs/23, generated from measured results): all three are Not verified for SimpleSAMLphp. Keycloak and Shibboleth are Success for a1/a2.

## What each case needs (from tests/cases.yaml, unchanged)

| Case | Level / testability | Variants (all_of) | Controls |
|---|---|---|---|
| a1 `IIP-MD05.a1` | MUST / CONFIG | duplicate-entityID metadata offered as the control and rejected or treated as a conflict; two different entityIDs in one deployment | positive `idp-core-no-ecp`, negative mutant `mut-iip-md05-a1-idp`; a single entity never proves uniqueness, a secondary peer is required |
| a2 `IIP-MD05.a2` | MUST_NOT / CONFIG | two entities registered simultaneously with the same entityID but different keys and endpoints | positive / negative `mut-iip-md05-a2-idp`; overwrite or merge into an ambiguous state is not Satisfied; an explicit replacement is distinct from simultaneous references |
| e7 `IIP-MD05.e7` | MUST / CONFIG | order of two SigningMethods; order of two DigestMethods (tested individually) | positive / negative `mut-iip-md05-e7-idp` |

## Reuse

- a1/a2: model on the Shibboleth and Keycloak adopters (`verify_shibboleth_entityid_uniqueness_acceptance.py`, `verify_keycloak_metadata_entity_identity_acceptance.py`) and on `dev/simplesamlphp/configuration_batch.py` (single overlay, single restoration, inode-preserving). No SimpleSAMLphp entityID adopter exists, so one campaign script and one adopter are new.
- e7: `verify_metadata_algorithm_preference.py` (Shibboleth fixtures `algorithm-entity-order-256-384`, `-384-256`, `algorithm-role-order-*`) and `dev/simplesamlphp/default_algorithm_campaign.py`.

## Known risk, stated before running anything

- **a1/a2 mechanics are unconfirmed.** SimpleSAMLphp keeps remote SP metadata as a PHP array keyed by entityID (`saml20-sp-remote.php`) and can read several metadata sources. Whether duplicates are rejected, silently overwritten, or resolved by source order is the thing to measure. Only the product's own behaviour decides; silence or an overwritten key must not be turned into Satisfied or Failed without the approved controls (a2: overwrite or merge is not Satisfied).
- **e7 is the weakest of the three.** Earlier SimpleSAMLphp observations (docs/52) showed signatures stayed RSA-SHA256 and did not follow SHA384 declarations, and the capability control was not established. If the product ignores advertised algorithms, preference order cannot be observed, and e7 should stay NOT_VERIFIED (reason recorded, not a product FAIL). Plan: run one cheap capability check first (does the product ever change algorithm when only one method is advertised); only if yes, run the four ordering fixtures.

## Steps

1. Offline (no product): confirm the three cases exist in the adoption profile and the Run that will be used; confirm case digests and mutant ids; confirm the existing adopters' control lists apply (reject-everything / accept-everything must not pass).
2. Capture the original SimpleSAMLphp configuration and digest it. Record container image id, version, startup time.
3. a1/a2 campaign (one configuration overlay, one restoration):
   - control: single entity (baseline behaviour), distinct second peer with a different entityID (positive control).
   - duplicate entityID, different keys/endpoints, offered as simultaneous references; read back what the product holds and which entity answers each request.
   - negative control: the mutant fixture must be detected.
   - restore once; verify byte-identical restoration.
4. e7 capability check, then (only if it passes) four ordering fixtures with the positive and negative controls, one restoration.
5. Adopt only through the existing adopter pattern: archived Runner replay, request/response correlation, controls, restoration proof. Anything missing stays NOT_VERIFIED.
6. Regenerate comparison and inventory documents with their generators; record before/after counts, product-setting changes, write attempts, successful host writes, observed native applications, and restoration writes.

## Expected effect

At most 3 observations. Realistic range 0-3; e7 may well remain unverified, and a1/a2 depend on measured product behaviour.

## Operations budget (estimate)

Product configuration writes: about 2 per campaign (overlay + restoration) for a1/a2, about 2 more for e7 if it proceeds. Browser or human operations: 0 (protocol client). Docker: the existing SimpleSAMLphp reference container only.

## Needs your approval before execution

- Start the SimpleSAMLphp reference container and write its metadata configuration (restored afterwards).
- Create the new campaign script and adopter (code change) and run tests.
- Whether to proceed with e7 at all, given the risk above.
