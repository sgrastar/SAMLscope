# Keycloak evidence of SP-specific attribute release

`IIP-IDP02-a-idp-01` requires attribute-release configuration according to SP entityID, not product-native metadata interpretation. Preparation configures native clients/User Property mappers through the administration API. Suite extraction of XML configuration values is not evidence of Keycloak metadata interpretation.

## Matching preparation to originals

`dev/keycloak/relying_party_attribute_campaign.py` obtains entityID, POST ACS and public keys from a scoped preload aggregate. It rejects overwriting existing clients and creates test-only clients. Standard `saml-user-property-mapper` copies shared `firstName` to anchor/SP-specific attributes. Client scopes are fixed empty; request signatures, Response signatures, Assertion signatures and encryption are enabled.

Native configuration is read back through the administration API before/after each A/B/A request to check equality. Login input is fixed in memory. Original aggregate/requests/responses match Recorder originals, reusing signature/decryption/request correlation/Audience/Recipient checks. Attribute values/credentials are not saved in public diagnostics.

Preparation validation rederives expected keys/ACS from originals and matches mapper semantics, actual client IDs and deleted IDs. Configuration hashes include actual input source `firstName`. Existing Shibboleth/SimpleSAMLphp records using `uid` can still be regenerated/validated byte-for-byte unchanged.

## Formal adoption

<!--g1-literal--> Validated 3 A/B/A responses from Run `run_EEAG5F4CFPVHYP90GGDZXB8VN4` through the formal collector. Rejected 6 comparison controls and 4 native-configuration controls. Normal login also completed; the formal CONFIG case returned `SATISFIED/PASS`, `attested=false`. Adoption verification checked unchanged originals for 8 evidence references.

<!--g1-literal--> Unverified inventory decreased 464→463; distinct case IDs 157→156. This case is now Success for all 3 products. Per-case adoption combines separate product Runs; it does not represent one complete Run.

Evidence: `build/acceptance/reference-20260918/keycloak-relying-party-attributes/`; formal evaluation: `keycloak-relying-party-attribute-evaluation/`. Aggregates are updated through generators.

## Operations and restoration

<!--g1-literal--> Attribute-comparison client creation 2/deletion 2; normal-login client creation 1/deletion 1; total product writes 6. Administration API reads 27; preliminary serverinfo read 1; in-memory token acquisitions 3; protocol round trips 4. Preparation installation/test start/CONFIG confirmation 1 each. Builds, container recreation, product restarts, service reloads and user interactions were all 0.

If the creation response or subsequent search fails after successful creation, recovery searches the test-specific entityID absent before creation and deletes the client. Existing configuration is never overwritten. Post-delete absence is checked; failure cannot be recorded as completed restoration.

## Validation scope

<!--g1-literal--> Performed actual-product original verification, comparison/native-configuration negative controls, readoption checks for the existing 2 products, and inventory-contract audit. Java evaluation code/running image were unchanged. Broad integration tests are deferred to batch implementation validation. G1 generated-document consistency/structural checks ran; the existing protected-source signed difference G2-30 remains unresolved.
