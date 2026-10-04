# Keycloak observations of attribute Name/NameFormat generation

Retested `IIP-IDP01-a-idp-01` with explicit standard User Property mapper client configuration. This is attribute-generation capability testing, not evidence of product-native metadata XML interpretation.

## Observation path

`dev/keycloak/attribute_name_capability.py` rejects overwriting existing clients and creates a test-specific entityID. First it performs ordinary login without mappers and verifies absent test attributes through Suite original evaluation. It then configures standard `saml-user-property-mapper` to generate URI/arbitrary-string names from the same user input `firstName`, using a dedicated custom NameFormat URI.

Configuration is read back through the administration API and matched exactly; subsequent signed/encrypted SAML responses use existing Suite evaluation. Afterwards, created client ID/entityID are rechecked before deletion and absence is confirmed. Tokens, credentials and attribute values are not saved in diagnostics.

## Results and remaining conditions

<!--g1-literal--> Run `run_8EC5HRA77MZWGCHCXR1DKB9ADE` performed 2 normal/configured round trips. Configured responses established `urn-name` and `non-uri-name`; `unknown-name-format` was unobserved, so formal Outcome/Verdict remain NOT_VERIFIED. No original-reading/signature-verification errors were recorded.

Custom NameFormat remained in configuration read-back but was not established in signed responses. Saved settings do not establish generation capability. This mapper path also does not establish product-wide inability to generate custom NameFormat. Other standard mappers/native configuration paths are next.

`verify_keycloak_attribute_name_diagnosis.py` matches absent normal-control attributes, before/after mapper identity, changed settings, original-response digests/references, restoration and formal unverified results. Inventory reasons changed from earlier pending operations to these measured remaining conditions.

<!--g1-literal--> Unverified observations remain 462 with 156 case IDs. Partial conditions are not counted as whole-case Success. Evidence: `build/acceptance/reference-20260918/keycloak-attribute-name-capability/`.

## Operation costs and validation scope

<!--g1-literal--> Product writes 3: client creation, mapper update, client deletion. Administration API reads 8; protocol round trips 2. Service reloads, product restarts, Suite updates and user interactions 0. Existing clients were not overwritten; created-client deletion was verified.

Checked Python syntax, native read-back/restoration, formal case results, original references and generated-inventory contract audit. Full tests are grouped into batch validation of additional implementation. Existing G2 signed-source difference remains unresolved.
