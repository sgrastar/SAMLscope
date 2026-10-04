# Missing metadata-extension and default-ACS conditions

## Results

<!--g1-literal--> Unverified observations 490→489; distinct IDs remain 161. SimpleSAMLphp IIP-IDP12.c became Success. No Failed/Warning additions. New input generation alone is not counted as a reduction.

## Batched inputs and execution paths

| Target | Added conditions | Implemented scope |
|---|---|---|
| Extension points | Non-SAML namespaces in Organization, ContactPerson, AffiliationDescriptor | Preserve required parent structure in signed metadata; native parsing and signed SSO |
| Namespace negative control | SAML namespace element inside Organization/Extensions | Separate variant from the old root-level input; no evidence reuse across conditions |
| Default ACS | First explicitly false/next omitted; all false; multiple true | Omit request selection fields and compare response destination with metadata default selection |
| Index negative control | Duplicate index in one ACS collection | Input generation only; no oracle that treats acceptance alone as product violation |

AffiliationDescriptor occupies a separate EntityDescriptor in the aggregate, not an EntityDescriptor containing ordinary roles. Default selection compares only the AssertionConsumerService collection.

The SimpleSAMLphp driver gained browser_sso_idp. Default-ACS controls change response destinations after metadata updates; the normal-AuthnRequest-specific signature-corruption API is not called on this path. The initial unsupported call remains a Suite HTTP error, not successful rejection evidence.

## Incorrect Suite judgment found and corrected

MD05.a3 separates unknown-extension acceptance (MD05.g) from namespace/extension-point constraints. The old consumer oracle returned VIOLATED when the product accepted a Suite-authored malformed extension. This does not prove malformed target-authored extensions.

Without direct namespace evidence, the case now remains not ready and NOT_VERIFIED, requiring namespace-qualification:extension-points. Old false FAIL is retained historically but not adopted in comparison/inventory. A fresh Run still accepted the same input without a product FAIL.

The unfinished case keeps case.pending-interaction. Protocol-evidence detail identifies a namespace observation path that additional operations cannot resolve. The inventory next action was updated. Suite rejected the attempted configure conclusion because Transcript-driven cases cannot be operator-confirmed; that path did not substitute for evidence.

## Evidence and reproduction

Root: build/acceptance/reference-20260918/. Original fixtures, parser output, install/restore, flow correlation, original requests/responses and SHA-256 manifests are retained.

| Trial | Run | Folder |
|---|---|---|
| Default ACS | run_XKNHNHTS27D8V15RGGVWPPNWX4 | simplesamlphp-default-acs |
| Extensions before correction | run_9HVYC3FA0WW6BYBZSMY1PN33YN | simplesamlphp-extension-points |
| Extensions after correction | run_NTB45B0333JF88W97SGWEMZD0D | simplesamlphp-extension-points-corrected |

verify_default_acs_batch.py requires absent ACS-selection attributes in the actual request, signature presence, correlated InResponseTo/Success, and actual reception URL matching the original metadata-selected endpoint. Adoption requires every specified condition and change control.

Final image: samlscope:reference-metadata-conditions-v27-final; digest sha256:98a366f4362bddb9d5d1d395c6080b53d7eeeac67378cec0159a4eb9c3de04d4.

## Costs, verification and remaining work

<!--g1-literal--> Added input kinds 8; native imports 23; configuration writes 49 (46 install/restores plus three finally restorations); Runs 3; preflight 3; docker builds 2; Suite/forward recreations 2 each; user actions 0; product restarts 0; rejected configure attempt 1. Original SHA-256 restoration verified.

Batched SAML/Runner regression passed, with additional verification of the false-judgment correction. G1 generation/structure passed. Existing G2 protected-source differences remained unresolved; no release approval is claimed.

Direct namespace inspection, all nested entity endpoint/key usage, sound duplicate-index controls and equivalent trials on other products remain. Acceptance or unit tests alone do not complete them.
