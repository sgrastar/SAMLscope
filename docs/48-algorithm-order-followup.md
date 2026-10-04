# Skipping unsupported algorithms and evaluating encryption-order conditions

## Implementation

MD05.e9 was added to the common original-byte, request/response-correlation, and signature-verified evaluator. Alongside reversed supported-algorithm order and single-algorithm conditions, it requires a Suite-defined unsupported URI followed by a supported algorithm. Always choosing the first entry or a fixed algorithm for all conditions cannot yield Success. Insufficient evidence or unconfirmed policy remains NOT_VERIFIED.

MD05.e5 implements the approved branch in which the condition is false when algorithms of the same general type are absent or there is only one. It examines each encryption or unspecified-use KeyDescriptor in published SAML2 IdP metadata. Multiple candidates or unclassifiable URIs cannot satisfy this branch. Suite does not invent algorithm-strength rankings. This evaluates public metadata, not the ability to configure multiple algorithms.

Preparation confirmation can reevaluate Run-fixed published metadata even for existing Runs waiting on old implementation configuration. Configuration-unavailable and canceled events are preserved. Confirmation itself supplies no Outcome; missing evidence continues through the existing undecided path.

## Results from saved runtime evidence

| Case | Keycloak | Shibboleth | SimpleSAMLphp | Evidence type |
|---|---|---|---|---|
| IIP-MD05-e5-idp-01 | Success | Success | Success | The published snapshots contain no EncryptionMethod advertisements in applicable KeyDescriptors, satisfying the explicitly defined false-condition branch. |
| IIP-MD05-e9-idp-01 | NOT_VERIFIED | Success | NOT_VERIFIED | Shibboleth's verified signed responses follow reversed supported order and skip unsupported candidates. Other products' local policy and SHA384 availability remain unconfirmed. |

<!--g1-literal--> Unverified observations changed from 479 to 475; distinct case IDs changed from 158 to 157. Of four Success observations, three concern a false condition in the approved definition and one measures algorithm selection. Unit tests and completed operations were not counted as resolved observations.

Evidence is in `build/acceptance/reference-20260918/algorithm-followup/{product}/`. Originals and signed responses reference previous product algorithm directories; before/after results and confirmation responses are saved separately. `verify_algorithm_followup.py` checks fixed metadata digest, applicable Roles/KeyDescriptors, native import/restoration, signature verification, required conditions, and evidence references before generated adoption.

## Validation

Runner and API regressions verified that unconditional first selection, fixed algorithms, and missing conditions cannot pass ordering. Multiple algorithms of the same type, unknown URIs, and incorrect Roles cannot conclude the public-condition branch. Tests after saved-Run reevaluation integration covered resumption and preservation of configuration-unavailable events.

Product saved-evidence audits, inventory audits, G1 generation, and structural validation ran. The existing G2 signature difference remained unresolved; release completion was not claimed.

## Operation cost

<!--g1-literal--> Product configuration writes: 0; reimports: 0; product restarts: 0; new Runs: 0; new SSO attempts: 0; user interactions: 0. Saved-Run confirmations: 6; Docker builds: 1; Suite/forwarder recreations: 1 each. Previous native-import operations were not counted again.

Runtime was `samlscope:reference-algorithm-order-v37`, digest `sha256:982a123e8351d1bb8094254491fdf6e445f33a379752a674249ee90a0ed2e99b`. Only Runner was updated; pre-existing unrelated SOAP differences were excluded.
