# Formal evaluation integration for attribute-release policy comparisons

## Reevaluation path added to the next batch

Corrected attribute-policy CONFIG implementation that always reported evidence as unprepared even after successful original/native-preparation comparison. EntityAttributes, RequestedAttribute and index-comparison cases proceed to automatic evaluation only when existing signature checks and fixed-input comparisons succeed.

Added saved-evidence reevaluation for cases terminated because attestation was disallowed or attribute-comparison evidence was incomplete. Updates are limited to completed Runs with additional Transcript evidence and successful comparison. Existing conclusive results and unrelated unverified reasons are excluded. Reevaluation sends no requests and changes no product configuration.

This change was included with certificate/UI processing in `reference-config-ui-v64`. Existing comparison, binding, original-reading and preparation checks passed in the same batch. No new product-level attribute conclusion was made or counted as an inventory reduction. The following Shibboleth formal results and contemporary validation records are retained.

Connected fixed-policy preparation records, signed/decrypted attribute observations and request-specific comparison conditions to CONFIG cases. The comparison, collection and binding introduced incrementally in [55](55-fixed-attribute-policy-observations.md) now participate in actual Run evaluation.

## Formal results

Used saved observations from Run `run_C97YCPR7F5KNWRMCMHWNPQ11N9`. Without changing product configuration or rerunning SSO, installed validated preparation records and performed preparation confirmation.

| Shibboleth case | Formal result | Evidence |
|---|---|---|
| `IIP-IDP03-a-idp-01` | Success | Attribute differences with EntityAttributes presence/absence |
| `IIP-IDP04-a-idp-01` | Success | RequestedAttribute presence/absence and isRequired differences |
| `IIP-IDP04-b-idp-01` | Success | Attribute differences and return to baseline when switching request indices with identical metadata |

Evaluator converted every `SATISFIED / configuration.attribute-policy.comparison-observed` to PASS. These are not attested results: `attested=false`. Preparation confirmation alone cannot pass. If automatic comparison fails, the existing manual evidence-confirmation path remains.

<!--g1-literal--> Unverified observations decreased 470→467; distinct case IDs remain 157. The corresponding Keycloak/SimpleSAMLphp cases are not inferred from this Shibboleth evidence. No inventory-audit errors; inventory SHA-256: `3cfb7fa86140303319cbd9faccf5661ae55f227cba3477090eb09e302d456a6f`.

## Preparation records

`export_attribute_policy_preparation.py` checks native-policy semantics, before/after configuration equality, original metadata conditions and signed/decrypted observations to generate local-adapter records. Records contain no Verdict. Fixed-input comparison fingerprints derive from the inspected rules' target SP/uid input and fixed configuration. Signed attribute-input equality is also required independently.

Runner reads `attribute-policy-preparations/<run>.json` from its data directory. This is a trusted local-adapter/administrator boundary, not permission to submit arbitrary unvalidated external files. No HTTP submission path was added. Run, fixed target metadata, original hashes referenced by preparation, and request/response references are rechecked; nonregular/oversized files are rejected. Product signatures alone are not claimed to detect an administrator fabricating the record itself.

Initial output contained a Suite defect using public-result value `redacted:internal-target` as target entityID. Runner rejected it and retained unverified status. The exporter was corrected to use entityID from fixed original metadata. Rejected records were saved separately; corrected hashes and explanation are in `preparation-correction.json`. Accepted results were not overwritten with different preparation information.

Original evidence: `build/acceptance/reference-20260918/shibboleth-attribute-policy-preparation/`; formal configure responses/results: `shibboleth-attribute-policy-evaluation/`. `verify_attribute_policy_acceptance.py` matches both before adopting into the generated inventory. Original observations, rejection records and corrected formal results are retained separately.

## Batched validation and operations

<!--g1-literal--> 15 Java tests passed: comparison, binding, original attribute reading, metadata inputs, signed indexed requests, API input restrictions and preparation-file boundary. 4 Python preparation-record tests also passed. Previously deferred negative controls ran together, supplemented by the later preparation-file checks. G1 generated-document consistency/structural checks 46/46. The existing G2 signed-source difference remains unresolved.

<!--g1-literal--> G2 remains 20/21, blocked by G2-30. This M1Runtime integration change is also part of the protected-source signed difference. Earlier approvals are not reused for the current implementation; release completion is not claimed.

<!--g1-literal--> Product configuration writes, product restarts, SSO, new Run creation and user interactions for this formal integration were 0. Preparation-confirmation POSTs 3; local preparation-input installations 2, including the rejected input; relocation of rejection records 1. Image build 1; Suite/forwarder recreations 1 each. Earlier observations are recorded with failures/restoration in [55](55-fixed-attribute-policy-observations.md) and are not charged twice here.

Built in isolation from signed implementation checkpoint `1afa954a`. Running image: `samlscope:reference-attribute-policy-oracle-v43`; digest: `sha256:ebc4f33b53048011f765dc1b7189850bf7fee1d01a3e447dae0c41691e41e3ca`. Unrelated working-tree SOAP changes were excluded. The exporter's entityID correction is a local-driver change, not a change to distributed Java artifacts.
