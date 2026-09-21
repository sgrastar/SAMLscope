# Native display-name precedence observation

The display-name campaign now derives its candidate mapping from the original SP metadata rather than hard-coded names. It rejects ambiguous roles, names, languages, and endpoint hostnames. A display-only campaign and diagnostic comparison bind the native import, browser-sent request, visible selection, and metadata conditions. Missing UI remains unverified and is not proof of nonuse.

The comparison also checks unchanged metadata settings, endpoint correlation, observation order, language, and native-template stability. Metadata validity must extend through the observation. Only the campaign variant parameter and signature digest/value are normalized for comparison; advertised certificates are retained. The schema-required consuming-service wrapper is checked for the fixed optional uid request before removing it from the comparison; changed service names or fallback candidates are rejected.

## Native evidence and discovered blockers

Evidence: `build/acceptance/reference-20260918/shibboleth-display-precedence-bound`, Run `run_GBT32N46PSQPTN5S6127CAJYS7`. Original evidence and the initial binding record are retained. No formal evaluation was started.

- DisplayName was selected when supplied, and ServiceName was selected when DisplayName was absent.
- With both absent, the expected heading was not observed. A subsequent read of the reference `login.vm` found a guard suppressing names contained in the relying-party ID. This is an explanation candidate, not proof of runtime branch execution or a product violation.
- The original fixture generator changed trusted keys between display conditions. The comparison detected the uncontrolled change. The source now keeps the display-condition key constant, while unrelated polling fixtures retain separate keys. This source change has not yet been deployed or exercised in a new native campaign.
- The collector now records the template hash and checks unchanged template bytes through restoration. The native run above predates that addition; it cannot establish template stability retroactively.

<!--g1-literal--> Operations in this native run: metadata/config writes 5 (including restoration), resolver reloads 4, temporary metadata deletion 1, browser launches 3, Suite builds 0, product restarts 0, human interactions 0. Provider bytes were restored and temporary metadata removed.

<!--g1-literal--> No new verdict was adopted. The unresolved ledger remains 438 observations / 154 distinct case IDs. This is diagnostic progress, not a reduction in the ledger.

## Pending grouped verification

The key-isolation regression test checks metadata signatures, advertised certificates, runtime credentials, and separation from an unrelated polling control. It was added for the next grouped test execution; no Java/Web suite was run for this small increment. The Runner now has a display receipt reader, comparison, campaign case, registry wiring, and local receipt exporter. The browser records a hash of the exact normalized candidate mapping; Runner derives that mapping again from the immutable metadata. The reader requires every condition, unique transcript origins, native template stability, exact request/page identity, and unchanged policy/key inputs. A known lower-priority selection returns `violated` for the central Evaluator; missing or unbound observations remain `not_verified`. No path infers product-wide nonuse from a missing heading.

Comparison controls and the production replay verifier cover missing/duplicate conditions, mixed Runs, evidence reuse, changed keys/policy fingerprints, wrong candidate mappings, language/endpoint mismatch, timing, and constant-selection mutants. These checks have been authored for the grouped execution; they have not yet been executed. The API/Runner/SAML sources and test sources compiled in the isolated build. The final provenance-tightening edits were then included in a successful `:api:installDist -x test` build; the production replay verifier also compiled against that distribution. No test or replay was executed in this increment. Formal native adoption remains incomplete. Rebuild/deploy the accumulated changes, then collect a new display campaign before considering any ledger change.

## Fixed-key runtime observation

The fixture and reader changes are deployed in `samlscope:reference-native-certificate-v60`. The grouped metadata-generator and display-comparison checks passed. The new native campaign is `shibboleth-display-precedence-v60`, Run `run_RAG09WWDD0R8WTVXYBDJ2Q7FQX`.

DisplayName and ServiceName were observed under their respective conditions. The fallback entity heading remains missing or ambiguous. Unlike the earlier campaign, the original-bound comparison now confirms unchanged key and policy inputs, original-derived candidate maps, and unchanged native template/language settings. Only the entity selection remains unproven; the adapter does not reinterpret that absence as a product violation.

<!--g1-literal--> The production receipt replay returned NOT_VERIFIED and rejected all 13 evidence/comparison mutations. All 3 browser observations completed. Configuration writes 5 (including restoration), resolver reloads 4, temporary metadata deletion 1, browser launches 3, product restarts 0, human interactions 0. Restoration of provider bytes, removal of the temporary metadata, and unchanged template/language configuration were checked. The comparison added no ledger reduction; the current ledger is 432 / 152 after the separate certificate adoption.
