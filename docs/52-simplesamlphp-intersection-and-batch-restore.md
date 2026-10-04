# SimpleSAMLphp intersection-selection observations and efficient configuration restoration

## Additional observations

Passed original XML to SimpleSAMLphp's native metadata parser in Run `run_Z15GR24Z1AWTH8DX9ZFZYPQSEK`. Adding product configuration `assertion.encryption=true` only for the test SP was recorded separately from metadata-import results. The Suite did not transform signature/encryption algorithm attributes.

<!--g1-literal--> Completed all 13 required MD05.e8 conditions, checking original-metadata equality, signed normal responses, matching-key decryption, rejection of decryption with another key, and restored product configuration. Missing-condition and evidence-check error lists were empty; all conditions belong to one campaign.

Signatures observed through this path remained RSA-SHA256 and did not follow SHA384 declarations or conditions excluding candidates through MaxKeySize. Encryption selections also differed. Because the RSA-SHA384 capability control was not established, intersection selection remains `NOT_VERIFIED / metadata.algorithms.intersection-evidence-incomplete`. The record states that the control could not be observed through this path, rather than asserting product-wide SHA384 non-support.

Adopted new formal results into the inventory, replacing the earlier `case.pending-interaction` reason with a measured reason. Configuration operations alone were not converted into Success.

<!--g1-literal--> Unverified observations remain 472, with 157 case IDs. The 13 additional conditions were not counted as resolved, and no new product FAIL was assigned.

Evidence: `build/acceptance/reference-20260918/simplesamlphp-intersection-metadata/`; before/after evaluation and preparation evidence: `simplesamlphp-intersection-evaluation/`. `verify_simplesamlphp_intersection.py` checks original evidence hashes, all conditions, native import, signatures, decryption, missing capability controls, restoration and formal results before inventory adoption.

## Fewer configuration writes

The earlier script restored original configuration after every condition and immediately wrote the next condition. Added `ConfigurationBatch` to overlay one test-SP configuration on the original, replace it for the next condition, and restore once at the end. Each condition starts from the original, without accumulating preceding conditions.

The reference container bind-mounts the host configuration file, so its inode is preserved. Per-write read-back and original/final SHA-256 equality are retained. If a change outside the batch is detected, the script does not overwrite or blindly restore it; result adoption stops. Intermediate operation records explicitly state that restoration is pending, and claim restoration only after the final check.

<!--g1-literal--> New Run `run_KGH0BADKXNC77QE2SRKM43P370` completed 3 conditions with 4 configuration writes, including 1 restoration. The earlier procedure would require 7 writes for those conditions. The earlier 13-condition execution measured 27 writes; the new procedure's calculated count is 14, but the record does not claim that all 13 conditions were rerun with it.

Product evidence: `simplesamlphp-batched-restoration/`. `restoration.json` records write attempts, applied conditions, restoration attempts and original/final hashes. Temporary-file unit tests covered restoration after abnormal completion, protection against external changes, empty batches, duplicate restoration and non-accumulating conditions.

## Operations and validation

<!--g1-literal--> Total product configuration writes for this work: 31, comprising 27 for 13 earlier-procedure conditions and 4 for 3 new-procedure conditions. Normal SSO 16; invalid-signature controls 16; Run creation/preflight 2 each; preparation-confirmation POST 1. Product restarts 0; user interactions 0; Suite image updates 0. Both Runs restored original configuration.

Java evaluation logic was unchanged; execution used the preceding image `samlscope:reference-producer-metadata-v40`. Validated the Python changes and product evidence, G1 generated-document consistency/structure, and inventory audit. The existing G2 signed-source difference remains unresolved.

Remaining work is to identify product configurations/execution paths establishing capability controls and implement other incomplete clusters. Failed observations must not be reinterpreted as specification-level non-support or inapplicability.
