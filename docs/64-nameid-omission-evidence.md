# NameID-omission evidence checks and comparison

Approved `IIP-IDP11-a-idp-01` requires the ability to generate an Assertion whose Subject contains no NameID. Existing CONFIG confirmation cannot establish this from observations, so original checks/internal comparison were added. Runner registration, native preparation records and measured product omission configuration are not connected at this stage; no formal conclusion is established.

## Original checks

Extracted existing attribute-comparison signature/decryption processing into `VerifiedResponseAssertion`. It retains Response signature verification, verification of any Assertion signature, target issuer, matching prepared-SP encryption keys and a single Assertion. Calls requiring request correlation also check Destination, InResponseTo, Audience and bearer Recipient. Existing optional-correlation attribute calls retain their behavior.

`NameIdOmissionResponseEvidence` requires correlation inputs and checks one Subject in the verified Assertion. It distinguishes NameID, BaseID and complete omission. EncryptedID is decrypted with prepared keys; a concealed NameID is not omission. Missing Subject, duplicate identifiers, failed decryption, invalid signatures or mismatched requests invalidate evidence. Identifier values/cryptographic exception causes are not returned externally.

`NameIdOmissionComparison` requires ordered normal-NameID to complete-omission responses within the same experiment/SP, fixed login inputs and fixed unrelated inputs. Original references for each exchange must be unique. Complete evidence returns SATISFIED; otherwise NOT_VERIFIED. Missing configuration/execution paths do not become product FAIL. This complete-omission path does not determine the acceptability of BaseID configurations.

## Remaining integration and validation

Internal Samples are constructed only after native preparation/original-collector binding. No HTTP-attestation-to-evidence path was added. Next are a standard product omission path, before/after/restoration records, original request/response matching and CONFIG integration.

<!--g1-literal--> Added boundary tests for plaintext/encrypted Assertions and NameIDs, complete omission, missing Subject, duplicates, absent keys, correlation mismatch, modified signatures, mixed inputs and reused evidence. Test sources compiled; execution awaits batch validation. Unverified observations remain 463 with 156 case IDs.

<!--g1-literal--> Product operations were only 2 SimpleSAMLphp source-search reads. Configuration writes/reloads/restarts, protocol round trips and user interactions were 0. The running product's NameID generation path was inspected, but these searches do not establish absence of omission capability.

The running image was unchanged. Because signature processing was extracted, batch validation must also cover existing attribute-comparison boundary tests/original replay. The protected-implementation G2 signed-source difference remains unresolved; release completion is not claimed.

## Original collector and formal CONFIG integration

`NameIdOmissionProtocolEvidence` matches preparation-selected metadata/request/response references against same-Run Recorder originals. It checks preloaded MetadataFetch/MetadataPrepared, original XML digest, SP entityID, request destination, advertised ACS, request ID, unique response and chronology before signature/decryption checks. It does not select unrelated recent responses.

`NameIdOmissionExperimentBinding` uniquely binds normal/omission conditions to configuration-record references. Both conditions fix imported metadata and match original AuthnRequest content except ID/IssueInstant/signature. Comparisons also changing NameIDPolicy or authentication requirements are not adopted. A native adapter proving configured omission is separately required.

`NameIdOmissionPreparationFile` reads only local `nameid-omission-preparations/<run>.json`, binding Run, target entityID, fixed target-metadata SHA-256 and all selected-original hashes. Symlinks, oversized files, incomplete conditions and duplicate references are rejected. No HTTP preparation submission exists.

Added `NameIdOmissionConfigurationTestCase` and M1 registry integration. CONFIG confirmation returns an Outcome only for complete bound evidence; otherwise existing confirmation remains. Reevaluation after new originals are added to an unverified case uses the existing history-preserving update path. Incorrect historical results are not overwritten, nor conclusions established by reevaluation without new evidence.

<!--g1-literal--> API/test sources compiled. Added binding negative controls; execution awaits batch validation. With no image update/product measurement, unverified observations remain 463. Shibboleth read-only investigation made 3 searches: configuration, jar locations and API. The API search returned no results and is not evidence of feature absence. Writes, restarts and user interactions were 0.

## Omission requests and Shibboleth driver preparation

Existing preloaded requests explicitly requested transient NameIDPolicy. Retaining that request while disabling generators confuses inability to satisfy the request with omission capability. Added `VALID_NO_NAMEID_POLICY` and dedicated preloaded variant `nameid-omission`. Requests remain fully signed; normal/disabled conditions use identical request forms. Existing variants' requests were unchanged.

`dev/shibboleth/nameid_omission_preparation.py` generates configuration emptying only the native `shibboleth.SAML2NameIDGenerators` list. It rejects an initially empty list, duplicate IDs or changes outside the list. This temporarily changes SAML2 generation configuration for the entire isolated reference IdP, not only an SP.

`nameid_omission_campaign.py` records dedicated metadata import, normal login, generator switching/reload, same-request login, complete restoration/reload, before/after read-back, original references and fixed login inputs. ACS transport completion is not a successful determination. A successful NameID-free response under standard configuration is not yet established and requires original-response validation.

<!--g1-literal--> Read running Shibboleth configuration, jar locations and service resources, and retrieved 3 public-configuration API jar files. Parent-class investigation also searched nonexistent classes/directories. Located implementation NameIDFormatPrecedence/native generator lists, without establishing omission capability. Behavior without generators has not run either.

The new driver passed Python syntax/Java test-source compilation. Execution tests await batch validation. Dedicated variants are not deployed, so product configuration and inventory remain unchanged for this work.

## Formal adoption in Shibboleth

<!--g1-literal--> Built signed `bf6b46aa` in isolation and deployed `samlscope:reference-nameid-omission-v51`; digest: `sha256:5800c4056621e3c66d36d509ba82f5c73b83305a41e2eab7b63ccf22b423fc1e`. Retained existing data, updated Suite/forwarder containers and verified health. Unrelated working-tree changes were excluded.

<!--g1-literal--> Run `run_J7YRDB4T4J8FXKSRXG4K7ZNJ3Q` established normal NAME_ID and OMITTED after generator disablement. Both responses passed formal-collector signature/decryption/correlation checks; request comparison fingerprints matched. Restored original native bytes, reloaded and checked temporary-metadata deletion.

`export_nameid_omission_preparation.py` audits equality outside generator lists, before/after read-back, fixed login inputs, original hashes/references, original metadata and protocol conditions before preparing records. `ObserveNameIdOmissionExperiment` is a read-only helper using the formal collector/comparison; it does not rewrite Run results.

<!--g1-literal--> Rejected 5 measured-evidence controls: missing/duplicate evidence, different responses, mixed login inputs and mixed comparison inputs. After normal-login prerequisite confirmation, CONFIG confirmation returned `SATISFIED/PASS`, `attested=false`. Adoption verification matched restoration, installed-preparation read-back, formal comparison, 6 result references and unchanged originals.

<!--g1-literal--> Unverified observations decreased 463→462; case IDs remain 156. No inference was adopted for other products/ECP. Evidence: `build/acceptance/reference-20260918/shibboleth-nameid-omission/`; formal evaluation: `shibboleth-nameid-omission-evaluation/`. Inventory/product comparison were regenerated; contract audit had no errors.

<!--g1-literal--> Combined comparison/normal-login operations: configuration writes 8; reloads 6; temporary-file deletions 2; protocol round trips 3. Build 1; Suite/forwarder recreations 1 each; product restarts/user interactions 0. Initial helper compilation failed with an incorrect distribution path; including corrected compilation and added controls, compilation ran 3 times. Failures are included in the operation ledger.

Execution tests remain grouped into batch validation. Actual-product originals, negative controls and generated-inventory audit required for formal adoption were performed. The protected-source G2 signed difference remains unresolved; release is incomplete.
