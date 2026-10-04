# Comparison observations under a fixed attribute-release policy

This document retains the implementation/observation history. See [56](56-attribute-policy-acceptance.md) for later formal-case integration, batched validation and result adoption.

Added a Shibboleth driver that initially installs attribute-resolver, release-filter and metadata-provider configuration, then varies metadata inputs/request indices without changing those settings during comparison. Run: `run_K737VNKMS7Y66MSGPCZ0F0PZSQ`. It is restricted to the test SP entityID and uses distinct attribute names to avoid confusion with ordinary released attributes.

The policy uses the product's [EntityAttributeExactMatch](https://shibboleth.atlassian.net/wiki/spaces/IDP5/pages/3199502013/EntityAttributeExactMatchConfiguration) and [AttributeInMetadata](https://shibboleth.atlassian.net/wiki/spaces/IDP5/pages/3199501959/AttributeInMetadataConfiguration). The latter uses separate attributes with different `onlyIfRequired` values, distinguishing RequestedAttribute presence from required designation.

## Attributes observed after signature verification/decryption

The following are suffixes of attribute names under `urn:samlscope:test:policy:`. Values are not saved in extracted results. `anchor` is a control attribute always released from the same resolver input; this table alone is not proof of the same user.

| Condition | Observed attributes |
|---|---|
| Ordinary control | anchor |
| EntityAttributes present | anchor, entity |
| EntityAttributes absent | anchor |
| RequestedAttribute, isRequired=true | anchor, required, optional |
| RequestedAttribute, isRequired=false | anchor, optional |
| RequestedAttribute absent | anchor |
| Index zero | anchor, required, optional |
| Index one | anchor, surname |
| Return to index zero | anchor, required, optional |

Configuration read-backs had identical hashes for every comparison. Original XML SHA-256 matched for index comparisons, avoiding subsequent metadata writes/service reloads. Verified original normal-response signatures, encrypted Assertion decryption, enclosed signatures and Issuer inside the container. Private keys and decrypted attribute values were not exported.

Driver: `dev/shibboleth/attribute_policy_campaign.py`; cryptographic verification: `dev/reference-acceptance/VerifyAttributePolicy.java`; record consistency: `verify_attribute_policy_experiment.py`. Evidence: `build/acceptance/reference-20260918/shibboleth-attribute-policy-campaign/`. Matched original manifests, MetadataPrepared/fetch, signed request/response correlation, fixed configuration, index changes/return and restoration records.

## Evaluation and remaining work

These observations are candidate evidence for integrating evaluation of `IIP-IDP03-a-idp-01`, `IIP-IDP04-a-idp-01` and `IIP-IDP04-b-idp-01`. Runner cases do not yet evaluate this comparison. Evaluation and negative controls must cover fixed configuration, original XML equality, execution user/attribute input, request correlation and missing controls. Index comparisons cross campaigns, so unrelated attempts must not be joined merely because they share a Run.

### Added comparison evaluation

Added `AttributePolicyComparison`, an internal comparison accepting only validated Samples and checking each case's required conditions/test attribute sets. Differences in fixed policy, execution user, SP entityID, inputs outside the comparison or experiment identity remain unverified. Index comparisons require exact original-metadata equality and ordering in which each next request follows completed response receipt. Duplicate conditions, reused evidence, incomplete controls and collection-time validation errors cannot establish Success.

Sample fingerprints must be constructed by the collector after verifying originals/preparation records, not from user-entered hashes or confirmation checkboxes alone. Execution-user matching values are used temporarily in comparison and not saved in CaseOutcome details. Current extraction files contain only attribute names and cannot establish user equality by themselves.

Added tests for valid comparisons, missing controls, unconditional release, different experiments, policy/user/SP changes, changed original metadata, uncontrolled inputs, invalid ordering and duplicate evidence. Java tests await batch validation and have not run. This internal comparison is not yet registered with CONFIG cases; no active evaluation path was added.

Next is the collection boundary binding original signatures/decrypted attribute inputs to fixed-policy preparation. Existing product-configuration hashes are in external-driver records and not connected as validated preparation in Runner Transcripts. Do not pass constant fingerprints to comparison while this evidence is missing.

### Attribute collection from originals

Added `AttributePolicyAttributeReader` and `AttributePolicyProtocolEvidence`. They reuse MetadataPrepared/fetch/request/response correlation checks, reading attributes only after normal-response signature verification, matching advertised encryption keys to private keys, and checking decrypted Issuer/enclosed signatures. Indices come from original AuthnRequests, not Transcript-summary declarations; metadata comparison fingerprints derive from original bytes.

Compared attribute inputs must belong to the same Assertion. Missing anchor, markers with different values, duplicate/unknown markers, different NameFormat, empty/structured values and remaining undecrypted EncryptedAttribute invalidate evidence. Encrypted attributes are not ignored and called absent. Attribute values are also excluded from exceptions and Observation string representations.

Same-Run attribute matching temporarily uses a hash of length-prefixed input containing the Run and target entityID. This establishes the same attribute input, not independent login-user identity. Do not assign it directly to the comparison's principalFingerprint. Binding native preparation/execution-user records and checking inputs outside the comparison remain incomplete.

Added tests for matching plaintext/encrypted responses, Run-specific matching-value separation, incomplete/ambiguous attributes, modified signatures, missing decryption keys and key mismatch. As above, tests await batch validation; neither the running image nor inventory conclusions were updated because of this addition.

### Original rereading through the production collector

Ran Runner/API `compileTestJava` together and confirmed compilation of the added production/test code. Tests themselves did not run, so negative-control validation is not complete.

Added `ObserveAttributePolicyExperiment.java` to feed saved originals from the above Run into `AttributePolicyProtocolEvidence`. This read-only execution references existing container key files and does not generate absent keys. It revalidates signatures/decryption and compares observations with external verification.

<!--g1-literal--> The production collector read 9 round trips with an empty issues list. Attribute-input matching values agreed across all conditions, without claiming authenticated-user equality. Results in `production-observation.json` were checked for original hashes, conditions, indices, attribute names and request/response references. Product-configuration operations, application restarts and new Run creation were all 0. The inventory remains 470 observations.

The current auxiliary key-input service binds a Run to target metadata but does not express experiment preparation boundaries/user matching. Its purpose is not repurposed; transfer of validated preparation and formal-case integration remain outstanding.

### Binding preparation records to original observations

Added `AttributePolicyExperimentBinding`. It accepts internal validated preparation and checks Run equality, request/response references, original-derived variants/indices and unique conditions before comparison. Attempts are not guessed from nearby timestamps or variant names alone. Metadata fetch/original/request/response references remain in evaluation results.

Collection results retain Run ID and reject preparation from a different Run. Missing preparation yields unverified reason `verified_preparation_unavailable`. Added unverified controls for different response references, reused requests, duplicate original requests, mixed-up conditions and changed signed attribute input. Tests still await batch validation.

Preparation is an internal contract for validated native information, not public API input. The adapter generating that information is not yet connected; user-declared hashes or confirmation checkboxes are not passed directly. Adding the type does not establish validated preparation or passing cases.

### Supplemented native preparation records

Added `preparation.json` output to the Shibboleth driver. Besides hashes of all fixed configuration, it extracts only Suite-added metadata-provider, attribute-definition and filter nodes from product read-back. Entire configuration is not exported. It checks byte equality against expected generated configuration and equal extracted rules before/after comparison. Missing/duplicate Suite-owned nodes reject the record.

Login inputs are read once at start and passed in memory to every condition. A random reference token records use of the same inputs; usernames, passwords and their hashes are not saved. The token is driver provenance, `fixed-in-memory-driver-input`, rather than authenticated identity evidence.

When new preparation records exist, record validation checks content hashes, per-condition read-back and login-input references. Preparation is not backfilled into historical observations; absence is not treated as established. These records have not yet been obtained from a product and are absent from existing Runs. Added rejection tests for changes, missing/duplicate records and different Runs; tests await batch validation. Product-policy semantic validation and formal-case integration remain outstanding.

### Policy semantics and new measured preparation

Subsequently added `verify_policy_semantics`. It strictly checks target-SP-only Requester, uid input source, test attribute names/NameFormat, EntityAttributeExactMatch values and AttributeInMetadata names/onlyIfRequired/matchIfMetadataSilent. Extra rules, different input sources/metadata files and unknown attributes are rejected. Added negative controls that remain rejected even after recalculating hashes of modified inputs.

Applied these checks to read-backs before execution and before/after comparisons in new Run `run_C97YCPR7F5KNWRMCMHWNPQ11N9`. Evidence: `build/acceptance/reference-20260918/shibboleth-attribute-policy-preparation/`. Earlier missing records remain absent; the new Run captured `preparation.json`, per-condition before/after policy records and fixed in-memory login-input references.

<!--g1-literal--> Completed 9 conditions, confirming signed/decrypted observations through both external verification and the production collector. Original collection had no issues; preparation semantics passed. Product-configuration operations 14: writes 13, temporary-file deletion 1. Service reloads 14; SSO 9; Run/preflight 1 each; campaigns 9. Configuration was restored. User interactions, product restarts and Suite recreations were 0.

Renamed the misleading comparison field `principalFingerprint` to `loginInputFingerprint`. The requirement is matching fixed driver inputs and signed attribute inputs, not claiming independent user-identity verification in this attribute-release capability test. A random input reference alone is not user proof. G1/G2 interpretations and judgment levels were unchanged.

Runner production compilation succeeded. Java tests and added Python negative controls await batch validation. The first original reread failed because internal verifier classes were not copied; copying the missing class enabled rereading the same evidence. This was not a failed product SSO rerun.

<!--g1-literal--> Formal-case integration/preparation transfer remain incomplete; unverified observations remain 470. Obtaining new measured preparation alone does not change inventory results.

<!--g1-literal--> No formal Success was added; unverified observations remain 470 with 157 case IDs. The 9 measured conditions are not added to resolved counts.

## Operations and builds

<!--g1-literal--> Product-configuration and related operations 14: writes 13, test-metadata deletion 1. Service reloads 14; SSO 9; Run creation/preflight 1 each; campaign creation 9; preparation confirmations 0. User interactions/product restarts 0. Verified original/restored configuration SHA-256 equality and deletion of temporary metadata.

Built source from signed commit `2de509ec` in isolation, excluding unrelated uncommitted API changes. `api:installDist -x test --offline` succeeded. Java tests await batch validation and are not recorded as passed. The first cryptographic-verifier compilation failed because of an incorrect distribution directory; recompilation with `install/samlscope/lib` succeeded.

<!--g1-literal--> Image build 1; Suite/forwarder recreations 1 each. Running image: `samlscope:reference-attribute-policy-v42`; digest: `sha256:45706f6b4ed6c5ec2d95643252aa0d3aedd15ac8cfde7f869d5f8d51104990b1`. G1 generated-document consistency/structural checks 46/46. The existing protected-source G2 signed difference remains unresolved.
