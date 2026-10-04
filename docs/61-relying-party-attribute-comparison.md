# Attribute release comparison across different SPs

The target is `IIP-IDP02-a-idp-01`. The approved condition assigns different attribute release policies to different secondary-peer entityIDs and checks the returned attribute sets. Existing `AttributePolicyComparison` compares EntityAttributes or RequestedAttribute within the same SP and treats an entityID change as uncertain. Its determination must not be reused for this obligation.

## Added comparison logic

`RelyingPartyAttributeComparison` accepts only collected, verified internal Samples. A public declaration API or manual confirmation alone cannot create a Sample.

With the entire configuration fixed, it compares the first SP, a different SP, and a repeat of the first SP. Each SP must return the common anchor and its dedicated Suite attribute; the first and last entityID and metadata must match; the second SP must have a different entityID. It also checks order, request and response uniqueness, policy configuration, login input, attribute input, and other fixed conditions.

The final repeat is a control that prevents elapsed time or configuration switching from being mistaken for an SP-specific decision. It adds no SAML obligation. Missing controls or configuration yield NOT_VERIFIED, not a product violation. The logic returns Outcome; Evaluator performs the Verdict conversion.

This comparison demonstrates a capability without falsely failing another legitimate attribute release policy. It compares only Suite marker sets and does not put attribute values or login identifiers in CaseOutcome.

## Native Shibboleth configuration

`relying_party_attribute_preparation.py` preserves the original configuration and generates an experiment-specific FilesystemMetadataProvider, AttributeDefinition, and Requester-specific AttributeFilterPolicy. The common and SP-specific attributes resolve from the same uid, preventing a different user's attribute input from affecting the determination. This module does not perform configuration changes or reloads.

It rejects ID conflicts with existing configuration and identical entityIDs. When both SPs use the same aggregate metadata, they share a provider to avoid duplicate configuration operations. Read-back checks the entire file and matches Requester values and attribute rules to the expected native XML structure. A matching hash alone does not establish a correct policy. Each native namespace is emitted as the default namespace so unqualified xsi:type names also resolve correctly.

## Connections still outstanding

At this stage the comparison is not registered in the registry. Remaining work is:

- A metadata and request generation path linking different secondary SPs to one experiment.
- Execution, configuration read-back, and restoration records with the same configuration and in-memory login input fixed.
- Strict correlation of original requests and signature-verified responses, including each SP's Audience/Recipient and decryption key.
- Fixed-input comparison from actual metadata and verification that common attribute values establish identical attribute input. Do not accept a user-declared fingerprint.
- A collector that revalidates local preparation records, registration in the existing CONFIG case, and adoption in a formal Run.

<!--g1-literal--> The Java comparison compiles. Verification code covers normal differences, incomplete evidence, identical SPs, altered fixed conditions, and mixed requests, but functional tests await the integration batch. Python syntax checks pass. Product configuration changes, native tests, and user interactions in this step: 0. The inventory remains 466 unverified observations and 157 case IDs; no resolution is counted.

## Native collection through the preloaded path

The comparison SPs already present in the preloaded aggregate have no EntityAttributes or RequestedAttribute. Each has a different entityID and corresponding ACS. A native FilesystemMetadataProvider reads the original preloaded document for the same Run, and first, second, and first-repeat execute with fixed configuration. No new peer generation or product configuration switching was required.

`relying_party_attribute_campaign.py` stops the redirect from ACS to the next automatic test. Submission to ACS is a transport observation, not proof of SAML acceptance or a successful determination. It saves raw requests and responses, configuration read-back, an identifier for use of the same in-memory login input, restoration results, and operation counts. It does not record credentials.

<!--g1-literal--> Run `run_Z43RFP9ZF0175WP18Y1FZD70P9` recorded 3 A/B/A round trips, and Suite receipt records showed a Success response correlated to each request. Evidence: `build/acceptance/reference-20260918/shibboleth-relying-party-attributes/`. The formal attribute-set comparison has not yet been adopted.

<!--g1-literal--> Operations: Run/preflight 1 each, original preloaded fetch 1, native writes 7 (metadata 1, configuration 3, restoration 3), reloads 8 (including AttributeRegistry), temporary-file deletion 1, protocol round trips 3, user interactions 0. Configuration was read back before and after each exchange; final configuration matched the original hashes. Product restarts and Suite rebuilds: 0.

`AttributePolicyAttributeReader.readRelyingParty` was added. Alongside existing signature, encrypted Assertion decryption, and single-Assertion checks, it verifies Response and SubjectConfirmationData InResponseTo/destination and that every AudienceRestriction includes the target SP. It extracts only Suite anchor/first/second attributes and does not expose the attribute-input fingerprint in public diagnostics. The existing attribute comparison API retains its behavior. The new path compiles; connection to the original-evidence collector and registry is the next step.

## Joining signed and decrypted originals with preparation records

`RelyingPartyAttributeProtocolEvidence` was added. It joins a single preloaded original and fetch record from the same Run, the original AuthnRequest Issuer/destination/ACS, and the unique correlated response. It checks original hashes, chronology, duplicate metadata entityIDs, and duplicate request IDs. The attribute reader revalidates the response signature, correspondence to the public encryption key, and decrypted Audience/SubjectConfirmationData. Fetch timestamps alone do not select among multiple originals.

`ObserveRelyingPartyAttributeExperiment.java` is a read-only diagnostic that passes saved originals to this collector without generating or changing keys. Reprocessing the recorded Run's raw responses produced:

| Condition | Verified Suite attribute markers |
|---|---|
| first | anchor, first |
| second | anchor, second |
| first-repeat | anchor, first |

<!--g1-literal--> All 3 responses passed signature, decryption, destination, and Audience checks and yielded the same attribute-input fingerprint. Diagnostics do not output fingerprint or attribute values. `production-observation.json` stores only original hashes, markers, and evidence references. Collector issues: 0.

`verify_relying_party_attribute_experiment.py` rechecks recorded native nodes against the expected Requester-specific configuration structure, all before/after configuration hashes, and records fixing the in-memory login input. It also checks that newly recorded requests and responses for each condition exactly match collector evidence references, and that the imported aggregate original matches the Recorder original. The output is `native-protocol-binding.json`. This local diagnostic JSON is neither a public self-declaration nor a formal Outcome.

<!--g1-literal--> This step only reprocessed saved originals. Product configuration writes, reloads, Run creation, and user interactions: 0. Diagnostic classes and existing evidence were copied to a temporary directory inside the Suite container; running application classes and settings were unchanged. Java compilation and processing of demonstration originals succeeded. Functional tests still await the integration batch. Formal registry and preparation-validation connections remain outstanding; the inventory remains 466 unverified observations.

## Connecting the CONFIG case

`RelyingPartyAttributeExperimentBinding` strictly joins preparation conditions to original-collector request and response references. A different imported original, extra or missing exchanges, swapped conditions, or inability to establish identical attribute input returns NOT_VERIFIED. Metadata fetch, preparation, request, and response references remain in Outcome evidence.

`RelyingPartyAttributePreparationFile` reads only a Run-specific local file and accepts no network submission. It revalidates the Run, current target metadata entityID and SHA-256, current Recorder original hashes, and correspondence to cryptographically collected exchanges. The audited local adapter is the trust boundary for native configuration and fixed-input evidence. Public APIs do not accept self-declared diagnostic JSON.

`export_relying_party_attribute_preparation.py` generates immutable preparation records only from records that pass the preceding audit. `RelyingPartyAttributeConfigurationTestCase` connects to the CONFIG registry and obtains Outcome from the comparison during preparation confirmation. Missing preparation or demonstration evidence retains the existing manual-confirmation path. The activity is displayed as CONFIGURATION to distinguish it from single-SP polling.

M1Runtime passes the Plan key corresponding to the preloaded document, not a polling-variant key. Preparation records go in `/data/relying-party-attribute-preparations/<run>.json`. At this stage only source integration is complete; the running application and formal Run have not yet been updated or reevaluated.

<!--g1-literal--> `VerifyRelyingPartyAttributeExperiment.java` passed saved originals and exported preparation records to the formal comparison and obtained SATISFIED. The 6 negative controls—missing evidence, duplicates, another response, configuration changes, login-input changes, and fixed-input changes—returned NOT_VERIFIED. These checks establish the determination boundary before formal inventory adoption. The functional test batch remains pending. Java compilation of the entire API also succeeded.

<!--g1-literal--> Evidence is `production-comparison.json` and `preparation-receipts/` in the same demonstration directory. Product configuration changes, protocol sends, and user interactions in this step: 0. Deployment and result adoption remain outstanding; the inventory remains 466 observations.

## Adoption in the formal Run

An isolated build of the signed implementation was deployed to the reference environment. The existing Run's normal-login prerequisite was completed and preparation records installed. Initial formal confirmation returned NOT_VERIFIED: the normal-login AuthnRequest had no variant, and immutable Set contains(null) threw an exception, making the whole collector incomplete. This was a Suite defect. Out-of-scope normal requests were changed to be excluded using a stringified variant.

After the fix, comparison also succeeded against current Recorder originals containing the normal login. `RecordedEvidenceReevaluation` explicitly revalidates current originals only for the corresponding NOT_VERIFIED reasons. It uses existing audited result revisions without resending to the product or manually overwriting results. Preparation confirmation alone or an Outcome from saved diagnostics alone is insufficient for adoption.

The formal result for `IIP-IDP02-a-idp-01` is SATISFIED/PASS, `attested=false`. It demonstrates different attributes for each SP under the same configuration and restoration of the original attribute set when returning to the first SP. Adoption applies only to this Shibboleth browser SSO profile, not other products or cases.

`verify_relying_party_attribute_acceptance.py` checks re-audited native preparation, equality with regenerated preparation records, installed-record read-back, signature-verified comparison, negative controls, normal login and configuration restoration, formal Outcome, and unchanged original references. Only results passing this verification feed the inventory generator.

<!--g1-literal--> Unverified observations: 466→465 (−1). Case IDs remain 157 because other products retain unverified observations. Formally adopted evidence references: 8. Demonstration Run: `run_Z43RFP9ZF0175WP18Y1FZD70P9`; evaluation records: `build/acceptance/reference-20260918/shibboleth-relying-party-attribute-evaluation/`.

<!--g1-literal--> Deployment and evaluation operations: image builds 2, Suite/forwarder container recreation 2 each, preparation installation 1, tests/start 1, preparation confirmation 1, explicit reevaluation API call 1. Temporary normal-login configuration writes 3, reloads 2, deletion 1, protocol round trip 1. Attribute-comparison reruns and user interactions: 0. The initial unverified result remains in the record. Product configuration is fully restored.

Running image: `samlscope:reference-rp-attribute-v49`, digest `sha256:56636b7e26ce3cfb45baf6ac3e9798558ea82911c56a9e6c8148ccb97c90f824`. Signed implementation-fix commit: `8a673a56`. Unrelated uncommitted SOAP changes are excluded. Existing G2 issue G2-30 remains unresolved; this demonstration is not release approval.
