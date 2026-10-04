# Comparison inputs for attribute-release policy

Added metadata inputs to `MetadataService` for approved `IIP-IDP03-a-idp-01`, `IIP-IDP04-a-idp-01` and `IIP-IDP04-b-idp-01`. Generated XML uses existing signing and original MetadataPrepared recording. Generation is not proof of product consumption.

| Input ID | Content | Purpose |
|---|---|---|
| `attribute-policy-entity-present` | EntityAttributes in Extensions directly under EntityDescriptor | EntityAttributes presence condition |
| `attribute-policy-entity-absent` | No EntityAttributes | Absence control |
| `attribute-policy-requested-required` | RequestedAttribute for uid, isRequired=true | Required designation |
| `attribute-policy-requested-optional` | Same attribute, isRequired=false | Differential control for required designation |
| `attribute-policy-requested-absent` | No RequestedAttribute | Attribute-request absence control |
| `attribute-policy-indexed` | AttributeConsumingService entries requesting different attributes | Comparison input for AuthnRequest selection |

EntityAttributes uses name `urn:samlscope:test:release-policy` and value `release`. RequestedAttribute uses OID-form names for uid and surname. Indexed inputs prepare metadata; they do not establish completion of request-index switching or product-response comparison.

## Conditions required for the next integration

Submit EntityAttributes presence/absence, RequestedAttribute presence/absence and isRequired values through the product's own import path. Keep release policy and execution user fixed, and observe attribute-set differences in signed responses. Directly rewriting a configuration file to a different release result per condition is not evidence of metadata-consumption capability. Do not add a determination that isRequired=true always requires release.

Use polling with the same entityID as the basic comparison path. Preloaded aggregates change entityID per condition, so output differences alone cannot establish that metadata attributes caused them. Existing polling also changes keys/ACS per condition; inspect these differences and the actual product-policy inputs before adopting a conclusion.

Index selection requires retaining identical metadata and changing only AttributeConsumingServiceIndex in AuthnRequest. Different attributes returned from a different metadata document's default service do not establish this test.

## Indexed-request execution path

Added an index-accepting overload to `SamlSignedRequestFactory`. The attribute is set before signing; existing calls retain omission. Values outside XML Schema unsignedShort are rejected. AssertionConsumerServiceURL is not confused with this index; response ACS stays fixed.

<!--g1-literal--> Polling-start API `attributeConsumingServiceIndex` permits only 0 or 1, and only for `attribute-policy-indexed`. It survives waiting-state retransitions, normal requests and invalid-signature controls, and is recorded in original AuthnRequests and Transcript summaries. Added a shared execution path accepting `dev/keycloak/import_metadata_batch.py --flow-run ... --attribute-service-index ...`. This argument alone performs neither product-specific import operations nor evaluation.

Polling delivery of the indexed fixture retains original XML in the existing bounded cache for the same Run, avoiding validUntil/XML-signature changes on refetch. Because eviction/restart can occur, evaluation must still check original MetadataPrepared hash equality for both compared requests.

Ordinary polling campaigns advance after a response, so the index-comparison driver needs next-campaign preparation in the same Run and checks of fixed product configuration, user and original XML. This integrated driver and the oracle evaluating signed/decrypted attribute differences remain incomplete.

## Validation status

The following records the input-implementation stage. See [55](55-fixed-attribute-policy-observations.md) for subsequent isolated builds, deployment and fixed-policy comparison observations. Evaluation integration and Java tests remain incomplete at this stage.

Added tests for generated-condition placement, presence/absence, isRequired differences and index-specific attributes. Request tests cover signature verification, rejection of an index-modified signature, out-of-range rejection, omission compatibility and API fixture restrictions. Following the user's batch-validation policy, Java tests and product deployment will run together with later execution-path/evaluation integration. They have not run at this stage; the running image was not updated. Only G1 generated-document consistency and structural checks ran.

<!--g1-literal--> No new conclusive results; the inventory remains 470 observations and 157 case IDs. Product configuration writes, product restarts and user interactions were all 0 for this work.
