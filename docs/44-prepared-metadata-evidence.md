# Recording metadata originals within a Run

## Implementation

Test metadata generation now records the exact bytes passed to the HTTP response in the Transcript. `MetadataResponseEvidence` records `MetadataPrepared` with the retrieval/export entry ID, variant, feed, and original SHA-256. decodedSamlRef gives access to the original XML, avoiding inference from variant names.

<!--g1-literal--> Five paths are covered: variant metadata, live, live/content, preloaded, and preloaded/download. Ordinary metadata retrieval unbound to a Run is not assigned to an arbitrary Run. Redirect-only responses do not record XML originals; subsequent content retrieval does. sourceType distinguishes exports from fetches.

Recording occurs before Servlet delivery, so delivery is `PREPARED`. Saving bytes does not establish successful HTTP delivery, native import, or metadata consumption. Authorization/Cookie headers from requests are not copied into these response records.

## Runtime verification

SimpleSAMLphp algorithm-advertisement conditions were executed in new Run `run_ZTEB6PCRWXJM0CZ6QWCZRR966T`. `verify_prepared_metadata_batch.py` compared Suite originals, retrieval records, fixtures supplied to the native parser, configuration read-back, and restoration.

<!--g1-literal--> Original XML matched byte for byte in all thirteen conditions. Response signatures verified under the Run-fixed IdP key for all thirteen. SHA256 selection despite different advertisements reproduced, but case integration remained unfinished: 483 observations and 159 case IDs stayed unverified.

Evidence is in `build/acceptance/reference-20260918/simplesamlphp-algorithm-recorded-metadata/`: `prepared-metadata-verification.json`, `verified-algorithm-signatures.json`, and `algorithm-selection-diagnosis.json`. Additional observations for MD05.ea/eb were updated to this Run; existing case Verdicts were unchanged.

Originals and correlation in the saved Run allow later evaluators to replay this evidence. Product configuration and login do not need to be repeated for every new evidence reader.

## Validation and deployment

API regressions verified equality between received HTTP bytes and saved originals, SHA-256, references to retrieval entries, OUTBOUND direction, PREPARED delivery, and separation from redirect-only records. G1 generation, structural validation, and inventory auditing were also checked. The existing G2 signature difference remained unresolved.

The deployed image was `samlscope:reference-metadata-response-v33`, digest `sha256:009c94ba10599f298720703560592652ac4fb0e2384dde12049edfa897dd74e0`. Application was recompiled with this change while excluding only the pre-existing unrelated SOAP differences. Source and JAR hashes are in `build/acceptance/reference-20260918/metadata-response-runtime/`.

<!--g1-literal--> Native imports: 13; product configuration writes: 27 (application/restoration plus final restoration); Run creation: 1; preflight: 1; signature-control requests: 13; normal requests: 13; Docker builds: 1; Suite/forwarder recreations: 1 each; user interactions: 0; product restarts: 0. Original configuration SHA-256 confirmed complete restoration.
