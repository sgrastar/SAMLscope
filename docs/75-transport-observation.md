# TLS session observations and evidence boundary

Approved IIP-ALG07.a requires user attestation for consideration of TLS best practices. A negotiated TLS version or cipher cannot replace that attestation. The new observation deliberately has `affects_verdict: false`, does not assign a security grade, and does not mark an attested case complete.

`TlsSessionObservation` reads the actual JDK HttpClient response session. It retains only the bounded protocol/cipher names and a digest identifying the final response endpoint. It does not read session IDs, certificates, peer principals, request credentials, or headers. A reused connection is possible, so `fresh_handshake_verified` is false. Plaintext HTTP and unavailable session evidence are distinct statuses; neither is converted into a product failure.

The observation is connected to metadata retrieval in preflight and to ECP/SLO outbox response transcripts and delivery details. It concerns that actual connection only: a metadata endpoint is not evidence about all advertised SAML endpoints, and no browser transport observation is inferred. No additional network probe, TLS downgrade, certificate bypass, or configuration change is introduced.

While adding these hooks, the ECP recorder boundary was corrected: Basic Authorization is now attached only to the actual HTTP request and is omitted before calling Recorder. Cookie and credential response headers are likewise removed before recording ECP/SLO responses. Recorder-side redaction remains defense in depth. The test captures raw Recorder inputs to check this boundary, while the local HTTP server still receives the intended Basic credential.

## Pending grouped verification

Tests were added for real sender-boundary credential omission, plaintext observation, negotiated session fields, unavailable/inconsistent sessions, identifier exclusion, and explicit non-verdict semantics. The implementation and test sources compile successfully in the isolated build. These tests have not yet been run. The runtime has not yet been rebuilt/deployed for this increment; reference operations and human interactions are unchanged.

<!--g1-literal--> This fills an informational evidence gap affecting the ALG07 cluster of 12 existing observations, not 12 resolved determinations. The unresolved ledger remains 438 observations / 154 case IDs.

## Grouped validation and deployment

The TLS observation and Recorder-boundary changes are now deployed with `samlscope:reference-native-certificate-v60`. The grouped `TlsSessionObservationTest` and `HttpOutboundSenderTest` checks passed, including actual outgoing credential delivery while the Recorder sees no credentials. This remains supplemental observation only: it supplies no TLS-policy conformance verdict and reduces no unresolved case on its own. Runtime jar hashes were checked against the built distribution.
