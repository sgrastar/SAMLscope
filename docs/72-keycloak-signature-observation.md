# Observing Keycloak signature-verification events

`dev/keycloak/signed_request_observation.py` creates temporary native SAML clients and executes normal login and the existing outbox shared-signature matrix. It reads back registered public keys, required-signature settings, and ACS through the admin API, then deletes only clients it created. This prepares signature-verification testing; it does not prove product metadata interpretation.

It records request IDs, original hashes, direct-response status/body hashes, and before/after product-event differences. Credentials and Cookie are not saved; response URL queries and fragments are also excluded. Event configuration is saved beforehand and restored with read-back. Differences in URI-set or event-type-set order are not configuration changes. Detected changes by others are not overwritten.

## Native observations

<!--g1-literal--> For ALG01/ALG02 on browser_sso_idp, metadata_idp, ecp_idp, and single_logout_idp, 8 case observations collected 32 conditions: normal, altered body, altered reference, and altered signature value. Normal requests had correlated SAML responses. The 24 abnormal direct responses were HTTP 400, with product LOGIN_ERROR / invalid_signature recorded in the same sending/receiving window. Every observed request hash matched Suite outbox originals.

Product events, however, lacked SAML request IDs and had null clientId. Retrieval differences or timestamps alone cannot establish request correlation. These results are diagnostic; generic “Invalid requester” text is not signature-rejection evidence. Formal adoption requires cryptographic normal-response validation and request-specific product event binding.

`dev/reference-acceptance/diagnose_keycloak_signed_requests.py` matches each fixture's outbox records, HTTP observations, correlated response, and event request ID, then writes missing evidence to `signature-diagnosis.json`. It does not change product Verdict.

<!--g1-literal--> At this diagnostic stage the inventory remained 452 unverified observations. Formal integration below uses request-correlated events from new Runs and does not count this diagnosis as resolution.

## Interruption and restoration

The initial SLO-profile attempt falsely detected configuration mismatch because Keycloak reordered ACS lists and strict array comparison rejected them. Event-type restoration had the same issue. Comparison was changed to sets; remaining temporary client settings and identifiers were checked before deletion, and event configuration restoration was verified. Failed records were retained, with additional restoration checks in `recovery.json`.

The next SLO attempt lost its connection before authentication and made no configuration changes. Docker daemon status and Suite HTTP requests also timed out. Normal Desktop restart failed because it could not stop, so the authorized forced termination and restart were used. Only previously running test containers resumed, and Shibboleth Tomcat was started. After Suite and product HTTP health checks, a new SLO Run completed the matrix, temporary client deletion, and event restoration. Startup authentication failures remain recorded and are not test successes.

<!--g1-literal--> Initial and recovered attempts total: Run creations 5, client creations 5/deletions 5 (including additional restoration), event configuration writes 4 (including restoration). Docker Desktop forced stop/start 1 each, test container starts 5, Tomcat starts 1, user interactions 0. Saved Transcripts: AuthnRequest 40, Response 15. The 2 SLO retries failing before authentication created no Runs. No commit or full Java/Web test run was performed.

Evidence: `build/acceptance/reference-20260918/keycloak-native-signed-request-observation/`; completed SLO: `keycloak-native-signed-request-observation-slo-ready/`. Read each profile's `native-http-observations.json`, `signature-diagnosis.json`, `decoded-manifest.json`, and `restoration.json` with parent `operations.json` and `recovery.json`. Failed SLO retry outputs: `keycloak-native-signed-request-observation-slo/` and `keycloak-native-signed-request-observation-slo-recovered/`.

## Request-specific event integration and formal adoption

The observer plugin in `signature-listener/` runs as a product `EventListenerProvider`. Within the product-issued `LOGIN_ERROR / invalid_signature` callback, it records that HTTP request's SAML original hash and request ID. It is restricted to Suite temporary clients, POST endpoints, AuthnRequest, and a fixed request-ID format. It does not change events, HTTP input, client settings, or authentication processing. Observation failure is missing evidence, not a changed product verification result.

Compilation uses SPI libraries retrieved from the running Keycloak. The plugin is installed only during testing, with a temporary realm listener-list change. Completion restores configuration, verifies the installed jar hash before deletion, and confirms healthy responses after product restart. Observer logs exclude credentials, Cookie, usernames, sessions, and complete request XML.

The `keycloak-native-event` path in `NativeSignedRequestEvidence` checks:

- Original outbox requests regenerated with the Run key exactly match the specified altered fixtures.
- Event request ID, original hash, and issuer match the sent original.
- The product event is a signature error within the corresponding sending/receiving interval.
- A direct abnormal-request HTTP response is received at the original endpoint, with no correlated SAML response. HTTP errors alone cannot determine the result.
- The correlated normal-request Success response has an actual Response signature verifiable with the target metadata key and the target algorithm.

<!--g1-literal--> New 4 Runs collected 32 conditions and formally established PASS for 8 ALG01/ALG02 observations. Unverified observations decreased 452 → 444; distinct case IDs 156 → 154. These shared BROWSER tests do not replace ECP SOAP or SLO-message-specific verification.

<!--g1-literal--> Each observation checked 17 negative controls during original replay, 136 total. Alongside Run, case, request, event, target metadata, fixture, response, HTTP status, original hash, and endpoint, incorrect native-record hash, issuer, time, event type, and substitution of an indirect HTTP response were rejected as NOT_VERIFIED. The inventory adopter checks configuration restoration, originals, controls, formal determinations, and matching evidence references.

<!--g1-literal--> Formal-adoption batch operations: client creations 4/deletions 4, event configuration writes 2, observer jar installation 1/removal 1, product restarts 2. Suite build, Suite recreation, forwarder recreation 1 each; receipt installations 8, formal evaluations 4, user interactions 0. Operation record: `native-keycloak-signature-runtime-v58/acceptance-operations.json`. Collected evidence: `keycloak-native-signature-audit/<profile>/`; product observer source and installation/removal records are in its parent.

Execution image: `samlscope:reference-native-keycloak-signature-v58`. `native_signature_campaign.py` performs library retrieval, build, installation, tests, configuration restoration, jar removal, and restart together. It rejects replacement of existing plugins or overwriting settings changed during execution.

<!--g1-literal--> The combined script was also verified natively with 1 additional metadata_idp Run. It collected 6 native signature errors and completed client deletion, realm restoration, jar removal, and restart. This automation check adds no formal resolutions. Additional operations: client creation 1/deletion 1, event configuration writes 2, jar installation 1/removal 1, product restarts 2. Record: `keycloak-native-signature-automation-check/`.

New formal results were matched against the unverified inventory by product, profile, and case to detect missed adoption. No additional PASS/FAIL/WARNING candidates remained beyond this batch's adopted results. Output: `native-keycloak-signature-runtime-v58/additional-adoption-candidates.json`. G1, originals, controls, and formal evaluation were checked together; the full Java/Web tests were not rerun, and no commit was made.

<!--g1-literal--> G1 generated-document consistency and structural validation passed 46/46. G2 is 20/21, with known G2-30 (protected implementation source differs from signed approval) remaining. This demonstrated resolution does not complete release approval.
