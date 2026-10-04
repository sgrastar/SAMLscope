# SimpleSAMLphp shared signature tests

SimpleSAMLphp shared signature tests now use observations of signature-verification errors returned directly by the product. Generic HTTP errors are not converted to rejection. The evidence combines acceptance of normal signatures, creation of signed successful responses, and specific validation errors for requests with corrupted bodies, references, or signature values.

<!--g1-literal--> ALG01 and ALG02 ran on browser_sso_idp / metadata_idp / ecp_idp / single_logout_idp, producing 8 formal PASS observations. Unverified observations decreased 460 → 452; distinct case IDs are 156. These are each profile's shared BROWSER tests, not substitutes for signature tests specific to ECP SOAP or SLO messages.

## Product errors and Suite evidence

Running product source confirmed that the IdP calls `Message::validateMessage` and, with signature validation enabled, executes `checkSign`. The product's own parser imported original SP metadata and `validate.authnrequest=true` was confirmed. Suite did not imitate the product's signature policy to make the determination.

Direct native responses to corrupted bodies/references contained `SimpleSAML\Error\Exception: Validation of received messages enabled, but no signature found on message.` Corrupted signature values produced `NOTVALIDCERTSIGNATURE` for an AuthnRequest element. The former does not merely mean an unsigned request was sent: Suite original replay separately verifies that the request is the specified signed, corrupted fixture.

The observer saves a fixed signature-error category, request ID, original request SHA-256, request/response URLs, response time, and response-body hash. It does not save Cookie, credentials, form inputs, or complete error pages. Generic `UNHANDLEDEXCEPTION`, page text “Signature failed,” other SAML element types, normal HTTP responses, and strings appearing only in script/style are insufficient for classification.

The verifier regenerates existing outbox originals with the Run key and checks equality. It verifies the actual normal-response signature using the target metadata key and checks producer algorithms. Abnormal evidence is adopted only for a direct response from the endpoint receiving the original request, with matching request hash/time and an explicit signature error corresponding to that fixture. Generic errors, redirects to another URL, no response, and conflicting SAML responses remain unverified.

## Demonstration and negative controls

<!--g1-literal--> Initial observations recorded only generic error codes and were not adopted. After 3 corrupted requests were resent diagnostically to inspect specific product errors, detailed classification was connected and the full matrix rerun with new Runs. Initial and diagnostic resends are not formal determination evidence.

<!--g1-literal--> Each observation checked 12 negative controls covering mismatched/missing Run, case, request, error, target metadata, fixture, and response, plus incorrect HTTP status, original hash, and endpoint. Across 8 observations, all 96 controls returned NOT_VERIFIED. They are not added to resolved product-observation counts.

Classifier checks were added to reject generic errors, other elements, normal responses, and error strings present only in hidden scripts. This batch combined compilation, the native matrix, original/control replay, and formal API evaluation. The full Java/Web test suite was not rerun, and no commit was made.

## Configuration operations and storage

<!--g1-literal--> Including initial attempts, diagnostics, and reruns: Run creations 8, product configuration writes including restoration 12, product restarts 0, user interactions 0. Suite recorded AuthnRequests 80 and Responses 32, plus 3 unadopted diagnostic resends. Suite build, Suite recreation, and forwarder recreation 1 each; receipt installations 8; formal evaluation API calls 4. Only configuration differences were applied across profiles; restoration to original bytes was finally verified.

Adopted evidence: `build/acceptance/reference-20260918/simplesamlphp-native-signature-observation-v2/<profile>/`. Originals and controls: `verification/protocol-verification.json`; formal results: `evaluation/result.json`. Running-product validation functions and callers are stored with source and hashes in the parent `native-source/`.

Operation records: `native-ssp-signature-runtime-v57/acceptance-operations.json`; execution image: `samlscope:reference-native-ssp-signature-v57`. The inventory adopts results checked by `verify_native_signed_acceptance.py` for configuration restoration, original fixtures, read-back, originals, controls, formal determinations, and matching evidence references.

```sh
.venv/bin/python dev/reference-acceptance/verify_native_signed_acceptance.py build/acceptance/reference-20260918 simplesamlphp
.venv/bin/python dev/reference-acceptance/generate_remaining_audit.py --evidence-root build/acceptance/reference-20260914/remaining-audit
.venv/bin/python dev/reference-acceptance/generate_comparison.py --evidence-root build/acceptance/reference-20260914
```

Equivalent Keycloak cases remain unverified. These product-specific errors are not reused for other products.
