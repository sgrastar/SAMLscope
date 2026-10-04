# Condition-specific evidence of encryption generation capability and omitted-MGF audit

## Implementation

Connected `MetadataEncryptionAlgorithmEvidence` to the ALG04/06 browser-evidence evaluation. In addition to existing ordinary SSO evidence, it can use signed responses from a metadata campaign in the same Run. The shared collector verifies correlation among original metadata, fetch records, outgoing requests and signed responses.

Extracted key matching, Assertion decryption and enclosed-signature verification into `MetadataEncryptionProof`, shared with MD05.e8. It checks that the fixture-specific private key matches the public key in the original metadata, and verifies the decrypted plaintext type and Issuer. Missing evidence, different keys, invalid signatures and ambiguous structures cannot establish a conclusion. Private keys and decrypted plaintext are not saved.

Declarations alone cannot establish Success for generation capability. The generated encryption algorithm and OAEP parameters are observed after successful decryption. Conformance to metadata-consumption obligations is not inferred from this generation-capability evaluation.

Added the browser SSO profile to the Shibboleth automation script. Results from a metadata Run are not reused for another profile; tests use a new Run for the relevant profile.

## Product results

Executed with Run `run_0TMTHFWK5HEM14WFNJ10RD5D1X`, Plan `plan_989BVXEKC7VCVDY56VR4H5SQJR`.

<!--g1-literal--> Executed 8 conditions: control, AES128/256 GCM, old/new RSA-OAEP × SHA1/SHA256, and declarations omitting MGF. Verified original-fixture import, signature verification, decryption with the matching key and rejection with another key for every condition, then restored product configuration.

| Case | Formal result in this campaign | Established observation |
|---|---|---|
| IIP-ALG04-b-idp-01 | PASS | AES256-GCM generation and decryption |
| IIP-ALG06-b-idp-01 | PASS | rsa-oaep generation and decryption |
| IIP-ALG06-c-idp-01 | PASS | Both OAEP methods with all SHA1/SHA256 combinations |
| IIP-ALG06-d-idp-01 | NOT_VERIFIED | Responses explicitly specify MGF; no omitted-form evidence |

ALG04.a and ALG06.a also passed but were already established, so they are not counted as newly resolved. Originals were saved in `build/acceptance/reference-20260918/shibboleth-producer-algorithms/`, and formal evaluation results in `shibboleth-producer-evaluation/`. Adoption requires `verify_producer_algorithms.py` to check the profile, originals, signatures, decryption, controls, all combinations and case evidence references.

## Omitted-MGF evaluation correction and withdrawal of an earlier conclusion

The approved ALG06.d variant concerns default behavior with no explicit MGF. Earlier code also treated explicit MGF1-SHA1 as Success. Evaluation now requires the omitted form, with a control showing that an explicit specification alone remains unverified even for the same SHA1. Approved G1/G2 definitions were not changed.

Audited the earlier Keycloak Run `run_6AD6T3VS8H87WQQBB1T2DEB3MX`. Every adopted original ALG06.d response explicitly specified MGF for rsa-oaep. Responses without an MGF element used the old rsa-oaep-mgf1p method and did not satisfy this condition. The earlier conclusion was excluded from adoption into the current comparison and unverified inventory and returned to unverified. Saved historical Run results remain for audit and must not be readopted as a valid conclusion.

Audit originals and hashes were saved in `keycloak-default-mgf-audit/`. During inventory generation, `verify_default_mgf_withdrawal` checks every adopted response in the earlier result against the original MGF evidence. This was not merely relabeling an existing result.

<!--g1-literal--> 3 new PASS observations and 1 withdrawn conclusion reduced unverified observations from 474 to 472. Distinct case IDs remain 157. No product FAIL was added.

## Validation and operation burden

Validated positive/negative encryption controls, missing combinations, explicit versus omitted MGF, signature/original/condition-specific key correlation, and regression coverage for the preceding intersection-selection evaluation together. The entire test suite was not repeated for each observation. G1 generated-document consistency, structural validation and inventory audit were also performed. The existing signed-source difference for G2-protected implementation remains.

<!--g1-literal--> Metadata writes 8; ingestion-configuration application/restoration 2; temporary-file deletion 1; total product writes 11. Service reloads 9; normal SSO 8; invalid-signature attempts 8; Run creation and preflight 1 each. Docker build 1; Suite/forwarder container recreation 1 each; product restarts 0; user interactions 0. Decryption inspection 1 execution; other-key controls 8. The first adoption audit stopped because of an assumed difference in profile-name capitalization; it succeeded after matching the API's lowercase spelling.

Execution image: `samlscope:reference-producer-metadata-v40`; digest: `sha256:cc159b10d6721a300e79756ff7d4342067466cdc37ccba2e2a2916b8e5582f67`. Unrelated uncommitted SOAP changes were excluded.

<!--g1-literal--> 20 targeted Runner tests passed; G1 structural checks 46/46; no inventory-audit errors. G2 remained 20/21, with only the existing G2-30 signed-source difference unresolved.

## Remaining work

Other products, ECP-specific paths and paths generating omitted-MGF responses remain incomplete. Partial capability observations, declarations, successful administration screens or campaign completion alone do not establish a conclusion.

## Additional generation-capability observations for the ECP profile

Executed with Run `run_SSWFM7EX1V67WPRXPK975NW52B`, Plan `plan_0T6SEXB43B3RGP5WFP6F1CSMHP`. The profile is `ecp_idp`, but this campaign observed generation capability through browser SSO. PAOS-specific conformance is not inferred from the result. Shared encryption cases were evaluated using measured evidence in the same Run; another profile's results were not copied.

<!--g1-literal--> Verified original-fixture import for 8 conditions, 8 signed responses, 8 matching-key decryptions and 8 other-key rejections. Completed the normal-login prerequisite in the same Run and formally evaluated through the protocol-evidence evaluation API. The 3 new PASS observations were ALG04.b, ALG06.b and ALG06.c. ALG06.d remains unverified because MGF is explicit.

Extended adoption validation per profile to match the Run, profile, imported originals, restoration, signatures, decryption, all conditions and case evidence references. Duplicate conditions/original IDs and missing required conditions are rejected. Confirmed that the earlier browser-profile adoption evidence passes the same validation.

Originals were saved in `shibboleth-producer-algorithms-ecp/`; formal results in `shibboleth-producer-evaluation-ecp/`. Regenerated the unverified inventory and comparison, and confirmed no unresolved-contract audit errors.

<!--g1-literal--> Unverified observations decreased 438→435; distinct case IDs remain 154. Omitted-MGF conditions in original responses and unobserved cases were not resolved by inference.

<!--g1-literal--> Operations: metadata and related writes 13, including restoration; temporary-file deletions 2; service reloads 11; Run creation/preflight 1 each. AuthnRequests sent 17: ordinary login 1, condition-specific normal requests 8, invalid-signature attempts 8. Responses received 9. Product restarts 0; Docker builds 0; Suite/forwarder recreations 0; user interactions 0. 1 decryption-inspection container execution used disabled networking and a read-only Suite key area; private keys and decrypted plaintext were not saved.

Only required evidence checks were performed; the full Java/Web tests were not repeated. Batch validation and deployment of the newly added display-name/TLS observation code remain separate work.

## Automated Keycloak generation-setting changes

Added `dev/keycloak/producer_algorithm_campaign.py` to create a Run-specific client and switch encryption-generation settings. It reads back configuration at every stage, leaves existing clients intact, and deletes only the client with the DB ID created by this campaign at completion, checking its absence. Administration tokens are obtained per operation and are not recorded. This path establishes generation capability through explicit settings; it is not evidence of the product's metadata interpretation.

Executed in Run `run_BCJDFCFSWYMHVSESDMZCMBNAKA`. The profile is `ecp_idp`; actual generation observations use browser SSO. Originals and formal results are retained in `keycloak-producer-algorithms-ecp/`.

<!--g1-literal--> Completed 5 stages combining AES256/128 GCM, old/new OAEP and SHA1/SHA256. Checked the original Redirect-query signature and equality with sent XML, Response signature, Assertion decryption/signature/Issuer, other-key rejection and rejection of modified responses. Private keys and decrypted plaintext are not saved. Adopted ALG06.c as a new PASS; unverified observations decreased 435→434, with distinct case IDs unchanged at 154.

`VerifyNativeProducerAlgorithms.java` and `verify_native_producer_acceptance.py` bind hashes of the original inventory, Transcripts, fixtures and configuration operations, checking through to evidence references in formal results. ALG06.d remains unverified because the new OAEP explicitly specifies MGF. Administration API acceptance alone does not establish a conclusion.

<!--g1-literal--> Administration API operations: GET 16, POST 1, PUT 5, DELETE 1, for 7 configuration writes; token acquisitions 23; browser SSO 5. Product restarts, Suite recreations, Docker builds and user interactions were all 0. Read-only decryption-inspection containers had 3 attempts. The first stopped because the verifier incorrectly assumed an XML signature for the Redirect signature; verification was corrected to use the original query. Subsequent attempts completed normally, and the final attempt also bound original adoption-evidence hashes. Failed attempts and operation counts are recorded in `operation-summary.json`.

Regenerated the inventory and comparison; the unresolved-contract audit had no errors. Full Java/Web tests were not repeated, and no commit was made.
