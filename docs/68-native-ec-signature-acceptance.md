# Product audit records and formal EC signature evaluation

Shibboleth ECDSA-SHA256 acceptance was verified using the original metadata imported by the product, signed request/response originals, and product audit records containing request IDs. Independent browser SSO and metadata-profile Runs were connected to formal evaluation and adopted in the comparison table and unverified inventory.

<!--g1-literal--> This batch reduced unverified observations 458 → 456; distinct case IDs remain 156. Newly determined results are 1 PASS each for IIP-ALG03-a-idp-01 on Shibboleth / browser_sso_idp and metadata_idp. No product FAIL was added.

## Evidence used for determination

- Verify successful responses correlated to RSA control and EC requests with the target metadata signing key.
- Normal and corrupted EC requests use the same public key. Check that the corrupted request's body Reference digest is valid and only SignatureValue verification fails.
- Correlate product audit `MessageAuthenticationError` for the corrupted request by request ID, SP entityID, time, binding, and profile. A local error page, no response, or campaign termination alone does not establish rejection.
- Temporarily change only the audit format, not signature-verification policy. Verify restoration of original audit configuration and metadata providers at adoption. Save only permitted fields for the target Run, excluding usernames and session information.
- Bind local receipts to the Run, target metadata SHA-256, and original Transcript hashes. Missing evidence remains NOT_VERIFIED and is not an EC-unsupported determination.

<!--g1-literal--> Original-evidence replay checked 5 negative controls on both Runs: wrong-run / wrong-request / wrong-event / wrong-metadata / missing-condition. The inventory adopter checks originals, negative-control results, restoration records, formal PASS, attested=false, and equality of Transcript references used in formal evaluation.

## Execution path and remaining scope

`signature_audit_campaign.py` can collect both profiles together. `NativeEcSignatureEvidence` connects to the actual runtime browser registry and evaluates through the dedicated `protocol-evidence/evaluate` path. Completed normal login is a prerequisite; evidence collection alone does not satisfy it.

<!--g1-literal--> An initial manual configure API call returned 500 because the existing guard prevents manually confirming protocol-evaluated cases; the guard was retained. Subsequent proper evaluation had ready=0 because normal login was incomplete, then returned PASS after login completion. These attempts remain in the operation record.

Evidence from earlier local-error paths and remote-error configuration attempts is also saved. Attempts without a SAML error response are not determination evidence. Results are not reused for ECP, SLO, or other products.

## Storage and reproduction

Evidence is under `build/acceptance/reference-20260918/` in `shibboleth-ecdsa-native-audit/browser_sso_idp/` and `shibboleth-ecdsa-native-audit-metadata/metadata_idp/`. `evaluation/result.json` contains adopted formal results. `native-ec-runtime-v54/acceptance-operations.json` records attempts, configuration changes/restoration, restarts, protocol request counts, and normal-login operations.

```sh
.venv/bin/python dev/reference-acceptance/verify_native_ec_acceptance.py build/acceptance/reference-20260918
.venv/bin/python dev/reference-acceptance/generate_remaining_audit.py --evidence-root build/acceptance/reference-20260914/remaining-audit
.venv/bin/python dev/reference-acceptance/generate_comparison.py --evidence-root build/acceptance/reference-20260914
```

The execution image at EC adoption was `samlscope:reference-native-ec-v54`. The full Java/Web tests were not rerun, and no commit was made. Later return to revalidation and additional fixes through the shared algorithm audit are in the [audit record](69-algorithm-verification-evidence-audit.md). Opening counts describe the EC-adoption change, separately from the latest inventory.

## Shared test path for ECP and SLO profiles

Because the `import_metadata_batch.py` and `signature_audit_campaign.py` CLIs could not select ECP/SLO profiles, the existing shared BROWSER test was enabled for those Runs. Approved ALG03 fixtures and determination conditions were unchanged.

<!--g1-literal--> New ecp_idp and single_logout_idp Runs each executed the 3 conditions: RSA control, normal EC, and corrupted EC, and completed normal login. Checking original metadata, requests, signed responses, and request-specific product audit records produced 2 formal PASS observations. Following Keycloak shared-signature adoption, unverified observations decreased 444 → 442; distinct case IDs remain 154.

<!--g1-literal--> Each Run checked 5 negative controls, 10 total. Additional Transcripts: AuthnRequest 12, Response 6. Original audit configuration, metadata providers, and normal-login configuration were restored. Product restarts and Tomcat starts for audit changes/restoration were 2 each; user interactions were 0. No additional Suite build was needed; existing v58 EC determination was used.

Evidence is in `shibboleth-ecdsa-native-audit-additional/{ecp_idp,single_logout_idp}/`. The inventory adopter cross-checks `native-ec-verification.json`, `baseline/operations.json`, `receipt-installation.json`, and `evaluation/result.json`. Each result is adopted from that Run's originals and observations, without reusing another profile's result.

<!--g1-literal--> Total configuration writes in the additional batch: 18 (audit format/restoration, each metadata fixture, provider registration/restoration, and normal-login preparation), reloads 12, temporary-file deletions 4. The aggregate record is `acceptance-operations.json` in the same parent directory.
