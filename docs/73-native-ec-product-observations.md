# Keycloak and SimpleSAMLphp EC signature observations

The shared EC signature execution path now uses the product's own metadata import and request-specific signature errors. Cases, obligation levels, and approved fixtures are unchanged.

<!--g1-literal--> Keycloak browser_sso_idp / metadata_idp / ecp_idp / single_logout_idp established 4 formal PASS observations. Unverified observations decreased 442 → 438; distinct case IDs remain 154. The same 4 SimpleSAMLphp observations retain NOT_VERIFIED with more specific diagnostics.

## Original metadata and actual requests

Keycloak receives original fixtures through the admin console's Import client. Admin API read-back checks product-interpreted certificates and required-signature settings. Adoption also checks certificate equality with the original fixture. Converting Suite XML into admin API attributes is not treated as evidence of metadata import.

The in-product observer plugin adds the same HTTP operation's request ID and original hash to Keycloak's own signature-verification event. It now also accepts the metadata-test request-ID format. At completion it restores realm configuration, checks the installed jar hash before removal, and verifies product restart.

SimpleSAMLphp uses its installed XML validator and metadata parser to import static metadata settings. Configuration writes, read-back, and restoration are recorded. Each Run executes normal RSA control, normal EC, corrupted EC, and normal login. Signature errors bind to the sent original request hash and direct HTTP response; Cookie, credentials, and session URL queries are excluded.

`NativeEcSignatureEvidence` verifies original certificates, SignatureMethod, Reference digest, and SignatureValue. Normal and corrupted EC requests share a key; the latter must have a valid Reference digest and only an invalid signature value. RSA control Success responses also undergo actual signature verification with the target metadata key. Keycloak normal EC responses received the same verification.

## SimpleSAMLphp remains unverified

SimpleSAMLphp accepted the RSA control but returned AuthnRequest `NOTVALIDCERTSIGNATURE` for a cryptographically valid EC request. This is not based merely on an HTTP error. Verification of the original EC public key/signature and product-specific error is recorded in the formal result as `ec-signature.native-valid-request-rejected`.

That rejection alone cannot prove that EC is unavailable under other settings. `EcSignatureSupportTestCase` finalizes the observation as NOT_VERIFIED without converting it to absence of capability or product FAIL/WARNING. Additional future evidence can reevaluate the same unverified result.

<!--g1-literal--> Mismatch/missing-evidence negative controls were checked together: 14 per Keycloak observation, 10 per SimpleSAMLphp observation, 96 total. For SimpleSAMLphp, changes omitting evidence required for the original diagnosis revert to `native-incomplete`; the diagnosis of verified originals cannot remain. Controls add no resolutions.

## Execution fixes and operation records

The metadata test driver accepts an HTTP observer and executes normal and corrupted fixtures through the same driver. An already corrupted EC fixture no longer receives another signature alteration. Shared audit-format conversion was separated into a pure function, resolving same-name module collisions when product drivers share a Python process.

Keycloak's initial attempt failed to launch Chrome in the restricted environment. Configuration and plugin were restored before retrying where local Chrome was available. Normal-login read-back then falsely rejected different ACS-set order. Shared comparison of set fields was corrected, and normal login completed while retaining failed records.

<!--g1-literal--> Keycloak console client imports/deletions: 12 each; normal-login client creations/deletions: 5 each (including failed read-back). Observer plugin installations/removals: 3 each; product restarts 6; event configuration writes 6. Failed-attempt restoration was also verified.

<!--g1-literal--> SimpleSAMLphp configuration writes across the batch: 17, plus 2 temporary-setting/restoration writes for unadopted diagnostic resends. Product restarts 0. Transcripts for all adopted/diagnostic Runs: AuthnRequest 48, Response 20, plus 1 unadopted diagnostic direct resend. User interactions 0.

<!--g1-literal--> Suite build, Suite recreation, and forwarder recreation: 1 each; receipt installations and formal evaluations: 8 each. The full Java/Web tests were not rerun, and no commit was made. Aggregate operation record: `native-ec-products-runtime-v59/acceptance-operations.json`.

## Evidence and adoption

Evidence parent: `build/acceptance/reference-20260918/`.

- Keycloak browser_sso_idp: `keycloak-native-ec-signature-v2/observations/browser_sso_idp/`. Completed normal-login records: `baseline-retry/`.
- Other Keycloak profiles: `keycloak-native-ec-signature-v3/observations/<profile>/`.
- SimpleSAMLphp: `simplesamlphp-native-ec-signature/<profile>/`.

`verify_native_ec_acceptance.py` cross-checks each directory's `native-ec-verification.json`, original manifest, receipt, configuration restoration, and `evaluation/result.json`. Formal results were also compared to the unverified inventory to confirm no other determined results were missed in adoption.

Running image: `samlscope:reference-native-ec-products-v59`. Read-back confirmed retention of existing Shibboleth EC determinations. G2 signature differences remain a separate approval issue; this demonstration does not complete release approval.
