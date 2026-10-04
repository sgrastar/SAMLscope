# Metadata behavior after native console import

## Adopted conclusions

<!--g1-literal--> Six Keycloak metadata_idp observations became Success: unresolved observations fell from 517 to 511, with 170 distinct case IDs unchanged. Adopted Run: run_23BNMTA3K9G83SMEN2F2HFRMGK.

| Case | Conditions observed |
|---|---|
| IIP-MD02-c | EntityDescriptor and EntitiesDescriptor imported through the product console and used in correlated SSO |
| IIP-MD05-a4 | These document-root forms |
| IIP-MD05-a5 | Required combinations of cacheDuration, validUntil and single/aggregate roots |
| IIP-MD05-g | Unknown-namespace extensions and mdrpi:RegistrationInfo separately imported and used |
| IIP-MD12-a | Self-signed, multiple-certificate and long-validity fixtures |
| IIP-MD12-c | SHA-1-signed and SHA-512-signed certificates separately imported and used as key information |

The original Suite XML was passed unchanged to Keycloak Import client. Records identify parsed entityID, saved client ID, administration-API read-back and enabled signature verification. Correlated Success Responses to Suite-signed AuthnRequests followed; each temporary client was deleted and absence read back. Saving alone does not conclude a case.

Dedicated Plans avoid changing existing clients. Existing metadata campaigns provide fixtures, requests and response correlation. Although called automatic polling, this batch uses driver file retrieval and console import. It does not prove product HTTP refresh and is not counted toward HTTP acquisition/refresh obligations.

## Results not adopted

<!--g1-literal--> Original results also reported MD05.cd and MD06.a7 PASS; neither was adopted. KeyValue-only import left saml.client.signature=false and no signing certificate. SSO success therefore does not establish KeyValue signature verification. MetadataFixtureObservationTestCase could not distinguish this, so the Suite gap remains unverified. Original result.json is unchanged. Key-consumption cases need correlated invalid-signature controls.

Expired/not-yet-valid certificates imported but SSO returned Invalid requester. Without correlated SAML rejection Responses, no product Failed conclusion was adopted. Multiple entities, nesting and some multiple-key conditions also lack required behavior. Existing ACS fixtures were run, but not all approved conditions were covered.

## Implementation

- dev/keycloak/import_metadata_batch.py: dedicated Plan/Run, fixture retrieval, native import, correlated SSO, continuation without conclusions after failures, result/cost capture and additional campaigns in one Run.
- dev/keycloak/console_import.mjs: waits for asynchronous XML parsing before saving, selects explicit entity IDs in aggregates, prevents client overwrite and checks absence after unsaved failures.
- dev/keycloak/reference_flow.py: tracked version of the local form driver. Credentials/cookies remain in memory; this is not a substitute for JavaScript Webflow execution.
- dev/reference-acceptance/verify_keycloak_import_batch.py: limits adoption and checks original fixture SHA-256, native save, signature setting, SSO, deletion and Run/Transcript references during ledger generation.

<!--g1-literal--> Five altered-evidence controls were rejected: signature verification disabled, deletion unconfirmed, fixture hash mismatch, entity mismatch and native save unconfirmed. These are verifier tests, not new product conclusions.

## Cost and failed attempts

<!--g1-literal--> Totals: 45 import attempts, 40 save clicks, 39 confirmed creates/deletes and follow-up SSO attempts, 32 driver-correlated successes. Confirmed product writes: 78 creates/deletes; one additional click had unconfirmed save. Direct user operations: zero. All browser clicks/inputs and administration reads were unmeasured, not zero.

Chrome initially failed under the sandbox and was retried with permission. Corrected save-before-parse, fixture retrieval before Suite preparation, and choosing the first aggregate entity incorrectly. Failed records are retained. Recovery started Docker Desktop, stopped test containers and Shibboleth Tomcat. The running Suite image did not change.

## Evidence

Original XML, import/deletion records and SSO are in build/acceptance/reference-20260917/keycloak-import-batch-5/ and keycloak-import-batch-7/. The latter holds final result, Transcript, pre-decryption SAML copies and hash list. operations-summary.json, cleanup-verification.json and import-adoption-verification.json in the parent hold counts, final cleanup and verification. Evidence is ignored by Git.

## Retest with signature controls

<!--g1-literal--> Thirty distinct fixtures were tested through 36 imports. No new case conclusions; unresolved remained 511. The six prior adopted observations were replaced with positive/negative-signature evidence from run_J7HCGRMNJHC614BA103CNGMVZ5. Conditions or SSO successes are not counted as resolved cases.

--signature-control tests a damaged signature first under identical imported settings, then requires correlated Success with a valid signature. Only SignatureValue changes; SignedInfo, signed XML and other Redirect query bytes remain original. XML newline character references are supported. Missing/multiple signatures stop the trial as a Suite failure.

<!--g1-literal--> Thirty-one damaged signatures were sent. Three correlated Success Responses occurred across KeyValue-only and multiple-key/use-omitted conditions; these were not adopted as successful key consumption. Ordinary certificate imports returned Invalid requester for damaged signatures and Success for valid signatures. UI errors/silence alone establish neither product FAIL nor successful rejection obligations.

The generic Suite observer no longer concludes KeyValue consumption from SSO alone. It requires correlated signature discrimination, absent from the current Transcript contract, and remains unverified. Connecting external driver records to automatic Suite judgments is unfinished; driver success alone cannot release the gate.

<!--g1-literal--> All 473 Runner tests and four Python signature-mutation tests passed. Only Runner was overlaid into samlscope:reference-keyvalue-guard-v23; JAR SHA-256 matched. Earlier uncommitted API changes were excluded. In run_Q702A3RAKW9S48CPYZZFCA4GV5, normal SSO succeeded but MD05.cd/MD06.a7 stayed NOT_VERIFIED, exposing missing signature controls through protocol-evidence.

<!--g1-literal--> Costs: 36 import attempts, 35 saves/creates/deletes, 70 confirmed product writes, 35 follow-up flows and 26 correlated normal successes. Every attempt's deletion/non-creation was read back. Docker build 1, Suite/forward recreation 1 each, product restarts 0 and direct user actions 0. Total UI/API operations were unmeasured. The initial newline-character-reference processing failure is included.

Evidence folders: keycloak-signature-control-1/, keycloak-signature-control-2/, keycloak-signature-control-3/ and keycloak-keyvalue-guard-smoke/ under the same parent. Counts: signature-control-operations.json; deployment/JAR checks: keyvalue-guard-runtime/. Adoption requires all normal/damaged-signature/import/deletion records. Reruns cannot overwrite existing evidence directories.
