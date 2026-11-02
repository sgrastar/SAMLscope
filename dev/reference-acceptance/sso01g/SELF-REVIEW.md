# Self-review

> Addendum (2026-10-31): The following is the record of the initial offline preparation. The Keycloak management API investigation and the live configuration driver, based on later user approval, are recorded in [SELF-REVIEW-KC.md](SELF-REVIEW-KC.md). The SAML campaign as a whole and the adoption of all four cases remain on hold.

2026-10-31. A record of offline preparation. No official determination or ledger update was made.

## Deliverables and what was reached

- `PLAN.md`: case definitions, all variants, positive/negative controls, differences from Shibboleth, configuration hypotheses based on stored product code, and undetermined items.
- `campaign.py`: reuse of the request matrix, advance confirmation of Run/digest/preconditions, original state capture, application of the normal/maximum groups, product read-back before and after condition communication, finally restoration, original state reconciliation, and individual counters.
- `keycloak_campaign.py`: dry-run CLI, and a batch implementing GET/compare/write/GET of public native configuration and restoration. Even if a write response is lost, it confirms via product read-back whether the change is a known one, and does not overwrite external edits.
- `simplesamlphp_campaign.py`: dry-run CLI, and host write and restoration of public configuration fragments using the existing ConfigurationBatch. It preserves the inode and prohibits a Docker fallback.
- `test_campaign.py`: unit tests of the memory driver, public fixture files, and CLI.
- `dry-run-keycloak/plan.json`, `dry-run-simplesamlphp/plan.json`: conditions, stop reasons, and conditional count estimates. They are not records of operations that were carried out.

**The live product driver and the product-specific independent receipt reader are unimplemented. We have not yet reached a state where conclusions can be confirmed on a real machine.**
Features that the stored materials indicate as unimplemented or unconfirmed were not filled in with speculative configuration or custom comparison code.
The CLI requires `--dry-run` and has no real-machine execution flag, HTTP client, Docker invocation, or arbitrary shell hook.
The lifecycle is the connection point for a future trusted driver, and this time was verified only with the memory driver.
Each driver's boolean preconditions and `product-runtime` labels have meaning only if that collection implementation is independently verified.
No API was provided that accepts arbitrary JSON containing labels, or an operator's self-report, as proof.

## Misjudgment risks

|Checklist item|Measures this time / remaining verification|
|---|---|
|Treating all-error as g-series success|The report is always supplemental-unadopted. It emits neither a case outcome nor a Verdict. Even a test with an all-error envelope does not yield conformance success. In future, the successful-selection control for each kind of the existing AuthnContextComparison is mandatory.|
|Error control for unachievable requests|The unachievable ClassRef/DeclRef for each of ga/gb/gc remain in the request matrix. Correlation, signature, and verification of the actual SAML error in the original require an independent reader. HTTP error is not substituted.|
|Maximum selection that is too weak|EXACT success for low/medium is collected under the same maximum configuration. Unreachability of high and the completeness of the available set are also native preconditions. Returning low is not made conforming on the grounds of being at or below the upper bound.|
|Detection power of first precedence|Independent low/high EXACT controls and both forward/reverse are planned for each kind. Error alone or only one order cannot be adopted.|
|Suite-specific strength|Shibboleth's URNs are only reused as a planning template. If the order is not what the product's map/flow/source actually defined, hold before sending. No general strength ranking of authentication methods is assumed.|
|DeclRef unsupported|A partial experiment with ClassRef only is not extended to success for all cases. For both products, the preconditions are currently not met.|
|Silence/HTTP 500/configuration not applied|Tests were run confirming that timeout, HTTP error, UNKNOWN_DELIVERY, and native read-back mismatch stop at incomplete. They are not converted to product FAIL.|
|Direct HTTP sending|The script has no sending function. A future driver consumes only the persisted outbox of the existing Run. There is a test that rejects a preloaded-recorder-only receipt. Existing CONFIG g cases have empty action keys, so they are on hold until the path is prepared.|
|Duplicate sending/apparent success|Duplicates of requestId/actionId/request/response references are rejected. The same mode/condition is processed exactly once, with no retry after an exception. Double-click prevention on the real browser side is unverified.|
|Reattaching originals from another Run|Match of Run/hash/condition/mode is confirmed. A foreign Run stops collection. There is no function to add a case to a stored Run or rewrite a Transcript. The IDP19.b-specific binding is not repurposed.|
|Overclaiming evidence verification|Envelope matching is not cryptographic verification. An independent reader that verifies signature, decryption, metadata, destination, issuer, request fingerprint, and session/operation is needed separately. An unverified receipt is not promoted to official evidence.|
|Omitting positive/negative controls|The IDs and triggers of the cases and mutants are recorded in PLAN. The product's positive/negative controls were not run this time. Unit test success is not rewritten as control VERIFIED.|
|Confusing host write with product application|Host success, native write success, group application confirmed by product read-back, and restoration attempts/successes are tallied separately. The existing ConfigurationBatch.applied_count is not used as the native application count.|
|Restoration failure|Marked dirty before the first apply, and restored in finally even on a mid-way exception. If it does not match the effective fingerprint of the original state, it is incomplete. External edits are not overwritten and become subject to manual confirmation.|
|Process stop/power loss|finally alone cannot handle this. The original public state is currently only in memory. A future live driver needs a recovery snapshot without secrets, a pre-write journal, native reconciliation on resume, and duplicate-action prevention. The current code is not to be exposed live as is.|
|Credentials|This time, credentials, keys, .env, and private files were not read. Arbitrary driver data and exception bodies are not output to logs; only permitted public envelopes are output. Secret removal by a future driver needs separate verification.|
|Verdict on the case side|The case implementations were not changed. The preparation code also does not generate outcome/Verdict. Existing cases return only outcome, and the Evaluator converts according to the official level.|

## To confirm before the real machine

1. In a permitted environment, verify the signed definitions and the G1/G2 boundary, the case membership/digest of the profile and real Run, and transitive linked variants. Do not resume a Run with stale retained definitions using new definitions.
2. Investigate native functionality before login. Confirm Keycloak's running version, the SAML step-up feature, the actual URI/LoA attribute names, flow/execution/config/mapper, and DeclRef support.
3. Confirm whether SimpleSAMLphp's standard selector in the running version handles minimum/better/maximum and DeclRef. If the unimplemented state of the stored version cannot be resolved, keep NOT_VERIFIED. Do not create product behavior with custom PHP.
4. Determine the isolation scope of the dedicated client/flow or public selector fragment, the original state, dependencies, restoration privileges, and storable public values. Neither the whole existing authsources nor a realm export containing secrets is used as evidence.
5. Implement a read-back method for the running configuration as interpreted by the product itself. The configuration values from a management GET alone do not prove flow execution. Diagnose non-reflection such as PHP opcache or bind mounts before login.
6. Prepare an implementation and independent verification that ties all comparison conditions to persisted outbox actions of the existing Runner. Merely selecting the case in CONFIG, or merely assembling a URL for preloaded, does not satisfy the requirement.
7. Fix the current Run, metadata, and login input, and confirm in the original the real success of low/high and of maximum low/medium, unreachability of high, and unachievable error. Availability is not carried over between changed configurations.
8. The user enters input in a visible browser. Follow the Suite's instructions for fresh/reuse, and do not enter input passively. Do not save authentication headers, Cookies, raw login HTML, storage, or screens.
9. Verify with an independent reader the Recorder decoded original digest, the unique correlation of the original request/response with the action, signature, decryption, issuer/ACS/Audience/SubjectConfirmation/RelayState, and the fixed request fingerprint.
10. Rerun the positive/negative controls for each case, and verify that mutations of missing, duplicate, foreign Run, mismatched response, and unverified control become NOT_VERIFIED.
11. Confirm the product read-back after restoration and the normal-SSO control of the same Run. Adoption only after independent verification, and update comparison/inventory with the existing generators.

What is needed on the real-machine side is an isolated product, permissions to read/change/restore public configuration, a current Run containing the target cases, a compatible signed Suite, an outbox-capable path, a product-specific read-back driver/independent reader, and the user's visible browser.
From the present materials, we cannot promise that all functionality will hold for both products.

## Operation counts

|Item|Measured this time|Plan after all preconditions are met, 1 product, no retries|
|---|---|---|
|Product configuration write attempts / host success / native success / effective application / restoration|All 0|2 configuration groups plus 1 restoration group. The real write count of each group increases with the number of dependent objects, so it is undetermined. If 1 group = 1 write, at least 3 attempts. Host configuration writes for the Keycloak management API approach: not applicable, 0.|
|Condition communication|0|24. 16 approved evaluation conditions, 4 maximum availability controls, 4 first-candidate availability controls.|
|Normal SSO|0|1 after restoration, and 1 more if the initial control is incomplete. 25 to 26 round trips in total.|
|Login submissions|0|If every operation is fresh, at most 26 is the baseline. Increases if MFA, re-auth, or additional admin login is needed. Measured value is unmeasured.|
|Explicit logout|0|Planned 0. Context disposal and logout are distinct. Add to the count if it becomes necessary.|
|User clicks/consent/admin screen operations|0|Unmeasured. Even assuming at least 1 submit operation per authentication, screen transitions and MFA add to it, so the upper bound is not fixed.|
|Product effective read-back|0|At least 53 calls in the common engine. The internal API/PHP read counts of each call are tallied separately per dependency.|

For 2 products, 48 condition communications are estimated, and 50 to 52 including normal SSO. At this stage the preconditions are not met, so planned real-machine execution remains 0.
The write counts of the dry-run and memory fixtures are not counted as product configuration changes.

## Verification results and unrun checks

25 additional tests plus 6 existing tests in `dev/simplesamlphp/test_configuration_batch.py`, 31 in total, passed.
AST syntax checks of the 4 Python files also passed. Plan JSON was generated by dry-run of both CLIs.
In the re-run of the tests, a Python audit hook rejected sockets/external process launches, reads of prohibited files, and writes outside the designated destination.
The Docker invocations in existing tests are mocks, and no actual Docker process was started.

Logs are `unit-tests.log` and `test-results.json` in the designated job directory. In the run with external-operation audit: 31 tests / 0 failures / 0 errors.
Reflection delay, native functionality, real HTTP, Chrome session behavior, cryptographic verification of positive/negative controls, and re-verification of signed approvals are outside the scope of this test.

AGENTS.md's usual checks `g1_docgen.py --check` and `g1_validate.py --structural-only` were not run, because they read coverage/specs/predicates/approvals, which were explicitly prohibited from reading this time.
Gradle, browser integration, the full G1 comparison, and G2 execution were also not run, in order to avoid output outside the designated destination, prohibited inputs, the network, and so on.
Therefore we do not claim a passed structural check, release readiness, or independent approval.

No existing files were changed. The existing AGENTS.md change shown by `git status --short --untracked-files=no` at the start of work was not touched, and its diff was not read either.
Write destinations of deliverables are only the designated sso01g and children of the job directory. No commit, push, Docker, network, or ledger update was done.
