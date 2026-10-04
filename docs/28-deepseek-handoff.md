# DeepSeek handoff prompt

You are taking over implementation in `/Users/yuta/Documents/SAMLscope`. First record the SHA of the signed commit containing this file, the current HEAD, and the working-tree diff. Track subsequent changes against that checkpoint. This is an in-progress checkpoint, not release approval.

## Objective and approach

The user requested implementation of as many missing judgments, test conditions, evidence paths, additional observations and individual diagnoses as possible, aiming for zero unresolved items. Batch validation after roughly fifty resolved observations where appropriate, rather than testing after every few cases, and periodically check for implementation omissions.

Collect real-product evidence to resolve unverified observations. Additional unit-test conditions alone do not resolve them. Performing configuration on the operator's behalf still incurs configuration work. Record configuration writes, restoration, reloads, browser operations and direct user operations separately, and prioritize reuse and fewer required actions.

Local implementation, verification and deployment to the test environment are authorized. Publication, push and production release are outside this historical handoff request. Existing G1/G2 approvals are not independent approval of new source.

## Required reading and judgment constraints

Read local `AGENTS.md`, `docs/README.md`, `docs/03-test-model.md`, `docs/05-test-definition-format.md`, `docs/02-architecture.md` and `docs/11-review-log.md`.

- Do not edit protected G1 artifacts: `tests/coverage.yaml`, `tests/specs.yaml`, `tests/predicates.yaml` or `tests/approvals/*`.
- Cases return Outcome; Evaluator determines Verdict. Send only through the outbox and derive actionId deterministically.
- UNKNOWN_DELIVERY, missing evidence and incomplete Suite paths are not product failures. An unprepared environment is not NOT_APPLICABLE.
- Cover approved variants, linked obligations and positive/negative controls. Source presence or configuration values alone do not establish protocol conformance.
- Verify Redirect signatures over the raw query before URL decoding. Remove credentials before Recorder receives data.
- Update generated documents through their generators. Follow the existing G1 number-marker rules.
- Do not commit ignored paths, even if tracked. Do not stage private/, AGENTS.md, .authrim/, .authrim_keys/ or .authrim-keys/.

## Status at this handoff

<!--g1-literal--> Phase 1 is incomplete and cannot be released. Of the baseline 594 unverified observations, 27 were concluded, leaving 567 observations across 180 distinct case IDs. These are aggregate product/profile/case observations, not a completed Run or a conformance rate. Phase 2 remains a scope proposal; later phases are incomplete.

<!--g1-literal--> Remaining categories: missing automatic judgments 102; partial test conditions 61; post-configuration evidence/attestation paths 187; disabled attestation 75; metadata observation gaps 71; browser/SLO observation gaps 20; individual diagnoses 51. See `docs/26-unverified-case-inventory.md`.

Product comparisons are in `docs/23-reference-test-comparison.md`, operation accounting in `docs/25-interaction-execution-cost.md`, and implementation history in `docs/27-additional-implementation.md`. Adopted Runs vary by case; do not confuse the comparison with totals from the latest Run.

<!--g1-literal--> Measured follow-up work included 39 configuration writes including restoration, 16 product reloads, 17 delegated browser operations and zero direct user operations. Earlier environment setup was unmeasured, not zero.

## Environment and verified scope

The last test deployment at this checkpoint was `samlscope:reference-key-capability-v18`; verify actual Docker state. Suite uses port 18080, Keycloak 18180, Shibboleth 18280 and SimpleSAMLphp 18380. Evidence is in ignored `build/acceptance/reference-20260914/` and is absent from this commit. It is available on the same machine, not from a fresh clone.

Basic SLO and signed Redirect LogoutRequest passed for all products. Shibboleth also passed encrypted NameID, multiple decryption keys and configuration capability backed by both trials in one Run. Keycloak metadata lacks an encryption key, but its administration state already has an encryption-key provider. Read `keycloak-decryption-keys/diagnosis.json` before creating providers. SimpleSAMLphp also accepts the wrong-key control; this lack of detection power is not a product-wide failure.

Shibboleth runs from `/opt/reference-idp`. `/opt/shibboleth-idp` also exists but is inactive. The container's main command is sleep, so restarting the container alone does not start Tomcat. Consult existing operation records and identify the target process before operating it.

## Unfinished supplemental public-key input

Implemented and tested in an earlier batch:

- Core `SupplementalDecryptionKeys`: RSA public keys only, bound to Run, target entity, metadata SHA-256, source and recorded time.
- Store `SqliteSupplementalDecryptionKeys` and migration V013: first INSERT only; absence also becomes fixed; Run deletion cascades.
- Runner `SupplementalDecryptionKeyService`: identical resubmission is idempotent; replacement is rejected; published keys precede deduplicated supplemental keys.

Added immediately before handoff, with compilation only:

- `SupplementalDecryptionKeyRoutes`: GET `/api/runs/{id}/supplemental-decryption-keys`, POST `.../submit`, fixed-field validation and no-store.
- `SamlScopeApplication`: route registration and read/write authorization.
- `M1Runtime`: input scope limited to SINGLE_LOGOUT_IDP; reads/submission; input freezing on quickCheck/startTests/startInteractive.

**This connection was incomplete and undeployed at this checkpoint. Scenarios did not yet consume supplemental keys.** Implement the following together:

1. Check API authorization, older Runs, races with test start, and premature freezing during initial login/automatic execution. `withManualEvidenceWork` is not a local exclusive lock. Audit whether the first SQLite INSERT protects every start path.
2. Connect API state and UI input, displaying fixed state, source and target metadata.
3. Make encrypted 19a/19c and capability 19b use the same fixed effective key set. Preserve published metadata and disclose supplemental-input provenance in results.
4. Preserve strict evidence sets in `MultipleDecryptionKeysConfigurationTestCase`; adding provenance must not change counts or correlations.
5. Verify the API/scenario/result connection, deploy to the test environment and retest. Reduce unverified counts only after new evidence.
6. Continue beyond this area with common missing judgments, fixtures and observations from the complete inventory.

## Verification and generation

Set JAVA_HOME to `/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home`. Use `.venv/bin/python`. Gradle cache access may require the environment's additional permission.

```sh
.venv/bin/python tools/g1_docgen.py --check
GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=gpg.ssh.allowedSignersFile GIT_CONFIG_VALUE_0=/private/tmp/samlscope-ci-allowed-signers .venv/bin/python tools/g1_validate.py --structural-only
GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=gpg.ssh.allowedSignersFile GIT_CONFIG_VALUE_0=/private/tmp/samlscope-ci-allowed-signers .venv/bin/python tools/g2_validate.py
```

<!--g1-literal--> G1 generation and structure passed 46/46. G2 remained 20/21 with the G2-30 protected-source difference. A signed work checkpoint does not replace independent approval. Earlier Runner 444, Core 179 and Store 39 tests passed, but were not the final full test including the API connection. `:api:compileJava --offline` passed before handoff.

```sh
.venv/bin/python dev/reference-acceptance/generate_comparison.py --evidence-root build/acceptance/reference-20260914
.venv/bin/python dev/reference-acceptance/generate_remaining_audit.py --evidence-root build/acceptance/reference-20260914/remaining-audit
.venv/bin/python dev/reference-acceptance/generate_interaction_report.py --evidence-root build/acceptance/reference-20260914/interaction-followup
```

`unresolved-contract-audit.json` checks required variants, controls and original-result consistency; it does not prove completed implementation. Append to `operations.jsonl`, including restoration and failed configuration attempts.

## Changes and reporting

The handoff commit also preserves earlier OIDC, administration UI, user-management and retention work. Preserve those changes and do not attribute them all to this acceptance campaign. Record changed locations, rationale, verification scope, unresolved-count changes and configuration effort; report to the user in Japanese. Test counts or an approved catalog alone do not establish release readiness.
