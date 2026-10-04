# Supplemental public-key acceptance record (2026-09-15)

This follows the unfinished supplemental-key connection in `docs/28-deepseek-handoff.md`, based on commit `52e8feff9507b4bcae4e9f46152a6439ef94a4dd`. Implementation, verification and deployment were local; no publication or push occurred in this batch.

## Connections changed

| Area | Change | Verification |
|---|---|---|
| Runner | `SupplementalDecryptionKeyService.KeySet`, published/supplemental provenance, `keySet`, `TestInputFixed` | Unit and race tests |
| Encryption scenarios | Select effective keys excluding Suite control keys; record `decryption_key_source` | 19a/19c key-selection matrix |
| Configuration capability | `19-b` uses the same fixed keys and preserves strict evidence checks: four entries for each encryption test | Provenance regression tests |
| API | `GET/POST /api/runs/{id}/supplemental-decryption-keys`, state/submission, 409 Conflict, no-store, authorization and CSRF | API integration and HOSTED authorization |
| UI | Run input panel: target entity, metadata SHA-256, fixed state, source and time | Component/workspace tests |
| Result | Public diagnostic `decryption_key_source`, fixed tokens `published-metadata` / `supplemental-input` | Result assembly and real Run result.json |

Published metadata is not rewritten. Source URIs are not fetched, and signing-only keys are not silently reused.

## Local verification

<!--g1-literal--> Core 179, SAML 75, Store 39, Runner 451, Peer 13, API 86 and Web 83 tests passed: 926 total. G1 generated-document matching and structure passed 46/46.

<!--g1-literal--> G2 remained 20/21: G2-30 protected source did not match its signed approval commit. Earlier approval was not reused as independent approval of new source.

GET does not freeze Run inputs. Identical resubmission preserves time and provenance; replacement returns 409. Starting tests preserves submitted inputs or fixes an unsubmitted Run to no supplemental keys, rejecting late additions. Twenty concurrent freeze/submit trials persisted either the submitted key or the no-key state consistently.

## Real-environment retest

Image: `samlscope:reference-supplemental-v19`, digest `sha256:59a7760e2becec15c7f2854ad71011fd0a3c9bcab87a63bfe6d94f8c600bd878`. The preceding `samlscope:reference-key-capability-v18` lacked this API path, so the working tree was fully built and deployed.

| Product | Run | Supplemental input | Compared cases | Difference |
|---|---|---|---:|---|
| Keycloak | `run_YXCS140PP32WZD22SSH60HTW0M` | One administration-API RSA-OAEP ENC public key, source `http://localhost:18180/admin/realms/samlscope/keys` | 49 | 19a/19c reason codes changed; Verdict stayed NOT_VERIFIED |
| Shibboleth | `run_S3994DAQTP7WYFB6XSMJ1Q57QJ` | None; two published encryption keys | 49 | None |

Keycloak changes:

- `IIP-IDP19-a`: `slo.encrypted-id.key-unavailable` → `slo.encrypted-id.negative-control-failed`.
- `IIP-IDP19-c`: `slo.encrypted-id.multiple-keys.key-unavailable` → `slo.encrypted-id.multiple-keys.configuration-unavailable`.

Supplemental input was applied: 19a passed key selection and sent a LogoutRequest encrypted with the unregistered Suite control key. Keycloak accepted that request, so the positive trial was not sent; the negative control failed and the case remains unverified. No product Failed conclusion was added. 19c has fewer than two registered keys and remains configuration-unavailable.

Shibboleth had no Verdict change across 49 cases. 19a/19c retained Success with four evidence entries each; 19b retained Success with eight. result.json gained `decryption_key_source: ["published-metadata"]`. SimpleSAMLphp was not rerun because it already had the same negative-control failure.

<!--g1-literal--> Unverified counts remained 567 observations / 180 distinct case IDs. The batch proves supplemental-input application and provenance, not new evidence sufficient to conclude product Verdicts.

## Operation accounting

Following docs/25, writes, reloads, browser work and direct user operations are separate. Only work on 2026-09-15 was measured; earlier setup was unmeasured.

| Operation | Count |
|---|---:|
| docker build | 2: initial overlay and subsequent full build |
| Failed deployment attempt | 1: overlay lacked required startup classes; rolled back and not adopted |
| Suite container recreation | 2: failed attempt and full deployment; one running-image change |
| Forward container recreation | 2 |
| Product container restart | 0 |
| Product configuration writes | 0 |
| Product administration API reads | 2: token and key listing |
| Supplemental input submission | 1 |
| Suite Run creation | 2 |
| preflight | 2 |
| Protocol/browser round trips | 46: Keycloak 19, Shibboleth 25, initial login 2 |
| Automatic browser transitions | 4: Shibboleth SLO page |
| Direct user operations | 0 |

The first overlay used a base image predating the supplemental-key Store implementation and failed startup. This failed attempt is retained; a full build replaced it. No product setting, reload or direct user action was required.

## Limits and remaining work

- Keycloak encryption cases remain unverified because the unregistered-key control is accepted, preventing positive trials.
- The full image includes earlier OIDC, administration and user-management work. This batch claims only the SLO-profile regression comparison for those unrelated changes.
- G2-30 remained unresolved; these changes had not received independent approval.
- Other inventory categories, including missing automatic judgments, partial fixtures and evidence paths, were not addressed here.

## Evidence

Ignored `build/acceptance/reference-20260915/` contains full-build logs, source/class SHA-256, Run result.json/report.html/transcripts, operation logs and comparisons.
