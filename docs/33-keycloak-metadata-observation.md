# Keycloak metadata observation paths and classification

The original investigation covered 91 Keycloak observations in the `metadata_idp` profile. These obligations concern target behavior after consuming Suite metadata: the Suite creates metadata document content and observes the target consumption results. They were separated into 3 categories according to available execution paths rather than grouped as attestations.

<!--keycloak-metadata:start-->
Unique scope: 34 case IDs (34 Keycloak metadata_idp ledger observations, without duplicates).

| # | Case | Obligation | Classification | Reason code |
|---:|---|---|---|---|
| 1 | `IIP-ALG07-a-idp-01` | IIP-ALG07.a | `operator-attestation-available` | `attestation.interaction-disallowed` |
| 2 | `IIP-EXT01-c-idp-01` | IIP-EXT01.c | `role-inapplicable` | `browser_fixture_partial` |
| 3 | `IIP-G01-a-idp-01` | IIP-G01.a | `suite-observation-gap` | `browser_fixture_partial` |
| 4 | `IIP-MD02-d-idp-01` | IIP-MD02.d | `suite-observation-gap` | `case.pending-interaction` |
| 5 | `IIP-MD05-a-idp-01` | IIP-MD05.a | `suite-observation-gap` | `case.pending-interaction` |
| 6 | `IIP-MD05-a3-idp-01` | IIP-MD05.a3 | `suite-observation-gap` | `case.pending-interaction` |
| 7 | `IIP-MD05-a8-idp-01` | IIP-MD05.a8 | `suite-observation-gap` | `case.pending-interaction` |
| 8 | `IIP-MD05-ac-idp-01` | IIP-MD05.ac | `suite-observation-gap` | `case.pending-interaction` |
| 9 | `IIP-MD05-am-idp-01` | IIP-MD05.am | `suite-observation-gap` | `case.pending-interaction` |
| 10 | `IIP-MD05-an-idp-01` | IIP-MD05.an | `suite-observation-gap` | `case.pending-interaction` |
| 11 | `IIP-MD05-ao-idp-01` | IIP-MD05.ao | `suite-observation-gap` | `case.pending-interaction` |
| 12 | `IIP-MD05-ap-idp-01` | IIP-MD05.ap | `suite-observation-gap` | `case.pending-interaction` |
| 13 | `IIP-MD05-aq-idp-01` | IIP-MD05.aq | `suite-observation-gap` | `case.pending-interaction` |
| 14 | `IIP-MD05-ar-idp-01` | IIP-MD05.ar | `suite-observation-gap` | `case.pending-interaction` |
| 15 | `IIP-MD05-aw-idp-01` | IIP-MD05.aw | `suite-observation-gap` | `case.pending-interaction` |
| 16 | `IIP-MD05-c1-idp-01` | IIP-MD05.c1 | `suite-observation-gap` | `case.pending-interaction` |
| 17 | `IIP-MD05-c2-idp-01` | IIP-MD05.c2 | `suite-observation-gap` | `case.pending-interaction` |
| 18 | `IIP-MD05-c3-idp-01` | IIP-MD05.c3 | `suite-observation-gap` | `case.pending-interaction` |
| 19 | `IIP-MD05-c5-idp-01` | IIP-MD05.c5 | `operator-attestation-available` | `attestation.interaction-disallowed` |
| 20 | `IIP-MD05-c6-idp-01` | IIP-MD05.c6 | `operator-attestation-available` | `attestation.interaction-disallowed` |
| 21 | `IIP-MD05-c7-idp-01` | IIP-MD05.c7 | `operator-attestation-available` | `attestation.interaction-disallowed` |
| 22 | `IIP-MD05-d1-idp-01` | IIP-MD05.d1 | `suite-observation-gap` | `case.pending-interaction` |
| 23 | `IIP-MD05-e7-idp-01` | IIP-MD05.e7 | `suite-observation-gap` | `case.pending-interaction` |
| 24 | `IIP-MD05-e9-idp-01` | IIP-MD05.e9 | `suite-observation-gap` | `metadata.algorithms.local-policy-unverified` |
| 25 | `IIP-MD05-ea-idp-01` | IIP-MD05.ea | `suite-observation-gap` | `metadata.algorithms.local-policy-unverified` |
| 26 | `IIP-MD05-f-idp-01` | IIP-MD05.f | `suite-observation-gap` | `case.pending-interaction` |
| 27 | `IIP-MD05-f5-idp-01` | IIP-MD05.f5 | `suite-observation-gap` | `browser_fixture_partial` |
| 28 | `IIP-MD06-a1-idp-01` | IIP-MD06.a1 | `suite-observation-gap` | `case.pending-interaction` |
| 29 | `IIP-MD06-a2-idp-01` | IIP-MD06.a2 | `suite-observation-gap` | `case.pending-interaction` |
| 30 | `IIP-MD06-a6-idp-01` | IIP-MD06.a6 | `suite-observation-gap` | `case.pending-interaction` |
| 31 | `IIP-MD07-b-idp-01` | IIP-MD07.b | `suite-observation-gap` | `case.pending-interaction` |
| 32 | `IIP-MD09-a-idp-01` | IIP-MD09.a | `operator-attestation-available` | `attestation.interaction-disallowed` |
| 33 | `IIP-MD09-b-idp-01` | IIP-MD09.b | `operator-attestation-available` | `attestation.interaction-disallowed` |
| 34 | `IIP-MD11-a-idp-01` | IIP-MD11.a | `suite-observation-gap` | `case.pending-interaction` |

Classification totals: `operator-attestation-available` 6 / `role-inapplicable` 1 / `suite-observation-gap` 27 = 34.

Metadata classification totals are `suite-observation-gap` 27 + `operator-attestation-available` 6 + `feature-absent` 0 = 33. The remaining 1 observations are non-metadata cases in the same profile (`role-inapplicable` 1 = `IIP-EXT01-b/c`, `evidence-form-mismatch` 0 = `IIP-ALG01/02`).

The 61 cases whose absence was unconfirmed were moved to `suite-observation-gap` (`absence_basis=not-confirmed-investigated-path`). The 7 `feature-absent` cases concern published mdui elements; absence was confirmed from target public metadata fetched by the Suite. `IIP-MD05.aw` belongs only to import observation (`suite-observation-gap`), resolving the previous classification overlap.
<!--keycloak-metadata:end-->

## 0. Recounting observations

At the time of this investigation, the Keycloak `metadata_idp` ledger contained **91 observations (91 case IDs, without duplicates)**: 84 `IIP-MD*` cases and 7 non-MD cases (`IIP-ALG01/02/03/07`, `IIP-EXT01-b/c`, and `IIP-G01-a`). The baseline ledger at 546 observations contained 92 (85 MD); earlier additional verification resolved 1 `IIP-MD05-fi` observation, reducing the count to 91. The count of 87 cannot be reproduced from that unique inventory. The distinction between the MD total of 84 (85 at baseline) and the overall scope consists of this 1 resolved observation and the 7 non-MD cases. Classification used the following disjoint sets; `IIP-MD05.aw` belongs only to import observation.

## 1. Keycloak capabilities examined on the product

Recorded findings from the admin API (`build/acceptance/reference-20260915/slo-oracle/keycloak-metadata-probe.json`):

- SAML clients use explicit fields, including `saml_assertion_consumer_url_post/redirect`, `saml_single_logout_service_url_*`, `saml.signing.certificate`, `saml.encryption.certificate`, `saml_name_id_format`, and `saml.client.signature`.
- **No metadata URL or refresh-interval attributes were found**. The investigated configuration had no path to fetch or refetch Suite metadata at runtime.
- **No server-side metadata import API was found on the investigated paths** (`client-descriptions` and `clients/import` returned 404). Admin console import parsed XML in the browser and created a client representation.
- There was **1 signing certificate per client** (a single `saml.signing.certificate`). The model could not represent multiple keys for the same purpose.

## 2. 3 classifications

### (a) Capability unconfirmed on the investigated paths (feature-absent)

Attributes or APIs for runtime fetch/refetch, document expiration, document signature verification, and multiple-document aggregation **could not be confirmed on the investigated paths: admin API attribute listings, availability of a server-side import API, and the single-certificate model**. Because absence remains unconfirmed, classification follows the evidence as `suite-observation-gap`, without using `feature-absent`. The next action is to recheck through the product import path (admin console metadata import). Ledger `absence_basis` is `not-confirmed-investigated-path`.

The unconfirmed set (`_KEYCLOAK_METADATA_FEATURE_ABSENT`): `IIP-MD01.a`, `IIP-MD02.a/b/c/d`, `IIP-MD03.a/b/c/d`, `IIP-MD04.a/b/c`, `IIP-MD05.a/a1/a2/a3/a5/a8/ac/ad/ae/af/ah/am/an/ao/ap/aq/ar/as/b/c/c2/c3/cd/d/d1/e/e5/e7/e8/e9/ea/eb/g`, `IIP-MD06.a1/a2/a3/a6/a7/a9/ab/b`, and `IIP-MD07.a`. `IIP-MD05.aw` is excluded and belongs only to import observation.

### (b) Observation through the product import path (suite-observation-gap, including 61 cases with unconfirmed absence)

**Suite XML parsing and conversion to admin API attributes is not proof of product metadata interpretation capability.** Submit the original fixture through the product import path (admin console metadata import), then observe signature verification, key selection, ACS selection, and certificate acceptance. Obligations that can be checked by direct attribute configuration are limited separately according to approved definitions. Record fixture identity, import results, and restoration through test-client deletion. Import success alone does not establish Success. At this stage, the path and oracle were both unimplemented, so the observations remained inconclusive.

Scope: `IIP-MD05.a4` (single EntityDescriptor acceptance), `IIP-MD05.av` (isDefault ACS), `IIP-MD05.aw` (signature verification with a use=signing key), `IIP-MD05.c1` (role-specific endpoint/key resolution), `IIP-MD06.a` (metadata-only provisioning), `IIP-MD06.a5/a8` (metadata/runtime key identity), `IIP-MD07.b` (rejection of signatures from keys outside metadata), `IIP-MD11.a` (keys without use), and `IIP-MD12.a/b/c/d` (certificate validity, signature method, and subject). The 61 cases in (a) were also assigned to this execution path because absence was unconfirmed; see the generated table above for the inventory.

### (c) Publication and operational evidence required (operator-attestation-available)

Runtime protocol observation cannot verify published key rollover history, revocation handling, whether Trust configuration such as CA import is required, or how algorithm publication is generated. These are verified through operator testimony, with 1 answer per case.

Scope: `IIP-MD05.c5/c6/c7`, `IIP-MD06.c`, and `IIP-MD09.a/b`.

## 3. Product import path implementation (verified in code)

Admin console metadata import was automated with Playwright, submitting the **original fixture file** through the product import path (`dev/keycloak/console_import.mjs`; execution requires `npm i playwright`). Suite XML-to-attribute conversion is not used.

Verified behavior:

- Console Import client accepted the Suite SP metadata document and created a client. **Clicking is distinguished from successful saving**: a success signal (navigation to client settings) is matched with **admin API read-back** confirming attributes and certificates. Verification does not rely solely on fixed delays.
- **1 test record** binds fixture identity (path, SHA-256, entityID), the created client (DB ID, clientId), import results (UI display, API read-back), optional subsequent flow (`--verify-command`), and deletion/restoration read-back (`--delete`).
- Script termination is explicit. Only verified import produces `IMPORT VERIFIED` with exit code 0. Failure records `IMPORT FAILED` and `status=failure`, then exits with code 1 without success-like output. This was checked with a success example and 2 failure kinds: missing entityID and rejected metadata.
- Import recreated an existing client with the same clientId, changing its client DB ID. Existing attributes were retained, SLO Redirect endpoints used by subsequent Runs were reapplied, and restoration was verified (`console-import/restore.json`).
- Import success does not establish Success. Subsequent protocol flows evaluate actual signature verification, key selection, and certificate acceptance behavior.

## 4. Why observations remain inconclusive and the next action

In addition to the implemented import path, category (b) requires an oracle observing signature verification, key selection, and ACS selection after import. The next implementation unit adds SSO/signature flow observation for imported clients through the interfaces in `docs/05`, starting with MD05.a4/av/aw and MD12 cases. Classification is reflected in `docs/26` diagnostics without changing Verdicts.
