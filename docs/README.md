# SAMLscope — SAML Conformance Test Suite

**Design documentation** / Created: 2026-08-25 / Status: v0.1 implementation and reference acceptance incomplete; release blocked

An OSS tool that allows anyone to verify any SAML IdP / SP implementation under the same conditions, based on requirements in published specifications.
It aims to be the SAML equivalent of the OIDF Conformance Suite.

## Decided Items

| Item | Decision |
|---|---|
| Product name | **SAMLscope** (repo `github.com/sgrastar/samlscope` / package `com.samlscope.*` / image `samlscope/suite`) |
| License | **Apache-2.0** (DCO, no CLA) |
| v0.1 scope | **Complete Phase 1** — all <!--g1:requirements-->69<!--/g1--> IIP v1.1 requirements, including SLO / ECP |
| Trust model for published results | **Level 0 (local export) + Level 2 (shared URLs only for Hosted Runs)**. Uploading self-hosted results is not adopted |
| Backend | **Java 21 + Javalin/Jetty + OpenSAML 5 + Apache Santuario + SQLite** |
| Frontend | **React + Vite (TypeScript)**. `report.html` is also a static build of the same application |
| Hosted-version administrative access | **Secret URLs when OIDC is off; account-only access and admin roles when OIDC is on** ([17](17-oidc-authentication.md)) |
| Reference implementation results | **Published as version-pinned samples**. Run in CI, but do not publish continuously |
| Build / repository | **Gradle (Kotlin DSL)** / **single repository** |
| Quoting specification source text | **ID + original summary + link to the original-text anchor**. Do not reproduce the full text (inquiry to Kantara in parallel) |
| Languages | **English only**. Public test-definition YAML uses English fields only; legacy `ja` fields are rejected in CI |
| Requirements catalog | **`tests/coverage.yaml` is authoritative**; the tables in `04` are generated from it |

**The production domain is `samlscope.com`; the remaining D-15 items (operator, provider,
retention enforcement, and cost) remain operational deployment decisions.**
See [09-open-decisions.md](09-open-decisions.md) for the decision history.

## Status of Design Gate G1

**G1 and G2 have signed approval records. New production connections require the signed boundary renewal described in [82](82-generic-evidence-and-configuration-binding.md). The `PENDING_REVIEW` fields inside authored catalogs remain unchanged by design; approval evidence lives outside the reviewed target commit.**

| Artifact | Contents |
|---|---|
| `tests/specs.yaml` | Specification catalog (<!--g1:specs-->25<!--/g1--> specifications. Pin the versions of external drafts) |
| `tests/coverage.yaml` | **The sole source of truth for the requirements catalog and evaluation levels**. <!--g1:requirements-->69<!--/g1--> requirements → **<!--g1:obligations-->544<!--/g1--> obligations** (of which <!--g1:multi_clause-->129<!--/g1--> have multiple `source_clauses` ranges) |
| `tests/predicates.yaml` | Fixed set of conditional predicates (<!--g1:predicates-->26<!--/g1--> predicates) |
| `build/spec-reconcile-report.json` | Result of the independent validator (must satisfy **`totals.blocking_failures == 0`**. Before approval, SR-30 “open questions remain” and SR-31 “unapproved” remain FAIL, which is the completion condition for G1). **Do not place it under Git management because it is a build artifact** (save it as a CI artifact) |
| `docs/04-requirement-coverage.md` | **Generated artifact** from `coverage.yaml` (manual editing prohibited) |
| `tools/ci-stages.md` | CI stages for each gate and the locations of trust anchors |
| `.github/workflows/g1.yml` | Actual CI (`g1-check` / `spec-reconcile` / `g1b-approval`) |
| `.github/CODEOWNERS` | Protection for trust-anchor files |
| `tools/g1_{author,docgen,validate,extract}.py` | Generation / documentation / **independent validation** / shared normalization modules |
| `tools/g1_{trusted_verify.py,ci_verify.sh}` | Trusted entry point for approval verification and CI wrapper |
| `tools/requirements.txt` | Pinned dependencies (PyYAML 6.0.2 / pdfminer.six 20240706) |

The author has not filled in `reviewer` / `approved_at`.
**Approvals are not written to `coverage.yaml`** — the canonical source is the signed `tests/approvals/g1.yaml`
(outside the approved commit).

## Gates Until Implementation

```
G1a  Catalog creation             ✅ Complete
  ↓
G1b  Review obligation meaning    ✅ Signed approval complete
  ↓                               Verification: G1_TOOLS_COMMIT=<SHA> tools/g1_ci_verify.sh
M0   Skeleton implementation      ✅ Peer, transcript, preflight, API, and UI skeleton
  ↓
G2   Test design                  ✅ Role-specific cases, controls, counterexamples, mutants, and feasibility spikes have signed independent approval
  ↓                               Also include the verification infrastructure (schema / g2_validate / approvals/g2.yaml / CI)
M1–M4 Evaluation and publication ⚠ Runtime framework exists; missing or partial case oracles remain release blockers (docs/26, docs/27)
```

The conventions for implementation agents (such as Codex) are in [`AGENTS.md`](../AGENTS.md).

**G1b and G2 are separate reviews.** G1b checks “whether obligations correctly correspond to the original text,”
while G2 checks “whether cases have detection power.”
Because this was an area in which 41 of 49 original-text comparisons were incorrect in past reviews,
approval by someone other than the author is mandatory for both.

Detection power is demonstrated with a **mutant peer** (a Test IdP/SP with known violations injected),
not by differences in reference-implementation results ([00 §5](00-concept.md)).

## Documents

| # | Document | Contents |
|---|---|---|
| 00 | [concept.md](00-concept.md) | What to build / not build, differences from existing tools, success criteria |
| 01 | [scope-and-roadmap.md](01-scope-and-roadmap.md) | Definitions of Phases 1–5 and completion conditions for each phase |
| 02 | [architecture.md](02-architecture.md) | System architecture, technology stack, Test Peer design |
| 03 | [test-model.md](03-test-model.md) | Test Plan / Test Case / execution modes / evaluation vocabulary |
| 04 | [requirement-coverage.md](04-requirement-coverage.md) | Testability mapping for all <!--g1:requirements-->69<!--/g1--> Kantara IIP v1.1 requirements |
| 05 | [test-definition-format.md](05-test-definition-format.md) | Schema for test-definition YAML |
| 06 | [results-and-publication.md](06-results-and-publication.md) | Result format, shared URLs, trust model |
| 07 | [deployment-and-networking.md](07-deployment-and-networking.md) | Docker, URL/TLS requirements, Hosted version |
| 08 | [suite-security.md](08-suite-security.md) | Security of the Suite itself (SSRF, etc.) |
| 09 | [open-decisions.md](09-open-decisions.md) | Decision log (D-01–D-15) |
| 10 | [memo-review.md](10-memo-review.md) | Review results for the original concept memo (contradictions, omissions, improvements) |
| 11 | [review-log.md](11-review-log.md) | Design review records and resulting changes |
| 12 | [g2-test-design.md](12-g2-test-design.md) | G2 case, mutant, feasibility, and signed-approval design |

| 13 | [release-readiness.md](13-release-readiness.md) | Verification history and remaining release gates |
| 14 | [reference-acceptance.md](14-reference-acceptance.md) | Reference execution matrix and evidence requirements |
| 15 | [hosted-operations.md](15-hosted-operations.md) | Backup, restore, deletion and launch preparation |
| 16 | [phase2-preparation.md](16-phase2-preparation.md) | Draft scope and approval sequence |
| 17 | [oidc-authentication.md](17-oidc-authentication.md) | Standard OIDC login, ownership, deployment settings and pending G2 review |
| 18 | [request-signing-plans.md](18-request-signing-plans.md) | Fixed required/optional request signing, isolated results and acceptance limits |
| 19 | [oidf-product-alignment.md](19-oidf-product-alignment.md) | OIDF usability benchmark and comparison scope |
| 20 | [profiles-and-public-summaries.md](20-profiles-and-public-summaries.md) | Agreed functional profiles, variants, product summaries and badge presentation |

## 30-Second Summary

- **Target specification (Phase 1)**: Kantara Initiative *SAML V2.0 Implementation Profile for Federation Interoperability* **v1.1 (2019-12-18)**
- **Requirement count**: Common 31 + SP 17 + IdP 21 = **IdP Profile 52 / SP Profile 48**
- **Approach**: Black-box testing in which the Suite plays the opposite side of the test target (Test SP / Test IdP)
- **Execution**: Single Docker image. The Hosted and self-hosted versions use the same image
- **Results**: PASS/FAIL by Requirement ID, with traceability from specification basis → sent/received XML → reason for determination
- **Publication**: Opt-in shared URLs. However, never call the result “Certified”

## Most Important Design Decisions (Phase 1)

0. **Strictly distinguish “not applicable” from “could not be verified.”** A MUST obligation that cannot be tested due to the execution environment is `NOT_VERIFIED`, not `NOT_APPLICABLE`. It remains in the denominator, and the Run becomes
   `conformance = INDETERMINATE` / `completeness = INCOMPLETE`. Run determinations are reported on **two axes: conformance and execution completeness**.
   Evaluation levels are held only by `coverage.yaml`, **at the obligation level**, and must not be written into test definitions or implementations. → [03](03-test-model.md), [05](05-test-definition-format.md)

1. **Test Plan = one entityID**. Because SAML has no dynamic client registration, changing the entityID for each test case would force users to perform dozens of manual registrations. Issue one “all-inclusive metadata” set per Test Plan, and switch cases using the ACS index / RelayState / pre-arming. → [02](02-architecture.md)
2. **Three evaluation paths**. Automated (back channel only) / Browser-assisted (through the user’s browser) / Attested (the user attests to behavior on the Target side). SAML black-box tests may be unable to mechanically observe “the other party rejected it”; unless this is incorporated into the design, the resulting numbers have no meaning. → [03](03-test-model.md)
3. **Metadata requirements require reconfiguration on the test-target side**. IIP-MD01–MD04 and similar requirements cannot be verified unless the Target is configured to retrieve the Suite’s metadata. Give the Test Plan a metadata distribution method (manual / HTTP / MDQ). In the manual case, these become
**`NOT_VERIFIED(plan_configuration)`** (**not** `NOT_APPLICABLE`). They remain in the denominator, and the result becomes `conformance = INDETERMINATE` / `completeness = INCOMPLETE`. → [04](04-requirement-coverage.md)

- [Reference per-test comparison and Suite fixes](23-reference-test-comparison.md) — reviewed local IdP results, attribution, and remaining approval/browser limitations.
- [Unverified case inventory](26-unverified-case-inventory.md) — all remaining observations, Suite implementation gaps, supplemental retests, and evidence provenance.
- [Interaction execution and setup cost](25-interaction-execution-cost.md) — measured configuration changes, delegated operations, result deltas, and work-reduction priorities.

- [Additional implementation and retests](27-additional-implementation.md) — implemented observations, automation fixes, verified results, and remaining release blockers.
- [Supplemental decryption key acceptance](29-supplemental-key-acceptance.md) — explicit Run input for IdP decryption tests, local verification, and reference re-tests (2026-09-15).
- [Algorithm observation operations](30-algorithm-observation-operations.md) — producer-side IIP-ALG04/06 evidence, SSO/SLO evidence-generation gaps, and operation counts (2026-09-15).
- [Target-initiated acceptance](31-peer-intent-acceptance.md) — single-use intents for IdP-initiated SSO and target-initiated logout, reference results, and limits (2026-09-15).

- [Metadata behavior after product console import](34-native-metadata-import-acceptance.md)
- [Suite signature controls and product-native import](35-suite-signature-controls.md)
- [Published UI information notes and aggregate metadata retests](36-published-ui-acceptance.md)
- [Completing missing metadata extension and default ACS conditions](37-metadata-condition-completion.md)
- [Keycloak default ACS verification and signing-key uniqueness](38-keycloak-acs-and-signing-key.md)
- [SimpleSAMLphp encrypted SSO execution paths and missing evidence](39-encrypted-sso-execution.md)
- [Shared-key GCM decryption and opaque Assertion evaluation fixes](40-shared-key-decryption-foundation.md)

- [SimpleSAMLphp shared-key GCM product verification](41-shared-key-gcm-acceptance.md)

- [Metadata algorithm order and role-priority execution conditions](42-metadata-algorithm-fixtures.md)

- [Signature-verified evidence for algorithm selection](43-verified-algorithm-evidence.md)

- [Recording original metadata within a Run](44-prepared-metadata-evidence.md)

- [Connecting and verifying metadata algorithm selection evaluation](45-metadata-algorithm-oracle.md)

- [Deploying algorithm selection tests to Keycloak](46-keycloak-algorithm-oracle.md)

- [Shibboleth native loading and algorithm selection verification](47-shibboleth-native-algorithm-batch.md)

- [Skipping unsupported algorithms and evaluating encryption order conditions](48-algorithm-order-followup.md)

- [Encryption method, OAEP parameter, and key-size input conditions](49-encryption-metadata-fixtures.md)

- [Evaluating and verifying shared encryption, signature, and parameter choices](50-metadata-intersection-oracle.md)

- [Condition-specific encryption generation evidence and MGF omission audit](51-producer-algorithm-metadata-evidence.md)

- [SimpleSAMLphp intersection selection and efficient configuration restoration](52-simplesamlphp-intersection-and-batch-restore.md)

- [Attribute name and NameFormat generation verification](53-attribute-name-capability.md)

- [Attribute release policy comparison inputs](54-attribute-policy-fixtures.md)

- [Comparison under a fixed attribute release policy](55-fixed-attribute-policy-observations.md)

- [Connecting attribute release policy comparison to formal evaluation](56-attribute-policy-acceptance.md)

- [Preliminary diagnosis of SimpleSAMLphp attribute release paths](57-simplesamlphp-attribute-policy-probe.md)

- [UI metadata consumption inputs and remaining observation paths](58-ui-consumer-fixtures.md)

- [Formal evaluation of UI logo language selection](59-ui-logo-acceptance.md)

- [UI URL scheme comparison inputs](60-ui-url-scheme-inputs.md)

- [Attribute release comparison across SPs](61-relying-party-attribute-comparison.md) — IDP02.a internal comparison, native configuration, original-evidence verification, and formal Shibboleth adoption.

- [Scoped SP preloading and SimpleSAMLphp attribute comparison](62-scoped-preloaded-campaigns.md)

- [Keycloak attribute release verification by SP](63-keycloak-relying-party-attributes.md)

- [NameID omission evidence checking and comparison](64-nameid-omission-evidence.md)

- [Measured Keycloak attribute name and NameFormat generation](65-keycloak-attribute-name-diagnosis.md)

- [Common authentication context strength and preference comparison](66-authn-context-comparison-inputs.md)

- [Product integration and formal authentication context comparison](67-authn-context-native-acceptance.md)

- [EC signature product audit records and formal evaluation](68-native-ec-signature-acceptance.md)

- [Evidence audit for shared signature algorithm evaluation](69-algorithm-verification-evidence-audit.md)

- [Product audit integration for shared signature tests](70-native-signed-request-acceptance.md)

- [SimpleSAMLphp shared signature tests](71-simplesamlphp-signature-acceptance.md)

- [Keycloak signature verification event observations](72-keycloak-signature-observation.md)

- [Keycloak and SimpleSAMLphp EC signature observations](73-native-ec-product-observations.md)

- [Display name precedence and observation-condition diagnosis](74-display-precedence-observation.md)

- [Supplemental TLS observations and recording boundaries](75-transport-observation.md)

- [Correlating certificate conditions with product signature rejection](76-native-certificate-diagnosis.md)
- [Native signature-mode capability](77-signature-mode-capability.md) — independent Response/Assertion signing observation and native configuration campaigns.
- [Measured SimpleSAMLphp encrypted responses](78-simplesamlphp-native-encryption.md)
- [Metadata key selection and unpublished-key controls](79-metadata-key-selection.md)
- [Generic evidence collection and independent configuration completion](82-generic-evidence-and-configuration-binding.md)
