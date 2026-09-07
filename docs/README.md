# SAMLscope — SAML Conformance Test Suite

**Design documentation** / Created: 2026-08-25 / Status: v0.1 implementation complete; operational reference runs remain release evidence

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
| Hosted-version administrative access | **Per-Run secret URLs** (Phase 1) → OIDC login through Authrim in the future |
| Reference implementation results | **Published as version-pinned samples**. Run in CI, but do not publish continuously |
| Build / repository | **Gradle (Kotlin DSL)** / **single repository** |
| Quoting specification source text | **ID + original summary + link to the original-text anchor**. Do not reproduce the full text (inquiry to Kantara in parallel) |
| Languages | **English only**. Public test-definition YAML uses English fields only; legacy `ja` fields are rejected in CI |
| Requirements catalog | **`tests/coverage.yaml` is authoritative**; the tables in `04` are generated from it |

**The production domain is `samlscope.com`; the remaining D-15 items (operator, provider,
retention enforcement, and cost) remain operational deployment decisions.**
See [09-open-decisions.md](09-open-decisions.md) for the decision history.

## Status of Design Gate G1

**G1 and G2 are approved by signed records. The `PENDING_REVIEW` fields inside authored catalogs remain unchanged by design; approval evidence lives outside the reviewed target commit.**

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
M1–M4 Evaluation and publication ✅ Approved cases, evidence workflows, protocol probes, result JSON, report HTML, and hosted publication controls are implemented
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
