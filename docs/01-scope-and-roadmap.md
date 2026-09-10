# 01. Scope and Roadmap

> **Current profile model:** Phase 1 execution is migrating from the historical
> Core/Full scopes described below to the seven functional case-set profiles in
> [20](20-profiles-and-public-summaries.md). The historical definitions remain here
> to interpret existing results; they are not the names of new Plans.

## Overall phases

```
Phase 1  Implementation Conformance      Kantara IIP v1.1            ← Current
   ↓
Phase 2  Core Conformance                OASIS SAML Core / Bindings / Profiles
   ↓                                     + Conformance classes from OASIS Conformance Requirements
Phase 3  Deployment / Interoperability   Kantara Deployment Profile v2.0 (formerly SAML2int)
   ↓                                     + Operational requirements such as eduGAIN / InCommon
Phase 4  Security / Attacker Model       OASIS Security & Privacy Considerations
   ↓
Phase 5  Fuzzing / Differential Testing
```

> **Correction to the original memo**: Phase 3’s “SAML2Int” has now been carried forward in
> Kantara Initiative’s *SAML V2.0 Deployment Profile for Federation Interoperability v2.0*.
> saml2int.org’s v0.2.1 is treated as a historical document; references point to the Kantara version.

## Phase 1 scope

### Included

| Area | Contents |
|---|---|
| Profiles | SAML IdP Implementation Profile / SAML SP Implementation Profile (two levels each, below) |
| Bindings | HTTP-Redirect, HTTP-POST, SOAP (back-channel SLO / ECP) |
| Protocols | Web Browser SSO, Single Logout, Enhanced Client or Proxy (ECP) |
| Metadata | Static inspection + distribution from the Suite (HTTP / MDQ) + signatures / validUntil / multiple keys |
| Cryptography | Verification of supported signature and encryption algorithms, and compliance with algorithm declarations |
| Execution | Test Plan creation from the Web UI, interactive execution, complete recording of communication logs |
| Output | HTML report, JSON result, opt-in sharing URL |

### Excluded (Phase 1)

| Exclusion | Reason / Deferred to |
|---|---|
| Attack testing (XSW, signature forgery, replay, etc.) | Phase 4. However, the foundation (low-level XML generation) will be prepared in Phase 1. |
| Artifact binding | Not a required feature of IIP v1.1. Phase 2 |
| SAML Attribute Query / AuthzDecisionQuery | Phase 2 |
| Special behavior of IdP Proxies / Gateways | Phase 3 |
| Browser automation (Playwright, etc.) | Phase 2 onward. Phase 1 uses the user’s browser. |
| Multilingual UI | English only |
| User accounts / access control | When needed for the Hosted version. Phase 1 self-hosted has no authentication. |
| CI integration (GitHub Action, etc.) | Phase 2. Stabilization of the result JSON will be done in Phase 1. |

## Test Profile structure

```
SAML Implementation Profile (Kantara IIP v1.1)
│
├── IdP
│   ├── IdP Core     — Common(31) + IdP(21) obligations that are MUST and SSO/Metadata/Algorithm
│   └── IdP Full     — Above + SLO + ECP + SHOULD/RECOMMENDED obligations
│
└── SP
    ├── SP Core      — Common(31) + SP(17) obligations that are MUST and SSO/Metadata/Algorithm
    └── SP Full      — Above + SLO + SHOULD/RECOMMENDED obligations
```

> **Improvement from the original memo + review feedback**: The memo used “Basic / Full,”
> but did not state the distinction’s criteria. We establish them here. **The unit of assignment is an obligation, not a requirement.**

```
Full(role)  = All obligations applicable to that role (excluding NOT_APPLICABLE)
              ★ Nothing is excluded. By definition, this is the entire profile.
Core(role)  ⊂ Full(role)
              The subset SAMLscope selected as the “minimum interoperability line.”
```

**Core selection criteria** (recorded per obligation in `coverage.yaml`’s `level_assignment`):

1. Its level is `MUST_CLASS`.
2. It also falls into one of the following categories:
   - Directly necessary for Web Browser SSO to succeed (SSO / Bindings / NameID / signature locations)
   - Metadata retrieval, validation, and key handling (**including IIP-MD01–MD12**)
   - Signature and encryption algorithm interoperability (ALG01–ALG06, ALG08)
   - Basic attribute transfer (SP01, SP02, SP10, IDP01)
3. It does not belong to SLO / ECP / Discovery.

> **Correction**: The previous version said “all MUST Metadata requirements are Core,”
> while the coverage table made IIP-MD02 Full (review finding 13).
> **IIP-MD02 is Core** has been corrected.
> In addition, the previous definition of Full omitted role-specific MUST obligations (attribute release, Discovery, etc.).
> Redefining **Full = all obligations** prevents omissions.

`level_assignment` is maintained **per obligation, not per requirement**.
Within the same requirement, `.a` may be Core while `.b` is Full
(for example, IIP-SP13.a is Core, while IIP-SP13.b (deny by default / SHOULD) is Full).

The source of truth for Core / Full assignments is `coverage.yaml`,
and [04-requirement-coverage.md](04-requirement-coverage.md) is generated from it.
The report must state that **the IIP source does not distinguish Core/Full** (this is SAMLscope’s own classification).

## v0.1 milestones

**Decision**: v0.1 = complete Phase 1 (all <!--g1:requirements-->69<!--/g1--> requirements of IIP v1.1, including SLO / ECP).
Because the first release will take longer, internal milestones make progress visible.

> **Meaning of “all <!--g1:requirements-->69<!--/g1--> requirements”** (aligned with [04](04-requirement-coverage.md))
> - ✅ Record **all <!--g1:requirements-->69<!--/g1--> requirements decomposed into obligations** and include them in reports.
> - ✅ Implement test cases for **every obligation except** `testability: NOT_OBSERVABLE`
>   (CI enforces that there are zero `NOT_VERIFIED(not_implemented)` results).
> - ❌ It does not mean that **all <!--g1:requirements-->69<!--/g1--> requirements are determined in every Run**.
>   `NOT_VERIFIED` may remain depending on the Test Plan structure, reachability, and whether the target can be configured;
>   in that case, `conformance = INDETERMINATE` / `completeness = INCOMPLETE`.

| M | Contents | Completion guideline |
|---|---|---|
| **G1a** Creation ✅ | Read all <!--g1:requirements-->69<!--/g1--> requirements through the end of their original sections and decompose them into <!--g1:obligations-->544<!--/g1--> obligations. Create `tests/{specs,coverage,predicates}.yaml` and `docs/04` (generated artifact). | Complete; authored state remains `PENDING_REVIEW` because approval is external. |
| **G1b** Approval ✅ | **Someone other than the author** directly compares the source with `coverage.yaml` and approves all obligations in **signed `tests/approvals/g1.yaml`** (outside the commit under approval). Do not edit `coverage.yaml`. | `g1_ci_verify.sh` returns `g1.complete == true`. |
| **G2** Test design ✅ | **Assign <!--g1:case_target-->543<!--/g1--> obligations to case IDs** and define coverage of `required_variants` and positive/negative controls. **Someone other than the author reviews the design** ([G2 details](#-design-gate-g2--test-design)). | Signed independent approval protects the complete design and implementation boundary. |
| **M0** Skeleton ✅ | Test Peer metadata issuance, Transcript Recorder, Preflight, Test Plan CRUD, SSE. Even with zero tests, reach the point where “SSO with Keycloak completes one round trip.” | The Suite functions as a SAML counterpart. |
| **M1** SSO core ✅ | Common SSO / Algorithms + IdP/SP SSO requirements. Implement verdict vocabulary, evidence ladder, and attestation UI. **Requires G2 completion.** | Quick execution and exact implementation-registry audits are implemented. |
| **M2** Metadata ✅ | Metadata distribution / MDQ / variants from the Suite (IIP-MD01–12). `WAITING_CONFIG` step. | Tests requiring target reconfiguration can run. |
| **M3** SLO + ECP + remainder ✅ | IIP-SP14–17 / IIP-IDP13–21. ECP is automated by acting as an **ECP client + SP** using only the back channel ([02 §3.7](02-architecture.md)). Also add the `secondary_peer` (second Test IdP) for IIP-SP05. | ECP, SAML-EC, channel-binding, SLO, and secondary-peer paths are implemented without `not_implemented` placeholders. |
| **M4** Publication ✅ | Freeze result JSON v1, `report.html`, Hosted version, sharing URL, pre-publication scrubbing. | Implementation complete; official Hosted operations and reference-run publication are release operations. |

> **Run against a mutant peer at least once at M1** ([00 §5](00-concept.md)).
> The worst pattern is discovering after everything is built that there is no detection power.
> **Do not use “whether real-product results differ” as the detection-power oracle**
> (all three products may conform, or differences may result from configuration differences).

## ★ Design gate G2 — Test design

Even after passing G1b (correct correspondence between obligations and the source),
the failure **“the obligations are correct but the cases have no detection power”** remains.
Reviews R5–R9 repeatedly found cases without controls
(SSO07 “either error or ignore is acceptable,” only one side of ALG04’s algorithms, SP07 rejection only).

**Place G2 between G1b and M1 (implementation of verdict cases).**
M0 (the skeleton) may begin after G1b, but **verdict-case implementation starts only after G2 is complete**.

### Target

Of the <!--g1:obligations-->544<!--/g1--> obligations in `coverage.yaml`, the **<!--g1:case_target-->543<!--/g1--> obligations** excluding `NOT_OBSERVABLE` (<!--g1:not_observable_keys-->`IIP-SSO05.a4`<!--/g1-->)
.

> The denominator is inserted from `tests/coverage.yaml`, rather than written directly in this document (`tools/g1_docgen.py`).
> To prevent stale numbers across multiple files when obligations are added,
> **SR-41** in `g1_validate.py` detects “denominators written outside markers” and fails.

| testability | Count | Notes |
|---|---|---|
| `BROWSER` | <!--g1:tb_browser-->216<!--/g1--> | User’s browser is required |
| `CONFIG` | <!--g1:tb_config-->178<!--/g1--> | Request a configuration change on the target side |
| `ATTESTED` | <!--g1:tb_attested-->53<!--/g1--> | Report behavior inside the target |
| `AUTOMATED` | <!--g1:tb_automated-->96<!--/g1--> | Completes using only the back channel |
| `NOT_OBSERVABLE` | <!--g1:tb_not_observable-->1<!--/g1--> | No case is created |

### Deliverable — `tests/cases.yaml` (machine-readable)

```yaml
schema_version: 1
g2_state: PENDING_REVIEW          # As with G1, approval is by signed record
cases:
  - id: IIP-SP13-01
    obligation: IIP-SP13.a
    covers_variants:               # ★ Qualify with <obligation key>#<variant ID> (03 §Link semantics L3)
      - IIP-SP13.a#v-3f2a1b7c9d
      - IIP-SP13.a#v-8e41c05b62
    role: sp
    mode: CONFIG
    milestone: M1
    controls:
      - kind: positive             # A conforming implementation passes
        description_en: Send a signed Response → it is accepted
      - kind: negative             # A nonconforming implementation fails
        description_en: With rejection configured, send an unsigned Response → it is rejected
    counterexample_en: >           # ★ Required: an implementation that passes without satisfying the obligation
      An implementation that rejects every Response regardless of whether an AuthnRequest exists.
      The positive control catches this.
    depends_on: [IIP-SSO01-01]
    destroys_session: false
    detected_by_mutants: [no-signature-validation]   # ★ Must be non-empty or have mutant_waiver (below)
    baseline: sp-full-slo-enc      # ★ Fix the expected baseline
```

`required_variants` in `coverage.yaml` was migrated to stable IDs **before G1b**
(all <!--g1:variants-->1211<!--/g1--> variants). Do not change G1 artifacts during G2.

```yaml
        required_variants:
          - id: v-3f2a1b7c9d
            description_en: With rejection configured, send a completely unsigned Response → it is rejected
          - id: v-8e41c05b62
            description_en: Signed Response → it is accepted (control)
```

The ID is a content hash derived from **the obligation key + description** (`v-` + 10 hex).
It does not change when reordered; editing the description changes it (= the variant has changed).
**SR-22b / SR-22c** in `g1_validate.py` check format and uniqueness.

### Pass criteria

- [ ] **All <!--g1:case_target-->543<!--/g1--> obligations are assigned to at least one case** (verified in CI).
- [ ] Each obligation’s **`required_variants` is completely covered by `covers_variants`**, with
      `variant_groups` preserving `all_of` / `one_of` / `one_of_available` semantics.
- [ ] **Expanded `linked_obligations` are also covered** — the variant set obtained by **transitively expanding** links with `kind: inherit_variants` is the denominator ([03 §Link semantics](03-test-model.md) L1). Apply each link's `variant_applicability` rule while scheduling the imported variants (L2).
      Covering the destination’s variants **does not cover the linked obligation itself** (L4).
      Refer to them with the qualified form `<obligation key>#<variant ID>` (L3).
- [ ] Each evaluative case has both a **positive control and a negative control**.
      An explicitly non-evaluative MAY/OPTIONAL choice instead has an informational fixture,
      `control_waiver_en`, and `mutant_waiver`; it must not invent a `violated` outcome.
- [ ] Each case includes a **`counterexample_en`** (an implementation that passes without satisfying the obligation).
      If one cannot be written, redesign the case because it has no detection power.
- [ ] ★ Each obligation is **detected by an executable mutant or has a waiver**
      (`detected_by_mutants` is non-empty, or `mutant_waiver` records the reason and
      an **alternative executable control fixture**).
      Without this, even a mutant set covering only <!--g1-literal-->10 obligations could pass G2
      by claiming that “the expected results of all mutants matched.”
- [ ] `covers_variants` refers to **stable variant IDs** (array indexes are prohibited).
- [ ] `depends_on` contains no cycles, and `destroys_session` is reflected in execution order.
- [ ] Every case is assigned to one of **M1–M3**
      (M0 is a “zero-test skeleton” and has no cases).
- [ ] The **feasibility spikes** below have been completed.
- [ ] **Someone other than the case author** reviews and signs off on the design (same method as G1b).

### G2 validation infrastructure (the unit to have Codex implement)

G2 cannot be satisfied by “review” alone. It needs the same concrete machinery as G1.

| Deliverable | Contents |
|---|---|
| `schema/cases-v1.json` | JSON Schema for `tests/cases.yaml` |
| `tests/cases.yaml` | Case definitions (the form above) |
| `tests/mutants/*.yaml` | Mutant definitions ([00 §5](00-concept.md)) |
| `tools/g2_validate.py` | A validator independent of generation, as with G1 |
| `tests/approvals/g2.yaml` | Signed G2 approval record (**outside the commit under approval**) |
| `case_digest` / `mutant_digest` | Digests fixing case and mutant contents (same method as G1’s `obligation_digest`) |
| `g2.complete` | Completion determination, reported in the same form as `g1.complete` |
| `.github/workflows/g2.yml` | `g2-check` / `g2b-approval` |

**The separation rule between author and reviewer is also the same as G1**
(`authored_by` required, `reviewer != authored_by`, signed record, `C..A` change restriction).

### Feasibility spikes (resolve these first in G2)

Areas where discovering “this cannot be done” after implementation would force a redesign.

| # | Target | What to verify |
|---|---|---|
| S1 | ECP + SAML-EC | PAOS/SOAP round trip, generation and inspection of `samlec:GeneratedKey`, five channel-bindings cases |
| S2 | SLO | Front-channel / SOAP, Async SLO extension, session-destruction ordering |
| S3 | MDQ / metadata variants | Path to make the target re-fetch, switching `?variant=`, 301/302/307 |
| S4 | `secondary_peer` | Issuing and registration path for a second entityID (IIP-SP05 / MD01.c / IDP02) |
| S5 | Raw XML generation | DTD-containing messages, unknown attributes, 256-character boundary, handling XML attribute-value normalization |
| S6 | Raw query string | Whether HTTP-Redirect signature verification works on the byte sequence ([02 §3.5](02-architecture.md)) |

**“Quick execution” mode (required for v0.1)**
Skip all tests requiring target-side reconfiguration (`mode: CONFIG`),
and provide an approximately 10-minute preset completed with one metadata registration + one login.
Even with a complete scope, the first-run experience must not take one hour.

> **However, quick-execution results may not be called “conformance.”**
> Skipped obligations remain in the denominator as `NOT_VERIFIED(plan_configuration)`;
> because MUST obligations are included, `conformance = INDETERMINATE` / `completeness = INCOMPLETE` ([03 §7.2](03-test-model.md)).
> The UI must clearly state: “This is an operational check, not a conformance determination.”

## Determination of Phase 1 completion

Phase 1 is complete when all of the following are in place.

1. Every requirement designated as a Phase 1 target in the table in [04](04-requirement-coverage.md) has a test definition and implementation.
2. Requirements classified as externally unverifiable are displayed as such in reports.
3. Execution results for three reference implementations (Keycloak / Shibboleth IdP / SimpleSAMLphp) are public.
4. It starts with a single `docker run`, and the initial test can be completed by following the README.
5. The result JSON schema is frozen as v1, and the process requires a version increase for breaking changes.

## Phase 4 (future) — Security Profile outline

The Phase 1 Test Runner foundation can be reused as-is. Define tests by working backward from attacker capabilities.

```
Attacker capabilities                Derived tests
├─ Obtain a legitimate Assertion     → Assertion replay / Response replay
├─ Modify XML                         → XML Signature Wrapping (XSW1-8)
│                                       Signature removal / Status tampering / signature exclusion
├─ Act as a malicious IdP             → Wrong Issuer / IdP confusion / accept an Assertion from an unregistered IdP
├─ Act as a malicious SP              → Forward an Assertion to another SP (ignore Audience)
├─ Intervene in the metadata path     → Metadata key substitution / ignore validUntil
└─ Act as a man in the middle         → Algorithm downgrade / TLS validation failure

Other: Wrong Audience / Wrong Destination / Expired Assertion / NotBefore in the future /
       Invalid signature / accept unsigned Response / XXE / Billion laughs /
       Comment truncation attack (CVE-2017-11427 family) / NameID normalization differences
```

> For Phase 4, it is **essential to be able to intentionally generate invalid XML that OpenSAML will not accept**.
> This requirement is incorporated into the SAML Engine design in Phase 1’s [02-architecture.md](02-architecture.md).
