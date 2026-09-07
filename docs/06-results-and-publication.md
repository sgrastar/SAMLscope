# 06. Result Format and Publication

The agreed next-stage product summary and badge presentation is specified in
[20 — Functional profiles and public summaries](20-profiles-and-public-summaries.md).
It does not replace the current result schema, trust model or Evaluator rules.

## 1. Result JSON (Schema v1)

The Suite’s longest-lived artifact. Increment the version for breaking changes.

> ⚠ **The following describes the structure; its values will be replaced by generated artifacts.**
> The previous review pointed out that the hand-written example formerly placed here
> **contradicted its own determination rules**
> (`CONFORMANT_WITH_WARNINGS` despite unresolved MUSTs,
> SP-only obligations listed in an IdP Run, and a duplicated `not_observable` key).
>
> In accordance with the decision in [03 §7.5](03-test-model.md), examples in the
> documentation are **generated from `Evaluator` output as a golden fixture** and
> validated against the JSON Schema (`schema/result-v1.json`) and in CI
> (rules 23–25 in [05 §5](05-test-definition-format.md)).
> Until the switch to generation, this section contains **structure only**, with no consistent numeric values.

### 1.1 Top-Level Structure

```jsonc
{
  "schema_version": "1",

  "run": { "id", "started_at", "finished_at",
           "conformance",           // CONFORMANT | CONFORMANT_WITH_WARNINGS
                                    // | CONFORMANT_WITH_DECLARED_EXCLUSIONS
                                    // | NON_CONFORMANT | INDETERMINATE
           "completeness",          // COMPLETE | INCOMPLETE
           "scope_qualifications" },// Machine-readable record of declaration-only exclusions ([03 §1])
  //  ★ These are separate axes. Displaying only one is prohibited ([03 §7.2]).
  //  ★ Always calculated by Evaluator.evaluate(); do not enter manually.

  "suite":   { "name", "version", "image_digest", "execution_mode" },

  "evaluation_bundle": {              // ★ Canonical source for determinations (review finding 10)
    "digest": "sha256:…",             //   Composite digest including everything below
    "components": {
      "coverage_yaml":        "sha256:…",   // Canonical source for obligations, levels, and conditions
      "test_definitions":     "sha256:…",   // defs/*.yaml
      "specs_yaml":           "sha256:…",   // Specification catalog (including external draft versions)
      "outcome_mapping_version": "1",       // outcome × level → Verdict rules
      "aggregation_policy_version": "1"     // Severity ordering and Run determination rules
    }
  },

  "profile": { "id", "spec": { "document", "version", "date" },
               "level_definition_note" },

  "target":  { "declared_product", "declared_by", "verified": false,
               "entity_id", "metadata_digest", "role",
               "kind" },            // idp | sp | token_translation_proxy ★
  //  role ∈ idp | sp   ★ Every obligation appearing in this Run must apply to this role.

  "configuration": { "suite_metadata_delivery", "reachability",
                     "declared_features", "parameters" },

  "applicability": [                  // ★ The Evaluator’s input itself ([03 §6.2])
    { "obligation": "IIP-SP15.a",
      "predicate": "supports_single_logout",
      "predicate_kind": "CAPABILITY_BASED",   // CLAIM_BASED | CAPABILITY_BASED | CLASSIFICATION_BASED
      "declared": true,                        // User-declared value (null = not declared)
      "observed": true,                        // Value derived from observation (null = no evidence)
      "effective_result": "TRUE",              // TRUE | FALSE | UNKNOWN  ← Whether the case can execute
      "conflict": false,                       // ★ Independent of effective_result; true means INCONSISTENT
      "basis": "observed",                     // declared | observed | declaration_only_exclusion
      "evidence": [ { "kind": "metadata", "xpath": "…" } ] }
  ],

  "advisories": [                     // ★ Observations without a basis in the source text; do not affect determinations
    { "code", "obligation", "severity", "message_en", "affects_verdict": false }
  ],

  "suite_incidents": [                // ★ Suite-side incidents; separate from the target evaluation
    { "kind": "UNKNOWN_DELIVERY", "case": "IIP-IDP13-02",
      "action_id": "…", "note": "Could not determine whether delivery occurred" }
  ],

  "summary":  { "requirements": {…}, "obligations": {…}, "cases": {…} },
  "coverage": { … },                  // Must conform to the definition in [03 §7.4]

  "requirements": [ { "id", "verdict", "spec_url",
                      "obligations": [ { "key", "level", "role", "verdict" } ],
                      "cases": [ { "id", "obligation", "outcome", "verdict",
                                   "mode", "reason_code", "reason",
                                   "attested", "evidence", "definition_url" } ] } ],

  "unresolved":     [ { "obligation", "level", "verdict", "reason", "how_to_resolve" } ],
  "not_observable": [ { "obligation", "level", "reason" } ],   // ★ The key appears only once

  "conformance_statement": "…"        // Standard text that the UI must display verbatim
}
```

### 1.2 Invariants Enforced by the Schema

Validate with both the JSON Schema and `ResultInvariantTest`.

| # | Invariant |
|---|---|
| 1 | `run.conformance` / `run.completeness` matches `Evaluator` output ([03 §7.2](03-test-model.md)) |
| 2 | If `coverage.must_unresolved > 0`, then `run.conformance ∈ {INDETERMINATE, NON_CONFORMANT}` |
| 3 | If `summary.obligations.fail > 0`, then `run.conformance = NON_CONFORMANT` |
| 3b | If the selected profile contains an unresolved obligation, `run.completeness = INCOMPLETE` (regardless of level) |
| 4 | **Every `requirements[].obligations[].role` matches `target.role`** (SP-only obligations do not appear in an IdP Run) |
| 5 | `coverage.verified_ratio = must_resolved / must_observable`（[03 §7.4](03-test-model.md)） |
| 6 | `not_observable` / `unresolved` always exist, even when empty, and **keys are not duplicated** |
| 7 | Every element of `unresolved` has `how_to_resolve` |
| 8 | A MUST obligation declared unsupported in `declared_features` is not `NOT_SUPPORTED` (it should be FAIL) |
| 8b | A case with `reason_code: capability_absent` has `outcome` `violated`, and the obligation verdict corresponds to `obligation.level` (MUST→FAIL / SHOULD→WARNING / MAY→NOT_SUPPORTED). **A SHOULD obligation is not FAIL**. [03 §4](03-test-model.md) |
| 9 | Every conditional obligation is recorded in `applicability`. `effective_result` ∈ `{TRUE, FALSE, UNKNOWN}`, and `conflict` is an independent boolean. **There is no `CONFLICT` value** (retired). |
| 9b | For an obligation with `applicability[].conflict = true`, `INCONSISTENT` is **injected** into the aggregation input (regardless of `effective_result`). ★ The final verdict is **not necessarily** `INCONSISTENT` — if the same obligation has a `FAIL` case, `FAIL` is correct under severity ordering ([03 §6.1](03-test-model.md)). Verify that verdict severity is **at least** `INCONSISTENT`. |
| 9d | The count of `basis = "declaration_only_exclusion"` matches `coverage.excluded_by_declaration`, is stated in `conformance_statement`, and is recorded in `run.scope_qualifications[]` with `reason` / `attested_by` / `attested_at`. |
| 9e | For an item with `predicate_kind ∈ {CAPABILITY_BASED, CLASSIFICATION_BASED}`, `observed = null`, and `declared = false`, `effective_result` is not `FALSE` (except for `declaration_only_exclusion`). |
| 9f | ★ If `coverage.excluded_by_declaration > 0`, then `run.conformance ∉ {CONFORMANT, CONFORMANT_WITH_WARNINGS}` (it is at least `CONFORMANT_WITH_DECLARED_EXCLUSIONS`). |
| 9g | Every `advisories[].affects_verdict` is `false`. Recalculated `run.conformance` / `run.completeness` / `coverage`, excluding advisories, matches the result. |
| 9c | ★ For the **CaseRun** in which `UNKNOWN_DELIVERY` occurred, `outcome` is not `violated` and `verdict` is not `FAIL`. **This does not exclude the entire obligation** (if another case for the same obligation clearly proves a violation, the obligation is correctly `FAIL` under the aggregation rules). |
| 10 | `evaluation_bundle.digest` can be deterministically recalculated from `components` |

### 1.3 Design Points

 - Keep summaries at **three granularities**: `requirements` / `obligations` / `cases`.
  Because determination levels apply at the obligation level, `obligations` is the effective denominator.
 - `coverage` is mandatory. **Display it at the same prominence as the conformance label** ([03 §7.4](03-test-model.md)).
 - Always emit `unresolved` / `not_observable`, **even when empty**. Do not create a way to hide them.
 - `conformance_statement` is text that the UI, publication page, and `report.html` **must display verbatim**.
  **Generate this from the golden fixture as well** (do not include hand-written examples).
 - `suite_incidents` records Suite incidents. **Do not mix them into the target evaluation**
  ([05 §4.3.1](05-test-definition-format.md)).
 - `target.verified: false` embeds in the structure that the product name is self-declared.
 - **`evaluation_bundle.digest` is essential to reproducibility**. The Suite version alone is insufficient.
  Because determinations derive from `coverage.yaml` level / condition, changing the catalog can change the conclusion even with identical code.
  Because obligations may reference external drafts (such as SAML-EC), `specs_yaml` includes
  **the version of the referenced specification** ([02 §3.7](02-architecture.md)).

## 2. Output Formats

| Format | Use |
|---|---|
| `result.json` | Machine-readable; for CI and archiving. **This is authoritative**: the `Evaluator` output itself. |
| `report.html` | Self-contained single-file HTML (embedded images and CSS); distributable offline. |
| `transcript.zip` | Raw data for all HTTP / SAML messages; for debugging. |
| Badge SVG | Format `Tested: IIP v1.1 IdP Core — 41/45`; Phase 2. |

## 3. Result Sharing and the Trust Model ★ The Major Gap in the Original Memo

The original memo states that “after a Test Run finishes, a shareable URL can be issued; it is private by default,”
but allowing the results of a tool that anyone can run self-hosted to become a public URL directly
would make the results easy to forge. One could simply hand-write JSON saying “PASS 74 / FAIL 0.”

The value of this Suite is that “the reproducible test result itself serves as evidence of quality,”
so **forgeability is fundamental to the design**.

### Explicitly Distinguish Three Trust Levels

```
┌──────────────────────────────────────────────────────────────┐
│ Level 0 — LOCAL                                              │
│   Results of execution in a self-hosted environment; exist only as local files │
│   → JSON / HTML can be exported                                              │
│   → The file itself states that it is “self-declared”                         │
├──────────────────────────────────────────────────────────────┤
│ Level 1 — ATTESTED UPLOAD   ❌ Not adopted                                    │
│   Upload self-hosted results to the Hosted version and turn them into a URL   │
│   → Forged JSON could be uploaded, causing even Level 2 results               │
│      to be viewed as “probably self-declared”; therefore it is not adopted    │
├──────────────────────────────────────────────────────────────┤
│ Level 2 — HOSTED RUN                                         │
│   Results executed on the official Hosted version                            │
│   → The Suite retains the execution process (Transcript)                     │
│   → Only these may be displayed as “verified execution”                      │
└──────────────────────────────────────────────────────────────┘
```

**Decision ([09 D-04](09-open-decisions.md)): implement only Level 0 and Level 2.**
Level 1 is not adopted because forged uploads cannot be distinguished.

Implications:
- Self-hosted users cannot turn results into shareable URLs. They distribute `report.html` (a self-contained file) themselves.
- **Those who want to test an internal IdP cannot use a shareable URL**. State this asymmetry explicitly in the README.
- Operating the Hosted version is included in the Phase 1 deliverables ([09 D-15](09-open-decisions.md)).

### Publication Page Display

> ⚠ **The numeric example formerly placed here has been removed.**
> The review identified the contradiction of displaying `CONFORMANT` with
> `Resolved 45 / 47` and `NOT_VERIFIED 2` (`conformance = INDETERMINATE` is correct
> because there are two unresolved MUSTs).
> **Hand-written examples have produced inconsistencies four times in a row.**
> The publication-page display example is also generated from the `Evaluator` golden fixture.

Items the publication page **must always include** (requirements for items, not values):

| Item | Requirement |
|---|---|
| `Conformance` | Display `run.conformance` verbatim. **Always show it together with `Completeness`** ([03 §7.2](03-test-model.md)). |
| `Completeness` | `run.completeness` and the unresolved count. |
| `Resolved` | Display `must_resolved / must_observable` **as a fraction**; do not show only the ratio. |
| Not verified / not observable | Always display the counts of `NOT_VERIFIED` and `NOT_OBSERVABLE`. |
| Declaration-only exclusions | If `excluded_by_declaration > 0`, place the count, reason, and statement that it is “not verified” **prominently**. |
| `conformance_statement` | Display the full text verbatim. |
| Product name | Append `(self-declared)`. |
| Standard text | `This is a test result, not a certification.` |
| Configuration | `declared_features` / `parameters` / `suite_metadata_delivery` / `reachability`. |
| Version | Suite version and `evaluation_bundle.digest`. |

### Terminology Rules (Frozen in Phase 1)

**Permitted terms**
- `Tested against SAML V2.0 Implementation Profile for Federation Interoperability v1.1`
- `Conformance Test Result`
- `Test Report`

**Prohibited terms**
- `Certified` / `Certification`
- `Compliant` / `Compliance` (permitted as a summary of test results, but not as a title)
- `Approved` / `Endorsed` / `Validated by <organization name>`
- Using the names Kantara / OASIS **as though they were certifying bodies**

These rules must be stated permanently in the README and the publication-page footer.

## 4. Items Prohibited in Published Results

Scrub automatically at `publish` time.

| Item | Handling |
|---|---|
| Full Transcript | **Private by default**. Retained internally only by the Hosted version; may be published opt-in. |
| Target IP addresses / internal hostnames | Mask. |
| Test-user IDs / passwords (IIP-IDP14 ECP credentials) | **Never store**. Keep in memory only during execution. |
| Cookie / Authorization headers | ★ **Irreversibly removed before insertion into the Transcript, not at publication time** ([02 §5.2](02-architecture.md)). Masking here is a second safety net. |
| Attribute values in Assertions | Mask by default. Real-user attributes from a real IdP may be present. |
| `test_user_hint` in the `Test Plan` | Do not publish. |

> When testing with a real IdP, **real users’ names and email addresses can enter Assertions**.
> Accidentally publishing these is the most likely incident. Prevent it with default masking and a pre-publication preview.
>
> **Do not rely on this table for credentials.** Publication-time scrubbing can leave them,
> even for private Runs, in `/data` or backups in plaintext-equivalent form (Base64).
> Remove `Authorization` / `Cookie` / password-equivalent form values
> **before insertion into the Recorder** ([02 §5.2](02-architecture.md)).

## 5. Retention Periods (Hosted Version)

| Data | Default retention |
|---|---|
| Private Run | 30 days |
| Results of a published Run | Indefinitely (the user may delete them) |
| Transcript of a published Run | 90 days |
| Deletion request | The owner can delete it through the secret URL issued at publication. |
