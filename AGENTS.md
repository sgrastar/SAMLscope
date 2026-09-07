# AGENTS.md — Rules for SAMLscope implementation agents

SAMLscope is a tool for determining the conformance of SAML implementations.
**An incorrect determination can unfairly label someone else's product as “non-conforming,”**
so these rules take precedence over merely “making it work.”

See [`docs/README.md`](docs/README.md) for the overall design. When in doubt, read the design documents before implementing.

---

## Absolute requirements

### 1. Do not edit approved G1 artifacts

```
tests/coverage.yaml   tests/specs.yaml   tests/predicates.yaml   tests/approvals/*
```

These are **bound by digest to signed approval records**.
Changing even one byte invalidates the approval (`SR-25c` / `SR-36` / `SR-38` in `tools/g1_validate.py`).

If you want to change a judgment level (MUST / SHOULD / MAY), that is a **change in specification interpretation**;
it requires rerunning G1 (source-text comparison → reapproval), not changing code. **Do not change it unilaterally.**

### 2. Do not manually edit generated artifacts

| Artifact | Generator | Command |
|---|---|---|
| `docs/04-requirement-coverage.md` | `tests/coverage.yaml` | `tools/g1_docgen.py` |
| `build/spec-reconcile-report.json` | validator execution result (**not tracked by Git**; the canonical copy is the CI artifact) | `tools/g1_validate.py` |
| `result.json` examples in documents | `Evaluator` golden fixture | (implemented in M1) |
| Counts in documents (number of obligations, requirements, etc.) | `tests/coverage.yaml` | `tools/g1_docgen.py` |

`tools/g1_docgen.py --check` detects differences in CI.

**Do not hard-code counts in the body text.** Write them with markers such as `<!--g1:obligations-->544<!--/g1-->`,
and have `g1_docgen.py` insert them. When writing a fictional number for explanation, put `<!--g1-literal-->` on the line.
Hard-coded values are detected by **SR-41** in `g1_validate.py` and cause FAIL
(to prevent stale numbers across multiple files when obligations are added).

### 3. Cases do not return Verdict

Case implementations return only **`outcome`** (`satisfied` / `satisfied_with_note` / `violated` /
`indeterminate` / `inconsistent` / `not_verified`).

Conversion to `PASS` / `FAIL` / `WARNING` is performed centrally by **`Evaluator`**, which consults the `level` in `coverage.yaml`
([docs/05 §2.3](docs/05-test-definition-format.md)).

> Violating this causes a **SHOULD obligation to become FAIL**. This has actually happened once
> ([R10 in docs/11](docs/11-review-log.md)). Do not create a case-side type that returns `Verdict`.

### 4. Sending is outbox-only

Cases do not send HTTP directly to the target. They return `OutboundAction`, which Runner executes through the outbox
([docs/05 §4.3](docs/05-test-definition-format.md)).

- `actionId` is **deterministically derived** from `CaseState`.
  Do not use `UUID.randomUUID()` / `System.nanoTime()`.
- Do **not treat unknown delivery (`UNKNOWN_DELIVERY`) as FAIL for the target**.
  Even if replay on retry returns an error, that is uncertainty on the Suite side.
- Cases do not declare whether retry is allowed. Runner decides using the `OutboundKind` allowlist.

### 5. Do not confuse “not applicable” with “could not be verified”

| | Permitted use |
|---|---|
| `NOT_APPLICABLE` | **Role mismatch**, or **the condition of a conditional obligation is false**. These two cases only. |
| `NOT_VERIFIED(reason)` | Every other case of “could not execute.” It remains in the denominator, and if MUST, the Run is incomplete. |

Marking a MUST as `NOT_APPLICABLE` because the environment prevents testing it
**would allow MUST verification to be bypassed simply by choosing a configuration**.

### 6. Do not add conditions or thresholds absent from the source

Do not impose a SAMLscope-specific absolute threshold on requirements with no numeric value in the specification (such as clock skew).
Make operationally useful observations **advisory** (`affects_verdict: false`)
([the Advisory section of docs/04](docs/04-requirement-coverage.md)).

### 7. Do not create cases without controls

If an implementation can satisfy the expected value while failing the obligation, that case has no detection power.
Pair positive / negative controls for every evaluative case ([G2 in docs/01](docs/01-scope-and-roadmap.md)).
For an explicitly non-evaluative MAY/OPTIONAL choice, use an informational fixture plus
`control_waiver_en` and `mutant_waiver`; never fabricate an unreachable `violated` outcome.
If a mutant targets a `one_of` variant group, it must make every member of that group
nonconforming in the same fixture. Mutating only one permitted alternative has no detection power.

**Cover expanded `linked_obligations` as well.** A link with `kind: inherit_variants` means
“also cover the linked obligation's `required_variants`,” and must be expanded **transitively**.
Always use the owning obligation's `role` / `level` / `testability`. Variant applicability normally uses
the owner's condition (`owner_condition`), but when the link explicitly declares
`variant_applicability: linked_condition`, apply the linked obligation's condition **only to the imported variants**.
Do not silently discard or infer this setting.
Coverage does **not** count as coverage of the linked obligation itself (do not double-count).
See [the section on link semantics in docs/03](docs/03-test-model.md) for the complete rule.

### 8. Do not corrupt the raw request

Signature verification for the HTTP-Redirect binding covers the **bytes of the query string before URL decoding**.
Parsing and reconstructing it breaks verification and can falsely report a **correct implementation as “invalid signature.”**
([docs/02 §3.5](docs/02-architecture.md)).

### 9. Do not persist credentials

ECP HTTP Basic credentials exist only in memory for the Run scope.
Do not write them to `CaseState`, outbox payloads, or Transcripts.
Irreversibly remove `Authorization` / `Cookie` **before submitting data to Recorder**
([docs/02 §5.2](docs/02-architecture.md)).

---

## Checks to run for every change

```bash
# Dependencies (first run only)
python3 -m venv .venv
.venv/bin/pip install --require-hashes -r tools/requirements.lock

# Always
.venv/bin/python tools/g1_docgen.py --check        # Confirm generated artifacts match
.venv/bin/python tools/g1_validate.py --structural-only   # Structural rules (no network required)

# When touching tests/ or tools/g1_*
.venv/bin/python tools/g1_validate.py              # Compare against source text and all referenced specifications (network required)

# After approval
G1_TOOLS_COMMIT=<40-digit SHA> PY=.venv/bin/python tools/g1_ci_verify.sh

# During G2 / after G2 approval
.venv/bin/python tools/g2_validate.py
G2_TOOLS_COMMIT=<40-digit SHA> PY=.venv/bin/python tools/g2_ci_verify.sh
```

If `--structural-only` reports a blocking violation, **do not include that change**.

---

## Work order (gates)

```
G1a ✅ Catalog creation
G1b ✅ Review of obligation meaning (source-text comparison and signed approval by someone other than the author)
M0  ✅ Skeleton implementation. 0 verdict cases.
G2  ✅ Test design       ← Signed independent approval verified; preserve its protected boundary.
M1–M4 ✅ Implementation  ← Operational acceptance remains incomplete; see docs/13-release-readiness.md.
```

**Do not begin M1 or later before G2.**
In the past, 41 of 49 source-text comparisons contained errors;
the most likely failure is “the obligations are correct, but the cases have no detection power.”

## Implementation stack

| Layer | Choice |
|---|---|
| Language | Java 21 |
| Web | Javalin + Jetty (raw request access is required) |
| SAML | OpenSAML 5.x (normal paths) + raw DOM/StAX (abnormal paths; foundation for Phase 4) |
| XML Security | Apache Santuario |
| DB | SQLite (Transcript is a file; DB contains references only) |
| Frontend | React + Vite. `report.html` is a static build of the same application. |
| Build | Gradle (Kotlin DSL) |

Follow the code structure in [`docs/02-architecture.md`](docs/02-architecture.md).
In particular, do not mix **`peer/` (for tests; relaxed validation)** with **`auth/` (for administration; strict validation)**
([docs/09 D-09](docs/09-open-decisions.md)).

## Reading order when in doubt

1. [`docs/03-test-model.md`](docs/03-test-model.md) — Verdict vocabulary, aggregation rules, and common evaluation procedure
2. [`docs/05-test-definition-format.md`](docs/05-test-definition-format.md) — Test definitions and implementation interfaces
3. [`docs/02-architecture.md`](docs/02-architecture.md) — Test Peer design, ECP, and Transcript
4. [`docs/11-review-log.md`](docs/11-review-log.md) — **What has been done wrong before**, to avoid repeating the same mistakes
