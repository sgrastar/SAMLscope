# Phase 2 preparation

Status: scope draft, not an approved specification interpretation or authorization
to implement new verdict cases. Phase 1 acceptance remains open.

## Proposed work packages

| Package | Specification/design deliverable | Acceptance boundary |
|---|---|---|
| Artifact binding | Version-pinned Core/Bindings/Profiles sources; role-specific obligations for resolution, correlation and failure handling | Independently approved catalog and controls before evaluative implementation |
| Attribute and authorization queries | Supported query/response types, roles, conditional applicability and evidence model | Positive/negative controls, malformed and unavailable-response distinctions |
| Browser automation | Adapter for existing user-browser operations, session isolation and fresh-session proof | Same outcomes as equivalent manual flows; unavailable automation remains NOT_VERIFIED |
| CI integration | Stable result contract, exit policy for conformance versus incomplete execution, private artifact handling | Repeatable pinned fixtures without credential persistence |
| Badges | Profile/version, evidence depth and completeness representation, provenance and revocation | No certification implication or misleading success for incomplete Runs |

Artifact and query work expands conformance scope. Browser automation, CI and
badges are execution or presentation work and must not silently redefine existing
approved levels, variants or applicability.

## Entry and review sequence

Close or explicitly disposition Phase 1 acceptance findings first, including the
database reliability issue and hosted retention/deletion gaps. Record the release
baseline and compatible result format. Then inventory exact source clauses and
open interpretation questions for each proposed package, without modifying the
current signed catalog in place.

For new obligations, use the G1 source-comparison and independent signed-review
process, followed by G2 controls, mutants and feasibility approval. Specify
outbox/retry behavior, raw binding bytes, encryption visibility and credential
lifetime before implementation. Do not reuse Phase 1 approval as approval for a
new specification interpretation.

Decisions still required include the first protocol package, supported query
variants, browser-runtime deployment constraints and the CI result compatibility
policy. This draft deliberately assigns no new MUST/SHOULD levels or target
capabilities. Resolve these from source and review evidence at the Phase 2 gate.
