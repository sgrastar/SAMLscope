# Licensing build change: G2 reapproval scope

The repository owner authorized applying and validating the proposed build change
and renewing G2 approval on 2026-09-11. This is a reapproval of the existing case
bundle with a packaging/integrity change, not a claim of a new case-by-case design
review or completed third-party copyright clearance.

The protected delta is limited to `build.gradle.kts`: retain original license and
scope text in standalone JARs and source JARs, and reject a runtime dependency
inventory whose JAR names or SHA-256 hashes differ from Gradle's resolved external
artifacts before application resource packaging or checks. A separate task emits
regeneration inputs without needing to create a distribution first.

The signed case definitions, controls, mutants, source catalog, evaluation rules,
profile membership and verification tools remain byte-for-byte unchanged from the
previous G2-approved tree. The existing owner's reviewer/signing identity is used
for the authorized renewal; no reviewer is invented or substituted. The new
per-case timestamps record renewal of unchanged approvals, not new design reviews.

Validation includes the current-inventory success case, a temporary incorrect
hash that must block `:api:processResources`, restoration and inventory regeneration
checks, Gradle tests/assembly and actual ZIP/TAR/JAR notice comparisons. The negative
case failed with the expected stale-inventory message and the input was restored.

The target commit contains this scope record and the licensing implementation.
Its descendant approval commit changes only `tests/approvals/g2.yaml`, binding the
protected artifact digests and unchanged case digests to the new target. Existing
external signer allowlists and pinned verification tools are retained. Completion
is determined by the signed G2 verifier, not by this scope document.

No public push or deployment is part of this approval. Unresolved source permissions
and material allocation remain recorded in `LICENSES/material-review.md`.
