# Unified profile test start: implementation review and G2 renewal

The owner requested replacing user-facing M1/M2/M3 controls with one profile test
start/resume action, retaining the internal milestone classification. Existing
owner authorization permits implementation, validation and signed G2 renewal.
This record describes renewal of the unchanged case bundle for runtime changes;
it does not assert a new independent case-by-case design review.

The new Run endpoint starts the existing M1 automated and interactive registries,
then M2 and M3, through the pinned profile membership and applicability gates.
An incomplete initial login is rejected before cases are started. ECP's existing
required-outbox-fixtures gate defers M3 and returns an explicit next action. The
UI submits ECP probes, clears the credential form, and resumes profile tests only
after the probe request succeeds. Legacy milestone endpoints remain available.

Integration testing exposed two existing obstacles to this path. Production
QuickCheck now uses ApprovedCaseStarter to avoid starting conditional obligations
before applicability is TRUE. Campaign summaries and evaluator projections exclude the exact known ECP
send fixture IDs: these carry evidence but are not approved evaluative cases.
Unknown case IDs are still rejected; verdict and denominator rules are unchanged.

The G1 catalog, G2 case definitions, controls, mutants, profile memberships and
verification tools are unchanged. Tests cover every released profile, premature
start rejection, resume membership stability, equivalence with the old milestone
entry points, ECP deferral/continuation, ownership and CSRF enforcement, and UI
request/next-action behavior. Website and README instructions use the same labels.

The signed renewal must bind the exact target commit and protected file digests.
Per-case renewal timestamps preserve the existing owner/reviewer identity and
unchanged case digests; they are not new case-design review claims. The approval
commit changes only tests/approvals/g2.yaml. Pinned G1/G2 verification and the
release check determine completion; this document alone is not approval evidence.
