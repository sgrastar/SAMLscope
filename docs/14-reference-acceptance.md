# Reference acceptance matrix

This matrix records actual executions, not advertised product capabilities.
Profile Core/Full and evidence plan Quick/Standard/Full are separate dimensions.
An unexecuted combination is not NOT_APPLICABLE and does not establish a product
failure. Detailed Run provenance and known-invalid historical results are in
[release readiness](13-release-readiness.md).

| Target | IdP Core | IdP Full | SP Core | SP Full |
|---|---|---|---|---|
| Keycloak, pinned local fixture | Partial: browser SSO, repeated protocol Runs, M2/M3 startup, correlation and full registered active-chain execution | Not executed | Not executed | Not executed |
| Shibboleth | Not executed | Not executed | Not executed | Not executed |
| SimpleSAMLphp | Not executed | Not executed | Not executed | Not executed |

Keycloak IdP Core exports remain INDETERMINATE / INCOMPLETE. The fixed-image
encrypted AuthnContext observation is NOT_VERIFIED, not a conformance failure.
Other cells require a supported target role and version-specific fixture; do not
infer support or applicability from this planning table.

## Remaining evidence, in execution order

| Work | Required observation | Current limitation |
|---|---|---|
| Current candidate rerun | Current-image independent Runs verified immediate report refresh and final JSON/HTML agreement | Registered chain and M2/M3 exports reproduced; real-browser and operator campaigns remain |
| Active probe chain | Correlated positive/negative controls and explicit unavailable-response outcomes | Corrected-image chain completed twice with matching outcomes; failure candidates and remaining campaigns require review |
| Conditional features | Configuration or observed protocol evidence for each predicate | Undetermined inputs remain; do not submit blanket answers |
| Metadata campaigns | Actual target import/refresh, changed metadata and subsequent correlated flow | Target refresh setup remains unestablished |
| Browser campaigns and SLO | Requested browser/session transitions with Transcript correlation | Baseline SSO alone does not establish these |
| Full profile and ECP | Authorized fixture, supported endpoints, ephemeral credentials and actual exchanges | No Full-profile reference execution recorded |
| SP target and other products | Separate pinned fixtures and repeatable Run records | Setup and execution outstanding |
| Sample publication | Scrubbed preview, provenance, known-bug review, hosted access tests | No reference sample approved for publication |

## Reproduction record

For each execution, retain the Suite commit, local image ID and registry digest
when applicable, target version/digest, sanitized configuration, profile,
evidence plan, Plan/Run IDs, client type and session-reset method. Export JSON
and standalone HTML, and record unresolved outcome/reason pairs and corresponding
Transcript IDs. Keep raw artifacts out of Git and public CI logs.

Repeat with a new Run and an independent session. Compare obligation outcomes,
case reasons, completeness and coverage; timestamps, identifiers and generated
keys are expected to differ. Investigate unexplained semantic differences before
declaring reproducibility. A repeated incomplete result demonstrates stability
only for the exercised evidence.

Fixture administration APIs may provision targets; their responses do not become
conformance evidence. Record unsupported configuration explicitly and preserve
the evaluator's applicability rules. Reference acceptance supplements the signed
controls and mutants; it does not replace their detection-power checks.
