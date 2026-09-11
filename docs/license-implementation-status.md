> Superseded license-material decisions: see [the current publication audit](../LICENSES/publication-audit.md). This file retains the previous implementation and gate-validation record.

# License implementation status

Checked locally on 2026-09-11. Implementation and G2 renewal are complete for the
changes below; material-level copyright clearance is explicitly not complete.

| Target | Implementation | Verification | Remaining work |
| --- | --- | --- | --- |
| Repository policy | Original software Apache-2.0; owned original prose/definitions CC BY-SA 4.0; third-party exceptions and contribution terms explicit | README, scope and retained texts checked | Per-field quotations/adaptations and asset provenance |
| Source registry/index | Source notices and hashes; case/profile/obligation membership; numbered suffixes and transitive references | Regeneration matches; every current case/obligation ID recognized | Historical supplemental terms, BetterCrypto and SAML XSD permissions |
| Result JSON / offline HTML | Selected notices and full original-content license; readable offline display; measurements not assigned CC | Runner/API tests, golden/schema and prior browser inspection | Existing saved results are not rewritten; material allocation remains open |
| Application UI | Case drawer, focused case, plan profile and requirement details link to contextual source notices | Web tests pass; no new consent step/modal | Individual resource permission review |
| Website | Shared source index, source notices, original-content license and downloadable catalog | Export regeneration, build and row/index/download comparison pass | Public deployment not performed |
| Standalone YAML/JSON/Markdown | In-file selected notices and exact original payload retained by explicit exporter | All profile selections and numbered references tested; actual examples generated | Raw GitHub downloads and protected historical migration generators remain unwrapped |
| Distribution | All binary/source JARs retain scope/license; Java inventory checked against resolved external JAR names/hashes before application packaging/checks | Full Gradle check/assembly; ZIP/TAR and all module JARs compared; corrupted inventory correctly blocks processResources and was restored | Docker daemon unavailable; embedded dependency resources are not legally cleared by package notices |
| Approval gates | Owner-authorized build change recorded in a target commit and separate signed G2 renewal | G1 structural 46/46; externally pinned G1 64/64; G2 and externally pinned G2 21/21 pass | Separate catalog edition/date corrections still require G1 review |

## Approval and validation evidence

- Target: `f66384ce371eb363bbf51915d31b6361c551afd9`.
- Signed G2 renewal: `7f60b7b695450ddfbdc8595fb02c8322272d678a`.
- The only changed G2-protected implementation artifact is `build.gradle.kts`.
  Case definitions, controls, mutants, source catalog, profiles and evaluation
  semantics were compared with the previous approved digests and are unchanged.
- The owner explicitly authorized applying/testing the guard and renewing G2.
  The existing configured signing identity was used. No signer allowlist, key
  authorization or validation rule was rewritten. Scope is recorded in
  `docs/license-g2-reapproval.md`; per-case timestamps record renewal of existing
  unchanged approvals, not a new case-design review.
- Java tests: core 178, SAML 53, store 33, Runner 378, peer 9, API 82; all pass.
  Web tests: 67 pass. Licensing helper tests: six pass.
- `build/license-guard-negative.log` records the expected stale-inventory failure.
  `build/license-distribution-report.json` records actual artifact comparisons.
  Reproduction commands are in `dev/licensing/README.md`.

The Java inventory retains observed notices, Manifest and POM declarations from
102 runtime dependency JARs. Resource review remains pending for 228 embedded XSDs;
18 JARs lack these embedded notice/declaration evidence forms. This is an
investigation queue, not a finding of infringement. Historical research and
unfinished boundaries are in `LICENSES/historical-term-review.md` and
`LICENSES/material-review.md`.

Local commits were created to satisfy the authorized signed G2 workflow. No push
or public deployment was performed. Website edits remain local to its repository.
