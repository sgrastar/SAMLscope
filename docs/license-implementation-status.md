# License implementation status

Latest update: the owner authorized the additional Gradle inventory guard and G2
renewal on 2026-09-11. The guard is now applied; positive and negative checks pass.
Earlier references below to rejection/pending authorization describe the earlier
audit state. See `docs/license-g2-reapproval.md` for the actual renewal scope.


Checked locally on 2026-09-11. This work implements distribution and display
mechanisms; it does not claim complete material-level copyright clearance.

| Target | Implementation | Verification | Remaining work |
| --- | --- | --- | --- |
| Repository policy | Original software Apache-2.0; owned original prose/definition contributions CC BY-SA 4.0; third-party exceptions explicit; contribution guide added | Main README and website About no longer present a whole-project Apache label | Individual mixed-content allocation and asset provenance |
| Source registry | Additional adopted IETF/W3C notice text, source/text hashes and supplemental-review status | Newly retrieved source bytes matched approved catalog digests; notice hashes checked | Historical supplemental permissions, BetterCrypto and SAML XSD permission scope |
| Result JSON | Optional `attribution` metadata with selected source notices, original-content license text and explicit unmapped/missing sources | Evaluator golden regenerated; schema validation, Runner/API tests and non-disclosure/selection tests pass | Existing saved results unchanged; mixed-content legal review |
| Offline HTML | Displays selected notices as readable paragraphs; original software license and scope embedded; legacy fallback retained | Generated fixture opened in browser; Internet2 notice and original terms visible without fetching them | No legal-clearance claim for pending sources |
| Application UI | Content-license details and previously omitted unresolved-source list; short prose rather than internal status codes | Browser inspection and UI tests pass; no consent modal added | Case drawer, focused case, plan profile and requirement details now link to contextual notices; broader material permission review remains open |
| Website | Original-content grant, full license download, source terms and generated JSON | Build, browser inspection, generator check and download-content comparison pass | Public deployment not performed |
| Distribution | JVM integrity checks, all module binary/source JARs retain original license/scope, runtime dependency notice inventory downloadable in the app | ZIP/TAR, nested API/Runner resources and all twelve binary/source JARs compared with current files; dependency inventory regeneration matches | Docker daemon unavailable; dependency resource permissions remain under review |
| Standalone material exports | YAML comments, JSON envelope and Markdown appendix preserve original payload and selected source notices | Format/byte preservation, attribution selection and markup isolation tests pass; public catalog/profile/document examples generated | Raw GitHub downloads and older developer generators are not automatically wrapped; unmarked quotations still require review |
| Approval gates | Signed catalogs, approval records and evaluation semantics unchanged; common JAR packaging configuration changed | Current G1 structural: 46/46 PASS. Current G2: 20/21 PASS; sole blocker is `build.gradle.kts` differing from signed approval commit | Independent G2 review/reapproval of the common build change required. Catalog edition/date corrections still require G1 approval |

The previous local signature failures came from a missing temporary allowlist.
Verification used the existing GitHub repository G1/G2 signer variables through
per-command configuration; no approval record, key authorization or repository
Git configuration was rewritten.

Independent licensing scripts are in `dev/licensing/`, outside the G1 validator's
protected Python import directory. They do not suppress G1's shadow-import rule.
The container check uses JVM hashing because the existing production build does
not include Python tooling. The Dockerfile is unchanged. The common `build.gradle.kts` JAR packaging change is G2-protected and intentionally remains pending independent review/reapproval; no signature was replaced. The earlier full pinned G1/G2 passes predate this packaging change and are not presented as approval of the current tree.

The result schema now accepts optional attribution metadata. It also documents
already-emitted evidence-summary/evidence-class fields and functional-profile
identifiers, which the old schema rejected. The evaluator and generated assessment
values are unchanged. Consumers validating new exports must use the updated schema;
existing exports remain accepted by it.

Reproduction commands and the generated UI fixture location are in
`dev/licensing/README.md`. Archive inspection emits
`build/license-distribution-report.json`. The material/output inventory and
explicit unfinished boundaries are in `LICENSES/material-review.md`.

No commit, push or public deployment was performed by this task.

## Latest continuation evidence

`assemble :runner:test :web:check :api:distZip :api:distTar` passed.
The licensing helper tests pass (four tests). The dependency inventory is derived
from actual distribution JAR bytes, including embedded notice files, unfolded
manifest declarations and POM license declarations. There are 102 dependency JARs
and 228 embedded XSD resources; 18 JARs have none of those notice/declaration
evidence forms. That is an investigation queue, not a finding of infringement.
The index explicitly leaves resource-level permission review open.

The historical-terms investigation is recorded in
`LICENSES/historical-term-review.md`; retrieved policies have not been used to
relicense catalog expressions or schemas.

## Implementation omission audit — 2026-09-11 continuation

- Added context links from case drawers, focused case views, plan profiles and
  requirement details to the matching source notices, with an all-notices link.
  No new consent step or modal was added. Public membership is generated from
  the same catalog/index as result attribution.
- Fixed source extraction for numbered obligation suffixes such as `IIP-MD05.a1`.
  The old expression truncated these keys and could omit sources from case and
  transitive-link attribution. All current obligation and case identifiers match
  the corrected extraction; all profile exports are checked against membership.
- Profile exports now resolve case identifiers and non-executable obligation
  references, without expanding unrelated sibling obligations by prefix.
- Website generation now consumes and checks the shared material index instead
  of independently selecting a smaller set of references. Actual website rows
  are compared against that index by the distribution verifier.
- The explicit distribution verifier now compares its Java inventory against
  actual dependency JAR contents, rather than only comparing copied JSON files.

The proposed automatic Java inventory check in the standard Gradle build was
**not applied**: automatic approval review rejected editing the G2-protected
common build configuration without authorization for that specific change.
The concrete patch and validation plan are in
`build/proposed-license-inventory-guard.patch` and
`build/proposed-license-inventory-guard-review.md`. The current root build diff
still contains only the earlier JAR license packaging change. G2 remains blocked
on that earlier diff, not on an applied inventory guard.

Protected developer migration generators and raw GitHub file downloads remain
unwrapped. The standalone exporter covers explicit redistributable copies; it
does not silently modify signed candidate schemas or approval inputs.

Audit validation: Runner 378 tests and web 67 tests pass; six licensing helper
tests pass. Application assembly/ZIP/TAR, website build/export check, standalone
JAR notice comparison, shared website source membership and G1 structural checks
pass. Current G2 is 20/21 with the previously documented root-build blocker.
