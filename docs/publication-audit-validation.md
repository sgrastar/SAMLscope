> Initial audit validation snapshot. Subsequent publication-review changes and G2 renewal are recorded in [license-publication-review.md](license-publication-review.md).

# Publication audit validation — 2026-09-11

This records local verification of the changes described in
[the license publication audit](../LICENSES/publication-audit.md).
It is not a G1/G2 approval record or operational acceptance sign-off.

| Check | Result |
| --- | --- |
| `./gradlew check assemble :api:distZip :api:distTar` with Java 21 | PASS; all module checks and final archive build completed |
| Java test result XML | 733 tests, zero failures/errors across core, saml, store, runner, peer and api |
| Browser tests | 68 passed; includes lazy Java license/source-link display and escaped text |
| Licensing Python helper tests | 7 passed; includes rejecting changed JAR bytes with old permission evidence |
| G1 generated documentation | `g1_docgen.py --check` PASS |
| G1 structural validator | 46/46 PASS |
| G1 externally pinned verification | 64/64 PASS; existing approval signature verified |
| G2 validator and externally pinned verification | 21/21 PASS; existing signed approval verified; no protected input or approval edited |
| Material index / notice hashes | `materials.py --check` PASS |
| Publication register | `publication_audit.py --check` PASS |
| Actual ZIP/TAR, own binary/source JARs and dependency JARs | `verify_distribution.py --website ../SAMLscope-website` PASS; byte comparisons cover current retained files, nested resources and dependency inventory |
| Standalone exports | YAML/JSON/Markdown regenerated via `export_material.py`; original signed files unchanged |
| Result JSON / offline HTML | Runner tests produced `runner/build/license-qa/result.json` and `report.html`; canonical golden updated through the existing test-generation mechanism |
| Website | Traceability generator/check and `npm run build` PASS; built license page, catalog and legal downloads matched |
| Application page | Loaded final local static build in the in-app browser; scope sections, source links and collapsed license details visible without a consent modal |
| Whitespace | `git diff --check` passed in both repositories (website reports existing LF/CRLF normalization warnings) |
| Container | Not verified. Docker daemon unavailable; installed Desktop application could not launch (`kLSNoExecutableErr`). Image publication excluded from the license release decision pending actual final-layer/base-license/source-availability verification |

Commands used immutable validator pins already configured for this repository:
G1 `d3dfc41c0195ce8fbc61e7d569010289f90b4cdc`,
G2 `9e1afc740f61fa253458f5ec61fdc6ea1a33dd93`.
The signed approvals themselves were not rewritten or reissued.

Detailed local logs are under `build/publication-audit/` and
`build/license-distribution-report.json`. The registered decision totals are generated in
`LICENSES/publication-register.json`; do not copy its totals into other source files as a
second maintained authority. No external inquiry, push, deploy or publication was performed.
