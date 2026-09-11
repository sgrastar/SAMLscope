# Material review and remaining work

This is a progress record, not a claim of complete third-party clearance.
Original grants and exceptions are in `../LICENSING.md`. Source permissions are
retained verbatim or with the extraction transformation stated in the registry.

## Inventory and decisions

| Material/location | Origin, transformation and treatment | Status |
| --- | --- | --- |
| `tests/coverage.yaml`, `tests/cases.yaml`, `tests/predicates.yaml`, `tests/feasibility.yaml`, mutant definitions | Specification-derived summaries, conditions, variants and test instructions; original contributions use CC BY-SA 4.0, incorporated expression retains source terms | Mixed material; per-field allocation remains open. Signed files unchanged |
| `profiles/*.json`, `dev/profile-migration/*`, generated website correspondence | Functional grouping and test mappings are distinct from source membership; catalog hashes and selected notices travel with website JSON | Source membership generated; historical development exports need standalone-notice review |
| `docs/*`, schema descriptions, UI strings and code comments | Original explanations and specification-derived passages coexist; extension or folder alone is not proof of authorship | Original-contribution grant applies only to owned expression; quotation/adaptation audit remains open |
| Original Java/TypeScript implementations and test logic | Implement protocol behavior rather than reproduce specification prose; software grant applies only to original code | Apache-2.0; embedded examples and copied comments remain subject to material review |
| `tools/g1_authoring.py` | Local ignored authoring input containing original clauses; excluded from tracked source and distribution | Do not publish this input; no blanket software-license claim |
| SAML assertion/protocol/metadata XSD sources | Retrieved exact catalog bytes; file contents contain no copyright/license text found by this review | Retain source/version/hash references. Separate schema permission verification remains required; no OASIS document-license inference |
| IETF TXT sources | Adopted bytes match signed source digests. Copyright sections retained, including Internet Society / IETF Trust / authors and disclaimers | RFC2617 document permission retained. RFC4051 historical BCP78 and publication-date IETF Trust terms require supplemental review; code components must not inherit a prose license |
| W3C XML Signature / Encryption 1.1 | Adopted HTML bytes match catalog digests. Copyright paragraph and linked document-use rules retained, including IETF Trust for XML Signature | Historical document and schema/code permission scope remains unresolved; current policies do not override historical terms |
| BetterCrypto | Adopted catalog points to an undated living site; current retrieval failed TLS negotiation | Exact document/file, rights holders and permissions unresolved |
| Kantara Implementation Profile 1.1 | Internet2 and respective contributors retained with CC BY-SA 3.0 US notice; SAMLscope organizes and summarizes requirements | Material allocation / adaptation compatibility review remains open |
| Kantara Deployment Profile 2.0 | Source header says 2.00, 2019-12-09; copyright 2019 respective contributors; CC BY-SA 4.0 | Current repositories mention it as future scope, not an adopted executable catalog. Do not add its terms to every Run; review before importing its text |
| Java dependencies and transitive resources | Original upstream licenses/NOTICE resources stay inside dependency JARs | Actual ZIP-derived notice, Manifest and POM evidence is generated in `web/public/licenses/java-dependencies.json` and available from the app license page; dependency-by-dependency resource/schema audit remains open |
| Browser JavaScript dependencies | Actual bundled modules determine retained package notice texts and chunk banners | Generated during Vite build; missing package notices fail the build |
| Website Archivo font | Copyright and SIL OFL 1.1 retained from installed package | Full text downloadable and displayed |
| `web/public` icon PNGs and website visual assets | Project icon/design files; ownership cannot be established from file type or location | Creation provenance and third-party inputs remain to be verified; no blanket content grant claimed |

## Output paths

| Output | Notice handling and limitation |
| --- | --- |
| `/api/runs/{id}/result.json` | Additive `attribution` metadata includes source membership of selected obligations, notices, explicit missing sources and original-content license text. Measurements remain outside the content grant. Existing saved exports are not rewritten |
| `/api/runs/{id}/report.html` | Selected notices from embedded result metadata; software license and scope also embedded. Legacy inputs use registry fallback. No network needed for notices |
| Online report / application | Footer links to `/licenses`; source registry and browser dependency texts available. No consent modal |
| Website `/data/traceability.json` | Source/text hashes, transformations, used source notices and full original-content license travel in the JSON |
| Website HTML and font/legal downloads | License footer, source anchors and full license text; original website code and published content distinguished |
| Application ZIP/TAR, JAR, container | API distribution already copies LICENSE/LICENSING and LICENSES. Runner embeds attribution resources; Java dependency JAR resources remain intact |
| Source JARs | All module binary/source JARs retain original LICENSE, LICENSING and content-license text; actual artifacts checked. Common build change awaits G2 review |
| Raw YAML / Markdown / fixtures downloaded separately from GitHub | Explicit redistributable copies can now be generated by `dev/licensing/export_material.py` with in-file selected notices and preserved original payload. Raw GitHub downloads remain unwrapped. Protected catalog changes require approval; no claim that a URL alone meets all terms |
| G1/G2/release diagnostic JSON and developer migration JSON/Markdown | Operational counts/status are not automatically CC. Exports containing derived descriptions require remaining per-output handling |
| Protocol XML, metadata, transcripts and database backups | Protocol data and user-owned observations are not automatically CC. Preserve existing redaction and access controls; no private contents enter the public license registry |
| PDF / CSV product exports | No production PDF/CSV export route found in reviewed API/Runner code; do not claim support or clearance for future generators |

## Explicit follow-ups

Complete per-field quotation/adaptation and code-example review before describing
mixed definitions as cleared. Obtain historical IETF/W3C terms and confirm schema
permissions; narrow any request for separate permission to the affected material.
Do not use a file-wide SPDX identifier on mixed or unresolved files.

The registry distinguishes observed source edition/date from signed catalog
metadata. Date/edition corrections remain queued for the independent G1 process;
this work does not alter those approved artifacts. Retaining a notice is a
separate milestone from resolving its application to every copied/adapted field.

Reference checked on 2026-09-11:
https://kantarainitiative.github.io/SAMLprofiles/saml2int.html
