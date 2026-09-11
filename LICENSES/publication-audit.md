# SAMLscope publication license audit — 2026-09-11

## Decision

**Publication permitted for the revised repository, static website, application, JAR/source JAR, ZIP/TAR, licensed exports and offline reports, subject to the retained-notice and corresponding-source conditions below.**

This is a decision about the currently reviewed materials and retained conditions, not an approval
of product conformance or operational release readiness. Keep the YELLOW notices with the outputs.
No source text, dependency resource or measurement is assigned a new blanket license.
The complete requested table and counts are in [publication-register.md](publication-register.md).
Counts are by source ID / package version / named original-material group; the embedded XSD list is
subordinate evidence and is not counted a second time.

**Container publication is conditional on the runtime-source gate.** The initial local audit
could not inspect a running container. The publication review subsequently retrieved and
hash-verified the pinned linux/amd64 base layers, publisher SBOM and build provenance.
It identified the exact OS source-package versions and JRE release, retained their full source
archives, patches and build scripts, and added actual-image inventory/legal-file and public
source-download checks before image publication. See [container-publication.md](container-publication.md)
and `container-source-manifest.json`. PR CI must pass this gate before merging to the publishing
branch. Other architectures and future base/package versions require new evidence.

## Actual-use rationale

A = reference only; B = independently expressed implementation/description; C = reproduced or
adapted expression; D = third-party file distribution. Copyright/license notices retained as
legal evidence are distinguished from the substantive technical prose of a source document.

- **Kantara Implementation Profile 1.1: C / YELLOW.** Summaries and the source-comparison basis in
  `tests/coverage.yaml`, case instructions, profile mappings and generated correspondence incorporate
  source expression. The adopted [original](https://kantarainitiative.github.io/SAMLprofiles/fedinterop.html)
  credits Internet2 and respective contributors, not Kantara alone. The registry now retains the
  named contributor list and SAMLscope modification credit. Original text stays CC BY-SA 3.0 US;
  [section 4(b)](https://creativecommons.org/licenses/by-sa/3.0/us/legalcode.en) allows the adaptation's
  later same-elements license, CC BY-SA 4.0. Preserve title, authors, URL, license and change attribution.
- **The OASIS source entries in the register: C / YELLOW.** Source-specific notice text, page,
  adopted edition and SHA-256 remain in `source-notices.json`. These individual notices permit
  copies/translations and explanatory or implementation-assistance derivatives with their notices.
  For example, the adopted [SAML 2.0 Core OS](https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf)
  Appendix B supplies the grant. These are document-specific grants, not CC and not a current
  generic OASIS-policy substitution. SAMLscope's requirement/test/evidence descriptions serve
  implementation assistance; originals and specifications are not modified or represented as official.
- **MDQ, SAML-MDQ: A/B / GREEN.** Catalog entries/locators and IIP-MD01's independently organized
  protocol behavior are references. Its source-expression basis is the Kantara requirement, already
  covered above. No draft body or copied ABNF is distributed by the project.
- **SAML-EC: A/B / GREEN.** IIP-IDP15.a and its section 5.3.1 locator describe the channel-binding
  field/behavior. Protocol element names and the independently constructed test are not a draft
  translation. The similarly named schema inside OpenSAML is separately counted under D.
- **RFC2617 / RFC4051 / RFC7457: A/B / GREEN.** Names, algorithm identifiers, technical behavior
  and bibliography are used. IIP-ALG07.a refers readers to TLS guidance; it does not reproduce that
  RFC's discussion. No RFC prose/ABNF example is incorporated as a project file. Historical IETF
  notice extracts remain evidence; failure to retrieve TLP 4 is not a current publication blocker
  because the relevant document body/code is not being distributed. New imports need a fresh review.
- **XMLSig / XMLEnc: A/B / GREEN for these document references.** Algorithm/element names,
  source locators and original verification code do not copy the 2013 document body. The
  EncryptedAssertion applicability explanation is supported by retained OASIS Core source evidence.
  W3C schemas in dependencies have separate file-specific software terms below; the W3C document
  license is not substituted for a software license.
- **BetterCrypto: A / GREEN.** Living-site bibliographic link only; no corresponding executable
  catalog text import. An unavailable page is not a permission blocker for that reference.
- **SAML2-xsd, SAML2MD-xsd, SAML2P-xsd: A/B / GREEN for catalog usage.** Element/type/attribute
  names and schema selectors express protocol structure. The official source bytes are validation
  caches, not tracked independent XSD distribution. No inference is made that an OASIS PDF license
  necessarily licenses every standalone XSD. Dependencies are a different distribution boundary.
- **Deployment Profile 2.00: A / GREEN.** Future-scope/reference only. Its
  [original CC BY-SA 4.0 notice](https://kantarainitiative.github.io/SAMLprofiles/saml2int.html) is not
  copied into every result because its text is not an adopted executable source.
- **Own implementation/fixtures: B / GREEN.** Review of Java fixture builders and test controls
  shows synthetic XML produced for SAMLscope tests, with protocol-mandated names and deliberately
  chosen values. This is different from copying an upstream XML example. Original expressions use
  the existing software/content grants; raw protocol observations/verdicts do not acquire a CC license.
- **Favicon: B / GREEN on supplied provenance.** The project owner confirmed generation without
  external imagery in response to the icon provenance question. No external image attribution remains.

The review used source selectors, `summary_en`, `reference_evidence.basis_en`, case references and
actual dependency bytes. A source ID alone is not proof of adaptation, and matching a short required
technical expression is not treated as such. This is a reasonable actual-use assessment, not a
claim of exhaustive historical authorship reconstruction for every source-code token.

## Dependency files and primary permission evidence

`java-permissions.json` records each exact JAR digest, declared licenses, publisher POM/parent POM
URLs and hashes, version-specific source archives and added texts. It is reviewed evidence, not an
automatic license classifier. `java_dependencies.py` refuses to reuse it when the JAR bytes change.
The generated inventory retains upstream notice texts, manifest/POM declarations and every XSD
resource's path/hash. Per-resource review records retain original notice blocks, named license
URLs and the limited distribution rationale. Missing resource review is not inferred from the
parent package decision; the build compares the inventory against the canonical evidence. Package and embedded-resource terms are not collapsed into one SPDX label.

The D / YELLOW decision is limited to **unchanged upstream package redistribution** under the
publisher's declared grants and retained resource exceptions. OpenSAML is published as an Apache-2.0
library by [its publisher](https://shibboleth.atlassian.net/wiki/spaces/OSAML/overview); this does not
turn its OASIS/W3C/other resources into SAMLscope-owned Apache code. The artifact/parent POM and
original headers provide package-specific evidence; merely finding a schema inside a JAR would
not by itself settle permission. No conflicting restriction on this unchanged package distribution
was identified. Namespaces without a copyright header are not automatically classified as copied
prose, nor as public domain. Independent extraction/modification of those resources is not cleared.

- ASM's exact upstream source headers and [BSD notice](https://asm.ow2.io/LICENSE.txt) are now
  supplied for its binary packages that did not embed a full notice.
- Jakarta and Logback EPL materials now have full EPL terms and exact published source links with
  hashes. This implements [EPL-2.0 section 3.1(a)](https://www.eclipse.org/org/documents/epl-2.0/EPL-2.0.txt).
  Logback is used under its [EPL option](https://logback.qos.ch/license.html); other declared dual
  licenses are not cumulative requirements. Jetty servlet resource headers explicitly specify EPL;
  they retain that grant even where the outer package declares Apache.
- `opensaml-soap-api`, `opensaml-xmlsec-api` and `xmlsec` contain schemas explicitly linking
  [W3C's 1998 software notice](https://www.w3.org/Consortium/Legal/copyright-software-19980720) and
  [2002 software notice](https://www.w3.org/Consortium/Legal/2002/copyright-software-20021231).
  Full historical terms are now readable from the application and included in the distribution
  inventory, alongside unchanged original copyright headers. These are the versions named by the
  files, not replacement modern document-use terms. HTML-to-text extraction preserves permission
  paragraphs/disclaimers; original URLs remain in each supplemental notice record.
- Embedded native SQLite payloads remain inside the unchanged sqlite-jdbc JAR with its Apache and
  Zentus notices. No native file is extracted into the SAMLscope source distribution.
- Gradle wrapper JAR retains its embedded Apache-2.0 text; launcher scripts retain original
  author copyright/license headers. Their actual bytes are pinned in the other-material register.
  They are repository/build-context material, not extra application runtime dependencies.
- React, react-dom and scheduler retain MIT text/banners selected from actual browser modules.
  Archivo's OFL text and copyright remain in the website's legal page/download.

No material met all four conditions for a rights-holder inquiry. No inquiry draft or external
message was necessary. No bounded legal question currently blocks the reviewed artifacts when their retained-notice
and corresponding-source conditions are met. This does not turn an uninspected future artifact into a cleared one.

## Output paths and exclusions

| Output | Implementation | Verification and remaining work |
| --- | --- | --- |
| GitHub repository | Root scope, source notices, material index, Java permission evidence and this audit | Signed inputs unchanged; no tracked independent XSD/RFC mirror; publish the complete repository with its licensing files |
| App UI | `/licenses`, selected source links; expandable Java full notices/source availability | No consent modal or per-row long notices; lazy Java inventory; UI test checks safe text rendering |
| result.json / report.html / offline report | Selected source notices + full content terms, software scope; source-only public metadata | Runtime tests, canonical generated golden, schema-compatible JSON and offline notice embedding; existing saved exports are not rewritten |
| Catalog JSON / website | Traceability generator, full source attribution, license page/footer and font notice | Regenerated website assets; no blanket material review pending |
| YAML / JSON / Markdown exports | `dev/licensing/export_material.py` | Regenerate redistributable standalone copies; protected originals are not rewritten; a raw GitHub file detached from licensing context is not the licensed-export format |
| Binary/source JAR | `META-INF/samlscope` and API public-license resources | Actual module archives checked; dependency files remain unchanged |
| ZIP / TAR | Complete `LICENSES` plus application/dependency JARs | Archive-byte verifier checks current texts and dependency inventory |
| Docker context | `.dockerignore`, pinned multistage recipe and installDist copy | Local research caches/ignored authoring input excluded; Pinned linux/amd64 base layers inspected; runtime-source gate compares the actual built image and retained public source assets before publication |
| npm/web assets | Vite notice generator, static site font downloads | Production built assets inspected; development node_modules is not a published npm package |
| PDF / CSV | No production export route found in reviewed API/Runner | No artifact exists to verify; new routes require notice handling |
| Diagnostic JSON / migration files | Original counters/status or derived catalog descriptions | Operational facts are not CC; descriptions follow the same source terms; use licensed standalone export when detached |
| User XML / transcripts / DB backups | Existing recording/redaction boundaries | Not static third-party material; no private captures inserted into this public registry |

The initial audit performed no push, deploy, publication or external inquiry. The subsequent
owner-authorized publication review is recorded in `docs/license-publication-review.md`.
Its build guard change requires signed G2 renewal; case meanings and specification interpretation
remain unchanged. Publication follows the release gates, not this document alone. See `build/publication-audit/` and `build/license-distribution-report.json` for local
verification logs. Existing operational acceptance limitations in `docs/13-release-readiness.md`
remain separate from this license-only release decision.
