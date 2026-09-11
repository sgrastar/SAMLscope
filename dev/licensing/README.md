# License generation and verification

These independent licensing helpers live outside `tools/`, the G1 validator's
protected Python import directory. They do not extend or replace G1/G2 approval
checks, and they do not modify signed catalogs.

From the repository root:

```sh
.venv/bin/python dev/licensing/materials.py
.venv/bin/python dev/licensing/materials.py --check
# Generate from resolved dependencies before packaging (also works after upgrades).
./gradlew :api:writeJavaLicenseInputs
.venv/bin/python dev/licensing/java_dependencies.py --inputs-json build/java-license-inputs.json
./gradlew assemble :runner:test :web:check :api:distZip :api:distTar
.venv/bin/python dev/licensing/java_dependencies.py api/build/distributions/samlscope-0.1.0.zip --check
.venv/bin/python -m unittest discover -s dev/licensing -p 'test_*.py' 
.venv/bin/python dev/licensing/verify_distribution.py --website ../SAMLscope-website
```

The index generator records catalog input digests and selected source IDs.
`runner:verifyLicenseMaterials` verifies those digests and notice hashes using
only the JVM, including inside the existing container build. Changing a license
input invalidates the web build cache. The distribution checker compares actual
ZIP/TAR contents and nested JAR resources against the current source files.

`ResultAttributionTest` generates `runner/build/license-qa/report.html` and
`result.json` for UI inspection. These are synthetic test fixtures, not product
conformance evidence. `ResultDocumentAssemblerTest` owns the canonical golden
result; update it only using its `SAMLSCOPE_UPDATE_RESULT_GOLDEN=true` mechanism.

See `LICENSES/material-review.md` for unresolved permissions and output paths.

Standalone redistributable copies (the approved source files are not changed):

```sh
.venv/bin/python dev/licensing/export_material.py tests/coverage.yaml --output build/licensed-exports/coverage.licensed.yaml
.venv/bin/python dev/licensing/export_material.py profiles/browser_sso_idp.json --output build/licensed-exports/browser-sso-idp.bundle.json
.venv/bin/python dev/licensing/export_material.py docs/04-requirement-coverage.md --output build/licensed-exports/coverage.licensed.md
```

YAML keeps parsed values and original trailing bytes; JSON uses a new envelope
with both parsed content and exact original UTF-8 text; Markdown appends escaped
notice metadata. These copies are not signed approval artifacts. Selection by
explicit source/requirement references is a traceability mechanism, not a finding
that unmarked quotations or adaptations do not exist. Older raw-file download
paths are not retroactively wrapped.

The common JAR packaging and inventory-check change received owner-authorized
signed G2 renewal; see `docs/license-g2-reapproval.md`.
Running these helpers does not satisfy or bypass that gate.

The source index now includes case/profile membership and numbered obligation
suffixes. `materials.py` also generates `web/public/licenses/source-membership.json`;
`--check` verifies both copies. The website exporter consumes the same index and
verifies its source hashes. Run its exporter again after regenerating this index.

The distribution verifier compares dependency inventory content against actual
JARs, and website row source IDs against the shared index. Gradle inventory enforcement now runs before application resource packaging and
checks. The owner authorized this G2-protected build change and its reapproval. `java_dependencies.py --inputs-json FILE` supports a
JSON array of resolved local JAR paths for regeneration without a built archive.
