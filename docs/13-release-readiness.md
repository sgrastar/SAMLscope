# Phase 1 release readiness

Implementation milestones M0–M4 are recorded as complete. The hosting provider and
production environment are available. Deployment and production smoke verification
of the new functional-profile release remain separate release actions and require
explicit authorization.

## Current status

The seven functional-profile artifacts are now exact case-set release candidates.
The runtime, normal Plan/Run path, shared target metadata, presets, result output and
license/source display use existing approved cases as their only execution units.
No case split or missing implementation input remains in the case-level inventory.
The candidates remain unavailable in production until their exact memberships receive
independent G2 approval and their digests are added to `profiles/release-pins.properties`.
This is an approval boundary, not an implementation gap.

| Work | Latest state |
|---|---|
| Existing implementation and signed specifications | Full release verification passed for the runtime fixes |
| Local Keycloak and reproducibility | Independent current-image Runs completed the registered active chain; M2/M3 exports match and contain no not_implemented reasons |
| Reference scope inventory | Matrix documented; other products and Full/SP configurations remain unexecuted |
| Progress and operations preparation | Documentation reconciled; isolated restore, persisted Plan-file deletion and Hosted authorization tested; offline retention and CI added |
| Phase 2 | Scope draft available; no new verdict implementation authorized by that draft |

The functional-profile release is not yet publishable because its case-set artifacts
are not independently approved or release-pinned. Production deployment, smoke
verification and operational acceptance follow that approval. Stable reference
outputs can still be incomplete or contain failure candidates; reproducibility is
not a conformance endorsement.

## Prioritized work

| Priority | Work | Completion evidence | Hosting dependency |
|---|---|---|---|
| P0 | Verify the current implementation and approved catalogs | Successful Gradle `check`, generated-document check, structural validation, and externally pinned signed G1/G2 release verification for the candidate revision | None; specification reconciliation requires Internet access |
| P1 | Execute the local Keycloak acceptance fixture | Record image digest, Suite revision, Test Plan, browser round trip, exported results, and unresolved evidence; repeat the same plan and explain any differences | None; local containers and browser required |
| P1 | Establish the reference-implementation acceptance matrix | Track the seven functional profiles, conditional features, and Keycloak/Shibboleth/SimpleSAMLphp evidence separately; preserve historical Core/Full evidence under its original labels | None for local targets |
| P2 | Reconcile progress documentation | Align AGENTS.md, D-15, README, and roadmap status with verified evidence; preserve signed artifacts and the independent-review boundary | None |
| P2 | Prepare hosted operations | Document deployment and rollback, backup/restore verification, retention enforcement, deletion contact, and publication/scrubbing acceptance steps; leave operator-specific values pending | Preparation is local; production execution waits |
| P3 | Scope Phase 2 | Define the next specification catalog and review gates for Artifact, queries, browser automation, CI integration, and badges before implementing new verdict cases | None |

Complete Phase 1 acceptance before expanding conformance scope. Reference products
provide interoperability and regression evidence; executable mutants and controls
establish detection power. A reference product is not required to receive PASS.

## Verification log

Baseline: `27a9f66` (2026-09-07).

- Generated G1 documentation: passed.
- G1 structural validation: passed with no blocking failures.
- G2 local design validation: passed with no blocking failures; this is not signed approval verification.
- Gradle `check`: passed, including backend tests, frontend build/tests, and release-policy unit tests.
- Signed release-policy verification: passed (`complete=true`), including fresh source reconciliation and externally pinned G1/G2 signature verification. Executed with `tools/release_check.py` separately from the successful Gradle `check`.
- Local Docker daemon: available; no running containers and no `samlscope:keycloak-smoke` image at inspection time.
- Initial Keycloak IdP Core acceptance: completed as described below. Reference-run publication remains pending.

## Local Keycloak acceptance

The baseline above was built into image
`sha256:352e44f86e4c2745ad3d32a7438dc99472deb03e9c4200a8fda4d433264407e6`.
The fixture uses the digest-pinned Keycloak image in `dev/keycloak/compose.yml`.

- A real browser login completed the SSO round trip and displayed `normalFlowAccepted=true`.
- A second Run of the same IdP Core Test Plan completed through the existing Python smoke client with an independent cookie jar. This second execution is protocol-client evidence, not a second browser acceptance pass.
- Both Runs produced result JSON and standalone HTML exports. The application report was visually checked.
- Quick-check obligation verdict vectors, case outcome/reason vectors, summary, and coverage matched across Runs.
- Starting M2 and M3 removed the Quick-only `not_implemented` reasons. Both Runs then had matching obligation and case vectors and coverage, with no `not_implemented` reasons remaining.
- Both results remain `INDETERMINATE / INCOMPLETE`: pending interactions and undetermined applicability still require evidence. This is not full IdP Core acceptance or product certification.

Local, ignored evidence is in `build/acceptance/keycloak/`: `comparison.json`,
`all-milestones-comparison.json`, and per-Run JSON/HTML exports. These files are
operational evidence, not the canonical CI release artifacts. The containers and
their volume remain available for continued evidence collection.

### Findings and next acceptance work

1. Timestamp display fixed: numeric API epoch seconds and ISO strings now share
   a formatter in the Test Plans overview and interaction expiry display. The
   overview regression fixture uses the actual numeric wire format. Frontend
   tests/build, structural checks, and pinned G1/G2 release-policy verification
   passed. Browser verification against the existing backend displayed the
   correct September 2026 date through the Vite frontend.
2. Resolve the fixture's declared conditional features and execute the pending
   browser/configuration campaigns. Record unsupported or unavailable evidence
   explicitly; do not fabricate operator answers to increase coverage.
3. Extend the matrix to the functional IdP/SP profiles, then to the other reference
   products. These combinations have not been executed in this session.

### Continued browser evidence collection

The existing baseline container was restarted without changing its image or
Test Plan. Two consecutive SSO round trips in the same real browser session
produced distinct request IDs and correlated successful responses. The Suite
automatically resolved `IIP-SSO01-ap-idp-01` and `IIP-SSO01-k2-idp-01` as PASS;
no operator verdict or completion answer was submitted. The updated result is
saved as `build/acceptance/keycloak/after-browser-correlation.json`.

The pending-work inventory is saved alongside it as `interactions.json`,
`campaigns.json`, and `bootstrap-contracts.json`. The active abnormal-request
chain explicitly requires a fresh target session for its initial IsPassive
probe. Metadata campaigns require real target refresh/re-import and correlated
flows; current configuration has not established that setup. Conditional
features remain undetermined until supported by fixture configuration or
protocol evidence. These requirements must not be replaced with blanket
completion answers.

A separate image, `samlscope:keycloak-date-fix`, was built successfully for the
UI fix. It has not replaced the baseline acceptance container; existing Run
evidence therefore retains the original image provenance.

### Active-probe follow-up and evaluator correction

The initial IsPassive request used a protocol client with an empty cookie jar;
its correlated SAML response had Responder status. A subsequent localhost-cookie
handling failure in that client was recovered using the Suite's deterministic
retry operation, and the positive control continued in the real browser.
Credentials were used only in memory, and client logs exclude forms and bodies.

Keycloak displayed `Unsupported NameIDFormat` for the unknown-format fixture.
The missing SAML response was recorded through the existing response-unavailable
operation. Later browser steps displayed `Invalid redirect uri`; that visible
page alone does not identify the completed fixture because the Suite chains
requests automatically. Always use the active action and Transcript correlation
to identify which request produced a result.

The AuthnContext fixture returned Success with an EncryptedAssertion. The
wire-level observer could not inspect its AuthnContext but incorrectly produced
VIOLATED. `IdpErrorResponseTestCase` now returns NOT_VERIFIED when a successful
AuthnContext-probe response contains encrypted assertions. The regression test
also verifies that a visible wrong context still produces VIOLATED after the
controls run. This changes observation handling, not the approved obligation or
its level. Approved catalogs and signed records remain unchanged.

**The historical `after-active-probes.json` NON_CONFORMANT result is affected by
this Suite bug and must not be published as a finding about Keycloak.** The
baseline container still runs the old image. The fixed-image rerun below verifies
the correction; do not overwrite the historical evidence or represent it as
corrected. Correlation evidence is in `active-probe-transcript-index.json`
and the content-free summary `authn-context-observation.json`.

### Fixed-image acceptance rerun

The isolated container `samlscope-observation-fixed` listens only on loopback
port 8082 and uses its own data volume. Image:
`sha256:4c29e28bc9d2f1a5e1dc8f01c471dd3e69e51244aa0a72b7473b27894b29ba90`.
Run: `run_1793TEBEN7A0XF30EH4MA0XGGM`.

The existing fixture provisioned a new Test Plan and completed baseline SSO.
A protocol client with an empty cookie jar then ran the error-response case;
its localhost cookie policy mirrors the existing browser localhost exception.
This is protocol-client acceptance evidence, not a new browser acceptance pass.
Credentials remained in memory and no forms or response bodies were written to
the client log.

The recorded sequence includes the IsPassive Responder response, a successful
encrypted positive control, an unavailable unknown-NameID response, and a
successful encrypted AuthnContext response. The target case completed with
`NOT_VERIFIED` and reason `idp.error-response.inconclusive`, with correlated
Transcript evidence. The encrypted-response false FAIL is no longer reproduced.

Local evidence is under `build/acceptance/fixed-observation/`: `summary.json`,
`observation-summary.json`, `exchange-log.json`, `result.json`, and `report.html`.
The old and fixed containers and their data remain separate.

During the chained active-probe run, the report still showed the
previous `case.pending-interaction` snapshot after the case had finished and
the next case was awaiting input. Starting M2 refreshed the report and exposed
the completed outcome. `M1Runtime.acceptActiveProbe` previously regenerated only
when the coordinator reported the entire chain FINISHED. The next ALG01 action was
prepared automatically but was not sent by this bounded reproduction.

### Per-case report freshness correction

`M1Runtime.acceptActiveProbe` now checks the persisted execution associated with
the accepted outbox action. When that case is FINISHED, it regenerates the
result artifacts even if the coordinator has selected another waiting case.
The change does not advance that next case or change any verdict rules.

`ActiveProbeReportFreshnessTest` seeds only the M0 prerequisite and uses the
application's HTTP dispatch and inbound-response routes for the active case.
Before the fix it reproduced a stale NOT_VERIFIED result after the case finished.
After the fix it verifies the completed outcome, reason and Transcript evidence
while the next case is AWAITING_RESPONSE. It also decodes the standalone HTML's
embedded JSON and checks that its requirement results match the JSON endpoint.
The targeted regression passes. Repeated macOS runs also exposed
`SQLITE_IOERR_SHMSIZE` while HTTP and Transcript workers opened short-lived
connections. This report-specific test retains an idle connection for its
lifetime to keep WAL shared memory available; it does not retry failed HTTP
requests or suppress errors. Production connection-lifecycle behavior remains a
separate reliability follow-up and is not claimed to be fixed by this change.

The running acceptance containers predate this report-refresh change. Their
historical image digests and output must not be presented as verification of it.

The installed Java runtime needed an explicit `JAVA_HOME` on this workstation:

```bash
JAVA_HOME=/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home ./gradlew check
```

Use the existing GitHub repository variables for `G1_TOOLS_COMMIT` and
`G2_TOOLS_COMMIT`, and the configured SSH allowed-signers file, when running
`releaseCheck`. Never substitute a newly selected verifier commit just to make a
failed gate pass. Generated reports under `build/` are local evidence; preserve the
canonical release reports as CI artifacts.

## Follow-up inventory

The [reference matrix](14-reference-acceptance.md) now separates executed and
unexecuted product/role/profile combinations. [Operations preparation](15-hosted-operations.md)
records actual deployment rollback behavior and the remaining retention,
unpublication and complete file-deletion gaps. The old G2-pending text in
AGENTS.md and the pre-M4 wording in D-15 have been reconciled with signed-gate
verification and implementation status. [Phase 2 preparation](16-phase2-preparation.md)
is a scope draft only; its implementation gate remains closed.

A follow-up SQLite experiment moved persistent WAL initialization out of ordinary
connection acquisition. The unanchored report regression still reproduced
SQLITE_IOERR_SHMSIZE during a repository query. This did not resolve the I/O error.
A second experiment serialized connection attachment/detachment and also failed.
Both experimental lifecycle changes were discarded. Connection setup now closes
failed connections and preserves suppressed close errors; the report regression
retains its documented test-only anchor.
Production reliability diagnosis remains open.


### Isolated restore rehearsal

A stopped snapshot of `samlscope-observation-fixed` was copied into a separate
private directory and the source container restarted. All copied file hashes
matched. SQLite integrity and foreign-key checks passed, and all indexed body
and decoded-SAML references existed in the restored tree.

The snapshot's exact image was then started against the copy with Docker network
`none`. Health, result JSON and HTML retrieval succeeded; requirement results
matched the previously exported fixed-observation Run. The temporary restore
container was removed. Evidence is in `build/acceptance/restore-rehearsal/summary.json`;
private snapshot files and hashes remain ignored. This validates the local
self-hosted fixture's recovery, not production hosted authorization, deletion
reconciliation or the newer report-refresh image.

### Current verification limit

The follow-up full `releaseCheck` failed in
`SamlScopeApplicationTest.createsPlanAndPublishesSignedMetadata` with an HTTP 500
caused by SQLITE_IOERR_SHMSIZE. The report-freshness regression passed with its
existing anchor. Earlier successful release verification remains historical;
it must not be reported as a successful check of this follow-up batch.
Generated-document, G1 structural and G2 local checks pass. Production release
remains blocked on database reliability and the outstanding acceptance work.

A proper application-owned database lifetime would touch the signed G2 boundary
in `SamlScopeApplication.java`. That file is checked byte-for-byte against the
approval commit by `g2_validate.py`; do not bypass that gate or patch it silently.
Any such lifecycle change needs the corresponding independent review and renewed
approval. Changes to approved specification interpretation remain separately gated.


### Host storage constraint

Further inspection found the macOS data volume at full reported capacity with
approximately 126 MiB available. The standalone store tests also failed with
SQLITE_IOERR_SHMSIZE, including sequential database initialization. Connection
races are therefore not established as the root cause: storage exhaustion must
be ruled out before selecting a lifecycle redesign or dependency change.

The unused `samlscope:keycloak-date-fix` intermediate image was removed; baseline
and corrected acceptance images, containers and evidence volumes were retained.
This did not materially increase host free space. No unrelated Docker caches,
volumes or user files were pruned. Restore sufficient host space, then rerun the
unanchored reproduction and full release verification before claiming recovery.


### Verification after host space recovery

After the user requested removal of Xcode DerivedData, host free space recovered.
The standalone store tests passed without changing database runtime behavior.
The report-freshness regression's test-only idle connection has now been removed;
the API tests and full `releaseCheck` passed, including pinned G1/G2 signature
verification and fresh source reconciliation (`complete=true`).

These observations support storage pressure as the cause of the earlier failures;
they do not establish a production connection-lifecycle defect. The earlier failed
experiments and logs remain historical evidence. No signed-boundary lifecycle
change or new approval is needed on the evidence currently available. Monitor
host capacity before additional image builds and acceptance runs.


### Current-image Keycloak report acceptance

Image `sha256:e8a106cc1ac4bed01e80fcdc7419d4908a1f78264c7ff28a71622fa17d468e4a`
contains runtime commit `9830e28`; build-time uncommitted changes were the test-only
anchor removal and documentation. The isolated `samlscope-report-refresh`
container uses its own data volume and loopback port 8084.

Run `run_VJ64KTA7KAFD8GQ20XF49QEBT0` completed baseline SSO and the bounded
error-response sequence with a fresh-cookie protocol client. Immediately after
that case finished, with ALG01 AWAITING_RESPONSE, JSON showed NOT_VERIFIED with
`idp.error-response.inconclusive` and correlated evidence. The standalone HTML's
embedded requirement results matched JSON. No M2 start or other report-refresh
workaround was used. This verifies both observation handling and report freshness
against Keycloak; it is not complete IdP Core acceptance or a new browser pass.

Evidence and the credential-free reproduction script are under
`build/acceptance/report-refresh/`. The next algorithm case remains awaiting
response; its automatically generated form was outside this bounded execution.
Do not treat that unexecuted exchange as target evidence. Historical containers
and results remain separate.


### Continued algorithms and operations implementation

The current-image Run continued through ALG01 and ALG02 using correlated exchanges.
Tampered ACS requests received Keycloak's `Invalid redirect uri` page; the altered
ACS is part of the negative control, while ordinary signed requests did produce
SAML responses. Both cases ended NOT_VERIFIED with
`idp.signed-request.inconclusive`, not a target failure. EXT01 is now awaiting its
next exchange. Evidence is in `algorithm-exchanges.json`, `algorithm-summary.json`,
`outbound-shapes.json` and `after-algorithms-*` under the current-image evidence
folder. The recorded retry reflects the previously unsent browser form.

Plan deletion previously left results, cached metadata and generated keys on disk.
`FileTranscriptRecorder.deletePlanAndEvidence` now removes those persisted files
alongside Transcripts before deleting database rows. Its regression verifies
removal and preservation of unrelated files; failure retains database identifiers
for a retry. Hosted authorization and concurrent-writer deletion acceptance are
still open and must not be inferred from this storage-layer check.

Offline hosted retention tooling and optional Linux scheduling templates are now
available; see [operations](15-hosted-operations.md). Preview, boundary, preservation,
accounting, idempotence and path-safety tests pass. A real fixture snapshot copy
also passed a simulated future expiry rehearsal. The source acceptance container
and its data were unchanged. Production installation and backup rotation policy
remain pending.


Hosted HTTP deletion acceptance now checks that missing CSRF prevents deletion,
the owner can delete with the correct token, persisted results are removed, the
old Run session loses access, and another owner's Plan stays accessible. The
storage regression additionally checks metadata and key cleanup. These checks
pass; concurrent in-flight writer behavior remains a separate acceptance item.

The EXT01 unknown-extension scenario completed SATISFIED with
`idp.extension.satisfied`. Other exercised extension and general scenarios retain
`browser_fixture_partial` where the external evidence does not cover all variants.
Fresh-session scenarios are being exercised with explicit cookie resets in the
local protocol client; these are not real-browser verification records.


### Completion of the current active chain and finding triage

The protocol client reached active-probe FINISHED, resetting its cookie jar only
at explicit fresh-session boundaries. This completes the registered active chain,
not metadata campaigns, all applicability inputs, or Phase 1 acceptance.
Final historical exports are `after-session-cases-*` in the current-image folder.

The exported result contains target-failure candidates and a confirmed Suite bug.
IDP08 treated hidden AuthnContext values in successful EncryptedAssertions as
mismatches. Every correlated response for that case had encrypted assertions and
no visible context. A new regression reproduced VIOLATED and now expects
NOT_VERIFIED; visible plaintext mismatches remain detected. The wire-only observer
now declines to judge encrypted successful contexts. The running image predates
this correction, so its aggregate result must not be published as a validated
finding. `authn-context-visibility.json` records content-free evidence shapes.

Signed-request results were checked against the approved catalog: requiring a
signature and validating a signature that is present are separate obligations.
The signature-required fixture setting therefore does not justify suppressing
these candidates. NameID responses were inspected in memory inside the existing
container: Formats matched the transient/persistent requests, but SPNameQualifier
was absent. ACS-index response destinations pointed to the default endpoint.
These findings still need isolated, repeatable target-configuration review before
publication. Attribute-only observations are in
`nameid-acs-attribute-comparison.txt`; no subject identifier or private key was
exported. A proposed private-key copy was rejected by automatic approval review;
the inspection instead loaded the existing key only in container memory.

The added operations CI workflow runs the offline retention tests and shell syntax
check independently of the signed release workflow. No production timer or hosted
service has been enabled by this work.


### Retention failure recovery checks

An additional simulated storage failure verifies that a partial file cleanup keeps
the database identifiers needed for retry, preserves unexpired data, and completes
on retry. Unsupported database schema versions are rejected before file deletion.
These Python tests pass against the application migration schema and the existing
real-fixture retention copy remains readable by the tool.

Do not run standalone structural validation concurrently with `releaseCheck`:
both write `build/spec-reconcile-report.json`. One overlapping invocation replaced
the pinned report and correctly failed the provenance gate. A subsequent isolated
release verification passed with `complete=true`; no pin or policy was changed.


### Repeated current-image acceptance

Runtime commit `75579b8`, image
`sha256:ff5444a887ea44b5bfb7d3f07c3c476e9292022db06695e63d37faba5926d3d5`,
is isolated on loopback port 8086 with a new data volume. Runs
`run_Y0DW9X8MCJ2S31HKQJB5H613RV` and
`run_PSBXRH67VHZ72XXJ8XDQ09K6CH` independently executed the registered active chain.
Both reached FINISHED. Both report IDP08 as NOT_VERIFIED with
`idp.authn-context.inconclusive`, verifying the encrypted-context correction
against actual target responses.

The Keycloak converter had omitted the secondary HTTP-POST ACS from its URI
allowlist. For these new Runs, fixture provisioning explicitly registered every
ACS location from the Suite metadata. This is setup evidence, not a substitute
for SAML observations. Historical Runs were not changed. Even with this correction,
signed-request, NameIDPolicy and ACS-index failure candidates remain; publication
still requires their review against the exact target configuration and signed
specification interpretation.

Case outcome/reason vectors matched across Runs. Starting M2 and M3 then produced
matching case vectors, summaries, coverage and conformance statements without
not_implemented reasons. JSON and standalone HTML requirement data matched for
each Run. The resulting statement remains NON_CONFORMANT / INCOMPLETE for this
fixture, not an accepted certification or a completed full-profile reference run.
No operator completion answers or attestations were fabricated.

Local evidence is under `build/acceptance/complete-reproduction/`: image/commit
provenance, per-Run ACS registration inventory, protocol-client scripts and logs,
all-milestone exports, pending interactions/campaigns/bootstrap contracts,
`comparison.json` and `all-milestones-comparison.json`. These are private ignored
artifacts; CI remains the canonical source for signed release-check artifacts.
