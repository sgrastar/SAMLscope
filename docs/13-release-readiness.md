# Phase 1 release readiness

Implementation milestones M0–M4 are recorded as complete. This does not establish
operational acceptance or readiness of the official hosted service. Hosting-provider
preparation is pending; local verification can proceed independently.

## Prioritized work

| Priority | Work | Completion evidence | Hosting dependency |
|---|---|---|---|
| P0 | Verify the current implementation and approved catalogs | Successful Gradle `check`, generated-document check, structural validation, and externally pinned signed G1/G2 release verification for the candidate revision | None; specification reconciliation requires Internet access |
| P1 | Execute the local Keycloak acceptance fixture | Record image digest, Suite revision, Test Plan, browser round trip, exported results, and unresolved evidence; repeat the same plan and explain any differences | None; local containers and browser required |
| P1 | Establish the reference-implementation acceptance matrix | Track IdP/SP and Core/Full coverage, conditional features, and Keycloak/Shibboleth/SimpleSAMLphp evidence separately; mark unexecuted combinations explicitly | None for local targets |
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
3. Extend the matrix to IdP Full and SP Core/Full, then to the other reference
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
