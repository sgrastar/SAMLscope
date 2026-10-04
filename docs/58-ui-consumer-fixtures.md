# Comparison inputs for UI metadata consumption

Connected `MetadataUiConsumerFixtures` to ordinary/polling metadata generation to observe display-name precedence and logo language selection. Approved definitions were unchanged. Completed input generation does not establish completed product-browser observation/evaluation.

| Input | Case | Content |
|---|---|---|
| `ui-consumer-display-all` | `IIP-MD05-fj-idp-01` | Distinguishable UIInfo DisplayName, ServiceName and entityID |
| `ui-consumer-display-service` | Same case | No DisplayName; ServiceName present |
| `ui-consumer-display-entity` | Same case | Neither DisplayName nor ServiceName |
| `ui-consumer-logo-localized` | `IIP-MD05-f9-idp-01` | Language-neutral default logo and English logo |
| `ui-consumer-logo-fallback` | Same case | Same default logo and Japanese logo, corrected from initial French; see below |

UIInfo belongs in SPSSODescriptor Extensions. AttributeConsumingService containing ServiceName includes schema-required RequestedAttribute. Logo comparisons keep image bytes fixed and vary only localized-candidate language. Fixed data SVG contains no external communication/scripts.

Logo evaluation requires fixing/recording the product screen's actual preferred language and conditions that distinguish English/default selection. If product/CSP prevents data-image display, the comparison prerequisite fails; this is not a language-selection violation. Another reachable image transport is needed.

Display-name evaluation cannot rely on page-wide string searches. Candidate presence in configuration/source/hidden DOM differs from selection in the user-visible target-SP display. Browser collection must bind target entityID, original fixture hash, native import, identical screen/language/session conditions, visible display elements and before/after controls. The approved final fallback permits entityID or endpoint hostname.

## Incomplete work and validation

This addition supplies shared inputs and test code checking placement, candidate differences, absence and ordinary/polling paths. Product-browser observation, positive/negative oracle and formal Run integration remain incomplete. These inputs also do not cover DiscoveryHint/URL-scheme cases.

### Browser-observation module

`dev/reference-acceptance/ui_consumer_observation.mjs` accepts an existing Playwright Page and reads adapter-selected elements. It checks screen origin/path, preferred browser language, unique/visible elements, viewport placement and center-point occlusion. Logos require completed loading, natural dimensions and candidate-matching currentSrc. Text must exactly match the selected element's whole visible text, rather than a page-wide substring.

Records contain candidate tokens, fixture/import-record hashes and fixed diagnostics only. Unknown display text, form values, Cookies, communication bodies and screenshots are not saved. Exception strings may expose DOM/URL secrets and are excluded. Record creation is exclusive and never overwrites evidence.

Import-record hashes are correlation references, not verified import success/Run binding. Records include `import_binding_verified=false`, `verdict_adopted=false`. Matching browser language does not establish saved product-language settings. Adapter checks of import/language/target-SP display, actual SSO integration, controls and formal evaluation remain incomplete.

Added browser-boundary test code including negative controls. Only syntax checks ran; real-browser tests await the integration batch. No resolvable Playwright installation exists at the project root; the reference browser environment must be connected before execution. Unexecuted tests are not counted as passed.

### Shibboleth screen integration

`dev/shibboleth/ui_consumer_campaign.py` passes original fixtures through temporary FilesystemMetadataProvider; after read-back/Resolver reload, `observe_ui_consumer.mjs` opens standard product login. Each condition uses a fresh browser context with English preference and stops before authentication. No credentials are entered or completed SSO claimed. Provider configuration is restored byte-for-byte; temporary metadata is removed.

Reference Playwright uses Codex-bundled dependencies explicitly through `SAMLSCOPE_PLAYWRIGHT_MODULE`. The template displays SP names with a fixed English prefix in `header h1` and SP logos in `img.service-logo`; it does not select the IdP header logo.

| Input | Screen observation | Remaining evaluation condition |
|---|---|---|
| DisplayName and ServiceName | DisplayName shown | Strict import/request/screen correlation and all controls |
| No DisplayName | ServiceName shown | Same conditions |
| No name candidates | Target heading absent | Investigate another display; standard login.vm suppresses headings containing SP ID |
| English logo present | Localized logo shown | Establish actual product language-selection conditions |
| French-only candidate plus neutral logo | French candidate shown | Same conditions; browser preference alone cannot establish violation |

Measurements: `build/acceptance/reference-20260918/shibboleth-ui-consumer-campaign-v2/`, Run `run_7HK04E50WDXFR6NH3QSN5EH0JA`. Observed exact equality to saved image candidates, not hidden DOM/import success alone. Observation still has `import_binding_verified=false` and is not adopted into formal evaluation.

First Run `run_NC94WEZVKV6P8Z75J6YKZE52FH` remains in `shibboleth-ui-consumer-campaign/`. Every condition was rejected because the product used POST while observation allowed only Redirect. Corrected allowlisting to both entries advertised in fixed reference metadata. Also corrected completion-time result.json requirements for unevaluated Runs: record `evaluation-status.json` rather than start cases solely to generate absent results. Initial configuration restoration had completed.

<!--g1-literal--> Each batch: configuration writes 7; temporary deletions 1; MetadataResolver reloads 6; browser starts 5. Including initial failure: total writes 14, deletions 2, reloads 12, browser starts 10, Run/preflight 2 each. Completed SSO/user interactions/product restarts 0. Per-batch operations.json/restoration.json are originals.

<!--g1-literal--> Suite image build 1; Suite/forwarder recreations 1 each. `samlscope:reference-ui-consumer-v44` digest: `sha256:5631b8c2463afa95bbcedab550a2146b67f1687e6e5ac136c40b24fb7c07cee9`. Updated only SAML jar from signed UI-fixture source; unrelated API changes were excluded. Health passed. Boundary tests await integration; these screen observations do not substitute for passed tests.

<!--g1-literal--> No formal conclusions added; unverified observations remain 467. G2 signed-source difference remains unresolved.

### Correlation of sent requests and original fixtures

The browser adapter now observes main-frame SAMLRequests to the target IdP SSO entry. Bodies are decoded only in memory; records retain SHA-256/byte length. Redirect DEFLATE has an output limit. Duplicate parameters, multiple candidate requests or decode errors invalidate correlation. Only Accept-Language is retained; Cookies, Authorization, full URLs/request bodies are excluded.

`bind_ui_consumer_evidence.py` matches browser-request hashes to fetched Transcript originals. It checks Run/condition/Issuer/entityID/request ID/Destination/HTTP method/screen path/byte length and rejects request reuse. It also checks ordering of same-fixture MetadataPrepared, MetadataFetch, AuthnRequest and screen observation, requiring native-import hashes, actual writes/read-back/Resolver reloads and complete restoration.

Binding trusts local-adapter operation records. A file hash alone proves neither product processing nor administrator authenticity, and does not replace comparison/controls. Original observations remain unchanged; separate `ui-evidence-binding.json` records `originals_bound=true`, `native_readback_bound=true`, `verdict_adopted=false`.

<!--g1-literal--> New measured Run: `run_NHWX1F64WMGT7BMKZG5BQ7QTD2`. Evidence: `build/acceptance/reference-20260918/shibboleth-ui-consumer-correlated/`. All 5 conditions correlated; each request had Accept-Language `en-US`. HTML-root lang was unavailable and null. Display candidates/unresolved fallback conditions matched preceding observations.

<!--g1-literal--> Additional batch: configuration writes 7; temporary deletions 1; Resolver reloads 6; browser starts 5; Run/preflight 1 each. Credential input/completed SSO/user interactions/container changes 0. Full restoration verified. No incremental functional-test reruns; measurements/binding ran. Formal adoption still requires integrated negative-control validation.

### Corrected fallback input and observed switching

Inspected running `RelyingPartyUIContext` bytecode: logo lookup uses browser language, configured alternatives, then neutral candidates. Reference idp.properties has `idp.ui.fallbackLanguages=en,fr,de`. Initial French fixtures did not establish unavailable preferred/alternative languages; the Suite input condition prevented a violation conclusion.

Changed fixture language to Japanese, absent from alternatives, without changing product settings. The driver reads alternatives before execution and checks collisions with fixture/browser languages. Ambiguous/unsupported settings reject start; complete settings-file equality is also checked at completion.

New Run `run_GNBRVD9WSNFGHMXZEFN4BAH6NR`, `shibboleth-ui-consumer-language-control/`, observed localized with English candidates and default with Japanese-only candidates. Original request/fixture binding succeeded. `logo_comparison` checks identical images/dimensions, different language conditions, distinguishable candidates, sent Accept-Language and selection differences, returning `difference-observed`. Historical fr originals remain retained.

This diagnostic is not formal CaseOutcome. Local settings read-back is distinguished from runtime-context settings extraction; the latter is recorded as unperformed. Adapter/formal integration and controls excluding constant-logo implementations remain. Suppression of headings when both names are absent is unresolved.

<!--g1-literal--> Additional operations: writes 7; deletions 1; Resolver reloads 6; browser starts 5; Run/preflight 1 each. Language-setting writes/product restarts/credential input/user interactions 0. Complete restoration verified. Suite image build 1; Suite/forwarder recreations 1 each. Running `samlscope:reference-ui-language-v45` digest: `sha256:34c8e0d536e755b867973c4da15cb3f4b0c48bb8532ca669b88750e618794d13`. Updated SAML only, excluding unrelated API changes. Compilation/G1 generated consistency/structure passed. Functional tests await integration; unverified observations remain 467.

### Runner comparison

Added `UiLogoComparison` accepting original-validated internal Samples. It requires both preferred-language-present/unavailable conditions, same Run/SP/fixed inputs, comparison fingerprints including image bytes/dimensions, different metadata, request-to-screen ordering and unique originals. Only localized followed by default returns SATISFIED. Missing/failed evidence returns NOT_VERIFIED, never product violation or Verdict.

Sample is package-private, not a DTO for user-attested conditions/fingerprints. Conditions derive from original metadata/validated language preparation; collector fingerprints include target, policy, SP, browser settings, image/dimensions and display element. Unbound originals, unknown language settings or unloaded images cannot establish SATISFIED despite correct candidate tokens.

Added negative-control code for constant candidates, unobserved/missing conditions, different Runs/SPs, altered image/settings, treating one image as different candidates, identical metadata, invalid ordering and reused evidence. Compilation passed; tests await integration. Local-evidence collection into Samples and case registration remain incomplete; no new running-Suite/inventory conclusions were adopted.

### Original rechecks, case registration and integrated validation

`export_ui_logo_receipt.py` matches original-fixture logos to browser-candidate mappings and exclusively creates local-adapter receipts. Receipts contain fixed-target metadata hash, native preparation, original references/hashes and original browser observations, without Outcome/Verdict.

`UiLogoEvidenceFile` reads data-directory `ui-logo-evidence/<run>.json`; no HTTP submission exists. Files must be regular and Run-specific, bounded in size and nonsymlink. It rechecks original Transcript Run/type/condition/reference/hash/order, advertised target SSO entries, actual request Issuer/ID/Destination and browser hash/sent language/screen path. Original XML supplies logo language/image/dimensions for fixed-input fingerprints/Samples. Language matching looks up regional preference then general language.

Browser/native-preparation authenticity belongs to the local-adapter trust boundary. The experiment uses read-back settings and observed product selection; product signatures are not claimed to detect administrator-fabricated evidence. No direct JVM-settings extraction is claimed.

Connected `UiLogoBrowserEvidenceTestCase` to the M2 browser registry, evaluating at start/external evidence confirmation. Missing evidence remains NOT_VERIFIED and cannot be supplied by completion clicks/attestation.

<!--g1-literal--> Batched deferred validation passed 4 Java comparison/fixture tests and 1 Playwright boundary test. Production replay of measured originals returned SATISFIED; all 7 mutated receipts—constant default, constant localized, hidden element, different target/request, duplicates/missing evidence—returned NOT_VERIFIED. Replay report: `shibboleth-ui-consumer-language-control/production-logo-comparison.json`. This validates implementation before formal Run adoption.

<!--g1-literal--> Compilation passed. Execution of 2 added tests remains deferred to integration, not claimed as success. Following user direction, small additions do not each trigger functional reruns. G1 generated-document/structural checks remain mandatory per change.

<!--g1-literal--> Unverified observations remain 467 with 157 case IDs. Product writes/container changes/protocol execution/user interactions 0. New fixtures exist in working source but are not in the running image.
