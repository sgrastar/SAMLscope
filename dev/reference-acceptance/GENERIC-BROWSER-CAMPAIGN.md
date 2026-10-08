# Generic browser campaign collector

`generic_browser_campaign.mjs` drives the Suite's existing browser/outbox path for an arbitrary IdP. It contains no Keycloak, Shibboleth or SimpleSAMLphp management API, default password, product configuration path, or verdict mapping.

The operator first registers the Suite peer metadata in the target. By default, the collector requires an existing result and a completed normal SSO control: exactly one Recorder-owned, correlated `normalFlowAccepted` Success for the Run's current `context.authnRequestId`, paired with exactly one matching AuthnRequest. A valid older M0 from the same Run cannot satisfy a new nonce. `RUNNING` or a standalone Success is insufficient. Initial registration, native configuration read-back and eventual restoration belong to the normal preparation adapter; this collector neither changes nor attests to product settings.

Optional `completeNormalFlow: true` completes the normal SSO control inside the collector's primary visible browser context, then reuses that same in-memory context for actions with `requiresFreshSession: false`. A new normal request is permitted only for `CREATED`, no `context.authnRequestId`, no Recorder entries and zero actual case executions. The collector reads the official campaigns, protocol-evidence, interactions and active-probe projections, runs preflight once, and submits an empty protocol-evidence evaluation solely to create the actual pinned result membership. It checks that evaluation completed no cases and left those projections and Recorder empty before starting M0. The public API does not expose an outbox count, so its report marks that count unmeasured; the owned integration fixture independently asserts case/outbox/target sends remain zero through this preparation. The full profile starts only after the same strong M0 guard passes against the actual Run and Recorder response. No HTML success marker can satisfy that guard.

An existing `COMPLETED` Run uses the existing strong guard and issues no M0 request. An existing `WAITING_BROWSER` Run must have a Recorder AuthnRequest matching `context.authnRequestId`; it is observed without preflight, empty evaluation, GET/start or resend. Only a still-live page in this collector process can resume that browser session. A separate collector invocation reports the existing handle and cannot recover a previous browser or saved Chrome profile. Other incomplete states fail closed. Do not combine `completeNormalFlow` with the legacy `initialNormalFlow` option, which deliberately submits an additional normal request only after an already completed baseline.

Use an empty ignored evidence directory and a public task file:

```json
{
  "suiteBaseUrl": "http://localhost:18080",
  "runId": "run_0123456789ABCDEFGHJKMNPQRS",
  "planId": "plan_0123456789ABCDEFGHJKMNPQRS",
  "targetOrigins": ["https://idp.example"],
  "caseIds": ["IIP-SSO01-ep-idp-01", "IIP-SSO01-f-idp-01"],
  "startTests": true,
  "completeNormalFlow": true,
  "maxActions": 400,
  "actionTimeoutSeconds": 300,
  "outputDirectory": "/absolute/path/to/ignored/evidence"
}
```

```sh
SAML_SCOPE_PLAYWRIGHT=/absolute/path/to/installed/playwright \
  node dev/reference-acceptance/generic_browser_campaign.mjs /path/to/task.json
```

`targetOrigins` includes every approved IdP or authentication-broker navigation origin. Other top-level/frame navigation is blocked. The default is a visible installed Chrome; `SAML_SCOPE_BROWSER_CHANNEL` can select another installed Chromium channel. Passwords, cookies, storage state, authentication headers, login HTML and screenshots are not task inputs or exported evidence. The test user types into the visible IdP page when asked. Non-SAML HTTP bodies are discarded. Authentication checkpoints count observed password forms; they are explicitly **not** credential-submission or human-click counts.

The authenticated in-memory browser context is reused only for the Suite's explicit `requiresFreshSession: false`. Each `true` action gets an independent empty browser context. A passive action that displays a password form stops without filling it. Closing those contexts restores the collector's temporary browser resources; it does not assert logout or restoration of target settings.

If optional normal-flow observation times out, the CLI exports the Run/Plan/AuthnRequest handle and retains the existing page, browser context and process. Run it in an interactive terminal (or an exec session with a PTY). Enter `resume` to poll that same page; enter `stop` to close only the collector's browser resources. Closing stdin also stops the collector. Polling never reissues the start URL or aborts the Suite's live M0. Each attempt is retained separately, and explicit stop plus confirmed browser closure is recorded. The campaign counts one `normalLoginContexts` creation and subsequent context reuse; actual human login/click counts are unmeasured. This does not claim zero human interaction.

There is no selected-tests start API. `/tests/start` starts the full approved profile. The collector proves selected IDs exist in the actual Run, then prepares and aborts other actions at the Suite without following redirects, running HTML or submitting to the target. The output records the full-profile start call and membership count and marks the unavailable public-API queue-change count as unmeasured, never as zero. Use `startTests: false` only when the normal preparation path already started that profile. A live `AWAITING_RESPONSE` action is left intact; the collector does not restart it because an observation poll expired.

All fixtures of a selected case continue while Runner records terminal observations. In particular SSO01.f retains its normal control, unknown NameID Format, unrecognized Subject, and fresh passive request. A target HTTP error is reported from a real browser navigation with its body explicitly omitted. It cannot prove assertion absence, VersionMismatch, or an approved native terminal exception; these f/ep/d paths remain unverified. This observation lets the regular scenario progress to its next fixture instead of aborting the whole case. An observation timeout retains the same live action, stops collection, and exports its handle without aborting, retrying or invoking formal evaluation. A network exception never creates an invented HTTP status. No operator completion answer or self-attestation is submitted. Public SAML originals are retained on failed collection attempts, with no Recorder qualification when its transcript could not be fetched. Browser closure is recorded only after the browser disconnects; it does not terminate or attest to completion of a pending Suite action.

Only original SAML request/response bytes from allowed public form fields are captured. HTTP-Redirect requests are not reconstructed before sending. Case originals retain Run/case/action provenance; normal-control originals carry `operationKind: M0_NORMAL` with no invented case or action ID. They remain supplemental evidence until their hash and operation are matched to a unique Recorder original. The normal-flow bound marker also requires the guard-approved current nonce and exact request/response references; ambiguity leaves the bytes unqualified. Current Recorder exports normally omit the decoded SHA-256, so `original-captured-recorder-hash-unavailable` is an expected unqualified state; native acceptance export/verification must establish byte equality independently. Non-JSON API bodies are omitted, and nested management bearer URLs or explicit credential/token fields are rejected before persistence. The collector never relabels transcripts, adds missing saved cases, changes case digests, or adopts a result into the ledger. The Suite's official evaluation is exported unchanged.

`IdpErrorAssertionRecordedEvidenceTestCase` gives SSO01.f a pure formal re-evaluation path. It validates the original ordered request graph, exact probe XML, configured request-signing policy, Response correlation, target issuer, ACS destination and present signatures. Unsigned OPTIONAL transport is retained; it does not add a new signature obligation. Success requires every error path and the positive assertion control; HTTP, missing paths and successful abnormal requests cannot satisfy it. Both plain and encrypted assertions on an actual error are counterexamples. It does not claim that separate requests share an authentication session: Recorder intentionally excludes cookies. The ordinary start/resume sequence remains deterministic and outbox-only, and an original-free delegate success fails closed.

Run the policy/correlation tests with Node's built-in runner:

```sh
node --test dev/reference-acceptance/test_generic_browser_campaign.mjs \
  dev/reference-acceptance/test_synthetic_normal_browser_http.mjs
SAML_SCOPE_PLAYWRIGHT=/absolute/path/to/installed/playwright \
  node --test dev/reference-acceptance/test_generic_browser_campaign_integration.mjs \
    dev/reference-acceptance/test_generic_browser_campaign_normal_integration.mjs
./gradlew :runner:test --offline \
  --tests com.samlscope.runner.cases.IdpErrorAssertionRecordedEvidenceTestCaseTest
```

The integration tests use real headless Chrome against synthetic local HTTP Suite/IdP fixtures. They prove cold preparation has zero case/outbox/target sends, normal and subsequent actions share one cookie context, fresh/passive isolation remains intact, timeouts preserve the same page with poll-only resume, and an unrelated Recorder Response cannot pass the guard. They use no real product, user credential or conformance adoption. Neither synthetic tests nor a successful collector run reduce the canonical unresolved count; formal original-backed product acceptance remains necessary.

`synthetic_normal_browser_runtime_smoke.mjs --execute <fresh-output>` separately exercises a single owned actual Suite Run at localhost:18080 with an ephemeral in-memory signing fixture and `startTests: false`. Its new `ReadSyntheticNormalBrowserScope` reads only that explicitly named synthetic Run through SQLite `mode=ro`/`query_only`, counts all case executions and outbox rows before preflight and after empty evaluation, then exports the two actual M0 originals with independent Redirect, Response and Assertion signature verification. It copies only public helper classes and public Suite metadata to a fresh owned `/tmp` directory; cleanup uses Suite exec user 0 solely for those Docker-copied public files. It never starts formal cases or qualifies subsequent case-session behavior. After a pre-M0 harness failure, `--existing-created <public-created.json>` can continue the same untouched CREATED Run after native zero-state verification, without creating another Plan/Run. API originals pass strict duplicate-key/UTF-8/size and recursive public-field validation before retention; malformed/non-public/HTML bodies are omitted. This fixture harness is a separate calibration tool, not a product configuration adapter.
