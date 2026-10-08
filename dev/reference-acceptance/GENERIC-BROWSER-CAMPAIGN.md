# Generic browser campaign collector

`generic_browser_campaign.mjs` drives the Suite's existing browser/outbox path for an arbitrary IdP. It contains no Keycloak, Shibboleth or SimpleSAMLphp management API, default password, product configuration path, or verdict mapping.

The operator first registers the Suite peer metadata in the target and completes the Run's normal SSO control. The collector requires an existing result and a Recorder-owned, correlated `normalFlowAccepted` Success before starting tests. `RUNNING` or a standalone Success is insufficient. Initial registration, native configuration read-back and eventual restoration belong to the normal preparation adapter; this collector neither changes nor attests to product settings.

Use an empty ignored evidence directory and a public task file:

```json
{
  "suiteBaseUrl": "http://localhost:18080",
  "runId": "run_0123456789ABCDEFGHJKMNPQRS",
  "planId": "plan_0123456789ABCDEFGHJKMNPQRS",
  "targetOrigins": ["https://idp.example"],
  "caseIds": ["IIP-SSO01-ep-idp-01", "IIP-SSO01-f-idp-01"],
  "startTests": true,
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

There is no selected-tests start API. `/tests/start` starts the full approved profile. The collector proves selected IDs exist in the actual Run, then prepares and aborts other actions at the Suite without following redirects, running HTML or submitting to the target. The output records the full-profile start call and membership count and marks the unavailable public-API queue-change count as unmeasured, never as zero. Use `startTests: false` only when the normal preparation path already started that profile. A live `AWAITING_RESPONSE` action is left intact; the collector does not restart it because an observation poll expired.

All fixtures of a selected case continue while Runner records terminal observations. In particular SSO01.f retains its normal control, unknown NameID Format, unrecognized Subject, and fresh passive request. A target HTTP error is reported from a real browser navigation with its body explicitly omitted. It cannot prove assertion absence, VersionMismatch, or an approved native terminal exception; these f/ep/d paths remain unverified. This observation lets the regular scenario progress to its next fixture instead of aborting the whole case. An observation timeout retains the same live action, stops collection, and exports its handle without aborting, retrying or invoking formal evaluation. A network exception never creates an invented HTTP status. No operator completion answer or self-attestation is submitted. Public SAML originals are retained on failed collection attempts, with no Recorder qualification when its transcript could not be fetched. Browser closure is recorded only after the browser disconnects; it does not terminate or attest to completion of a pending Suite action.

Only original SAML request/response bytes are captured. HTTP-Redirect requests are not reconstructed before sending. Browser originals retain Run/case/action provenance and remain supplemental evidence until their hash and action are matched to a unique Recorder original. Current Recorder exports normally omit the decoded SHA-256, so `original-captured-recorder-hash-unavailable` is an expected unqualified state; native acceptance export/verification must establish byte equality independently. The collector never relabels transcripts, adds missing saved cases, changes case digests, or adopts a result into the ledger. The Suite's official evaluation is exported unchanged.

`IdpErrorAssertionRecordedEvidenceTestCase` gives SSO01.f a pure formal re-evaluation path. It validates the original ordered request graph, exact probe XML, configured request-signing policy, Response correlation, target issuer, ACS destination and present signatures. Unsigned OPTIONAL transport is retained; it does not add a new signature obligation. Success requires every error path and the positive assertion control; HTTP, missing paths and successful abnormal requests cannot satisfy it. Both plain and encrypted assertions on an actual error are counterexamples. It does not claim that separate requests share an authentication session: Recorder intentionally excludes cookies. The ordinary start/resume sequence remains deterministic and outbox-only, and an original-free delegate success fails closed.

Run the policy/correlation tests with Node's built-in runner:

```sh
node --test dev/reference-acceptance/test_generic_browser_campaign.mjs
SAML_SCOPE_PLAYWRIGHT=/absolute/path/to/installed/playwright \
  node --test dev/reference-acceptance/test_generic_browser_campaign_integration.mjs
./gradlew :runner:test --offline \
  --tests com.samlscope.runner.cases.IdpErrorAssertionRecordedEvidenceTestCaseTest
```

The integration test uses real headless Chrome against synthetic local HTTP Suite/IdP fixtures. It proves session reuse, fresh-context isolation and byte capture without any real product, user credential or conformance adoption. Neither synthetic tests nor a successful collector run reduce the canonical unresolved count; formal original-backed product acceptance remains necessary.
