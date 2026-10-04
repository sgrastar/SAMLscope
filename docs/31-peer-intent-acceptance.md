# Target-initiated message acceptance (2026-09-15)

This batch creates evidence for IdP-initiated SSO and target-initiated logout, which the Suite cannot initiate directly. It follows the ALG04/06 producer-oracle batch (`eec07cdd`) and baseline commit `f653393413204cf9549e4175695ddc09f9598d56`. Implementation, verification and deployment were local; no publication or push occurred in this batch.

## Implementation

- `TargetInitiatedIntents`: single-use preparation intents (`UNSOLICITED_SSO` / `TARGET_LOGOUT`), Run consumption, TTL, unique Run resolution within a Plan, rejection of ambiguity and expiry on process restart.
- `SpPeerService`: accepts unsolicited Responses without RelayState, or resolves a Plan to its sole waiting Run, only with a prepared intent. Validates Issuer, Destination, Success and single use; otherwise preserves rejection.
- `SloPeerService`: accepts a target-initiated LogoutRequest without Run correlation only when the Plan has exactly one `TARGET_LOGOUT` intent. Validates Issuer and consumes the intent.
- API: `GET/POST /api/runs/{id}/target-initiated`, state/preparation, no-store, existing Run authorization and CSRF.
- UI: preparation panel, RelayState and waiting state in browser_sso_idp and single_logout_idp workspaces.
- `LogoutBrowserEvidenceTestCase`: completed NOT_VERIFIED cases can be reevaluated after new Transcript evidence.
- SLO observation decrypts NameID/SessionIndex from encrypted Assertions with Run keys before comparison, enabling IDP17-n/u observation after encrypted login.
- Adversarial outbound requests containing DOCTYPE no longer stop all normal-flow observation. Unparseable inbound responses still produce uncertainty.

## Observed results

| Case | Product | Result | Evidence |
|---|---|---|---|
| IIP-SSO01-g | Keycloak / Shibboleth | Success | Assertions in both SP-initiated and IdP-initiated successful Responses |
| IIP-SSO01-z | Keycloak / Shibboleth | Warning | Observed unsolicited successful Response |
| IIP-SSO01-k | Shibboleth | Success | Bearer confirmation at another ACS, including recipient and expiry |
| IIP-IDP17-j/k/l/m | Shibboleth | Success | Target LogoutRequest Issuer count/value/format/signature |
| IIP-IDP17-t | Shibboleth | Failed (Product) | Target LogoutRequest NotOnOrAfter precedes session expiry; approved known FAIL |
| IIP-IDP17-n | Shibboleth | Not verified | Identifier strong match remains unproven after decryption |
| IIP-IDP17-u | Shibboleth | Not verified | NotOnOrAfter/session-expiry correlation remains unproven |

<!--g1-literal--> Unverified observations fell from 559 to 546; distinct IDs from 180 to 179. This includes six Keycloak browser observations (ALG04.a/ALG06.a/ALG06.c/ALG06.d/SSO01-g/SSO01-z), three Shibboleth browser observations (SSO01-g/k/z), two Keycloak ECP observations (ALG04.a/ALG06.a after AES128-GCM + rsa-oaep-mgf1p configuration and PAOS registration, restored afterward), and two SimpleSAMLphp ALG06.a browser/ECP observations (assertion.encryption=true in Suite SP metadata, RSA-OAEP-MGF1P key transport; CBC content encryption leaves ALG04 unresolved; configuration restored). Shibboleth IDP17-j/k/l/m/t were not in the baseline unresolved set and are not counted as reductions.

A Shibboleth AES256-GCM + rsa-oaep(1.1) trial added custom EncryptionConfiguration to global.xml and restarted Tomcat, but old/new Tomcat processes conflicted and observation stayed at AES128-GCM. Processes and settings were restored; metadata HTTP 200 confirmed health. No additional conclusion was counted.

## Product behavior and Suite gaps

- Keycloak IdP-initiated SSO starts through an administration-API URL-name registration and RelayState; `IIP-SSO01-g/z` passed. Neither administration-session termination nor OIDC logout delivered a SAML LogoutRequest to Suite. A container-reachable SOAP SLO URL also did not establish delivery, so target-initiated logout remains unverified.
- SimpleSAMLphp provided no IdP-initiated SSO start URL in the investigated implementation, which requires AuthnRequest. Its target-initiated logout also did not reach Suite.
- Suite gaps resolved here: incoming target-message correlation, single-use intents, completed-NOT_VERIFIED reevaluation, encrypted-Assertion decryption and DOCTYPE-request isolation.
- Remaining investigations: Keycloak target-initiated logout reachability/product propagation, and availability of a SimpleSAMLphp IdP-initiated path.

## Operation accounting

Only this 2026-09-15 batch was measured. Docker restarted once; Suite/forward containers were recreated after implementation changes approximately six times. The first full build was corrupted during Docker Desktop restart and not adopted.

| Product | Setting writes | Restorations | Reloads | Changes |
|---|---:|---:|---:|---|
| Keycloak | 11 | 2 | 0 | Algorithm phases/default restoration, IdP-initiated URL name and SOAP SLO URL |
| Shibboleth | 4 | 2 | 1 | Temporary persistent NameID settings/restoration in saml-nameid.properties, NameIdentifierGenerationService reload and Tomcat restart |
| SimpleSAMLphp | 0 | 0 | 0 | None |

Keycloak attribute deletion did not take effect, so original observed defaults were explicitly restored: AES256-GCM / rsa-oaep / sha256 / mgf1sha256. saml_idp_initiated_sso_url_name and the SOAP SLO URL remain registered; their purpose/current values are recorded under `build/acceptance/reference-20260915/peer-intent/keycloak/`. Direct user operations: zero.

## Shibboleth persistent NameID trial

`IIP-SSO05-a` / `IIP-SSO05-a2` require successful persistent responses; defaults reject these requests with Requester. Temporarily set idp.persistentId.sourceAttribute=uid and useUnfilteredAttributes=true in saml-nameid.properties, reloaded the generation service and restarted Tomcat, confirming property loading. Two browser retests still rejected all three persistent requests with SubjectCanonicalizationError because the subject canonicalization flow was absent. Restored the before configuration and confirmed metadata HTTP 200 after restart. Both cases remain unverified, with the next action to establish c14n prerequisites before retesting; no product FAIL. Evidence: `build/acceptance/reference-20260915/peer-intent/shib-config/diagnosis.json`.

## Unimplemented SLO browser oracles at this checkpoint

The fourteen product-specific cases `IIP-IDP17-b/b1/b2/c/r/s/x/y/z/aa/al` and `IIP-IDP18-b/c/d` in each product's single_logout_idp lacked Suite observations and ended browser.oracle-unavailable. They require Suite-generated asynchronous SLO, wrong Destination, invalid-signature acceptance controls, propagation timeout and Redirect-only SLO advertisements. These are implementation gaps, not missing IdP responses or user actions. Reasons were classified suite-observation-gap, not product FAIL. Shibboleth `IIP-IDP17-n/u` had target messages; remaining reasons identify strong match and NotOnOrAfter correlation.

## Evidence and limits

result.json, report.html, transcripts, logs and configuration backups are under ignored `build/acceptance/reference-20260915/peer-intent/`. G2-30 remained unresolved; this batch is not independent approval. The [complete inventory](26-unverified-case-inventory.md) and [comparison](23-reference-test-comparison.md) were updated through their generators.
