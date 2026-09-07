# 09. Decision Log

`✅` = Decided / `⏸` = On hold / `★` = Must be decided first

**The only remaining undecided matter is D-15 (operation of the Hosted version).** Implementation from M0 through M3 does not depend on it.

---

## ✅ D-01. Project Name / Repository Name — **Decision: SAMLscope**

| Item | Value |
|---|---|
| Product name | **SAMLscope** |
| Tagline | `SAMLscope — SAML Conformance Test Suite` |
| Repository | **`github.com/sgrastar/samlscope`** (under a personal account for the time being) |
| Java package | `com.samlscope.*` |
| Docker image | `samlscope/suite` |
| Environment-variable prefix | `SAMLSCOPE_` |

Because it is a coined name, the risk of conflict with trademarks or existing projects is low. The functionality is conveyed by the tagline.
(Rejected: `samlconf` = poor searchability, `saml-conformance-suite` = easily confused with codice/saml-conformance,
`samltest` = conflicts with Shibboleth's SAMLtest.id)

### Namespace availability (checked 2026-08-25)

| Namespace | Status | Notes |
|---|---|---|
| GitHub repo `sgrastar/samlscope` | ⏳ Rename required | Rename the existing repository before enabling deployment |
| GitHub org/user **`samlscope`** | Not assessed | A dedicated organization is optional; the personal repository is sufficient initially |
| GHCR `ghcr.io/sgrastar/samlscope` | Planned | Published automatically from verified `main` builds |
| Docker Hub **`samlscope`** | Not assessed | Not required for the initial GHCR-based deployment |
| npm / PyPI `samlscope` | Not assessed | No public package publication is currently planned |
| `samlscope.com` | ✅ Acquired | Primary production domain |
| Other TLDs | Not assessed | Not required for the initial deployment |

**Response to the unavailable GitHub org**: `sgrastar/samlscope` is fine for now.
Once the community has grown, create an org such as `samlscope-project` and transfer the repository.
GitHub redirects the old URL after a transfer, so migration costs are low.

> **Do now**: Rename the GitHub repository and configure its `production` environment before
> enabling the deployment workflow.

## ✅ D-02. License — **Decision: Apache-2.0**

The same as OpenSAML / Santuario. It includes patent provisions and is the de facto standard for identity-infrastructure OSS.
It is easy for vendors to integrate into their own CI, encouraging adoption.

**Constraint**: [codice/saml-conformance](https://github.com/codice/saml-conformance) is **LGPL-3.0**.
Referencing its design and testing perspectives is permitted, but **do not copy its code**.
Read `ctk/idp/NotTested.md` (a list of requirements that cannot be externally verified) only as a reference for its approach.

Contributor handling: adopt DCO (`Signed-off-by`) and require no CLA (to lower the barrier to contribution).

## ✅ D-03. First Phase 1 release (v0.1) — **Decision: C = Complete Phase 1**

v0.1 targets all IIP v1.1 requirements (Common 31 + SP 17 + IdP 21),
**including Single Logout and ECP**.

> **Implication**: The first release will take longer. Divide the work into internal milestones to make progress visible.
> See the milestones section of [01-scope-and-roadmap.md](01-scope-and-roadmap.md).
>
> However, the UI's **Quick Run mode** (which skips tests requiring reconfiguration of the target side
> and checks only the SSO core in 10 minutes) is mandatory in v0.1.
> A complete scope must not result in a first-run experience that takes an hour.

## ✅ D-04. Trust Model for Published Results — **Decision: Level 0 + Level 2**

| Level | Implementation |
|---|---|
| Level 0 — LOCAL | ✅ Results from self-hosted runs are exported locally only as `result.json` / `report.html` |
| Level 1 — ATTESTED UPLOAD | ❌ **Rejected**. Forged JSON could be uploaded, reducing the value of all results |
| Level 2 — HOSTED RUN | ✅ Issue shared URLs only for results from runs executed on the official Hosted version. The Suite retains the Transcript |

`SAMLSCOPE_PUBLISH_ENABLED` becomes `true` only in `hosted` mode;
even if enabled in a self-hosted build, it **will not appear on the official results domain**.

> **Implication**: Operating a Hosted version becomes necessary in Phase 1.
> The domain, hosting provider, authentication, and deletion-request contact must be decided (D-09, D-15).

---

## ✅ D-05. Web Framework — **Decision: Javalin + Jetty**

**Technical constraint**: Signature verification for SAML's HTTP-Redirect binding requires the
**raw query string before URL decoding** (the bytes of `SAMLRequest=...&RelayState=...&SigAlg=...`
are themselves the signed data). Parsing and reconstructing the parameters breaks verification.
HTTP-POST likewise requires the raw base64. → [02 §3.5](02-architecture.md)

Reasons for choosing Javalin:
- Small dependency footprint and a lightweight image. Straightforward access to the raw request (`ctx.req().getQueryString()` / raw body)
- Built-in SSE support (progress streaming for Test Runs)
- The framework code is thin, keeping the reader's attention on the SAML processing itself

Things to provide ourselves (included with Spring Boot):

| Function | Policy |
|---|---|
| Configuration | Environment variables + a simple configuration class. Do not add a configuration library |
| DI | Write constructor injection by hand. Do not add a DI container |
| Scheduler | `ScheduledExecutorService` (retention deletion, periodic metadata retrieval) |
| Validation | Hand-written. The API schema is small |
| Migration | Plain SQL files + a manually maintained version table |

> Fix the **prohibition on URL normalization by filters / proxies** in tests at the beginning of implementation.
> If normalization that converts `%2F` back to `/` is introduced, the Suite will distribute false signature-verification judgments.

## ✅ D-06. Frontend — **Decision: React + Vite**

It has the largest ecosystem, with libraries for XML / code viewers, diff displays, and virtual scrolling (for large result trees).
Contributors are also easier to find.

Main elements of the Phase 1 UI:
- Test Plan creation form (configuration declaration, `declared_features`, `parameters`)
- Test Run progress (SSE; interactive UI for `WAITING_BROWSER` / `WAITING_CONFIG` / `WAITING_ATTEST`)
- Result tree (requirement → case → judgment rationale → Transcript → raw XML)
- XML viewer (formatting, highlighting, highlighting of signed elements)
- Pre-publication preview (review of masked results)

`report.html` (a self-contained single HTML file) will be **a static build of the same React application
with the result JSON embedded**. Do not create a separate implementation.

## ✅ D-07. Build Tool — **Decision: Gradle (Kotlin DSL)**

It provides straightforward multi-module and npm-build integration (`com.github.node-gradle`),
and makes task dependencies such as the static build of `report.html` easy to express. Incremental builds are also fast.

Responsibilities of the build:

```
:core :saml :peer :runner :tests :api      Java 21 multi-module
:tests:defs   → Embed YAML in resources + incorporate consistency checks (05 §5) into check
:web          → Vite build. Place artifacts in :api resources
:web:report   → Single HTML build for embedding result JSON (same React application)
:dist         → Docker image (jib or Dockerfile). amd64 / arm64
```

`./gradlew check` **must include consistency checks for test definitions** (1:1 correspondence between YAML and implementations,
and comparison against the coverage table). If this is a CI-only script, broken code can be sent in a PR while still broken locally.

## ✅ D-08. Repository Structure — **Decision: Single repository**

Place the backend / frontend / test definitions all in `github.com/sgrastar/samlscope`.

Splitting test definitions into another repository would make it impossible to enforce in CI the
**“1:1 correspondence between YAML and implementation classes”** designed in [05 §5](05-test-definition-format.md).
Because a change in specification interpretation affects both test definitions and logic, being able to change them in the same PR is valuable.

If, in the future, another project wants to reuse only the test definitions,
**distribute `tests/defs/**` and `tests/coverage.yaml` separately as release artifacts**
(separate the artifacts, not the repository).

## ✅ D-09. Hosted-Version Authentication — **Decision: No authentication + secret URL (future OIDC/SAML login via Authrim)**

### Phase 1

Display the administrative secret URL only once when creating a Run. In Hosted mode, the Test Plan creation
request also creates the initial Run so that the caller receives a credential before any Plan or Run can be
listed or mutated. Creating later Runs and reading or changing the Plan require a valid session belonging
to an existing Run in that Plan. Use the secret URL for evidence management, publication, and deletion.
This provides the lowest barrier to use. Counter bot activity with rate limiting (per IP) + Turnstile or equivalent.

#### ★ Handling the secret (incorporating review finding 11)

**Do not put it in a query parameter.** Queries remain in browser history, access logs,
`Referer` from the same origin, screenshots, and shared URLs.

```
Completely separate the public ID and administrative token:

  Result URL   https://app.samlscope.com/results/01K3ZQ8N…        (public ID only)
  Manage URL   https://app.samlscope.com/manage/01K3ZQ8N…#t=<token>
                                                     ^^^^^^^^^^
                                                     fragment (not sent to the server)
```

| Measure | Content |
|---|---|
| Separate ID and token | `runId` is an identifier that may be public. The administrative token is an unrelated high-entropy value (at least 128 bits) |
| Storage format | **Store the token hashed** (`SHA-256`) so that a database leak cannot be used to obtain the token |
| Transfer | Receive it in the initial URL's **fragment**, then have JS exchange it via `POST /api/manage/session` for an **HttpOnly + Secure + SameSite=Strict Cookie** |
| ★ Removal from history | The fragment is not sent to the server, but **remains in browser history, bookmarks, and restored tabs**. Immediately after reading the value, **before network processing**, JS must remove the fragment with `history.replaceState(null, "", location.pathname)`. Execute this regardless of whether the exchange succeeds |
| ★ CSP | Strict CSP on the management screen. Explicitly specify `script-src 'self' 'nonce-{random value per response}'`; do not use `'unsafe-inline'` / `'unsafe-eval'` / `'strict-dynamic'`. A complete example is in [08 §5](08-suite-security.md) |
| ★ Origin separation | On Hosted, separating `app.<domain>` and `peer.<domain>` is **MUST** ([08 §5](08-suite-security.md)). Refuse startup if they have the same origin |
| ★ Origin verification | `POST /api/manage/session` verifies the `Origin` header and rejects anything other than `app.<domain>` |
| `Referrer-Policy` | `no-referrer` on both the management and results pages |
| External resources | Do not place externally sourced resources (images, scripts, iframes) on the management screen |
| CSRF | Cookie session + CSRF token for `publish` / `delete` / `unpublish`. Do not rely only on `SameSite=Strict` |
| Rotation | Allow the token to be reissued from the management screen. Invalidate the old token immediately |
| Revocation | Delete the token when the Run is deleted or its retention period expires |
| Logs | A fragment is not included in access logs, but **if a token arrives in a query, immediately return 400 and do not record it** (to detect misuse) |
| Brute force | Rate-limit per `runId`. Compare tokens in constant time |

> Because `peer.<domain>` and `app.<domain>` are separated ([08 §5](08-suite-security.md)),
> content originating from the target that reaches the Test Peer cannot access the administrative Cookie.

### Use Authrim as the login IdP

Implementation update (2026-09-07): standard OIDC login and account-owned Plans are
implemented using a generic library, with no Authrim SDK dependency. Integration into
the signed startup/build boundary requires renewed G2 approval. Configuration, anonymous
access policies, and remaining deployment choices are in [17](17-oidc-authentication.md).

Use Authrim (OIDC or SAML) for login to the Hosted version.
**There are two design cautions here.**

**Caution 1 — Do not add Authrim-specific dependencies to the code.**
The non-goal in [00-concept.md](00-concept.md), “do not include any Authrim-specific code,” remains in force.
What SAMLscope implements is a **standards-compliant OIDC RP (or SAML SP)**;
Authrim is merely a deployment choice. It must be possible to point it at Keycloak or Auth0 through configuration.
Depending on Authrim-only endpoints or proprietary claims would violate the principle.

**Caution 2 — ★ Completely separate the login SP and the Test Peer.**
If SAMLscope logs in as a SAML SP, **the “Test SP for testing” and the “SP for login”
will coexist in the same process**. This is dangerous.

| | Test Peer (`/p/{plan}/sp/...`) | Login SP (`/auth/...`) |
|---|---|---|
| entityID | Issued per Test Plan | One fixed SAMLscope value |
| Keys | Generated per Test Plan, plaintext in `/data` | Operational keys. **Manage separately** |
| Signature verification | **Intentionally lax** (its job is to “receive and observe” invalid signatures) | Strict. Same as a normal SP |
| Session | Disposable for testing | Has SAMLscope administrative privileges |
| Assertion acceptance | Accept and record even aggressive Assertions | Pass all normal validations |

Because **Test Peer verification is intentionally lax**, creating a SAMLscope login session from an Assertion that arrives there would be an authentication bypass. Observe the following:

- Use separate code paths, separate session stores, and separate Cookie names
- **Use separate origins** (`app.samlscope.com` and `peer.samlscope.com`). This matches the policy in [08 §5](08-suite-security.md)
- Make OIDC the first choice for the Login SP (using SAML increases the confusion caused by coexistence)
- Retain the secret-URL method after introducing OIDC login (to preserve the migration path and anonymous use)

> Secondary benefit: having SAMLscope log in through Authrim's OIDC/SAML provides dogfooding for Authrim's implementation. However, README must make clear that **Authrim as SAMLscope's test target is an entirely separate matter**, so this does not appear to be a conflict of interest.

## ✅ D-10. Machine-Readable Requirement Catalog — **Decision / Implemented: `tests/coverage.yaml` is authoritative**

[04-requirement-coverage.md](04-requirement-coverage.md) is **generated from `tests/coverage.yaml`** and must not be edited by hand.
**Implemented during the G1 creation phase** (`tools/g1_build.py`).

The schema is at the **obligation level** ([05 §2.1](05-test-definition-format.md) is authoritative).
`level` / `testability` / `level_assignment` all attach to obligations.

```yaml
# tests/coverage.yaml
spec: kantara-fedinterop-impl
version: "1.1"
requirements:
  - id: IIP-MD04
    section: "2.2.1"
    anchor: IIP-MD04
    obligations:
      - key: IIP-MD04.a
        roles: [idp, sp]
        level: MUST
        condition: null
        summary_en: "Reject metadata whose root element lacks a validUntil attribute"
        testability: CONFIG
        level_assignment: { idp: core, sp: core }
      - key: IIP-MD04.b
        roles: [idp, sp]
        level: MUST
        summary_en: "Reject metadata whose validUntil is in the past"
        testability: CONFIG
        level_assignment: { idp: core, sp: core }
      - key: IIP-MD04.c
        roles: [idp, sp]
        level: MUST
        summary_en: >
          Reject metadata whose validUntil is further into the future than the
          implementation's configured limit; that limit must be configurable
        testability: CONFIG
        level_assignment: { idp: core, sp: core }
```

> **Correction**: The schema example in the previous version was still at the requirement level (`level: [MUST]` / `applies_to`).
> It conflicted with the decision on the Obligation layer in D-03, so it was replaced (review finding 12).

Using this as the source of truth:
- Generate `04-requirement-coverage.md` (`./gradlew :docs:generateCoverage`)
- Verify in CI that “every requirement in `phase1: full` has at least one test case”
- Have the UI results screen obtain requirement metadata (level / section / summary) from here

> Hand-written Markdown tables inevitably diverge from reality. Do not manually maintain <!--g1:requirements-->69<!--/g1--> requirements × 5 columns.

## ✅ D-11. Scope of Quoting the Original Specification — **Decision: ID + Original Summary + Link to Original Anchor**

**Do not reproduce** the requirement text from the Kantara document. Put the following in test definitions and the results screen:

1. Requirement ID (`IIP-MD04`)
2. A **short English summary written by us** (`spec.quote_summary` / `summary_en`)
3. A link to the relevant anchor in the original
   (`https://kantarainitiative.github.io/SAMLprofiles/fedinterop.html#IIP-MD04`)
4. Explicit document name, version, publication date, and publisher

This is legally safest and can proceed immediately.

**Do in parallel**: Ask the Kantara Initiative whether embedding the original requirement text is permitted.
If permission is granted, design the system so it can switch simply by adding `quote_full` to the `spec` block
(retain the summary field, with the original as an optional addition).

**Known drawback**: In offline environments or isolated networks, the original supporting text cannot be read.
`report.html` will also contain only summaries and links. Accept this limitation until the inquiry is approved.

## ✅ D-12. Publication of Reference-Implementation Results — **Decision: Publish as Version-Pinned Samples**

| Purpose | Policy |
|---|---|
| SAMLscope's own regression detection | Run Keycloak / Shibboleth IdP / SimpleSAMLphp periodically in CI (GitHub Actions) and **detect result changes internally** |
| ★ Proof of detection power | **Use mutant peers, not reference implementations** ([00 §5](00-concept.md)). “Differences among three products” has been removed from the completion criteria |
| External presentation | Publish **sample results pinned to specific versions**. They demonstrate “what this report looks like” and will not be continuously updated |

Always include with a public sample:

- The target version and acquisition date (`Keycloak 26.0.5, tested 2026-09-01`)
- A statement that “this is a point-in-time measurement against a specific version and does not represent the current state”
- The Test Plan configuration used (`declared_features` / `parameters`)
- The standard wording “This is not a certification” ([06 §3](06-results-and-publication.md))

> Publishing nightly results continuously would continually expose other vendors' FAIL results,
> creating tension with the policy of “not calling ourselves a certification body.” The liability of false judgments would also be substantial.
> **Run CI, but limit publication to fixed samples** to resolve this tension.

Feedback to implementers should be provided through **issues / PRs for each project**, not public reports.

### ★ Reference implementations are not the oracle of detection power

The condition “results differ among three products” was a completion criterion, but has been **withdrawn**.
No difference does not indicate a defect in the Suite (all products may conform,
or a difference may be no more than a configuration difference).
**Prove detection power with mutant peers** ([00 §5](00-concept.md)).
The role of reference implementations is **regression detection and interoperability verification**.

### ★ Scope that can run in CI (resolving the conflict with browser automation)

[01](01-scope-and-roadmap.md) excludes browser automation in Phase 1,
but because **<!--g1:case_target-->543<!--/g1--> obligations include <!--g1:tb_browser-->216<!--/g1--> `BROWSER` obligations, Full Profile cannot run in unattended CI**.
Separate the scopes to eliminate the conflict.

| Purpose | Scope | Browser |
|---|---|---|
| **CI (per PR / periodic)** | <!--g1:tb_automated-->96<!--/g1--> `AUTOMATED` obligations + **mutant peer golden tests** | Not required |
| **Periodic execution of reference implementations** | `AUTOMATED` subset only | Not required |
| **Full Profile** | All <!--g1:case_target-->543<!--/g1--> obligations | **Required**. Run manually and publish as fixed samples |

**Decision: Do not introduce browser automation such as Playwright in Phase 1.**
Limit CI to the `AUTOMATED` subset and mutant golden tests.
(Introducing browser automation in Phase 2 would allow the CI scope to expand.)

### Pinning reference implementations (create by M4)

```yaml
# tests/reference-impls.yaml
- id: keycloak
  roles: [idp, sp]                              # ★ Per-role matrix
  image: quay.io/keycloak/keycloak@sha256:…     # ★ Pin by digest (tags move)
  config_fixture: tests/fixtures/keycloak/
- id: shibboleth-idp
  roles: [idp]
  image: "…@sha256:…"
- id: simplesamlphp
  roles: [idp, sp]
  image: "…@sha256:…"
```

Pin images by digest and place configuration fixtures in the repository.
If results change due to environmental differences, they cannot function as regression detection.

## ✅ D-13. Language Support — **Decision: English only**

The Phase 1 UI, reports, test definitions, and public documentation are English only.
Do not reserve language-specific fields in the canonical schema.

```
CI required:  title, instructions, expected, (attestation.question)
```

Adding another language later requires an explicit schema and design revision. Do not introduce dormant language slots now,
because they would reintroduce non-English canonical field names immediately after the English-only migration.

## ✅ D-14. Numerical Interpretation of “reasonable” — **Decision: Use an intermediate value by default, configurable in the Test Plan**

Defaults adopted by SAMLscope for requirements without a numeric value in the specification.

| Requirement | Default | Judgment |
|---|---|---|
| **IIP-G01** clock skew | `clock_skew_tolerance_seconds: 180` | **FAIL** if a ±180-second difference is rejected (the lower bound that should be tolerated). **Do not judge an upper bound** (separate it as an advisory; see below) |
| **IIP-MD04.c** validUntil too distant | ★ **Do not set a threshold on the SAMLscope side** (below) | Judge at the **boundary** of the target's configured threshold |

> **SAMLscope will not set an upper bound for clock skew either.** The original text (IIP-G01)
> merely requires that “reasonable skew can be tolerated” and
> **does not define a non-conformance condition for tolerating too much**.
> Accepting an extremely large skew is recorded as `clock_skew.very_permissive` in
> [04 §Advisory](04-requirement-coverage.md) as **information that does not affect the judgment** (the previous version made it WARNING without support in the original text).

#### ★ SAMLscope must not set the threshold for IIP-MD04.c (review finding 5)

The original MUST is *reject metadata if `validUntil` is too far into the future (**configurable**)*,
and the obligations are that **the threshold be configurable** and **rejection based on that configuration be possible**.
The SAMLscope-specific absolute threshold “FAIL if more than 90 days is accepted” is stricter than the original
and would incorrectly FAIL a product configured with a 365-day threshold.

Correct procedure:

```
① Have the user set the target product's “validUntil upper limit” to an arbitrary value T (WAITING_CONFIG)
   → If this is impossible, follow the [common judgment procedure in 03 §4](03-test-model.md).
      `configuration_failure_semantics: normative_capability`
      (because the ability to configure a threshold is itself part of the obligation).
      The case returns an outcome; Evaluator converts it to a Verdict based on level
② Suite distributes metadata with validUntil = now + T − δ  → Should be accepted
③ Suite distributes metadata with validUntil = now + T + δ  → Should be rejected
   δ is Test Plan's metadata_boundary_delta_hours (default 24h)
④ Record the adopted T and δ in the result JSON
```

**Do not FAIL because of SAMLscope's convenience.**
Do not treat “the user cannot answer” as the product's non-conformance (follow the three branches in the common judgment procedure).

Basis (clock skew only):
- **180 seconds** matches the default clock skew of Shibboleth / SimpleSAMLphp and is easy to explain

Provide three safety measures.

1. **Everything can be changed in the Test Plan** (`parameters`)
2. **Always record the adopted values in the result JSON** (`configuration` in [06 §1](06-results-and-publication.md))
3. **State in the report that “this is SAMLscope's interpretation, not a provision of the specification”**

> A stricter value (±60 seconds / 7 days) would be desirable for security, but would be stricter than existing implementations in practice,
> causing frequent FAIL results and undermining trust in the report as a whole.
> A looser value (no judgment) would effectively leave IIP-G01 / MD04 untested.
> Intermediate values + parameterization + recording resolve this tension.

## ⏸ D-15. Operation of the Hosted Version — **Production launch pending**

Because Level 2 was adopted, the official Hosted version is included in the Phase 1 deliverables.

### Domain — decided

`samlscope.com` has been acquired and is the primary production domain.

### Subdomain structure

Align with [09 D-09](#-d-09-hosted-version-authentication--decision-no-authentication--secret-url-future-oidcsaml-login-via-authrim)
and the separate-origin policy in [08 §5](08-suite-security.md).

```
samlscope.com           Redirect to the Hosted application; future project site / documentation
app.samlscope.com       Hosted-version UI and administration (future OIDC login also here)
peer.samlscope.com      Test Peer endpoint (surface reached by the target) ★ separate origin
results.samlscope.com   Reserved for future separately served published results
```

Reason for separating `peer`: Test Peer is designed to receive and observe invalid Assertions as well,
so content arriving there must not touch the management UI's session.

### Other decisions

| Item | Options |
|---|---|
| Hosting | Initial deployment profile: VPS + Docker + Caddy; provider provisioning pending |
| Cost | Personally funded / GitHub Sponsors / Open Collective |
| Operating policy | Terms of use, deletion-request contact, retention period ([06 §5](06-results-and-publication.md)) |

> The Hosted version can test only IdPs/SPs reachable from the Internet.
> **Testing an internal IdP requires self-hosting**, and those results cannot become shared URLs.
> This asymmetry must be explained clearly in the README
> (the audience that “wants to test an internal system” differs from the audience that “wants to publish results”).

M4 implementation exists; this decision now gates production launch. Retention,
complete deletion, and restore acceptance still require work. See
[release readiness](13-release-readiness.md) and [operations](15-hosted-operations.md).
