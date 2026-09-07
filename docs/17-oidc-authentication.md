# Administrative OIDC login

Status: implementation prepared; independent review and renewed G2 approval are required
before merging or releasing the signed-boundary changes. Authrim live-provider acceptance
has not yet been performed.

SAMLscope uses the generic Nimbus OAuth/OIDC library, not an Authrim SDK. A configured
OIDC provider authenticates the user; SAMLscope authorizes access to Plans and Runs.
Authrim is a deployment choice, independent of its role as a SAML test target.

## Selected requirements — follow-up decisions

These decisions supersede the initial access/sharing assumptions below. They are
requirements for the next implementation revision, not claims about the current code.

- Decision 1:A: non-public Plans and Runs are accessible only to their owner. Secret
  URLs must not provide an alternative sharing/authorization path in this configuration.
  Existing published-report visibility is a separate policy.
- Decision 2:A: allow provider-authenticated anonymous users and guide them to formal
  registration for continued access. The provider preserves `sub` on upgrade, as confirmed
  by the user; ownership therefore remains attached to the same issuer/subject pair.
- Decision 4:B: anonymous-user data expires after 30 days without application use.
  Formal registration removes the user from anonymous-specific expiry. Reconcile this
  policy with existing Run retention before implementation; authentication activity alone
  is not a reliable measure of application use.
- Decision 5:B: expiry covers all of that anonymous user's SAMLscope data, including
  published reports. Disclose expiry when publishing; expired public URLs cease to work.
  SAMLscope does not request deletion of the Authrim account under this policy.
- Decision 6:A: the logout button terminates the local SAMLscope session only. Receive
  standard OP Back-Channel Logout notifications to invalidate matching local sessions.
  Logout notifications never imply account or application-data deletion. RP-Initiated
  Logout is not part of the selected behavior.
- Authrim account lifecycle is a separate Authrim follow-up: consider both authorized
  deletion APIs and optional automatic anonymous-account cleanup, with a common deletion
  event path. Its implementation and exact integration contract remain outside this change.

Proposed lifecycle design: SAMLscope owns the expiry/deletion of its own application data;
the provider owns anonymous-account status and upgrade/deletion events. Standard `sub`
does not identify an anonymous account. A verified, configurable claim mapping and/or
an authenticated lifecycle integration is needed. Event names such as `user.upgraded`
and `user.deleted` are proposed contract examples, not verified Authrim event names.
Events must identify the same issuer and RP-visible subject used by OIDC, including
pairwise-subject handling. Authenticate events, deduplicate them, and reconcile missing
or out-of-order notifications. Before irreversible anonymous-data deletion, confirm the
current account state; do not delete on a stale anonymous claim or failed status lookup.
A formal-registration event cancels pending anonymous expiry. Published reports follow
decision 5:B. Any additional behavior on provider-account deletion needs its own policy;
neither deletion path is a logout-token side effect. Until reliable anonymous/upgrade
state is available, do not enable destructive anonymous-specific cleanup.

Back-Channel Logout can use standard OIDC and needs no Authrim SDK. Register the RP's
back-channel endpoint and verify signed logout tokens, issuer/audience, time, event type,
replay policy, and sid/sub targeting. Retain the OP session identifier when supplied.
To initiate OP logout from SAMLscope, use RP-Initiated Logout in addition to receiving
back-channel notifications. Verify support in the deployed provider's discovery and
client registration. References: [Back-Channel Logout](https://openid.net/specs/openid-connect-backchannel-1_0.html)
and [RP-Initiated Logout](https://openid.net/specs/openid-connect-rpinitiated-1_0.html).

## Configuration

Register a confidential web client in the provider with Authorization Code flow and
PKCE S256 enabled. Register this exact redirect URI:

```text
https://app.samlscope.com/auth/callback
```

For another installation, substitute its configured `SAMLSCOPE_PUBLIC_BASE_URL` origin.
The callback URI is derived from that setting, never from request headers. The requested
scopes are `openid profile`; the signed ID token's optional `name` is for display only.
UserInfo, refresh tokens, offline access, and Authrim-specific APIs are not required.

| Environment variable | Default | Meaning |
|---|---|---|
| `SAMLSCOPE_OIDC_ISSUER` | Unset; OIDC disabled | Exact issuer, including any tenant path; must match discovery and token `iss` |
| `SAMLSCOPE_OIDC_CLIENT_ID` | None | Registered web client ID |
| `SAMLSCOPE_OIDC_CLIENT_SECRET` | None | Confidential client secret, supplied by the operator |
| `SAMLSCOPE_OIDC_CLIENT_AUTH_METHOD` | `client_secret_basic` | Also supports `client_secret_post`; must match the registered client |
| `SAMLSCOPE_OIDC_SIGNING_ALGORITHM` | `RS256` | Also supports `PS256` and `ES256`; must match the client/provider signing configuration |
| `SAMLSCOPE_OIDC_ACCESS_POLICY` | `optional` | See the access policy table below |

Set no `SAMLSCOPE_OIDC_*` variables to disable OIDC. Partial configuration fails startup;
it never silently falls back to anonymous access. Discovery is fetched at startup, and
startup fails if discovery or its issuer/endpoint validation fails. Restart after
changing issuer, client settings, or discovery endpoints.

The application origin must use HTTPS. App and Test Peer must use **different hostnames**,
even in self-hosted mode: cookies are not isolated by TCP port. OIDC discovery, token,
and JWKS endpoints require HTTPS with normal certificate validation. The Test Peer's
relaxed TLS/private-network options do not apply to login. Private HTTPS identity
providers are supported; the operator controls the trusted issuer configuration.

For the supplied Hosted Compose profile, install the contents of
[`deploy/oidc.env.example`](../deploy/oidc.env.example) as `/etc/samlscope/oidc.env`
on the server, set the real issuer/client values, and restrict the file to the operator
(mode `0600`). The optional file is loaded by Compose and is not overwritten by
`deploy.sh`, which manages the separate image-version `.env`. Keep actual credentials
outside the source checkout and Docker build context. This profile needs Docker Compose
2.24.0 or later for an optional `env_file`; see the
[Compose documentation](https://docs.docker.com/compose/how-tos/environment-variables/set-environment-variables/).
No deployment or credential registration is performed by this implementation change.

## Access policy and ownership

| Policy | Create a new Plan | Existing secret URL / Run session |
|---|---|---|
| `optional` | Anonymous or signed in | Works without login |
| `new_plans` | Login required | Works without login |
| `required` | Login required | Login also required; the Run capability still grants access to that Run |

`optional` preserves D-09's anonymous-use path. Deployment policy remains an operator
choice. Publicly published reports remain public in all modes; publication still follows
the existing Hosted-only rules.

- A Plan created while signed in belongs to the exact `issuer + sub` identity. All Runs
  of that Plan inherit account access. Another user cannot read or mutate it by guessing
  an ID. Authentication does not grant global administration privileges.
- Ownership is stored atomically with Plan/initial Run creation as a length-delimited
  SHA-256 identity fingerprint with the `oidc:` prefix. The existing
  `hosted_plan_owners` table holds these fingerprints as well as anonymous quota owners.
  Only the `oidc:` identity namespace can grant account access; IP-derived anonymous
  fingerprints never do so. Raw subjects, email addresses, and login tokens are not
  copied into Run context, result artifacts, or Transcripts.
- The Plan list contains owned Plans and, when present, the Plan accessible through the
  browser's existing Run capability. Possessing a secret URL does not transfer ownership.
  Logging in does not claim existing anonymous Plans.
- The secret URL remains an independent sharing capability. In `required` mode a recipient
  must also log in, but does not have to be the Plan owner. Do not share the link when
  account-only access is intended.
- Self-hosted deployments with OIDC enabled also protect management APIs and create the
  initial Run/capability with the Plan. Existing unowned self-hosted data is **not** assigned
  to the first person who logs in. Establish a migration policy before enabling OIDC on
  an existing shared data directory. With OIDC disabled, prior self-hosted behavior remains.

## Browser and server behavior

`GET /auth/login` starts a login. `GET /auth/callback` consumes the response exactly once,
exchanges the code using PKCE, verifies the ID token, then redirects to `/`.
`GET /auth/session` returns login availability, display name, and a CSRF token.
`POST /auth/logout` signs out of SAMLscope. Authentication responses are `no-store`.
There is no arbitrary return URL parameter.

Login attempts expire after five minutes and are bound to a random, host-only browser
cookie. ID tokens must be signed with the configured algorithm. Nimbus verifies the
signature, issuer, audience, expiry, issue time, and nonce; SAMLscope also enforces `azp`
consistency, non-empty subject, and a future `nbf` check. Unsigned/encrypted ID tokens
are not accepted. JWKS are cached and refreshed for key rotation. Back-channel responses
have timeouts and a size limit; HTTP redirects are rejected. Provider error text and token
contents are not exposed in error responses or application exception logs.

The login session cookie is `__Host-samlscope-login` (`Secure`, `HttpOnly`, `SameSite=Lax`,
`Path=/`, no Domain). It is separate from Run-management and Test Peer state. Login sessions
have an eight-hour absolute server-enforced lifetime. Pending logins and sessions are
bounded in-memory stores; a process restart signs users out, while SQLite Plan ownership
survives. This implementation is for one application process, consistent with the current
single-instance deployment.

Account-authorized mutations require both the application `Origin` and the session's
`X-OIDC-CSRF-Token`. Existing capability-authorized mutations retain `X-CSRF-Token`.
React receives no ID/access/refresh token. Tokens from the code exchange are discarded
after identity verification. Sign out invalidates the OIDC session and clears browser
login/Run cookies. It does not revoke a separately shared secret URL or its server-side
capability, and does not sign the user out of the provider or other applications.

## Verification and approval

Automated fixtures exercise real signed ID tokens, PKCE code exchange, key rotation,
invalid claims/signatures, browser-state binding, replay rejection, CSRF, cross-user
access, policy modes, anonymous links, and ownership across application restart. These
are protocol fixtures, not evidence of acceptance against a deployed Authrim or Keycloak.

Verification of this implementation on 2026-09-07:

| Check | Result |
|---|---|
| `./gradlew check` using Java 21 | PASS, including OIDC integration and React tests |
| `g1_docgen.py --check` / `g1_validate.py --structural-only` | PASS |
| `g1_ci_verify.sh` with the repository CI pin | PASS, signed approval and source comparison |
| `g2_validate.py` / pinned `g2_ci_verify.sh` | BLOCKED only by `G2-30`, the changed signed boundary listed below |
| Hosted Compose configuration validation | PASS; no deployment performed |

The dependency selection is Nimbus `oauth2-oidc-sdk` **11.38.2**, with
`nimbus-jose-jwt` **10.9.1**. Official
[SDK documentation](https://connect2id.com/products/nimbus-oauth-openid-connect-sdk) and
[Maven artifacts](https://central.sonatype.com/artifact/com.nimbusds/oauth2-oidc-sdk/11.38.2)
were checked. On 2026-09-07, OSV queries for the newly added runtime packages/versions
returned no reported vulnerabilities. The Snyk package-health connector was unavailable;
this is not a complete Snyk health assessment. Gradle SHA-256 verification entries were
generated for the new artifacts; existing entries were retained.

The change necessarily modifies these signed G2 boundary files:

- `api/src/main/java/com/samlscope/api/SamlScopeApplication.java`
- `api/build.gradle.kts`
- `gradle/libs.versions.toml`
- `gradle/verification-metadata.xml`

`G2-30` therefore rejects the working tree until independent review and renewed signed
approval are completed. Do not edit the old approval record, relax protected paths, or
report this working tree as G2-approved. Specification catalogs and test-design artifacts
are unchanged. See [release readiness](13-release-readiness.md#current-verification-limit).

## Deployment decisions still to make

Choose the production issuer/client registration and access policy. Initially all users
who can authenticate to that provider's registered client may create their own Plans;
restrict client access at the provider if invitation-only use is desired. Organization
sharing, account roles, anonymous-Plan ownership transfer, provider-wide logout, and
multi-instance sessions are separate future features, not assumptions made here.
