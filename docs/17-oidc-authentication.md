# Administrative OIDC login

Status: account-only authorization, local user roles, and an admin page are implemented.
The current change requires independent review and renewed G2 approval for its signed
runtime boundary. UserInfo integration, Back-Channel Logout, and acceptance against a
live Authrim provider remain deferred. The Authrim UserInfo contract is documented below;
OP-managed expiry and deletion webhooks are the selected direction, with the webhook
contract still under coordination.

SAMLscope uses the generic Nimbus OAuth/OIDC library, not an Authrim SDK. The provider
authenticates the user; SAMLscope controls local account roles and Plan access. Authrim
as a login provider is independent of its role as a SAML test target.

## Access and roles

When OIDC is enabled, management requires an authenticated local account. Secret URLs
are disabled regardless of the legacy `SAMLSCOPE_OIDC_ACCESS_POLICY` value. Existing
secret exchanges and session resumptions are rejected; management cookies grant no
access. New Runs have revoked, credential-free placeholder grant records and ordinary
`/manage/{run}` links without secret fragments. Publicly published reports remain public.
With OIDC disabled, the existing self-hosted/Hosted secret-URL behavior remains.

| Local role | Own Plans and Runs | Other users | Other users' Plans and Runs |
|---|---|---|---|
| `ANONYMOUS` | Create, view, operate, delete | No access | No access |
| `USER` | Create, view, operate, delete | No access | No access |
| `ADMIN` | Create, view, operate, delete | View, edit local display name/role, delete | View Plans and Run evidence; delete Plans |

Admin does not gain permission to execute tests, alter evidence, publish results, or
create Runs under somebody else's Plan. Admin's normal Plan list includes all Plans.
The `/admin` page provides user and Plan lists, search, versioned account edits and
explicit deletion confirmation. All `/api/admin/*` endpoints independently check the
current database role. Mutations require the application's Origin and OIDC CSRF token.
The last active admin cannot be deleted or demoted. Management mutations are serialized
with role changes/deletion within the supported single application process.

A local user is keyed by the SHA-256 fingerprint of the exact, length-delimited
`issuer + sub` pair. Plan ownership and target connections use the same fingerprint.
Login never claims pre-existing unowned or secret-URL Plans. Legacy OIDC owners are
backfilled as general users; unowned Plans remain accessible to admin for review/deletion.
The raw subject, tokens, and email are not persisted. Local display names and roles are
not placed in results, Run context or Transcripts.

New logins default to `USER` until reliable provider account information is integrated.
`ANONYMOUS` means a provider-authenticated anonymous account, not a visitor without login.
Admins can edit the local role. No ID-token role, display name or email grants admin.
Normal login does not overwrite local role/profile edits.

## Initial admin

Set `SAMLSCOPE_OIDC_BOOTSTRAP_ADMIN_SUBJECT` to the exact RP-visible `sub` of the intended
operator in `/etc/samlscope/oidc.env`, before that account's first login with this user
registry. The configured issuer must also match. This is an explicit operator choice,
never “first visitor becomes admin.” Existing OIDC Plan owners that have not yet enrolled
in the local registry can also be bootstrapped on their first login after migration.

After that login, the admin role persists in SQLite. Remove the bootstrap setting after
verifying `/admin`. Leaving it configured never re-promotes a previously enrolled user
who was subsequently demoted or deleted. If the intended user already enrolled without
the setting, another admin must promote them, or the operator must perform a reviewed,
offline database recovery. No public bootstrap or role-escalation endpoint exists.

## Authrim account lifecycle — selected specification (2026-09-11)

**Authrim (the OP) owns time-based account deletion.** SAMLscope does not independently
schedule account deletion from its own inactivity clock. Authrim is expected to notify
SAMLscope by webhook when deleting an account; this webhook contract is **under
coordination**, not an implemented or verified integration.

This supersedes the earlier requirement to expire anonymous accounts/application data
based on 30 days without SAMLscope application use. Do not infer Authrim's retention
period or its renewal rules from that previous local policy. The OP's lifecycle state
and `deletion_due_at` describe the OP's schedule; passing that timestamp is not a
completed-deletion notification.

### UserInfo request and response

The dedicated scope is **`account:lifecycle:read`**. Request it during authorization,
then call Authrim's UserInfo endpoint with the issued access token:

```ini
scope=openid account:lifecycle:read
```

```http
GET /userinfo
Authorization: Bearer <access_token>
```

`/userinfo` denotes the endpoint on the configured Authrim provider, not a SAMLscope
route. The RP integration should use that provider's discovered UserInfo endpoint.
This scope returns lifecycle information, not the values of all profile fields.
An example response is:

```json
{
  "sub": "user-subject",
  "authrim_account_lifecycle": {
    "registration_state": "guest",
    "status": "active",
    "created_at": 1789084800,
    "deletion_due_at": 1791676800,
    "upgrade_eligible": true,
    "profile_complete": false
  }
}
```

| Field | Meaning |
|---|---|
| `sub` | RP-visible user identity; correlate with the authenticated issuer and ID-token subject |
| `registration_state` | `guest` for an anonymous account, `registered` after formal registration |
| `status` | Operational account status, separate from registration state; unavailable accounts may produce an error instead |
| `created_at` | Account creation time in Unix seconds |
| `deletion_due_at` | OP deletion eligibility time in Unix seconds, or `null` when not scheduled; not proof that deletion has completed |
| `upgrade_eligible` | Whether upgrade is currently available for this account and requesting client |
| `profile_complete` | Whether required profile fields are present; does not include their values |

Conditions and behavior of the supplied Authrim implementation:

- The access token must actually have the granted `account:lifecycle:read` scope.
  Without it, `authrim_account_lifecycle` is omitted. The `claims` parameter and claim
  mapping cannot bypass this restriction.
- The client's `guestAuth.allowedScopes` must permit the requested scopes. Its default
  allowlist is `openid` and `account:lifecycle:read`; guest authentication itself is
  disabled by default. Additional scopes, including `profile`, require explicit permission.
- `upgrade_eligible` can be true only for the client that created the guest account and
  when an upgrade method is allowed by both tenant and client. Email registration also
  checks readiness, including proof protection and notification delivery. Readiness
  lookup failure is an error, not optimistic eligibility.
- After registration, the same object is returned with `registration_state: "registered"`,
  `deletion_due_at: null`, and `upgrade_eligible: false`. The provider preserves `sub`
  during upgrade, so Plan ownership remains attached to the same issuer/subject identity.
- Reading UserInfo does not extend retention or upgrade the account. Passing
  `deletion_due_at` does not immediately invalidate access: deletion is asynchronous.
  Deleting/deleted accounts return HTTP `401` with `invalid_token` instead of this object.
- This object is not added to ID tokens. The scope grants no mutation permission.
  Device/agent identities do not receive this human account lifecycle object.

Source references in the Authrim repository, supplied by the user and checked locally:
`packages/ar-userinfo/openapi/userinfo.openapi.yaml` (`AccountLifecycle`, line 324),
`packages/ar-lib-core/src/services/guest-client-policy.ts` (default policy, line 4),
`packages/ar-userinfo/src/account-lifecycle.ts` (claim construction, line 15), and
`packages/ar-userinfo/src/userinfo.ts` (scope enforcement/error handling, line 329).
These references describe the local Authrim implementation, not live-provider acceptance.

### SAMLscope integration requirements

UserInfo integration remains deferred. On implementation, retrieve lifecycle data on the
server using the granted access token and require its `sub` to match the validated
ID-token subject. Do not expose the provider token to React or persist it in Run state,
results or Transcripts. Missing scope/claim, unknown values and lookup failures must not
be interpreted as proof of a guest account, an upgrade, or a completed deletion.
A generic `401 invalid_token` also does not establish account deletion; tokens may be
invalid for other reasons.

Map verified `guest`/`registered` state to anonymous/general account classification.
`ADMIN` remains a separately controlled SAMLscope privilege: this claim cannot grant
admin. Precedence between provider registration updates and manual local role overrides
must be settled during integration; do not silently demote admins on a UserInfo refresh.
No profile-update API or registration/upgrade endpoint is specified by this read scope.

### Deletion webhook — under coordination

The intended flow is OP-managed account expiry/deletion, followed by an authenticated
notification to SAMLscope. SAMLscope will reconcile its local account/session state and
clean up the associated application data. The existing intended cleanup scope includes
owned Plans, Runs, evidence, keys, target connections and published reports; deleted
public reports must cease to be accessible. SAMLscope does not request time-based OP
account deletion itself.

The following are integration requirements/open contract points, not claims about
Authrim's current webhook implementation:

- Event name, payload schema and schema version; whether delivery denotes deletion
  start or completed deletion, and when SAMLscope may perform irreversible cleanup.
- Authenticated issuer/tenant and RP-visible subject correlation, including pairwise
  subjects. An internal OP account ID must not be assumed to equal the RP's `sub`.
- Webhook authentication/signature verification, key rotation, replay protection,
  event identifiers and idempotent processing.
- Retry/acknowledgement behavior, durable receipt, and reconciliation of missed,
  duplicate or out-of-order events, including a registration upgrade near expiry.
- Session invalidation, restart-safe local data cleanup and failure recovery; treatment
  of the last local admin and whether any deletion tombstone is retained.

Do not implement a guessed event name or delete data from `deletion_due_at` alone.
Back-Channel Logout remains a separate deferred feature; logout notifications are not
account-deletion events. Ordinary Run/Transcript retention and backup policies are
separate from OP account lifecycle and must be reconciled during implementation.

### Current implementation gap and superseded local expiry

This specification update changes documentation only. The earlier local implementation
still records `last_used_at`, displays a local 30-day anonymous expiry in the UI, reports
`anonymousExpiryCandidates`, and includes the guarded offline
`--anonymous-confirmations` deletion interface. **These are superseded behavior, not the
selected OP-driven lifecycle integration.** Do not enable that interface as a substitute
for the forthcoming deletion webhook. The default timer supplies no confirmations and
automatic anonymous-account cleanup remains paused.

A follow-up implementation must replace the local expiry calculation/UI copy with the
OP lifecycle information and agreed webhook processing. The existing non-anonymous
private-Run and published-Transcript retention mechanisms remain separate. Current
anonymous-Run exemptions also need review against the OP-driven cleanup policy.

Explicit admin deletion currently removes a local profile and all owned live data while
retaining its fingerprint in `deleted_user_ids` to block re-enrollment. It does not
modify the OP account. Failed cleanup leaves status `DELETING` and can be retried.
Whether OP webhook deletion uses the same tombstone/last-admin rules is still to be
agreed. Backups are not rewritten by live deletion.

## Provider configuration and persistence

Register a confidential web client using Authorization Code flow with PKCE S256 and
this exact redirect URI (substitute the configured application origin for other installs):

```text
https://app.samlscope.com/auth/callback
```

The current code still requests `openid profile`; the lifecycle integration specified
above will require `openid account:lifecycle:read` (and explicit guest-client permission
for any additional scope). UserInfo, refresh tokens, offline access,
provider-wide logout and Back-Channel Logout are not implemented in this revision.
The logout button terminates only the local SAMLscope session. Back-Channel Logout may
be added later; a logout token will never imply data/account deletion.

| Variable | Default | Meaning |
|---|---|---|
| `SAMLSCOPE_OIDC_ISSUER` | Unset; disabled | Exact issuer, including tenant path |
| `SAMLSCOPE_OIDC_CLIENT_ID` | None | Registered confidential web client |
| `SAMLSCOPE_OIDC_CLIENT_SECRET` | None | Operator-supplied secret |
| `SAMLSCOPE_OIDC_CLIENT_AUTH_METHOD` | `client_secret_basic` | Also supports `client_secret_post` |
| `SAMLSCOPE_OIDC_SIGNING_ALGORITHM` | `RS256` | Also supports `PS256` and `ES256` |
| `SAMLSCOPE_OIDC_ACCESS_POLICY` | `optional` | Legacy accepted values: `optional`, `new_plans`, `required`; all enforce account-only access when OIDC is enabled |
| `SAMLSCOPE_OIDC_BOOTSTRAP_ADMIN_SUBJECT` | Empty | Exact first-enrollment admin subject; never logged |

No OIDC variables means disabled. Partial configuration fails startup. Application and
Test Peer must use different hostnames; the application origin, discovery, token and JWKS
endpoints require HTTPS with normal certificate validation. The Test Peer's relaxed TLS
settings do not apply to login. Discovery issuer/endpoints are validated at startup;
restart after changing provider configuration.

Install [the configuration example](../deploy/oidc.env.example) as
`/etc/samlscope/oidc.env` with mode `0600`, outside the checkout and Docker build context.
Compose reads it separately from the image-version `.env` rewritten by `deploy.sh`, so
CI image updates preserve provider/client settings. Compose 2.24.0 or later is required
for the optional env file. `/srv/samlscope/data` is mounted at `/data` and preserves SQLite,
user roles/activity, Plan ownership and evidence across updates. The deploy script backs
up data before replacing the container. Credentials must not be committed to the repository.

## Protocol and session behavior

`GET /auth/login` starts login. `GET /auth/callback` consumes a browser-bound, five-minute
state exactly once, exchanges the code with PKCE, validates the ID token, and redirects
to `/`. Nimbus validates signature, issuer, audience, expiry, issue time and nonce;
SAMLscope additionally checks `azp`, non-empty subject and future `nbf`. Unsigned/encrypted
ID tokens are rejected. JWKS refresh supports rotation; back-channel HTTP has timeouts,
size limits and no redirects. Provider error details and tokens are not echoed or logged.

`GET /auth/session` returns current local role, user identifier, display name and CSRF token.
`POST /auth/logout` invalidates the local session and clears login/management cookies.
Authentication and admin responses use `no-store`. React never receives provider tokens.

The `__Host-samlscope-login` cookie is Secure, HttpOnly and SameSite=Lax with Path=/ and
no Domain. Sessions have an absolute eight-hour lifetime and bounded in-memory storage.
Application restart signs users out; their local accounts and ownership survive.
Role changes are read from SQLite on each request. Deleted/deleting accounts cannot use
existing sessions, and SSE rechecks authorization before sending subsequent Run events.
Multi-instance sessions and organization sharing remain outside this implementation.

## Verification and approval boundary

Protocol fixtures exercise signed tokens, PKCE, key rotation, invalid claims, replay,
browser binding and CSRF. Account/admin tests cover secret URL rejection in all legacy
policies, ownership isolation, read-only cross-owner admin access, role changes, last-admin
protection, deletion and restart persistence. Tests for the superseded local retention
implementation cover public-report deletion, missing/stale confirmations, account upgrades
and resumed activity; they do not verify the new OP-managed deletion/webhook contract.

These are local automated fixtures, not evidence of acceptance against a deployed Authrim
provider. The application wiring is within the signed G2 boundary; independent review and
renewed signed approval are required before release. Existing approvals and specification
catalogs must not be edited to bypass this boundary. See [release readiness](13-release-readiness.md).
