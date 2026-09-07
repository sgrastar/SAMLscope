# 07. Distribution and Networking Requirements

## 1. Single Docker Image

The policy in the original memo (not implementing separate Cloudflare Workers and Docker versions) is correct.
Use the **same image, same Test Runner, and same evaluation logic** for the Hosted and self-hosted versions.

```bash
docker run \
  -p 8080:8080 \
  -v samlscope-data:/data \
  -e SAMLSCOPE_PUBLIC_BASE_URL=https://app.samlscope.com \
  -e SAMLSCOPE_PEER_BASE_URL=https://peer.samlscope.com \
  samlscope/suite:0.1.0
```

- Base image: distroless or Alpine + JRE 21
- Multi-architecture: `linux/amd64`, `linux/arm64` (many developers use Apple Silicon)
- All state under `/data` (SQLite files, generated keys, Transcript)
- Run as a non-root user

### Environment variables

| Variable | Default | Description |
|---|---|---|
| `SAMLSCOPE_PUBLIC_BASE_URL` | `http://localhost:8080` | **Most important**. The URL at which the Suite is externally visible. All metadata endpoint URLs are generated based on this |
| `SAMLSCOPE_MODE` | `selfhosted` | `selfhosted` / `hosted` |
| `SAMLSCOPE_DATA_DIR` | `/data` | |
| `SAMLSCOPE_HTTP_PORT` | `8080` | |
| `SAMLSCOPE_TLS_CERT` / `_KEY` | None | When terminating TLS directly |
| `SAMLSCOPE_OUTBOUND_ALLOW_PRIVATE` | `true`(selfhosted) / `false`(hosted) | Whether to allow back-channel connections to private IP addresses. See [08](08-suite-security.md) |
| `SAMLSCOPE_OUTBOUND_ALLOW_INSECURE_TLS` | `false` | Whether to accept the target's self-signed certificate |
| `SAMLSCOPE_PUBLISH_ENABLED` | `false`(selfhosted) / `true`(hosted) | Whether to issue shared URLs |
| `SAMLSCOPE_TRUSTED_PROXY_ADDRESS` | None | One numeric reverse-proxy peer address. Required in hosted mode; forwarded client addresses are ignored from every other peer |
| `SAMLSCOPE_RUN_RETENTION_DAYS` | `30` | |

During migration from the former product name, the runtime variables consumed by the application
also accept their `SAMLIER_*` aliases. If both names are present they must have exactly the same value;
conflicting definitions make startup fail instead of silently changing the security mode. The aliases
are deprecated and operators should migrate to `SAMLSCOPE_*`.

## 2. ★ Networking Requirements (The Most Important Omission in the Original Memo)

“Just run `docker run -p 8080:8080` and open `http://localhost:8080`”
**works only for front-channel testing**.

### There are two network paths

```
(A) Front channel (via browser)
    Browser ──▶ Suite      The Suite can run on localhost
    Browser ──▶ Target     Both only need to be reachable from the browser

(B) Back channel (direct server-to-server)
    Target ──▶ Suite       ★ The Suite must be reachable from the Target
      - Retrieving metadata / MDQ      (IIP-MD01–MD04, MD07, MD10-12)
      - Single Logout via SOAP          (IIP-SP14, IIP-IDP17)
    Suite ──▶ Target       The Target must be reachable from the Suite
      - Retrieving the Target's metadata
      - ECP / PAOS                      (IIP-IDP13–16)
      - SOAP SLO
```

**The `(B)` direction, `Target → Suite`, does not work with `http://localhost:8080`.**
As shown by the aggregation in [04](04-requirement-coverage.md), tests requiring configuration on the Target side account for approximately 40% of the total,
and many of them require this path.

### ★ Reachability cannot be determined by Preflight alone

The reachability of `Target → Suite` is **not proved even if the Suite itself can connect to its public URL**.
It can fail because of factors invisible from the Suite, such as NAT, split-horizon DNS, the Target-side egress firewall, or the Target's proxy configuration.

Therefore, **asserted** and **confirmed** must be distinguished.

```
Preflight (what the Suite can do independently)
  ├ Can the Suite connect to its own PUBLIC_BASE_URL?
  ├ Can the Suite connect to the Target metadata URL?
  └ Result: reachability = ASSERTED  (it only means “probably reachable” so far)

Reachability challenge (involving the Target)
  ├ The Suite embeds a one-time nonce in the metadata URL
  ├ Instruct the user: “Reload the metadata on the Target side” (WAITING_CONFIG)
  ├ The Suite observes an inbound request to the nonce-bearing URL in the Transcript
  │   (also recording the source IP, User-Agent, and TLS information)
  └ Result: reachability = CONFIRMED
```

**A case declaring `requires.reachability: target_to_suite` must not run until it becomes `CONFIRMED`** ([05 §2.2](05-test-definition-format.md)).
If it remains `ASSERTED`, it becomes `NOT_VERIFIED(target_unreachable)`, and for a MUST obligation, this results in `conformance = INDETERMINATE` / `completeness = INCOMPLETE` ([03 §7.2](03-test-model.md)).

For paths such as SOAP SLO that do not involve metadata retrieval,
promote the path to confirmed **when the first inbound SOAP request is observed**.

### Operating modes

| Mode | Condition | Tests that can run |
|---|---|---|
| **Local-only** | `PUBLIC_BASE_URL` is localhost. The reachability challenge cannot succeed | Front-channel only. Metadata is distributed manually. IIP-MD01–04, etc. are `NOT_VERIFIED(target_unreachable)` |
| **Reachable (asserted)** | The Suite has a seemingly reachable URL, but no inbound request from the Target has yet been observed | Front channel + Suite-initiated back channel (Target metadata retrieval, ECP, SOAP sending) |
| **Reachable (confirmed)** | An inbound request from the Target has actually been observed | All tests |
| **Hosted** | Official Hosted version. The Target is on the Internet | **Reachability confirmation is also required for Hosted**. The Suite having a public URL does not mean that the Target's egress can reach the Suite (Target-side firewall, proxy, or allowlist). Back-channel tests remain `NOT_VERIFIED(target_unreachable)` in Hosted until they become `CONFIRMED`. An internal IdP cannot be tested in the first place |

When creating a Test Plan, the UI displays the current mode and
**warns in advance, with a count, “In this configuration, N MUST obligations will currently be unverified.”**
When the challenge succeeds, reduce the count in real time.

### Ways to obtain a reachable URL (to be documented in the README)

1. Run the Suite on a host with a public IP / internal DNS (recommended)
2. Place it behind a reverse proxy (nginx / Caddy) and set `PUBLIC_BASE_URL` to the actual URL
3. Obtain a temporary URL through a tunnel (`cloudflared tunnel` / `ngrok`)
   → **Consider bundling this in Phase 2 as an optional profile for `docker compose`**
4. Use the official Hosted version (only when the Target is reachable from the Internet)

## 3. ★ HTTPS Requirements

- Many SPs / IdPs **reject `http://` ACS URLs / SSO URLs** (many implementations enforce this in their configuration)
- Due to the browser default for `SameSite` cookies, **cookies may be dropped on cross-site POSTs (HTTP-POST binding).
  `Secure` + `SameSite=None` is required, which requires HTTPS**
- Therefore, **HTTPS is practically mandatory**

Options:

| Method | Use |
|---|---|
| TLS termination at a reverse proxy | Production-like self-hosting. Recommended |
| Direct termination with `SAMLSCOPE_TLS_CERT` / `_KEY` | Standalone operation |
| Generate and bundle a self-signed certificate | Local development. Warn that trust must be configured in both the browser and the Target |
| Tunnel | Temporary use |

Preflight **must issue a warning** when `PUBLIC_BASE_URL` is `http://` and is not localhost.

## 4. ★ Time

If the container clock is skewed, **all tests will fail** (`NotOnOrAfter` / `IssueInstant` / `validUntil`).

- At startup, measure the difference from an external NTP source or HTTP `Date` header, and **warn at startup if it is off by one minute or more**
- During Preflight, compare the `Date` header from the Target metadata retrieval with the local clock and record the difference in the Run
- Test code must not use `System.currentTimeMillis()` directly; it must go through `TestContext.clock()`
  (to intentionally manipulate time in clock-skew tests)

## 5. Additions for the Hosted Version

The image is the same, with features enabled by `SAMLSCOPE_MODE=hosted`.

| Feature | Reason |
|---|---|
| Rate limiting / concurrent execution limits | Abuse prevention |
| Prohibit outbound connections to private IP addresses | SSRF protection ([08](08-suite-security.md)) |
| Public result storage | Shared URLs |
| Administrative access | Phase 1 uses **a per-Run secret URL** (no account login). A Hosted Plan-creation request also creates the initial Run; all subsequent Plan and Run reads or mutations require that Run session. Optional standard OIDC login and account ownership are implemented, pending renewed G2 approval; see [17](17-oidc-authentication.md). [09 D-09](09-open-decisions.md) |
| Automatic deletion after the retention period | |

The bundled Caddy configuration accepts `CF-Connecting-IP` only when the immediate
sender belongs to Cloudflare's published address ranges. For all other senders, it
overwrites `X-Forwarded-For` with the direct client's numeric address. Keep the configured
Cloudflare ranges current. Its Compose network fixes the host gateway to `172.30.0.1` and configures
that exact address as `SAMLSCOPE_TRUSTED_PROXY_ADDRESS`. The application ignores forwarded
addresses from every other peer. If the default subnet conflicts with the host network, set
both `SAMLSCOPE_DOCKER_SUBNET` and `SAMLSCOPE_DOCKER_GATEWAY`; the gateway is propagated to
the application's trusted-proxy setting.

The VPS serves only the `app` and `peer` origins; the apex website and `www` redirect
remain on Cloudflare Workers. Caddy uses ACME HTTP challenges through the proxy.
The container keeps its root filesystem read-only and general `/tmp` non-executable.
SQLite JDBC uses a separate owner-only executable tmpfs to load its native library.

self-hosted has no authentication (it is intended for use within a trusted network).
**State this explicitly in the README**. Instruct users to put authentication in front of it when exposing it to the Internet.

## 6. Suitability of Starting with SQLite

- Sufficient for single-user self-hosted use
- As concurrency increases in the Hosted version, write contention may become a problem (substantially mitigated by WAL mode)
- **Mitigation**: confine data access to a thin repository layer, leaving room to replace it with PostgreSQL.
  Manage it with plain SQL + migration files without using an ORM
- Store large data such as Transcripts **as files under `/data` rather than in the database**, keeping only references in the database

## 7. Separation of the Login SP / OIDC RP and Test Peer

When adding login through Authrim or similar to the Hosted version, **the same process will contain both a “test SP” and a “login SP/RP.”** The Test Peer’s job is to
“receive and observe” even invalid Assertions, so its validation is **intentionally relaxed**.
If an administrative session is created from an Assertion that arrives there, that becomes an authentication bypass.

Protect the structure from Phase 1 onward. The OIDC implementation additionally requires distinct app/peer hostnames because cookies are shared across ports; see [17](17-oidc-authentication.md).

- Separate the session stores, Cookie names, and code paths for `peer/` (testing) and `auth/` (administration)
- **Serve them from separate origins**: `app.<domain>` (UI + administration) and `peer.<domain>` (Test Peer endpoints)
- Add `SAMLSCOPE_PEER_BASE_URL` alongside `SAMLSCOPE_PUBLIC_BASE_URL`
- **A separate origin is mandatory in `SAMLSCOPE_MODE=hosted`**. If the origins are the same, make startup fail
- If unset in self-hosted, fall back to the same origin and **issue a startup warning**
  (do not break a simple configuration in a closed network). The normative level is [08 §5](08-suite-security.md)

See [09 D-09](09-open-decisions.md) for details.
