# SAMLscope

SAMLscope is an open-source black-box conformance test suite for SAML identity providers (IdPs) and service providers (SPs). It currently targets the [Kantara SAML V2.0 Implementation Profile for Federation Interoperability v1.1](docs/04-requirement-coverage.md).

SAMLscope drives standard SAML and metadata endpoints, records redacted Transcripts, and evaluates observable evidence. It does not use vendor administration APIs as conformance evidence and does not ask operators to decide PASS or FAIL. Evidence that cannot be obtained is reported as `NOT_VERIFIED`, not silently excluded or treated as target failure.

## Test coverage

- SAML requests, responses, assertions, identifiers, bindings, signatures, and encryption
- browser SSO, ForceAuthn, IsPassive, NameIDPolicy, ACS selection, and proxy processing
- single logout, ECP, channel binding, and SAML Enhanced Client extensions
- metadata acquisition, trust, refresh, key rollover, MDQ, discovery, and algorithm declarations
- IdP and SP Core and Full profiles

Cases produce an `outcome`; the central Evaluator combines it with the approved requirement level to produce `PASS`, `WARNING`, `FAIL`, or an unresolved result. See the [test model](docs/03-test-model.md) and [case format](docs/05-test-definition-format.md).

## Evidence plans

The plans are cumulative and differ only in evidence depth.

| Plan | Evidence | Operator involvement |
|---|---|---|
| **Quick** | Protocol-observed | Follow login, consent, logout, or Continue steps. SAMLscope evaluates the resulting SAML, metadata, browser result, and Transcript. |
| **Standard** | Quick + operator-assisted | Make requested configuration or metadata-refresh changes. SAMLscope determines the outcome from subsequent observations. |
| **Full** | Standard + self-attested | Supply grouped evidence only for behavior that standard external interfaces cannot establish. |

One action can provide evidence to multiple cases. The UI reports both case coverage and remaining deliberate user actions. Self-attested evidence is always shown separately from externally verified evidence.

## Status

The signed G1 requirement catalog and signed G2 case design are complete. The application implements IdP/SP Test Peers, browser and metadata workflows, SLO, ECP, evidence campaigns, result JSON, self-contained HTML reports, and hosted result publication controls.

External-observation coverage and reference implementation acceptance testing continue to improve. Capabilities that cannot be observed remain explicit `SELF_ATTESTED` or `NOT_VERIFIED` rather than being guessed.

Current acceptance status and remaining launch work are tracked in the [release checklist](docs/13-release-readiness.md), [reference matrix](docs/14-reference-acceptance.md), and [operations preparation](docs/15-hosted-operations.md). Production hosting is not yet ready.

## Requirements

- Java 21
- Node.js 20.19 or later for frontend development
- Docker or Apple Container, only when using a containerized deployment or the Keycloak fixture

## Run from source

```bash
./gradlew check
SAMLSCOPE_IMAGE_DIGEST="sha256:<digest-of-the-build-you-are-running>" \
SAMLSCOPE_DATA_DIR="$PWD/data" ./gradlew :api:run
```

Open <http://localhost:8080>. Runtime state, generated Test Peer keys, cached metadata, and redacted Transcripts are stored below `SAMLSCOPE_DATA_DIR`.

## Run a test

1. Create a Test Plan for an IdP or SP that you are authorized to test.
2. Enter its entity ID and metadata URL, then run **Preflight**.
3. Register the displayed SAMLscope Test Peer metadata in the target.
4. Start the initial browser round trip and use a non-production test account.
5. Run or resume M1, M2, and M3 as required by the selected evidence plan.
6. Follow the operation prompts. SAMLscope completes protocol-driven cases when correlated evidence arrives.
7. Review the result and export `result.json` or the self-contained `report.html`.

Use a fresh/private browser context when instructed. Positive and negative controls must both have sufficient evidence before an evaluative case can complete.

### Result terminology

- **Externally verified**: derived from Suite-observed SAML, browser, metadata, or Transcript evidence.
- **Self-attested**: based on operator-supplied evidence for behavior that cannot be externally established.
- **Not verified**: required evidence or configuration was unavailable or inconclusive.
- **Incomplete**: applicable mandatory obligations remain unresolved.

A SAMLscope report is a test result, not a certification. Neither Kantara nor OASIS endorses an individual result.

## Run with Docker

```bash
docker build -t samlscope:0.1.0 .
IMAGE_DIGEST="$(docker image inspect --format '{{.Id}}' samlscope:0.1.0)"
docker run --rm -p 8080:8080 -v samlscope-data:/data \
  -e SAMLSCOPE_PUBLIC_BASE_URL=http://localhost:8080 \
  -e SAMLSCOPE_PEER_BASE_URL=http://localhost:8080 \
  -e SAMLSCOPE_IMAGE_DIGEST="$IMAGE_DIGEST" \
  samlscope:0.1.0
```

By default, self-hosted mode has no application authentication and must not be exposed directly to an untrusted network. Optional standard OIDC login is implemented with per-user Plan ownership; see [OIDC configuration and pending G2 reapproval](docs/17-oidc-authentication.md). Generated Test Peer private keys are test-only and must never be trusted by production systems.

## Deploy samlscope.com

The initial production profile runs on one VPS with Caddy, a digest-pinned GHCR image, SQLite, and
all persistent state mounted from `/srv/samlscope/data`. It serves administration from
`https://app.samlscope.com` and Test Peer endpoints from `https://peer.samlscope.com`, as required by
hosted mode. The version-controlled deployment manifests are in [`deploy/`](deploy/);
operator-specific VPS and GitHub environment setup notes are kept outside the public repository.

## Keycloak acceptance fixture

Docker:

```bash
SAMLSCOPE_SMOKE_MANUAL=1 dev/keycloak/prepare-smoke.sh
```

Apple Container on macOS:

```bash
python3 dev/keycloak/prepare-smoke-apple.py --manual
```

The fixture provisions a disposable Keycloak target and prepares a Run for browser testing. Keycloak-specific provisioning is setup only and is never used as conformance evidence.

## Development

```bash
./gradlew check
```

Before publishing a release or OCI image, configure the immutable G1/G2 verifier commits and SSH allowed-signers file, then run:

```bash
./gradlew releaseCheck
```

See the [design index](docs/README.md), [security design](docs/08-suite-security.md), and [implementation rules](AGENTS.md).

## License

Original software and test code: Apache-2.0. SAMLscope-owned original prose and
definition content: CC BY-SA 4.0. Third-party material retains its original terms;
measured results are not automatically CC-licensed. See [licensing scope](LICENSING.md),
[source review status](LICENSES/material-review.md) and [contribution terms](CONTRIBUTING.md).
