# SAMLscope

**[Try SAMLscope at samlscope.com](https://samlscope.com)**

Explore the available SAML checks and [open the hosted application](https://app.samlscope.com) to try them with your IdP or SP. Follow the guided workflow, inspect the evidence, and export a report. You can get started without building or running SAMLscope locally.

The hosted service is in **early access**. Use a dedicated test environment and non-production accounts; do not rely on it as the sole store of your test evidence.

SAMLscope is an open-source black-box conformance test suite for SAML identity providers (IdPs) and service providers (SPs). It acts as the opposite side of the SAML exchange, observes protocol behavior, and connects each result to its requirement, test case and evidence. The current catalog targets the [Kantara SAML V2.0 Implementation Profile for Federation Interoperability v1.1](docs/04-requirement-coverage.md) and its referenced specifications.

## What you can test

Choose a functional profile for the target's role:

| Profile | Target roles | Focus |
| --- | --- | --- |
| Web Browser SSO | IdP, SP | Browser sign-in, requests and responses, bindings, signatures, encryption and session behavior |
| Metadata | IdP, SP | Metadata structure, acquisition, trust, refresh, key rollover and related declarations |
| Single Logout | IdP, SP | Logout protocol and session behavior |
| ECP | IdP | Enhanced Client or Proxy sign-in |

Profiles select existing approved cases. Conditional checks depend on the target's declared features and available evidence. See the [profile definitions](profiles/README.md) and [requirement coverage](docs/04-requirement-coverage.md) for exact scope.

**Execution assistance** is a separate choice from the functional profile:

| Assistance | How you participate |
| --- | --- |
| **Quick** | Complete browser login, consent, logout or continuation steps while SAMLscope observes protocol evidence. |
| **Assisted** | Also perform requested configuration changes, metadata refreshes and other operator steps. |
| **Assisted + attestation** | Also provide the requested declarations for behavior that cannot be established through external observation. |

Checks lacking the selected evidence method remain not verified. The UI distinguishes externally verified, self-attested and unresolved evidence and shows the remaining interactions.

## Try your first test

Use a target you own or are authorized to test, with a non-production test account.

1. [Open SAMLscope](https://app.samlscope.com) and create a **Test Plan**. Choose the functional profile matching your target's IdP or SP role.
2. Enter the target entity ID and metadata URL, or reuse a compatible saved target. Select the execution assistance you can provide. Where shown, keep the target's request-signing requirement fixed for the Plan.
3. Register the SAMLscope Test Peer metadata shown on the Plan page in your target. Open the existing Run, or select **Create Run and preflight** if no Run exists. In the Run workspace, follow **What to do next** and select **Run preflight** when requested.
4. Complete the initial login round trip as instructed. Return to the Run after the response is recorded.
5. Select **Start or resume tests** to run the selected profile’s available tests. Follow **Pending interactions** for required logins, configuration changes, and evidence. For ECP, use **Run ECP probes and continue tests** when prompted; the remaining tests resume automatically. Use a fresh/private browser session when requested.
6. Open **Export / report** to inspect the current result or download `result.json` and the self-contained `report.html`.

A successful login is only the starting point. SAMLscope determines case outcomes from correlated evidence; operators supply actions and evidence, not PASS/FAIL decisions.

## Understand and share results

Results trace specification → requirement → obligation → test → evidence → verdict. Requirement levels and case controls come from the signed catalogs, and the central Evaluator derives the verdict.

- **PASS / WARNING / FAIL** reflect the applicable requirement level and observed case outcomes.
- **Externally verified** and **self-attested** evidence remain distinguishable.
- **NOT_VERIFIED** means evidence could not be obtained. It is not treated as a target failure or silently excluded.
- **INCOMPLETE** means applicable mandatory obligations still need evidence. Conformance and execution completeness are separate result dimensions.

JSON and offline HTML exports retain the relevant license and source notices. Hosted Runs can also use the application's publication controls for shared result URLs; self-hosted result uploads are not supported. See [results and publication](docs/06-results-and-publication.md) for the trust model.

A SAMLscope report is a test result, not a certification. Neither Kantara nor OASIS endorses an individual result.

## Current status

The hosted application is available for evaluation. Signed G1 requirements and G2 case/profile approvals are in place, and the release workflow verifies these boundaries before publishing a container. It also runs the pinned Keycloak SAML round trip and checks runtime notices and corresponding-source availability.

Reference acceptance remains limited: the pinned Keycloak fixture supplies interoperability and regression evidence, while broader product/profile combinations and operator-led campaigns still need recorded acceptance evidence. Availability of a profile does not establish acceptance of every product or configuration. See the [release evidence and remaining work](docs/13-release-readiness.md) and [reference acceptance matrix](docs/14-reference-acceptance.md).

Operational acceptance is also in progress. Production restore, retention, deletion and publication/access acceptance are not all recorded as complete in the [operations guide](docs/15-hosted-operations.md). Deployment success does not establish those guarantees; retain your own exported evidence.

## Run locally with Docker

Docker builds the Java application and browser UI together. The following example uses the linux/amd64 runtime covered by the publication audit and listens only on the local machine:

```bash
docker build --platform linux/amd64 -t samlscope:local .
SAMLSCOPE_LOCAL_IMAGE_DIGEST="$(docker image inspect --format '{{.Id}}' samlscope:local)"
docker run --rm --platform linux/amd64 -p 127.0.0.1:8080:8080 -v samlscope-data:/data \
  -e SAMLSCOPE_PUBLIC_BASE_URL=http://localhost:8080 \
  -e SAMLSCOPE_PEER_BASE_URL=http://localhost:8080 \
  -e SAMLSCOPE_IMAGE_DIGEST="$SAMLSCOPE_LOCAL_IMAGE_DIGEST" \
  samlscope:local
```

Open <http://localhost:8080>. The named volume retains runtime state, generated Test Peer keys, cached metadata and redacted Transcripts.

Remote targets need reachable peer URLs and appropriate TLS configuration; see [deployment and networking](docs/07-deployment-and-networking.md). Self-hosted mode has no application authentication by default. For access beyond the local machine, configure authentication and networking first. Standard OIDC login and per-user Plan ownership are supported; see [OIDC configuration](docs/17-oidc-authentication.md). Generated Test Peer keys are test-only.

Published images retain their runtime's original licenses. Their
[corresponding OS and JRE sources](https://github.com/sgrastar/SAMLscope/releases/tag/runtime-sources-96975602e131)
are available alongside the image. See [container licensing](LICENSES/container-publication.md)
for exact versions and redistribution conditions.

## Develop from source

Use Java 21 and Node.js 24.11.1, matching the CI setup. The repository includes the Gradle wrapper; Gradle installs the locked frontend dependencies with `npm ci`.

```bash
./gradlew check
SAMLSCOPE_DATA_DIR="$PWD/data" ./gradlew :api:run
```

This starts the development server at <http://localhost:8080>. Startup without `SAMLSCOPE_IMAGE_DIGEST` does not enable report generation. For local Runs that export reports, use the Docker instructions above, which supply the actual image digest. Do not substitute a made-up digest.

The optional Keycloak fixture provisions a disposable target and prepares a Run:

```bash
SAMLSCOPE_SMOKE_MANUAL=1 dev/keycloak/prepare-smoke.sh
```

For Apple Container on macOS, use `python3 dev/keycloak/prepare-smoke-apple.py --manual`.
Fixture administration APIs are used for setup, not as conformance evidence.

Before publishing a release or OCI image, configure the immutable G1/G2 verifier commits and SSH allowed-signers file, then run `./gradlew releaseCheck`. Follow the [implementation rules](AGENTS.md), [licensing tools](dev/licensing/README.md) and [contribution terms](CONTRIBUTING.md).

## Deployment and documentation

The production deployment uses Caddy, a digest-pinned GHCR image and SQLite. Administration is served at `app.samlscope.com` and Test Peer endpoints at `peer.samlscope.com`. See the [deployment manifests](deploy/) and [operations guide](docs/15-hosted-operations.md) for deployment, rollback, backup and retention procedures.

For implementation details, start with the [design index](docs/README.md), [test model](docs/03-test-model.md), [case format](docs/05-test-definition-format.md) and [security design](docs/08-suite-security.md).

## License

Original software and test code: [Apache-2.0](LICENSE). SAMLscope-owned original prose and
definition content: [CC BY-SA 4.0](LICENSES/CC-BY-SA-4.0.txt). Third-party material retains
its original terms; measured results are not automatically CC-licensed.

Start with the [licensing guide](LICENSING.md) and [license and source index](LICENSES/README.md).

- [Publication audit and retained conditions](LICENSES/publication-audit.md)
- [Material-by-material decisions and required notices](LICENSES/publication-register.md)
- [Original specification notices and attribution](LICENSES/source-notices.json)
- [Java dependency notices and source availability](web/public/licenses/java-dependencies.json)
- [Container licenses and corresponding-source downloads](LICENSES/container-publication.md)
- [Contribution terms](CONTRIBUTING.md)

The [application license page](https://app.samlscope.com/licenses) and
[website license page](https://samlscope.com/licenses/) provide readable notices for their respective distributions.
