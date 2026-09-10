# Request signing configurations

## Decision

IdP testing uses separate Plans for `REQUIRED` and `OPTIONAL` request signing.
A Plan keeps its mode for its entire lifetime, including bootstrap and all Runs.
Changing the mode requires a new Plan and a separately configured target client.
The operator configures the target to match; SAMLscope does not silently change
vendor settings or claim that the declaration proves the target's configuration.

Both Plans cover ordinary functionality such as NameIDPolicy and ACS selection.
They are not a split between signature-only tests and all other tests. Compare
results side by side; never aggregate the best outcomes from different modes into
one conformance determination. A signature that is present remains subject to the
approved requirements in either mode. This setting does not change applicability,
obligation levels, or the verdict mapping.

## Contract

`parameters.requestSigningMode` is `REQUIRED` or `OPTIONAL`. Missing values in
older Plan documents retain `OPTIONAL` behavior. Both self-hosted and hosted Plan
updates reject a mode change atomically. New Plan forms expose the setting and
Plan details show it. Public result configuration includes `request_signing_mode`;
reports written before the field existed display “Not recorded”.

In required mode, baseline SP metadata declares `AuthnRequestsSigned=true`.
The bootstrap Redirect binding signs the original encoded query, including
RelayState, with the Plan key. Ordinary front-channel AuthnRequests are signed
before persistence of the outbox intent, so Recorder and transport see the same
payload. Action identifiers, target destinations and ephemeral credential flags
are preserved. Existing XML signatures are retained byte-for-byte, including
intentionally invalid values, references, and transforms.

Fixtures which cannot be safely signed, such as malformed or DTD-bearing XML,
finish `NOT_VERIFIED` with `request_signing_unavailable`. They remain unresolved;
they are neither sent unsigned as a fallback nor counted as target failures.
Signing is a transport precondition, not a replacement for the fixture's controls.

## Acceptance and limits

The earlier signature-ON diagnostic completed bootstrap with enforcement OFF and
switched ON for the active chain. It remains historical diagnostic evidence, not
acceptance of the fixed required mode. New acceptance must start with enforcement
ON and registered signing keys, verify bootstrap, then execute the active chain
without changing enforcement. Optional mode needs a separate client and Run.

Explicit protocol campaigns that alter metadata or cryptographic policy still
require their documented operator actions. This change does not establish all
functional-profile, ECP, SP-role, or metadata-campaign acceptance. Deliberately unsigned
fixtures introduced in future must carry an explicit policy exemption; they must
not be silently signed as ordinary traffic.

The Plan-summary API wiring and existing OIDC working-tree changes affect signed
G2 boundary files and require renewed independent approval before release. This
implementation does not renew that approval or modify the signed requirement catalogs.

## Local verification

The fixed-mode protocol-client acceptance is recorded under
`build/acceptance/fixed-signing-plans/`, with independent `required` and `optional`
Plan/client folders. Both completed the registered active chain with their mode
unchanged from bootstrap. Each folder contains the setup declaration, exchanges,
final result and HTML report. The comparison remains separate from both results.

Required mode verifies the ordinary signed controls and changes the signed-request
verification/reliance outcomes to satisfied. Excluded signed content, NameIDPolicy
and ACS selection remain failure candidates. Malformed requests which cannot be
signed without repairing the tested defect remain unresolved. Some additional
normal-flow observations differ between Runs; a changed outcome alone does not
prove that signing mode caused it.

`provenance.json` distinguishes the tested protocol image from the subsequent
Plan-summary display correction. The latter was checked through API integration
tests and a live readback of both Plan modes. Cryptographic and outbox regression
tests, Plan immutability tests (self-hosted and hosted), backend tests, frontend
build/tests and G1 structural validation passed. G2 still requires renewed approval;
this is local implementation evidence, not a release acceptance claim.

## Implementation completeness review

The review traced bootstrap Redirect, ordinary browser outbox transitions,
resume/retry coordination, ECP fixture generation, Plan persistence and public
report configuration. Production coordinators use the signing-aware execution
service. Legacy constructors now fail closed for a required Plan's AuthnRequest:
missing signing infrastructure yields NOT_VERIFIED and no outbox intent, on start
and on resume. Non-sending transitions remain usable.

The API now rejects REQUIRED for SP-profile Plans, matching the IdP-only form.
The Plan list also displays the mode, rather than requiring each detail page to
be opened. Normal ECP requests are signed in required mode; the explicitly named
unsigned channel-binding negative control intentionally remains unsigned. Tests
cover that distinction without changing the approved fixture interpretation.

Backend regression tests and frontend build/tests passed for these corrections.
The historical Keycloak runs were not rerun or rewritten during this review.
The review corrections were subsequently deployed to the local environment as
`sha256:f2ab4bbd0bdc7b5c2f3e4dfb63458eaeca476358d747dc1e24b8a76a2fd9a335`.
Health, existing Plan modes and frontend delivery were checked at localhost:8087.
The outstanding independent G2 approval remains required before release.

## Local Docker cleanup

After the reviewed image was deployed, superseded SAMLscope verification containers,
unreferenced images and the rebuildable Docker build cache were removed at the
operator's request. The current SAMLscope and Keycloak containers remain running.
Historical result exports and all data volumes were retained. Other projects'
stopped containers were retained because their writable layers may contain data.
Historical image digests in acceptance records are provenance, not a promise that
the images remain available in the local Docker cache.
