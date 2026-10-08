# Generic evidence collection and independent configuration completion

This implementation extends existing approved cases. It does not change their
interpretation, levels, variants, controls, or functional-profile membership.
Phase 1 acceptance remains incomplete; the generated [inventory](26-unverified-case-inventory.md)
and [comparison](23-reference-test-comparison.md) are the current reference record.

## Browser and Artifact originals

The generic browser collector follows persisted Suite actions for a registered
IdP. The test user enters credentials in the visible browser; credentials,
cookies, authentication headers, login HTML, and browser storage are not exported.
An authenticated browser context is reused when the action permits it. Fresh
session requests use an empty context, and passive requests never fill a login form.
See [the collector instructions](../dev/reference-acceptance/GENERIC-BROWSER-CAMPAIGN.md).

Error-response and ACS-binding cases inspect Recorder originals and their actual
request, response, action, issuer, destination, and signature correlation. Artifact
resolution uses persisted unsafe SOAP actions and retains the original envelopes.
An uncertain delivery remains a Suite observation gap.

The production HTTP factory provides the existing Run-to-Plan signing capability
to the closed PKIX/hostname transport recorder. Its TLS receipt is bound to the
actual exchange. A supplied client or an unsigned transport label cannot establish
TLS evidence. The production Recorder wrapper delegates original-body reads to
the integrity-checking file recorder for both Artifact and metadata evidence.

## Automatic AdditionalMetadataLocation inspection

For the approved metadata CONFIG case `IIP-MD05.a8`, the Suite creates deterministic
GET intents from the selected entity's immutable Run metadata. Runner applies
outbound policy, dispatches the persisted actions, and records their actual replies.
The sender has no authenticator or cookie handler and does not follow redirects.
URLs containing recognized credential query parameters are observation prerequisites
that the automatic path cannot use; the URI is never rewritten.

The reader checks every referenced XML root namespace against the declaration in
the target's metadata. It verifies Run, role, profile, entity, case, snapshot,
outbox ownership, response reference, URI, and original-body hashes. HTML,
redacted or missing originals, unsupported locations, and uncertain delivery remain
unverified. Operational size and timeout limits do not impose target conformance
thresholds.

The production calibration producer records a matching baseline and a namespace-only
mutant using the same retrieved XML original. Their control and fixture identifiers,
bytes, and detector results are checked again by the reader. These are explicitly
Suite calibration originals; they are not target publication or native-configuration
claims. After the actual target evidence and calibration are complete, normal
ready-evaluation finishes the case without another operator answer. Existing manual
CONFIG, attestation, cancellation, and configuration-failure behavior remains available.

The initial Run preparation remains required. The new path adds no login for the
reference retrieval itself. It does not configure a product to publish a missing
AdditionalMetadataLocation. The namespace-extension and affiliation cases retain
their existing evidence requirements and fallback behavior.

## Source-bound native configuration evidence

SimpleSAMLphp `IIP-IDP19.b` now has an explicit, case-specific source-Run binding.
The original native campaign proves independent configuration of multiple
decryption keys through original configuration, native key operations, removal
controls, restoration, code dependencies, and a signed current read-back.

The source Run remains incomplete and has no invented initial login, case execution,
or protocol history. Its proof is qualified through an existing completed recipient
Run with its own signed request/response identity. Both original metadata inputs
remain byte-bound; the reader permits only the recorded key-rotation and same-URL
SLO advertisement differences for this configuration obligation. Other differences
invalidate the binding. This is not general metadata equivalence.

The actual recipient transition was a first outcome: `WAITING_CONFIG` with no
outcome became `FINISHED` with `SATISFIED`, through the existing evidence-ready
automation. Its case state was preserved, its wait cleared, and other cases and
the source history remained unchanged. No previous-result audit was fabricated.
Existing signed SSO originals establish recipient identity only. This adoption does
not establish `IDP19.a`, `IDP19.c`, metadata consumption, or logout behavior.

The adoption added no product setting changes, login, SAML send, or human interaction.
Earlier configuration writes and restoration writes remain separately recorded,
including their overlap. Failed preparation attempts and unmeasured exploratory
totals remain visible in the operation record. Docker build/deployment operations
belong to the deployment batch and are not counted as product setting changes.

## Repeatable reference generation

`regenerate_reference_evidence.py` owns a temporary compatibility classpath for
legacy acceptance readers within one explicit generation. It binds the complete
deployed API dependency graph and independent project foundations to runtime and
source qualification. An older reader's own archive remains first in its classpath.
Each normal verifier and its controls still executes; outcomes are not substituted
from a previous generation. Input, dependency, ownership, and byte changes stop
generation, and only the unmodified owned temporary file is removed on exit.

```sh
.venv/bin/python dev/reference-acceptance/regenerate_reference_evidence.py \
  --generator remaining \
  --evidence-root build/acceptance/reference-20260914/remaining-audit \
  --qualification build/acceptance/reference-20261008/deployment-v235-r2 \
  --report build/acceptance/reference-20261008/remaining-generation.json

.venv/bin/python dev/reference-acceptance/regenerate_reference_evidence.py \
  --generator comparison \
  --evidence-root build/acceptance/reference-20260914 \
  --qualification build/acceptance/reference-20261008/deployment-v235-r2 \
  --report build/acceptance/reference-20261008/comparison-generation.json
```

Use fresh report paths. The locally retained acceptance originals and independent
runtime archives are ignored operational evidence, not committed reference data.

## Initial independent G2 renewal

The protected implementation delta is limited to the Artifact transport factory
composition in `SamlScopeApplication` and metadata collector composition in
`M1Runtime`. Independent review checked these changes, the Recorder delegation,
production calibration, normal first-outcome automation, original integrity,
credential handling, and existing transport regressions. The earlier missing
`readBody` delegation was corrected before the final review.

The signed target commit contains the implementation and this review record. Its
immediate approval descendant changes only `tests/approvals/g2.yaml`, renews the
unchanged case approvals, and binds the complete protected target tree. Renewal
timestamps describe renewal of the existing bundle, not invented new design reviews.
The existing signer and external G1/G2 validator pins are retained. G2-30 is verified
through the normal trusted wrapper without changing or bypassing its boundary.

Runtime deployment and new product conclusions require their own evidence after
the signed renewal and build checks. Unit or integration test success alone does
not reduce the reference inventory.

## Deployed API qualification

The signed composition has been deployed to the local Suite. The installed
distribution, running JARs, and launcher agree byte for byte; the existing data
volume and application inputs are retained. Signed release-policy verification
also passes for this source revision.

An owned synthetic IdP exercised the actual public Plan, Run, preflight, signed
normal-login, and milestone-start APIs. AdditionalMetadataLocation matching and
mismatching namespaces produced the expected first stored outcomes before any
result API read. No second configuration answer or attestation was submitted.
Duplicate declarations shared one recorded retrieval, and the stored normal
Response and Assertion signatures were checked against the Run metadata.

Separate synthetic Runs exercised HTML, redirects, and an HTTP service error.
Their cases remained unverified. HTML content was discarded, redirect targets
were not fetched, and an HTTP error was not classified as product nonconformance.
The temporary read-only inspection helper was removed after each campaign;
the database was inspected in place and was not copied.

These checks qualify production composition and automatic evidence completion.
They do not establish reference-product conformance and add no observations to
the generated comparison. The investigated reference metadata does not publish
AdditionalMetadataLocation declarations, so its namespace cases still need the
approved evidence prerequisites. Operational originals and synthetic operation
counts are retained separately under the ignored acceptance evidence directory.

The same image also completed the approved ProtocolBinding case through the
actual public API, first with a signed ArtifactResponse and then with an unsigned
ArtifactResponse authenticated by closed PKIX and hostname-verified TLS. The
POST control, Redirect error, unsupported-binding error, and Artifact exchange
were all observed. An independent reader checked the signed normal flow,
persisted unsafe SOAP action, original request and reply, outer and inner
correlation, issuer, destination, and Suite-signed TLS receipt.

Only the selected case and normal-flow originals were qualified. Unselected DTD
fixtures were not sent to the target and remain rejected by the secure XML
parser; the whole Run export is explicitly incomplete. The selected originals
and their byte hashes were exported before the owned synthetic container and
test-data volume were removed. The main Suite's TLS settings were unchanged.
These synthetic results likewise add no reference-product conclusions.

## Initial login in the campaign browser

The optional browser preparation now performs the initial normal SSO in the
collector's own visible browser context. Subsequent actions reuse that context
only when the Suite explicitly permits session reuse; fresh and passive actions
still use separate empty contexts. The test user enters credentials in the target
page, and the collector does not fill or export them.

An owned actual Suite Run verified the cold preparation path: no case execution,
outbox action, or Recorder operation existed before preflight or after the empty
evaluation that prepared pinned result membership. The normal SSO then completed
with independently verified Redirect, Response, and Assertion signatures. Formal
cases were not started. This qualifies initial preparation and its original
correlation; subsequent session reuse was checked separately in the synthetic
Chrome integration and was not measured in this actual Suite Run.

A timed-out normal operation retains its live page and request handle in the
collector process. Resuming polls that existing operation without resubmitting
the start URL. Explicit stop closes the collector's resources without claiming
that the Suite operation completed. Human login and click counts remain
unmeasured, rather than being inferred from browser-context creation counts.

## Saved results across definition updates

The application retains the exact public functional-profile bundle from the
signed initial target and its approval descendant. A closed manifest binds the
original profiles, case catalog, coverage, predicates, specifications, controls,
and approval records. A Run cannot supply a replacement manifest or select a
newer definition merely by naming the same profile.

Retained results are assembled with their own case catalog, obligation levels,
conditions, source URLs, and component digests. Cached result and report bytes
are read unchanged. A missing report can wrap an existing result without storing
or re-evaluating either artifact. An existing report does not permit replacement
of a missing result with a new determination. Older definitions outside the
retained bundle remain unavailable; their stored artifacts and physical evidence
records are still exposed without interpretation through current catalogs.

The workspace presents these Runs as saved records and hides setup and execution
actions. New execution under a retained definition is held until exact runtime
compatibility is independently established. Valid arriving protocol originals
are preserved, but they do not advance an old campaign, consume its execution
intent, claim a propagation participant, or generate a new peer response. Current
Runs retain their normal execution path. This preserves evidence without claiming
that every historical test can resume under a newer implementation.

Independent review checked cached and asymmetric artifact pairs, retired case
IDs, owning evaluation semantics, queued reads, public continuation and receipt
paths, and their current positive controls. The changes do not modify approved
case meaning, functional-profile membership, or the reference inventory. The
NameID interpretation correction remains separate.

The retained release shares an immutable source inventory across its profiles.
Installed typed catalogs may be reused only after the closed manifest and every
retained original have been verified again. Current inputs must match the exact
source bytes, profile bytes, and declared digest keys before sharing those
models; changed inputs use their own resolver. Injected resource readers are
always validated and parsed independently. Outcomes and applicability decisions
are not cached. This removes duplicated catalog parsing without enlarging the
test heap or weakening original-byte verification.

The independent follow-up review checked the final memory changes, immutable
ingress and reads, fresh original verification, and changed-input controls.
The complete offline build check passed with the unchanged heap configuration.
The protected composition changes require renewal of the existing signed G2
bundle before publication. The target and its immediate approval descendant
retain the case-design digests and external validator pins; the renewal does
not represent new case definitions or new reference-product conclusions.
