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

## Independent G2 renewal

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
