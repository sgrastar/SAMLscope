# Reference execution record — 2026-09-14

Follow-up: [review-qualified per-test comparison and Suite fixes](23-reference-test-comparison.md). Historical raw results below remain unchanged.

Status: local IdP reference executions and publication-draft preparation completed.
Baseline SSO and registered browser-probe chains completed for all requested products.
Independent repeats agree for Keycloak and Shibboleth; SimpleSAMLphp has a
ForceAuthn timestamp-dependent difference requiring Suite-side review. This document is a local
working draft for eventual publication review, not published reference results
or a certification.

A shorter [publication draft](22-reference-publication-draft.md) separates the
reader-facing scope and concerns from this detailed execution history.

The requested targets are Keycloak, Shibboleth IdP and SimpleSAMLphp. This record
reports their exercised IdP behavior and the unresolved concerns found during
execution; it does not assert complete conformance. Historical Keycloak observations
in [release readiness](13-release-readiness.md) are not results of this attempt.

## Provenance

- Selected Suite source: `874ba19d1d7383f15dfbad3736bcc5c761a8f69e`.
- Source was extracted with `git archive HEAD` into
  `build/acceptance/reference-20260914/source/` before building. Existing
  uncommitted application, OIDC and administration changes are excluded from
  this candidate; no claim is made about testing those changes.
- Suite image tag: `samlscope:reference-874ba19`; completed build and running
  image digest: `sha256:59d00df3514d94d9c48a7b6e814b3a600af56b4ad6dbe2be519d7e013a25eebc`.
- Raw preparation logs remain under `build/acceptance/reference-20260914/`,
  which is ignored by Git. No raw evidence, credentials or private keys belong
  in the publication draft.

| Target | Selected version | Preparation evidence | New Run results |
|---|---|---|---|
| Keycloak | 26.7.2 | Existing fixture pins `quay.io/keycloak/keycloak:26.7.2@sha256:9d1f1b2b7261ff53c66cb1092dfcdc34a5fb77e81f9e6a6e75b8b6a795de8067` | Baseline and registered chain completed; repeat results agree |
| Shibboleth IdP | 5.2.3, InCommon image `5.2.3_20260824_rocky9_multiarch` | Digest `sha256:3c1b1fa64c58258aefc9e38d4ae60e9f0340731318a472110ea56ce88c18a11a`; re-pulled after corrupt local extraction; fresh IdP installation in the isolated container | Baseline and registered chain completed; repeat results agree |
| SimpleSAMLphp | 2.5.0, verified through installed Composer metadata and application version constant | `cirrusid/simplesamlphp@sha256:9ae050473c68ce13c5451839cb64257eaa17be3a4d2c9a3f87996bbe0cebb0aa`, explicit `linux/amd64` (container reports `x86_64`), PHP 8.4.19 | Baseline and registered chain completed with Redirect/POST advertised; ForceAuthn repeat differs |

The pre-existing Shibboleth 5.1.3 image is not evidence for the selected 5.2.3
fixture. Image tags must be resolved to digests before execution. A successful
image download alone is not an installed-product acceptance check.

## Observed environment failure

Host free space fell from approximately 749 MiB to 122 MiB during preparation.
SimpleSAMLphp extraction failed while writing containerd's overlayfs
`metadata.db`, reporting an input/output error. `docker system df` then also
failed with an input/output error while reading existing image content. The
Suite build had reached Java compilation but had not produced a verified image.
These observations concern the workstation and Docker storage, not SAML
behavior in any target product.

The task's build was interrupted and exited with status 130 and `context canceled`.
The last host check showed approximately 565 MiB free; this does not establish
storage recovery or repair of the Docker I/O errors.

No target-failure verdict can be derived from these failures. Existing unrelated
containers, volumes, images and user data have not been pruned. Free space must
be recovered and Docker storage health checked before resuming. Previous
storage-related failures are documented in [release readiness](13-release-readiness.md).

## Execution work still required

### Recovery follow-up

The user authorized removal of selected VS Code, npm/npx, Playwright and uv
caches. Their removal was verified, and host free space recovered to approximately
8 GiB. This resolves the immediate host-capacity constraint but does not prove
Docker storage integrity.

Docker's API still did not respond. A normal `docker desktop restart --timeout 45`
failed while waiting for application processes to exit. TERM signals stopped
the application and most backend processes, after which the API reported that
the daemon was unavailable. `docker desktop start --timeout 45` nevertheless
reported that Docker was already running. Process inspection found one remaining
`com.docker.backend` process. Automatic approval review rejected a proposed
SIGKILL because of possible state/container/volume damage without explicit user
authorization. No SIGKILL, factory reset, Docker disk deletion or volume pruning
was executed at that point. Stronger termination was paused for the user's decision.

The user subsequently authorized forced termination. The remaining backend was
terminated, Docker started successfully, and image listing plus a disposable
container write/read check succeeded. Existing unrelated containers and volumes
were preserved. The Suite image was rebuilt successfully from the fixed source.

Some layers extracted during disk exhaustion remained corrupt despite successful
image-list operations: the Shibboleth JVM library and the SimpleSAMLphp ARM64 PHP
executable were truncated. Re-pulling the task's Shibboleth image restored its
JVM. SimpleSAMLphp execution uses the explicitly selected AMD64 image, whose PHP
binary and version were verified. This is a local storage/recovery observation,
not a finding against either product or a claim that every Docker layer is sound.

### Current fixture and client qualifications

- Containers expose only loopback ports: Suite `18080`, Keycloak `18180`,
  Shibboleth `18280`, SimpleSAMLphp `18380`. HTTP is a local fixture choice and
  does not exercise public TLS deployment behavior.
- Shibboleth uses a fresh `/opt/reference-idp` installation, generated keys,
  an htpasswd demonstration identity and in-memory session/consent storage.
  HTML local storage is disabled for the protocol-client fixture. These settings
  must accompany any eventual sample; they are not the default deployment.
- SimpleSAMLphp uses `exampleauth:UserPass`. The first baseline advertised only
  Redirect SSO; many active cases consequently had unmet preconditions. Its
  subsequent fixture configuration advertises both Redirect and POST at the supported
  SSO endpoint. Historical exports must retain their original metadata digest.
- The Python client performs HTTP/form exchanges and is not evidence of browser
  JavaScript behavior. Its localhost-only cookie policy permits Secure cookies
  during intermediate HTTP redirects, matching the browser localhost exception.
  The earlier client set this only after redirects; those interrupted Runs are
  diagnostic evidence and excluded from clean reproducibility comparisons.
- Fresh cookie jars are used at the Suite's explicit fresh-session boundaries.
  A passive request that displays a login form is not answered with credentials.
  Known terminal error pages without a SAML response are reported through the
  Suite's response-unavailable operation, not translated into a product verdict.
- No new attestation answers have been fabricated. No target conformance finding
  has been approved for publication.

### Completed browser SSO observations

These executions use `browser_sso_idp`, the `quick` assistance preset, browser
steps enabled and attestation disabled. The protocol client followed the registered
chain through `FINISHED`. That state means the chain was traversed; pending
interactions and unresolved applicability remain. Every selected export is
`NON_CONFORMANT / INCOMPLETE` as a **raw Suite result**, not an independently
approved determination against the product. The Suite's verified ratio is not
a product quality score.

| Target | Selected Run | Repeat evidence directory | Raw verified ratio | Repeat comparison |
|---|---|---|---|---|
| Keycloak | `run_553R88270S7HFSTNVN57Q1ADTD` | `keycloak/run4` and `keycloak/run5` | 44.23% | Semantic results agree |
| Shibboleth | `run_JGADJKCN6GBGKJ68D1WP0G3GMX` | `shibboleth/run7` and `shibboleth/run8` | 48.72% | Semantic results agree |
| SimpleSAMLphp | `run_YY05MVCTPMHGQEJQFD2DHCENGE` | `simplesamlphp/run4` and `simplesamlphp/run5` | 48.08% | `IIP-IDP06-b-idp-01` changes from PASS to FAIL; other case results agree |

Directories above are relative to `build/acceptance/reference-20260914/`.
`compare_runs.py` compares conformance, completeness, coverage, metadata digest,
profile, requirement/obligation/case outcomes and reasons, unresolved reasons and
Suite incident kinds. Random identifiers, timestamps and generated assertion
values are excluded from this comparison. `review_results.py` separately verifies
that each selected standalone HTML embeds exactly the exported JSON. These checks
passed for the selected exports. `UNKNOWN_DELIVERY` incidents remain Suite
uncertainty even when the HTTP client observed a terminal target error page.

#### Client correction and Suite judgment concerns

The initial form parser submitted unchecked checkboxes. In the Shibboleth login
form this submitted `donotcache`, preventing the intended retained session. After
implementing successful-checkbox selection, the passive-with-session scenario
no longer fails in the clean repeat pair. Earlier diagnostic Runs are excluded
from product findings. This correction does **not** establish the cause of
SimpleSAMLphp's ForceAuthn differences: those also occur with the corrected parser.

SimpleSAMLphp ForceAuthn responses advance `AuthnInstant`, but express it with
whole-second precision. In repeat `run5`, the final request in
`IIP-IDP06-b-idp-01` has `IssueInstant=2026-09-14T07:16:52.479385919Z`, while
the new response has `AuthnInstant=2026-09-14T07:16:52Z`; the control had
`AuthnInstant=2026-09-14T07:16:51Z`. Suite code in
`IdpForceAuthnScenarioTestCase` treats any authentication time earlier than the
fractional request time as reused context. In `run4`, authentication crosses the
next second and the same case passes. `IIP-IDP06-a-idp-01` shows the same precision
problem. Therefore neither ForceAuthn FAIL is publishable as proof of session
reuse. The correlated timestamps are retained in `force-authn-timestamps.json`;
the approved implementation and interpretation have not been changed here.

#### Other failure candidates and source review

| Target | Candidate case family | Observed evidence and qualification |
|---|---|---|
| Keycloak | `IIP-SSO01-ai`, `aj`, `fk` | The original fixture sets `saml.client.signature=false`. A separate signature-required comparison makes `ai` and `aj` PASS; `fk` still receives Success for excluded-content XPath transforms. Details below; do not combine these into one signature-validation claim. |
| Keycloak | `IIP-IDP10-b`, `d`; `IIP-IDP12-a` | NameID policy and ACS selection candidates. Independently decrypted NameIDs omit `SPNameQualifier`; the same-SP omission in `IDP10-d` has a specific Suite interpretation concern below and must not be combined with the unknown-SP request in `IDP10-b`. |
| Shibboleth | `IIP-SSO05-b2` | The decrypted transient NameID contains `+`, `/` and `=`. Suite rejects its lexical form. Preserve the exact interpretation and generator configuration for independent review; do not publish the raw NameID. |
| SimpleSAMLphp | `IIP-SSO01-ag`, `ai`, `aj`, `fk` | Destination and signed-request mutation candidates under the original fixture. A separate signature-required pair makes `ai` and `aj` PASS while `ag` and `fk` remain FAIL; repeat semantic results agree. |
| SimpleSAMLphp | `IIP-IDP05-a`, `IIP-IDP08-a`, `IIP-IDP10-b`, `d` | Error response, requested authentication context and NameID policy candidates. The exported FAILs require individual source/control review; they are not approved product findings. |

Case stems in the table have the suffix `-idp-01` in the exports. Encrypted
Assertions were decrypted only in memory using the disposable Suite fixture key;
the review saves structural fields and a hash of NameID values, not plaintext
identities or private keys. No new operator attestation was submitted. Exported
`attested`/coverage fields reflect the approved obligation's **testability**,
not the existence of a submitted answer: `ResultDocumentAssembler` derives the
case flag from `Testability.ATTESTED`, and `Evaluator` counts applicable
obligations of that testability. Thus these fields must not be described as a
count of operator confirmations. The client trace is the record of what was
actually done; `evidence_class` and actual evidence references require separate
consideration.

A separate Keycloak Plan `plan_T6JYFA3F47189JS007RJE8WBPT` uses Suite
`requestSigningMode=REQUIRED` and target `saml.client.signature=true`.
The original optional-signature Plan remains unchanged. In
`run_30YY6ZW7ZYNAQNZZBBVFJMF7T1`, signed baseline SSO and the registered chain
completed, JSON/HTML agree, and `IIP-SSO01-ai` / `IIP-SSO01-aj` became PASS.
`IIP-SSO01-fk` remained FAIL: the valid control and the XPath fixtures excluding
scoping, all content, ACS and NameID policy each received correlated Success
responses. Transcript inspection confirms HTTP-POST with XML signatures and no
Redirect query signature; an outer query signature is not an explanation for
acceptance in this exchange. This isolates a more specific excluded-content
candidate under the signature-required fixture. Repeat
`run_XJRRFBHXTKM9A4Z3JE6VPP63JN` completed with an identical full semantic vector
and matching HTML/JSON. The approved `IIP-SSO01.fk` source basis is SAML Core
5.4.4: accepting another transform does not permit excluding request content.
This is a signature-profile candidate, not proof of an account compromise;
signature-transform review remains open. No external finding was filed or
published.

SimpleSAMLphp comparison Plan `plan_BKMAFEA2A5NMHN6PXJ1A93CHFG` similarly uses
Suite `requestSigningMode=REQUIRED` and per-SP `validate.authnrequest=true`,
leaving its original Plan unchanged. In
`run_AQ3A9R1AXMVTF58M1XPZ4541VV`, baseline and the registered chain completed and
HTML/JSON agree. `IIP-SSO01-ai` and `aj` became PASS, while the Destination
candidate `ag` and excluded-content candidate `fk` remained FAIL. This Plan also
observed `IIP-SSO05-a` (a persistent-NameID request returned a transient NameID),
so changing fixture/probe conditions must not be described as changing only the
signature cases. Independent repeat `run_NHP6JS56X1R5B71KY8X2NW9CYK` completed
with an identical full semantic vector and matching HTML/JSON. Agreement does
not resolve the previously identified ForceAuthn precision issue. The
[SP metadata reference](https://simplesamlphp.org/docs/2.3/simplesamlphp-reference-sp-remote.html)
describes the signature requirement setting; the installed fixture version
remains 2.5.0 as recorded above.

The Keycloak `IIP-IDP10-d` qualifier request names the requesting SP itself.
Independent in-memory inspection confirms that the returned transient NameID
omits the qualifier and that the assertion's audiences contain only that SP.
SAML Core sections 8.3.7–8.3.8 permit omission of the SP qualifier in the
direct-consumer case. The Suite's
`IdpNameIdPolicyScenarioTestCase` instead compares the requested qualifier with
the literal returned attribute, and the approved variant also describes literal
equality. This requires interpretation review before using that FAIL as a
product allegation. Neither approved artifact was changed. The separate
`IIP-IDP10-b` request specifies an unknown *different* SP, so the same-SP
omission rationale does not dispose of it. Sanitized correlation checks are in
`keycloak/run5/nameid-qualifier-review.json`.
[SAML Core, sections 8.3.7–8.3.8](https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf).

The Shibboleth transient lexical candidate has a different basis: SAML Core
8.3.8 refers to the identifier rules in 1.3.4, including the XML ID encoding
constraint. The observed punctuation is therefore relevant to lexical validity,
not merely an unfamiliar opaque value. The installed fixture leaves
`idp.transientId.generator` at its documented-in-file
`shibboleth.CryptoTransientIdGenerator` default and enables
`shibboleth.SAML2TransientGenerator`. This supports retaining the candidate for
review with its precise generator configuration; it does not establish any
failure of confidentiality, uniqueness or authentication.
[SAML Core, sections 1.3.4 and 8.3.8](https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf).

### Additional functional-profile executions

The selected raw FAILs have now all been assigned an explicit review disposition
in the local `candidate-review-inventory.json`. It records the source review
hashes and Transcript references; it does not edit exported results or grant
publication approval. Remaining uncertainty is named rather than inferred from
the absence of another test failure.

| Candidate family | Review disposition and observed boundary |
|---|---|
| SimpleSAMLphp Destination (`IIP-SSO01-ag`) | Success is observed for the control and requests naming another host, a non-SSO path and another IdP URI. These are attribute mutations sent to the configured test target; they are not requests sent to the other IdP. Retain as a fixture-specific candidate. |
| SimpleSAMLphp error/context (`IIP-IDP05-a`, `IIP-IDP08-a`) | Unknown NameID format and unavailable authentication context receive Success. The passive-without-session exchange instead returns Responder without assertions. An exact context request receives Password rather than the requested class. Do not describe every subscenario as failed or rely on the fixture label “satisfiable” as proof of target capability. |
| SimpleSAMLphp NameID (`IIP-IDP10-b`, `d`, `IIP-SSO05-a`) | Unknown format / different-SP policy or persistent format receives a successful response with a different identifier policy. These overlap and must not be presented as independent product defects merely because several case IDs report them. |
| Keycloak ACS (`IIP-IDP12-a`) | An index-1 request receives its response at ACS 0. Readback confirms index 1 exists in the original Suite metadata but its URL is absent from the native imported client's redirect URIs; the POST ACS attribute points to index 0. The target was not configured with the full indexed endpoint set, so this Run does not isolate runtime ACS-index handling. |
| Keycloak / SimpleSAMLphp SAML-EC (`IIP-IDP15-a`) | The corrected SOAP Success response lacks a visible GeneratedKey header. This is a mechanism-specific candidate; earlier redirect-only attempts remain Suite/fixture diagnostics. |
| Logout expiry / signature (`IIP-IDP17-t`, `m`) | Missing attributes and signatures were checked directly on inbound messages. Keep message direction, binding, configuration and end-to-end completion separate. |

For SAML-EC, the cached reference text was independently hashed and matches the
approved source digest for `draft-ietf-kitten-sasl-saml-ec-16`:
`7c3266f6e19445e9e5f06d637a73769fcd99dd35865101544be8ec6444d625a6`.
Its sections 5.3–5.3.1 describe SessionKey exchange between initiator and acceptor
and GeneratedKey in the IdP-issued assertion and response header. The captured
Suite request has a SessionKey header with actor `next` and mustUnderstand=1;
the captured successful responses have no visible GeneratedKey. The assertion
is encrypted for Keycloak and unencrypted for SimpleSAMLphp. These structural
observations are saved in `saml-ec-header-review.json`, without key values.
Review of how the probe establishes the draft mechanism context is still needed;
ordinary ECP Success alone is not proof of that context.
[Pinned SAML-EC draft](https://www.ietf.org/archive/id/draft-ietf-kitten-sasl-saml-ec-16.txt).

The Keycloak ACS import readback is retained in
`keycloak/browser_sso_idp/acs-registration-review.json`. It contains only endpoint
and signature-requirement settings, not administration tokens. This identifies
a reproduction/configuration limitation; it does not silently change the raw
case result or establish whether another supported configuration can preserve
indexed endpoints.

Dedicated Plans were created for `metadata_idp`, `single_logout_idp` and
`ecp_idp` for every target. They use the `assisted` preset with attestation
disabled and actual SP metadata registered at each IdP. Baseline SSO and the
available registered probe chains completed. These executions are separate from
the earlier `quick` browser SSO Plans.

| Target | Profile | Selected Run | Current raw result | Work performed / qualification |
|---|---|---|---|---|
| Keycloak | Metadata | `run_S1JH00056VJRZ2GN63C8RX46CG` | INDETERMINATE / INCOMPLETE | Imported preloaded fixture entities through the metadata converter/admin API and attempted their signed authentication flows. |
| Shibboleth | Metadata | `run_G4YCHCWZJ5E8RAT5DMGGKW9XM1` | INDETERMINATE / INCOMPLETE | Fetched the preloaded aggregate in the target container, loaded it through a dedicated filesystem provider, and obtained Success responses for all preloaded variants. |
| SimpleSAMLphp | Metadata | `run_X2NRGYPCFF9EMJZ18YT4PT3Q7Y` | INDETERMINATE / INCOMPLETE | Imported the aggregate using the installed SAMLParser, then attempted every preloaded variant. |
| Keycloak | SLO | `run_FXJDYH4QRNA809YFMBD3KEJVFN` | INDETERMINATE / INCOMPLETE | Baseline and registered chain only; actual logout/session campaigns remain pending. |
| Shibboleth | SLO | `run_NAXTEN318M4SMY3SM56YRFM755` | INDETERMINATE / INCOMPLETE | Baseline and registered chain only; actual logout/session campaigns remain pending. |
| SimpleSAMLphp | SLO | `run_77A55V09F1D9Y8X5T0SNX3HAKM` | INDETERMINATE / INCOMPLETE | Baseline and registered chain only; actual logout/session campaigns remain pending. |
| Keycloak | ECP | `run_H38KM96SRSD9ESW4B0JQ0RV5JC` | NON_CONFORMANT / INCOMPLETE | SOAP Success responses obtained after enabling ECP for the dedicated client and registering the exact PAOS URL. SAML-EC candidate below remains unapproved; repeat agrees. |
| Shibboleth | ECP | `run_4E2YMVJR6DPW196YFMWX4V9DN3` | INDETERMINATE / INCOMPLETE | Baseline and signed matching-channel probe return Success; unsigned/mismatched or incomplete channel-binding probes return a channel-binding error. |
| SimpleSAMLphp | ECP | `run_KNM1G6JW0H7MYS6RT0FQX69EK5` | NON_CONFORMANT / INCOMPLETE | SOAP Success responses obtained after registering the exact PAOS URL and allowing configuration revalidation. Repeat agrees; SAML-EC candidate remains unapproved. Earlier redirect-only attempts are fixture diagnostics. |

Each selected JSON/standalone HTML pair was compared and agrees. Independent
repeat pairs are recorded below. Individual finding review and the remaining
campaigns are still required; repeated partial coverage does not establish full
acceptance.

#### Metadata import observations

Keycloak's converter rejected `unknown-endpoint-extension` with HTTP 400. Its
`keyvalue-only`, `certificate-expired` and `certificate-not-yet-valid` flows also
stopped without correlated Success. SimpleSAMLphp stopped at `keyvalue-only`;
the target log reports a missing certificate. Other attempted preloaded flows
returned Success. The client resumed at the next independent fixture after
recording each terminal error; it did not invent a response or submit a verdict.
The current Metadata exports have no FAIL candidates. Unavailable responses and
remaining refresh/attestation requirements remain unresolved.

Keycloak/SimpleSAMLphp used the operator download route (`MetadataExport`) and
their native import mechanisms. This is not evidence that they fetched a live
metadata URL. Shibboleth used a target-side download and filesystem reload;
this does not establish automatic HTTP refresh. The preloaded campaign avoids
separate manual imports but does not cover every available live-feed variant.
No metadata signature trust filter was added to these trusted local imports.

The Suite leaves the Run in `WAITING_BROWSER` after its preloaded completion
page, so `tests/start` and `quick-check` reject immediate manual reevaluation.
An additional real baseline SSO round trip restored the completed Run state,
after which profile evaluation/export succeeded. This workaround is recorded in
`postcampaign-baseline.json`; it is not evidence that the campaign state/UI is
ready for publication.

The preloaded metadata campaign was repeated with fresh Runs and protocol-client
sessions. Corrected comparisons include the same target metadata digest:

| Fixture | Independent pair | Comparison |
|---|---|---|
| Keycloak | `run_S1JH00056VJRZ2GN63C8RX46CG` / `run_HEGZFSAG1WFGFCXX1XE6N1C52B` | Full semantic vectors agree; INDETERMINATE / INCOMPLETE; verified ratio 27.18% |
| Shibboleth | `run_EPQBX03QRJECP6SB3A0X6VKQRC` / `run_HQ5H6JMEBGFRQAYZ8RC924DJCK` | Full semantic vectors agree; INDETERMINATE / INCOMPLETE; verified ratio 29.13% |
| SimpleSAMLphp | `run_W76258AHYX3ARSK9SMZ9H43QZR` / `run_YVZ8AB57K11T5XRZNEYVHMPQ1Z` | Full semantic vectors agree; INDETERMINATE / INCOMPLETE; verified ratio 27.18% |

All selected repeat HTML/JSON pairs agree and have no raw FAIL candidates. The
same import/flow exceptions listed above recurred, with later independent
variants resumed after preserving each terminal error. Shibboleth's and
SimpleSAMLphp's first-to-second comparisons differed only in target metadata
digest following the ECP setup changes; the table therefore uses their second
and third Runs, without ignoring that provenance difference.

Keycloak uses stable metadata-peer entity IDs across Runs. Repeating a create
operation initially returned HTTP 409 for already registered peers. The fixture
then passed the new exported metadata through the native converter and updated
each matching existing test client through the administration API. The
unknown-endpoint-extension variant still failed conversion with HTTP 400.
Duplicate-client conflicts are retained as fixture setup diagnostics, not
metadata-conformance findings. Shibboleth repeats used explicit operator export,
local trusted-file replacement and resolver reload; they do not establish
automatic target-side metadata fetching or refresh.

#### ECP fixture changes and judgment concerns

The Suite container could not initially reach target URLs advertised as
`localhost`. `samlscope-reference-local-forward` now shares its network namespace
and forwards loopback target ports through `host.docker.internal`. This preserves
the outbox request bytes and records no payloads or credentials. The first
Keycloak ECP Run's `UNKNOWN_DELIVERY` is a fixture-network diagnostic, not a
target failure. New Runs were used after the correction.

Keycloak's dedicated ECP client sets `saml.allow.ecp.flow=true`. Shibboleth's
default relying-party configuration already enables `SAML2.ECP`; its local IdP
metadata was extended to advertise `/idp/profile/SAML2/SOAP/ECP`. SimpleSAMLphp
sets `saml20.ecp=true`, allowing the application to generate its SOAP endpoint.
See the [Keycloak administration guide](https://www.keycloak.org/docs/latest/server_admin/),
[Shibboleth ECP configuration](https://shibboleth.atlassian.net/wiki/spaces/IDP5/pages/3199508598),
and [SimpleSAMLphp ECP configuration](https://simplesamlphp.org/docs/stable/simplesamlphp-ecp-idp).

Suite ECP requests append `?run=<Run ID>` to the PAOS ACS, whereas its ordinary
metadata advertises the endpoint without that query. Shibboleth logged
`EndpointResolutionFailed`; Keycloak logged `invalid_redirect_uri`. Registering
the exact Run-specific URL resolved those baseline failures. Keycloak received
an additional exact redirect URI. Shibboleth received an additional PAOS endpoint
in a trusted local metadata copy, removing its original Suite signature before
editing that copy. Original downloaded Suite metadata is retained unchanged.
This required setup is a Suite interoperability concern, not target misbehavior.

Keycloak's `IIP-IDP15-a-idp-01` candidate concerns the separately referenced
SAML-EC generated-key extension; it must not be described as a general SAML 2.0
SSO failure. Earlier SimpleSAMLphp attempts produced the same raw FAIL even though
their responses were HTTP redirects rather than SOAP authentication responses. Inspection of
`EcpTranscriptProfileCase.generatedKey` shows that a missing correlated SOAP
response is added directly to the violation list. That is insufficient evidence
of target nonconformance. Keep this result unapproved and review the Suite's
unavailable-response handling before publication. No protected code or catalog
was modified to change the result.

ECP repeats now have matching full semantic vectors (including target metadata
digests) and matching JSON/HTML results:

| Fixture | Independent pair | Correlated response observation |
|---|---|---|
| Keycloak | `run_KBTXHADMA5K58JPP9JC5BS9RBB` / `run_H38KM96SRSD9ESW4B0JQ0RV5JC` | SOAP Success for each registered probe; SAML-EC generated-key candidate remains |
| Shibboleth | `run_12DJKEZWAS15M7P5KPCEQZHZZH` / `run_4E2YMVJR6DPW196YFMWX4V9DN3` | Matching Success and channel-binding error response vector; no raw FAIL |
| SimpleSAMLphp | `run_DERPSQN6KFZ41JRNEZBYTA6A7S` / `run_KNM1G6JW0H7MYS6RT0FQX69EK5` | SOAP Success for each registered probe; SAML-EC generated-key candidate remains; verified ratio 14.81% |

For SimpleSAMLphp, the installed `saml/IdP/SAML2::getAssertionConsumerService`
falls back to a default ACS when the requested URL does not match a registered
endpoint. Its `core/Auth/UserPassBase` uses HTTP Basic credentials only when the
selected state binding is PAOS. The ordinary Suite metadata's query-free PAOS URL
therefore did not provide the exact registration needed for these probes. The
successful fixture adds each Run's exact PAOS URL to its trusted SP configuration,
using the same approach as the other products. No password-handling code was
modified, and credentials remained ephemeral.

The first attempt immediately after adding that endpoint still redirected.
The installed PHP configuration has OPcache timestamp validation enabled with a
two-second revalidation interval. Two subsequent independent Runs, with a delay
between metadata registration and ECP dispatch, returned SOAP Success throughout.
This is consistent with configuration-cache timing; the failed immediate attempt
is retained as a diagnostic rather than silently replaced. Reproduction must
allow the configured metadata revalidation interval after editing the fixture.
SimpleSAMLphp's documented lack of channel-binding and holder-of-key support
also limits what these Success responses establish; see its linked ECP guide.
Earlier Runs `run_ZT8H040EPNQDWS8E73798J7T1E`,
`run_V1HMJ9Z6VHQRK6CRB1PSJDD6QC` and `run_7HVWEANGAJEHMCM0HYYKY3GJV1`
remain diagnostic evidence and are excluded from the corrected-fixture pair.

### Real-browser target-initiated logout

The following executions used the in-app Chromium browser, synthetic fixture
credentials and native IdP logout pages. They are distinct from the protocol
client runs above. Each selected Run has `browser-protocol-shapes.json`,
`slo-candidate-shapes.json`, a Transcript index, result JSON and standalone HTML
in the ignored local evidence directory. The HTML embedded results matched JSON
for every exported Run below.

| Fixture | Browser Runs | Observed exchange and completion | Raw Suite result |
|---|---|---|---|
| Keycloak | `run_0HF6F0ZTFVPPR9YAJSE4N5YWZ0`, `run_J5SM20CM8MH8BG894VXA2N4BFM` | Credential login, recorded SSO, native end-session confirmation, inbound LogoutRequest and generated Success LogoutResponse; returned to sign-in | NON_CONFORMANT / INCOMPLETE; verified ratio 22%; repeat semantic vectors agree |
| SimpleSAMLphp | `run_FTGMCH9JK444FQDB5JZPK9FT34`, `run_DVCVA0CEB6PRZGXWWMV4AKMR1K` | Credential login, recorded SSO, native `initSingleLogout`, inbound LogoutRequest and generated Success LogoutResponse; returned to welcome | NON_CONFORMANT / INCOMPLETE; verified ratio 24%; repeat semantic vectors agree |
| Shibboleth | `run_ZGRSGBKXT6MR768EF12TAQ460M`, `run_SCGYBP310A39JB98CTP0Q5DBPD` | Credential login, recorded SSO, native `/idp/profile/Logout` listed the Suite SP; automatic propagation in the first Run and explicit global logout in the repeat; inbound LogoutRequest and generated Success LogoutResponse, but UI reported **Logout failed** in both | NON_CONFORMANT / INCOMPLETE; verified ratio 22%; corrected-fixture repeat semantic vectors agree |

Target-local SP registrations use `/p/{plan}/sp/slo?run={run}` for explicit Run
correlation. The receiver requires either this query parameter or a Run-valued
RelayState; the native IdP logout flow need not supply the latter. Shibboleth and
SimpleSAMLphp registrations select HTTP-POST. Shibboleth's modified trusted local
SP metadata copy is unsigned; the Suite's original generated metadata is retained.
Register the new Run endpoint before its login when reproducing a repeat.

Browser testing exposed local fixture differences that the HTTP client missed:

- SimpleSAMLphp's loopback HTTP fixture now explicitly uses
  `session.cookie.samesite = Lax` with `session.cookie.secure = false`. Its previous
  SameSite=None configuration produced a cookie-not-found browser error. The
  first browser Run also required restarting baseline SSO after a stalled sending
  page; the second Run completed without that retry. The stall's cause is not
  established. No target UI or language changes were retained.
- Shibboleth's earlier browser Runs (`run_R3CQ4XJNNM8VGNJ63JMPCK5GS1` and
  `run_Z7M9F56RBS4MTYNMVE3XDMX7TF`) reported no other services at logout and
  produced no Suite logout exchange. Changing `idp.cookie.secure` from false to
  true, with the default `__Host-` cookie name, restored the SP listing and
  propagation in the new Run. This supports a fixture cookie explanation;
  those earlier Runs do not prove missing product SLO support.
- Shibboleth's propagation uses an embedded browser flow. The pinned Suite's
  `serveSlo` POST response sets `frame-ancestors 'none'`. This is a concrete
  integration concern consistent with the failed logout UI. The Transcript's
  outbound entry records response generation, not proof that the IdP received
  and accepted it. Keep end-to-end completion unverified; do not weaken the
  policy or change the approved implementation merely to make the Run pass.

The new raw FAIL candidates were inspected against the actual inbound XML:
Keycloak and Shibboleth omit `LogoutRequest/@NotOnOrAfter`, producing
`IIP-IDP17-t-idp-01`; SimpleSAMLphp's POST LogoutRequest has no XML signature,
producing `IIP-IDP17-m-idp-01`. The observed Keycloak and Shibboleth messages do
contain XML signatures. These observations support the reported missing-field
and missing-signature shapes, but remain fixture-specific candidates pending
independent source/control review. They are not blanket product assessments.
The approved catalog requires NotOnOrAfter for the session-authority path; no
catalog interpretation or verdict was changed during this investigation.

### Execution procedure and delivery evidence

Recovery, the isolated build, fixed-revision CI inspection, fixture setup,
registered SSO chains, additional-profile executions and the selected independent
repeat pairs are recorded above. The following procedure preserves the
reproduction requirements. Broader operator campaigns and formal finding approval
remain outside the claims established by these partial-coverage results.

1. Recover host space; verify Docker image inspection and disposable-container
   filesystem writes. Recheck the selected image digests and finish the isolated
   Suite build. Record its image digest and source revision.
2. Run the Suite verification checks for that revision, including the existing
   externally pinned G1/G2 release verification. Do not select new verifier pins
   to bypass a failing approval gate.
3. Create isolated, loopback-only fixtures with dedicated data directories or
   volumes. Register the actual Suite-generated SP metadata in each IdP. Use
   disposable fixture identities; keep passwords and authentication responses
   out of client logs and the document.
4. Start with each target's `browser_sso_idp` profile. Complete baseline SSO and
   the available registered probe chain, following explicit fresh-session and
   configuration requirements. Record protocol-client and real-browser evidence
   separately. Starting a milestone alone is not completion of its campaigns.
5. Exercise `metadata_idp`, `single_logout_idp` and `ecp_idp` with configuration
   and endpoint evidence. Record features that cannot be configured and remaining
   interactions individually; never invent applicability or operator answers.
   SimpleSAMLphp SP profiles require a separately configured SP fixture and must
   not inherit IdP results. Establish supported roles for each pinned product
   before adding SP executions to the matrix.
6. Repeat each executed plan in a new Run with an independent session. Preserve
   result JSON, standalone HTML, pending interactions, campaign state and
   Transcript references. Compare semantic outcomes and reasons, investigate
   differences, and verify the HTML's embedded results agree with JSON.
7. Review every target-failure candidate against correlated requests, responses,
   controls and actual fixture settings. Known Suite bugs and unobserved encrypted
   contents must not become published allegations about a product. Record
   incomplete coverage even if two Runs reproduce the same results.
8. Produce a scrubbed publication draft containing provenance, fixture settings,
   profile and assistance preset, exercised scope, results, reproduction steps,
   and unresolved concerns. Keep publication, uploading and deployment pending
   a separate user request.

The delivery audit verifies the evidence supporting the completed execution and
documentation work:

| Requested outcome | Authoritative evidence | Result |
|---|---|---|
| Execute Keycloak, Shibboleth IdP and SimpleSAMLphp | Version-pinned fixture records, created Runs, correlated Transcripts and exported results listed above | Executed for the documented IdP scopes |
| Make results reviewable and reproducible | Independent Run comparisons, configuration differences, JSON/HTML equality, source and image provenance | Verified; the original SimpleSAMLphp ForceAuthn difference is explicitly retained |
| Identify concerns | Every selected raw FAIL is mapped to a review disposition and source-evidence hash; Suite, fixture and interpretation limitations are distinguished | Documented without granting product-finding approval |
| Prepare documentation for eventual publication | This execution record and the linked publication draft; raw evidence remains in the ignored local directory | Local artifacts prepared; no publication performed |

No full-profile PASS, product certification, SP/broker result or independent
publication approval is implied by completion of the requested local execution
and reporting work. These remain explicit limitations, not hidden successful
checks. The
historical Core/Full matrix does not establish results for the currently pinned
functional profiles. Completion of these reference executions also does not,
by itself, prove completion of all Phase 1 acceptance criteria.

## Document validation

The local `delivery-audit.json` verifies the selected repeat comparisons,
presence of JSON/HTML, Run state, interactions, campaigns and Transcript indexes,
and the hashes linking each selected raw FAIL to its review disposition. The
original SimpleSAMLphp SSO precision difference is explicitly retained rather
than ignored. All selected profiles remain INCOMPLETE; this artifact checks
evidence consistency, not completion of every campaign or publication approval.

The generated-document check and G1 structural validation passed with no blocking
failures. The initial structural attempt found a missing local allowed-signers
file; rerunning with the repository's existing `G1_ALLOWED_SIGNERS` variable
resolved it. No approval record or catalog was changed. These checks validate
the documentation/catalog boundary and are not reference-product executions or
full release verification.

G2 local validation remains blocked: `G2-30` reports that the existing working-tree
`api/src/main/java/com/samlscope/api/SamlScopeApplication.java` differs from the
signed approval commit. This was checked using the repository's existing
`G2_ALLOWED_SIGNERS` variable. The file was already modified before this task and
has not been changed by this attempt. The archived source was separately checked
against every blob in the selected Git revision (`source-verification.json`, no
mismatches). Existing successful
[Build CI for that revision](https://github.com/sgrastar/SAMLscope/actions/runs/34573673928)
includes `check`, `releaseCheck` and the pinned Keycloak smoke, and its
[G2 CI run](https://github.com/sgrastar/SAMLscope/actions/runs/34573673953) succeeded.
These existing runs were inspected; no deployment or new CI run was triggered.
The current worktree must not be described as release approved on that basis.

## Fixture setup sources

- [Existing pinned Keycloak fixture](../dev/keycloak/compose.yml) and
  [provisioning/round-trip client](../dev/keycloak/smoke.py).
- [InCommon Shibboleth image versions](https://hub.docker.com/r/i2incommon/shib-idp/tags).
- [SimpleSAMLphp IdP configuration](https://simplesamlphp.org/docs/stable/simplesamlphp-idp.html).
- [Cirrus image configuration](https://github.com/cirrusidentity/docker-simplesamlphp):
  the selected container is a packaging choice; its identity must be disclosed
  alongside the installed SimpleSAMLphp version.
