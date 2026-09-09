# Functional profiles and public verification summaries

Status: product specification agreed with the operator on 2026-09-07. Exact
case sets and their common Plan/Run/result path are implemented. Profile membership
has independent G2 approval and each installed definition is release-pinned.
This document does not approve new conformance interpretations or a certification program.

## Purpose

SAMLscope is a SAML counterpart to the OIDF Conformance Suite. Match the usability,
configuration burden and user-visible test granularity of representative OIDC
OP/RP plans, while using SAML terminology and functional boundaries. Do not copy
OIDC names merely to resemble OIDF. Numerical parity is a design benchmark, not a
reason to discard specification requirements or controls; precise targets await
version-pinned comparison ([19](19-oidf-product-alignment.md)).

A visitor to a product's website should understand which product version and role
were tested, which functions completed verification, which remain unknown, and
which configuration the result describes. A headline must not imply support or
conformance beyond the linked evidence.

## Profile catalog

Use these names as the basis of the user-facing profile catalog:

| Profile | Target role | Intended functional scope |
|---|---|---|
| Web Browser SSO — IdP | IdP | Authentication request handling and Response/Assertion generation |
| Web Browser SSO — SP | SP | Authentication Response/Assertion reception and validation |
| Metadata — IdP | IdP | IdP metadata publication and SP metadata consumption |
| Metadata — SP | SP | SP metadata publication and IdP metadata consumption |
| Single Logout — IdP | IdP | Logout messages, correlation and session handling |
| Single Logout — SP | SP | Logout messages, correlation and session handling |
| Enhanced Client or Proxy (ECP) — IdP | IdP | ECP authentication and associated protocol processing |

These are SAMLscope verification units, not a claim that the boundaries exactly
match profile definitions in SAML specifications. Each functional profile is a
versioned set of existing approved cases. The cases remain the execution and
verdict units and retain their approved obligations, conditions, variants and controls.
Profile membership requires a traceable mapping.
Metadata publication and consumption must remain distinguishable in detailed results.
Do not grant a combined Metadata completion claim from evidence for only one side.

Prioritize Browser SSO, Metadata and Single Logout for both roles. ECP remains a
separate additional profile. Artifact is a Browser SSO binding variant, not a
separate top-level profile in this catalog; its implementation and evaluative
scope remain future work under the existing approval gates. Including it in a
catalog design does not make it available for verified claims today.

## Profiles, variants and execution

| Concept | Meaning | Example |
|---|---|---|
| Profile | Function whose conformance is assessed | Web Browser SSO — IdP |
| Configuration variant | Declared, reproducible target configuration | Required AuthnRequest signing |
| Plan | Configured instance of a profile with target/peer identities | One target client with fixed signature policy |
| Run | Execution with a recorded configuration and evidence | A repeat against the same product version |
| Case | Approved execution and verdict unit | NameIDPolicy handling with its controls and variants |
| Traceability row | Searchable case-to-obligation relationship | Case IIP-SP13-a-sp-01 covers obligation IIP-SP13.a |

Do not append Core, Standard or Full to the new public profile names. Standard
is not introduced. Existing Core/Full remain legacy execution scopes until all
existing cases and obligations have been mapped and migration has been reviewed.
Do not simply rename legacy results as new-profile results.

Users may run all cases or selected cases during development. Selected successful
cases alone cannot yield a complete-profile claim. A complete profile result must
account for every applicable case in the pinned profile definition. Variants remain
inside their approved cases; they do not become separate runtime test records.

Convenience selection sets may include “SSO” (Browser SSO plus Metadata),
“SSO and Logout”, and “All selected supported functions”. Sets are shortcuts for
selecting profiles, not additional conformance levels or certification ranks.
Do not infer that a declaration of unsupported functionality permits excluding
unconditional obligations.

## Configuration boundaries

Keep a target configuration fixed within its Plan. Use separately identified
Plan instances for configurations that cannot coexist. They may belong to the
same profile. A future profile may use multiple registered clients/peer identities
with documented purposes instead of toggling a single client during execution.
Each message and result must remain attributable to its configuration.

| Dimension | Treatment |
|---|---|
| AuthnRequest signature required/optional | Separate fixed-mode Plan instances; already implemented in [18](18-request-signing-plans.md) |
| Response/Assertion signature placement | Configuration variant when a target setting changes |
| Assertion encryption | Configuration variant when a target setting changes |
| Request/response Binding | Specify direction as well as Binding; separate configurations only when target settings require it |
| SP-initiated/IdP-initiated SSO | Browser SSO variants, not independent top-level profiles |
| NameID format, qualifier, ACS URL/index | Cases inside the profile when the target configuration permits them |
| Fresh/existing session, ForceAuthn, IsPassive | Isolated case preconditions and controls within the Plan |
| Metadata retrieval and key rollover | Documented scenarios with before/after evidence; distinguish an intentional transition from unrecorded configuration drift |

A setting being OFF does not by itself establish NOT_APPLICABLE. Preserve the
approved applicability rules and unresolved obligations. A missing signature
component, unavailable observation or incompatible fixture remains NOT_VERIFIED;
it is not a target failure or an automatic exclusion.

Keep essential connection and configuration choices in the main form. Generate
keys and routine fixtures where appropriate. Do not make individual negative
checks optional user switches. Diagnostic options may be more extensive than
those needed for profile verification.

## Public summary identity and evidence

The publication unit is a product/version summary with explicitly identified
roles, profiles, tested configurations and verification dates. Product identity
and version must be marked as operator-declared unless independently established.
A role may have a different profile/variant result from another role of the same
product. Do not silently substitute results from another version or configuration.

The summary must link to the actual source Runs and preserve Suite version/image,
profile-definition version, test/evaluation provenance, verification dates and
configuration. Separate observed evidence, self-attestation, declared exclusions
and externally unobservable obligations. A simple headline never replaces these
qualifications. Exact public schema changes remain an implementation deliverable;
existing result-v1 and Evaluator semantics remain authoritative meanwhile.

A summary can organize several results but cannot compute an overall conformance
claim by selecting the best case outcomes from incompatible Runs. Any future
cross-Run completeness rule requires independent review and evidence compatibility
checks. An older passing Run must not silently conceal a newer failing or incomplete
Run for the same selected configuration; show history and identify the selected Run.

## Visitor-facing result display

Display all catalog profiles relevant to the declared role, including those not
tested. Catalog availability and target support are different: an unavailable
Suite variant does not prove the product lacks support.

| Public state | Meaning and guard |
|---|---|
| Verification complete — conforms | The approved profile/variant assessment is COMPLETE and CONFORMANT |
| Nonconformance found | The assessment contains a nonconformance determination; may coexist with incomplete verification |
| Verification incomplete | Required verification is unresolved, interrupted or otherwise not complete |
| Not tested | No executed assessment is available for that profile/configuration; not synonymous with unsupported or nonconforming |

These are display labels, not replacements for the current outcome vocabulary.
Show conformance and completeness together. COMPLETE with
CONFORMANT_WITH_WARNINGS must visibly qualify the success label with warnings.
CONFORMANT_WITH_DECLARED_EXCLUSIONS must visibly state the declared exclusions;
it cannot receive an unqualified conformance label. INDETERMINATE and inconsistent
evidence cannot receive a success label even if execution has stopped. A started
but unfinished assessment is incomplete rather than “Not tested”.

Display the tested configuration close to each profile result. In particular,
make signature policy, encryption and Binding scope accessible without searching
raw logs. Unobservable and attested portions must not appear externally verified.
Do not use pass percentages as the principal product claim. If coverage is shown,
label its denominator and distinguish verification coverage from pass rate.

## Product-site badge

A product site may show a compact SAMLscope verification badge when at least one
profile/configuration qualifies for a completed conformance claim under the
reviewed rules. List the qualifying functions and link to the Suite-issued public
summary. A profile with warnings or exclusions needs its qualification visible;
badge eligibility for these qualified outcomes must be settled before issuing them.

Illustrative display copy only, not a real result or a result.json example:

> SAMLscope verified
>
> Example IdP — version X.Y
>
> Web Browser SSO · Metadata · Single Logout
>
> Tested as IdP · Verification date
>
> View tested configurations and results

The badge must identify product/version, target role and verification date, and
must not imply that unlisted features or other versions conform. The linked page
shows untested profiles and any other published failures/incomplete results for
the identified product/version. No “fully SAML compliant”, “all tests passed”,
or equivalent claim without an explicit and justified scope.

Use “SAMLscope verified”, not “Certified”, until a certification program and its
review/issuance process exist. OIDF-like usability does not imply OIDF endorsement.
Publication remains opt-in under [06](06-results-and-publication.md). Self-hosted
exports are not automatically eligible for a Suite-issued public badge; preserve
the existing distinction between local exports and hosted evidence-backed links.

The canonical summary is the source of truth. Deleted, unpublished, withdrawn or
superseded results must not continue to resolve as an unqualified current success.
The concrete badge transport, caching and withdrawal mechanism must be specified
before badge issuance; a copied image alone cannot establish current validity.

## Migration and implementation acceptance

- Inventory every existing approved case in the functional catalog and preserve
  its obligation owner, conditions, variants and positive/negative controls.
- Reuse one case in multiple profiles when the same approved behavior belongs to
  multiple functions. This does not duplicate execution within one Run.
- Split an approved case only when incompatible target configuration, a distinct
  protocol flow, independent verdict meaning, a user-visible function boundary or
  evidence attribution makes one execution ambiguous. A split requires the normal
  G2 design and independent approval process.
- Treat traceability rows as navigation and review data. Their count is not a test count.
- Preserve old Core/Full results and their original scope labels. Introduce
  versioned profile mappings before creating new functional-profile claims.
- Persist summary identity/configuration and validate result compatibility before
  publishing. Keep the current signed catalogs and approvals unchanged until reviewed.
- Verify that selected-test success, mixed configurations, another product version,
  warnings, exclusions and incomplete evidence cannot produce a misleading badge.
- Verify that relevant untested profiles remain visible, and that unavailable or
  withdrawn source results cannot be presented as current verified evidence.

## Remaining design work

The catalog, case execution unit and exact memberships are implemented, independently
approved through G2 and installed through digest-pinned profile definitions.
The numerical OIDF benchmark, qualified-outcome badge eligibility, summary schema,
badge delivery and withdrawal behavior remain later publication work; they are not
prerequisites for running and exporting the seven functional profiles.
