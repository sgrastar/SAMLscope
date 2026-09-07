# OIDF Conformance Suite alignment

The agreed SAML-specific catalog and public presentation contract are in
[20 — Functional profiles and public summaries](20-profiles-and-public-summaries.md).
That document supersedes earlier naming proposals based on Basic/Config labels.

## Product direction

The operator's goal is a SAML counterpart to the OIDF Conformance Suite, with
comparable user-facing profile granularity, configuration burden and certification
test-module counts. Use OIDC OP/RP certification plans as the initial comparison
scope; do not compare SAMLscope with the entire OAuth/FAPI/Federation suite combined.
Exact targets require a version-pinned inventory and have not been established.

Distinguish certification profile, configured Plan instance, test module, fixture
exchange and specification obligation. Compare like-for-like counts. Do not delete
approved obligations or controls to meet a user-interface count target.

A certification profile is a defined capability scope. Signing REQUIRED/OPTIONAL
is a configuration variant, not a new certification profile by itself. Separate
fixed-mode Plan instances remain useful for reproducible execution, while belonging
to the same logical profile. A profile may require several separately registered
clients/peer identities; settings need not all be global switches on one client.
Results may be grouped for navigation, but incompatible configurations must remain
visible and their best individual outcomes must not be combined into a conformance
claim without an independently reviewed aggregation rule.

Expose essential connection and profile-variant settings first. Generate keys and
protocol fixtures where appropriate. Diagnostic plans may expose more configuration
than certification-oriented plans. Existing SAMLscope Core/Full scopes must not be
silently relabeled as approved certification profiles.

## Next design evidence

Inventory representative OIDC OP/RP plans: profile boundaries, variant selectors,
mandatory/manual configuration inputs, registered-client requirements, visible test
modules and their internal checks. Pin the source revision and distinguish enabled
modules from all variants. Map those structures to current SAMLscope cases and
obligations to validate the agreed SAML functional-profile boundaries and propose module groups.
Any change to normative scope, controls or verdict aggregation requires the existing
G1/G2 independent review process. User-facing grouping alone must preserve traceability.

## Primary references

- https://openid.net/certification/connect_op_testing/
- https://openid.net/certification/connect_rp_testing/
- https://gitlab.com/openid/conformance-suite

The OP instructions describe profile selection and multiple registered clients for
some plans. The RP instructions distinguish certification profiles from more
configurable non-certification plans. These support the hierarchy above; they do not
establish a numerical parity target for SAML.
