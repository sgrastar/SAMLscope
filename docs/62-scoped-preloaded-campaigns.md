# Scoped SP preloading and SimpleSAMLphp attribute comparison

Added a native collector using standard `core:AttributeCopy` to extend the adopted Shibboleth per-SP attribute comparison to SimpleSAMLphp. Original XML is parsed by the product's own SAMLParser; each SP authproc copies uid to a common anchor and dedicated attributes. Both SP configurations are installed together, read back from the actual container before/after each round trip, and restored to the original file at completion.

The reference product's source confirms `AttributeCopy` handles multiple array-form destinations. This configures a standard product feature rather than implementing conformance behavior for it. Attribute values/login inputs are not recorded. The shared per-SP protocol collector is intended, but SimpleSAMLphp preparation audit/formal adoption are not connected yet.

## Problem found in the first product attempt

The existing preloaded aggregate also contained UI URL comparisons. SimpleSAMLphp native parsing threw an invalid-logo-URL exception before reaching the SPs required for attribute comparison. Original: `build/acceptance/reference-20260918/simplesamlphp-relying-party-attributes/fixture.xml`; diagnosis: `parser-failure.stderr`, `attempt-status.json`. This is not converted into product FAIL.

<!--g1-literal--> Run/preflight 1 each; aggregate fetch 1; native parsing 2, including reanalysis of the failure cause. Execution stopped before configuration changes, so product writes, protocol round trips and user interactions were 0. The driver was also changed to use fixed errors excluding full command text.

## Suite correction

Added optional `variants` to `POST /api/runs/{id}/metadata-lab/preloaded`. Empty bodies/objects retain all existing candidates. Explicit empty lists, duplicates, out-of-scope variants and null are rejected. The Suite generates signed aggregates for only the selected scope; external scripts do not rewrite XML before delivery.

Metadata fetch, download and browser execution share the Run-persisted scope list. Rearming rotates the token, which is also part of the cache key. This prevents returning an old aggregate in the same Run after scope changes. New imported originals/evidence are recorded separately.

Excluded javascript/file URL negative controls from positive preload candidates. Individual ordinary/polling URL tests remain. Support for data or other capabilities is not assumed uniformly; selecting the required scope avoids import failures caused by combining unrelated capabilities.

The SimpleSAMLphp driver now selects only existing distinct SPs required for attribute comparison. The new API has not yet been deployed at this stage; retesting with it is next.

<!--g1-literal--> API/generator/Run-management/validation compilation succeeded. Added checks for scoped SP membership, rejection of out-of-scope negative controls/duplicates/empty lists, and invalidation of old tokens. Functional tests await batch execution. Unverified observations remain 465.

## Scoped deployment and formal adoption

Built in isolation from signed `418e9603` and deployed `samlscope:reference-scoped-preload-v50`; digest: `sha256:3bcdb93e2ed9e86d928b43b6323058ea4bd2f2d8036232f4bfa07adbc7876e3d`. Unrelated uncommitted SOAP changes were excluded.

<!--g1-literal--> New SimpleSAMLphp Run `run_WNMZ106QK6JKRN8P6JFZQ0KNWG` successfully parsed an aggregate restricted to 2 SPs through native import. Collected 3 A/B/A round trips with fixed configuration, then restored original bytes. SP B is the final aggregate member, so the generic driver recorded its ACS completion screen as unhandled. Original correlation/signatures/decryption succeeded; this screen label was not used as evaluation evidence.

The shared collector established anchor/first for A, anchor/second for B, and anchor/first for the repeated A. Attribute-input fingerprints matched. SimpleSAMLphp preparation audit checks standard AttributeCopy mappings, SP association, NameFormat, encryption/request-signature settings, original fixture, native parser output, applied overlay and before/after configuration read-back. PHP processing is not replaced with Suite-side XML interpretation.

Added native-configuration differences to `verify_relying_party_attribute_experiment.py` and the preparation exporter; Java evaluation, original collector and CONFIG cases remain shared. Confirmed unchanged regenerated Shibboleth preparation records and successful adoption checks.

<!--g1-literal--> Formal comparison of saved originals was SATISFIED and rejected 6 evidence-contamination/incompleteness controls. Subsequently completed normal login and installed/read back Run-specific preparation. Formal Run `IIP-IDP02-a-idp-01`: SATISFIED/PASS, attested=false. Regenerated comparison/inventory through adoption validation; unverified observations decreased 465→464 (−1), with case IDs unchanged at 157.

Evidence: `build/acceptance/reference-20260918/simplesamlphp-relying-party-attributes-scoped/`; formal evaluation: `simplesamlphp-relying-party-attribute-evaluation/`. The earlier failed broad-aggregate Run remains retained in the preceding history.

<!--g1-literal--> This campaign: image build 1; Suite/forwarder recreations 1 each; new Run/preflight 1 each; import parsing 2, for per-SP aggregate and normal-login metadata; container policy read-backs 7; product writes 4, comprising comparison application/restoration 2 and normal-login application/restoration 2; protocol round trips 4; preparation installation 1; tests/start 1; preparation confirmation 1. Product restarts/service reloads/user interactions 0. An operational wait followed application because of standard OPcache. Earlier failed-attempt costs are recorded separately, not hidden in these counts.

Consolidated normal-login import/restoration in `dev/simplesamlphp/complete_run_baseline.py` for reuse. Broad functional tests were again not executed; required original/adoption-boundary checks ran. Existing G2-30 signed-source difference remains unresolved.
