# Formal evaluation of UI logo language selection

Connected [comparison inputs, browser observations and original correlation](58-ui-consumer-fixtures.md) to Runner cases and established Shibboleth `IIP-MD05-f9-idp-01` as Success in a formal Run. Evidence is the actual-screen difference: the preferred-language logo is selected when present; when no candidate matches preferred/alternative languages, selection switches to the language-neutral logo.

| Product/profile | Case | Formal result |
|---|---|---|
| Shibboleth/metadata_idp | IIP-MD05-f9-idp-01 | SATISFIED/PASS, attested=false |

<!--g1-literal--> Unverified observations decreased 467→466; distinct case IDs remain 157. Only this observation was adopted into generated comparison/inventory; other products were not inferred. Inventory-audit inconsistencies 0; inventory SHA-256: `22f622b87a2f9ba13568196755517d95f1d35bb5453fafac3a5c42492b1cf7e8`.

## Adopted evidence

Run: `run_GNBRVD9WSNFGHMXZEFN4BAH6NR`. Original observations: `build/acceptance/reference-20260918/shibboleth-ui-consumer-language-control/`; formal evaluation in sibling `shibboleth-ui-logo-evaluation/`.

`verify_ui_logo_acceptance.py` rechecks original XML/browser-candidate mappings, original Transcripts, local receipts, installed-record read-back, Runner replay/negative controls, restored configuration, fixed target metadata and formal CaseOutcome references before inventory adoption. Formal reason: `browser.ui-logo.language-fallback-observed`. Candidate tokens or configuration confirmation alone cannot establish a pass.

Browser observations/native preparation come from a trusted local adapter; no arbitrary HTTP evidence-submission mechanism was added. Screen evidence is Suite-managed browser observation, not a product-signed SAML response. Evaluation combines original-request correlation, fixed target, actual screen elements, language conditions and control differences.

Initial tests/start was rejected because normal login was incomplete. This is a required prerequisite for a Run starting with unauthenticated-screen observations. Without weakening conditions, performed normal login in the same Run before reevaluation. Added `complete_run_baseline.py` for reusable native metadata import, normal round trip and complete restoration.

## Validation and costs

<!--g1-literal--> 4 accumulated Java comparison/fixture tests and 1 Playwright boundary test passed. Replaying measured originals through production collection/comparison established SATISFIED; all 7 mutant controls were NOT_VERIFIED. Compilation/isolated distribution build passed. G1 generated-document consistency/structural checks 46/46. G2 remains 20/21 with protected-source signed difference G2-30 unresolved; release completion is not claimed.

Built in isolation from signed checkpoint `e8174820`. Running image: `samlscope:reference-ui-logo-oracle-v46`; digest: `sha256:0f04f7c9844540cdce76177c83c064613ad511f348b5490f4840c1f1f32088d5`. Unrelated uncommitted API changes were excluded.

<!--g1-literal--> Additional formal-evaluation operations: receipt installation 1; tests/start attempts 3, with 2 rejected for incomplete normal login and 1 success; normal-login round trip 1, adding 2 request/response Transcripts; normal-login configuration writes 3/deletion 1/Resolver reloads 2. Configuration fully restored. User interactions/product restarts 0. Suite image build 1; Suite/forwarder recreations 1 each. Earlier UI-observation batch costs are recorded in [58](58-ui-consumer-fixtures.md) and not counted again here.

Final display-name fallback, other products' UI displays, DiscoveryHint and URL-scheme evaluations remain incomplete.
