# SSO01-g campaign preparation

> Addendum (2026-10-31): The following is the record of the initial offline preparation. The Keycloak management API investigation and the live configuration driver, based on later user approval, are recorded in [SELF-REVIEW-KC.md](SELF-REVIEW-KC.md). The SAML campaign as a whole and the adoption of all four cases remain on hold.

2026-10-31. The target is ga/gb/gc/gj in `browser_sso_idp` for Keycloak and SimpleSAMLphp.
This time no real machines, Docker, network, or credentials are used, and the official ledger is not updated.
**Completing the tests of the preparation code and the feasibility of a real-machine campaign are separate matters. At present, running all cases is on hold for both products.**

## Basis and boundaries

- First checked AGENTS.md, docs/67-authn-context-native-acceptance.md, docs/82-generic-evidence-and-configuration-binding.md, and dev/reference-acceptance/GENERIC-BROWSER-CAMPAIGN.md.
- Read the definitions from line 34748 onward and line 35395 onward of `tests/cases.yaml`, and the negative controls from line 13657 onward and line 13951 onward of `tests/mutants/catalog.yaml`. Nothing was changed.
- `coverage.yaml`, `specs.yaml`, `predicates.yaml`, and `approvals/*` were not read, in accordance with the read prohibition for this task. No signature re-verification or independent reinterpretation of levels and conditions was performed. "Approved" refers to the G2 boundary indicated by the project documents; the PENDING_REVIEW field inside a case is not treated as proof of approval.
- All variants are exactly the `covers_variants` in the table below. All are owner_condition, default-all-of. The cases that were read contain no inheritance link declarations. Because coverage was not read, the completeness of transitive links will be confirmed, before the real machine run, in a verification environment where this is permitted. The owner's role/level/testability are not changed.
- The base of the local product evidence is written as `AUDIT` below.
  `build/acceptance/reference-20261002/cross-cluster-audit/authn-context-contracts/`.
  Checked `grouped-contract-review.json`, `kc-archived-bytecode-execution.json`, `ssp-public-source-execution.json`, and the stored code they point to. These are records from that time and do not prove future running versions.

## Conditions, all variants, and positive/negative controls

|case / case_digest|Tail of all variants and approved conditions|Positive control / negative control|
|---|---|---|
|IIP-SSO01-ga-idp-01 / `765d35ba28060794b59849437e24158b120872a6c4206ecf58688f9edfc897e8`|`ga#v-1c554772bb`: DeclRef follows the same minimum rule. `ga#v-96adbf55c8`: product low < high, and the success value for minimum low is ≥ low. `ga#v-f97a937262`: an error Response to an unachievable request is recorded as conforming.|`iip-sso01-ga-idp-01-positive` / `iip-sso01-ga-idp-01-negative`. baseline `idp-core-no-ecp` / mutant `mut-iip-sso01-ga-idp`. Detects a mutation where the success value falls below low.|
|IIP-SSO01-gb-idp-01 / `1bd2950222633a51bd756b9ac18629c82fb654b2821afc407d3fff84615d8c19`|`gb#v-09620a84ce`: unachievable error. `gb#v-5fe19b2dd9`: product low < high, and the success value for better low is > low. `gb#v-a24a0bb304`: DeclRef follows the same rule.|gb positive/negative with the same naming, baseline same as above / `mut-iip-sso01-gb-idp`. Detects a success at or below low.|
|IIP-SSO01-gc-idp-01 / `2907382964c0928d342d883bc76dd3331922dea687a1dcd64c8f363fa25a325c`|`gc#v-783eafdabe`: low < medium < high, only low/medium available, and on success with maximum high the result is medium. `gc#v-eb393305b0`: unachievable error. `gc#v-f709ff344a`: DeclRef follows the same rule.|gc positive/negative with the same naming, baseline same as above / `mut-iip-sso01-gc-idp`. Also detects a mutation that returns low although medium is available. "At or below the upper bound" alone is insufficient.|
|IIP-SSO01-gj-idp-01 / `87b0066aa931850eb730d22136df8bf53253518c4b662a01ea60bec9e87dba15`|`gj#v-1650dc6d0a`: for a satisfiable DeclRef, the first one takes precedence. `gj#v-3a6f061c0d`: the same candidates in reverse order, with the success value also reversed. `gj#v-f1a318dbe9`: for satisfiable, different ClassRefs [A,B], A takes precedence.|gj positive/negative with the same naming, baseline same as above / `mut-iip-sso01-gj-idp`. Detects mutations including ignoring DeclRef order. A single candidate or an error is not a positive control for order.|

All variants in the table above are prefixed with `IIP-SSO01.`. If a positive or negative control fails or is not run, treat it as control_failed/NOT_VERIFIED and do not treat it as success.
Do not extend a conclusion that covers only ClassRef to the whole case. ga/gb/gc permit an error, but if every request is an error there is no successful-selection control, so the whole is unverified.
An unachievable request requires an original SAML error whose correlation, signature, and so on have been verified. HTTP 500, silence, or HTML are not substituted.

## Differences from Shibboleth

Actually import `dev/shibboleth/authn_context_preparation.py:inputs()` and reuse its request matrix.
The evaluation conditions are 2 each of CLASS/DECLARATION per case, and maximum EXACT low/medium controls are prepared for each kind.
This time, in addition, EXACT low/high is collected for each kind during the normal setting to corroborate the candidate availability for gj.
Combine into normal and maximum, and read back from the product before and after communication in the same state. The normal-SSO restoration control is done separately.

Shibboleth could set `AuthnComparisonRules`, Password.supportedPrincipals, and `saml2`/`saml2declref` on the product itself.
In docs/67, ga/gb/gj success was adopted, and for gc, product non-conformance was adopted for ClassRef medium and DeclRef low. This cannot be carried over to other products.
At that time there were 20 round trips of evaluation and availability controls plus normal SSO after restoration; this plan, including the independent controls for gj, becomes 24 conditions plus normal SSO.

The Docker operations, default credentials, automatic login, and dedicated Shibboleth receipt exporter of the old campaign are not imported.
`export_authn_context_preparation.py` re-verifies Shibboleth's XML and Password flow, so it cannot be reused by merely swapping the product name.
From Keycloak's `browser_chain_campaign.py`, only the public read-back projection and the comparison/restoration method are referenced; the authenticated module itself is not imported.
For SimpleSAMLphp, wrap `configuration_batch.py:ConfigurationBatch` and reuse its inode preservation and external-edit rejection.
The old applied_count is the host application count, so it is not used as the product's effective application count.

### Unresolved items in the communication path

For the g series, `AuthnContextConfigurationTestCase.evidenceActionKeys()` is empty in CONFIG.
Merely adding to the generic collector's `caseIds` does not generate comparison requests.
The old Shibboleth calls `/start/metadata-preloaded/{index}` of `SamlScopeApplication`, which generates the signed request, updates the Run, and records to the Recorder, but the routes that were checked do not generate a persisted outbox action.
Therefore we do not claim that the outbox requirement specified this time is satisfied by the old path alone.
In future, independently confirm that all 24 conditions can be retrieved from the current signed Run as **persisted outbox/browser actions of the existing Runner**.
If the correspondence among condition, original request, and actionId cannot be confirmed, stop before sending. Do not create a new direct HTTP sender or a fallback to preloaded.
If the necessary Suite-side path work falls under the protected implementation, it requires independent review and a G2 update as separate work. It is not done within the write scope of this task.

## Hypotheses for the product's own configuration path

### Keycloak

Basis: AUDIT's `AuthnContextClassRefMapper.javap.txt` references enabling via `STEP_UP_AUTHENTICATION_SAML`, `LoAUtil.getCurrentLevelOfAuthentication`, the client note `saml_authn_context_class_ref`, and `AcrUtils.getUriLoaMap`.
`AcrStore.javap.txt`/`LoAUtil.javap.txt` and the audit records indicate native LoA candidates, but do not prove a complete implementation of comparison or DeclRef support.

|Condition|Hypothesis of the configuration path|To confirm on the real machine|
|---|---|---|
|minimum/better|Combine the SAML step-up feature, a dedicated client's native URI→LoA map, a dedicated native authentication flow, and the ClassRef mapper. low/medium/high are obtained from the map adopted by the product.|Running state of the feature, exact attribute names and configuration API, all executions and authenticator configs, the actual selection for each LoA, and minimum/better interpretation. Do not judge SAML support from OIDC configuration alone.|
|maximum|Use the high of the same native map as the upper bound, and make a dedicated flow in which only low/medium are achievable with the same login input.|Completeness of the available set, unreachability of high, low/medium EXACT success, selection of the maximum permitted value, unachievable error.|
|First-precedence|Fix the native map and flow, make low/high EXACT each succeed, and reverse only the order of the candidates.|Whether the request order is actually used. Do not confuse LoA numeric order with preference order.|
|DeclRef for all cases|A native configuration path cannot be identified from the stored materials.|Confirm acceptance, comparison, and Response/AuthnContextDeclRef output with the same configuration. Do not infer from the existence of the ClassRef mapper. If not satisfied, hold all cases.|

The hypothesis limits the change scope to the dedicated client, mapper, dedicated flow, and related executions/config. The whole realm and existing shared flows are not rewritten.
Obtain the original state including dependencies through the product API, and save only the public configuration. Count the difference check by product GET separately from PUT success.
Host write success is 0 (not applicable) for the management API approach, and the native management API success count is tallied separately.
On restoration, re-confirm the existence/non-existence of the dedicated objects, references, and exact match of the original public representation. Exports containing secret values are not read.

### SimpleSAMLphp

Basis: AUDIT's `RequestedAuthnContextSelector.php` reads the numeric keys of `contexts` → identifier/source and default, and for ClassRef exact it searches in the order of the request array.
On the other hand, minimum/maximum/better explicitly `throw new Exception('Not implemented.')`.
DeclRef-only enters the default branch without ClassRef.
In the stored copy `build/acceptance/reference-20261004/ssp-nameid-omission-readonly-preflight/SimpleSAML_Module_saml_IdP_SAML2.php`, line 1167 onward sets ClassRef, and no DeclRef setter could be confirmed at that generation site.

|Condition|Hypothesis of the configuration path|To confirm on the real machine|
|---|---|---|
|minimum/better/maximum|Native contexts of `core:RequestedAuthnContextSelector` are a candidate. However, it is unimplemented in the stored version, so as it stands the precondition for execution is not met.|Whether the standard functionality of a future running version has an implementation. If another standard source exists, add evidence via stored source and read-back. Otherwise keep NOT_VERIFIED.|
|First-precedence|Place a dedicated selector that uses a credential-free source reference in the native authsources configuration, and point the IdP's auth reference at it. Fix numeric contexts low/high.|Source selection, EXACT low/high success, forward/reverse success, and the auth configuration the product actually loaded plus all dependencies of selector/source/filter.|
|DeclRef for all cases|There is no reproducible path in the stored version.|Whether DeclRef can be generated by standard configuration. A partial experiment with ClassRef only cannot be adopted for all cases.|

The `saml:AuthnContextClassRef` filter is a fixed label and not an implementation of strength comparison.
`ExpectedAuthnContextClassRef` is validation of the SP's received state and is not repurposed for the IdP's comparison processing.
Do not rewrite responses or implement comparison with custom PHP and treat it as "the product's own functionality".
authsources.php as a whole may contain credentials, so it is not read this time. In future too, use a separated file containing only public selector/source references, and do not save the original file containing secrets as evidence.
After a host write that preserves the inode, obtain the effective values by projecting them from the product PHP's Configuration/running process.
A cat of the same mount alone cannot prove effective application. In case of opcache or mount inconsistency, diagnose and do not repeat the login.

## Contract for code and future adapters

`keycloak_campaign.py` and `simplesamlphp_campaign.py` expose only `--dry-run --out ...`.
Because the product path and the outbox path are not yet determined, no live backend is bundled. Real-machine execution is not feigned with a blank management API or arbitrary shell hooks.
`campaign.py` uses an injected driver to implement membership check → original state capture → configuration application for the 2 groups → read-back before and after each communication → finally restoration → original state reconciliation, and unit tests use only a memory driver.
This is preparation code for connecting a future driver, and is not a deliverable meaning that a real-machine campaign will run to completion with this CLI.

The driver implements `preflight(product, caseIds)`, `capture()`, `apply(mode, counters)`, `read_effective()`, `collect_existing_outbox(input)`, and `restore(original, counters)`.
preflight confirms the real Run's profile/role/target/hash/case digest, signed-definition compatibility, and backing for native order/DeclRef/all-condition outbox.
Each real write in apply and restore is counted before the attempt by `Counters.write(...)`, and host success and native success are each counted on completion.
If one apply writes multiple settings, count each real write. It is not decided that 1 group = 1 write.
`read_effective` is a fingerprint of all dependencies of the public configuration as interpreted by the product. A mere host hash is not acceptable.
`collect_existing_outbox` consumes the existing Run/action exactly once and returns the Recorder request/response and the original bytes digest. On timeout/UNKNOWN_DELIVERY, stop and keep the same handle, and do not resend automatically.
A future implementation using the generic collector's browser display, non-persistence of credentials, and fresh/reuse policy will be reviewed separately. If the g series remains with empty actions, hold at preflight.

Logs are supplemental/unadopted and do not generate official receipts, Outcomes, or Verdicts.
A future product-specific receipt reader will independently verify the original Run, metadata, request fingerprint, signature, decryption, destination, issuer, Audience, SubjectConfirmation, RelayState, and action/session/operation, and rerun the positive/negative controls.
Reattaching originals to another Run or inserting a case is not permitted. The IDP19.b-specific source-Run binding of docs/82 does not apply to the g series.
If restoration is unconfirmed, adoption is not allowed. Official cases return only outcome, and the Evaluator converts level to Verdict.

## Estimate of operation counts

For 1 product, no retries, with all preconditions satisfied: 24 condition communications, 1 M0 after restoration, and 1 more if a pre-start M0 is needed.
For 2 products, 50 to 52 round trips is the baseline for the planning upper bound. If every request used an independent browser, logins would be at most 26 per product; fewer if shareable, but not measured.
Logout is planned as 0 times, and closing a fresh context is not counted as logout. The click counts for MFA, consent, and IdP screen transitions are not measured.
If explicit logout is needed, add the count separately. Whether administrator operations can be automated is unconfirmed.
Native configuration is 3 groups: normal/maximum/restore. The number of writes depends on the number of dependent objects and is therefore undetermined.
The dry-run outputs the minimum attempt count of 3 for the case of 1 group = 1 write, and the minimum counts of product GET/read-back, etc., distinguished from measured values.
Until the known holds are resolved, all planned real-machine writes/communications/logins remain 0. Do not log in first for exploration.

## How to run (offline only)

```sh
PYTHONDONTWRITEBYTECODE=1 python3 dev/reference-acceptance/sso01g/keycloak_campaign.py --dry-run --out dev/reference-acceptance/sso01g/dry-run-keycloak
PYTHONDONTWRITEBYTECODE=1 python3 dev/reference-acceptance/sso01g/simplesamlphp_campaign.py --dry-run --out dev/reference-acceptance/sso01g/dry-run-simplesamlphp
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s dev/reference-acceptance/sso01g -p 'test_*.py' -v
```

The output destination is only this sso01g directory or a child of the specified job directory. Existing dry-run JSON is not overwritten.
Generation of the ledger, comparison, and inventory is separate work after real-machine adoption. The count of unverified observations does not change this time.
