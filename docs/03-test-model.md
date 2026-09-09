# 03. Test Model

> **Current profile model:** An approved case remains the execution and verdict
> unit. New Plans select a versioned functional profile, which is a reviewed set of
> those cases. The Core/Full labels below document the legacy result model and do
> not create a second execution path. See [20](20-profiles-and-public-summaries.md).

## 1. Data Model

```
Profile          Static, versioned set of approved cases for one function and role
  └─ Requirement Static. IIP-G01 … IIP-IDP21 (69 items)
       └─ Obligation ★ Static. An obligation unit of “role × condition × RFC2119 level” within one requirement
            └─ TestCase  Static. 0..N cases per Obligation. YAML + implementation class

TestPlan         Created by the user. Profile + Target + configuration declarations + issued Test Peer key/entityID
  └─ TestRun     One execution
       └─ CaseRun  Execution result for one case (Verdict + rationale + Transcript reference)

Determinations are aggregated in the order CaseRun → Obligation → Requirement (by role) → Run (§6, §7)
```

### ★ Why the Obligation Layer Is Necessary

Within a single requirement ID, **different levels by role** and **conditional obligations** coexist.
Correct FAIL / WARNING results cannot be derived from `applies_to: [idp, sp]` and a single `level`.

| Requirement | Structure of the original text |
|---|---|
| IIP-MD01 | *Identity Providers **MUST** and Service Providers **SHOULD** support … the Metadata Query Protocol* |
| IIP-MD10 | *… Identity providers **MUST** and Service Providers **SHOULD** limit the use of algorithms* |
| IIP-SP13 | *Service Providers **MUST** support the ability to reject unsigned `<samlp:Response>` elements and **SHOULD** do so by default* |
| IIP-SP14 | *Service Providers **SHOULD** support the … SingleLogout profile. Service Providers **that claim support for this profile MUST** be capable of issuing logout requests* |
| IIP-ALG08 | *… **MUST** support the ability to prevent the use of particular algorithms … The set of such algorithms **MUST** be configurable and it is **RECOMMENDED** that the default set include …* |
| IIP-MD09 | *… **MUST** be capable of publishing the cryptographic capabilities … It is **RECOMMENDED** that they support dynamic generation* |

Therefore, requirements are decomposed into obligations.

```yaml
# tests/coverage.yaml
- id: IIP-SP13
  obligations:
    - key: IIP-SP13.a
      roles: [sp]
      level: MUST
      condition: null
      summary_en: "Support the ability to reject unsigned <samlp:Response> elements"
    - key: IIP-SP13.b
      roles: [sp]
      level: SHOULD
      condition: null
      summary_en: "Reject unsigned <samlp:Response> elements by default"

- id: IIP-SP14
  obligations:
    - key: IIP-SP14.a
      roles: [sp]
      level: SHOULD
      summary_en: "Support the SAML V2.0 SingleLogout profile"
    - key: IIP-SP14.b
      roles: [sp]
      level: MUST
      condition: declared_features.single_logout == true   # ★ Conditional MUST
      summary_en: "If claiming SLO support, be capable of issuing logout requests"
```

- `condition` is evaluated using **three-valued logic** (see ★ below). If false, it is **`NOT_APPLICABLE`** (excluded from the denominator).
- The determination level is set **per obligation unit**. If `IIP-SP13.a` is not satisfied, the result is FAIL;
  if `IIP-SP13.b` (reject by default) is not satisfied, the result is **WARNING** (not FAIL).
- A requirement's Verdict is the aggregation of the obligations applicable to that role (§6).

### ★ Separate Condition Evaluation: `effective_result` and `conflict`

If `condition` is evaluated solely from the Test Plan's self-declaration,
one can avoid a conditional MUST simply by declaring, **“SLO is not supported.”**

The evaluation produces **two independent values**. If they are collapsed into one,
“whether it should be executed” and “whether there is a contradiction” can no longer be distinguished.

```
effective_result ∈ { TRUE, FALSE, UNKNOWN }   → whether to execute the case (scheduling)
conflict         ∈ { true, false }            → whether the declaration and observation disagree
```

| `effective_result` | Case | Input to obligation |
|---|---|---|
| `TRUE` | Execute | (None. Aggregate the case as usual.) |
| `FALSE` | Do not execute | `NOT_APPLICABLE` |
| `UNKNOWN` | Do not execute | `NOT_VERIFIED(applicability_undetermined)` |

`conflict = true` injects `INCONSISTENT` into the obligation aggregation **independently of** `effective_result`.
Because `INCONSISTENT` ranks higher than `NOT_APPLICABLE` in severity order,
an obligation **cannot be silently excluded while contradictory**.

| declared | observed | effective_result | conflict | Result |
|---|---|---|---|---|
| true | true | `TRUE` | false | Execute |
| false | false | `FALSE` | false | NOT_APPLICABLE |
| **false** | **true** | `TRUE` (observation takes precedence) | **true** | Execute + `INCONSISTENT` |
| **true** | **false** | `FALSE` (observation takes precedence) | **true** | Do not execute + `INCONSISTENT` |
| true / false | No evidence | Depends on predicate type (below) | false | — |
| No evidence | No evidence | `UNKNOWN` | false | `NOT_VERIFIED` |

### ★ Handling of “Declaration Only” Depends on Predicate Type

When no observational evidence is available, whether the declaration may be adopted as-is **depends on the nature of the condition**.
Adopting it uniformly would allow a MUST to be excluded simply by selecting `target.kind = token_translation_proxy` or
`outbound_encryption: false`.

| Type | Nature of condition | Example | `FALSE` declaration when no observational evidence is available |
|---|---|---|---|
| `CLAIM_BASED` | The condition itself is **whether support is claimed** | IIP-SP14.b *SPs **that claim support** for this profile* | ✅ **Adopt `FALSE`**. The declaration itself is the truth value. |
| `CAPABILITY_BASED` | The condition is actual capability | IIP-MD08 *implementations **that support outbound encryption*** | ❌ **`UNKNOWN`** → `NOT_VERIFIED(applicability_undetermined)`. The absence of capability cannot be proved by declaration alone. |
| `CLASSIFICATION_BASED` | The condition is the product classification | IIP-IDP13 *does not apply to **token translation Proxies*** | ❌ The default is **`UNKNOWN`** (with the exception below). |

Because rerunning a `CLASSIFICATION_BASED` condition does not increase the observational evidence,
a complete report can never be produced while it remains `UNKNOWN`. Therefore, only the
explicit exclusion-declaration path is opened.

```
Only when the user makes an explicit exclusion declaration that
“this product is a token translation Proxy”
(check box + entry of a reason), adopt:
effective_result = FALSE. However:

  - Record applicability[].basis = "declaration_only_exclusion"
  - Count it in coverage.excluded_by_declaration
  - Leave a machine-readable record in run.scope_qualifications[]
  - ★ run.conformance must not become CONFORMANT / CONFORMANT_WITH_WARNINGS
```

### ★ A Run with a Declaration-Only Exclusion Does Not Return `CONFORMANT`

Merely adding a note to `conformance_statement` is insufficient.
**Badges and API consumers read only `run.conformance`.**
That would make it possible to mechanically obtain `CONFORMANT` with the ECP MUST excluded simply by declaring,
“This is a token translation Proxy.”

Therefore, **make it appear in the enum value itself**.

```
run.conformance ∈ {
    CONFORMANT,
    CONFORMANT_WITH_WARNINGS,
    CONFORMANT_WITH_DECLARED_EXCLUSIONS,   ★ Newly added
    NON_CONFORMANT,
    INDETERMINATE
}

excluded_by_declaration > 0 and everything else is satisfied
    → CONFORMANT_WITH_DECLARED_EXCLUSIONS   (regardless of whether WARNING exists)
```

A naïve consumer branching on `run.conformance == "CONFORMANT"` **will not match this value**.
The problem of the second field being skipped cannot occur.

Also retain machine-readable details in `run.scope_qualifications[]`.

```json
"scope_qualifications": [
  { "kind": "declared_exclusion",
    "predicate": "is_token_translation_proxy",
    "target_kind": "token_translation_proxy",
    "excluded_obligations": ["IIP-IDP13.a", "IIP-IDP13.b"],
    "reason": "<reason entered by the user>",
    "attested_by": "<user identifier or 'anonymous'>",
    "attested_at": "2026-08-25T04:12:03Z",
    "verified": false }
]
```

`target.kind` must also always be included in the result JSON ([06 §1](06-results-and-publication.md)).

### ★ The Exclusion Scope Is Limited to the Requirement Containing the Original Exclusion Text

In the example above, only the **obligations of IIP-IDP13** are excluded.
*This requirement does not apply to token translation Proxies.* is
**a sentence at the end of IIP-IDP13** and does not extend to IIP-IDP14–16.
IDP14 (HTTP Basic), IDP15 (SAML-EC keys), and IDP16 (ECP configuration metadata import)
are **unconditional MUSTs**.

- `excluded_obligations` is **not manually enumerated**.
  The Evaluator mechanically collects the obligations with the relevant `condition` in `coverage.yaml`.
- If an exclusion predicate spans multiple requirements, `:specReconcile` obtains the original text and confirms that
  the exclusion text exists in the original text of **each requirement** ([04 Design Gate G1](04-requirement-coverage.md)).
- CI rule 5b-4: if an obligation with the same `predicate` is attached to a requirement whose
  **corresponding section in the original text contains no exclusion text**, reject it.

> If the exclusion scope expands by even one requirement, **an unconditional MUST can be removed by self-declaration alone**.
> The scope to which an exclusion predicate is attached is itself the subject of G1 review.

**Do not create a path for silent exclusion.** Exclusion is possible, but it must always appear at the top level of the result.

### Observational Evidence

Each condition is evaluated from **both the declaration value and observed facts**.

| Condition | Type | Declaration | Observation (precedence) |
|---|---|---|---|
| `claims_single_logout` | `CLAIM_BASED` | `declared_features.single_logout` | — |
| `supports_single_logout` | `CAPABILITY_BASED` | Same as above | `<SingleLogoutService>` in the target metadata / actual issuance of a LogoutRequest |
| `supports_outbound_encryption` | `CAPABILITY_BASED` | `declared_features.assertion_encryption` | Whether `<EncryptedAssertion>` / `<EncryptedID>` was actually generated |
| `supports_ecp` | `CAPABILITY_BASED` | `declared_features.ecp` | Whether the target metadata's `SingleSignOnService` has a SOAP binding |
| `is_token_translation_proxy` | `CLASSIFICATION_BASED` | `target.kind` | — (explicit exclusion declaration only) |

Rules:

1. **If observation contradicts the declaration, set `conflict = true`**. Observation takes precedence for `effective_result`.
2. Handling when no observational evidence is available depends on the **predicate type** (the table above).
3. The basis for the applicability determination (`declared` / `observed` / `effective_result` / `conflict` / `basis`) is
   recorded **for every item** in the result JSON ([06 §1](06-results-and-publication.md)).
4. `ApplicabilityEvaluation` is an explicit input to `Evaluator.evaluate()` (§6.2, §7.5).

### ★ Meaning of Links — `linked_obligations`

The original text sometimes **incorporates a rule from another section as-is**.
For example, the beginning of IIP-IDP16 (ECP, §2.3.10) **inherits the rules of Browser SSO §4.1.6**.
Representing this only as a note would cause the inherited portion to be omitted when creating cases in G2.
Therefore, `coverage.yaml` carries a **machine-readable link**.

```yaml
linked_obligations:
  - obligation: IIP-SSO06.a
    kind: inherit_variants          # The only type currently defined
    variant_applicability: linked_condition
    note_en: "…why it is incorporated…"
```

**Definition of Meaning** (G2 / implementations MUST handle this accordingly):

| # | Rule | Reason |
|---|---|---|
| **L1** | `kind: inherit_variants` means that "**A's cases MUST also cover B's `required_variants`**." Expansion is **transitive** | To prevent inherited items from being omitted from case design |
| **L2** | `role`, `level`, and `testability` always come from A. Variant applicability defaults to A's condition (`owner_condition`). When the incorporated rule expressly retains B's applicability boundary, set `variant_applicability: linked_condition`; only the imported variants then use B's condition | A is established in a different context, so actor and level must not leak across the link. At the same time, dropping an element-level capability condition can turn unsupported optional functionality into a violation |
| **L3** | Expanded variants are referenced using **`<obligation-key>#<variant-id>`** (the `covers_variants` notation) | To identify which obligation a variant originated from |
| **L4** | **Do not double-count**. Even if A's case covers B's variant, **B's coverage is not satisfied** (and vice versa). The denominators for completeness / mutant coverage are counted **per obligation** | To prevent “B is also done because A has a case” |
| **L5** | Include the **set of expanded variant IDs** in the case digest. Editing B's variant changes the digest of A's case as well, requiring **re-review** | To prevent changes to B from silently propagating to A's cases |
| **L6** | `docs/04` outputs “**reference import**” on A's side and “**referenced by**” on B's side | If only one direction is shown, editors of B may fail to notice the impact scope |

**Enforced by CI** (`tools/g1_validate.py`):

| Check | Content |
|---|---|
| `SR-22g-shape` | Must have the shape `{obligation, kind, optional variant_applicability, note_en}` |
| `SR-22d` | The reference target exists |
| `SR-22e` | It is not a self-reference |
| `SR-22f` | There are no cycles |
| `SR-22g` | `kind` is a defined vocabulary term (currently only `inherit_variants`) |
| `SR-22h` | Expansion is finite (within depth 4) and non-empty |
| `SR-22i` | The import target is not `NOT_OBSERVABLE` (which would make the link meaningless because there are no variants) |
| `SR-22j` | `variant_applicability` is `owner_condition` or `linked_condition` |
| `SR-22k` | `linked_condition` points to an obligation that actually has a condition |

> **When adding a type, update `docs/03` (this table) → `LINK_KINDS` in `g1_author.py` →
> `SR-22g` in `g1_validate.py` at the same time.**
> This prohibits artifacts from containing a `kind` whose meaning is undefined.

## 2. Test Plan Components

The original memo's UI proposal contained only “Profile / metadata URL / options,”
but this would leave many tests impossible to execute. The actually required components are as follows.

```yaml
name: "Keycloak 26 IdP"
profile: idp-full                  # idp-core | idp-full | sp-core | sp-full

target:
  kind: idp | sp | token_translation_proxy   # ★ Used to determine applicability
  #  Selecting token_translation_proxy makes IIP-IDP13 NOT_APPLICABLE
  #  (original text: "This requirement does not apply to token translation Proxies.")
  entity_id: "https://kc.example.org/realms/test"
  metadata_source:
    kind: url | mdq | upload
    location: "https://kc.example.org/realms/test/protocol/saml/descriptor"

# How to deliver the Suite's metadata to the target ★ A precondition for many metadata-related tests
suite_metadata_delivery:
  kind: manual | http_url | mdq
  # manual  = The user downloads the XML and pastes it into the target
  #           → IIP-MD01–MD04 are NOT_VERIFIED(plan_configuration).
  #             They are not NOT_APPLICABLE (they remain in the denominator,
  #             and the Run becomes conformance=INDETERMINATE / completeness=INCOMPLETE)
  # http_url= The target periodically retrieves the Suite's metadata URL
  # mdq     = The target queries the Suite's MDQ (required to verify IIP-MD01)

declared_features:               # Optional features that the target declares it implements
  single_logout: true
  ecp: false
  assertion_encryption: true
  encrypted_nameid: false
  idp_discovery: false           # SP only
  accepts_unsolicited_sso: true  # SP only. If false, fall back to the arming method

parameters:
  clock_skew_tolerance_seconds: 180   # Interpretive value for “reasonable.” MUST always be recorded in the result
  metadata_refresh_wait_seconds: 300  # Waiting time for IIP-MD02
  test_user_hint: "testuser / Notes on the login method (not shown in the result)"

interaction:
  allow_browser_steps: true      # If false, limit tests to back-channel-only tests
  allow_attestation: true        # If false, ATTESTED cases become
                                 # NOT_VERIFIED(interaction_disallowed).
                                 # INDETERMINATE is limited to cases where execution occurred but evidence was insufficient
```

> **Important**: `declared_features` and `parameters` **MUST always be recorded in the result**.
> Without them, two results cannot be compared. A number such as “PASS 74” has no meaning by itself.

## 3. Testability Classification (5 Categories)

SAML black-box tests cannot all be observed mechanically.
Because this point was completely absent from the original memo, it is explicitly modeled here.
This classification is recorded in `coverage.yaml` **for each obligation** ([05 §2.1](05-test-definition-format.md)).

| Mode | Description | Example |
|---|---|---|
| `AUTOMATED` | The Suite interacts directly with the target and completes the test. No browser is required | Static metadata inspection, MDQ, SOAP SLO, ECP |
| `BROWSER` | The user's browser is required as the SAML user agent | Web Browser SSO in general |
| `ATTESTED` | Because behavior inside the target is not visible externally, the user is asked structured questions and provides answers | “Did the SP display an error and not create a login session?” |
| `CONFIG` | After asking the user to change the target's configuration, perform `AUTOMATED`/`BROWSER` | Have the target reload the Suite's metadata, change the attribute release configuration |
| `NOT_OBSERVABLE` | It cannot in principle be verified externally. Do not create a test; report it with a reason | “Does not assign meaning to persistent NameID” (IIP-SP12) |

### Handling ATTESTED

```
┌──────────────────────────────────────────────┐
│ IIP-SP13-02  MUST reject an unsigned Response │
├──────────────────────────────────────────────┤
│ The Suite POSTed an unsigned Response to the  │
│ SP's ACS.                                     │
│                                              │
│ What happened on the target SP's screen?      │
│  ○ An error was displayed and login did not   │
│    occur                                       │
│  ○ Login succeeded                 ← FAIL     │
│  ○ Other / Don't know              ← Hold     │
│    determination                              │
│                                              │
│ [Submit]  [Recheck the browser's actual screen]│
└──────────────────────────────────────────────┘
```

- Results based on the user's report MUST always be displayed as `(attested)` in the report
- If the report conflicts with observations (for example, the Suite observed issuance of a session Cookie through HTTP 302, while the user reported that “login did not occur”), issue an `INCONSISTENT` warning
- Public results MUST always display the number of attested items

## 4. Verdict Vocabulary

Strictly distinguish between **not applicable** and **could not be verified**. This is the easiest point to get wrong.

| Verdict | Meaning | Denominator | Impact on the Run when it occurs for MUST |
|---|---|---|---|
| `PASS` | Verified, and the obligation was satisfied | Included | — |
| `WARNING` | A SHOULD / RECOMMENDED was not satisfied, or there is a point of caution despite PASS | Included | `CONFORMANT_WITH_WARNINGS` |
| `FAIL` | Verified, and the obligation was not satisfied | Included | `NON_CONFORMANT` |
| `INCONSISTENT` | The user's report conflicts with the Suite's observation | Included | `conformance = INDETERMINATE` / `completeness = INCOMPLETE` (prompt the user to redo the report) |
| `INDETERMINATE` | Execution occurred, but evidence sufficient for determination was not obtained | Included | `conformance = INDETERMINATE` / `completeness = INCOMPLETE` |
| `NOT_VERIFIED` | **The obligation applies, but could not be verified in this Run** (`reason` is required) | Included | `conformance = INDETERMINATE` / `completeness = INCOMPLETE` |
| `NOT_OBSERVABLE` | It cannot **in principle** be verified from the external protocol surface. A static attribute of the requirement | Included (displayed separately) | **Explicitly excluded** from the conformance claim (§7) |
| `NOT_SUPPORTED` | The implementation is reported as absent for a `MAY` / `OPTIONAL` obligation | Excluded | — |
| `NOT_APPLICABLE` | **The applicability condition of the obligation is not satisfied** (outside the role, or the condition of a conditional obligation is false) | **Excluded** | — |
| `ERROR` | A Suite-side failure (timeout, internal exception, or Suite bug) | Included | `conformance = INDETERMINATE` / `completeness = INCOMPLETE` |

### ★ There are only 2 cases in which `NOT_APPLICABLE` may be used

**Incorrect**: “`NOT_APPLICABLE` because the test cannot be performed due to the Test Plan configuration.”
Choosing the execution environment does not make an unconditional MUST inapplicable.
Allowing this would mean that **verification of MUST requirements could be avoided through configuration**.

`NOT_APPLICABLE` is correct only in the following 2 cases.

1. **Different role**: `IIP-IDP*` in an SP profile (the obligation's subject is not the SP in the first place)
2. **The condition of a conditional obligation is false**: `IIP-SP14.b` is a MUST imposed only on an SP that declares support for SLO.
   If it has not made that declaration, this obligation does not exist

All other cases of “could not execute” are **`NOT_VERIFIED`**, are included in the denominator,
and, for MUST, result in `conformance = INDETERMINATE` / `completeness = INCOMPLETE` ([§7.2](#72-determination)).

### `NOT_VERIFIED` Reasons (Required)

| reason | Example |
|---|---|
| `plan_configuration` | IIP-MD01–04 cannot be executed because `suite_metadata_delivery: manual` was selected |
| `target_unreachable` | The target cannot reach the Suite, so back-channel tests cannot be executed ([07 §2](07-deployment-and-networking.md)) |
| `target_config_unavailable` | The product has the capability, but configuration or verification could not be performed **due to the user's permissions or environment** |
| `capability_undetermined` | **It could not be determined whether the product has the capability or whether the user simply cannot configure it** |
| `precondition_failed` | Not executed because a prerequisite case returned FAIL |
| `interaction_disallowed` | `allow_browser_steps: false` / `allow_attestation: false` |
| `user_skipped` | The user did not execute it |
| `timeout` | A `WAITING_*` timed out |
| `not_implemented` | The Suite side has not yet implemented it. **CI MUST enforce that there are 0 cases at release time** |

> The UI presents `NOT_VERIFIED` as “Not verified (N more items are needed for a complete report)”
> and shows **how verification can be performed** for each reason. Do not hide it.

### ★ Common Determination Procedure When Configuration Cannot Be Performed

#### Shared bootstrap contracts (configuration is not a questionnaire)

`mode: CONFIG` means that a case needs a known Target state. It does **not** mean that Runner must
ask one question per case. Runner groups compatible prerequisites into a small set of Run-scoped
bootstrap contracts and reuses the verified setup across cases.

- **Standard metadata contract**: the operator registers one stable Suite metadata URL or MDQ
  source. SAMLscope changes controlled fixtures behind that standard interface and records Target
  fetches plus correlated SAML traffic. A vendor administration API is neither required nor used.
- When the Target periodically polls the registered URL or refreshes metadata after encountering an
  unknown signing key, the operator MAY arm one ordered automatic polling campaign. Each fixture
  uses a distinct deterministic test key and the URL carries a Run-scoped correlation token. A
  token-correlated fetch records retrieval but keeps the same fixture selected, including across
  duplicate key-reload fetches. Only the correlated browser response advances the persisted fixture
  index. If the Target leaves the browser on its own result page, an explicit continuation MAY
  advance orchestration after the browser attempt even when no fetch was observed; it MUST NOT
  create a target outcome or substitute for missing retrieval or response evidence. The operator can
  set a delay between successful fixtures to accommodate
  the Target's ordinary metadata-key refresh window. This is orchestration pacing only and cannot
  change a case outcome.
- Automatic polling removes repeated Target-side re-import operations, but it does not manufacture
  use evidence. Cases that require a correlated SAML flow remain waiting until that flow is observed
  or the operator records that the approved attempts were made.
- A static-import Target MAY instead use the preloaded positive aggregate. SAMLscope combines only
  mutually compatible acceptance fixtures in one downloadable signed `EntitiesDescriptor`, gives each fixture
  a distinct entityID and correlated ACS URL, and then runs a browser sequence across the imported
  entities. A Target fetch of the aggregate URL is retrieval evidence for its listed logical
  fixtures; an operator download is not. Use evidence still requires a correlated SAML response for
  each entity, so file-import products do not need a fabricated Target-fetch observation.
- Rejection fixtures and document-wide root, signature, redirect, expiry, cardinality, and duplicate
  entityID fixtures are never mixed into the aggregate. They remain separate because combining them
  would make the accept/reject oracle ambiguous. A Target that cannot import an aggregate uses the
  manual queue; lack of aggregate-import support is not itself a target violation.
- **Operator-policy contracts**: where SAML defines no management protocol (for example attribute
  release or local algorithm policy), the operator prepares a small set of fixed Test Peer policy
  states once. Protocol cases then exercise those states.
- **Browser session campaigns**: cases in the same active-probe chain reuse one established Target
  session. A forced reauthentication checkpoint is counted separately. Crossing any fresh-session
  boundary adds one shared session-recovery action, not one new login per case. Sharing affects only
  orchestration and the interaction budget; each case retains its own fixtures, controls, correlation,
  and outcome.
- **Shared local-policy actions**: cases that require the same Target policy state use one stable
  action key. The initial IdP algorithm campaign has separate content-encryption and key-transport
  policy keys. Completing such an action may advance legacy browser waits, but it does not provide a
  target verdict or external evidence. Cases for which no protocol oracle is conclusive finish as
  `NOT_VERIFIED` rather than inheriting a result from another case in the action.
- A metadata fetch proves only that the bootstrap channel was reached. It is not evidence that a
  particular obligation was satisfied. Each case still needs its approved positive and negative
  controls and must derive its outcome from observed behavior.
- If the Target supports only static file import, the manual fallback remains available. Cases that
  require refresh behavior remain `NOT_VERIFIED` unless the required behavior can actually be
  observed; static import is not silently treated as dynamic consumption.
- A Run-level evidence evaluation may resume multiple ready cases at once, but only when each case's
  approved implementation declares its own required observations complete. Incomplete cases remain in
  `WAITING_CONFIG`; the shared action cannot convert them to `NOT_VERIFIED`, `satisfied`, or `violated`.

Product-specific adapters may exist only as development fixtures and cannot be part of a published
conformance determination.

Many obligations require the **capability** to “**be able to …**”
(*MUST support the ability to …* / *MUST be configurable with …* / *MUST be capable of …*).
The fact that the target could not be configured into the desired state
**MUST NOT uniformly be treated as `NOT_VERIFIED(target_config_unavailable)`**.

However, **the case MUST NOT return `FAIL` either**.
As specified in [05 §2.3](05-test-definition-format.md), cases return `outcome`, and
conversion to Verdict is performed centrally by the Evaluator based on `obligation.level`.
**If this is directly made `FAIL`, a SHOULD obligation becomes FAIL** (repeating the error that was supposedly eliminated in R2).

#### Procedure

```
① First assess applicability (§1)
     effective_result == FALSE  → NOT_APPLICABLE. Do not execute the case
     ★ Example: IIP-ALG05.b (an implementation supporting CBC SHOULD issue a warning when used)
        If CBC is unsupported, the condition is false → NOT_APPLICABLE, not FAIL

② Execute the case. If the configuration cannot be achieved, ask the user (Runner displays this commonly)
   ┌──────────────────────────────────────────────┐
   │ Q. Does the product have this configuration  │
   │    capability?                                │
   │   ○ The product does not have the feature /  │
   │     configuration item does not exist        │
   │   ○ The feature exists, but I cannot change  │
   │     it with my permissions / in my environment│
   │   ○ Don't know                                │
   └──────────────────────────────────────────────┘

③ The case returns outcome (not Verdict)
```

| Answer | Case returns `outcome` | `reason_code` |
|---|---|---|
| The product does not have the feature | **`violated`** ※ | `capability_absent` |
| Cannot change it due to permission or environment constraints | `not_verified` | `target_config_unavailable` |
| Don't know | `not_verified` | `capability_undetermined` |

※ However, returning `violated` is permitted only when **the configuration capability itself is the obligation** (see below).

#### `configuration_failure_semantics` (Required Test Definition Field)

`mode: CONFIG` is an **execution method**; it does not mean that “the configuration capability is a normative requirement.”
This MUST be stated explicitly in the test definition.

| Value | Meaning | `outcome` when capability is absent |
|---|---|---|
| `normative_capability` | **The ability to configure it is itself an obligation** (such as *MUST be configurable with at least two decryption keys*) | `violated` + `capability_absent` |
| `test_precondition` | The configuration is **only a precondition for making the test possible**; the inability itself is not a violation (for example, changing the attribute release policy to observe a difference) | `not_verified` + `test_precondition_unavailable` |

#### Conversion to Verdict (Performed by the Evaluator)

```
outcome: violated (capability_absent)
   × MUST_CLASS   → FAIL
   × SHOULD_CLASS → WARNING          ★ Do not make it FAIL
   × MAY_CLASS    → NOT_SUPPORTED
```

```

#### Conventions

1. **Every `mode: CONFIG` case has `configuration_failure_semantics`** (CI rule 5d)
2. Case implementations do not return `FAIL` / `WARNING`. There is no type they can return ([05 §4](05-test-definition-format.md))
3. The question text is issued commonly by Runner (variation in wording causes variation in determinations)
4. A Run for which the user selects “I don't know” has `completeness = INCOMPLETE`. It can be re-declared later
5. Applicability evaluation occurs **before** case execution. A procedure with a false condition must not enter this process

> When this procedure was newly established in R9, **all `CONFIG` cases were mapped directly to `FAIL`**.
> This violated the design in which cases do not return Verdict, and incorrectly determined SHOULD obligations and conditional obligations.
> Even when determination rules are standardized, **the conversion must always pass through Evaluator**.

### Scope of `NOT_SUPPORTED` (reiterated; §3 rule)

```
RFC2119 level of obligation       When the user declares “not implemented”
─────────────────────────────────────────────────
MUST / MUST NOT / REQUIRED  →  FAIL   (reason: declared-unsupported)
SHOULD / RECOMMENDED        →  WARNING
MAY / OPTIONAL              →  NOT_SUPPORTED
```

### `INCONSISTENT`

Applied when the user's declaration contradicts the Suite's observations.
Example: The Suite observed `302 → protected resource` and `Set-Cookie` after POST to the target ACS,
but the user declared “did not log in.”

- Do not automatically make it PASS or FAIL
- Present the contradiction (the observed evidence) in the UI and prompt the user to **re-declare or re-run**
- If the Run ends with the contradiction unresolved, then for MUST, `conformance = INDETERMINATE` / `completeness = INCOMPLETE`

## 5. Evidence ladder for negative tests

How should it be determined that “the target rejected the invalid message”? In descending order of strength.

| Level | Evidence | Automatic determination |
|---|---|---|
| L1 | A response was returned containing an error in SAML `<Status>` (`Requester` / `RequestDenied`, etc.) | Yes |
| L2 | The target endpoint returned HTTP 4xx / 5xx | Yes |
| L3 | Within the scope observable by the Suite, no state transition indicating success occurred | Conditionally |
| L4 | The user declared that an error was displayed on the target's screen | `ATTESTED` |
| — | None of the above was obtained | `INDETERMINATE` |

**Rule: Do not make PASS based only on the fact that “nothing happened.”**

Automatic determination at L3 is limited to observation points on the Suite side (for example, no successful Response reached the Suite's ACS).
Because the target's session Cookie cannot be viewed, all other cases fall to L4.

> The more an IdP satisfies IIP-IDP05 (returning an error Response when conditions permit),
> the more negative tests can be automatically determined at L1. IIP-IDP05 is a
> **key requirement** affecting the detection power of many other tests and should be placed early in the execution order.

## 6. Aggregation rules (decision table)

### 6.1 Severity ordering

Aggregation always follows **“the most severe item wins.”** The ordering is defined uniquely.

```
FAIL  >  INCONSISTENT  >  ERROR  >  INDETERMINATE  >  NOT_VERIFIED
      >  WARNING  >  PASS  >  NOT_SUPPORTED  >  NOT_OBSERVABLE  >  NOT_APPLICABLE
```

Design decisions:

- **`FAIL` > `ERROR`**: Known non-conformance must not be hidden by a failure on the Suite side.
  If one case is FAIL and another case is ERROR, the obligation is `FAIL`
- **`NOT_VERIFIED` > `PASS`**: Even if only some cases pass, an obligation with remaining unverified cases is
  `NOT_VERIFIED`. **This is the correction for review finding 2**
- **`NOT_VERIFIED` > `WARNING`**: Unverified status represents greater incompleteness than a SHOULD violation
- **`INCONSISTENT` > `ERROR`**: A contradiction can be resolved through the user's action, so it is presented first

### 6.2 CaseRun → Obligation

An obligation's Verdict is **not determined by case aggregation alone**.
The result of applicability evaluation ([the three-valued evaluation in §1](#-conditions-are-evaluated-in-three-values-do-not-trust-self-declarations-alone)) is also an input.

```
verdict(obligation) = max_severity(
      applicabilityVerdict(obligation)              ★ Applicability evaluation is also one input
    ∪ { verdict(case) for case in cases(obligation) }
)

applicabilityVerdicts(o) = the following 2 inputs (independent)
    ① effective_result(o) == FALSE    → NOT_APPLICABLE
       effective_result(o) == UNKNOWN → NOT_VERIFIED(applicability_undetermined)
       effective_result(o) == TRUE    → (no input; execute and aggregate cases)
    ② conflict(o) == true             → INCONSISTENT   ★ Injected independently of ①
    (There is no fourth value called `CONFLICT`; conflict is an independent boolean)
```

Because `INCONSISTENT` ranks above both `PASS` and `NOT_APPLICABLE` in the severity ordering,

- Even if all cases PASS while the contradiction remains, the obligation becomes `INCONSISTENT`
- **An obligation with an unresolved contradiction is never silently excluded as `NOT_APPLICABLE`**

This eliminates any path for ignoring a contradiction and claiming conformance.

`ApplicabilityEvaluation` is an explicit input to `Evaluator.evaluate()`
(the authoritative signature is [§7.5](#75--confine-determination-to-a-single-function)).

All evaluation results (`effective_result` ∈ TRUE/FALSE/UNKNOWN and `conflict`) are recorded, with the grounds for the determination,
in `applicability[]` in the result JSON ([06 §1](06-results-and-publication.md)).

```
verdict_from_cases(obligation) = max_severity( verdict(case) for case in cases(obligation) )

However:
  cases(obligation) is empty          → NOT_OBSERVABLE or NOT_VERIFIED(not_implemented)
                                      (determined by testability in coverage.yaml; verified in CI)
  obligation.condition is false       → NOT_APPLICABLE (do not execute cases)
  obligation.roles contains no target role → NOT_APPLICABLE
```

### 6.3 Obligation → Requirement (by role)

```
verdict(requirement, role) = max_severity(
    verdict(o) for o in obligations(requirement) if role in o.roles
)
all NOT_APPLICABLE → NOT_APPLICABLE
```

Requirements are displayed **by role**. A Run for an IdP profile displays only obligations applicable to the IdP.

### 6.4 Decision table (fixed through table-driven tests)

In the implementation, use the following table directly as test data. `>` means the left side wins.

| Input (set of cases within the same obligation) | Aggregated result |
|---|---|
| `{PASS}` | `PASS` |
| `{PASS, PASS}` | `PASS` |
| `{PASS, WARNING}` | `WARNING` |
| `{PASS, NOT_VERIFIED}` | **`NOT_VERIFIED`** ← was PASS under the old rule |
| `{PASS, NOT_VERIFIED, WARNING}` | `NOT_VERIFIED` |
| `{PASS, FAIL}` | `FAIL` |
| `{FAIL, ERROR}` | **`FAIL`** ← do not hide a known FAIL |
| `{FAIL, INCONSISTENT}` | `FAIL` |
| `{INCONSISTENT, ERROR}` | `INCONSISTENT` |
| `{ERROR, INDETERMINATE}` | `ERROR` |
| `{INDETERMINATE, NOT_VERIFIED}` | `INDETERMINATE` |
| `{NOT_VERIFIED, NOT_APPLICABLE}` | `NOT_VERIFIED` |
| `{PASS, NOT_APPLICABLE}` | `PASS` |
| `{NOT_SUPPORTED, NOT_APPLICABLE}` | `NOT_SUPPORTED` |
| `{NOT_OBSERVABLE}` | `NOT_OBSERVABLE` |
| `{NOT_OBSERVABLE, PASS}` | `PASS` (if even part of it can be verified, prioritize the verification result) |
| `{NOT_OBSERVABLE, FAIL}` | `FAIL` |
| `{NOT_APPLICABLE}` | `NOT_APPLICABLE` |
| `{}` (no cases) | `NOT_OBSERVABLE` or `NOT_VERIFIED(not_implemented)` |

> Place `VerdictAggregationTest` in CI and compare **all 100 combinations of 10 values × 10 values**
> against the table above. A PR that changes the ordering must break this test.

## 7. Overall Run determination

### 7.1 Definition of the denominator

```
applicable   = all applicable obligations (all except NOT_APPLICABLE)
must_set     = those in applicable whose level ∈ {MUST, MUST NOT, REQUIRED}
observable   = those in must_set that are not NOT_OBSERVABLE   ← denominator for claiming conformance
```

### 7.2 Determination

`WARNING` means “the obligation is satisfied but has a point requiring attention” or “SHOULD/RECOMMENDED is not satisfied.”
Because a MUST obligation may also receive `WARNING`, treat `{PASS, WARNING}` as “satisfied” when determining MUST satisfaction.

```
satisfied(o)   ≡ verdict(o) ∈ {PASS, WARNING}
unresolved(o)  ≡ verdict(o) ∈ {NOT_VERIFIED, INDETERMINATE, INCONSISTENT, ERROR}
```

**Conformance and execution completeness are separate axes.**
If they are collapsed into one label, the Run becomes `CONFORMANT` when all MUSTs pass even if every SHOULD fails
(review finding 7). **Separate them into two fields.**

```
run.conformance ∈ { CONFORMANT, CONFORMANT_WITH_WARNINGS,
                    CONFORMANT_WITH_DECLARED_EXCLUSIONS, NON_CONFORMANT, INDETERMINATE }

  NON_CONFORMANT             ∃ o ∈ applicable : verdict(o) = FAIL
  INDETERMINATE              ¬NON_CONFORMANT ∧ ∃ o ∈ must_observable : unresolved(o)
  CONFORMANT_WITH_DECLARED_EXCLUSIONS
                             ∀ o ∈ must_observable : satisfied(o)
                             ∧ coverage.excluded_by_declaration > 0
                             (regardless of whether WARNING exists. ★ Determine this with highest priority)
  CONFORMANT_WITH_WARNINGS   ∀ o ∈ must_observable : satisfied(o)
                             ∧ coverage.excluded_by_declaration = 0
                             ∧ ∃ o ∈ W : verdict(o) = WARNING
  CONFORMANT                 ∀ o ∈ must_observable : verdict(o) = PASS
                             ∧ coverage.excluded_by_declaration = 0
                             ∧ ¬∃ o ∈ W : verdict(o) = WARNING

  W = applicable ∩ selected_profile      ← ★ Set counted for WARNING
      (all applicable obligations included in the selected profile (Core / Full), regardless of level)

run.completeness ∈ { COMPLETE, INCOMPLETE }

  INCOMPLETE   ∃ o ∈ observable (all levels; all obligations included in the selected profile)
               : unresolved(o)
  COMPLETE     otherwise
```

- The **pass/fail** of `run.conformance` is determined only by `must_observable`. The conformance claim is confined here
- ★ However, **the set `W` counted for `WARNING` consists of all obligations in the selected profile**.
  If there is a SHOULD violation, the result is `CONFORMANT_WITH_WARNINGS`, not `CONFORMANT`.
  Do not create a state in which warnings are not surfaced because “all MUSTs pass.”
  If `W` were defined as `must_observable`, SHOULD violations would be completely hidden;
  if it were defined as all of `applicable`, obligations from Full would also be counted during a Core Run.
  Therefore, **take the intersection with the selected profile**
- Include both “all MUSTs PASS + 1 SHOULD WARNING” and “1 MUST `satisfied_with_note`”
  in `VerdictAggregationTest`
- `run.completeness` considers **all obligations in the selected profile (Core / Full)**.
  If Full is selected but a SHOULD obligation is `ERROR` or `NOT_VERIFIED`, it becomes `INCOMPLETE`
```

- **The UI and report MUST always be displayed together**. Displaying only one of them is prohibited.

```text
CONFORMANT (tested scope)  ·  INCOMPLETE (3 obligations unresolved) <!--g1-literal-->
```

- The former single label `INCOMPLETE` corresponds to `conformance = INDETERMINATE`.
  To avoid confusion, the name on the conformance side has been changed to `INDETERMINATE`.

`RunVerdictTest` verifies the completeness and exclusivity of both fields
([05 §5](05-test-definition-format.md), rule 18).

### 7.3 ★ Conformance statements when `NOT_OBSERVABLE` MUST obligations exist

Kantara IIP contains MUST obligations that cannot, in principle, be verified from the external protocol surface
(for example, IIP-SP12, “Do not give a persistent NameID meaning beyond the specification”).
If every Run were assigned `conformance = INDETERMINATE` for this reason, the top-level determination would become meaningless.

Therefore, **the scope of the conformance claim is structurally limited**.

- The denominator for the conformance determination consists only of `observable` obligations.
- `NOT_OBSERVABLE` MUST obligations **MUST always be accompanied by both a count and a list**.
- The UI, report, and public page **MUST NOT display `CONFORMANT` by itself**.
  They MUST always display the result JSON’s `conformance_statement` unchanged alongside it.

> ⚠ **The display example previously placed here has been removed.**
> During review, it was pointed out that `IIP-IDP02.b` was mixed into the example for an SP Run,
> and that `IIP-SP11.b` does not exist in the current obligation decomposition
> (role/key inconsistency).
> **`conformance_statement` is also generated from the `Evaluator` golden fixture**
> ([§7.5](#75--confine-determination-to-a-single-function)). No example will be included until the system switches to generation.

Likewise, when `conformance ≠ CONFORMANT`, all unresolved obligation IDs and reasons are enumerated.

### 7.4 Coverage metrics (required in the result JSON)

Conformance labels alone do not convey what was verified or how much was verified.
**The denominator and numerator are defined uniquely** (review finding 14).

```text
applicable       = all applicable obligations (excluding NOT_APPLICABLE)
must_applicable  = among applicable, those whose level ∈ MUST_CLASS
                   MUST_CLASS = {MUST, MUST_NOT, REQUIRED}
must_observable  = among must_applicable, those whose verdict ≠ NOT_OBSERVABLE   ← denominator of the conformance claim
must_resolved    = among must_observable, those whose verdict ∈ {PASS, WARNING, FAIL}
                   (= those for which a conclusion was reached; NOT_VERIFIED / INDETERMINATE /
                     INCONSISTENT / ERROR are not included)

verified_ratio   = must_resolved / must_observable     ← denominator is must_observable
```

`verified_ratio` is **“the proportion for which a conclusion was reached,” not “the conformance rate.”**
FAIL is also included in the numerator. Because the name can be misleading, the UI displays it as a fraction,
such as `Resolved: 45 / 47 externally-testable MUST obligations`, and does not display the ratio by itself.

```json
"coverage": {
  "obligations_total": 63,
  "obligations_applicable": 61,
  "must_applicable": 48,
  "must_observable": 45,
  "must_resolved": 45,
  "must_unresolved": 0,
  "must_not_observable": 3,
  "verified_ratio": 1.0,
  "attested_obligations": 11,
  "applicability_from_declaration_only": 2
}
```

**The public page displays these metrics at the same size as the conformance label.**
This structurally prevents a state in which only “PASS 74” takes on a life of its own.

### 7.5 ★ Confine determination to a single function

The code that derives the Run determination, requirement aggregation, and coverage metrics **MUST be placed in one location**.

```java
public final class Evaluator {
    /** ★ This is the sole canonical source. Its signature MUST be identical to §6.2. */
    public static RunResult evaluate(CoverageCatalog catalog,
                                     TestPlan plan,
                                     List<ApplicabilityEvaluation> applicability,
                                     List<CaseRun> caseRuns,
                                     List<SuiteIncident> incidents);
}
```

> **The signature MUST be written in only one place.** In the previous review, although
> `ApplicabilityEvaluation` had been added as an input in §6.2, the signature here remained in its old form,
> leaving the system in a state where the same problem would recur if an implementer treated this one as canonical.
> In the documentation, **§7.5 is the canonical source** and §6.2 is reference-only.

- The UI, `result.json`, `report.html`, and **all** examples in the documentation use this function’s output.
- JSON examples in the documentation MUST NOT be handwritten. The `Evaluator` output is generated into `docs/`
  as a golden fixture, and differences are detected in CI
  ([06 §1](06-results-and-publication.md), [05 §5](05-test-definition-format.md), rule 23).

> The previous review pointed out that the `result.json` examples in the documentation
> contradicted their own determination rules.
> **As long as examples are written by hand, they will inevitably diverge.** Make them generated artifacts.

## 8. Test Run state machine

```text
        ┌─────────┐
        │ CREATED │
        └────┬────┘
             │ start
             ▼
      ┌─────────────┐   All cases finished    ┌───────────┐
      │  RUNNING    │────────────────────────▶│ COMPLETED │
      └──┬───┬───┬──┘                         └───────────┘
         │   │   │                                  ▲
         │   │   └── Waiting for user action ───┐   │
         │   │       ┌────────────────┐         │   │
         │   └──────▶│ WAITING_BROWSER│─────────┘   │
         │           └────────────────┘             │
         │           ┌────────────────┐             │
         ├──────────▶│ WAITING_ATTEST │─────────────┤
         │           └────────────────┘             │
         │           ┌────────────────┐             │
         ├──────────▶│ WAITING_CONFIG │─────────────┤
         │           └────────────────┘             │
         │           ┌────────────────────┐         │
         └──────────▶│ WAITING_CREDENTIAL │─────────┘
                     └────────────────────┘
                       When ECP credentials are lost on restart
                       ([05 §4.3.2](05-test-definition-format.md))
             │ abort / timeout
             ▼
        ┌─────────┐
        │ ABORTED │
        └─────────┘
```

- `WAITING_*` states MUST have a **timeout** (15 minutes by default).
  Cases that time out become **`NOT_VERIFIED(timeout)`** (`SKIPPED` has already been removed from the vocabulary).
- The state during a Run is pushed to the UI via SSE.
- The Transcript is retained even if the Run is interrupted.

## 9. Test execution order

There are dependencies on the order. The Runner handles dependencies declaratively.

```text
1. Preflight        Reachability of the Suite itself, time, TLS, and whether target metadata can be retrieved
2. Metadata (static) Inspection of the target metadata’s syntax, signature, and algorithm declarations (AUTOMATED)
3. Metadata (dynamic) Distribution and signature of Suite metadata, and validUntil (CONFIG)
4. Algorithms       Verification of supported signature and encryption algorithms
5. Core SSO         Normal Web Browser SSO flow (BROWSER; first login occurs here)
6. SSO variations   NameID / AuthnContext / ForceAuthn / IsPassive / attributes
7. Error handling   Negative flows, including IIP-IDP05
8. SLO              Single Logout (placed later because it destroys the session)
9. ECP              Back channel (AUTOMATED; may run at any time)
```

`ForceAuthn` and `SLO` MUST always be placed at the end because they destroy the session.
The Runner determines the order from the case definitions’ `requires_session` / `destroys_session` flags.

## 10. Preflight checks (newly added)

This was not included in the original notes, but without it users would be left struggling with failures of unknown cause.
It MUST always run immediately after the Test Plan is created.

- [ ] Is `PUBLIC_BASE_URL` configured, and can the Suite itself reach itself at that URL?
- [ ] Is the container’s time synchronized with NTP? (A discrepancy breaks all tests.)
- [ ] Can the target metadata URL be retrieved and parsed, and is it within its validity period?
- [ ] Are the target metadata’s `SingleSignOnService` / `AssertionConsumerService` reachable from the Suite
      when a back channel is required?
- [ ] **Reachability from `Target → Suite` is not established by Preflight**. Preflight can report only
      `reachability = ASSERTED`; promotion to `CONFIRMED` occurs only after an inbound request from the target
      has been observed ([07 §2](07-deployment-and-networking.md)).
- [ ] Is the Suite’s base URL HTTPS? (Many SPs reject an HTTP ACS.)
- [ ] Is the target’s TLS certificate chain verifiable? (If it is self-signed, require explicit permission.)

The Preflight results are recorded as part of the Run, and tests depending on failed items are assigned
**`NOT_VERIFIED` (with the applicable reason)**. They MUST NOT be assigned `NOT_APPLICABLE` (§4).
