# 04. Requirement Coverage Map (Generated)

> ⚠ **Generated from `tests/coverage.yaml`; do not edit manually.**
> Regenerate: `python3 tools/g1_docgen.py` (no network / authoring input required)
> G1 state: **PENDING_REVIEW**

Document: **SAML V2.0 Implementation Profile for Federation Interoperability, Version 1.1 (2019-12-18)**

https://kantarainitiative.github.io/SAMLprofiles/fedinterop.html
Source digest: `sha256:6cbc97a652651d6a5cff26a41c51195b8b914ed59dc63ed1d6ce254e88edd13d`

Validation: `python3 tools/g1_validate.py` → `build/spec-reconcile-report.json`

## Summary

| Metric | Value |
|---|---|
| Requirements | 69 |
| Obligations | 544 |
| MUST_CLASS | 403 |
| SHOULD_CLASS | 111 |
| MAY_CLASS | 30 |
| Conditional obligations | 108 |
| IdP profile | 414 obligations (Core 254 / Full 160) |
| SP profile | 320 obligations (Core 183 / Full 137) |
| Non-normative (italic) spans | 26 |

**Testability**

| Symbol | Meaning | Count |
|---|---|---|
| `AUTOMATED` | Completed through direct Suite-to-target communication (no browser) | 96 |
| `BROWSER` | Requires the user's browser | 216 |
| `ATTESTED` | The user attests to behavior inside the target | 53 |
| `CONFIG` | Run after requesting a configuration change on the target | 178 |
| `NOT_OBSERVABLE` | Fundamentally unverifiable externally; no case is created | 1 |

**Verdict notes**

- The sole source of verdict levels is `tests/coverage.yaml`.
- Cases return `outcome`; the Evaluator maps it to Verdict by consulting `level` ([03 §4](03-test-model.md)).
- `NOT_APPLICABLE` is limited to role mismatch and false conditional-obligation conditions. Anything that could not be executed is `NOT_VERIFIED`.
- **Core / Full is Samlier's own classification**; the IIP source does not make this distinction.

## Requirements and Obligations

### 2.1 Common / General

#### IIP-G01

[Source](https://kantarainitiative.github.io/SAMLprofiles/fedinterop.html#IIP-G01) / Section digest `sha256:53941f0bef83…` / Section length 781 / Non-normative spans 3

| Obligation | Level | Role | Testability | Condition | Core/Full | Summary |
|---|---|---|---|---|---|---|
| `IIP-G01.a` | MUST | idp/sp | `BROWSER` | — | core | Allow for reasonable clock skew when interpreting xsd:dateTime values and enforcing policy based on them |

<details><summary><code>IIP-G01.a</code> details</summary>

- **Required variants**:
  - `v-e58a6e87cd` Shift IssueInstant within the target-attested tolerance T, to T-delta; it should be accepted. This is the only verdict-affecting check.
  - `v-5c725f9df6` Shift NotBefore and NotOnOrAfter by T-delta; they should be accepted.
  - `v-cb7eb7556e` Shift metadata validUntil by T-delta; it should be accepted.
  - `v-469ba48d06` Information only: behavior when shifted outside T, to T+delta. Acceptance is not a violation.
- **Controls (negative controls)**:
  - Samlier has no absolute threshold. Judge only whether a value inside the tolerance T attested by the target is accepted.
  - Correction: the previous version treated acceptance at T+delta as violated, but the source requires allowing reasonable skew, not rejecting anything beyond it. That would fail conforming implementations with wider tolerance. Record behavior outside the boundary as advisory clock_skew.very_permissive and exclude it from the verdict.
  - If T cannot be attested, return NOT_VERIFIED. Configurability is not required by the source, so its absence is not a violation.
- **Configuration failure semantics**: `test_precondition`
- **Notes**: The source establishes no universal number of seconds that must be accepted; "3–5 minutes" is italicized and non-normative. The previous mandatory ±180-second variant could violate a conforming implementation configured for 120 seconds. If T cannot be attested or configured, return NOT_VERIFIED. Record excessive tolerance as advisory clock_skew.very_permissive and exclude it from the verdict.
- **source_clauses**: `[0, 155)` `sha256:9a9e31b61f2f…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

#### IIP-G02

[Source](https://kantarainitiative.github.io/SAMLprofiles/fedinterop.html#IIP-G02) / Section digest `sha256:1ca7eb8542d7…` / Section length 566 / Non-normative spans 1

| Obligation | Level | Role | Testability | Condition | Core/Full | Summary |
|---|---|---|---|---|---|---|
| `IIP-G02.a` | MUST | idp/sp | `BROWSER` | — | core | Accept, without error, xs:string values of any valid XML characters up to 256 characters |
| `IIP-G02.b` | MUST | sp | `CONFIG` | — | core | A Service Provider must not truncate received xs:string values of up to 256 characters |
| `IIP-G02.c` | MUST | idp | `ATTESTED` | — | core | An Identity Provider must not truncate received xs:string values of up to 256 characters |

<details><summary><code>IIP-G02.a</code> details</summary>

- **Required variants**:
  - `v-dffad0561a` Standard type: a 256-character transient NameID, matching the SAML2Core 8.3.8 maximum.
  - `v-3906636ecf` Standard type: a 256-character persistent NameID, matching the SAML2Core 8.3.7 maximum.
  - `v-e5e955eb1c` Standard type: 256 characters in AuthnRequest/@ProviderName.
  - `v-ac5c0aa54a` User-defined type: 256 characters in a value of a user-schema xs:string-derived type, such as <saml:AttributeValue xsi:type="myns:MyStringType">.
  - `v-e2eb9ead4d` User-defined type: 256 characters in an xs:string-typed attribute of a user-defined element inside samlp:Extensions.
  - `v-3bb6d4de96` User-defined type: 256 characters in xs:string-typed element content of a user-defined element inside saml:Advice.
  - `v-cb2b5ca561` Character category: the len=255 boundary.
  - `v-b53cde0652` Character category: the len=256 boundary.
  - `v-940be55376` Character category: non-ASCII characters, including CJK and Cyrillic.
  - `v-07bc620a46` Character category: combining characters whose normalization changes length.
  - `v-e63f47012d` Character category: supplementary-plane code points; do not generate isolated surrogates.
  - `v-8932a64395` Character category: TAB and LF encoded as character references, because literals are normalized to spaces in XML attributes.
  - `v-45ac9759d7` Character category: XML-special characters (<, &, double quote, single quote, >) encoded using character or entity references.
- **Controls (negative controls)**:
  - Test both axes: type category and character category. Passing only standard types does not verify that the requirement also applies to user-defined types.
  - This obligation judges only absence of an error. Truncation is judged under IIP-G02.b for an SP and IIP-G02.c for an IdP.
  - Control: detect an implementation that accepts 255 characters but rejects 256; two cases spanning the boundary are mandatory.
  - Literal TAB and LF are normalized to spaces in XML attribute values. Use separate literal and character-reference cases and compare values after XML parsing.
  - Count length in Unicode code points.
- **Applicability**: Applicability is limited by the opening clause, "where no SAML standard or profile-specific constraint exists." Select fields for which SAML imposes no length or character-set constraint.
- **Notes**: The transcript suffices as acceptance evidence: no error response and completion of the flow. However, user-defined types in samlp:Extensions or saml:Advice may be ignored, so success does not distinguish acceptance from ignoring. Whether content was not ignored and not truncated is observed separately under IIP-G02.b/.c. Use a field known to be xs:string; saml:Attribute/@Name and @FriendlyName are schema-defined SAML types and are not controls for a user-defined type.
- **source_clauses**: `[81, 291)` `sha256:d07e84e7979b…` , `[293, 435)` `sha256:fe98afa5ffc2…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-G02.b</code> details</summary>

- **Required variants**:
  - `v-bbec42f7c8` Read back the received transient and persistent NameIDs and verify that all 256 code points are preserved.
  - `v-1a367fbed8` Read back the received standard-type saml:AttributeValue and verify that all 256 code points are preserved.
  - `v-eeb2369cc7` Read back the received user-defined AttributeValue type identified by xsi:type and verify that its value is preserved.
  - `v-207e07ddfe` Character category: non-ASCII characters, combining characters, and supplementary-plane code points are not lost.
  - `v-f6d79585b0` Character category: TAB and LF sent as character references are preserved in the post-XML-parsing value.
  - `v-ab7394032c` Control: detect an implementation for which 255 characters match exactly but the final character is missing only at 256.
- **Controls (negative controls)**:
  - A successful response is not evidence of non-truncation. Unknown content in samlp:Extensions or saml:Advice may be ignored, so success alone cannot distinguish ignored, truncated, and preserved content.
  - Read back through the target's observation surface. Compare the value sent by the Suite with the value read from the target as sequences of Unicode code points.
  - If no readback path can be provided, return not_verified(no_readback_path), not target nonconformance.
- **Configuration failure semantics**: `test_precondition`
- **Applicability**: Applicability is the same as IIP-G02.a. This obligation covers only non-truncation and requires a value-readback path.
- **Notes**: Example readback paths are an SP attribute-display endpoint such as a Shibboleth Session handler, a diagnostic page in the target application, or session information issued by the target. Register the URL and reading procedure during Test Plan preflight; the Suite performs the comparison automatically. If no path exists, return not_verified rather than falling back to attestation, as with IIP-G02.c; SPs ordinarily expose readback, and attestation would remove detection power.
- **source_clauses**: `[81, 291)` `sha256:d07e84e7979b…` , `[293, 435)` `sha256:fe98afa5ffc2…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-G02.c</code> details</summary>

- **Required variants**:
  - `v-5fd589e897` When a round-trip path exists, set 256 characters in samlp:ManageNameIDRequest/samlp:NewID, whose schema type is string, and verify that a later Assertion returns SPProvidedID with the identical 256 code points. Automatic comparison is possible only when SAML2Core 3.6 is supported.
  - `v-59304685a7` Without a round-trip path, use attestation to confirm that the 256 characters sent in AuthnRequest/@ProviderName, NameIDPolicy/@SPNameQualifier, and samlp:Extensions are not truncated in the target's administration UI, audit log, or session information.
  - `v-12bc7d3a9f` Character category: confirm through the same path that non-ASCII characters, combining characters, and supplementary-plane code points are not lost.
- **Controls (negative controls)**:
  - Prefer a variant with a round-trip path, SPProvidedID. Attestation-only and automatically compared results occupy different evidence-ladder grades.
  - The SPProvidedID round trip shares the observation used by IIP-SSO05.a5, but the judged properties differ: provenance there and length preservation here.
  - If attestation is unavailable, return not_verified(attestation_unavailable), not target nonconformance.
- **Applicability**: Applicability is the same as IIP-G02.a. Many IdPs do not re-emit accepted xs:string values through the protocol surface, so observation is generally attested.
- **Notes**: IIP-G02.a acceptance and this non-truncation obligation are separate because a successful response cannot be distinguished from ignoring. No IdP readback surface is standardized; automatic comparison is possible only for implementations supporting SAML2Core 3.6 Name Identifier Management.
- **source_clauses**: `[81, 291)` `sha256:d07e84e7979b…` , `[293, 435)` `sha256:fe98afa5ffc2…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

#### IIP-G03

[Source](https://kantarainitiative.github.io/SAMLprofiles/fedinterop.html#IIP-G03) / Section digest `sha256:b4fcb67b6c41…` / Section length 133 / Non-normative spans 0

| Obligation | Level | Role | Testability | Condition | Core/Full | Summary |
|---|---|---|---|---|---|---|
| `IIP-G03.a` | MUST_NOT | idp/sp | `AUTOMATED` | — | core | Do not send SAML protocol messages containing a DTD |
| `IIP-G03.b` | MUST | idp/sp | `BROWSER` | — | core | Have the ability to reject SAML protocol messages containing a DTD |

<details><summary><code>IIP-G03.a</code> details</summary>

- **Required variants**:
  - `v-5cee57cbfd` Inspect every target-generated SAML protocol message in the complete Transcript.
- **Controls (negative controls)**:
  - Apply this passive continuous check across every case.
- **source_clauses**: `[0, 29)` `sha256:0c97ff7a8417…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-G03.b</code> details</summary>

- **Required variants**:
  - `v-89eb06c832` An AuthnRequest containing a DOCTYPE.
  - `v-15dd159dfe` A Response containing a DOCTYPE.
  - `v-65f5890ff4` A DOCTYPE plus an external-entity reference.
- **Controls (negative controls)**:
  - Use the evidence ladder in document 03 for rejection evidence; no response is not PASS.
- **Configuration failure semantics**: `normative_capability`
- **source_clauses**: `[34, 133)` `sha256:c96995d7bd60…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

### 2.2 Common / Metadata and Trust Management

#### IIP-MD01

[Source](https://kantarainitiative.github.io/SAMLprofiles/fedinterop.html#IIP-MD01) / Section digest `sha256:a62aa94bedb6…` / Section length 398 / Non-normative spans 0

| Obligation | Level | Role | Testability | Condition | Core/Full | Summary |
|---|---|---|---|---|---|---|
| `IIP-MD01.a` | MUST | idp | `CONFIG` | — | core | Support acquisition of metadata rooted in md:EntityDescriptor via the Metadata Query Protocol |
| `IIP-MD01.b` | SHOULD | sp | `CONFIG` | — | full | (SP) Should support acquisition of metadata rooted in md:EntityDescriptor via MDQ |
| `IIP-MD01.c` | MUST | idp/sp | `CONFIG` | `claims_mdq_support`<br>(CLAIM_BASED) | core | Implementations claiming MDQ support must request and utilize metadata from one or more MDQ responders for any peer from which a SAML message is received |

<details><summary><code>IIP-MD01.a</code> details</summary>

- **Required variants**:
  - `v-4b215360ab` Direct the target to the Suite's /mdq/{entityID}
- **Configuration failure semantics**: `normative_capability`
- **source_clauses**: `[0, 166)` `sha256:137fea64b4d3…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-MD01.b</code> details</summary>

- **Required variants**:
  - `v-9ef4fc74ee` Same as above
- **Configuration failure semantics**: `normative_capability`
- **source_clauses**: `[0, 166)` `sha256:137fea64b4d3…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-MD01.c</code> details</summary>

- **Required variants**:
  - `v-8ad96c4d98` Send a message from a second, unregistered entityID (secondary_peer) and determine whether it can be dynamically retrieved through MDQ
- **Controls (negative controls)**:
  - The key point is “any peer.” Do not return PASS based only on a pre-registered entityID
- **Configuration failure semantics**: `normative_capability`
- **source_clauses**: `[201, 398)` `sha256:1a71b947a778…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

#### IIP-MD02

[Source](https://kantarainitiative.github.io/SAMLprofiles/fedinterop.html#IIP-MD02) / Section digest `sha256:03a520f61183…` / Section length 899 / Non-normative spans 1

| Obligation | Level | Role | Testability | Condition | Core/Full | Summary |
|---|---|---|---|---|---|---|
| `IIP-MD02.a` | MUST | idp/sp | `CONFIG` | — | core | Support scheduled/recurring consumption of metadata over HTTP/1.1, automatically applied upon successful validation |
| `IIP-MD02.b` | MUST | idp/sp | `CONFIG` | — | core | Honor HTTP/1.1 redirects with status codes 301, 302 and 307 |
| `IIP-MD02.c` | MUST | idp/sp | `CONFIG` | — | core | Support consumption of metadata rooted in both md:EntityDescriptor and md:EntitiesDescriptor via this mechanism |
| `IIP-MD02.d` | MUST | idp/sp | `CONFIG` | — | core | When rooted in md:EntitiesDescriptor, allow any number of child elements |

<details><summary><code>IIP-MD02.a</code> details</summary>

- **Required variants**:
  - `v-e40223245f` Change the Suite-side metadata and confirm that the change is applied after metadata_refresh_wait_seconds has elapsed
- **Controls (negative controls)**:
  - ETag / Last-Modified are not present in the source text, so do not use them for the determination
- **Configuration failure semantics**: `normative_capability`
- **source_clauses**: `[0, 215)` `sha256:cead52521318…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-MD02.b</code> details</summary>

- **Required variants**:
  - `v-82fd7d00e1` A metadata URL that returns 301
  - `v-96306eabdb` A metadata URL that returns 302
  - `v-2f1f9a927a` A metadata URL that returns 307
- **Controls (negative controls)**:
  - Make the three status codes separate variants. Do not return PASS based on only one
- **Configuration failure semantics**: `test_precondition`
- **source_clauses**: `[216, 284)` `sha256:1d899d31d098…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-MD02.c</code> details</summary>

- **Required variants**:
  - `v-1c85f2ce8c` A variant rooted in EntityDescriptor
  - `v-dee1b0d082` A variant rooted in EntitiesDescriptor
- **Controls (negative controls)**:
  - Make both forms separate variants
- **Configuration failure semantics**: `test_precondition`
- **source_clauses**: `[285, 439)` `sha256:e846fa6f6c57…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-MD02.d</code> details</summary>

- **Required variants**:
  - `v-9817f45cbe` 1 child
  - `v-9f2d44e187` 2 children
  - `v-dc41f06b71` 50 children
- **Configuration failure semantics**: `test_precondition`
- **source_clauses**: `[440, 505)` `sha256:6ad7c544c3e5…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

#### IIP-MD03

[Source](https://kantarainitiative.github.io/SAMLprofiles/fedinterop.html#IIP-MD03) / Section digest `sha256:b103b4db3a97…` / Section length 541 / Non-normative spans 0

| Obligation | Level | Role | Testability | Condition | Core/Full | Summary |
|---|---|---|---|---|---|---|
| `IIP-MD03.a` | MUST | idp/sp | `CONFIG` | — | core | Validate authenticity and integrity of metadata by verifying an enveloped XML Signature on the root element |
| `IIP-MD03.b` | MUST | idp/sp | `CONFIG` | — | core | Public keys used for metadata signature verification must be configured out of band |
| `IIP-MD03.c` | MUST | idp/sp | `CONFIG` | — | core | It must be possible to ignore other certificate contents and verify the signature based solely on the public key |
| `IIP-MD03.d` | MUST | idp/sp | `CONFIG` | — | core | It must be possible to limit the use of a trusted key to a single metadata source |
| `IIP-MD03.e` | MAY | idp/sp | `CONFIG` | — | full | The public keys used for metadata signature verification may be contained in X.509 certificates |

<details><summary><code>IIP-MD03.a</code> details</summary>

- **Required variants**:
  - `v-ca7aad37fa` variant=unsigned
  - `v-ae722a3ed5` variant=badsig
  - `v-85d90c9bab` variant=signed-with-other-key
  - `v-8f2a5dd28d` Valid signature (control)
- **Controls (negative controls)**:
  - Use acceptance of a valid signature as the control. Do not return PASS for an implementation that rejects everything
- **Configuration failure semantics**: `normative_capability`
- **source_clauses**: `[0, 183)` `sha256:3dac3bd94487…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-MD03.b</code> details</summary>

- **Required variants**:
  - `v-1a2a03662e` Distribute a variant signed with a key different from the certificate in the metadata, and determine whether it is verified with the out-of-band configured key
- **Controls (negative controls)**:
  - An implementation that verifies using a key contained in the metadata itself violates .b
- **Configuration failure semantics**: `normative_capability`
- **source_clauses**: `[184, 275)` `sha256:92864e274fac…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-MD03.c</code> details</summary>

- **Required variants**:
  - `v-12c3c565ee` Signed with an expired certificate
  - `v-be5f098481` Signed with a not-yet-valid certificate
  - `v-9690e9e55f` Signed with a certificate whose KeyUsage does not include digitalSignature
  - `v-1e3ba08551` Signed with a certificate containing a critical extension
- **Configuration failure semantics**: `normative_capability`
- **source_clauses**: `[330, 457)` `sha256:0cb7cf156c40…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-MD03.d</code> details</summary>

- **Required variants**:
  - `v-6f0c662f2c` Bind key K to source A, distribute source B signed with the same key K → determine whether B is rejected
- **Controls (negative controls)**:
  - Use acceptance of source A as the control
- **Configuration failure semantics**: `normative_capability`
- **source_clauses**: `[459, 541)` `sha256:cff82511463a…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-MD03.e</code> details</summary>

- **Required variants**:
  - `v-cf5ab2560b` Configure a bare public key (RSAKeyValue)
  - `v-a38c9f2c43` Configure the key contained in an X.509 certificate
- **Controls (negative controls)**:
  - Check that either form can be configured. An implementation that accepts only certificate form is within the permitted scope of .e, but evaluate it together with .c
- **Configuration failure semantics**: `test_precondition`
- **source_clauses**: `[276, 325)` `sha256:d3aa92e8b211…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

#### IIP-MD04

[Source](https://kantarainitiative.github.io/SAMLprofiles/fedinterop.html#IIP-MD04) / Section digest `sha256:3239311e8332…` / Section length 635 / Non-normative spans 1

| Obligation | Level | Role | Testability | Condition | Core/Full | Summary |
|---|---|---|---|---|---|---|
| `IIP-MD04.a` | MUST | idp/sp | `CONFIG` | — | core | Be capable of rejecting metadata whose root element lacks the validUntil attribute |
| `IIP-MD04.b` | MUST | idp/sp | `CONFIG` | — | core | Be capable of rejecting metadata whose root validUntil is in the past |
| `IIP-MD04.c` | MUST | idp/sp | `CONFIG` | — | core | Be capable of rejecting metadata whose root validUntil is too far into the future, where the threshold is a configurable option |

<details><summary><code>IIP-MD04.a</code> details</summary>

- **Required variants**:
  - `v-c1f4c2ad09` variant=no-validuntil
- **Controls (negative controls)**:
  - Use a normal variant with validUntil as the control
- **Configuration failure semantics**: `normative_capability`
- **Notes**: A non-normative note states that “this requirement applies only to the root element.” validUntil on child elements follows SAML2Meta
- **source_clauses**: `[0, 106)` `sha256:bf7b40e687da…` , `[107, 166)` `sha256:8effeb7d5621…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-MD04.b</code> details</summary>

- **Required variants**:
  - `v-58140e1e12` variant=expired (now-24h)
- **Controls (negative controls)**:
  - Use a normal variant with a valid validUntil as the control
- **Configuration failure semantics**: `normative_capability`
- **source_clauses**: `[0, 106)` `sha256:bf7b40e687da…` , `[167, 258)` `sha256:2b13ca2967eb…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-MD04.c</code> details</summary>

- **Required variants**:
  - `v-314939a128` Have the target configure threshold T, then use now+T-δ (should be accepted)
  - `v-1750e09ef6` now+T+δ (should be rejected)
- **Controls (negative controls)**:
  - Samlier has no absolute threshold. Make the determination using a boundary-value pair around the target's configured threshold
- **Configuration failure semantics**: `normative_capability`
- **Notes**: The fact that the threshold is configurable is itself part of the obligation. If there is no configuration capability, outcome=violated / capability_absent
- **source_clauses**: `[0, 106)` `sha256:bf7b40e687da…` , `[259, 421)` `sha256:850cfc185ebb…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

#### IIP-MD05

[Source](https://kantarainitiative.github.io/SAMLprofiles/fedinterop.html#IIP-MD05) / Section digest `sha256:179e60c42ba2…` / Section length 762 / Non-normative spans 0

| Obligation | Level | Role | Testability | Condition | Core/Full | Summary |
|---|---|---|---|---|---|---|
| `IIP-MD05.a` | MUST | idp/sp | `CONFIG` | — | core | Support SAML Metadata as defined in SAML V2.0 Metadata [SAML2Meta] as updated by Errata |
| `IIP-MD05.a1` | MUST | idp/sp | `CONFIG` | — | core | Metadata entity identifiers must be unique across all interacting entities |
| `IIP-MD05.a2` | MUST_NOT | idp/sp | `CONFIG` | — | core | A single metadata entity identifier must not refer to different entities |
| `IIP-MD05.a3` | MUST | idp/sp | `CONFIG` | — | core | Metadata extension content must be namespace-qualified as required by its extension point |
| `IIP-MD05.a4` | MUST | idp/sp | `CONFIG` | — | core | A metadata instance root must be EntityDescriptor for one entity or EntitiesDescriptor for multiple entities |
| `IIP-MD05.a5` | MUST | idp/sp | `CONFIG` | — | core | A root EntityDescriptor or EntitiesDescriptor must contain validUntil or cacheDuration |
| `IIP-MD05.a6` | RECOMMENDED | idp/sp | `CONFIG` | — | full | Only the root metadata element should contain validUntil or cacheDuration |
| `IIP-MD05.a7` | RECOMMENDED | idp/sp | `CONFIG` | — | full | Multiple role descriptors of the same type should not overlap in protocolSupportEnumeration |
| `IIP-MD05.a8` | MUST | idp/sp | `CONFIG` | — | core | AdditionalMetadataLocation namespace must identify the root namespace at the referenced location |
| `IIP-MD05.a9` | MUST | idp/sp | `CONFIG` | — | core | A SAML V2.0 role protocolSupportEnumeration must include the SAML V2.0 protocol namespace URI |
| `IIP-MD05.ab` | MUST | idp/sp | `CONFIG` | — | core | ResponseLocation must be omitted for endpoints associated with only one message direction |
| `IIP-MD05.ac` | MUST | idp/sp | `CONFIG` | — | core | If an affiliation owner is also a member, its identifier must appear as AffiliateMember |
| `IIP-MD05.ad` | SHOULD | idp/sp | `CONFIG` | — | full | A relying party should allow use of any same-purpose key included in metadata |
| `IIP-MD05.ae` | SHOULD | idp/sp | `CONFIG` | — | full | A signing or encrypting party should identify the key used as specifically as possible |
| `IIP-MD05.af` | RECOMMENDED | idp/sp | `CONFIG` | — | full | At least the root metadata element should be signed when no direct authenticated context exists |
| `IIP-MD05.ag` | MUST | idp/sp | `AUTOMATED` | — | core | SAML metadata signatures must be enveloped signatures |
| `IIP-MD05.ah` | SHOULD | idp/sp | `AUTOMATED` | — | full | Metadata processors should support RSA-SHA1 signing and verification |
| `IIP-MD05.ai` | MUST | idp/sp | `AUTOMATED` | — | core | A signed metadata element must have an identifier attribute value |
| `IIP-MD05.aj` | MUST | idp/sp | `AUTOMATED` | — | core | A metadata signature must contain one same-document Reference to the signed element ID and cover all its content |
| `IIP-MD05.ak` | SHOULD | idp/sp | `AUTOMATED` | — | full | Metadata signatures should use Exclusive Canonicalization in SignedInfo and as a Transform |
| `IIP-MD05.al` | SHOULD_NOT | idp/sp | `AUTOMATED` | — | full | Metadata signatures should not contain transforms other than enveloped-signature or Exclusive Canonicalization |
| `IIP-MD05.am` | MAY | idp/sp | `AUTOMATED` | — | full | A metadata signature verifier may reject signatures using other transforms |
| `IIP-MD05.an` | MUST | idp/sp | `AUTOMATED` | — | core | If a verifier accepts other transforms, it must ensure no signed metadata content is excluded |
| `IIP-MD05.ao` | MAY | idp/sp | `AUTOMATED` | — | full | A metadata signature may omit ds:KeyInfo |
| `IIP-MD05.ap` | MUST | idp/sp | `CONFIG` | — | core | A consumer must apply the shorter effective validUntil or cacheDuration from nested metadata |
| `IIP-MD05.aq` | MUST | idp/sp | `CONFIG` | — | core | Metadata caching must be based on cacheDuration |
| `IIP-MD05.ar` | MUST | idp/sp | `CONFIG` | — | core | Metadata must be considered invalid at effective validUntil |
| `IIP-MD05.as` | MUST_NOT | idp/sp | `CONFIG` | — | core | Invalid metadata must not be used |
| `IIP-MD05.at` | MAY | idp/sp | `CONFIG` | — | full | Stale but not explicitly invalid metadata may be used |
| `IIP-MD05.au` | MAY | idp/sp | `CONFIG` | — | full | When ResponseLocation is omitted, responses are handled at Location |
| `IIP-MD05.av` | MUST | idp/sp | `CONFIG` | — | core | Indexed endpoints must use unique indexes and the defined default-selection order within each same-name set |
| `IIP-MD05.aw` | MUST | idp/sp | `CONFIG` | — | core | Explicit KeyDescriptor use values must be interpreted as signing/TLS or encryption-key wrapping |
| `IIP-MD05.b` | MUST | idp/sp | `CONFIG` | — | core | Support SAML Metadata as defined by the SAML V2.0 Metadata Schema |
| `IIP-MD05.c` | MUST | idp/sp | `CONFIG` | — | core | Support metadata as defined by the SAML V2.0 Metadata Interoperability Profile |
| `IIP-MD05.c1` | MUST | idp/sp | `CONFIG` | — | core | Produced MDIOP metadata must stand alone as the description of secure communication requirements |
| `IIP-MD05.c2` | MUST | idp/sp | `CONFIG` | — | core | Every role descriptor in a conforming metadata instance must meet MDIOP requirements |
| `IIP-MD05.c3` | MUST | idp/sp | `CONFIG` | — | core | All keys currently valid for a role must appear within that role metadata |
| `IIP-MD05.c4` | MAY | idp/sp | `CONFIG` | — | full | Future signing or transport-authentication keys may be included for rollover |
| `IIP-MD05.c5` | SHOULD | idp/sp | `ATTESTED` | — | full | Expired rollover keys should be removed after migration completes |
| `IIP-MD05.c6` | MUST | idp/sp | `ATTESTED` | — | core | Compromised keys must be removed from metadata |
| `IIP-MD05.c7` | MUST_NOT | idp/sp | `ATTESTED` | — | core | A metadata producer must not rely on consumers to validate key status through PKIX or revocation services |
| `IIP-MD05.c8` | MUST | idp/sp | `CONFIG` | — | core | Each metadata role key must be in its own KeyDescriptor with the appropriate use |
| `IIP-MD05.c9` | MUST | idp/sp | `CONFIG` | — | core | KeyInfo must contain KeyValue or one X509Certificate representation |
| `IIP-MD05.ca` | MUST | idp/sp | `CONFIG` | — | core | An X509Data key representation must contain only one certificate |
| `IIP-MD05.cb` | MUST | idp/sp | `CONFIG` | — | core | When KeyValue and X509Certificate are both present they must represent the same key |
| `IIP-MD05.cc` | MAY | idp/sp | `CONFIG` | — | full | Additional KeyInfo representations may appear as hints |
| `IIP-MD05.cd` | MUST_NOT | idp/sp | `CONFIG` | — | core | Additional KeyInfo hints must not be required to identify a key |
| `IIP-MD05.ce` | RECOMMENDED | idp/sp | `CONFIG` | — | full | Certificates used as key containers should be unexpired |
| `IIP-MD05.d` | MUST | idp/sp | `CONFIG` | — | core | Support the Metadata Extension for Entity Attributes |
| `IIP-MD05.d1` | MUST | idp/sp | `CONFIG` | — | core | EntityAttributes assertions must be processed using the standard SAML assertion rules |
| `IIP-MD05.d2` | MUST_NOT | idp/sp | `CONFIG` | — | core | EntityAttributes under EntitiesDescriptor must not contain assertions |
| `IIP-MD05.d3` | MUST_NOT | idp/sp | `CONFIG` | — | core | EntityAttributes must not appear more than once in one Extensions element |
| `IIP-MD05.d4` | MUST | idp/sp | `CONFIG` | — | core | An EntityAttributes assertion subject must be an entity NameID whose value identifies the enclosing entity |
| `IIP-MD05.d5` | MUST_NOT | idp/sp | `CONFIG` | — | core | An EntityAttributes assertion subject must not contain SubjectConfirmation |
| `IIP-MD05.d6` | MUST | idp/sp | `CONFIG` | — | core | An EntityAttributes assertion must contain exactly one AttributeStatement |
| `IIP-MD05.d7` | MUST_NOT | idp/sp | `CONFIG` | — | core | An EntityAttributes assertion must not contain other statement types |
| `IIP-MD05.d8` | MUST | idp/sp | `CONFIG` | — | core | An EntityAttributes assertion must be independently signed |
| `IIP-MD05.d9` | MAY | idp/sp | `CONFIG` | — | full | Other legal assertion content may appear in an EntityAttributes assertion |
| `IIP-MD05.e` | MUST | idp/sp | `CONFIG` | — | core | Support the Metadata Extension for Algorithm Support |
| `IIP-MD05.e1` | SHOULD | idp/sp | `CONFIG` | — | full | An asymmetric encryption KeyDescriptor should list both data-encryption and key-transport or key-agreement algorithms |
| `IIP-MD05.e2` | MUST | idp/sp | `CONFIG` | — | core | Listed key-transport or key-agreement algorithms must be compatible with the associated encryption key |
| `IIP-MD05.e3` | SHOULD | idp/sp | `CONFIG` | — | full | A symmetric-key KeyDescriptor should list a block or stream encryption algorithm |
| `IIP-MD05.e4` | MUST | idp/sp | `CONFIG` | — | core | Every EncryptionMethod must contain an Algorithm URI |
| `IIP-MD05.e5` | MUST | idp/sp | `CONFIG` | — | core | Multiple EncryptionMethod elements of the same general type must be in preference order |
| `IIP-MD05.e6` | SHOULD | idp/sp | `CONFIG` | — | full | An entity should publish DigestMethod and SigningMethod capabilities |
| `IIP-MD05.e7` | MUST | idp/sp | `CONFIG` | — | core | Multiple DigestMethod or SigningMethod elements must be in preference order |
| `IIP-MD05.e8` | MUST | idp/sp | `CONFIG` | — | core | A consumer using peer-aware XML Signature or Encryption must consult metadata for the supported intersection |
| `IIP-MD05.e9` | SHOULD | idp/sp | `CONFIG` | — | full | A metadata consumer should consult algorithm elements in order |
| `IIP-MD05.ea` | SHOULD | idp/sp | `CONFIG` | — | full | A metadata consumer should select the first supported algorithm |
| `IIP-MD05.eb` | MUST | idp/sp | `CONFIG` | — | core | Role-level signature algorithm metadata must take precedence over entity-level metadata without combining the sets |
| `IIP-MD05.ec` | MUST | idp/sp | `CONFIG` | — | core | DigestMethod and SigningMethod elements must contain an Algorithm URI |
| `IIP-MD05.ed` | MAY | idp/sp | `CONFIG` | — | full | A symmetric-key KeyDescriptor may list EncryptionMethod elements for other algorithm types |
| `IIP-MD05.f` | MUST | idp/sp | `CONFIG` | — | core | Support the Metadata Extensions for Login and Discovery User Interface |
| `IIP-MD05.f1` | MUST | idp/sp | `CONFIG` | — | core | UIInfo must occur within the Extensions element of a role descriptor |
| `IIP-MD05.f2` | MUST | idp/sp | `CONFIG` | — | core | UIInfo must contain at least one child element |
| `IIP-MD05.f3` | MUST_NOT | idp/sp | `CONFIG` | — | core | UIInfo must not appear more than once in one Extensions element |
| `IIP-MD05.f4` | MUST_NOT | idp/sp | `CONFIG` | — | core | Localized UIInfo child elements must not repeat the same xml:lang for the same element type in one role |
| `IIP-MD05.f5` | MUST | idp/sp | `BROWSER` | — | core | A UI description must be standalone and not require templated additional text |
| `IIP-MD05.f6` | SHOULD | sp | `BROWSER` | — | full | An SP role description should describe the offered service |
| `IIP-MD05.f7` | SHOULD | idp | `BROWSER` | — | full | An IdP role description should describe the serviced user community |
| `IIP-MD05.f8` | SHOULD | idp/sp | `BROWSER` | — | full | Published logos should follow the profile's usability guidance |
| `IIP-MD05.f9` | SHOULD | idp/sp | `BROWSER` | — | full | A logo without xml:lang should be treated as the default when the preferred language is unavailable |
| `IIP-MD05.fa` | SHOULD | idp/sp | `BROWSER` | — | full | InformationURL content should provide more information than Description |
| `IIP-MD05.fb` | SHOULD_NOT | idp/sp | `BROWSER` | — | full | Discovery hints should not definitively select an identity provider without user confirmation |
| `IIP-MD05.fc` | MUST | idp/sp | `CONFIG` | — | core | DiscoHints must occur within IDPSSODescriptor Extensions |
| `IIP-MD05.fd` | MUST | idp/sp | `CONFIG` | — | core | DiscoHints must contain at least one child element |
| `IIP-MD05.fe` | MUST_NOT | idp/sp | `CONFIG` | — | core | DiscoHints must not appear more than once in one Extensions element |
| `IIP-MD05.ff` | MUST | idp/sp | `CONFIG` | — | core | Both IPv4 and IPv6 CIDR blocks must be supported in IPHint |
| `IIP-MD05.fg` | MUST | idp/sp | `BROWSER` | — | core | URLs used from metadata UI extensions must be sanitized and encoded against XSS |
| `IIP-MD05.fh` | SHOULD_NOT | idp/sp | `BROWSER` | — | full | Metadata UI URLs should not use schemes other than https, http, or data |
| `IIP-MD05.fi` | RECOMMENDED | idp/sp | `BROWSER` | — | full | Metadata UI URLs should use HTTPS |
| `IIP-MD05.fj` | SHOULD | idp/sp | `BROWSER` | — | full | Display-name consumers should prefer UIInfo DisplayName, then ServiceName, then entityID or endpoint hostname |
| `IIP-MD05.fk` | MUST | idp/sp | `CONFIG` | — | core | Every Logo element must contain height and width attributes |
| `IIP-MD05.g` | MUST_NOT | idp/sp | `CONFIG` | — | core | Other metadata extension content must not prevent consumption and use of the metadata |

<details><summary><code>IIP-MD05.a</code> details</summary>

- **Required variants**:
  - `v-6e4f504873` Place IDPSSODescriptor / SPSSODescriptor / AuthnAuthorityDescriptor / AttributeAuthorityDescriptor / PDPDescriptor directly under EntityDescriptor
  - `v-bed02785b7` Place derived types of the abstract RoleDescriptor
  - `v-a45bf64287` Place AffiliationDescriptor instead of the group of role descriptors
  - `v-58a609b1f1` Nest EntitiesDescriptor to two or more levels and interpret the expiration, extensions, and signatures at each level
  - `v-74e7bf1385` Include Organization / ContactPerson / AdditionalMetadataLocation
  - `v-ba7c269c2f` Use the semantics of KeyDescriptor / endpoint / NameIDFormat / AttributeProfile / AttributeConsumingService
- **Controls (negative controls)**:
  - Do not return PASS for syntactic acceptance alone. Confirm that endpoint, key, attribute request, and other meanings are actually used for interoperability
  - Do not make the optional publication mechanisms in SAML2Meta §4 (DNS / well-known location) required capabilities. HTTP retrieval is assessed separately by IIP-MD02, signature verification by IIP-MD03, and the ability to reject expired metadata by IIP-MD04
- **Configuration failure semantics**: `test_precondition`
- **Referenced specification**: `SAML2Meta`
- **Reference basis (SAML2Meta)**; locator: `2 Metadata for SAML V2\.0||3 Signature Processing`: Normative definitions of metadata elements, types, and semantics
- **Notes**: The phrase “future SAML specifications ... SHOULD provide alternate protocol support identifiers” in SAML2Meta §2.4.1 has authors of future specifications as its subject, so it is not an independent obligation for IdP / SP implementations
- **source_clauses**: `[0, 92)` `sha256:7dfacaaae6f1…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-MD05.a1</code> details</summary>

- **Required variants**:
  - `v-d4f5a455e9` Assign different entityIDs to two entities within the same deployment
  - `v-00be50cbc1` Use metadata with duplicate entityIDs as the control and have it rejected or treated as a conflict
- **Controls (negative controls)**:
  - A single entity does not verify uniqueness. Always include secondary_peer
- **Configuration failure semantics**: `test_precondition`
- **Referenced specification**: `SAML2Meta`
- **Reference basis (SAML2Meta)**; locator: `2\.2\.1 Simple Type entityIDType||2\.2\.2 Complex Type EndpointType`: The uniqueness of entityIDType is MUST
- **source_clauses**: `[0, 92)` `sha256:7dfacaaae6f1…` , `[93, 159)` `sha256:1360c8fd9ba8…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-MD05.a2</code> details</summary>

- **Required variants**:
  - `v-a7b52b7064` Register two entities simultaneously with the same entityID but different keys and endpoints
- **Controls (negative controls)**:
  - Do not mark an implementation that overwrites or merges entries to create an ambiguous state as satisfied. Distinguish an explicit replacement operation from simultaneous references
- **Configuration failure semantics**: `test_precondition`
- **Referenced specification**: `SAML2Meta`
- **Reference basis (SAML2Meta)**; locator: `2\.2\.1 Simple Type entityIDType||2\.2\.2 Complex Type EndpointType`: MUST NOT support multiple entities for a single URI
- **source_clauses**: `[0, 92)` `sha256:7dfacaaae6f1…` , `[93, 159)` `sha256:1360c8fd9ba8…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-MD05.a3</code> details</summary>

- **Required variants**:
  - `v-fff264c07f` Non-SAML namespace elements and attributes in EndpointType
  - `v-714c63dda0` Non-SAML namespace extensions in root / role / Organization / ContactPerson / AffiliationDescriptor
  - `v-490dfd8a4a` Negative control placing a global element or a SAML-defined namespace element in Organization/Extensions
- **Controls (negative controls)**:
  - Acceptance of unknown extensions is IIP-MD05.g; here, determine namespace qualification and extension-point constraints
- **Configuration failure semantics**: `test_precondition`
- **Referenced specification**: `SAML2Meta`
- **Reference basis (SAML2Meta)**; locator: `2\.2\.2 Complex Type EndpointType||2\.6 Examples`: Extension qualification rules for Endpoint / root / role / organization / contact / affiliation
- **source_clauses**: `[0, 92)` `sha256:7dfacaaae6f1…` , `[93, 159)` `sha256:1360c8fd9ba8…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-MD05.a4</code> details</summary>

- **Required variants**:
  - `v-2c53d0dd05` EntityDescriptor root for a single entity
  - `v-fd3b4d7771` EntitiesDescriptor root for multiple entities
- **Controls (negative controls)**:
  - Both forms can reuse the same fixture as IIP-MD02.c for consumption capability, but this obligation determines the structural semantics of SAML2Meta
- **Configuration failure semantics**: `test_precondition`
- **Referenced specification**: `SAML2Meta`
- **Reference basis (SAML2Meta)**; locator: `2\.3 Root Elements||2\.3\.1 Element <EntitiesDescriptor>`: MUST choose between the two root element types
- **source_clauses**: `[0, 92)` `sha256:7dfacaaae6f1…` , `[93, 159)` `sha256:1360c8fd9ba8…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-MD05.a5</code> details</summary>

- **Required variants**:
  - `v-8d4aa5e10b` EntityDescriptor root + validUntil
  - `v-4b096b7098` EntityDescriptor root with cacheDuration only
  - `v-a03e63f844` EntitiesDescriptor root + validUntil
  - `v-35122cb781` EntitiesDescriptor root with cacheDuration only
- **Controls (negative controls)**:
  - IIP-MD04.a separately requires the ability to reject a missing validUntil, but SAML2Meta permits a cacheDuration-only root. Detect implementations that always reject this during ordinary consumption under this obligation
- **Configuration failure semantics**: `test_precondition`
- **Referenced specification**: `SAML2Meta`
- **Reference basis (SAML2Meta)**; locator: `2\.3\.1 Element <EntitiesDescriptor>||2\.4 Role Descriptor Elements`: MUST have validUntil / cacheDuration on both root types
- **source_clauses**: `[0, 92)` `sha256:7dfacaaae6f1…` , `[93, 159)` `sha256:1360c8fd9ba8…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-MD05.a6</code> details</summary>

- **Required variants**:
  - `v-9ce4caa3ce` Inspect the expiration attributes on the root and child role / entity elements of the metadata generated by the target
- **Controls (negative controls)**:
  - Because E76 itself permits placement on a child as a MAY, do not mark the instance violated merely because a child has a shorter expiration. Evaluate the recommendation as avoiding unnecessary duplication
- **Configuration failure semantics**: `test_precondition`
- **Referenced specification**: `SAML2Meta`
- **Reference basis (SAML2Meta)**; locator: `2\.3\.1 Element <EntitiesDescriptor>||2\.4 Role Descriptor Elements`: RECOMMENDED to place expiration attributes only on the root
- **source_clauses**: `[0, 92)` `sha256:7dfacaaae6f1…` , `[93, 159)` `sha256:1360c8fd9ba8…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-MD05.a7</code> details</summary>

- **Required variants**:
  - `v-0b02d119ca` Compare protocolSupportEnumeration when the target issues multiple role descriptors of the same type
- **Controls (negative controls)**:
  - If there are zero or one role descriptors of the same type, the antecedent is false and the outcome is satisfied. If the meaning of overlap is defined by another profile, give precedence to that profile's rules
- **Configuration failure semantics**: `test_precondition`
- **Referenced specification**: `SAML2Meta`
- **Reference basis (SAML2Meta)**; locator: `2\.3\.2 Element <EntityDescriptor>||2\.3\.2\.1 Element <Organization>`: RECOMMENDED non-overlap of role descriptors of the same type
- **source_clauses**: `[0, 92)` `sha256:7dfacaaae6f1…` , `[93, 159)` `sha256:1360c8fd9ba8…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-MD05.a8</code> details</summary>

- **Required variants**:
  - `v-37403b861f` Match the referenced root namespace
  - `v-34181f3e0f` Negative control with a different namespace
- **Controls (negative controls)**:
  - If the URL cannot be retrieved, return not_verified(additional_metadata_location_unreachable). Do not return satisfied based solely on string comparison
- **Configuration failure semantics**: `test_precondition`
- **Referenced specification**: `SAML2Meta`
- **Reference basis (SAML2Meta)**; locator: `2\.3\.2\.3 Element <AdditionalMetadataLocation>||2\.4 Role Descriptor Elements`: MUST match the referenced root namespace
- **source_clauses**: `[0, 92)` `sha256:7dfacaaae6f1…` , `[93, 159)` `sha256:1360c8fd9ba8…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-MD05.a9</code> details</summary>

- **Required variants**:
  - `v-8fb515f377` All SAML V2 roles issued by the target have urn:oasis:names:tc:SAML:2.0:protocol
  - `v-83c2077ad3` Negative control with the role missing
- **Controls (negative controls)**:
  - Do not require this URI for non-SAML roles
- **Configuration failure semantics**: `test_precondition`
- **Referenced specification**: `SAML2Meta`
- **Reference basis (SAML2Meta)**; locator: `2\.4\.1 Element <RoleDescriptor>||2\.4\.1\.1 Element <KeyDescriptor>`: MUST have the protocol URI for a SAML V2 role
- **source_clauses**: `[0, 92)` `sha256:7dfacaaae6f1…` , `[93, 159)` `sha256:1360c8fd9ba8…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-MD05.ab</code> details</summary>

- **Required variants**:
  - `v-438a98ca4f` ArtifactResolutionService
  - `v-a551c9448c` SingleSignOnService
  - `v-5c568d3b1f` NameIDMappingService
- **Controls (negative controls)**:
  - Inspect the three element kinds individually. When ResponseLocation is omitted, also verify the E41 semantics in the fixture that Location becomes the response location for request/response endpoints
- **Configuration failure semantics**: `test_precondition`
- **Referenced specification**: `SAML2Meta`
- **Reference basis (SAML2Meta)**; locator: `2\.4\.2 Complex Type SSODescriptorType||2\.4\.4 Element <SPSSODescriptor>`: MUST omit ResponseLocation for ArtifactResolutionService / SSO / NameIDMapping
- **source_clauses**: `[0, 92)` `sha256:7dfacaaae6f1…` , `[93, 159)` `sha256:1360c8fd9ba8…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-MD05.ac</code> details</summary>

- **Required variants**:
  - `v-b946d9f6f1` Affiliation where the owner is also a member
  - `v-d27ac3e514` Control where the owner is not a member
- **Controls (negative controls)**:
  - Do not assume that the owner is always a member. Do not require AffiliateMember for an owner who is not a member
- **Configuration failure semantics**: `test_precondition`
- **Referenced specification**: `SAML2Meta`
- **Reference basis (SAML2Meta)**; locator: `2\.5 Element <AffiliationDescriptor>||2\.6 Examples`: MUST enumerate the owner when the owner is a member
- **source_clauses**: `[0, 92)` `sha256:7dfacaaae6f1…` , `[93, 159)` `sha256:1360c8fd9ba8…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-MD05.ad</code> details</summary>

- **Required variants**:
  - `v-3b5078a4db` Sign with the first / second key having the same use=signing
  - `v-8dca69d239` Sign with the first / second key with use omitted
- **Controls (negative controls)**:
  - The MUST in IIP-MD07 (consumption of all keys and trying each key) is stronger. Use the same fixture for the results and design aggregation so that this SHOULD is not reported as a separate additional failure
- **Configuration failure semantics**: `test_precondition`
- **Referenced specification**: `SAML2Meta`
- **Reference basis (SAML2Errata)**; locator: `E68: Use of Multiple <KeyDescriptor> Elements||E69: Semantics of <ds:KeyInfo> in <KeyDescriptor>`: SHOULD allow multiple keys for the same purpose
- **source_clauses**: `[0, 92)` `sha256:7dfacaaae6f1…` , `[93, 159)` `sha256:1360c8fd9ba8…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-MD05.ae</code> details</summary>

- **Required variants**:
  - `v-6b9def4bb4` When there are multiple candidate keys, the target's ds:KeyInfo or equivalent identifies the key used
- **Controls (negative controls)**:
  - If there is only one candidate key, the signing key is already unique and the antecedent is vacuously satisfied. Do not limit identification methods to X509Data
- **Configuration failure semantics**: `test_precondition`
- **Referenced specification**: `SAML2Meta`
- **Reference basis (SAML2Errata)**; locator: `E68: Use of Multiple <KeyDescriptor> Elements||E69: Semantics of <ds:KeyInfo> in <KeyDescriptor>`: SHOULD identify the key used
- **source_clauses**: `[0, 92)` `sha256:7dfacaaae6f1…` , `[93, 159)` `sha256:1360c8fd9ba8…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-MD05.af</code> details</summary>

- **Required variants**:
  - `v-26601ab56b` The root signature on metadata issued by the target via an unauthenticated channel or intermediary
- **Controls (negative controls)**:
  - Do not mark an unsigned result as WARNING when the context is obtained directly from the publisher over an authenticated secure channel. If the context is unknown, return not_verified
- **Configuration failure semantics**: `test_precondition`
- **Referenced specification**: `SAML2Meta`
- **Reference basis (SAML2Meta)**; locator: `3 Signature Processing||3\.1 XML Signature Profile`: RECOMMENDED root signature when there is no direct authenticated context
- **source_clauses**: `[0, 92)` `sha256:7dfacaaae6f1…` , `[93, 159)` `sha256:1360c8fd9ba8…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-MD05.ag</code> details</summary>

- **Required variants**:
  - `v-184bb0a467` Signed root, nested entity, role, and affiliation metadata issued by the target
- **Controls (negative controls)**:
  - A Run in which no signature is observed is satisfied_with_note. Whether a signature is mandatory is determined separately by IIP-MD03 / IIP-MD05.af
- **Referenced specification**: `SAML2Meta`
- **Reference basis (SAML2Meta)**; locator: `3\.1\.1 Signing Formats and Algorithms||3\.1\.2 References`: enveloped signature MUST
- **source_clauses**: `[0, 92)` `sha256:7dfacaaae6f1…` , `[93, 159)` `sha256:1360c8fd9ba8…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-MD05.ah</code> details</summary>

- **Required variants**:
  - `v-5fb0dc480b` Capability to verify RSA-SHA1-signed metadata
  - `v-09e26c70e7` RSA-SHA1 capability when the target signs metadata
- **Controls (negative controls)**:
  - A default policy that disables a compromised algorithm is permitted under IIP-ALG08.a. Capability present and policy disabled is satisfied; capability absent is violated→WARNING; capability unknown is not_verified
- **Referenced specification**: `SAML2Meta`
- **Reference basis (SAML2Meta)**; locator: `3\.1\.1 Signing Formats and Algorithms||3\.1\.2 References`: RSA-SHA1 support SHOULD
- **source_clauses**: `[0, 92)` `sha256:7dfacaaae6f1…` , `[93, 159)` `sha256:1360c8fd9ba8…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-MD05.ai</code> details</summary>

- **Required variants**:
  - `v-99ed1322b4` The @ID of each signed root, nested EntityDescriptor, RoleDescriptor, and AffiliationDescriptor
- **Controls (negative controls)**:
  - Passively inspect all metadata signatures
- **Referenced specification**: `SAML2Meta`
- **Reference basis (SAML2Meta)**; locator: `3\.1\.2 References||3\.1\.3 Canonicalization Method`: signed element identifier MUST
- **source_clauses**: `[0, 92)` `sha256:7dfacaaae6f1…` , `[93, 159)` `sha256:1360c8fd9ba8…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-MD05.aj</code> details</summary>

- **Required variants**:
  - `v-3bfa542451` Exactly one ds:Reference
  - `v-8530d7caf2` @URI is # followed by the signed element's @ID
  - `v-1b48aa8921` All content, including child elements, is covered by the signature
- **Controls (negative controls)**:
  - Use multiple References, an empty URI, an external URI, and a reference to a wrapped different element as negative controls
- **Referenced specification**: `SAML2Meta`
- **Reference basis (SAML2Meta)**; locator: `3\.1\.2 References||3\.1\.3 Canonicalization Method`: single Reference / URI / full content MUST
- **source_clauses**: `[0, 92)` `sha256:7dfacaaae6f1…` , `[93, 159)` `sha256:1360c8fd9ba8…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-MD05.ak</code> details</summary>

- **Required variants**:
  - `v-fe1090fdaf` CanonicalizationMethod
  - `v-75da6152f9` Reference Transform
- **Controls (negative controls)**:
  - Allow both with comments and without comments
- **Referenced specification**: `SAML2Meta`
- **Reference basis (SAML2Meta)**; locator: `3\.1\.3 Canonicalization Method||3\.1\.4 Transforms`: Exclusive C14N SHOULD
- **source_clauses**: `[0, 92)` `sha256:7dfacaaae6f1…` , `[93, 159)` `sha256:1360c8fd9ba8…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-MD05.al</code> details</summary>

- **Required variants**:
  - `v-4f316a5bd3` Transform allowlist for all metadata signatures issued by the target
- **Controls (negative controls)**:
  - The recipient MAY reject an unauthorized transform. The two alternatives are handled by IIP-MD05.am / .an
- **Referenced specification**: `SAML2Meta`
- **Reference basis (SAML2Meta)**; locator: `3\.1\.4 Transforms||3\.1\.5 KeyInfo`: SHOULD NOT use unauthorized transforms
- **source_clauses**: `[0, 92)` `sha256:7dfacaaae6f1…` , `[93, 159)` `sha256:1360c8fd9ba8…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-MD05.am</code> details</summary>

- **Required variants**:
  - `v-1f160949b2` An unauthorized transform that does not exclude content
- **Controls (negative controls)**:
  - Because both rejection and safe acceptance are permitted, this variant alone receives no target verdict. Use it for fixture self-validation and as branching input for IIP-MD05.an
- **Referenced specification**: `SAML2Meta`
- **Reference basis (SAML2Meta)**; locator: `3\.1\.4 Transforms||3\.1\.5 KeyInfo`: MAY reject an unauthorized transform
- **source_clauses**: `[0, 92)` `sha256:7dfacaaae6f1…` , `[93, 159)` `sha256:1360c8fd9ba8…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-MD05.an</code> details</summary>

- **Required variants**:
  - `v-798bb0a999` XPath that excludes child RoleDescriptors
  - `v-cdcf50aec5` XPath that excludes endpoints
  - `v-d7816d91ca` XPath that excludes KeyDescriptors
- **Controls (negative controls)**:
  - For each transform: rejection→satisfied, acceptance with no exclusion→satisfied, acceptance with exclusion→violated, inability to determine→not_verified
- **Referenced specification**: `SAML2Meta`
- **Reference basis (SAML2Meta)**; locator: `3\.1\.4 Transforms||3\.1\.5 KeyInfo`: MUST guarantee full content when accepting an unauthorized transform
- **source_clauses**: `[0, 92)` `sha256:7dfacaaae6f1…` , `[93, 159)` `sha256:1360c8fd9ba8…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-MD05.ao</code> details</summary>

- **Required variants**:
  - `v-b8d786e01b` Signed metadata without ds:KeyInfo, verified using an out-of-band configuration key
- **Controls (negative controls)**:
  - Combine with the out-of-band key from IIP-MD03.b. Detect parsers that require KeyInfo
- **Referenced specification**: `SAML2Meta`
- **Reference basis (SAML2Meta)**; locator: `3\.1\.5 KeyInfo||4 Metadata Publication and Resolution`: KeyInfo absence MAY
- **source_clauses**: `[0, 92)` `sha256:7dfacaaae6f1…` , `[93, 159)` `sha256:1360c8fd9ba8…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-MD05.ap</code> details</summary>

- **Required variants**:
  - `v-563c895efd` The parent has the shorter validUntil
  - `v-0ae77a103c` The child has the shorter validUntil
  - `v-3260a8f038` The parent has the shorter cacheDuration
  - `v-79c21076ba` The child has the shorter cacheDuration
- **Controls (negative controls)**:
  - The MAY in E76 permits the publisher to place a shorter value on the child; it does not mean that the consumer may adopt the longer value
- **Configuration failure semantics**: `test_precondition`
- **Referenced specification**: `SAML2Meta`
- **Reference basis (SAML2Errata)**; locator: `E76: Clarify nested validUntil/cacheDuration||E77: Generalize scope of Metadata specification`: Prefer the smaller nested expiry/cache duration value
- **source_clauses**: `[0, 92)` `sha256:7dfacaaae6f1…` , `[93, 159)` `sha256:1360c8fd9ba8…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-MD05.aq</code> details</summary>

- **Required variants**:
  - `v-9198a7f64b` Immediately before/after cacheDuration measured from the instance retrieval time
  - `v-52e102e686` The parent's cacheDuration is shorter than the child's
- **Controls (negative controls)**:
  - Do not confuse cache expiration with metadata invalidity. Treating metadata as invalid solely because refresh failed is not required by this obligation
  - An internal implementation that explicitly stores the retrieval time is not required. The same cache expiry may be derived from other time information
- **Configuration failure semantics**: `test_precondition`
- **Referenced specification**: `SAML2Meta`
- **Reference basis (SAML2Errata)**; locator: `E94: Discussion of metadata caching mixes in validity||3 Acknowledgments`: MUST cache based on cacheDuration
- **Notes**: The replacement text in Errata E94 uses uppercase MUST for caching but lowercase “consumers must retain” for retrieval time. Under the SAML2Meta §1.2 Notation, do not evaluate the latter as an independent MUST
- **source_clauses**: `[0, 92)` `sha256:7dfacaaae6f1…` , `[93, 159)` `sha256:1360c8fd9ba8…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-MD05.ar</code> details</summary>

- **Required variants**:
  - `v-6312fa9513` The root validUntil is reached
  - `v-6f728e21b0` The earlier parent validUntil is reached
  - `v-88191815f6` The earlier child validUntil is reached
- **Controls (negative controls)**:
  - Reasonable clock skew follows IIP-G01
- **Configuration failure semantics**: `test_precondition`
- **Referenced specification**: `SAML2Meta`
- **Reference basis (SAML2Errata)**; locator: `E94: Discussion of metadata caching mixes in validity||3 Acknowledgments`: MUST treat metadata as invalid when validUntil is reached
- **source_clauses**: `[0, 92)` `sha256:7dfacaaae6f1…` , `[93, 159)` `sha256:1360c8fd9ba8…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-MD05.as</code> details</summary>

- **Required variants**:
  - `v-0080ee6fd9` Do not use the endpoints, signing key, or encryption key from expired metadata
- **Controls (negative controls)**:
  - Metadata that is merely stale because cacheDuration has elapsed is not invalid. Pair this with the MAY in IIP-MD05.at
- **Configuration failure semantics**: `test_precondition`
- **Referenced specification**: `SAML2Meta`
- **Reference basis (SAML2Errata)**; locator: `E94: Discussion of metadata caching mixes in validity||3 Acknowledgments`: MUST NOT use invalid metadata
- **source_clauses**: `[0, 92)` `sha256:7dfacaaae6f1…` , `[93, 159)` `sha256:1360c8fd9ba8…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-MD05.at</code> details</summary>

- **Required variants**:
  - `v-e72d918b3e` cacheDuration elapsed, validUntil not reached, and a temporary refresh failure
- **Controls (negative controls)**:
  - Both continued use and suspension are permitted. Do not assign a unique target verdict; use this as a control for a separate determination that incorrectly equates cache expiry with invalidity
- **Configuration failure semantics**: `test_precondition`
- **Referenced specification**: `SAML2Meta`
- **Reference basis (SAML2Errata)**; locator: `E94: Discussion of metadata caching mixes in validity||3 Acknowledgments`: stale metadata use MAY
- **source_clauses**: `[0, 92)` `sha256:7dfacaaae6f1…` , `[93, 159)` `sha256:1360c8fd9ba8…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-MD05.au</code> details</summary>

- **Required variants**:
  - `v-9d5353558e` An endpoint with both a request and a response, with ResponseLocation omitted
  - `v-70cd58af4a` A control case explicitly specifying ResponseLocation
- **Controls (negative controls)**:
  - The source text says “may be assumed,” so do not elevate capability permission to a MUST. For an endpoint with a single message direction, ResponseLocation itself is unused (IIP-MD05.ab)
- **Configuration failure semantics**: `test_precondition`
- **Referenced specification**: `SAML2Meta`
- **Reference basis (SAML2Errata)**; locator: `E41: EndpointType ResponseLocation Clarification in Metadata||E42: Match Authorities to Queries in Conformance`: ResponseLocation omission semantics MAY
- **source_clauses**: `[0, 92)` `sha256:7dfacaaae6f1…` , `[93, 159)` `sha256:1360c8fd9ba8…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-MD05.av</code> details</summary>

- **Required variants**:
  - `v-3f02af3b60` The first isDefault=true
  - `v-b93b346158` If none is true, the first endpoint with isDefault omitted
  - `v-74448cfe49` If none is omitted, the first in sequence
  - `v-cc54ad0238` A negative control with duplicate indexes under the same parent and identical element name
- **Controls (negative controls)**:
  - Do not mix AssertionConsumerService and ArtifactResolutionService into one set. Evaluate them by element name plus namespace, as required by E37
- **Configuration failure semantics**: `test_precondition`
- **Referenced specification**: `SAML2Meta`
- **Reference basis (SAML2Meta)**; locator: `2\.2\.3 Complex Type IndexedEndpointType||2\.2\.4 Complex Type localizedNameType`: index uniqueness / default semantics
- **Reference basis (SAML2Errata)**; locator: `E37: Clarification in Metadata on Indexed Endpoints||E38: Clarification Regarding Index on <LogoutRequest>`: The default set for each identical element name and namespace
- **source_clauses**: `[0, 92)` `sha256:7dfacaaae6f1…` , `[93, 159)` `sha256:1360c8fd9ba8…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-MD05.aw</code> details</summary>

- **Required variants**:
  - `v-3f0cdace88` XML signature with use=signing
  - `v-bccf77c036` TLS with use=signing
  - `v-ea26280294` Key wrapping with use=encryption
- **Controls (negative controls)**:
  - Do not narrow use=signing to XML signatures alone. Do not confuse use=encryption with declaring the data encryption algorithm itself
  - When use is omitted, evaluate XML signatures, TLS/SSL, and encryption-key wrapping only once under IIP-MD11.a, which the IIP text makes directly MUST by citing E62; do not double-count them under this obligation
- **Configuration failure semantics**: `test_precondition`
- **Referenced specification**: `SAML2Meta`
- **Reference basis (SAML2Errata)**; locator: `E62: TLS Keys in KeyDescriptor||E63: IdP Discovery Cookie Interpretation`: KeyDescriptor use semantics
- **source_clauses**: `[0, 92)` `sha256:7dfacaaae6f1…` , `[93, 159)` `sha256:1360c8fd9ba8…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-MD05.b</code> details</summary>

- **Required variants**:
  - `v-f7c226f99b` EntityDescriptor, and EntitiesDescriptor recursively containing a mixture of EntityDescriptor and EntitiesDescriptor
  - `v-8b70c046e7` The exclusive structure of the six standard role descriptors, RoleDescriptor-derived types, and AffiliationDescriptor
  - `v-3bfeba85a9` Organization with multilingual Name, DisplayName, and URL, and ContactPerson with every contactType and multiple email and telephone elements
  - `v-2aaa9dc560` AdditionalMetadataLocation and element and attribute extensions in non-SAML namespaces
  - `v-080c62a277` KeyDescriptor with use omitted, signing, and encryption, and multiple EncryptionMethod elements
  - `v-38e1ce2006` Common SSO endpoint set and NameIDFormat
  - `v-8be0a0a974` All optional elements of IDPSSODescriptor and WantAuthnRequestsSigned
  - `v-a6db211cb3` Multiple AssertionConsumerService elements in SPSSODescriptor, and AuthnRequestsSigned and WantAssertionsSigned
  - `v-2d489562c8` AttributeConsumingService with multilingual ServiceName and Description, multiple RequestedAttribute elements, and isRequired
  - `v-bc8c8a94a1` Required endpoints and all optional child elements of AuthnAuthority, PDP, and AttributeAuthority
  - `v-cdc3698d98` Multiple AffiliateMember and KeyDescriptor elements in AffiliationDescriptor
  - `v-7d06c99c1f` Binding, Location, ResponseLocation, and extensions of EndpointType, plus index and isDefault of IndexedEndpointType
  - `v-2d1aa712b4` The 1,024-character boundary of entityIDType, and required xml:lang for localizedNameType and localizedURIType
- **Controls (negative controls)**:
  - Do not make this a smoke test containing only one arbitrary element type. Cover every global element family and both sides of each choice in the fixture inventory
  - Place a schema-invalid fixture as a control to detect both implementations that reject all unknown extensions and implementations that perform no schema validation
- **Configuration failure semantics**: `test_precondition`
- **Referenced specification**: `SAML2MD-xsd`
- **Reference basis (SAML2MD-xsd)**; locator: `<schema\n||</schema>`: The metadata schema itself: types, cardinality, and extension points
- **source_clauses**: `[0, 92)` `sha256:7dfacaaae6f1…` , `[160, 199)` `sha256:7843eb17ece7…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-MD05.c</code> details</summary>

- **Required variants**:
  - `v-35eb2ff7f8` MDIOP metadata with either EntityDescriptor or EntitiesDescriptor as the root
  - `v-547364d60c` KeyDescriptors in which KeyValue only, X509Certificate only, or both represent the same key
  - `v-fd5e1cd1a9` KeyDescriptors for signing, encryption, or omitted use, including multiple keys for the same use
  - `v-af6c7be3af` Certificate representations that are expired, not yet valid, or have optional subject, issuer, extension, or usage flags
- **Controls (negative controls)**:
  - This obligation group concerns the ability to generate and accept representations conforming to the MDIOP. Runtime interpretation of keys after acceptance is evaluated once in the IIP-MD06.a group.
  - Each certificate variation may reuse the same fixture as IIP-MD12.d, but MD05.c evaluates consumption of the MDIOP representation, whereas MD12.d evaluates the ability not to reject it because of the certificate contents.
- **Configuration failure semantics**: `test_precondition`
- **Referenced specification**: `SAML2MDIOP`
- **Reference basis (SAML2MDIOP)**; locator: `2 SAML V2\.0 Metadata Interoperability Profile||2\.6 Metadata Consumer Requirements`: MDIOP overview, producer requirements, and key representation
- **source_clauses**: `[0, 92)` `sha256:7dfacaaae6f1…` , `[200, 256)` `sha256:889fb918741c…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-MD05.c1</code> details</summary>

- **Required variants**:
  - `v-4dbd484b01` The target role's endpoint, protocol, signing, encryption, and transport-authentication keys can be resolved solely from metadata
- **Controls (negative controls)**:
  - Local policies that cannot be expressed in metadata are out of scope. Detect implementations that place a policy in a separate configuration even though it can be expressed in metadata
- **Configuration failure semantics**: `test_precondition`
- **Referenced specification**: `SAML2MDIOP`
- **Reference basis (SAML2MDIOP)**; locator: `2\.5 Metadata Producer Requirements||2\.5\.1 Key Representation`: The producer metadata self-contained MUST
- **source_clauses**: `[0, 92)` `sha256:7dfacaaae6f1…` , `[200, 256)` `sha256:889fb918741c…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-MD05.c2</code> details</summary>

- **Required variants**:
  - `v-8d7d2362fc` The first and second roles within the same EntityDescriptor
  - `v-15ca29d55b` Each role nested within EntitiesDescriptor
- **Controls (negative controls)**:
  - Do not inspect only the first role and mark the result PASS. Traverse all roles
- **Configuration failure semantics**: `test_precondition`
- **Referenced specification**: `SAML2MDIOP`
- **Reference basis (SAML2MDIOP)**; locator: `2\.5 Metadata Producer Requirements||2\.5\.1 Key Representation`: The profile-conformance MUST for every role descriptor
- **source_clauses**: `[0, 92)` `sha256:7dfacaaae6f1…` , `[200, 256)` `sha256:889fb918741c…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-MD05.c3</code> details</summary>

- **Required variants**:
  - `v-b2d85eabc3` The current signing key
  - `v-f686c07641` The current encryption key
  - `v-e1fe6df5a8` The transport-authentication key, such as mutual TLS, when used
  - `v-405eb1f45b` Multiple current keys for the same purpose
- **Controls (negative controls)**:
  - Compare the target's actual key inventory with its metadata. Because metadata alone cannot prove that no keys are missing, return not_verified if the inventory cannot be obtained
- **Configuration failure semantics**: `test_precondition`
- **Referenced specification**: `SAML2MDIOP`
- **Reference basis (SAML2MDIOP)**; locator: `2\.5 Metadata Producer Requirements||2\.5\.1 Key Representation`: The MUST to publish current signing, encryption, and TLS keys
- **source_clauses**: `[0, 92)` `sha256:7dfacaaae6f1…` , `[200, 256)` `sha256:889fb918741c…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-MD05.c4</code> details</summary>

- **Required variants**:
  - `v-a815abb853` Rollover metadata publishing the current and future keys simultaneously
- **Controls (negative controls)**:
  - Both publishing and not publishing are permitted. Use this as a fixture to verify that a consumer does not reject valid metadata containing a future key, and do not assign a unique verdict to the publisher
- **Configuration failure semantics**: `test_precondition`
- **Referenced specification**: `SAML2MDIOP`
- **Reference basis (SAML2MDIOP)**; locator: `2\.5 Metadata Producer Requirements||2\.5\.1 Key Representation`: future key inclusion MAY
- **source_clauses**: `[0, 92)` `sha256:7dfacaaae6f1…` , `[200, 256)` `sha256:889fb918741c…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-MD05.c5</code> details</summary>

- **Required variants**:
  - `v-8ddc15d00f` Compare the inventory of old keys from a completed rollover with the published metadata
- **Controls (negative controls)**:
  - Do not mark an old key still within the permitted transition period as WARNING. If the rollover completion time cannot be confirmed, return not_verified
- **Referenced specification**: `SAML2MDIOP`
- **Reference basis (SAML2MDIOP)**; locator: `2\.5 Metadata Producer Requirements||2\.5\.1 Key Representation`: expired rollover key removal SHOULD
- **source_clauses**: `[0, 92)` `sha256:7dfacaaae6f1…` , `[200, 256)` `sha256:889fb918741c…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-MD05.c6</code> details</summary>

- **Required variants**:
  - `v-c9258c75d9` A test key marked as compromised disappears from the next published metadata
- **Controls (negative controls)**:
  - Do not compromise a real key. If this cannot be performed using an isolated test fixture or instrumented inventory, return not_verified(compromise_workflow_not_testable)
- **Referenced specification**: `SAML2MDIOP`
- **Reference basis (SAML2MDIOP)**; locator: `2\.5 Metadata Producer Requirements||2\.5\.1 Key Representation`: compromised key removal MUST
- **source_clauses**: `[0, 92)` `sha256:7dfacaaae6f1…` , `[200, 256)` `sha256:889fb918741c…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-MD05.c7</code> details</summary>

- **Required variants**:
  - `v-839a6e21db` There is no configuration that leaves a compromised key in metadata and relies only on its inclusion in a CRL/OCSP
- **Controls (negative controls)**:
  - If reliance on the internal process cannot be proven externally, return not_verified with attestation_unavailable. Do not mark the result violated merely because a CRL exists
- **Referenced specification**: `SAML2MDIOP`
- **Reference basis (SAML2MDIOP)**; locator: `2\.5 Metadata Producer Requirements||2\.5\.1 Key Representation`: The MUST NOT on consumer reliance on revocation
- **source_clauses**: `[0, 92)` `sha256:7dfacaaae6f1…` , `[200, 256)` `sha256:889fb918741c…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-MD05.c8</code> details</summary>

- **Required variants**:
  - `v-b2ef372156` signing key
  - `v-c52072263f` encryption key
  - `v-2b2a04c0ab` TLS/transport authentication key（use=signing）
  - `v-ed7b2d4fe1` use omitted (both uses)
- **Controls (negative controls)**:
  - Detect output that places multiple different keys in one KeyDescriptor. Do not treat an omitted use attribute as a violation, because E62 defines it as applying to both uses.
- **Configuration failure semantics**: `test_precondition`
- **Referenced specification**: `SAML2MDIOP`
- **Reference basis (SAML2MDIOP)**; locator: `2\.5\.1 Key Representation||2\.6 Metadata Consumer Requirements`: one key per KeyDescriptor / appropriate use MUST
- **source_clauses**: `[0, 92)` `sha256:7dfacaaae6f1…` , `[200, 256)` `sha256:889fb918741c…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-MD05.c9</code> details</summary>

- **Required variants**:
  - `v-675d5f3f5b` KeyValue only
  - `v-7feb6f3353` X509Data/X509Certificate only
  - `v-055edc006d` Both
- **Controls (negative controls)**:
  - Use a KeyInfo containing only KeyName as the negative control.
- **Configuration failure semantics**: `test_precondition`
- **Referenced specification**: `SAML2MDIOP`
- **Reference basis (SAML2MDIOP)**; locator: `2\.5\.1 Key Representation||2\.6 Metadata Consumer Requirements`: required key representations MUST
- **source_clauses**: `[0, 92)` `sha256:7dfacaaae6f1…` , `[200, 256)` `sha256:889fb918741c…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-MD05.ca</code> details</summary>

- **Required variants**:
  - `v-7ca3a603b8` One X509Certificate
  - `v-a1d82babea` Negative control with two X509Certificate elements
- **Controls (negative controls)**:
  - Because the schema itself may allow multiple X509Certificate elements, do not mark the result PASS based on schema validation alone.
- **Configuration failure semantics**: `test_precondition`
- **Referenced specification**: `SAML2MDIOP`
- **Reference basis (SAML2MDIOP)**; locator: `2\.5\.1 Key Representation||2\.6 Metadata Consumer Requirements`: single certificate representation
- **source_clauses**: `[0, 92)` `sha256:7dfacaaae6f1…` , `[200, 256)` `sha256:889fb918741c…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-MD05.cb</code> details</summary>

- **Required variants**:
  - `v-cd083fb317` KeyValue and certificate for the same public key
  - `v-ba193b7e13` Negative control with different keys
- **Controls (negative controls)**:
  - Compare canonical public-key values, not their string representations.
- **Configuration failure semantics**: `test_precondition`
- **Referenced specification**: `SAML2MDIOP`
- **Reference basis (SAML2MDIOP)**; locator: `2\.5\.1 Key Representation||2\.6 Metadata Consumer Requirements`: dual representation same-key MUST
- **source_clauses**: `[0, 92)` `sha256:7dfacaaae6f1…` , `[200, 256)` `sha256:889fb918741c…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-MD05.cc</code> details</summary>

- **Required variants**:
  - `v-6f840955cf` KeyValue or X509Certificate accompanied by KeyName, X509SubjectName, or X509IssuerSerial
- **Controls (negative controls)**:
  - Check that the consumer can consume the representation even when an additional hint is present. Do not require the publisher to include the hint.
- **Configuration failure semantics**: `test_precondition`
- **Referenced specification**: `SAML2MDIOP`
- **Reference basis (SAML2MDIOP)**; locator: `2\.5\.1 Key Representation||2\.6 Metadata Consumer Requirements`: additional KeyInfo hints MAY
- **source_clauses**: `[0, 92)` `sha256:7dfacaaae6f1…` , `[200, 256)` `sha256:889fb918741c…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-MD05.cd</code> details</summary>

- **Required variants**:
  - `v-b9a73a5e4a` KeyValue only, without KeyName
  - `v-12230c9520` X509Certificate only, without subject or issuer hints
- **Controls (negative controls)**:
  - Test both basic representations separately. Do not mark PASS based on only one of them.
- **Configuration failure semantics**: `test_precondition`
- **Referenced specification**: `SAML2MDIOP`
- **Reference basis (SAML2MDIOP)**; locator: `2\.5\.1 Key Representation||2\.6 Metadata Consumer Requirements`: hints-only identification MUST NOT
- **source_clauses**: `[0, 92)` `sha256:7dfacaaae6f1…` , `[200, 256)` `sha256:889fb918741c…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-MD05.ce</code> details</summary>

- **Required variants**:
  - `v-efc5ad499f` The NotBefore / NotAfter values of the X509Certificate generated by the subject
- **Controls (negative controls)**:
  - An expired certificate is still profile-valid, and the consumer must not reject it (MD12.d / MD06.aj). It is subject to a WARNING only on the publisher side.
- **Configuration failure semantics**: `test_precondition`
- **Referenced specification**: `SAML2MDIOP`
- **Reference basis (SAML2MDIOP)**; locator: `2\.5\.1 Key Representation||2\.6 Metadata Consumer Requirements`: unexpired certificate RECOMMENDED
- **source_clauses**: `[0, 92)` `sha256:7dfacaaae6f1…` , `[200, 256)` `sha256:889fb918741c…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-MD05.d</code> details</summary>

- **Required variants**:
  - `v-feb71dd10e` Place multiple direct Attributes in EntityAttributes under EntityDescriptor/Extensions, with multiple values and unknown attributes in each Attribute.
  - `v-bed2418e24` Place a profile-conforming, signed Assertion in EntityAttributes under EntityDescriptor/Extensions.
  - `v-13f7012200` Place a direct Attribute in EntityAttributes under EntitiesDescriptor/Extensions and exercise its binding to all child EntityDescriptors.
  - `v-c6ae05eabd` Include additional content permitted by the Assertion profile, such as Conditions.
- **Controls (negative controls)**:
  - Do not mark the result PASS merely because the metadata as a whole was accepted while extension elements were ignored. Obtain evidence that the attributes were used through a read-back path such as policy or discovery.
- **Configuration failure semantics**: `test_precondition`
- **Referenced specification**: `MetaAttr`
- **Reference basis (MetaAttr)**; locator: `2 SAML V2\.0 Metadata Extension for Entity Attributes||3 Conformance`: EntityAttributes placement, assertion profile, and consumer conformance
- **source_clauses**: `[0, 92)` `sha256:7dfacaaae6f1…` , `[257, 318)` `sha256:2dfa8c656abb…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-MD05.d1</code> details</summary>

- **Required variants**:
  - `v-5dabfdc805` An attribute assertion with a valid signature and valid Conditions
  - `v-2303c095eb` Negative control with an invalid signature or expired Conditions
- **Controls (negative controls)**:
  - Confirm that the implementation performs standard processing, including signatures and Conditions, rather than merely reading the assertion's attributes.
- **Configuration failure semantics**: `test_precondition`
- **Referenced specification**: `MetaAttr`
- **Reference basis (MetaAttr)**; locator: `2\.3 Element <mdattr:EntityAttributes>||2\.4 Assertion Profile`: assertion processing MUST
- **source_clauses**: `[0, 92)` `sha256:7dfacaaae6f1…` , `[257, 318)` `sha256:2dfa8c656abb…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-MD05.d2</code> details</summary>

- **Required variants**:
  - `v-ac40c02178` EntitiesDescriptor + direct Attribute（valid）
  - `v-80a2da2696` EntitiesDescriptor + Assertion（invalid）
- **Controls (negative controls)**:
  - An Assertion is permitted in the EntityDescriptor scope. Do not prohibit it in every context.
- **Configuration failure semantics**: `test_precondition`
- **Referenced specification**: `MetaAttr`
- **Reference basis (MetaAttr)**; locator: `2\.3 Element <mdattr:EntityAttributes>||2\.4 Assertion Profile`: MUST NOT allow an Assertion in the group scope
- **source_clauses**: `[0, 92)` `sha256:7dfacaaae6f1…` , `[257, 318)` `sha256:2dfa8c656abb…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-MD05.d3</code> details</summary>

- **Required variants**:
  - `v-24f1fa730a` One EntityAttributes element
  - `v-38ddb5cb1b` Negative control with two elements in the same Extensions element
- **Controls (negative controls)**:
  - It is permitted to place one in each of separate EntityDescriptor elements.
- **Configuration failure semantics**: `test_precondition`
- **Referenced specification**: `MetaAttr`
- **Reference basis (MetaAttr)**; locator: `2\.3 Element <mdattr:EntityAttributes>||2\.4 Assertion Profile`: single occurrence MUST NOT
- **source_clauses**: `[0, 92)` `sha256:7dfacaaae6f1…` , `[257, 318)` `sha256:2dfa8c656abb…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-MD05.d4</code> details</summary>

- **Required variants**:
  - `v-6e85cc0870` Format=urn:oasis:names:tc:SAML:2.0:nameid-format:entity
  - `v-a574e53811` The textual content of NameID matches enclosing EntityDescriptor/@entityID
  - `v-266c91df82` Negative control with a different NameID value
- **Controls (negative controls)**:
  - Do not use NameQualifier as a substitute for the matching value. For an entity NameID, do not require NameQualifier, SPNameQualifier, or SPProvidedID, in accordance with SAML2Core §8.3.6.
- **Configuration failure semantics**: `test_precondition`
- **Referenced specification**: `MetaAttr`
- **Reference basis (MetaAttr)**; locator: `2\.4 Assertion Profile||3 Conformance`: subject NameID format / value correspondence MUST
- **source_clauses**: `[0, 92)` `sha256:7dfacaaae6f1…` , `[257, 318)` `sha256:2dfa8c656abb…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-MD05.d5</code> details</summary>

- **Required variants**:
  - `v-d10e303d7c` Valid assertion without SubjectConfirmation
  - `v-bc6e07b358` Negative control with bearer or holder-of-key SubjectConfirmation
- **Controls (negative controls)**:
  - Test both Methods and do not miss an implementation that rejects only a specific Method.
- **Configuration failure semantics**: `test_precondition`
- **Referenced specification**: `MetaAttr`
- **Reference basis (MetaAttr)**; locator: `2\.4 Assertion Profile||3 Conformance`: SubjectConfirmation exclusion MUST NOT
- **source_clauses**: `[0, 92)` `sha256:7dfacaaae6f1…` , `[257, 318)` `sha256:2dfa8c656abb…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-MD05.d6</code> details</summary>

- **Required variants**:
  - `v-15d4102e85` One AttributeStatement
  - `v-e3a3e49579` Negative control with zero or two AttributeStatement elements
- **Controls (negative controls)**:
  - Allow multiple Attribute and AttributeValue elements within AttributeStatement.
- **Configuration failure semantics**: `test_precondition`
- **Referenced specification**: `MetaAttr`
- **Reference basis (MetaAttr)**; locator: `2\.4 Assertion Profile||3 Conformance`: one and only one AttributeStatement MUST
- **source_clauses**: `[0, 92)` `sha256:7dfacaaae6f1…` , `[257, 318)` `sha256:2dfa8c656abb…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-MD05.d7</code> details</summary>

- **Required variants**:
  - `v-7f421a554a` AuthnStatement
  - `v-50938938ac` AuthzDecisionStatement
  - `v-b552b5c510` Unknown Statement-derived type
- **Controls (negative controls)**:
  - Conditions, Advice, and similar elements are permitted as MAY content rather than being statements; do not treat them as grounds for rejection.
- **Configuration failure semantics**: `test_precondition`
- **Referenced specification**: `MetaAttr`
- **Reference basis (MetaAttr)**; locator: `2\.4 Assertion Profile||3 Conformance`: other statement types MUST NOT
- **source_clauses**: `[0, 92)` `sha256:7dfacaaae6f1…` , `[257, 318)` `sha256:2dfa8c656abb…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-MD05.d8</code> details</summary>

- **Required variants**:
  - `v-a7d9ec1006` The Assertion's own signature plus the parent metadata signature
  - `v-430b2c9f4c` Negative control signed only by the parent
- **Controls (negative controls)**:
  - Verify the Assertion's own ds:Signature regardless of whether a parent signature is present.
- **Configuration failure semantics**: `test_precondition`
- **Referenced specification**: `MetaAttr`
- **Reference basis (MetaAttr)**; locator: `2\.4 Assertion Profile||3 Conformance`: independent assertion signature MUST
- **source_clauses**: `[0, 92)` `sha256:7dfacaaae6f1…` , `[257, 318)` `sha256:2dfa8c656abb…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-MD05.d9</code> details</summary>

- **Required variants**:
  - `v-538de5bcd1` Conditions
  - `v-6fd223051d` Advice
  - `v-8f0986c30b` Standard content such as Issuer
- **Controls (negative controls)**:
  - Verify the ability to accept all content using the parent MUST fixture. Do not require the publisher to output optional content.
- **Configuration failure semantics**: `test_precondition`
- **Referenced specification**: `MetaAttr`
- **Reference basis (MetaAttr)**; locator: `2\.4 Assertion Profile||3 Conformance`: other legal assertion content MAY
- **source_clauses**: `[0, 92)` `sha256:7dfacaaae6f1…` , `[257, 318)` `sha256:2dfa8c656abb…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-MD05.e</code> details</summary>

- **Required variants**:
  - `v-3fb2d179fe` DigestMethod and SigningMethod at the EntityDescriptor and role levels
  - `v-1aaaf97ca5` SigningMethod MinKeySize and MaxKeySize, and optional algorithm-specific extensions
  - `v-7e9a8ae918` Multiple EncryptionMethods in a KeyDescriptor, including block/stream encryption, key transport/agreement, KeySize, and optional algorithm-specific content
  - `v-819554415f` Metadata in which each algorithm type is absent; absence must not be interpreted as lack of support.
- **Controls (negative controls)**:
  - Do not mark the result PASS merely because the extension can be read as XML. Compare the algorithm actually selected by the target with the metadata's preference order and intersection.
  - The absence of elements for an algorithm type does not mean that the type is unsupported; it means that no information is provided. When the type is absent, the consumer itself may choose any algorithm it supports.
- **Configuration failure semantics**: `test_precondition`
- **Referenced specification**: `SAML2MetaAlgSup`
- **Reference basis (SAML2MetaAlgSup)**; locator: `2 SAML V2\.0 Metadata Profile for Algorithm Support||3 Conformance`: Representation of encryption and signing algorithm capabilities and consumer selection rules
- **source_clauses**: `[0, 92)` `sha256:7dfacaaae6f1…` , `[319, 387)` `sha256:c5226e0be20d…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-MD05.e1</code> details</summary>

- **Required variants**:
  - `v-a3e7c8b021` Block/Stream EncryptionMethod
  - `v-f1aa3a6f82` Key Transport/Key Agreement EncryptionMethod
- **Controls (negative controls)**:
  - The source text requires at least one item from each category; it does not require enumerating every individual algorithm.
- **Configuration failure semantics**: `test_precondition`
- **Referenced specification**: `SAML2MetaAlgSup`
- **Reference basis (SAML2MetaAlgSup)**; locator: `2\.3 Expression of Encryption Capabilities||2\.4 Expression of Signature Capabilities`: The SHOULD for asymmetric encryption capabilities
- **source_clauses**: `[0, 92)` `sha256:7dfacaaae6f1…` , `[319, 387)` `sha256:c5226e0be20d…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-MD05.e2</code> details</summary>

- **Required variants**:
  - `v-7125c6f168` RSA key + RSA-OAEP
  - `v-5682b897a8` EC key + compatible key agreement
  - `v-6ed626680d` Negative control with an RSA key and an EC-only algorithm
- **Controls (negative controls)**:
  - Check not only for the presence of an algorithm URI, but also against the key type, size, and parameters.
- **Configuration failure semantics**: `test_precondition`
- **Referenced specification**: `SAML2MetaAlgSup`
- **Reference basis (SAML2MetaAlgSup)**; locator: `2\.3 Expression of Encryption Capabilities||2\.4 Expression of Signature Capabilities`: key compatibility MUST
- **source_clauses**: `[0, 92)` `sha256:7dfacaaae6f1…` , `[319, 387)` `sha256:c5226e0be20d…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-MD05.e3</code> details</summary>

- **Required variants**:
  - `v-b2121e6e3a` A KeyDescriptor representing a shared secret or password, with a Block or Stream EncryptionMethod
- **Controls (negative controls)**:
  - If the observed metadata contains no symmetric-key KeyDescriptor, the antecedent is false and the outcome is satisfied. Do not impose this obligation on asymmetric keys.
- **Configuration failure semantics**: `test_precondition`
- **Referenced specification**: `SAML2MetaAlgSup`
- **Reference basis (SAML2MetaAlgSup)**; locator: `2\.3 Expression of Encryption Capabilities||2\.4 Expression of Signature Capabilities`: The SHOULD for the symmetric-key case
- **source_clauses**: `[0, 92)` `sha256:7dfacaaae6f1…` , `[319, 387)` `sha256:c5226e0be20d…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-MD05.e4</code> details</summary>

- **Required variants**:
  - `v-0d1cc7296c` block/stream
  - `v-f2326bb9ef` key transport
  - `v-5a9c7da46e` Each EncryptionMethod for key agreement
- **Controls (negative controls)**:
  - Check both schema validation and semantic use.
- **Configuration failure semantics**: `test_precondition`
- **Referenced specification**: `SAML2MetaAlgSup`
- **Reference basis (SAML2MetaAlgSup)**; locator: `2\.3 Expression of Encryption Capabilities||2\.4 Expression of Signature Capabilities`: EncryptionMethod/@Algorithm MUST
- **source_clauses**: `[0, 92)` `sha256:7dfacaaae6f1…` , `[319, 387)` `sha256:c5226e0be20d…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-MD05.e5</code> details</summary>

- **Required variants**:
  - `v-69ec0f5a73` Swap the order of two algorithms of the same type and verify that the target's selection follows the first-listed algorithm.
- **Controls (negative controls)**:
  - If the same general type has only zero or one algorithm, the antecedent is false and the outcome is satisfied. Do not determine strength ordering independently in Samlier; treat the publisher's enumeration order as a preference.
- **Configuration failure semantics**: `test_precondition`
- **Referenced specification**: `SAML2MetaAlgSup`
- **Reference basis (SAML2MetaAlgSup)**; locator: `2\.3 Expression of Encryption Capabilities||2\.4 Expression of Signature Capabilities`: encryption algorithm preference order MUST
- **source_clauses**: `[0, 92)` `sha256:7dfacaaae6f1…` , `[319, 387)` `sha256:c5226e0be20d…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-MD05.e6</code> details</summary>

- **Required variants**:
  - `v-56ad1fe7dc` Publish both DigestMethod and SigningMethod at at least one of the EntityDescriptor level or role level, or at both levels.
- **Controls (negative controls)**:
  - Do not split the source text's and/or into required variants at each level. Converting it into conjunctions in G2 would mark an implementation that correctly publishes only at the EntityDescriptor level as WARNING.
  - This SHOULD applies to the publisher. The parent IIP-MD05.e separately verifies that a consumer must not interpret a missing element as unsupported.
- **Configuration failure semantics**: `test_precondition`
- **Referenced specification**: `SAML2MetaAlgSup`
- **Reference basis (SAML2MetaAlgSup)**; locator: `2\.4 Expression of Signature Capabilities||2\.5 Metadata Consumers`: signature capability publication SHOULD
- **source_clauses**: `[0, 92)` `sha256:7dfacaaae6f1…` , `[319, 387)` `sha256:c5226e0be20d…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-MD05.e7</code> details</summary>

- **Required variants**:
  - `v-e0c572064f` The order of two DigestMethods
  - `v-14dfe85294` The order of two SigningMethods
- **Controls (negative controls)**:
  - Test both element types individually.
- **Configuration failure semantics**: `test_precondition`
- **Referenced specification**: `SAML2MetaAlgSup`
- **Reference basis (SAML2MetaAlgSup)**; locator: `2\.4 Expression of Signature Capabilities||2\.5 Metadata Consumers`: signature/digest preference order MUST
- **source_clauses**: `[0, 92)` `sha256:7dfacaaae6f1…` , `[319, 387)` `sha256:c5226e0be20d…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-MD05.e8</code> details</summary>

- **Required variants**:
  - `v-68d4430af5` signature algorithm intersection
  - `v-e17ab3d848` digest algorithm intersection
  - `v-0757d67517` encryption algorithm intersection
  - `v-dffb3c2b60` key-size / algorithm-specific parameter intersection
- **Controls (negative controls)**:
  - An operation that does not use peer knowledge is out of scope and satisfied_with_note. Detect implementations that select using only local support and ignore peer metadata.
- **Configuration failure semantics**: `test_precondition`
- **Referenced specification**: `SAML2MetaAlgSup`
- **Reference basis (SAML2MetaAlgSup)**; locator: `2\.5 Metadata Consumers||2\.6 Security Considerations`: supported intersection consultation MUST
- **source_clauses**: `[0, 92)` `sha256:7dfacaaae6f1…` , `[319, 387)` `sha256:c5226e0be20d…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-MD05.e9</code> details</summary>

- **Required variants**:
  - `v-c2f60ce650` The first algorithm is unsupported and the second is supported.
  - `v-bdfbe36ea3` Both the first and second algorithms are supported.
- **Controls (negative controls)**:
  - If none are supported, failure according to local policy is acceptable. Do not mark an implementation PASS when it unconditionally uses the first algorithm.
- **Configuration failure semantics**: `test_precondition`
- **Referenced specification**: `SAML2MetaAlgSup`
- **Reference basis (SAML2MetaAlgSup)**; locator: `2\.5 Metadata Consumers||2\.6 Security Considerations`: ordered consultation SHOULD
- **source_clauses**: `[0, 92)` `sha256:7dfacaaae6f1…` , `[319, 387)` `sha256:c5226e0be20d…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-MD05.ea</code> details</summary>

- **Required variants**:
  - `v-373ae89ad8` Swap supported orders A,B and B,A, and verify that the selection also swaps.
- **Controls (negative controls)**:
  - This is subject to local policy. If local policy prohibits the first algorithm, selecting the next permitted algorithm must not be marked violated.
- **Configuration failure semantics**: `test_precondition`
- **Referenced specification**: `SAML2MetaAlgSup`
- **Reference basis (SAML2MetaAlgSup)**; locator: `2\.5 Metadata Consumers||2\.6 Security Considerations`: first supported selection SHOULD
- **source_clauses**: `[0, 92)` `sha256:7dfacaaae6f1…` , `[319, 387)` `sha256:c5226e0be20d…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-MD05.eb</code> details</summary>

- **Required variants**:
  - `v-20a4134177` A conflict between EntityDescriptor and role DigestMethods
  - `v-bb88e6dadd` A conflict between EntityDescriptor and role SigningMethods
- **Controls (negative controls)**:
  - Ignore entity-level information of the same type only when that type exists at the role level. If only DigestMethod exists at the role level, do not discard entity-level SigningMethod information.
- **Configuration failure semantics**: `test_precondition`
- **Referenced specification**: `SAML2MetaAlgSup`
- **Reference basis (SAML2MetaAlgSup)**; locator: `2\.5 Metadata Consumers||2\.6 Security Considerations`: role-level precedence MUST
- **source_clauses**: `[0, 92)` `sha256:7dfacaaae6f1…` , `[319, 387)` `sha256:c5226e0be20d…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-MD05.ec</code> details</summary>

- **Required variants**:
  - `v-90d18294da` alg:DigestMethod/@Algorithm
  - `v-6326ec70fb` alg:SigningMethod/@Algorithm
  - `v-bde28e1a58` Negative controls for each missing attribute
- **Controls (negative controls)**:
  - md:EncryptionMethod/@Algorithm is evaluated separately under IIP-MD05.e4. Do not delegate the required attributes on the alg: side to metadata XSD validation.
- **Configuration failure semantics**: `test_precondition`
- **Referenced specification**: `SAML2MetaAlgSup`
- **Reference basis (SAML2MetaAlgSup)**; locator: `2\.4 Expression of Signature Capabilities||2\.5 Metadata Consumers`: DigestMethod / SigningMethod Algorithm [Required]
- **source_clauses**: `[0, 92)` `sha256:7dfacaaae6f1…` , `[319, 387)` `sha256:c5226e0be20d…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-MD05.ed</code> details</summary>

- **Required variants**:
  - `v-5d5d617819` Symmetric Key Wrap
  - `v-4648e00631` Key Derivation
- **Controls (negative controls)**:
  - Because both publishing and omitting the elements are permitted, do not assign the publisher a unique verdict. Verify that the consumer can handle published valid elements in the parent IIP-MD05.e acceptance fixture.
- **Configuration failure semantics**: `test_precondition`
- **Referenced specification**: `SAML2MetaAlgSup`
- **Reference basis (SAML2MetaAlgSup)**; locator: `2\.3 Expression of Encryption Capabilities||2\.4 Expression of Signature Capabilities`: Publishing Symmetric Key Wrap / Key Derivation is MAY.
- **source_clauses**: `[0, 92)` `sha256:7dfacaaae6f1…` , `[319, 387)` `sha256:c5226e0be20d…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-MD05.f</code> details</summary>

- **Required variants**:
  - `v-4ab799adba` Multilingual metadata containing all UIInfo elements: DisplayName, Description, Keywords, Logo (height / width required), InformationURL, and PrivacyStatementURL
  - `v-70733bfdff` An extension in an unknown namespace within UIInfo
  - `v-5f83e32e5b` DiscoHints containing IPv4 CIDR, IPv6 CIDR, DomainHint, geo URI, and an extension in an unknown namespace
  - `v-65581d50d7` Multiple elements of the same type with different xml:lang values
- **Controls (negative controls)**:
  - Do not mark PASS merely because the metadata as a whole was accepted while ignoring the extension. Confirm that the value is available in the target's discovery/login UI or read-back surface.
- **Configuration failure semantics**: `test_precondition`
- **Referenced specification**: `MetaUi`
- **Reference basis (MetaUi)**; locator: `2 Metadata Extensions for Login and Discovery User Interfa||3 Conformance`: UIInfo / DiscoHints structure, consumer semantics, and security considerations
- **source_clauses**: `[0, 92)` `sha256:7dfacaaae6f1…` , `[388, 465)` `sha256:62b5f48cfcc2…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-MD05.f1</code> details</summary>

- **Required variants**:
  - `v-8b5611a25b` IDPSSODescriptor/Extensions
  - `v-3ed7c655aa` SPSSODescriptor/Extensions
  - `v-49645baf2a` Invalid control for EntityDescriptor/Extensions
- **Controls (negative controls)**:
  - UIInfo output itself is optional. Inspect the placement of each observed UIInfo; if there are none, the antecedent is false and the outcome is satisfied.
- **Configuration failure semantics**: `test_precondition`
- **Referenced specification**: `MetaUi`
- **Reference basis (MetaUi)**; locator: `2\.1 User Interface Information||2\.1\.1 Element <mdui:UIInfo>`: UIInfo placement MUST
- **source_clauses**: `[0, 92)` `sha256:7dfacaaae6f1…` , `[388, 465)` `sha256:62b5f48cfcc2…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-MD05.f2</code> details</summary>

- **Required variants**:
  - `v-e5c4653bf3` Include one of each standard child.
  - `v-0fbce3fcf0` Include exactly one extension from an unknown namespace.
  - `v-7fa920d845` Invalid control for empty UIInfo
- **Controls (negative controls)**:
  - Do not permit empty content merely because the schema choice has minOccurs=0. The MUST in the body takes precedence.
- **Configuration failure semantics**: `test_precondition`
- **Referenced specification**: `MetaUi`
- **Reference basis (MetaUi)**; locator: `2\.1 User Interface Information||2\.1\.1 Element <mdui:UIInfo>`: non-empty UIInfo MUST
- **source_clauses**: `[0, 92)` `sha256:7dfacaaae6f1…` , `[388, 465)` `sha256:62b5f48cfcc2…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-MD05.f3</code> details</summary>

- **Required variants**:
  - `v-151a4fa1eb` One UIInfo element
  - `v-b8385cdf0e` Two invalid control elements in the same Extensions element
- **Controls (negative controls)**:
  - It is permissible to place one in each separate role.
- **Configuration failure semantics**: `test_precondition`
- **Referenced specification**: `MetaUi`
- **Reference basis (MetaUi)**; locator: `2\.1 User Interface Information||2\.1\.1 Element <mdui:UIInfo>`: single UIInfo MUST NOT
- **source_clauses**: `[0, 92)` `sha256:7dfacaaae6f1…` , `[388, 465)` `sha256:62b5f48cfcc2…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-MD05.f4</code> details</summary>

- **Required variants**:
  - `v-04ced06b0f` DisplayName
  - `v-76a7ab58cb` Description
  - `v-031866c9a2` Keywords
  - `v-4b17fd9580` InformationURL
  - `v-a6f74382cb` Duplicate PrivacyStatementURL values with the same language
- **Controls (negative controls)**:
  - Test each of the five element types separately. Different element types are permitted to have the same xml:lang.
- **Configuration failure semantics**: `test_precondition`
- **Referenced specification**: `MetaUi`
- **Reference basis (MetaUi)**; locator: `2\.1\.2 Element <mdui:DisplayName>||2\.2 Discovery Hinting Information`: localized child uniqueness MUST NOT
- **source_clauses**: `[0, 92)` `sha256:7dfacaaae6f1…` , `[388, 465)` `sha256:62b5f48cfcc2…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-MD05.f5</code> details</summary>

- **Required variants**:
  - `v-13b15b16b7` A complete description text
  - `v-1b12534d52` Invalid output containing a placeholder such as “This service offers $description”
- **Controls (negative controls)**:
  - Do not fully automate validity assessment of natural-language content. Detect explicit placeholders, and if the result is ambiguous, return not_verified(description_standalone_undetermined).
- **Referenced specification**: `MetaUi`
- **Reference basis (MetaUi)**; locator: `2\.1\.3 Element <mdui:Description>||2\.1\.4 Element <mdui:Keywords>`: standalone description MUST
- **source_clauses**: `[0, 92)` `sha256:7dfacaaae6f1…` , `[388, 465)` `sha256:62b5f48cfcc2…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-MD05.f6</code> details</summary>

- **Required variants**:
  - `v-4003d48f44` The content of the mdui:Description published by the target SP
- **Controls (negative controls)**:
  - A Run that does not publish Description is satisfied_with_note. Do not equate only the Organization description with the service description.
- **Referenced specification**: `MetaUi`
- **Reference basis (MetaUi)**; locator: `2\.1\.3 Element <mdui:Description>||2\.1\.4 Element <mdui:Keywords>`: SP description content SHOULD
- **source_clauses**: `[0, 92)` `sha256:7dfacaaae6f1…` , `[388, 465)` `sha256:62b5f48cfcc2…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-MD05.f7</code> details</summary>

- **Required variants**:
  - `v-92375a37b5` The content of the mdui:Description published by the target IdP
- **Controls (negative controls)**:
  - A Run that does not publish Description is satisfied_with_note. If the content cannot be determined, return not_verified.
- **Referenced specification**: `MetaUi`
- **Reference basis (MetaUi)**; locator: `2\.1\.3 Element <mdui:Description>||2\.1\.4 Element <mdui:Keywords>`: IdP description content SHOULD
- **source_clauses**: `[0, 92)` `sha256:7dfacaaae6f1…` , `[388, 465)` `sha256:62b5f48cfcc2…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-MD05.f8</code> details</summary>

- **Required variants**:
  - `v-455f97f3cd` An appropriate transparent background
  - `v-dac45d139e` PNG or GIF
  - `v-371110f8d4` HTTPS URL
- **Controls (negative controls)**:
  - Three items belonging to one SHOULD in the source text. A Run in which the target does not publish Logo is satisfied_with_note. Do not treat “appropriate” as a mechanical absolute condition.
- **Referenced specification**: `MetaUi`
- **Reference basis (MetaUi)**; locator: `2\.1\.5 Element <mdui:Logo>||2\.1\.6 Element <mdui:InformationURL>`: logo guidance SHOULD
- **source_clauses**: `[0, 92)` `sha256:7dfacaaae6f1…` , `[388, 465)` `sha256:62b5f48cfcc2…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-MD05.f9</code> details</summary>

- **Required variants**:
  - `v-76dc47927a` A preferred language is present
  - `v-d4171244cb` No preferred language and no xml:lang: fallback
- **Controls (negative controls)**:
  - A Run in which the consumer does not display a logo is satisfied_with_note. Do not conflate the general MAY allowing any logo to be selected with the fallback SHOULD.
- **Referenced specification**: `MetaUi`
- **Reference basis (MetaUi)**; locator: `2\.1\.5 Element <mdui:Logo>||2\.1\.6 Element <mdui:InformationURL>`: language-neutral logo fallback SHOULD
- **source_clauses**: `[0, 92)` `sha256:7dfacaaae6f1…` , `[388, 465)` `sha256:62b5f48cfcc2…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-MD05.fa</code> details</summary>

- **Required variants**:
  - `v-54b236d39a` Compare the retrieved content of Description and InformationURL
- **Controls (negative controls)**:
  - Return not_verified if the URL is unreachable or its content cannot be compared. Absence of the URL is satisfied_with_note.
- **Referenced specification**: `MetaUi`
- **Reference basis (MetaUi)**; locator: `2\.1\.6 Element <mdui:InformationURL>||2\.1\.7 Element <mdui:PrivacyStatementURL>`: InformationURL content SHOULD
- **source_clauses**: `[0, 92)` `sha256:7dfacaaae6f1…` , `[388, 465)` `sha256:62b5f48cfcc2…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-MD05.fb</code> details</summary>

- **Required variants**:
  - `v-5f902c08fd` Only IPHint matches
  - `v-1dfc3db08b` Only DomainHint matches
  - `v-3e84f06954` Only GeolocationHint matches
- **Controls (negative controls)**:
  - For each hint type, verify that user selection/confirmation remains possible. If the target has no discovery UI, return satisfied_with_note.
- **Referenced specification**: `MetaUi`
- **Reference basis (MetaUi)**; locator: `2\.2 Discovery Hinting Information||2\.2\.1 Element <mdui:DiscoHints>`: hint-only definitive selection SHOULD NOT
- **source_clauses**: `[0, 92)` `sha256:7dfacaaae6f1…` , `[388, 465)` `sha256:62b5f48cfcc2…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-MD05.fc</code> details</summary>

- **Required variants**:
  - `v-6869a8d502` IDPSSODescriptor/Extensions
  - `v-20c8181558` Invalid controls placing DiscoHints in SPSSODescriptor/Extensions or EntityDescriptor/Extensions
- **Controls (negative controls)**:
  - Publishing DiscoHints is optional. Inspect the placement of each observed DiscoHints element; if there are none, the antecedent is false, so the result is satisfied.
  - The roles include both the IdP publisher and the SP consumer that consumes IdP metadata. Do not require the SP itself to publish DiscoHints.
- **Configuration failure semantics**: `test_precondition`
- **Referenced specification**: `MetaUi`
- **Reference basis (MetaUi)**; locator: `2\.2 Discovery Hinting Information||2\.2\.1 Element <mdui:DiscoHints>`: DiscoHints placement MUST
- **source_clauses**: `[0, 92)` `sha256:7dfacaaae6f1…` , `[388, 465)` `sha256:62b5f48cfcc2…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-MD05.fd</code> details</summary>

- **Required variants**:
  - `v-84e647f016` IPHint / DomainHint / GeolocationHint
  - `v-00ee5fd07e` Only an extension in an unknown namespace
  - `v-c4229d5d59` An invalid control with empty DiscoHints
- **Controls (negative controls)**:
  - Do not allow an empty element merely because the schema choice has minOccurs=0.
- **Configuration failure semantics**: `test_precondition`
- **Referenced specification**: `MetaUi`
- **Reference basis (MetaUi)**; locator: `2\.2 Discovery Hinting Information||2\.2\.1 Element <mdui:DiscoHints>`: non-empty DiscoHints MUST
- **source_clauses**: `[0, 92)` `sha256:7dfacaaae6f1…` , `[388, 465)` `sha256:62b5f48cfcc2…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-MD05.fe</code> details</summary>

- **Required variants**:
  - `v-4981a98d74` One DiscoHints element
  - `v-08fc280072` Two invalid control elements in the same Extensions element
- **Controls (negative controls)**:
  - It is permissible to place one in each separate IdP role.
- **Configuration failure semantics**: `test_precondition`
- **Referenced specification**: `MetaUi`
- **Reference basis (MetaUi)**; locator: `2\.2 Discovery Hinting Information||2\.2\.1 Element <mdui:DiscoHints>`: single DiscoHints MUST NOT
- **source_clauses**: `[0, 92)` `sha256:7dfacaaae6f1…` , `[388, 465)` `sha256:62b5f48cfcc2…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-MD05.ff</code> details</summary>

- **Required variants**:
  - `v-b585406ac3` 192.0.2.0/24
  - `v-03de6977e2` 2001:db8::/32
- **Controls (negative controls)**:
  - Test both address families separately. Do not mark PASS based on IPv4 alone.
- **Configuration failure semantics**: `test_precondition`
- **Referenced specification**: `MetaUi`
- **Reference basis (MetaUi)**; locator: `2\.2\.2 Element <mdui:IPHint>||2\.2\.3 Element <mdui:DomainHint>`: IPv4 / IPv6 CIDR support MUST
- **source_clauses**: `[0, 92)` `sha256:7dfacaaae6f1…` , `[388, 465)` `sha256:62b5f48cfcc2…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-MD05.fg</code> details</summary>

- **Required variants**:
  - `v-9708523a75` A script-capable payload in a Logo data/http URL
  - `v-e08c481f42` A quote, angle bracket, or javascript-like payload in InformationURL / PrivacyStatementURL
- **Controls (negative controls)**:
  - Use a runtime scope only when the URL is used in the UI, rather than for a parser that merely stores the URL. A Run that does not execute it is satisfied_with_note.
- **Referenced specification**: `MetaUi`
- **Reference basis (MetaUi)**; locator: `2\.3 Security Considerations||2\.4 Relationship with Existing Metadata Elements`: UI URL sanitization MUST
- **source_clauses**: `[0, 92)` `sha256:7dfacaaae6f1…` , `[388, 465)` `sha256:62b5f48cfcc2…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-MD05.fh</code> details</summary>

- **Required variants**:
  - `v-f2ecd531e3` https
  - `v-c23b13d16d` http
  - `v-31528ff2d4` data
  - `v-0598a22330` Negative control for javascript / file
- **Controls (negative controls)**:
  - The data scheme is explicitly permitted by the source text, so uniform rejection is not required. A Run in which the consumer does not use the URL is satisfied_with_note.
- **Referenced specification**: `MetaUi`
- **Reference basis (MetaUi)**; locator: `2\.3 Security Considerations||2\.4 Relationship with Existing Metadata Elements`: URL scheme allowlist SHOULD NOT
- **source_clauses**: `[0, 92)` `sha256:7dfacaaae6f1…` , `[388, 465)` `sha256:62b5f48cfcc2…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-MD05.fi</code> details</summary>

- **Required variants**:
  - `v-6a69dc0d85` Logo / InformationURL / PrivacyStatementURL generated by the target
- **Controls (negative controls)**:
  - http/data are permitted schemes under IIP-MD05.fh but may be subject to WARNING under this obligation. Do not conflate prohibition with recommendation.
- **Referenced specification**: `MetaUi`
- **Reference basis (MetaUi)**; locator: `2\.3 Security Considerations||2\.4 Relationship with Existing Metadata Elements`: HTTPS URL RECOMMENDED
- **source_clauses**: `[0, 92)` `sha256:7dfacaaae6f1…` , `[388, 465)` `sha256:62b5f48cfcc2…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-MD05.fj</code> details</summary>

- **Required variants**:
  - `v-c325b09ab7` All three candidates are present
  - `v-7fabee9fcd` DisplayName is missing
  - `v-6021df474d` DisplayName / ServiceName are missing
- **Controls (negative controls)**:
  - An implementation that does not depend on display name is satisfied_with_note. Do not make optional migration support for OrganizationDisplayName mandatory.
- **Referenced specification**: `MetaUi`
- **Reference basis (MetaUi)**; locator: `2\.4\.3 Suggested Precedence||2\.5 Example`: display-name precedence SHOULD
- **source_clauses**: `[0, 92)` `sha256:7dfacaaae6f1…` , `[388, 465)` `sha256:62b5f48cfcc2…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-MD05.fk</code> details</summary>

- **Required variants**:
  - `v-aaf52a43f2` Both height and width are present
  - `v-b0c5b6435e` height missing
  - `v-b949f3a0fb` width missing
  - `v-39eaf35f27` Both missing
- **Controls (negative controls)**:
  - Both attributes are mandatory even for vector images. Do not add the condition, absent from the source text, that the image's actual dimensions must match the attribute values.
- **Configuration failure semantics**: `test_precondition`
- **Referenced specification**: `MetaUi`
- **Reference basis (MetaUi)**; locator: `2\.1\.5 Element <mdui:Logo>||2\.1\.6 Element <mdui:InformationURL>`: Logo height / width [Required]
- **source_clauses**: `[0, 92)` `sha256:7dfacaaae6f1…` , `[388, 465)` `sha256:62b5f48cfcc2…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-MD05.g</code> details</summary>

- **Required variants**:
  - `v-05792c9fbf` A well-formed extension element in an unknown namespace
  - `v-ce29c3d6fe` mdrpi:RegistrationInfo (a real extension not included in the six mandatory specifications)
- **Controls (negative controls)**:
  - Using only mdrpi would incorrectly pass an implementation with special handling for mdrpi. Always use an unknown namespace that the implementation cannot know in advance as well.
- **Configuration failure semantics**: `test_precondition`
- **source_clauses**: `[0, 92)` `sha256:7dfacaaae6f1…` , `[657, 761)` `sha256:6fcd73094189…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

#### IIP-MD06

[Source](https://kantarainitiative.github.io/SAMLprofiles/fedinterop.html#IIP-MD06) / Section digest `sha256:745b1d02df86…` / Section length 1445 / Non-normative spans 2

| Obligation | Level | Role | Testability | Condition | Core/Full | Summary |
|---|---|---|---|---|---|---|
| `IIP-MD06.a` | MUST | idp/sp | `CONFIG` | — | core | Support interpretation and application of metadata as defined by the Metadata Interoperability Profile |
| `IIP-MD06.a1` | MUST | idp/sp | `CONFIG` | — | core | A consumer must process both EntityDescriptor and EntitiesDescriptor roots and every nested entity |
| `IIP-MD06.a2` | MUST | idp/sp | `CONFIG` | — | core | Each KeyDescriptor key must be treated as valid in the context of its containing role |
| `IIP-MD06.a3` | MUST | idp/sp | `CONFIG` | — | core | Signatures and transport sessions verifiable with a role signing key must be treated as valid |
| `IIP-MD06.a4` | MAY | idp/sp | `CONFIG` | — | full | Encryption keys found in metadata may be used for the containing entity |
| `IIP-MD06.a5` | MUST_NOT | idp/sp | `CONFIG` | — | core | After accepting metadata, a consumer must not add key-acceptance or runtime-validity criteria |
| `IIP-MD06.a6` | MUST_NOT | idp/sp | `CONFIG` | — | core | A consumer must not perform PKIX path validation, revocation-list, OCSP, or similar checks on accepted metadata keys |
| `IIP-MD06.a7` | MUST | idp/sp | `CONFIG` | — | core | A consumer must support KeyValue and X509Certificate KeyInfo representations |
| `IIP-MD06.a8` | MUST | idp/sp | `CONFIG` | — | core | A consumer must extract the public key from an X509Certificate representation |
| `IIP-MD06.a9` | MUST_NOT | idp/sp | `CONFIG` | — | core | A consumer must not honor certificate information other than the public key except to identify the key |
| `IIP-MD06.aa` | MAY | idp/sp | `CONFIG` | — | full | A consumer authenticating a TLS server may retain server-name checking |
| `IIP-MD06.ab` | MUST | idp/sp | `CONFIG` | — | core | Accepted metadata must be treated as true for operational behavior until superseded |
| `IIP-MD06.b` | MUST | idp/sp | `CONFIG` | — | core | Be capable of interoperating with any number of SAML peers for which metadata is available, without additional inputs or separate configuration |
| `IIP-MD06.c` | MUST | idp/sp | `ATTESTED` | — | core | Metadata must be usable as a self-contained vehicle for communicating trust, with all rules for processing signatures and encrypted XML derivable from the metadata alone |

<details><summary><code>IIP-MD06.a</code> details</summary>

- **Required variants**:
  - `v-63eba4f51a` Provision endpoints, bindings, keys, and profile support using only the accepted metadata
- **Controls (negative controls)**:
  - The existence of a local policy that metadata cannot represent is not a violation. Detect paths that impose additional trust requirements on information represented by the metadata.
  - The obligation to interoperate within the scope of the default policy without additional peer-specific configuration is assessed exactly once, under the explicit text of IIP-MD06.b.
  - This group of obligations concerns only interpretation and application after acceptance. Structural acceptance of MDIOP-shaped XML is assessed under the IIP-MD05.c group.
- **Configuration failure semantics**: `test_precondition`
- **Referenced specification**: `SAML2MDIOP`
- **Reference basis (SAML2MDIOP)**; locator: `2\.6 Metadata Consumer Requirements||2\.7 Security Considerations`: Consumer interpretation and runtime key processing of accepted MDIOP metadata
- **Notes**: The IIP illustrative paragraph about the trust store (“As an example ...”) is italicized and non-normative, so it must not become an independent obligation. However, the uppercase MUST / MUST NOT statements in MDIOP §2.6 itself are normative through incorporation by reference into IIP-MD06.a.
- **source_clauses**: `[0, 151)` `sha256:85cd4426cdc6…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-MD06.a1</code> details</summary>

- **Required variants**:
  - `v-5bee9ee17d` EntityDescriptor root
  - `v-eec93d57ae` EntitiesDescriptor root
  - `v-5887743378` Each EntityDescriptor within nested EntitiesDescriptor elements at two or more levels
- **Controls (negative controls)**:
  - The fixture can be shared with IIP-MD02.c/.d, but this obligation verifies through endpoint and key use that the MDIOP interpretation was applied to each nested entity.
- **Configuration failure semantics**: `test_precondition`
- **Referenced specification**: `SAML2MDIOP`
- **Reference basis (SAML2MDIOP)**; locator: `2\.6 Metadata Consumer Requirements||2\.6\.1 Key Processing`: root forms / nested entity processing MUST
- **source_clauses**: `[0, 151)` `sha256:85cd4426cdc6…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-MD06.a2</code> details</summary>

- **Required variants**:
  - `v-41f844d0d3` Different keys for role A and role B of the same entity
  - `v-52f6a08b4b` use=signing / encryption / omitted
- **Controls (negative controls)**:
  - Do not transfer role A's key across to role B, and use it for role A without additional PKIX conditions. Do not broaden the meaning of valid to trust shared across all roles.
- **Configuration failure semantics**: `test_precondition`
- **Referenced specification**: `SAML2MDIOP`
- **Reference basis (SAML2MDIOP)**; locator: `2\.6\.1 Key Processing||2\.7 Security Considerations`: role-scoped key validity MUST
- **source_clauses**: `[0, 151)` `sha256:85cd4426cdc6…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-MD06.a3</code> details</summary>

- **Required variants**:
  - `v-a0716aee94` XML signature
  - `v-db467340b5` TLS server authentication
  - `v-f7ea57ffbd` Mutual TLS peer authentication (when used)
- **Controls (negative controls)**:
  - For a target that does not use TLS, the TLS variant is satisfied_with_note. Do not treat the XML signature and TLS as alternatives; inspect each path actually used.
- **Configuration failure semantics**: `test_precondition`
- **Referenced specification**: `SAML2MDIOP`
- **Reference basis (SAML2MDIOP)**; locator: `2\.6\.1 Key Processing||2\.7 Security Considerations`: signature / TLS validity with signing key MUST
- **source_clauses**: `[0, 151)` `sha256:85cd4426cdc6…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-MD06.a4</code> details</summary>

- **Required variants**:
  - `v-57817c9261` Use a metadata key to encrypt an Assertion, NameID, Attribute, or data-encryption key
- **Controls (negative controls)**:
  - A local policy that is not used is also conformant. The capability to accept it is assessed separately under stronger obligations such as IIP-MD07 and MD08.
- **Configuration failure semantics**: `test_precondition`
- **Referenced specification**: `SAML2MDIOP`
- **Reference basis (SAML2MDIOP)**; locator: `2\.6\.1 Key Processing||2\.7 Security Considerations`: encryption key use MAY
- **source_clauses**: `[0, 151)` `sha256:85cd4426cdc6…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-MD06.a5</code> details</summary>

- **Required variants**:
  - `v-acb038785a` The metadata key and runtime key have the same value, but differ in certificate serial, issuer, validity, or usage
  - `v-ed7ede461f` KeyValue representation
- **Controls (negative controls)**:
  - Trust establishment before metadata acceptance is out of scope. Limit the assessment to runtime key comparison after acceptance.
- **Configuration failure semantics**: `test_precondition`
- **Referenced specification**: `SAML2MDIOP`
- **Reference basis (SAML2MDIOP)**; locator: `2\.6\.1 Key Processing||2\.7 Security Considerations`: additional key criteria MUST NOT
- **source_clauses**: `[0, 151)` `sha256:85cd4426cdc6…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-MD06.a6</code> details</summary>

- **Required variants**:
  - `v-d7d93da45e` Unknown CA
  - `v-74f465d49d` Revoked certificate
  - `v-911bafa5b2` CRL/OCSP unreachable
  - `v-47ba8f587f` critical extension
- **Controls (negative controls)**:
  - Reuse the same certificate fixture as IIP-MD12.d. Here, assess the addition of runtime key-acceptance checks, and do not exaggerate the same failure as two independent causes.
- **Configuration failure semantics**: `test_precondition`
- **Referenced specification**: `SAML2MDIOP`
- **Reference basis (SAML2MDIOP)**; locator: `2\.6\.1 Key Processing||2\.7 Security Considerations`: online/offline validation SHALL NOT
- **source_clauses**: `[0, 151)` `sha256:85cd4426cdc6…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-MD06.a7</code> details</summary>

- **Required variants**:
  - `v-50a3c25b37` ds:KeyValue
  - `v-6544cef276` ds:X509Data/ds:X509Certificate
- **Controls (negative controls)**:
  - Test both forms individually. Do not mark PASS based on only one of them.
- **Configuration failure semantics**: `test_precondition`
- **Referenced specification**: `SAML2MDIOP`
- **Reference basis (SAML2MDIOP)**; locator: `2\.6\.1 Key Processing||2\.7 Security Considerations`: both key representations MUST
- **source_clauses**: `[0, 151)` `sha256:85cd4426cdc6…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-MD06.a8</code> details</summary>

- **Required variants**:
  - `v-bf22d3d547` The metadata certificate and runtime certificate differ, but their public keys are the same
  - `v-dc53ce5053` Negative control: the subject and issuer are the same, but the public keys differ
- **Controls (negative controls)**:
  - Demonstrate comparison of key values equivalent to SubjectPublicKeyInfo, rather than certificate object equality
- **Configuration failure semantics**: `test_precondition`
- **Referenced specification**: `SAML2MDIOP`
- **Reference basis (SAML2MDIOP)**; locator: `2\.6\.1 Key Processing||2\.7 Security Considerations`: public-key extraction MUST
- **source_clauses**: `[0, 151)` `sha256:85cd4426cdc6…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-MD06.a9</code> details</summary>

- **Required variants**:
  - `v-2924eed781` Expired / not-yet-valid
  - `v-2f6a15c28d` Arbitrary subject / issuer
  - `v-a1ec7f69cb` critical / non-critical extension
  - `v-fa7e5a922c` KeyUsage / ExtendedKeyUsage
- **Controls (negative controls)**:
  - The observation can be shared with IIP-MD12.d, but this concerns MDIOP runtime interpretation. Using certificate information as a hint for matching key candidates is itself permitted.
- **Configuration failure semantics**: `test_precondition`
- **Referenced specification**: `SAML2MDIOP`
- **Reference basis (SAML2MDIOP)**; locator: `2\.6\.1 Key Processing||2\.7 Security Considerations`: non-key certificate information MUST NOT
- **source_clauses**: `[0, 151)` `sha256:85cd4426cdc6…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-MD06.aa</code> details</summary>

- **Required variants**:
  - `v-3071d10fbe` Same public key + matching hostname
  - `v-8bf6b30c43` Same public key + mismatching hostname
- **Controls (negative controls)**:
  - Because both rejecting and not rejecting a hostname mismatch are permitted, do not assign a unique verdict. Do not extend this to subject-name validation of the metadata certificate itself.
- **Configuration failure semantics**: `test_precondition`
- **Referenced specification**: `SAML2MDIOP`
- **Reference basis (SAML2MDIOP)**; locator: `2\.6\.1 Key Processing||2\.7 Security Considerations`: TLS server-name checking MAY
- **source_clauses**: `[0, 151)` `sha256:85cd4426cdc6…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-MD06.ab</code> details</summary>

- **Required variants**:
  - `v-7e4460130e` Reflect accepted endpoints, bindings, keys, and profile support in actual processing
  - `v-0944b2d101` Change the values for the same entity in new metadata and replace the old information
- **Controls (negative controls)**:
  - Before metadata trust validation is complete, this is out of scope. Assess it only after explicit acceptance.
  - Detect implementations that merge old and new metadata and continue retaining conflicting old endpoints or keys. However, retain both keys when old and new keys are published simultaneously as part of rollover.
- **Configuration failure semantics**: `test_precondition`
- **Referenced specification**: `SAML2MDIOP`
- **Reference basis (SAML2MDIOP)**; locator: `2\.3 Metadata Exchange and Acceptance||2\.4 Implementation Constraints`: MDIOP acceptance semantics
- **source_clauses**: `[0, 151)` `sha256:85cd4426cdc6…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-MD06.b</code> details</summary>

- **Required variants**:
  - `v-6fb51a4ca3` Add a second entityID to secondary_peer and determine whether it works without additional configuration
- **Controls (negative controls)**:
  - The key point is “no additional input.” Have the user report the fact that manual input was required.
- **Configuration failure semantics**: `normative_capability`
- **source_clauses**: `[168, 401)` `sha256:0a652b7b66ca…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-MD06.c</code> details</summary>

- **Required variants**:
  - `v-c05514a5bf` Report whether trust configuration beyond metadata registration, such as importing a CA certificate, was required
- **Notes**: The quotation is normative because it comes from SAML2MDIOP. However, because it is difficult to observe directly from outside, mark it ATTESTED.
- **source_clauses**: `[403, 501)` `sha256:b2afc74e43b9…` , `[503, 789)` `sha256:910c64c040d0…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

#### IIP-MD07

[Source](https://kantarainitiative.github.io/SAMLprofiles/fedinterop.html#IIP-MD07) / Section digest `sha256:f94701b531c8…` / Section length 370 / Non-normative spans 0

| Obligation | Level | Role | Testability | Condition | Core/Full | Summary |
|---|---|---|---|---|---|---|
| `IIP-MD07.a` | MUST | idp/sp | `CONFIG` | — | core | Consume and make use of any number of signing keys bound to a single role descriptor |
| `IIP-MD07.b` | MUST | idp/sp | `CONFIG` | — | core | Attempt each signing key until the signature verifies or keys are exhausted, in which case verification fails |

<details><summary><code>IIP-MD07.a</code> details</summary>

- **Required variants**:
  - `v-d8c83b5202` 1 key
  - `v-8c75ba0433` 2 keys
  - `v-bfbd2f0ed1` 3 keys
- **Configuration failure semantics**: `normative_capability`
- **source_clauses**: `[0, 138)` `sha256:a42a2153ec96…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-MD07.b</code> details</summary>

- **Required variants**:
  - `v-ef2c6a3da0` Publish keys A and B, then sign with B (the second key) → accepted
  - `v-365f948ae7` Sign with a key not present in the metadata → rejected (control)
- **Controls (negative controls)**:
  - A control for the “failure when exhausted” case is mandatory. Detect implementations that accept a signature made with an unregistered key.
- **Configuration failure semantics**: `test_precondition`
- **source_clauses**: `[174, 369)` `sha256:148333ca84dc…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

#### IIP-MD08

[Source](https://kantarainitiative.github.io/SAMLprofiles/fedinterop.html#IIP-MD08) / Section digest `sha256:7c567a659ae4…` / Section length 255 / Non-normative spans 0

| Obligation | Level | Role | Testability | Condition | Core/Full | Summary |
|---|---|---|---|---|---|---|
| `IIP-MD08.a` | MUST | idp/sp | `CONFIG` | `supports_outbound_encryption`<br>(CAPABILITY_BASED) | core | If supporting outbound encryption, consume any number of encryption keys bound to a single role descriptor |

<details><summary><code>IIP-MD08.a</code> details</summary>

- **Required variants**:
  - `v-4c677c4907` 1 encryption key
  - `v-fa5cd1f9c6` 2 encryption keys
  - `v-0b1224822c` 3 Suite metadata variants
- **Controls (negative controls)**:
  - When multiple encryption keys are published, the target may use any one of them for outbound encryption. Do not require a particular key or key order.
- **Configuration failure semantics**: `normative_capability`
- **Notes**: This obligation concerns whether the peer’s multiple encryption keys can be consumed. It is distinct from rollover of the implementation’s own decryption keys (SP08 / IDP19).
- **source_clauses**: `[0, 154)` `sha256:8b1c5bad9782…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

#### IIP-MD09

[Source](https://kantarainitiative.github.io/SAMLprofiles/fedinterop.html#IIP-MD09) / Section digest `sha256:4ca3e2d9fd30…` / Section length 348 / Non-normative spans 0

| Obligation | Level | Role | Testability | Condition | Core/Full | Summary |
|---|---|---|---|---|---|---|
| `IIP-MD09.a` | MUST | idp/sp | `ATTESTED` | — | core | Be capable of publishing the cryptographic capabilities of the runtime configuration for XML Signature and Encryption |
| `IIP-MD09.b` | RECOMMENDED | idp/sp | `ATTESTED` | — | full | Recommended: support dynamic generation and export in a machine-readable format per SAML2MetaAlgSup |

<details><summary><code>IIP-MD09.a</code> details</summary>

- **Required variants**:
  - `v-4872f89e6a` Static check for whether the peer metadata contains alg:* declarations
  - `v-408331db18` If not, declare whether the capability to publish them exists.
- **Controls (negative controls)**:
  - The mere absence of declarations in metadata is not a violation. The obligation is whether the capability to publish them exists.
- **source_clauses**: `[0, 153)` `sha256:a62935618447…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-MD09.b</code> details</summary>

- **Required variants**:
  - `v-6949005bf0` Declare whether alg:* is generated dynamically from the actual configuration.
- **source_clauses**: `[154, 348)` `sha256:3827b367d3a9…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

#### IIP-MD10

[Source](https://kantarainitiative.github.io/SAMLprofiles/fedinterop.html#IIP-MD10) / Section digest `sha256:6f504687203e…` / Section length 849 / Non-normative spans 1

| Obligation | Level | Role | Testability | Condition | Core/Full | Summary |
|---|---|---|---|---|---|---|
| `IIP-MD10.a` | MUST | idp | `CONFIG` | `peer_declares_algorithm_support`<br>(CAPABILITY_BASED) | core | (IdP) Limit XML Signature and Encryption algorithms to those declared in the peer's metadata |
| `IIP-MD10.b` | SHOULD | sp | `CONFIG` | `peer_declares_algorithm_support`<br>(CAPABILITY_BASED) | full | (SP) Should limit XML Signature and Encryption algorithms to those declared in the peer's metadata |

<details><summary><code>IIP-MD10.a</code> details</summary>

- **Required variants**:
  - `v-54a42392d5` The Suite declares only SHA-256 → does it refrain from responding with a SHA-1 signature?
  - `v-92e8b598bc` Only GCM is declared → does it refrain from encrypting with CBC?
- **Configuration failure semantics**: `test_precondition`
- **source_clauses**: `[94, 279)` `sha256:2d1ad89d04d5…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-MD10.b</code> details</summary>

- **Required variants**:
  - `v-6856bed612` Same as above
- **Configuration failure semantics**: `test_precondition`
- **source_clauses**: `[94, 279)` `sha256:2d1ad89d04d5…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

#### IIP-MD11

[Source](https://kantarainitiative.github.io/SAMLprofiles/fedinterop.html#IIP-MD11) / Section digest `sha256:944302bff8e7…` / Section length 301 / Non-normative spans 0

| Obligation | Level | Role | Testability | Condition | Core/Full | Summary |
|---|---|---|---|---|---|---|
| `IIP-MD11.a` | MUST | idp/sp | `CONFIG` | — | core | A md:KeyDescriptor with no use attribute must be valid for XML signing, TLS/SSL, and encryption-key wrapping |

<details><summary><code>IIP-MD11.a</code> details</summary>

- **Required variants**:
  - `v-7713cb5e0e` XML signature verification succeeds with metadata containing only a key with no use attribute
  - `v-80bb197ce5` TLS server / peer authentication using the same public key as the key with no use attribute succeeds over the TLS path for that role.
  - `v-c660c15210` The key with no use attribute can be used for encryption key wrapping
- **Controls (negative controls)**:
  - For E62, signing use includes TLS/SSL as well as XML signatures. Check all three uses separately; do not assign PASS based on only one of them.
  - If a safely executable TLS path cannot be configured for the peer role, the outcome is not_verified(tls_key_usage_path_unavailable), not violated. Do not substitute a key explicitly marked use=signing.
- **Configuration failure semantics**: `test_precondition`
- **Referenced specification**: `SAML2Errata#E62`
- **Reference basis (SAML2Errata)**; locator: `E62: TLS Keys in KeyDescriptor||E63: IdP Discovery Cookie Interpretation`: When use is omitted, the key applies to all signing uses: XML signatures, TLS/SSL, and encryption key wrapping.
- **source_clauses**: `[0, 128)` `sha256:561322c88cc5…` , `[193, 301)` `sha256:f525aec15d8f…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

#### IIP-MD12

[Source](https://kantarainitiative.github.io/SAMLprofiles/fedinterop.html#IIP-MD12) / Section digest `sha256:3781bdd68fae…` / Section length 727 / Non-normative spans 0

| Obligation | Level | Role | Testability | Condition | Core/Full | Summary |
|---|---|---|---|---|---|---|
| `IIP-MD12.a` | REQUIRED | idp/sp | `CONFIG` | — | core | Support any number of long-lived, self-signed end entity certificates |
| `IIP-MD12.b` | REQUIRED | idp/sp | `CONFIG` | — | core | Support expired certificates |
| `IIP-MD12.c` | REQUIRED | idp/sp | `CONFIG` | — | core | Support certificates signed with any digest algorithm |
| `IIP-MD12.d` | MUST_NOT | idp/sp | `CONFIG` | — | core | A certificate may be expired, not yet valid, carry critical or non-critical extensions or usage flags, and contain any subject or issuer — none of these may prevent use of the contained key |

<details><summary><code>IIP-MD12.a</code> details</summary>

- **Required variants**:
  - `v-0f4ee545b4` 1 self-signed certificate
  - `v-99b4a8488f` 3 self-signed certificates
  - `v-a1e480dcec` 20-year validity period
- **Configuration failure semantics**: `normative_capability`
- **source_clauses**: `[0, 85)` `sha256:efe1ac438853…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-MD12.b</code> details</summary>

- **Required variants**:
  - `v-f21abb1c89` Expired certificate
  - `v-3bc7889026` Not-yet-valid certificate
- **Configuration failure semantics**: `normative_capability`
- **Notes**: The cited MDIOP states that not-yet-valid status, critical and non-critical extensions, and usage flags also do not prevent use of the key.
- **source_clauses**: `[0, 85)` `sha256:efe1ac438853…` , `[86, 124)` `sha256:be414b37d785…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-MD12.c</code> details</summary>

- **Required variants**:
  - `v-8a46b69554` Certificate signed with SHA-1
  - `v-524e4a98e5` Certificate signed with SHA-512
- **Configuration failure semantics**: `normative_capability`
- **source_clauses**: `[0, 85)` `sha256:efe1ac438853…` , `[126, 175)` `sha256:731dafad9c7e…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-MD12.d</code> details</summary>

- **Required variants**:
  - `v-91f3bb3acc` Not-yet-valid certificate (notBefore is in the future)
  - `v-d591aa78b1` Certificate with a critical extension
  - `v-d9f93d6d92` Certificate with a non-critical extension
  - `v-a1a2c42717` Certificate whose KeyUsage does not include digitalSignature (the usage flag conflicts with the use)
  - `v-4af24459ba` Certificate whose extendedKeyUsage is unrelated to SAML
  - `v-0ff8af956e` Certificate with an empty subject
  - `v-9899332f07` Certificate issued by an unknown CA
  - `v-80652c7142` Valid certificate (control; detects implementations that reject all certificates)
- **Controls (negative controls)**:
  - ★ Make each variation a separate variant. Passing one does not detect implementations that reject the others.
- **Configuration failure semantics**: `normative_capability`
- **Referenced specification**: `SAML2MDIOP`
- **Reference derivation**: The quoted text is directly included in the IIP source text (non-italicized, therefore normative), so its meaning is definite without reading the referenced section.
- **Notes**: The previous version mixed not-yet-valid certificates into the MD12.b note and left the remainder only as notes. Because the quoted portions are non-italicized, they are normative under the G1 rules; make every item that could be used as a reason for rejection a separate variant.
- **source_clauses**: `[177, 245)` `sha256:dc1cb942899a…` , `[246, 416)` `sha256:c60e9935f8d0…` , `[431, 569)` `sha256:85ad17063115…` , `[571, 727)` `sha256:66a9a16a166f…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

### 2.3 Common / Web Browser SSO

#### IIP-SSO01

[Source](https://kantarainitiative.github.io/SAMLprofiles/fedinterop.html#IIP-SSO01) / Section digest `sha256:ff1057626aaa…` / Section length 125 / Non-normative spans 0

| Obligation | Level | Role | Testability | Condition | Core/Full | Summary |
|---|---|---|---|---|---|---|
| `IIP-SSO01.a` | MUST | idp/sp | `BROWSER` | — | core | Support the SAML V2.0 Web Browser SSO Profile end to end |
| `IIP-SSO01.b` | MUST | sp | `BROWSER` | — | core | The AuthnRequest Issuer must be present and contain the unique identifier of the requesting service provider |
| `IIP-SSO01.c` | MUST_NOT | sp | `BROWSER` | — | core | A Subject element included in an AuthnRequest must not contain any SubjectConfirmation elements |
| `IIP-SSO01.d` | MUST | idp | `BROWSER` | — | core | If the identity provider does not recognize the principal named in the request Subject, it must respond with an error status and no assertions |
| `IIP-SSO01.e` | MUST_NOT | idp | `ATTESTED` | — | core | Information in an AuthnRequest that is not authenticated and integrity protected must not be trusted except as advisory |
| `IIP-SSO01.f` | MUST_NOT | idp | `BROWSER` | — | core | If the identity provider wishes to return an error, it must not include any assertions in the Response |
| `IIP-SSO01.g` | MUST | idp | `BROWSER` | — | core | A successful Response must contain at least one Assertion |
| `IIP-SSO01.h` | MUST | idp | `BROWSER` | — | core | If the Response Issuer is present it must contain the unique identifier of the issuing identity provider with Format omitted or entity |
| `IIP-SSO01.h1` | MUST | idp | `BROWSER` | — | core | If the Response is signed or an enclosed assertion is encrypted, the Issuer element must be present |
| `IIP-SSO01.i` | MUST | idp | `BROWSER` | — | core | Each assertion's Issuer must contain the unique identifier of the responding identity provider with Format omitted or entity |
| `IIP-SSO01.i1` | MUST | idp | `BROWSER` | — | core | All assertions in a response must be issued by the same entity |
| `IIP-SSO01.i2` | MUST | idp | `BROWSER` | — | core | If multiple assertions are included, each assertion's Subject must refer to the same principal |
| `IIP-SSO01.j` | MUST | idp | `BROWSER` | — | core | Any assertion issued for consumption using this profile must contain a Subject with at least one bearer SubjectConfirmation |
| `IIP-SSO01.k` | MUST | idp | `BROWSER` | — | core | At least one bearer SubjectConfirmation must contain a SubjectConfirmationData with a Recipient attribute containing the service provider's assertion consumer service URL and a NotOnOrAfter attribute |
| `IIP-SSO01.k1` | MUST_NOT | idp | `BROWSER` | — | core | The bearer SubjectConfirmationData must not contain a NotBefore attribute |
| `IIP-SSO01.k2` | MUST | idp | `BROWSER` | — | core | If the containing message is in response to an AuthnRequest, the InResponseTo attribute must match the request's ID |
| `IIP-SSO01.l` | MUST | idp | `BROWSER` | — | core | The set of one or more bearer assertions must contain at least one AuthnStatement that reflects the authentication of the principal |
| `IIP-SSO01.l1` | MUST | idp | `BROWSER` | `supports_slo_idp`<br>(CAPABILITY_BASED) | core | If the identity provider supports the Single Logout profile, any authentication statements must include a SessionIndex attribute |
| `IIP-SSO01.m` | MUST | idp | `BROWSER` | — | core | Each bearer assertion must contain an AudienceRestriction including the service provider's unique identifier as an Audience |
| `IIP-SSO01.n` | MUST | sp | `BROWSER` | — | core | The service provider must verify any signatures present on the assertion(s) or the response |
| `IIP-SSO01.o` | MUST | sp | `BROWSER` | — | core | The service provider must verify that the Recipient attribute in the bearer SubjectConfirmationData matches the assertion consumer service URL to which the Response was delivered |
| `IIP-SSO01.p` | MUST | sp | `BROWSER` | — | core | The service provider must verify that the NotOnOrAfter attribute in the bearer SubjectConfirmationData has not passed, subject to allowable clock skew |
| `IIP-SSO01.q` | MUST | sp | `BROWSER` | — | core | The service provider must verify that the InResponseTo attribute in the bearer SubjectConfirmationData equals the ID of its original AuthnRequest |
| `IIP-SSO01.r` | MUST | sp | `BROWSER` | — | core | The service provider must verify that any assertions relied upon are valid in other respects |
| `IIP-SSO01.r1` | MUST | sp | `BROWSER` | — | core | If more than one assertion is present, each assertion must be evaluated independently |
| `IIP-SSO01.s` | SHOULD | sp | `BROWSER` | — | full | Any assertion which is not valid, or whose subject confirmation requirements cannot be met, should be discarded |
| `IIP-SSO01.s1` | SHOULD_NOT | sp | `BROWSER` | — | full | Such an assertion should not be used to establish a security context for the principal |
| `IIP-SSO01.t` | SHOULD | sp | `ATTESTED` | — | full | If an AuthnStatement used to establish a security context contains a SessionNotOnOrAfter attribute, the security context should be discarded once this time is reached |
| `IIP-SSO01.u` | MUST | idp/sp | `CONFIG` | `supports_artifact_binding`<br>(CAPABILITY_BASED) | core | If the HTTP Artifact binding is used, dereferencing of the artifact must be mutually authenticated, integrity protected, and confidential |
| `IIP-SSO01.u1` | MUST | idp | `CONFIG` | `supports_artifact_binding`<br>(CAPABILITY_BASED) | core | The identity provider must ensure that only the service provider to whom the Response was issued is given the message as the result of an ArtifactResolve request |
| `IIP-SSO01.v` | MUST | idp | `BROWSER` | — | core | If the HTTP POST binding is used to deliver the Response, each assertion must be protected by a digital signature |
| `IIP-SSO01.w` | MUST | sp | `BROWSER` | — | core | The service provider must ensure that bearer assertions are not replayed, by maintaining the set of used ID values for the length of time for which the assertion would be considered valid |
| `IIP-SSO01.x` | MUST_NOT | idp | `BROWSER` | — | core | The HTTP Redirect binding must not be used to deliver the Response |
| `IIP-SSO01.y` | MUST_NOT | idp | `BROWSER` | `supports_unsolicited_responses`<br>(CAPABILITY_BASED) | core | An unsolicited Response must not contain an InResponseTo attribute |
| `IIP-SSO01.y1` | SHOULD | idp | `BROWSER` | `unsolicited_acs_from_metadata`<br>(CAPABILITY_BASED) | full | If metadata is used, the unsolicited Response should be delivered to the assertion consumer service endpoint designated as the default |
| `IIP-SSO01.z` | MAY | idp | `BROWSER` | — | full | An identity provider may initiate this profile by delivering an unsolicited Response message to a service provider |
| `IIP-SSO01.aa` | SHOULD | sp | `CONFIG` | — | full | Service providers should have a means of disabling the acceptance of unsolicited responses if circumstances warrant |
| `IIP-SSO01.ab` | SHOULD | idp/sp | `BROWSER` | `derives_url_from_relaystate`<br>(CAPABILITY_BASED) | full | The URL scheme eventually derived from RelayState should be limited to https or http |
| `IIP-SSO01.ac` | SHOULD | sp | `BROWSER` | `relaystate_privacy_required`<br>(CLASSIFICATION_BASED) | full | The service provider should reveal as little of the request as possible in the RelayState value |
| `IIP-SSO01.ad` | RECOMMENDED | idp/sp | `BROWSER` | — | full | It is recommended that the HTTP exchanges in the request and response steps be made over TLS to maintain confidentiality and message integrity |
| `IIP-SSO01.ae` | MUST | idp | `CONFIG` | — | core | The identity provider must establish the identity of the principal, unless it returns an error to the service provider |
| `IIP-SSO01.af` | MUST | sp | `AUTOMATED` | — | core | The AuthnRequest ID must follow the SAML identifier uniqueness requirements |
| `IIP-SSO01.ag` | MUST | idp | `BROWSER` | — | core | If the AuthnRequest Destination is present, the recipient must check that it identifies the location at which the message was received, and discard the request if it does not |
| `IIP-SSO01.ah` | MUST | idp/sp | `AUTOMATED` | — | core | SAML extension elements must be namespace-qualified in a non-SAML-defined namespace |
| `IIP-SSO01.ai` | MUST | idp | `BROWSER` | — | core | If the AuthnRequest carries an XML signature, the responder must verify that the signature is valid |
| `IIP-SSO01.aj` | MUST_NOT | idp | `BROWSER` | — | core | If the signature on the request is invalid, the responder must not rely on the contents of the request |
| `IIP-SSO01.ak` | SHOULD | idp | `BROWSER` | — | full | If the signature on the request is invalid, the responder should respond with an error |
| `IIP-SSO01.al` | SHOULD | idp | `ATTESTED` | — | full | If the signature is valid, the responder should evaluate the signature to determine the identity and appropriateness of the signer |
| `IIP-SSO01.am` | SHOULD | sp | `BROWSER` | — | full | If a Consent attribute indicating that principal consent has been obtained is included, the request should be signed |
| `IIP-SSO01.an` | MUST | idp | `BROWSER` | — | core | If a responder deems a request invalid according to SAML syntax or processing rules, then if it responds it must return a SAML response whose StatusCode value is Requester |
| `IIP-SSO01.ao` | MUST | idp | `AUTOMATED` | — | core | The identifiers the identity provider assigns — the Response ID and the Assertion ID — must follow the SAML identifier uniqueness requirements |
| `IIP-SSO01.ap` | MUST | idp | `BROWSER` | — | core | If the response is generated in response to a request, the InResponseTo attribute must be present and must match the corresponding request's ID |
| `IIP-SSO01.aq` | MUST | sp | `BROWSER` | — | core | If the Response Destination is present, the recipient must check that it identifies the location at which the message was received, and discard the response if it does not |
| `IIP-SSO01.ar` | MUST_NOT | sp | `BROWSER` | — | core | If the signature on the response is invalid, the requester must not rely on the contents of the response |
| `IIP-SSO01.as` | SHOULD | sp | `BROWSER` | — | full | If the signature on the response is invalid, the requester should treat it as an error |
| `IIP-SSO01.at` | SHOULD | sp | `ATTESTED` | — | full | If the signature is valid, the requester should evaluate the signature to determine the identity and appropriateness of the signer |
| `IIP-SSO01.au` | SHOULD | idp | `BROWSER` | — | full | If a Consent attribute indicating that principal consent has been obtained is included, the response should be signed |
| `IIP-SSO01.av` | MUST | idp/sp | `CONFIG` | `emits_idplist_getcomplete`<br>(CAPABILITY_BASED) | core | Retrieving the resource associated with a GetComplete URI must result in an XML instance whose root element is an IDPList that does not itself contain a GetComplete element |
| `IIP-SSO01.aw` | MUST | idp | `CONFIG` | `supports_authnrequest_proxying`<br>(CAPABILITY_BASED) | core | When ProxyCount is zero and the identity provider cannot directly authenticate the presenter, it must return a Response whose top-level StatusCode is Responder |
| `IIP-SSO01.ax` | MAY | idp | `CONFIG` | `supports_authnrequest_proxying`<br>(CAPABILITY_BASED) | full | When ProxyCount is zero and direct authentication is not possible, the identity provider may return ProxyCountExceeded as a second-level StatusCode |
| `IIP-SSO01.ay` | MUST | idp | `CONFIG` | `supports_authnrequest_proxying`<br>(CAPABILITY_BASED) | core | When creating the new AuthnRequest, the proxying identity provider must include equivalent or stricter forms of all the information included in the original request |
| `IIP-SSO01.az` | MUST | idp | `ATTESTED` | `proxies_to_non_saml_provider`<br>(CLASSIFICATION_BASED) | core | If the authenticating identity provider is not a SAML identity provider, the proxying provider must have some other way to ensure that elements governing user agent interaction will be honored |
| `IIP-SSO01.ba` | MUST | idp | `CONFIG` | `supports_authnrequest_proxying`<br>(CAPABILITY_BASED) | core | The new AuthnRequest must contain a ProxyCount attribute with a value of at most one less than the original value |
| `IIP-SSO01.bb` | SHOULD | idp | `CONFIG` | `supports_authnrequest_proxying`<br>(CAPABILITY_BASED) | full | If the original request does not contain a ProxyCount attribute, the new request should contain one |
| `IIP-SSO01.bc` | MUST | idp | `CONFIG` | `supports_authnrequest_proxying`<br>(CAPABILITY_BASED) | core | If an IDPList was specified in the original request, the new request must also contain an IDPList |
| `IIP-SSO01.bd` | MUST_NOT | idp | `CONFIG` | `supports_authnrequest_proxying`<br>(CAPABILITY_BASED) | core | The proxying identity provider must not remove any identity providers from the IDPList |
| `IIP-SSO01.be` | MUST | idp | `CONFIG` | `supports_authnrequest_proxying`<br>(CAPABILITY_BASED) | core | The new assertion's Subject must contain an identifier that satisfies the original requester's preferences as defined by its NameIDPolicy element |
| `IIP-SSO01.bf` | MUST | idp | `CONFIG` | `supports_authnrequest_proxying`<br>(CAPABILITY_BASED) | core | The AuthnStatement in the new assertion must include an AuthnContext containing an AuthenticatingAuthority element referencing the identity provider to which the presenter was referred |
| `IIP-SSO01.bg` | SHOULD | idp | `CONFIG` | `supports_authnrequest_proxying`<br>(CAPABILITY_BASED) | full | If the original assertion contains AuthenticatingAuthority elements, those should be included in the new assertion with the new element placed after them |
| `IIP-SSO01.bh` | MUST | idp | `ATTESTED` | `proxies_to_non_saml_provider`<br>(CLASSIFICATION_BASED) | core | If the authenticating identity provider is not a SAML provider, the proxying identity provider must generate a unique identifier value for the authenticating provider |
| `IIP-SSO01.bi` | SHOULD | idp | `ATTESTED` | `proxies_to_non_saml_provider`<br>(CLASSIFICATION_BASED) | full | The generated identifier value should be consistent over time across different requests |
| `IIP-SSO01.bj` | MUST_NOT | idp | `ATTESTED` | `proxies_to_non_saml_provider`<br>(CLASSIFICATION_BASED) | core | The generated identifier value must not conflict with values used or generated by other SAML providers |
| `IIP-SSO01.cc` | MUST | idp/sp | `AUTOMATED` | — | core | Where a data object declares that it has a particular identifier, there must be exactly one such declaration |
| `IIP-SSO01.cd` | MUST | idp/sp | `ATTESTED` | `uses_random_identifier_generation`<br>(CAPABILITY_BASED) | core | If a random or pseudorandom technique is employed, the probability of two randomly chosen identifiers being identical must be less than or equal to 2^-128 |
| `IIP-SSO01.ce` | SHOULD | idp/sp | `ATTESTED` | `uses_random_identifier_generation`<br>(CAPABILITY_BASED) | full | The probability of two randomly chosen identifiers being identical should be less than or equal to 2^-160 |
| `IIP-SSO01.cf` | MUST | idp/sp | `ATTESTED` | `uses_random_identifier_generation`<br>(CAPABILITY_BASED) | core | A pseudorandom generator must be seeded with unique material in order to ensure the desired uniqueness properties between different systems |
| `IIP-SSO01.cg` | MUST | sp | `AUTOMATED` | — | core | The AuthnRequest messages a service provider issues must conform to the SAML V2.0 protocol schema, including the required ID, Version and IssueInstant attributes |
| `IIP-SSO01.dv` | MUST | idp | `AUTOMATED` | — | core | The Response messages an identity provider issues must conform to the SAML V2.0 protocol schema, including the required ID, Version and IssueInstant attributes and the required Status element |
| `IIP-SSO01.dw` | MUST | idp | `AUTOMATED` | — | core | The assertions an identity provider issues must conform to the SAML V2.0 assertion schema, including the required Version, ID, IssueInstant and Issuer of an assertion and the required AuthnInstant and AuthnContext of an authentication statement |
| `IIP-SSO01.dx` | MUST | idp | `CONFIG` | `supports_authnrequest_proxying`<br>(CAPABILITY_BASED) | core | The AuthnRequest messages a proxying identity provider issues to an upstream identity provider must conform to the SAML V2.0 protocol schema |
| `IIP-SSO01.ch` | MUST | idp | `AUTOMATED` | — | core | The value of the topmost StatusCode element must be from the top-level list provided in SAML2Core 3.2.2.2 |
| `IIP-SSO01.ci` | MUST | idp | `AUTOMATED` | — | core | An xsi:type attribute must be used to indicate the actual statement type when a generic Statement element is used |
| `IIP-SSO01.cj` | MUST | idp | `AUTOMATED` | — | core | An assertion with no statements must contain a Subject element |
| `IIP-SSO01.ck` | MUST | idp | `AUTOMATED` | — | core | An xsi:type attribute must be used to indicate the actual condition type when a generic Condition element is used |
| `IIP-SSO01.cl` | MUST | idp | `AUTOMATED` | — | core | There must be at most one OneTimeUse element within a Conditions element of an assertion |
| `IIP-SSO01.cm` | MUST | idp | `AUTOMATED` | — | core | There must be at most one ProxyRestriction element within a Conditions element of an assertion |
| `IIP-SSO01.cn` | MUST | idp | `AUTOMATED` | — | core | If both NotBefore and NotOnOrAfter are present, the value for NotBefore must be earlier than the value for NotOnOrAfter |
| `IIP-SSO01.co` | MUST | sp | `BROWSER` | — | core | An assertion that is determined to be Invalid or Indeterminate must be rejected by a relying party |
| `IIP-SSO01.cp` | MUST | sp | `BROWSER` | — | core | Multiple AudienceRestriction elements in a single assertion must each be evaluated independently |
| `IIP-SSO01.cq` | SHOULD | sp | `ATTESTED` | — | full | An assertion carrying a OneTimeUse condition should be used immediately by the relying party |
| `IIP-SSO01.cr` | MUST_NOT | sp | `ATTESTED` | — | core | An assertion carrying a OneTimeUse condition must not be retained for future use |
| `IIP-SSO01.cs` | MUST | sp | `ATTESTED` | — | core | Implementations that choose to retain assertions for future use must observe the OneTimeUse element |
| `IIP-SSO01.ct` | MUST_NOT | idp | `CONFIG` | `supports_authnrequest_proxying`<br>(CAPABILITY_BASED) | core | A relying party acting as an asserting party must not issue an assertion that itself violates the restrictions specified in a ProxyRestriction condition |
| `IIP-SSO01.cu` | MUST_NOT | idp | `CONFIG` | `supports_authnrequest_proxying`<br>(CAPABILITY_BASED) | core | A ProxyRestriction Count value of zero indicates that a relying party must not issue an assertion to another relying party on the basis of this assertion |
| `IIP-SSO01.cv` | MUST | idp | `CONFIG` | `supports_authnrequest_proxying`<br>(CAPABILITY_BASED) | core | If the ProxyRestriction Count is greater than zero, any assertions so issued must themselves contain a ProxyRestriction element with a Count value of at most one less |
| `IIP-SSO01.cw` | MUST | idp | `CONFIG` | `supports_authnrequest_proxying`<br>(CAPABILITY_BASED) | core | Otherwise any assertions so issued must contain an AudienceRestriction with at least one of the Audience elements present in the previous ProxyRestriction element |
| `IIP-SSO01.cx` | MUST | sp | `BROWSER` | — | core | An assertion that is malformed with respect to the SAML assertion schema must be rejected by the relying party |
| `IIP-SSO01.cy` | SHOULD | idp/sp | `AUTOMATED` | — | full | The NameQualifier and SPNameQualifier attributes should be omitted unless the element or format explicitly defines their use and semantics |
| `IIP-SSO01.cz` | SHOULD_NOT | idp | `AUTOMATED` | — | full | A Subject element should not identify more than one principal |
| `IIP-SSO01.da` | MUST_NOT | idp | `AUTOMATED` | — | core | SAML extensions must not add local or SAML-namespace-qualified XML attributes to the SubjectConfirmationDataType complex type |
| `IIP-SSO01.db` | SHOULD | idp | `AUTOMATED` | — | full | The time period specified by the NotBefore and NotOnOrAfter attributes of SubjectConfirmationData should fall within the overall assertion validity period |
| `IIP-SSO01.dc` | MUST | idp | `AUTOMATED` | — | core | If both NotBefore and NotOnOrAfter are present on SubjectConfirmationData, NotBefore must be earlier than NotOnOrAfter |
| `IIP-SSO01.dd` | MUST | idp | `AUTOMATED` | — | core | Assertions containing AuthnStatement elements must contain a Subject element |
| `IIP-SSO01.de` | SHOULD_NOT | idp | `ATTESTED` | — | full | The SessionIndex value should not be usable to correlate activity by a principal across different session participants |
| `IIP-SSO01.df` | SHOULD | idp | `ATTESTED` | `uses_small_integer_sessionindex`<br>(CAPABILITY_BASED) | full | The SAML authority should choose the range of SessionIndex values such that the cardinality of any one integer is sufficiently high to prevent correlation |
| `IIP-SSO01.dg` | SHOULD | idp | `ATTESTED` | `uses_small_integer_sessionindex`<br>(CAPABILITY_BASED) | full | The SAML authority should choose values for SessionIndex randomly from within the chosen range |
| `IIP-SSO01.dh` | MUST | idp | `AUTOMATED` | — | core | Assertions containing AttributeStatement elements must contain a Subject element |
| `IIP-SSO01.di` | MUST_NOT | idp | `AUTOMATED` | — | core | SAML extensions must not add local or SAML-namespace-qualified XML attributes to the AttributeType complex type |
| `IIP-SSO01.dj` | MUST | idp | `AUTOMATED` | — | core | Within an AttributeStatement, if the SAML attribute exists but has no values, then the AttributeValue element must be omitted |
| `IIP-SSO01.dk` | MUST | idp | `AUTOMATED` | — | core | If a SAML attribute includes an empty value, the corresponding AttributeValue element must be empty |
| `IIP-SSO01.dl` | MUST | idp | `AUTOMATED` | — | core | If a SAML attribute includes a null value, the corresponding AttributeValue element must be empty and must contain xsi:nil with a value of true or 1 |
| `IIP-SSO01.dm` | SHOULD | idp | `AUTOMATED` | — | full | The Type attribute of an encrypted SAML element should be present |
| `IIP-SSO01.dn` | MUST | idp | `AUTOMATED` | — | core | If the Type attribute of an encrypted SAML element is present, it must contain the value http://www.w3.org/2001/04/xmlenc#Element |
| `IIP-SSO01.do` | MUST | idp | `AUTOMATED` | — | core | The encrypted content must contain an element of the type required for that encrypted SAML element |
| `IIP-SSO01.dp` | MUST | idp | `AUTOMATED` | — | core | For an encrypted identifier, the ciphertext must be unique to any given encryption operation |
| `IIP-SSO01.dq` | SHOULD | idp | `AUTOMATED` | — | full | Each wrapped key should include a Recipient attribute that specifies the entity for whom the key has been encrypted, and its value should be the URI identifier of a SAML system entity |
| `IIP-SSO01.ds` | SHOULD | idp | `AUTOMATED` | — | full | IPv4 addresses should be represented in dotted-decimal format and IPv6 addresses as defined by RFC 3513 |
| `IIP-SSO01.du` | RECOMMENDED | idp | `AUTOMATED` | — | full | If an attribute contains more than one discrete value, it is recommended that each value appear in its own AttributeValue element |
| `IIP-SSO01.dy` | RECOMMENDED | idp | `ATTESTED` | — | full | Two solutions that prevent correlation of SessionIndex values are provided by SAML2Core and are recommended |
| `IIP-SSO01.dz` | MUST | idp/sp | `AUTOMATED` | — | core | All strings in SAML messages must consist of at least one non-whitespace character |
| `IIP-SSO01.ea` | MUST | idp/sp | `ATTESTED` | — | core | All elements of type xs:string or derived from it must be compared using an exact binary comparison |
| `IIP-SSO01.eb` | MUST_NOT | idp/sp | `BROWSER` | — | core | SAML implementations and deployments must not depend on case-insensitive string comparisons, normalization or trimming of whitespace, or conversion of locale-specific formats |
| `IIP-SSO01.ec` | MUST | idp/sp | `ATTESTED` | — | core | When comparing values represented using different character encodings, the implementation must use a comparison method equivalent to converting both to Unicode Normalization Form C and performing an exact binary comparison |
| `IIP-SSO01.ed` | MUST | idp/sp | `ATTESTED` | — | core | Applications that compare data received in SAML documents to data from external sources must take into account the normalization rules specified for XML |
| `IIP-SSO01.ee` | MUST_NOT | idp/sp | `ATTESTED` | — | core | SAML implementations must not depend on specific sorting orders for values |
| `IIP-SSO01.ef` | MUST | idp/sp | `AUTOMATED` | — | core | All URI reference values used within SAML-defined elements or attributes must consist of at least one non-whitespace character and are required to be absolute |
| `IIP-SSO01.eg` | MUST | idp/sp | `AUTOMATED` | — | core | All SAML time values must be expressed in UTC form, with no time zone component |
| `IIP-SSO01.eh` | SHOULD_NOT | idp/sp | `ATTESTED` | — | full | SAML system entities should not rely on time resolution finer than milliseconds |
| `IIP-SSO01.ei` | MUST_NOT | idp/sp | `AUTOMATED` | — | core | Implementations must not generate time instants that specify leap seconds |
| `IIP-SSO01.ej` | MUST_NOT | idp | `AUTOMATED` | — | core | A SAML asserting party must not issue any assertion with an overall Major.Minor assertion version number not supported by the authority |
| `IIP-SSO01.ek` | MUST_NOT | sp | `BROWSER` | — | core | A SAML relying party must not process any assertion with a major assertion version number not supported by the relying party |
| `IIP-SSO01.el` | MUST_NOT | sp | `AUTOMATED` | — | core | A SAML requester must not issue a request message with an overall Major.Minor request version number matching a response version number that the requester does not support |
| `IIP-SSO01.em` | MUST | idp | `BROWSER` | — | core | A SAML responder must reject any request with a major request version number not supported by the responder |
| `IIP-SSO01.en` | MUST_NOT | idp | `BROWSER` | — | core | A SAML responder must not issue a response message with a response version number higher than the request version number of the corresponding request message |
| `IIP-SSO01.eo` | MUST_NOT | idp | `BROWSER` | — | core | A SAML responder must not issue a response message with a major response version number lower than the major request version number of the corresponding request, except to report the error RequestVersionTooHigh |
| `IIP-SSO01.ep` | MUST | idp | `BROWSER` | — | core | An error response resulting from incompatible SAML protocol versions must report a top-level StatusCode value of VersionMismatch |
| `IIP-SSO01.eq` | MUST_NOT | idp | `AUTOMATED` | — | core | A V1.0 assertion must not appear in a V2.0 response message because they are of different major versions |
| `IIP-SSO01.fg` | SHOULD | sp | `AUTOMATED` | — | full | A SAML requester should issue requests with the highest request version supported by both the requester and the responder |
| `IIP-SSO01.fh` | SHOULD | sp | `ATTESTED` | — | full | If the requester does not know the capabilities of the responder, it should assume that the responder supports requests with the highest request version supported by the requester |
| `IIP-SSO01.er` | MUST | idp/sp | `AUTOMATED` | — | core | SAML assertions and protocol messages must use enveloped signatures |
| `IIP-SSO01.es` | SHOULD | idp | `BROWSER` | — | full | A SAML assertion obtained by a relying party from an entity other than the asserting party should be signed by the asserting party |
| `IIP-SSO01.et` | SHOULD | idp | `BROWSER` | — | full | A Response message arriving at a destination from an entity other than the originating sender should be signed by the sender |
| `IIP-SSO01.fj` | SHOULD | sp | `BROWSER` | — | full | An AuthnRequest should be signed or otherwise authenticated and integrity protected by its delivery binding |
| `IIP-SSO01.eu` | MUST | idp/sp | `AUTOMATED` | — | core | SAML assertions and protocol messages must supply a value for the ID attribute on the root element being signed |
| `IIP-SSO01.ev` | MUST | idp/sp | `AUTOMATED` | — | core | Signatures must contain a single ds:Reference containing a same-document reference to the ID attribute value of the root element being signed |
| `IIP-SSO01.ew` | SHOULD | idp/sp | `AUTOMATED` | — | full | SAML implementations should use Exclusive Canonicalization both in the CanonicalizationMethod and as a Transform algorithm |
| `IIP-SSO01.ex` | SHOULD_NOT | idp/sp | `AUTOMATED` | — | full | Signatures in SAML messages should not contain transforms other than the enveloped signature transform or the exclusive canonicalization transforms |
| `IIP-SSO01.ey` | MUST | sp | `BROWSER` | — | core | A service provider that does not reject signatures containing other transform algorithms must ensure that no content of the Response or Assertion is excluded from the signature |
| `IIP-SSO01.fk` | MUST | idp | `BROWSER` | — | core | An identity provider that does not reject signatures containing other transform algorithms must ensure that no content of the AuthnRequest is excluded from the signature |
| `IIP-SSO01.ez` | MUST | idp | `CONFIG` | — | core | When an Assertion is encrypted, the encrypted data must replace the plaintext information in the same location within the XML instance |
| `IIP-SSO01.fd` | MUST | idp | `CONFIG` | — | core | When a BaseID or NameID is encrypted, the encrypted data must replace the plaintext information in the same location |
| `IIP-SSO01.fe` | MUST | idp | `CONFIG` | — | core | When an Attribute is encrypted, the encrypted data must replace the plaintext information in the same location |
| `IIP-SSO01.dr` | MUST | idp | `CONFIG` | `supports_authnrequest_proxying`<br>(CAPABILITY_BASED) | core | The AuthnRequest that a proxying identity provider generates for the upstream identity provider must follow the SAML identifier uniqueness requirements |
| `IIP-SSO01.bk` | MAY | idp | `BROWSER` | — | full | The identity provider may include a binding-specific RelayState parameter with an unsolicited Response, based on mutual agreement with the service provider |
| `IIP-SSO01.y2` | SHOULD | sp | `BROWSER` | — | full | The service provider should be prepared to handle unsolicited responses by designating a default location to send the user agent subsequent to processing a response successfully |
| `IIP-SSO01.fl` | SHOULD | sp | `AUTOMATED` | `allowcreate_general_interoperability_case`<br>(CLASSIFICATION_BASED) | full | A service provider requester that does not make specific use of AllowCreate should generally set it to true, except when requesting a transient name identifier |
| `IIP-SSO01.fm` | SHOULD | idp | `CONFIG` | `proxy_allowcreate_general_interoperability_case`<br>(CLASSIFICATION_BASED) | full | A proxying identity provider requester that does not make specific use of AllowCreate should generally set it to true, except when requesting a transient name identifier |
| `IIP-SSO01.fn` | MUST_NOT | sp | `AUTOMATED` | — | core | A service provider must not use AllowCreate in a request for a transient name identifier |
| `IIP-SSO01.fo` | MUST_NOT | idp | `CONFIG` | `supports_authnrequest_proxying`<br>(CAPABILITY_BASED) | core | A proxying identity provider must not use AllowCreate in an upstream request for a transient name identifier |
| `IIP-SSO01.fp` | SHOULD | idp | `BROWSER` | — | full | An identity provider should ignore AllowCreate in conjunction with requests for, or assertions issued with, transient name identifiers |
| `IIP-SSO01.fr` | SHOULD | idp | `CONFIG` | — | full | If an assertion is issued for use by an entity other than the subject, that entity should be identified in SubjectConfirmation |
| `IIP-SSO01.fs` | SHOULD_NOT | idp/sp | `AUTOMATED` | — | full | The ds:Object element should not be present in SAML signatures |
| `IIP-SSO01.ft` | SHOULD | sp | `BROWSER` | — | full | A service provider verifier should reject SAML signatures that contain a ds:Object element |
| `IIP-SSO01.fu` | SHOULD | idp | `BROWSER` | — | full | An identity provider verifier should reject SAML signatures that contain a ds:Object element |
| `IIP-SSO01.fv` | SHOULD | idp | `AUTOMATED` | — | full | If an EncryptedAssertion is present and CBC-mode encryption is used, the Response should be signed |
| `IIP-SSO01.fw` | SHOULD | sp | `ATTESTED` | — | full | Before processing CBC-encrypted assertions or assertions containing CBC-encrypted data, the relying party should require integrity protection |
| `IIP-SSO01.fx` | SHOULD | idp | `CONFIG` | `supports_authnrequest_proxying`<br>(CAPABILITY_BASED) | full | An AuthnRequest issued by a proxying identity provider should be signed or otherwise authenticated and integrity protected by its delivery binding |
| `IIP-SSO01.fy` | MUST_NOT | sp | `BROWSER` | — | core | If an assertion signature is invalid, the relying party must not rely on the contents of the assertion |
| `IIP-SSO01.fz` | SHOULD | sp | `ATTESTED` | — | full | If an assertion signature is valid, the relying party should evaluate it to determine the identity and appropriateness of the issuer |
| `IIP-SSO01.ga` | MUST | idp | `CONFIG` | — | core | If RequestedAuthnContext Comparison is minimum and the identity provider succeeds, the resulting authentication context must be at least as strong as one of the requested contexts |
| `IIP-SSO01.gb` | MUST | idp | `CONFIG` | — | core | If RequestedAuthnContext Comparison is better and the identity provider succeeds, the resulting authentication context must be stronger than one of the requested contexts |
| `IIP-SSO01.gc` | MUST | idp | `CONFIG` | — | core | If RequestedAuthnContext Comparison is maximum and the identity provider succeeds, the resulting authentication context must be as strong as possible without exceeding at least one requested context |
| `IIP-SSO01.gd` | SHOULD | idp | `CONFIG` | — | full | If multiple attesting entities are permitted to use a bearer assertion, multiple SubjectConfirmation elements should be included |
| `IIP-SSO01.ge` | SHOULD | idp | `CONFIG` | `supports_authnrequest_proxying`<br>(CAPABILITY_BASED) | full | A proxying identity provider requester should use the highest request version supported by both it and the upstream responder |
| `IIP-SSO01.gf` | SHOULD | idp | `CONFIG` | `supports_authnrequest_proxying`<br>(CAPABILITY_BASED) | full | If a proxying identity provider requester does not know the upstream responder's capabilities, it should assume support for its own highest request version |
| `IIP-SSO01.gg` | MUST_NOT | idp | `CONFIG` | `supports_authnrequest_proxying`<br>(CAPABILITY_BASED) | core | A proxying identity provider requester must not issue a request version corresponding to a response version it does not support |
| `IIP-SSO01.gh` | SHOULD | idp | `CONFIG` | `supports_authnrequest_proxying`<br>(CAPABILITY_BASED) | full | A proxying identity provider should sign an upstream AuthnRequest when its Consent attribute indicates that principal consent has been obtained |
| `IIP-SSO01.gi` | MUST_NOT | idp | `BROWSER` | — | core | If the request ID cannot be determined, the response must not contain InResponseTo |
| `IIP-SSO01.gj` | MUST | idp | `CONFIG` | — | core | When ordering is relevant to RequestedAuthnContext evaluation, the supplied references must be evaluated as an ordered set with the first element most preferred |

<details><summary><code>IIP-SSO01.a</code> details</summary>

- **Required variants**:
  - `v-2aa671608e` SP-initiated happy path: protected resource → AuthnRequest → authentication → Response → resource access
  - `v-d462b4546b` Request via Redirect / response via POST (the same combination as IIP-SSO02 and IIP-SSO03)
  - `v-c8f2acaa60` Request via POST / response via POST
- **Controls (negative controls)**:
  - ★ This obligation is a comprehensive case that checks only that the profile works end to end. It must not be treated as having exercised each individual normative sentence
  - ★ The happy path alone has no detection power. The individual obligations from IIP-SSO01.b onward provide the controls
  - ★ Correction: The previous version made the IdP-initiated (unsolicited) happy path a required variant, but initiation in §4.1.5 is MAY (IIP-SSO01.z). Making it required would mark a conforming IdP that does not issue unsolicited responses as FAIL. Obligations specific to unsolicited responses were placed conditionally in IIP-SSO01.y/.y1
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Prof)**; locator: `4\.1 Web Browser SSO Profile||4\.2 Enhanced Client or Proxy`: The Web Browser SSO Profile as a whole. Individual normative sentences are decomposed from IIP-SSO01.b onward
- **Notes**: 【CP1 reconciliation record】On 2026-08-27, §4.1 (with Errata applied), incorporation sentence A, and incorporation sentence B were rechecked bidirectionally: omission checking (source text → obligations) and overreach checking (obligations → effective source text). The Errata replacement precedence was confirmed, and the obsolete §6.2 removed by E43/E93, the former SessionNotOnOrAfter MUST removed by E79, and the former RSA-SHA1 SHOULD removed by E81 were excluded from generation targets. The following is the authoritative source for the mapping table. 【RFC2119 sentences in §4.1 → obligation mapping】 4.1.1: use the bearer confirmation method → .fr; the SHOULD added by E47 to identify the intended attesting entity for the bearer method → .fr; the SHOULD for multiple SubjectConfirmations for multiple attesting entities → .gd. 4.1.2: do not use Redirect for the response → .x; the SP MAY use Discovery → IIP-SP04. 4.1.3.1: RelayState MAY be used → note on .ab; expose as little of the original request as possible (SHOULD) → .ac. 4.1.3.2: Discovery, redirection to another service, and use of metadata (all MAY) → permissions, creating no obligations. 4.1.3.3: operation over TLS is RECOMMENDED → .ad; signing the AuthnRequest is MAY → permission; “IdP MUST process the <AuthnRequest> as described in [SAMLCore]” is an incorporation sentence, and the incorporated SAML2Core normative sentences were expanded under 【Incorporation sentence A】 below. 4.1.3.4: establish the principal's identity (MUST) → .ae. 4.1.3.5: generate an HTTP response containing a Response/artifact regardless of success or failure (SHOULD, with error responses strengthened by E85) → success path .a/.g, error path IIP-IDP05.a (IIP strengthened it to MUST); verify that the ACS location is under the SP's control (MUST) → IIP-IDP12.b; honor the specified binding and ACS where possible (MUST) → IIP-IDP12.a/.e/.f; TLS is RECOMMENDED → .ad; POST-time Assertion/Response signing (MUST, reflecting E26/E93) → .v; Response signing for CBC-mode EncryptedAssertion (SHOULD, E93) → .fv; “SP MUST process the <Response> as described in [SAMLCore]” is an incorporation sentence: profile-specific processing rules are .n–.r1, and the incorporated general SAML2Core rules are 【Incorporation sentence B】 below. 4.1.3.6: establishing a security context is MAY → permission. 4.1.4.1: Issuer (MUST) → .b; error response when the request cannot be satisfied (MUST) → IIP-IDP05.a; do not include SubjectConfirmation in Subject (MUST NOT) → .c; error when the principal cannot be recognized (MUST) → .d; do not rely on information from an unauthenticated request (MUST NOT) → .e; ACS validation (MUST) → IIP-IDP12.b; ★ the former Profile MUST “if an SP wants creation of a new identifier, it must include AllowCreate=true” was removed from §4.1.4.1 by SAML2Errata E14. The new rule E14 added to Core 3.4.1.1 is decomposed into .fl–.fp under incorporation sentence A. 4.1.4.2 (reflecting E17/E26/E52): .f–.m; ignoring the Address attribute, additional statements, and AttributeConsumingServiceIndex is MAY → permissions; “if the conditions are not understood and accepted by the SP, the assertion is not valid” is SP-side processing and included in .r. 4.1.4.3 (reflecting E26/E93): .n–.t; Response signing for CBC-mode EncryptedAssertion (SHOULD) → .fv; matching Address is MAY → permission. 4.1.4.4: .u/.u1. “using the Artifact Resolution profile” identifies the artifact reference-resolution mechanism, but the additional normative content explicitly stated by this section is mutual authentication, integrity, confidentiality, and restriction to the intended SP; decompose it into these two obligations. Do not recursively double-count the entire Artifact Resolution Profile §5 under SSO01. 4.1.4.5 (reflecting E26): .v/.w. 4.1.5 (including the E90 addition): initiation is MAY → .z; do not include InResponseTo (MUST NOT) → .y; delivery to the default ACS (SHOULD) → .y1; the SP should be able to handle unsolicited responses (SHOULD) → .y2; the SP should be able to disable acceptance of unsolicited responses (SHOULD, E90) → .aa; RelayState transfer is MAY → permission. E90 adds new §4.1.6 “Use of Relay State”: limit the URL scheme to https/http (SHOULD) → .ab. The OS edition's §4.1.6 “Use of Metadata”: IIP-SSO06 directly handles the same section, so it is not duplicated here. ★ Because E90 inserts a new §4.1.6 into the Errata-applied edition, section number 4.1.6 refers to different sections in the OS edition (“Use of Metadata”) and the Errata-applied edition (“Use of Relay State”). IIP-SSO06 specifies the section title as well, so it unambiguously refers to the OS-edition section. 【Incorporation sentence A: IdP MUST process the <AuthnRequest> as described in [SAMLCore]】The incorporated scope is the syntax, validation, and processing of <AuthnRequest>, plus the dependency closure of common rules directly referenced by that processing. The authoritative source is the section-by-section mapping table below (§1.1, §1.3, §3.2.1, §3.3.2.2.1, §3.4.1–§3.4.1.5.1, §4, §5, §6), not a short list of section numbers. Independent protocols such as §3.5 Artifact Resolution and §3.6 Name Identifier Management are out of scope except for normative sentences individually incorporated by Profile §4.1 or the mapping table. §1.1 Notation (the schema document is authoritative for syntax) plus protocol/assertion schema: SP AuthnRequest → .cg; IdP Response → .dv; IdP Assertion/AuthnStatement → .dw; proxy IdP AuthnRequest (conditional) → .dx. ★ Obligations are separated by role (because variants have no role field; assigning idp/sp to one obligation would make it appear in G2 that a variant for one role must also cover the other role). §1.3.1 strings: at least one non-whitespace character → .dz; exact binary comparison → .ea; do not ignore case, normalize whitespace, or rely on locale conversion → .eb; compare different encodings using NFC → .ec; account for XML normalization when comparing with external data → .ed; do not rely on sort order → .ee. §1.3.2 URI: at least one non-whitespace character and an absolute URI → .ef. §1.3.3 time: UTC without a timezone → .eg; do not rely on sub-millisecond resolution (SHOULD NOT) → .eh; do not generate leap seconds → .ei; E92’s reasonable clock-skew SHOULD is strengthened to MUST and handled directly by IIP-G01. §1.3.4: do not assign the same value to different objects → .af (SP)/.ao (IdP; both <Response>/@ID and <Assertion>/@ID); exactly one declaration → .cc; collision probability ≤2^-128 when randomness is used → .cd; the same ≤2^-160 (SHOULD) → .ce; PRNG seed → .cf. §3.2.1: request @ID and response @InResponseTo match → .ap; match and discard on @Destination → .ag; namespace-qualify extension elements → .ah; verify signatures → .ai; do not rely on content when the signature is invalid → .aj; error response for an invalid signature (SHOULD) → .ak; evaluate signer identity and validity (SHOULD) → .al; sign requests with Consent (SHOULD) → .am (SP)/.gh (proxy IdP); <StatusCode> when responding to an invalid request (MUST) → .an. §3.4.1 body and §3.4.1.1 NameIDPolicy: ForceAuthn → IIP-IDP06; IsPassive → IIP-IDP07; authentication and integrity protection of AuthnRequest by signature or binding (SHOULD) → .fj (SP)/.fx (proxy IdP); basic NameIDPolicy processing → IIP-IDP10; E14’s new AllowCreate rule → .fl–.fp (.fl/.fm explicitly state the “do not use for specific purposes” condition in the predicate); three ACS attributes → IIP-IDP12; RequestedAuthnContext exact → IIP-IDP08, minimum/better/maximum → .ga/.gb/.gc, priority evaluation of candidates → .gj; AttributeConsumingServiceIndex → IIP-IDP04.b; Subject → IIP-SSO01.c/.d and IIP-SSO07.b; ProviderName and Consent have no processing rule and are information recorded by IIP-SSO07.b. §3.4.1.2 <Scoping>: the only RFC2119 obligation is the MAY for “profiles specifying an active intermediary” → permission. §3.4.1.3 <IDPList>: MUST for the result of resolving <GetComplete> → .av. §3.4.1.4 processing rules: an assertion satisfying the request's specification or an error response → IIP-IDP10.d; error response when authentication fails, the subject is unknown, or policy rejects → IIP-IDP05.a and .d; strongly match <Subject> → IIP-SSO07.b; implications when content is empty (AuthnStatement/AudienceRestriction) → .l/.m. §3.4.1.5 and §3.4.1.5.1 proxying: .aw–.bj (all conditioned on supports_authnrequest_proxying). ★ E65 replaced the former ProxyCount=0 “MUST NOT proxy / secondary ProxyCountExceeded MUST”; accordingly .aw is the top-level Responder MUST and .ax is the secondary ProxyCountExceeded MAY. §4 version processing: issue requests using the highest version supported by both parties (SHOULD) → .fg (SP)/.ge (proxy IdP); assume one's own highest version when the responder's capability is unknown (SHOULD) → .fh (SP)/.gf (proxy IdP); do not issue assertions with an unsupported version → .ej; do not process assertions with an unsupported major version → .ek; do not issue a request corresponding to a response version the implementation cannot handle → .el (SP)/.gg (proxy IdP); reject requests with an unsupported major version → .em; do not issue a response with a version higher than the request → .en; do not issue a lower major version than the request (except when reporting VersionMismatch) → .eo; top-level VersionMismatch for incompatibility → .ep; do not include a V1 assertion in a V2 response → .eq. ★ The exception in .eo is limited to the secondary code RequestVersionTooHigh, not VersionMismatch in general. “A request with a higher minor version MAY be processed or rejected” and “a request sharing the same major version MUST have the same processing rules” are not obligations (the latter is a specification-property declaration, not an implementation obligation). §4.2 namespace-version handling is a norm for specification authors and creates no obligation. The SHOULD for future extensibility and SHOULD to reject unknown extensions with mandatory semantics in §4.2.1 are assessed through IIP-SSO07.b and IIP-EXT01, which directly specify processing results by content type; do not double-count them. §5 XML Signature profile: enveloped signatures → .er; ★ the former RSA-SHA1 support SHOULD creates no obligation because E81 replaced it with “any XML Signature algorithm MAY be used”; signatures on assertions obtained from parties other than the issuer (SHOULD) → .es; signatures on messages received from parties other than the sender (SHOULD) → .et (IdP Response)/.fj (SP AuthnRequest); ID of the signed root → .eu; **a single <ds:Reference> and same-document reference → .ev**; Exclusive C14N (SHOULD) → .ew; do not include unauthorized transforms (SHOULD NOT) → .ex; **if unauthorized transforms are accepted, ensure that no content is excluded from the signature → .ey (SP)/.fk (IdP)**; <ds:KeyInfo> MAY be omitted → permission; E91’s <ds:Object> SHOULD NOT be sent → .fs, and verifier SHOULD reject it → .ft (SP)/.fu (IdP); §5.3 signature inheritance is advisory because it uses lowercase “should.” §6 encryption: replacement at the same location remaining after E30 → .ez (assertion)/.fd (identifier)/.fe (attribute); §6.1 @Type → .dm/.dn (same rule as §2.2.4). ★ The OS edition's §6.2 “verify/decrypt in reverse order / encrypt the assertion after signing / outer-sign identifiers and attributes after encryption” was replaced in its entirety by E43 with the Key and Data Referencing Guidelines, and then by E93 with Encryption and Integrity Protection. Therefore .fa/.fb/.fc/.ff derived from the former §6.2 do not exist after applying the Errata and must be deleted. The current §6.2’s SHOULD for integrity protection before processing CBC-encrypted data → .fw; the SHOULD added to Profile 4.1 for Response signing → .fv. ★ .ez/.fd/.fe are passive rules for each encrypted element actually sent; if none is observed, return satisfied_with_note. ★ .er/.eu/.ev/.ew/.ex have no conditions. The §5.4 constraints apply to each XML signature actually generated at runtime, not to products capable of signing; passively inspect each signature sent by the target, and if no signature is observed, return satisfied_with_note. ★ .ey also has no condition. Applicability is evaluated before case execution, so conditioning it on whether the target accepted the message would cause the observation case to be skipped before observation, creating a cycle. Evaluate each transform as follows: rejected → satisfied; accepted but excludes no content → satisfied; accepted and the signature excludes content → violated; inability to determine whether content was excluded → not_verified. The source requires “no content of the SAML message is excluded from the signature,” not merely that excluded content is unused. Received messages differ by role (SP: <Response>/<Assertion>; IdP: <AuthnRequest>), so obligations are separated by role. An identity transform permits only a binary accept/reject outcome, so it is not a required variant; place it in Suite-side fixture self-validation and do not let it affect the target verdict. Self-validation checks only that the fixture signature is cryptographically valid and that the identity transform excludes no content. The target remains conforming even if it rejects solely because an unauthorized transform is present; do not distinguish rejection reasons. ★ .fk always sends a signed AuthnRequest. Whether the target requires signatures and whether it correctly verifies a received signature are separate obligations. Return not_verified only if the Suite SP's key cannot be trusted. ★ .ev/.ey directly detect XML Signature Wrapping. 【Incorporation sentence B: SP MUST process the <Response> and enclosed <Assertion> as described in [SAMLCore]】The incorporated scope is the syntax, validation, and processing of <Response> and its enclosed <Assertion>, plus the dependency closure of common rules they directly reference. The authoritative source is the mapping table below (§2 in its entirety, §3.2.2, §3.2.2.2, and §1/§4/§5/§6 explicitly listed as common rules), not a short list of section numbers. §3.5 Artifact Resolution is a separate protocol and is not recursively incorporated by this sentence except for the two normative sentences explicitly stated by Profile §4.1.4.4 (IIP-SSO01.u/.u1). §3.2.2: @ID uniqueness → .ao; @InResponseTo required and matching in responses to requests → .ap; prohibit @InResponseTo in unsolicited responses → .y; prohibit the error path when the request ID cannot be identified → .gi; match and discard on @Destination → .aq; namespace-qualify extension elements → .ah; verify signatures → .n; do not rely on content when the signature is invalid → .ar; treat an invalid signature as an error (SHOULD) → .as; evaluate signer identity and validity (SHOULD) → .at; sign responses with Consent (SHOULD) → .au. §3.2.2.2: top-level <StatusCode>/@Value is a value from the top-level list → .ch. ★ The scope of incorporation sentence B is all of §2, SAML Assertions (the previous version was limited primarily to §2.5 Conditions). The section mapping is as follows; reasons are given for sections that create no obligation. §2.1 schema declarations: no normative sentence. §2.2.1 <BaseID>/§2.2.2 NameIDType: omission of NameQualifier/SPNameQualifier (SHOULD) → .cy. §2.2.3 <NameID>: no normative sentence (rules by Format are in §8.3 and handled by IIP-SSO05). §2.2.4 <EncryptedID>: presence of @Type (SHOULD) → .dm; value of @Type → .dn; type of encrypted content (NameIDType or AssertionType, and their derived types) → .do; **ciphertext uniqueness → .dp (this MUST is located only in §2.2.4, so it is limited to <EncryptedID>)**; Recipient of the wrapped key (SHOULD) → .dq. §2.2.5 <Issuer>: no RFC2119 sentence. The consequence of the default Format entity is .h/.i; omission of qualifier attributes is .cy. §2.3.1 <AssertionIDRef>/§2.3.2 <AssertionURIRef>: no normative sentence. Web Browser SSO carries assertions by value, so reference forms are not used. §2.3.3 <Assertion>: @ID uniqueness → .ao; required @Version/@IssueInstant/<Issuer> → .dw (generation)/.cx (reception rejection); xsi:type on <Statement> → .ci; an assertion without a statement contains <Subject> → .cj; signature verification → .n; do not rely on an assertion with an invalid signature → .fy; evaluate the assertion issuer (SHOULD) → .fz; “the issuer should be unambiguous to the relying party” (SHOULD) is subsumed by .i (MUST). §2.3.4 <EncryptedAssertion>: .dm/.dn/.do/.dq. §2.4.1 <Subject>: do not identify two or more subjects (SHOULD NOT) → .cz (inspect semantic multiplicity, including identifiers inside <SubjectConfirmation>, not only the schema choice constraint). §2.4.1.1 <SubjectConfirmation>: E47’s addition “if used by an entity different from the Subject, identify that entity (SHOULD)” → .fr; bearer requirements → .j/.k (from SAML2Prof). §2.4.1.2 <SubjectConfirmationData>: namespace for extension attributes → .da; validity interval lies within the assertion (SHOULD; **both upper and lower bounds**) → .db; NotBefore < NotOnOrAfter → .dc; @Address notation (SHOULD) → .ds; bearer prohibition of Recipient/NotOnOrAfter/NotBefore/InResponseTo → .k/.k1/.k2. §2.4.1.3 KeyInfoConfirmationDataType: **creates no obligation**. “The confirmation method defines the mechanism” is a norm for specification authors, not an implementation obligation; the remainder is specific to holder-of-key confirmation, while Web Browser SSO uses bearer (.j). ECP holder-of-key is handled separately by IIP-IDP13. §2.5 Conditions: as follows. §2.6 <Advice>: optional content that may be ignored, handled by IIP-EXT01. §2.7.1 <Statement>: xsi:type → .ci. §2.7.2 <AuthnStatement>: required <Subject> → .dd; required @AuthnInstant/<AuthnContext> → .dw/.cx; ★ the former SessionNotOnOrAfter MUST to treat the session as ended was replaced by E79 with an explanation of the upper bound and creates no obligation. In Web Browser SSO, apply only the concrete processing rule in Profile 4.1.4.3, .t (SHOULD); prevent SessionIndex correlation (SHOULD NOT) → .de; two recommended methods (RECOMMENDED) → .dy; cardinality of method (a)'s value range (SHOULD) → .df; random selection for method (a) (SHOULD) → .dg; SessionIndex required when SLO is supported → .l1. ★ .df/.dg are internal rules for method (a) in the source, so they are conditioned on the predicate uses_small_integer_sessionindex. They do not apply to implementations using method (b), which uses the assertion's @ID. §2.7.2.1 <SubjectLocality>: @Address notation (SHOULD) → .ds. §2.7.2.2 <AuthnContext>: no profile-specific RFC2119 sentence. Request-side handling is IIP-IDP08/IIP-SP06/IIP-SP07. §2.7.3 <AttributeStatement>: required <Subject> → .dh. §2.7.3.1 <Attribute>: do not use @FriendlyName as the basis for identification → IIP-SP11.a; namespace for extension attributes → .di; omit <AttributeValue> when the attribute has no value → .dj; **represent multiple discrete values in separate <AttributeValue> elements (RECOMMENDED) → .du**; “if multiple <AttributeValue> elements have xsi:type, all must have the same type” uses lowercase “must” and is advisory; “other uses must define semantics” is a **norm for specification authors** and creates no obligation. §2.7.3.1.1 <AttributeValue>: empty value → .dk; null value → .dl. §2.7.3.2 <EncryptedAttribute>: .dm/.dn/.do/.dq. §2.7.4 <AuthzDecisionStatement> and below: **creates no obligation**. The Web Browser SSO Profile does not use authorization decision statements; handling when an IdP includes one is covered by IIP-SSO07.b (unsupported optional content). The SHOULD group for URI normalization is specific to authorization-decision resources and out of scope for this profile. §2.5.1 <Conditions>: xsi:type on <Condition> → .ck; at most one <OneTimeUse> → .cl; at most one <ProxyRestriction> → .cm. §2.5.1.1: reject Invalid/Indeterminate assertions → .co. §2.5.1.2: NotBefore < NotOnOrAfter → .cn; validate the interval → .p/.r. §2.5.1.4: independently evaluate multiple <AudienceRestriction> elements → .cp; SP entityID in <Audience> → .m. §2.5.1.5 <OneTimeUse>: use immediately (SHOULD) → .cq; do not retain for future use → .cr; implementations that retain it must comply → .cs; at most one → .cl. §2.5.1.6 <ProxyRestriction>: do not issue assertions violating the restriction → .ct; Count=0 → .cu; decrement Count → .cv; scope of <Audience> → .cw; at most one → .cm. Validation of the §2.5 Conditions interval and Audience itself is .r. Among the details of §1.3.4, the @ID of an AuthnRequest generated upstream by a proxy IdP is .dr (conditional).
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.b</code> details</summary>

- **Required variants**:
  - `v-4b3409c994` The AuthnRequest sent by the target SP contains <saml:Issuer>
  - `v-8c8c008cd8` Its value matches the target’s metadata entityID
  - `v-356444abc6` @Format is omitted or is urn:oasis:names:tc:SAML:2.0:nameid-format:entity
- **Controls (negative controls)**:
  - ★ Examine the three conditions (presence, value, and Format) separately. Checking presence alone cannot detect an incorrect value
  - ★ In a configuration where the target has multiple entityIDs, compare against the entityID corresponding to the Test Peer receiving the response
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Prof)**; locator: `4\.1\.4\.1 <AuthnRequest> Usage||4\.1\.4\.2 <Response> Usage`: 『The <Issuer> element MUST be present and MUST contain the unique identifier of the requesting service provider; the Format attribute MUST be omitted or have a value of urn:oasis:names:tc:SAML:2.0:nameid-format:entity』
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.c</code> details</summary>

- **Required variants**:
  - `v-0a009374b2` Inspect every AuthnRequest sent by the target across the entire Transcript and verify that no <Subject>/<SubjectConfirmation> is present.
  - `v-70a5b457b3` The requirement is satisfied even when the target is configured not to send <Subject> (vacuously true).
- **Controls (negative controls)**:
  - ★ A passive always-on check, applied across all cases.
  - ★ A target that does not send <Subject> cannot violate this requirement. The target must declare during preflight whether it sends <Subject>; if it does not, record the result as satisfied_with_note (no observation opportunity).
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Prof)**; locator: `4\.1\.4\.1 <AuthnRequest> Usage||4\.1\.4\.2 <Response> Usage`: 『Note that the service provider MAY include a <Subject> element in the request that names the actual identity about which it wishes to receive an assertion. This element MUST NOT contain any <SubjectConfirmation> elements』
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.d</code> details</summary>

- **Required variants**:
  - `v-56375de24a` An AuthnRequest with a <Subject> referring to a nonexistent principal → an error <Status> is returned and there are zero <Assertion> elements
  - `v-a68a404cce` Control: a <Subject> referring to an existing principal → a successful response is returned (to catch implementations that return errors for everything)
  - `v-299c7ac543` The error response contains neither <Assertion> nor <EncryptedAssertion>
- **Controls (negative controls)**:
  - ★ “Return an error” and “include no assertion” are separate observations. Check both.
  - ★ Because no secondary status code is specified, do not use a specific value as a determination condition.
  - ★ If the target does not support requests with a <Subject>, returning an error is correct behavior and does not conflict with this obligation.
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Prof)**; locator: `4\.1\.4\.1 <AuthnRequest> Usage||4\.1\.4\.2 <Response> Usage`: 『If the identity provider does not recognize the principal as that identity, then it MUST respond with a <Response> message containing an error status and no assertions』
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.e</code> details</summary>

- **Required variants**:
  - `v-66f925ac8c` Confirm through attestation how the contents of an unsigned AuthnRequest are handled, namely, the design of the trust boundary.
  - `v-5e451a7890` Confirm through attestation that ProviderName, Scoping, and Conditions from an unsigned request are not applied without validation.
- **Controls (negative controls)**:
  - ★ The only directly observable consequence is ACS validation (IIP-IDP12.b, not IIP-SSO01.f). Determine this automatically there.
  - ★ “What was trusted” is internal processing, so this obligation itself is limited to attestation. If the attestation contradicts the observation under IIP-IDP12.b, return INCONSISTENT.
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Prof)**; locator: `4\.1\.4\.1 <AuthnRequest> Usage||4\.1\.4\.2 <Response> Usage`: 『Note that if the <AuthnRequest> is not authenticated and/or integrity protected, the information in it MUST NOT be trusted except as advisory』
- **Notes**: The obligation to validate the ACS request by confirming that it is associated with the requester, regardless of whether it is signed, belongs to IIP-IDP12.b. This obligation is the general principle covering the rest of the request content.
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.f</code> details</summary>

- **Required variants**:
  - `v-cd793caf17` A request that induces an error (unknown Format / unrecognized subject / unsatisfied IsPassive) → the returned <Response> contains zero <Assertion> elements
  - `v-bf8cf92ded` The number of <saml:EncryptedAssertion> elements must also be zero
  - `v-ca06edbd44` Control: successful request → one or more <Assertion> elements (IIP-SSO01.g)
- **Controls (negative controls)**:
  - ★ An encrypted assertion is also an “assertion.” Check for the presence of EncryptedAssertion as well
  - ★ Test multiple error paths (Format / subject / IsPassive). A single path cannot detect implementation differences
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Prof)**; locator: `4\.1\.4\.2 <Response> Usage||4\.1\.4\.3 <Response> Message Processing Rules`: 『If the identity provider wishes to return an error, it MUST NOT include any assertions in the <Response> message』
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.g</code> details</summary>

- **Required variants**:
  - `v-f93edb9312` On SP-initiated success → at least one <Assertion> or <EncryptedAssertion>.
  - `v-b079feff23` On IdP-initiated (unsolicited) success → the same.
- **Controls (negative controls)**:
  - ★ Pair this with IIP-SSO01.f. It has meaning only when both zero assertions on error and at least one assertion on success are observed.
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Prof)**; locator: `4\.1\.4\.2 <Response> Usage||4\.1\.4\.3 <Response> Message Processing Rules`: 『It MUST contain at least one <Assertion>』
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.h</code> details</summary>

- **Required variants**:
  - `v-c9e9f6c1c9` When <Response>/<Issuer> is present, its value matches the subject's entityID.
  - `v-3a299cc52b` Its @Format is omitted or is entity.
  - `v-293a907965` Control: do not FAIL a response that omits <Issuer> (it MAY be omitted).
- **Controls (negative controls)**:
  - ★ Omission is permitted. Requiring presence would cause a conforming implementation to FAIL. Presence becomes mandatory only when the condition of IIP-SSO01.h1 is met.
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Prof)**; locator: `4\.1\.4\.2 <Response> Usage||4\.1\.4\.3 <Response> Message Processing Rules`: 『The <Issuer> element MAY be omitted, but if present it MUST contain the unique identifier of the issuing identity provider; the Format attribute MUST be omitted or have a value of urn:oasis:names:tc:SAML:2.0:nameid-format:entity』
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.h1</code> details</summary>

- **Required variants**:
  - `v-7ed31f8165` Configuration with Response signing enabled → <Response>/<Issuer> is present.
  - `v-dc1ef94b72` Configuration with assertion encryption enabled → <Response>/<Issuer> is present.
  - `v-66fec7d114` Control: configuration with neither signing nor encryption → it may be omitted.
- **Controls (negative controls)**:
  - ★ IIP-SSO01.h concerns correctness of the value, whereas this obligation concerns the requirement that it be present; they are separate observations.
  - ★ If the presence of signatures and encryption cannot be toggled, a control cannot be created. Couple this with the configuration of IIP-SSO04 / IIP-IDP09.
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Prof)**; locator: `4\.1\.4\.2 <Response> Usage||4\.1\.4\.3 <Response> Message Processing Rules`: The corresponding passage before revision (the target rewritten by E17).
- **Reference basis (SAML2Errata)**; locator: `E17: Authentication Response IssuerName||E18: Reference to Identity Provider Discovery`: “If the <Response> message is signed or if an enclosed assertion is encrypted, then the <Issuer> element MUST be present”. Because IIP-SSO01 incorporates [SAML2Prof] “as updated by [SAML2Errata]”, this revision applies normatively.
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.i</code> details</summary>

- **Required variants**:
  - `v-949c34d845` <Assertion>/<Issuer> matches the entityID of the subject, the IdP that sent the response.
  - `v-26844dff60` Its @Format is omitted or is entity.
  - `v-0da8be1d45` Proxy configuration: it is the entityID of the subject itself, which sent the response, not the upstream IdP's entityID.
- **Controls (negative controls)**:
  - ★ <Response>/<Issuer> and <Assertion>/<Issuer> are separate elements. Check both.
  - ★ The proxy variant is the highest-detection-power case. Do not confuse it with IIP-SSO05.a6 (NameQualifier is the original generator). Issuer is the responder; NameQualifier is the identifier generator.
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Prof)**; locator: `4\.1\.4\.2 <Response> Usage||4\.1\.4\.3 <Response> Message Processing Rules`: 『Each assertion's <Issuer> element MUST contain the unique identifier of the issuing identity provider; the Format attribute MUST be omitted or have a value of urn:oasis:names:tc:SAML:2.0:nameid-format:entity』
- **Reference basis (SAML2Errata)**; locator: `E26: Ambiguities Around Multiple Assertions||E27: `: E26 changes “issuing” to “responding”. The purpose is to exclude implementations that put the upstream IdP's entityID in a proxy configuration.
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.i1</code> details</summary>

- **Required variants**:
  - `v-7431118793` Configuration returning multiple assertions → all <Assertion>/<Issuer> values are identical.
  - `v-09d89eb915` With a response containing one assertion, the condition is vacuously true.
- **Controls (negative controls)**:
  - ★ If the subject cannot be made to return multiple assertions, there is no observation opportunity. Record satisfied_with_note and do not state that it was “verified”.
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Prof)**; locator: `4\.1\.4\.2 <Response> Usage||4\.1\.4\.3 <Response> Message Processing Rules`: The corresponding passage before revision (the target rewritten by E26).
- **Reference basis (SAML2Errata)**; locator: `E26: Ambiguities Around Multiple Assertions||E27: `: 『Note that this profile assumes a single responding identity provider, and all assertions in a response MUST be issued by the same entity』
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.i2</code> details</summary>

- **Required variants**:
  - `v-2ebcd43a2a` Configuration returning multiple assertions → each <Subject> refers to the same principal.
  - `v-2ebff8cd8c` The fact that the contents of <Subject>, such as the <NameID> Format or value, differ is itself permitted. Do not FAIL this.
- **Controls (negative controls)**:
  - ★ “Same principal” does not mean identical values. Identifiers with different Formats can refer to the same principal. Determine this by whether they correspond to the single principal that the Suite logged in, not by simple string comparison.
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Prof)**; locator: `4\.1\.4\.2 <Response> Usage||4\.1\.4\.3 <Response> Message Processing Rules`: The corresponding passage before revision (the target rewritten by E26).
- **Reference basis (SAML2Errata)**; locator: `E26: Ambiguities Around Multiple Assertions||E27: `: 『If multiple assertions are included, then each assertion's <Subject> element MUST refer to the same principal. It is allowable for the content of the <Subject> elements to differ』
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.j</code> details</summary>

- **Required variants**:
  - `v-544fb33469` The returned assertion contains a <SubjectConfirmation> with Method=urn:oasis:names:tc:SAML:2.0:cm:bearer.
  - `v-ab995918c2` Additional <SubjectConfirmation> elements MAY be present. Do not mark this as FAIL.
  - `v-4ec5793090` An accompanying assertion without a bearer confirmation MAY be treated as outside the scope of this profile.
- **Controls (negative controls)**:
  - ★ Before the E26 revision, the rule applied to “at least one of the assertions containing an AuthnStatement”. After the revision, it is strengthened to “all consumed assertions”. Evaluate using the errata-applied version.
  - ★ The implementation must be able to detect one that returns only other Methods, such as holder-of-key.
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Prof)**; locator: `4\.1\.4\.2 <Response> Usage||4\.1\.4\.3 <Response> Message Processing Rules`: The corresponding passage before revision (the target rewritten by E26).
- **Reference basis (SAML2Errata)**; locator: `E26: Ambiguities Around Multiple Assertions||E27: `: 『Any assertion issued for consumption using this profile MUST contain a <Subject> element with at least one <SubjectConfirmation> element containing a Method of urn:oasis:names:tc:SAML:2.0:cm:bearer』
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.k</code> details</summary>

- **Required variants**:
  - `v-0623be5814` Recipient exactly matches the ACS URL to which the <Response> was actually delivered.
  - `v-ef4635cfc0` In the variant that switches the ACS, Recipient follows the selected ACS and is not fixed to a default value.
  - `v-3c2ce78583` NotOnOrAfter is present and is later than the response time.
  - `v-fb00db5594` The Address attribute MAY be present or absent. Do not mark this as FAIL.
- **Controls (negative controls)**:
  - An implementation that fills Recipient with a fixed value can be detected only with metadata containing two ACS endpoints.
  - The source text does not specify a “reasonable duration” for NotOnOrAfter. Do not make the relative size of the value a verdict condition, for the same reason as IIP-G01.
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Prof)**; locator: `4\.1\.4\.2 <Response> Usage||4\.1\.4\.3 <Response> Message Processing Rules`: The relevant passage before the revisions (the passage rewritten by E26 and E52).
- **Reference basis (SAML2Errata)**; locator: `E26: Ambiguities Around Multiple Assertions||E27: `: 『At lease one bearer <SubjectConfirmation> element MUST contain a <SubjectConfirmationData> element that itself MUST contain a Recipient attribute containing the service provider's assertion consumer service URL and a NotOnOrAfter attribute』
- **Reference basis (SAML2Errata)**; locator: `E52: Clarification on NotOnOrAfter||E53: `: E52 changes the meaning of NotOnOrAfter from “the period during which the assertion can be delivered” to “the period during which the relying party can validate it.”
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.k1</code> details</summary>

- **Required variants**:
  - `v-98887db35b` The bearer <SubjectConfirmationData> has no @NotBefore.
  - `v-49ce082fdd` <saml:Conditions>/@NotBefore is a different element attribute and MAY be present there. Do not confuse the two.
- **Controls (negative controls)**:
  - Confusing Conditions/@NotBefore with SubjectConfirmationData/@NotBefore either causes a conforming implementation to FAIL or misses a violation. Fix the XPath through the element level.
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Prof)**; locator: `4\.1\.4\.2 <Response> Usage||4\.1\.4\.3 <Response> Message Processing Rules`: “It MUST NOT contain a NotBefore attribute” (unchanged after the E26 revision).
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.k2</code> details</summary>

- **Required variants**:
  - `v-6aea0e46b1` For SP-initiated SSO, bearer <SubjectConfirmationData>/@InResponseTo matches AuthnRequest/@ID.
  - `v-e434d4b28e` Run SSO twice consecutively in the same session; each response matches its corresponding request ID and does not reuse the previous value.
  - `v-3c4f456f9a` The <Response>/@InResponseTo also has the same value.
- **Controls (negative controls)**:
  - Without running two consecutive trials, an implementation that reuses the last ID cannot be detected.
  - For an unsolicited response, switch to IIP-SSO01.y, which prohibits including it.
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Prof)**; locator: `4\.1\.4\.2 <Response> Usage||4\.1\.4\.3 <Response> Message Processing Rules`: “If the containing message is in response to an <AuthnRequest>, then the InResponseTo attribute MUST match the request's ID” (unchanged after the E26 revision).
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.l</code> details</summary>

- **Required variants**:
  - `v-1f7d4375c2` A successful response contains at least one <saml:AuthnStatement>.
  - `v-23564ca63c` @AuthnInstant represents the actual authentication time and is not later than the request time.
  - `v-1e69bc52b4` Multiple <AuthnStatement> elements MAY be present. Do not mark this as FAIL.
- **Controls (negative controls)**:
  - It must be possible to detect an implementation that returns only an AttributeStatement.
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Prof)**; locator: `4\.1\.4\.2 <Response> Usage||4\.1\.4\.3 <Response> Message Processing Rules`: The corresponding passage before revision (the target rewritten by E26).
- **Reference basis (SAML2Errata)**; locator: `E26: Ambiguities Around Multiple Assertions||E27: `: 『The set of one or more bearer assertions MUST contain at least one <AuthnStatement> that reflects the authentication of the principal to the identity provider』
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.l1</code> details</summary>

- **Required variants**:
  - `v-1585b32f4b` For an SLO-capable IdP, <AuthnStatement>/@SessionIndex is present.
  - `v-837c3ac2a1` When multiple <AuthnStatement> elements are present, the attribute exists on all of them, reflecting E26’s “any.”
  - `v-2e48c87091` The SessionIndex value can actually be used in an SLO LogoutRequest, linking this requirement to IIP-IDP17.
- **Controls (negative controls)**:
  - Before the E26 revision, this said “any such authentication statements” (those in assertions with a bearer confirmation); after the revision, it has broadened to “any authentication statements.”
  - If the condition is false (the IdP does not support SLO), the result is NOT_APPLICABLE. However, because IIP-IDP17 makes SLO a MUST for the IdP, the condition being false for an IdP itself indicates a violation of IIP-IDP17.
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Prof)**; locator: `4\.1\.4\.2 <Response> Usage||4\.1\.4\.3 <Response> Message Processing Rules`: The corresponding passage before revision (the target rewritten by E26).
- **Reference basis (SAML2Errata)**; locator: `E26: Ambiguities Around Multiple Assertions||E27: `: 『If the identity provider supports the Single Logout profile ... any authentication statements MUST include a SessionIndex attribute to enable per-session logout requests by the service provider』
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.m</code> details</summary>

- **Required variants**:
  - `v-14d3d5eb46` Each bearer assertion contains a <saml:AudienceRestriction>, and its <saml:Audience> includes the Test Peer’s entityID.
  - `v-94947b0de6` Other <Audience> values MAY also be listed. Do not mark this as FAIL.
  - `v-d5e8690081` When there are multiple assertions, it is included in every bearer assertion.
- **Controls (negative controls)**:
  - A case implemented on the assumption that presence in one assertion is sufficient cannot detect “Each” in the post-E26 revision.
  - Check that Audience exactly matches the entityID. Do not apply normalization such as ignoring a trailing-slash difference.
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Prof)**; locator: `4\.1\.4\.2 <Response> Usage||4\.1\.4\.3 <Response> Message Processing Rules`: The corresponding passage before revision (the target rewritten by E26).
- **Reference basis (SAML2Errata)**; locator: `E26: Ambiguities Around Multiple Assertions||E27: `: “Each bearer assertion MUST contain an <AudienceRestriction> including the service provider's unique identifier as an <Audience>.” Before the revision, this said “The assertion(s) containing a bearer subject confirmation.”
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.n</code> details</summary>

- **Required variants**:
  - `v-6cd66bfef2` A <Response> with a tampered <ds:SignatureValue> is rejected.
  - `v-21454e9e61` An <Assertion> with a tampered <ds:SignatureValue> is rejected.
  - `v-6b4e0c839b` A response whose signed content was tampered with while leaving <ds:Signature> unchanged is rejected.
  - `v-6e61ee7feb` A response whose <ds:Reference>/@URI was changed to another element is rejected.
  - `v-18980ad201` Control: A correctly signed response is accepted.
- **Controls (negative controls)**:
  - Correction: The previous version made “a Response signed with a key absent from the target’s metadata → rejected” a required variant, but this confused it with IIP-SSO01.ai. That concerns signer/key suitability, not cryptographic validity, and is a separate SHOULD (IIP-SSO01.at) in the source text. Accepting a cryptographically valid response signed with an unknown key is not a violation of this MUST.
  - This obligation is to verify signatures that are present, not to require signatures. The latter is IIP-SP13.
  - Use separate cases for Response signatures and Assertion signatures, because some implementations verify only one of them.
  - A control is required. An implementation that rejects everything would appear to satisfy this obligation.
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Prof)**; locator: `4\.1\.4\.3 <Response> Message Processing Rules||4\.1\.4\.4 Artifact-Specific`: 『Regardless of the SAML binding used, the service provider MUST do the following: Verify any signatures present on the assertion(s) or the response』
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.o</code> details</summary>

- **Required variants**:
  - `v-62f92f6bb0` A Response with Recipient changed to a different ACS URL is rejected.
  - `v-afc5a00dda` A Response with Recipient set to an ACS URL belonging to another entity is rejected.
  - `v-b6de81efec` A Response with an empty Recipient is rejected.
  - `v-91c22021a2` Control: A correct Recipient is accepted.
- **Controls (negative controls)**:
  - The strongest variant uses metadata with two ACS endpoints, delivers the response to one, and sets Recipient to the other.
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Prof)**; locator: `4\.1\.4\.3 <Response> Message Processing Rules||4\.1\.4\.4 Artifact-Specific`: 『Verify that the Recipient attribute in the bearer <SubjectConfirmationData> matches the assertion consumer service URL to which the <Response> or artifact was delivered』
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.p</code> details</summary>

- **Required variants**:
  - `v-3c351acbb7` A NotOnOrAfter timestamp earlier than the declared clock-skew allowance T → rejected.
  - `v-aff50e37ad` Bearer <SubjectConfirmationData> missing NotOnOrAfter → rejected (required by IIP-SSO01.k).
  - `v-5d66ebbb8b` Control: NotOnOrAfter within T → accepted (handled the same way as IIP-G01).
- **Controls (negative controls)**:
  - Samlier has no absolute threshold. It uses for verdicts only whether the value lies outside the T declared by the target, following the IIP-G01 decision.
  - ★ If T cannot be declared, the result is not_verified. The inability to configure it is not itself a violation.
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Prof)**; locator: `4\.1\.4\.3 <Response> Message Processing Rules||4\.1\.4\.4 Artifact-Specific`: 『Verify that the NotOnOrAfter attribute in the bearer <SubjectConfirmationData> has not passed, subject to allowable clock skew between the providers』
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.q</code> details</summary>

- **Required variants**:
  - `v-9c255b2c00` InResponseTo containing a different ID → rejected.
  - `v-226fdba69a` SP-initiated response missing InResponseTo → rejected.
  - `v-461d7a65cd` Response reusing the AuthnRequest ID from a previous session → rejected.
  - `v-d7dae24ad6` Unsolicited response containing InResponseTo → rejected.
  - `v-b94df5e935` Control: correct InResponseTo → accepted. Unsolicited response without InResponseTo → accepted.
- **Controls (negative controls)**:
  - ★ This test addresses a representative SAML vulnerability: response substitution. Pair the five variants.
  - ★ Some SPs do not accept unsolicited responses. Have this declared during preflight, and mark the unsolicited variant not_verified when unsupported.
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Prof)**; locator: `4\.1\.4\.3 <Response> Message Processing Rules||4\.1\.4\.4 Artifact-Specific`: 『Verify that the InResponseTo attribute in the bearer <SubjectConfirmationData> equals the ID of its original <AuthnRequest> message, unless the response is unsolicited (see Section 4.1.5), in which case the attribute MUST NOT be present』
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.r</code> details</summary>

- **Required variants**:
  - `v-08ccc8ec43` Assertion with <saml:Conditions>/@NotOnOrAfter in the past → rejected.
  - `v-11dd84b7cc` Assertion with <saml:Conditions>/@NotBefore in the future → rejected.
  - `v-e7099d3d5c` Assertion whose <AudienceRestriction> does not contain the target entityID → rejected.
  - `v-fc07daed04` Control: all assertions valid → accepted.
- **Controls (negative controls)**:
  - ★ The scope of “other respects” is not stated in the source. Limit it to the SAML2Core Conditions processing rules and do not make Samlier-specific additional checks mandatory.
  - ★ Make each variant an independent case, to detect implementations that miss even one of them.
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Prof)**; locator: `4\.1\.4\.3 <Response> Message Processing Rules||4\.1\.4\.4 Artifact-Specific`: 『Verify that any assertions relied upon are valid in other respects』
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.r1</code> details</summary>

- **Required variants**:
  - `v-0be2c992e6` A valid assertion and an invalid assertion included in one Response → do not rely on the invalid assertion.
  - `v-63ce8c0a11` If one bearer <SubjectConfirmation> is valid, that assertion can be confirmed (the first stage of E26).
- **Controls (negative controls)**:
  - ★ The goal is to detect implementations that accept everything when even one item is valid. Detection requires variants mixing valid and invalid items.
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Prof)**; locator: `4\.1\.4\.3 <Response> Message Processing Rules||4\.1\.4\.4 Artifact-Specific`: The corresponding passage before revision (the target rewritten by E26).
- **Reference basis (SAML2Errata)**; locator: `E26: Ambiguities Around Multiple Assertions||E27: `: 『each assertion, if more than one is present, MUST be evaluated independently』
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.s</code> details</summary>

- **Required variants**:
  - `v-892b156269` Response containing an invalid assertion → observe that the assertion is neither retained nor used.
- **Controls (negative controls)**:
  - ★ SHOULD_CLASS. Failure to satisfy it results in WARNING, not FAIL.
  - ★ “Discarding” is not directly observable externally. Determine it from indirect evidence, such as whether attributes are applied; if it cannot be determined, mark it not_verified.
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Prof)**; locator: `4\.1\.4\.3 <Response> Message Processing Rules||4\.1\.4\.4 Artifact-Specific`: 『Any assertion which is not valid, or whose subject confirmation requirements cannot be met SHOULD be discarded』
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.s1</code> details</summary>

- **Required variants**:
  - `v-d4b3f3148b` Response containing only invalid assertions → no session is established.
  - `v-4bc3f90663` Valid and invalid assertions included together → a session is established using only the valid assertion.
- **Controls (negative controls)**:
  - ★ IIP-SSO01.s (discarding) and this obligation (not using) are separate observations. Even if it is not discarded, this obligation is satisfied if it is not used to establish the context.
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Prof)**; locator: `4\.1\.4\.3 <Response> Message Processing Rules||4\.1\.4\.4 Artifact-Specific`: 『... SHOULD NOT be used to establish a security context for the principal』
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.t</code> details</summary>

- **Required variants**:
  - `v-a968b93a3a` Set a short SessionNotOnOrAfter → after that time, reauthentication is required to access protected resources.
  - `v-96bb26b352` When multiple <AuthnStatement> elements exist, the closest SessionNotOnOrAfter is used (E26; SHOULD).
- **Controls (negative controls)**:
  - ★ Automation is difficult because a waiting period is required. By default, use declaration; promote it to automated observation only for targets that can be configured with a short value.
  - ★ SHOULD_CLASS. Failure to satisfy it results in WARNING.
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Prof)**; locator: `4\.1\.4\.3 <Response> Message Processing Rules||4\.1\.4\.4 Artifact-Specific`: 『If an <AuthnStatement> used to establish a security context for the principal contains a SessionNotOnOrAfter attribute, the security context SHOULD be discarded once this time is reached』
- **Reference basis (SAML2Errata)**; locator: `E26: Ambiguities Around Multiple Assertions||E27: `: E26 adds that when multiple <AuthnStatement> elements exist, the SessionNotOnOrAfter closest to the current time should be honored.
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.u</code> details</summary>

- **Required variants**:
  - `v-6419f8b8ea` The ArtifactResolve exchange takes place over TLS.
  - `v-a58d077f79` Mutual authentication is established (through a client certificate or message signature).
  - `v-7d5839ca92` Control: resolution request without mutual authentication → rejected.
- **Controls (negative controls)**:
  - ★ IIP-SSO02 / IIP-SSO03 require only Redirect and POST. Lack of Artifact support is not a violation.
  - ★ “Mutual authentication, integrity protection, and confidentiality” are three conditions. TLS alone does not satisfy mutual authentication.
- **Configuration failure semantics**: `test_precondition`
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Prof)**; locator: `4\.1\.4\.4 Artifact-Specific <Response> Message Processing Rules||4\.1\.4\.5 POST-Specific`: 『the dereferencing of the artifact using the Artifact Resolution profile MUST be mutually authenticated, integrity protected, and confidential』
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.u1</code> details</summary>

- **Required variants**:
  - `v-631b88a792` Send ArtifactResolve as a different entity → rejected.
  - `v-a87f9c7d0e` Control: send it as the legitimate SP → <Response> is returned.
- **Controls (negative controls)**:
  - ★ Use a second Test Peer (secondary_peer) as a separate entity. The IIP-SP05 configuration can be reused.
  - ★ Artifact one-time use is a separate rule in SAML2Core §3.5.3, distinct from the intended-recipient restriction expressly specified by Profile §4.1.4.4. Following the scope boundary that this CP does not recursively incorporate all of §3.5, it is not a verdict target for this obligation.
- **Configuration failure semantics**: `test_precondition`
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Prof)**; locator: `4\.1\.4\.4 Artifact-Specific <Response> Message Processing Rules||4\.1\.4\.5 POST-Specific`: 『The identity provider MUST ensure that only the service provider to whom the <Response> message has been issued is given the message as the result of an <ArtifactResolve> request』
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.v</code> details</summary>

- **Required variants**:
  - `v-4cb999a62d` Individual <Assertion> signature in POST delivery → conforming.
  - `v-946f72e7d5` Response-only signature in POST delivery → conforming (explicitly permitted by E26).
  - `v-aec6b5a023` No signature in POST delivery → violation.
  - `v-d2495f20b5` Only some of multiple assertions signed → violation (“each”).
- **Controls (negative controls)**:
  - ★ Looking only for “the assertion is signed,” as in the pre-revision wording, would mark an otherwise conforming implementation with only a signed Response as FAIL. The evaluation must accept both routes specified by E26.
  - ★ IIP-SSO04 (the ability to support both methods) is a capability obligation; this obligation is the prohibition applicable when POST is used. Do not conflate them.
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Prof)**; locator: `4\.1\.4\.5 POST-Specific Processing Rules||4\.1\.5 Unsolicited Responses`: Pre-revision wording: “the enclosed assertion(s) MUST be signed” (the wording E26 changes).
- **Reference basis (SAML2Errata)**; locator: `E26: Ambiguities Around Multiple Assertions||E27: `: 『each assertion MUST be protected by a digital signature. This can be accomplished by signing each individual <Assertion> element or by signing the <Response> element』
- **Reference basis (SAML2Errata)**; locator: `E93: Mitigation for XML Encryption CBC deficiencies||E94: `: Update 4.1.3.5 to “either the <Response> or the <Assertion> element(s) ... MUST be signed,” retaining the same two routes as E26.
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.w</code> details</summary>

- **Required variants**:
  - `v-db41c38ef8` POST the same Assertion (with the same @ID) twice → the second attempt is rejected
  - `v-24dfacc3f9` POST the same Assertion from a different session and a different browser → it is rejected
  - `v-243e1ecea3` Control: an equivalent Assertion with a changed @ID → it is accepted (confirming that rejection is not based on the content rather than the ID)
  - `v-f5a5c4d27e` Replay after NotOnOrAfter has passed → it is rejected (because IIP-SSO01.p also requires rejection, both reasons apply)
- **Controls (negative controls)**:
  - ★ A control is mandatory. Looking only at “the second attempt is always rejected” cannot distinguish an implementation that accepts only one attempt in the first place.
  - ★ Do not create a variant that changes other content without changing the ID. The signature would be invalidated and rejected for another reason, eliminating its detection power.
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Prof)**; locator: `4\.1\.4\.5 POST-Specific Processing Rules||4\.1\.5 Unsolicited Responses`: 『The service provider MUST ensure that bearer assertions are not replayed, by maintaining the set of used ID values for the length of time for which the assertion would be considered valid based on the NotOnOrAfter attribute in the <SubjectConfirmationData>』
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.x</code> details</summary>

- **Required variants**:
  - `v-8ed1917794` All <Response> messages returned by the target are delivered via POST (or Artifact)
  - `v-f2f92458d1` Even if the metadata's md:AssertionConsumerService includes the Redirect binding, responses are not returned via Redirect
- **Controls (negative controls)**:
  - ★ IIP-SSO03 (POST support for responses) is the capability-side control, while this obligation is the prohibition-side control. Without both, an implementation that can still deliver responses via Redirect passes undetected
  - ★ Passive checking of all Transcript entries is sufficient for observation
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Prof)**; locator: `4\.1\.2 Profile Overview||4\.1\.3 Profile Description`: Step 5: “The HTTP Redirect binding MUST NOT be used, as the response will typically exceed the URL length permitted by most user agents”
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.y</code> details</summary>

- **Required variants**:
  - `v-164adbc03e` IdP-initiated SSO → <Response>/@InResponseTo is absent
  - `v-d6054ed784` Also record that bearer <SubjectConfirmationData>/@InResponseTo is absent (the source uses lowercase “should,” so this is advisory)
- **Controls (negative controls)**:
  - ★ The second instance in the source is lowercase “should,” not an RFC 2119 keyword. Record the presence or absence on the SubjectConfirmationData side as advisory and do not use it for evaluation
  - ★ Counterpart to IIP-SSO01.k2 (must match for SP-initiated SSO). It has meaning only when both are present
  - ★ For an IdP that does not issue unsolicited responses, the condition is false → NOT_APPLICABLE. The opening of §4.1.5 is a MAY
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Prof)**; locator: `4\.1\.5 Unsolicited Responses||4\.1\.6 Use of Metadata`: 『An unsolicited <Response> MUST NOT contain an InResponseTo attribute, nor should any bearer <SubjectConfirmationData> elements contain one』
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.y1</code> details</summary>

- **Required variants**:
  - `v-47224390ed` IdP-initiated SSO → delivery occurs to the ACS with isDefault="true"
  - `v-804c7cc4f1` Change isDefault to a different ACS and retrieve again → the delivery destination changes
- **Controls (negative controls)**:
  - ★ SHOULD_CLASS. Delivery to an ACS other than the default is a WARNING, not a FAIL
  - ★ Metadata containing only one ACS has no detection power
  - ★ Correction: The source text contains a conditional SHOULD, “If metadata ... is used,” and its applicability condition is the conjunction of “issuing an unsolicited response” ∧ “using metadata to determine the ACS.” The previous version conditioned only on the former and therefore imposed the SHOULD on IdPs that determine the ACS by means other than metadata. This was folded into the predicate unsolicited_acs_from_metadata as a conjunction
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Prof)**; locator: `4\.1\.5 Unsolicited Responses||4\.1\.6 Use of Metadata`: 『If metadata as specified in [SAMLMeta] is used, the <Response> or artifact SHOULD be delivered to the <md:AssertionConsumerService> endpoint of the service provider designated as the default』
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.z</code> details</summary>

- **Required variants**:
  - `v-1e58ab9f57` Perform IdP-initiated SSO → a session is established without an AuthnRequest (when supported)
  - `v-e50909aa91` If unsupported, return NOT_SUPPORTED. This is not a conformance violation
- **Controls (negative controls)**:
  - ★ MAY_CLASS. An IdP that does not issue unsolicited responses must not be marked FAIL
  - ★ The observation result for this obligation provides input to the supports_unsolicited_responses condition predicate for IIP-SSO01.y / .y1
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Prof)**; locator: `4\.1\.5 Unsolicited Responses||4\.1\.6 Use of Metadata`: 『An identity provider MAY initiate this profile by delivering an unsolicited <Response> message to a service provider』
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.aa</code> details</summary>

- **Required variants**:
  - `v-8fdd792dfd` A means exists to disable acceptance of unsolicited responses (through a configuration option, policy, or build configuration)
  - `v-bf3889a840` With acceptance disabled, IdP-initiated SSO → not accepted
  - `v-27a878dd4d` An implementation that never accepts unsolicited responses (always disabled) → treat it as satisfied because it fulfills E90’s safety purpose
- **Controls (negative controls)**:
  - ★ The subject of evaluation is the existence of the means to disable acceptance itself (a SHOULD-level capability). There are only the following three branches:
  - (1) No means of disabling it → violated (WARNING because this is SHOULD_CLASS)
  - (2) The means exists, but it cannot be toggled in this Run due to authorization or environmental constraints → not_verified
  - (3) Unsolicited responses are never accepted → satisfied (the safety purpose of E90 is met merely because the disabled state is the default)
  - ★ Correction: The previous version made configuration_failure_semantics a test_precondition, causing even the case where the disabling capability does not exist to fall into not_verified. Because the subject is the capability itself, normative_capability is correct
  - ★ Correction: The previous version placed “acceptance occurs when enabled” as a required variant, but E90 does not impose an obligation to accept unsolicited responses. An implementation that always rejects them is also conformant and cannot be made the subject of a verdict
- **Configuration failure semantics**: `normative_capability`
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Prof)**; locator: `4\.1\.5 Unsolicited Responses||4\.1\.6 Use of Metadata`: §4.1.5 before revision (the section to which E90 adds text)
- **Reference basis (SAML2Errata)**; locator: `E90: RelayState sanitization||E91: `: E90 also adds text to [SAMLProf] §4.1.5: “Service providers SHOULD have a means of disabling the acceptance of unsolicited responses if circumstances warrant.” Because IIP-SSO01 incorporates [SAML2Prof] “as updated by [SAML2Errata],” this addition applies normatively
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.ab</code> details</summary>

- **Required variants**:
  - `v-ffeb6afc87` Put a URL with the javascript: scheme in RelayState → do not transition to that URL
  - `v-14995f6acb` Put a URL with the data: scheme in RelayState → same as above
  - `v-2ad087a496` Put a URL with the file: scheme in RelayState → same as above
  - `v-5d66f9aaea` Put a URL with the vbscript: / about: scheme in RelayState → same as above
- **Controls (negative controls)**:
  - ★ SHOULD_CLASS. The only subject of evaluation is not transitioning to a prohibited scheme
  - ★ Correction: The previous version placed “a URL with an https / http scheme → transition successfully” as a required variant, but E90 does not impose an obligation to accept or transition to RelayState values using http / https. An implementation that accepts no absolute URLs at all, or one that treats RelayState as an opaque token, is also conformant. Transitions using http / https are used only as Suite-side control fixtures (to verify that detection of prohibited schemes is not vacuously satisfied by an implementation that never transitions) and do not affect the target’s verdict
  - ★ If the condition derives_url_from_relaystate is false, NOT_APPLICABLE (it does not apply to implementations that do not derive a URL)
  - ★ The same E90 text, “implementations MUST carefully sanitize the URL schemes,” is an addition to [SAMLBind], and IIP does not reference [SAML2Bind] with errata incorporated; therefore, that MUST is not used for evaluation
  - ★ “protection against unencoded executable content must be applied” uses lowercase “must,” and [SAML2Prof] §1.2 Notation specifies RFC2119 keywords in uppercase; therefore, it is not a normative keyword. Observations of XSS protection are recorded as advisories
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Prof)**; locator: `4\.1\.5 Unsolicited Responses||4\.1\.6 Use of Metadata`: Immediately after the pre-revision §4.1.5 (the location where E90 inserts the new §4.1.6)
- **Reference basis (SAML2Errata)**; locator: `E90: RelayState sanitization||E91: `: The new §4.1.6, “Use of Relay State,” added by E90 to [SAMLProf]: “The URL scheme eventually derived SHOULD be limited to \"https\" or \"http\", and protection against unencoded executable content must be applied”
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.ac</code> details</summary>

- **Required variants**:
  - `v-b5deeee431` Exposure of information unnecessary for restoration: the original URL fragment or query parameters unrelated to the session are included in RelayState → candidate for violated
  - `v-7114a9c96a` Exposure of identifiers: an email address or similar value placed in the original URL is included in RelayState even though it is unnecessary for restoring the navigation → candidate for violated
  - `v-b254b6de3f` Control: only the path of the original resource is present in RelayState → do not determine violated on this basis alone (depending on the state-retention method, it may be the minimum necessary for restoration)
  - `v-65479ca7d2` Control: RelayState is an opaque token → satisfied (although opacity is not required)
- **Controls (negative controls)**:
  - ★ SHOULD_CLASS. The evaluation has three branches:
  - (1) Information unnecessary for restoration is exposed → violated (WARNING because this is SHOULD_CLASS)
  - (2) It cannot be determined whether the contents are the minimum necessary → not_verified
  - (3) The original URL string is merely included → do not determine violated on this basis alone
  - Correction: The previous version required that the original URL, query, and identifiers not appear verbatim, but the source says “as little ... as possible” and does not require complete non-occurrence. Depending on the state-retention method, the minimum necessary path or identifier may be included; therefore, applying the previous rule as written would issue a WARNING for a conforming SP.
  - ★ Determining (1) requires a criterion for what is necessary for restoration. During preflight, require the target to declare its state-retention method (what it places in RelayState); if the declaration conflicts with the observation, return INCONSISTENT. If there is no declaration, fall back to not_verified as in (2).
  - ★ SAML bindings specify that RelayState must be no more than 80 bytes. Looking only at length could incorrectly determine that a value is non-revealing because it is short. Inspect the value itself.
  - ★ “RelayState should be an opaque token” is also a requirement absent from the source, so it was removed from the variant.
  - ★ Correction 2: The previous version returned satisfied_with_note based solely on a declaration that privacy protection was unnecessary. Because that would create a path for passing a SHOULD through self-declaration, the source’s unless clause was moved to the explicit condition predicate relaystate_privacy_required. The exclusion can be made false only through a declaration with a reason, and that Run appears at the top level of the result as “declaration-only exclusion” (docs/03, “Declaration-only exclusions”).
- **Referenced specification**: `SAML2Prof#4.1`
- **Exclusion**: unless the use of the profile does not require such privacy measures
- **Reference basis (SAML2Prof)**; locator: `4\.1\.3\.1 HTTP Request to Service Provider||4\.1\.3\.2 Service Provider Determines Identity Provider`: 『The service provider SHOULD reveal as little of the request as possible in the RelayState value unless the use of the profile does not require such privacy measures』
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.ad</code> details</summary>

- **Required variants**:
  - `v-cdcc2b77e1` The actual HTTP exchange in the request step (delivery of the AuthnRequest) takes place over TLS.
  - `v-1a7534933a` The actual HTTP exchange in the response step (delivery of the <Response>) takes place over TLS.
- **Controls (negative controls)**:
  - ★ SHOULD_CLASS (RECOMMENDED). If TLS is not used, return violated → WARNING
  - ★ Correction 1: The previous version made all SSO/ACS endpoints listed in metadata being HTTPS a required variant, but the source recommends TLS for the HTTP exchanges in this step and does not prohibit unused endpoints listed in metadata. **The assessment target is limited to the actual exchanges appearing in the Transcript.**
  - ★ Correction 2: The previous version treated a non-production configuration as not_verified, but the source contains no such exclusion. Do not create a Samlier-specific exemption (for the same reason as IIP-G01).
  - ★ The source names SSL 3.0 and TLS 1.0, but both are now compromised. Use only “TLS is used” for this assessment, and defer version suitability to IIP-ALG07 (RFC 7457 and current best practices).
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Prof)**; locator: `4\.1\.3\.3 <AuthnRequest> Is Issued by Service Provider||4\.1\.3\.4 Identity Provider Identifies Principal`: “It is RECOMMENDED that the HTTP exchanges in this step be made over either SSL 3.0 [SSL3] or TLS 1.0 [RFC2246] to maintain confidentiality and message integrity” (request step)
- **Reference basis (SAML2Prof)**; locator: `4\.1\.3\.5 Identity Provider Issues <Response> to Service Provider||4\.1\.3\.6 Service Provider Grants`: The same RECOMMENDED guidance is also specified for the response step.
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.ae</code> details</summary>

- **Required variants**:
  - `v-07d7e8e12d` [Precondition] Use a configuration in which all non-interactive means of establishing identity are disabled, including an existing IdP session (cookie), client certificates, Kerberos/integrated authentication, and IP-based authentication.
  - `v-80672b29f0` Under the precondition above, initiate SSO → authentication is requested, or an error <Status> is returned (no successful assertion is returned).
  - `v-488eb16bca` Control: after satisfying the precondition, authenticate correctly → a successful response is returned (to catch implementations that always return an error).
  - `v-db1d370dd5` Control: when the identity cannot be established → an error <Status> is returned and no assertion is included (IIP-SSO01.f).
- **Controls (negative controls)**:
  - ★ Correction: The previous version treated a successful response without an on-screen authentication operation as evidence of violation, but an IdP can establish the principal’s identity through non-interactive means such as an existing session, a client certificate, Kerberos, or integrated authentication. For an ordinary request without ForceAuthn, use of an existing session is also permitted. **BROWSER observations alone cannot establish that the identity was not established, and must not cause a conforming IdP to FAIL.**
  - ★ Therefore, assessment requires a configuration that reliably excludes ambient authentication. Set testability to CONFIG; if the precondition cannot be established, return not_verified(ambient_auth_not_excludable). This is not nonconformance by the target.
  - ★ Correction: The previous version placed “alternative when the precondition cannot be established: confirm by declaration” in a variant while the control said “return not_verified when the precondition cannot be established,” so they were inconsistent. **Do not return satisfied based only on a declaration.** Record the declaration only as evidence/advisory and keep the outcome as not_verified (to avoid an incorrect MUST PASS).
  - ★ The obligation to re-establish authentication using ForceAuthn is IIP-IDP06.a, and the constraint involving IsPassive is IIP-IDP07.a. This obligation is the general rule underlying those requirements.
  - ★ If this obligation alone results in PASS, an implementation that issues an assertion to any arbitrary principal will pass undetected. Pair it with IIP-SSO01.f / .l.
- **Configuration failure semantics**: `test_precondition`
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Prof)**; locator: `4\.1\.3\.4 Identity Provider Identifies Principal||4\.1\.3\.5 Identity Provider Issues <Response>`: 『At any time during the previous step or subsequent to it, the identity provider MUST establish the identity of the principal (unless it returns an error to the service provider)』
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.af</code> details</summary>

- **Required variants**:
  - `v-ccb73ad85b` Across multiple consecutive SSO attempts, @ID is different each time (the same value is not assigned to different objects representing different requests).
  - `v-9a2aad8f85` @ID does not collide across multiple concurrent sessions.
  - `v-b117e71014` The AuthnRequest @ID does not collide with the @ID of any other object issued by the same target.
- **Controls (negative controls)**:
  - ★ A passive always-on check, applied across all cases.
  - ★ The lexical rules for xs:ID are assessed under schema conformance (IIP-SSO01.cg). Do not also count the same lexical violation as a violation of identifier uniqueness.
  - ★ This obligation extends only to not assigning the same identifier to another data object (with negligible probability). Assessment of the probability itself is separated into IIP-SSO01.cd / .ce, the PRNG seed into .cf, and “exactly one declaration per object” into .cc. None can be proven by BROWSER / AUTOMATED observation, so their testability differs.
  - ★ Being sequential by itself is not a violation (the source requires only uniqueness). Record it as an advisory.
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Core)**; locator: `3\.2\.1 Complex Type RequestAbstractType||3\.2\.2 Complex Type StatusResponseType`: This is incorporated by SAML2Prof 4.1.3.3, “The identity provider MUST process the <AuthnRequest> message as described in [SAMLCore],” and 4.1.4.1, “All processing rules are as defined in [SAMLCore].” “An identifier for the request. It is of type xs:ID and MUST follow the requirements specified in Section 1.3.4 for identifier uniqueness”
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.ag</code> details</summary>

- **Required variants**:
  - `v-cd87b3a7f4` AuthnRequest with @Destination set to another IdP’s SSO endpoint → discarded.
  - `v-9273b3fb4c` AuthnRequest with @Destination set to another endpoint of the target (such as SLO) → discarded.
  - `v-278408b491` AuthnRequest with only the host in @Destination changed → discarded.
  - `v-3b0751090c` Control: correct @Destination → accepted.
- **Controls (negative controls)**:
  - ★ A countermeasure against malicious forwarding. Without a control, an implementation that always discards requests would incorrectly receive PASS.
  - ★ The fact that @Destination is Optional does not imply an obligation to accept a message in which it is omitted. When omitted, do not assign a verdict under this obligation; defer to the binding and the target’s policy rules.
  - ★ In the HTTP-Redirect binding, @Destination is covered by the signature. Tampering will also cause rejection due to an invalid signature, so test an unsigned request as well to distinguish the reason.
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Core)**; locator: `3\.2\.1 Complex Type RequestAbstractType||3\.2\.2 Complex Type StatusResponseType`: This is incorporated by SAML2Prof 4.1.3.3, “The identity provider MUST process the <AuthnRequest> message as described in [SAMLCore],” and 4.1.4.1, “All processing rules are as defined in [SAMLCore].” “If it is present, the actual recipient MUST check that the URI reference identifies the location at which the message was received. If it does not, the request MUST be discarded”
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.ah</code> details</summary>

- **Required variants**:
  - `v-effd9b8e5c` The child elements of the target’s <samlp:Extensions> belong to a namespace not defined by SAML.
  - `v-c6eea4c51b` For a target that sends no extensions, the condition is vacuously true.
- **Controls (negative controls)**:
  - ★ A passive, always-on check. Its direction is opposite to IIP-EXT01 (consumption of extensions); this is a rule for the generating side.
  - ★ For a target that sends no extensions, there is no opportunity for observation. Use satisfied_with_note and do not say that it was “verified.”
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Core)**; locator: `3\.2\.1 Complex Type RequestAbstractType||3\.2\.2 Complex Type StatusResponseType`: SAML2Prof 4.1.3.3, “The identity provider MUST process the <AuthnRequest> message as described in [SAMLCore],” and 4.1.4.1, “All processing rules are as defined in [SAMLCore],” incorporate: “SAML extension elements MUST be namespace-qualified in a non-SAML-defined namespace”
- **Reference basis (SAML2Core)**; locator: `3\.2\.2 Complex Type StatusResponseType||3\.2\.2\.1 Element <Status>`: SAML2Prof 4.1.3.5, “The service provider MUST process the <Response> message and any enclosed <Assertion> elements as described in [SAMLCore],” incorporates the same rule on the response side.
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.ai</code> details</summary>

- **Required variants**:
  - `v-d3b6247f4e` An AuthnRequest with <ds:SignatureValue> tampered with → not accepted.
  - `v-371da9bd8e` An AuthnRequest in which only signed content, such as the ACS URL, was tampered with while <ds:Signature> was left unchanged → not accepted.
  - `v-bf406f00d0` An AuthnRequest in which <ds:Reference>/@URI was changed to reference another element → not accepted.
  - `v-ba6442d549` Control: an AuthnRequest with a valid signature → accepted.
- **Controls (negative controls)**:
  - ★ Correction: The previous version made “a request signed with a key not present in the subject’s metadata → not accepted” a required variant, but that concerns signer/key trust evaluation rather than cryptographic validity and is a separate SHOULD (IIP-SSO01.al) in the source. Accepting a cryptographically valid request signed with an unknown key is not a violation of this MUST.
  - ★ The IdP-side obligation corresponding to IIP-SSO01.n (SP-side response-signature verification). IIP has no other requirement covering this.
  - ★ This is not an obligation to reject unsigned requests (WantAuthnRequestsSigned is MAY). It checks only that a signature is verified when one is present.
  - ★ This obligation applies only to XML Signature (<ds:Signature>). The DEFLATE plus query-string signature of the HTTP-Redirect binding is a separate mechanism in [SAML2Bind], not a normative clause of [SAML2Core] incorporated by IIP-SSO01. Observations of Redirect signature verification are recorded as advisory (implementation note: docs/02 §3.5).
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Core)**; locator: `3\.2\.1 Complex Type RequestAbstractType||3\.2\.2 Complex Type StatusResponseType`: It is incorporated by SAML2Prof 4.1.3.3, “The identity provider MUST process the <AuthnRequest> message as described in [SAMLCore],” and 4.1.4.1, “All processing rules are as defined in [SAMLCore].” “If such a signature is used, then the <ds:Signature> element MUST be present, and the SAML responder MUST verify that the signature is valid.”
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.aj</code> details</summary>

- **Required variants**:
  - `v-9536f3446a` The ACS URL, ProviderName, and NameIDPolicy carried in an invalidly signed AuthnRequest are not reflected in the result.
  - `v-64f4214754` No assertion is issued in response to an invalidly signed AuthnRequest.
- **Controls (negative controls)**:
  - ★ IIP-SSO01.ai (the obligation to verify) and this obligation (the obligation not to use the result) are separate observations. Some implementations verify the signature but still use the request contents.
  - ★ Distinguish this from IIP-SSO01.e (not trusting information in an unsigned request beyond advisory use). That concerns the absence of a signature; this concerns a present but invalid signature.
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Core)**; locator: `3\.2\.1 Complex Type RequestAbstractType||3\.2\.2 Complex Type StatusResponseType`: It is incorporated by SAML2Prof 4.1.3.3, “The identity provider MUST process the <AuthnRequest> message as described in [SAMLCore],” and 4.1.4.1, “All processing rules are as defined in [SAMLCore].” “If it is invalid, then the responder MUST NOT rely on the contents of the request and SHOULD respond with an error.”
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.ak</code> details</summary>

- **Required variants**:
  - `v-fa0a99065a` An invalidly signed AuthnRequest → a <Response> containing an error <Status> is returned.
  - `v-336cba9483` Control: no response (timeout) or a 500 error does not satisfy the SHOULD.
- **Controls (negative controls)**:
  - ★ SHOULD_CLASS. Not returning an error is a WARNING, not a FAIL.
  - ★ The response destination is determined according to IIP-IDP05 (acceptable location). The responder must not return the response to the ACS URL carried in the invalidly signed request (IIP-IDP12.b).
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Core)**; locator: `3\.2\.1 Complex Type RequestAbstractType||3\.2\.2 Complex Type StatusResponseType`: It is incorporated by SAML2Prof 4.1.3.3, “The identity provider MUST process the <AuthnRequest> message as described in [SAMLCore],” and 4.1.4.1, “All processing rules are as defined in [SAMLCore].” This is the SHOULD portion of the same text.
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.al</code> details</summary>

- **Required variants**:
  - `v-50a97d82dc` A correctly signed AuthnRequest using another entity’s key (the signature itself is valid) → detect the mismatch between the Issuer and the signer.
  - `v-113fd846d5` Confirm by attestation that the keys used for signature verification are restricted to the Issuer’s metadata.
- **Controls (negative controls)**:
  - ★ “The signature is mathematically valid” and “the signer is the correct signer” are distinct. An implementation that verifies against any trusted key checks only the former.
  - ★ This can be observed automatically by using a request signed with secondary_peer’s key. Fall back to attestation only if that configuration cannot be created.
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Core)**; locator: `3\.2\.1 Complex Type RequestAbstractType||3\.2\.2 Complex Type StatusResponseType`: It is incorporated by SAML2Prof 4.1.3.3, “The identity provider MUST process the <AuthnRequest> message as described in [SAMLCore],” and 4.1.4.1, “All processing rules are as defined in [SAMLCore].” “If it is valid, then the responder SHOULD evaluate the signature to determine the identity and appropriateness of the signer.”
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.am</code> details</summary>

- **Required variants**:
  - `v-d2b592a83d` When the subject sends an AuthnRequest containing an @Consent value indicating that consent was obtained, the request is signed.
  - `v-bad0b73fa6` For a subject that does not send @Consent or sends unspecified, the condition is vacuously true.
- **Controls (negative controls)**:
  - ★ SHOULD_CLASS. The condition is stated in the source (when @Consent indicates that consent was obtained), so do not create a predicate.
  - ★ If there is no opportunity for observation, use satisfied_with_note and do not write that it was verified.
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Core)**; locator: `3\.2\.1 Complex Type RequestAbstractType||3\.2\.2 Complex Type StatusResponseType`: It is incorporated by SAML2Prof 4.1.3.3, “The identity provider MUST process the <AuthnRequest> message as described in [SAMLCore],” and 4.1.4.1, “All processing rules are as defined in [SAMLCore].” “If a Consent attribute is included and the value indicates that some form of principal consent has been obtained, then the request SHOULD be signed.”
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.an</code> details</summary>

- **Required variants**:
  - `v-607bbd98dc` A schema-invalid AuthnRequest (with a required attribute missing) → if a response is returned, it is a SAML <Response> with <StatusCode>/@Value=urn:oasis:names:tc:SAML:2.0:status:Requester.
  - `v-c352789ca1` An AuthnRequest whose Version is not 2.0 → same as above.
  - `v-03a25a2fe3` Control: return status:Responder for the same invalid request → violation.
  - `v-0a264a8f00` Control: not responding (terminating with an HTTP error) is not a violation of this obligation (the source says “if it responds”).
- **Controls (negative controls)**:
  - ★ The source is conditional: “if it responds.” Do not treat no response as a FAIL.
  - ★ Returning an HTML error page is not a SAML response. If the responder responds, check whether it is a SAML <Response>.
  - ★ This overlaps with IIP-IDP05 (issuing a <Response> with an appropriate status code on error), but that is an independent IIP requirement addressed to the IdP, whereas this is a general rule of the incorporated Core. Use a shared fixture in case design, while evaluating each obligation separately.
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Core)**; locator: `3\.2\.1 Complex Type RequestAbstractType||3\.2\.2 Complex Type StatusResponseType`: It is incorporated by SAML2Prof 4.1.3.3, “The identity provider MUST process the <AuthnRequest> message as described in [SAMLCore],” and 4.1.4.1, “All processing rules are as defined in [SAMLCore].” “If a SAML responder deems a request to be invalid according to SAML syntax or processing rules, then if it responds, it MUST return a SAML response message with a <StatusCode> element with the value urn:oasis:names:tc:SAML:2.0:status:Requester.”
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.ao</code> details</summary>

- **Required variants**:
  - `v-ba152f549d` Across multiple consecutive SSO transactions, <Response>/@ID and <Assertion>/@ID are different on every transaction.
  - `v-7abcff8213` <Response>/@ID and the @ID of its enclosed <Assertion> do not have the same value (duplicate assignment to different objects).
  - `v-4e4ecdee00` When a single <Response> contains multiple <Assertion> elements, their @ID values are different.
  - `v-8a978b7c0c` No collision occurs even across multiple concurrent sessions.
- **Controls (negative controls)**:
  - ★ Passive continuous check.
  - ★ The lexical rules for xs:ID are evaluated under schema conformance (IIP-SSO01.dv / .dw). Do not also count the same lexical violation as a violation of identifier uniqueness.
  - ★ Correction: The previous version stated that Assertion/@ID uniqueness was covered by IIP-SSO01.w, but that was inaccurate. IIP-SSO01.w concerns SP-side replay detection and cannot substitute for the obligation that the IdP generate Assertion IDs in accordance with SAML2Core 1.3.4. <Assertion>/@ID is included in this obligation.
  - ★ Probability evaluation is covered by IIP-SSO01.cd / .ce, the PRNG seed by .cf, and “exactly one declaration per object” by .cc.
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Core)**; locator: `3\.2\.2 Complex Type StatusResponseType||3\.2\.2\.1 Element <Status>`: It is incorporated by SAML2Prof 4.1.3.5, “The service provider MUST process the <Response> message and any enclosed <Assertion> elements as described in [SAMLCore].” “An identifier for the response. It is of type xs:ID, and MUST follow the requirements specified in Section 1.3.4 for identifier uniqueness.”
- **Reference basis (SAML2Core)**; locator: `2\.3\.3 Element <Assertion>||2\.3\.4 Element <EncryptedAssertion>`: SAML2Prof 4.1.4, “This profile is based on the Authentication Request protocol defined in [SAMLCore],” and the incorporation clause in 4.1.3.5 bring in the SAML2Core rules for assertion generation and processing. For <Assertion>/@ID, this also includes: “It is of type xs:ID, and MUST follow the requirements specified in Section 1.3.4 for identifier uniqueness.”
- **Reference basis (SAML2Core)**; locator: `1\.3\.4 ID and ID Reference Values||2 SAML Assertions`: It is incorporated by SAML2Prof 4.1.3.5, “The service provider MUST process the <Response> message and any enclosed <Assertion> elements as described in [SAMLCore].” “Any party that assigns an identifier MUST ensure that there is negligible probability that that party or any other party will accidentally assign the same identifier to a different data object.”
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.ap</code> details</summary>

- **Required variants**:
  - `v-009ff56bb3` SP-initiated → <Response>/@InResponseTo matches AuthnRequest/@ID
  - `v-25aa8080b4` Run SSO twice consecutively in the same session; each response matches its corresponding request ID and does not reuse the previous value.
  - `v-cf0b5c08c8` For an SP-initiated flow, it does not return a response lacking @InResponseTo
- **Controls (negative controls)**:
  - ★ IIP-SSO01.k2 concerns bearer <SubjectConfirmationData>/@InResponseTo; this obligation concerns an attribute of the <Response> element. They are in different locations, so check both.
  - ★ The prohibition for unsolicited cases is IIP-SSO01.y.
  - Without running two consecutive trials, an implementation that reuses the last ID cannot be detected.
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Core)**; locator: `3\.2\.2 Complex Type StatusResponseType||3\.2\.2\.1 Element <Status>`: Incorporated through SAML2Prof 4.1.3.5: “The service provider MUST process the <Response> message and any enclosed <Assertion> elements as described in [SAMLCore].” “Otherwise, it MUST be present and its value MUST match the value of the corresponding request's ID attribute.”
- **Reference basis (SAML2Core)**; locator: `3\.2\.1 Complex Type RequestAbstractType||3\.2\.2 Complex Type StatusResponseType`: Incorporated through SAML2Prof 4.1.3.3: “The identity provider MUST process the <AuthnRequest> message as described in [SAMLCore],” and 4.1.4.1: “All processing rules are as defined in [SAMLCore].” “The values of the ID attribute in a request and the InResponseTo attribute in the corresponding response MUST match” (the same rule from the requester’s perspective).
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.aq</code> details</summary>

- **Required variants**:
  - `v-66cde3dc49` <Response> with @Destination set to another ACS of the same target → discarded
  - `v-294bd8d1a0` <Response> with @Destination set to an ACS of a different entity → discarded
  - `v-46978f4bbb` <Response> with only the host in @Destination changed → discarded
  - `v-6055cbf77f` Control: correct @Destination → accepted.
- **Controls (negative controls)**:
  - ★ Protection against malicious forwarding. Similar to IIP-SSO01.o (Recipient matching), but a different element and a different rule. Recipient is the bearer <SubjectConfirmationData>; Destination is a root attribute of <Response>.
  - ★ The fact that @Destination is Optional does not imply an obligation to accept a response that omits it. When it is omitted, do not issue a verdict under this obligation; defer to the binding and the target’s policy rules.
  - ★ In a signed <Response>, @Destination is also covered by the signature. Tampering with it will cause rejection as an invalid signature, so toggle signing on and off to distinguish the reason.
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Core)**; locator: `3\.2\.2 Complex Type StatusResponseType||3\.2\.2\.1 Element <Status>`: Incorporated through SAML2Prof 4.1.3.5: “The service provider MUST process the <Response> message and any enclosed <Assertion> elements as described in [SAMLCore].” “If it is present, the actual recipient MUST check that the URI reference identifies the location at which the message was received. If it does not, the response MUST be discarded.”
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.ar</code> details</summary>

- **Required variants**:
  - `v-13d561d18f` A session is not established from a <Response> with an invalid signature
  - `v-306d6994df` Attributes carried in a <Response> with an invalid signature are not propagated to the target application
- **Controls (negative controls)**:
  - ★ IIP-SSO01.n (performing the verification) and this obligation (not reflecting the result in the verdict) are separate observations.
  - ★ Attribute propagation requires a read-back surface (using the same path as IIP-G02.b). If read-back is unavailable, determine only whether a session was established and record that limitation.
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Core)**; locator: `3\.2\.2 Complex Type StatusResponseType||3\.2\.2\.1 Element <Status>`: Incorporated through SAML2Prof 4.1.3.5: “The service provider MUST process the <Response> message and any enclosed <Assertion> elements as described in [SAMLCore].” “If it is invalid, then the requester MUST NOT rely on the contents of the response and SHOULD treat it as an error.”
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.as</code> details</summary>

- **Required variants**:
  - `v-caf29170b8` Invalidly signed <Response> → the security context is not established
  - `v-f249edda6e` The event is treated as an error, verifiable through any of the following: presentation to the user, an audit log, or an error page.
- **Controls (negative controls)**:
  - ★ SHOULD_CLASS
  - ★ Correction: The previous version made “an error is presented to the user” the satisfaction condition, but the source requires “treat it as an error,” not UI presentation. An implementation that does not establish a session and handles and records it as an internal error is also conformant. Making UI presentation mandatory would impose a WARNING condition stronger than the source.
  - ★ If internal handling cannot be observed, return not_verified. The fact that the security context is not established can be observed automatically, so use that fact in the verdict.
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Core)**; locator: `3\.2\.2 Complex Type StatusResponseType||3\.2\.2\.1 Element <Status>`: Incorporated through SAML2Prof 4.1.3.5: “The service provider MUST process the <Response> message and any enclosed <Assertion> elements as described in [SAMLCore].” The SHOULD portion of the same sentence.
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.at</code> details</summary>

- **Required variants**:
  - `v-c39adf22c5` A <Response> correctly signed with the key of secondary_peer (a different IdP), with the signature itself valid → detect the mismatch between Issuer and signer
  - `v-36df4f88cf` Confirm through a declaration that signature verification keys are restricted to the Issuer’s metadata.
- **Controls (negative controls)**:
  - ★ “The signature is mathematically valid” and “the signer is the correct signer” are distinct. An implementation that verifies using any key in the trust store checks only the former.
  - ★ This can be observed automatically using secondary_peer. Reuse the configuration from IIP-SP05.
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Core)**; locator: `3\.2\.2 Complex Type StatusResponseType||3\.2\.2\.1 Element <Status>`: Incorporated through SAML2Prof 4.1.3.5: “The service provider MUST process the <Response> message and any enclosed <Assertion> elements as described in [SAMLCore].” “If it is valid, then the requester SHOULD evaluate the signature to determine the identity and appropriateness of the signer.”
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.au</code> details</summary>

- **Required variants**:
  - `v-553f2e863d` When the target sends a <Response> with @Consent set to a value indicating that consent was obtained, the <samlp:Response> element itself has a <ds:Signature>.
  - `v-ca279869e6` For a subject that does not send @Consent or sends unspecified, the condition is vacuously true.
- **Controls (negative controls)**:
  - ★ SHOULD_CLASS. The condition is present in the source, so do not create a predicate.
  - ★ Correction: The previous version made “the response (or assertion) is signed” the satisfaction condition, but the source requires a signature on the <Response>. Signing only the assertion does not protect <Response>/@Consent. Use a Response-level signature as the condition for the determination.
  - ★ Therefore, satisfying IIP-SSO01.v (each assertion is protected by a signature when using POST) does not necessarily satisfy this SHOULD. Do not conflate the two.
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Core)**; locator: `3\.2\.2 Complex Type StatusResponseType||3\.2\.2\.1 Element <Status>`: Incorporated through SAML2Prof 4.1.3.5: “The service provider MUST process the <Response> message and any enclosed <Assertion> elements as described in [SAMLCore].” “If a Consent attribute is included and the value indicates that some form of principal consent has been obtained, then the response SHOULD be signed.”
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.av</code> details</summary>

- **Required variants**:
  - `v-aea887bd71` Retrieve the URI of the <GetComplete> issued by the target → the root element is <samlp:IDPList>
  - `v-be54cfa5b6` That <IDPList> does not contain <samlp:GetComplete> (no recursion)
  - `v-8da585b88f` The retrieved <IDPList> contains one or more <samlp:IDPEntry> elements (required by the schema)
- **Controls (negative controls)**:
  - ★ For a target that does not issue <GetComplete>, the condition is false → NOT_APPLICABLE
  - ★ role also includes idp. A proxy IdP may include <IDPList>/<GetComplete> in a new <AuthnRequest> (IIP-SSO01.bc).
  - ★ Correction: The previous version classified all unreachable cases as not_verified, but that would conceal broken URIs. Distinguish them as follows:
  - (1) The Suite has no outbound connectivity / cannot reach the resource because of proxy restrictions → not_verified(suite_egress_restricted)
  - (2) The Suite can reach other hosts, but the URI returns 404, connection refused, or a TLS failure → violated (it does not satisfy “Retrieving the resource ... MUST result in an XML instance”).
  - (3) The resource was retrieved, but it is not XML, its root is not <IDPList>, or it contains <GetComplete> → violated
  - ★ To distinguish (1) and (2), first verify connectivity to a known reachable host during preflight.
  - ★ Retrieve through the Suite’s outbox, with redirect following and the size limit restricted by the Runner.
- **Configuration failure semantics**: `test_precondition`
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Core)**; locator: `3\.4\.1\.3 Element <IDPList>||3\.4\.1\.4 Processing Rules`: Incorporated through SAML2Prof 4.1.3.3: “The identity provider MUST process the <AuthnRequest> message as described in [SAMLCore],” and 4.1.4.1: “All processing rules are as defined in [SAMLCore].” “Retrieving the resource associated with the URI MUST result in an XML instance whose root element is an <IDPList> that does not itself contain a <GetComplete> element.”
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.aw</code> details</summary>

- **Required variants**:
  - `v-b02f725bb7` <Scoping ProxyCount="0"> and the target cannot directly authenticate the presenter → a <Response> is returned, and the top-level <StatusCode>/@Value is urn:oasis:names:tc:SAML:2.0:status:Responder
  - `v-d5b01c2b20` In the same case, the target does not send an AuthnRequest to an upstream IdP and does not return a successful assertion.
  - `v-606d76e124` Control: even with ProxyCount=0, if the target can directly authenticate the presenter, a successful response is acceptable.
  - `v-fa7423ad9d` Control: ProxyCount=1 → proxying is permitted
- **Controls (negative controls)**:
  - ★ Errata E65 replaced the entire previous text. Do not retain the former “ProxyCount=0 MUST NOT proxy” as an independent obligation; determine the required error response when direct authentication is not possible.
  - ★ Because the secondary ProxyCountExceeded response was relaxed to MAY by E65, do not make it a satisfaction condition for this obligation.
  - ★ The test presupposes that a “presenter that cannot be directly authenticated” can be created. If it cannot be created, return not_verified.
- **Configuration failure semantics**: `test_precondition`
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Errata)**; locator: `E65: Second-level StatusCode||E66: `: SAML2Core 3.4.1.5.1 is part of the processing rules for <AuthnRequest> and enters the Web Browser SSO Profile through the incorporation clause in SAML2Prof 4.1.3.3. E65 replaced the former “MUST NOT proxy / secondary ProxyCountExceeded MUST” text with: “Unless the identity provider can directly authenticate the presenter, it MUST return a <Response> message with a top-level <StatusCode> value of ...:Responder.”
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.ax</code> details</summary>

- **Required variants**:
  - `v-98d528b3e5` If an IIP-SSO01.aw error Response contains a secondary <StatusCode>, record its value
  - `v-9af8bc0669` Do not treat the absence of ProxyCountExceeded as a violation
- **Controls (negative controls)**:
  - ★ MAY_CLASS. Errata E65 relaxed the former MUST to MAY. A conforming implementation that omits the secondary code must not be marked FAIL
  - ★ The top-level Responder is evaluated separately as the MUST in IIP-SSO01.aw
- **Configuration failure semantics**: `test_precondition`
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Errata)**; locator: `E65: Second-level StatusCode||E66: `: SAML2Core 3.4.1.5.1 is part of the processing rules for <AuthnRequest> and enters the Web Browser SSO Profile through the incorporation clause in SAML2Prof 4.1.3.3. “MAY return a second-level <StatusCode> value of ...:ProxyCountExceeded”
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.ay</code> details</summary>

- **Required variants**:
  - `v-365371e8a5` The original request’s <RequestedAuthnContext> appears in the new request to the upstream provider with equivalent or greater strictness
  - `v-e07adaa12a` The original request’s ForceAuthn=true also appears as true in the new request
  - `v-8035e74d93` The original request’s IsPassive=true also appears as true in the new request
  - `v-4be4025eac` Control: Only <NameIDPolicy> may be specified freely (the source text explicitly excludes it)
- **Controls (negative controls)**:
  - ★ If <NameIDPolicy> is not excluded, a conforming proxy will be marked FAIL. The source text states that “the proxying provider is free to specify whatever <NameIDPolicy> it wishes”
  - ★ Fix the criteria for determining “equivalent or stricter” element by element. For AuthnContext, compare the comparison method (exact / minimum, etc.) as well
- **Configuration failure semantics**: `test_precondition`
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Core)**; locator: `3\.4\.1\.5\.1 Proxying Processing Rules||3\.5 Artifact Resolution Protocol`: SAML2Core 3.4.1.5.1 is part of the processing rules for <AuthnRequest> and enters the Web Browser SSO Profile through the incorporation clause in SAML2Prof 4.1.3.3. “the proxying identity provider MUST include equivalent or stricter forms of all the information included in the original request (such as authentication context policy)”
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.az</code> details</summary>

- **Required variants**:
  - `v-0ff0dc0d44` For a configuration using a non-SAML upstream provider (OIDC / LDAP / proprietary), verify by declaration how IsPassive=true is conveyed to the upstream provider
  - `v-856e3c2b15` Also verify by declaration that an equivalent mechanism is provided for ForceAuthn=true
- **Controls (negative controls)**:
  - ★ If the upstream provider is non-SAML, Samlier cannot act as the upstream provider and therefore cannot observe this. Limit the check to a declaration
  - ★ Correction: The previous version placed “vacuously true in a configuration that does not use a non-SAML upstream” in the variant, but when the condition is false the result is NOT_APPLICABLE, not “satisfied.” It has been removed
  - ★ If the upstream provider is SAML, the condition is false → NOT_APPLICABLE. Equivalent content is automatically checked by IIP-SSO01.ay
  - ★ The condition predicate proxies_to_non_saml_provider is CLASSIFICATION_BASED. Because the upstream provider’s type does not appear at the protocol level, it can be made false only through a reasoned exclusion declaration
- **Referenced specification**: `SAML2Prof#4.1`
- **Exclusion**: If the authenticating identity provider is not a SAML identity provider
- **Reference basis (SAML2Core)**; locator: `3\.4\.1\.5\.1 Proxying Processing Rules||3\.5 Artifact Resolution Protocol`: SAML2Core 3.4.1.5.1 is part of the processing rules for <AuthnRequest> and enters the Web Browser SSO Profile through the incorporation clause in SAML2Prof 4.1.3.3. “If the authenticating identity provider is not a SAML identity provider, then the proxying provider MUST have some other way to ensure that the elements governing user agent interaction (<IsPassive>, for example) will be honored by the authenticating provider”
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.ba</code> details</summary>

- **Required variants**:
  - `v-7a82cbb983` Original request ProxyCount=3 → the new request to the upstream provider has ProxyCount no greater than 2
  - `v-4453575101` Original request ProxyCount=1 → the new request has ProxyCount=0
  - `v-252a15a5a7` Control: Detect an implementation in which the new request’s ProxyCount is equal to or greater than the original
- **Controls (negative controls)**:
  - ★ “At most one less” means that reducing it by two or more is also conforming. Requiring “exactly one less” would mark a conforming proxy FAIL
  - ★ ProxyCount is an attribute of <Scoping>. Searching for it as an element will not find it
- **Configuration failure semantics**: `test_precondition`
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Core)**; locator: `3\.4\.1\.5\.1 Proxying Processing Rules||3\.5 Artifact Resolution Protocol`: SAML2Core 3.4.1.5.1 is part of the processing rules for <AuthnRequest> and enters the Web Browser SSO Profile through the incorporation clause in SAML2Prof 4.1.3.3. “The new <AuthnRequest> MUST contain a <ProxyCount> attribute with a value of at most one less than the original value”
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.bb</code> details</summary>

- **Required variants**:
  - `v-f6906823d2` AuthnRequest omitting ProxyCount → the new request to the upstream provider contains ProxyCount
- **Controls (negative controls)**:
  - ★ SHOULD_CLASS. The source text does not specify the value’s magnitude, so do not use it for evaluation (check presence only)
- **Configuration failure semantics**: `test_precondition`
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Core)**; locator: `3\.4\.1\.5\.1 Proxying Processing Rules||3\.5 Artifact Resolution Protocol`: SAML2Core 3.4.1.5.1 is part of the processing rules for <AuthnRequest> and enters the Web Browser SSO Profile through the incorporation clause in SAML2Prof 4.1.3.3. “If the original request does not contain a <ProxyCount> attribute, then the new request SHOULD contain a <ProxyCount> attribute”
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.bc</code> details</summary>

- **Required variants**:
  - `v-d47370d147` AuthnRequest containing <IDPList> → the new request to the upstream provider also contains <IDPList>
  - `v-c753e3b555` Control: AuthnRequest not containing <IDPList> → the new request need not contain <IDPList>
- **Controls (negative controls)**:
  - ★ Without a control, it cannot be distinguished from an implementation that always adds <IDPList> (which is not itself a violation, but does not demonstrate dependence on the original request)
- **Configuration failure semantics**: `test_precondition`
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Core)**; locator: `3\.4\.1\.5\.1 Proxying Processing Rules||3\.5 Artifact Resolution Protocol`: SAML2Core 3.4.1.5.1 is part of the processing rules for <AuthnRequest> and enters the Web Browser SSO Profile through the incorporation clause in SAML2Prof 4.1.3.3. “If an <IDPList> was specified in the original request, the new request MUST also contain an <IDPList>”
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.bd</code> details</summary>

- **Required variants**:
  - `v-197a6cd1c6` AuthnRequest containing 3 <IDPEntry> elements (one upstream Samlier-IdP and two unreachable entityIDs) → all 3 remain in the <IDPList> of the new request to the upstream provider
  - `v-f0014b8b32` If any <IDPEntry> elements were added, they are placed at the end (MAY; the source text specifies “to the end”)
  - `v-14b25e14ec` Control: Detect an implementation that “cleans up” and removes unreachable entries
- **Controls (negative controls)**:
  - ★ Essential for detection power: Unless unreachable or unknown <IDPEntry> elements are included, an implementation that removes them cannot be detected
  - ★ Adding entries to the end is permitted. The mere presence of additions must not be marked FAIL
- **Configuration failure semantics**: `test_precondition`
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Core)**; locator: `3\.4\.1\.5\.1 Proxying Processing Rules||3\.5 Artifact Resolution Protocol`: SAML2Core 3.4.1.5.1 is part of the processing rules for <AuthnRequest> and enters the Web Browser SSO Profile through the incorporation clause in SAML2Prof 4.1.3.3. “The proxying identity provider MAY add additional identity providers to the end of the <IDPList>, but MUST NOT remove any from the list”
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.be</code> details</summary>

- **Required variants**:
  - `v-b16b35de81` Original request specifies Format=persistent → the <NameID>/@Format in the assertion returned through the proxy is persistent
  - `v-db097e3a9e` Original request specifies SPNameQualifier → the returned <NameID>/@SPNameQualifier matches
  - `v-71213121df` Even if the upstream provider returns a different Format, the target conforms the response to the original request’s Format
- **Controls (negative controls)**:
  - ★ The proxying version of IIP-IDP10.d (compliance with NameIDPolicy when not proxying). Its purpose is to detect an implementation that simply passes through the upstream provider’s response
  - ★ The strongest variant deliberately makes the upstream Samlier-IdP return a different Format
- **Configuration failure semantics**: `test_precondition`
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Core)**; locator: `3\.4\.1\.5\.1 Proxying Processing Rules||3\.5 Artifact Resolution Protocol`: SAML2Core 3.4.1.5.1 is part of the processing rules for <AuthnRequest> and enters the Web Browser SSO Profile through the incorporation clause in SAML2Prof 4.1.3.3. “The new assertion's <saml:Subject> MUST contain an identifier that satisfies the original requester's preferences, as defined by its <NameIDPolicy> element”
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.bf</code> details</summary>

- **Required variants**:
  - `v-50ed42fd8c` A proxy-mediated assertion contains <saml:AuthenticatingAuthority>
  - `v-64c493d3ee` Its value matches the upstream Samlier-IdP's entityID
  - `v-9a21128a9d` Control: when no proxying occurred (direct authentication), <AuthenticatingAuthority> need not be present
- **Controls (negative controls)**:
  - ★ The presence or absence of this element is evidence, from the Suite's perspective, that proxying occurred. It is also observational material for the supports_authnrequest_proxying predicate
  - ★ The implementation must be detectable when the value is the target's own entityID
- **Configuration failure semantics**: `test_precondition`
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Core)**; locator: `3\.4\.1\.5\.1 Proxying Processing Rules||3\.5 Artifact Resolution Protocol`: SAML2Core 3.4.1.5.1 is part of the processing rules for <AuthnRequest> and enters the Web Browser SSO Profile through the incorporation statement in SAML2Prof 4.1.3.3. “The <saml:AuthnStatement> in the new assertion MUST include a <saml:AuthnContext> element containing a <saml:AuthenticatingAuthority> element referencing the identity provider to which the proxying identity provider referred the presenter”
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.bg</code> details</summary>

- **Required variants**:
  - `v-644ca37a6e` The upstream Samlier-IdP returns an assertion containing one <AuthenticatingAuthority> → that one remains in the target's new assertion, and the element added by the target appears after it
  - `v-f46023d748` The order is preserved (the order of the chain can be inferred)
- **Controls (negative controls)**:
  - ★ SHOULD_CLASS
  - ★ Without checking the order, an implementation that merely includes them as a set cannot be distinguished
- **Configuration failure semantics**: `test_precondition`
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Core)**; locator: `3\.4\.1\.5\.1 Proxying Processing Rules||3\.5 Artifact Resolution Protocol`: SAML2Core 3.4.1.5.1 is part of the processing rules for <AuthnRequest> and enters the Web Browser SSO Profile through the incorporation statement in SAML2Prof 4.1.3.3. “If the original assertion contains <saml:AuthnContext> information that includes one or more <saml:AuthenticatingAuthority> elements, those elements SHOULD be included in the new assertion, with the new element placed after them”
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.bh</code> details</summary>

- **Required variants**:
  - `v-42cea121aa` For a configuration using a non-SAML upstream provider, verify by declaration how the value placed in <AuthenticatingAuthority> is generated
  - `v-b7602c6170` Verify by declaration that the value is distinguishable for each upstream provider
- **Controls (negative controls)**:
  - ★ When the upstream provider is non-SAML, Samlier cannot act as the upstream provider, so this remains a declaration-only check
  - ★ Correction: the variant “vacuously true when no non-SAML upstream is used” was removed. If the condition is false, the result is NOT_APPLICABLE, not satisfied
  - ★ Value consistency is IIP-SSO01.bi; collision avoidance is IIP-SSO01.bj
- **Referenced specification**: `SAML2Prof#4.1`
- **Exclusion**: If the authenticating identity provider is not a SAML identity provider
- **Reference basis (SAML2Core)**; locator: `3\.4\.1\.5\.1 Proxying Processing Rules||3\.5 Artifact Resolution Protocol`: SAML2Core 3.4.1.5.1 is part of the processing rules for <AuthnRequest> and enters the Web Browser SSO Profile through the incorporation statement in SAML2Prof 4.1.3.3. “If the authenticating identity provider is not a SAML provider, then the proxying identity provider MUST generate a unique identifier value for the authenticating provider”
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.bi</code> details</summary>

- **Required variants**:
  - `v-e82fa08833` In a configuration using a non-SAML upstream provider, perform SSO twice and verify through observation or declaration that the <AuthenticatingAuthority> value is the same
- **Controls (negative controls)**:
  - ★ SHOULD_CLASS
  - ★ Agreement across two observations does not prove “temporal consistency.” Automatically detect only clear inconsistencies; the remainder is declaration-only
- **Referenced specification**: `SAML2Prof#4.1`
- **Exclusion**: If the authenticating identity provider is not a SAML identity provider
- **Reference basis (SAML2Core)**; locator: `3\.4\.1\.5\.1 Proxying Processing Rules||3\.5 Artifact Resolution Protocol`: SAML2Core 3.4.1.5.1 is part of the processing rules for <AuthnRequest> and enters the Web Browser SSO Profile through the incorporation statement in SAML2Prof 4.1.3.3. “This value SHOULD be consistent over time across different requests”
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.bj</code> details</summary>

- **Required variants**:
  - `v-069a56c1e2` The generated value does not match any known SAML entityID, including the Test Peer's entityID
  - `v-6ab11bd709` Verify by declaration that the generated value is in URI form and belongs to a namespace managed by the target
- **Controls (negative controls)**:
  - ★ The original text has uppercase MUST followed by lowercase not (the same formatting as IIP-G03.a). Treat it as MUST NOT
  - ★ Non-conflict with “all other SAML providers” cannot be verified in principle. Automatically detect only clear violations (a match with a known entityID); the remainder is declaration-only
- **Referenced specification**: `SAML2Prof#4.1`
- **Exclusion**: If the authenticating identity provider is not a SAML identity provider
- **Reference basis (SAML2Core)**; locator: `3\.4\.1\.5\.1 Proxying Processing Rules||3\.5 Artifact Resolution Protocol`: SAML2Core 3.4.1.5.1 is part of the processing rules for <AuthnRequest> and enters the Web Browser SSO Profile through the incorporation statement in SAML2Prof 4.1.3.3. “The value MUST not conflict with values used or generated by other SAML providers”
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.cc</code> details</summary>

- **Required variants**:
  - `v-2c5a251f72` Within a single XML document, there must not be two or more elements declaring the same xs:ID value (the xs:ID uniqueness constraint).
  - `v-9fee2766e0` A single element must not declare the same identifier in two attributes (a well-formedness and schema constraint).
  - `v-dd5e3ba78e` The document passes XML Schema validation (a duplicate xs:ID appears as a schema violation).
- **Controls (negative controls)**:
  - ★ Correction: The previous version made “<Response> and <Assertion> do not share the same @ID” and “multiple <Assertion> elements do not have the same @ID” variants. Those are separate rules prohibiting the assignment of the same ID to different objects and belong under IIP-SSO01.af / .ao. This obligation means that, for one data object, a declaration that it has a particular identifier occurs exactly once; it is checked as duplicate declarations within the same document, well-formedness, and a schema constraint.
  - ★ A passive always-on check; it must remain valid even when the XML parser does not perform DTD or schema validation.
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Core)**; locator: `1\.3\.4 ID and ID Reference Values||2 SAML Assertions`: It is incorporated by SAML2Prof 4.1.3.3, “The identity provider MUST process the <AuthnRequest> message as described in [SAMLCore],” and 4.1.4.1, “All processing rules are as defined in [SAMLCore].” “Where a data object declares that it has a particular identifier, there MUST be exactly one such declaration.”
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.cd</code> details</summary>

- **Required variants**:
  - `v-d965994336` Verify through declaration the identifier generation method, including random bit length and encoding, and confirm that it is a random value of at least 128 bits.
  - `v-4b9bd01f36` The estimated entropy of the observed identifier set is not less than 128 bits (automatic detection of obvious violations).
  - `v-b55e73062c` Control: detect an implementation that returns identifiers that are obviously too short, such as 8 hexadecimal digits.
- **Controls (negative controls)**:
  - ★ The probability itself cannot be proven from a finite number of observations. It cannot be determined from BROWSER observations, so mark it ATTESTED and automatically detect only obvious violations, such as values that are too short or sequential.
  - ★ The source text gives “MAY be met by encoding a randomly chosen value between 128 and 160 bits” as an example implementation method, but because this is MAY, other methods must not be failed.
  - ★ For a non-random method, such as a sequence or a hash-derived value, the condition is false and the result is NOT_APPLICABLE. IIP-SSO01.af / .ao / .cc still apply unconditionally.
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Core)**; locator: `1\.3\.4 ID and ID Reference Values||2 SAML Assertions`: It is incorporated by SAML2Prof 4.1.3.3, “The identity provider MUST process the <AuthnRequest> message as described in [SAMLCore],” and 4.1.4.1, “All processing rules are as defined in [SAMLCore].” “In the case that a random or pseudorandom technique is employed, the probability of two randomly chosen identifiers being identical MUST be less than or equal to 2^-128.”
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.ce</code> details</summary>

- **Required variants**:
  - `v-b14fe90c79` Verify through declaration that the identifier generation method uses a random value of at least 160 bits.
- **Controls (negative controls)**:
  - ★ SHOULD_CLASS. An implementation using 128–160 bits satisfies MUST (.cd) but does not satisfy this SHOULD, resulting in WARNING.
  - ★ Combining .cd and this obligation into one would either fail a 128-bit implementation or miss implementations that do not reach 160 bits.
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Core)**; locator: `1\.3\.4 ID and ID Reference Values||2 SAML Assertions`: It is incorporated by SAML2Prof 4.1.3.3, “The identity provider MUST process the <AuthnRequest> message as described in [SAMLCore],” and 4.1.4.1, “All processing rules are as defined in [SAMLCore].” “... and SHOULD be less than or equal to 2^-160.”
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.cf</code> details</summary>

- **Required variants**:
  - `v-2c0cfa6774` Verify through a declaration the PRNG seed source, such as the OS CSPRNG.
  - `v-947c80a8cf` Verify through a declaration that two instances cloned from the same image do not produce the same identifier sequence.
- **Controls (negative controls)**:
  - ★ The uniqueness of the seed cannot be observed externally. ATTESTED.
  - The incident in which cloning a container image preserves a fixed seed is real. Include duplicate identifiers across cloned instances as a declaration item.
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Core)**; locator: `1\.3\.4 ID and ID Reference Values||2 SAML Assertions`: This is incorporated by SAML2Prof 4.1.3.3, “The identity provider MUST process the <AuthnRequest> message as described in [SAMLCore],” and 4.1.4.1, “All processing rules are as defined in [SAMLCore].” “A pseudorandom generator MUST be seeded with unique material in order to ensure the desired uniqueness properties between different systems.”
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.cg</code> details</summary>

- **Required variants**:
  - `v-3b173cdc2e` The <samlp:AuthnRequest> sent by the target has an @ID.
  - `v-da465915e3` It has @Version="2.0".
  - `v-a9178fd90c` @IssueInstant is present and uses the UTC representation specified in SAML2Core 1.3.3.
  - `v-719031c07d` Every AuthnRequest passes protocol schema validation.
- **Controls (negative controls)**:
  - ★ Passive continuous check. Apply schema validation to every AuthnRequest in the Transcript.
  - ★ The source of the norm is the schema document, not RFC 2119 wording (SAML2Core 1.1).
  - ★ Correction: The previous version assigned role [idp, sp] to one obligation and mixed the SP’s AuthnRequest, the IdP’s Response, and the IdP’s Assertion as variants. Because variants have no role field, it appeared that G2 would require SP cases to cover IdP-targeted variants as well. The obligations have been separated by role (.cg / .dv / .dw / .dx).
  - ★ An AuthnRequest generated by a proxy IdP for an upstream party is .dx (conditional).
  - ★ Perform schema validation with DTD disabled, consistently with IIP-G03.
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Core)**; locator: `1\.1 Notation||1\.2 Schema Organization and Namespaces`: “In cases of disagreement between the SAML schema documents and schema listings in this specification, the schema documents take precedence.” SAML2Core places the schema documents as the authoritative source for syntax.
- **Reference basis (SAML2P-xsd)**; locator: `<complexType name="RequestAbstractType"||<complexType name="ExtensionsType"`: The use="required" attributes of RequestAbstractType (ID / Version / IssueInstant).
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.dv</code> details</summary>

- **Required variants**:
  - `v-ea7e4a432a` The <samlp:Response> sent by the subject contains all of @ID, @Version="2.0", and @IssueInstant.
  - `v-f5f90eeb58` <samlp:Status> is present, whether the result is success or failure.
  - `v-e5fb34793f` @IssueInstant uses the UTC representation specified in SAML2Core 1.3.3.
  - `v-290fc4299d` Every Response passes protocol-schema validation.
- **Controls (negative controls)**:
  - ★ Passive continuous check.
  - ★ The contents of <Status> (the top-level <StatusCode>/@Value) are specified by IIP-SSO01.ch.
  - ★ The rule for responding when the receiving side receives a syntactically invalid request is specified by IIP-SSO01.an.
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Core)**; locator: `1\.1 Notation||1\.2 Schema Organization and Namespaces`: Same as above. The authoritative syntax is defined in the schema document.
- **Reference basis (SAML2P-xsd)**; locator: `<complexType name="StatusResponseType"||<complexType name="StatusType"`: The required use="required" attribute of StatusResponseType and the required <samlp:Status> element.
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.dw</code> details</summary>

- **Required variants**:
  - `v-97ff0e1966` The <saml:Assertion> sent by the subject contains all of @Version="2.0", @ID, @IssueInstant, and <saml:Issuer>.
  - `v-7b3836b838` <saml:AuthnStatement> contains @AuthnInstant and <saml:AuthnContext>.
  - `v-a0a542eefb` @IssueInstant and @AuthnInstant use the UTC representation specified in SAML2Core 1.3.3.
  - `v-4c7737184d` Every assertion passes assertion-schema validation.
- **Controls (negative controls)**:
  - ★ Passive continuous check.
  - ★ The receiving side's obligation to reject a schema-invalid assertion is specified by IIP-SSO01.cx.
  - An encrypted assertion is validated after decryption.
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Core)**; locator: `1\.1 Notation||1\.2 Schema Organization and Namespaces`: Same as above. The authoritative syntax is defined in the schema document.
- **Reference basis (SAML2-xsd)**; locator: `<complexType name="AssertionType"||<complexType name="SubjectType"`: The required use="required" attributes of AssertionType (Version, ID, and IssueInstant) and the required <saml:Issuer> element.
- **Reference basis (SAML2-xsd)**; locator: `<complexType name="AuthnStatementType"||<complexType name="SubjectLocalityType"`: The required use="required" attribute of AuthnStatementType (AuthnInstant) and the required <saml:AuthnContext> element.
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.dx</code> details</summary>

- **Required variants**:
  - `v-9016e3a912` The AuthnRequest sent by the subject to the upstream Samlier-IdP contains all of @ID, @Version="2.0", and @IssueInstant.
  - `v-d263d8bd47` That AuthnRequest passes protocol-schema validation.
- **Controls (negative controls)**:
  - ★ IIP-SSO01.cg has role sp. Requests generated by a proxy IdP are examined here.
  - ★ The uniqueness of @ID is specified by IIP-SSO01.dr.
- **Configuration failure semantics**: `test_precondition`
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Core)**; locator: `1\.1 Notation||1\.2 Schema Organization and Namespaces`: Same as above. The authoritative syntax is defined in the schema document.
- **Reference basis (SAML2P-xsd)**; locator: `<complexType name="RequestAbstractType"||<complexType name="ExtensionsType"`: The use="required" attributes of RequestAbstractType (ID / Version / IssueInstant).
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.ch</code> details</summary>

- **Required variants**:
  - `v-86bf881f6a` On success, the top-level @Value is urn:oasis:names:tc:SAML:2.0:status:Success.
  - `v-ad1cc31726` On error, the top-level @Value is one of Requester, Responder, or VersionMismatch.
  - `v-a5a5621cd6` Control: A secondary code (such as AuthnFailed) is not placed at the top level.
- **Controls (negative controls)**:
  - ★ The value of the secondary <StatusCode> is unrestricted (the source says “responders MAY omit subordinate status codes”). Evaluate only the top-level code.
  - ★ Placing the secondary code at the top level is a common implementation error. Make it detectable.
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Core)**; locator: `3\.2\.2\.2 Element <StatusCode>||3\.2\.2\.3 Element <StatusMessage>`: This is incorporated by SAML2Prof 4.1.3.5, “The service provider MUST process the <Response> message and any enclosed <Assertion> elements as described in [SAMLCore].” “The value of the topmost <StatusCode> element MUST be from the top-level list provided in this section.”
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.ci</code> details</summary>

- **Required variants**:
  - `v-26e0549240` If the target emits <saml:Statement>, that element has xsi:type.
  - `v-79a9aa95f9` For a target that does not emit <saml:Statement>, this is vacuously true.
- **Controls (negative controls)**:
  - ★ Passive continuous check. <AuthnStatement> / <AttributeStatement> are concrete types and are out of scope.
  - ★ If there is no opportunity for observation, use satisfied_with_note and do not write that it was verified.
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Core)**; locator: `2\.3\.3 Element <Assertion>||2\.3\.4 Element <EncryptedAssertion>`: SAML2Prof 4.1.4, “This profile is based on the Authentication Request protocol defined in [SAMLCore],” and the incorporation wording in 4.1.3.5 bring in SAML2Core rules concerning assertion generation and processing. “An xsi:type attribute MUST be used to indicate the actual statement type.”
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.cj</code> details</summary>

- **Required variants**:
  - `v-f3cd6f133d` In a configuration that returns an assertion with no statements, that assertion has a <saml:Subject>.
  - `v-cf85de5b3a` For an assertion containing statements, the presence of <Subject> is immaterial (IIP-IDP11.a handles a Subject without a NameID).
- **Controls (negative controls)**:
  - ★ In Web Browser SSO, IIP-SSO01.l ensures that there is always at least one <AuthnStatement>, so this obligation has independent significance only for configurations that include an additional assertion.
  - ★ If there is no opportunity for observation, use satisfied_with_note.
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Core)**; locator: `2\.3\.3 Element <Assertion>||2\.3\.4 Element <EncryptedAssertion>`: SAML2Prof 4.1.4, “This profile is based on the Authentication Request protocol defined in [SAMLCore],” and the incorporation wording in 4.1.3.5 bring in SAML2Core rules concerning assertion generation and processing. “An assertion with no statements MUST contain a <Subject> element.”
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.ck</code> details</summary>

- **Required variants**:
  - `v-bb588b83f0` If the target emits <saml:Condition>, that element has xsi:type.
  - `v-9ee813cdc7` For a target that does not emit <saml:Condition>, this is vacuously true.
- **Controls (negative controls)**:
  - ★ Passive continuous check. Unrelated to IIP-SP07 (acceptance decisions based on AuthnContext).
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Core)**; locator: `2\.5\.1 Element <Conditions>||2\.5\.1\.1 General Processing Rules`: SAML2Prof 4.1.4, “This profile is based on the Authentication Request protocol defined in [SAMLCore],” and the incorporation wording in 4.1.3.5 bring in SAML2Core rules concerning assertion generation and processing. “An xsi:type attribute MUST be used to indicate the actual condition type.”
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.cl</code> details</summary>

- **Required variants**:
  - `v-f7b7bd0cec` In a configuration where the target emits <OneTimeUse>, there is only one within each <Conditions>.
  - `v-6caddf82dd` For a target that does not emit <OneTimeUse>, this is vacuously true.
- **Controls (negative controls)**:
  - ★ Because the schema permits multiple occurrences, schema validation cannot detect this. Count the elements.
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Core)**; locator: `2\.5\.1 Element <Conditions>||2\.5\.1\.1 General Processing Rules`: SAML2Prof 4.1.4, “This profile is based on the Authentication Request protocol defined in [SAMLCore],” and the incorporation wording in 4.1.3.5 bring in SAML2Core rules concerning assertion generation and processing. “Although the schema permits multiple occurrences, there MUST be at most one instance of this element” (<OneTimeUse>).
- **Reference basis (SAML2Core)**; locator: `2\.5\.1\.5 Element <OneTimeUse>||2\.5\.1\.6 Element <ProxyRestriction>`: SAML2Prof 4.1.4, “This profile is based on the Authentication Request protocol defined in [SAMLCore],” and the incorporation wording in 4.1.3.5 bring in SAML2Core rules concerning assertion generation and processing. “A SAML authority MUST NOT include more than one <OneTimeUse> element within a <Conditions> element of an assertion.”
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.cm</code> details</summary>

- **Required variants**:
  - `v-8b6b3354fd` In a configuration where the target emits <ProxyRestriction>, there is only one within each <Conditions>.
  - `v-cb28415e24` For a target that does not emit <ProxyRestriction>, this is vacuously true.
- **Controls (negative controls)**:
  - ★ Because the schema permits multiple occurrences, schema validation cannot detect this. Count the elements.
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Core)**; locator: `2\.5\.1 Element <Conditions>||2\.5\.1\.1 General Processing Rules`: SAML2Prof 4.1.4, “This profile is based on the Authentication Request protocol defined in [SAMLCore],” and the incorporation wording in 4.1.3.5 bring in SAML2Core rules concerning assertion generation and processing. “Although the schema permits multiple occurrences, there MUST be at most one instance of this element” (<ProxyRestriction>).
- **Reference basis (SAML2Core)**; locator: `2\.5\.1\.6 Element <ProxyRestriction>||2\.6 Advice`: SAML2Prof 4.1.4, “This profile is based on the Authentication Request protocol defined in [SAMLCore],” and the incorporation wording in 4.1.3.5 bring in SAML2Core rules concerning assertion generation and processing. “A SAML authority MUST NOT include more than one <ProxyRestriction> element within a <Conditions> element of an assertion.”
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.cn</code> details</summary>

- **Required variants**:
  - `v-34daae94f8` In the returned assertion, <Conditions>/@NotBefore < @NotOnOrAfter.
  - `v-79a29bf318` This is vacuously true for a configuration with only one of the attributes and for a configuration with neither.
- **Controls (negative controls)**:
  - ★ Passive continuous check. Perform time comparisons only after normalizing times to UTC.
  - ★ The length of the validity period is not specified in the source and must not be used for evaluation (for the same reason as IIP-G01).
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Core)**; locator: `2\.5\.1\.2 Attributes NotBefore and NotOnOrAfter||2\.5\.1\.3 Element <Condition>`: SAML2Prof 4.1.4, “This profile is based on the Authentication Request protocol defined in [SAMLCore],” and the incorporation wording in 4.1.3.5 bring in SAML2Core rules concerning assertion generation and processing. “If both attributes are present, the value for NotBefore MUST be less than (earlier than) the value for NotOnOrAfter.”
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.co</code> details</summary>

- **Required variants**:
  - `v-4a1c407b28` Invalid: an assertion past <Conditions>/@NotOnOrAfter → rejected
  - `v-56b5dd470a` Invalid: an assertion whose <AudienceRestriction> does not contain the target’s entityID → rejected
  - `v-08f7cf1bcd` Indeterminate: an assertion containing an unknown <saml:Condition> (its xsi:type is not understood) → rejected
  - `v-2152ea8514` Control: all assertions valid → accepted.
- **Controls (negative controls)**:
  - ★ The key to detection power is Indeterminate. An implementation that “ignores unknown conditions because it cannot understand them” violates this MUST. Do not confuse this with IIP-EXT01.b1, which permits ignoring the contents of <Extensions> / <Advice>.
  - ★ IIP-SSO01.r (“verify that it is valid in all other respects”) handles the Invalid side. This obligation concerns the consequence side—rejecting as a result of the evaluation—and explicitly addresses Indeterminate.
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Core)**; locator: `2\.5\.1\.1 General Processing Rules||2\.5\.1\.2 Attributes NotBefore and NotOnOrAfter`: Incorporated through SAML2Prof 4.1.3.5: “The service provider MUST process the <Response> message and any enclosed <Assertion> elements as described in [SAMLCore].” “An assertion that is determined to be Invalid or Indeterminate MUST be rejected by a relying party (within whatever context or profile it was being processed), just as if the assertion were malformed.”
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.cp</code> details</summary>

- **Required variants**:
  - `v-905cbc175f` Include both an <AudienceRestriction> containing the target’s entityID and another <AudienceRestriction> that does not contain it → rejected
  - `v-7dc1d645cc` Control: every <AudienceRestriction> contains the target’s entityID → accepted
  - `v-497279531e` List both a non-matching <Audience> and the target’s entityID in one <AudienceRestriction> → accepted (OR within the same condition)
- **Controls (negative controls)**:
  - ★ Each <AudienceRestriction> is evaluated independently (logical AND). A typical violation is an implementation that accepts the assertion if the target appears in any one of them
  - ★ Multiple <Audience> elements within one <AudienceRestriction> are logical OR. Confusing this produces the opposite misjudgment
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Core)**; locator: `2\.5\.1\.4 Elements <AudienceRestriction> and <Audience>||2\.5\.1\.5 Element <OneTimeUse>`: Incorporated through SAML2Prof 4.1.3.5: “The service provider MUST process the <Response> message and any enclosed <Assertion> elements as described in [SAMLCore].” “Note that multiple <AudienceRestriction> elements MAY be included in a single assertion, and each MUST be evaluated independently.”
- **Reference basis (SAML2Errata)**; locator: `E46: AudienceRestriction Clarifications||E47: `: E46 clarifies that <Audience> elements within one condition are OR, while multiple <AudienceRestriction> elements are AND
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.cq</code> details</summary>

- **Required variants**:
  - `v-58bbc6b01e` Confirm by attestation that an assertion carrying <OneTimeUse> is processed without delay
- **Controls (negative controls)**:
  - ★ SHOULD_CLASS. The source text specifies no threshold for “immediately,” so time must not be used as a decision condition
  - ★ No verifiable observation is available, so this is attestation-only. satisfied applies only when an attestation is provided
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Core)**; locator: `2\.5\.1\.5 Element <OneTimeUse>||2\.5\.1\.6 Element <ProxyRestriction>`: Incorporated through SAML2Prof 4.1.3.5: “The service provider MUST process the <Response> message and any enclosed <Assertion> elements as described in [SAMLCore].” “The <OneTimeUse> element indicates that the assertion SHOULD be used immediately by the relying party.”
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.cr</code> details</summary>

- **Required variants**:
  - `v-b986f6272b` Confirm by attestation that an assertion carrying <OneTimeUse> is not cached or persisted
  - `v-ebde122620` Retransmit the same assertion → it is not accepted (the observation overlaps with replay detection under IIP-SSO01.w)
- **Controls (negative controls)**:
  - ★ Whether it is “not retained” cannot be observed externally. ATTESTED
  - ★ Even if retransmission is rejected, this may be due to replay detection (IIP-SSO01.w). Because it is weak evidence for this obligation, record it together with the attestation
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Core)**; locator: `2\.5\.1\.5 Element <OneTimeUse>||2\.5\.1\.6 Element <ProxyRestriction>`: Incorporated through SAML2Prof 4.1.3.5: “The service provider MUST process the <Response> message and any enclosed <Assertion> elements as described in [SAMLCore].” “… and MUST NOT be retained for future use.”
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.cs</code> details</summary>

- **Required variants**:
  - `v-08f27238bc` Confirm by attestation that an implementation caching assertions excludes those carrying <OneTimeUse>
  - `v-0956d4444d` For an implementation that retains no assertions at all, this is vacuously true
- **Controls (negative controls)**:
  - ★ IIP-SSO01.cr (do not retain) and this obligation (if retained, handle it compliantly) lead to the same conclusion but have different addressees. Because the source text includes both, retain both
  - ★ IIP-SSO01.w (retaining the ID to prevent replay) is distinct from “retaining” under <OneTimeUse>. Recording the ID is not retaining the assertion
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Core)**; locator: `2\.5\.1\.5 Element <OneTimeUse>||2\.5\.1\.6 Element <ProxyRestriction>`: Incorporated through SAML2Prof 4.1.3.5: “The service provider MUST process the <Response> message and any enclosed <Assertion> elements as described in [SAMLCore].” “However, implementations that choose to retain assertions for future use MUST observe the <OneTimeUse> element.”
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.ct</code> details</summary>

- **Required variants**:
  - `v-a41c7e530a` The upstream Samlier-IdP returns an assertion with <ProxyRestriction> → the target does not issue an assertion that violates those restrictions
  - `v-61e325ec8a` Control: an upstream assertion without <ProxyRestriction> → no restrictions are required
- **Controls (negative controls)**:
  - ★ Because Samlier can act as the upstream party, this can be observed automatically. A proxy configuration is assumed
  - ★ Specific violations are subdivided into IIP-SSO01.cu (Count=0), .cv (decrementing Count), and .cw (Audience)
- **Configuration failure semantics**: `test_precondition`
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Core)**; locator: `2\.5\.1\.6 Element <ProxyRestriction>||2\.6 Advice`: SAML2Core 3.4.1.5.1 is part of the processing rules for <AuthnRequest> and enters the Web Browser SSO Profile through the incorporation clause in SAML2Prof 4.1.3.3. “A relying party acting as an asserting party MUST NOT issue an assertion that itself violates the restrictions specified in this condition on the basis of an assertion containing such a condition.”
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.cu</code> details</summary>

- **Required variants**:
  - `v-f31b880b86` The upstream party returns an assertion with <ProxyRestriction Count="0"> → the target does not issue an assertion to the downstream Samlier-SP
  - `v-4058e44d0a` Control: <ProxyRestriction Count="1"> → issuance is permitted
- **Controls (negative controls)**:
  - ★ Without a control, this cannot be distinguished from an implementation that does not proxy at all
  - ★ The alternative behavior when not issuing an assertion (an error response) is not specified by the source text, so it must not be used for the decision
- **Configuration failure semantics**: `test_precondition`
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Core)**; locator: `2\.5\.1\.6 Element <ProxyRestriction>||2\.6 Advice`: SAML2Core 3.4.1.5.1 is part of the processing rules for <AuthnRequest> and enters the Web Browser SSO Profile through the incorporation clause in SAML2Prof 4.1.3.3. “A Count value of zero indicates that a relying party MUST NOT issue an assertion to another relying party on the basis of this assertion.”
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.cv</code> details</summary>

- **Required variants**:
  - `v-771fec6158` Upstream Count="3" → the <ProxyRestriction>/@Count in an assertion issued by the target is at most 2
  - `v-3d78d3d656` Upstream Count="1" → the @Count in an assertion issued by the target is 0
  - `v-74515e6d57` Control: detect an implementation that issues an assertion after dropping <ProxyRestriction>
- **Controls (negative controls)**:
  - ★ Because the requirement is “at most one less,” decreasing the value by two or more is also compliant. It does not require decreasing it by exactly one
  - ★ This is distinct from IIP-SSO01.ba (decrementing ProxyCount in AuthnRequest). That one concerns a request; this one concerns an assertion
- **Configuration failure semantics**: `test_precondition`
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Core)**; locator: `2\.5\.1\.6 Element <ProxyRestriction>||2\.6 Advice`: SAML2Core 3.4.1.5.1 is part of the processing rules for <AuthnRequest> and enters the Web Browser SSO Profile through the incorporation clause in SAML2Prof 4.1.3.3. “If greater than zero, any assertions so issued MUST themselves contain a <ProxyRestriction> element with a Count value of at most one less than this value.”
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.cw</code> details</summary>

- **Required variants**:
  - `v-be75a9e907` [Requirement 1] The upstream party includes an <Audience> (the downstream Samlier-SP’s entityID) in <ProxyRestriction> → the <AudienceRestriction> in an assertion issued by the target contains that value at least once
  - `v-6ff46d0e56` [Requirement 2] The <AudienceRestriction> in an assertion issued by the target contains no <Audience> that was absent from the original <ProxyRestriction>
  - `v-1ae0b9e9da` Control: the upstream <ProxyRestriction> contains no <Audience> elements → no audience restriction is imposed (out of scope for this obligation)
- **Controls (negative controls)**:
  - ★ Correction 1: The previous version stated “do not issue an assertion to a party not included in the original <Audience>,” but the source text directly requires the contents of the issued assertion’s <AudienceRestriction>, not a prohibition on issuance itself. That version imposed a stronger obligation
  - ★ Correction 2: The latter part of the source text, “and no <Audience> elements present that were not in the previous <ProxyRestriction> element,” had not been made a variant. It is now stated explicitly as Requirement 2
  - ★ The source text states, “If no <Audience> elements are specified, then no audience restrictions are imposed,” so a configuration with no <Audience> is out of scope. Test both configurations to confirm the branch
- **Configuration failure semantics**: `test_precondition`
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Core)**; locator: `2\.5\.1\.6 Element <ProxyRestriction>||2\.6 Advice`: SAML2Core 3.4.1.5.1 is part of the processing rules for <AuthnRequest> and enters the Web Browser SSO Profile through the incorporation clause in SAML2Prof 4.1.3.3. “Otherwise, any assertions so issued MUST themselves contain an <AudienceRestriction> element with at least one of the <Audience> elements present in the previous <ProxyRestriction> element, and no <Audience> elements present that were not in the previous <ProxyRestriction> element.”
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.cx</code> details</summary>

- **Required variants**:
  - `v-1786c38e89` An assertion missing @Version → rejected
  - `v-5058c12103` An assertion missing @IssueInstant → rejected
  - `v-9fd04f3723` An assertion missing <saml:Issuer> → rejected
  - `v-21e10ab2f3` An assertion missing <saml:AuthnStatement>/@AuthnInstant → rejected
  - `v-cfe01fea86` An <AuthnStatement> missing <saml:AuthnContext> → rejected
  - `v-d49ef3bd0d` An assertion with @Version="1.1" → rejected
  - `v-a5f87d7e73` Control: an assertion with all required components present → accepted
- **Controls (negative controls)**:
  - ★ This is the receiving-side obligation corresponding to IIP-SSO01.dw (assertion schema compliance on the IdP side)
  - ★ Removing attributes from a signed assertion also breaks its signature. Test an unsigned configuration as well to distinguish “rejected for schema violation” from “rejected for invalid signature”
  - ★ IIP-SSO01.co (rejection of Invalid / Indeterminate) is a consequence of the condition evaluation. The original text, “just as if the assertion were malformed,” links the two.
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Core)**; locator: `2\.5\.1\.1 General Processing Rules||2\.5\.1\.2 Attributes NotBefore and NotOnOrAfter`: This is incorporated by SAML2Prof 4.1.3.5: “The service provider MUST process the <Response> message and any enclosed <Assertion> elements as described in [SAMLCore].” “An assertion that is determined to be Invalid or Indeterminate MUST be rejected by a relying party ..., just as if the assertion were malformed.” This provision presupposes that a malformed assertion is rejected.
- **Reference basis (SAML2-xsd)**; locator: `<complexType name="AssertionType"||<complexType name="SubjectType"`: Required attributes and required elements of AssertionType (omission makes the assertion malformed)
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.cy</code> details</summary>

- **Required variants**:
  - `v-4e2251f09b` <saml:Issuer> (entity Format) has no @NameQualifier / @SPNameQualifier
  - `v-bd3ef612d5` <saml:NameID> with Format=unspecified has no @NameQualifier / @SPNameQualifier
  - `v-ea25a78aa1` Control: for persistent Format, §8.3.7 defines their use, so their presence is permitted (IIP-SSO05.a3)
  - `v-98fe050240` Control: for transient Format, §8.3.8 permits them as MAY, so their presence is permitted
- **Controls (negative controls)**:
  - ★ SHOULD_CLASS. Even when present, this is a WARNING, not a FAIL.
  - ★ A control is mandatory. The presence of these attributes for persistent / transient must not be treated as a violation.
  - ★ Passive continuous check.
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Core)**; locator: `2\.2\.2 Complex Type NameIDType||2\.2\.3 Element <NameID>`: SAML2Core rules concerning assertion generation and processing are incorporated through SAML2Prof 4.1.4, “This profile is based on the Authentication Request protocol defined in [SAMLCore],” and the incorporation language in 4.1.3.5. “The NameQualifier and SPNameQualifier attributes SHOULD be omitted unless the element or format explicitly defines their use and semantics.”
- **Reference basis (SAML2Core)**; locator: `2\.2\.1 Element <BaseID>||2\.2\.2 Complex Type NameIDType`: Through SAML2Prof 4.1.4, “This profile is based on the Authentication Request protocol defined in [SAMLCore],” and the incorporation language in 4.1.3.5, SAML2Core rules concerning assertion generation and processing are included. The same SHOULD also applies to <BaseID>.
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.cz</code> details</summary>

- **Required variants**:
  - `v-6b359dc3cd` There is exactly one identifier directly under <Subject> (consistent with the schema choice constraint)
  - `v-87da200d3e` Semantic check: the identifier (<NameID> / <BaseID> / <EncryptedID>) placed inside <Subject>/<SubjectConfirmation> refers to the same principal as the identifier directly under <Subject>
  - `v-01c6f88a0b` When there are multiple <SubjectConfirmation> elements, their identifiers each refer to the same principal
  - `v-a8c6eb966a` The identifier directly under <Subject> does not conflict with the subject-identifying attribute returned by <AttributeStatement>
  - `v-4c6062ba93` Control: a configuration listing identifiers for the same principal in different Formats is not a violation (treated the same as IIP-SSO01.i2)
- **Controls (negative controls)**:
  - ★ SHOULD_NOT
  - ★ Correction: the previous version made only “there is exactly one identifier element” a variant, but that primarily reflects the schema choice constraint and does not detect the original text’s concern, namely “two or more principals.” A variant examining semantically multiple principals, such as identifiers within <SubjectConfirmation>, has been added.
  - ★ “Is it the same principal?” is not determined by equality of values. Determine whether it corresponds to the single principal that the Suite authenticated.
  - ★ If it cannot be determined, use not_verified. Do not mark it violated based solely on string comparison.
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Core)**; locator: `2\.4\.1 Element <Subject>||2\.4\.1\.1 Element <SubjectConfirmation>`: Through SAML2Prof 4.1.4, “This profile is based on the Authentication Request protocol defined in [SAMLCore],” and the incorporation language in 4.1.3.5, SAML2Core rules concerning assertion generation and processing are included. “A <Subject> element SHOULD NOT identify more than one principal.”
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.da</code> details</summary>

- **Required variants**:
  - `v-d23edc14bb` All undefined attributes of <SubjectConfirmationData> are qualified by non-SAML namespaces
  - `v-1f4523551b` No custom attribute without a namespace is present
- **Controls (negative controls)**:
  - ★ A passive always-on check. Paired with IIP-EXT01.c (undefined attributes on xsd:anyAttribute may be ignored). That concerns receiver-side tolerance; this concerns generator-side prohibition.
  - ★ For a target that emits no extension attributes, this is vacuously true; use satisfied_with_note and do not state that it was “verified.”
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Core)**; locator: `2\.4\.1\.2 Element <SubjectConfirmationData>||2\.4\.1\.3 Complex Type KeyInfoConfirmationDataType`: Through SAML2Prof 4.1.4, “This profile is based on the Authentication Request protocol defined in [SAMLCore],” and the incorporation language in 4.1.3.5, SAML2Core rules concerning assertion generation and processing are included. “SAML extensions MUST NOT add local (non-namespace-qualified) XML attributes or XML attributes qualified by a SAML-defined namespace to the SubjectConfirmationDataType complex type or a derivation of it.”
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.db</code> details</summary>

- **Required variants**:
  - `v-43974d7d64` 【Upper bound】<SubjectConfirmationData>/@NotOnOrAfter ≤ <Conditions>/@NotOnOrAfter
  - `v-1f6a1c03bf` 【Lower bound】<SubjectConfirmationData>/@NotBefore ≥ <Conditions>/@NotBefore (for non-bearer confirmation methods)
  - `v-992698d1e8` Both endpoints are contained within the <Conditions> period
  - `v-98630c1a73` If the assertion has no <Conditions>, or the relevant attributes are absent, this is vacuously true
- **Controls (negative controls)**:
  - ★ SHOULD_CLASS. A passive always-on check.
  - ★ Correction: the previous version checked only the upper bound (@NotOnOrAfter). This obligation concerns general <SubjectConfirmationData>; because confirmation methods other than bearer may have @NotBefore, the lower bound must also be checked.
  - ★ @NotBefore is prohibited for bearer (IIP-SSO01.k1), so in a bearer-only configuration only the upper bound applies
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Core)**; locator: `2\.4\.1\.2 Element <SubjectConfirmationData>||2\.4\.1\.3 Complex Type KeyInfoConfirmationDataType`: Through SAML2Prof 4.1.4, “This profile is based on the Authentication Request protocol defined in [SAMLCore],” and the incorporation language in 4.1.3.5, SAML2Core rules concerning assertion generation and processing are included. “Note that the time period specified by the optional NotBefore and NotOnOrAfter attributes, if present, SHOULD fall within the overall assertion validity period as specified by the <Conditions> element's NotOnOrAfter attribute.”
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.dc</code> details</summary>

- **Required variants**:
  - `v-7dc1919cb3` In a configuration containing a non-bearer <SubjectConfirmation>, @NotBefore < @NotOnOrAfter
  - `v-a2808860a4` NotBefore is prohibited in bearer <SubjectConfirmationData> (IIP-SSO01.k1), so this is vacuously true
- **Controls (negative controls)**:
  - ★ Because Web Browser SSO bearer does not permit @NotBefore, this obligation is meaningful only for configurations that include an additional <SubjectConfirmation>
  - ★ This is a separate element from IIP-SSO01.cn (<Conditions> NotBefore < NotOnOrAfter). Do not confuse them.
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Core)**; locator: `2\.4\.1\.2 Element <SubjectConfirmationData>||2\.4\.1\.3 Complex Type KeyInfoConfirmationDataType`: Through SAML2Prof 4.1.4, “This profile is based on the Authentication Request protocol defined in [SAMLCore],” and the incorporation language in 4.1.3.5, SAML2Core rules concerning assertion generation and processing are included. “If both attributes are present, the value for NotBefore MUST be less than (earlier than) the value for NotOnOrAfter” (for <SubjectConfirmationData>).
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.dd</code> details</summary>

- **Required variants**:
  - `v-2d66b5adcb` When the returned assertion contains <AuthnStatement>, it also contains <Subject>
- **Controls (negative controls)**:
  - ★ Passive, continuously applicable check. Distinct from IIP-IDP11.a (can generate an assertion that does not include NameID in Subject). That check concerns whether <NameID> is present within <Subject>; this one concerns whether <Subject> itself is present
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Core)**; locator: `2\.7\.2 Element <AuthnStatement>||2\.7\.2\.1 Element <SubjectLocality>`: Through SAML2Prof 4.1.4's statement that “This profile is based on the Authentication Request protocol defined in [SAMLCore]” and the incorporation language in 4.1.3.5, the SAML2Core rules concerning assertion generation and processing apply. “Assertions containing <AuthnStatement> elements MUST contain a <Subject> element”
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.de</code> details</summary>

- **Required variants**:
  - `v-1e7a6aa016` SessionIndex does not contain a value that can identify the principal (such as a username, email address, or NameID)
  - `v-7897bc6173` The SessionIndex for the same principal in different sessions is not the same constant (it is not a principal-specific constant)
  - `v-6870b86cc0` Correlation assessment: even if the same value appears at secondary_peer (another SP), it cannot enable correlation if that value is shared by many principals. Confirm the value range and degree of sharing through declaration
  - `v-2ff80d2b10` Control: with method (b) (using the enclosing assertion's @ID), the value differs across SPs. This is also conforming
- **Controls (negative controls)**:
  - ★ SHOULD_NOT. The determination is whether the principal can be correlated, not whether the value differs at another SP
  - ★ Correction: The previous version made “a different SessionIndex is issued for secondary_peer” a required variant, but the method (a) recommended by the source (a small positive integer, a repeated constant) prevents correlation by making the same value shared by many principals, and the value may therefore be equal across SPs. Treating equality as a violation would reject conforming implementations
  - ★ Automatic detection can identify only obvious violations (the principal identifier itself or a principal-specific constant). The degree of sharing within the value range cannot be observed, so it is handled through declaration
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Core)**; locator: `2\.7\.2 Element <AuthnStatement>||2\.7\.2\.1 Element <SubjectLocality>`: Through SAML2Prof 4.1.4's statement that “This profile is based on the Authentication Request protocol defined in [SAMLCore]” and the incorporation language in 4.1.3.5, the SAML2Core rules concerning assertion generation and processing apply. “Accordingly, the value SHOULD NOT be usable to correlate activity by a principal across different session participants”
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.df</code> details</summary>

- **Required variants**:
  - `v-fb9a5f2934` For a configuration using method (a), confirm through declaration the design of the SessionIndex value range (the range and the number of principals per value)
- **Controls (negative controls)**:
  - ★ SHOULD_CLASS. The density of the value range cannot be verified through observation, so it is declaration-only
  - ★ The source provides no threshold for “sufficiently high,” so do not turn it into a numerical condition
  - ★ Correction: This SHOULD is an internal rule of method (a) in the source (a small positive integer, a repeated constant). It does not apply to implementations using method (b) (the enclosing assertion's @ID), so the predicate uses_small_integer_sessionindex was made its condition
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Core)**; locator: `2\.7\.2 Element <AuthnStatement>||2\.7\.2\.1 Element <SubjectLocality>`: Through SAML2Prof 4.1.4's statement that “This profile is based on the Authentication Request protocol defined in [SAMLCore]” and the incorporation language in 4.1.3.5, the SAML2Core rules concerning assertion generation and processing apply. “The SAML authority SHOULD choose the range of values such that the cardinality of any one integer will be sufficiently high to prevent a particular principal's actions from being correlated”
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.dg</code> details</summary>

- **Required variants**:
  - `v-9a83ce42d8` For a configuration using method (a), SessionIndex values for consecutive SSO operations are not sequential
  - `v-b5338a9386` Confirm through declaration the exception for preserving uniqueness in subsequent statements given to the same session participant
- **Controls (negative controls)**:
  - ★ SHOULD_CLASS. Sequential numbering can be detected automatically, but because the source provides an exception for ensuring uniqueness across different sessions with the same session participant, do not mark it violated based solely on automatic detection; combine it with declaration
  - ★ Correction: This SHOULD is also an internal rule of method (a). It does not apply to method (b)
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Core)**; locator: `2\.7\.2 Element <AuthnStatement>||2\.7\.2\.1 Element <SubjectLocality>`: Through SAML2Prof 4.1.4's statement that “This profile is based on the Authentication Request protocol defined in [SAMLCore]” and the incorporation language in 4.1.3.5, the SAML2Core rules concerning assertion generation and processing apply. “The SAML authority SHOULD choose values for SessionIndex randomly from within this range (except when required to ensure unique values for subsequent statements given to the same session participant)”
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.dh</code> details</summary>

- **Required variants**:
  - `v-f9d8069088` In a configuration that returns attributes, an assertion containing <AttributeStatement> contains <Subject>
- **Controls (negative controls)**:
  - ★ Passive continuous check.
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Core)**; locator: `2\.7\.3 Element <AttributeStatement>||2\.7\.3\.1 Element <Attribute>`: Through SAML2Prof 4.1.4's statement that “This profile is based on the Authentication Request protocol defined in [SAMLCore]” and the incorporation language in 4.1.3.5, the SAML2Core rules concerning assertion generation and processing apply. “Assertions containing <AttributeStatement> elements MUST contain a <Subject> element”
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.di</code> details</summary>

- **Required variants**:
  - `v-0013c9fdf7` All undefined attributes of <saml:Attribute> are qualified by non-SAML namespaces
  - `v-bbe4835d55` No custom attribute without a namespace is present
- **Controls (negative controls)**:
  - ★ Passive, continuously applicable check. Distinct from IIP-SP01 (consumption of arbitrary Name / NameFormat); this is a prohibition on the generation side
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Core)**; locator: `2\.7\.3\.1 Element <Attribute>||2\.7\.3\.1\.1 Element <AttributeValue>`: Through SAML2Prof 4.1.4's statement that “This profile is based on the Authentication Request protocol defined in [SAMLCore]” and the incorporation language in 4.1.3.5, the SAML2Core rules concerning assertion generation and processing apply. “SAML extensions MUST NOT add local (non-namespace-qualified) XML attributes or XML attributes qualified by a SAML-defined namespace to the AttributeType complex type or a derivation of it”
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.dj</code> details</summary>

- **Required variants**:
  - `v-571159254b` In a configuration that releases an attribute with no values, <saml:Attribute> contains zero <AttributeValue> elements
  - `v-5a9bb5aba5` Control: for an attribute with a value, <AttributeValue> is present
- **Controls (negative controls)**:
  - ★ Passive, continuously applicable check. A typical violation is an implementation that emits an empty <AttributeValue/>
  - ★ When the value is the empty string, this falls under IIP-SSO01.dk (emit an empty element), not omission. Do not confuse the two
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Core)**; locator: `2\.7\.3\.1 Element <Attribute>||2\.7\.3\.1\.1 Element <AttributeValue>`: Through SAML2Prof 4.1.4's statement that “This profile is based on the Authentication Request protocol defined in [SAMLCore]” and the incorporation language in 4.1.3.5, the SAML2Core rules concerning assertion generation and processing apply. “Within an <AttributeStatement>, if the SAML attribute exists but has no values, then the <AttributeValue> element MUST be omitted”
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.dk</code> details</summary>

- **Required variants**:
  - `v-4a815eec28` In a configuration that releases an attribute value that is the empty string, <AttributeValue/> is emitted as an empty element
- **Controls (negative controls)**:
  - ★ Counterpart to IIP-SSO01.dj (no value → omit the element). Distinguish an empty value from no value
  - ★ Passive continuous check.
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Core)**; locator: `2\.7\.3\.1\.1 Element <AttributeValue>||2\.7\.3\.2 Element <EncryptedAttribute>`: Through SAML2Prof 4.1.4's statement that “This profile is based on the Authentication Request protocol defined in [SAMLCore]” and the incorporation language in 4.1.3.5, the SAML2Core rules concerning assertion generation and processing apply. “If a SAML attribute includes an empty value, such as the empty string, the corresponding <AttributeValue> element MUST be empty (generally this is serialized as <AttributeValue/>)”
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.dl</code> details</summary>

- **Required variants**:
  - `v-46e78dea3d` In a configuration that releases an attribute with a null value, <AttributeValue xsi:nil="true"/> is emitted
  - `v-6e12876e9b` The element is empty (it has neither child nodes nor text)
- **Controls (negative controls)**:
  - ★ Check both that it is an empty element and that it has xsi:nil
  - ★ Vacuously true for targets that do not handle null; satisfied_with_note
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Core)**; locator: `2\.7\.3\.1\.1 Element <AttributeValue>||2\.7\.3\.2 Element <EncryptedAttribute>`: Through SAML2Prof 4.1.4's statement that “This profile is based on the Authentication Request protocol defined in [SAMLCore]” and the incorporation language in 4.1.3.5, the SAML2Core rules concerning assertion generation and processing apply. “If a SAML attribute includes a "null" value, the corresponding <AttributeValue> element MUST be empty and MUST contain the reserved xsi:nil XML attribute with a value of "true" or "1"”
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.dm</code> details</summary>

- **Required variants**:
  - `v-90100b8582` The target's returned <saml:EncryptedAssertion> contains @Type on its <xenc:EncryptedData>
  - `v-efc073ac08` The same applies to configurations that emit <saml:EncryptedID> / <saml:EncryptedAttribute>
- **Controls (negative controls)**:
  - ★ SHOULD_CLASS. Because IIP-IDP09.a requires assertion encryption support, there is an opportunity for observation
  - ★ The correctness of the value is covered by IIP-SSO01.dn
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Core)**; locator: `2\.3\.4 Element <EncryptedAssertion>||2\.4 Subjects`: Through SAML2Prof 4.1.4's statement that “This profile is based on the Authentication Request protocol defined in [SAMLCore]” and the incorporation language in 4.1.3.5, the SAML2Core rules concerning assertion generation and processing apply. For <EncryptedAssertion>, “The Type attribute SHOULD be present”
- **Reference basis (SAML2Core)**; locator: `2\.2\.4 Element <EncryptedID>||2\.2\.5 Element <Issuer>`: Through SAML2Prof 4.1.4's statement that “This profile is based on the Authentication Request protocol defined in [SAMLCore]” and the incorporation language in 4.1.3.5, the SAML2Core rules concerning assertion generation and processing apply. The same SHOULD applies to <EncryptedID>
- **Reference basis (SAML2Core)**; locator: `2\.7\.3\.2 Element <EncryptedAttribute>||2\.7\.4 Element <AuthzDecisionStatement>`: Through SAML2Prof 4.1.4's statement that “This profile is based on the Authentication Request protocol defined in [SAMLCore]” and the incorporation language in 4.1.3.5, the SAML2Core rules concerning assertion generation and processing apply. The same SHOULD applies to <EncryptedAttribute>
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.dn</code> details</summary>

- **Required variants**:
  - `v-d9062efd5e` If @Type is present, its value is http://www.w3.org/2001/04/xmlenc#Element.
  - `v-cb57d8ec3d` Control: detect implementations that use #Content.
- **Controls (negative controls)**:
  - ★ If @Type is absent, it is outside the scope of this obligation (the SHOULD concerning presence is IIP-SSO01.dm)
  - ★ #Content is the form that replaces only the contents of EncryptedData, and is incorrect for SAML encrypted elements
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Core)**; locator: `2\.3\.4 Element <EncryptedAssertion>||2\.4 Subjects`: Through SAML2Prof 4.1.4's statement that “This profile is based on the Authentication Request protocol defined in [SAMLCore]” and the incorporation language in 4.1.3.5, the SAML2Core rules concerning assertion generation and processing apply. For <EncryptedAssertion>, “if present, MUST contain a value of http://www.w3.org/2001/04/xmlenc#Element”
- **Reference basis (SAML2Core)**; locator: `2\.2\.4 Element <EncryptedID>||2\.2\.5 Element <Issuer>`: SAML2Prof 4.1.4's “This profile is based on the Authentication Request protocol defined in [SAMLCore]” and the incorporation clause in 4.1.3.5 bring in the SAML2Core rules concerning assertion generation and processing. The same MUST applies to <EncryptedID>.
- **Reference basis (SAML2Core)**; locator: `2\.7\.3\.2 Element <EncryptedAttribute>||2\.7\.4 Element <AuthzDecisionStatement>`: SAML2Prof 4.1.4's “This profile is based on the Authentication Request protocol defined in [SAMLCore]” and the incorporation clause in 4.1.3.5 bring in the SAML2Core rules concerning assertion generation and processing. The same MUST applies to <EncryptedAttribute>.
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.do</code> details</summary>

- **Required variants**:
  - `v-b849088ad7` Decrypting <saml:EncryptedAssertion> reveals an element of type AssertionType or a type derived from it.
  - `v-94e617d58d` Decrypting <saml:EncryptedID> reveals an element of type NameIDType **or AssertionType**, or of a type derived from BaseIDAbstractType, NameIDType, or AssertionType.
  - `v-3d42b8c329` Decrypting <saml:EncryptedAttribute> reveals an element of type AttributeType or a type derived from it.
  - `v-835366b1ee` Control: do not mark as a violation a configuration that places an assertion inside <EncryptedID>, which the source text explicitly permits.
- **Controls (negative controls)**:
  - ★ Correction: The previous version omitted **AssertionType** from the permitted types for <EncryptedID>. The source text says “an element that has a type of NameIDType or AssertionType, or a type that is derived from BaseIDAbstractType, NameIDType, or AssertionType” and adds that “an entire assertion can be encrypted into this element and used as an identifier.”
  - ★ This can be observed only in a configuration where the Suite holds the decryption key. Have the Test Peer encrypt using the Test Peer's encryption key.
  - ★ If decryption is impossible, return not_verified. This is not nonconformance by the target.
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Core)**; locator: `2\.3\.4 Element <EncryptedAssertion>||2\.4 Subjects`: SAML2Prof 4.1.4's “This profile is based on the Authentication Request protocol defined in [SAMLCore]” and the incorporation clause in 4.1.3.5 bring in the SAML2Core rules concerning assertion generation and processing. “The encrypted content MUST contain an element that has a type of or derived from AssertionType.”
- **Reference basis (SAML2Core)**; locator: `2\.2\.4 Element <EncryptedID>||2\.2\.5 Element <Issuer>`: SAML2Prof 4.1.4's “This profile is based on the Authentication Request protocol defined in [SAMLCore]” and the incorporation clause in 4.1.3.5 bring in the SAML2Core rules concerning assertion generation and processing. <EncryptedID> is derived from NameIDType, AssertionType, or BaseIDAbstractType.
- **Reference basis (SAML2Core)**; locator: `2\.7\.3\.2 Element <EncryptedAttribute>||2\.7\.4 Element <AuthzDecisionStatement>`: SAML2Prof 4.1.4's “This profile is based on the Authentication Request protocol defined in [SAMLCore]” and the incorporation clause in 4.1.3.5 bring in the SAML2Core rules concerning assertion generation and processing. <EncryptedAttribute> is derived from AttributeType.
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.dp</code> details</summary>

- **Required variants**:
  - `v-d7e2bc11e9` Encrypt the same persistent NameID twice → the <xenc:CipherValue> of <saml:EncryptedID> differs each time.
  - `v-2ab1c9b19a` Perform SSO twice consecutively for the same subject and the same SP → the ciphertext differs each time.
  - `v-e09da70cee` Control: if the plaintext differs, the ciphertext naturally differs; this control alone cannot detect deterministic encryption.
- **Controls (negative controls)**:
  - ★ Key to detection power: the **same plaintext** must be encrypted twice to detect deterministic encryption (the same IV or ECB). A transient NameID changes every time, so the plaintext changes. Use a persistent NameID.
  - ★ Correction: The previous version made this a general ciphertext obligation, but this MUST is a **rule placed only on <EncryptedID> (§2.2.4)**. The same sentence does not appear for §2.3.4 <EncryptedAssertion> or §2.7.3.2 <EncryptedAttribute>. The scope has been limited to <EncryptedID>.
  - ★ The uniqueness of ciphertexts for <EncryptedAssertion> / <EncryptedAttribute> is an [XMLEnc] issue and is outside the scope incorporated by IIP-SSO01, so record it as advisory.
  - ★ Treat this as a passive rule. Check each applicable element actually sent by the target, and if none is observed during the Run, return satisfied_with_note (no observation opportunity). **Do not add a condition predicate**: a CAPABILITY_BASED predicate can only create positive evidence and cannot make “does not have the capability” FALSE (a declaration-only false is UNKNOWN), causing unsupported targets to remain not_verified forever. Align the treatment with IIP-SSO01.er and similar obligations.
  - ★ This rule addresses the real vulnerability of IV reuse.
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Core)**; locator: `2\.2\.4 Element <EncryptedID>||2\.2\.5 Element <Issuer>`: SAML2Prof 4.1.4's “This profile is based on the Authentication Request protocol defined in [SAMLCore]” and the incorporation clause in 4.1.3.5 bring in the SAML2Core rules concerning assertion generation and processing. This rule appears only in the <EncryptedID> section: “Encrypted identifiers are intended as a privacy protection mechanism when the plain-text value passes through an intermediary. As such, the ciphertext MUST be unique to any given encryption operation.”
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.dq</code> details</summary>

- **Required variants**:
  - `v-bf3b6a0968` <xenc:EncryptedKey>/@Recipient is present.
  - `v-e3797b5205` Its value matches the entityID of the Test Peer.
- **Controls (negative controls)**:
  - ★ SHOULD_CLASS. The two SHOULDs (presence and value) are combined into one obligation. If it is absent, its value cannot be evaluated, so there is no branch and the result is the same.
  - ★ In a configuration with multiple decryption keys (IIP-SP08.b / IIP-IDP19.b), Recipient provides a clue for key selection.
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Core)**; locator: `2\.3\.4 Element <EncryptedAssertion>||2\.4 Subjects`: SAML2Prof 4.1.4's “This profile is based on the Authentication Request protocol defined in [SAMLCore]” and the incorporation clause in 4.1.3.5 bring in the SAML2Core rules concerning assertion generation and processing: “Each wrapped key SHOULD include a Recipient attribute that specifies the entity for whom the key has been encrypted” and “The value of the Recipient attribute SHOULD be the URI identifier of a SAML system entity.”
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.ds</code> details</summary>

- **Required variants**:
  - `v-6cc094e5e1` In a configuration where the target emits @Address, the IPv4 address uses dotted-decimal notation.
  - `v-7d5195b573` The IPv6 address uses RFC 3513 notation, including compressed forms.
  - `v-bb1c8d741e` Vacuously true for a target that does not emit @Address.
- **Controls (negative controls)**:
  - ★ SHOULD_CLASS. @Address itself is MAY, so omitting it is not a violation.
  - ★ Both <SubjectConfirmationData>/@Address and <SubjectLocality>/@Address are covered. Because the rule is the same, they are combined into one obligation, with the basis drawn from two locations.
  - ★ Passive continuous check.
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Core)**; locator: `2\.4\.1\.2 Element <SubjectConfirmationData>||2\.4\.1\.3 Complex Type KeyInfoConfirmationDataType`: SAML2Prof 4.1.4's “This profile is based on the Authentication Request protocol defined in [SAMLCore]” and the incorporation clause in 4.1.3.5 bring in the SAML2Core rules concerning assertion generation and processing. For <SubjectConfirmationData>/@Address: “IPv4 addresses SHOULD be represented in the usual dotted-decimal format” and “IPv6 addresses SHOULD be represented as defined by Section 2.2 of IETF RFC 3513.”
- **Reference basis (SAML2Core)**; locator: `2\.7\.2\.1 Element <SubjectLocality>||2\.7\.2\.2 Element <AuthnContext>`: SAML2Prof 4.1.4's “This profile is based on the Authentication Request protocol defined in [SAMLCore]” and the incorporation clause in 4.1.3.5 bring in the SAML2Core rules concerning assertion generation and processing. The same two SHOULDs apply to <SubjectLocality>/@Address.
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.du</code> details</summary>

- **Required variants**:
  - `v-7e7e399ffb` In a configuration that releases a multi-valued attribute (for example, two values for eduPersonAffiliation), there is one <AttributeValue> per value.
  - `v-0518f9802a` Multiple values are not packed into a single <AttributeValue> using delimiters such as semicolons or commas.
  - `v-bf3b7ebf20` For a single-valued attribute, there is exactly one <AttributeValue> (vacuously true).
- **Controls (negative controls)**:
  - ★ SHOULD_CLASS (RECOMMENDED). Packing values with delimiters is a WARNING, not a FAIL.
  - ★ Passive, always-on check. For targets that cannot release multi-valued attributes, there is no observation opportunity, so return satisfied_with_note and do not state that it was “verified.”
  - ★ The statement in the same section that “if multiple <AttributeValue> elements have xsi:type, all must have the same type” uses lowercase “must” and is not an RFC 2119 keyword, so record it as advisory.
  - ★ Do not confuse this with IIP-SSO01.dj (no value → omit the element) / .dk (empty value → empty element).
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Core)**; locator: `2\.7\.3\.1 Element <Attribute>||2\.7\.3\.1\.1 Element <AttributeValue>`: SAML2Prof 4.1.4's “This profile is based on the Authentication Request protocol defined in [SAMLCore]” and the incorporation clause in 4.1.3.5 bring in the SAML2Core rules concerning assertion generation and processing: “If an attribute contains more than one discrete value, it is RECOMMENDED that each value appear in its own <AttributeValue> element.”
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.dy</code> details</summary>

- **Required variants**:
  - `v-d6e3c96d7a` Method (a): SessionIndex is selected from a set of small positive integers and repeating constants.
  - `v-2aed0f0d69` Method (b): SessionIndex matches the enclosing <saml:Assertion>/@ID.
  - `v-eafd71a824` Confirm through attestation and observation that one of the methods is used.
- **Controls (negative controls)**:
  - ★ SHOULD_CLASS (RECOMMENDED). Either method is conformant; WARNING is returned when neither method is used.
  - ★ Method (b) can be determined automatically (SessionIndex == Assertion/@ID). Method (a) requires an attestation.
  - ★ The purpose is IIP-SSO01.de (preventing correlation). This obligation recommends methods for achieving that purpose and must not return FAIL when an implementation prevents correlation by a third method. In that case, if de is satisfied, this obligation is satisfied_with_note.
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Core)**; locator: `2\.7\.2 Element <AuthnStatement>||2\.7\.2\.1 Element <SubjectLocality>`: SAML2Prof 4.1.4 states that “This profile is based on the Authentication Request protocol defined in [SAMLCore]”; together with the incorporation language in 4.1.3.5, this incorporates SAML2Core rules concerning assertion generation and processing. “Two solutions that achieve this goal are provided below and are RECOMMENDED”: (a) use a small positive integer and a repeating constant, or (b) use the enclosing assertion's @ID.
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.dz</code> details</summary>

- **Required variants**:
  - `v-7dcf73a7c6` The element content and attribute values of type xs:string in all messages and assertions sent by the subject are neither empty nor whitespace-only.
  - `v-e220b8f45f` An empty <saml:AttributeValue> is an exception (IIP-SSO01.dk explicitly requires an empty element).
- **Controls (negative controls)**:
  - ★ Passive continuous check.
  - ★ Exclude cases where the source text's “Unless otherwise noted” applies. Empty and null <AttributeValue> values (IIP-SSO01.dk / .dl) are covered. If the exclusion is not stated explicitly, the empty elements required by the source text would incorrectly be treated as violations.
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Core)**; locator: `1\.3\.1 String Values||1\.3\.2 URI Values`: The common data-type rules in SAML2Core 1.3 apply to all xs:string, xs:anyURI, and xs:dateTime values in messages and assertions, and therefore enter through both incorporation clauses. “Unless otherwise noted in this specification or particular profiles, all strings in SAML messages MUST consist of at least one non-whitespace character.”
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.ea</code> details</summary>

- **Required variants**:
  - `v-80bee84836` Confirm through attestation that entityID, NameID, and attribute values are compared byte-for-byte.
  - `v-31fd6ce140` Treat metadata with entityIDs differing only in case as separate entities, where this can be observed automatically.
- **Controls (negative controls)**:
  - ★ The comparison method is internal processing and is therefore ATTESTED in principle. Observable consequences are separated under IIP-SSO01.eb.
  - ★ This is opposite in direction to IIP-IDP21.a, which concerns a deployment that does not assign identifiers differing only in case to separate entities. That requirement concerns operational deployment; this one concerns the implementation's comparison method.
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Core)**; locator: `1\.3\.1 String Values||1\.3\.2 URI Values`: The common data-type rules in SAML2Core 1.3 apply to all xs:string, xs:anyURI, and xs:dateTime values in messages and assertions, and therefore enter through both incorporation clauses. “All elements in SAML documents that have the XML Schema xs:string type, or a type derived from that, MUST be compared using an exact binary comparison.”
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.eb</code> details</summary>

- **Required variants**:
  - `v-32297bca29` Persistent NameID with changed case → treated as a different subject (not equivalent).
  - `v-e1152fb335` entityID with trailing whitespace appended → does not match (not trimmed).
  - `v-9c38b3050e` Whitespace before and after an attribute value is preserved.
  - `v-7377018379` Control: an exactly matching value → matches.
- **Controls (negative controls)**:
  - ★ The observable consequence of IIP-SSO01.ea (the comparison method itself). This can be determined automatically.
  - ★ XML attribute-value normalization (XML 3.3.3) is performed by the XML parser and is distinct from this obligation's “trimming.” Comparison is performed on values after XML parsing (handled the same way as IIP-G02.a).
  - ★ An implementation that treats case variants as equivalent directly enables account takeover. Use it as a candidate mutant SUT.
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Core)**; locator: `1\.3\.1 String Values||1\.3\.2 URI Values`: The common data-type rules in SAML2Core 1.3 apply to all xs:string, xs:anyURI, and xs:dateTime values in messages and assertions, and therefore enter through both incorporation clauses. “In particular, SAML implementations and deployments MUST NOT depend on case-insensitive string comparisons, normalization or trimming of whitespace, or conversion of locale-specific formats such as numbers or currency.”
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.ec</code> details</summary>

- **Required variants**:
  - `v-4318176311` Confirm by declaration whether there is a path that compares inputs in different encodings (such as UTF-8 / UTF-16), and what comparison method it uses.
  - `v-7038a80c14` When identifiers containing combining characters (represented differently in NFC and NFD) are sent, the result is the same as NFC normalization plus binary comparison: values that should match match, and values that should not match do not match.
- **Controls (negative controls)**:
  - ★ This is an internal comparison method, so it is ATTESTED. It can share observations with the IIP-G02.a variant for “combining characters (whose length changes under normalization)”.
  - ★ Correction: The previous version stated that “an implementation that normalizes to NFD is non-compliant,” but the source requires a method that returns the same result as NFC plus binary comparison, not a particular internal normalization form. Internal NFD normalization is not non-compliant if the comparison result is the same. The determination is based on result equivalence.
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Core)**; locator: `1\.3\.1 String Values||1\.3\.2 URI Values`: The common data-type rules in SAML2Core 1.3 apply to all xs:string / xs:anyURI / xs:dateTime values in messages and assertions, and therefore enter through both intake clauses. “If an implementation is comparing values that are represented using different character encodings, the implementation MUST use a comparison method that returns the same result as converting both values to the Unicode character encoding, Normalization Form C [UNICODE-C], and then performing an exact binary comparison”.
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.ed</code> details</summary>

- **Required variants**:
  - `v-46583a3483` Confirm by declaration that, in a path matching element content containing line breaks against external data such as LDAP, XML end-of-line normalization (CRLF → LF, [XML] 2.11) is taken into account.
  - `v-0ca3520117` Confirm by declaration that the replacement of TAB / line breaks in XML attribute values with whitespace ([XML] 3.3.3) is taken into account.
  - `v-a3535abd71` As a result, the SAML-side value and the external data are matched correctly.
- **Controls (negative controls)**:
  - ★ Matching against external data cannot be observed by the Suite. ATTESTED.
  - ★ Correction: The previous version said “confirm that it does not assume replacement with whitespace,” which reversed the intended direction. The obligation is to take normalization into account, not to avoid assuming that normalization occurs.
  - ★ This addresses the same phenomenon as IIP-G02.a: literal TAB/LF characters become whitespace through XML attribute-value normalization.
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Core)**; locator: `1\.3\.1 String Values||1\.3\.2 URI Values`: The common data-type rules in SAML2Core 1.3 apply to all xs:string / xs:anyURI / xs:dateTime values in messages and assertions, and therefore enter through both intake clauses. “Applications that compare data received in SAML documents to data from external sources MUST take into account the normalization rules specified for XML”.
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.ee</code> details</summary>

- **Required variants**:
  - `v-468ef19957` Confirm by declaration that processing of sets of values does not depend on locale-dependent collation order, including case order, accent order, or language-specific ordering.
  - `v-d193729e19` Confirm by declaration that the same input produces the same result even when the locale settings are changed.
  - `v-3bcc23e26a` An implementation that does not perform collation or sorting in the first place satisfies this obligation.
- **Controls (negative controls)**:
  - ★ Correction: The previous version made “using only the first <AttributeValue>” and “reordering document order” variants, but the source prohibits dependence on collation or sorting orders that vary by locale and similar settings, not dependence on ordering within the XML document. An implementation that performs no sorting at all could otherwise have been incorrectly treated as non-compliant.
  - ★ The source does not specify whether dependence on document order is problematic. Do not use it for the determination; record it as an advisory.
  - ★ Locale-dependent collation order cannot be observed by the Suite, so it is ATTESTED.
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Core)**; locator: `1\.3\.1 String Values||1\.3\.2 URI Values`: The common data-type rules in SAML2Core 1.3 apply to all xs:string / xs:anyURI / xs:dateTime values in messages and assertions, and therefore enter through both intake clauses. “SAML implementations MUST NOT depend on specific sorting orders for values, because these can differ depending on the locale settings of the hosts involved”.
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.ef</code> details</summary>

- **Required variants**:
  - `v-8d63690680` All entityID / Format / StatusCode/@Value / AuthnContextClassRef / Destination / AssertionConsumerServiceURL values sent by the target are absolute URIs.
  - `v-fd1faaaf49` There are no empty or whitespace-only URI values.
  - `v-60023c6731` Relative URIs, such as /acs, are not used.
- **Controls (negative controls)**:
  - ★ Passive continuous check. Schema xs:anyURI also accepts relative URIs, so this cannot be detected through schema validation.
  - ★ The same-document reference (#foo) in <ds:Reference>/@URI is governed by XML Signature and is not an element or attribute defined by SAML, so it is out of scope here (IIP-SSO01.ev handles it separately).
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Core)**; locator: `1\.3\.2 URI Values||1\.3\.3 Time Values`: The common data-type rules in SAML2Core 1.3 apply to all xs:string / xs:anyURI / xs:dateTime values in messages and assertions, and therefore enter through both intake clauses. “Unless otherwise indicated in this specification, all URI reference values used within SAML-defined elements or attributes MUST consist of at least one non-whitespace character, and are REQUIRED to be absolute [RFC 2396]”.
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.eg</code> details</summary>

- **Required variants**:
  - `v-e23a616fad` IssueInstant / AuthnInstant / NotBefore / NotOnOrAfter / SessionNotOnOrAfter / validUntil are all represented in UTC notation with a trailing Z.
  - `v-b193b5540c` There are no representations with offsets such as +09:00.
  - `v-97badf6ad5` There are no bare representations without a time-zone designation.
- **Controls (negative controls)**:
  - ★ Passive continuous check. Schema xs:dateTime also accepts values with offsets, so this cannot be detected through schema validation.
  - ★ Separate from IIP-G01 (clock skew). That obligation concerns interpretation of values; this one concerns the representation format.
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Core)**; locator: `1\.3\.3 Time Values||1\.3\.4 ID and ID Reference Values`: The common data-type rules in SAML2Core 1.3 apply to all xs:string / xs:anyURI / xs:dateTime values in messages and assertions, and therefore enter through both intake clauses. “All SAML time values have the type xs:dateTime ... and MUST be expressed in UTC form, with no time zone component”.
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.eh</code> details</summary>

- **Required variants**:
  - `v-bb07801679` Confirm by declaration that time comparison does not treat precision finer than milliseconds as significant.
  - `v-cee05ad2d8` Even when a time with digits finer than microseconds is sent, processing does not change, where this can be observed automatically.
- **Controls (negative controls)**:
  - ★ SHOULD_NOT. The requirement is not “do not generate” but “do not rely on,” so emitting more precise fractional digits is not itself non-compliant.
  - ★ This could be upgraded to automatic observation by sending a time with microsecond digits from the Suite and checking whether behavior changes.
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Core)**; locator: `1\.3\.3 Time Values||1\.3\.4 ID and ID Reference Values`: The common data-type rules in SAML2Core 1.3 apply to all xs:string / xs:anyURI / xs:dateTime values in messages and assertions, and therefore enter through both intake clauses. “SAML system entities SHOULD NOT rely on time resolution finer than milliseconds”.
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.ei</code> details</summary>

- **Required variants**:
  - `v-a6a8879523` The seconds component of every time value sent by the target is never 60 or greater; there are no :60 or :61 values.
- **Controls (negative controls)**:
  - ★ Passive continuous check. The xs:dateTime schema permits second 60, so this cannot be detected through schema validation.
  - ★ This cannot naturally be observed unless it is the date on which a leap second occurs, but it runs for every Run as a continuous check on the generating side.
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Core)**; locator: `1\.3\.3 Time Values||1\.3\.4 ID and ID Reference Values`: The common data-type rules in SAML2Core 1.3 apply to all xs:string / xs:anyURI / xs:dateTime values in messages and assertions, and therefore enter through both intake clauses. “Implementations MUST NOT generate time instants that specify leap seconds”.
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.ej</code> details</summary>

- **Required variants**:
  - `v-da55aae106` The @Version of every assertion sent by the target is included in the set of versions the target has declared that it supports.
  - `v-0db6f83055` Within the IIP scope, only 2.0 applies.
- **Controls (negative controls)**:
  - ★ Passive continuous check. IIP-SSO01.dw (schema conformance) checks for the presence of @Version, whereas this obligation checks whether the target supports the value.
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Core)**; locator: `4\.1\.2 SAML Assertion Version||4\.1\.3 SAML Protocol Version`: The version-processing rules in SAML2Core section 4 are themselves rules for processing requests, responses, and assertions, and therefore enter through both intake clauses. “A SAML asserting party MUST NOT issue any assertion with an overall Major.Minor assertion version number not supported by the authority”.
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.ek</code> details</summary>

- **Required variants**:
  - `v-f73089ff98` An assertion with @Version="1.1" → is not processed (no session is established).
  - `v-f0fdfb97be` An assertion with @Version="3.0" → is not processed.
  - `v-dba3854468` Control: @Version="2.0" → is processed.
- **Controls (negative controls)**:
  - ★ “Does not process” is broader than “rejects.” Check whether the assertion's attributes are not ingested and no session is created.
  - ★ This overlaps with IIP-SSO01.cx (rejection of schema-invalid assertions), but @Version="1.1" is not valid under the 2.0 schema, so both reasons actually apply. Share the case, while making the determination separately for each obligation.
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Core)**; locator: `4\.1\.2 SAML Assertion Version||4\.1\.3 SAML Protocol Version`: The version-processing rules in SAML2Core section 4 are themselves rules for processing requests, responses, and assertions, and therefore enter through both intake clauses. “A SAML relying party MUST NOT process any assertion with a major assertion version number not supported by the relying party”.
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.el</code> details</summary>

- **Required variants**:
  - `v-8abd06d627` The @Version of the AuthnRequest sent by the target is consistent with the response versions that the target can process.
  - `v-ccb85f2cb0` Because the IIP scope covers only version 2.0, verify that the target issues 2.0 and can process a 2.0 response.
- **Controls (negative controls)**:
  - ★ Passive continuous check. This is trivially satisfied by an implementation that supports only a single version.
  - ★ A configuration that issues a 2.0 request but cannot process a 2.0 response is non-compliant. It is satisfied if the normal-flow case for IIP-SSO01.a passes.
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Core)**; locator: `4\.1\.3\.1 Request Version||4\.1\.3\.2 Response Version`: The version-processing rules in SAML2Core §4 are themselves processing rules for requests, responses, and assertions, so they enter through both import clauses. “A SAML requester MUST NOT issue a request message with an overall Major.Minor request version number matching a response version number that the requester does not support”
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.em</code> details</summary>

- **Required variants**:
  - `v-d08f839147` An AuthnRequest with @Version="1.1" → rejected.
  - `v-ff5d4319b4` An AuthnRequest with @Version="3.0" → rejected.
  - `v-af38923be9` Control: @Version="2.0" → accepted.
- **Controls (negative controls)**:
  - ★ The status code when responding is IIP-SSO01.ep (VersionMismatch).
  - ★ This overlaps with IIP-SSO01.an (general responses to invalid requests), but this one is version-specific.
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Core)**; locator: `4\.1\.3\.1 Request Version||4\.1\.3\.2 Response Version`: The version-processing rules in SAML2Core §4 are themselves processing rules for requests, responses, and assertions, so they enter through both import clauses. “A SAML responder MUST reject any request with a major request version number not supported by the responder”
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.en</code> details</summary>

- **Required variants**:
  - `v-ab23e7eb92` For a request with @Version="2.0", the response @Version is 2.0 or lower.
  - `v-28f7dac6bb` An unsolicited response has no corresponding request and is outside the scope of this obligation.
- **Controls (negative controls)**:
  - ★ Passive continuous check. This is trivially satisfied by a single-version implementation.
  - ★ This obligation becomes meaningful if versions such as 2.1 are introduced in the future. For now, it is included as a regression check.
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Core)**; locator: `4\.1\.3\.2 Response Version||4\.1\.3\.3 Permissible Version Combinations`: The version-processing rules in SAML2Core §4 are themselves processing rules for requests, responses, and assertions, so they enter through both import clauses. “A SAML responder MUST NOT issue a response message with a response version number higher than the request version number of the corresponding request message”
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.eo</code> details</summary>

- **Required variants**:
  - `v-0733600f5a` For a request with @Version="2.0", the response major version is 2 or higher.
  - `v-de79362fc6` Control: Only when the secondary code is urn:oasis:names:tc:SAML:2.0:status:RequestVersionTooHigh may the response have a lower major version (the exception clause in the source).
  - `v-a55141ac88` Control: A secondary code of RequestVersionTooLow or RequestVersionDeprecated does not constitute an exception.
- **Controls (negative controls)**:
  - ★ Correction: The previous version described the exception as “reporting VersionMismatch,” but the exception clause in the source is limited to the secondary code RequestVersionTooHigh. VersionMismatch was incorrectly taken from another item in the same section (the top-level-code requirement, IIP-SSO01.ep), thereby allowing a lower-major response even for RequestVersionTooLow.
  - ★ If the exception clause is not included in the control, an implementation that correctly reports the error will be marked FAIL.
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Core)**; locator: `4\.1\.3\.2 Response Version||4\.1\.3\.3 Permissible Version Combinations`: The version-processing rules in SAML2Core §4 are themselves processing rules for requests, responses, and assertions, so they enter through both import clauses. “A SAML responder MUST NOT issue a response message with a major response version number lower than the major request version number of the corresponding request message except to report the error urn:oasis:names:tc:SAML:2.0:status:RequestVersionTooHigh”
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.ep</code> details</summary>

- **Required variants**:
  - `v-d49a9605bb` An AuthnRequest with @Version="1.1" → if a response is sent, its top-level @Value is urn:oasis:names:tc:SAML:2.0:status:VersionMismatch.
  - `v-5b95b4024e` Control: VersionMismatch is not used for errors caused by reasons other than the version.
- **Controls (negative controls)**:
  - ★ The secondary code is MAY (the source continues with “MAY result in ...”). Judge only the top-level code.
  - ★ This overlaps with IIP-SSO01.ch (the top-level code is a value in the top-level list), but this one also requires identifying the value.
  - ★ An implementation that does not respond and terminates with an HTTP error is treated the same as under IIP-SSO01.an and is not considered to violate this obligation.
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Core)**; locator: `4\.1\.3\.2 Response Version||4\.1\.3\.3 Permissible Version Combinations`: The version-processing rules in SAML2Core §4 are themselves processing rules for requests, responses, and assertions, so they enter through both import clauses. “An error response resulting from incompatible SAML protocol versions MUST result in reporting a top-level <StatusCode> value of urn:oasis:names:tc:SAML:2.0:status:VersionMismatch”
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.eq</code> details</summary>

- **Required variants**:
  - `v-6f81be3978` All assertions in the <samlp:Response> sent by the target (@Version="2.0") have @Version values in the 2.x range.
  - `v-92c2db4704` No assertion in the V1.x namespace (urn:oasis:names:tc:SAML:1.0:assertion) is included.
- **Controls (negative controls)**:
  - ★ Passive continuous check. Inspect both the namespace and @Version.
  - ★ This is a separate perspective from IIP-SSO01.i1 (all assertions are issued by the same entity).
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Core)**; locator: `4\.1\.3\.3 Permissible Version Combinations||4\.2 SAML Namespace Version`: The version-processing rules in SAML2Core §4 are themselves processing rules for requests, responses, and assertions, so they enter through both import clauses. “But a V1.0 assertion MUST NOT appear in a V2.0 response message because they are of different major versions”
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.fg</code> details</summary>

- **Required variants**:
  - `v-03143ac099` The @Version of the AuthnRequest sent by the subject is the highest version supported by both parties
  - `v-9f9f866bf9` Because IIP covers only SAML 2.0, this is in practice that the version is 2.0
- **Controls (negative controls)**:
  - ★ SHOULD_CLASS. A passive always-on check.
  - ★ IIP v1.1 covers only the single SAML 2.0 version, so currently producing 2.0 is sufficient. It remains in the evaluation scope, rather than being excluded, so that it can detect regressions when versions such as 2.1 are introduced in the future
  - ★ Because metadata provides no way to know the version supported by the other party, this effectively checks whether 2.0 is produced
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Core)**; locator: `4\.1\.3\.1 Request Version||4\.1\.3\.2 Response Version`: SAML2Core section 4's version-processing rules are themselves the processing rules for requests, responses, and assertions, so they enter through both incorporation phrases. “A SAML requester SHOULD issue requests with the highest request version supported by both the SAML requester and the SAML responder”
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.fh</code> details</summary>

- **Required variants**:
  - `v-e975b09c9c` Confirm by attestation that the policy is to issue requests using its own highest version (2.0) even to a peer whose supported version is unknown
  - `v-f3ae497289` The default configuration is not set to issue requests using a lower version
- **Controls (negative controls)**:
  - ★ SHOULD_CLASS. This policy is an internal configuration setting, so it is ATTESTED
  - ★ Because IIP covers only the single SAML 2.0 version, this is currently trivially satisfied. It remains in the evaluation scope, rather than being excluded, so that it is not silently dropped from the source-reconciliation table
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Core)**; locator: `4\.1\.3\.1 Request Version||4\.1\.3\.2 Response Version`: SAML2Core section 4's version-processing rules are themselves the processing rules for requests, responses, and assertions, so they enter through both incorporation phrases. “If the SAML requester does not know the capabilities of the SAML responder, then it SHOULD assume that the responder supports requests with the highest request version supported by the requester”
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.er</code> details</summary>

- **Required variants**:
  - `v-9f04ed3489` The <ds:Signature> added by the target is a child of the signed element and includes the enveloped-signature transform.
  - `v-baff9ef1c3` An enveloping signature (the form that places the signed object inside <ds:Object>) is not used.
  - `v-97f4a163cd` A detached signature (the form in which the signed object is outside the signature) is not used.
- **Controls (negative controls)**:
  - ★ Passive continuous check.
  - ★ The query signature of the HTTP-Redirect binding is not an XML Signature and is therefore out of scope.
  - ★ Correction: The previous version conditioned this on the predicate target_signs_saml_messages, but the §5.4 constraints are runtime conditions applying to each XML signature actually generated, not to a product’s signing capability. It was incorrect to treat an SP that has the capability but does not sign in this request as a declared=true / observed=false inconsistency. The condition was removed, and each signature sent by the target is passively inspected.
  - ★ If the target sends no XML signatures at all during the Run, use satisfied_with_note (no observation opportunity) and do not state that it was “verified.” Do not use NOT_APPLICABLE (the obligation applies).
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Core)**; locator: `5 SAML and XML Signature Syntax and Processing||5\.1 Signing Assertions`: SAML2Core §5 is the profile for <ds:Signature> placed directly on assertions and protocol messages, and enters through SAML2Prof §4.1.4.1, “All processing rules are as defined in [SAMLCore].” “Unless a profile specifies an alternative signature mechanism, any XML Digital Signatures MUST be enveloped”
- **Reference basis (SAML2Core)**; locator: `5\.4\.1 Signing Formats and Algorithms||5\.4\.2 References`: SAML2Core §5 is the profile for <ds:Signature> placed directly on assertions and protocol messages, and enters through SAML2Prof §4.1.4.1, “All processing rules are as defined in [SAMLCore].” “SAML assertions and protocols MUST use enveloped signatures when signing assertions and protocol messages”
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.es</code> details</summary>

- **Required variants**:
  - `v-ab2c90cdc5` In Web Browser SSO, the assertion arrives through the browser, so this SHOULD applies → the assertion is signed.
  - `v-6d8fb12a3c` Control: A Response signature alone may be treated as “inheritance” (§5.3).
- **Controls (negative controls)**:
  - ★ SHOULD_CLASS. For the POST binding, IIP-SSO01.v requires equivalent content as a MUST, so this obligation has independent significance only for the Artifact binding.
  - ★ The §5.3 statement on signature inheritance (a signature on an enclosing element extends to the assertion) uses lowercase “should,” so do not use whether inheritance suffices as a basis for the verdict; follow E26’s explicit statement that a Response signature is also acceptable (IIP-SSO01.v).
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Core)**; locator: `5 SAML and XML Signature Syntax and Processing||5\.1 Signing Assertions`: SAML2Core §5 is the profile for <ds:Signature> placed directly on assertions and protocol messages, and enters through SAML2Prof §4.1.4.1, “All processing rules are as defined in [SAMLCore].” “A SAML assertion obtained by a SAML relying party from an entity other than the SAML asserting party SHOULD be signed by the SAML asserting party”
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.et</code> details</summary>

- **Required variants**:
  - `v-3b234593b9` A <ds:Signature> is present on the <samlp:Response> received through the browser
  - `v-bbbed3e103` Control: In the POST binding, signing each assertion alone is sufficient to satisfy IIP-SSO01.v, but this SHOULD recommends signing the <Response> itself
- **Controls (negative controls)**:
  - ★ SHOULD_CLASS. Web Browser SSO always passes through the browser (an entity other than the originating sender), so this applies.
  - ★ Correction: The previous version set role to [idp, sp] and mixed the AuthnRequest generated by the SP with the <Response> generated by the IdP in the same variant set. Because the variant has no role field, they were separated by role for the same reason IIP-SSO01.cg was split (the SP side is IIP-SSO01.fj).
  - ★ This is separate from IIP-SP13 (which allows the SP to reject an unsigned Response). That concerns the receiving side’s capability.
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Core)**; locator: `5 SAML and XML Signature Syntax and Processing||5\.1 Signing Assertions`: SAML2Core §5 is the profile for <ds:Signature> placed directly on assertions and protocol messages, and enters through SAML2Prof §4.1.4.1, “All processing rules are as defined in [SAMLCore].” “A SAML protocol message arriving at a destination from an entity other than the originating sender SHOULD be signed by the sender”
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.fj</code> details</summary>

- **Required variants**:
  - `v-a0f328878d` An AuthnRequest delivered through a browser using HTTP-Redirect or HTTP-POST is protected by an XML signature or a binding-specific signature
  - `v-2a132dd7e2` In the HTTP-Redirect binding, a query signature is also permitted (the signing mechanism specified by [SAML2Bind])
  - `v-5dcdcf7e60` For HTTP-Artifact, an XML signature on the AuthnRequest is unnecessary if the synchronous binding used for artifact resolution provides sender authentication and integrity protection
- **Controls (negative controls)**:
  - ★ SHOULD_CLASS. AuthnRequest signing is MAY in SAML2Prof 4.1.4.1, but SHOULD in Core §5. Adopt the stronger requirement (SHOULD). An unsigned request is WARNING, not FAIL
  - ★ Core 3.4.1 uses the disjunction “signed or otherwise authenticated and integrity protected by the binding.” Making only the signing path required would classify a conforming implementation using mutually authenticated Artifact resolution as WARNING
  - ★ A Redirect query signature is not an XML signature and is therefore outside the scope of IIP-SSO01.er / .eu / .ev / .ew / .ex. This obligation checks only whether the message is signed, so either signing mechanism satisfies it
  - ★ The IdP metadata field WantAuthnRequestsSigned is MAY (SAML2Prof 4.1.6). Do not use it as a basis for elevating the requirement to MUST
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Core)**; locator: `3\.4\.1 Element <AuthnRequest>||3\.4\.1\.1 Element <NameIDPolicy>`: This is incorporated by SAML2Prof 4.1.3.3, “The identity provider MUST process the <AuthnRequest> message as described in [SAMLCore],” and 4.1.4.1, “All processing rules are as defined in [SAMLCore].” “The <AuthnRequest> message SHOULD be signed or otherwise authenticated and integrity protected by the protocol binding used to deliver the message”
- **Reference basis (SAML2Core)**; locator: `5 SAML and XML Signature Syntax and Processing||5\.1 Signing Assertions`: SAML2Core section 5 profiles <ds:Signature> placed directly on assertions and protocol messages, and enters through SAML2Prof 4.1.4.1, “All processing rules are as defined in [SAMLCore].” It is a general SHOULD that protocol messages delivered through a browser or other entity besides the sender should be signed by the sender
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.eu</code> details</summary>

- **Required variants**:
  - `v-ed0f265a79` The root of the element signed by the subject has an @ID (the element being signed differs by role, but the determination is the same)
  - `v-cbcba8c589` That @ID is non-empty
- **Controls (negative controls)**:
  - ★ Passive always-on check. The determination is role-neutral: because it examines the element signed by the subject, it automatically targets <Response> / <Assertion> for an IdP and <AuthnRequest> for an SP. Since role-specific variants are not mixed, G2 does not require one role to cover the other role's variant
  - ★ This overlaps with IIP-SSO01.cg / .dv / .dw (schema conformance), but this one concerns the ID as a prerequisite for signing
  - ★ Correction: The previous version conditioned this on the predicate target_signs_saml_messages, but the §5.4 constraints are runtime conditions applying to each XML signature actually generated, not to a product’s signing capability. It was incorrect to treat an SP that has the capability but does not sign in this request as a declared=true / observed=false inconsistency. The condition was removed, and each signature sent by the target is passively inspected.
  - ★ If the target sends no XML signatures at all during the Run, use satisfied_with_note (no observation opportunity) and do not state that it was “verified.” Do not use NOT_APPLICABLE (the obligation applies).
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Core)**; locator: `5\.4\.2 References||5\.4\.3 Canonicalization Method`: SAML2Core 5 is the profile for <ds:Signature> placed directly on assertions and protocol messages, incorporated through SAML2Prof 4.1.4.1, “All processing rules are as defined in [SAMLCore].” “SAML assertions and protocol messages MUST supply a value for the ID attribute on the root element of the assertion or protocol message being signed”
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.ev</code> details</summary>

- **Required variants**:
  - `v-a28453797e` The signature produced by the subject contains exactly one <ds:Reference>
  - `v-35f6b5ef91` Its @URI exactly matches "#" plus the @ID of the root element being signed
  - `v-ff444b2e55` @URI is neither empty (the entire document) nor an external URI
- **Controls (negative controls)**:
  - ★ Passive always-on check. This rule is a direct defense against XML Signature Wrapping
  - ★ The determination is role-neutral (it examines the element signed by the subject)
  - ★ On the receiving side, it is necessary to verify that the signature actually covers the element being processed. That obligation is represented together with IIP-SSO01.ey (the assurance required when an unauthorized transform is present)
  - ★ It must be possible to detect a signature containing multiple <ds:Reference> elements
  - ★ Correction: The previous version conditioned this on the predicate target_signs_saml_messages, but the §5.4 constraints are runtime conditions applying to each XML signature actually generated, not to a product’s signing capability. It was incorrect to treat an SP that has the capability but does not sign in this request as a declared=true / observed=false inconsistency. The condition was removed, and each signature sent by the target is passively inspected.
  - ★ If the target sends no XML signatures at all during the Run, use satisfied_with_note (no observation opportunity) and do not state that it was “verified.” Do not use NOT_APPLICABLE (the obligation applies).
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Core)**; locator: `5\.4\.2 References||5\.4\.3 Canonicalization Method`: SAML2Core 5 is the profile for <ds:Signature> placed directly on assertions and protocol messages, incorporated through SAML2Prof 4.1.4.1, “All processing rules are as defined in [SAMLCore].” “Signatures MUST contain a single <ds:Reference> containing a same-document reference to the ID attribute value of the root element of the assertion or protocol message being signed. For example, if the ID attribute value is "foo", then the URI attribute in the <ds:Reference> element MUST be "#foo"”
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.ew</code> details</summary>

- **Required variants**:
  - `v-a33044b7ed` <ds:CanonicalizationMethod>/@Algorithm is http://www.w3.org/2001/10/xml-exc-c14n# (or #WithComments)
  - `v-8f7d78ce83` <ds:Transform> also includes Exclusive Canonicalization
- **Controls (negative controls)**:
  - ★ SHOULD_CLASS. Inclusive C14N results in a WARNING, not a FAIL
  - ★ Passive always-on check. The determination is role-neutral
  - ★ Correction: The previous version conditioned this on the predicate target_signs_saml_messages, but the §5.4 constraints are runtime conditions applying to each XML signature actually generated, not to a product’s signing capability. It was incorrect to treat an SP that has the capability but does not sign in this request as a declared=true / observed=false inconsistency. The condition was removed, and each signature sent by the target is passively inspected.
  - ★ If the target sends no XML signatures at all during the Run, use satisfied_with_note (no observation opportunity) and do not state that it was “verified.” Do not use NOT_APPLICABLE (the obligation applies).
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Core)**; locator: `5\.4\.3 Canonicalization Method||5\.4\.4 Transforms`: SAML2Core 5 is the profile for <ds:Signature> placed directly on assertions and protocol messages, incorporated through SAML2Prof 4.1.4.1, “All processing rules are as defined in [SAMLCore].” “SAML implementations SHOULD use Exclusive Canonicalization [Excl-C14N], with or without comments, both in the <ds:CanonicalizationMethod> element of <ds:SignedInfo>, and as a <ds:Transform> algorithm”
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.ex</code> details</summary>

- **Required variants**:
  - `v-793a661231` The <ds:Transforms> in the signature produced by the subject consists only of enveloped-signature and Exclusive C14N transforms
  - `v-0ce7802c87` It does not contain an XPath / XSLT transform
- **Controls (negative controls)**:
  - ★ SHOULD_NOT. This is a rule for the signing side. The determination is role-neutral
  - ★ How unauthorized transforms are handled on the receiving side is covered by IIP-SSO01.ey
  - ★ Correction: The previous version conditioned this on the predicate target_signs_saml_messages, but the §5.4 constraints are runtime conditions applying to each XML signature actually generated, not to a product’s signing capability. It was incorrect to treat an SP that has the capability but does not sign in this request as a declared=true / observed=false inconsistency. The condition was removed, and each signature sent by the target is passively inspected.
  - ★ If the target sends no XML signatures at all during the Run, use satisfied_with_note (no observation opportunity) and do not state that it was “verified.” Do not use NOT_APPLICABLE (the obligation applies).
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Core)**; locator: `5\.4\.4 Transforms||5\.4\.5 KeyInfo`: SAML2Core 5 is the profile for <ds:Signature> placed directly on assertions and protocol messages, incorporated through SAML2Prof 4.1.4.1, “All processing rules are as defined in [SAMLCore].” “Signatures in SAML messages SHOULD NOT contain transforms other than the enveloped signature transform ... or the exclusive canonicalization transforms”
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.ey</code> details</summary>

- **Required variants**:
  - `v-c5973bf642` An assertion in which an XPath transform **excluded** <saml:AttributeStatement> from the signed content → rejected
  - `v-8d217b0080` An assertion in which an XPath transform excluded <saml:Conditions> from the signed content → rejected
  - `v-613a7f9468` A response in which an XSLT transform excluded part of <Response> → rejected
  - `v-cd8a4633ec` A signature containing a transform that makes the signed content empty → rejected
  - `v-18fc98ef5b` A signature with <ds:Reference>/@URI empty (the entire document) and an XPath transform that excludes part of the content → rejected
  - `v-548ddb7a41` Control: A correct signature containing only permitted transforms → accepted
- **Controls (negative controls)**:
  - ★ **Core defense against XML Signature Wrapping**. It must provide detection capability equivalent to P0
  - ★ Correction 1: The previous version used roles [idp, sp] and made a **response** excluding AttributeStatement the main variant. That tested only SP <Response> verification and could not demonstrate IdP AuthnRequest verification. They were split by role (the IdP side is IIP-SSO01.fk)
  - ★ Correction 2: The previous version made “a signature containing an unauthorized transform but excluding no content at all (an identity XPath) → may be accepted” a required variant, but the source text states that it is permissible to reject it even when no content is excluded (MAY). Acceptance and rejection are both allowed, so no verdict can be assigned. It was moved to self-validation of the Suite fixture. Self-validation checks only (a) that the fixture signature is cryptographically valid and (b) that the identity transform excludes no content; it does not check the subject’s reason for rejection or whether the subject accepts it
  - ★ Because the subject conforms even if it rejects solely because an unauthorized transform is present, there is no need to distinguish the reason for rejection
  - ★ Evaluation rules:
  - Rejected → satisfied (the source text’s MAY case)
  - Accepted, but no content was excluded from the signed content → satisfied
  - **Accepted a signature that excluded content → violated** (regardless of whether the excluded content was used)
  - Unable to determine whether content was excluded → not_verified
  - ★ The source text requires that “no content of the SAML message is excluded from the signature,” not that excluded content must go unused
  - ★ The observation of “accepted” is determined by whether the subject processed the assertion / message and proceeded (session establishment or application of attributes)
  - ★ Together with IIP-SSO01.ev (a single <ds:Reference> points to the target root), this checks whether the signature actually covers the element being processed
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Core)**; locator: `5\.4\.4 Transforms||5\.4\.5 KeyInfo`: SAML2Core 5 is the profile for <ds:Signature> placed directly on assertions and protocol messages, incorporated through SAML2Prof 4.1.4.1, “All processing rules are as defined in [SAMLCore].” “Verifiers of signatures MAY reject signatures that contain other transform algorithms as invalid. If they do not, verifiers MUST ensure that no content of the SAML message is excluded from the signature”
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.fk</code> details</summary>

- **Required variants**:
  - `v-88fc611002` An AuthnRequest whose signature uses an XPath transform that **excludes** @AssertionConsumerServiceURL from the signed content → rejected
  - `v-8bbde86f33` An AuthnRequest whose signature uses an XPath transform to exclude <samlp:NameIDPolicy> from the signed content → rejected
  - `v-3593f363ea` An AuthnRequest whose signature uses an XPath transform to exclude <samlp:Scoping> from the signed content → rejected
  - `v-42854be57c` A signature on an AuthnRequest containing a transform that makes the signed content empty → rejected
  - `v-c3f6ad120f` Control: an AuthnRequest with a valid signature using only permitted transforms → accepted
- **Controls (negative controls)**:
  - ★ An attack that excludes the ACS URL from the signed content directly affects implementations that trust the signed request to determine the response destination (and is related to IIP-SSO01.aj / IIP-IDP12.b)
  - ★ The evaluation rules are the same as for IIP-SSO01.ey (reject → satisfied / accept without exclusion → satisfied / accept with exclusion → violated / unable to determine whether exclusion occurred → not_verified)
  - ★ A case using an identity transform is not made a required variant (it has no detection power because the only outcomes are acceptance or rejection). It was moved to self-validation of the Suite-side fixture. Self-validation checks only (a) that the fixture signature is cryptographically valid and (b) that the identity transform does not exclude any content; it does not check the subject's reason for rejection or whether the subject accepts the request
  - ★ Correction: the previous version incorrectly stated that there was no observation opportunity when the configuration accepted unsigned AuthnRequests. Whether the subject requires signatures and the obligation to correctly verify a received signature are separate; the Suite can always send a signed AuthnRequest. If this statement remains, an IdP that never verifies signatures and always accepts requests could escape as “no observation opportunity”
  - ★ For this obligation's case, the Suite always sends a signed AuthnRequest. Use not_verified(test_precondition_signing_key_not_trusted) only when the target cannot be made to trust the Suite SP's key, such as when metadata cannot be registered
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Core)**; locator: `5\.4\.4 Transforms||5\.4\.5 KeyInfo`: SAML2Core section 5 profiles <ds:Signature> placed directly on assertions and protocol messages, and enters through SAML2Prof 4.1.4.1, “All processing rules are as defined in [SAMLCore].” This is the same clause. Because it is a recipient-side (verifier) obligation, the same constraint applies to an IdP that verifies AuthnRequests
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.ez</code> details</summary>

- **Required variants**:
  - `v-847ad346b3` In a configuration with assertion encryption enabled, <saml:EncryptedAssertion> is directly under <samlp:Response> (in the same location as the plaintext <saml:Assertion>)
  - `v-cadb77c68c` The same <Response> does not retain both a plaintext <Assertion> and an <EncryptedAssertion>
- **Controls (negative controls)**:
  - ★ Treat this as a passive rule. Check each applicable element actually sent by the target, and if none is observed during the Run, return satisfied_with_note (no observation opportunity). **Do not add a condition predicate**: a CAPABILITY_BASED predicate can only create positive evidence and cannot make “does not have the capability” FALSE (a declaration-only false is UNKNOWN), causing unsupported targets to remain not_verified forever. Align the treatment with IIP-SSO01.er and similar obligations.
  - ★ Correction: The previous version made the locations of <EncryptedID> and <EncryptedAttribute> required variants without conditions, but IIP-IDP09.b specifies encryption of identifiers and attributes as **OPTIONAL**. It incorrectly classified a conforming IdP that does not encrypt identifiers or attributes as non-conforming or not verified. They were separated into assertion (required by IIP-IDP09.a), identifier (IIP-SSO01.fd), and attribute (IIP-SSO01.fe)
  - ★ A typical violation is an implementation that adds ciphertext while leaving the plaintext in place
  - ★ It derives from the same section as IIP-SSO01.dm / .dn (@Type), but this one is a placement rule
- **Configuration failure semantics**: `test_precondition`
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Core)**; locator: `6\.1 General Considerations||6\.2 Combining Signatures and Encryption`: SAML2Core 6 defines encryption of assertions, identifiers, and attributes. IIP-IDP09.a makes assertion encryption a MUST, incorporated through inclusion phrase B. Errata E43 and E93 have replaced the signature/encryption ordering rules in the OS version of 6.2. The replacement position in the OS version is a MUST (E30 corrects the cardinality expression for encrypted keys)
- **Reference basis (SAML2Errata)**; locator: `E30: Key Replacement||E31: `: After applying E30: “Encrypted data and zero or more encrypted keys MUST replace the plaintext information in the same location within the XML instance”
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.fd</code> details</summary>

- **Required variants**:
  - `v-a9cbb870e0` With identifier encryption enabled, <saml:EncryptedID> appears directly under <saml:Subject>, in the same position as the plaintext <saml:NameID>
  - `v-a703414667` The same <Subject> does not retain both a plaintext <NameID> and an <EncryptedID>
- **Controls (negative controls)**:
  - ★ Treat this as a passive rule. Check each applicable element actually sent by the target, and if none is observed during the Run, return satisfied_with_note (no observation opportunity). **Do not add a condition predicate**: a CAPABILITY_BASED predicate can only create positive evidence and cannot make “does not have the capability” FALSE (a declaration-only false is UNKNOWN), causing unsupported targets to remain not_verified forever. Align the treatment with IIP-SSO01.er and similar obligations.
  - ★ Under IIP-IDP09.b, identifier encryption is OPTIONAL. For subjects that are not encrypted, <EncryptedID> is not observed and the outcome is satisfied_with_note
- **Configuration failure semantics**: `test_precondition`
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Core)**; locator: `6\.1 General Considerations||6\.2 Combining Signatures and Encryption`: SAML2Core section 6 specifies encryption of assertions, identifiers, and attributes. IIP-IDP09.a makes assertion encryption MUST through incorporation phrase B. Errata E43 and E93 replace the signature-and-encryption ordering rules in OS section 6.2. The same MUST applies in OS. The target element is <EncryptedID> in §2.2.4
- **Reference basis (SAML2Errata)**; locator: `E30: Key Replacement||E31: `: After applying E30: “Encrypted data and zero or more encrypted keys MUST replace the plaintext information in the same location within the XML instance”
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.fe</code> details</summary>

- **Required variants**:
  - `v-959fe1e328` With attribute encryption enabled, <saml:EncryptedAttribute> appears directly under <saml:AttributeStatement>, in the same position as the plaintext <saml:Attribute>
  - `v-f04aa99838` The same <AttributeStatement> does not retain both a plaintext <Attribute> and an <EncryptedAttribute>
- **Controls (negative controls)**:
  - ★ Treat this as a passive rule. Check each applicable element actually sent by the target, and if none is observed during the Run, return satisfied_with_note (no observation opportunity). **Do not add a condition predicate**: a CAPABILITY_BASED predicate can only create positive evidence and cannot make “does not have the capability” FALSE (a declaration-only false is UNKNOWN), causing unsupported targets to remain not_verified forever. Align the treatment with IIP-SSO01.er and similar obligations.
  - ★ Under IIP-IDP09.b, attribute encryption is OPTIONAL. For subjects that are not encrypted, <EncryptedAttribute> is not observed and the outcome is satisfied_with_note
- **Configuration failure semantics**: `test_precondition`
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Core)**; locator: `6\.1 General Considerations||6\.2 Combining Signatures and Encryption`: SAML2Core section 6 specifies encryption of assertions, identifiers, and attributes. IIP-IDP09.a makes assertion encryption MUST through incorporation phrase B. Errata E43 and E93 replace the signature-and-encryption ordering rules in OS section 6.2. The same MUST applies in OS. The target element is <EncryptedAttribute> in §2.7.3.2
- **Reference basis (SAML2Errata)**; locator: `E30: Key Replacement||E31: `: After applying E30: “Encrypted data and zero or more encrypted keys MUST replace the plaintext information in the same location within the XML instance”
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.dr</code> details</summary>

- **Required variants**:
  - `v-72620ece99` The @ID sent to the upstream provider differs in each of two consecutive proxy operations.
  - `v-84b8462d96` The @ID sent to the upstream provider does not simply reuse the @ID of the original request (downstream Samlier-SP → target).
- **Controls (negative controls)**:
  - ★ The lexical rules for xs:ID are evaluated as schema conformance (IIP-SSO01.dx). Do not also count the same lexical violation as an identifier uniqueness violation.
  - ★ IIP-SSO01.af targets only role sp (requests generated by the SP). A proxying IdP also generates a new AuthnRequest for the upstream provider, so the same rule applies to its @ID.
  - ★ A typical violation is an implementation that “uses the original request's @ID unchanged,” assigning the same identifier to a different data object.
  - ★ The details of probability and seed are covered by IIP-SSO01.cd / .ce / .cf for roles idp/sp.
- **Configuration failure semantics**: `test_precondition`
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Core)**; locator: `3\.2\.1 Complex Type RequestAbstractType||3\.2\.2 Complex Type StatusResponseType`: This is incorporated by SAML2Prof 4.1.3.3, “The identity provider MUST process the <AuthnRequest> message as described in [SAMLCore],” and 4.1.4.1, “All processing rules are as defined in [SAMLCore].” “An identifier for the request. It is of type xs:ID and MUST follow the requirements specified in Section 1.3.4 for identifier uniqueness”
- **Reference basis (SAML2Core)**; locator: `1\.3\.4 ID and ID Reference Values||2 SAML Assertions`: SAML2Prof 4.1.3.3's “The identity provider MUST process the <AuthnRequest> message as described in [SAMLCore]” and 4.1.4.1's “All processing rules are as defined in [SAMLCore]” incorporate: “Any party that assigns an identifier MUST ensure that there is negligible probability that that party or any other party will accidentally assign the same identifier to a different data object.”
- **Notes**: The obligations are divided into an unconditional obligation for SPs (IIP-SSO01.af) and a conditional obligation for proxying IdPs (this obligation).
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.bk</code> details</summary>

- **Required variants**:
  - `v-1cd2409048` An IdP-initiated SSO configuration that includes RelayState can be used, where supported.
  - `v-0f7e1ec62d` If unsupported, return NOT_SUPPORTED. This is not a conformance violation
- **Controls (negative controls)**:
  - ★ MAY_CLASS. An IdP that does not include RelayState must not be marked FAIL
  - ★ RelayState MAY also be a URL; it may instead be an opaque value that is not a URL.
  - ★ The receiving SP's handling is covered by IIP-SSO01.y2 (the default destination) and IIP-SSO01.ab (scheme restrictions).
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Prof)**; locator: `4\.1\.5 Unsolicited Responses||4\.1\.6 Use of Metadata`: 『Of special mention is that the identity provider MAY include a binding-specific "RelayState" parameter that indicates, based on mutual agreement with the service provider, how to handle subsequent interactions with the user agent. This MAY be the URL of a resource at the service provider』
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.y2</code> details</summary>

- **Required variants**:
  - `v-7584a53629` An unsolicited response without RelayState → it reaches the default redirect destination (without error)
  - `v-19382cf0be` Send two unsolicited responses without RelayState → both reach the default redirect destination
- **Controls (negative controls)**:
  - ★ SHOULD_CLASS. The only subject of evaluation is whether a default redirect destination is provided
  - ★ Correction: The previous version made “with RelayState → redirect to that URL” a required variant, but the source text treats handling RelayState as a URL as a MAY based on mutual agreement (IIP-SSO01.bk). An SP that does not redirect to the URL still satisfies this SHOULD if it provides a default redirect destination. Removed from the verdict scope
  - ★ Scheme restrictions when interpreting RelayState as a URL are evaluated under IIP-SSO01.ab (the new §4.1.6 added by E90)
  - ★ An SP without a default redirect destination errors on an unsolicited response without RelayState. That is the behavior to detect
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Prof)**; locator: `4\.1\.5 Unsolicited Responses||4\.1\.6 Use of Metadata`: 『The service provider SHOULD be prepared to handle unsolicited responses by designating a default location to send the user agent subsequent to processing a response successfully』
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.fl</code> details</summary>

- **Required variants**:
  - `v-57b4fb774e` An AuthnRequest sent by the SP in which NameIDPolicy/@Format is not transient and the configuration does not perform AllowCreate-specific state management → AllowCreate=true
  - `v-3c2b013767` A configuration that uses AllowCreate for a specific purpose, such as consent or dynamic identifier creation, is outside the scope of this SHOULD
- **Controls (negative controls)**:
  - ★ E14 not only removed the former MUST from SAML2Prof 4.1.4.1; it also added a new SHOULD to Core 3.4.1.1
  - ★ This SHOULD applies only when the attribute is not used for a specific purpose. It must not be forced to true in all cases
  - ★ A NameIDPolicy with @Format=transient is outside the runtime scope of this SHOULD, and IIP-SSO01.fn's MUST_NOT applies
  - ★ If no AuthnRequest with a NameIDPolicy other than transient is observed during the Run, the outcome is satisfied_with_note. Do not make it globally NOT_APPLICABLE; treat it as per-message runtime scope
  - ★ When a proxy IdP is the requester, handle it separately under IIP-SSO01.fm
- **Referenced specification**: `SAML2Prof#4.1`
- **Exclusion**: Requesters that do not make specific use of this attribute SHOULD generally set it to
- **Reference basis (SAML2Errata)**; locator: `E14: AllowCreate||E15: `: This is incorporated by SAML2Prof 4.1.3.3, “The identity provider MUST process the <AuthnRequest> message as described in [SAMLCore],” and 4.1.4.1, “All processing rules are as defined in [SAMLCore].” “Requesters that do not make specific use of this attribute SHOULD generally set it to true to maximize interoperability.” The immediately following statement, “The use of the AllowCreate attribute MUST NOT be used ... in conjunction with requests for ...:transient,” is a narrower and stronger exception
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.fm</code> details</summary>

- **Required variants**:
  - `v-76d059ad16` An AuthnRequest sent by the subject to the upstream IdP in which NameIDPolicy/@Format is not transient and the configuration does not perform AllowCreate-specific state management → AllowCreate=true
- **Controls (negative controls)**:
  - ★ The roles were separated because the observation paths and applicability conditions differ between the SP and the proxy IdP
  - ★ An upstream NameIDPolicy/@Format=transient is outside the runtime scope of this SHOULD; apply the MUST_NOT in IIP-SSO01.fo
  - ★ If no upstream AuthnRequest with a non-transient NameIDPolicy is observed during the Run, return satisfied_with_note
- **Configuration failure semantics**: `test_precondition`
- **Referenced specification**: `SAML2Prof#4.1`
- **Exclusion**: Requesters that do not make specific use of this attribute SHOULD generally set it to
- **Reference basis (SAML2Errata)**; locator: `E14: AllowCreate||E15: `: SAML2Core 3.4.1.5.1 is part of the processing rules for <AuthnRequest> and enters the Web Browser SSO Profile through the incorporation clause in SAML2Prof 4.1.3.3. The same “Requesters ... SHOULD generally set it to true” and the immediately following MUST NOT for transient. A proxy IdP is also a requester with respect to the upstream party
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.fn</code> details</summary>

- **Required variants**:
  - `v-345c6833d1` An AuthnRequest with NameIDPolicy/@Format=transient → do not include @AllowCreate
- **Controls (negative controls)**:
  - ★ An implementation that never sends AllowCreate is also conformant. Requiring the use of AllowCreate with persistent identifiers as a positive control would add a generation capability not required by the original MUST NOT
  - ★ If there is no opportunity to observe a transient AuthnRequest being sent, record satisfied_with_note; do not record a violation or NOT_APPLICABLE
  - ★ AllowCreate is an attribute of <NameIDPolicy> in an AuthnRequest and does not exist in the assertion itself. Determine the MUST NOT from the output sent by the requester that uses the attribute; do not create a fictitious attribute-processing obligation for the assertion consumer
  - ★ Do not retroactively classify the requester as nonconformant because the IdP returned a transient identifier when @Format was omitted. The returned Format is at the IdP’s discretion; the context of assertions issued with transient is handled by IIP-SSO01.fp
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Errata)**; locator: `E14: AllowCreate||E15: `: SAML2Prof 4.1.3.3 incorporates “The identity provider MUST process the <AuthnRequest> message as described in [SAMLCore]” and 4.1.4.1 incorporates “All processing rules are as defined in [SAMLCore].” “The use of the AllowCreate attribute MUST NOT be used and SHOULD be ignored in conjunction with requests for or assertions issued with name identifiers with a Format of ...:transient”
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.fo</code> details</summary>

- **Required variants**:
  - `v-4ce8506c89` An AuthnRequest sent by the subject to the upstream party with NameIDPolicy/@Format=transient → do not include @AllowCreate
- **Controls (negative controls)**:
  - ★ Requests sent by the SP are covered separately by IIP-SSO01.fn
  - ★ The capability to use AllowCreate with persistent identifiers is not required by this MUST NOT and therefore is not required as a control
  - ★ Do not retroactively classify the proxy requester as nonconformant based on the Format returned by the upstream IdP when @Format was omitted. The context of assertions issued with transient is handled by IIP-SSO01.fp
- **Configuration failure semantics**: `test_precondition`
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Errata)**; locator: `E14: AllowCreate||E15: `: SAML2Core 3.4.1.5.1 is part of the processing rules for <AuthnRequest> and enters through the incorporation clause in SAML2Prof 4.1.3.3. The same “MUST NOT be used and SHOULD be ignored in conjunction with requests for or assertions issued with ...:transient” also applies to upstream requests generated by a proxy IdP acting as a requester
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.fp</code> details</summary>

- **Required variants**:
  - `v-083a9e94c3` Three requests with Format=transient and AllowCreate=true, false, and omitted → do not change success or error solely because of the AllowCreate value
  - `v-ccee5bfb27` If the resulting assertion contains a transient NameID because @Format was omitted or for another reason → do not create or associate persistent state solely because of the AllowCreate value
- **Controls (negative controls)**:
  - ★ SHOULD_CLASS. Even when the requester-side MUST NOT (IIP-SSO01.fn) applies, the receiver-side SHOULD remains independent for robustness
  - ★ Because the value of a transient NameID may vary for each request, do not use value matching or opacity to determine this obligation
  - ★ If the result may change because of another factor, such as an authentication policy, do not conclude that AllowCreate was the cause; return not_verified
  - ★ The subject of SHOULD ignore is the IdP processing <NameIDPolicy>/@AllowCreate. Because the assertion itself has no such attribute, do not create an independent obligation for the SP or upstream assertion consumer to “ignore AllowCreate”
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Errata)**; locator: `E14: AllowCreate||E15: `: SAML2Prof 4.1.3.3 incorporates “The identity provider MUST process the <AuthnRequest> message as described in [SAMLCore]” and 4.1.4.1 incorporates “All processing rules are as defined in [SAMLCore].” “The use of the AllowCreate attribute MUST NOT be used and SHOULD be ignored in conjunction with requests for or assertions issued with name identifiers with a Format of ...:transient”
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.fr</code> details</summary>

- **Required variants**:
  - `v-156e9876ec` A configuration that intentionally specifies an attesting entity different from the subject → identify that entity in SubjectConfirmation using BaseID, NameID, or EncryptedID
  - `v-c8a2d34679` When the subject itself is the attesting entity in ordinary bearer SSO, record that there was no opportunity for observation
- **Controls (negative controls)**:
  - ★ The fact that the SP is the destination of the assertion alone does not satisfy the condition. The entity in the original text means the attesting entity presenting the assertion
  - ★ If the implementation cannot configure an attesting entity different from the subject, return satisfied_with_note. Do not force the SP entityID to be required
- **Configuration failure semantics**: `test_precondition`
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Errata)**; locator: `E47: Clarification on SubjectConfirmation||E48: `: SAML2Prof 4.1.4 states “This profile is based on the Authentication Request protocol defined in [SAMLCore]” and, through the incorporation clause in 4.1.3.5, brings in SAML2Core rules concerning assertion generation and processing. The addition to Core 2.4.1.1 states: “If an assertion is issued for use by an entity other than the subject, then that entity SHOULD be identified in the <SubjectConfirmation> element”
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.fs</code> details</summary>

- **Required variants**:
  - `v-cb55b2a316` None of the XML Signatures sent by the subject contains <ds:Object>
  - `v-c6411d2ca0` A role or Run that sent no signature is satisfied_with_note
- **Controls (negative controls)**:
  - ★ SHOULD_CLASS. Redirect-binding query signatures are not XML Signatures and are outside the scope
  - ★ The receiver-side rejection obligation is separated by role into IIP-SSO01.ft and .fu
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Errata)**; locator: `E91: Disallow <ds:Object> element in signatures||E92: `: SAML2Core 5 is the profile for <ds:Signature> placed directly on assertions and protocol messages, and enters through SAML2Prof 4.1.4.1, “All processing rules are as defined in [SAMLCore].” The addition to Core 5.4.5 states: “The <ds:Object> element ... SHOULD NOT be present”
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.ft</code> details</summary>

- **Required variants**:
  - `v-9840739279` A signed Response that is cryptographically valid but contains <ds:Object> → reject
  - `v-a8c1994865` A signed Assertion under the same conditions → reject
  - `v-7054385ce1` Control: the same content with only <ds:Object> removed and a valid signature → accept
- **Controls (negative controls)**:
  - ★ There is no need to place an attack string inside ds:Object. Reject based solely on the element’s presence
  - ★ Test both Response and Assertion. Testing only one does not cover all verifier paths
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Errata)**; locator: `E91: Disallow <ds:Object> element in signatures||E92: `: SAML2Prof 4.1.3.5 incorporates “The service provider MUST process the <Response> message and any enclosed <Assertion> elements as described in [SAMLCore].” It also incorporates “verifiers SHOULD reject signatures that contain a <ds:Object> element”
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.fu</code> details</summary>

- **Required variants**:
  - `v-dc82802006` A signed AuthnRequest that is cryptographically valid but contains <ds:Object> → reject
  - `v-392adb0816` Control: the same content with only <ds:Object> removed and a valid signature → accept
- **Controls (negative controls)**:
  - ★ If the Suite SP’s signing key cannot be trusted by the subject, return not_verified(test_precondition_signing_key_not_trusted)
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Errata)**; locator: `E91: Disallow <ds:Object> element in signatures||E92: `: SAML2Prof 4.1.3.3 incorporates “The identity provider MUST process the <AuthnRequest> message as described in [SAMLCore]” and 4.1.4.1 incorporates “All processing rules are as defined in [SAMLCore].” The same verifier SHOULD applies to AuthnRequests verified by the IdP
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.fv</code> details</summary>

- **Required variants**:
  - `v-4678cae385` A Response sent by the subject containing a CBC-mode <EncryptedAssertion> → the Response element has a valid XML Signature
  - `v-3cb78ddbc6` An outbound message using non-CBC encryption, or one without an EncryptedAssertion, is recorded as outside the scope of this SHOULD
- **Controls (negative controls)**:
  - ★ This is a runtime passive rule, so do not add a capability predicate. If no CBC EncryptedAssertion is observed, return satisfied_with_note
  - ★ Because a signature inside the assertion cannot fully integrity-check the ciphertext before decryption, inspect the Response signature
  - ★ The same normative sentence appears in two places, Profile 4.1.3.5 and 4.1.4.3, but the obligation must not be counted twice
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Errata)**; locator: `E93: Mitigation for XML Encryption CBC deficiencies||E94: `: The additions to SAMLProf 4.1.3.5 and 4.1.4.3 state: “If an <EncryptedAssertion> element is present and a CBC-mode algorithm is used, then the <Response> SHOULD be signed”
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.fw</code> details</summary>

- **Required variants**:
  - `v-2a7594e9b2` Confirm through internal policy, traces, or instrumentation that outer integrity protection is required and verified before processing the decryption of CBC-encrypted data.
  - `v-dc31e32318` Supporting evidence: a Response containing a CBC EncryptedAssertion with no valid integrity protection outside the encryption layer → rejected.
  - `v-8b12a7928b` Supporting evidence: an assertion containing a CBC EncryptedID or EncryptedAttribute without an outer signature covering the encrypted element → rejected.
  - `v-a78c231a75` Control: covering the same ciphertext with a valid Response or Assertion signature → accepted.
- **Controls (negative controls)**:
  - ★ SHOULD_CLASS. If it is not rejected, the result is WARNING, not FAIL
  - ★ Rejection by the external party alone cannot prove the processing order. A misimplementation that rejects after decryption because the signature is missing produces the same result. Therefore, the verdict must be based on internal policy, traces, and instrumentation, with external fixtures limited to supporting evidence.
  - ★ If internal evidence cannot be obtained, record not_verified(processing_order_not_observable).
  - ★ The signature on an inner plaintext assertion can be verified only after decryption and therefore does not satisfy the CBC-oracle mitigation requirement of “before processing encrypted data.”
  - ★ When relying on TLS as the basis, it is necessary to show that it is the layer authenticating the asserting party for the encrypted data. Do not automatically regard TLS between the browser and SP for a browser POST as integrity protection provided by the IdP.
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Errata)**; locator: `E93: Mitigation for XML Encryption CBC deficiencies||E94: `: SAML2Prof 4.1.3.5 incorporates this through “The service provider MUST process the <Response> message and any enclosed <Assertion> elements as described in [SAMLCore].” The replaced Core 6.2 states: “when CBC-mode algorithms are used ... relying parties SHOULD require the presence of integrity protection before processing encrypted SAML assertions or assertions containing encrypted data.”
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.fx</code> details</summary>

- **Required variants**:
  - `v-ffd828ebdf` The AuthnRequest sent by the subject to the upstream IdP is protected either by an XML or binding-specific signature, or by a synchronous binding with sender authentication and integrity protection.
- **Controls (negative controls)**:
  - ★ The AuthnRequest generated by the SP is IIP-SSO01.fj. A proxy IdP has a different observation path and different conditions, so it must be kept separate.
  - ★ Do not require a signature alone. The source text permits alternative protection provided by the binding, disjunctively.
- **Configuration failure semantics**: `test_precondition`
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Core)**; locator: `3\.4\.1 Element <AuthnRequest>||3\.4\.1\.1 Element <NameIDPolicy>`: SAML2Core 3.4.1.5.1 is part of the processing rules for <AuthnRequest> and enters the Web Browser SSO Profile through the incorporation clause in SAML2Prof 4.1.3.3. “The <AuthnRequest> message SHOULD be signed or otherwise authenticated and integrity protected by the protocol binding used to deliver the message.”
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.fy</code> details</summary>

- **Required variants**:
  - `v-bb849bf286` Make only the Assertion signature invalid and do not include a Response signature → do not establish a session.
  - `v-e9f659d273` Put a valid Assertion and an Assertion with an invalid signature in the same Response → do not rely on the attributes or Subject of the invalid one.
  - `v-3812b64e10` Control: a Response with the same content and a correctly valid Assertion signature → accepted.
- **Controls (negative controls)**:
  - ★ IIP-SSO01.ar concerns the Response signature, whereas this obligation concerns the Assertion signature. A case that breaks only the Response signature cannot prove the Assertion verification path.
  - ★ Determine non-reliance after verification failure separately from IIP-SSO01.n (verify the signature).
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Core)**; locator: `2\.3\.3 Element <Assertion>||2\.3\.4 Element <EncryptedAssertion>`: SAML2Prof 4.1.3.5 incorporates this through “The service provider MUST process the <Response> message and any enclosed <Assertion> elements as described in [SAMLCore].” “If it is invalid, then the relying party MUST NOT rely on the contents of the assertion.”
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.fz</code> details</summary>

- **Required variants**:
  - `v-60bd7fd182` A Response cryptographically correctly signed with the secondary_peer's key but with the subject IdP in Assertion/@Issuer → detect the mismatch and do not rely on it.
  - `v-b63544f795` Confirm through the subject's declaration or configuration evidence that the Assertion signature verification key is linked to the issuer's trusted metadata.
- **Controls (negative controls)**:
  - ★ IIP-SSO01.at concerns the Response signer, whereas this obligation concerns the Assertion issuer. They must be separated because the signature layers differ.
  - ★ Cryptographic signature success alone is insufficient. Check the correspondence between the trusted issuer and the key.
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Core)**; locator: `2\.3\.3 Element <Assertion>||2\.3\.4 Element <EncryptedAssertion>`: SAML2Prof 4.1.3.5 incorporates this through “The service provider MUST process the <Response> message and any enclosed <Assertion> elements as described in [SAMLCore].” “If it is valid, then the relying party SHOULD evaluate the signature to determine the identity and appropriateness of the issuer.”
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.ga</code> details</summary>

- **Required variants**:
  - `v-96adbf55c8` Provide low < high in the context-strength ordering declared by the subject, and request Comparison=minimum + low → on success, at least low.
  - `v-1c554772bb` Even in a configuration using AuthnContextDeclRef, the same minimum rule applies on success.
  - `v-f97a937262` Record an error Response for an unachievable requirement as conformant.
- **Controls (negative controls)**:
  - ★ Core states that the responder determines the strength of the context. Do not impose a Suite-specific ordering; compare using the ordering declared and configured by the subject.
  - ★ Errors are permitted, so only results on success are subject to the verdict. Do not treat an implementation that always returns an error as a violation based on this obligation alone.
- **Configuration failure semantics**: `test_precondition`
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Core)**; locator: `3\.3\.2\.2\.1 Element <RequestedAuthnContext>||3\.3\.2\.3 Element <AttributeQuery>`: SAML2Prof 4.1.3.3 incorporates this through “The identity provider MUST process the <AuthnRequest> message as described in [SAMLCore]” and 4.1.4.1 through “All processing rules are as defined in [SAMLCore].” “If Comparison is set to "minimum", then the resulting authentication context MUST be at least as strong (as deemed by the responder) as one of the authentication contexts specified.”
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.gb</code> details</summary>

- **Required variants**:
  - `v-5fe19b2dd9` Provide low < high in the context-strength ordering declared by the subject, and request Comparison=better + low → on success, a context stronger than low, such as high.
  - `v-a24a0bb304` Even in a configuration using AuthnContextDeclRef, the same better rule applies on success.
  - `v-09620a84ce` Record an error Response for an unachievable requirement as conformant.
- **Controls (negative controls)**:
  - ★ E45 did not remove the ordered-set rule; it conditioned it on cases where ordering is relevant. Because AuthnRequest explicitly states that ordering is significant, the candidate order is meaningful as preference order.
  - ★ However, preference order is not necessarily context-strength order. The strength determination for better is made by the responder; do not reinterpret list order as a Suite-specific strength order.
  - ★ Strength is determined by the responder. Do not add a Suite-specific ranking of authentication methods.
- **Configuration failure semantics**: `test_precondition`
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Errata)**; locator: `E45: AuthnContext Comparison Order||E46: `: SAML2Prof 4.1.3.3 incorporates this through “The identity provider MUST process the <AuthnRequest> message as described in [SAMLCore]” and 4.1.4.1 through “All processing rules are as defined in [SAMLCore].” As reflected after E45: “If Comparison is set to "better", then the resulting authentication context MUST be stronger (as deemed by the responder) than one of the authentication contexts specified.”
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.gc</code> details</summary>

- **Required variants**:
  - `v-783eafdabe` Provide low < medium < high in the context-strength ordering declared by the subject, make low and medium available, and request Comparison=maximum + high → on success, medium (the strongest value possible without exceeding the upper bound).
  - `v-f709ff344a` Even in a configuration using AuthnContextDeclRef, the same maximum rule applies on success.
  - `v-eb393305b0` Record an error Response for an unachievable requirement as conformant.
- **Controls (negative controls)**:
  - ★ Do not confuse “maximum” with returning the strongest authentication available. Select the strongest value without exceeding the requested upper bound.
  - ★ Merely not exceeding the upper bound is insufficient. Detect an implementation that returns low even though both low and medium are available.
  - ★ Because strength is determined by the responder, fix the ordering declared by the subject in the fixture.
- **Configuration failure semantics**: `test_precondition`
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Core)**; locator: `3\.3\.2\.2\.1 Element <RequestedAuthnContext>||3\.3\.2\.3 Element <AttributeQuery>`: SAML2Prof 4.1.3.3 incorporates this through “The identity provider MUST process the <AuthnRequest> message as described in [SAMLCore]” and 4.1.4.1 through “All processing rules are as defined in [SAMLCore].” “If Comparison is set to "maximum", then the resulting authentication context MUST be as strong as possible without exceeding the strength of at least one of the authentication contexts specified.”
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.gd</code> details</summary>

- **Required variants**:
  - `v-66d6ef3933` A configuration permitting multiple attesting entities → a separate bearer <SubjectConfirmation> exists for each entity.
  - `v-cab763dac1` Record the ordinary single-attesting-entity configuration as having no observation opportunity.
- **Controls (negative controls)**:
  - ★ Do not permit a structure that packs multiple entities into one SubjectConfirmation.
  - ★ This is not a rule that requires capability from a subject that cannot configure multiple attesting entities.
- **Configuration failure semantics**: `test_precondition`
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Errata)**; locator: `E47: Clarification on SubjectConfirmation||E48: `: The addition to SAMLProf 3.3 bearer confirmation states: “If multiple attesting entities are to be permitted to use the assertion based on bearer semantics, then multiple <SubjectConfirmation> elements SHOULD be included.” Web Browser SSO uses the bearer confirmation method in 4.1.1.
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.ge</code> details</summary>

- **Required variants**:
  - `v-d69c72d677` Configure multiple versions supported in common by the subject and the upstream Test IdP → the subject's upstream AuthnRequest uses the highest common version.
- **Controls (negative controls)**:
  - ★ The SP requester is IIP-SSO01.fg. Requests to the proxy IdP's upstream provider are a separate observation path and must be separated.
- **Configuration failure semantics**: `test_precondition`
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Core)**; locator: `4\.1\.3\.1 Request Version||4\.1\.3\.2 Response Version`: SAML2Core 3.4.1.5.1 is part of the processing rules for <AuthnRequest> and enters the Web Browser SSO Profile through the incorporation clause in SAML2Prof 4.1.3.3. “A SAML requester SHOULD issue requests with the highest request version supported by both the requester and the responder”
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.gf</code> details</summary>

- **Required variants**:
  - `v-49d3171470` Configuration in which no information about the upstream responder's version capabilities is provided → the subject's upstream AuthnRequest uses the highest version supported by the subject itself.
- **Controls (negative controls)**:
  - ★ The SP requester is IIP-SSO01.fh. If the capabilities are known through metadata or another means, this is outside the condition of the SHOULD.
- **Configuration failure semantics**: `test_precondition`
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Core)**; locator: `4\.1\.3\.1 Request Version||4\.1\.3\.2 Response Version`: SAML2Core 3.4.1.5.1 is part of the processing rules for <AuthnRequest> and enters the Web Browser SSO Profile through the incorporation clause in SAML2Prof 4.1.3.3. “If the SAML requester does not know the capabilities of the SAML responder, then it SHOULD assume that the responder supports requests with the highest request version supported by the requester”
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.gg</code> details</summary>

- **Required variants**:
  - `v-144f2abf3c` Restrict the response versions supported by the subject → the upstream AuthnRequest does not use a version corresponding to an unsupported response version.
- **Controls (negative controls)**:
  - ★ The SP requester is IIP-SSO01.el. Other messages generated by the proxy IdP follow the same rule.
- **Configuration failure semantics**: `test_precondition`
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Core)**; locator: `4\.1\.3\.1 Request Version||4\.1\.3\.2 Response Version`: SAML2Core 3.4.1.5.1 is part of the processing rules for <AuthnRequest> and enters the Web Browser SSO Profile through the incorporation clause in SAML2Prof 4.1.3.3. “A SAML requester MUST NOT issue a request message with an overall Major.Minor request version number matching a response version number that the requester does not support”
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.gh</code> details</summary>

- **Required variants**:
  - `v-d2c7785c91` When the subject includes @Consent indicating that consent was obtained in the upstream AuthnRequest, an XML signature or binding-specific signature is present.
- **Controls (negative controls)**:
  - ★ The SP's AuthnRequest is IIP-SSO01.am. If the proxy IdP does not send Consent, there is no observation opportunity.
- **Configuration failure semantics**: `test_precondition`
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Core)**; locator: `3\.2\.1 Complex Type RequestAbstractType||3\.2\.2 Complex Type StatusResponseType`: SAML2Core 3.4.1.5.1 is part of the processing rules for <AuthnRequest> and enters the Web Browser SSO Profile through the incorporation clause in SAML2Prof 4.1.3.3. “If a Consent attribute is included and the value indicates that some form of principal consent has been obtained, then the request SHOULD be signed”
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.gi</code> details</summary>

- **Required variants**:
  - `v-df86e8311a` Malformed AuthnRequest whose ID cannot be determined, such as one lacking @ID → if the subject returns a SAML Response, that Response has no @InResponseTo.
  - `v-7ceb1a2c3a` Control: Response to a valid AuthnRequest whose ID can be determined → @InResponseTo is present and matches it (IIP-SSO01.ap).
- **Controls (negative controls)**:
  - ★ IIP-SSO01.y concerns an unsolicited Response; this obligation is the error path in which a request arrived but its ID cannot be determined. It is a separate path and must be separated.
  - ★ The source text does not itself require returning a Response. An HTTP error or no response must not be treated as a violation of this obligation.
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Core)**; locator: `3\.2\.2 Complex Type StatusResponseType||3\.2\.2\.1 Element <Status>`: SAML2Prof 4.1.3.5 incorporates the rule: “The service provider MUST process the <Response> message and any enclosed <Assertion> elements as described in [SAMLCore]”. “If the response is not generated in response to a request, or if the ID attribute value of a request cannot be determined (for example, the request is malformed), then this attribute MUST NOT be present”
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO01.gj</code> details</summary>

- **Required variants**:
  - `v-f1a318dbe9` Request two satisfiable AuthnContextClassRef values of different strengths in the order [A, B] → upon success, A is preferred.
  - `v-3a6f061c0d` Reverse the same candidates to [B, A] → upon success, B is preferred.
  - `v-1650dc6d0a` Even when multiple AuthnContextDeclRef values are specified and both can be satisfied, evaluate the first as the highest priority.
- **Controls (negative controls)**:
  - ★ E45 did not delete the former unconditional ordered-set statement; it limited it to cases where ordering is relevant. Furthermore, because AuthnRequest is explicitly identified as an example where ordering is significant, the MUST applies in this profile.
  - ★ A case sending only one candidate cannot detect an implementation that ignores order. A control with the order reversed is mandatory.
  - ★ If the subject errors because it cannot satisfy any candidate, this is not positive evidence that order was evaluated; record it as not_verified.
- **Configuration failure semantics**: `test_precondition`
- **Referenced specification**: `SAML2Prof#4.1`
- **Reference basis (SAML2Errata)**; locator: `E45: AuthnContext Comparison Order||E46: `: SAML2Prof 4.1.3.3 incorporates “The identity provider MUST process the <AuthnRequest> message as described in [SAMLCore]” and 4.1.4.1 incorporates “All processing rules are as defined in [SAMLCore]”. After applying E45: “If ordering is relevant to the evaluation of the request, then the set of supplied references MUST be evaluated as an ordered set, where the first element is the most preferred ...”. The same addition explicitly states that ordering is significant for AuthnRequest.
- **source_clauses**: `[0, 125)` `sha256:ff1057626aaa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

#### IIP-SSO02

[Source](https://kantarainitiative.github.io/SAMLprofiles/fedinterop.html#IIP-SSO02) / Section digest `sha256:32e4a914797e…` / Section length 98 / Non-normative spans 0

| Obligation | Level | Role | Testability | Condition | Core/Full | Summary |
|---|---|---|---|---|---|---|
| `IIP-SSO02.a` | MUST | idp/sp | `BROWSER` | — | core | Support both HTTP-Redirect and HTTP-POST bindings for authentication requests |

<details><summary><code>IIP-SSO02.a</code> details</summary>

- **Required variants**:
  - `v-353a87bb1c` IdP: receive an AuthnRequest via Redirect
  - `v-7600aeab7a` IdP: receive an AuthnRequest via POST
  - `v-88385ab5d4` SP: issue with the SSO endpoint configured for Redirect only
  - `v-a9dd623dff` SP: issue with POST only
- **Controls (negative controls)**:
  - Have the SP issue requests in two configurations. Observation of only one configuration cannot prove support for both
- **Configuration failure semantics**: `normative_capability`
- **source_clauses**: `[0, 98)` `sha256:32e4a914797e…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

#### IIP-SSO03

[Source](https://kantarainitiative.github.io/SAMLprofiles/fedinterop.html#IIP-SSO03) / Section digest `sha256:9e1f7ca1df32…` / Section length 90 / Non-normative spans 0

| Obligation | Level | Role | Testability | Condition | Core/Full | Summary |
|---|---|---|---|---|---|---|
| `IIP-SSO03.a` | MUST | idp/sp | `BROWSER` | — | core | Support the HTTP-POST binding for authentication responses |
| `IIP-SSO03.b` | MUST | idp/sp | `BROWSER` | — | core | Support the HTTP-POST binding for error responses |

<details><summary><code>IIP-SSO03.a</code> details</summary>

- **Required variants**:
  - `v-f98fbee636` Send and receive a successful Response via POST
- **source_clauses**: `[0, 90)` `sha256:9e1f7ca1df32…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO03.b</code> details</summary>

- **Required variants**:
  - `v-3e0cb99090` SP: POST a Response whose Status is an error → whether it is handled as an error
  - `v-9710604856` IdP: issue an unsatisfiable request → whether an error Response is returned via POST
- **Controls (negative controls)**:
  - If the SP treats an error Response as successful, it is a violation (control)
- **source_clauses**: `[0, 90)` `sha256:9e1f7ca1df32…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

#### IIP-SSO04

[Source](https://kantarainitiative.github.io/SAMLprofiles/fedinterop.html#IIP-SSO04) / Section digest `sha256:23dda2a90643…` / Section length 102 / Non-normative spans 0

| Obligation | Level | Role | Testability | Condition | Core/Full | Summary |
|---|---|---|---|---|---|---|
| `IIP-SSO04.a` | MUST | idp/sp | `BROWSER` | — | core | Support signing of assertions and responses both together and independently |

<details><summary><code>IIP-SSO04.a</code> details</summary>

- **Required variants**:
  - `v-6bd0516694` Only the Assertion is signed
  - `v-cf1fe754f1` Only the Response is signed
  - `v-314e6b52c5` Both are signed
- **Controls (negative controls)**:
  - Verify all three configurations on both the sending and receiving sides. Observation of one configuration has no detection power
- **Configuration failure semantics**: `normative_capability`
- **source_clauses**: `[0, 102)` `sha256:23dda2a90643…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

#### IIP-SSO05

[Source](https://kantarainitiative.github.io/SAMLprofiles/fedinterop.html#IIP-SSO05) / Section digest `sha256:b44add5bc36e…` / Section length 274 / Non-normative spans 0

| Obligation | Level | Role | Testability | Condition | Core/Full | Summary |
|---|---|---|---|---|---|---|
| `IIP-SSO05.a` | MUST | idp/sp | `BROWSER` | — | core | Support the persistent name identifier format |
| `IIP-SSO05.a1` | MUST | idp | `ATTESTED` | — | core | Persistent identifiers must be constructed using pseudo-random values with no discernible correspondence with the subject's actual identifier |
| `IIP-SSO05.a2` | MUST_NOT | idp | `BROWSER` | — | core | Persistent name identifier values must not exceed a length of 256 characters |
| `IIP-SSO05.a3` | MUST | idp | `BROWSER` | — | core | NameQualifier / SPNameQualifier / SPProvidedID must carry the values defined by SAML2Core 8.3.7 when present |
| `IIP-SSO05.a4` | MUST_NOT | idp/sp | `NOT_OBSERVABLE` | — | core | Persistent identifiers must not be shared in clear text with other providers, and must not appear in log files without appropriate controls |
| `IIP-SSO05.a5` | MUST | idp | `BROWSER` | `supports_name_identifier_management`<br>(CAPABILITY_BASED) | core | SPProvidedID must contain the alternative identifier of the principal most recently set by the service provider or affiliation |
| `IIP-SSO05.a6` | MUST | idp | `CONFIG` | `reissues_foreign_persistent_identifier`<br>(CAPABILITY_BASED) | core | When re-issuing an identifier created by another entity, NameQualifier must continue to identify the entity that originally created it |
| `IIP-SSO05.a7` | MUST_NOT | idp | `CONFIG` | `reissues_foreign_persistent_identifier`<br>(CAPABILITY_BASED) | core | When re-issuing an identifier created by another entity, the NameQualifier attribute must not be omitted |
| `IIP-SSO05.a8` | MUST_NOT | idp | `ATTESTED` | — | core | Deployments must not overload the persistent format with persistent but non-opaque values |
| `IIP-SSO05.b` | MUST | idp/sp | `BROWSER` | — | core | Support the transient name identifier format |
| `IIP-SSO05.b1` | MUST_NOT | idp | `BROWSER` | — | core | Transient name identifier values must not exceed a length of 256 characters |
| `IIP-SSO05.b2` | MUST | idp | `BROWSER` | — | core | Transient identifier values must be generated in accordance with the rules for SAML identifiers (SAML2Core 1.3.4) |
| `IIP-SSO05.b3` | SHOULD | sp | `ATTESTED` | — | full | Relying parties should treat transient identifiers as opaque and temporary values |

<details><summary><code>IIP-SSO05.a</code> details</summary>

- **Required variants**:
  - `v-d97b574253` Request persistent using NameIDPolicy → the same Format is returned.
  - `v-2c2e3bda43` [SP consumer side] Accept a NameID with the persistent Format.
- **Controls (negative controls)**:
  - The obligation checks only the Format round trip. The individual rules in §8.3 are tested by the other obligations of this requirement (IIP-SSO05.a1 and later).
- **Referenced specification**: `SAML2Core#8.3.7`
- **Reference basis (SAML2Core)**; locator: `8\.3\.7 Persistent Identifier||8\.3\.8 Transient Identifier`: The normative obligations for persistent NameID are derived from §8.3.7 because IIP-SSO05 states that it is in accordance with ... [SAML2Core] §8.3; the test content is therefore derived from §8.3.7.
- **source_clauses**: `[0, 169)` `sha256:e66a1c4b4350…` , `[170, 222)` `sha256:200d6cc58795…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO05.a1</code> details</summary>

- **Required variants**:
  - `v-a609810263` The observed value does not contain a username, email address, or similar identifier (detection of an obvious violation)
  - `v-82c0464e15` Confirm by declaration that the generation method is pseudorandom
- **Controls (negative controls)**:
  - ★ Pseudorandomness itself cannot be evaluated from a single observation. Automatically detect only obvious violations; confirm the remainder by declaration
- **Referenced specification**: `SAML2Core#8.3.7`
- **Reference basis (SAML2Core)**; locator: `8\.3\.7 Persistent Identifier||8\.3\.8 Transient Identifier`: The normative obligations for persistent NameID are derived from §8.3.7 because IIP-SSO05 states that it is in accordance with ... [SAML2Core] §8.3; the test content is therefore derived from §8.3.7.
- **source_clauses**: `[0, 169)` `sha256:e66a1c4b4350…` , `[170, 222)` `sha256:200d6cc58795…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO05.a2</code> details</summary>

- **Required variants**:
  - `v-0c4fd26a5e` The length of the returned persistent NameID is at most 256 code points
- **Controls (negative controls)**:
  - Counterpart to the 256-character boundary in IIP-G02.a (that requirement concerns the receiving side; this one concerns the generating side)
- **Referenced specification**: `SAML2Core#8.3.7`
- **Reference basis (SAML2Core)**; locator: `8\.3\.7 Persistent Identifier||8\.3\.8 Transient Identifier`: The normative obligations for persistent NameID are derived from §8.3.7 because IIP-SSO05 states that it is in accordance with ... [SAML2Core] §8.3; the test content is therefore derived from §8.3.7.
- **source_clauses**: `[0, 169)` `sha256:e66a1c4b4350…` , `[170, 222)` `sha256:200d6cc58795…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO05.a3</code> details</summary>

- **Required variants**:
  - `v-84787b2fd4` If NameQualifier is present, it matches the IdP's entityID.
  - `v-744f78cb72` If SPNameQualifier is present, it matches the SP's entityID (or affiliation).
  - `v-f17f3d30e9` If the SP has never set an alternative identifier, SPProvidedID is omitted (the positive case when one has been set is IIP-SSO05.a5).
  - `v-2149cd7226` A different value is returned to secondary_peer (another SP) (pairwise pseudonym).
- **Controls (negative controls)**:
  - ★ Pairwise cannot be verified without pairing two SPs
  - ★ The expected NameQualifier is the entityID of the entity that generated the identifier, not the entityID of the sender. A configuration in which the target reissues an identifier generated by another entity is handled by IIP-SSO05.a6 / .a7
  - ★ Omission of NameQualifier / SPNameQualifier is permitted as a MAY in 8.3.7. Omission must not be treated as FAIL
- **Referenced specification**: `SAML2Core#8.3.7`
- **Reference basis (SAML2Core)**; locator: `8\.3\.7 Persistent Identifier||8\.3\.8 Transient Identifier`: The normative obligations for persistent NameID are derived from §8.3.7 because IIP-SSO05 states that it is in accordance with ... [SAML2Core] §8.3; the test content is therefore derived from §8.3.7.
- **source_clauses**: `[0, 169)` `sha256:e66a1c4b4350…` , `[170, 222)` `sha256:200d6cc58795…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO05.a4</code> details</summary>

- **Reason not observable**: Whether the identifier is shared with third parties or written to logs does not appear at the SAML protocol level. External black-box testing cannot distinguish conforming from non-conforming behavior.
- **Controls (negative controls)**:
  - —
- **Referenced specification**: `SAML2Core#8.3.7`
- **Reference basis (SAML2Core)**; locator: `8\.3\.7 Persistent Identifier||8\.3\.8 Transient Identifier`: The normative obligations for persistent NameID are derived from §8.3.7 because IIP-SSO05 states that it is in accordance with ... [SAML2Core] §8.3; the test content is therefore derived from §8.3.7.
- **source_clauses**: `[0, 169)` `sha256:e66a1c4b4350…` , `[170, 222)` `sha256:200d6cc58795…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO05.a5</code> details</summary>

- **Required variants**:
  - `v-1053afa95e` The SP (Samlier) sets an alternative identifier using <samlp:ManageNameIDRequest>/<samlp:NewID> → SPProvidedID in subsequent Assertions contains that value.
  - `v-468aec4df7` Update the alternative identifier twice → SPProvidedID contains the latest value (the first value does not remain).
  - `v-2304124410` The alternative identifier set by secondary_peer (another SP) does not appear in SPProvidedID for this SP (pairwise separation).
- **Controls (negative controls)**:
  - ★ Setting the value once and checking for a match does not verify the “most recently set value.” Update it twice and confirm that the old value does not remain.
  - ★ If the target does not support Name Identifier Management in SAML2Core 3.6, an alternative identifier cannot be established, so the result is NOT_APPLICABLE. Only the omission case (IIP-SSO05.a3) applies.
  - ★ <samlp:Terminate> means “termination of use of the identifier,” not “removal of SPProvidedID” (§3.6.3). Do not create a case that expects the identifier to become omitted after removal.
- **Referenced specification**: `SAML2Core#8.3.7`
- **Reference basis (SAML2Core)**; locator: `8\.3\.7 Persistent Identifier||8\.3\.8 Transient Identifier`: Positive-case basis. §8.3.7: “The element's SPProvidedID attribute MUST contain the alternative identifier of the principal most recently set by the service provider or affiliation, if any (see Section 3.6)”
- **Reference basis (SAML2Core)**; locator: `3\.6\.1 Element <ManageNameIDRequest>||3\.6\.2 Element <ManageNameIDResponse>`: Means of setting the alternative identifier. §3.6.1: “if the requester is the service provider, the new identifier MUST appear in subsequent <NameID> elements in the SPProvidedID attribute.” <NewID> has type="string", so it can also be used for the xs:string round trip in IIP-G02.c.
- **Notes**: The source text says, “MUST contain the alternative identifier of the principal most recently set by the service provider or affiliation, if any.” “If any” is a conditional clause: when one has been set, it branches to the positive MUST; when none has been set, it branches to the MUST to omit it (IIP-SSO05.a3). The previous version included only the omission side of this branch as a variant and did not test the positive case.
- **source_clauses**: `[0, 169)` `sha256:e66a1c4b4350…` , `[170, 222)` `sha256:200d6cc58795…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO05.a6</code> details</summary>

- **Required variants**:
  - `v-d4a93a7f08` Place Samlier as the upstream IdP, the target as the Proxy, and Samlier as the downstream SP, and have the target re-issue the persistent NameID issued by the upstream.
  - `v-337e37618a` The NameQualifier of the re-issued NameID remains the entityID of the upstream Samlier-IdP; it is not rewritten to the target's own entityID.
  - `v-d279d0116c` Control: when the target newly generates and returns its own persistent identifier, NameQualifier is the target's own. Do not mark this as FAIL.
- **Controls (negative controls)**:
  - ★ A test that unconditionally expects “NameQualifier == the entityID of the IdP that sent the response” misclassifies this re-issuance case.
  - ★ The upstream Samlier-IdP and downstream Samlier-SP roles are both played by Test Peers in the same Test Plan. testability is CONFIG because reconfiguration of the target is assumed. Browser interaction is also required at runtime.
  - ★ If the target cannot act as a Proxy, the condition is false → NOT_APPLICABLE. If it merely cannot be configured, the result is not_verified.
- **Configuration failure semantics**: `test_precondition`
- **Referenced specification**: `SAML2Core#8.3.7`
- **Reference basis (SAML2Core)**; locator: `8\.3\.7 Persistent Identifier||8\.3\.8 Transient Identifier`: The relevant sentence in §8.3.7 begins “Note that a different system entity might later issue...,” but contains MUST / MUST NOT and is therefore treated as normative. It is in scope because IIP-SSO05 incorporates the normative obligations of §8.3.
- **Notes**: The relevant sentence begins with “Note that” but contains MUST / MUST NOT. The “Finally, note that ...” restatement at the end of the same paragraph contains no RFC2119 keyword and therefore does not create an obligation.
- **source_clauses**: `[0, 169)` `sha256:e66a1c4b4350…` , `[170, 222)` `sha256:200d6cc58795…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO05.a7</code> details</summary>

- **Required variants**:
  - `v-95448cd3f3` The NameID in the re-issued Assertion contains a NameQualifier attribute.
  - `v-32059aa7ee` Control: for an identifier generated by the target itself, omission is permitted as MAY when it can be inferred from context. Do not mark this as FAIL.
- **Controls (negative controls)**:
  - ★ Under the general rule (§8.3.7), NameQualifier may be omitted when it can be inferred from context. Omission is prohibited only in the re-issuance case. These two cases must be paired to distinguish an implementation that always includes it from one that follows the rule.
- **Configuration failure semantics**: `test_precondition`
- **Referenced specification**: `SAML2Core#8.3.7`
- **Reference basis (SAML2Core)**; locator: `8\.3\.7 Persistent Identifier||8\.3\.8 Transient Identifier`: The relevant sentence in §8.3.7 begins “Note that a different system entity might later issue...,” but contains MUST / MUST NOT and is therefore treated as normative. It is in scope because IIP-SSO05 incorporates the normative obligations of §8.3.
- **Notes**: IIP-SSO05.a6 (value correctness) and this obligation (presence) are separate observations. If it is omitted, a6 cannot be satisfied either, but even a value satisfying a6 may be omitted, so the presence check must be independent.
- **source_clauses**: `[0, 169)` `sha256:e66a1c4b4350…` , `[170, 222)` `sha256:200d6cc58795…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO05.a8</code> details</summary>

- **Required variants**:
  - `v-3fde0a01ba` Automatic detection of an obvious violation: the returned value is in email-address form, in LDAP DN form, or matches a declared user identifier.
  - `v-7bad849f14` Confirm by declaration that the value is not a business identifier such as an employee number or student number.
- **Controls (negative controls)**:
  - ★ Although the observation surface overlaps with IIP-SSO05.a1 (constructing the identifier using pseudorandomness), the addressee and obligation differ. a1 concerns the IdP's generation method; this obligation prohibits deployments without privacy requirements from reusing the Format with persistent but non-opaque values.
  - ★ Opacity is a negative property, so automation can detect only obvious violations. The remainder must be declared.
- **Referenced specification**: `SAML2Core#8.3.7`
- **Reference basis (SAML2Core)**; locator: `8\.3\.7 Persistent Identifier||8\.3\.8 Transient Identifier`: The normative obligations for persistent NameID are derived from §8.3.7 because IIP-SSO05 states that it is in accordance with ... [SAML2Core] §8.3; the test content is therefore derived from §8.3.7.
- **Notes**: The source says, “Deployments without such requirements are free to use other kinds of identifiers in their SAML exchanges, but MUST NOT overload this format with persistent but non-opaque values.” The addressee is the deployment, but the subject of conformance testing is the deployed target implementation, so it can be tested.
- **source_clauses**: `[0, 169)` `sha256:e66a1c4b4350…` , `[170, 222)` `sha256:200d6cc58795…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO05.b</code> details</summary>

- **Required variants**:
  - `v-79f0292f65` Request transient using NameIDPolicy → the same Format is returned.
  - `v-1330d958f6` [SP consumer side] Accept a NameID with the transient Format.
- **Controls (negative controls)**:
  - The obligation checks only the Format round trip. The individual rules in §8.3.8 are tested by the other obligations of this requirement (IIP-SSO05.b1 and later).
- **Referenced specification**: `SAML2Core#8.3.8`
- **Reference basis (SAML2Core)**; locator: `8\.3\.8 Transient Identifier||8\.4 `: The normative obligations for transient NameID.
- **source_clauses**: `[0, 169)` `sha256:e66a1c4b4350…` , `[223, 274)` `sha256:5bab1ac68cbe…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO05.b1</code> details</summary>

- **Required variants**:
  - `v-60b49b6444` The length of the returned transient NameID is no more than 256 code points.
- **Controls (negative controls)**:
  - Perform the same check as IIP-SSO05.a2 for transient.
- **Referenced specification**: `SAML2Core#8.3.8`
- **Reference basis (SAML2Core)**; locator: `8\.3\.8 Transient Identifier||8\.4 `: The normative obligations for transient NameID.
- **source_clauses**: `[0, 169)` `sha256:e66a1c4b4350…` , `[223, 274)` `sha256:5bab1ac68cbe…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO05.b2</code> details</summary>

- **Required variants**:
  - `v-d5d42a4d54` The value conforms to the lexical rules for a SAML identifier (for example, it does not begin with a digit).
  - `v-d69fcf7f04` The value changes across two logins (the meaning of transient).
- **Controls (negative controls)**:
  - ★ “The value changes between two runs” alone does not test the lexical rules.
- **Referenced specification**: `SAML2Core#8.3.8`
- **Reference basis (SAML2Core)**; locator: `8\.3\.8 Transient Identifier||8\.4 `: The normative obligations for transient NameID.
- **source_clauses**: `[0, 169)` `sha256:e66a1c4b4350…` , `[223, 274)` `sha256:5bab1ac68cbe…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO05.b3</code> details</summary>

- **Required variants**:
  - `v-c67c0b54d4` Confirm by declaration that the transient NameID is not stored as a persistent identifier.
- **Controls (negative controls)**:
  - ★ Because this is SHOULD, a violation is WARNING. Handling inside the SP cannot be observed.
- **Referenced specification**: `SAML2Core#8.3.8`
- **Reference basis (SAML2Core)**; locator: `8\.3\.8 Transient Identifier||8\.4 `: The normative obligations for transient NameID.
- **source_clauses**: `[0, 169)` `sha256:e66a1c4b4350…` , `[223, 274)` `sha256:5bab1ac68cbe…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

#### IIP-SSO06

[Source](https://kantarainitiative.github.io/SAMLprofiles/fedinterop.html#IIP-SSO06) / Section digest `sha256:5f89f43ec523…` / Section length 1318 / Non-normative spans 3

| Obligation | Level | Role | Testability | Condition | Core/Full | Summary |
|---|---|---|---|---|---|---|
| `IIP-SSO06.a` | MUST | idp/sp | `CONFIG` | `setting_supported_by_implementation`<br>(CAPABILITY_BASED) | core | Consume peer configuration values from metadata, without additional inputs, for every element identified as MUST or MAY in SAML2Prof 4.1.6 that corresponds to a supported setting |

<details><summary><code>IIP-SSO06.a</code> details</summary>

- **Required variants**:
  - `v-03f60bb35b` md:IDPSSODescriptor/@WantAuthnRequestsSigned — MAY be used by an identity provider to document a requirement that requests be signed
  - `v-7b96873711` md:SPSSODescriptor/@AuthnRequestsSigned — MAY be used by a service provider to document the intention to sign all of its requests
  - `v-f62a2e7351` md:KeyDescriptor use=signing — providers MAY document the key(s) used to sign requests, responses, and assertions (Errata 05 E58 changes sign to signing).
  - `v-6c76bf31dc` md:KeyDescriptor use=encryption — MAY be used to document supported encryption algorithms and settings, and public keys (Errata 05 E58 changes encrypt to encryption).
  - `v-87b1079472` md:SPSSODescriptor/@WantAssertionsSigned — MAY be used by a service provider to document a requirement that assertions be signed
  - `v-32b77fa59b` md:ArtifactResolutionService — conditional MUST: when delivery uses the HTTP Artifact binding, the artifact issuer MUST provide at least one.
  - `v-43b44b0983` md:IDPSSODescriptor MAY contain md:NameIDFormat, md:AttributeProfile, and saml:Attribute.
  - `v-dec1ae9bfb` md:AttributeConsumingService — One or more ... MAY be included in its metadata (@index and @isDefault are part of this element and are not individually specified as MAY).
- **Controls (negative controls)**:
  - Change the Suite metadata value for each element and observe whether the target's behavior follows the change.
  - If an element does not follow the change, first confirm whether the target has the configuration corresponding to that element (condition (b) of IIP-SSO06), and then make the determination.
  - ★ md:SingleSignOnService and md:AssertionConsumerService are described in §4.1.6 without RFC2119 keywords, so they do not meet condition (a) of IIP-SSO06 (“elements indicated with ‘MUST’ or ‘MAY’”) and are outside the scope of this obligation.
- **Referenced by**: `IIP-IDP16.a` incorporates this obligation via `inherit_variants`. Editing this obligation's variants also affects `IIP-IDP16.a` cases.
- **Configuration failure semantics**: `normative_capability`
- **Referenced specification**: `SAML2Prof#4.1.6`
- **Reference basis (SAML2Prof)**; locator: `4\.1\.6\s+Use of Metadata||4\.2\s+Enhanced Client or Proxy`: Read the entire text of §4.1.6 and list only the elements accompanied by RFC2119 MUST / MAY.
- **Notes**: Per Errata 05 E58, the allowed values of KeyDescriptor's use attribute are signing and encryption.
- **source_clauses**: `[0, 376)` `sha256:7bf32b4a620f…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

#### IIP-SSO07

[Source](https://kantarainitiative.github.io/SAMLprofiles/fedinterop.html#IIP-SSO07) / Section digest `sha256:72d0eb9146c7…` / Section length 1077 / Non-normative spans 1

| Obligation | Level | Role | Testability | Condition | Core/Full | Summary |
|---|---|---|---|---|---|---|
| `IIP-SSO07.a` | OPTIONAL | idp/sp | `AUTOMATED` | — | full | Including optional elements and attributes in issued messages and assertions is optional |
| `IIP-SSO07.b` | REQUIRED | idp/sp | `BROWSER` | — | core | Successfully process messages and assertions containing unsupported optional content — such content must either result in errors or be ignored, as directed by SAML2Core processing rules for that element |

<details><summary><code>IIP-SSO07.a</code> details</summary>

- **Required variants**:
  - `v-dd69ae37fc` Record as information whether the target generates the optional element; do not evaluate it.
- **Controls (negative controls)**:
  - Do not treat failure to generate it as a violation.
- **source_clauses**: `[75, 217)` `sha256:4502107e9167…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SSO07.b</code> details</summary>

- **Required variants**:
  - `v-d6027c6344` Verdict subject: an AuthnRequest containing <saml:Subject>. SAML2Core 3.4.1.4 specifies a unique outcome: the Subject of the returned Assertion must strongly match the request, or an error <Status> must be returned if the requested subject cannot be recognized.
  - `v-d14758c55d` strong match — identifier: the content and all attributes of the requested Subject's BaseID / NameID / EncryptedID match those of the response Subject's identifier after decryption (only when NameIDPolicy specifies a different Format may the physical values differ, provided they identify the same subject).
  - `v-3da131fa07` strong match — encryption: even if only one of the request and response uses EncryptedID, treat them as matching if their identifiers are identical after decryption.
  - `v-5faf2fe37d` strong match — confirmation: if the requested Subject contains at least one SubjectConfirmation, the response Subject contains a SubjectConfirmation that can be confirmed by at least one of those methods.
  - `v-bcc37b4f47` negative control: return as a successful response an Assertion whose identifier content or attributes differ, or that satisfies none of the requested confirmation methods → violated.
  - `v-56887fd6a7` Information only: <saml:Conditions> (SAML2Core 3.4.1: 'The responder MAY modify or supplement this set as it deems necessary').
  - `v-81a7b8d524` Out of scope (the incorporated SAML2Core rules address it): <Scoping>/@ProxyCount and <IDPList> — the ProxyCount=0 error handling and proxying rules after applying E65 are evaluated under IIP-SSO01.aw through .bd. However, those rules are conditional on 'proxying'; an IdP that does not proxy is conformant if it ignores Scoping.
  - `v-67bb50c96f` Information only: <RequesterID> (SAML2Core 3.4.1.2 contains no processing-rule description, and the <IDPList> inspection in 3.4.1.2 is a two-outcome rule: 'the intermediary MAY examine the list and return ...').
  - `v-9c7fd0cbe3` Information only: invalid AssertionConsumerServiceIndex (SAML2Core 3.4.1 explicitly permits either 'MAY return an error <Response> or it MAY use the default location').
  - `v-d36db51eb7` Information only: ProviderName / Consent — SAML2Core contains no processing-rule description.
  - `v-805f1e5039` Out of scope (other obligations address the specific processing rules): <NameIDPolicy> → IIP-IDP10 and IIP-SSO01.fl through .fp / <RequestedAuthnContext> exact → IIP-IDP08, minimum/better/maximum → IIP-SSO01.ga through .gc, candidate ordering → .gj / ForceAuthn → IIP-IDP06 / IsPassive → IIP-IDP07 / AssertionConsumerServiceURL, ProtocolBinding, and AssertionConsumerServiceIndex → IIP-IDP12 / AttributeConsumingServiceIndex → IIP-IDP04.b / <Extensions> and <Advice> → IIP-EXT01.
- **Controls (negative controls)**:
  - Evaluation rule: only elements for which SAML2Core specifies a unique outcome (error XOR ignore) are verdict subjects. Elements for which either of two outcomes is permitted receive no verdict and are recorded for information only.
  - ★ Correction: the previous version grouped <Scoping>, ProxyCount, and <IDPList> together as information-only because they allowed two outcomes, but SAML2Core 3.4.1.5.1 contains explicit MUST NOT / MUST requirements for ProxyCount and IDPList. Via the incorporated text (SAML2Prof 4.1.3.3), these were decomposed into IIP-SSO01.aw through .bd.
  - ★ Conclusion of the cross-cutting review: among the optional AuthnRequest content, <saml:Conditions>, <RequesterID>, ProviderName, and Consent are not addressed by other IIP requirements or obligations derived from incorporated text, and none has a unique processing rule. Only <saml:Subject>, which has a unique processing rule, is a verdict subject of this obligation.
  - The opening phrase of the source, 'Unless specifically called out by subsequent requirements in this profile,' excludes elements addressed by other IIP requirements from the scope of this obligation.
- **Referenced specification**: `SAML2Core#3.4.1`
- **Reference basis (SAML2Core)**; locator: `3\.4\.1\s+Element <AuthnRequest>||3\.4\.1\.1\s+Element <NameIDPolicy>`: List of optional AuthnRequest elements and attributes, and the two-outcome rules for Conditions and AssertionConsumerServiceIndex.
- **Reference basis (SAML2Core)**; locator: `3\.4\.1\.4\s+Processing Rules||3\.4\.1\.5\s+`: The unique processing rule for <saml:Subject> (strongly match / error Status).
- **Reference basis (SAML2Core)**; locator: `3\.3\.4\s+Processing Rules||3\.4\s+Authentication Request Protocol`: Definition of strongly match (post-decryption identity of the identifier, matching content and attributes, and confirmability of SubjectConfirmation).
- **Reference basis (SAML2Core)**; locator: `3\.4\.1\.2\s+Element <Scoping>||3\.4\.1\.3\s+`: <Scoping> / <IDPList> have two permitted outcomes ('MAY examine ... and return an error').
- **Notes**: I directly read SAML2Core 3.4.1 / 3.4.1.4 (saml-core-2.0-os, sha256:dc0890f8…) and finalized the evaluation rules and verdict subjects. This also agrees with the source's non-normative examples (Subject has required semantics, while Conditions has optional semantics).
- **source_clauses**: `[219, 497)` `sha256:ea583e6744f8…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

### 2.4 Common / Extensibility

#### IIP-EXT01

[Source](https://kantarainitiative.github.io/SAMLprofiles/fedinterop.html#IIP-EXT01) / Section digest `sha256:224aadd3c64e…` / Section length 510 / Non-normative spans 0

| Obligation | Level | Role | Testability | Condition | Core/Full | Summary |
|---|---|---|---|---|---|---|
| `IIP-EXT01.a` | MUST | idp/sp | `BROWSER` | — | core | Successfully consume any and all well-formed extensions |
| `IIP-EXT01.b1` | MAY | idp/sp | `BROWSER` | — | full | The content of samlp:Extensions, md:Extensions and saml:Advice may be ignored |
| `IIP-EXT01.b` | MUST_NOT | idp/sp | `BROWSER` | — | core | Content of samlp:Extensions, md:Extensions and saml:Advice may be ignored but must not result in software failures |
| `IIP-EXT01.c1` | MAY | idp/sp | `BROWSER` | — | full | Undefined attribute content on elements whose type definition contains xsd:anyAttribute may likewise be ignored |
| `IIP-EXT01.c` | MUST_NOT | idp/sp | `BROWSER` | — | core | Undefined attribute content on elements whose type definition contains xsd:anyAttribute may be ignored but must not result in software failures |

<details><summary><code>IIP-EXT01.a</code> details</summary>

- **Required variants**:
  - `v-35bad2ee0e` A successful flow containing a well-formed extension element in an unknown namespace.
- **source_clauses**: `[0, 77)` `sha256:fbe3e14936db…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-EXT01.b1</code> details</summary>

- **Required variants**:
  - `v-a40ed1abd1` Record as information that the extension content was not reflected; do not use it for the verdict.
- **Controls (negative controls)**:
  - Do not treat ignored content as a violation; ignoring is permitted, not required.
- **source_clauses**: `[118, 211)` `sha256:b791ed59cb10…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-EXT01.b</code> details</summary>

- **Required variants**:
  - `v-0d8fcda487` An unknown element in samlp:Extensions.
  - `v-d0a7cbcd56` An unknown element in md:Extensions.
  - `v-572cf4d0bd` An unknown element in saml:Advice.
- **Controls (negative controls)**:
  - Use separate variants for all three elements. Judge only whether no software failure occurs; do not treat failure to reflect the content as a violation.
- **source_clauses**: `[188, 252)` `sha256:b34c8c238913…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-EXT01.c1</code> details</summary>

- **Required variants**:
  - `v-820900fd29` Record as information that the unknown attribute was not reflected; do not use it for the verdict.
- **source_clauses**: `[432, 468)` `sha256:798d677c4e7e…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-EXT01.c</code> details</summary>

- **Required variants**:
  - `v-3efd721c6d` Schema-driven matrix: for every applicable element established in SAML2-xsd or SAML2MD-xsd whose declared type definition directly contains xsd:anyAttribute, add a foreign-namespace undefined attribute and consume the otherwise schema-valid message or metadata document.
- **Controls (negative controls)**:
  - Generate the fixture matrix from the pinned SAML2-xsd and SAML2MD-xsd schemas rather than a handwritten element list.
  - Include only elements whose declared type definition directly contains xsd:anyAttribute. Use a foreign, non-SAML namespace so every fixture remains schema-valid.
  - Unknown attributes exercise a path distinct from unknown elements. Judge only whether the content causes a software failure; ignoring it is permitted.
- **source_clauses**: `[432, 510)` `sha256:c0b40d046c81…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

### 2.5 Common / Cryptographic Algorithms

#### IIP-ALG01

[Source](https://kantarainitiative.github.io/SAMLprofiles/fedinterop.html#IIP-ALG01) / Section digest `sha256:8d6c5d8785fe…` / Section length 210 / Non-normative spans 0

| Obligation | Level | Role | Testability | Condition | Core/Full | Summary |
|---|---|---|---|---|---|---|
| `IIP-ALG01.a` | MUST | idp/sp | `BROWSER` | — | core | Support the SHA-256 digest algorithm for creation and verification of XML Signatures |

<details><summary><code>IIP-ALG01.a</code> details</summary>

- **Required variants**:
  - `v-68bb80d43d` The Suite signs using SHA-256; the signature is verified.
  - `v-d2ca094885` Observe the DigestMethod of signatures generated by the target.
- **Controls (negative controls)**:
  - Examine both the generation and verification sides.
- **source_clauses**: `[0, 161)` `sha256:b6bf2b68df09…` , `[162, 210)` `sha256:af381b64781b…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

#### IIP-ALG02

[Source](https://kantarainitiative.github.io/SAMLprofiles/fedinterop.html#IIP-ALG02) / Section digest `sha256:f2d0d73c3799…` / Section length 224 / Non-normative spans 0

| Obligation | Level | Role | Testability | Condition | Core/Full | Summary |
|---|---|---|---|---|---|---|
| `IIP-ALG02.a` | MUST | idp/sp | `BROWSER` | — | core | Support the RSA-SHA256 signature algorithm for creation and verification of XML Signatures |

<details><summary><code>IIP-ALG02.a</code> details</summary>

- **Required variants**:
  - `v-7d65d44317` The Suite signs using RSA-SHA256; the signature is verified.
  - `v-f614cc24f2` Observe the SignatureMethod of signatures generated by the target.
- **source_clauses**: `[0, 164)` `sha256:0f8cfe5f768e…` , `[165, 224)` `sha256:cd9524eeed35…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

#### IIP-ALG03

[Source](https://kantarainitiative.github.io/SAMLprofiles/fedinterop.html#IIP-ALG03) / Section digest `sha256:89164a697161…` / Section length 228 / Non-normative spans 0

| Obligation | Level | Role | Testability | Condition | Core/Full | Summary |
|---|---|---|---|---|---|---|
| `IIP-ALG03.a` | SHOULD | idp/sp | `BROWSER` | — | full | Should support the ECDSA-SHA256 signature algorithm |

<details><summary><code>IIP-ALG03.a</code> details</summary>

- **Required variants**:
  - `v-c2172c8c5c` Suite metadata containing an EC key, plus an ECDSA-SHA256 signature.
- **source_clauses**: `[0, 166)` `sha256:b1a3ee05b976…` , `[167, 228)` `sha256:01026de6d26f…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

#### IIP-ALG04

[Source](https://kantarainitiative.github.io/SAMLprofiles/fedinterop.html#IIP-ALG04) / Section digest `sha256:a9c0ba8421c4…` / Section length 253 / Non-normative spans 0

| Obligation | Level | Role | Testability | Condition | Core/Full | Summary |
|---|---|---|---|---|---|---|
| `IIP-ALG04.a` | MUST | idp/sp | `BROWSER` | — | core | Support the AES128-GCM block encryption algorithm |
| `IIP-ALG04.b` | MUST | idp/sp | `BROWSER` | — | core | Support the AES256-GCM block encryption algorithm |

<details><summary><code>IIP-ALG04.a</code> details</summary>

- **Required variants**:
  - `v-caac1615db` An Assertion encrypted with AES128-GCM is decrypted.
  - `v-757662f824` Observe the EncryptionMethod generated by the target.
- **Controls (negative controls)**:
  - This is a separate variant from ALG04.b; detect implementations that support only one of them.
- **source_clauses**: `[0, 149)` `sha256:13d87f311f30…` , `[150, 201)` `sha256:9f1a39f71c80…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-ALG04.b</code> details</summary>

- **Required variants**:
  - `v-ce0aeebcf0` An Assertion encrypted with AES256-GCM is decrypted.
- **source_clauses**: `[0, 149)` `sha256:13d87f311f30…` , `[202, 253)` `sha256:c51f189a9750…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

#### IIP-ALG05

[Source](https://kantarainitiative.github.io/SAMLprofiles/fedinterop.html#IIP-ALG05) / Section digest `sha256:9aec9a7a9af8…` / Section length 485 / Non-normative spans 0

| Obligation | Level | Role | Testability | Condition | Core/Full | Summary |
|---|---|---|---|---|---|---|
| `IIP-ALG05.a` | MAY | idp/sp | `BROWSER` | — | full | May support AES-CBC block encryption algorithms for backwards compatibility |
| `IIP-ALG05.b` | SHOULD | idp/sp | `ATTESTED` | `supports_cbc`<br>(CAPABILITY_BASED) | full | Implementations supporting AES-CBC should warn on use |

<details><summary><code>IIP-ALG05.a</code> details</summary>

- **Required variants**:
  - `v-c16fcb2cd4` AES128-CBC
  - `v-dc06f9c264` AES256-CBC
- **Controls (negative controls)**:
  - Lack of support yields NOT_SUPPORTED, not a violation.
- **source_clauses**: `[0, 176)` `sha256:989c558053ce…` , `[177, 229)` `sha256:c14640817b7b…` , `[230, 282)` `sha256:57d120372c50…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-ALG05.b</code> details</summary>

- **Required variants**:
  - `v-5eb6f7a6ba` Have the user configure CBC use and attest whether a warning appears in logs, the UI, or configuration screens.
- **Configuration failure semantics**: `test_precondition`
- **Notes**: This non-italicized SHOULD is normative. The previous version's rule, "WARNING if CBC is the default," was absent from the source and has been removed.
- **source_clauses**: `[434, 485)` `sha256:092e01d660bb…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

#### IIP-ALG06

[Source](https://kantarainitiative.github.io/SAMLprofiles/fedinterop.html#IIP-ALG06) / Section digest `sha256:b69c91cb5f3c…` / Section length 595 / Non-normative spans 0

| Obligation | Level | Role | Testability | Condition | Core/Full | Summary |
|---|---|---|---|---|---|---|
| `IIP-ALG06.a` | MUST | idp/sp | `BROWSER` | — | core | Support the rsa-oaep-mgf1p key transport algorithm |
| `IIP-ALG06.b` | MUST | idp/sp | `BROWSER` | — | core | Support the rsa-oaep key transport algorithm |
| `IIP-ALG06.c` | MUST | idp/sp | `BROWSER` | — | core | Support DigestMethod sha256 and sha1 for both key transport algorithms |
| `IIP-ALG06.d` | MUST | idp/sp | `BROWSER` | — | core | Support the default mask generation function (MGF1 with SHA1) for rsa-oaep |

<details><summary><code>IIP-ALG06.a</code> details</summary>

- **Required variants**:
  - `v-8826dd288f` An Assertion whose key was transported using rsa-oaep-mgf1p.
- **source_clauses**: `[0, 146)` `sha256:95da6649c896…` , `[147, 203)` `sha256:9fe50ef0a275…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-ALG06.b</code> details</summary>

- **Required variants**:
  - `v-d682ac8588` An Assertion whose key was transported using rsa-oaep.
- **source_clauses**: `[0, 146)` `sha256:95da6649c896…` , `[204, 253)` `sha256:dcccf3518c1f…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-ALG06.c</code> details</summary>

- **Required variants**:
  - `v-8812cd0959` oaep-mgf1p + sha256
  - `v-ea0501e2c5` oaep-mgf1p + sha1
  - `v-2a76534278` rsa-oaep + sha256
  - `v-0791ed212e` rsa-oaep + sha1
- **Controls (negative controls)**:
  - Test all four combinations of two algorithms and two digests.
- **source_clauses**: `[0, 146)` `sha256:95da6649c896…` , `[254, 357)` `sha256:3a58e24fe6c6…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-ALG06.d</code> details</summary>

- **Required variants**:
  - `v-a012befa2c` rsa-oaep with MGF1-SHA1, the default case in which the MGF is not explicitly specified.
- **source_clauses**: `[0, 146)` `sha256:95da6649c896…` , `[437, 595)` `sha256:3af2f3ce27e9…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

#### IIP-ALG07

[Source](https://kantarainitiative.github.io/SAMLprofiles/fedinterop.html#IIP-ALG07) / Section digest `sha256:44246f8fe2b7…` / Section length 198 / Non-normative spans 0

| Obligation | Level | Role | Testability | Condition | Core/Full | Summary |
|---|---|---|---|---|---|---|
| `IIP-ALG07.a` | RECOMMENDED | idp/sp | `ATTESTED` | — | full | Recommended: consider RFC7457 and current TLS best practice |

<details><summary><code>IIP-ALG07.a</code> details</summary>

- **Required variants**:
  - `v-4e31984759` Observe the TLS handshake from the Suite to the target endpoint, including protocol version and cipher suite.
- **Controls (negative controls)**:
  - A single TLS-handshake observation cannot prove that RFC 7457 and current best practices were considered globally. Record the observation as information; base the verdict on user attestation.
- **Notes**: Correction: the previous version was AUTOMATED. What can be observed is factual—the TLS version and cipher suite used—not whether they were considered. The source also states, "This document is not normative with respect to TLS security."
- **source_clauses**: `[61, 198)` `sha256:54ab3c733ee5…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

#### IIP-ALG08

[Source](https://kantarainitiative.github.io/SAMLprofiles/fedinterop.html#IIP-ALG08) / Section digest `sha256:7b6623731dbb…` / Section length 449 / Non-normative spans 0

| Obligation | Level | Role | Testability | Condition | Core/Full | Summary |
|---|---|---|---|---|---|---|
| `IIP-ALG08.a` | MUST | idp/sp | `CONFIG` | — | core | Support the ability to prevent the use of particular algorithms so that any attempt to configure or select them fails |
| `IIP-ALG08.b` | MUST | idp/sp | `CONFIG` | — | core | The set of prevented algorithms must be configurable |
| `IIP-ALG08.c` | RECOMMENDED | idp/sp | `ATTESTED` | — | full | Recommended: the default prevented set includes md5, rsa-md5 and rsa-1_5 |

<details><summary><code>IIP-ALG08.a</code> details</summary>

- **Required variants**:
  - `v-4ff893513e` Have the user configure RSA-1.5 as prevented, then determine whether an Assertion encrypted using RSA-1.5 is rejected.
  - `v-26d3e6023e` As a control, an algorithm that is not prevented is accepted.
- **Configuration failure semantics**: `normative_capability`
- **source_clauses**: `[0, 158)` `sha256:c63a3041cf05…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-ALG08.b</code> details</summary>

- **Required variants**:
  - `v-51b4d7eb3d` Determine whether algorithms can be added to and removed from the set.
- **Configuration failure semantics**: `normative_capability`
- **source_clauses**: `[159, 206)` `sha256:31a9af35cd3f…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-ALG08.c</code> details</summary>

- **Required variants**:
  - `v-bd58331c02` With default configuration unchanged, send an MD5 signature and RSA-1.5 key transport and determine whether they are rejected.
- **Notes**: Not being prevented by default is not FAIL: RECOMMENDED maps to WARNING.
- **source_clauses**: `[211, 258)` `sha256:dce1af2e995e…` , `[266, 318)` `sha256:439a7fbb6a6c…` , `[329, 385)` `sha256:645b4323254d…` , `[400, 449)` `sha256:94d25a2a6e8d…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

### 3.1 Service Provider / Web Browser SSO

#### IIP-SP01

[Source](https://kantarainitiative.github.io/SAMLprofiles/fedinterop.html#IIP-SP01) / Section digest `sha256:f215d50e93db…` / Section length 201 / Non-normative spans 0

| Obligation | Level | Role | Testability | Condition | Core/Full | Summary |
|---|---|---|---|---|---|---|
| `IIP-SP01.a` | MUST | sp | `BROWSER` | — | core | Consume saml:Attribute elements with any arbitrary xs:string Name and any arbitrary xs:anyURI NameFormat |

<details><summary><code>IIP-SP01.a</code> details</summary>

- **Required variants**:
  - `v-544afdeba5` Name in URN form
  - `v-aff59ed0bd` Long OID
  - `v-ea110a56a2` Name containing non-ASCII characters
  - `v-73c9fe76b6` Unknown NameFormat URI
  - `v-c2640a2ba4` NameFormat omitted
- **Controls (negative controls)**:
  - Confirmation that the attribute was received is ATTESTED. First, automatically determine that no error occurs.
- **source_clauses**: `[0, 201)` `sha256:f215d50e93db…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

#### IIP-SP02

[Source](https://kantarainitiative.github.io/SAMLprofiles/fedinterop.html#IIP-SP02) / Section digest `sha256:f1ed3c95c82e…` / Section length 363 / Non-normative spans 0

| Obligation | Level | Role | Testability | Condition | Core/Full | Summary |
|---|---|---|---|---|---|---|
| `IIP-SP02.a` | MUST | sp | `BROWSER` | — | core | Consume saml:AttributeValue elements containing any simple (text-only) element content |
| `IIP-SP02.b` | MUST_NOT | sp | `BROWSER` | — | core | Must not require the presence of the xsi:type attribute on AttributeValue |
| `IIP-SP02.c` | OPTIONAL | sp | `BROWSER` | — | full | Support for complex (mixed/nested) AttributeValue content is optional |

<details><summary><code>IIP-SP02.a</code> details</summary>

- **Required variants**:
  - `v-45f7c3f7d1` Simple text value
  - `v-fc0f5a1270` Empty-string value
  - `v-1b758958d0` Whitespace-only value
- **source_clauses**: `[0, 241)` `sha256:ab4988e76741…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SP02.b</code> details</summary>

- **Required variants**:
  - `v-7314cfd1e1` AttributeValue without xsi:type
  - `v-4b53de3244` AttributeValue with xsi:type=xs:string (control)
- **Controls (negative controls)**:
  - Use a variant with xsi:type to establish the control, and detect implementations that reject only the variant without it.
- **source_clauses**: `[285, 363)` `sha256:6e6c5dcfbf2c…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SP02.c</code> details</summary>

- **Required variants**:
  - `v-e1554a6df6` Send an AttributeValue containing nested elements and record the support status as information
- **Controls (negative controls)**:
  - Lack of support yields NOT_SUPPORTED, not a violation.
- **source_clauses**: `[242, 284)` `sha256:52cf69ff062a…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

#### IIP-SP03

[Source](https://kantarainitiative.github.io/SAMLprofiles/fedinterop.html#IIP-SP03) / Section digest `sha256:100e1a7d1291…` / Section length 181 / Non-normative spans 0

| Obligation | Level | Role | Testability | Condition | Core/Full | Summary |
|---|---|---|---|---|---|---|
| `IIP-SP03.a` | MUST | sp | `CONFIG` | — | core | Be capable of generating AuthnRequest messages without a samlp:NameIDPolicy element |
| `IIP-SP03.b` | MUST | sp | `CONFIG` | — | core | Be capable of generating AuthnRequest messages with a NameIDPolicy element but no Format attribute |

<details><summary><code>IIP-SP03.a</code> details</summary>

- **Required variants**:
  - `v-08ce1eb9d8` Have it issue an AuthnRequest without a NameIDPolicy and statically inspect the received AuthnRequest
- **Configuration failure semantics**: `normative_capability`
- **source_clauses**: `[0, 116)` `sha256:765325dd4101…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SP03.b</code> details</summary>

- **Required variants**:
  - `v-dca1827622` Have it issue an AuthnRequest with a NameIDPolicy and without a Format attribute
- **Configuration failure semantics**: `normative_capability`
- **source_clauses**: `[117, 180)` `sha256:338191d91556…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

#### IIP-SP04

[Source](https://kantarainitiative.github.io/SAMLprofiles/fedinterop.html#IIP-SP04) / Section digest `sha256:9f4cd8b6cb55…` / Section length 421 / Non-normative spans 2

| Obligation | Level | Role | Testability | Condition | Core/Full | Summary |
|---|---|---|---|---|---|---|
| `IIP-SP04.a` | MUST | sp | `BROWSER` | — | full | Support the IdP Discovery redirect protocol end to end as a Service Provider |
| `IIP-SP04.b` | MUST | sp | `BROWSER` | — | full | Initiate the Discovery Protocol by redirecting the user agent to the Discovery Service with HTTP GET |
| `IIP-SP04.c` | MUST | sp | `BROWSER` | — | full | Support at least the single-selection Discovery Service policy value |
| `IIP-SP04.d` | MUST | sp | `BROWSER` | — | full | Include the SP entityID parameter in every Discovery request |
| `IIP-SP04.e` | MUST | sp | `BROWSER` | — | full | URL-encode the entityID parameter in a Discovery request |
| `IIP-SP04.f` | MUST_NOT | sp | `BROWSER` | — | full | Do not place the effective returned-IdP parameter name in the query component of the return URL |
| `IIP-SP04.g` | MUST | sp | `BROWSER` | — | full | For every Discovery request, include return or use a default DiscoveryResponse endpoint from metadata |
| `IIP-SP04.h` | MUST | sp | `AUTOMATED` | — | full | Set DiscoveryResponse/@Binding to the IdP Discovery Protocol URI whenever publishing that metadata extension |
| `IIP-SP04.i` | MUST | sp | `AUTOMATED` | — | full | Publish each DiscoveryResponse metadata extension with the md:IndexedEndpointType structure defined by IdPDisco |

<details><summary><code>IIP-SP04.a</code> details</summary>

- **Required variants**:
  - `v-6db16b8b8e` The Suite acts as the Discovery Service. The target SP redirects the UA to the DS and can continue SSO after receiving the entityID of the selected IdP returned by the DS
  - `v-b863790eec` If the return URL does not contain a parameter with the effective returnIDParam name, do not treat it as returning the identifier of the selected IdP
- **Controls (negative controls)**:
  - Pair a successful result with an empty result. A success-only case cannot detect an implementation that ignores the returned parameter and uses the default IdP
  - Because IdPDisco does not specify the behavior after no selection result is returned, such as the product's own IdP-selection UI, navigation to a default IdP, or displaying an error, do not make it subject to the verdict
  - The MUST/SHOULD statements in IdPDisco section 2 concerning the DS, such as the UI when isPassive is set, the return method, and metadata matching, are fixture rules for the Suite side, which is the Test Peer, and are not obligations of the target SP
  - The MAY provisions for return, policy, returnIDParam, and isPassive authorize their use; they do not require the SP to provide every capability. Judge only the MUST/MUST NOT provisions applicable to the actually selected path in .b through .i
- **Referenced specification**: `IdPDisco`
- **Reference basis (IdPDisco)**; locator: `2\.4 Conformance||2 Identity Provider Discovery Protocol and Profile`: A conformant SP must conform to the normative statements in section 2 concerning SP behavior
- **Reference basis (IdPDisco)**; locator: `2\.4 Protocol Description||2\.4\.1 HTTP Request to Discovery Service`: As the first stage of the two normative message exchanges, the SP redirects the UA to the Discovery Service
- **Reference basis (IdPDisco)**; locator: `2\.4\.3 HTTP Redirect to Service Provider||2\.5 Use of Metadata`: The Discovery Service returns a selection result or an empty result to the SP in the second message exchange
- **Notes**: The non-normative IIP note does not require implementation of a product-specific discovery UI; the scope is support for IdPDisco's simple redirect protocol. The normative IdPDisco content applicable to the SP was decomposed into .b through .i. Normative statements concerning the Discovery Service, and optional parameters that the SP may use, were not made independent obligations of the target SP. The IIP note that “discovery mechanisms SHOULD use SAML metadata…” is also italicized and therefore non-normative, so it is not made an independent obligation
- **source_clauses**: `[0, 75)` `sha256:ce8bdccd17ea…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SP04.b</code> details</summary>

- **Required variants**:
  - `v-4697164eb7` Initiate Discovery and verify in the Transcript that the UA sends an HTTP GET request to the DS endpoint
- **Controls (negative controls)**:
  - Judge only the transport of the message exchange from the SP to the DS. The HTTP GET from the DS to the SP concerns the DS and is placed in the Suite fixture's self-validation
  - Because IdPDisco does not fix the redirect status code at this point, do not make a specific 3xx code an independent verdict condition
- **Referenced specification**: `IdPDisco`
- **Reference basis (IdPDisco)**; locator: `2\.4 Conformance||2 Identity Provider Discovery Protocol and Profile`: A conformant SP must conform to the normative statements in section 2 concerning SP behavior. This is the basis for incorporating the HTTP GET description as a MUST
- **Reference basis (IdPDisco)**; locator: `2\.4 Protocol Description||2\.4\.1 HTTP Request to Discovery Service`: This profile contains two normative message exchanges, and in the first stage the SP redirects the UA to the DS
- **Reference basis (IdPDisco)**; locator: `2\.4\.1 HTTP Request to Discovery Service||2\.4\.2 Discovery Service determines appropriate Identity Provider`: In the first stage, the requesting SP redirects the UA to the DS with an HTTP GET request
- **source_clauses**: `[0, 75)` `sha256:ce8bdccd17ea…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SP04.c</code> details</summary>

- **Required variants**:
  - `v-d89f0cedb2` Omit policy to use the default single value, or specify policy=urn:oasis:names:tc:SAML:profiles:SSO:idp-discovery-protocol:single, and process the selection result for a single IdP
- **Controls (negative controls)**:
  - Do not require both the omitted default value and the explicitly specified value as capabilities; it is sufficient to process the single policy through at least one path
- **Referenced specification**: `IdPDisco`
- **Reference basis (IdPDisco)**; locator: `2\.4 Conformance||2 Identity Provider Discovery Protocol and Profile`: Every conformant implementation must support at least the default single policy
- **source_clauses**: `[0, 75)` `sha256:ce8bdccd17ea…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SP04.d</code> details</summary>

- **Required variants**:
  - `v-cc1463d020` Verify that the query received by the DS contains an entityID parameter and that its value matches the target SP's entityID
- **Controls (negative controls)**:
  - Match the value as well as the parameter name. Do not let an implementation that sends a fixed dummy value pass
  - Because the source text does not specify cardinality at this point, do not make the presence of exactly one parameter with that name an independent verdict condition
- **Referenced specification**: `IdPDisco`
- **Reference basis (IdPDisco)**; locator: `2\.4\.1 HTTP Request to Discovery Service||2\.4\.2 Discovery Service determines appropriate Identity Provider`: The query string must contain an entityID parameter representing the SP's unique identifier
- **source_clauses**: `[0, 75)` `sha256:ce8bdccd17ea…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SP04.e</code> details</summary>

- **Required variants**:
  - `v-6fdf605e36` Use a Test SP entityID containing the query delimiter, such as &, and verify in the raw query that the delimiter is percent-encoded and that one decode restores the original entityID
- **Controls (negative controls)**:
  - Do not judge a query reconstructed after parsing. Record and inspect the raw query component of the Location received by the browser
  - If an entityID containing & cannot be configured, fall back to a value that remains a valid absolute URI and requires encoding when embedded in the query, such as the # in https://sp.example.test/id#probe or the % in https://sp.example.test/id%25probe. If that also cannot be configured, return NOT_VERIFIED(entityid_encoding_probe_unavailable) and do not attribute a violation to the target
- **Referenced specification**: `IdPDisco`
- **Reference basis (IdPDisco)**; locator: `2\.4\.1 HTTP Request to Discovery Service||2\.4\.2 Discovery Service determines appropriate Identity Provider`: The entityID parameter must be present in the query string and must be URL-encoded
- **source_clauses**: `[0, 75)` `sha256:ce8bdccd17ea…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SP04.f</code> details</summary>

- **Required variants**:
  - `v-e632e47b26` For each request sent by the target, determine the effective returnIDParam and verify that the existing query of the return URL contains no parameter with that name
- **Controls (negative controls)**:
  - Because support for a custom returnIDParam is MAY, do not require it. For each observed request, judge using the explicit value or the default entityID
  - For every request containing return with no collision, return satisfied; if even one collision occurs, return violated. If a Discovery request was observed but zero requests containing return were observed, return satisfied because the prohibited state did not arise
  - If no Discovery request itself can be observed, return NOT_VERIFIED(no_discovery_request_observed). Do not generate a WARNING through satisfied_with_note
- **Referenced specification**: `IdPDisco`
- **Reference basis (IdPDisco)**; locator: `2\.4\.1 HTTP Request to Discovery Service||2\.4\.2 Discovery Service determines appropriate Identity Provider`: The query of the return URL must not contain a parameter with the same name as the value of returnIDParam, or entityID when omitted
- **source_clauses**: `[0, 75)` `sha256:ce8bdccd17ea…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SP04.g</code> details</summary>

- **Required variants**:
  - `v-e886065491` For each Discovery request sent by the target, verify that either return is present or, when return is omitted, the effective default DiscoveryResponse endpoint from the SP metadata can be used as the return destination
- **Controls (negative controls)**:
  - Evaluate as a disjunction over messages: return present means satisfied; return absent with an effective default metadata endpoint means satisfied; neither means violated; inability to verify the metadata correspondence means not_verified(metadata_return_basis_undetermined)
  - “When metadata is not used” is a per-request runtime scope, not a condition predicate for the product as a whole. Do not require the capability to provide a configuration without metadata
  - If no Discovery request itself can be observed, return NOT_VERIFIED(no_discovery_request_observed). Do not generate a WARNING through satisfied_with_note
- **Referenced specification**: `IdPDisco`
- **Reference basis (IdPDisco)**; locator: `2\.4\.1 HTTP Request to Discovery Service||2\.4\.2 Discovery Service determines appropriate Identity Provider`: When metadata is used, return may be omitted, and the return destination must be based on the default DiscoveryResponse. When metadata is not used, return is mandatory
- **Reference basis (SAML2Meta)**; locator: `2\.2\.3 Complex Type IndexedEndpointType||2\.2\.4 Complex Type localizedNameType`: For selecting a default endpoint from an IndexedEndpointType collection of the same kind: choose the first with isDefault=true; if none exists, choose the first that is not isDefault=false; if none exists, choose the first endpoint in the collection
- **source_clauses**: `[0, 75)` `sha256:ce8bdccd17ea…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SP04.h</code> details</summary>

- **Required variants**:
  - `v-a5f58a9432` Verify that each idpdisc:DiscoveryResponse/@Binding in the published metadata matches urn:oasis:names:tc:SAML:profiles:SSO:idp-discovery-protocol
- **Controls (negative controls)**:
  - Publication of the DiscoveryResponse extension itself is optional. If none is observed, return satisfied_with_note rather than NOT_APPLICABLE
  - Location, index, and isDefault are general rules for md:IndexedEndpointType, but the reference phrase for this obligation additionally fixes only the Binding value
- **Referenced specification**: `IdPDisco`
- **Reference basis (IdPDisco)**; locator: `2\.5 Use of Metadata||Appendix A\. Acknowledgments`: The Binding attribute of the DiscoveryResponse extension must be the specified IdP Discovery Protocol URI
- **source_clauses**: `[0, 75)` `sha256:ce8bdccd17ea…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SP04.i</code> details</summary>

- **Required variants**:
  - `v-fa35a132e6` Verify that each idpdisc:DiscoveryResponse in the published metadata conforms to the accompanying schema and has the required md:IndexedEndpointType structure of Location, index, and Binding
- **Controls (negative controls)**:
  - Publication of the DiscoveryResponse extension itself is optional. If none is observed, return satisfied_with_note rather than NOT_APPLICABLE
  - The fixed Binding URI is judged separately in .h. This obligation covers the type, required attributes, and XML structure
  - Placement in SPSSODescriptor/Extensions is described in IdPDisco §2.5 as part of a SHOULD for the DS, and is not elevated to an independent verdict condition for this obligation
- **Referenced specification**: `IdPDisco`
- **Reference basis (IdPDisco)**; locator: `2\.5 Use of Metadata||Appendix A\. Acknowledgments`: DiscoveryResponse is defined as an extension element of type md:IndexedEndpointType, and the schema in the same section fixes that type
- **Reference basis (SAML2MD-xsd)**; locator: `<complexType name="EndpointType">||<element name="EntitiesDescriptor"`: md:IndexedEndpointType extends md:EndpointType. Binding and Location from EndpointType and index from IndexedEndpointType are required; isDefault is optional
- **source_clauses**: `[0, 75)` `sha256:ce8bdccd17ea…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

#### IIP-SP05

[Source](https://kantarainitiative.github.io/SAMLprofiles/fedinterop.html#IIP-SP05) / Section digest `sha256:f39652fbeca5…` / Section length 394 / Non-normative spans 1

| Obligation | Level | Role | Testability | Condition | Core/Full | Summary |
|---|---|---|---|---|---|---|
| `IIP-SP05.a` | MUST | sp | `CONFIG` | — | core | Process responses from any number of issuing IdPs for any given resource URL |
| `IIP-SP05.b` | MUST_NOT | sp | `CONFIG` | — | core | It must not be a restriction that multiple IdPs are only supported by requiring distinct resource URLs for each IdP |

<details><summary><code>IIP-SP05.a</code> details</summary>

- **Required variants**:
  - `v-b1dc98ae4e` Register a second Test IdP on secondary_peer
- **Configuration failure semantics**: `normative_capability`
- **source_clauses**: `[0, 118)` `sha256:f4a511022846…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SP05.b</code> details</summary>

- **Required variants**:
  - `v-d9758f401f` Log in to the same protected resource R using IdP A
  - `v-688ef4512c` After clearing the session, log in to the same R using IdP B
- **Controls (negative controls)**:
  - A control using the same R is mandatory. Merely registering two IdPs would allow an implementation that requires a different URL for each IdP to pass
- **Configuration failure semantics**: `normative_capability`
- **source_clauses**: `[128, 267)` `sha256:2060c0fafbab…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

#### IIP-SP06

[Source](https://kantarainitiative.github.io/SAMLprofiles/fedinterop.html#IIP-SP06) / Section digest `sha256:2f6eca940d8c…` / Section length 218 / Non-normative spans 0

| Obligation | Level | Role | Testability | Condition | Core/Full | Summary |
|---|---|---|---|---|---|---|
| `IIP-SP06.a` | MUST | sp | `CONFIG` | — | core | Generate AuthnRequest with a RequestedAuthnContext element containing the exact comparison method |
| `IIP-SP06.b` | MUST | sp | `CONFIG` | — | core | Generate AuthnRequest with any number of AuthnContextClassRef elements |

<details><summary><code>IIP-SP06.a</code> details</summary>

- **Required variants**:
  - `v-1b58b13fac` Cause issuance with Comparison=exact and perform static inspection
- **Configuration failure semantics**: `normative_capability`
- **source_clauses**: `[0, 161)` `sha256:740dfcdcf7a5…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SP06.b</code> details</summary>

- **Required variants**:
  - `v-e60b9bb195` One ClassRef
  - `v-683d547711` Three ClassRefs
- **Controls (negative controls)**:
  - Zero is invalid under SAML Core (ClassRef/DeclRef must contain one or more items), so do not use it as a capability test
- **Configuration failure semantics**: `normative_capability`
- **Referenced specification**: `SAML2Core`
- **Reference basis (SAML2Core)**; locator: `3\.3\.2\.2\.1 Element <RequestedAuthnContext>||3\.3\.2\.3 Element <AttributeQuery>`: Basis for AuthnContextClassRef / DeclRef being [One or More] and zero being invalid
- **source_clauses**: `[162, 217)` `sha256:3e81e23f3e30…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

#### IIP-SP07

[Source](https://kantarainitiative.github.io/SAMLprofiles/fedinterop.html#IIP-SP07) / Section digest `sha256:10ef0528b7e8…` / Section length 129 / Non-normative spans 0

| Obligation | Level | Role | Testability | Condition | Core/Full | Summary |
|---|---|---|---|---|---|---|
| `IIP-SP07.a` | MUST | sp | `CONFIG` | — | core | Support acceptance or rejection of assertions based on the content of the saml:AuthnContext element |

<details><summary><code>IIP-SP07.a</code> details</summary>

- **Required variants**:
  - `v-b7e4abaacb` Configure the target with a policy that accepts only a specific ClassRef
  - `v-16d1ba8845` Matching ClassRef → accepted
  - `v-e54d0b199c` Non-matching ClassRef → rejected
- **Controls (negative controls)**:
  - Pair acceptance and rejection under the same configuration. Rejection alone would allow an implementation that rejects every Assertion to pass
  - ★ Correction: The previous version said ATTESTED, but CONFIG is correct because configuration changes on the target side and positive / negative browser controls are defined. A Core MUST must not be passed based solely on self-reporting
- **Configuration failure semantics**: `normative_capability`
- **source_clauses**: `[0, 129)` `sha256:10ef0528b7e8…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

#### IIP-SP08

[Source](https://kantarainitiative.github.io/SAMLprofiles/fedinterop.html#IIP-SP08) / Section digest `sha256:92e936a52bb0…` / Section length 395 / Non-normative spans 0

| Obligation | Level | Role | Testability | Condition | Core/Full | Summary |
|---|---|---|---|---|---|---|
| `IIP-SP08.a` | MUST | sp | `BROWSER` | — | core | Support decryption of saml:EncryptedAssertion elements |
| `IIP-SP08.b` | MUST | sp | `CONFIG` | — | core | Be configurable with at least two decryption keys |
| `IIP-SP08.c` | MUST | sp | `BROWSER` | — | core | Attempt each decryption key until the assertion decrypts or keys are exhausted, in which case decryption fails |

<details><summary><code>IIP-SP08.a</code> details</summary>

- **Required variants**:
  - `v-c1fa3f79f5` Encrypt with the first encryption key → decrypted
- **source_clauses**: `[0, 80)` `sha256:af9bf4b2235e…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SP08.b</code> details</summary>

- **Required variants**:
  - `v-c148f76627` Whether two decryption keys can be configured
- **Configuration failure semantics**: `normative_capability`
- **source_clauses**: `[121, 193)` `sha256:519f9396b701…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SP08.c</code> details</summary>

- **Required variants**:
  - `v-80e1e53f3f` Encrypt with the second key → decrypted
  - `v-5e5d4403f3` Encrypt with an unregistered key → fails (control)
- **source_clauses**: `[223, 394)` `sha256:b37e7cb5f264…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

#### IIP-SP09

[Source](https://kantarainitiative.github.io/SAMLprofiles/fedinterop.html#IIP-SP09) / Section digest `sha256:3f2195190fb2…` / Section length 824 / Non-normative spans 2

| Obligation | Level | Role | Testability | Condition | Core/Full | Summary |
|---|---|---|---|---|---|---|
| `IIP-SP09.a` | MUST | sp | `BROWSER` | — | core | Support deep linking and maintain direct addressability of protected resources with Web Browser SSO |
| `IIP-SP09.b` | RECOMMENDED | sp | `ATTESTED` | — | full | Recommended: preserve POST bodies across a successful SSO exchange, subject to size limits |

<details><summary><code>IIP-SP09.a</code> details</summary>

- **Required variants**:
  - `v-b270c52ba0` Access the protected resource URL while unauthenticated → after SSO, reach the original URL
- **Controls (negative controls)**:
  - A non-normative note states that an unsolicited response (IdP-initiated SSO) is not an alternative to this requirement
- **source_clauses**: `[0, 141)` `sha256:87fc6164d0a7…` , `[142, 318)` `sha256:4c34496f1345…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SP09.b</code> details</summary>

- **Required variants**:
  - `v-9eefc9ab03` POST to the protected resource → SSO → verify whether the body is preserved
- **source_clauses**: `[332, 531)` `sha256:ad457a9b3c34…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

#### IIP-SP10

[Source](https://kantarainitiative.github.io/SAMLprofiles/fedinterop.html#IIP-SP10) / Section digest `sha256:40c0440d4c6d…` / Section length 114 / Non-normative spans 0

| Obligation | Level | Role | Testability | Condition | Core/Full | Summary |
|---|---|---|---|---|---|---|
| `IIP-SP10.a` | MUST_NOT | sp | `BROWSER` | — | core | Must not fail or reject responses due to unrecognized saml:Attribute elements |

<details><summary><code>IIP-SP10.a</code> details</summary>

- **Required variants**:
  - `v-0d048a797a` One unknown attribute
  - `v-56f30c0fc8` Fifty unknown attributes
  - `v-b85a87e8ab` A mixture of unknown and known attributes
- **source_clauses**: `[0, 114)` `sha256:40c0440d4c6d…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

#### IIP-SP11

[Source](https://kantarainitiative.github.io/SAMLprofiles/fedinterop.html#IIP-SP11) / Section digest `sha256:468f4e59dbba…` / Section length 111 / Non-normative spans 0

| Obligation | Level | Role | Testability | Condition | Core/Full | Summary |
|---|---|---|---|---|---|---|
| `IIP-SP11.a` | MUST_NOT | sp | `BROWSER` | — | core | Must not treat FriendlyName normatively or make comparisons based on its value |

<details><summary><code>IIP-SP11.a</code> details</summary>

- **Required variants**:
  - `v-2ab04d61bf` Change the FriendlyName while keeping the same Name
  - `v-85cc9e2f6e` Omit the FriendlyName
  - `v-57b326b05e` Only the FriendlyName matches and the Name differs (must not be accepted)
- **Controls (negative controls)**:
  - Use as a control a case where only the FriendlyName matches
- **source_clauses**: `[0, 111)` `sha256:468f4e59dbba…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

#### IIP-SP12

[Source](https://kantarainitiative.github.io/SAMLprofiles/fedinterop.html#IIP-SP12) / Section digest `sha256:5ce6664100b8…` / Section length 484 / Non-normative spans 2

| Obligation | Level | Role | Testability | Condition | Core/Full | Summary |
|---|---|---|---|---|---|---|
| `IIP-SP12.a` | MUST_NOT | sp | `CONFIG` | — | core | Must not require that a persistent name identifier carry semantics or structure beyond what SAML2Core 8.3.7 defines |
| `IIP-SP12.b` | MUST_NOT | sp | `ATTESTED` | — | core | Must not require, through configuration or deployment documentation, that persistent identifiers carry structure or semantics beyond SAML2Core 8.3.7 |

<details><summary><code>IIP-SP12.a</code> details</summary>

- **Required variants**:
  - `v-5885277de2` [Precondition] Execute with a configuration that automatically accepts unknown subjects (automatic provisioning / JIT)
  - `v-bee0d1e4b5` For new subject A, use an opaque pseudorandom value (32 alphanumeric characters) → accepted
  - `v-9cdbfdd8ad` For new subject B, use a value one code point long → accepted
  - `v-8a381bf5cf` For new subject C, use a value 256 code points long → accepted
  - `v-91b5201d94` For new subject D, use a value containing delimiters (@ / = / :) → accepted
  - `v-0dfef821e2` For new subject E, use a value containing no delimiters at all → accepted
  - `v-aff528e732` For new subject F, use a NameID with SPNameQualifier omitted → accepted (§8.3.7 permits omission)
  - `v-9cefd016cc` Control: A value that does not conform to §8.3.7 (257 code points) → may be rejected. Do not mark this as FAIL
  - `v-e0118f8452` Control: New subject with automatic provisioning disabled → rejected. Do not mark this as FAIL either
- **Controls (negative controls)**:
  - ★ Correction: The previous version said “accept any value conforming to §8.3.7,” but the source says “must not require NameID to have meaning or structure beyond §8.3.7”; it does not prohibit rejection for legitimate non-structural reasons such as an unknown subject, lack of provisioning, or account-linking policy
  - ★ Therefore, make it a test precondition that automatic provisioning is enabled and any new subject can be accepted. If the precondition cannot be met, use not_verified(provisioning_precondition_unmet). This is not nonconformity of the target
  - ★ Correction: The previous version included a variant that issued a different opaque value to the same subject, but this itself breaks the persistence of the persistent identifier. When changing the value, use a different subject or a different IdP
  - ★ If it cannot be determined that the rejection reason was the structure of the NameID, use NOT_VERIFIED. Keep attributes fixed across all variants; change only the NameID. Mark it violated only when the reason is identified through the wording of the error page, audit log, or target self-report
  - ★ An SP that does not work unless the value has an email-address format is a typical violation of this obligation and should be a candidate for a mutant SUT
- **Configuration failure semantics**: `test_precondition`
- **Referenced specification**: `SAML2Core#8.3.7`
- **Reference basis (SAML2Core)**; locator: `8\.3\.7 Persistent Identifier||8\.3\.8 Transient Identifier`: The value space that §8.3.7 gives persistent identifiers (opaque, pseudorandom, no more than 256 code points, and the meanings of NameQualifier / SPNameQualifier / SPProvidedID). IIP-SP12 means that structure or content beyond this must not be required
- **Notes**: Correction 1: The previous version classified this obligation as NOT_OBSERVABLE, but §8.3.7 specifies the value space of persistent identifiers, so whether the range is narrowed for structural reasons is observable. Correction 2: However, what is observable is only rejection for structural reasons; the source does not require unconditional acceptance of any value. Because a test precondition (provisioning configuration) is required, testability is CONFIG, and failure to meet the precondition is not a violation but not_verified. Requirements in configuration and deployment documentation are handled as IIP-SP12.b (self-reporting).
- **source_clauses**: `[0, 220)` `sha256:4487b42c2037…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SP12.b</code> details</summary>

- **Required variants**:
  - `v-222c2466bb` Confirm through self-reporting that no mandatory configuration requires a particular format, prefix, or regular expression for persistent NameID values
  - `v-8ac46997c4` Confirm through self-reporting that there is no assumption that NameID is used as a primary key or email address
  - `v-82893f2cf4` Confirm by declaration that there is no processing that interprets organizational affiliation, authorization, or other meaning from the value of NameID.
- **Controls (negative controls)**:
  - ★ IIP-SP12.a can observe only behavior toward the set of values sent by the Suite. If the target requires a particular format as a mandatory configuration, it may be that only values satisfying that configuration have been tested
  - ★ If the self-report contradicts the observation under IIP-SP12.a, mark it INCONSISTENT (the self-report says no requirement, but the implementation actually rejects for structural reasons)
  - ★ The fact that “NameID is used as a primary key” is not itself a violation. It becomes a violation only when “NameID must have a particular format” is required
- **Referenced specification**: `SAML2Core#8.3.7`
- **Reference basis (SAML2Core)**; locator: `8\.3\.7 Persistent Identifier||8\.3\.8 Transient Identifier`: Same as above. Requirements at the configuration and operational levels do not appear at the SAML protocol level, so confirm them through self-reporting
- **Notes**: IIP-SP12.a (observation) and this obligation (self-reporting) are different aspects of the same source sentence. On the evidence ladder, automatic observation under a is stronger
- **source_clauses**: `[0, 220)` `sha256:4487b42c2037…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

#### IIP-SP13

[Source](https://kantarainitiative.github.io/SAMLprofiles/fedinterop.html#IIP-SP13) / Section digest `sha256:0edbdad1b685…` / Section length 409 / Non-normative spans 1

| Obligation | Level | Role | Testability | Condition | Core/Full | Summary |
|---|---|---|---|---|---|---|
| `IIP-SP13.a` | MUST | sp | `CONFIG` | — | core | Support the ability to reject unsigned samlp:Response elements |
| `IIP-SP13.b` | SHOULD | sp | `BROWSER` | — | full | Should reject unsigned samlp:Response elements by default |

<details><summary><code>IIP-SP13.a</code> details</summary>

- **Required variants**:
  - `v-6800ee15e2` With rejection configured, send a completely unsigned Response → is it rejected?
  - `v-e917dd494d` Signed Response → accepted (control).
- **Configuration failure semantics**: `normative_capability`
- **source_clauses**: `[0, 87)` `sha256:f07ff14e90c1…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SP13.b</code> details</summary>

- **Required variants**:
  - `v-8babbb004d` Send an unsigned Response with the default configuration unchanged.
- **Controls (negative controls)**:
  - Even if accepted by default, classify it as WARNING, not FAIL (SHOULD). Because it is security-critical, make it prominent in the UI.
- **source_clauses**: `[88, 115)` `sha256:950fb1309efc…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

### 3.2 Service Provider / Single Logout

#### IIP-SP14

[Source](https://kantarainitiative.github.io/SAMLprofiles/fedinterop.html#IIP-SP14) / Section digest `sha256:443554848deb…` / Section length 612 / Non-normative spans 1

| Obligation | Level | Role | Testability | Condition | Core/Full | Summary |
|---|---|---|---|---|---|---|
| `IIP-SP14.a` | SHOULD | sp | `BROWSER` | — | full | Should support the SAML V2.0 SingleLogout profile |
| `IIP-SP14.b` | MUST | sp | `BROWSER` | `claims_slo_support_sp`<br>(CLAIM_BASED) | full | Service Providers claiming support for SLO must be capable of issuing logout requests |
| `IIP-SP14.c` | OPTIONAL | sp | `BROWSER` | — | full | Consumption of logout requests is optional |
| `IIP-SP14.c1` | OPTIONAL | sp | `BROWSER` | — | full | Consumption of logout responses is optional |
| `IIP-SP14.d` | MUST | sp | `BROWSER` | `supports_slo_initiation_sp`<br>(CAPABILITY_BASED) | full | When a session involves multiple identity providers, repeat SLO independently for each identity provider |
| `IIP-SP14.e` | MUST | sp | `BROWSER` | `supports_slo_initiation_sp`<br>(CAPABILITY_BASED) | full | Send each participant-initiated LogoutRequest to the corresponding identity provider's SLO request endpoint |
| `IIP-SP14.f` | MUST | sp | `BROWSER` | `supports_slo_initiation_sp`<br>(CAPABILITY_BASED) | full | Include at least one applicable SessionIndex in a participant-issued LogoutRequest |
| `IIP-SP14.g` | SHOULD | sp | `BROWSER` | `supports_slo_initiation_sp`<br>(CAPABILITY_BASED) | full | When the user agent is present, prefer an asynchronous front-channel binding for an SP-initiated LogoutRequest |
| `IIP-SP14.h` | RECOMMENDED | sp | `BROWSER` | `supports_slo_initiation_sp`<br>(CAPABILITY_BASED) | full | Use TLS for the HTTP exchange that sends an SP-initiated LogoutRequest |
| `IIP-SP14.i` | MUST | sp | `BROWSER` | `supports_slo_initiation_sp`<br>(CAPABILITY_BASED) | full | Sign an SP-issued LogoutRequest sent with HTTP POST or Redirect |
| `IIP-SP14.j` | SHOULD | sp | `BROWSER` | `slo_relaystate_privacy_required`<br>(CLASSIFICATION_BASED) | full | Reveal as little information as possible in SLO RelayState when privacy measures are required |
| `IIP-SP14.k` | MUST | sp | `BROWSER` | `supports_slo_initiation_sp`<br>(CAPABILITY_BASED) | full | Authenticate the SP as LogoutRequest requester and protect message integrity |
| `IIP-SP14.l` | MUST | sp | `BROWSER` | `supports_slo_initiation_sp`<br>(CAPABILITY_BASED) | full | Include Issuer in an SP-issued LogoutRequest |
| `IIP-SP14.m` | MUST | sp | `BROWSER` | `supports_slo_initiation_sp`<br>(CAPABILITY_BASED) | full | Use the SP's unique entity identifier as LogoutRequest Issuer |
| `IIP-SP14.n` | MUST | sp | `BROWSER` | `supports_slo_initiation_sp`<br>(CAPABILITY_BASED) | full | Omit LogoutRequest Issuer Format or set it to the SAML entity NameID format |
| `IIP-SP14.o` | MUST | sp | `BROWSER` | `supports_slo_initiation_sp`<br>(CAPABILITY_BASED) | full | Identify the principal in LogoutRequest with an identifier that strongly matches the authentication assertion |
| `IIP-SP14.p` | MUST | sp | `BROWSER` | — | full | Invalidate the sessions identified by an authenticated LogoutRequest from the session authority |
| `IIP-SP14.q` | MUST | sp | `BROWSER` | — | full | Issue a LogoutResponse with an appropriate status after processing a LogoutRequest or encountering a protocol error |
| `IIP-SP14.r` | MUST | sp | `BROWSER` | — | full | Authenticate the SP as responder when returning LogoutResponse over a synchronous binding |
| `IIP-SP14.s` | RECOMMENDED | sp | `BROWSER` | — | full | Use TLS for the HTTP exchange that returns LogoutResponse to the identity provider |
| `IIP-SP14.t` | MUST | sp | `BROWSER` | — | full | Sign every consumed-flow LogoutResponse sent with HTTP POST or Redirect |
| `IIP-SP14.u` | MUST | sp | `BROWSER` | — | full | Include Issuer in an SP-issued LogoutResponse |
| `IIP-SP14.v` | MUST | sp | `BROWSER` | — | full | Use the SP's unique entity identifier as LogoutResponse Issuer |
| `IIP-SP14.w` | MUST | sp | `BROWSER` | — | full | Omit LogoutResponse Issuer Format or set it to the SAML entity NameID format |
| `IIP-SP14.x` | MUST | sp | `BROWSER` | — | full | Authenticate the SP as LogoutResponse responder and protect message integrity |
| `IIP-SP14.y` | MUST | sp | `BROWSER` | — | full | Authenticate every consumed LogoutRequest before applying it to local sessions |
| `IIP-SP14.z` | MUST | sp | `BROWSER` | — | full | Apply an unexpired LogoutRequest to a matching authentication assertion even when the assertion arrives after the request |
| `IIP-SP14.aa` | MUST | sp | `AUTOMATED` | — | full | Assign unique SAML identifiers to every LogoutRequest and LogoutResponse the service provider emits |
| `IIP-SP14.ab` | MUST | sp | `AUTOMATED` | — | full | Set LogoutResponse InResponseTo according to the corresponding LogoutRequest |
| `IIP-SP14.ac` | MUST | sp | `BROWSER` | — | full | If Destination is present on a consumed SLO request or response, compare it with the actual receiving location and discard a mismatch |
| `IIP-SP14.ad` | MUST | sp | `BROWSER` | — | full | Verify every XML signature present on a consumed LogoutRequest or LogoutResponse |
| `IIP-SP14.ae` | MUST_NOT | sp | `BROWSER` | — | full | Do not rely on the contents of a consumed SLO request or response whose XML signature is invalid |
| `IIP-SP14.af` | SHOULD | sp | `BROWSER` | — | full | Treat an invalid XML signature on a consumed SLO request or response as an error |
| `IIP-SP14.ag` | SHOULD | sp | `ATTESTED` | — | full | For a valid XML signature on a consumed SLO request or response, evaluate the identity and appropriateness of the signer |
| `IIP-SP14.ah` | SHOULD | sp | `AUTOMATED` | — | full | Sign an emitted SLO request or response when its Consent value indicates that principal consent was obtained |
| `IIP-SP14.ai` | MUST | sp | `BROWSER` | — | full | When responding to a SAML-invalid LogoutRequest, use top-level Requester status |
| `IIP-SP14.aj` | MUST | sp | `AUTOMATED` | — | full | Use a permitted top-level StatusCode in every emitted LogoutResponse |
| `IIP-SP14.ak` | MUST | sp | `BROWSER` | — | full | Reject a consumed LogoutRequest whose major request version is unsupported |
| `IIP-SP14.al` | MUST_NOT | sp | `AUTOMATED` | — | full | Do not emit a LogoutResponse with a version higher than its corresponding LogoutRequest |
| `IIP-SP14.am` | MUST_NOT | sp | `AUTOMATED` | — | full | Do not emit a LogoutResponse with a lower major version except to report RequestVersionTooHigh |
| `IIP-SP14.an` | MUST | sp | `BROWSER` | — | full | If responding to an incompatible SAML protocol version, use top-level VersionMismatch |
| `IIP-SP14.ao` | MUST_NOT | sp | `AUTOMATED` | `supports_slo_initiation_sp`<br>(CAPABILITY_BASED) | full | Do not issue a LogoutRequest whose version corresponds to a LogoutResponse version the service provider cannot process |
| `IIP-SP14.ap` | SHOULD | sp | `AUTOMATED` | `supports_slo_initiation_sp`<br>(CAPABILITY_BASED) | full | Issue LogoutRequest using the highest request version supported by both requester and responder |
| `IIP-SP14.aq` | SHOULD | sp | `ATTESTED` | `supports_slo_initiation_sp`<br>(CAPABILITY_BASED) | full | When responder capabilities are unknown, assume support for the highest request version supported by the service provider |
| `IIP-SP14.ar` | MUST | sp | `BROWSER` | — | full | If accepting a SLO XML signature with a non-standard transform, ensure that no message content is excluded from the signature |
| `IIP-SP14.as` | MUST | sp | `AUTOMATED` | — | full | Make every emitted LogoutRequest and LogoutResponse conform to the SAML protocol schema |

<details><summary><code>IIP-SP14.a</code> details</summary>

- **Required variants**:
  - `v-8c7b5dff0b` The SP initiates SLO for a session with one Test IdP and can issue a profile-conformant LogoutRequest.
- **Controls (negative controls)**:
  - ★ The capability itself is a SHOULD. If the capability is absent, the outcome is violated → WARNING, not FAIL.
  - ★ The MUSTs within the profile apply as IIP-SP14.d–.o only to SPs that actually support SLO.
  - ★ Because IIP-SP14.c / .c1 explicitly state that receiving LogoutRequest / LogoutResponse is OPTIONAL, do not derive an unconditional MUST from the responder rules in §4.4.3.4.
- **Referenced specification**: `SAML2Prof#4.4`
- **Reference basis (SAML2Prof)**; locator: `4\.4 Single Logout Profile||4\.5 Name Identifier Management Profile`: The basic flow initiated by the SP as a session participant, and the actor-specific processing rules for requests / responses.
- **Reference basis (SAML2Errata)**; locator: `E38: Clarification Regarding Index on <LogoutRequest>||E39: `: Replace the SessionIndex rule in §4.4.4.1 and clarify that a session participant must contain at least one entry.
- **Notes**: In CP2b, cross-checked all of §4.4, Errata E38, Core §3.7, and the underlying request / response rules by actor. Separated the SP's capability to initiate the profile as a SHOULD, its capability to issue messages when claiming support as the MUST in .b, and receiving support as OPTIONAL under .c / .c1. The Core common data types, producer-side XML Signature profile, and extension namespace are not counted twice, because the existing obligations IIP-SSO01.dz / .ea / .eb / .ec / .ed / .ee / .ef / .eg / .eh / .ei / .er / .eu / .ev / .ew / .ex / .ah, which apply across all SAML messages, also passively inspect SLO messages. Only rules whose result changes by SLO actor / direction were decomposed separately.
- **source_clauses**: `[0, 109)` `sha256:284c8f093605…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SP14.b</code> details</summary>

- **Required variants**:
  - `v-867681febc` Whether a LogoutRequest reaches the Suite from the SP's logout operation
- **source_clauses**: `[110, 207)` `sha256:9c42b647597d…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SP14.c</code> details</summary>

- **Required variants**:
  - `v-bfa56bd081` Send a valid LogoutRequest from the Suite. If unsupported, return NOT_SUPPORTED; if consumed, determine wire behavior under .p–.x
- **Controls (negative controls)**:
  - ★ An SP that does not implement this feature is NOT_SUPPORTED. Do not elevate OPTIONAL to MUST
  - ★ Profile responder MUST / RECOMMENDED requirements in .p–.x apply passively to the LogoutRequest actually consumed and the LogoutResponse actually generated. Do not turn OPTIONAL into an exemption that permits an implemented feature to be invalid, and do not leave an unimplemented SP permanently NOT_VERIFIED with a capability predicate that observes only positive evidence
- **source_clauses**: `[208, 279)` `sha256:9a27ae08bafe…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SP14.c1</code> details</summary>

- **Required variants**:
  - `v-e1c263261b` For each binding that the SP declares it supports for consuming LogoutResponse, it receives a valid response and can complete the exchange
- **Controls (negative controls)**:
  - ★ Support for receiving LogoutRequest (.c) and support for receiving LogoutResponse (.c1) are independently optional. Do not combine them into one obligation's required variants and thereby require both implementations
  - ★ Lack of support is NOT_SUPPORTED. If the response status is Success, treat it as successful; do not unconditionally treat a non-Success status as a violation by the target
- **source_clauses**: `[208, 279)` `sha256:9a27ae08bafe…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SP14.d</code> details</summary>

- **Required variants**:
  - `v-82d18146e5` Establish SAML sessions originating from Test IdP A and B in the same browser session, then perform global logout and send an independent LogoutRequest to each of A and B
- **Controls (negative controls)**:
  - In a Run involving no multiple IdPs, the runtime condition is false, so the outcome is satisfied. Do not require the capability to support multiple IdPs itself
- **Referenced specification**: `SAML2Prof#4.4.3.1`
- **Reference basis (SAML2Prof)**; locator: `4\.4\.3\.1 <LogoutRequest> Issued by Session Participant to Identity Provider||4\.4\.3\.2 Identity Provider Determines`: 『If multiple identity providers are involved, then the profile MUST be repeated independently for each one』
- **source_clauses**: `[0, 109)` `sha256:284c8f093605…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SP14.e</code> details</summary>

- **Required variants**:
  - `v-b481bea1e0` Log out the session established by IdP A's assertion, send the request to A's request endpoint, and do not send it to IdP B's endpoint
- **Controls (negative controls)**:
  - Use of metadata is MAY. Do not restrict the endpoint's configuration source to metadata; IIP-SP17 separately evaluates metadata consumption
- **Referenced specification**: `SAML2Prof#4.4.3.1`
- **Reference basis (SAML2Prof)**; locator: `4\.4\.3\.1 <LogoutRequest> Issued by Session Participant to Identity Provider||4\.4\.3\.2 Identity Provider Determines`: The session participant sends the LogoutRequest to the single logout service request endpoint of the IdP that issued the corresponding assertion
- **source_clauses**: `[0, 109)` `sha256:284c8f093605…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SP14.f</code> details</summary>

- **Required variants**:
  - `v-c43cdd9af2` Establish a session with AuthnStatement/@SessionIndex=S1, then include S1 at least once in the LogoutRequest
- **Controls (negative controls)**:
  - Do not count an empty SessionIndex or a value from another session as one item. Compare the value with the Transcript from session establishment
- **Referenced specification**: `SAML2Prof#4.4.3.1,#4.4.4.1+E38`
- **Reference basis (SAML2Prof)**; locator: `4\.4\.3\.1 <LogoutRequest> Issued by Session Participant to Identity Provider||4\.4\.3\.2 Identity Provider Determines`: §4.4.3.1 requires one or more applicable SessionIndex values, with at least one item being MUST
- **Reference basis (SAML2Errata)**; locator: `E38: Clarification Regarding Index on <LogoutRequest>||E39: `: After reflecting E38, §4.4.4.1 reconfirms that the session participant must include at least one item
- **source_clauses**: `[0, 109)` `sha256:284c8f093605…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SP14.g</code> details</summary>

- **Required variants**:
  - `v-44acc73941` A logout operation in the browser sends the LogoutRequest to the IdP over the Redirect, POST, or Artifact front channel
- **Controls (negative controls)**:
  - Back-channel API logout without a user agent is outside this SHOULD's runtime scope. Do not prohibit support for synchronous bindings
- **Referenced specification**: `SAML2Prof#4.4.3.1`
- **Reference basis (SAML2Prof)**; locator: `4\.4\.3\.1 <LogoutRequest> Issued by Session Participant to Identity Provider||4\.4\.3\.2 Identity Provider Determines`: When the principal's user agent exists, the session participant SHOULD use an asynchronous binding such as Redirect, POST, or Artifact
- **source_clauses**: `[0, 109)` `sha256:284c8f093605…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SP14.h</code> details</summary>

- **Required variants**:
  - `v-fd2c3490fc` The SP-to-IdP LogoutRequest HTTP exchange appearing in the Transcript uses TLS
- **Controls (negative controls)**:
  - Do not evaluate the scheme of an endpoint that was not used. Do not require obsolete versions such as SSL 3.0 or TLS 1.0; accept currently secure TLS
- **Referenced specification**: `SAML2Prof#4.4.3.1`
- **Reference basis (SAML2Prof)**; locator: `4\.4\.3\.1 <LogoutRequest> Issued by Session Participant to Identity Provider||4\.4\.3\.2 Identity Provider Determines`: It is RECOMMENDED that this step's HTTP exchange use SSL 3.0 or TLS 1.0 for confidentiality and integrity protection
- **source_clauses**: `[0, 109)` `sha256:284c8f093605…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SP14.i</code> details</summary>

- **Required variants**:
  - `v-fe7cac494f` Cause at least an HTTP-Redirect LogoutRequest to be issued, and ensure that every observed POST or Redirect LogoutRequest has a valid signature
- **Controls (negative controls)**:
  - Because IIP-SP15 separately makes support for Redirect requests a MUST, Redirect can be a fixed variant
  - When the target actually provides HTTP-POST, the same case passively inspects the XML signature. The POST capability itself is not required
- **Referenced specification**: `SAML2Prof#4.4.3.1`
- **Reference basis (SAML2Prof)**; locator: `4\.4\.3\.1 <LogoutRequest> Issued by Session Participant to Identity Provider||4\.4\.3\.2 Identity Provider Determines`: A LogoutRequest using the POST or Redirect binding MUST be signed
- **source_clauses**: `[0, 109)` `sha256:284c8f093605…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SP14.j</code> details</summary>

- **Required variants**:
  - `v-b42f3746e7` When an SP-issued LogoutRequest uses RelayState, it must not expose principal, NameID, session, resource URL, or similar information unnecessary for restoration
- **Controls (negative controls)**:
  - A Run with no target-emitted LogoutRequest or with no RelayState used in that request is satisfied because the runtime precondition is false. SLO initiation capability is evaluated separately by .a / .b
  - Do not incorrectly apply this initiator rule to a responder path that merely returns RelayState received from the IdP in the response
  - Do not mark it satisfied merely because it appears random; compare it with the target's state-retention method
- **Referenced specification**: `SAML2Prof#4.4.3.1`
- **Exclusion**: unless the use of the profile does not require
- **Reference basis (SAML2Prof)**; locator: `4\.4\.3\.1 <LogoutRequest> Issued by Session Participant to Identity Provider||4\.4\.3\.2 Identity Provider Determines`: A session participant using RelayState SHOULD minimize publicly disclosed information as much as possible, unless the profile does not require privacy measures
- **source_clauses**: `[0, 109)` `sha256:284c8f093605…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SP14.k</code> details</summary>

- **Required variants**:
  - `v-c2f37063f6` A LogoutRequest with a signature or binding-specific authentication and integrity mechanism verifies successfully
- **Controls (negative controls)**:
  - The specific signature requirements for POST / Redirect are in .i. Paths using binding-specific mechanisms, such as Artifact / SOAP, are also covered by this obligation
  - G2 must confirm that a mutant target sending a request without authentication or integrity protection is violated under this obligation. Do not introduce a variant that requires the target to issue an incorrect message
- **Referenced specification**: `SAML2Prof#4.4.4.1`
- **Reference basis (SAML2Prof)**; locator: `4\.4\.4\.1 <LogoutRequest> Usage||4\.4\.4\.2 <LogoutResponse> Usage`: The requester MUST authenticate itself to the responder and guarantee message integrity by means of a signature or a binding-specific mechanism
- **source_clauses**: `[0, 109)` `sha256:284c8f093605…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SP14.l</code> details</summary>

- **Required variants**:
  - `v-b7ca21ef3c` Exactly one Issuer exists in the SP-issued LogoutRequest
- **Referenced specification**: `SAML2Prof#4.4.4.1`
- **Reference basis (SAML2Prof)**; locator: `4\.4\.4\.1 <LogoutRequest> Usage||4\.4\.4\.2 <LogoutResponse> Usage`: The Issuer element of LogoutRequest MUST be present
- **source_clauses**: `[0, 109)` `sha256:284c8f093605…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SP14.m</code> details</summary>

- **Required variants**:
  - `v-5f17f3d69c` The Issuer value matches the target SP's metadata entityID
- **Referenced specification**: `SAML2Prof#4.4.4.1`
- **Reference basis (SAML2Prof)**; locator: `4\.4\.4\.1 <LogoutRequest> Usage||4\.4\.4\.2 <LogoutResponse> Usage`: Issuer MUST contain the unique identifier of the requesting entity
- **source_clauses**: `[0, 109)` `sha256:284c8f093605…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SP14.n</code> details</summary>

- **Required variants**:
  - `v-892a27ea69` For every target-emitted LogoutRequest, Issuer/@Format is omitted or is urn:oasis:names:tc:SAML:2.0:nameid-format:entity
- **Referenced specification**: `SAML2Prof#4.4.4.1`
- **Reference basis (SAML2Prof)**; locator: `4\.4\.4\.1 <LogoutRequest> Usage||4\.4\.4\.2 <LogoutResponse> Usage`: Issuer/@Format must be omitted or be urn:oasis:names:tc:SAML:2.0:nameid-format:entity
- **source_clauses**: `[0, 109)` `sha256:284c8f093605…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SP14.o</code> details</summary>

- **Required variants**:
  - `v-f6e2c956f9` The NameID, BaseID, or EncryptedID in the target-emitted LogoutRequest strongly matches the identifier in the assertion used to establish the session
- **Controls (negative controls)**:
  - Compare using the strong-match rules in Core 3.3.4, including NameQualifier, SPNameQualifier, Format, and so on, rather than string equality alone
  - Use a mutant target that sends another principal's identifier as the negative control; do not require the conforming target to issue an incorrect message
- **Referenced specification**: `SAML2Prof#4.4.4.1`
- **Reference basis (SAML2Prof)**; locator: `4\.4\.4\.1 <LogoutRequest> Usage||4\.4\.4\.2 <LogoutResponse> Usage`: The principal MUST be identified by an identifier that strongly matches, in accordance with Core 3.3.4, the identifier of the authentication assertion received by the requester for the session being terminated
- **source_clauses**: `[0, 109)` `sha256:284c8f093605…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SP14.p</code> details</summary>

- **Required variants**:
  - `v-f3bafa3d0b` For two sessions with SessionIndex S1 and S2 belonging to the same principal, an authenticated LogoutRequest specifying only S1 terminates S1 and preserves S2
  - `v-28a23ccbb2` For sessions S1 and S2 belonging to the same principal, an authenticated LogoutRequest specifying both SessionIndexes terminates both
  - `v-e81e9fcbfd` For sessions S1 and S2 belonging to the same principal, an authenticated LogoutRequest with no SessionIndex terminates both S1 and S2
  - `v-80c3fb97ee` Do not terminate a session belonging to a different principal or a session with a SessionIndex that was not specified
- **Controls (negative controls)**:
  - Use multiple sessions for the same principal and a session for a different principal as controls to detect an implementation that unconditionally terminates all local sessions
  - Do not use a request whose sender is not the session authority as the positive fixture for this obligation. Authenticate the sender under IIP-SP14.y separately
  - LogoutRequest consumption itself is OPTIONAL under IIP-SP14.c. If the target does not consume the request, treat it as satisfied_with_note; mark it violated only when it claims or is observed to consume the request but does not process it
- **Referenced specification**: `SAML2Prof#4.4.3.4 + SAML2Core#3.7`
- **Reference basis (SAML2Prof)**; locator: `4\.4\.3\.4 Session Participant/Authority Issues <LogoutResponse> to Identity||4\.4\.3\.5 Identity Provider Issues`: The session participant or authority MUST process the LogoutRequest message in accordance with SAML Core
- **Reference basis (SAML2Core)**; locator: `3\.7\.3\.1 Session Participant Rules||3\.7\.3\.2 Session Authority Rules`: If the sender is the authority that issued the authentication assertion for the session in question, it MUST invalidate the session identified by the identifier and the specified SessionIndex; if no SessionIndex is present, it MUST invalidate all sessions of the principal
- **source_clauses**: `[0, 109)` `sha256:284c8f093605…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SP14.q</code> details</summary>

- **Required variants**:
  - `v-bbfec36485` Successful processing of a valid request that does not contain aslo:Asynchronous produces a LogoutResponse with a Success status
- **Controls (negative controls)**:
  - Core §3.7.3.1 does not prescribe a status code specific to a session participant failure condition. Do not create a Suite-specific mapping for unknown SessionIndex or similar cases
  - For a response to a request that is invalid under SAML syntax or processing rules, assess the top-level Requester separately under IIP-SP14.ai
  - Responding to a request with an invalid signature is itself a SHOULD (IIP-SP14.af); do not treat the absence of a response as a violation of this MUST
  - A request containing the Asynchronous SLO extension is outside this obligation's runtime scope because it does not require a response. IIP-SP14 does not itself require the SP's ASLO capability
  - For an SP that does not consume LogoutRequest, use satisfied_with_note. Assess the response status only when the request is consumed
- **Referenced specification**: `SAML2Prof#4.4.3.4 + SAML2Core#3.7`
- **Reference basis (SAML2Prof)**; locator: `4\.4\.3\.4 Session Participant/Authority Issues <LogoutResponse> to Identity||4\.4\.3\.5 Identity Provider Issues`: After processing the message or upon an error, the entity MUST issue a LogoutResponse with an appropriate status code to the requesting IdP
- **Reference basis (SAML2Core)**; locator: `3\.7 Single Logout Protocol||3\.8 Name Identifier Mapping Protocol`: Decompose the mapping between error conditions and statuses into CP2b-Core using the participant rules and underlying response rules of Core §3.7
- **source_clauses**: `[0, 109)` `sha256:284c8f093605…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SP14.r</code> details</summary>

- **Required variants**:
  - `v-77e5dc30ac` When the target uses a supported synchronous SLO binding, the LogoutResponse signature or binding-specific responder authentication can be verified
- **Controls (negative controls)**:
  - If synchronous binding or LogoutRequest consumption is not implemented, the runtime precondition is false and the result is satisfied_with_note. Do not additionally require the optional capability itself
- **Referenced specification**: `SAML2Prof#4.4.3.4`
- **Reference basis (SAML2Prof)**; locator: `4\.4\.3\.4 Session Participant/Authority Issues <LogoutResponse> to Identity||4\.4\.3\.5 Identity Provider Issues`: The responder over a synchronous binding MUST authenticate itself to the requesting IdP by a signature or a binding-specific mechanism
- **source_clauses**: `[0, 109)` `sha256:284c8f093605…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SP14.s</code> details</summary>

- **Required variants**:
  - `v-c1cb5aca28` The SP-to-IdP LogoutResponse HTTP exchange appearing in the Transcript uses TLS
- **Controls (negative controls)**:
  - If no LogoutResponse is observed, use satisfied_with_note. Do not assess the scheme of an endpoint that was not used; accept currently secure TLS and do not require SSL 3.0 or TLS 1.0
- **Referenced specification**: `SAML2Prof#4.4.3.4`
- **Reference basis (SAML2Prof)**; locator: `4\.4\.3\.4 Session Participant/Authority Issues <LogoutResponse> to Identity||4\.4\.3\.5 Identity Provider Issues`: It is RECOMMENDED that this step's HTTP exchange use SSL 3.0 or TLS 1.0 for confidentiality and integrity protection
- **source_clauses**: `[0, 109)` `sha256:284c8f093605…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SP14.t</code> details</summary>

- **Required variants**:
  - `v-c78656e0dd` Every observed HTTP POST or Redirect LogoutResponse has a valid signature
- **Controls (negative controls)**:
  - For a Run in which no POST or Redirect response is observed, the runtime precondition is false and the result is satisfied_with_note. Do not additionally require optional consumption or binding capability
- **Referenced specification**: `SAML2Prof#4.4.3.4`
- **Reference basis (SAML2Prof)**; locator: `4\.4\.3\.4 Session Participant/Authority Issues <LogoutResponse> to Identity||4\.4\.3\.5 Identity Provider Issues`: A LogoutResponse sent over a POST or Redirect binding MUST be signed
- **source_clauses**: `[0, 109)` `sha256:284c8f093605…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SP14.u</code> details</summary>

- **Required variants**:
  - `v-8324ba1139` The SP-issued LogoutResponse contains exactly one Issuer
- **Controls (negative controls)**:
  - If no SP-issued LogoutResponse is observed, use satisfied_with_note. Do not additionally require response-generation capability
- **Referenced specification**: `SAML2Prof#4.4.4.2`
- **Reference basis (SAML2Prof)**; locator: `4\.4\.4\.2 <LogoutResponse> Usage||4\.4\.5 Use of Metadata`: The Issuer element is present in the LogoutResponse
- **source_clauses**: `[0, 109)` `sha256:284c8f093605…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SP14.v</code> details</summary>

- **Required variants**:
  - `v-7ab6c51339` The Issuer value matches the target SP's metadata entityID
- **Controls (negative controls)**:
  - If no SP-issued LogoutResponse is observed, use satisfied_with_note. Do not additionally require response-generation capability
- **Referenced specification**: `SAML2Prof#4.4.4.2`
- **Reference basis (SAML2Prof)**; locator: `4\.4\.4\.2 <LogoutResponse> Usage||4\.4\.5 Use of Metadata`: The Issuer MUST contain the responding entity's unique identifier
- **source_clauses**: `[0, 109)` `sha256:284c8f093605…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SP14.w</code> details</summary>

- **Required variants**:
  - `v-2450adb850` For every target-emitted LogoutResponse, Issuer/@Format is either omitted or set to urn:oasis:names:tc:SAML:2.0:nameid-format:entity
- **Controls (negative controls)**:
  - If no SP-issued LogoutResponse is observed, use satisfied_with_note. Do not additionally require response-generation capability
- **Referenced specification**: `SAML2Prof#4.4.4.2`
- **Reference basis (SAML2Prof)**; locator: `4\.4\.4\.2 <LogoutResponse> Usage||4\.4\.5 Use of Metadata`: Issuer/@Format must be omitted or be urn:oasis:names:tc:SAML:2.0:nameid-format:entity
- **source_clauses**: `[0, 109)` `sha256:284c8f093605…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SP14.x</code> details</summary>

- **Required variants**:
  - `v-effc3446a4` The SP-issued LogoutResponse has a signature or binding-specific authentication and integrity mechanism, and verification succeeds
- **Controls (negative controls)**:
  - Place operations that break authentication or integrity evidence in Suite fixture self-validation, and do not require the target to issue an incorrect message
  - If no SP-issued LogoutResponse is observed, use satisfied_with_note. Do not additionally require response-generation capability
- **Referenced specification**: `SAML2Prof#4.4.4.2`
- **Reference basis (SAML2Prof)**; locator: `4\.4\.4\.2 <LogoutResponse> Usage||4\.4\.5 Use of Metadata`: The responder MUST authenticate itself to the requester by a signature or a binding-specific mechanism and guarantee message integrity
- **source_clauses**: `[0, 109)` `sha256:284c8f093605…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SP14.y</code> details</summary>

- **Required variants**:
  - `v-55d29c596e` A LogoutRequest correctly authenticated with the trusted key of the session authority can be applied to the target session
  - `v-76aab46001` A LogoutRequest whose signature value or signed content has been tampered with does not terminate local sessions
  - `v-dd0259eab3` A LogoutRequest cryptographically correctly signed with another entity's key does not terminate local sessions
- **Controls (negative controls)**:
  - Confirm not only cryptographic validity but also that the sender is the session authority in question. Pair it with a correct request to fail implementations that always reject
  - Whether to respond to a request and whether to apply it to sessions are separate matters. Do not require a response
  - LogoutRequest consumption itself is OPTIONAL under IIP-SP14.c. If unsupported, use satisfied_with_note; mark it violated only when a consumed request is applied without authentication
- **Referenced specification**: `SAML2Prof#4.4.3.4 + SAML2Core#3.7.3.1`
- **Reference basis (SAML2Prof)**; locator: `4\.4\.3\.4 Session Participant/Authority Issues <LogoutResponse> to Identity||4\.4\.3\.5 Identity Provider Issues`: The session participant MUST process the LogoutRequest in accordance with SAML Core
- **Reference basis (SAML2Core)**; locator: `3\.7\.3\.1 Session Participant Rules||3\.7\.3\.2 Session Authority Rules`: The session participant MUST authenticate the received LogoutRequest message
- **source_clauses**: `[0, 109)` `sha256:284c8f093605…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SP14.z</code> details</summary>

- **Required variants**:
  - `v-96ea29c466` Receive first a non-expired LogoutRequest with an identifier and SessionIndex that strongly match a future-arriving assertion; do not establish or maintain a session from the later-arriving assertion
  - `v-a45b0da80d` A non-expired LogoutRequest without a SessionIndex applies to all SessionIndexes of a later-arriving assertion that strongly matches
  - `v-1e424085ee` Control: a later-arriving assertion whose identifier does not strongly match is not rejected solely because of this request
  - `v-6e4c9ba4fc` Control: After an unexpired LogoutRequest specifying only SessionIndex S1, an assertion for the same principal but with SessionIndex S2 arrives → do not reject it solely because of this request
  - `v-68b2ad1aed` Control: An assertion arrives after LogoutRequest/@NotOnOrAfter → do not reject it solely because of this request
- **Controls (negative controls)**:
  - Pair a positive fixture satisfying all four conditions with negative controls that each break one condition. Do not mark an implementation that always rejects later-arriving assertions as PASS
  - LogoutRequest consumption itself is OPTIONAL under IIP-SP14.c. If unsupported, use satisfied_with_note
  - Ordinary validity verification of a later-arriving assertion is assessed separately under the SSO obligation; do not confuse it with failure of this obligation
- **Referenced specification**: `SAML2Prof#4.4.3.4 + SAML2Core#3.7.3.1`
- **Reference basis (SAML2Prof)**; locator: `4\.4\.3\.4 Session Participant/Authority Issues <LogoutResponse> to Identity||4\.4\.3\.5 Identity Provider Issues`: The session participant MUST process the LogoutRequest in accordance with SAML Core
- **Reference basis (SAML2Core)**; locator: `3\.7\.3\.1 Session Participant Rules||3\.7\.3\.2 Session Authority Rules`: If the Subject strongly matches and the SessionIndex matches (or the request has no index), the assertion is time-valid, and the LogoutRequest has not expired, the logout MUST be applied to an assertion arriving after the request
- **source_clauses**: `[0, 109)` `sha256:284c8f093605…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SP14.aa</code> details</summary>

- **Required variants**:
  - `v-0702d61ba9` Do not reuse the same @ID for different message objects across sequential or concurrent SLO exchanges and between requests / responses.
- **Controls (negative controls)**:
  - An SP-issued LogoutResponse is observed only if request consumption is implemented. Do not require an unobserved direction as an additional capability.
  - The lexical rules for @ID as xs:ID are evaluated under the schema conformance obligation IIP-SP14.as. Do not count the same defect as a uniqueness violation as well.
  - Being sequential is not itself a violation. Do not impose an absolute threshold on probability that is outside the specification.
- **Referenced specification**: `SAML2Core#3.2.1-3.2.2,#1.3.4`
- **Reference basis (SAML2Core)**; locator: `3\.2\.1 Complex Type RequestAbstractType||3\.2\.2 Complex Type StatusResponseType`: RequestAbstractType/@ID inherited by LogoutRequest MUST follow the identifier uniqueness requirements of §1.3.4.
- **Reference basis (SAML2Core)**; locator: `3\.2\.2 Complex Type StatusResponseType||3\.2\.2\.1 Element <Status>`: StatusResponseType/@ID inherited by LogoutResponse must also follow the identifier uniqueness requirements of §1.3.4.
- **Reference basis (SAML2Core)**; locator: `1\.3\.4 ID and ID Reference Values||2 SAML Assertions`: The party assigning identifiers MUST ensure that the probability of assigning the same value to another data object is negligible.
- **source_clauses**: `[0, 109)` `sha256:284c8f093605…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SP14.ab</code> details</summary>

- **Required variants**:
  - `v-a800afc6b6` LogoutResponse returned after consuming a valid LogoutRequest → @InResponseTo exists and matches request/@ID.
  - `v-d6c4441eb5` If the request is malformed, its @ID cannot be identified, and a SAML response is returned → do not include @InResponseTo.
- **Controls (negative controls)**:
  - If the SP does not implement LogoutRequest consumption and therefore does not issue LogoutResponse, the outcome is satisfied_with_note. Do not additionally require response-generation capability.
- **Referenced specification**: `SAML2Core#3.2.2`
- **Reference basis (SAML2Core)**; locator: `3\.2\.2 Complex Type StatusResponseType||3\.2\.2\.1 Element <Status>`: If the response is for a request, InResponseTo MUST be present and MUST match the request ID; if the request ID cannot be identified, InResponseTo MUST NOT be present.
- **source_clauses**: `[0, 109)` `sha256:284c8f093605…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SP14.ac</code> details</summary>

- **Required variants**:
  - `v-ce18b6711d` A LogoutRequest with an incorrect Destination sent to an SP supporting reception → do not apply it to the local session.
  - `v-9f40ef55d5` A LogoutResponse with an incorrect Destination sent to an SP supporting response consumption → do not treat it as a successful exchange.
  - `v-9e3a9c9da3` Control for each direction: correct Destination → proceed with normal processing.
- **Controls (negative controls)**:
  - Request / response consumption is independently OPTIONAL under IIP-SP14.c / .c1. Treat an unimplemented direction as satisfied_with_note and do not infer it from the other direction.
  - Do not require acceptance of a message with Destination omitted under this obligation. Core's Optional does not impose an acceptance obligation; for signed Redirect / POST, the Binding requires Destination.
- **Referenced specification**: `SAML2Core#3.2.1-3.2.2 + SAML2Bind#3.4.5.2,#3.5.5.2`
- **Reference basis (SAML2Core)**; locator: `3\.2\.1 Complex Type RequestAbstractType||3\.2\.2 Complex Type StatusResponseType`: If the request contains Destination, the recipient MUST check it against the receiving location and MUST discard the request if they do not match.
- **Reference basis (SAML2Core)**; locator: `3\.2\.2 Complex Type StatusResponseType||3\.2\.2\.1 Element <Status>`: The same MUST-check / discard rule applies to the response's Destination.
- **Reference basis (SAML2Bind)**; locator: `3\.4\.5\.2 Security Considerations||3\.4\.6 Error Reporting`: A signed HTTP-Redirect message MUST contain Destination, and the recipient MUST verify that it matches the receiving location.
- **Reference basis (SAML2Bind)**; locator: `3\.5\.5\.2 Security Considerations||3\.5\.6 Error Reporting`: The same Destination MUST / matching MUST requirements apply to a signed HTTP-POST message.
- **source_clauses**: `[0, 109)` `sha256:284c8f093605…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SP14.ad</code> details</summary>

- **Required variants**:
  - `v-8c5df579b9` A LogoutRequest with its signature value or signed content tampered with → do not consume it.
  - `v-dadfa9a202` A LogoutResponse with its signature value or signed content tampered with → do not consume it as successful.
  - `v-ea2537f668` Control for each direction: correct XML Signature from a trusted peer → proceed with normal processing.
- **Controls (negative controls)**:
  - The HTTP-Redirect query signature is on the SAML2Bind side, not an XML Signature. This checks <ds:Signature>.
  - An unimplemented direction of request / response consumption is satisfied_with_note.
- **Referenced specification**: `SAML2Core#3.2.1-3.2.2`
- **Reference basis (SAML2Core)**; locator: `3\.2\.1 Complex Type RequestAbstractType||3\.2\.2 Complex Type StatusResponseType`: When an XML signature is used on a request, the responder MUST verify that the signature is valid.
- **Reference basis (SAML2Core)**; locator: `3\.2\.2 Complex Type StatusResponseType||3\.2\.2\.1 Element <Status>`: When an XML signature is used on a response, the requester MUST verify that the signature is valid.
- **source_clauses**: `[0, 109)` `sha256:284c8f093605…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SP14.ae</code> details</summary>

- **Required variants**:
  - `v-b7554f1762` A local session must not be terminated based on the identifier / SessionIndex of a LogoutRequest with an invalid signature.
  - `v-c7623bbca6` Do not complete the exchange successfully based on Success, RelayState, or other content of a LogoutResponse with an invalid signature.
- **Controls (negative controls)**:
  - Separate from IIP-SP14.ad (perform verification). Detect implementations that use the content after verification fails. An unimplemented consumption direction is satisfied_with_note.
- **Referenced specification**: `SAML2Core#3.2.1-3.2.2`
- **Reference basis (SAML2Core)**; locator: `3\.2\.1 Complex Type RequestAbstractType||3\.2\.2 Complex Type StatusResponseType`: If the request signature is invalid, the responder MUST NOT rely on the request's content.
- **Reference basis (SAML2Core)**; locator: `3\.2\.2 Complex Type StatusResponseType||3\.2\.2\.1 Element <Status>`: If the response signature is invalid, the requester MUST NOT rely on the response's content.
- **source_clauses**: `[0, 109)` `sha256:284c8f093605…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SP14.af</code> details</summary>

- **Required variants**:
  - `v-e6b3ab64ae` Invalid LogoutRequest → if responding, return a LogoutResponse containing an error; no response is a WARNING.
  - `v-cc526d61f6` Invalid LogoutResponse → process and record the exchange as an error.
- **Controls (negative controls)**:
  - ★ SHOULD_CLASS. If internal error handling cannot be observed, the outcome is not_verified. An unimplemented consumption direction is satisfied_with_note.
  - The aslo:Asynchronous element of a message with an invalid signature cannot be trusted, and no ASLO consumption capability is required of the SP; therefore, do not include the extension in this obligation's fixture.
- **Referenced specification**: `SAML2Core#3.2.1-3.2.2`
- **Reference basis (SAML2Core)**; locator: `3\.2\.1 Complex Type RequestAbstractType||3\.2\.2 Complex Type StatusResponseType`: Treat responding with an error to an invalid request signature as a SHOULD.
- **Reference basis (SAML2Core)**; locator: `3\.2\.2 Complex Type StatusResponseType||3\.2\.2\.1 Element <Status>`: Treat handling an invalid response signature as an error as a SHOULD.
- **source_clauses**: `[0, 109)` `sha256:284c8f093605…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SP14.ag</code> details</summary>

- **Required variants**:
  - `v-c997241117` A cryptographically valid LogoutRequest or LogoutResponse signed with another entity's key → detect the mismatch between Issuer and signer
- **Controls (negative controls)**:
  - Cryptographic validity (IIP-SP14.ad) and signer appropriateness are separate. An unsupported consumption direction is satisfied_with_note
- **Referenced specification**: `SAML2Core#3.2.1-3.2.2`
- **Reference basis (SAML2Core)**; locator: `3\.2\.1 Complex Type RequestAbstractType||3\.2\.2 Complex Type StatusResponseType`: For a valid request signature, the responder SHOULD evaluate the signer's identity and appropriateness
- **Reference basis (SAML2Core)**; locator: `3\.2\.2 Complex Type StatusResponseType||3\.2\.2\.1 Element <Status>`: For a valid response signature, the requester SHOULD perform the same evaluation
- **source_clauses**: `[0, 109)` `sha256:284c8f093605…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SP14.ah</code> details</summary>

- **Required variants**:
  - `v-cdba97be43` A LogoutRequest or LogoutResponse issued by the target SP with @Consent indicating that principal consent was obtained → an XML signature or the message signature specified by the delivery binding is present and verifiable
- **Controls (negative controls)**:
  - If @Consent is not sent or is unspecified, the result is satisfied_with_note. Do not additionally require response-issuance capability
  - For HTTP-Redirect, remove <ds:Signature> and add a query signature using SigAlg / Signature. Do not make the absence of an XML signature alone a WARNING
- **Referenced specification**: `SAML2Core#3.2.1-3.2.2 + SAML2Bind#3.4.4.1`
- **Reference basis (SAML2Core)**; locator: `3\.2\.1 Complex Type RequestAbstractType||3\.2\.2 Complex Type StatusResponseType`: If the request's Consent indicates that principal consent was obtained, the request SHOULD be signed
- **Reference basis (SAML2Core)**; locator: `3\.2\.2 Complex Type StatusResponseType||3\.2\.2\.1 Element <Status>`: If the response's Consent indicates that principal consent was obtained, the response SHOULD be signed
- **Reference basis (SAML2Bind)**; locator: `3\.4\.4\.1 DEFLATE Encoding||3\.4\.5 Message Exchange`: HTTP-Redirect removes the XML signature, and if the original message was signed, adds a SigAlg / Signature signature to the encoded query string
- **source_clauses**: `[0, 109)` `sha256:284c8f093605…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SP14.ai</code> details</summary>

- **Required variants**:
  - `v-5da6850354` For an invalid LogoutRequest, such as one missing required attributes, if a SAML LogoutResponse is returned, its top-level @Value MUST be Requester
- **Controls (negative controls)**:
  - The source says “if it responds.” Do not treat an HTTP error or no response as a violation of this MUST. An SP that does not support request consumption is satisfied_with_note
  - For a SAML response to an unsupported version, apply the more specific VersionMismatch requirement in IIP-SP14.an and do not duplicate this obligation's Requester status
- **Referenced specification**: `SAML2Core#3.2.1`
- **Reference basis (SAML2Core)**; locator: `3\.2\.1 Complex Type RequestAbstractType||3\.2\.2 Complex Type StatusResponseType`: If responding to a request invalid under SAML syntax or processing rules, the responder MUST return a SAML response with StatusCode=Requester
- **source_clauses**: `[0, 109)` `sha256:284c8f093605…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SP14.aj</code> details</summary>

- **Required variants**:
  - `v-083b977e6d` The top-level @Value of the target SP's issued LogoutResponse must be one of Success / Requester / Responder / VersionMismatch, and a secondary code such as PartialLogout must not be placed at the top level
- **Controls (negative controls)**:
  - If an SP-issued LogoutResponse is not observed, the result is satisfied_with_note. Omitting the subordinate status code or using a custom URI is MAY, so neither is prohibited
- **Referenced specification**: `SAML2Core#3.2.2.2`
- **Reference basis (SAML2Core)**; locator: `3\.2\.2\.2 Element <StatusCode>||3\.2\.2\.3 Element <StatusMessage>`: The topmost StatusCode/@Value MUST be selected from the top-level list in §3.2.2.2
- **source_clauses**: `[0, 109)` `sha256:284c8f093605…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SP14.ak</code> details</summary>

- **Required variants**:
  - `v-a6bd944191` A LogoutRequest with @Version=1.1 / 3.0 → do not apply it to the local session
  - `v-f15e61c4db` Control: A valid LogoutRequest with @Version=2.0 → proceed with normal processing
- **Controls (negative controls)**:
  - Request consumption is OPTIONAL. An unsupported SP is satisfied_with_note. If it responds, VersionMismatch is governed by IIP-SP14.an
  - A request with the same major version as a supported version but a higher minor version may be processed or rejected, so neither outcome receives a verdict
- **Referenced specification**: `SAML2Core#4.1.3.1`
- **Reference basis (SAML2Core)**; locator: `4\.1\.3\.1 Request Version||4\.1\.3\.2 Response Version`: A SAML responder MUST reject a request with an unsupported major request version
- **source_clauses**: `[0, 109)` `sha256:284c8f093605…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SP14.al</code> details</summary>

- **Required variants**:
  - `v-ea6785d31b` The target SP's issued LogoutResponse/@Version must be <= the corresponding LogoutRequest/@Version
- **Controls (negative controls)**:
  - If an SP-issued LogoutResponse is not observed, the result is satisfied_with_note
- **Referenced specification**: `SAML2Core#4.1.3.2`
- **Reference basis (SAML2Core)**; locator: `4\.1\.3\.2 Response Version||4\.1\.3\.3 Permissible Version Combinations`: A SAML responder MUST NOT issue a response version higher than that of the supported request
- **source_clauses**: `[0, 109)` `sha256:284c8f093605…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SP14.am</code> details</summary>

- **Required variants**:
  - `v-ed96ec7e6b` For a normal LogoutRequest, the response major version must be >= the request major version
  - `v-63eb0e03c8` Control: Only when the secondary code is RequestVersionTooHigh is a lower-major response permitted
- **Controls (negative controls)**:
  - RequestVersionTooLow / RequestVersionDeprecated is not an exception. If no SP-issued response exists, the result is satisfied_with_note
- **Referenced specification**: `SAML2Core#4.1.3.2`
- **Reference basis (SAML2Core)**; locator: `4\.1\.3\.2 Response Version||4\.1\.3\.3 Permissible Version Combinations`: Except when reporting RequestVersionTooHigh, a SAML responder MUST NOT issue a response with a major version lower than that of the supported request
- **source_clauses**: `[0, 109)` `sha256:284c8f093605…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SP14.an</code> details</summary>

- **Required variants**:
  - `v-387329ec7d` For an unsupported-major LogoutRequest, if a SAML response is returned, its top-level @Value must be VersionMismatch
- **Controls (negative controls)**:
  - Do not treat a lack of response as a violation. The secondary code is MAY, so do not fix it to a particular value
- **Referenced specification**: `SAML2Core#4.1.3.2`
- **Reference basis (SAML2Core)**; locator: `4\.1\.3\.2 Response Version||4\.1\.3\.3 Permissible Version Combinations`: An error response for an incompatible SAML protocol version MUST report top-level VersionMismatch
- **source_clauses**: `[0, 109)` `sha256:284c8f093605…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SP14.ao</code> details</summary>

- **Required variants**:
  - `v-8fd172b748` The @Version of a LogoutRequest issued by the target SP that implements LogoutResponse consumption corresponds to a LogoutResponse version that the SP can process
- **Controls (negative controls)**:
  - IIP-SP14.c1 explicitly makes LogoutResponse consumption OPTIONAL. Do not indirectly require response-consumption capability from an unsupported SP; use satisfied_with_note
  - An implementation or run that consumes responses passively applies this Core rule; it is violated only if it issues a request with a version it cannot support
  - A request that does not request a response because of the Asynchronous SLO extension is outside runtime scope. The IdP's ASLO rules are evaluated by IIP-IDP17.b through .b4
- **Referenced specification**: `SAML2Core#4.1.3.1`
- **Reference basis (SAML2Core)**; locator: `4\.1\.3\.1 Request Version||4\.1\.3\.2 Response Version`: A SAML requester MUST NOT issue a request version corresponding to a response version that it cannot support
- **source_clauses**: `[0, 109)` `sha256:284c8f093605…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SP14.ap</code> details</summary>

- **Required variants**:
  - `v-576d7e1be2` A LogoutRequest issued by the target SP to a SAML 2.0 peer has @Version=2.0
- **Controls (negative controls)**:
  - ★ SHOULD_CLASS. The IIP target supports only version 2.0, so the current check is for 2.0. Do not infer a future version
- **Referenced specification**: `SAML2Core#4.1.3.1`
- **Reference basis (SAML2Core)**; locator: `4\.1\.3\.1 Request Version||4\.1\.3\.2 Response Version`: A SAML requester SHOULD issue a request using the highest request version supported by both parties
- **source_clauses**: `[0, 109)` `sha256:284c8f093605…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SP14.aq</code> details</summary>

- **Required variants**:
  - `v-b74044f219` Even when the peer's version capability is unknown, the target SP's policy is to issue a LogoutRequest using its own highest version, 2.0
- **Controls (negative controls)**:
  - ★ SHOULD_CLASS. This is an internal policy, so it is ATTESTED. Do not independently assume a version newer than SAML 2.0
- **Referenced specification**: `SAML2Core#4.1.3.1`
- **Reference basis (SAML2Core)**; locator: `4\.1\.3\.1 Request Version||4\.1\.3\.2 Response Version`: If responder capabilities are unknown, the requester SHOULD assume that the responder supports its own highest request version
- **source_clauses**: `[0, 109)` `sha256:284c8f093605…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SP14.ar</code> details</summary>

- **Required variants**:
  - `v-802287b5b0` A LogoutRequest or LogoutResponse whose identifier / SessionIndex / Destination / Status is excluded from the signed content by XPath / XSLT → reject it
  - `v-948667a6e0` An SLO message containing a transform that leaves the signed content empty → reject it
- **Controls (negative controls)**:
  - Rejected → satisfied. Only acceptance requires ensuring that no content is excluded. The mere presence of a non-permitted transform may be grounds for rejection
  - An unimplemented request or response consumption direction is satisfied_with_note. The Suite self-validates the fixture's cryptographic validity and the actual exclusions
- **Referenced specification**: `SAML2Core#5.4.4`
- **Reference basis (SAML2Core)**; locator: `5\.4\.4 Transforms||5\.4\.5 KeyInfo`: The verifier MAY reject a signature containing a non-permitted transform; if it does not reject it, it MUST ensure that no content of the SAML message is excluded from the signature
- **source_clauses**: `[0, 109)` `sha256:284c8f093605…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SP14.as</code> details</summary>

- **Required variants**:
  - `v-e04404b7fc` A LogoutRequest issued by the target SP passes the protocol schema and contains @ID, @Version=2.0, @IssueInstant, and a principal identifier
  - `v-2da5839ef5` A LogoutResponse issued by the target SP passes the protocol schema and contains @ID, @Version=2.0, @IssueInstant, and <Status>
- **Controls (negative controls)**:
  - LogoutResponse issuance is an optional request-consumption path. If it is not observed, evaluate only the request direction
  - Evaluate value semantics, uniqueness, and UTC representation under their individual obligations; do not substitute schema validation alone
- **Referenced specification**: `SAML2Core#3.7.1-3.7.2 + SAML2P-xsd`
- **Reference basis (SAML2Core)**; locator: `3\.7\.1 Element <LogoutRequest>||3\.7\.2 Element <LogoutResponse>`: LogoutRequestType inherits from RequestAbstractType and requires a principal identifier choice
- **Reference basis (SAML2Core)**; locator: `3\.7\.2 Element <LogoutResponse>||3\.7\.3 Processing Rules`: LogoutResponse is StatusResponseType and has no additional content
- **Reference basis (SAML2P-xsd)**; locator: `<complexType name="RequestAbstractType"||<complexType name="ExtensionsType"`: ID, Version, and IssueInstant of RequestAbstractType have use=required
- **Reference basis (SAML2P-xsd)**; locator: `<complexType name="StatusResponseType"||<element name="Status"`: ID, Version, and IssueInstant of StatusResponseType, and Status, are required
- **Reference basis (SAML2P-xsd)**; locator: `<complexType name="LogoutRequestType"||<element name="LogoutResponse"`: The identifier choice of LogoutRequestType is required
- **source_clauses**: `[0, 109)` `sha256:284c8f093605…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

#### IIP-SP15

[Source](https://kantarainitiative.github.io/SAMLprofiles/fedinterop.html#IIP-SP15) / Section digest `sha256:c44ab5ee19a9…` / Section length 139 / Non-normative spans 0

| Obligation | Level | Role | Testability | Condition | Core/Full | Summary |
|---|---|---|---|---|---|---|
| `IIP-SP15.a` | MUST | sp | `BROWSER` | `supports_slo_initiation_sp`<br>(CAPABILITY_BASED) | full | Support sending SP-initiated LogoutRequest messages with HTTP-Redirect |
| `IIP-SP15.b` | MUST | sp | `BROWSER` | `supports_slo_sp`<br>(CAPABILITY_BASED) | full | When consuming LogoutRequest messages, support receiving them with HTTP-Redirect |
| `IIP-SP15.c` | MUST | sp | `BROWSER` | `supports_slo_sp`<br>(CAPABILITY_BASED) | full | When consuming LogoutRequest messages, support returning LogoutResponse messages with HTTP-Redirect |
| `IIP-SP15.d` | MUST | sp | `BROWSER` | `supports_slo_sp`<br>(CAPABILITY_BASED) | full | When consuming LogoutResponse messages, support receiving them with HTTP-Redirect |

<details><summary><code>IIP-SP15.a</code> details</summary>

- **Required variants**:
  - `v-157d025659` Configure the Suite IdP's SLO request endpoint for HTTP-Redirect only → the SP sends a LogoutRequest using HTTP-Redirect
- **Controls (negative controls)**:
  - The request-sending direction required by IIP-SP14.b. Do not conjunct any arbitrary receiving direction into the same variant
- **source_clauses**: `[0, 139)` `sha256:c44ab5ee19a9…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SP15.b</code> details</summary>

- **Required variants**:
  - `v-189688a5f2` The Suite IdP sends a LogoutRequest using HTTP-Redirect → the SP consumes it
- **Controls (negative controls)**:
  - Evaluate wire behavior only when the implementation of request consumption, which IIP-SP14.c makes OPTIONAL, is implemented. If unsupported, return satisfied_with_note; if support is claimed or observed but a Redirect request cannot be consumed, return violated
- **source_clauses**: `[0, 139)` `sha256:c44ab5ee19a9…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SP15.c</code> details</summary>

- **Required variants**:
  - `v-9f05ba1f0a` Advertise only HTTP-Redirect for the Suite IdP's SLO response endpoint and send an HTTP-Redirect LogoutRequest → the SP returns a LogoutResponse using HTTP-Redirect
- **Controls (negative controls)**:
  - The responder direction is coupled to request consumption. An SP that does not support reception is satisfied_with_note; do not require it to issue a response
  - When the Suite IdP advertises Redirect and POST, among others, do not force a Redirect response. SAML2Prof 4.4.3.4 states that either party MAY use any asynchronous binding supported by both parties
- **source_clauses**: `[0, 139)` `sha256:c44ab5ee19a9…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SP15.d</code> details</summary>

- **Required variants**:
  - `v-bd4ddb8fdd` For an SP's LogoutRequest, the Suite IdP returns an HTTP-Redirect LogoutResponse → the SP consumes it
- **Controls (negative controls)**:
  - Evaluate wire behavior only when response consumption, which IIP-SP14.c1 makes OPTIONAL, is implemented. If unsupported, return satisfied_with_note; do not infer support from request consumption
- **source_clauses**: `[0, 139)` `sha256:c44ab5ee19a9…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

#### IIP-SP16

[Source](https://kantarainitiative.github.io/SAMLprofiles/fedinterop.html#IIP-SP16) / Section digest `sha256:10a52215727f…` / Section length 467 / Non-normative spans 0

| Obligation | Level | Role | Testability | Condition | Core/Full | Summary |
|---|---|---|---|---|---|---|
| `IIP-SP16.a` | MUST | sp | `BROWSER` | `supports_slo_sp`<br>(CAPABILITY_BASED) | full | SPs supporting SLO must support decryption of saml:EncryptedID in logout requests |
| `IIP-SP16.b` | MUST | sp | `CONFIG` | `supports_slo_sp`<br>(CAPABILITY_BASED) | full | Be configurable with at least two decryption keys (for encrypted identifiers) |
| `IIP-SP16.c` | MUST | sp | `BROWSER` | `supports_slo_sp`<br>(CAPABILITY_BASED) | full | Attempt each decryption key until the identifier decrypts or keys are exhausted |

<details><summary><code>IIP-SP16.a</code> details</summary>

- **Required variants**:
  - `v-6e138e936f` EncryptedID encrypted with the first key
- **source_clauses**: `[0, 140)` `sha256:c80bcbdb664f…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SP16.b</code> details</summary>

- **Required variants**:
  - `v-d10ed99386` Whether two keys can be configured
- **Configuration failure semantics**: `normative_capability`
- **source_clauses**: `[141, 254)` `sha256:059756073dbf…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-SP16.c</code> details</summary>

- **Required variants**:
  - `v-c495957ae7` Encrypt with the second key → decrypted
  - `v-28ac3cb696` Unregistered key → failure (control)
- **source_clauses**: `[255, 466)` `sha256:d842bb823694…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

#### IIP-SP17

[Source](https://kantarainitiative.github.io/SAMLprofiles/fedinterop.html#IIP-SP17) / Section digest `sha256:d18728f041da…` / Section length 314 / Non-normative spans 0

| Obligation | Level | Role | Testability | Condition | Core/Full | Summary |
|---|---|---|---|---|---|---|
| `IIP-SP17.a` | MUST | sp | `CONFIG` | `supports_slo_sp`<br>(CAPABILITY_BASED) | full | SPs supporting SLO must consume peer configuration from metadata, without additional inputs, for every element listed in SAML2Prof 4.4.5 |

<details><summary><code>IIP-SP17.a</code> details</summary>

- **Required variants**:
  - `v-ba43e6e461` md:SingleLogoutService (binding and Location)
  - `v-d6e1eb89af` md:KeyDescriptor use=encryption when identifiers are encrypted (algorithm, configuration, and public key)
- **Controls (negative controls)**:
  - Only two elements. Do not return PASS merely because the SLO endpoint is followed
- **Configuration failure semantics**: `normative_capability`
- **Referenced specification**: `SAML2Prof#4.4.5`
- **Reference basis (SAML2Prof)**; locator: `4\.4\.5\s+Use of Metadata||4\.5\s+Name Identifier Management Profile`: Read the full text of §4.4.5 and confirmed that the enumeration contains only two items: md:SingleLogoutService and, when encryption is used, md:KeyDescriptor with use=encryption
- **Notes**: Enumerated directly from SAML2Prof 4.4.5 (saml-profiles-2.0-os, sha256:5df9b874…). Section 4.4.5 contains only two items: SingleLogoutService and, when encryption is used, an encryption KeyDescriptor
- **source_clauses**: `[0, 314)` `sha256:d18728f041da…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

### 4.1 Identity Provider / Web Browser SSO

#### IIP-IDP01

[Source](https://kantarainitiative.github.io/SAMLprofiles/fedinterop.html#IIP-IDP01) / Section digest `sha256:dfe610974de9…` / Section length 201 / Non-normative spans 0

| Obligation | Level | Role | Testability | Condition | Core/Full | Summary |
|---|---|---|---|---|---|---|
| `IIP-IDP01.a` | MUST | idp | `CONFIG` | — | core | Generate saml:Attribute elements with any arbitrary xs:string Name and any arbitrary xs:anyURI NameFormat |

<details><summary><code>IIP-IDP01.a</code> details</summary>

- **Required variants**:
  - `v-e80aaa3f9e` Define a URN-form Name.
  - `v-4daff1ecd1` An arbitrary non-URI string Name.
  - `v-81d7518ef5` Unknown NameFormat URI
- **Controls (negative controls)**:
  - The Suite can statically inspect Name and NameFormat on received attributes.
- **Configuration failure semantics**: `normative_capability`
- **source_clauses**: `[0, 201)` `sha256:dfe610974de9…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

#### IIP-IDP02

[Source](https://kantarainitiative.github.io/SAMLprofiles/fedinterop.html#IIP-IDP02) / Section digest `sha256:920a5795b541…` / Section length 183 / Non-normative spans 0

| Obligation | Level | Role | Testability | Condition | Core/Full | Summary |
|---|---|---|---|---|---|---|
| `IIP-IDP02.a` | MUST | idp | `CONFIG` | — | core | Determine whether to include specific attributes or values based on the relying party's entityID |

<details><summary><code>IIP-IDP02.a</code> details</summary>

- **Required variants**:
  - `v-2ab734b923` Configure different attribute-release policies for two secondary_peer entityIDs and determine whether the returned attribute sets differ.
- **Controls (negative controls)**:
  - Two entityIDs enable automated judgment; with one, it is impossible to establish that entityID caused the decision.
- **Configuration failure semantics**: `normative_capability`
- **source_clauses**: `[0, 183)` `sha256:920a5795b541…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

#### IIP-IDP03

[Source](https://kantarainitiative.github.io/SAMLprofiles/fedinterop.html#IIP-IDP03) / Section digest `sha256:f70fbcd3d70f…` / Section length 259 / Non-normative spans 0

| Obligation | Level | Role | Testability | Condition | Core/Full | Summary |
|---|---|---|---|---|---|---|
| `IIP-IDP03.a` | MUST | idp | `CONFIG` | — | core | Determine whether to include specific attributes or values based on mdattr:EntityAttributes in the relying party's metadata |

<details><summary><code>IIP-IDP03.a</code> details</summary>

- **Required variants**:
  - `v-f83eae348f` Variant with EntityAttributes present.
  - `v-51cdf23b6a` Variant without EntityAttributes; determine whether the returned attribute set differs.
- **Controls (negative controls)**:
  - A presence/absence control is mandatory.
- **Configuration failure semantics**: `normative_capability`
- **source_clauses**: `[0, 259)` `sha256:f70fbcd3d70f…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

#### IIP-IDP04

[Source](https://kantarainitiative.github.io/SAMLprofiles/fedinterop.html#IIP-IDP04) / Section digest `sha256:5b9aa663bbde…` / Section length 973 / Non-normative spans 1

| Obligation | Level | Role | Testability | Condition | Core/Full | Summary |
|---|---|---|---|---|---|---|
| `IIP-IDP04.a` | MUST | idp | `CONFIG` | — | core | Determine attribute inclusion based on md:AttributeConsumingService / md:RequestedAttribute in the peer's metadata, including the value of the isRequired attribute |
| `IIP-IDP04.b` | MUST | idp | `CONFIG` | — | core | Support the AttributeConsumingServiceIndex attribute in AuthnRequest as the means of selecting the applicable md:AttributeConsumingService |

<details><summary><code>IIP-IDP04.a</code> details</summary>

- **Required variants**:
  - `v-ebb75050f9` Presence versus absence of RequestedAttribute.
  - `v-577d080a7e` Control with isRequired=true versus false.
- **Controls (negative controls)**:
  - The source requires only the ability to use isRequired as an input; it does not prescribe an outcome such as mandatory release when true. Configure a target policy that produces a difference based on isRequired, then observe that difference.
- **Configuration failure semantics**: `normative_capability`
- **source_clauses**: `[0, 351)` `sha256:09a0490b28aa…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-IDP04.b</code> details</summary>

- **Required variants**:
  - `v-5563261fa5` Define AttributeConsumingService entries at index 0 and index 1, vary the AuthnRequest index, and determine whether the returned attribute set changes.
- **Controls (negative controls)**:
  - Because the Suite initiates the request, this can be judged fully automatically.
- **Configuration failure semantics**: `test_precondition`
- **source_clauses**: `[352, 553)` `sha256:1dfb85471b7a…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

#### IIP-IDP05

[Source](https://kantarainitiative.github.io/SAMLprofiles/fedinterop.html#IIP-IDP05) / Section digest `sha256:cdc106db01a2…` / Section length 494 / Non-normative spans 0

| Obligation | Level | Role | Testability | Condition | Core/Full | Summary |
|---|---|---|---|---|---|---|
| `IIP-IDP05.a` | MUST | idp | `AUTOMATED` | — | core | Issue samlp:Response messages with appropriate status codes on error, provided the user agent remains available and an acceptable response location is known |

<details><summary><code>IIP-IDP05.a</code> details</summary>

- **Required variants**:
  - `v-361beef8de` An unknown NameIDPolicy/@Format produces an error Response.
  - `v-73e9109fd7` An unsatisfiable RequestedAuthnContext produces an error Response with top-level Responder; secondary NoAuthnContext is MAY.
  - `v-b4ec386f3d` IsPassive with no session produces an error Response; secondary NoPassive is MAY.
- **Controls (negative controls)**:
  - Do not use an unregistered ACS URL as a FAIL condition. In that case no acceptable location is known, and the source permits omission of an error Response.
  - Secondary StatusCode values are MAY under E65 and Core processing rules; do not require any specific secondary value.
- **Referenced specification**: `SAML2Core`
- **Reference basis (SAML2Core)**; locator: `3\.4\.1\.4\s+Processing Rules||3\.4\.1\.5\s+`: Rules for returning a Response on error, including the basis for handling cases where no acceptable location is known.
- **Notes**: The source does not formalize acceptability and explicitly leaves it to IdP policy.
- **source_clauses**: `[0, 258)` `sha256:4b26a1ff778d…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

#### IIP-IDP06

[Source](https://kantarainitiative.github.io/SAMLprofiles/fedinterop.html#IIP-IDP06) / Section digest `sha256:9f0c9ea1d83d…` / Section length 925 / Non-normative spans 2

| Obligation | Level | Role | Testability | Condition | Core/Full | Summary |
|---|---|---|---|---|---|---|
| `IIP-IDP06.a` | MUST | idp | `BROWSER` | — | core | If ForceAuthn is true, authenticate the presenter directly rather than rely on a previous security context |
| `IIP-IDP06.b` | MUST | idp | `ATTESTED` | — | core | Authentication mechanisms within the implementation must have access to the ForceAuthn indicator so their behaviour may be influenced by its value |
| `IIP-IDP06.c` | MUST_NOT | idp | `BROWSER` | — | core | If both ForceAuthn and IsPassive are true, must not freshly authenticate the presenter unless the constraints of IsPassive can be met |

<details><summary><code>IIP-IDP06.a</code> details</summary>

- **Required variants**:
  - `v-abf501b54d` After establishing a session, ForceAuthn=true causes a new authentication action.
  - `v-3915a2be59` The returned Assertion's AuthnStatement/@AuthnInstant is at or after the AuthnRequest IssueInstant.
  - `v-7c11c7ca52` Control: omit ForceAuthn, defaulting to false, with an existing session; reuse of the existing context is permitted and must not FAIL.
  - `v-a5344652c4` Control: explicitly set ForceAuthn=false with an existing session; same expectation.
- **Controls (negative controls)**:
  - What is prohibited is reliance on an existing context when ForceAuthn is true. Fresh authentication when false or omitted is not prohibited. A case requiring reuse when false would fail a conforming implementation that always reauthenticates.
  - AuthnInstant alone is weak evidence. Begin with a valid existing session, or the effect of ForceAuthn cannot be distinguished.
  - SAML2Prof 4.1.3.4 states the same rule, but IIP-IDP06 references SAML2Core, so use section 3.4.1 as the basis.
- **Referenced specification**: `SAML2Core#3.4.1`
- **Reference basis (SAML2Core)**; locator: `3\.4\.1 Element <AuthnRequest>||3\.4\.1\.1 Element <NameIDPolicy>`: SAML2Core 3.4.1 ForceAuthn rule: when true, the identity provider MUST authenticate the presenter directly rather than rely on a previous security context.
- **Notes**: "If a value is not provided, the default is false" defines a default, not an IdP obligation. The MUST NOT for combination with IsPassive is separated into IIP-IDP06.c.
- **source_clauses**: `[0, 116)` `sha256:40cd2c53a3cb…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-IDP06.b</code> details</summary>

- **Required variants**:
  - `v-e6fa1fe5de` Attest whether authentication mechanisms such as forms, MFA, or certificates can access ForceAuthn.
- **Notes**: Because external observation only sees reauthentication when true, reachability inside the mechanism is ATTESTED.
- **source_clauses**: `[117, 271)` `sha256:928b3a562d85…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-IDP06.c</code> details</summary>

- **Required variants**:
  - `v-c288373b3b` ForceAuthn=true and IsPassive=true with only interactive authentication available: show no user-visible authentication UI and return a Response containing an error Status.
  - `v-8b2f0a67ab` Control: ForceAuthn=true and IsPassive=false may cause visible reauthentication; do not FAIL it.
  - `v-90c6972c04` Control: ForceAuthn=true and IsPassive=true with non-interactive authentication such as a certificate or Kerberos may freshly authenticate.
- **Controls (negative controls)**:
  - A case implemented as "always reauthenticate when ForceAuthn=true" cannot detect this MUST NOT. Always pair it with IsPassive.
  - Secondary status is MAY; do not require NoPassive. An error Status is sufficient.
  - The condition differs for targets with non-interactive authentication. Collect the authentication method at preflight and select the expected outcome accordingly.
- **Referenced specification**: `SAML2Core#3.4.1`
- **Reference basis (SAML2Core)**; locator: `3\.4\.1 Element <AuthnRequest>||3\.4\.1\.1 Element <NameIDPolicy>`: SAML2Core 3.4.1 ForceAuthn rule: if ForceAuthn and IsPassive are both true, the identity provider MUST NOT freshly authenticate unless the IsPassive constraints can be met.
- **Notes**: This differs from IIP-IDP07: that obligation covers IsPassive alone; this one prohibits behavior for the two-attribute combination.
- **source_clauses**: `[0, 116)` `sha256:40cd2c53a3cb…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

#### IIP-IDP07

[Source](https://kantarainitiative.github.io/SAMLprofiles/fedinterop.html#IIP-IDP07) / Section digest `sha256:50adf1500e90…` / Section length 115 / Non-normative spans 0

| Obligation | Level | Role | Testability | Condition | Core/Full | Summary |
|---|---|---|---|---|---|---|
| `IIP-IDP07.a` | MUST_NOT | idp | `BROWSER` | — | core | If IsPassive is true, the identity provider and the user agent must not visibly take control of the user interface and interact with the presenter in a noticeable fashion |

<details><summary><code>IIP-IDP07.a</code> details</summary>

- **Required variants**:
  - `v-6189dc7f32` Existing session plus IsPassive=true: return an Assertion without user interaction or visible page transition.
  - `v-0d71fb5c27` No existing session plus IsPassive=true: display no authentication or consent screen; this is the judged property.
  - `v-cdf6d22855` In that case, observe that the returned Response contains an error Status. IIP-IDP05.a owns the verdict; record only the observation here.
  - `v-4d75f46b04` Control: no session with IsPassive omitted, default false, may display authentication UI; do not FAIL it.
  - `v-a0398bfdb6` Consent and attribute-release screens also constitute noticeable interaction and must not appear when IsPassive=true.
- **Controls (negative controls)**:
  - Controls for both states—session present and absent—are mandatory; one alone cannot prove support.
  - Correction: the previous version required NoPassive for no session plus IsPassive=true, but SAML2Core 3.4.1.4 makes the secondary status MAY. Absence of NoPassive must not FAIL. Judge only that a Response with an error Status is returned and no visible UI appears.
  - The Suite must directly observe visible UI takeover. Browser automation records intermediate pages and forms. Redirects are not violations if they require no user interaction.
  - The source addresses both the identity provider and user agent, but the conformance target is only the IdP.
  - Returning an error Response is a general SAML2Core 3.4.1.4 rule owned by IIP-IDP05.a; do not judge it twice here.
- **Referenced specification**: `SAML2Core#3.4.1`
- **Reference basis (SAML2Core)**; locator: `3\.4\.1 Element <AuthnRequest>||3\.4\.1\.1 Element <NameIDPolicy>`: SAML2Core 3.4.1 IsPassive rule: if true, the identity provider and user agent MUST NOT visibly take control of the requester’s user interface or noticeably interact with the presenter.
- **Notes**: "If a value is not provided, the default is false" defines a default, not an obligation. The ForceAuthn combination is covered by IIP-IDP06.c.
- **source_clauses**: `[0, 115)` `sha256:50adf1500e90…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

#### IIP-IDP08

[Source](https://kantarainitiative.github.io/SAMLprofiles/fedinterop.html#IIP-IDP08) / Section digest `sha256:a569f8d22b05…` / Section length 148 / Non-normative spans 0

| Obligation | Level | Role | Testability | Condition | Core/Full | Summary |
|---|---|---|---|---|---|---|
| `IIP-IDP08.a` | MUST | idp | `BROWSER` | — | core | Support the RequestedAuthnContext exact comparison method in AuthnRequest as defined in SAML2Core |

<details><summary><code>IIP-IDP08.a</code> details</summary>

- **Required variants**:
  - `v-511d656674` A satisfiable ClassRef returns the matching AuthnContextClassRef.
  - `v-bde8bf2fe0` A satisfiable DeclRef returns an authentication context corresponding to the matching AuthnContextDeclRef.
  - `v-e8c76830df` An unsatisfiable ClassRef or DeclRef returns an error Response with top-level StatusCode=Responder; secondary NoAuthnContext is optional.
- **Controls (negative controls)**:
  - Controls for satisfiable and unsatisfiable requests are mandatory.
  - Errata E65 makes NoAuthnContext MAY; omission of that secondary code must not FAIL.
- **Referenced specification**: `SAML2Core#3.3.2.2.1`
- **Reference basis (SAML2Core)**; locator: `3\.3\.2\.2\.1 Element <RequestedAuthnContext>||3\.3\.2\.3 Element <AttributeQuery>`: Rules for exact comparison; Errata E65 updates status handling when the request cannot be satisfied.
- **Reference basis (SAML2Errata)**; locator: `E65: Second-level StatusCode||E66: `: When unsatisfiable, top-level Responder is MUST and secondary NoAuthnContext is MAY.
- **source_clauses**: `[0, 148)` `sha256:a569f8d22b05…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

#### IIP-IDP09

[Source](https://kantarainitiative.github.io/SAMLprofiles/fedinterop.html#IIP-IDP09) / Section digest `sha256:3950d82bd15d…` / Section length 123 / Non-normative spans 0

| Obligation | Level | Role | Testability | Condition | Core/Full | Summary |
|---|---|---|---|---|---|---|
| `IIP-IDP09.a` | MUST | idp | `CONFIG` | — | core | Support encryption of assertions |
| `IIP-IDP09.b` | OPTIONAL | idp | `BROWSER` | — | full | Encryption of identifiers and attributes is optional |

<details><summary><code>IIP-IDP09.a</code> details</summary>

- **Required variants**:
  - `v-cc1cc289bd` With an encryption key in Suite metadata, an EncryptedAssertion is returned.
- **Configuration failure semantics**: `normative_capability`
- **source_clauses**: `[0, 57)` `sha256:082229255930…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-IDP09.b</code> details</summary>

- **Required variants**:
  - `v-5e91627386` Record as information whether EncryptedID or EncryptedAttribute is returned.
- **source_clauses**: `[58, 123)` `sha256:8c57da38ea1a…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

#### IIP-IDP10

[Source](https://kantarainitiative.github.io/SAMLprofiles/fedinterop.html#IIP-IDP10) / Section digest `sha256:02dce7a982bb…` / Section length 124 / Non-normative spans 0

| Obligation | Level | Role | Testability | Condition | Core/Full | Summary |
|---|---|---|---|---|---|---|
| `IIP-IDP10.a` | MUST | idp | `BROWSER` | — | core | Accept and process the samlp:NameIDPolicy element and its Format, SPNameQualifier and AllowCreate attributes |
| `IIP-IDP10.b` | MUST | idp | `BROWSER` | — | core | If the content of NameIDPolicy is not understood or not acceptable, return a Response with an error Status |
| `IIP-IDP10.c` | MUST | idp | `BROWSER` | `supports_encrypted_nameid`<br>(CAPABILITY_BASED) | core | If Format is the encrypted value, the resulting assertions must contain EncryptedID elements instead of plaintext |
| `IIP-IDP10.d` | MUST | idp | `BROWSER` | — | core | If the NameIDPolicy content is accepted, the returned identifier must conform to it; otherwise an error must be returned |

<details><summary><code>IIP-IDP10.a</code> details</summary>

- **Required variants**:
  - `v-db49b17381` Specify Format=persistent; the request can be processed, with result validation under IIP-IDP10.d.
  - `v-ef43334521` Specify Format=transient; the request can be processed.
  - `v-047fe75dfa` Omit Format; the IdP may return any identifier and must not error merely for omission.
  - `v-a9f225bd83` Specify Format=urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified; same expectation.
  - `v-379659e791` Specify SPNameQualifier; the request can be processed, with result validation under IIP-IDP10.d.
  - `v-c8d530c346` Specify AllowCreate=true; the request can be processed.
  - `v-5c728816e6` Specify AllowCreate=false; the request can be processed.
  - `v-04749c96fd` Omit AllowCreate; the request can be processed.
  - `v-f4691278c3` Omit NameIDPolicy itself; the request can be processed, paired with generation-side IIP-SP03.a.
- **Controls (negative controls)**:
  - Do not interpret AllowCreate=false as an absolute prohibition on creating identifiers. The source imposes no MUST on the IdP, and SAML2Errata E14 explicitly softens it: the requester tries to constrain creation, but the IdP may assume such information exists.
  - "Can process" means returning a SAML-valid response, either success or an error Status. IIP-IDP10.d judges the returned identifier; IIP-IDP10.b judges error handling.
  - Do not require a particular Format when Format is unspecified or omitted; the source permits any kind of identifier.
- **Referenced specification**: `SAML2Core#3.4.1.1`
- **Reference basis (SAML2Core)**; locator: `3\.4\.1\.1 Element <NameIDPolicy>||3\.4\.1\.2 Element <Scoping>`: Normative definitions of NameIDPolicy and its three attributes in SAML2Core 3.4.1.1.
- **Notes**: SAML2Errata E14 rewrites AllowCreate and removes the old MUST from SAML2Prof 4.1.4.1 in favor of SAMLCore. IIP-IDP10 alone does not state that errata are incorporated, so this obligation covers base OS Core processing. IIP-SSO01 requires the Web Browser SSO Profile with errata, so E14 additions are normative under IIP-SSO01.fl–.fp, not downgraded to advisory.
- **source_clauses**: `[0, 124)` `sha256:02dce7a982bb…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-IDP10.b</code> details</summary>

- **Required variants**:
  - `v-d229b73c90` Specify an unsupported Format, such as an unknown URI; a Response containing an error Status is returned.
  - `v-80b26f20f9` Specify an SPNameQualifier unknown to the target, such as another SP's entityID; either succeed or return an error Status, but do not silently ignore it.
  - `v-4c7f43fdd5` Control: specify a supported Format; a successful response is returned, rejecting an implementation that errors for everything.
- **Controls (negative controls)**:
  - Secondary InvalidNameIDPolicy is MAY; its absence must not FAIL.
  - Silently returning a different Format violates this obligation: the IdP neither accepts nor rejects the policy. Inspect it together with IIP-IDP10.d.
  - A negative control is mandatory: an implementation that always errors even for supported Formats could appear to satisfy this obligation, but must fail the IIP-IDP10.a success case.
- **Referenced specification**: `SAML2Core#3.4.1.1`
- **Reference basis (SAML2Core)**; locator: `3\.4\.1\.1 Element <NameIDPolicy>||3\.4\.1\.2 Element <Scoping>`: 『When this element is used, if the content is not understood by or acceptable to the identity provider, then a <Response> message element MUST be returned with an error <Status>, and MAY contain a second-level <StatusCode> of urn:oasis:names:tc:SAML:2.0:status:InvalidNameIDPolicy』
- **source_clauses**: `[0, 124)` `sha256:02dce7a982bb…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-IDP10.c</code> details</summary>

- **Required variants**:
  - `v-a2956817eb` Format=urn:oasis:names:tc:SAML:2.0:nameid-format:encrypted: Subject contains saml:EncryptedID and no plaintext saml:NameID.
  - `v-56c2ee19ec` After decryption, the underlying identifier may have any type supported by the IdP; do not restrict the type and FAIL.
- **Controls (negative controls)**:
  - Identifier encryption is OPTIONAL under IIP-IDP09.b. If unsupported, the condition is false and the result is NOT_APPLICABLE; IIP-IDP10.b then expects an error response.
  - Regardless of Format, an IdP MAY return EncryptedID under its own policy; account for this in the IIP-IDP10.d control.
- **Referenced specification**: `SAML2Core#3.4.1.1`
- **Reference basis (SAML2Core)**; locator: `3\.4\.1\.1 Element <NameIDPolicy>||3\.4\.1\.2 Element <Scoping>`: 『The special Format value urn:oasis:names:tc:SAML:2.0:nameid-format:encrypted indicates that the resulting assertion(s) MUST contain <EncryptedID> elements instead of plaintext』
- **source_clauses**: `[0, 124)` `sha256:02dce7a982bb…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-IDP10.d</code> details</summary>

- **Required variants**:
  - `v-e4467623ff` Request Format=persistent; returned NameID/@Format equals the requested value.
  - `v-898a349947` Request Format=transient; returned NameID/@Format equals the requested value.
  - `v-e2c03ed209` Specify SPNameQualifier; returned NameID/@SPNameQualifier equals the specified value, or persistent/transient NameID omits it when the message is intended only for direct consumption by that SP and the implicit value equals that SP identifier (Core 8.3.7-8.3.8).
  - `v-534e8baf05` Control: detect silent return of a Format different from the request—a successful response with the wrong Format.
  - `v-96ea6f9410` Control: this obligation does not apply when Format is omitted, unspecified, or encrypted; any identifier is permitted.
- **Controls (negative controls)**:
  - Key detection control: checking only for a successful response lets an implementation ignore the request and return its default Format.
  - Exclude unspecified and encrypted from applicability, where the source permits any kind of identifier.
  - Correction: the prior basis was the 3.4.1.1 rule requiring an error when content is not understood or acceptable, but that MUST does not require conformance after acceptance. Use 3.4.1.4, requiring assertions that meet the request's specifications.
  - SAML2Errata E15 states the same conclusion explicitly, but IIP-IDP10 does not reference SAML2Core with errata incorporated, so do not use E15 as verdict basis; record it as advisory.
  - If policy causes the IdP to return EncryptedID, compare the decrypted Format.
- **Referenced specification**: `SAML2Core#3.4.1.4`
- **Reference basis (SAML2Core)**; locator: `3\.4\.1\.4 Processing Rules||3\.4\.1\.5 Proxying`: The basis is 3.4.1.4: the responder MUST ultimately answer AuthnRequest with a Response containing assertions meeting the request's specifications, or a Response with Status describing the error. NameIDPolicy is part of those specifications, so the response must satisfy it or report an error. Section 3.4.1 refers to 3.4.1.4 for general processing, placing this within IIP-IDP10's "as defined in SAML2Core" scope.
- **Reference basis (SAML2Core)**; locator: `3\.4\.1\.4 Processing Rules||3\.4\.1\.5 Proxying`: Corroboration: the same section's strong-match rule allows a different identifier format when specified by NameIDPolicy, presupposing that NameIDPolicy determines identifier format.
- **Notes**: Under the errata policy, only clauses whose IIP text expressly incorporates errata are normative. Do not create a rule relying only on E15; this obligation derives solely from OS 3.4.1.4.
- **source_clauses**: `[0, 124)` `sha256:02dce7a982bb…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

#### IIP-IDP11

[Source](https://kantarainitiative.github.io/SAMLprofiles/fedinterop.html#IIP-IDP11) / Section digest `sha256:83f67b30db0d…` / Section length 137 / Non-normative spans 0

| Obligation | Level | Role | Testability | Condition | Core/Full | Summary |
|---|---|---|---|---|---|---|
| `IIP-IDP11.a` | MUST | idp | `CONFIG` | — | core | Generate saml:Assertion elements without a saml:NameID in the saml:Subject |

<details><summary><code>IIP-IDP11.a</code> details</summary>

- **Required variants**:
  - `v-c98f3c4755` Perform SSO with NameID disabled; Subject contains no NameID.
- **Configuration failure semantics**: `normative_capability`
- **source_clauses**: `[0, 137)` `sha256:83f67b30db0d…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

#### IIP-IDP12

[Source](https://kantarainitiative.github.io/SAMLprofiles/fedinterop.html#IIP-IDP12) / Section digest `sha256:3662ba485eda…` / Section length 247 / Non-normative spans 0

| Obligation | Level | Role | Testability | Condition | Core/Full | Summary |
|---|---|---|---|---|---|---|
| `IIP-IDP12.a` | MUST | idp | `BROWSER` | — | core | Support the AssertionConsumerServiceIndex attribute in AuthnRequest for identifying the response endpoint |
| `IIP-IDP12.e` | MUST | idp | `BROWSER` | — | core | Support the AssertionConsumerServiceURL attribute in AuthnRequest for identifying the response endpoint |
| `IIP-IDP12.f` | MUST | idp | `BROWSER` | — | core | Support the ProtocolBinding attribute in AuthnRequest for identifying the binding used to return the Response |
| `IIP-IDP12.b` | MUST | idp | `BROWSER` | — | core | The responder must ensure that the AssertionConsumerServiceURL value is in fact associated with the requester, and must have a trusted means to map an index to a location associated with the requester |
| `IIP-IDP12.c` | MUST | idp | `BROWSER` | — | core | If AssertionConsumerServiceIndex is omitted, return the Response to the default location associated with the requester |
| `IIP-IDP12.d` | MAY | idp | `BROWSER` | — | full | If the specified index is invalid, the identity provider may return an error Response or may use the default location |

<details><summary><code>IIP-IDP12.a</code> details</summary>

- **Required variants**:
  - `v-36498b67e0` Specify AssertionConsumerServiceIndex; Response is returned to the metadata ACS having that index.
  - `v-d051803f2c` Specify a non-default index; Response goes to that ACS rather than the default, rejecting fixed-default implementations.
  - `v-85d98fa8a5` Control: omit all three attributes; Response goes to the default ACS under IIP-IDP12.c.
- **Controls (negative controls)**:
  - Test Peer metadata must contain at least two ACS endpoints, or the test cannot distinguish an implementation fixed to the default.
  - Always include a non-default index; testing only the default cannot distinguish an implementation that ignores the index.
- **Referenced specification**: `SAML2Core#3.4.1`
- **Reference basis (SAML2Core)**; locator: `3\.4\.1 Element <AuthnRequest>||3\.4\.1\.1 Element <NameIDPolicy>`: Normative definitions of the three attributes in SAML2Core 3.4.1; all three IIP-IDP12 attributes are defined there.
- **Notes**: Because the source enumerates three attributes, obligations are split per attribute: Index in .a, URL in .e, and ProtocolBinding in .f. Detection differs, especially because ProtocolBinding may lack positive evidence. Keeping them separate preserves verified versus unverified status. Value validation is IIP-IDP12.b, default-location return is .c, and invalid-index handling is .d.
- **source_clauses**: `[0, 247)` `sha256:3662ba485eda…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-IDP12.e</code> details</summary>

- **Required variants**:
  - `v-bf3d699d20` Specify a non-default ACS URL present in metadata; Response is returned to it.
  - `v-6178b9e94c` Specify only the URL, without ProtocolBinding; Response is returned there, proving URL alone is effective.
  - `v-640bdbfff4` Control: omit URL; Response is returned to the default ACS under IIP-IDP12.c.
- **Controls (negative controls)**:
  - Specifying the default ACS URL has no detection power; always specify a non-default ACS.
  - Behavior for a URL absent from metadata belongs to IIP-IDP12.b validation and is not covered here.
- **Referenced specification**: `SAML2Core#3.4.1`
- **Reference basis (SAML2Core)**; locator: `3\.4\.1 Element <AuthnRequest>||3\.4\.1\.1 Element <NameIDPolicy>`: 『AssertionConsumerServiceURL [Optional] Specifies by value the location to which the <Response> message MUST be returned to the requester』
- **source_clauses**: `[0, 247)` `sha256:3662ba485eda…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-IDP12.f</code> details</summary>

- **Required variants**:
  - `v-d52d921b7f` Positive evidence A: switch ProtocolBinding between HTTP-POST and HTTP-Artifact; the response binding switches, when the target supports Artifact.
  - `v-506e90c9bf` Positive evidence B: specify a binding unusable for Response, HTTP-Redirect or an undefined binding URI; a Response with an error Status is returned, optionally with secondary UnsupportedBinding.
  - `v-5d97fd0b51` Specify ProtocolBinding=HTTP-POST; Response uses POST. This is not positive evidence because POST is the default.
  - `v-d7fa7792d4` Specify ProtocolBinding=HTTP-Redirect; Response is not returned through HTTP-Redirect. Alone this is not positive evidence because IIP-SSO01.x prohibits Redirect.
- **Controls (negative controls)**:
  - Detection-critical: "POST requested, POST returned" and "Redirect requested, Redirect not returned" both pass an implementation that entirely ignores ProtocolBinding and always uses default POST. These two alone cannot yield satisfied.
  - Return satisfied only when positive evidence A or B is obtained. If neither is available, return not_verified(no_positive_evidence_for_protocol_binding).
  - If an unsupported binding silently falls back to another binding, processing cannot be distinguished from ignoring; return not_verified.
  - Secondary status is MAY under SAML2Core 3.4.1.4, so absence of UnsupportedBinding alone is not a violation. Evidence B requires an error Status.
  - SAML2Core 3.4.1 makes Index mutually exclusive with URL/ProtocolBinding, but this constrains the requester SP and carries no RFC2119 keyword, so it creates no IdP obligation. Record behavior for requests containing both as advisory.
- **Referenced specification**: `SAML2Core#3.4.1`
- **Reference basis (SAML2Core)**; locator: `3\.4\.1 Element <AuthnRequest>||3\.4\.1\.1 Element <NameIDPolicy>`: 『ProtocolBinding [Optional] A URI reference that identifies a SAML protocol binding to be used when returning the <Response> message』
- **Notes**: The Web Browser SSO Profile cannot deliver Response via HTTP-Redirect under IIP-SSO01.x. For a target without Artifact support, HTTP-POST is the only legal response binding, so positive proof may depend on observing an error. Explicitly use not_verified rather than calling unverifiable behavior conforming.
- **source_clauses**: `[0, 247)` `sha256:3662ba485eda…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-IDP12.b</code> details</summary>

- **Required variants**:
  - `v-3a95a9db0c` Specify an ACS URL absent from the requester's metadata; do not return to it. Return an error Status or use the default ACS.
  - `v-7bb5cc8278` Specify an ACS URL listed in another entity's metadata; do not return to it.
  - `v-ceda198a77` Specify an index absent from metadata; handling is governed by IIP-IDP12.d, but never return to a location not associated with the requester.
  - `v-1af5c9d390` Control: specify an ACS URL present in the requester's metadata; return there, rejecting an implementation that rejects everything.
- **Controls (negative controls)**:
  - This obligation addresses a canonical SAML vulnerability, open redirection. Pair it with a case where a metadata-listed URL succeeds, or an implementation rejecting everything could PASS.
  - The rule also applies to signed AuthnRequests. SAML2Prof 4.1.4.1 says it applies whether signed or not; create both cases.
  - Observe non-delivery using both browser destination URL and Response destination. Whether the implementation displays an error or sends to the default ACS is implementation-specific; neither is a violation.
- **Referenced specification**: `SAML2Core#3.4.1`
- **Reference basis (SAML2Core)**; locator: `3\.4\.1 Element <AuthnRequest>||3\.4\.1\.1 Element <NameIDPolicy>`: Basis: the responder MUST ensure the specified AssertionConsumerServiceURL is associated with the requester, and the IdP MUST have a trusted means to map AssertionConsumerServiceIndex to such a location.
- **Notes**: This pairs with IIP-IDP05 concerning acceptable error-response locations. SAML2Prof 4.1.3.5 is equivalent, but IIP-IDP12 references SAML2Core, so use 3.4.1 as the basis.
- **source_clauses**: `[0, 247)` `sha256:3662ba485eda…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-IDP12.c</code> details</summary>

- **Required variants**:
  - `v-41b5049aed` Omit all three attributes; return to the endpoint whose md:AssertionConsumerService/@isDefault is true.
  - `v-3afcbfbda5` For metadata with no explicit isDefault, return to the endpoint selected by SAML2Meta's default rule, the lowest index.
  - `v-458174c918` Control: change a non-default ACS to isDefault and refetch metadata; the destination changes, proving metadata was read.
- **Controls (negative controls)**:
  - Metadata with only one ACS has no detection power; test a variant with at least two.
  - Determine "default" under SAML2Meta rules. This overlaps IIP-MD05 and IIP-SSO06 metadata consumption, but judge only return to the default location here.
- **Referenced specification**: `SAML2Core#3.4.1`
- **Reference basis (SAML2Core)**; locator: `3\.4\.1 Element <AuthnRequest>||3\.4\.1\.1 Element <NameIDPolicy>`: 『If omitted, then the identity provider MUST return the <Response> message to the default location associated with the requester for the profile of use』
- **source_clauses**: `[0, 247)` `sha256:3662ba485eda…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-IDP12.d</code> details</summary>

- **Required variants**:
  - `v-188d32eb7f` Specify an index absent from metadata; returning a Response with an error Status is permitted.
  - `v-f4c580ba77` Specify an index absent from metadata; returning to the default ACS is permitted.
- **Controls (negative controls)**:
  - This is a MAY obligation. Either permitted behavior conforms; judge only that behavior is one of the two. Returning elsewhere violates IIP-IDP12.b.
  - A case expecting only one permitted behavior would FAIL a conforming implementation choosing the other.
- **Referenced specification**: `SAML2Core#3.4.1`
- **Reference basis (SAML2Core)**; locator: `3\.4\.1 Element <AuthnRequest>||3\.4\.1\.1 Element <NameIDPolicy>`: 『If the index specified is invalid, then the identity provider MAY return an error <Response> or it MAY use the default location』
- **Notes**: Because this is MAY_CLASS, Evaluator yields only PASS or NOT_SUPPORTED. IIP-IDP12.b detects a third behavior outside the two permitted choices.
- **source_clauses**: `[0, 247)` `sha256:3662ba485eda…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

### 4.2 Identity Provider / Enhanced Client or Proxy

#### IIP-IDP13

[Source](https://kantarainitiative.github.io/SAMLprofiles/fedinterop.html#IIP-IDP13) / Section digest `sha256:48b976641b3d…` / Section length 449 / Non-normative spans 0

| Obligation | Level | Role | Testability | Condition | Core/Full | Summary |
|---|---|---|---|---|---|---|
| `IIP-IDP13.a` | MUST | idp | `AUTOMATED` | `not_token_translation_proxy`<br>(CLASSIFICATION_BASED) | full | Support the SAML V2.0 Enhanced Client or Proxy Profile Version 2.0 |
| `IIP-IDP13.e` | MUST | idp | `AUTOMATED` | `not_token_translation_proxy`<br>(CLASSIFICATION_BASED) | full | Complete the ECP SAML SOAP binding exchange and return a SAML Response or SOAP fault |
| `IIP-IDP13.f` | MUST | idp | `CONFIG` | `not_token_translation_proxy`<br>(CLASSIFICATION_BASED) | full | Establish the identity of the principal unless returning an error |
| `IIP-IDP13.g` | MUST | idp | `AUTOMATED` | `not_token_translation_proxy`<br>(CLASSIFICATION_BASED) | full | When returning a SAML Response, include an ecp:Response header with the derived response destination |
| `IIP-IDP13.h` | SHOULD | idp | `AUTOMATED` | `not_token_translation_proxy`<br>(CLASSIFICATION_BASED) | full | When a signed AuthnRequest is successfully authenticated, include an ecp:RequestAuthenticated header |
| `IIP-IDP13.i` | MUST | idp | `AUTOMATED` | `not_token_translation_proxy`<br>(CLASSIFICATION_BASED) | full | Set the required SOAP actor and mustUnderstand values on ECP response header blocks |
| `IIP-IDP13.j` | MUST | idp | `AUTOMATED` | `not_token_translation_proxy`<br>(CLASSIFICATION_BASED) | full | Integrity-protect assertions in an ECP Response at the assertion or response level |
| `IIP-IDP13.k` | SHOULD | idp | `ATTESTED` | `not_token_translation_proxy`<br>(CLASSIFICATION_BASED) | full | Integrity-protect SOAP headers in the ECP exchange |
| `IIP-IDP13.l` | MUST | idp | `CONFIG` | `not_token_translation_proxy`<br>(CLASSIFICATION_BASED) | full | Securely associate intermediate HTTP exchanges with the original ECP AuthnRequest |
| `IIP-IDP13.m` | SHOULD | idp | `ATTESTED` | `not_token_translation_proxy`<br>(CLASSIFICATION_BASED) | full | Support SOAP- or HTTP-based authentication with no or minimal presentation-oriented interface |
| `IIP-IDP13.n` | SHOULD_NOT | idp | `ATTESTED` | `not_token_translation_proxy`<br>(CLASSIFICATION_BASED) | full | Do not derive an ECP assertion-encryption key merely by probing a service provider TLS endpoint |
| `IIP-IDP13.o` | MAY | idp | `AUTOMATED` | `not_token_translation_proxy`<br>(CLASSIFICATION_BASED) | full | An ECP response may include an ecp:RelayState header |
| `IIP-IDP13.p` | MAY | idp | `AUTOMATED` | `not_token_translation_proxy`<br>(CLASSIFICATION_BASED) | full | The identity provider may interpret the delegation audience marker as a request to identify itself in an audience restriction |
| `IIP-IDP13.q` | SHOULD_NOT | idp | `ATTESTED` | `not_token_translation_proxy`<br>(CLASSIFICATION_BASED) | full | Avoid HTML or other presentation-oriented authentication in the ECP exchange |
| `IIP-IDP13.r` | MAY | idp | `AUTOMATED` | `not_token_translation_proxy`<br>(CLASSIFICATION_BASED) | full | The identity provider may use intermediate HTTP presentation exchanges before completing the SAML SOAP exchange |
| `IIP-IDP13.b` | OPTIONAL | idp | `ATTESTED` | `not_token_translation_proxy`<br>(CLASSIFICATION_BASED) | full | Full conformance to the ECP Profile is optional |
| `IIP-IDP13.c` | MUST | idp | `AUTOMATED` | `not_token_translation_proxy`<br>(CLASSIFICATION_BASED) | full | Support Bearer subject confirmation in ECP |
| `IIP-IDP13.d` | MUST | idp | `AUTOMATED` | `not_token_translation_proxy`<br>(CLASSIFICATION_BASED) | full | Support verification of channel bindings in ECP |

<details><summary><code>IIP-IDP13.a</code> details</summary>

- **Required variants**:
  - `v-c213e9b086` Using Suite metadata containing a PAOS ACS and HTTP Basic authentication, complete the basic ECP exchange from SOAP AuthnRequest through SOAP Response or fault.
  - `v-bdd537b3c3` For both success and authentication-failure paths, complete the SAML SOAP binding exchange rather than ending with an HTTP display alone.
- **Controls (negative controls)**:
  - Do not PASS an implementation that merely returns HTTP 200 or that never returns a SOAP Response or fault after HTML login.
  - IIP-IDP13.b makes full conformance OPTIONAL. Do not elevate support for every HoK, X.509, TLS Client Authentication, and client XML Signature capability into this basic capability's MUST.
  - Because the IIP source says all applicable Web Browser SSO requirements apply except IIP-SSO02 and IIP-SSO03, the G2 ECP plan also schedules IdP-applicable IIP-SSO obligations in ECP context. Preserve each obligation's level; do not collapse them into one container MUST that elevates SHOULD or MAY.
- **Referenced specification**: `SAML2ECP`
- **Exclusion**: This requirement does not apply to token translation Proxies.
- **Reference basis (SAML2ECP)**; locator: `2\.3 Profile Description||2\.3\.1 ECP Issues HTTP Request to Service Provider`: SOAP header rules common to each ECP Profile step, plus the preconditions for the subsequent basic ECP exchange.
- **Reference basis (SAML2ECP)**; locator: `2\.3\.4 ECP Routes <samlp:AuthnRequest> to Identity Provider||2\.3\.4\.1`: Basic flow in which the client delivers a SOAP AuthnRequest to the IdP and the IdP ultimately completes the SAML SOAP binding exchange.
- **Reference basis (SAML2ECP)**; locator: `2\.3\.5 Identity Provider Identifies Principal||2\.3\.5\.1`: Basic flow in which the IdP identifies the principal.
- **Reference basis (SAML2ECP)**; locator: `2\.3\.6 Identity Provider Issues <samlp:Response> to ECP||2\.3\.6\.1`: Basic flow in which the IdP returns a SAML Response or SOAP fault.
- **Notes**: The source excludes token-translation Proxies. ECP v2.0 2.2 makes channel bindings and HoK optional additions to the base profile. IIP makes basic ECP support MUST and full conformance OPTIONAL, while separately making Bearer and channel-binding verification MUST; therefore do not import 3.1.1 full-conformance-only capabilities into .a. Decompose only the IdP actor's basic exchange in 2.3.4–.6 and security rules directly governing it in 2.3.9. Do not duplicate client/SP actor rules from 2.3.1–.4 and .7–.8, optional HoK-specific rules from 2.3.4.1/.5.1/.6.3, metadata consumption from 2.3.10 (IIP-IDP16), or Bearer/channel bindings from IIP-IDP13.c/.d.
- **source_clauses**: `[0, 102)` `sha256:01ca8c2a74c0…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-IDP13.e</code> details</summary>

- **Required variants**:
  - `v-255d03fe48` Authentication succeeds → return a samlp:Response in the SOAP body
  - `v-e75f69c6ac` Authentication fails or AuthnRequest processing fails → return an error samlp:Response or SOAP fault
- **Controls (negative controls)**:
  - Detect implementations that end the exchange with only an HTML login form or HTTP error. A SOAP fault is an explicitly conformant path in the source specification, so do not require only an error Response
- **Referenced specification**: `SAML2ECP#2.3.4+2.3.6`
- **Exclusion**: This requirement does not apply to token translation Proxies.
- **Reference basis (SAML2ECP)**; locator: `2\.3\.4 ECP Routes <samlp:AuthnRequest> to Identity Provider||2\.3\.4\.1`: Even if an HTTP presentation exchange is inserted along the way, the IdP must ultimately complete the SAML SOAP binding exchange and return a SAML Response
- **Reference basis (SAML2ECP)**; locator: `2\.3\.6 Identity Provider Issues <samlp:Response> to ECP||2\.3\.6\.1`: Regardless of whether authentication and AuthnRequest processing succeed, the IdP returns a samlp:Response or SOAP fault
- **source_clauses**: `[0, 102)` `sha256:01ca8c2a74c0…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-IDP13.f</code> details</summary>

- **Required variants**:
  - `v-af665f564d` With ambient authentication excluded, correct credentials → a successful assertion corresponding to the principal
  - `v-10933ea432` Incorrect credentials → do not issue an assertion for another principal; return an error Response or SOAP fault
- **Controls (negative controls)**:
  - If existing sessions, client certificates, or integrated authentication cannot be excluded, return not_verified(ambient_auth_not_excludable). The mere absence of visible login UI is not itself a violation
  - Evaluate ForceAuthn fresh authentication under IIP-IDP06 and HTTP Basic capability under IIP-IDP14, without double-counting either observation
- **Configuration failure semantics**: `test_precondition`
- **Referenced specification**: `SAML2ECP#2.3.5`
- **Exclusion**: This requirement does not apply to token translation Proxies.
- **Reference basis (SAML2ECP)**; locator: `2\.3\.5 Identity Provider Identifies Principal||2\.3\.5\.1`: Except when returning an error to the service provider, the IdP MUST establish the principal's identity. Fresh establishment with ForceAuthn=true is evaluated separately by IIP-IDP06
- **source_clauses**: `[0, 102)` `sha256:01ca8c2a74c0…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-IDP13.g</code> details</summary>

- **Required variants**:
  - `v-24db742de6` Regardless of whether the result is success or error, for each observed samlp:Response, an ecp:Response header is present and @AssertionConsumerServiceURL matches the PAOS ACS selected in the request
  - `v-561f9b1c81` SOAP fault → no samlp:Response exists, so this is outside the runtime scope of the header-presence rule
- **Controls (negative controls)**:
  - To detect implementations that always return a fixed URL, use a control that switches the PAOS ACS in the AuthnRequest and metadata
  - On the error path, either a samlp:Response or SOAP fault is permitted. Do not make an error Response the mandatory path
- **Referenced specification**: `SAML2ECP#2.3.6`
- **Exclusion**: This requirement does not apply to token translation Proxies.
- **Reference basis (SAML2ECP)**; locator: `2\.3\.6 Identity Provider Issues <samlp:Response> to ECP||2\.3\.6\.1`: When a Response is included, the SOAP envelope contains an ecp:Response header, and AssertionConsumerServiceURL is the delivery location derived from the AuthnRequest
- **source_clauses**: `[0, 102)` `sha256:01ca8c2a74c0…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-IDP13.h</code> details</summary>

- **Required variants**:
  - `v-90f108a9da` The IdP authenticates the Suite SP's signed AuthnRequest and returns a samlp:Response → include the ecp:RequestAuthenticated header regardless of whether principal authentication succeeds or fails
- **Controls (negative controls)**:
  - Paths where AuthnRequest signature verification could not be performed, unsigned requests, and SOAP faults are outside the runtime scope. An error samlp:Response caused by principal authentication failure is in scope. ★ SHOULD_CLASS
- **Referenced specification**: `SAML2ECP#2.3.6`
- **Exclusion**: This requirement does not apply to token translation Proxies.
- **Reference basis (SAML2ECP)**; locator: `2\.3\.6 Identity Provider Issues <samlp:Response> to ECP||2\.3\.6\.1`: If the IdP successfully authenticates the AuthnRequest by digital signature, it SHOULD include the ecp:RequestAuthenticated SOAP header
- **source_clauses**: `[0, 102)` `sha256:01ca8c2a74c0…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-IDP13.i</code> details</summary>

- **Required variants**:
  - `v-7f2165101d` IdP-sent ecp:Response → S:actor=.../next and S:mustUnderstand=1
  - `v-bf84a18824` IdP-sent cb:ChannelBindings response header → S:actor=.../next and S:mustUnderstand=1
  - `v-5b518f9648` In the signed-request scenario of IIP-IDP13.h, if ecp:RequestAuthenticated is observed → S:actor=.../next. Because §2.3.6.1 makes mustUnderstand optional, do not evaluate its presence or absence
  - `v-cded90137d` If IdP-origin ecp:RelayState is observed on the MAY path of IIP-IDP13.o → S:actor=.../next and S:mustUnderstand=1
- **Controls (negative controls)**:
  - Do not require headers whose existence is MAY or SHOULD under this obligation. Passively inspect only the attributes of observed IdP-origin headers
  - The HoK header belongs to Full Conformance or the optional HoK feature, so do not include it in the required variants for basic ECP support
- **Referenced specification**: `SAML2ECP#2.3`
- **Exclusion**: This requirement does not apply to token translation Proxies.
- **Reference basis (SAML2ECP)**; locator: `2\.3 Profile Description||2\.3\.1 ECP Issues HTTP Request to Service Provider`: Unless otherwise specified, every SOAP header block described by the profile MUST contain actor=.../next and mustUnderstand=1
- **Reference basis (SAML2ECP)**; locator: `2\.3\.6 Identity Provider Issues <samlp:Response> to ECP||2\.3\.6\.1`: IdP-sent context for ecp:Response / ecp:RequestAuthenticated
- **source_clauses**: `[0, 102)` `sha256:01ca8c2a74c0…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-IDP13.j</code> details</summary>

- **Required variants**:
  - `v-be9c5e4883` Each observed ECP Response has its assertion covered by at least one of valid individual-assertion integrity protection or valid Response-level integrity protection
- **Controls (negative controls)**:
  - The source text states a disjunction at the assertion or response level. Do not split it into path-specific required variants, which would become AND in G2. If both are present, verify both
  - An ECP Response with neither form of valid protection is violated
- **Referenced specification**: `SAML2ECP#2.3.9`
- **Exclusion**: This requirement does not apply to token translation Proxies.
- **Reference basis (SAML2ECP)**; locator: `2\.3\.9 Security Considerations||2\.3\.10 Use of Metadata`: The assertion in an ECP Response MUST have integrity protection either at the individual assertion level or at the Response level
- **source_clauses**: `[0, 102)` `sha256:01ca8c2a74c0…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-IDP13.k</code> details</summary>

- **Required variants**:
  - `v-21fa966c5d` In the response exchange between the IdP and ECP client, the IdP-sent SOAP headers are protected by TLS or a message-level mechanism
- **Controls (negative controls)**:
  - The source text also permits protection other than TLS. If internal transport or message protection cannot be verified, return not_verified. ★ SHOULD_CLASS
- **Referenced specification**: `SAML2ECP#2.3.9`
- **Exclusion**: This requirement does not apply to token translation Proxies.
- **Reference basis (SAML2ECP)**; locator: `2\.3\.9 Security Considerations||2\.3\.10 Use of Metadata`: Including bearer cases, all SOAP headers SHOULD be integrity protected by TLS or an equivalent mechanism
- **source_clauses**: `[0, 102)` `sha256:01ca8c2a74c0…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-IDP13.l</code> details</summary>

- **Required variants**:
  - `v-c07bf54635` Intermediate authentication exchange within the same browser/client session → a Response corresponding to the original AuthnRequest
  - `v-032ce1c346` Mix correlation information from another client/session → reject or isolate it without crossing with the original AuthnRequest
- **Controls (negative controls)**:
  - A single exchange cannot prove correlation. A negative control that crosses two concurrent ECP exchanges is required
  - An implementation with no intermediate HTTP exchange between AuthnRequest delivery and Response return vacuously satisfies the source condition, so use satisfied_with_note. Do not make IIP-IDP13.r's MAY mandatory
  - If an intermediate HTTP exchange exists but internal correlation cannot be observed, return only not_verified(ecp_request_association_not_observable)
- **Configuration failure semantics**: `test_precondition`
- **Referenced specification**: `SAML2ECP#2.3.9`
- **Exclusion**: This requirement does not apply to token translation Proxies.
- **Reference basis (SAML2ECP)**; locator: `2\.3\.9 Security Considerations||2\.3\.10 Use of Metadata`: HTTP exchanges between AuthnRequest delivery and Response return MUST be securely associated with the original request
- **source_clauses**: `[0, 102)` `sha256:01ca8c2a74c0…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-IDP13.m</code> details</summary>

- **Required variants**:
  - `v-14b8beb01a` Complete the ECP authentication exchange without operating an HTML form, such as with HTTP Basic
- **Controls (negative controls)**:
  - The same observation as IIP-IDP14's Basic capability may be reused, but this obligation concerns the SHOULD for the UI characteristic. Its violation is a WARNING and must not be aggregated with Basic's MUST
- **Referenced specification**: `SAML2ECP#2.3.4`
- **Exclusion**: This requirement does not apply to token translation Proxies.
- **Reference basis (SAML2ECP)**; locator: `2\.3\.4 ECP Routes <samlp:AuthnRequest> to Identity Provider||2\.3\.4\.1`: HTML or presentation-oriented authentication is NOT RECOMMENDED, and the IdP and client SHOULD support mechanisms requiring no UI or only minimal SOAP/HTTP interaction
- **source_clauses**: `[0, 102)` `sha256:01ca8c2a74c0…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-IDP13.n</code> details</summary>

- **Required variants**:
  - `v-50e7d2368f` Configuration that encrypts ECP assertions → the encryption key originates from metadata, explicit trust, or equivalent, rather than from unauthenticated endpoint probing alone
- **Controls (negative controls)**:
  - A Run that does not encrypt assertions is satisfied_with_note. Do not require a capability to avoid encryption. If internal key provenance cannot be verified, return not_verified. ★ SHOULD_NOT_CLASS
- **Referenced specification**: `SAML2ECP#2.3.9`
- **Exclusion**: This requirement does not apply to token translation Proxies.
- **Reference basis (SAML2ECP)**; locator: `2\.3\.9 Security Considerations||2\.3\.10 Use of Metadata`: Unless the assertion-encryption key has separately been authenticated and confirmed for encryption, it SHOULD NOT be derived from a TLS certificate obtained by probing the SP endpoint
- **source_clauses**: `[0, 102)` `sha256:01ca8c2a74c0…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-IDP13.o</code> details</summary>

- **Required variants**:
  - `v-3f2e4a11cf` Record as informational evidence that both responses containing and not containing ecp:RelayState are conformant.
- **Controls (negative controls)**:
  - MAY_CLASS. Neither presence nor absence is a violation
- **Referenced specification**: `SAML2ECP#2.3.6`
- **Exclusion**: This requirement does not apply to token translation Proxies.
- **Reference basis (SAML2ECP)**; locator: `2\.3\.6 Identity Provider Issues <samlp:Response> to ECP||2\.3\.6\.1`: The SOAP envelope MAY contain an ecp:RelayState SOAP header.
- **source_clauses**: `[0, 102)` `sha256:01ca8c2a74c0…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-IDP13.p</code> details</summary>

- **Required variants**:
  - `v-f5813f3707` Record the identity provider's interpretation of a request containing the delegation marker as informational evidence. Both adoption and non-adoption are conformant.
- **Controls (negative controls)**:
  - MAY_CLASS. Do not treat the absence of an added Audience as a violation.
- **Referenced specification**: `SAML2ECP#2.3.6`
- **Exclusion**: This requirement does not apply to token translation Proxies.
- **Reference basis (SAML2ECP)**; locator: `2\.3\.6 Identity Provider Issues <samlp:Response> to ECP||2\.3\.6\.1`: The identity provider MAY interpret a request containing the delegation Audience as a request for an assertion that includes the identity provider itself in an audience restriction.
- **source_clauses**: `[0, 102)` `sha256:01ca8c2a74c0…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-IDP13.q</code> details</summary>

- **Required variants**:
  - `v-791ecbb12f` The basic ECP authentication path does not require an HTML login form or other presentation-oriented interface.
- **Controls (negative controls)**:
  - NOT RECOMMENDED is not a prohibition. If only an HTML path is provided, the outcome is violated → WARNING, and it must not cause the basic ECP capability to FAIL.
  - Treat the positive capability of IIP-IDP13.m (the minimal-UI mechanism) and this obligation's actual presentation path as separate outcomes.
- **Referenced specification**: `SAML2ECP#2.3.4`
- **Exclusion**: This requirement does not apply to token translation Proxies.
- **Reference basis (SAML2ECP)**; locator: `2\.3\.4 ECP Routes <samlp:AuthnRequest> to Identity Provider||2\.3\.4\.1`: The use of an HTML or presentation-oriented interface for authentication is NOT RECOMMENDED.
- **source_clauses**: `[0, 102)` `sha256:01ca8c2a74c0…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-IDP13.r</code> details</summary>

- **Required variants**:
  - `v-e99809d446` Record the presence or absence and the number of intermediate HTTP exchanges as informational evidence, treating both as conformant.
- **Controls (negative controls)**:
  - MAY_CLASS. Do not treat the absence of an intermediate exchange as a violation. Final SOAP completion is assessed separately by IIP-IDP13.e.
- **Referenced specification**: `SAML2ECP#2.3.4`
- **Exclusion**: This requirement does not apply to token translation Proxies.
- **Reference basis (SAML2ECP)**; locator: `2\.3\.4 ECP Routes <samlp:AuthnRequest> to Identity Provider||2\.3\.4\.1`: The identity provider MAY return an HTML login form or similar to the client's HTTP request and MAY perform multiple HTTP exchanges, but must ultimately complete the SOAP exchange.
- **source_clauses**: `[0, 102)` `sha256:01ca8c2a74c0…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-IDP13.b</code> details</summary>

- **Required variants**:
  - `v-44d180fb2f` Record as information whether full conformance is claimed; do not use it for the verdict.
- **Controls (negative controls)**:
  - Do not treat lack of full conformance as a violation. Do not make every 3.1.1 capability—X.509 proof, TLS Client Authentication, and client XML Signature—a MUST of basic ECP support.
  - Judge the basic ECP IdP-actor rules under .a and .e–.r, explicitly selected Bearer and channel binding under .c/.d, and HTTP Basic under IIP-IDP14, preserving each source level.
- **Referenced specification**: `SAML2ECP`
- **Reference derivation**: The reference specification is cited only to identify the obligation's subject; required_variants derive from the IIP source clause itself. Nothing changes only by reading the referenced section.
- **Exclusion**: This requirement does not apply to token translation Proxies.
- **source_clauses**: `[103, 131)` `sha256:35392bd66ad5…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-IDP13.c</code> details</summary>

- **Required variants**:
  - `v-9d8630f2bc` SubjectConfirmation/@Method equals bearer.
  - `v-c6de7d20a2` Recipient equals the Suite's PAOS ACS.
- **Referenced specification**: `SAML2ECP`
- **Exclusion**: This requirement does not apply to token translation Proxies.
- **Reference basis (SAML2Core)**; locator: `2\.4\.1\.1 Element <SubjectConfirmation>||2\.4\.1\.3 Complex Type KeyInfoConfirmationDataType`: Normative Bearer subject-confirmation Method URI and SubjectConfirmationData content, including Recipient, NotOnOrAfter, and InResponseTo.
- **Reference basis (SAML2Prof)**; locator: `4\.1\.4\.2 <Response> Usage||4\.1\.4\.3 <Response> Message Processing Rules`: Rules for IdP-generated bearer SubjectConfirmation and SubjectConfirmationData, including Method, Recipient, NotOnOrAfter, and InResponseTo.
- **source_clauses**: `[133, 195)` `sha256:01939572cebe…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-IDP13.d</code> details</summary>

- **Required variants**:
  - `v-1bd1b237bf` Matching channel bindings plus a signed AuthnRequest succeeds, and cb:ChannelBindings is returned in both the SOAP header and saml:Advice.
  - `v-6b0d67978b` Mismatch → error Response
  - `v-786b8974d7` Present only on the AuthnRequest side
  - `v-c706213ca2` Present only on the SOAP header side
  - `v-374f134660` When channel bindings are used, an unsigned AuthnRequest → error Response
- **Controls (negative controls)**:
  - In the success case, verify output to both locations, not merely success. Output to only one is a violation.
- **Referenced specification**: `SAML2ECP#2.3.6.2`
- **Exclusion**: This requirement does not apply to token translation Proxies.
- **Reference basis (SAML2ECP)**; locator: `2\.3\.6\.2 Verification of Channel Bindings||2\.3\.7 ECP Routes`: Basis for the duties to include cb:ChannelBindings in both the SOAP header and saml:Advice on a match, and to sign AuthnRequest when channel bindings are used.
- **source_clauses**: `[196, 232)` `sha256:66ae2da5ebad…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

#### IIP-IDP14

[Source](https://kantarainitiative.github.io/SAMLprofiles/fedinterop.html#IIP-IDP14) / Section digest `sha256:9ee0ba91ea64…` / Section length 158 / Non-normative spans 0

| Obligation | Level | Role | Testability | Condition | Core/Full | Summary |
|---|---|---|---|---|---|---|
| `IIP-IDP14.a` | MUST | idp | `AUTOMATED` | — | full | Support HTTP Basic Authentication to authenticate the user agent |
| `IIP-IDP14.b` | MAY | idp | `ATTESTED` | — | full | Other forms of authentication may be supported |

<details><summary><code>IIP-IDP14.a</code> details</summary>

- **Required variants**:
  - `v-6c2db65b48` HTTP Basic Authentication in the ECP round trip.
- **Controls (negative controls)**:
  - Credentials exist only in Run-scoped memory. Do not write them to the outbox payload, CaseState, or Transcript.
- **Notes**: The token-translation Proxy exclusion at the end of IIP-IDP13 belongs only to the IIP-IDP13 section and does not apply to this requirement, which is an unconditional MUST.
- **source_clauses**: `[0, 110)` `sha256:76629288ec58…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-IDP14.b</code> details</summary>

- **Required variants**:
  - `v-957d3f8015` Record the supported authentication method as informational evidence.
- **source_clauses**: `[111, 158)` `sha256:5ea3eb5da6c8…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

#### IIP-IDP15

[Source](https://kantarainitiative.github.io/SAMLprofiles/fedinterop.html#IIP-IDP15) / Section digest `sha256:d68561769b7a…` / Section length 121 / Non-normative spans 0

| Obligation | Level | Role | Testability | Condition | Core/Full | Summary |
|---|---|---|---|---|---|---|
| `IIP-IDP15.a` | MUST | idp | `AUTOMATED` | — | full | Generate and include a random key in accordance with SAML-EC section 5.3.1 |

<details><summary><code>IIP-IDP15.a</code> details</summary>

- **Required variants**:
  - `v-827c8309d7` <samlec:GeneratedKey> is present within <saml:Advice> in the assertion.
  - `v-8080b5ee2b` The value of <samlec:GeneratedKey> is base64-encoded and sufficiently long to be pseudorandom.
  - `v-fb2affcfcb` ★ The identity provider encrypts the assertion (§5.3.1: The identity provider MUST encrypt the assertion).
  - `v-38f60bc508` ★ A copy of the same element is also included in the SOAP header block from the identity provider to the client (§5.3.1: A copy of the element is also added as a SOAP header block).
  - `v-f7a5f89666` If multiple assertions are returned, inclusion in any one of them is sufficient.
- **Controls (negative controls)**:
  - This cannot be verified using an ordinary ECP plus HTTP Basic round trip. A separate case for a SAML-EC extended client is required.
  - ★ Looking only inside Advice would allow an implementation that emits no SOAP header or does not encrypt the assertion to PASS.
- **Referenced specification**: `SAML-EC#5.3.1`
- **Reference basis (SAML-EC)**; locator: `5\.3\.1\. Generated by Identity Provider||5\.3\.2\. Alternate Key Derivation Mechanisms`: The requirement to generate and include samlec:GeneratedKey is specified with reference draft draft-ietf-kitten-sasl-saml-ec-16 fixed.
- **Notes**: The reference is not the ECP Profile but the IETF kitten document SAML Enhanced Client SASL and GSS-API Mechanisms (draft-ietf-kitten-sasl-saml-ec-16). Fix the version in specs.yaml.
- **source_clauses**: `[0, 121)` `sha256:d68561769b7a…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

#### IIP-IDP16

[Source](https://kantarainitiative.github.io/SAMLprofiles/fedinterop.html#IIP-IDP16) / Section digest `sha256:0e06ebedf8f5…` / Section length 237 / Non-normative spans 0

| Obligation | Level | Role | Testability | Condition | Core/Full | Summary |
|---|---|---|---|---|---|---|
| `IIP-IDP16.a` | MUST | idp | `CONFIG` | — | full | Consume peer configuration from metadata, without additional inputs, for every element listed in SAML2ECP section 2.3.10 |

<details><summary><code>IIP-IDP16.a</code> details</summary>

- **Required variants**:
  - `v-520fe98bb0` ★ Apply all elements of Web Browser SSO §4.1.6 inherited at the beginning of §2.3.10 (apply the complete set of IIP-SSO06.a variants unchanged).
  - `v-13ac186e94` md:AssertionConsumerService Binding=PAOS
  - `v-23ad8b1ba3` md:SingleSignOnService Binding=SOAP
  - `v-c5b1dd4422` cb:supportsChannelBindings (both endpoints).
  - `v-7f7368de36` hoksso:ProtocolBinding when HoK is supported (SOAP / PAOS; conditional).
  - `v-188408c603` The holder-of-key browser binding when HoK is supported.
  - `v-7c141e27e8` ACS index and isDefault.
- **Controls (negative controls)**:
  - Verify that ecp:Response/@AssertionConsumerServiceURL matches the PAOS ACS in metadata.
  - ★ Covering only ECP-specific elements omits the subjects covered by §4.1.6, which is inherited at the beginning of §2.3.10.
  - For variants imported from IIP-SSO06.a, apply condition (b) element by element. If the implementation does not support the corresponding setting, that imported variant is not applicable and must not be reported as a violation.
  - The hoksso:ProtocolBinding and holder-of-key browser-binding variants apply only when Holder of Key is supported. If it is not supported, record satisfied_with_note for those runtime-scoped variants rather than a violation.
- **Linked obligation**: `IIP-SSO06.a` (`inherit_variants` / 8 variants / applicability: `linked_condition`) — Because the beginning of IIP-IDP16 (§2.3.10) inherits the Web Browser SSO §4.1.6 rules for ECP, the required_variants of IIP-SSO06.a must also be covered in the ECP context. Use IIP-IDP16.a's role, level, and testability, but retain the linked IIP-SSO06.a condition for those imported variants.
- **Configuration failure semantics**: `normative_capability`
- **Referenced specification**: `SAML2ECP#2.3.10`
- **Reference basis (SAML2ECP)**; locator: `2\.3\.10 Use of Metadata||2\.3\.11 Message Signing Profile`: Basis for the metadata elements enumerated in §2.3.10 (PAOS ACS / SOAP SingleSignOnService / cb:supportsChannelBindings / conditional HoK requirements / index and isDefault).
- **source_clauses**: `[0, 237)` `sha256:0e06ebedf8f5…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

### 4.3 Identity Provider / Single Logout

#### IIP-IDP17

[Source](https://kantarainitiative.github.io/SAMLprofiles/fedinterop.html#IIP-IDP17) / Section digest `sha256:b8fbb3dc6012…` / Section length 273 / Non-normative spans 0

| Obligation | Level | Role | Testability | Condition | Core/Full | Summary |
|---|---|---|---|---|---|---|
| `IIP-IDP17.a` | MUST | idp | `BROWSER` | — | full | Support the SAML V2.0 SingleLogout profile |
| `IIP-IDP17.b` | MUST | idp | `BROWSER` | — | full | Support the SAML V2.0 Asynchronous Single Logout Protocol Extension |
| `IIP-IDP17.b1` | MUST_NOT | idp | `BROWSER` | — | full | For a trusted asynchronous LogoutRequest, do not send a LogoutResponse to its initiator |
| `IIP-IDP17.b2` | MUST | idp | `BROWSER` | — | full | Provide all relevant feedback when no LogoutResponse is returned for a trusted asynchronous request |
| `IIP-IDP17.b3` | MUST | idp | `AUTOMATED` | — | full | Place an emitted aslo:Asynchronous element inside samlp:LogoutRequest/samlp:Extensions |
| `IIP-IDP17.b4` | MAY | idp | `AUTOMATED` | — | full | Metadata endpoints may advertise support for asynchronous logout requests |
| `IIP-IDP17.c` | OPTIONAL | idp | `BROWSER` | — | full | Propagation of logout requests to other session participants is optional |
| `IIP-IDP17.d` | MUST | idp | `CONFIG` | `supports_slo_idp`<br>(CAPABILITY_BASED) | full | Examine the principal identifier and SessionIndex values and determine the exact sessions to terminate |
| `IIP-IDP17.e` | MUST | idp | `BROWSER` | `supports_slo_idp`<br>(CAPABILITY_BASED) | full | For a response-bearing request, if the identity provider successfully terminates its own session, return a LogoutResponse with top-level Success |
| `IIP-IDP17.f` | MUST | idp | `BROWSER` | `supports_slo_idp`<br>(CAPABILITY_BASED) | full | Include Issuer in an IdP-issued LogoutResponse |
| `IIP-IDP17.g` | MUST | idp | `BROWSER` | `supports_slo_idp`<br>(CAPABILITY_BASED) | full | Use the IdP's unique entity identifier as LogoutResponse Issuer |
| `IIP-IDP17.h` | MUST | idp | `BROWSER` | `supports_slo_idp`<br>(CAPABILITY_BASED) | full | Omit LogoutResponse Issuer Format or set it to the SAML entity NameID format |
| `IIP-IDP17.i` | MUST | idp | `BROWSER` | `supports_slo_idp`<br>(CAPABILITY_BASED) | full | Authenticate the IdP as LogoutResponse responder and protect message integrity |
| `IIP-IDP17.j` | MUST | idp | `BROWSER` | — | full | Include Issuer in any IdP-issued LogoutRequest |
| `IIP-IDP17.k` | MUST | idp | `BROWSER` | — | full | Use the IdP's unique entity identifier as LogoutRequest Issuer |
| `IIP-IDP17.l` | MUST | idp | `BROWSER` | — | full | Omit LogoutRequest Issuer Format or set it to the SAML entity NameID format |
| `IIP-IDP17.m` | MUST | idp | `BROWSER` | — | full | Authenticate the IdP as LogoutRequest requester and protect message integrity |
| `IIP-IDP17.n` | MUST | idp | `BROWSER` | — | full | Identify the principal in an IdP-issued LogoutRequest with an identifier that strongly matches the authentication assertion |
| `IIP-IDP17.o` | MUST | idp | `CONFIG` | `supports_slo_idp`<br>(CAPABILITY_BASED) | full | For a response-bearing request, if the identity provider cannot terminate its own session, return a LogoutResponse with an error top-level status code |
| `IIP-IDP17.p` | MUST | idp | `BROWSER` | `supports_slo_idp`<br>(CAPABILITY_BASED) | full | Authenticate the sender of every received LogoutRequest before applying it to sessions |
| `IIP-IDP17.q` | SHOULD | idp | `BROWSER` | `supports_slo_idp`<br>(CAPABILITY_BASED) | full | When a current-session participant sends LogoutRequest, terminate the identity provider's own matching current session |
| `IIP-IDP17.r` | SHOULD | idp | `BROWSER` | — | full | When propagation is performed, attempt every applicable participant using any usable protocol binding despite individual failures |
| `IIP-IDP17.s` | MUST | idp | `BROWSER` | — | full | When attempted propagation does not receive successful responses from every participant, include PartialLogout as a second-level status code |
| `IIP-IDP17.t` | MUST | idp | `BROWSER` | — | full | Set NotOnOrAfter on every LogoutRequest constructed by the identity provider |
| `IIP-IDP17.u` | SHOULD | idp | `BROWSER` | — | full | Set LogoutRequest NotOnOrAfter no earlier than the latest assertion NotOnOrAfter for the targeted session |
| `IIP-IDP17.v` | MUST | idp | `AUTOMATED` | — | full | Assign unique SAML identifiers to every LogoutRequest and LogoutResponse the identity provider emits |
| `IIP-IDP17.w` | MUST | idp | `AUTOMATED` | `supports_slo_idp`<br>(CAPABILITY_BASED) | full | Set LogoutResponse InResponseTo according to the corresponding LogoutRequest |
| `IIP-IDP17.x` | MUST | idp | `BROWSER` | — | full | If Destination is present on a consumed SLO request or response, compare it with the actual receiving location and discard a mismatch |
| `IIP-IDP17.y` | MUST | idp | `BROWSER` | — | full | Verify every XML signature present on a consumed LogoutRequest or LogoutResponse |
| `IIP-IDP17.z` | MUST_NOT | idp | `BROWSER` | — | full | Do not rely on the contents of a consumed SLO request or response whose XML signature is invalid |
| `IIP-IDP17.aa` | SHOULD | idp | `BROWSER` | — | full | Treat an invalid XML signature on a consumed SLO request or response as an error |
| `IIP-IDP17.ab` | SHOULD | idp | `ATTESTED` | — | full | For a valid XML signature on a consumed SLO request or response, evaluate the identity and appropriateness of the signer |
| `IIP-IDP17.ac` | SHOULD | idp | `AUTOMATED` | — | full | Sign an emitted SLO request or response when its Consent value indicates that principal consent was obtained |
| `IIP-IDP17.ad` | MUST | idp | `BROWSER` | `supports_slo_idp`<br>(CAPABILITY_BASED) | full | When responding to a SAML-invalid LogoutRequest, use top-level Requester status |
| `IIP-IDP17.ae` | MUST | idp | `BROWSER` | `supports_slo_idp`<br>(CAPABILITY_BASED) | full | Reject a received LogoutRequest whose major request version is unsupported |
| `IIP-IDP17.af` | MUST_NOT | idp | `AUTOMATED` | `supports_slo_idp`<br>(CAPABILITY_BASED) | full | Do not emit a LogoutResponse with a version higher than its corresponding LogoutRequest |
| `IIP-IDP17.ag` | MUST_NOT | idp | `AUTOMATED` | `supports_slo_idp`<br>(CAPABILITY_BASED) | full | Do not emit a LogoutResponse with a lower major version except to report RequestVersionTooHigh |
| `IIP-IDP17.ah` | MUST | idp | `BROWSER` | `supports_slo_idp`<br>(CAPABILITY_BASED) | full | If responding to an incompatible SAML protocol version, use top-level VersionMismatch |
| `IIP-IDP17.ai` | MUST_NOT | idp | `AUTOMATED` | — | full | Do not issue a LogoutRequest whose version corresponds to a LogoutResponse version the identity provider cannot process |
| `IIP-IDP17.aj` | SHOULD | idp | `AUTOMATED` | — | full | Issue LogoutRequest using the highest request version supported by both requester and responder |
| `IIP-IDP17.ak` | SHOULD | idp | `ATTESTED` | — | full | When responder capabilities are unknown, assume support for the highest request version supported by the identity provider |
| `IIP-IDP17.al` | MUST | idp | `BROWSER` | — | full | If accepting a SLO XML signature with a non-standard transform, ensure that no message content is excluded from the signature |
| `IIP-IDP17.am` | MUST | idp | `AUTOMATED` | — | full | Make every emitted LogoutRequest and LogoutResponse conform to the SAML protocol schema |
| `IIP-IDP17.an` | MUST | idp | `AUTOMATED` | — | full | Use a permitted top-level StatusCode in every emitted LogoutResponse |

<details><summary><code>IIP-IDP17.a</code> details</summary>

- **Required variants**:
  - `v-a54be75218` The SP sends a valid LogoutRequest without aslo:Asynchronous → inspect the identifier and SessionIndex, then return a LogoutResponse to the original SP. The SHOULD to terminate the session and status branching are assessed by IIP-IDP17.e / .o / .q.
- **Controls (negative controls)**:
  - ★ §4.4.2 only states that the identity provider can initiate the profile from step 2; it does not make IdP-initiated SLO capability a MUST.
  - ★ Propagation to other session participants is explicitly OPTIONAL in IIP-IDP17.c. Do not turn the propagation SHOULD and steps 3 and 4 of §4.4.3.1/.2 back into unconditional obligations.
  - ★ The basic flow is receipt of an SP-initiated request, session determination, and a response to the original requester. Request-binding and response-binding capabilities are assessed separately by IIP-IDP18.
- **Referenced specification**: `SAML2Prof#4.4 + SAML2Core#3.7`
- **Reference basis (SAML2Prof)**; locator: `4\.4 Single Logout Profile||4\.5 Name Identifier Management Profile`: The basic flow in which the identity provider, acting as the session authority, processes SP-initiated SLO and responds to the original requester.
- **Reference basis (SAML2Errata)**; locator: `E38: Clarification Regarding Index on <LogoutRequest>||E39: `: Clarify the SessionIndex rule in §4.4.4.1. The identity provider processes the SessionIndex of the received participant request.
- **Reference basis (SAML2Core)**; locator: `3\.7 Single Logout Protocol||3\.8 Name Identifier Mapping Protocol`: The session-authority rules and underlying message rules incorporated by “processes the request as defined in [SAMLCore]” in §4.4.3.2. Decompose them under CP2b-Core.
- **Notes**: Under CP2b, cross-checked all of §4.4, Errata E38, Core §3.7, and the underlying request and response rules by actor. IdP-initiated initiation is permission, and propagation to other participants is explicitly OPTIONAL in the IIP, so neither is included as a mandatory identity-provider capability. The Core common data types, producer-side XML Signature profile, and extension namespaces are not double-counted because the existing obligations IIP-SSO01.dz / .ea / .eb / .ec / .ed / .ee / .ef / .eg / .eh / .ei / .er / .eu / .ev / .ew / .ex / .ah, which cover all SAML messages, also passively inspect SLO messages. The top-level StatusCode of an IdP-issued LogoutResponse is assessed by IIP-IDP17.an. Only rules whose results vary by SLO actor or direction are decomposed into .d and later.
- **source_clauses**: `[0, 107)` `sha256:0649b5f4937d…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-IDP17.b</code> details</summary>

- **Required variants**:
  - `v-59c7950255` For a valid LogoutRequest with aslo:Asynchronous, perform the same session determination and request validation as for a synchronous LogoutRequest with the same identifier / SessionIndex.
  - `v-10b47d4843` For an async request with a valid signature and an authenticated sender but a mismatched Destination or an unknown SessionIndex, return no response and do not incorrectly apply it to the session; follow the corresponding Core request processing.
- **Controls (negative controls)**:
  - ★ §2.2 requires processing according to Core §3.7.3.2, but termination of the Core session itself is SHOULD (IIP-IDP17.q). Do not make “the session always terminates” the expectation for this MUST.
  - Distinguish request-initiator conformance (the capability to include the async element) from session-authority conformance (inbound processing). Because IIP-IDP17.c makes LogoutRequest propagation OPTIONAL, do not additionally require the IdP to have the capability to issue async requests.
  - For a message whose XML signature verification fails, do not suppress the response based on the extension. Apply the Core signature-processing paths of IIP-IDP17.y / .z / .aa; neither no response nor an error response is violated for this obligation.
  - Response prohibition is separated under IIP-IDP17.b1, feedback under .b2, and placement of an async request actually issued by the target under .b3.
- **Referenced specification**: `SAML2ASLO`
- **Reference basis (SAML2ASLO)**; locator: `2 Single Logout Protocol Extension for Asynchronous Reques||3 Conformance`: The rule that the session authority processes an async LogoutRequest according to Core and does not return LogoutResponse to the request initiator, and the rule for user-facing feedback.
- **source_clauses**: `[109, 184)` `sha256:b6bba3e952da…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-IDP17.b1</code> details</summary>

- **Required variants**:
  - `v-0803106d2a` For a LogoutRequest with a valid signature, an authenticated sender, and a trusted aslo:Asynchronous, do not return samlp:LogoutResponse through either the front channel or back channel.
- **Controls (negative controls)**:
  - Provide a control in which a synchronous LogoutResponse is returned for a synchronous LogoutRequest without an extension, according to the conditions of IIP-IDP17.a / .e / .o.
  - For a message with an invalid signature, do not rely on the contents of aslo:Asynchronous. Prioritize the Core paths of IIP-IDP17.z / .aa; returning an error LogoutResponse is not a violation of this MUST_NOT.
  - HTTP user-facing feedback is permitted separately from a LogoutResponse and is in fact a MUST under IIP-IDP17.b2. Do not prohibit the HTTP response itself.
- **Referenced specification**: `SAML2ASLO#2.2`
- **Reference basis (SAML2ASLO)**; locator: `2\.2 Asynchronous Logout Request Processing||2\.3 Metadata Considerations`: The session authority processes an async request according to Core but MUST NOT send samlp:LogoutResponse to the request initiator.
- **source_clauses**: `[109, 184)` `sha256:b6bba3e952da…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-IDP17.b2</code> details</summary>

- **Required variants**:
  - `v-2359a2c376` For a successful front-channel async LogoutRequest with a valid signature and an authenticated sender, the user-facing HTTP response indicates logout success.
  - `v-f39de0daee` For a failed front-channel async LogoutRequest with a valid signature and an authenticated sender, the user-facing HTTP response indicates failure.
- **Controls (negative controls)**:
  - Pair success and failure paths to detect an implementation that returns only a fixed “success” page.
  - If the failure path cannot be safely induced, use not_verified(session_termination_failure_not_inducible) and do not mark the target as violating. Reuse the same induction mechanism as IIP-IDP17.o.
  - For a message with an invalid signature, apply IIP-IDP17.z / .aa without relying on the extension; therefore this feedback obligation is outside the runtime scope.
  - Do not require a web page when there is no user agent on the back channel. Determine the relevant feedback channel from the binding / application.
- **Configuration failure semantics**: `test_precondition`
- **Referenced specification**: `SAML2ASLO#2.2`
- **Reference basis (SAML2ASLO)**; locator: `2\.2 Asynchronous Logout Request Processing||2\.3 Metadata Considerations`: Because no LogoutResponse is returned, the session authority MUST provide all relevant feedback; for the front channel, a web page indicating logout success or failure is exemplified.
- **source_clauses**: `[109, 184)` `sha256:b6bba3e952da…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-IDP17.b3</code> details</summary>

- **Required variants**:
  - `v-dfa8d4fb4d` If the target IdP actually issues an async LogoutRequest, aslo:Asynchronous is present within samlp:Extensions directly under that LogoutRequest.
- **Controls (negative controls)**:
  - The capability to issue / propagate LogoutRequest is OPTIONAL under IIP-IDP17.c. If it is not observed, the outcome is satisfied_with_note.
  - Use outside LogoutRequest or Extensions is undefined by the specification. This obligation assesses only the placement of the target-emitted element and does not add an independent rejection obligation for the receiver.
- **Referenced specification**: `SAML2ASLO#2.1`
- **Reference basis (SAML2ASLO)**; locator: `2\.1 Element <aslo:Asynchronous>||2\.2 Asynchronous Logout Request Processing`: The aslo:Asynchronous element MUST appear within samlp:Extensions of samlp:LogoutRequest; its use in other contexts is undefined.
- **source_clauses**: `[109, 184)` `sha256:b6bba3e952da…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-IDP17.b4</code> details</summary>

- **Required variants**:
  - `v-d96c87266e` Record the presence and value of the SLO endpoint's aslo:supportsAsynchronous attribute as information.
  - `v-22d4e2b580` Record as information the choice to include or omit the extension in a LogoutRequest sent to an endpoint with supportsAsynchronous=true.
- **Controls (negative controls)**:
  - MAY_CLASS. Do not treat the absence of a metadata declaration or sending a synchronous request to a declared endpoint as a violation.
- **Referenced specification**: `SAML2ASLO#2.3`
- **Reference basis (SAML2ASLO)**; locator: `2\.3 Metadata Considerations||3 Conformance`: Metadata MAY be used to indicate extension support per endpoint, and a request sent to an endpoint with supportsAsynchronous=true MAY include the extension.
- **source_clauses**: `[109, 184)` `sha256:b6bba3e952da…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-IDP17.c</code> details</summary>

- **Required variants**:
  - `v-fc8cf50c5e` Register the secondary_peer as a second SP and record, as information, whether propagation to the downstream session participant occurs.
  - `v-182faf2e20` In a configuration where the target IdP uses an upstream session authority as an authentication proxy, record, as information, whether propagation to the upstream authority occurs.
  - `v-4afb59e6ff` If propagation is implemented, the LogoutRequest issued by the target IdP satisfies the message rules of IIP-IDP17.j through .n.
- **Controls (negative controls)**:
  - ★ An IdP that does not propagate is NOT_SUPPORTED and must not be marked FAIL for IIP-IDP17.a.
  - ★ The “IdP SHOULD then propagate” language in SAML2Prof §4.4.3.1 and steps 3 / 4 of §4.4.3.2 are treated in this catalog as optional functionality because of the more specific OPTIONAL in IIP-IDP17.c.
  - ★ Although the upstream actor in Core's strict actor terminology is the session authority, Profile §4.4.3.3 places sending to both the authority and participants under the same “propagate the logout” procedure. Narrowing the IIP's “propagation ... to other session participants” to downstream participants only and restoring upstream sending as SHOULD would circumvent the intended optionality of the IIP's propagation capability; therefore, both paths are included in this OPTIONAL.
  - ★ IdP-initiated SLO is also a permission under the Profile; failure to implement this OPTIONAL feature must not be treated as a violation.
- **Referenced specification**: `SAML2Prof#4.4.3.2-4.4.3.3`
- **Reference basis (SAML2Prof)**; locator: `4\.4\.3\.2 Identity Provider Determines Session Participants||4\.4\.3\.4 Session Participant/Authority Issues`: §4.4.3.3 defines a single propagation procedure in which the IdP sends a LogoutRequest to the session authority or a participant under “To propagate the logout.” IIP-IDP17.c overrides support for this propagation to OPTIONAL.
- **Reference basis (SAML2Core)**; locator: `3\.7\.3\.2 Session Authority Rules||3\.8 Name Identifier Mapping Protocol`: The first bullet of the session authority rules concerns the proxy's upstream authority, while the second concerns a LogoutRequest to another session participant. Profile §4.4.3.3 calls both propagation.
- **source_clauses**: `[186, 273)` `sha256:7c03e19402eb…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-IDP17.d</code> details</summary>

- **Required variants**:
  - `v-639ec91454` Two sessions with SessionIndex S1 and S2 exist for the same principal → a request containing only S1 terminates only S1 and preserves S2.
  - `v-05acdb6272` S1 and S2 exist for the same principal → a request containing both indices terminates both.
  - `v-a46bebbe18` A combination of a different principal's identifier and S1 → do not terminate an unrelated session.
- **Controls (negative controls)**:
  - ★ An implementation that merely accepts the LogoutRequest and terminates all sessions without examining the identifier or index can pass. Pair multiple sessions for the same principal with a negative control for a different principal.
  - ★ Do not assess propagation to other SPs. Determining the set of sessions to terminate and propagating externally are separate acts; the latter is OPTIONAL under .c.
- **Configuration failure semantics**: `test_precondition`
- **Referenced specification**: `SAML2Prof#4.4.3.2`
- **Reference basis (SAML2Prof)**; locator: `4\.4\.3\.2 Identity Provider Determines Session Participants||4\.4\.3\.3 <LogoutRequest> Issued by Identity Provider`: Upon receiving a valid LogoutRequest, the IdP MUST examine the identifier and SessionIndex elements and determine the set of sessions to terminate.
- **source_clauses**: `[0, 107)` `sha256:0649b5f4937d…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-IDP17.e</code> details</summary>

- **Required variants**:
  - `v-8648b6c29b` For a request that does not contain aslo:Asynchronous, successful termination of the IdP's own session → the originating SP receives a LogoutResponse with top-level Success.
- **Controls (negative controls)**:
  - Do not require a SAML response for an invalidly signed or syntactically invalid request. Do not add an independent requirement to respond to an unauthenticated attacker.
  - This MUST is conditional on successful termination. The IdP's attempt to terminate the session itself is only a Core SHOULD (IIP-IDP17.q), and must not be elevated to MUST here.
  - If the IdP cannot terminate its own session, the error top-level status is governed by IIP-IDP17.o. The success or failure of propagation to recipients is handled not by the top-level status but by PartialLogout under IIP-IDP17.s.
  - A request containing the Asynchronous SLO extension does not require a response under IIP-IDP17.b1 and is therefore outside this obligation's execution scope.
  - Do not require PartialLogout or similar solely because propagation is unsupported. IIP-IDP17.c makes propagation OPTIONAL.
- **Referenced specification**: `SAML2Prof#4.4.3.5 + SAML2Core#3.7.3.2`
- **Reference basis (SAML2Prof)**; locator: `4\.4\.3\.5 Identity Provider Issues <LogoutResponse> to Session Participant||4\.4\.4 Use of Single Logout Protocol`: The IdP MUST respond to the original request with a LogoutResponse containing an appropriate status code.
- **Reference basis (SAML2Core)**; locator: `3\.7\.3\.2 Session Authority Rules||3\.8 Name Identifier Mapping Protocol`: If the session authority successfully terminates the session concerning itself, it MUST return top-level Success; if it cannot, it MUST return an error status.
- **source_clauses**: `[0, 107)` `sha256:0649b5f4937d…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-IDP17.f</code> details</summary>

- **Required variants**:
  - `v-3c7de2bcfe` The LogoutResponse returned by the IdP to the originating SP contains exactly one Issuer.
- **Referenced specification**: `SAML2Prof#4.4.4.2`
- **Reference basis (SAML2Prof)**; locator: `4\.4\.4\.2 <LogoutResponse> Usage||4\.4\.5 Use of Metadata`: The Issuer element is present in the LogoutResponse
- **source_clauses**: `[0, 107)` `sha256:0649b5f4937d…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-IDP17.g</code> details</summary>

- **Required variants**:
  - `v-f06162a8d7` The Issuer value matches the target IdP's metadata entityID.
- **Referenced specification**: `SAML2Prof#4.4.4.2`
- **Reference basis (SAML2Prof)**; locator: `4\.4\.4\.2 <LogoutResponse> Usage||4\.4\.5 Use of Metadata`: The Issuer MUST contain the responding entity's unique identifier
- **source_clauses**: `[0, 107)` `sha256:0649b5f4937d…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-IDP17.h</code> details</summary>

- **Required variants**:
  - `v-85bb052911` For every target-emitted LogoutResponse, Issuer/@Format is either omitted or set to urn:oasis:names:tc:SAML:2.0:nameid-format:entity
- **Referenced specification**: `SAML2Prof#4.4.4.2`
- **Reference basis (SAML2Prof)**; locator: `4\.4\.4\.2 <LogoutResponse> Usage||4\.4\.5 Use of Metadata`: Issuer/@Format must be omitted or be urn:oasis:names:tc:SAML:2.0:nameid-format:entity
- **source_clauses**: `[0, 107)` `sha256:0649b5f4937d…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-IDP17.i</code> details</summary>

- **Required variants**:
  - `v-9b1a2ecd2e` The IdP-issued LogoutResponse contains a signature or binding-specific authentication and integrity mechanism, and verification succeeds.
- **Controls (negative controls)**:
  - ★ The §4.4.3.4 rule that a POST/Redirect response MUST be signed, and the TLS RECOMMENDED rule, are step 4 rules for the session participant responding to the IdP's request. Do not extend them laterally to the step 5 response that the IdP returns to the originating SP.
  - If the binding specification separately requires a signature, inspect it on that basis; this obligation also permits binding-specific mechanisms other than signatures.
  - Tampering that breaks the authentication and integrity evidence of the same response is self-validation of a Suite fixture and must not be made a required variant for the target.
- **Referenced specification**: `SAML2Prof#4.4.4.2`
- **Reference basis (SAML2Prof)**; locator: `4\.4\.4\.2 <LogoutResponse> Usage||4\.4\.5 Use of Metadata`: The responder MUST authenticate itself to the requester by a signature or a binding-specific mechanism and guarantee message integrity
- **source_clauses**: `[0, 107)` `sha256:0649b5f4937d…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-IDP17.j</code> details</summary>

- **Required variants**:
  - `v-fe3f8b9022` An IdP-issued LogoutRequest contains exactly one Issuer.
- **Controls (negative controls)**:
  - The IdP-initiated / propagation capability itself is OPTIONAL. If no LogoutRequest issued by the target IdP is observed, use satisfied_with_note; do not use IIP-IDP18 as the basis for its issuance capability.
- **Referenced specification**: `SAML2Prof#4.4.4.1`
- **Reference basis (SAML2Prof)**; locator: `4\.4\.4\.1 <LogoutRequest> Usage||4\.4\.4\.2 <LogoutResponse> Usage`: The LogoutRequest Issuer element MUST be present. This applies to messages in which the IdP actually issues a request through any initiation or propagation path.
- **source_clauses**: `[0, 107)` `sha256:0649b5f4937d…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-IDP17.k</code> details</summary>

- **Required variants**:
  - `v-ccb3583da7` The Issuer of the target-emitted LogoutRequest matches the target IdP's metadata entityID.
- **Controls (negative controls)**:
  - If no LogoutRequest issued by the target IdP is observed, use satisfied_with_note.
- **Referenced specification**: `SAML2Prof#4.4.4.1`
- **Reference basis (SAML2Prof)**; locator: `4\.4\.4\.1 <LogoutRequest> Usage||4\.4\.4\.2 <LogoutResponse> Usage`: Issuer MUST contain the unique identifier of the requesting entity
- **source_clauses**: `[0, 107)` `sha256:0649b5f4937d…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-IDP17.l</code> details</summary>

- **Required variants**:
  - `v-ea81bb8143` For every target-emitted LogoutRequest, Issuer/@Format is omitted or is urn:oasis:names:tc:SAML:2.0:nameid-format:entity
- **Controls (negative controls)**:
  - If no LogoutRequest issued by the target IdP is observed, use satisfied_with_note.
- **Referenced specification**: `SAML2Prof#4.4.4.1`
- **Reference basis (SAML2Prof)**; locator: `4\.4\.4\.1 <LogoutRequest> Usage||4\.4\.4\.2 <LogoutResponse> Usage`: Issuer/@Format must be omitted or be urn:oasis:names:tc:SAML:2.0:nameid-format:entity
- **source_clauses**: `[0, 107)` `sha256:0649b5f4937d…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-IDP17.m</code> details</summary>

- **Required variants**:
  - `v-ab2e73f722` An IdP-issued LogoutRequest contains a signature or binding-specific authentication and integrity mechanism, and verification succeeds.
- **Controls (negative controls)**:
  - Tampering that breaks the authentication and integrity evidence of the same request is self-validation of a Suite fixture and must not be made a required variant for the target.
  - If no LogoutRequest issued by the target IdP is observed, use satisfied_with_note.
- **Referenced specification**: `SAML2Prof#4.4.4.1`
- **Reference basis (SAML2Prof)**; locator: `4\.4\.4\.1 <LogoutRequest> Usage||4\.4\.4\.2 <LogoutResponse> Usage`: The requester MUST authenticate itself to the responder and guarantee message integrity by means of a signature or a binding-specific mechanism
- **source_clauses**: `[0, 107)` `sha256:0649b5f4937d…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-IDP17.n</code> details</summary>

- **Required variants**:
  - `v-767d715196` The NameID, BaseID, or EncryptedID in the IdP-issued LogoutRequest strongly matches the identifier in the assertion issued by the target IdP when the session was established.
- **Controls (negative controls)**:
  - Compare using the strong-match rules in Core 3.3.4, including NameQualifier, SPNameQualifier, Format, and so on, rather than string equality alone
  - Use a mutant target that sends another principal's identifier as the negative control; do not require the conforming target to issue an incorrect message
  - If no LogoutRequest issued by the target IdP is observed, use satisfied_with_note.
- **Referenced specification**: `SAML2Prof#4.4.4.1`
- **Reference basis (SAML2Prof)**; locator: `4\.4\.4\.1 <LogoutRequest> Usage||4\.4\.4\.2 <LogoutResponse> Usage`: The principal MUST be identified, with respect to the session being terminated, by an identifier that strongly matches the identifier in the authentication assertion issued by the requester, in accordance with Core 3.3.4.
- **source_clauses**: `[0, 107)` `sha256:0649b5f4937d…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-IDP17.o</code> details</summary>

- **Required variants**:
  - `v-78a59f51f4` For a request that does not contain aslo:Asynchronous, deliberately cause termination of the IdP's own session to fail in the test configuration → the originating SP receives a LogoutResponse whose top-level status is not Success.
- **Controls (negative controls)**:
  - The source text does not specify a particular error code. Do not fix Requester, Responder, or similar values by Suite-specific rule.
  - If session-termination failure cannot be safely induced, use not_verified(session_termination_failure_not_inducible); do not treat it as a violation by the target.
  - A request containing the Asynchronous SLO extension does not require a response under IIP-IDP17.b1 and is therefore outside this obligation's execution scope.
  - Failure to propagate to other participants is outside this obligation and is handled by PartialLogout under IIP-IDP17.s.
- **Configuration failure semantics**: `test_precondition`
- **Referenced specification**: `SAML2Prof#4.4.3.5 + SAML2Core#3.7.3.2`
- **Reference basis (SAML2Prof)**; locator: `4\.4\.3\.5 Identity Provider Issues <LogoutResponse> to Session Participant||4\.4\.4 Use of Single Logout Protocol`: The IdP MUST respond to the original requester with a LogoutResponse containing an appropriate status code.
- **Reference basis (SAML2Core)**; locator: `3\.7\.3\.2 Session Authority Rules||3\.8 Name Identifier Mapping Protocol`: If the session authority cannot terminate the session concerning itself, it MUST respond with a LogoutResponse whose top-level status code indicates an error.
- **source_clauses**: `[0, 107)` `sha256:0649b5f4937d…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-IDP17.p</code> details</summary>

- **Required variants**:
  - `v-8c50de7605` A LogoutRequest correctly authenticated using the trusted key of a registered SP → proceed to session processing.
  - `v-dd2f8ddd5d` A LogoutRequest whose signature value or signed content has been tampered with → do not terminate the session.
  - `v-1a7a77cf25` A LogoutRequest cryptographically signed correctly with another entity's key → do not terminate the session as a request from the target SP.
- **Controls (negative controls)**:
  - Check not only cryptographic validity but also the correspondence between the sender and the session participant. Pair this with a valid request to catch implementations that always reject.
  - Whether to respond to an invalid request and whether to refrain from applying it to sessions are separate matters. Do not require no response.
- **Referenced specification**: `SAML2Prof#4.4.3.2 + SAML2Core#3.7.3.2`
- **Reference basis (SAML2Prof)**; locator: `4\.4\.3\.2 Identity Provider Determines Session Participants||4\.4\.3\.3 <LogoutRequest> Issued by Identity Provider`: The IdP processes a valid LogoutRequest in accordance with SAMLCore.
- **Reference basis (SAML2Core)**; locator: `3\.7\.3\.2 Session Authority Rules||3\.8 Name Identifier Mapping Protocol`: The session authority MUST authenticate the sender of the received LogoutRequest.
- **source_clauses**: `[0, 107)` `sha256:0649b5f4937d…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-IDP17.q</code> details</summary>

- **Required variants**:
  - `v-ff7ca75195` For an authenticated LogoutRequest for the same principal specifying SessionIndex S1 / S2 → S1, terminate the IdP-side S1 session and preserve S2.
  - `v-6d8f4c417f` For an authenticated LogoutRequest for the same principal specifying S1 / S2 without a SessionIndex, terminate both IdP-side sessions.
- **Controls (negative controls)**:
  - ★ SHOULD_CLASS. An implementation that does not terminate the session is WARNING, and must not be elevated to a MUST violation of IIP-IDP17.a or .e.
  - Propagation to other participants is OPTIONAL under IIP-IDP17.c. This obligation concerns only the IdP's own session.
  - To detect implementations that unconditionally terminate all sessions, use a different principal and an unspecified SessionIndex as the control.
- **Referenced specification**: `SAML2Core#3.7.3.2`
- **Reference basis (SAML2Core)**; locator: `3\.7\.3\.2 Session Authority Rules||3\.8 Name Identifier Mapping Protocol`: If the sender is a participant in the current session, the session authority SHOULD terminate its own current session according to the specified identifier and SessionIndex.
- **source_clauses**: `[0, 107)` `sha256:0649b5f4937d…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-IDP17.r</code> details</summary>

- **Required variants**:
  - `v-2cdca3181d` Make the first of three participants time out or return an error → an IdP that implements propagation also attempts a LogoutRequest to the remaining participants.
- **Controls (negative controls)**:
  - IIP-IDP17.c makes the propagation capability itself OPTIONAL. An IdP that does not implement propagation is satisfied_with_note, not WARNING.
  - With only one participant, “continue after failure” cannot be verified; therefore, use a control with an initial failure followed by subsequent reachability.
  - If propagation to an upstream session authority is also implemented and observed, apply the same passive rule.
- **Referenced specification**: `SAML2Core#3.7.3.2`
- **Reference basis (SAML2Core)**; locator: `3\.7\.3\.2 Session Authority Rules||3\.8 Name Identifier Mapping Protocol`: The session authority SHOULD attempt to contact each session participant using an applicable and usable binding, even if an individual attempt fails or cannot be performed.
- **source_clauses**: `[0, 107)` `sha256:0649b5f4937d…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-IDP17.s</code> details</summary>

- **Required variants**:
  - `v-9b090d424a` For a request without aslo:Asynchronous, make at least one participant time out or return a non-success response in an IdP that implements propagation → the second-level StatusCode of the LogoutResponse to the original requester is PartialLogout.
- **Controls (negative controls)**:
  - IIP-IDP17.c makes the propagation capability itself OPTIONAL. Do not require PartialLogout from an IdP that did not attempt propagation.
  - A request containing the Asynchronous SLO extension does not receive a LogoutResponse under IIP-IDP17.b1, so it is outside this obligation's execution scope.
  - Do not require PartialLogout in a control where all participants succeeded.
  - The top-level status represents the IdP's own local operation. Do not require a top-level error solely because propagation failed.
- **Referenced specification**: `SAML2Core#3.7.3.2`
- **Reference basis (SAML2Core)**; locator: `3\.7\.3\.2 Session Authority Rules||3\.8 Name Identifier Mapping Protocol`: If not all session participants successfully respond to the LogoutRequest, or if not all participants can be contacted, the LogoutResponse MUST include PartialLogout as a second-level status code.
- **source_clauses**: `[0, 107)` `sha256:0649b5f4937d…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-IDP17.t</code> details</summary>

- **Required variants**:
  - `v-446591d622` Every LogoutRequest actually issued by the target IdP through IdP-initiated SLO or propagation has @NotOnOrAfter with a UTC time value.
- **Controls (negative controls)**:
  - IdP-initiated SLO and the propagation capability itself are OPTIONAL. If no IdP-issued LogoutRequest is observed, use satisfied_with_note.
  - Determine whether NotOnOrAfter is present; do not add Suite-specific lower or upper bounds.
- **Referenced specification**: `SAML2Core#3.7.3.2`
- **Reference basis (SAML2Core)**; locator: `3\.7\.3\.2 Session Authority Rules||3\.8 Name Identifier Mapping Protocol`: When constructing a LogoutRequest, the session authority MUST set NotOnOrAfter to indicate the expiration time.
- **source_clauses**: `[0, 107)` `sha256:0649b5f4937d…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-IDP17.u</code> details</summary>

- **Required variants**:
  - `v-779dd7a47a` For an IdP-issued LogoutRequest, @NotOnOrAfter is greater than or equal to the maximum NotOnOrAfter specified in the assertions most recently issued for the targeted session.
- **Controls (negative controls)**:
  - ★ SHOULD_CLASS. A short value is WARNING, not FAIL.
  - If no IdP-issued LogoutRequest is observed, or if the latest assertion has no comparable NotOnOrAfter, use satisfied_with_note.
  - The source text specifies no absolute upper bound into the future. Do not warn based on Samlier-specific days or seconds.
- **Referenced specification**: `SAML2Core#3.7.3.2`
- **Reference basis (SAML2Core)**; locator: `3\.7\.3\.2 Session Authority Rules||3\.8 Name Identifier Mapping Protocol`: LogoutRequest/@NotOnOrAfter SHOULD be set to a time no earlier than the NotOnOrAfter of the most recently issued assertion for the targeted session indicated by SessionIndex.
- **source_clauses**: `[0, 107)` `sha256:0649b5f4937d…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-IDP17.v</code> details</summary>

- **Required variants**:
  - `v-9af1d44ea7` Do not reuse the same @ID for different message objects across sequential or concurrent SLO exchanges and between requests / responses.
- **Controls (negative controls)**:
  - IdP-issued LogoutRequests are an optional capability. Do not require the unobserved direction. Being sequential by itself is not a violation.
  - The xs:ID lexical rules for @ID are evaluated as schema conformance under IIP-IDP17.am. Do not count the same defect again as a uniqueness violation.
- **Referenced specification**: `SAML2Core#3.2.1-3.2.2,#1.3.4`
- **Reference basis (SAML2Core)**; locator: `3\.2\.1 Complex Type RequestAbstractType||3\.2\.2 Complex Type StatusResponseType`: RequestAbstractType/@ID inherited by LogoutRequest MUST follow the identifier uniqueness requirements of §1.3.4.
- **Reference basis (SAML2Core)**; locator: `3\.2\.2 Complex Type StatusResponseType||3\.2\.2\.1 Element <Status>`: StatusResponseType/@ID inherited by LogoutResponse must also follow the identifier uniqueness requirements of §1.3.4.
- **Reference basis (SAML2Core)**; locator: `1\.3\.4 ID and ID Reference Values||2 SAML Assertions`: The party assigning identifiers MUST ensure that the probability of assigning the same value to another data object is negligible.
- **source_clauses**: `[0, 107)` `sha256:0649b5f4937d…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-IDP17.w</code> details</summary>

- **Required variants**:
  - `v-cfb187068c` A LogoutResponse returned for a valid LogoutRequest has @InResponseTo present and matching request/@ID.
  - `v-e0e2be4082` If the request is malformed, its @ID cannot be identified, and a SAML response is returned → do not include @InResponseTo.
- **Controls (negative controls)**:
  - Do not evaluate attributes of a LogoutResponse received for an IdP-initiated request as generation obligations of the target IdP.
- **Referenced specification**: `SAML2Core#3.2.2`
- **Reference basis (SAML2Core)**; locator: `3\.2\.2 Complex Type StatusResponseType||3\.2\.2\.1 Element <Status>`: If the response is for a request, InResponseTo MUST be present and MUST match the request ID; if the request ID cannot be identified, InResponseTo MUST NOT be present.
- **source_clauses**: `[0, 107)` `sha256:0649b5f4937d…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-IDP17.x</code> details</summary>

- **Required variants**:
  - `v-54315f1996` A LogoutRequest with an incorrect Destination → do not apply it to the IdP session.
  - `v-642240f979` For an optional path in which the IdP issued a request, a LogoutResponse with an incorrect Destination → do not process it as successful.
  - `v-a7348f506b` Control for each observed direction: a correct Destination → proceed with normal processing.
- **Controls (negative controls)**:
  - Receiving a LogoutRequest is a mandatory basic flow. Receiving a LogoutResponse is a passive rule only when the IdP has issued a response-bearing request; it does not add a requirement to implement request issuance.
  - Do not require acceptance of a message with Destination omitted under this obligation. Core's Optional does not impose an acceptance obligation; for signed Redirect / POST, the Binding requires Destination.
- **Referenced specification**: `SAML2Core#3.2.1-3.2.2 + SAML2Bind#3.4.5.2,#3.5.5.2`
- **Reference basis (SAML2Core)**; locator: `3\.2\.1 Complex Type RequestAbstractType||3\.2\.2 Complex Type StatusResponseType`: If the request contains Destination, the recipient MUST check it against the receiving location and MUST discard the request if they do not match.
- **Reference basis (SAML2Core)**; locator: `3\.2\.2 Complex Type StatusResponseType||3\.2\.2\.1 Element <Status>`: The same MUST-check / discard rule applies to the response's Destination.
- **Reference basis (SAML2Bind)**; locator: `3\.4\.5\.2 Security Considerations||3\.4\.6 Error Reporting`: A signed HTTP-Redirect message MUST contain Destination, and the recipient MUST verify that it matches the receiving location.
- **Reference basis (SAML2Bind)**; locator: `3\.5\.5\.2 Security Considerations||3\.5\.6 Error Reporting`: The same Destination MUST / matching MUST requirements apply to a signed HTTP-POST message.
- **source_clauses**: `[0, 107)` `sha256:0649b5f4937d…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-IDP17.y</code> details</summary>

- **Required variants**:
  - `v-9cef2dba4e` A LogoutRequest with a tampered signature value or signed content → do not apply it to the session.
  - `v-c22c05fc4b` On a path where the IdP issued a response-bearing request, a LogoutResponse with a tampered signature value or signed content → do not consume it as successful.
  - `v-5dfddfde7d` Control for each observed direction: a valid XML signature from a trusted peer → proceed with normal processing.
- **Controls (negative controls)**:
  - HTTP-Redirect query signatures are governed by SAML2Bind. If the optional LogoutResponse-receiving direction is not observed, use satisfied_with_note.
- **Referenced specification**: `SAML2Core#3.2.1-3.2.2`
- **Reference basis (SAML2Core)**; locator: `3\.2\.1 Complex Type RequestAbstractType||3\.2\.2 Complex Type StatusResponseType`: When an XML signature is used on a request, the responder MUST verify that the signature is valid.
- **Reference basis (SAML2Core)**; locator: `3\.2\.2 Complex Type StatusResponseType||3\.2\.2\.1 Element <Status>`: When an XML signature is used on a response, the requester MUST verify that the signature is valid.
- **source_clauses**: `[0, 107)` `sha256:0649b5f4937d…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-IDP17.z</code> details</summary>

- **Required variants**:
  - `v-b848c1ce08` Do not terminate the IdP session based on the identifier or SessionIndex in a LogoutRequest with an invalid signature.
  - `v-a8e170980d` On an optional response-consumption path, do not rely on Success or other statuses in a LogoutResponse with an invalid signature.
- **Controls (negative controls)**:
  - This is distinct from IIP-IDP17.y, which performs verification. If the LogoutResponse-receiving direction is not observed, use satisfied_with_note.
  - Do not suppress a response based on aslo:Asynchronous in a LogoutRequest with an invalid signature. If the extension cannot be trusted, prioritize this MUST_NOT and the IIP-IDP17.aa Core path.
- **Referenced specification**: `SAML2Core#3.2.1-3.2.2`
- **Reference basis (SAML2Core)**; locator: `3\.2\.1 Complex Type RequestAbstractType||3\.2\.2 Complex Type StatusResponseType`: If the request signature is invalid, the responder MUST NOT rely on the request's content.
- **Reference basis (SAML2Core)**; locator: `3\.2\.2 Complex Type StatusResponseType||3\.2\.2\.1 Element <Status>`: If the response signature is invalid, the requester MUST NOT rely on the response's content.
- **source_clauses**: `[0, 107)` `sha256:0649b5f4937d…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-IDP17.aa</code> details</summary>

- **Required variants**:
  - `v-7e79a357aa` Invalid LogoutRequest → if responding, return a LogoutResponse containing an error; no response is a WARNING.
  - `v-6fc4b3cf73` On the optional response-consumption path, process and record a LogoutResponse with an invalid signature as an error in the exchange.
- **Controls (negative controls)**:
  - ★ SHOULD_CLASS. If internal error handling cannot be observed, return not_verified. If receipt of a LogoutResponse is not observed, return satisfied_with_note.
  - For a request with an invalid signature, aslo:Asynchronous cannot be trusted. Assess the Core choice between returning an error LogoutResponse and returning no response, without additionally imposing the response prohibition of IIP-IDP17.b1.
- **Referenced specification**: `SAML2Core#3.2.1-3.2.2`
- **Reference basis (SAML2Core)**; locator: `3\.2\.1 Complex Type RequestAbstractType||3\.2\.2 Complex Type StatusResponseType`: Treat responding with an error to an invalid request signature as a SHOULD.
- **Reference basis (SAML2Core)**; locator: `3\.2\.2 Complex Type StatusResponseType||3\.2\.2\.1 Element <Status>`: Treat handling an invalid response signature as an error as a SHOULD.
- **source_clauses**: `[0, 107)` `sha256:0649b5f4937d…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-IDP17.ab</code> details</summary>

- **Required variants**:
  - `v-63086a507a` A LogoutRequest or optional LogoutResponse that is cryptographically valid but uses another entity's key → detect the mismatch between the Issuer and the signer.
- **Controls (negative controls)**:
  - Cryptographic validity (IIP-IDP17.y) and signer appropriateness are separate. If receipt of a LogoutResponse is not observed, return satisfied_with_note.
- **Referenced specification**: `SAML2Core#3.2.1-3.2.2`
- **Reference basis (SAML2Core)**; locator: `3\.2\.1 Complex Type RequestAbstractType||3\.2\.2 Complex Type StatusResponseType`: For a valid request signature, the responder SHOULD evaluate the signer's identity and appropriateness
- **Reference basis (SAML2Core)**; locator: `3\.2\.2 Complex Type StatusResponseType||3\.2\.2\.1 Element <Status>`: For a valid response signature, the requester SHOULD perform the same evaluation
- **source_clauses**: `[0, 107)` `sha256:0649b5f4937d…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-IDP17.ac</code> details</summary>

- **Required variants**:
  - `v-e34de6747c` The target identity provider issues a LogoutRequest or LogoutResponse containing @Consent to indicate that consent was obtained → it has a verifiable XML signature or message signature specified by the delivery binding.
- **Controls (negative controls)**:
  - If @Consent is absent or unspecified, return satisfied_with_note. Do not additionally require LogoutRequest issuance capability.
  - For HTTP-Redirect, remove <ds:Signature> and add a query signature using SigAlg / Signature. Do not make the absence of an XML signature alone a WARNING
- **Referenced specification**: `SAML2Core#3.2.1-3.2.2 + SAML2Bind#3.4.4.1`
- **Reference basis (SAML2Core)**; locator: `3\.2\.1 Complex Type RequestAbstractType||3\.2\.2 Complex Type StatusResponseType`: If the request's Consent indicates that principal consent was obtained, the request SHOULD be signed
- **Reference basis (SAML2Core)**; locator: `3\.2\.2 Complex Type StatusResponseType||3\.2\.2\.1 Element <Status>`: If the response's Consent indicates that principal consent was obtained, the response SHOULD be signed
- **Reference basis (SAML2Bind)**; locator: `3\.4\.4\.1 DEFLATE Encoding||3\.4\.5 Message Exchange`: HTTP-Redirect removes the XML signature, and if the original message was signed, adds a SigAlg / Signature signature to the encoded query string
- **source_clauses**: `[0, 107)` `sha256:0649b5f4937d…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-IDP17.ad</code> details</summary>

- **Required variants**:
  - `v-b7e0498ffb` For an invalid LogoutRequest, such as one missing required attributes, if a SAML LogoutResponse is returned, its top-level @Value MUST be Requester
- **Controls (negative controls)**:
  - The source text says “if it responds.” Do not treat an HTTP error or no response as a violation of this MUST.
  - For a SAML response using an unsupported version, apply the more specific VersionMismatch of IIP-IDP17.ah and do not duplicate this obligation's Requester.
- **Referenced specification**: `SAML2Core#3.2.1`
- **Reference basis (SAML2Core)**; locator: `3\.2\.1 Complex Type RequestAbstractType||3\.2\.2 Complex Type StatusResponseType`: If responding to a request invalid under SAML syntax or processing rules, the responder MUST return a SAML response with StatusCode=Requester
- **source_clauses**: `[0, 107)` `sha256:0649b5f4937d…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-IDP17.ae</code> details</summary>

- **Required variants**:
  - `v-a3394e16e6` Do not apply a LogoutRequest with @Version=1.1 / 3.0 to the IdP session.
  - `v-8af753c974` Control: A valid LogoutRequest with @Version=2.0 → proceed with normal processing
- **Controls (negative controls)**:
  - When responding, the VersionMismatch is IIP-IDP17.ah.
  - A request with the same major version as a supported version but a higher minor version may be processed or rejected, so neither outcome receives a verdict
- **Referenced specification**: `SAML2Core#4.1.3.1`
- **Reference basis (SAML2Core)**; locator: `4\.1\.3\.1 Request Version||4\.1\.3\.2 Response Version`: A SAML responder MUST reject a request with an unsupported major request version
- **source_clauses**: `[0, 107)` `sha256:0649b5f4937d…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-IDP17.af</code> details</summary>

- **Required variants**:
  - `v-6581c77326` The @Version of a LogoutResponse issued by the target IdP is less than or equal to the @Version of the corresponding LogoutRequest.
- **Referenced specification**: `SAML2Core#4.1.3.2`
- **Reference basis (SAML2Core)**; locator: `4\.1\.3\.2 Response Version||4\.1\.3\.3 Permissible Version Combinations`: A SAML responder MUST NOT issue a response version higher than that of the supported request
- **source_clauses**: `[0, 107)` `sha256:0649b5f4937d…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-IDP17.ag</code> details</summary>

- **Required variants**:
  - `v-aee69aaab7` For a normal LogoutRequest, the response major version must be >= the request major version
  - `v-3515b6acc5` Control: Only when the secondary code is RequestVersionTooHigh is a lower-major response permitted
- **Controls (negative controls)**:
  - RequestVersionTooLow / RequestVersionDeprecated are not exceptions.
- **Referenced specification**: `SAML2Core#4.1.3.2`
- **Reference basis (SAML2Core)**; locator: `4\.1\.3\.2 Response Version||4\.1\.3\.3 Permissible Version Combinations`: Except when reporting RequestVersionTooHigh, a SAML responder MUST NOT issue a response with a major version lower than that of the supported request
- **source_clauses**: `[0, 107)` `sha256:0649b5f4937d…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-IDP17.ah</code> details</summary>

- **Required variants**:
  - `v-e63450d6fa` For an unsupported-major LogoutRequest, if a SAML response is returned, its top-level @Value must be VersionMismatch
- **Controls (negative controls)**:
  - Do not treat a lack of response as a violation. The secondary code is MAY, so do not fix it to a particular value
- **Referenced specification**: `SAML2Core#4.1.3.2`
- **Reference basis (SAML2Core)**; locator: `4\.1\.3\.2 Response Version||4\.1\.3\.3 Permissible Version Combinations`: An error response for an incompatible SAML protocol version MUST report top-level VersionMismatch
- **source_clauses**: `[0, 107)` `sha256:0649b5f4937d…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-IDP17.ai</code> details</summary>

- **Required variants**:
  - `v-b6dfcea87a` If the target IdP actually issues a response-bearing LogoutRequest, its @Version corresponds to a LogoutResponse version that the IdP can process.
- **Controls (negative controls)**:
  - The capability to issue LogoutRequest is itself OPTIONAL. If it is not observed, the outcome is satisfied_with_note.
  - A request that does not require a response under the Asynchronous SLO extension is outside the runtime scope. Do not add response-consumption capability to an async-only implementation.
- **Referenced specification**: `SAML2Core#4.1.3.1`
- **Reference basis (SAML2Core)**; locator: `4\.1\.3\.1 Request Version||4\.1\.3\.2 Response Version`: A SAML requester MUST NOT issue a request version corresponding to a response version that it cannot support
- **source_clauses**: `[0, 107)` `sha256:0649b5f4937d…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-IDP17.aj</code> details</summary>

- **Required variants**:
  - `v-70b443b0e1` A LogoutRequest with @Version=2.0 actually issued by the target IdP to a SAML 2.0 peer.
- **Controls (negative controls)**:
  - The capability to issue LogoutRequest is itself OPTIONAL. If it is not observed, the outcome is satisfied_with_note. ★ SHOULD_CLASS
- **Referenced specification**: `SAML2Core#4.1.3.1`
- **Reference basis (SAML2Core)**; locator: `4\.1\.3\.1 Request Version||4\.1\.3\.2 Response Version`: A SAML requester SHOULD issue a request using the highest request version supported by both parties
- **source_clauses**: `[0, 107)` `sha256:0649b5f4937d…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-IDP17.ak</code> details</summary>

- **Required variants**:
  - `v-6ed1055ae2` An implementation in which the IdP issues requests follows a policy of using its highest version, 2.0, even when the peer's version capability is unknown.
- **Controls (negative controls)**:
  - The capability to issue LogoutRequest is itself OPTIONAL. An IdP that does not issue it has the outcome satisfied_with_note. ★ SHOULD_CLASS
- **Referenced specification**: `SAML2Core#4.1.3.1`
- **Reference basis (SAML2Core)**; locator: `4\.1\.3\.1 Request Version||4\.1\.3\.2 Response Version`: If responder capabilities are unknown, the requester SHOULD assume that the responder supports its own highest request version
- **source_clauses**: `[0, 107)` `sha256:0649b5f4937d…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-IDP17.al</code> details</summary>

- **Required variants**:
  - `v-355885ea15` Reject a LogoutRequest / optional LogoutResponse whose identifier / SessionIndex / Destination / Status have been excluded from the signature target using XPath / XSLT.
  - `v-0c12e79a57` An SLO message containing a transform that leaves the signed content empty → reject it
- **Controls (negative controls)**:
  - Rejected → satisfied. Only acceptance requires ensuring that no content is excluded. The mere presence of a non-permitted transform may be grounds for rejection
  - If the inbound LogoutResponse direction is not observed, assess only the request direction. The Suite shall self-verify the fixture's cryptographic validity and the actual exclusion.
- **Referenced specification**: `SAML2Core#5.4.4`
- **Reference basis (SAML2Core)**; locator: `5\.4\.4 Transforms||5\.4\.5 KeyInfo`: The verifier MAY reject a signature containing a non-permitted transform; if it does not reject it, it MUST ensure that no content of the SAML message is excluded from the signature
- **source_clauses**: `[0, 107)` `sha256:0649b5f4937d…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-IDP17.am</code> details</summary>

- **Required variants**:
  - `v-2fb8a4a034` A LogoutRequest issued by the target IdP through any route passes the protocol schema and has @ID / @Version=2.0 / @IssueInstant and a principal identifier.
  - `v-46b9dcb1ea` A LogoutResponse issued by the target IdP passes the protocol schema and has @ID / @Version=2.0 / @IssueInstant and <Status>.
- **Controls (negative controls)**:
  - The capability to issue LogoutRequest is itself OPTIONAL. If it is not observed, assess only the response direction.
  - Evaluate value semantics, uniqueness, and UTC representation under their individual obligations; do not substitute schema validation alone
- **Referenced specification**: `SAML2Core#3.7.1-3.7.2 + SAML2P-xsd`
- **Reference basis (SAML2Core)**; locator: `3\.7\.1 Element <LogoutRequest>||3\.7\.2 Element <LogoutResponse>`: LogoutRequestType inherits from RequestAbstractType and requires a principal identifier choice
- **Reference basis (SAML2Core)**; locator: `3\.7\.2 Element <LogoutResponse>||3\.7\.3 Processing Rules`: LogoutResponse is StatusResponseType and has no additional content
- **Reference basis (SAML2P-xsd)**; locator: `<complexType name="RequestAbstractType"||<complexType name="ExtensionsType"`: ID, Version, and IssueInstant of RequestAbstractType have use=required
- **Reference basis (SAML2P-xsd)**; locator: `<complexType name="StatusResponseType"||<element name="Status"`: ID, Version, and IssueInstant of StatusResponseType, and Status, are required
- **Reference basis (SAML2P-xsd)**; locator: `<complexType name="LogoutRequestType"||<element name="LogoutResponse"`: The identifier choice of LogoutRequestType is required
- **source_clauses**: `[0, 107)` `sha256:0649b5f4937d…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-IDP17.an</code> details</summary>

- **Required variants**:
  - `v-7e8d34ce6e` The top-level @Value of a LogoutResponse issued by the target IdP is one of Success / Requester / Responder / VersionMismatch; do not place a secondary code such as PartialLogout / AuthnFailed at the top level.
- **Controls (negative controls)**:
  - Apply this to both success and failure paths. Determine IIP-IDP17.e / .o / .s according to the circumstances; this obligation determines the syntactic constraint on the top-level list.
  - An asynchronous request does not require a response. However, in ordinary SP-initiated SLO, IIP-IDP17.a makes the capability to issue LogoutResponse mandatory, so non-observation must not result in satisfied_with_note.
  - Omission of a subordinate status code and a proprietary URI are MAYs, so they are not prohibited.
- **Referenced specification**: `SAML2Core#3.2.2.2`
- **Reference basis (SAML2Core)**; locator: `3\.2\.2\.2 Element <StatusCode>||3\.2\.2\.3 Element <StatusMessage>`: The topmost StatusCode/@Value MUST be selected from the top-level list in §3.2.2.2
- **source_clauses**: `[0, 107)` `sha256:0649b5f4937d…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

#### IIP-IDP18

[Source](https://kantarainitiative.github.io/SAMLprofiles/fedinterop.html#IIP-IDP18) / Section digest `sha256:4874105bfdab…` / Section length 92 / Non-normative spans 0

| Obligation | Level | Role | Testability | Condition | Core/Full | Summary |
|---|---|---|---|---|---|---|
| `IIP-IDP18.a` | MUST | idp | `BROWSER` | — | full | Support receiving SP-initiated LogoutRequest messages with HTTP-Redirect |
| `IIP-IDP18.b` | MUST | idp | `BROWSER` | — | full | Support sending LogoutResponse messages with HTTP-Redirect for SP-initiated logout |
| `IIP-IDP18.c` | MUST | idp | `BROWSER` | — | full | When the IdP emits LogoutRequest messages, support sending them with HTTP-Redirect |
| `IIP-IDP18.d` | MUST | idp | `BROWSER` | — | full | For a response-bearing IdP-issued LogoutRequest, support receiving LogoutResponse with HTTP-Redirect |

<details><summary><code>IIP-IDP18.a</code> details</summary>

- **Required variants**:
  - `v-928303abea` The Suite SP sends a LogoutRequest over HTTP-Redirect → the IdP accepts it.
- **Controls (negative controls)**:
  - This is the receiving direction corresponding to the mandatory basic flow of IIP-IDP17.a. Do not include the IdP's optional request issuance in the same variant.
- **source_clauses**: `[0, 92)` `sha256:4874105bfdab…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-IDP18.b</code> details</summary>

- **Required variants**:
  - `v-707ae4806d` Advertise only an HTTP-Redirect SLO response endpoint for the Suite SP and send an HTTP-Redirect LogoutRequest → the IdP returns a LogoutResponse over HTTP-Redirect.
- **Controls (negative controls)**:
  - This is the sending direction corresponding to the mandatory basic flow of IIP-IDP17.a. Do not assume that the IdP issues an optional request.
  - When the Suite SP advertises Redirect and POST, among others, simultaneously, do not force a Redirect response. SAML2Prof 4.4.3.5 permits either side to use any binding supported by both.
- **source_clauses**: `[0, 92)` `sha256:4874105bfdab…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-IDP18.c</code> details</summary>

- **Required variants**:
  - `v-a7b4b1bf23` Configure the Suite participant's SLO request endpoint for HTTP-Redirect only, and have the target IdP send an HTTP-Redirect LogoutRequest through any initiation or propagation path.
- **Controls (negative controls)**:
  - IdP-initiated SLO and propagation are optional. If no LogoutRequest issued by the target IdP is observed, use satisfied_with_note; evaluate the binding only when one is issued.
- **source_clauses**: `[0, 92)` `sha256:4874105bfdab…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-IDP18.d</code> details</summary>

- **Required variants**:
  - `v-e4672ac5a0` The target IdP issues a normal LogoutRequest → the Suite participant returns an HTTP-Redirect LogoutResponse → the IdP consumes it
- **Controls (negative controls)**:
  - IdP-initiated SLO and propagation are optional. Evaluate the binding only if the target issues a LogoutRequest.
  - A Run in which only requests that do not require a response are observed due to the Asynchronous SLO extension is outside the execution scope and is satisfied_with_note. Do not turn async capability into response-consumption capability.
- **source_clauses**: `[0, 92)` `sha256:4874105bfdab…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

#### IIP-IDP19

[Source](https://kantarainitiative.github.io/SAMLprofiles/fedinterop.html#IIP-IDP19) / Section digest `sha256:12344a291d09…` / Section length 421 / Non-normative spans 0

| Obligation | Level | Role | Testability | Condition | Core/Full | Summary |
|---|---|---|---|---|---|---|
| `IIP-IDP19.a` | MUST | idp | `BROWSER` | — | full | Support decryption of saml:EncryptedID elements in logout requests |
| `IIP-IDP19.b` | MUST | idp | `CONFIG` | — | full | Be configurable with at least two decryption keys |
| `IIP-IDP19.c` | MUST | idp | `BROWSER` | — | full | Attempt each decryption key until the identifier decrypts or keys are exhausted, in which case decryption fails |

<details><summary><code>IIP-IDP19.a</code> details</summary>

- **Required variants**:
  - `v-fb7478ddf4` EncryptedID encrypted with the first key
- **source_clauses**: `[0, 93)` `sha256:0034ef3c7104…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-IDP19.b</code> details</summary>

- **Required variants**:
  - `v-ccc91da249` Whether two keys can be configured
- **Configuration failure semantics**: `normative_capability`
- **source_clauses**: `[94, 208)` `sha256:0b31c5b6d868…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

<details><summary><code>IIP-IDP19.c</code> details</summary>

- **Required variants**:
  - `v-10cf39bb7e` Encrypt with the second key → decrypted
  - `v-107d53fbc3` Unregistered key → failure (control)
- **source_clauses**: `[209, 421)` `sha256:1fb52db10611…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

#### IIP-IDP20

[Source](https://kantarainitiative.github.io/SAMLprofiles/fedinterop.html#IIP-IDP20) / Section digest `sha256:2082fe0afdf2…` / Section length 267 / Non-normative spans 0

| Obligation | Level | Role | Testability | Condition | Core/Full | Summary |
|---|---|---|---|---|---|---|
| `IIP-IDP20.a` | MUST | idp | `CONFIG` | — | full | Consume peer configuration from metadata, without additional inputs, for every element listed in SAML2Prof 4.4.5 |

<details><summary><code>IIP-IDP20.a</code> details</summary>

- **Required variants**:
  - `v-cb9d0acc64` md:SingleLogoutService (binding and Location)
  - `v-8f1c2adb07` md:KeyDescriptor use=encryption when identifiers are encrypted (algorithm, configuration, and public key)
- **Controls (negative controls)**:
  - Only two elements. Do not return PASS merely because the SLO endpoint is followed
- **Configuration failure semantics**: `normative_capability`
- **Referenced specification**: `SAML2Prof#4.4.5`
- **Reference basis (SAML2Prof)**; locator: `4\.4\.5\s+Use of Metadata||4\.5\s+Name Identifier Management Profile`: Same as above (the same reference clause as IIP-SP17.a)
- **Notes**: Enumerated directly from SAML2Prof 4.4.5 (saml-profiles-2.0-os, sha256:5df9b874…). Section 4.4.5 contains only two items: SingleLogoutService and, when encryption is used, an encryption KeyDescriptor
- **source_clauses**: `[0, 267)` `sha256:2082fe0afdf2…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

#### IIP-IDP21

[Source](https://kantarainitiative.github.io/SAMLprofiles/fedinterop.html#IIP-IDP21) / Section digest `sha256:9d1a7dcae624…` / Section length 492 / Non-normative spans 1

| Obligation | Level | Role | Testability | Condition | Core/Full | Summary |
|---|---|---|---|---|---|---|
| `IIP-IDP21.a` | MUST | idp | `ATTESTED` | — | full | Generate persistent name identifiers in a manner that allows deployers to avoid assigning identifiers that differ only by case to two different subjects |

<details><summary><code>IIP-IDP21.a</code> details</summary>

- **Required variants**:
  - `v-c5b5600053` Declare whether a case-collision-free format can be selected (base32 / hex / lowercase only, etc.)
- **Controls (negative controls)**:
  - This cannot be determined from the character set of one observed NameID. UUIDs and Base64 can also satisfy the requirement, so do not issue a WARNING based on the character set; record it only as information
- **Notes**: A non-normative note identifies base32 [RFC4648] as a common means of achieving this
- **source_clauses**: `[0, 251)` `sha256:9ba5b6a72531…`
- **review**: `PENDING_REVIEW` / reviewer: `None` / approved_at: `None`

</details>

## G1 Status

```
g1_state       : PENDING_REVIEW
obligations    : 544
unapproved      : 544
open questions  : 0
```

The author has not populated `reviewer` / `approved_at`.
Test implementation must not begin until another reviewer approves it after **directly comparing the source and `tests/coverage.yaml`**.
