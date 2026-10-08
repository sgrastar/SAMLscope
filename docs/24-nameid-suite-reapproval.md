# NameID and Suite reapproval record

The user explicitly approved the NameID determination definition and G2 reapproval in the local conversation on 2026-09-14. This record covers the NameID same-SP omission interpretation and the preceding Suite fixes only. Other uncommitted OIDC/admin changes are outside this approval tree.

Source comparison: SAML Core 2.0 OS section 8.3.7 permits omission of SPNameQualifier for a message intended only for direct consumption by the named SP; section 8.3.8 applies that rule to transient identifiers. The previous literal attribute equality variant omitted this permission. The MUST level is unchanged. The existing variant ID is retained, with its text and bound obligation/case digests updated. No other normative requirement is changed.

The implementation permits omission only for persistent/transient identifiers when the correlated response Destination is the registered ACS and the identifier's own assertion has explicit AudienceRestriction evidence exclusively naming the requesting SP. Missing, different, or multiple-SP audience evidence remains NOT_VERIFIED. An explicitly wrong qualifier or Format remains a violation. Positive and negative regression controls cover these paths.

The selected Suite fixes also cover ForceAuthn timestamp precision, ECP missing-response uncertainty, metadata wait completion tied to the currently issued request, and the SLO response CSP allowing only the metadata destination origin. Browser completion of the Shibboleth JSON result is not claimed by this approval.

Approval artifacts must be signed and verified using the existing external signer and validator pins. Local Git object links in approval records identify unpublished local commits until publication is separately authorized. No push or publication is authorized here.

## Functional-profile integration

The existing signed G1 source and approval history are retained byte-for-byte.
The current implementation imports only the already-approved NameID omission
handling and its direct-consumption controls; other runtime changes from the
older branch are resolved to the current implementation.

The functional release is `functional-case-v2-nameid`. Its profile membership
is unchanged, and every profile is regenerated against the approved coverage
and case-catalog bytes. The browser IdP profile now owns the already-approved
NameIDPolicy case digest. The retained initial release still owns its original
case meaning and stored outcomes, and is held for new execution.

Independent review checked the exact approved source delta, the destination and
exclusive-audience conditions, explicit mismatch and missing-proof controls,
profile bindings, and separation from retained definitions. The signed merge
preserves the original G1 approval ancestry. Its immediate G2 approval descendant
binds the current protected tree and carries the already-approved changed case
alongside the unchanged case designs. This does not constitute another change in
specification interpretation.

The held Keycloak observation remains unverified until a new Run under this exact
release supplies correlated native exchanges and the approved controls. Old Run
originals are not relabeled or replayed as a new-definition result. Product
acceptance and publication remain separate from implementation checks.
