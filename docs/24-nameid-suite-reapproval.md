# NameID and Suite reapproval record

The user explicitly approved the NameID determination definition and G2 reapproval in the local conversation on 2026-09-14. This record covers the NameID same-SP omission interpretation and the preceding Suite fixes only. Other uncommitted OIDC/admin changes are outside this approval tree.

Source comparison: SAML Core 2.0 OS section 8.3.7 permits omission of SPNameQualifier for a message intended only for direct consumption by the named SP; section 8.3.8 applies that rule to transient identifiers. The previous literal attribute equality variant omitted this permission. The MUST level is unchanged. The existing variant ID is retained, with its text and bound obligation/case digests updated. No other normative requirement is changed.

The implementation permits omission only for persistent/transient identifiers when the correlated response Destination is the registered ACS and the identifier's own assertion has explicit AudienceRestriction evidence exclusively naming the requesting SP. Missing, different, or multiple-SP audience evidence remains NOT_VERIFIED. An explicitly wrong qualifier or Format remains a violation. Positive and negative regression controls cover these paths.

The selected Suite fixes also cover ForceAuthn timestamp precision, ECP missing-response uncertainty, metadata wait completion tied to the currently issued request, and the SLO response CSP allowing only the metadata destination origin. Browser completion of the Shibboleth JSON result is not claimed by this approval.

Approval artifacts must be signed and verified using the existing external signer and validator pins. Local Git object links in approval records identify unpublished local commits until publication is separately authorized. No push or publication is authorized here.
