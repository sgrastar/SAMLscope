# Historical permission investigation

Observed on 2026-09-11. This record distinguishes retrieved evidence from a
completed decision about permission for each catalog expression. None of the
following findings changes a signed catalog or grants new rights in source text.

| Material | Evidence | Decision still needed |
| --- | --- | --- |
| MDQ, SAML-MDQ, SAML-EC (2017 adopted drafts) | Official IETF TLP 5 PDF has an effective date of March 25, 2015 on its first page and section 2. Sections 3 and 4 distinguish document text from code components. Interior page headers still say December 28, 2009; retained as observed, not silently corrected | Confirm stream-specific applicability and exact copied/adapted fields before selecting permissions; do not extend the code-component permission to prose |
| RFC7457 (February 2015) | TLP 5 section 2(c) preserves prior policies for pre-existing documents. The official December 28, 2009 policy URL was identified but could not be retrieved in this investigation | Retrieve and retain TLP 4, then apply it only to matching publication-date material |
| RFC4051 (April 2005) | Official RFC3978 (March 2005, BCP 78) text retrieved | Review applicable permissions and source notices together, including derivative and code distinctions |
| XMLSig and XMLEnc 1.1 (2013) | Dated W3C document-license-2002 page retrieved. It retains original attribution/document status and limits modifications; current generic policy is not substituted | Confirm historical linkage and each quotation, translation, adaptation or schema/code use |
| SAML assertion/protocol/metadata XSDs | Entries in the official SAML 2.0 OS ZIP exactly match all three approved source digests. The archive has no standalone LICENSE/NOTICE text | Schema-specific permission scope remains unresolved; membership in the ZIP alone does not establish that the PDF document permission applies |

## Reproducible evidence

Temporary retrieved originals are under `build/license-review/`, not committed.
Hashes describe the observed bytes, not approval of their legal interpretation.

| File | Official retrieval URL | SHA-256 |
| --- | --- | --- |
| IETF-TLP-5.pdf | https://trustee.ietf.org/wp-content/uploads/IETF-TLP-5.pdf | c7cdd9db6f8aa68fc1e3abe26bf858a8b5887e2e777c3ab12320e43a6fb16b08 |
| RFC3978.txt | https://www.rfc-editor.org/rfc/rfc3978.txt | 6a90d1a320b7cc722fad8516856e923734cd895bb2cb86284d0991edb7e6d02f |
| W3C-2002.html | https://www.w3.org/Consortium/Legal/2002/copyright-documents-20021231 (redirects to https://www.w3.org/copyright/document-license-2002/) | 62e6df0a226bfed9de8996e4e896113cdfb33cb33f80038e56f761abdc70d8f5 |
| saml-2.0-os.zip | https://docs.oasis-open.org/security/saml/v2.0/saml-2.0-os.zip | 4de58648fc958c7d81159addc678780390ae80bf3163c335c63d3580db2cb2f2 |

IETF TLP 5 pages 1, 3 and 4 were visually inspected alongside extracted text.
The historical TLP 4 location was
https://trustee.ietf.org/license-info/IETF-Trust-License-Policy-20091228.htm;
retrieval failure must not be treated as permission to use a newer policy.

The registry continues to mark supplemental permission and material allocation
as pending. These investigation references are not a substitute for distributing
all text and notices required by the applicable permission once determined.
