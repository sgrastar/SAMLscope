# Retained specification notices

`source-notices.json` is the shared source-notice registry. It preserves the
notice-page text of the adopted OASIS PDF files and the Kantara Implementation
Profile copyright/license paragraphs, with exact source/text hashes and notice
locations. Page furniture is retained; permission terms are not rewritten.
Kantara’s notice retains Internet2 and the respective contributors as named
by the source, and links its CC BY-SA 3.0 US terms. Each entry distinguishes the observed edition from the signed catalog entry.
A pending catalog correction is not silently applied to the approved definition.

This registry records source terms, not a license allocation to SAMLscope files.
Its unresolved source list includes the other adopted documents and schemas whose
notices are not yet included. The application exposes this registry alongside its
license page, and standalone reports embed the same registry. Material-level
attribution and the unresolved notices remain unfinished. Do not describe this
partial registry as complete third-party clearance.

Update source notices from the exact adopted source document, verify the full
notice section and hashes, then regenerate consumers. Do not replace individual
historical document terms with a newer general policy. The app and distribution
copy this registry from here; generated copies must not be edited separately.

The registry now also retains IETF TXT copyright sections and W3C copyright
paragraphs. `terms_review_status` distinguishes retaining these sections from
reviewing incorporated historical terms. See `material-review.md` for boundaries
and `material-index.json` for generated per-obligation source membership.
Run `.venv/bin/python dev/licensing/materials.py --check` before distribution.
