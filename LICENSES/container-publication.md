# Container publication conditions

The reviewed runtime is the linux/amd64 child of the exact Temurin base image in
`container-source-manifest.json`. The manifest maps every installed Ubuntu binary
package to its exact source package and records the actual JRE release and retained
legal-file hashes. Other architectures and changed runtime packages are outside this review.

The original OS copyrights, complete common license texts and JRE `legal/` directory
remain in the image. Source archives retain their own file-specific licenses, including
Ubuntu patches, packaging/build rules, OpenJDK exceptions and third-party notices.
Neither the image nor the source bundles receive a blanket Apache, CC or GPL label.
The independently executed SAMLscope application keeps its existing license scopes.

## Corresponding source

[Download the retained source bundles](https://github.com/sgrastar/SAMLscope/releases/tag/runtime-sources-96975602e131).
The image label `com.samlscope.runtime-sources` and repository Docker instructions
point to this release. These assets must remain downloadable for as long as the
associated image binaries are distributed. Do not delete or replace the assets while
retaining those image versions. This is source delivery, not a newly invented written offer.

The Ubuntu bundle contains the complete published source packages for the installed
versions, including `.dsc`, upstream archives, patches and build rules. Each `.dsc`
SHA-256 entry was compared with the downloaded bytes. Use `dpkg-source -x <file.dsc>`
to recover the package source tree. The Temurin bundle contains the official full
OpenJDK source archive, its upstream checksum, exact release build configuration and
the unchanged Temurin build-script repository archive at the release's `buildRef`.
Upstream license texts and exceptions remain within these unmodified source archives.

GPLv2 section 3 requires corresponding-source provision for redistributed binaries.
The [FSF's GPLv2 FAQ](https://www.gnu.org/licenses/old-licenses/gpl-2.0-faq.html#SourceAndBinaryOnDifferentSites)
explains why an unarranged upstream link alone is insufficient. SAMLscope therefore
retains its own downloadable copies, rather than relying solely on upstream retention.

## Verification and regeneration

`python3 dev/licensing/container_sources.py --image samlscope:ci` compares the actual
runtime's architecture, package database, JRE release and retained legal-file bytes
with the reviewed manifest, then downloads and verifies the full public source assets.
This runs before the workflow can publish an image or deploy it. A changed base pin,
changed inventory/notices, unavailable download or incorrect hash blocks publication.

To reproduce the source bundles from their hash-pinned inputs, run:

```sh
python3 dev/licensing/container_sources.py --assemble build/runtime-sources
```

Updating the base requires a new review of its actual package/source mapping, legal
files, exact source versions and available source archives. Regenerate the manifest
and source bundles, publish the new retained sources, and renew protected Docker/CI
approval before publishing the new image. Do not carry the current decision forward
merely because an image uses the same vendor or release family.

The existing source copyright notices include minor template/metadata cases: XZ's
`License: none` describes generated data or short lists, `noderivs` governs verbatim
license texts, and the ca-certificates example uses an unfilled packaging template.
These are not evidence that the executable packages lack a redistribution grant.
Original file-specific exceptions are retained; absent SPDX scanner values are not
used to infer either permission or a publication blocker.
