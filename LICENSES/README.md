# License and source index

Start with the [licensing guide](../LICENSING.md) for the distinction between
original software, original content, incorporated third-party material and measured
results. The links below provide the complete terms, attribution and publication
conditions for the reviewed distributions.

| Document | What to find |
| --- | --- |
| [Apache-2.0](../LICENSE) | Original software, tools and test code |
| [CC BY-SA 4.0](CC-BY-SA-4.0.txt) | SAMLscope-owned original prose and definitions only |
| [Publication audit](publication-audit.md) | Actual-use rationale, publication decision, conditions and scope |
| [Material register](publication-register.md) / [JSON](publication-register.json) | Per-material use, rights holders, permission evidence, required notices and GREEN/YELLOW/RED decisions |
| [Specification source notices](source-notices.json) | Original copyright, permission text, exact editions, source URLs and modification credits |
| [Material index](material-index.json) | Generated source membership for catalog obligations, tests and profiles |
| [Java notices and source availability](../web/public/licenses/java-dependencies.json) | Full retained package/resource notices and exact source-download links |
| [Java permission evidence](java-permissions.json) | Reviewed package and embedded-resource records bound to actual file hashes |
| [Container publication conditions](container-publication.md) / [source manifest](container-source-manifest.json) | Runtime-specific notices, exact source versions and retained corresponding-source downloads |
| [Publication review](../docs/license-publication-review.md) | Review findings, fixes, verification and signed-approval boundaries |
| [Contribution terms](../CONTRIBUTING.md) | Conditions for contributing software, prose and definitions |

Readable distribution-specific notices are also available in the
[application](https://app.samlscope.com/licenses) and on the
[website](https://samlscope.com/licenses/).

## Registry maintenance

The source registry retains the adopted documents' own notices, including Internet2
and named contributor credits for Kantara, individual historical OASIS permissions,
and relevant IETF/W3C evidence. Retaining a notice is distinct from deciding how a
material is used; the publication audit and register contain the current decisions.
[Material review](material-review.md) explains those boundaries.
[Historical term research](historical-term-review.md) is a research record, not the
current list of unresolved materials.

Update notices against the exact adopted document and verify its notice section
and hashes. Do not substitute current general policies for historical document
terms, relicense third-party material, or silently change signed catalog entries.
Regenerate consumers instead of editing generated copies; see the
[licensing tools](../dev/licensing/README.md). Run
`.venv/bin/python dev/licensing/materials.py --check` before distribution.
