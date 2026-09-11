# License publication review — 2026-09-11

The owner requested review followed by publication and explicitly authorized any
required approval renewal and signed commits. This supersedes the earlier local-only
execution restriction for publication; it does not authorize external rights-holder inquiries.

| Finding | Change | Validation |
| --- | --- | --- |
| Package review automatically replaced every embedded XSD's pending state without a per-resource record | Recorded original resource notices, named license URLs, exact resource hashes and the limited unchanged-package distribution rationale. Missing resource evidence remains pending | Generator checks each record/digest; build requires canonical package and resource evidence |
| YELLOW status was used as a proxy for copied expression; a RED quotation would be reported as reference/original material | Use classification now comes from the actual-use field independently of publication status; unknown use fails explicitly | Negative tests cover RED quotation and unknown use |
| Inquiry/legal flags were lost when rendering source/package rows, and implementation counts were inferred from package prefixes | Preserve decision flags and use explicit reviewed-material metadata | Register regeneration and tests |
| Java details omitted original JAR notices and hid packages without supplemental review metadata | Show original notices separately from supplemental texts; retain all packages and clear a previous fetch error after recovery | UI regression test includes an upstream notice without permission metadata |
| Build only checked dependency hashes, so a missing/RED or stale permission decision could still be packaged | Compare with canonical permission records and require complete resource review before packaging | Positive build and deliberate missing-evidence negative case |
| Main push automatically publishes/deploys a container, while previous audit excluded actual container verification | Perform PR CI/container verification before main publication; do not silently bypass deployment checks | Publication remains conditional on release/CI results |

A suspected missing Dockerfile copy was withdrawn after inspecting
`web/license-notices.mjs`: the CC text is embedded in the already copied source registry.
Dockerfile was not changed to address that non-issue.

The new protected change is limited to `build.gradle.kts`. Case meanings, controls,
mutants, applicability, profile membership and signed G1 inputs remain unchanged.
G2 renewal records renewed approval of that protected build boundary; it is not
represented as a fresh case-by-case design review or third-party legal certification.

The resource decision is intentionally limited to unmodified upstream package
distribution using publisher publication evidence and retained file exceptions.
An absent inline header is not an Apache/public-domain grant, and the review does
not authorize independent extraction or modification of an upstream schema.

## Runtime-source follow-up

After the original PR checks passed, the publication review found a real missing
condition in the publicly downloadable GHCR image: base licenses were retained,
but a corresponding-source delivery mechanism had not been established. The
source-delivery condition is not satisfied merely by successful CI or an upstream URL.

The owner-authorized fix retains exact Ubuntu source packages and Temurin source,
build scripts and configuration in a source-only GitHub release. A manifest binds
them to the actual package inventory, JRE release and original legal-file bytes.
The container job checks these and the full downloadable source hashes before
publishing. Docker labels and README link directly to the source release.

This follow-up changes the protected Dockerfile and build workflow. G2 renewal
covers those distribution changes, preserving existing case approvals and all G1
inputs. It does not assert a new case-design review. Negative tests reject a
changed source download, changed runtime inventory and unreviewed architecture.
