# Shared authentication context strength and preference comparison

The targets are the approved definitions of `IIP-SSO01-ga-idp-01`, `gb`, `gc`, and `gj`. Comparisons use the product's declared or configured strength order; candidate order does not substitute for strength order. At this stage request generation and internal rules for verified successful responses are implemented. Product configuration, the original-evidence collector, and whole-case aggregation are not yet connected.

## Request generation

`SamlRequestedAuthnContextRequestFactory.ContextRequest` accepts Comparison, reference type, and an ordered candidate set. Existing fixed exact fixtures retain their generation path; the new `buildConfiguredContext` can construct minimum, better, maximum, and reversed candidates. AuthnContextClassRef and AuthnContextDeclRef are explicitly separate. URI names and candidate positions do not imply strength.

Blank, duplicate, or empty candidates are rejected before generation for these normal comparison fixtures. This is not an additional product conformance requirement. The factory does not send requests; integration with execution also uses Runner's outbox.

## Internal rules

`AuthnContextSelectionRule` is a comparison component for already verified successful responses. It does not directly determine Outcome or Verdict. The case must separately verify original signatures and request correlation, native preparation, all conditions, and positive and negative controls.

- minimum compares the returned value to the single specified threshold using the product's order and requires it to be at least that threshold.
- better distinguishes returning the threshold itself and requires a strictly stronger value.
- maximum requires exhaustive confirmation of the set available with fixed user input and checks selection of its greatest value at or below the upper bound. A weaker value is not a match merely because it is below the bound.
- Preference checks selection of the first candidate when preparation confirms that every candidate is satisfiable. It does not use strength order. Whole-case evaluation also requires originals with the candidate order reversed.

Unconfirmed strength order, candidate satisfiability, or maximum's available set yields UNPROVEN. Native preparation's numeric values express order relations; they are not Suite-defined authentication strength scores.

Error Responses are not inputs to these success-selection rules. The approved definitions permit errors in some conditions; always returning errors alone does not establish a product violation. The preference case cannot infer successful order evaluation from an error. Future case aggregation must distinguish these situations.

## Remaining work and verification

A path must collect strength order, available sets, and fixed login conditions from standard product configuration and test class and declaration separately. Only evidence establishing error Response correlation and authenticity, candidate reversal, configuration restoration, and each case's request conditions can connect the comparison to formal results.

<!--g1-literal--> Added tests cover candidate-order preservation for every Comparison and both reference types, an overly weak maximum selection, an equal better selection, reversed product order, and unconfirmed candidate satisfiability. Compilation passed; execution awaits batch verification. Product configuration writes, protocol round trips, and user interactions: 0. The inventory remains 462 unverified observations; adding internal components is not counted as resolution.

## Reading signed responses and generating case conditions

`AuthnContextResponseEvidence` checks Response InResponseTo and Destination. For success it uses only an Assertion passing shared signature, decryption, Audience, and SubjectConfirmation validation. It reads ClassRef and DeclRef separately from a single AuthnStatement's AuthnContext, preserving both when present. Duplicate or blank references and simultaneous Decl and DeclRef invalidate the evidence. An inline declaration records presence only and does not prove return of an external DeclRef.

For errors it verifies the Response signature, request correlation, a standard top-level StatusCode, and absence of Assertions. It returns observation type ERROR without a successful selection value. Later case aggregation distinguishes strength comparisons that permit errors from cases where errors cannot establish preference order. Unsigned, undecryptable, or ambiguous structures cannot establish the demonstration.

`AuthnContextComparisonInputs` accepts reference values prepared by a native adapter and assembles each case's inputs. maximum assumes preparation making low/medium available and high the upper bound. Preference makes both low/high satisfiable and reverses their order. The argument name `unavailable` is not evidence of unreachability; product configuration must establish the conditions for each comparison method.

<!--g1-literal--> It constructs 16 inputs: 4 cases × class/declaration × 2 conditions each. The native preparation still to be connected must be fixed separately because available sets differ between cases. Generated requests are not counted as executions or resolutions.

<!--g1-literal--> Added test sources cover plaintext/encrypted Assertions, simultaneous ClassRef and DeclRef retention, signed errors, Assertions in errors, duplicate/blank/altered references, and all generated conditions. Compilation passed; execution awaits batch verification. Product configuration and protocol executions: 0; the inventory remains 462 unverified observations. Next are native preparation, the original-evidence collector, and whole-case comparison.

## Whole-case comparison

`AuthnContextComparison` matches required conditions generated from native preparation to actual requests and aggregates both class/declaration conditions. It fixes experiment, SP, login-input, and configuration fingerprints and checks non-overlapping exchange windows and unique original request/response references. Missing, duplicate, swapped, or mixed-configuration conditions yield NOT_VERIFIED.

Preparation explicitly states the product's low/high order, maximum's low/medium/high order and available set, preference candidate satisfiability, and demonstration of unreachable conditions. URI names alone do not establish these facts. Verified positive and negative controls are also required; without them, an observed selection mismatch does not become a product violation. This state is an internal value for a future trusted preparation/control-verification adapter, not an input set by a user confirmation click.

A successful selection mismatch becomes VIOLATED only when required conditions, prerequisites, and controls are complete. Cases do not return Verdict; Evaluator converts according to level. A correlated, signature-verified error in a strength comparison is not itself a violation. An error-only experiment lacks a successful-selection control and yields NOT_VERIFIED. Preference cannot be confirmed unless the reversed condition succeeds.

<!--g1-literal--> Tests for weak maximum selection, ignoring candidate order, unverified controls, errors only, and missing/duplicate conditions were added and compile. Execution is grouped into the test batch. This addition reaches internal comparison only; the original-evidence collector, native preparation, and formal registry remain unconnected. Product operations: 0; the inventory remains 462 unverified observations.

## Native integration update

<!--g1-literal--> The unconnected paths and pending tests above record the time each component was added. Original-evidence collection, native configuration automation, formal CONFIG registration, native verification, and inventory adoption are now complete. Shibboleth established 3 Success results and 1 Failed result, reducing unverified observations 462→458. Details and operation counts are in [Native authentication context comparison integration](67-authn-context-native-acceptance.md).
