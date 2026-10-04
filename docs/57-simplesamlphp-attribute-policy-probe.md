# Preliminary diagnosis of SimpleSAMLphp attribute-release paths

Before extending [formal attribute comparison](56-attribute-policy-acceptance.md) to other products, exercised the running SimpleSAMLphp's native import and standard attribute filter. `dev/simplesamlphp/probe_attribute_policy.py` passes saved original XML through product XML validation/SAMLParser and uses its returned value directly as the Destination for `core:AttributeLimit`. The Suite does not convert XML into configuration attributes.

Input attributes are synthetic diagnostic values, not authenticated users or signed SSO responses. Evidence is marked `protocol_observed=false`, `verdict_adopted=false`. This investigates execution paths and is not adopted as a case outcome.

## Observed processing

| Comparison | Parser output | Standard-filter result | Remaining condition |
|---|---|---|---|
| EntityAttributes present/absent | Tags retained/absent | No attribute-set difference | Identify existing policy path referencing tags |
| RequestedAttribute present/absent | Requested names retained/absent | uid only when present; unrestricted when absent | Observe actual SSO |
| isRequired=true/false | required list retained/absent | uid only in both cases | Fixed policy using isRequired as input |
| Indexed metadata | Attributes from the first service retained | uid only | Import/execution path retaining request-index selection |

Index-condition labels describe original-fixture collection conditions. The probe sends no AuthnRequest and is not protocol-level index testing. Repeated input of identical original metadata is not evidence that request indices were ignored. The running product's SAMLParser source also confirms import of the first element only.

`core:AttributeLimit` imposes no restriction for an empty requested-attribute list. Replacing absent requested attributes with an expectation to remove all attributes would be incorrect. Parser retention of isRequired alone also does not establish the release-policy difference required by the approved case.

No product-wide feature absence is inferred from a lack of differences through this standard filter. Adding custom PHP implementing expected branches in place of the tested feature is not adopted as evidence either.

## Evidence and operation costs

Original fixtures: `build/acceptance/reference-20260918/shibboleth-attribute-policy-preparation/`. Output in sibling directories `simplesamlphp-attribute-policy-native-probe/` and `simplesamlphp-attribute-policy-native-probe-provenance/`. The latter adds actual loaded parser/filter paths and SHA-256 hashes. Per-condition original-fixture hashes, exit codes and stderr are retained; existing outputs are not overwritten.

<!--g1-literal--> 9 conditions per execution; 18 native calls succeeded including a rerun after source identification. Product configuration writes/reloads/restarts, SSO and user interactions were all 0. The initial source search separately failed because the container lacked rg; it switched to grep. No configuration was changed.

<!--g1-literal--> Unverified observations remain 467 with 157 case IDs. This diagnosis established no new Success or Failed. The G2 signed-source difference remains unresolved.
