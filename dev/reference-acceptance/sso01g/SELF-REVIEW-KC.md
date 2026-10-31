# Keycloak live driver self-check

2026-10-31. The investigation of product capabilities through the admin API is complete. No formal SAML campaign, case outcome, Verdict, or reference inventory update has been performed. The investigation results are in the [live FINDINGS](../../../build/acceptance/reference-20261031/sso01g-keycloak/FINDINGS.md).

## Implementation and boundaries

`keycloak_live.py` creates a dedicated client, a standard LoA conditional flow, and a ClassRef mapper, stores the product GET for normal/maximum, and in finally performs deletion and verification against the original public state. `keycloak_campaign.py` requires an explicit `--dry-run` or `--live`. `--live` runs only the admin API configuration investigation. It is not connected to the `product-runtime` driver of `run_campaign()`.

The connection is fixed to `http://127.0.0.1:18180`, and localhost aliases, other ports, userinfo, external hosts, redirects, and proxies are rejected. Cookies are not retained. Credentials are read from a fixed development fixture via the AST. The authentication module is not imported, and there is no fallback to environment variables, private/, .env, or key files. The token is held in memory only, and the API log contains only method/path/status. Product-generated secret attributes mixed into the admin GET of the new SAML client are removed before public projection. An unknown secret attribute stops storage.

`campaign.py` updated the job in the output-permitted location to the destination specified this time and states that the SAML/outbox driver is unimplemented. Earlier offline artifacts are kept as records of that time. No live operation on SimpleSAMLphp was performed.

## Misjudgment and restoration risks

|Item|Countermeasure / remaining constraint|
|---|---|
|Inferring SAML support from OIDC configuration|Confirmed the running SAML-specific feature and the SAML mapper. Also examined the SAML callers in the stored-version bytecode of the same version. Saving a map alone is not proof of interpretation.|
|Missing DeclRef|No public native path was found, and the comparison and mapper in the stored version handle ClassRef only. Because the running Response is unconfirmed, all 4 cases are held. A partial ClassRef success is not extended to all cases.|
|Treating a configuration GET as execution evidence|The origin is set to `product-management-api` and `executionObserved=false`. Native authentication execution observations are 0, and the conventional `product_effective_*` is also 0. It is not promoted to a formal receipt.|
|Weak selection of maximum|Disabling high alone does not prove that medium is available and the strongest selection. low/medium EXACT originals, high being unreachable, and identical input and completeness are tasks for after user operation.|
|Treating all errors and HTTP failures as success|An admin HTTP error makes the investigation incomplete. Only a known 404 is used to confirm non-existence. There is no SAML error original, so neither conformance nor non-conformance is issued.|
|Confusing first-match priority with numeric LoA order|The findFirst in the stored function is auxiliary evidence. It is held until both orders and the EXACT control for each candidate are confirmed on the live system.|
|Direct sending / reassigning to another Run|The AuthnRequest sender, browser, and Suite access are not implemented. Without the outbox in place, a complete campaign cannot be started. The IDP19.b-specific source binding is also not reused.|
|Changing an existing realm or shared flow|Stops on an existing collision in the namespace. A write guard for dedicated IDs/aliases was added. No PUT to the realm's bindings. The public projections of existing flows and the client list are compared before and after.|
|Double write due to response loss|Before a write, the intent and attempt count are saved to an fsync journal, and after the ACK, the success count is saved. A GET verifies that the state is either the original or exactly the intended single change, and a partial write is not resent.|
|Concurrent configuration changes|The public projection is compared between writes and before restoration. Unknown differences are not overwritten and processing stops. Because the API has no CAS, races between a GET and a write cannot be fully excluded. Operationally, the isolated namespace must not be touched by other admin operations.|
|Interruption / restoration failure|Restoration in finally, capture of the first SIGINT/SIGTERM, and `--live --recover` resumes deletion only. SIGKILL and power loss require resuming from the journal. If safe restoration cannot be proven because of external edits or a product stop, it stays stopped as incomplete.|
|Residual child flows / config|The config IDs and child flow IDs are retained, and non-existence GETs are confirmed. In the final live GET too, the 3 child flows and 3 configs from the completed run return 404. The product cascaded when the parent flow was deleted, so no additional config DELETE was needed on the live system.|
|Scope of "exact match"|Public bindings, shared flow definitions/executions, the client identifier list, and non-existence of the dedicated resources are equal. A match of the full realm export, secret values, audit log, sessions, and generated ID sequences is out of scope.|
|Early implementation gaps|The first 2 attempts stopped because of alias appending and product-generated secret attributes. Both were restored. Without omitting failures or recovery, 65 writes / 65 ACKs and 5 restorations are tallied from the HTTP records.|
|ACK counts in the old journal|The first recovery Counters lack the ACK before the read-back exception. The status records of the original report are kept. The aggregator calculates from the status, and the final driver saves immediately after the ACK and verifies status at recovery.|

After the completed attempt that saved the restoration evidence first, the dedicated write guard, the count verification in journal recovery, and the child-flow non-existence confirmation were strengthened. These were verified with unit tests, and non-existence was also confirmed by an additional live GET. Configuration writes were not repeated with the final code.

## Number of user operations and unconfirmed items

User operations, browser logins, AuthnRequests, and normal SSO this time were all 0. Token acquisition through the admin API is automated, and the value is not stored. There are no admin screen operations.

The future evaluation matrix is 24 conditions plus 1 to 2 normal SSO runs. Adding the unachievable auxiliary request of gj for both reference types makes 27 to 28 round trips. This does not mean increasing the condition matrix itself or the approved cases.

The current flow is configured so that the first Username Form and each Password Form up to the requested LoA are submitted separately. In a simple model of fresh operation, the authentication-related form submissions at low/medium/high are at most 2/3/4 respectively, but because the actual step-up selection, the point at which an error occurs, and session reuse have not been observed, this is neither a measured value nor a guaranteed upper bound. If each of all 28 round trips takes 4 submissions, 112 submissions can serve as a provisional budget, but MFA, consent, and additional screens may separately be needed. Logout is planned at 0, and discarding the context is not counted as logout.

Unconfirmed items are: the bytes match between the running JAR and the stored version, the runtime LoA, the ClassRef/DeclRef output of the Response, all successful selections, unachievable errors, and candidate availability, the maximum-value selection, candidate-order reversal, the detection power of positive/negative controls, unique correlation and cryptographic verification of Run/outbox/Recorder, and normal SSO after restoration. Formal adoption is not possible before these are in place.

## Verification and reproduction

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover \
  -s dev/reference-acceptance/sso01g -p 'test_*.py' -v

PYTHONDONTWRITEBYTECODE=1 python3 dev/reference-acceptance/sso01g/keycloak_campaign.py \
  --dry-run --out build/acceptance/reference-20261031/sso01g-keycloak/dry-run-next

# Configuration investigation only. Use a new name and an empty output location.
PYTHONDONTWRITEBYTECODE=1 python3 dev/reference-acceptance/sso01g/keycloak_campaign.py \
  --live --name kc-next \
  --out build/acceptance/reference-20261031/sso01g-keycloak/live-next

# Cleanup after an interruption only. Specify the same name/out as the journal.
PYTHONDONTWRITEBYTECODE=1 python3 dev/reference-acceptance/sso01g/keycloak_campaign.py \
  --live --recover --name kc-next \
  --out build/acceptance/reference-20261031/sso01g-keycloak/live-next

# Re-aggregate from the retained HTTP records of attempts and recoveries. Existing output is not overwritten.
PYTHONDONTWRITEBYTECODE=1 python3 dev/reference-acceptance/sso01g/summarize_keycloak_operations.py \
  --out build/acceptance/reference-20261031/sso01g-keycloak/operational-totals-next.json \
  build/acceptance/reference-20261031/sso01g-keycloak/live-r1/report.json \
  build/acceptance/reference-20261031/sso01g-keycloak/live-r2/report.json \
  build/acceptance/reference-20261031/sso01g-keycloak/live-r3/report.json
```

The existing 25 plus 20 added, 45 tests in total, passed. The additions verify pre-application rejection and post-application ACK loss for all 27 configuration write sites, GET failures, recovery after a deletion ACK loss, journal-first saving, namespace collisions, preservation of external edits, rejection of shared-resource writes, secret removal, the 127.0.0.1 pin, redirect rejection, and dry-run sending no communication. Success on fixtures is not counted as a positive/negative control run of the product.

The final audited run also had 45 tests / 0 failures / 0 errors. Socket and external process launches, prohibited inputs, and writes outside the designated location were rejected by an audit hook, with 0 attempts each. They were recorded in the job's `audited-tests.log` and `test-results.json`. An AST inspection of the source was also performed.

`g1_docgen.py --check` succeeded. `g1_validate.py --structural-only` and `g2_validate.py` also include signature verification and involve Git key references and build output outside the designated location, so they were not run within this time's prohibition on key references and write scope. Mocking the signature verification and treating it as a pass is also not done. The full G1 source comparison was not performed because external communication is prohibited. No claim is made that Gradle, the G1/G2 trusted wrapper, browser integration, or release readiness passed.

The protected artifacts, case implementations, formal ledger, and comparison/inventory are unchanged. The AGENTS.md change from the start was also not touched. No commit, push, or Docker operation was performed. Write destinations were only the designated sso01g, acceptance evidence, and job scopes.
