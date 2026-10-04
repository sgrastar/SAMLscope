# SimpleSAMLphp encrypted SSO execution and missing evidence

## Progress

Native SimpleSAMLphp import plus assertion.encryption=true on a dedicated test SP now generates, receives and decrypts encrypted Assertions through ordinary SSO. Install, read-back, wait, SSO, Suite evaluation, original capture and restoration are automated.

<!--g1-literal--> No new Verdict conclusions; unverified remains 485 observations / 159 IDs. Reconfirming concluded rsa-oaep-mgf1p is not double-counted. Five remaining algorithm observations were reclassified from missing automatic oracle to missing producer-algorithm evidence.

## Implementation

- `dev/simplesamlphp/import_metadata_batch.py` gains explicit encryption enablement. Original XML interpretation stays native; supplemental configuration is recorded separately.
- `dev/simplesamlphp/normal_encrypted_sso.py` uses ordinary Suite metadata and SSO. Dedicated metadata-test keys/URLs do not substitute for normal-flow evidence.
- EvidenceStatus exposes encrypted-Assertion count, successful decryption count and actual algorithms with fixed tokens. Missing response, failed decryption and decrypted-but-required-algorithm-absent are distinct. Missing required conditions keep ready=false.
- Readers require matching Run and a response after its request, excluding cross-Run and pre-request evidence.

## Observations and limits

| Path | Observation | Judgment use |
|---|---|---|
| Metadata-fixture campaign | Encrypted Assertion | Dedicated keys/URLs exclude it from ordinary-SSO algorithm judgments |
| Ordinary SSO | normalFlowAccepted, encrypted Assertion, decryption with Run key | Existing algorithm oracle |
| Content encryption | AES128-CBC | Not evidence for AES128-GCM/AES256-GCM |
| Key transport | rsa-oaep-mgf1p | Not evidence for rsa-oaep(1.1) or every Digest/MGF combination |

Running product source confirms SP-prioritized assertion.encryption and rsa-oaep-mgf1p in the public-key path; originals are retained. A shared-key path also exists, so defaults do not prove product-wide lack of GCM. Shared-key generation/decryption and other allowed producer configurations remain to investigate.

Other raw normal-SSO judgments are not adopted wholesale. This encryption trial does not establish additional conditions such as semantic principal correspondence.

## Evidence

Root: build/acceptance/reference-20260918/.

| Trial | Run | Folder |
|---|---|---|
| Fixture path | run_CDE4QVH4TBJV6R8FYCWFKEW2CQ | simplesamlphp-encrypted-assertions |
| Ordinary SSO | run_XV8DY232PX2JEHS9QQ3EHEYWTY | simplesamlphp-normal-encrypted-sso |

verify_encrypted_sso_diagnosis.py checks original fixture, native parser output, encryption application/restoration, original response hash/algorithm, decrypted Suite outcome and unresolved diagnostics. Refreshing diagnostics reuses existing evidence without new settings or SSO.

Image: samlscope:reference-encryption-diagnostics-v29; digest sha256:dcf9a7071180aaf66569e54bfb28d50172af71f038bd0247729ce95753ab8b48.

## Costs and verification

<!--g1-literal--> Native imports 3; writes 7 (fixture install/restores 4 plus finally restore 1, ordinary install/restore 2); Runs 2; preflight 2; docker build 1; Suite/forward recreations 1 each; user actions 0; product restarts 0. Original configuration SHA-256 matched after restoration.

Runner regression passed after connecting execution and diagnostics. G1 generation/structure verified. Existing G2 signed-source differences remained unresolved.
