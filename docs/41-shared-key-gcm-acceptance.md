# SimpleSAMLphp shared-key GCM acceptance

## Results and evidence

<!--g1-literal--> Unverified observations 485→483; distinct IDs stay 159. SimpleSAMLphp browser_sso_idp IIP-ALG04.a/b became Success. Evidence is not transferred to other products/profiles.

Ordinary SP metadata was imported natively, with temporary assertion.encryption, sharedkey and sharedkey_algorithm settings. Correlated Success Responses to normal AuthnRequests contained EncryptedAssertions decrypted by Suite with the shared key. AES-CBC in the original RSA path does not establish product-wide lack of GCM.

| Condition | Correct-key Run | Wrong-key Run | Result |
|---|---|---|---|
| AES128-GCM | run_00MKHH590BSDDG411ST76J02AD | run_ZNEH2027V46ZFCD76WXK8R5XZ6 | Decrypted PASS with correct key; NOT_VERIFIED with wrong key |
| AES256-GCM | run_30QS0MMCHGS3Q02VGHJ5VYEP9J | run_B3N52X36FKQN3RA05MD0D7S3SK | Decrypted PASS with correct key; NOT_VERIFIED with wrong key |

`dev/reference-acceptance/verify_shared_gcm_batch.py` checks original XML hashes, Run/request/response correlation, algorithms, result references, native import, restoration, wrong-key uncertainty and key-replacement rejection before adoption. Unit success or configuration read-back alone is insufficient.

## Input lifetime and freezing

The authorized POST /api/runs/{id}/protocol-evidence/evaluate API accepts optional sharedKeyBase64. Empty input preserves existing evaluation. Key bytes are supplied only to that Run/thread during synchronous request evaluation; references are removed on completion/exception and the input array erased. Physical erasure of JVM/crypto-library temporary copies is not guaranteed.

SQLite stores only the first key's SHA-256. A different key for the same Run is rejected, including after restart. Repeated evaluation requires resubmitting the same key; lost keys require a new Run. Secret key bytes are not saved in CaseState, Transcript, result JSON or operation records.

This input connects to algorithm observation, without claiming support for every other decrypting observer or semantic principal matching. A UI shared-key panel is outside this change.

## Execution and effort

<!--g1-literal--> Native imports 5, writes 10 (install/restore), Runs 5, preflight 5, ordinary SSO round trips 5, docker build 1, Suite/forward recreation 1 each, user actions 0, product restarts 0. Every trial restored original SHA-256.

<!--g1-literal--> Initial wrong-key Run run_XM00XBWDXACHFD2HH78BD1VGFP correctly rejected key replacement, but the driver failed to catch a wrapped exception and stopped evidence collection. finally restored settings. This trial is not adopted; exception handling was corrected and a fresh Run completed. Costs above include it.

Evidence: build/acceptance/reference-20260918/simplesamlphp-shared-gcm*. Costs/deployment: shared-key-input-runtime/. Saved evidence was scanned for private-key leakage. Keys existed only in temporary product settings/process memory, not retained parser output.

Image: samlscope:reference-shared-key-input-v31; digest sha256:497fea94b6c8ffb1c6d3d04f6367fa1f88e7dd923c93b199a9fac91047012b95. Application was recompiled from prior tracked source to exclude unrelated existing SOAP changes. Build-input hashes are retained.

## Verification and remaining work

Store/Runner/API regressions verify Run/thread isolation, exception cleanup/input erasure, persistent digest-based replacement rejection, unknown-Run rejection and fixed errors that do not reflect secrets. API expectations for default ACS and explicit automatic-oracle inventory were updated for prior implementation additions.

<!--g1-literal--> G1 generation/structure 46/46 and inventory audit zero errors. G2 remained 20/21 due to existing G2-30 source differences. No completion/release approval.

Shared-key direct encryption generates no EncryptedKey, so it cannot establish remaining RSA-OAEP modes or Digest/MGF combinations.
