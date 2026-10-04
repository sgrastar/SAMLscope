# Shared-key GCM decryption and opaque-Assertion judgment correction

## Implemented foundation

Running SimpleSAMLphp EncryptedAssertion code generates an AES128-CBC content key for RSA encryption, but directly uses the supplied AES shared-key type otherwise. GCM exists in that investigated shared-key path; the previous public-key trial does not establish lack of GCM.

Suite now supports AES shared-key decryption through a Run-scoped SamlDecryptionKeyProvider input connected to algorithm observation. Existing RSA private-key input and behavior without shared keys remain unchanged. Keys are neither extracted from responses nor stored in CaseState.

Real AES128-GCM/AES256-GCM ciphertext verifies correct-key decryption, wrong-key and altered-tag rejection, and unchanged ciphertext DOM. SAML/Runner regressions passed.

At this stage the runtime connection between product-configured shared keys and Suite Runs was unfinished. Key freezing/lifetime, secret non-persistence and product restoration were next. Unit GCM success is not a real-product Verdict.

## Principal judgment and real-environment check

The observer incorrectly returned SATISFIED_WITH_NOTE when it could not find Subject inside an undecrypted EncryptedAssertion. Inability to observe is not evidence of absence; that path now returns NOT_VERIFIED.

Fresh Run run_NXTAXWN71DEJF02ZNAQXS4AZA8 under build/acceptance/reference-20260918/simplesamlphp-opaque-principal-control/ produced IIP-SSO01.cz reason saml.subject-principal.undetermined; existing IIP-ALG06.a retained decrypted PASS. Earlier opaque-Assertion note-success had not been adopted, so no concluded observations were revoked. Generated inventory reason/next action were updated.

Semantic principal matching still requires SubjectConfirmation/attributes in the decrypted Assertion and correspondence with the Suite-authenticated principal. Decryption alone does not establish identity.

## Records

<!--g1-literal--> Unverified remains 485 observations / 159 IDs. Product writes 2 (install/restore), native import 1, Run 1, preflight 1, docker build 1, Suite/forward recreation 1 each, user actions 0, product restarts 0. Original SHA-256 restoration verified.

Library originals/hashes: build/acceptance/reference-20260918/shared-key-foundation/. Deployment: shared-key-runtime/. Image: samlscope:reference-shared-key-foundation-v30; digest sha256:e312182078e8cf899a24a3c753cdcfe5c93f1e8f1c3f6200c853c4040c93e68c.

G1 generation/structure verified. Existing G2 signed-source differences remain; no full completion or release approval.
