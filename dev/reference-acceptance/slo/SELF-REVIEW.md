# Self-review of the offline SLO reader

The target is the 14 unverified observations in the ledger. There are 0 new confirmed conclusions this time, and a passing reader test must not be treated as product conformance or adoptability.

## Implementation boundaries

- `ReadSloStoredEvidence` is an offline-only diagnostic reader. It has no path to the DB, API, sender, Evaluator, Verdict, configuration changes, or Run updates. It separates the stored outcome from the diagnostic assessment, and the assessment is always NOT_VERIFIED.
- Being able to read valid JSON/XML, or an InResponseTo match, shows only a structural correspondence within that XML. It does not show cryptographic verification, delivery, or consumption by the product. The output's `wireBindingProven` and `nativeConsumptionProven` stay false.
- `declaredBinding` is a label in the Recorder summary. It is not proof of the binding checked against the actual method, rawQuery, HTTP Location, or the product's receipt log. The HTTP-Redirect query is not reconstructed.
- Case membership is checked against the result hash and the Run. Evidence from a different Run is not relabeled, no stored case is added, and no new source-Run binding is created. Unsupported native receipts are not guessed at and adopted.
- Rejected: duplicate JSON keys, trailing JSON, duplicate tx/message IDs, foreign Runs, reference escapes, symlinks, decoded hash/size mismatches, DTDs, and ambiguous SOAP Bodies. Problems in an original bundle are kept as NOT_VERIFIED gaps and are not turned into a product VIOLATED.
- For SOAP, the bytes of the whole envelope stay hashed while the Body's single element is referenced through the DOM. No re-serialization or replacement of the original is performed.

## Originals that are easy to misjudge

1. The Keycloak stored session termination comes with the POST exchange. It is not proof that the Redirect response was accepted. The possibility that the local session ended before the response arrived has also not been ruled out.
2. The existing Shibboleth nativeResult=Success is for POST, and a separate campaign is for SOAP. Do not reinterpret them as Redirect. The old response labeled Redirect has an invalid destination, and the origin's termination time does not prove a causal link to consumption either.
3. Do not infer acceptance of that participant's response from the SimpleSAMLphp PartialLogout after Continue. A participant request and a failure arriving at the same time is not "continuing after learning of the failure." Do not use the old campaign that was started twice as a control.
4. The SimpleSAMLphp v131i origin original contains async and an invalid Destination. Re-auditing the existing adoption 17-s is outside this scope, but it must not be substituted for a new, correct, synchronous campaign.
5. Do not adopt the old Keycloak 18-c/d VIOLATED as is. Issuing POST in a configuration where POST was also permitted, or a POST response chosen by the Suite, is not a counterexample to Redirect capability.
6. The old SATISFIED for Keycloak/Shibboleth 17-b2 has been withdrawn in the ledger. Do not substitute a 400, an invalid Destination, or a page reached by the Suite for the IdP's own session-termination failure feedback.
7. Do not build an original for the first key of 19-a from the limited counterexample of SSP19-c. Do not treat the state where Keycloak's metadata yields no key as the product being unable to decrypt.
8. Silence, HTTP errors, UNKNOWN_DELIVERY, and unknown session state are not grounds for a product violation. This reader has no path at all that generates a product violation.

## Check results and remaining limitations

JUnit passed 14/14. It checked hash corruption, Run mix-ups, JSON duplicates, missing originals, DTDs, symlinks, ambiguous SOAP, wrongly adopting a stored SAT, and the actual stored bundles. No product controls were run. These tests do not prove detection power against the approved mutants.

In the 19 stored-evidence replays, the bytes of the public originals were verified to be unchanged. The Java reader does not prove the signatures, issuer, destination, same session, or the complete set of participants for all messages, so a correlated graph alone must not be used for a formal conclusion. The authenticity and independence of receipts and the compatibility of source definitions are also required separately.

The Gradle offline test failed to start because of local socket permissions. The same JUnit tests were compiled and run with only local jars, and this is not reported as a Gradle success. The independent Gradle build does not change the repository's own settings/build/source.

G1 docgen --check succeeded. The G1 structural and G2 blocking failures are signature verification failures caused by the missing `/tmp/samlier-g1-allowed-signers` that the existing Git configuration references. The validation targets and validator logic were not changed, and only the report output destination was changed because of the write-location restriction. No claim is made that the checks passed, and no trusted key is added and the checks are not bypassed. The deliverable from this work remains a diagnostic prototype that is not incorporated into the main code, adoption, or commits.

`tests/`, the main source, the existing readers, docs, the formal ledger, and the stored Runs are unchanged. The AGENTS.md change that already existed and the sso01g/ work were not touched. private/, .env, private keys, and keystores were not read, and no network, Docker, physical device, commit, or push was used.

## Re-running

Run from the repository root. All outputs are placed in `build/acceptance/reference-20261031/slo/`.

```sh
.venv/bin/python dev/reference-acceptance/slo/inspect_saved_slo.py
python3 dev/reference-acceptance/slo/run_offline_checks.py
python3 dev/reference-acceptance/slo/replay_saved_slo.py
.venv/bin/python -I -B dev/reference-acceptance/slo/run_repository_checks.py
```

`run_offline_checks.py` uses JDK21 and the Jackson/core/JUnit jars that already exist locally. It records the dependency hashes each time and re-verifies them at replay. It does not fetch dependency files. It only reads the stored originals, and there is no command that registers the deliverable in the ledger.

The Gradle entry point is `dev/reference-acceptance/slo/build.gradle`. It uses the locally existing Gradle and also places user-home/project-cache in the specified output location.

```sh
JAVA_HOME=/Library/Java/JavaVirtualMachines/jdk-21.jdk/Contents/Home \
/Users/yuta/.gradle/wrapper/dists/gradle-9.7.1-bin/1w1c7tv4s851m17nbqdsro2tv/gradle-9.7.1/bin/gradle \
  --offline --no-daemon \
  -g /Users/yuta/Documents/SAMLscope/build/acceptance/reference-20261031/slo/gradle-home \
  --project-cache-dir /Users/yuta/Documents/SAMLscope/build/acceptance/reference-20261031/slo/gradle-project-cache \
  -p dev/reference-acceptance/slo test
```

The standalone reader's entry point is `offline result.json sha256 Run Case [transcript.json decoded-manifest.json]`. Information that comes out of a candidate original is diagnostic and must not be passed in as a receipt proving acceptance.
