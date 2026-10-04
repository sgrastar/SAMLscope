# Suite signature controls and native product import

## Evidence-based inventory update

<!--g1-literal--> Eleven SimpleSAMLphp metadata_idp observations became Success. Unverified: 511→500; distinct IDs: 170→164; concluded observations: 94 of baseline 594. These are neither cross-product conformance nor a completed single Run.

| Adopted cases | Observations |
|---|---|
| MD02.c, MD05.a4 | Single/aggregate roots parsed natively and used in SSO |
| MD05.a5 | Documents with cacheDuration/validUntil imported and used; not proof of expiry enforcement |
| MD05.g | Unknown extensions and RegistrationInfo imported and used |
| MD05.ad, MD07.a | Requests signed by each key position, including use-omitted keys, accepted |
| MD06.a9, MD12.b, MD12.d | Public keys from certificates with differing validity/start/subject/issuer/extensions/usage used |
| MD12.a, MD12.c | Self-signed/long-validity certificates and differing certificate-signature algorithms used |

Run: run_KDFJDGNQQCVFANEG53YYWYS4A1. Each condition binds original XML hash, product parser output, mandatory-signature settings/application, Suite-issued valid request, correlated Success and restoration. MD03.c is not adopted despite raw PASS, since this does not prove metadata-signature trust validation. KeyValue consumption also remains unproven.

## Suite-generated controls

Metadata campaigns accept signatureControl=invalid. Suite generates damaged-signature AuthnRequests and records actual displayed XML, request ID, variant, campaign identity and control kind. Responses correlate through InResponseTo; damaged-signature responses do not advance the campaign.

MetadataSignatureObservation establishes the control only with normal Success and invalid-signature SAML error from the same Run, variant, campaign member and destination. Silence, external self-report, different campaigns/Runs/variants, duplicate IDs, unissued requests and unknown statuses do not qualify. Success for an invalid signature invalidates the control and is excluded from normal metadata-use evidence.

KeyValue gates release only when this control succeeds. Keycloak returned Success for invalid signatures under KeyValue-only and multiple-key/use-omitted settings; these were not adopted as key-consumption evidence. Driver advancement is not success, since SAML errors also advance; the driver now checks actual correlated Success.

## SimpleSAMLphp native import

`dev/simplesamlphp/import_metadata_batch.py` invokes the same native conversion functions as administration: Utils\XML::checkSAMLMessage, Metadata\SAMLParser::parseDescriptorsString and getMetadata20SP. No Suite XML-to-attribute conversion occurs. This is a native-parser CLI path, not a management-UI test.

Like native static conversion, it removes entityDescriptor and expire from parser output and installs the product output for a dedicated entity. It cannot prove HTTP refresh, expiry enforcement or signature trust. Each trial restores exact original bytes and final hash.

The first trial applied Suite's optional-signature declaration and accepted the damaged signature. This was not treated as product failure; a new Plan with formal requestSigningMode=REQUIRED was retested.

<!--g1-literal--> A subsequent trial overlooked PHP OPcache refresh. It was not adopted. All 27 conditions were rerun with a three-second application wait exceeding the configured two-second recheck. This is local cache handling, not a conformance timing threshold.

HTTP errors for damaged signatures are recorded but do not establish SAML rejection. Adopted cases use positive evidence that native fixture documents/keys were actually used under mandatory signing. Suite signature discrimination remains unresolved when the negative control lacks a SAML error.

## Verification and costs

<!--g1-literal--> Runner 478, Peer 15, API 87 and driver Python 29 tests passed; G1 generation/structure 46/46. G2 stayed 20/21 with the protected-source G2-30 difference.

<!--g1-literal--> Import attempts 60; configuration writes 123, including Keycloak create/delete, SimpleSAMLphp install/restore and three duplicate final restorations. Cleanup verified for all attempts. Correlated normal successes 58; invalid-signature attempts 60; direct user actions 0; product restarts 0; docker builds 2; Suite/forward recreations 2 each. Total clicks/API reads were unmeasured.

Final local image: samlscope:reference-signature-controls-v24-final. Its full build used isolated source excluding earlier unrelated API changes, preserving the original tree. Real evidence was collected on the preceding image in the same series; the final image additionally preserves the signature-control selection on resumed fetch-wait pages, with API regression verification.

Evidence under build/acceptance/reference-20260917/: keycloak-suite-signature-controls/, simplesamlphp-native-parser-1/, simplesamlphp-native-parser-2/, simplesamlphp-native-parser-3/. Only the final SimpleSAMLphp trial is adopted. Totals: suite-signature-control-operations.json; deployment: suite-signature-control-runtime/.
