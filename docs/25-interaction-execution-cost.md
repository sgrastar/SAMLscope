# Follow-up tests and configuration and operation costs

This record measures only follow-up tests on 2026-09-14. Earlier environment setup and attempts have unmeasured counts and durations, which are not treated as zero. Additional evidence is collected for existing Runs and conclusion deltas are compared under the same case definitions.

Human user actions, agent browser actions on behalf of the user, and API/file configuration changes are counted separately. Each configuration write, including restoration, counts once; service reloads are separate. Opening a page, entering a field, clicking, and manual continuation each count as one browser action; automatic redirects do not. Scripted execution does not eliminate the configuration work itself.

## Changes in conclusions

| Product | Not verified: before | After | Reduction |
|---|---:|---:|---:|
| Keycloak | 209 | 207 | 2 |
| Shibboleth | 200 | 185 | 15 |
| SimpleSAMLphp | 203 | 202 | 1 |

The deltas above record the first follow-up tests. A later complete audit retested common cases in separate Runs and confirmed 5 additional Success observations. Subsequent retests after additional implementation are reflected in the current unverified counts in the complete inventory ([implementation record](27-additional-implementation.md)). See the [complete inventory](26-unverified-case-inventory.md) for details and retest results by product. The workload and details below include these retests and unsuccessful attempts to require signatures.

These counts are observations per product, profile, and case. They are distinct from operation and configuration counts.

## Workload

| Product | Configuration writes (including restoration) | Service reloads | Agent browser actions | Human user actions |
|---|---:|---:|---:|---:|
| Keycloak | 5 | 0 | 4 | 0 |
| Shibboleth | 27 | 16 | 7 | 0 |
| SimpleSAMLphp | 7 | 0 | 6 | 0 |

Auxiliary connection containers were started 5 times. Configuration retries caused by temporary script errors are retained in the ledger and are not classified as product defects.

The local Suite verification environment was restarted 15 times, and forwarding containers 15 times. These are counted separately from product configuration operations.

Operation durations are measured tool-call durations or script elapsed times. They exclude investigation, decisions, code authoring, and time between calls, and do not estimate human manual effort. Unmeasured durations are shown as an em dash.

## Operation details

| # | Product | Operation | Execution method | Configuration writes | Reloads | Browser actions | Measured seconds |
|---:|---|---|---|---:|---:|---:|---:|
| 1 | Keycloak | Signed plaintext assertion fixture; assertion and response signatures retained | api | 1 | 0 | 0 | 0.1 | <!--g1-literal-->
| 2 | Keycloak | Signed plaintext assertion fixture; assertion and response signatures retained | api | 1 | 0 | 0 | 0.1 | <!--g1-literal-->
| 3 | Keycloak | Signed plaintext response recorded via real in-app browser | browser | 0 | 0 | 4 | 32.6 | <!--g1-literal-->
| 4 | Shibboleth | Per-SP signed plaintext Assertion fixture | file_and_service_reload | 1 | 1 | 0 | 0.4 | <!--g1-literal-->
| 5 | SimpleSAMLphp | Additional signed SSO response recorded via real in-app browser | browser | 0 | 0 | 4 | 55.9 | <!--g1-literal-->
| 6 | Shibboleth | Per-SP signed plaintext Assertion fixture | file_and_service_reload | 1 | 1 | 0 | 0.3 | <!--g1-literal-->
| 7 | Shibboleth | Signed plaintext response recorded via real in-app browser | browser | 0 | 0 | 4 | 18.7 | <!--g1-literal-->
| 8 | SimpleSAMLphp | Preloaded aggregate for 20 metadata variants | native_metadata_parser | 1 | 0 | 0 | 0.5 | <!--g1-literal-->
| 9 | Shibboleth | Preloaded aggregate for 20 metadata variants | file_and_service_reload | 1 | 1 | 0 | 0.8 | <!--g1-literal-->
| 10 | SimpleSAMLphp | 20 variants attempted; KeyValue-only stopped at index 8; continued at index 9 and reached final page | browser | 0 | 0 | 2 | 23.9 | <!--g1-literal-->
| 11 | Shibboleth | Preloaded aggregate for 20 metadata variants | file_and_service_reload | 1 | 1 | 0 | 0.7 | <!--g1-literal-->
| 12 | Shibboleth | 20 variants attempted; final page reached without operator continuation | browser | 0 | 0 | 1 | 13.9 | <!--g1-literal-->
| 13 | SimpleSAMLphp | Restored original metadata; immediate container readback lagged, subsequent hash matched without another write | native_metadata_parser | 1 | 0 | 0 | — | <!--g1-literal-->
| 14 | Shibboleth | Native HTTP metadata provider; automatic fixture refresh | file_and_service_reload | 1 | 1 | 0 | 0.9 | <!--g1-literal-->
| 15 | Shibboleth | Native HTTP refresh with protocol client; browser completion not claimed | protocol_client | 0 | 0 | 0 | 3.1 | <!--g1-literal-->
| 16 | Shibboleth | Native HTTP refresh with protocol client; browser completion not claimed | protocol_client | 0 | 0 | 0 | 27.5 | <!--g1-literal-->
| 17 | Shibboleth | HTTP campaign browser start stalled; closed owned tab before protocol-only continuation | browser | 0 | 0 | 2 | — | <!--g1-literal-->
| 18 | Keycloak | Prepared Suite batch; stopped before any target write because expected existing client was absent | api | 0 | 0 | 0 | — | <!--g1-literal-->
| 19 | Shibboleth | Native HTTP refresh with protocol client; browser completion not claimed | protocol_client | 0 | 0 | 0 | 3.1 | <!--g1-literal-->
| 20 | suite | Deploy metadata request correlation fix; preserve prior containers and persisted Run data | docker | 0 | 0 | 0 | 4.2 | <!--g1-literal-->
| 21 | Shibboleth | Native HTTP refresh with protocol client; browser completion not claimed | protocol_client | 0 | 0 | 0 | 113.3 | <!--g1-literal-->
| 22 | Shibboleth | Reuse native HTTP configuration for redirect 301/302/307 and control | api | 0 | 0 | 0 | 0.0 | <!--g1-literal-->
| 23 | Shibboleth | Native HTTP refresh with protocol client; browser completion not claimed | protocol_client | 0 | 0 | 0 | 9.4 | <!--g1-literal-->
| 24 | environment | Resolve localhost Suite redirect URLs from inside the IdP container without rewriting HTTP bytes | docker | 0 | 0 | 0 | 0.1 | <!--g1-literal-->
| 25 | Shibboleth | Native HTTP refresh with protocol client; browser completion not claimed | protocol_client | 0 | 0 | 0 | 3.1 | <!--g1-literal-->
| 26 | Shibboleth | Native HTTP refresh with protocol client; browser completion not claimed | protocol_client | 0 | 0 | 0 | 3.1 | <!--g1-literal-->
| 27 | Shibboleth | Temporary helper serialized namespace prefixes incorrectly; resolver rejected reload and retained previous configuration | file_and_service_reload | 1 | 1 | 0 | — | <!--g1-literal-->
| 28 | Shibboleth | Correct namespace serialization and activate token-bearing fetch URL for Suite redirect key consistency | file_and_service_reload | 1 | 1 | 0 | 0.8 | <!--g1-literal-->
| 29 | Shibboleth | Native HTTP refresh with protocol client; browser completion not claimed | protocol_client | 0 | 0 | 0 | 15.4 | <!--g1-literal-->
| 30 | Shibboleth | Native HTTP metadata provider; automatic fixture refresh | file_and_service_reload | 1 | 1 | 0 | 0.5 | <!--g1-literal-->
| 31 | environment | Stop temporary IdP loopback bridge after restoring original metadata provider configuration | docker | 0 | 0 | 0 | 1.1 | <!--g1-literal-->
| 32 | Keycloak | Checked start/resume of existing SLO Runs. Expired completion is excluded from test success counts | Suite API | 0 | 0 | 0 | — | <!--g1-literal-->
| 33 | Keycloak | Retested common cases in new Runs without product configuration changes | protocol_client | 0 | 0 | 0 | 3.5 | <!--g1-literal-->
| 34 | Keycloak | Temporarily required signatures. Unsuccessful attempt stopped at positive-control startup. Configuration restored and read back | protocol_client_with_native_configuration | 2 | 0 | 0 | 0.1 | <!--g1-literal-->
| 35 | Shibboleth | Checked start/resume of existing SLO Runs. Expired completion is excluded from test success counts | Suite API | 0 | 0 | 0 | — | <!--g1-literal-->
| 36 | Shibboleth | Retested common cases in new Runs without product configuration changes | protocol_client | 0 | 0 | 0 | 3.3 | <!--g1-literal-->
| 37 | SimpleSAMLphp | Checked start/resume of existing SLO Runs. Expired completion is excluded from test success counts | Suite API | 0 | 0 | 0 | — | <!--g1-literal-->
| 38 | SimpleSAMLphp | Retested common cases in new Runs without product configuration changes | protocol_client | 0 | 0 | 0 | 3.8 | <!--g1-literal-->
| 39 | SimpleSAMLphp | Temporarily required signatures. Unsuccessful attempt stopped at positive-control startup. Configuration restored and read back | protocol_client_with_native_configuration | 2 | 0 | 0 | 0.4 | <!--g1-literal-->
| 40 | Keycloak | Retested additional implementation. Created new Runs in existing Plans and executed positive controls and approved tests | protocol_client | 0 | 0 | 0 | 274.9 | <!--g1-literal-->
| 41 | Keycloak | Retested additional implementation. Created new Runs in existing Plans and executed positive controls and approved tests | protocol_client | 0 | 0 | 0 | 0.7 | <!--g1-literal-->
| 42 | Shibboleth | Retested additional implementation. Created new Runs in existing Plans and executed positive controls and approved tests | protocol_client | 0 | 0 | 0 | 274.2 | <!--g1-literal-->
| 43 | Shibboleth | Retested additional implementation. Created new Runs in existing Plans and executed positive controls and approved tests | protocol_client | 0 | 0 | 0 | 0.8 | <!--g1-literal-->
| 44 | SimpleSAMLphp | Retested additional implementation. Created new Runs in existing Plans and executed positive controls and approved tests | protocol_client | 0 | 0 | 0 | 62.3 | <!--g1-literal-->
| 45 | SimpleSAMLphp | Retested additional implementation. Created new Runs in existing Plans and executed positive controls and approved tests | protocol_client | 0 | 0 | 0 | 0.6 | <!--g1-literal-->
| 46 | Shibboleth | Consecutive metadata tests send only after confirmed fetch. Removed extra URL tokens and fixed post-send delays. Configuration restored | native_http_provider_and_protocol_client | 2 | 2 | 0 | 10.0 | <!--g1-literal-->
| 47 | suite | Deployed a verification image limited to changed classes, preserving approved definitions and the old container | docker | 0 | 0 | 0 | 4.2 | <!--g1-literal-->
| 48 | suite | Deployed only verified additional classes and checked unchanged libraries and embedded catalogs | docker | 0 | 0 | 0 | 4.3 | <!--g1-literal-->
| 49 | Keycloak | Browser SSO test sequence after integrated additional implementation, executed with a protocol client | protocol_client | 0 | 0 | 0 | 362.8 | <!--g1-literal-->
| 50 | Shibboleth | Browser SSO test sequence after integrated additional implementation, executed with a protocol client | protocol_client | 0 | 0 | 0 | 369.8 | <!--g1-literal-->
| 51 | SimpleSAMLphp | Browser SSO test sequence after integrated additional implementation, executed with a protocol client | protocol_client | 0 | 0 | 0 | 87.4 | <!--g1-literal-->
| 52 | Shibboleth | Created metadata verification Runs and checked positive controls | protocol_client | 0 | 0 | 0 | 0.4 | <!--g1-literal-->
| 53 | Shibboleth | Executed 46 consecutive metadata inputs through native HTTP fetch. Configuration restored | native_http_provider_and_protocol_client | 2 | 2 | 0 | 97.7 | <!--g1-literal-->
| 54 | Shibboleth | Executed 17 consecutive extension-attribute and default-ACS inputs. Configuration restored | native_http_provider_and_protocol_client | 2 | 2 | 0 | 37.2 | <!--g1-literal-->
| 55 | suite | Deployed integrated encryption, ECDSA, and public-diagnostic classes. Checked unchanged existing JARs and approved definitions | docker | 0 | 0 | 0 | 4.2 | <!--g1-literal-->
| 56 | SimpleSAMLphp | Integrated SSO test sequence including encrypted Subject inputs and public diagnostics | protocol_client | 0 | 0 | 0 | 96.0 | <!--g1-literal-->
| 57 | Keycloak | Integrated SSO test sequence including encrypted Subject inputs and public diagnostics | protocol_client | 0 | 0 | 0 | 358.1 | <!--g1-literal-->
| 58 | Shibboleth | Integrated SSO test sequence including encrypted Subject inputs and public diagnostics | protocol_client | 0 | 0 | 0 | 436.9 | <!--g1-literal-->
| 59 | Shibboleth | ECDSA valid/invalid-signature attempts. Invalid signature stopped with HTTP400 and no SAML rejection response. Configuration restored | protocol_client | 2 | 2 | 0 | 8.2 | <!--g1-literal-->
| 60 | suite | Deployed integrated string-type observation and extension-input classes with pinned schemas. Checked unchanged existing JARs and approved definitions | docker | 0 | 0 | 0 | 4.2 | <!--g1-literal-->
| 61 | SimpleSAMLphp | Integrated SSO test sequence including extension-string inputs and NameID type observation | protocol_client | 0 | 0 | 0 | 116.5 | <!--g1-literal-->
| 62 | Keycloak | Integrated SSO test sequence including extension-string inputs and NameID type observation | protocol_client | 0 | 0 | 0 | 477.8 | <!--g1-literal-->
| 63 | Shibboleth | Integrated SSO test sequence including extension-string inputs and NameID type observation | protocol_client | 0 | 0 | 0 | 538.9 | <!--g1-literal-->
| 64 | suite | Deployed the fix deferring request generation until execution order. Checked unchanged existing JARs and approved definitions | docker | 0 | 0 | 0 | 4.3 | <!--g1-literal-->
| 65 | SimpleSAMLphp | SSO test sequence after the request-generation timing fix | protocol_client | 0 | 0 | 0 | 118.2 | <!--g1-literal-->
| 66 | Keycloak | SSO test sequence after the request-generation timing fix | protocol_client | 0 | 0 | 0 | 476.1 | <!--g1-literal-->
| 67 | Shibboleth | SSO test sequence after the request-generation timing fix | protocol_client | 0 | 0 | 0 | 574.5 | <!--g1-literal-->
| 68 | suite | Deployed G02 acceptance conditions, literal-string inputs, and signature preservation. Checked unchanged existing JARs and approved definitions | docker | 0 | 0 | 0 | 4.3 | <!--g1-literal-->
| 69 | Keycloak | SSO test sequence after G02 acceptance-condition and literal-string input fixes | protocol_client | 0 | 0 | 0 | 511.1 | <!--g1-literal-->
| 70 | Shibboleth | SSO test sequence after G02 acceptance-condition and literal-string input fixes | protocol_client | 0 | 0 | 0 | 617.5 | <!--g1-literal-->
| 71 | SimpleSAMLphp | SSO test sequence after G02 acceptance-condition and literal-string input fixes | protocol_client | 0 | 0 | 0 | 124.2 | <!--g1-literal-->
| 72 | suite | Deployed SLO evidence checking, request generation, send/receive integration, and basic cases. Checked unchanged existing JARs and approved definitions | docker | 0 | 0 | 0 | 4.3 | <!--g1-literal-->
| 73 | Keycloak | Changed the SLO response destination from an old Run-specific URL to a Plan-specific URL, eliminating per-Run configuration changes | Keycloak admin API | 1 | 0 | 0 | 0.1 | <!--g1-literal-->
| 74 | suite | Deployed Status URI fixes and verified unchanged existing libraries | docker | 0 | 0 | 0 | 4.3 | <!--g1-literal-->
| 75 | Shibboleth | Executed basic SP-initiated SLO scenarios; workload includes interrupted attempts | protocol_client | 0 | 0 | 0 | 3.5 | <!--g1-literal-->
| 76 | SimpleSAMLphp | Executed basic SP-initiated SLO scenarios; workload includes interrupted attempts | protocol_client | 0 | 0 | 0 | 4.4 | <!--g1-literal-->
| 77 | Keycloak | Executed basic SP-initiated SLO scenarios; workload includes interrupted attempts | protocol_client | 0 | 0 | 0 | 3.8 | <!--g1-literal-->
| 78 | Shibboleth | Executed basic SP-initiated SLO scenarios; workload includes interrupted attempts | protocol_client | 0 | 0 | 0 | 3.4 | <!--g1-literal-->
| 79 | Keycloak | Executed basic SP-initiated SLO scenarios; workload includes interrupted attempts | protocol_client | 0 | 0 | 0 | 2.8 | <!--g1-literal-->
| 80 | Keycloak | Executed basic SP-initiated SLO scenarios; workload includes interrupted attempts | protocol_client | 0 | 0 | 0 | 4.3 | <!--g1-literal-->
| 81 | SimpleSAMLphp | Changed the old Run-specific SLO response destination to a Plan-specific destination | local metadata file | 1 | 0 | 0 | 0.3 | <!--g1-literal-->
| 82 | Shibboleth | Changed the old Run-specific SLO response destination to a Plan-specific destination and reloaded metadata | local metadata file and reload | 1 | 0 | 0 | 0.4 | <!--g1-literal-->
| 83 | suite | Added signed Redirect SLO transmission and verified runtime classes and unchanged existing libraries | docker | 0 | 0 | 0 | 3.3 | <!--g1-literal-->
| 84 | SimpleSAMLphp | Enabled this SP sign.logout as a prerequisite for SLO signature verification. After an immediate read-back parse error, rechecked hash equality, PHP syntax, and configuration values | local metadata file | 1 | 0 | 0 | — | <!--g1-literal-->
| 85 | Shibboleth | Actual communication after adding Redirect SLO; interrupted attempts are also recorded | protocol_client | 0 | 0 | 0 | 2.6 | <!--g1-literal-->
| 86 | Shibboleth | Actual communication after adding Redirect SLO; interrupted attempts are also recorded | protocol_client | 0 | 0 | 0 | 3.5 | <!--g1-literal-->
| 87 | SimpleSAMLphp | Actual communication after adding Redirect SLO; interrupted attempts are also recorded | protocol_client | 0 | 0 | 0 | 3.0 | <!--g1-literal-->
| 88 | SimpleSAMLphp | Actual communication after adding Redirect SLO; interrupted attempts are also recorded | protocol_client | 0 | 0 | 0 | 4.6 | <!--g1-literal-->
| 89 | suite | Deployed Redirect-signature and SOAP-body-range fixes and verified runtime classes | docker | 0 | 0 | 0 | 4.3 | <!--g1-literal-->
| 90 | SimpleSAMLphp | Changed this SP SLO response mode to Redirect for actual Redirect-response signature testing | local metadata file | 1 | 0 | 0 | 0.7 | <!--g1-literal-->
| 91 | SimpleSAMLphp | Actual signed Redirect LogoutResponse communication and verification of related acceptance cases | protocol_client | 0 | 0 | 0 | 4.0 | <!--g1-literal-->
| 92 | suite | Deployed dedicated Redirect acceptance cases and verified classes and libraries | docker | 0 | 0 | 0 | 3.3 | <!--g1-literal-->
| 93 | Keycloak | Consecutive execution of basic SLO and dedicated Redirect acceptance cases | protocol_client | 0 | 0 | 0 | 5.1 | <!--g1-literal-->
| 94 | Shibboleth | Consecutive execution of basic SLO and dedicated Redirect acceptance cases | protocol_client | 0 | 0 | 0 | 5.1 | <!--g1-literal-->
| 95 | SimpleSAMLphp | Consecutive execution of basic SLO and dedicated Redirect acceptance cases | protocol_client | 0 | 0 | 0 | 5.3 | <!--g1-literal-->
| 96 | suite | Deployed the EncryptedID decryption verification case and verified runtime classes and libraries | docker | 0 | 0 | 0 | 4.3 | <!--g1-literal-->
| 97 | Keycloak | Consecutive SLO execution including EncryptedID decryption controls | protocol_client | 0 | 0 | 0 | 5.2 | <!--g1-literal-->
| 98 | Shibboleth | Consecutive SLO execution including EncryptedID decryption controls | protocol_client | 0 | 0 | 0 | 5.8 | <!--g1-literal-->
| 99 | SimpleSAMLphp | Consecutive SLO execution including EncryptedID decryption controls | protocol_client | 0 | 0 | 0 | 5.9 | <!--g1-literal-->
| 100 | Shibboleth | Added a decryption key through existing rollover configuration and published it in metadata | docker | 3 | 0 | 0 | 0.8 | <!--g1-literal-->
| 101 | suite | Deployed multiple-decryption-key scenarios and checked runtime classes | docker | 0 | 0 | 0 | 4.3 | <!--g1-literal-->
| 102 | Shibboleth | Restored changes to the inactive installation. The first 3 configuration files had not been applied to the running IdP | docker | 3 | 0 | 0 | — | <!--g1-literal-->
| 103 | Shibboleth | Added a decryption key through existing rollover configuration and published it in metadata | docker | 3 | 0 | 0 | 0.8 | <!--g1-literal-->
| 104 | Shibboleth | Recorded the test idp.home in startup configuration to preserve it across restarts | docker | 1 | 0 | 0 | — | <!--g1-literal-->
| 105 | Shibboleth | The disabled Tomcat shutdown port left old processes running. Terminated the 2 identified processes and started with the correct home | docker | 0 | 0 | 0 | — | <!--g1-literal-->
| 106 | Keycloak | Consecutive SLO execution including multiple-decryption-key controls | protocol_client | 0 | 0 | 0 | 4.8 | <!--g1-literal-->
| 107 | Shibboleth | Consecutive SLO execution including multiple-decryption-key controls | protocol_client | 0 | 0 | 0 | 5.9 | <!--g1-literal-->
| 108 | SimpleSAMLphp | Consecutive SLO execution including multiple-decryption-key controls | protocol_client | 0 | 0 | 0 | 4.7 | <!--g1-literal-->
| 109 | suite | Switched and verified configuration-capability and evidence-integrity classes | docker | 0 | 0 | 0 | 4.3 | <!--g1-literal-->
| 110 | Keycloak | Consecutive SLO execution including multiple-decryption-key controls | protocol_client | 0 | 0 | 0 | 4.9 | <!--g1-literal-->
| 111 | Shibboleth | Consecutive SLO execution including multiple-decryption-key controls | protocol_client | 0 | 0 | 0 | 7.3 | <!--g1-literal-->
| 112 | SimpleSAMLphp | Consecutive SLO execution including multiple-decryption-key controls | protocol_client | 0 | 0 | 0 | 5.2 | <!--g1-literal-->

## Cases with changed conclusions

| Product | Profile | Test | Before | After | Reason code |
|---|---|---|---|---|---|
| Keycloak | browser_sso_idp | `IIP-SSO01-m-idp-01` | NOT_VERIFIED | PASS | `browser.normal-flow.requester-audience-present` |
| Keycloak | browser_sso_idp | `IIP-SSO01-es-idp-01` | NOT_VERIFIED | PASS | `browser.normal-flow.assertions-protected` |
| Shibboleth | browser_sso_idp | `IIP-SSO01-m-idp-01` | NOT_VERIFIED | PASS | `browser.normal-flow.requester-audience-present` |
| Shibboleth | browser_sso_idp | `IIP-SSO01-es-idp-01` | NOT_VERIFIED | PASS | `browser.normal-flow.assertions-protected` |
| Shibboleth | metadata_idp | `IIP-MD02-b-idp-01` | NOT_VERIFIED | PASS | `metadata.fixture-probe.satisfied` |
| Shibboleth | metadata_idp | `IIP-MD02-c-idp-01` | NOT_VERIFIED | PASS | `metadata.fixture-probe.satisfied` |
| Shibboleth | metadata_idp | `IIP-MD02-d-idp-01` | NOT_VERIFIED | PASS | `metadata.fixture-probe.satisfied` |
| Shibboleth | metadata_idp | `IIP-MD03-c-idp-01` | NOT_VERIFIED | PASS | `metadata.fixture-probe.satisfied` |
| Shibboleth | metadata_idp | `IIP-MD05-a4-idp-01` | NOT_VERIFIED | PASS | `metadata.fixture-probe.satisfied` |
| Shibboleth | metadata_idp | `IIP-MD05-a5-idp-01` | NOT_VERIFIED | PASS | `metadata.fixture-probe.satisfied` |
| Shibboleth | metadata_idp | `IIP-MD05-cd-idp-01` | NOT_VERIFIED | PASS | `metadata.fixture-probe.satisfied` |
| Shibboleth | metadata_idp | `IIP-MD05-g-idp-01` | NOT_VERIFIED | PASS | `metadata.fixture-probe.satisfied` |
| Shibboleth | metadata_idp | `IIP-MD06-a1-idp-01` | NOT_VERIFIED | PASS | `metadata.fixture-probe.satisfied` |
| Shibboleth | metadata_idp | `IIP-MD12-a-idp-01` | NOT_VERIFIED | PASS | `metadata.fixture-probe.satisfied` |
| Shibboleth | metadata_idp | `IIP-MD12-b-idp-01` | NOT_VERIFIED | PASS | `metadata.fixture-probe.satisfied` |
| Shibboleth | metadata_idp | `IIP-MD12-c-idp-01` | NOT_VERIFIED | PASS | `metadata.fixture-probe.satisfied` |
| Shibboleth | metadata_idp | `IIP-MD12-d-idp-01` | NOT_VERIFIED | PASS | `metadata.fixture-probe.satisfied` |
| SimpleSAMLphp | browser_sso_idp | `IIP-SSO01-m-idp-01` | NOT_VERIFIED | PASS | `browser.normal-flow.requester-audience-present` |

## Issues directly affecting workload

| Priority | Issue | Observed in this follow-up | Proposed improvement |
|---|---|---|---|
| High | Unevaluable items appear to be waiting for operations | BrowserEvidenceTestCase returns oracle-unavailable after completion; some CONFIG cases proceed to attestation | Show automated evaluation, evidence verification, and unimplemented paths before startup; do not request configuration work that cannot be evaluated |
| High | Ordering while waiting for metadata fetch | Even with native HTTP fetching active, a response arriving before the post-start fetch causes the Suite to stop with 400 | Let the Suite enforce start, confirmed fetch, then request transmission; avoid fixed delays |
| High | Manual metadata import evidence does not reach evaluation | Responses follow batch import, but manual download is not counted as fetched evidence | Bind the imported file digest to target import records using an evidence kind distinct from HTTP fetch |
| High | Key mismatch after redirect | A redirect from a stable URL without a token returns the normal key, mismatching the polling request signature | Continue testing with an explicit token in the fetch URL; preserve the mode correctly in the Suite to remove extra configuration |
| Medium | localhost means different hosts on the host and in containers | The redirect target was unreachable, requiring auxiliary forwarding | Use a verification configuration with a hostname reachable by the browser, product, and Suite |
| Medium | Intermediate errors stop consecutive tests | SimpleSAMLphp stopped on KeyValue-only; continuing subsequent tests required one intervention | Save error evidence and allow independent subsequent tests to resume |
| Fixed | Switching metadata modes prioritizes an old request ID | The Suite incorrectly rejected a valid response as uncorrelated during HTTP update after batch import | Corrected issued-request correlation, deployed the verification image after regression tests, and completed continuation in the same Run |
| Medium | Repeated positive tests and configuration round trips | Additional SSO advances repeated Audience observations and signature checks of unencrypted Assertions | Include required positive controls in the initial execution plan; use product adapters for configuration snapshots and restoration |
| Medium | IdP-initiated SSO cannot be received | Normal reception requires InResponseTo to match an existing AuthnRequest | Design an explicitly permitted Run-specific IdP-initiated reception path with positive and negative controls |

The Shibboleth HTTP fetch path was checked against the [official FileBackedHTTPMetadataProvider documentation](https://shibboleth.atlassian.net/wiki/spaces/IDP5/pages/3199506865). Except for request-ID correlation explicitly marked Fixed, these improvements are proposals based on measurements and source inspection in this follow-up.

## Verification and remaining scope

Product configuration changes from this follow-up were restored. The request-ID correlation fix was verified with a SpPeerRoundTripTest regression covering the same variant in both modes and deployed to the local verification image. Case definitions and judgment levels are unchanged. HTML/JSON equality before and after execution and the existence of Transcripts referenced by new PASS conclusions were also verified.

Unverified observations remain, including missing automated evaluation that operations alone cannot resolve, tests with insufficient rejection evidence, and attestations requiring operational or configuration support. Completing additional attempts does not establish completion of all tests or whole-product conformance.

## Evidence and regeneration

The operation ledger, configuration backups, before/after result.json files, and test scripts are stored locally in `build/acceptance/reference-20260914/interaction-followup/`. Configuration backups are excluded from publication and commits.

Regenerate: `.venv/bin/python dev/reference-acceptance/generate_interaction_report.py --evidence-root build/acceptance/reference-20260914/interaction-followup`.
