package com.samlscope.api;

import static com.samlscope.api.ReadSyntheticArtifactRuntime.*;
import static com.samlscope.api.ReadOwnedKeycloakNameIdRuntime.*;

import com.samlscope.core.evaluation.EvidenceRef;
import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.Outcome;
import com.samlscope.core.plan.*;
import com.samlscope.core.profile.*;
import com.samlscope.core.run.*;
import com.samlscope.core.transcript.*;
import com.samlscope.saml.binding.SignedRedirectEncoder;
import com.samlscope.saml.crypto.*;
import com.samlscope.saml.normal.SecureXml;
import com.samlscope.store.JsonCodec;
import java.math.BigInteger;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.time.Instant;
import java.util.*;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.w3c.dom.Element;

/** Pure signed in-memory and temporary public-file controls; no actual Run, DB, or native product claims. */
public final class OwnedKeycloakNameIdReaderControls {
    static final String RUN = "run_00000000000000000000000000", OTHER_RUN = "run_11111111111111111111111111";
    static final String PLAN = "plan_00000000000000000000000000", GENERATION = "pure-controls";
    static final String TX = "tx_00000000000000000000000000";
    static final String ISSUER = "http://localhost:18080/p/" + PLAN, ACS = ISSUER + "/sp/acs/0";
    static final Instant AT = Instant.parse("2026-10-08T00:00:00Z");
    static final List<Map<String,Object>> CHECKS = new ArrayList<>();
    interface Check { void run() throws Exception; }
    static void accept(String id, Check check) throws Exception { check.run(); CHECKS.add(Map.of("id", id, "expected", "accepted", "passed", true)); }
    static void reject(String id, Check check) throws Exception {
        try { check.run(); } catch (IllegalArgumentException expected) { CHECKS.add(Map.of("id", id, "expected", "rejected", "passed", true)); return; }
        throw new IllegalStateException("Forbidden control accepted: " + id);
    }

    public static void main(String[] args) throws Exception {
        require(args.length == 0, "No arguments; controls cannot read an actual Run");
        scopeControls(); headerControls(); evidenceControls(); deliveryControls(); fileControls(); protocolControls();
        var output = new LinkedHashMap<String,Object>(); output.put("schema", "owned-keycloak-nameid-reader-controls-v1");
        output.put("checks", CHECKS); output.put("checksPassed", CHECKS.size()); output.put("networkOperations", 0);
        output.put("databaseReads", 0); output.put("databaseWrites", 0); output.put("actualSuiteProof", false);
        output.put("nativeProductOperations", 0); output.put("privateKeyReads", 0); output.put("privateKeysPersisted", false);
        output.put("canonicalAdoption", false); output.put("approvedControlReplayReplaced", false);
        System.out.println(new JsonCodec().write(output));
    }

    static TestPlan plan(String name, String entity, FunctionalDefinitionIdentity identity) {
        return new TestPlan(PLAN, name, FunctionalProfile.BROWSER_SSO_IDP, identity,
                new TestPlan.Target(TargetKind.IDP, entity, new TestPlan.MetadataSource(MetadataSourceKind.URL, TARGET + "/protocol/saml/descriptor")),
                MetadataDeliveryKind.MANUAL, Map.of(), new TestPlan.Parameters(180, 300, "", TestPlan.RequestSigningMode.REQUIRED),
                TestPlan.Interaction.defaults(), AT, AT);
    }

    static void scopeControls() throws Exception {
        var identity = new FunctionalDefinitionIdentity(FunctionalProfile.BROWSER_SSO_IDP, VERSION, PROFILE_DIGEST);
        var run = new TestRun(RUN, PLAN, RunStatus.CREATED, Reachability.UNKNOWN, Map.of(), AT, AT);
        var owned = plan("Owned Keycloak public-CI NameID v2 " + GENERATION, TARGET, identity);
        accept("exact-explicit-owned-v2-scope", () -> requireBoundScope(run, owned, RUN, GENERATION));
        reject("different-requested-run", () -> requireBoundScope(run, owned, OTHER_RUN, GENERATION));
        reject("different-generation", () -> requireBoundScope(run, owned, RUN, "another-generation"));
        reject("different-plan-binding", () -> requireBoundScope(new TestRun(RUN, "plan_11111111111111111111111111", RunStatus.CREATED, Reachability.UNKNOWN, Map.of(), AT, AT), owned, RUN, GENERATION));
        reject("foreign-native-target", () -> requireBoundScope(run, plan(owned.name(), "http://localhost:18180/realms/samlscope", identity), RUN, GENERATION));
        reject("foreign-plan-name", () -> requireBoundScope(run, plan("Existing product NameID Run", TARGET, identity), RUN, GENERATION));
        reject("v1-is-never-aliased-to-v2", () -> requireBoundScope(run, plan(owned.name(), TARGET,
                new FunctionalDefinitionIdentity(FunctionalProfile.BROWSER_SSO_IDP, "functional-case-v1", PROFILE_DIGEST)), RUN, GENERATION));
        reject("wrong-v2-digest", () -> requireIdentity(new FunctionalDefinitionIdentity(FunctionalProfile.BROWSER_SSO_IDP, VERSION, "sha256:" + "0".repeat(64))));
    }

    static TranscriptEntry entry(String run, Direction direction, String method, String url, String correlation,
            Map<String,List<String>> headers, byte[] body, byte[] xml, String query, Map<String,Object> summary) {
        return new TranscriptEntry(TX, run, direction, AT, correlation, method, url, direction == Direction.INBOUND ? 200 : null,
                headers, body.length == 0 ? null : "transcripts/" + run + "/" + TX + ".body", body.length,
                xml.length == 0 ? null : "transcripts/" + run + "/" + TX + ".saml.xml", xml.length,
                "application/x-www-form-urlencoded", query, summary);
    }

    static TranscriptEntry headerEntry(String run, Direction direction, String method, String type, Map<String,List<String>> headers) {
        return entry(run, direction, method, ACS, "_request", headers, new byte[0], new byte[0], null, Map.of("type", type));
    }

    static void headerControls() throws Exception {
        var headers = Map.of("Cookie", List.of("samlscope_session=<redacted: 80 bytes>; empty=<redacted: 0 bytes>"), "Content-Type", List.of("application/x-www-form-urlencoded"));
        var response = headerEntry(RUN, Direction.INBOUND, "POST", "Response", headers);
        accept("typed-same-run-irreversible-cookie-metadata-only", () -> {
            var clean = nativeHeaderProjection(response, RUN);
            require(clean.equals(Map.of("Content-Type", List.of("application/x-www-form-urlencoded"))) && headers.containsKey("Cookie")
                    && response.headers().equals(headers), "Projection changed stored metadata or retained cookies");
        });
        reject("cookie-from-wrong-run", () -> nativeHeaderProjection(response, OTHER_RUN));
        reject("cookie-on-outbound-request", () -> nativeHeaderProjection(headerEntry(RUN, Direction.OUTBOUND, "POST", "AuthnRequest", headers), RUN));
        reject("cookie-on-wrong-http-method", () -> nativeHeaderProjection(headerEntry(RUN, Direction.INBOUND, "GET", "Response", headers), RUN));
        reject("cookie-on-untyped-inbound-entry", () -> nativeHeaderProjection(headerEntry(RUN, Direction.INBOUND, "POST", "Other", headers), RUN));
        var invalids = new LinkedHashMap<String,Map<String,List<String>>>();
        invalids.put("raw-cookie", Map.of("Cookie", List.of("samlscope_session=secret-control-value")));
        invalids.put("partially-redacted-cookie", Map.of("Cookie", List.of("session=<redacted: 80 bytes>; other=raw")));
        invalids.put("malformed-redaction", Map.of("Cookie", List.of("session=<redacted: bytes>")));
        invalids.put("negative-redaction-length", Map.of("Cookie", List.of("session=<redacted: -1 bytes>")));
        invalids.put("oversized-redaction-length", Map.of("Cookie", List.of("session=<redacted: 1048577 bytes>")));
        invalids.put("duplicate-cookie-name", Map.of("Cookie", List.of("session=<redacted: 80 bytes>; session=<redacted: 80 bytes>")));
        invalids.put("multiple-cookie-header-values", Map.of("Cookie", List.of("session=<redacted: 80 bytes>", "other=<redacted: 80 bytes>")));
        invalids.put("case-colliding-cookie-fields", Map.of("Cookie", List.of("session=<redacted: 80 bytes>"), "cOoKiE", List.of("other=<redacted: 80 bytes>")));
        invalids.put("duplicate-public-header-fields", Map.of("Content-Type", List.of("text/xml"), "content-type", List.of("text/xml")));
        invalids.put("authorization-even-if-redacted", Map.of("Authorization", List.of("<redacted: Basic, 80 bytes>")));
        invalids.put("proxy-authorization-even-if-redacted", Map.of("Proxy-Authorization", List.of("<redacted: Basic, 80 bytes>")));
        invalids.put("set-cookie-even-if-redacted", Map.of("Set-Cookie", List.of("session=<redacted: 80 bytes>")));
        invalids.put("header-name-injection", Map.of("Content-Type\r\nCookie", List.of("text/xml")));
        invalids.put("header-value-injection", Map.of("Content-Type", List.of("text/xml\r\nCookie: raw")));
        for (var invalid : invalids.entrySet()) reject(invalid.getKey(), () -> nativeHeaderProjection(headerEntry(RUN, Direction.INBOUND, "POST", "Response", invalid.getValue()), RUN));
    }

    static void deliveryControls() throws Exception {
        var action = new OutboundAction("action_" + "1".repeat(32), OutboundKind.AUTHN_REQUEST, "<AuthnRequest/>".getBytes(StandardCharsets.UTF_8), URI.create(SSO), false);
        var accepted = new OutboxEntry(RUN, SELECTED, action, OutboxStatus.SENT, Map.of("confirmed_by", "inbound-response"), "response", AT, AT);
        accept("actual-inbound-confirmation-binds-response-not-request", () -> require(confirmedBrowserDelivery(accepted, "request", "response"), "delivery"));
        for (var status : List.of(OutboxStatus.UNKNOWN_DELIVERY, OutboxStatus.SENDING, OutboxStatus.PENDING)) {
            var incomplete = new OutboxEntry(RUN, SELECTED, action, status, accepted.sendResult(), "response", AT, AT);
            reject("delivery-" + status.name().toLowerCase(Locale.ROOT), () -> require(confirmedBrowserDelivery(incomplete, "request", "response"), "delivery"));
        }
        for (var reference : List.of("request", "foreign-response")) {
            var wrong = new OutboxEntry(RUN, SELECTED, action, OutboxStatus.SENT, accepted.sendResult(), reference, AT, AT);
            reject("delivery-wrong-" + reference, () -> require(confirmedBrowserDelivery(wrong, "request", "response"), "delivery"));
        }
        var unproven = new OutboxEntry(RUN, SELECTED, action, OutboxStatus.SENT, Map.of("transport", "browser-front-channel"), "response", AT, AT);
        reject("delivery-without-confirmation-source", () -> require(confirmedBrowserDelivery(unproven, "request", "response"), "delivery"));
        reject("delivery-request-response-alias", () -> require(confirmedBrowserDelivery(accepted, "response", "response"), "delivery"));
    }

    static void evidenceControls() throws Exception {
        var refs = List.of("response-1", "response-2", "response-3");
        var evidence = refs.stream().map(id -> new EvidenceRef("transcript", id)).toList();
        accept("exact-three-distinct-response-evidence", () -> requireEvidence(evidence, refs));
        reject("missing-response-evidence", () -> requireEvidence(evidence.subList(0, 2), refs));
        reject("extra-response-evidence", () -> requireEvidence(List.of(evidence.getFirst(), evidence.get(1), evidence.getLast(), new EvidenceRef("transcript", "extra")), refs));
        reject("duplicate-response-evidence", () -> requireEvidence(List.of(evidence.getFirst(), evidence.getFirst(), evidence.getLast()), refs));
        reject("foreign-response-evidence", () -> requireEvidence(List.of(evidence.getFirst(), evidence.get(1), new EvidenceRef("transcript", "wrong-response")), refs));
        reject("non-transcript-evidence", () -> requireEvidence(List.of(evidence.getFirst(), evidence.get(1), new EvidenceRef("file", "response-3")), refs));
        var match = new ResponseProof(true, false, false, false); var mismatch = new ResponseProof(true, true, false, false);
        accept("stored-satisfied-explained-by-three-authenticated-matches", () -> requireOutcomeExplained(Outcome.SATISFIED, List.of(match, match, match)));
        accept("stored-violated-explained-by-authenticated-explicit-mismatch", () -> requireOutcomeExplained(Outcome.VIOLATED, List.of(match, mismatch, match)));
        reject("stored-satisfied-cannot-hide-signed-mismatch", () -> requireOutcomeExplained(Outcome.SATISFIED, List.of(match, mismatch, match)));
        reject("stored-violated-cannot-be-inferred-from-three-matches", () -> requireOutcomeExplained(Outcome.VIOLATED, List.of(match, match, match)));
        reject("uncertain-stored-outcome-is-never-promoted", () -> requireOutcomeExplained(Outcome.NOT_VERIFIED, List.of(match, match, match)));
        reject("missing-authenticated-response-never-explains-outcome", () -> requireOutcomeExplained(Outcome.SATISFIED, List.of(match, match)));
    }

    static void fileControls() throws Exception {
        Path root = Files.createTempDirectory(Path.of("/private/tmp"), "owned-nameid-reader-public-controls-").toRealPath();
        try {
            byte[] xml = xml("<p:Response xmlns:p='" + P + "' ID='_public' Version='2.0'/>");
            var e = entry(RUN, Direction.INBOUND, "POST", ACS, "_request", Map.of(), form("SAMLResponse", xml), xml, null, Map.of("type", "Response"));
            Files.createDirectories(root.resolve("transcripts").resolve(RUN)); Files.write(root.resolve(e.bodyRef()), form("SAMLResponse", xml)); Files.write(root.resolve(e.decodedSamlRef()), xml);
            accept("exact-physical-owned-originals-and-twenty-field-export", () -> {
                var original = readOriginal(root, e); var exported = original.export();
                require(exported.size() == 20 && !exported.containsKey("headers") && Arrays.equals(original.decoded(), xml)
                        && exported.get("computedDecodedSha256").equals(hash(xml)), "Original export schema, bytes, or hashes differ");
            });
            reject("different-run-original-reference", () -> readReference(root, e, "transcripts/" + OTHER_RUN + "/" + TX + ".body", e.bodyBytes(), false));
            reject("different-row-original-reference", () -> readReference(root, e, "transcripts/" + RUN + "/tx_11111111111111111111111111.body", e.bodyBytes(), false));
            reject("declared-original-size-mismatch", () -> readReference(root, e, e.bodyRef(), e.bodyBytes() - 1, false));
            reject("body-reference-as-decoded-original", () -> readReference(root, e, e.bodyRef(), e.decodedSamlBytes(), true));
            Path linked = root.resolve("linked-root"); Files.createSymbolicLink(linked, root.resolve("transcripts"));
            reject("symlink-ancestor-is-not-a-public-original", () -> rejectSymlinkAncestors(linked.resolve(RUN).resolve(TX + ".body")));
            Files.write(root.resolve(e.decodedSamlRef()), new byte[xml.length + 1]);
            reject("physical-original-size-changed", () -> readOriginal(root, e));
        } finally { try (var paths = Files.walk(root)) { for (var path : paths.sorted(Comparator.reverseOrder()).toList()) Files.delete(path); } }
    }

    static void protocolControls() throws Exception {
        var suite = credentials("pure Suite public reader control"); var target = credentials("pure native response reader control");
        var suiteCerts = List.of(suite.certificate()); var targetCerts = List.of(target.certificate());
        byte[] normalBytes = request(null, suite); var encoded = new SignedRedirectEncoder().encode(URI.create(SSO), normalBytes, RUN, suite);
        var normal = entry(RUN, Direction.OUTBOUND, "GET", encoded.destination().toASCIIString(), "_request", Map.of(), new byte[0], encoded.decodedXml(), encoded.rawQuery(), Map.of("type", "AuthnRequest"));
        var normalOriginals = Map.of(normal.id(), new Original(normal, new byte[0], encoded.decodedXml()));
        accept("normal-raw-query-redirect-signature", () -> verifyRequest(normalOriginals, normal, suiteCerts, true));
        var changedRaw = encoded.rawQuery().replace("RelayState=" + RUN, "RelayState=" + OTHER_RUN);
        var changedNormal = entry(RUN, Direction.OUTBOUND, "GET", SSO + "?" + changedRaw, "_request", Map.of(), new byte[0], encoded.decodedXml(), changedRaw, Map.of("type", "AuthnRequest"));
        reject("modified-redirect-query-octets", () -> verifyRequest(Map.of(TX, new Original(changedNormal, new byte[0], encoded.decodedXml())), changedNormal, suiteCerts, true));
        reject("foreign-normal-signing-certificate", () -> verifyRequest(normalOriginals, normal, targetCerts, true));
        for (String fixture : FIXTURES) {
            byte[] authnBytes = request(fixture, suite); var authn = SecureXml.parse(authnBytes).getDocumentElement();
            var outbound = entry(RUN, Direction.OUTBOUND, "POST", SSO, "action", Map.of(), form("SAMLRequest", authnBytes), authnBytes, null, Map.of("type", "AuthnRequest"));
            var requestOriginals = Map.of(TX, new Original(outbound, form("SAMLRequest", authnBytes), authnBytes));
            accept("actual-signed-post-request-" + fixture, () -> { requirePolicy(authn, fixture, ISSUER); verifyRequest(requestOriginals, outbound, suiteCerts, false); });
            for (String change : List.of("wrong-request-format", "wrong-request-qualifier", "wrong-allow-create", "wrong-protocol-binding")) {
                var doc = SecureXml.parse(authnBytes); var changed = doc.getDocumentElement(); var policy = single(changed, P, "NameIDPolicy");
                switch (change) {
                    case "wrong-request-format" -> policy.setAttribute("Format", "urn:foreign:format");
                    case "wrong-request-qualifier" -> policy.setAttribute("SPNameQualifier", "urn:foreign:sp");
                    case "wrong-allow-create" -> policy.setAttribute("AllowCreate", fixture.equals("format-persistent") ? "false" : "true");
                    case "wrong-protocol-binding" -> changed.setAttribute("ProtocolBinding", "urn:foreign:binding");
                }
                reject(change + "-" + fixture, () -> requirePolicy(changed, fixture, ISSUER));
            }
            byte[] response = response(fixture, target, null); var incoming = responseEntry(response, ACS, "_request");
            accept("authenticated-native-success-" + fixture, () -> {
                var proof = verifyResponse(originals(incoming, response), incoming, authn, TARGET, targetCerts, ISSUER, ACS, fixture);
                require(proof.success() && !proof.policyMismatch() && (fixture.equals("sp-name-qualifier") == proof.implicitSameSpProven()), "Matching policy proof differs");
            });
            byte[] explicit = response(fixture, target, "explicit-qualifier"); var explicitEntry = responseEntry(explicit, ACS, "_request");
            accept("explicit-same-sp-qualification-" + fixture, () -> require(!verifyResponse(originals(explicitEntry, explicit), explicitEntry, authn, TARGET, targetCerts, ISSUER, ACS, fixture).policyMismatch(), "Explicit same-SP mismatch"));
            byte[] wrongFormat = response(fixture, target, "wrong-format"); var wrongFormatEntry = responseEntry(wrongFormat, ACS, "_request");
            accept("authenticated-format-mismatch-is-observation-only-" + fixture, () -> require(verifyResponse(originals(wrongFormatEntry, wrongFormat), wrongFormatEntry, authn, TARGET, targetCerts, ISSUER, ACS, fixture).formatMismatch(), "Signed format mismatch hidden"));
            for (String change : List.of("wrong-response-request", "wrong-response-entity", "wrong-response-destination", "missing-nameid", "encrypted-nameid", "encrypted-assertion", "nameid-in-advice", "missing-assertion-signature", "missing-response-signature", "duplicate-xml-id")) {
                byte[] altered = response(fixture, target, change); var alteredEntry = responseEntry(altered, ACS, "_request");
                reject(change + "-" + fixture, () -> verifyResponse(originals(alteredEntry, altered), alteredEntry, authn, TARGET, targetCerts, ISSUER, ACS, fixture));
            }
            reject("wrong-native-certificate-" + fixture, () -> verifyResponse(originals(incoming, response), incoming, authn, TARGET, suiteCerts, ISSUER, ACS, fixture));
            var otherAcs = responseEntry(response, ISSUER + "/sp/acs/1", "_request");
            reject("wrong-recorded-acs-" + fixture, () -> verifyResponse(originals(otherAcs, response), otherAcs, authn, TARGET, targetCerts, ISSUER, ACS, fixture));
            var otherCorrelation = responseEntry(response, ACS, "_foreign");
            reject("wrong-recorded-correlation-" + fixture, () -> verifyResponse(originals(otherCorrelation, response), otherCorrelation, authn, TARGET, targetCerts, ISSUER, ACS, fixture));
            reject("raw-post-body-differs-" + fixture, () -> verifyResponse(Map.of(TX, new Original(incoming, form("SAMLResponse", xml("<other/>")), response)), incoming, authn, TARGET, targetCerts, ISSUER, ACS, fixture));
            byte[] corrupted = response.clone(); var corruptedDoc = SecureXml.parse(corrupted); single(single(corruptedDoc.getDocumentElement(), A, "Assertion"), A, "Subject").getElementsByTagNameNS(A, "NameID").item(0).setTextContent("changed-after-signing"); corrupted = SecureXml.serialize(corruptedDoc);
            final byte[] untrusted = corrupted; var corruptedEntry = responseEntry(untrusted, ACS, "_request");
            reject("signature-uncertainty-" + fixture, () -> verifyResponse(originals(corruptedEntry, untrusted), corruptedEntry, authn, TARGET, targetCerts, ISSUER, ACS, fixture));
            for (String error : List.of("Requester", "Responder")) {
                byte[] reply = response(fixture, target, "error-" + error); var errorEntry = responseEntry(reply, ACS, "_request");
                accept("authenticated-explicit-" + error.toLowerCase(Locale.ROOT) + "-" + fixture,
                        () -> require(!verifyResponse(originals(errorEntry, reply), errorEntry, authn, TARGET, targetCerts, ISSUER, ACS, fixture).success(), "Explicit error misidentified as success"));
            }
            if (fixture.equals("sp-name-qualifier")) {
                byte[] mismatch = response(fixture, target, "wrong-qualifier"); var mismatchEntry = responseEntry(mismatch, ACS, "_request");
                accept("authenticated-explicit-qualifier-mismatch-is-observation-only", () -> require(verifyResponse(originals(mismatchEntry, mismatch), mismatchEntry, authn, TARGET, targetCerts, ISSUER, ACS, fixture).explicitSpNameQualifierMismatch(), "Signed explicit qualifier mismatch hidden"));
                for (String uncertainty : List.of("missing-audience", "foreign-audience", "mixed-audience", "other-assertion-audience", "empty-audience", "opaque-nameid-format")) {
                    byte[] reply = response(fixture, target, uncertainty); var unknownEntry = responseEntry(reply, ACS, "_request");
                    reject("implicit-qualification-" + uncertainty, () -> verifyResponse(originals(unknownEntry, reply), unknownEntry, authn, TARGET, targetCerts, ISSUER, ACS, fixture));
                }
            }
        }
        reject("raw-body-credential-field", () -> requireForm(xml("SAMLResponse=YWJj&password=control"), xml("abc"), "SAMLResponse"));
        reject("duplicate-raw-body-message", () -> requireForm(xml("SAMLResponse=YWJj&SAMLResponse=YWJj"), xml("abc"), "SAMLResponse"));
        reject("public-original-private-material", () -> require(publicXml(xml("-----BEGIN PRIVATE KEY-----")), "Private material is not public SAML"));
    }

    static byte[] request(String fixture, PlanCredentials suite) {
        String policy = fixture == null ? "" : "<p:NameIDPolicy Format='" + (fixture.equals("format-persistent") ? PERSISTENT : TRANSIENT)
                + "'" + (fixture.equals("sp-name-qualifier") ? " SPNameQualifier='" + ISSUER + "'" : "")
                + (fixture.equals("format-persistent") ? " AllowCreate='true'" : "") + "/>";
        var document = SecureXml.parse(xml("<p:AuthnRequest xmlns:p='" + P + "' xmlns:a='" + A + "' ID='_request' Version='2.0' IssueInstant='" + AT
                + "' Destination='" + SSO + "' AssertionConsumerServiceURL='" + ACS + "' ProtocolBinding='" + POST + "'><a:Issuer>" + ISSUER + "</a:Issuer>" + policy + "</p:AuthnRequest>"));
        new XmlSigner().sign(document.getDocumentElement(), suite, fixture == null ? null : single(document.getDocumentElement(), P, "NameIDPolicy"));
        return SecureXml.serialize(document);
    }

    static byte[] response(String fixture, PlanCredentials target, String change) {
        String format = fixture.equals("format-persistent") ? PERSISTENT : TRANSIENT;
        String qualifier = "explicit-qualifier".equals(change) || (fixture.equals("sp-name-qualifier") && "wrong-format".equals(change))
                ? " SPNameQualifier='" + ISSUER + "'" : "wrong-qualifier".equals(change) ? " SPNameQualifier='urn:foreign:sp'" : "";
        if ("wrong-format".equals(change)) format = "urn:foreign:format";
        if ("opaque-nameid-format".equals(change)) format = "";
        String subject = "<a:NameID Format='" + format + "'" + qualifier + ">pure-public-nameid-control</a:NameID>";
        if (Set.of("missing-nameid", "nameid-in-advice").contains(String.valueOf(change))) subject = "";
        if ("encrypted-nameid".equals(change)) subject = "<a:EncryptedID/>";
        String audience = "<a:AudienceRestriction><a:Audience>" + ISSUER + "</a:Audience></a:AudienceRestriction>";
        if (Set.of("missing-audience", "other-assertion-audience").contains(String.valueOf(change))) audience = "";
        if ("empty-audience".equals(change)) audience = "<a:AudienceRestriction/>";
        if ("foreign-audience".equals(change)) audience = "<a:AudienceRestriction><a:Audience>urn:foreign:sp</a:Audience></a:AudienceRestriction>";
        if ("mixed-audience".equals(change)) audience += "<a:AudienceRestriction><a:Audience>urn:foreign:sp</a:Audience></a:AudienceRestriction>";
        String advice = "nameid-in-advice".equals(change) ? "<a:Advice><a:NameID Format='" + format + "'>unrelated</a:NameID></a:Advice>"
                : "other-assertion-audience".equals(change) ? "<a:Advice><a:Assertion ID='_unrelated' Version='2.0'><a:Conditions><a:AudienceRestriction><a:Audience>" + ISSUER + "</a:Audience></a:AudienceRestriction></a:Conditions></a:Assertion></a:Advice>" : "";
        boolean error = change != null && change.startsWith("error-"); String status = error ? "urn:oasis:names:tc:SAML:2.0:status:" + change.substring(6) : SUCCESS;
        String assertion = error ? "" : "<a:Assertion ID='_assertion' Version='2.0' IssueInstant='" + AT
                + "'><a:Issuer>" + TARGET + "</a:Issuer><a:Subject>" + subject + "</a:Subject><a:Conditions>" + audience + "</a:Conditions>" + advice + "</a:Assertion>";
        if ("encrypted-assertion".equals(change)) assertion = "<a:EncryptedAssertion/>";
        String xml = "<p:Response xmlns:p='" + P + "' xmlns:a='" + A + "' ID='_response' Version='2.0' IssueInstant='" + AT
                + "' InResponseTo='" + ("wrong-response-request".equals(change) ? "_foreign" : "_request") + "' Destination='"
                + ("wrong-response-destination".equals(change) ? ISSUER + "/sp/acs/1" : ACS) + "'><a:Issuer>"
                + ("wrong-response-entity".equals(change) ? "urn:foreign:idp" : TARGET) + "</a:Issuer><p:Status><p:StatusCode Value='" + status + "'/></p:Status>" + assertion + "</p:Response>";
        var document = SecureXml.parse(xml(xml)); var root = document.getDocumentElement(); var signer = new XmlSigner();
        if (!children(root, A, "Assertion").isEmpty() && !"missing-assertion-signature".equals(change)) signer.sign(single(root, A, "Assertion"), target, single(single(root, A, "Assertion"), A, "Subject"));
        if (!"missing-response-signature".equals(change)) signer.sign(root, target, single(root, P, "Status"));
        if ("duplicate-xml-id".equals(change)) single(root, A, "Assertion").setAttribute("ID", "_response");
        return SecureXml.serialize(document);
    }

    static TranscriptEntry responseEntry(byte[] response, String acs, String correlation) {
        return entry(RUN, Direction.INBOUND, "POST", acs, correlation, Map.of(), form("SAMLResponse", response), response, null, Map.of("type", "Response"));
    }
    static Map<String,Original> originals(TranscriptEntry entry, byte[] response) { return Map.of(entry.id(), new Original(entry, form("SAMLResponse", response), response)); }
    static byte[] form(String message, byte[] bytes) { return xml(message + "=" + URLEncoder.encode(Base64.getEncoder().encodeToString(bytes), StandardCharsets.UTF_8)); }
    static byte[] xml(String value) { return value.getBytes(StandardCharsets.UTF_8); }

    static PlanCredentials credentials(String label) throws Exception {
        if (Security.getProvider("BC") == null) Security.addProvider(new BouncyCastleProvider());
        var generator = KeyPairGenerator.getInstance("RSA"); generator.initialize(2048); var pair = generator.generateKeyPair();
        var name = new X500Name("CN=" + label); var now = Instant.now();
        var builder = new JcaX509v3CertificateBuilder(name, new BigInteger(128, new SecureRandom()).abs(), Date.from(now.minusSeconds(60)), Date.from(now.plusSeconds(3600)), name, pair.getPublic());
        var cert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(builder.build(new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC").build(pair.getPrivate())));
        return new PlanCredentials(pair.getPrivate(), cert);
    }
}
