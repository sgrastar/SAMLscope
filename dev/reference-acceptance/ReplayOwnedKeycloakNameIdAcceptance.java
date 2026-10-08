package com.samlscope.api;

import static com.samlscope.api.ReadSyntheticArtifactRuntime.*;
import static com.samlscope.api.ReadOwnedKeycloakNameIdRuntime.*;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.JsonNode;
import com.samlscope.core.casedef.*;
import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.plan.*;
import com.samlscope.core.profile.*;
import com.samlscope.core.run.Reachability;
import com.samlscope.core.transcript.*;
import com.samlscope.runner.PinnedFunctionalCaseDefinitionResolver;
import com.samlscope.runner.cases.IdpErrorProbeConfiguration;
import com.samlscope.runner.cases.IdpNameIdPolicyScenarioTestCase;
import com.samlscope.saml.metadata.TargetMetadataParser;
import com.samlscope.saml.normal.SecureXml;
import com.samlscope.store.JsonCodec;
import java.math.BigDecimal;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.time.*;
import java.util.*;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

/** Offline replay of one owned native campaign. Physical Recorder originals establish the
 * authenticated input; deliberately unsigned in-memory mutants test only the actual case oracle.
 * It neither sends protocol messages nor assigns a Verdict nor adopts a canonical result. */
public final class ReplayOwnedKeycloakNameIdAcceptance {
    static final String RUN = "run_BPEHJD546WG5YJTCRD8F7JRQ1E";
    static final String PLAN = "plan_X6K5P280D25MDRAT2FC73EG1PC";
    static final String GENERATION = "20261008-nameid-r1";
    static final String ISSUER = "http://localhost:18080/p/" + PLAN;
    static final String ACS = ISSUER + "/sp/acs/0";
    static final Set<String> ORIGINAL_FIELDS = Set.of("id", "runId", "direction", "timestamp", "correlationId",
            "method", "url", "status", "contentType", "rawQuery", "summary", "bodyRef", "bodyBytes", "bodyBase64",
            "computedBodySha256", "storedBodySha256", "decodedSamlRef", "decodedSamlBytes", "decodedSamlBase64", "computedDecodedSha256");
    static final JsonCodec CODEC = new JsonCodec();
    static { CODEC.mapper().enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION); }

    record Pair(String fixture, String action, String request, String response) {}
    record Loaded(JsonNode runtime, JsonNode manifest, LinkedHashMap<String,Original> originals,
            String normalRequest, String normalResponse, List<Pair> pairs, List<Map<String,Object>> physical) {}
    record Proof(List<ResponseProof> responses, Map<String,Object> summary) {}

    public static void main(String[] args) throws Exception {
        require(args.length == 4, "Usage: <runtime.json> <portable/manifest.json> <Suite public metadata> <owned target metadata>");
        var loaded = load(Path.of(args[0]), Path.of(args[1]));
        requireCurrentApprovedBoundary();
        byte[] suite = publicFile(Path.of(args[2])), target = publicFile(Path.of(args[3]));
        require(hash(suite).equals(text(loaded.runtime(), "suitePublicMetadataSha256"))
                && hash(target).equals(text(loaded.runtime(), "runMetadataSnapshotSha256")), "Public metadata differs from actual native Run snapshot");
        var proof = authenticated(loaded, suite, target);
        var baseline = replay(loaded, responses(loaded), -1, null);
        require(baseline.outcome() == Outcome.SATISFIED
                && baseline.outcome().name().equals(text(loaded.runtime(), "selectedCaseOutcome"))
                && Objects.equals(baseline.reasonCode(), text(loaded.runtime(), "selectedCaseReasonCode")), "Actual case replay differs from saved outcome");
        requireEvidence(baseline.evidence(), loaded.pairs().stream().map(Pair::response).toList());
        var controls = replayControls(loaded, suite, target);
        var result = new LinkedHashMap<String,Object>();
        result.put("schema", "owned-keycloak-nameid-offline-replay-v1"); result.put("runId", RUN); result.put("planId", PLAN);
        result.put("generation", GENERATION); result.put("caseId", SELECTED); result.put("caseDigest", CASE_DIGEST);
        result.put("definitionIdentity", loaded.runtime().get("definitionIdentity")); result.put("qualificationOutcome", "VERIFIED");
        result.put("replayedCaseOutcome", baseline.outcome().name()); result.put("replayedReasonCode", baseline.reasonCode());
        result.put("replayedEvidenceReferences", baseline.evidence().stream().map(EvidenceRef::reference).toList());
        result.put("portableEvidenceReferences", List.copyOf(loaded.originals().keySet()));
        result.put("normalRequestReference", loaded.normalRequest()); result.put("normalResponseReference", loaded.normalResponse());
        result.put("selectedActionPairs", loaded.runtime().get("selectedActionPairs")); result.put("physicalOriginals", loaded.physical());
        result.put("physicalFileCount", loaded.physical().size()); result.put("authenticatedOriginalCount", loaded.originals().size());
        result.put("nativeProtocolProof", proof.summary()); result.put("controls", controls); result.put("controlsPassed", controls.size());
        result.put("approvedBaselineFixture", "idp-core-no-ecp"); result.put("approvedMutantFixture", "mut-iip-idp10-d-idp");
        result.put("semanticMutantsAreUnsignedInMemoryOracleInputs", true); result.put("mutantsAreNotProductProtocolObservations", true);
        result.put("suitePublicMetadataSha256", hash(suite)); result.put("runMetadataSnapshotSha256", hash(target));
        result.put("runtimeSha256", hash(readBoundFile(Path.of(args[0]), 2 * MAX_EXPORTED)));
        result.put("portableManifestSha256", hash(readBoundFile(Path.of(args[1]), MAX_ORIGINAL)));
        result.put("browserOriginalsAvailable", false); result.put("browserByteEqualityClaimed", false);
        result.put("canonicalAdoption", false); result.put("wholeRunConformance", "NOT_QUALIFIED");
        result.put("protocolSubmissions", 0); result.put("databaseReads", 0); result.put("privateKeyReads", 0);
        System.out.println(CODEC.write(result));
    }

    static void requireCurrentApprovedBoundary() {
        var documents = CatalogDocuments.load(); var releases = FunctionalProfileDocuments.load();
        var resolver = new PinnedFunctionalCaseDefinitionResolver(releases.artifacts(), releases.digests(),
                Map.of("tests/coverage.yaml", documents.bytes("tests/coverage.yaml"), "tests/cases.yaml", documents.bytes("tests/cases.yaml"),
                        "tests/predicates.yaml", documents.bytes("tests/predicates.yaml")),
                CaseDefinitionCatalogMapper.fromDocument(documents.parsed("tests/cases.yaml")),
                CoverageCatalogMapper.fromDocument(documents.parsed("tests/coverage.yaml")));
        var identity = resolver.identity(FunctionalProfile.BROWSER_SSO_IDP); requireIdentity(identity);
        requireApprovedCase(only(resolver.resolve(identity).cases().stream().filter(c -> SELECTED.equals(c.id())).toList(), "approved NameID case"));
    }

    static Loaded load(Path runtimeFile, Path manifestFile) throws Exception {
        JsonNode runtime = json(runtimeFile, 2 * MAX_EXPORTED), manifest = json(manifestFile, MAX_ORIGINAL);
        requireScope(runtime, manifest);
        var rawOriginals = array(runtime, "transcriptOriginals", 8); var manifestOriginals = array(manifest, "originals", 8);
        var originals = new LinkedHashMap<String,Original>(); var physical = new ArrayList<Map<String,Object>>();
        var seenFiles = new HashSet<String>(); long total = 0;
        Path directory = manifestFile.toAbsolutePath().getParent();
        for (int i = 0; i < 8; i++) {
            JsonNode raw = rawOriginals.get(i), portable = manifestOriginals.get(i); exactFields(raw, ORIGINAL_FIELDS);
            String id = text(raw, "id"); require(id.matches("tx_[0-9A-HJKMNP-TV-Z]{26}") && RUN.equals(text(raw, "runId"))
                    && id.equals(text(portable, "reference")) && RUN.equals(text(portable, "runId")), "Original row/Run or portable ordering differs");
            byte[] body = bytes(raw, "bodyBase64"), decoded = bytes(raw, "decodedSamlBase64");
            require(body.length == integer(raw, "bodyBytes") && decoded.length == integer(raw, "decodedSamlBytes") && decoded.length > 0
                    && hash(body).equals(text(raw, "computedBodySha256")) && hash(decoded).equals(text(raw, "computedDecodedSha256"))
                    && publicXml(decoded), "Exported original bytes/size/hash or public XML differs");
            total += body.length + decoded.length; require(total <= MAX_EXPORTED, "Original export exceeds bound");
            String bodyRef = nullableText(raw, "bodyRef"), decodedRef = text(raw, "decodedSamlRef");
            String prefix = "transcripts/" + RUN + "/" + id;
            require((bodyRef == null ? body.length == 0 : bodyRef.equals(prefix + ".body")) && decodedRef.equals(prefix + ".saml.xml")
                    && Objects.equals(bodyRef, nullableText(portable, "nativeBodyReference"))
                    && decodedRef.equals(text(portable, "nativeDecodedReference")), "Native physical reference escapes exact Run/row");
            String stored = nullableText(raw, "storedBodySha256"); require(stored == null || hash(body).equals(stored), "Stored body hash contradicts original");
            var summary = CODEC.mapper().convertValue(raw.get("summary"), Map.class);
            require(summary != null && !summary.containsKey("headers") && !summary.containsKey("Authorization") && !summary.containsKey("Cookie"), "Original summary is not public");
            var entry = new TranscriptEntry(id, RUN, Direction.valueOf(text(raw, "direction")), instant(raw.get("timestamp")),
                    text(raw, "correlationId"), text(raw, "method"), text(raw, "url"), nullableInteger(raw, "status"), Map.of(),
                    bodyRef, body.length, decodedRef, decoded.length, nullableText(raw, "contentType"), nullableText(raw, "rawQuery"), summary);
            require(originals.putIfAbsent(id, new Original(entry, body, decoded)) == null, "Duplicate original reference");
            JsonNode files = portable.get("physical"); require(files != null && files.isObject(), "Portable physical original absent");
            var expected = new HashSet<>(Set.of("body", "decoded")); if (entry.rawQuery() != null) expected.add("query"); exactFields(files, expected);
            physical(directory, files.get("body"), id + ".body", body, seenFiles, physical);
            physical(directory, files.get("decoded"), id + ".saml.xml", decoded, seenFiles, physical);
            if (entry.rawQuery() != null) physical(directory, files.get("query"), id + ".query.txt", entry.rawQuery().getBytes(StandardCharsets.UTF_8), seenFiles, physical);
        }
        String normalRequest = text(runtime, "normalRequestReference"), normalResponse = text(runtime, "normalResponseReference");
        var pairNodes = array(runtime, "selectedActionPairs", 3); var pairs = new ArrayList<Pair>();
        var expectedOrder = new ArrayList<String>(List.of(normalRequest, normalResponse)); var actions = new HashSet<String>();
        for (int i = 0; i < 3; i++) {
            var node = pairNodes.get(i); exactFields(node, Set.of("fixtureId", "actionId", "requestReference", "responseReference"));
            var pair = new Pair(text(node, "fixtureId"), text(node, "actionId"), text(node, "requestReference"), text(node, "responseReference"));
            require(pair.fixture().equals(FIXTURES.get(i)) && pair.action().matches("action_[a-f0-9]{32}") && actions.add(pair.action()), "Fixture order or distinct action identity differs");
            pairs.add(pair); expectedOrder.add(pair.request()); expectedOrder.add(pair.response());
        }
        require(expectedOrder.equals(List.copyOf(originals.keySet())) && expectedOrder.equals(strings(runtime, "portableEvidenceReferences", 8))
                && new HashSet<>(expectedOrder).size() == 8 && physical.size() == 17,
                "Exactly eight ordered normal/scenario originals and seventeen physical files required");
        require(pairs.stream().map(Pair::response).toList().equals(strings(runtime, "selectedCaseEvidence", 3)), "Stored case evidence differs from native responses");
        return new Loaded(runtime, manifest, originals, normalRequest, normalResponse, List.copyOf(pairs), List.copyOf(physical));
    }

    static void requireScope(JsonNode runtime, JsonNode manifest) {
        require("owned-keycloak-nameid-native-v1".equals(text(runtime, "schema")) && "runtime".equals(text(runtime, "mode"))
                && RUN.equals(text(runtime, "runId")) && PLAN.equals(text(runtime, "planId")) && GENERATION.equals(text(runtime, "generation"))
                && SELECTED.equals(text(runtime, "caseId")) && CASE_DIGEST.equals(text(runtime, "caseDigest")) && TARGET.equals(text(runtime, "targetEntityId")), "Foreign runtime scope");
        var identity = runtime.get("definitionIdentity"); require(identity != null && "browser_sso_idp".equals(text(identity, "profile"))
                && VERSION.equals(text(identity, "version")) && PROFILE_DIGEST.equals(text(identity, "digest")), "Foreign functional identity");
        require("VERIFIED".equals(text(runtime, "qualificationOutcome")) && "SATISFIED".equals(text(runtime, "selectedCaseOutcome"))
                && bool(runtime, "selectedRegisteredScenarioProven") && bool(runtime, "nativeRequiredRequestShapesProven")
                && !bool(runtime, "canonicalAdoption") && "NOT_QUALIFIED".equals(text(runtime, "wholeRunConformance")), "Native source not qualified or falsely adopted");
        require("owned-keycloak-nameid-native-portable-v1".equals(text(manifest, "schema")) && RUN.equals(text(manifest, "runId"))
                && PLAN.equals(text(manifest, "planId")) && SELECTED.equals(text(manifest, "caseId")) && CASE_DIGEST.equals(text(manifest, "caseDigest"))
                && "SATISFIED".equals(text(manifest, "actualSuiteOutcome")) && "PASS".equals(text(manifest, "centralVerdict"))
                && integer(manifest, "selectedOriginalCount") == 8 && !bool(manifest, "browserOriginalsAvailable")
                && !bool(manifest, "browserByteEqualityClaimed") && !bool(manifest, "canonicalAdoption"), "Foreign portable manifest or unsupported browser claim");
    }

    static Proof authenticated(Loaded loaded, byte[] suiteMetadata, byte[] targetMetadata) throws Exception {
        var originals = loaded.originals(); var normalRequest = entry(loaded, loaded.normalRequest()); var normalResponse = entry(loaded, loaded.normalResponse());
        var normal = saml(originals, normalRequest); var suite = suiteEntity(suiteMetadata, PLAN, ISSUER); var suiteCerts = certificates(suite);
        require(registeredAcsZero(suite, ACS), "Suite registered ACS zero differs");
        var target = new TargetMetadataParser().parse(targetMetadata, TARGET); var targetCerts = target.signingCertificates();
        require(!targetCerts.isEmpty() && target.singleSignOnServices().stream().anyMatch(e -> SSO.equals(e.location().toASCIIString()) && POST.equals(e.binding())), "Owned target signing key or POST endpoint unavailable");
        require(normal.getAttribute("ID").equals(normalRequest.correlationId()) && ISSUER.equals(single(normal, A, "Issuer").getTextContent())
                && ACS.equals(normal.getAttribute("AssertionConsumerServiceURL")) && SSO.equals(normal.getAttribute("Destination"))
                && endpoint(normalRequest.url()).equals(SSO) && !normalRequest.samlSummary().containsKey("scenario_case_id")
                && Boolean.TRUE.equals(normalResponse.samlSummary().get("normalFlowAccepted"))
                && !normalResponse.timestamp().isBefore(normalRequest.timestamp()), "Normal M0 identity, acceptance, order, issuer, or ACS differs");
        verifyRequest(originals, normalRequest, suiteCerts, true);
        require(verifyResponse(originals, normalResponse, normal, TARGET, targetCerts, ISSUER, ACS, null).success(), "Normal native Success unavailable");
        Instant previous = normalResponse.timestamp(); var proofs = new ArrayList<ResponseProof>();
        for (var pair : loaded.pairs()) {
            var request = entry(loaded, pair.request()); var response = entry(loaded, pair.response()); var authn = saml(originals, request);
            require(pair.action().equals(request.correlationId()) && SELECTED.equals(request.samlSummary().get("scenario_case_id"))
                    && pair.fixture().equals(request.samlSummary().get("fixture_id")) && pair.action().equals(request.samlSummary().get("action_id"))
                    && authn.getAttribute("ID").equals("_" + pair.action()) && ISSUER.equals(single(authn, A, "Issuer").getTextContent())
                    && SSO.equals(authn.getAttribute("Destination")) && SSO.equals(request.url()) && ACS.equals(authn.getAttribute("AssertionConsumerServiceURL"))
                    && Boolean.TRUE.equals(response.samlSummary().get("activeProbeAccepted"))
                    && !request.timestamp().isBefore(previous) && !response.timestamp().isBefore(request.timestamp()), "Formal action, acceptance, timestamp, issuer, request ID or ACS differs");
            requirePolicy(authn, pair.fixture(), ISSUER); verifyRequest(originals, request, suiteCerts, false);
            proofs.add(verifyResponse(originals, response, authn, TARGET, targetCerts, ISSUER, ACS, pair.fixture())); previous = response.timestamp();
        }
        requireOutcomeExplained(Outcome.SATISFIED, proofs);
        return new Proof(List.copyOf(proofs), Map.of("normalRedirectSignatureVerified", true, "formalRequestSignaturesVerified", 3,
                "responseSignaturesVerified", 4, "assertionSignaturesVerified", 4, "sameRunOrderedActionsVerified", true,
                "actualPublicCertificateRelationshipVerified", true, "responsePolicyProofs", proofs.stream().map(ResponseProof::export).toList()));
    }

    static CaseOutcome replay(Loaded loaded, List<byte[]> responses, int unavailable, String unavailableReason) {
        require(responses.size() == 3, "Exactly three replay inputs required");
        var configuration = new IdpErrorProbeConfiguration(URI.create(SSO), ISSUER, URI.create(ACS), Duration.ofMinutes(2), true, true, true);
        var test = new IdpNameIdPolicyScenarioTestCase(SELECTED, configuration); var context = new ReplayContext();
        context.at = issueInstant(loaded, 0); CaseStep step = test.start(context);
        for (int i = 0; i < 3; i++) {
            require(step instanceof CaseStep.AwaitInbound, "Actual NameID scenario did not await each fixture"); var waiting = (CaseStep.AwaitInbound) step;
            var pair = loaded.pairs().get(i); require(waiting.actions().size() == 1 && pair.fixture().equals(waiting.next().data().get("fixture_id"))
                    && pair.action().equals(waiting.actions().getFirst().actionId())
                    && ("_" + pair.action()).equals(waiting.next().data().get("expected_response_correlation")), "Actual registered scenario action or fixture differs from native operation");
            var generated = SecureXml.parse(waiting.actions().getFirst().payload()).getDocumentElement();
            require(sameRequestTree(generated, saml(loaded.originals(), entry(loaded, pair.request()))), "Captured signed request differs from actual fixture request semantics");
            context.at = i + 1 < 3 ? issueInstant(loaded, i + 1) : entry(loaded, pair.response()).timestamp();
            CaseEvent event = i == unavailable ? new CaseEvent.InboundUnavailable(unavailableReason)
                    : new CaseEvent.InboundMessage(responses.get(i), new EvidenceRef("transcript", pair.response()));
            step = test.resume(context, waiting.next(), event);
        }
        require(step instanceof CaseStep.Finish, "Actual NameID scenario did not finish exactly three fixtures"); return ((CaseStep.Finish) step).outcome();
    }

    static final class ReplayContext implements CaseContext {
        Instant at;
        @Override public String runId() { return RUN; }
        @Override public TargetRole targetRole() { return TargetRole.IDP; }
        @Override public Clock clock() { return Clock.fixed(at, ZoneOffset.UTC); }
        @Override public TestPlan.Parameters parameters() { return null; }
        @Override public TestPlan.Interaction interaction() { return TestPlan.Interaction.defaults(); }
        @Override public Reachability reachability() { return null; }
        @Override public TranscriptRecorder transcript() { return null; }
        @Override public boolean transcriptComplete() { return false; }
    }

    static List<Map<String,Object>> replayControls(Loaded loaded, byte[] suite, byte[] target) throws Exception {
        var checks = new ArrayList<Map<String,Object>>();
        semantic(checks, loaded, "approved-positive-all-three-native-responses", -1, null, Outcome.SATISFIED);
        semantic(checks, loaded, "approved-mutant-default-format-ignores-persistent-policy", 1, "wrong-format", Outcome.VIOLATED);
        semantic(checks, loaded, "transient-format-mismatch", 0, "wrong-format", Outcome.VIOLATED);
        semantic(checks, loaded, "explicit-foreign-SPNameQualifier", 2, "foreign-qualifier", Outcome.VIOLATED);
        semantic(checks, loaded, "implicit-qualifier-foreign-audience", 2, "foreign-audience", Outcome.NOT_VERIFIED);
        semantic(checks, loaded, "implicit-qualifier-missing-audience", 2, "missing-audience", Outcome.NOT_VERIFIED);
        semantic(checks, loaded, "implicit-qualifier-wrong-Destination", 2, "wrong-destination", Outcome.NOT_VERIFIED);
        semantic(checks, loaded, "missing-subject-NameID", 1, "missing-nameid", Outcome.NOT_VERIFIED);
        semantic(checks, loaded, "foreign-request-InResponseTo", 1, "foreign-correlation", Outcome.NOT_VERIFIED);
        semantic(checks, loaded, "non-SAML-response", 0, "non-saml", Outcome.NOT_VERIFIED);
        for (int i = 0; i < 3; i++) {
            var outcome = replay(loaded, responses(loaded), i, "no-native-protocol-response"); require(outcome.outcome() == Outcome.NOT_VERIFIED, "Missing response incorrectly concludes");
            checks.add(control("unavailable-" + FIXTURES.get(i), "case-oracle-in-memory", Outcome.NOT_VERIFIED.name(), outcome.outcome().name()));
        }
        for (int i = 0; i < 8; i++) {
            String reference = List.copyOf(loaded.originals().keySet()).get(i); var original = loaded.originals().get(reference);
            var replaced = new LinkedHashMap<>(loaded.originals());
            if (i == 0) {
                var entry = original.entry(); var query = fields(entry.rawQuery()); String signature = query.get("Signature");
                String changedSignature = (signature.startsWith("A") ? "B" : "A") + signature.substring(1);
                String encoded = java.net.URLEncoder.encode(changedSignature, StandardCharsets.UTF_8);
                String rawQuery = entry.rawQuery().replaceFirst("(?<=Signature=)[^&]+", encoded);
                var changedEntry = new TranscriptEntry(entry.id(), entry.runId(), entry.direction(), entry.timestamp(), entry.correlationId(), entry.method(),
                        SSO + "?" + rawQuery, entry.status(), Map.of(), entry.bodyRef(), entry.bodyBytes(), entry.decodedSamlRef(), entry.decodedSamlBytes(), entry.contentType(), rawQuery, entry.samlSummary());
                replaced.put(reference, new Original(changedEntry, original.body(), original.decoded()));
            } else {
                var root = SecureXml.parse(original.decoded()).getDocumentElement(); var signature = single(single(root, DS, "Signature"), DS, "SignatureValue");
                String value = signature.getTextContent(); signature.setTextContent((value.startsWith("A") ? "B" : "A") + value.substring(1));
                byte[] changed = SecureXml.serialize(root.getOwnerDocument());
                String field = original.entry().direction() == Direction.OUTBOUND ? "SAMLRequest" : "SAMLResponse";
                byte[] form = (field + "=" + java.net.URLEncoder.encode(base64(changed), StandardCharsets.UTF_8)).getBytes(StandardCharsets.UTF_8);
                replaced.put(reference, new Original(original.entry(), form, changed));
            }
            var mutant = new Loaded(loaded.runtime(), loaded.manifest(), replaced, loaded.normalRequest(), loaded.normalResponse(), loaded.pairs(), loaded.physical());
            reject(checks, "authenticated-original-tamper-" + i, () -> authenticated(mutant, suite, target));
        }
        reject(checks, "foreign-native-target-public-key", () -> authenticated(loaded, suite, replaceCertificates(target, suite)));
        reject(checks, "foreign-suite-public-key", () -> authenticated(loaded, replaceCertificates(suite, target), target));
        return List.copyOf(checks);
    }

    static byte[] replaceCertificates(byte[] metadata, byte[] other) {
        var document = SecureXml.parse(metadata); var certificates = document.getElementsByTagNameNS(DS, "X509Certificate");
        var foreign = SecureXml.parse(other).getElementsByTagNameNS(DS, "X509Certificate"); require(certificates.getLength() > 0 && foreign.getLength() > 0, "Public certificate control unavailable");
        String replacement = foreign.item(0).getTextContent(); for (int i = 0; i < certificates.getLength(); i++) certificates.item(i).setTextContent(replacement);
        return SecureXml.serialize(document);
    }

    static void semantic(List<Map<String,Object>> checks, Loaded loaded, String id, int index, String mutation, Outcome expected) {
        var inputs = new ArrayList<>(responses(loaded)); if (index >= 0) inputs.set(index, mutate(inputs.get(index), mutation));
        var outcome = replay(loaded, inputs, -1, null); require(outcome.outcome() == expected, "Actual case semantic control failed: " + id);
        checks.add(control(id, "case-oracle-in-memory", expected.name(), outcome.outcome().name()));
    }
    static byte[] mutate(byte[] xml, String mutation) {
        if ("non-saml".equals(mutation)) return "<not-saml/>".getBytes(StandardCharsets.UTF_8);
        var document = SecureXml.parse(xml); var response = document.getDocumentElement();
        var assertion = single(response, A, "Assertion"); var subject = single(assertion, A, "Subject"); var name = single(subject, A, "NameID");
        switch (mutation) {
            case "wrong-format" -> name.setAttribute("Format", TRANSIENT.equals(name.getAttribute("Format")) ? PERSISTENT : TRANSIENT);
            case "foreign-qualifier" -> name.setAttribute("SPNameQualifier", "https://foreign.example/sp");
            case "foreign-audience" -> single(single(single(assertion, A, "Conditions"), A, "AudienceRestriction"), A, "Audience").setTextContent("https://foreign.example/sp");
            case "missing-audience" -> { var conditions = single(assertion, A, "Conditions"); for (var restriction : children(conditions, A, "AudienceRestriction")) conditions.removeChild(restriction); }
            case "wrong-destination" -> response.setAttribute("Destination", "https://foreign.example/acs");
            case "missing-nameid" -> subject.removeChild(name);
            case "foreign-correlation" -> response.setAttribute("InResponseTo", "_foreign_request");
            default -> throw new IllegalArgumentException("Unknown in-memory oracle mutation");
        }
        return SecureXml.serialize(document);
    }
    interface Check { void run() throws Exception; }
    static void reject(List<Map<String,Object>> checks, String id, Check check) throws Exception {
        try { check.run(); } catch (IllegalArgumentException | com.samlscope.saml.normal.SamlException rejected) { checks.add(control(id, "authenticated-native-proof", "REJECTED", "REJECTED")); return; }
        throw new IllegalArgumentException("Native proof accepted corrupted input: " + id);
    }
    static Map<String,Object> control(String id, String layer, String expected, String observed) { return Map.of("id", id, "layer", layer, "expected", expected, "observed", observed, "passed", true); }
    static List<byte[]> responses(Loaded loaded) { return loaded.pairs().stream().map(p -> loaded.originals().get(p.response()).decoded().clone()).toList(); }
    static TranscriptEntry entry(Loaded loaded, String ref) { var value = loaded.originals().get(ref); require(value != null, "Missing exact original"); return value.entry(); }
    static Instant issueInstant(Loaded loaded, int index) { return Instant.parse(saml(loaded.originals(), entry(loaded, loaded.pairs().get(index).request())).getAttribute("IssueInstant")); }

    static boolean sameRequestTree(Element left, Element right) {
        if (!Objects.equals(left.getNamespaceURI(), right.getNamespaceURI()) || !Objects.equals(left.getLocalName(), right.getLocalName())
                || !attributes(left).equals(attributes(right))) return false;
        var a = requestChildren(left); var b = requestChildren(right); if (a.size() != b.size()) return false;
        for (int i = 0; i < a.size(); i++) {
            Node x = a.get(i), y = b.get(i);
            if (x instanceof Element xe && y instanceof Element ye) { if (!sameRequestTree(xe, ye)) return false; }
            else if (x instanceof Element || y instanceof Element || !Objects.equals(x.getTextContent(), y.getTextContent())) return false;
        }
        return true;
    }
    static Map<String,String> attributes(Element value) {
        var attributes = new TreeMap<String,String>(); for (int i = 0; i < value.getAttributes().getLength(); i++) {
            var attribute = value.getAttributes().item(i); if (!"http://www.w3.org/2000/xmlns/".equals(attribute.getNamespaceURI()))
                attributes.put(String.valueOf(attribute.getNamespaceURI()) + "|" + attribute.getNodeName(), attribute.getNodeValue());
        } return attributes;
    }
    static List<Node> requestChildren(Element value) {
        var children = new ArrayList<Node>(); for (Node n = value.getFirstChild(); n != null; n = n.getNextSibling()) {
            if (n instanceof Element e && DS.equals(e.getNamespaceURI()) && "Signature".equals(e.getLocalName())) continue;
            if (!(n instanceof Element) && n.getTextContent().isBlank()) continue; children.add(n);
        } return children;
    }
    static void physical(Path directory, JsonNode field, String expected, byte[] bytes, Set<String> seen, List<Map<String,Object>> output) throws Exception {
        exactFields(field, Set.of("file", "bytes", "sha256")); require(expected.equals(text(field, "file")) && seen.add(expected)
                && integer(field, "bytes") == bytes.length && hash(bytes).equals(text(field, "sha256")), "Portable physical file/hash scope differs");
        byte[] stored = readBoundFile(directory.resolve(expected), MAX_ORIGINAL); require(Arrays.equals(stored, bytes), "Physical file differs from Recorder export bytes");
        output.add(Map.of("file", expected, "bytes", bytes.length, "sha256", hash(bytes)));
    }
    static byte[] readBoundFile(Path path, long maximum) throws Exception {
        Path absolute = path.toAbsolutePath(); require(absolute.equals(absolute.normalize()), "Noncanonical public evidence path"); rejectSymlinkAncestors(absolute);
        require(Files.isRegularFile(absolute, LinkOption.NOFOLLOW_LINKS) && Files.size(absolute) <= maximum, "Public evidence file unavailable or oversized");
        long size = Files.size(absolute); try (var stream = Files.newInputStream(absolute, LinkOption.NOFOLLOW_LINKS)) {
            byte[] bytes = stream.readNBytes((int) maximum + 1); require(bytes.length == size && bytes.length <= maximum, "Public evidence file changed or exceeded bound"); return bytes;
        }
    }
    static JsonNode json(Path file, long maximum) throws Exception {
        try (var parser = CODEC.mapper().createParser(readBoundFile(file, maximum))) {
            JsonNode value = CODEC.mapper().readTree(parser); require(value != null && value.isObject() && parser.nextToken() == null, "Public evidence must be one complete JSON object"); return value;
        }
    }
    static void exactFields(JsonNode node, Set<String> fields) { require(node != null && node.isObject(), "Expected public evidence object"); var actual = new HashSet<String>(); node.fieldNames().forEachRemaining(actual::add); require(actual.equals(fields), "Unexpected or missing public evidence field"); }
    static String text(JsonNode node, String field) { JsonNode value = node == null ? null : node.get(field); require(value != null && value.isTextual() && !value.textValue().isBlank(), "Missing text field: " + field); return value.textValue(); }
    static String nullableText(JsonNode node, String field) { JsonNode value = node.get(field); require(value != null, "Missing nullable field: " + field); return value.isNull() ? null : text(node, field); }
    static int integer(JsonNode node, String field) { JsonNode value = node.get(field); require(value != null && value.isIntegralNumber() && value.canConvertToInt() && value.intValue() >= 0 && value.intValue() <= MAX_ORIGINAL, "Invalid integer field: " + field); return value.intValue(); }
    static Integer nullableInteger(JsonNode node, String field) { JsonNode value = node.get(field); require(value != null, "Missing nullable integer"); return value.isNull() ? null : integer(node, field); }
    static boolean bool(JsonNode node, String field) { JsonNode value = node.get(field); require(value != null && value.isBoolean(), "Missing boolean field: " + field); return value.booleanValue(); }
    static JsonNode array(JsonNode node, String field, int size) { JsonNode value = node.get(field); require(value != null && value.isArray() && value.size() == size, "Array count differs: " + field); return value; }
    static List<String> strings(JsonNode node, String field, int size) { var list = array(node, field, size); var values = new ArrayList<String>(); for (var value : list) { require(value.isTextual() && !value.textValue().isBlank(), "Invalid text array"); values.add(value.textValue()); } return List.copyOf(values); }
    static byte[] bytes(JsonNode node, String field) { JsonNode value = node.get(field); require(value != null && value.isTextual() && value.textValue().length() <= 2 * MAX_ORIGINAL, "Invalid original encoding"); byte[] decoded = Base64.getDecoder().decode(value.textValue()); require(Base64.getEncoder().encodeToString(decoded).equals(value.textValue()) && decoded.length <= MAX_ORIGINAL, "Noncanonical original encoding"); return decoded; }
    static Instant instant(JsonNode value) { require(value != null && value.isNumber(), "Original timestamp missing"); BigDecimal seconds = value.decimalValue(); long whole = seconds.longValue(); long nanos = seconds.subtract(BigDecimal.valueOf(whole)).movePointRight(9).longValueExact(); return Instant.ofEpochSecond(whole, nanos); }
}
