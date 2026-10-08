package com.samlscope.api;

import com.samlscope.core.casedef.*;
import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.plan.*;
import com.samlscope.core.profile.FunctionalProfile;
import com.samlscope.core.run.TestRun;
import com.samlscope.core.transcript.*;
import com.samlscope.runner.PinnedFunctionalCaseDefinitionResolver;
import com.samlscope.runner.cases.ArtifactBindingEvidence;
import com.samlscope.runner.outbox.ArtifactResolutionOutboundSender;
import com.samlscope.saml.artifact.*;
import com.samlscope.saml.binding.RedirectSignatureVerifier;
import com.samlscope.saml.crypto.XmlSignatureVerifier;
import com.samlscope.saml.metadata.TargetMetadataParser;
import com.samlscope.saml.normal.SecureXml;
import com.samlscope.store.JsonCodec;
import java.io.ByteArrayInputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.cert.*;
import java.sql.*;
import java.time.Instant;
import java.util.*;
import org.w3c.dom.Element;

/** Read-only, bounded public-original export for the owned synthetic Artifact qualification. */
public final class ReadSyntheticArtifactRuntime {
    static final String CASE = "IIP-IDP12-f-idp-01";
    static final String DIGEST = "sha256:1ef44e75e3fb37fc82a1a240b477490e15a5ecadc6471015f684e62cb12409d1";
    static final String MD = SamlArtifact.MD, P = ArtifactResolutionProtocol.P;
    static final String A = ArtifactResolutionProtocol.A, DS = ArtifactResolutionProtocol.DS;
    static final String ARTIFACT = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact";
    static final String POST = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";
    static final Set<String> VARIANTS = Set.of("IIP-IDP12.f#v-506e90c9bf", "IIP-IDP12.f#v-5d97fd0b51",
            "IIP-IDP12.f#v-d52d921b7f", "IIP-IDP12.f#v-d7fa7792d4");
    static final Set<String> PUBLIC_TYPES = Set.of("AuthnRequest", "Response", "ArtifactReceived", "ArtifactResolve", "ArtifactResponse");
    static final int MAX_ORIGINAL = 1024 * 1024, MAX_ENTRIES = 10000;
    static final long MAX_EXPORTED = 16L * 1024 * 1024;

    public static void main(String[] args) throws Exception {
        if (args.length == 1 && "--self-check".equals(args[0])) { selfCheck(); return; }
        require((args.length == 3 || args.length == 4) && args[1].matches("run_[0-9A-HJKMNP-TV-Z]{26}")
                && Set.of("scope", "runtime").contains(args[2]), "Usage: <data root> <bound Run> scope|runtime [suite-public-metadata.xml]");
        Path suppliedRoot = Path.of(args[0]).toAbsolutePath(); require(suppliedRoot.equals(suppliedRoot.normalize()), "Noncanonical data root"); rejectSymlinkAncestors(suppliedRoot); Path data = suppliedRoot.toRealPath();
        require(Files.isRegularFile(data.resolve("samlscope.db"), LinkOption.NOFOLLOW_LINKS), "Bound database unavailable");
        var codec = new JsonCodec(); var result = new LinkedHashMap<String,Object>();
        try (var db = readOnlyDatabase(data.resolve("samlscope.db"))) {
            TestRun run = codec.read(single(db, "SELECT document_json FROM runs WHERE id=?", args[1]), TestRun.class);
            TestPlan plan = codec.read(single(db, "SELECT document_json FROM plans WHERE id=?", run.planId()), TestPlan.class);
            require(run.id().equals(args[1]) && run.planId().equals(plan.id()) && plan.profile() == FunctionalProfile.BROWSER_SSO_IDP
                    && plan.target().kind() == TargetKind.IDP && plan.definitionIdentity() != null
                    && plan.name().startsWith("Synthetic artifact runtime "), "Run is outside owned synthetic scope");
            URI entity = URI.create(plan.target().entityId());
            require(Set.of("http://host.docker.internal:18937/signed/entity", "http://host.docker.internal:18937/unsigned/entity")
                    .contains(entity.toASCIIString()), "Target entity is outside owned synthetic scope");
            String fixtureMode = entity.getPath().split("/")[1];
            var documents = CatalogDocuments.load(); var releases = FunctionalProfileDocuments.load();
            var definitions = CaseDefinitionCatalogMapper.fromDocument(documents.parsed("tests/cases.yaml"));
            var coverage = CoverageCatalogMapper.fromDocument(documents.parsed("tests/coverage.yaml"));
            var resolver = new PinnedFunctionalCaseDefinitionResolver(releases.artifacts(), releases.digests(),
                    Map.of("tests/coverage.yaml", documents.bytes("tests/coverage.yaml"), "tests/cases.yaml", documents.bytes("tests/cases.yaml"),
                            "tests/predicates.yaml", documents.bytes("tests/predicates.yaml")), definitions, coverage);
            var membership = resolver.resolve(plan.definitionIdentity()).cases();
            var selected = membership.stream().filter(c -> CASE.equals(c.id())).toList();
            require(selected.size() == 1, "Approved case absent from actual pinned Plan membership");
            var slot = selected.getFirst();
            require(DIGEST.equals(slot.caseDigest()) && slot.role() == TargetRole.IDP
                    && slot.mode() == CaseDefinitionCatalog.ExecutionMode.BROWSER && slot.milestone() == CaseDefinitionCatalog.Milestone.M1
                    && Set.copyOf(slot.coversVariants()).equals(VARIANTS) && slot.controls().size() == 2,
                    "Approved case boundary differs");
            require(slot.controls().stream().anyMatch(c -> "iip-idp12-f-idp-01-positive".equals(c.id())
                    && "idp-core-no-ecp".equals(c.fixture())) && slot.controls().stream().anyMatch(c ->
                    "iip-idp12-f-idp-01-negative".equals(c.id()) && "mut-iip-idp12-f-idp".equals(c.fixture())), "Approved controls differ");
            result.put("schema", "samlscope-synthetic-artifact-runtime-v1"); result.put("mode", args[2]);
            result.put("runId", run.id()); result.put("planId", plan.id()); result.put("runStatus", run.status());
            result.put("profile", plan.profile().id()); result.put("targetEntityId", plan.target().entityId());
            result.put("fixtureMode", fixtureMode); result.put("definitionIdentity", plan.definitionIdentity());
            result.put("approvedCase", slot); result.put("actualPinnedCaseIds", membership.stream().map(CaseDefinitionCatalog.CaseDefinition::id).toList());
            result.put("databaseAccess", "read-only-query-only"); result.put("productEvidenceAdoption", false);
            result.put("protocolSubmissionsByReader", 0); result.put("privateKeyReads", 0);
            var execution = optional(db, "SELECT document_json FROM case_executions WHERE run_id=? AND case_id=?", run.id(), CASE);
            var outbox = outbox(db, codec, run.id());
            if ("scope".equals(args[2])) {
                require(execution.isEmpty() && outbox.isEmpty(), "Scope export requires case not started");
                result.put("caseStarted", false); result.put("resultGenerated", false); result.put("outbox", List.of());
            } else {
                CaseExecution stored = execution.map(value -> codec.read(value, CaseExecution.class)).orElse(null);
                if (stored != null) require(run.id().equals(stored.runId()) && CASE.equals(stored.caseId()), "Execution is outside bound Run");
                result.put("caseStarted", stored != null); result.put("caseExecution", stored); result.put("outbox", outbox);
                var entries = entries(db, codec, run.id());
                var diagnostics = new ArrayList<String>(); var originals = new LinkedHashMap<String,Original>();
                long total = 0;
                for (var entry : entries) {
                    if (!PUBLIC_TYPES.contains(String.valueOf(entry.samlSummary().get("type")))) continue;
                    try {
                        var original = readOriginal(data, entry); total += original.body().length + original.decoded().length;
                        require(total <= MAX_EXPORTED, "Original export exceeds bounded size"); originals.put(entry.id(), original);
                    } catch (Exception missing) { diagnostics.add("Original unavailable or unproven: " + entry.id()); }
                }
                result.put("transcriptOriginals", originals.values().stream().map(Original::export).toList());
                result.put("exportedOriginalBytes", total); result.put("noCredentialOrCookieHeaders", true);
                result.put("originalExportComplete", originals.size() == entries.stream().filter(e -> PUBLIC_TYPES.contains(String.valueOf(e.samlSummary().get("type")))).count());
                var proof = new LinkedHashMap<String,Object>(); boolean verified = false;
                try {
                    byte[] metadata = publicFile(data.resolve("target-metadata").resolve(run.id() + ".xml"));
                    require(args.length == 4, "Public Suite metadata required for Plan certificate relationship");
                    byte[] suiteMetadata = publicFile(Path.of(args[3]));
                    proof.put("runMetadataSnapshotSha256", hash(metadata)); proof.put("runMetadataSnapshotBase64", base64(metadata));
                    proof.put("suitePublicMetadataSha256", hash(suiteMetadata)); proof.put("suitePublicMetadataBase64", base64(suiteMetadata));
                    var certificates = new TargetMetadataParser().parse(metadata, plan.target().entityId()).signingCertificates();
                    require(!certificates.isEmpty(), "Target signing certificate absent");
                    var normal = only(entries.stream().filter(e -> e.direction() == Direction.INBOUND
                            && Boolean.TRUE.equals(e.samlSummary().get("normalFlowAccepted"))).toList(), "M0 normal response");
                    var normalXml = saml(originals, normal);
                    var normalRequest = only(entries.stream().filter(e -> e.direction() == Direction.OUTBOUND
                            && "AuthnRequest".equals(e.samlSummary().get("type"))
                            && Objects.equals(e.correlationId(), normal.correlationId())).toList(), "M0 AuthnRequest");
                    var normalAuthn = saml(originals, normalRequest);
                    String suiteIssuer = single(normalAuthn, A, "Issuer").getTextContent();
                    var suiteEntity = suiteEntity(suiteMetadata, plan.id(), suiteIssuer);
                    var suiteCertificates = certificates(suiteEntity);
                    X509Certificate suiteCertificate = suiteOriginalCertificate(originals, suiteCertificates);
                    require(matches(suiteCertificate, suiteCertificates)
                            && plan.parameters().requestSigningMode() == TestPlan.RequestSigningMode.REQUIRED
                            && "GET".equals(normalRequest.method()) && normalRequest.rawQuery() != null
                            && Objects.equals(URI.create(normalRequest.url()).getRawQuery(), normalRequest.rawQuery())
                            && new RedirectSignatureVerifier().isValidForMessage(normalRequest.rawQuery(), suiteCertificate, original(originals, normalRequest).decoded()),
                            "M0 Suite Redirect signature relationship unproven");
                    require(P.equals(normalXml.getNamespaceURI()) && "Response".equals(normalXml.getLocalName())
                            && "2.0".equals(normalXml.getAttribute("Version")) && normalAuthn.getAttribute("ID").equals(normalXml.getAttribute("InResponseTo"))
                            && plan.target().entityId().equals(single(normalXml, A, "Issuer").getTextContent())
                            && normalXml.getAttribute("Destination").equals(normalAuthn.getAttribute("AssertionConsumerServiceURL"))
                            && registeredAcs(suiteEntity, normalXml.getAttribute("Destination"), POST)
                            && certificates.stream().anyMatch(c -> new XmlSignatureVerifier().hasValidEnvelopedSignature(normalXml, c))
                            && ArtifactResolutionProtocol.SUCCESS.equals(status(normalXml)), "M0 target response unproven");
                    require(normalXml.getElementsByTagNameNS(A, "Assertion").getLength() == 1, "M0 Assertion unavailable");
                    proof.put("normalResponseReference", normal.id()); proof.put("normalResponseOuterSignatureVerified", true);
                    proof.put("normalAuthnRequestRedirectSignatureVerified", true);
                    proof.put("normalAssertionCoveredByOuterSignature", true); proof.put("suiteCertificateSha256", hash(suiteCertificate.getEncoded()));
                    proof.put("suiteCertificateMatchesPlanPublicMetadata", true);
                    var artifact = artifactProof(run, plan, fixtureMode, entries, originals, outbox, metadata, certificates, suiteEntity, suiteCertificate);
                    proof.putAll(artifact); verified = true;
                } catch (Exception missing) { diagnostics.add("Runtime proof unavailable: " + safeMessage(missing)); }
                if (stored == null || stored.status() != CaseExecutionStatus.FINISHED) diagnostics.add("Case has not finished");
                else if (stored.outcome().outcome() == Outcome.NOT_VERIFIED) diagnostics.add("Stored case is NOT_VERIFIED: " + stored.outcome().notVerifiedReason());
                result.put("runtimeProof", proof); result.put("runtimeProofVerified", verified);
                result.put("storedOutcome", stored == null || stored.outcome() == null ? "NOT_VERIFIED" : stored.outcome().outcome().name());
                result.put("qualificationOutcome", verified && diagnostics.isEmpty() && stored != null && stored.status() == CaseExecutionStatus.FINISHED
                        && stored.outcome().outcome() == Outcome.SATISFIED ? "VERIFIED" : "NOT_VERIFIED");
                result.put("diagnostics", diagnostics);
            }
        }
        System.out.println(codec.write(result));
    }

    static Map<String,Object> artifactProof(TestRun run, TestPlan plan, String mode, List<TranscriptEntry> entries,
            Map<String,Original> originals, List<OutboxEntry> outbox, byte[] metadata, List<X509Certificate> targetCertificates,
            Element suiteEntity, X509Certificate suiteCertificate) throws Exception {
        String authnAction = ActionIds.derive(run.id(), CASE, ArtifactBindingEvidence.PHASE, 0);
        String resolveAction = ActionIds.derive(run.id(), CASE, ArtifactResolutionOutboundSender.PHASE, 0);
        var authn = only(entries.stream().filter(e -> e.direction() == Direction.OUTBOUND && authnAction.equals(e.correlationId())).toList(), "Artifact AuthnRequest");
        var authnXml = saml(originals, authn); String issuer = single(authnXml, A, "Issuer").getTextContent();
        URI acs = URI.create(authnXml.getAttribute("AssertionConsumerServiceURL"));
        require(CASE.equals(authn.samlSummary().get("scenario_case_id")) && "artifact-binding".equals(authn.samlSummary().get("fixture_id"))
                && authnAction.equals(authn.samlSummary().get("action_id")) && P.equals(authnXml.getNamespaceURI())
                && "AuthnRequest".equals(authnXml.getLocalName()) && ("_" + authnAction).equals(authnXml.getAttribute("ID"))
                && "2.0".equals(authnXml.getAttribute("Version")) && ARTIFACT.equals(authnXml.getAttribute("ProtocolBinding"))
                && !authnXml.hasAttribute("AssertionConsumerServiceIndex") && registeredAcs(suiteEntity, acs.toString(), ARTIFACT)
                && suiteEntity.getAttribute("entityID").equals(issuer) && matches(originalCertificate(authnXml), List.of(suiteCertificate))
                && new XmlSignatureVerifier().hasValidEnvelopedSignature(authnXml, suiteCertificate), "Artifact AuthnRequest unbound");
        var received = only(entries.stream().filter(e -> e.direction() == Direction.INBOUND && authnAction.equals(e.correlationId())
                && "ArtifactReceived".equals(e.samlSummary().get("type"))).toList(), "Artifact delivery");
        require(CASE.equals(received.samlSummary().get("scenario_case_id")) && authnAction.equals(received.samlSummary().get("authn_action_id"))
                && hash(metadata).equals(received.samlSummary().get("target_metadata_sha256")) && !received.timestamp().isBefore(authn.timestamp()), "Artifact delivery unbound");
        var delivery = ArtifactBindingEvidence.delivery(received.method(), received.url(), received.contentType(), original(originals, received).body(),
                received.rawQuery(), run.id(), authnAction, acs);
        require(delivery.artifact().sha256().equals(received.samlSummary().get("artifact_sha256")), "Artifact delivery hash differs");
        URI endpoint = delivery.artifact().resolutionEndpoint(metadata, plan.target().entityId());
        require(endpoint.toASCIIString().equals("https://host.docker.internal:18938/" + mode + "/resolve"), "Resolution endpoint outside synthetic scope");
        var action = only(outbox.stream().filter(o -> resolveAction.equals(o.action().actionId())).toList(), "Artifact outbox");
        require(action.status() == OutboxStatus.SENT && action.action().kind() == OutboundKind.ARTIFACT_RESOLVE
                && endpoint.equals(action.action().target()) && !action.action().requiresEphemeralCredential()
                && !action.createdAt().isBefore(received.timestamp()), "Resolution outbox incomplete");
        var request = only(entries.stream().filter(e -> e.direction() == Direction.OUTBOUND && resolveAction.equals(e.correlationId())).toList(), "ArtifactResolve original");
        var response = only(entries.stream().filter(e -> e.direction() == Direction.INBOUND && resolveAction.equals(e.correlationId())
                && "ArtifactResponse".equals(e.samlSummary().get("type"))).toList(), "ArtifactResponse original");
        byte[] requestSoap = original(originals, request).decoded(), responseSoap = original(originals, response).decoded();
        for (var e : List.of(request, response)) require("POST".equals(e.method()) && endpoint.toString().equals(e.url()) && xml(e.contentType())
                && e.rawQuery() == null && CASE.equals(e.samlSummary().get("scenario_case_id")) && resolveAction.equals(e.samlSummary().get("action_id"))
                && Arrays.equals(original(originals, e).body(), original(originals, e).decoded()), "SOAP Recorder originals differ");
        require("ArtifactResolve".equals(request.samlSummary().get("type")) && Arrays.equals(requestSoap, action.action().payload())
                && hash(requestSoap).equals(request.samlSummary().get("request_sha256"))
                && !request.timestamp().isBefore(received.timestamp()) && !response.timestamp().isBefore(request.timestamp())
                && response.id().equals(action.transcriptEntryId()) && Objects.equals(response.status(), 200)
                && Objects.equals(action.sendResult().get("http_status"), 200) && request.id().equals(response.samlSummary().get("request_transcript"))
                && request.id().equals(action.sendResult().get("request_transcript"))
                && hash(responseSoap).equals(response.samlSummary().get("response_sha256"))
                && hash(responseSoap).equals(action.sendResult().get("response_sha256")), "SOAP action/capture correlation unbound");
        var protocol = new ArtifactResolutionProtocol(); var requestXml = protocol.soapMessage(requestSoap, "ArtifactResolve");
        require(matches(originalCertificate(requestXml), List.of(suiteCertificate)), "Resolve Suite certificate differs");
        protocol.verifyResolve(requestSoap, delivery.artifact(), "_" + resolveAction, endpoint, issuer, suiteCertificate);
        require(!Instant.parse(requestXml.getAttribute("IssueInstant")).isAfter(request.timestamp()), "Resolve IssueInstant after capture");
        ArtifactTlsEvidence tls = null; var receipt = action.sendResult().get("transport_authentication");
        if (receipt instanceof Map<?,?> map && receipt.equals(response.samlSummary().get("transport_authentication"))) {
            var captured = new LinkedHashMap<String,Object>();
            for (var item : map.entrySet()) { require(item.getKey() instanceof String, "TLS receipt field invalid"); captured.put((String)item.getKey(), item.getValue()); }
            tls = ArtifactTlsEvidence.verify(captured, run.id(), resolveAction, endpoint, request.id(), response.id(), requestSoap, responseSoap, suiteCertificate).orElse(null);
        }
        var resolved = protocol.verifyResponse(responseSoap, "_" + resolveAction, authnXml.getAttribute("ID"), plan.target().entityId(), acs, targetCertificates, tls);
        require(("signed".equals(mode) && "trusted-xml-signature".equals(resolved.authentication()))
                || ("unsigned".equals(mode) && tls != null && "closed-pkix-hostname-tls".equals(resolved.authentication())), "Expected mode authentication unproven");
        var proof = new LinkedHashMap<String,Object>(); proof.put("artifactAuthnRequestReference", authn.id()); proof.put("artifactDeliveryReference", received.id());
        proof.put("requestSoapReference", request.id()); proof.put("responseSoapReference", response.id()); proof.put("resolveActionId", resolveAction);
        proof.put("resolutionEndpoint", endpoint.toString()); proof.put("artifactSha256", delivery.artifact().sha256());
        proof.put("recommendedSourceIdMapping", delivery.artifact().usesRecommendedSourceId(plan.target().entityId()));
        proof.put("requestSoapSha256", hash(requestSoap)); proof.put("responseSoapSha256", hash(responseSoap));
        proof.put("artifactResponseId", resolved.artifactResponseId()); proof.put("resolvedResponseId", resolved.responseId());
        proof.put("authentication", resolved.authentication()); proof.put("status", resolved.status()); proof.put("tlsReceiptVerified", tls != null);
        proof.put("outerAndInnerCorrelationIssuerAcsVerified", true); proof.put("requestPayloadEqualsBothRecorderOriginals", true);
        proof.put("responseBodyEqualsDecodedOriginal", true); return proof;
    }

    record Original(TranscriptEntry entry, byte[] body, byte[] decoded) {
        Map<String,Object> export() {
            var value = new LinkedHashMap<String,Object>(); value.put("id", entry.id()); value.put("runId", entry.runId());
            value.put("direction", entry.direction()); value.put("timestamp", entry.timestamp()); value.put("correlationId", entry.correlationId());
            value.put("method", entry.method()); value.put("url", entry.url()); value.put("status", entry.status()); value.put("contentType", entry.contentType());
            value.put("rawQuery", entry.rawQuery()); value.put("summary", entry.samlSummary());
            value.put("bodyRef", entry.bodyRef()); value.put("bodyBytes", entry.bodyBytes()); value.put("bodyBase64", base64(body)); value.put("computedBodySha256", hash(body));
            value.put("storedBodySha256", entry.samlSummary().get("body_sha256")); value.put("decodedSamlRef", entry.decodedSamlRef());
            value.put("decodedSamlBytes", entry.decodedSamlBytes()); value.put("decodedSamlBase64", base64(decoded)); value.put("computedDecodedSha256", hash(decoded));
            return value;
        }
    }
    static Original readOriginal(Path data, TranscriptEntry entry) throws Exception {
        byte[] body = readReference(data, entry, entry.bodyRef(), entry.bodyBytes(), false);
        byte[] decoded = readReference(data, entry, entry.decodedSamlRef(), entry.decodedSamlBytes(), true);
        require(!entry.samlSummary().containsKey("body_sha256") || hash(body).equals(entry.samlSummary().get("body_sha256")), "Stored body hash differs");
        if (decoded.length != 0) require(publicXml(decoded), "Original is not public SAML/XML");
        if (Set.of("ArtifactResolve", "ArtifactResponse").contains(String.valueOf(entry.samlSummary().get("type")))) require(publicXml(body), "Original SOAP is not public XML");
        return new Original(entry, body, decoded);
    }
    static byte[] readReference(Path root, TranscriptEntry entry, String reference, int length, boolean decoded) throws Exception {
        require(entry != null && entry.runId().matches("run_[0-9A-HJKMNP-TV-Z]{26}")
                && entry.id().matches("tx_[0-9A-HJKMNP-TV-Z]{26}"), "Original entry identity invalid");
        require(length >= 0 && length <= MAX_ORIGINAL
                && length == (decoded ? entry.decodedSamlBytes() : entry.bodyBytes())
                && Objects.equals(reference, decoded ? entry.decodedSamlRef() : entry.bodyRef()), "Original size/reference differs from entry");
        if (reference == null) { require(length == 0, "Original reference missing"); return new byte[0]; }
        String expected = "transcripts/" + entry.runId() + "/" + entry.id() + (decoded ? ".saml.xml" : ".body");
        require(expected.equals(reference), "Original reference differs from exact bound Run entry");
        Path absoluteRoot = root.toAbsolutePath(); require(absoluteRoot.equals(absoluteRoot.normalize()), "Noncanonical data root"); Path path = absoluteRoot.resolve(expected);
        require(path.startsWith(absoluteRoot), "Original is outside bound data root");
        rejectSymlinkAncestors(path);
        require(Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS) && Files.size(path) == length,
                "Original size/type differs from entry before read");
        try (var stream = Files.newInputStream(path, LinkOption.NOFOLLOW_LINKS)) { byte[] bytes = stream.readNBytes(MAX_ORIGINAL + 1); require(bytes.length == length, "Original size changed during read"); return bytes; }
    }
    static void rejectSymlinkAncestors(Path path) {
        for (Path current = path.toAbsolutePath().normalize(); current != null; current = current.getParent())
            require(!Files.isSymbolicLink(current), "Original reference contains a symbolic link");
    }
    static Connection readOnlyDatabase(Path database) throws Exception {
        Path path = database.toAbsolutePath(); require(path.equals(path.normalize()), "Noncanonical database path"); rejectSymlinkAncestors(path);
        require(Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS), "Bound database unavailable");
        var connection = DriverManager.getConnection("jdbc:sqlite:" + path.toUri().toASCIIString() + "?mode=ro");
        try {
            try (var query = connection.createStatement()) {
                query.execute("PRAGMA query_only=ON");
                try (var rows = query.executeQuery("PRAGMA query_only")) {
                    require(rows.next() && rows.getInt(1) == 1 && !rows.next(), "Read-only query_only guard not enabled");
                }
            }
            return connection;
        } catch (Exception invalid) { connection.close(); throw invalid; }
    }
    static byte[] publicFile(Path path) throws Exception {
        require(path.toAbsolutePath().equals(path.toAbsolutePath().normalize()), "Noncanonical public file path"); rejectSymlinkAncestors(path);
        require(Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS) && Files.size(path) > 0 && Files.size(path) <= MAX_ORIGINAL, "Public XML file unavailable");
        long expectedSize = Files.size(path); try (var stream = Files.newInputStream(path, LinkOption.NOFOLLOW_LINKS)) { byte[] bytes = stream.readNBytes(MAX_ORIGINAL + 1); require(bytes.length == expectedSize && bytes.length <= MAX_ORIGINAL && publicXml(bytes), "Public XML file invalid or changed during read"); return bytes; }
    }
    static boolean publicXml(byte[] bytes) {
        try {
            String text = new String(bytes, StandardCharsets.UTF_8);
            if (!text.stripLeading().startsWith("<") || text.contains("PRIVATE KEY") || text.contains("Authorization") || text.contains("Cookie")) return false;
            var root = SecureXml.parse(bytes).getDocumentElement();
            return (P.equals(root.getNamespaceURI()) && Set.of("AuthnRequest", "Response", "ArtifactResolve", "ArtifactResponse").contains(root.getLocalName()))
                    || (MD.equals(root.getNamespaceURI()) && Set.of("EntityDescriptor", "EntitiesDescriptor").contains(root.getLocalName()))
                    || (ArtifactResolutionProtocol.SOAP.equals(root.getNamespaceURI()) && "Envelope".equals(root.getLocalName()));
        } catch (Exception invalid) { return false; }
    }
    static List<TranscriptEntry> entries(Connection db, JsonCodec codec, String runId) throws Exception {
        var entries = new ArrayList<TranscriptEntry>(); var ids = new HashSet<String>();
        try (var q = db.prepareStatement("SELECT id,document_json FROM transcript_entries WHERE run_id=? ORDER BY timestamp,id LIMIT ?")) {
            q.setString(1, runId); q.setInt(2, MAX_ENTRIES + 1);
            try (var rows = q.executeQuery()) { while (rows.next()) {
                var entry = codec.read(rows.getString(2), TranscriptEntry.class);
                require(rows.getString(1).equals(entry.id()), "Transcript row identity differs");
                require(entries.size() < MAX_ENTRIES && runId.equals(entry.runId()) && ids.add(entry.id()) && noCredentials(entry.headers()), "Transcript scope/header boundary invalid");
                entries.add(entry);
            } }
        } return entries;
    }
    static List<OutboxEntry> outbox(Connection db, JsonCodec codec, String runId) throws Exception {
        var entries = new ArrayList<OutboxEntry>();
        try (var q = db.prepareStatement("SELECT action_json,status,send_result_json,transcript_entry_id,created_at,updated_at FROM outbox_actions WHERE run_id=? AND case_id=? ORDER BY action_id LIMIT 33")) {
            q.setString(1, runId); q.setString(2, CASE);
            try (var rows = q.executeQuery()) { while (rows.next()) {
                require(entries.size() < 32, "Outbox export exceeds bounded size"); var action = codec.read(rows.getString(1), OutboundAction.class);
                require(!action.requiresEphemeralCredential() && Set.of(OutboundKind.AUTHN_REQUEST, OutboundKind.ARTIFACT_RESOLVE).contains(action.kind())
                        && action.payload().length > 0 && action.payload().length <= MAX_ORIGINAL && publicXml(action.payload()), "Outbox payload outside public SAML boundary");
                Map<String,Object> send = rows.getString(3) == null ? Map.of() : codec.read(rows.getString(3), Map.class);
                entries.add(new OutboxEntry(runId, CASE, action, OutboxStatus.valueOf(rows.getString(2)), send,
                        rows.getString(4), Instant.parse(rows.getString(5)), Instant.parse(rows.getString(6))));
            } }
        } return List.copyOf(entries);
    }
    static Element suiteEntity(byte[] metadata, String planId, String issuer) {
        var root = SecureXml.parse(metadata).getDocumentElement();
        require(MD.equals(root.getNamespaceURI()) && "EntityDescriptor".equals(root.getLocalName())
                && issuer.equals(root.getAttribute("entityID")) && URI.create(issuer).getPath().equals("/p/" + planId), "Suite public metadata is not actual Plan issuer");
        require(children(root, MD, "SPSSODescriptor").size() == 1, "Suite SP metadata unavailable"); return root;
    }
    static boolean registeredAcs(Element entity, String location, String binding) {
        var sp = single(entity, MD, "SPSSODescriptor");
        return children(sp, MD, "AssertionConsumerService").stream().filter(e -> location.equals(e.getAttribute("Location")) && binding.equals(e.getAttribute("Binding"))).count() == 1;
    }
    static List<X509Certificate> certificates(Element entity) throws Exception {
        var result = new ArrayList<X509Certificate>(); var sp = single(entity, MD, "SPSSODescriptor");
        for (var key : children(sp, MD, "KeyDescriptor")) if (!key.hasAttribute("use") || "signing".equals(key.getAttribute("use"))) {
            var values = key.getElementsByTagNameNS(DS, "X509Certificate");
            for (int i = 0; i < values.getLength(); i++) result.add(certificate(values.item(i).getTextContent()));
        } require(!result.isEmpty(), "Suite metadata signing certificate absent"); return result;
    }
    static X509Certificate originalCertificate(Element xml) throws Exception {
        var signature = single(xml, DS, "Signature"); var key = single(signature, DS, "KeyInfo");
        var data = single(key, DS, "X509Data"); return certificate(single(data, DS, "X509Certificate").getTextContent());
    }
    static X509Certificate suiteOriginalCertificate(Map<String,Original> originals, List<X509Certificate> publicMetadataCertificates) throws Exception {
        var values = new LinkedHashMap<String,X509Certificate>();
        for (var original : originals.values()) {
            if (original.entry().direction() != Direction.OUTBOUND || original.decoded().length == 0
                    || !Set.of("AuthnRequest", "ArtifactResolve").contains(String.valueOf(original.entry().samlSummary().get("type")))) continue;
            try {
                Element root = "ArtifactResolve".equals(original.entry().samlSummary().get("type"))
                        ? new ArtifactResolutionProtocol().soapMessage(original.decoded(), "ArtifactResolve")
                        : SecureXml.parse(original.decoded()).getDocumentElement();
                var certificate = originalCertificate(root);
                if (matches(certificate, publicMetadataCertificates) && new XmlSignatureVerifier().hasValidEnvelopedSignature(root, certificate))
                    values.put(hash(certificate.getEncoded()), certificate);
            } catch (Exception unavailable) { /* Another signed original may establish the relationship. */ }
        }
        return only(new ArrayList<>(values.values()), "Suite certificate in actual signed original");
    }
    static X509Certificate certificate(String text) throws Exception {
        return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(Base64.getMimeDecoder().decode(text)));
    }
    static boolean matches(X509Certificate certificate, List<X509Certificate> values) throws Exception {
        String digest = hash(certificate.getEncoded()); for (var value : values) if (digest.equals(hash(value.getEncoded()))) return true; return false;
    }
    static Original original(Map<String,Original> originals, TranscriptEntry entry) { var value = originals.get(entry.id()); require(value != null, "Original not exported"); return value; }
    static Element saml(Map<String,Original> originals, TranscriptEntry entry) { byte[] raw = original(originals, entry).decoded(); require(raw.length != 0, "Decoded original unavailable"); return SecureXml.parse(raw).getDocumentElement(); }
    static String status(Element root) { return single(single(root, P, "Status"), P, "StatusCode").getAttribute("Value"); }
    static Element single(Element root, String ns, String name) { return only(children(root, ns, name), name); }
    static List<Element> children(Element root, String ns, String name) {
        var values = new ArrayList<Element>(); for (var n = root.getFirstChild(); n != null; n = n.getNextSibling()) if (n instanceof Element e && ns.equals(e.getNamespaceURI()) && name.equals(e.getLocalName())) values.add(e); return values;
    }
    static <T> T only(List<T> values, String name) { require(values.size() == 1, "Missing or duplicate " + name); return values.getFirst(); }
    static String single(Connection db, String query, String... args) throws Exception { return optional(db, query, args).orElseThrow(() -> new IllegalArgumentException("Bound object missing")); }
    static Optional<String> optional(Connection db, String query, String... args) throws Exception {
        try (var q = db.prepareStatement(query)) { for (int i = 0; i < args.length; i++) q.setString(i + 1, args[i]);
            try (var rows = q.executeQuery()) { if (!rows.next()) return Optional.empty(); String value = rows.getString(1); require(!rows.next(), "Duplicate bound object"); return Optional.of(value); }
        }
    }
    static boolean noCredentials(Map<String,List<String>> headers) { return headers != null && headers.keySet().stream().noneMatch(n -> Set.of("authorization", "proxy-authorization", "cookie", "set-cookie").contains(n.toLowerCase(Locale.ROOT))); }
    static boolean xml(String value) { return value != null && Set.of("text/xml", "application/xml").contains(value.split(";", 2)[0].trim().toLowerCase(Locale.ROOT)); }
    static String base64(byte[] bytes) { return Base64.getEncoder().encodeToString(bytes); }
    static String hash(byte[] bytes) { try { return HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256").digest(bytes)); } catch (Exception impossible) { throw new IllegalStateException(impossible); } }
    static String safeMessage(Exception missing) { return missing instanceof IllegalArgumentException && missing.getMessage() != null ? missing.getMessage() : missing.getClass().getSimpleName(); }
    static void require(boolean value, String reason) { if (!value) throw new IllegalArgumentException(reason); }
    interface GuardCheck { void run() throws Exception; }
    static void acceptedGuard(List<Map<String,Object>> checks, String id, GuardCheck check) throws Exception {
        check.run(); checks.add(Map.of("id", id, "expected", "accepted", "observed", "accepted", "passed", true));
    }
    static void rejectedGuard(List<Map<String,Object>> checks, String id, GuardCheck check) throws Exception {
        try { check.run(); } catch (IllegalArgumentException rejected) {
            checks.add(Map.of("id", id, "expected", "rejected", "observed", "rejected", "passed", true)); return;
        }
        throw new IllegalStateException("Guard accepted forbidden owned fixture: " + id);
    }
    static TranscriptEntry guardEntry(String run, String id, String reference, int length, boolean decoded) {
        return new TranscriptEntry(id, run, Direction.INBOUND, Instant.EPOCH, "guard", "POST", "http://localhost/guard", 200,
                Map.of(), decoded ? null : reference, decoded ? 0 : length, decoded ? reference : null, decoded ? length : 0,
                "application/xml", null, Map.of("type", "Response"));
    }
    static void selfCheck() throws Exception {
        var checks = new ArrayList<Map<String,Object>>();
        acceptedGuard(checks, "sha256-and-public-original-byte-encoding", () -> {
            require(hash(new byte[0]).equals("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"), "Hash self-check failed");
            byte[] response = ("<p:Response xmlns:p='" + P + "' ID='_public' Version='2.0'/>").getBytes(StandardCharsets.UTF_8);
            require(publicXml(response) && Arrays.equals(response, Base64.getDecoder().decode(base64(response))), "Original byte encoding failed");
        });
        acceptedGuard(checks, "credential-header-rejection", () -> require(noCredentials(Map.of("Content-Type", List.of("text/xml")))
                && !noCredentials(Map.of("cOoKiE", List.of("redacted"))), "Header boundary failed"));
        acceptedGuard(checks, "non-XML-and-private-material-rejection", () -> require(!publicXml("private material".getBytes(StandardCharsets.UTF_8))
                && !publicXml("-----BEGIN PRIVATE KEY-----".getBytes(StandardCharsets.UTF_8)), "Public XML boundary failed"));
        Path owned = Files.createTempDirectory(Path.of("/private/tmp"), "samlscope-artifact-reader-guards-").toRealPath();
        try {
            String run = "run_00000000000000000000000000", otherRun = "run_11111111111111111111111111";
            String tx = "tx_00000000000000000000000000", otherTx = "tx_11111111111111111111111111";
            String bodyRef = "transcripts/" + run + "/" + tx + ".body", xmlRef = "transcripts/" + run + "/" + tx + ".saml.xml";
            byte[] value = "owned-public-fixture".getBytes(StandardCharsets.UTF_8);
            Files.createDirectories(owned.resolve("transcripts").resolve(run)); Files.write(owned.resolve(bodyRef), value); Files.write(owned.resolve(xmlRef), value);
            var body = guardEntry(run, tx, bodyRef, value.length, false); var decoded = guardEntry(run, tx, xmlRef, value.length, true);
            acceptedGuard(checks, "exact-owned-body-reference", () -> require(Arrays.equals(value, readReference(owned, body, bodyRef, value.length, false)), "Exact body differed"));
            acceptedGuard(checks, "exact-owned-decoded-reference", () -> require(Arrays.equals(value, readReference(owned, decoded, xmlRef, value.length, true)), "Exact XML differed"));
            String foreignRunRef = "transcripts/" + otherRun + "/" + tx + ".body";
            String foreignEntryRef = "transcripts/" + run + "/" + otherTx + ".body";
            Files.createDirectories(owned.resolve("transcripts").resolve(otherRun)); Files.write(owned.resolve(foreignRunRef), value); Files.write(owned.resolve(foreignEntryRef), value);
            rejectedGuard(checks, "foreign-Run-reference", () -> readReference(owned, guardEntry(run, tx, foreignRunRef, value.length, false), foreignRunRef, value.length, false));
            rejectedGuard(checks, "foreign-entry-reference-within-Run", () -> readReference(owned, guardEntry(run, tx, foreignEntryRef, value.length, false), foreignEntryRef, value.length, false));
            rejectedGuard(checks, "decoded-reference-used-as-body", () -> readReference(owned, guardEntry(run, tx, xmlRef, value.length, false), xmlRef, value.length, false));
            Files.createDirectories(owned.resolve("private")); Files.write(owned.resolve("private/fixture.txt"), value);
            for (String ref : List.of("private/fixture.txt", owned.resolve("private/fixture.txt").toString(), "../private/fixture.txt",
                    "transcripts/" + run + "/../" + run + "/" + tx + ".body"))
                rejectedGuard(checks, "root-private-or-noncanonical-reference-" + checks.size(), () -> readReference(owned, guardEntry(run, tx, ref, value.length, false), ref, value.length, false));
            rejectedGuard(checks, "oversized-declared-original", () -> readReference(owned, guardEntry(run, tx, bodyRef, MAX_ORIGINAL + 1, false), bodyRef, MAX_ORIGINAL + 1, false));
            rejectedGuard(checks, "declared-length-differs-from-entry", () -> readReference(owned, body, bodyRef, value.length - 1, false));
            rejectedGuard(checks, "file-size-differs-from-entry-before-read", () -> readReference(owned, guardEntry(run, tx, bodyRef, value.length - 1, false), bodyRef, value.length - 1, false));
            Path oversized = owned.resolve("oversized"); Files.createDirectories(oversized.resolve("transcripts").resolve(run));
            Files.write(oversized.resolve(bodyRef), new byte[MAX_ORIGINAL + 1]);
            rejectedGuard(checks, "oversized-actual-file-before-read", () -> readReference(oversized, body, bodyRef, value.length, false));
            Path parentRoot = owned.resolve("parent-link-root"), targetDir = owned.resolve("owned-link-target");
            Files.createDirectories(parentRoot.resolve("transcripts")); Files.createDirectories(targetDir);
            Files.write(targetDir.resolve(tx + ".body"), value); Files.createSymbolicLink(parentRoot.resolve("transcripts").resolve(run), targetDir);
            rejectedGuard(checks, "parent-symlink-inside-owned-root", () -> readReference(parentRoot, body, bodyRef, value.length, false));
            Path leafRoot = owned.resolve("leaf-link-root"); Files.createDirectories(leafRoot.resolve("transcripts").resolve(run));
            Files.createSymbolicLink(leafRoot.resolve(bodyRef), owned.resolve(bodyRef));
            rejectedGuard(checks, "leaf-symlink-inside-owned-root", () -> readReference(leafRoot, body, bodyRef, value.length, false));
            Path linkedRoot = owned.resolve("root-link"); Files.createSymbolicLink(linkedRoot, owned.resolve("transcripts"));
            rejectedGuard(checks, "symlink-data-root-ancestor", () -> rejectSymlinkAncestors(linkedRoot.resolve("unused-child")));
            rejectedGuard(checks, "noncanonical-data-root", () -> readReference(owned.resolve("unrelated").resolve(".."), body, bodyRef, value.length, false));
            Path dbPath = owned.resolve("SQLite guards space # question ?.db");
            try (var preparation = DriverManager.getConnection("jdbc:sqlite:" + dbPath.toUri().toASCIIString() + "?mode=rwc"); var write = preparation.createStatement()) {
                write.execute("CREATE TABLE owned_fixture(value TEXT NOT NULL)"); write.execute("INSERT INTO owned_fixture(value) VALUES('owned-public-sentinel')");
            }
            require(Files.isRegularFile(dbPath, LinkOption.NOFOLLOW_LINKS), "URI escaped preparation path differed");
            String before = hash(Files.readAllBytes(dbPath));
            acceptedGuard(checks, "URI-escaped-SQLite-path-space-hash-question", () -> {
                try (var read = readOnlyDatabase(dbPath); var query = read.createStatement(); var rows = query.executeQuery("SELECT value FROM owned_fixture")) {
                    require(rows.next() && "owned-public-sentinel".equals(rows.getString(1)) && !rows.next(), "Read-only URI opened different file");
                }
            });
            acceptedGuard(checks, "SQLite-query_only-verified-and-write-rejected", () -> {
                try (var read = readOnlyDatabase(dbPath); var query = read.createStatement()) {
                    try (var rows = query.executeQuery("PRAGMA query_only")) { require(rows.next() && rows.getInt(1) == 1, "query_only disabled"); }
                    boolean rejected = false;
                    try { query.execute("INSERT INTO owned_fixture(value) VALUES('must-not-write')"); }
                    catch (SQLException readOnly) { rejected = readOnly.getErrorCode() == 8; }
                    require(rejected, "Read-only SQLite write was not rejected");
                }
            });
            acceptedGuard(checks, "SQLite-prepared-bytes-unchanged-after-read-checks", () -> require(before.equals(hash(Files.readAllBytes(dbPath))), "Read-only checks changed owned database"));
            Path missing = owned.resolve("missing space # ?.db");
            rejectedGuard(checks, "read-only-open-refuses-missing-database", () -> readOnlyDatabase(missing));
            require(!Files.exists(missing), "Read-only open created missing database");
        } finally {
            try (var paths = Files.walk(owned)) { for (var path : paths.sorted(Comparator.reverseOrder()).toList()) Files.delete(path); }
        }
        var result = new LinkedHashMap<String,Object>(); result.put("schema", "samlscope-synthetic-artifact-runtime-reader-self-check-v2");
        result.put("label", "Owned temporary path and SQLite guard calibration only"); result.put("checks", checks); result.put("checkCount", checks.size());
        result.put("passed", true); result.put("networkOperations", 0); result.put("actualRunOrDatabaseReads", 0); result.put("privateKeyReads", 0);
        result.put("ownedTemporaryDatabasePreparationWrites", 2); result.put("ownedTemporaryReadOnlyDatabaseSuccessfulWrites", 0);
        result.put("ownedTemporaryFixturesRemoved", true); System.out.println(new JsonCodec().write(result));
    }
}
