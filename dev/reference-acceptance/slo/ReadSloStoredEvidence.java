package com.samlscope.runner.cases;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.StreamReadFeature;
import com.fasterxml.jackson.databind.*;
import com.samlscope.core.evaluation.CaseOutcome;
import java.io.ByteArrayInputStream;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;

/** Offline diagnostic reader, NOT an adoption evaluator. No database, sender or Verdict API.
 * Decoded XML correlation proves neither transport delivery nor native consumption.
 * Arguments name immutable public exports; no Run aliasing or source-Run substitution exists.
 */
public final class ReadSloStoredEvidence {
    static final ObjectMapper JSON = new ObjectMapper(JsonFactory.builder()
            .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION).build())
            .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS);
    static final Set<String> CASES = Set.of("IIP-IDP17-c-idp-01", "IIP-IDP17-r-idp-01",
            "IIP-IDP17-s-idp-01", "IIP-IDP17-b2-idp-01", "IIP-IDP18-c-idp-01",
            "IIP-IDP18-d-idp-01", "IIP-IDP19-a-idp-01", "IIP-IDP19-c-idp-01");
    static final String P = "urn:oasis:names:tc:SAML:2.0:protocol";
    static final long LIMIT = 32L * 1024 * 1024;
    public record Message(String transcriptId, String messageId, String inResponseTo, String type,
            String direction, String method, String declaredBinding, boolean asynchronous,
            java.math.BigDecimal timestamp) {}
    public record Pair(String requestReference, String responseReference, String declaredBinding,
            boolean wireBindingProven, boolean nativeConsumptionProven) {}
    public record Inspection(String runId, String caseId, String resultSha256, String storedOutcome,
            String storedReasonCode, CaseOutcome assessment, List<Message> messages,
            List<Pair> targetRequestReplyPairs, List<String> gaps) {}

    static void require(boolean value, String code) {
        if (!value) throw new IllegalArgumentException(code);
    }
    static String sha(byte[] raw) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(raw));
    }
    static byte[] bytes(Path file) throws Exception {
        Path path = file.toAbsolutePath().normalize();
        for (Path part : path) {
            String n = part.toString().toLowerCase(Locale.ROOT);
            require(!Set.of("private", ".git", ".authrim", ".authrim_keys", ".authrim-keys").contains(n)
                    && !n.startsWith(".env") && !n.endsWith(".key") && !n.endsWith(".pem")
                    && !n.endsWith(".p12") && !n.endsWith(".jks"), "non-public-path");
        }
        Path current = path.getRoot();
        for (Path part : path) {
            current = current.resolve(part);
            require(!Files.isSymbolicLink(current), "symbolic-original");
        }
        require(Files.isRegularFile(path) && Files.size(path) <= LIMIT, "missing-or-oversize-original");
        byte[] raw = Files.readAllBytes(path);
        require(raw.length <= LIMIT, "oversize-original");
        return raw;
    }
    static JsonNode read(Path file) throws Exception { return JSON.readTree(bytes(file)); }
    static String text(JsonNode node, String field) {
        require(node.path(field).isTextual() && !node.path(field).asText().isBlank(), "missing-" + field);
        return node.path(field).asText();
    }
    static Path child(Path folder, String relative) {
        Path p = Path.of(relative);
        require(!p.isAbsolute() && !p.toString().isBlank(), "unsafe-original-reference");
        for (Path part : p) require(!part.toString().equals(".."), "unsafe-original-reference");
        Path result = folder.toAbsolutePath().normalize().resolve(p).normalize();
        require(result.startsWith(folder.toAbsolutePath().normalize()), "unsafe-original-reference");
        return result;
    }
    static org.w3c.dom.Element onlyElement(org.w3c.dom.Element parent) {
        var elements = new ArrayList<org.w3c.dom.Element>();
        for (var n = parent.getFirstChild(); n != null; n = n.getNextSibling())
            if (n instanceof org.w3c.dom.Element e) elements.add(e);
        require(elements.size() == 1, "ambiguous-soap-body");
        return elements.getFirst();
    }
    static org.w3c.dom.Element messageRoot(org.w3c.dom.Element root) {
        String soap = "http://schemas.xmlsoap.org/soap/envelope/";
        if (!soap.equals(root.getNamespaceURI()) || !"Envelope".equals(root.getLocalName())) return root;
        var bodies = new ArrayList<org.w3c.dom.Element>();
        for (var n = root.getFirstChild(); n != null; n = n.getNextSibling())
            if (n instanceof org.w3c.dom.Element e && soap.equals(e.getNamespaceURI()) && "Body".equals(e.getLocalName()))
                bodies.add(e);
        require(bodies.size() == 1, "ambiguous-soap-body");
        return onlyElement(bodies.getFirst());
    }
    static List<Message> messages(Path transcript, Path manifest, String run) throws Exception {
        var entries = read(transcript);
        var originals = read(manifest);
        require(entries.isArray() && originals.isArray(), "invalid-original-index");
        var byId = new HashMap<String, JsonNode>();
        for (var item : originals) require(byId.put(text(item, "id"), item) == null, "duplicate-original");
        var seen = new HashSet<String>();
        var messageIds = new HashSet<String>();
        var result = new ArrayList<Message>();
        for (var e : entries) {
            String tx = text(e, "id");
            require(tx.matches("tx_[0-9A-HJKMNP-TV-Z]{26}") && seen.add(tx), "duplicate-or-invalid-transcript-id");
            require(run.equals(text(e, "runId")), "foreign-transcript-run");
            String type = e.path("samlSummary").path("type").asText();
            if (!Set.of("LogoutRequest", "LogoutResponse").contains(type)) continue;
            String direction = text(e, "direction");
            require(Set.of("INBOUND", "OUTBOUND").contains(direction), "invalid-direction");
            var original = byId.get(tx);
            require(original != null, "missing-decoded-original");
            require(("transcripts/" + run + "/" + tx + ".saml.xml").equals(text(e, "decodedSamlRef")),
                    "foreign-decoded-reference");
            byte[] raw = bytes(child(manifest.getParent(), text(original, "file")));
            require(sha(raw).equals(text(original, "sha256")) && e.path("decodedSamlBytes").isIntegralNumber()
                    && e.path("decodedSamlBytes").asLong() == raw.length, "decoded-digest-or-size-mismatch");
            var factory = DocumentBuilderFactory.newInstance();
            factory.setNamespaceAware(true);
            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
            factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
            factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
            factory.setXIncludeAware(false);
            factory.setExpandEntityReferences(false);
            var builder = factory.newDocumentBuilder();
            builder.setErrorHandler(new org.xml.sax.helpers.DefaultHandler() {
                @Override public void fatalError(org.xml.sax.SAXParseException e) throws org.xml.sax.SAXException { throw e; }
                @Override public void error(org.xml.sax.SAXParseException e) throws org.xml.sax.SAXException { throw e; }
            });
            // The original ENVELOPE bytes stay hashed and untouched; this is a DOM view only.
            var root = messageRoot(builder.parse(new ByteArrayInputStream(raw)).getDocumentElement());
            require(P.equals(root.getNamespaceURI()) && type.equals(root.getLocalName()), "wrong-original-root");
            String id = root.getAttribute("ID");
            require(!id.isBlank() && messageIds.add(id), "duplicate-or-missing-message-id");
            require(e.path("timestamp").isNumber(), "missing-timestamp");
            result.add(new Message(tx, id, root.getAttribute("InResponseTo"), type, direction,
                    e.path("method").asText(), e.path("samlSummary").path("binding").asText(),
                    root.getElementsByTagNameNS(P + ":ext:async-slo", "Asynchronous").getLength() > 0,
                    e.path("timestamp").decimalValue()));
        }
        return List.copyOf(result);
    }

    public static Inspection inspect(Path result, String expectedHash, String run, String caseId,
            Path transcript, Path manifest) throws Exception {
        require(run.matches("run_[0-9A-HJKMNP-TV-Z]{26}") && CASES.contains(caseId), "unsupported-scope");
        byte[] raw = bytes(result);
        require(expectedHash.matches("[0-9a-f]{64}") && sha(raw).equals(expectedHash), "result-digest-mismatch");
        var report = JSON.readTree(raw);
        require(run.equals(report.path("run").path("id").asText()), "foreign-result-run");
        require("single-logout-idp".equals(report.path("profile").path("id").asText()), "wrong-profile");
        var selected = new ArrayList<JsonNode>();
        for (var r : report.path("requirements")) for (var c : r.path("cases"))
            if (caseId.equals(c.path("id").asText())) selected.add(c);
        require(selected.size() == 1, "missing-or-duplicate-case-membership");
        var saved = selected.getFirst();
        var gaps = new ArrayList<String>();
        List<Message> graph = List.of();
        if (transcript == null || manifest == null) gaps.add("recorder-original-bundle-unavailable");
        else {
            try { graph = messages(transcript, manifest, run); }
            catch (Exception badOriginal) {
                // Do not leak parser messages, absolute paths, original XML or credential material.
                gaps.add("recorder-original-bundle-invalid");
            }
        }
        var pairs = new ArrayList<Pair>();
        for (var request : graph) {
            if (!request.type().equals("LogoutRequest") || !request.direction().equals("INBOUND")) continue;
            var replies = graph.stream().filter(m -> m.type().equals("LogoutResponse")
                    && m.direction().equals("OUTBOUND") && m.inResponseTo().equals(request.messageId())).toList();
            if (replies.size() != 1 || request.timestamp().compareTo(replies.getFirst().timestamp()) >= 0) {
                gaps.add("target-request-reply-absent-ambiguous-or-unordered");
                continue;
            }
            var reply = replies.getFirst();
            pairs.add(new Pair(request.transcriptId(), reply.transcriptId(), reply.declaredBinding(), false, false));
        }
        if (caseId.equals("IIP-IDP18-d-idp-01")) {
            if (pairs.isEmpty()) gaps.add("target-issued-request-and-suite-reply-required");
            gaps.add("original-redirect-response-transport-and-delivery-required");
            gaps.add("independent-same-response-native-consumption-and-controls-required");
        } else if (caseId.equals("IIP-IDP18-c-idp-01")) {
            gaps.add("redirect-only-effective-participant-configuration-and-signed-wire-request-controls-required");
        } else if (caseId.equals("IIP-IDP17-c-idp-01")) {
            gaps.add("all-applicable-informational-variants-and-native-configuration-required");
        } else if (caseId.equals("IIP-IDP17-b2-idp-01")) {
            gaps.add("own-session-termination-failure-and-correlated-user-feedback-controls-required");
        } else if (caseId.startsWith("IIP-IDP19-")) {
            gaps.add("registered-key-decryption-session-effect-and-unregistered-key-controls-required");
        } else {
            gaps.add("complete-same-operation-participant-set-failure-knowledge-and-approved-controls-required");
        }
        gaps.add("diagnostic-reader-has-no-adoption-contract");
        return new Inspection(run, caseId, expectedHash, text(saved, "outcome"), text(saved, "reason_code"),
                CaseOutcome.notVerified("offline_originals_do_not_establish_approved_case",
                        "slo.offline.adoption-unproven"), graph, List.copyOf(pairs), List.copyOf(gaps));
    }

    public static void main(String[] args) throws Exception {
        require((args.length == 5 || args.length == 7) && args[0].equals("offline"),
                "offline result.json sha256 Run Case [transcript.json decoded-manifest.json]");
        var result = inspect(Path.of(args[1]), args[2], args[3], args[4],
                args.length == 7 ? Path.of(args[5]) : null, args.length == 7 ? Path.of(args[6]) : null);
        System.out.println(JSON.writerWithDefaultPrettyPrinter().writeValueAsString(result));
    }
}
