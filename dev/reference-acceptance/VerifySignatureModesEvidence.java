package com.samlscope.runner.cases;

import com.samlscope.store.JsonCodec;
import com.samlscope.core.transcript.*;
import com.samlscope.core.plan.*;
import com.samlscope.core.run.Reachability;
import com.samlscope.core.evaluation.*;
import com.samlscope.runner.DefaultCaseContext;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import java.nio.file.*;
import java.security.MessageDigest;
import java.time.Clock;
import java.util.*;

/** Read-only production replay, with temporary receipt mutations that must never produce SATISFIED. */
public final class VerifySignatureModesEvidence {
    static String hash(byte[] bytes) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
    }
    public static void main(String[] args) throws Exception {
        var folder = Path.of(args[0]).toAbsolutePath().normalize();
        var output = Path.of(args[1]);
        var mapper = new JsonCodec().mapper();
        var run = mapper.readTree(folder.resolve("created.json").toFile()).at("/run/id").asText();
        var originals = new HashMap<String, byte[]>();
        for (var row : mapper.readTree(folder.resolve("decoded-manifest.json").toFile())) {
            var file = folder.resolve(row.path("file").asText()).normalize();
            if (!file.getParent().equals(folder.resolve("decoded"))) throw new IllegalArgumentException("Original path mismatch");
            var raw = Files.readAllBytes(file);
            if (!hash(raw).equals(row.path("sha256").asText()) || originals.put(row.path("id").asText(), raw) != null) {
                throw new IllegalArgumentException("Original hash mismatch");
            }
        }
        var entries = List.of(mapper.readValue(folder.resolve("transcript.json").toFile(), TranscriptEntry[].class));
        var recorder = new TranscriptRecorder() {
            public List<TranscriptEntry> list(String requested) {
                if (!run.equals(requested)) throw new IllegalArgumentException("Wrong Run"); return entries;
            }
            public TranscriptEntry record(TranscriptInput input) { throw new UnsupportedOperationException(); }
            public TranscriptEntry updateSamlAnalysis(String id, String correlation, Map<String,Object> summary) { throw new UnsupportedOperationException(); }
        };
        var context = new DefaultCaseContext(run, TargetRole.IDP, Clock.systemUTC(), TestPlan.Parameters.defaults(),
                TestPlan.Interaction.defaults(), Reachability.CONFIRMED, recorder, true);
        var target = Files.readAllBytes(folder.resolve("target-metadata.xml"));
        var fixtureBytes = Files.readAllBytes(folder.resolve("fixture.xml"));
        var fixture = com.samlscope.saml.normal.SecureXml.parse(fixtureBytes).getDocumentElement();
        var roles = fixture.getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:metadata", "SPSSODescriptor");
        if (roles.getLength() != 1 || !"false".equals(((org.w3c.dom.Element) roles.item(0)).getAttribute("WantAssertionsSigned")))
            throw new IllegalStateException("Optional Assertion signing fixture required");
        var encoded = roles.item(0).getOwnerDocument().getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "X509Certificate").item(0).getTextContent();
        var certificate = (java.security.cert.X509Certificate) java.security.cert.CertificateFactory.getInstance("X.509")
                .generateCertificate(new java.io.ByteArrayInputStream(Base64.getMimeDecoder().decode(encoded)));
        var verifier = new com.samlscope.saml.crypto.XmlSignatureVerifier();
        if (!verifier.hasValidEnvelopedSignature(fixture,certificate)) throw new IllegalStateException("Invalid Suite metadata signature");
        boolean prepared = entries.stream().anyMatch(e -> "MetadataPrepared".equals(e.samlSummary().get("type"))
                && "signature-modes-optional".equals(e.samlSummary().get("variant")) && Arrays.equals(fixtureBytes,originals.get(e.id())));
        if (!prepared) throw new IllegalStateException("Fixture was not recorded by this Run");
        for (var entry : entries) if (entry.direction() == Direction.OUTBOUND && "AuthnRequest".equals(entry.samlSummary().get("type"))) {
            var requestBytes = originals.get(entry.id());
            boolean signed = "GET".equals(entry.method())
                    ? new com.samlscope.saml.binding.RedirectSignatureVerifier().isValidForMessage(entry.rawQuery(),certificate,requestBytes)
                    : "POST".equals(entry.method()) && verifier.hasValidEnvelopedSignature(com.samlscope.saml.normal.SecureXml.parse(requestBytes).getDocumentElement(),certificate);
            if (!signed) throw new IllegalStateException("Invalid Suite request signature");
        }
        var outcome = SignatureModesObservation.observe(context, e -> originals.get(e.id()), target, ignored -> Optional.empty());
        if (outcome.outcome() != Outcome.SATISFIED) throw new IllegalStateException("Incomplete native modes: " + outcome);
        var pristine = new HashMap<>(originals);
        var checks = new LinkedHashMap<String,String>();
        var responseEntries = entries.stream().filter(e -> e.direction() == Direction.INBOUND && "Response".equals(e.samlSummary().get("type"))).toList();
        for (var responseEntry : responseEntries) {
            for (String mutation : List.of("signature-value", "wrong-audience", "wrong-confirmation", "wrong-issuer", "duplicate-id", "missing-response")) {
                originals.clear(); originals.putAll(pristine);
                var doc = com.samlscope.saml.normal.SecureXml.parse(originals.get(responseEntry.id()));
                var root = doc.getDocumentElement();
                String ns = "urn:oasis:names:tc:SAML:2.0:assertion";
                switch (mutation) {
                    case "signature-value" -> root.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "SignatureValue").item(0).setTextContent("AAAA");
                    case "wrong-audience" -> root.getElementsByTagNameNS(ns,"Audience").item(0).setTextContent("other-peer");
                    case "wrong-confirmation" -> ((org.w3c.dom.Element) root.getElementsByTagNameNS(ns,"SubjectConfirmationData").item(0)).setAttribute("InResponseTo", "_other");
                    case "wrong-issuer" -> root.getElementsByTagNameNS(ns,"Issuer").item(0).setTextContent("other-target");
                    case "duplicate-id" -> ((org.w3c.dom.Element) root.getElementsByTagNameNS(ns,"Assertion").item(0)).setAttribute("ID", root.getAttribute("ID"));
                    case "missing-response" -> { }
                    default -> throw new IllegalStateException();
                }
                originals.put(responseEntry.id(), mutation.equals("missing-response") ? new byte[0] : com.samlscope.saml.normal.SecureXml.serialize(doc));
                var invalid = SignatureModesObservation.observe(context, e -> originals.get(e.id()), target, ignored -> Optional.empty());
                if (invalid.outcome() != Outcome.NOT_VERIFIED) throw new IllegalStateException("Invalid evidence accepted: " + mutation);
                checks.put(responseEntry.id() + ":" + mutation, invalid.outcome().name());
            }
        }
        var report = Map.of("run", run, "outcome", outcome, "negative_controls", checks,
                "transcript_sha256", hash(Files.readAllBytes(folder.resolve("transcript.json"))),
                "manifest_sha256", hash(Files.readAllBytes(folder.resolve("decoded-manifest.json"))),
                "target_metadata_sha256", hash(target), "fixture_sha256", hash(fixtureBytes),
                "operations_sha256", hash(Files.readAllBytes(folder.resolve("operations.json"))), "verdict_adopted", false);
        Files.write(output, mapper.writerWithDefaultPrettyPrinter().writeValueAsBytes(report), StandardOpenOption.CREATE_NEW);
        System.out.println("Observed all signature modes; " + checks.size() + " mutations rejected; no Run verdict adopted");
    }
}
