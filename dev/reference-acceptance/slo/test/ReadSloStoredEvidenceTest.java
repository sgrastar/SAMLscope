package com.samlscope.runner.cases;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.*;
import java.util.*;
import com.samlscope.core.evaluation.Outcome;
import static org.junit.jupiter.api.Assertions.*;

class ReadSloStoredEvidenceTest {
    @TempDir Path tmp;
    final Path repo = Path.of(System.getProperty("slo.repo"));
    static final String RUN = "run_2671TXGC71MJ97JGK0AFJX3Y0D";
    static final String CASE = "IIP-IDP18-d-idp-01";
    static final String TX1 = "tx_VZPDNPQPHN22YEC058YT33EGYS";
    static final String TX2 = "tx_S9BJQ7HWBPZ6287K9MA3B5JFQ3";

    Path save(String name, Object value) throws Exception {
        Path path = tmp.resolve(name);
        Files.write(path, ReadSloStoredEvidence.JSON.writeValueAsBytes(value));
        return path;
    }
    Path result() throws Exception {
        return save("result.json", Map.of("run", Map.of("id", RUN), "profile", Map.of("id", "single-logout-idp"),
                "requirements", List.of(Map.of("cases", List.of(Map.of("id", CASE,
                        "outcome", "SATISFIED", "reason_code", "legacy-http-200"))))));
    }
    String hash(Path p) throws Exception { return ReadSloStoredEvidence.sha(Files.readAllBytes(p)); }
    Path[] graph(String request, String response) throws Exception {
        var originals = new ArrayList<Object>();
        var entries = new ArrayList<Object>();
        int i = 0;
        for (String raw : List.of(request, response)) {
            String tx = i == 0 ? TX1 : TX2;
            String type = i == 0 ? "LogoutRequest" : "LogoutResponse";
            Path f = tmp.resolve(tx + ".xml"); Files.writeString(f, raw);
            originals.add(Map.of("id", tx, "file", f.getFileName().toString(), "sha256", hash(f)));
            entries.add(Map.of("id", tx, "runId", RUN, "direction", i == 0 ? "INBOUND" : "OUTBOUND",
                    "timestamp", ++i, "decodedSamlRef", "transcripts/" + RUN + "/" + tx + ".saml.xml",
                    "decodedSamlBytes", Files.size(f), "samlSummary", Map.of("type", type,
                            "binding", "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect")));
        }
        return new Path[]{save("transcript.json", entries), save("decoded-manifest.json", originals)};
    }
    String request() { return "<p:LogoutRequest xmlns:p='" + ReadSloStoredEvidence.P + "' ID='req'/>"; }
    String response() { return "<p:LogoutResponse xmlns:p='" + ReadSloStoredEvidence.P + "' ID='reply' InResponseTo='req'/>"; }
    ReadSloStoredEvidence.Inspection inspect(Path r, Path[] g) throws Exception {
        return ReadSloStoredEvidence.inspect(r, hash(r), RUN, CASE, g == null ? null : g[0], g == null ? null : g[1]);
    }

    @Test void decodedPairAndRedirectLabelDoNotProveDeliveryOrNativeConsumption() throws Exception {
        var r = inspect(result(), graph(request(), response()));
        assertEquals(1, r.targetRequestReplyPairs().size());
        assertFalse(r.targetRequestReplyPairs().getFirst().wireBindingProven());
        assertFalse(r.targetRequestReplyPairs().getFirst().nativeConsumptionProven());
        assertEquals(Outcome.NOT_VERIFIED, r.assessment().outcome());
        assertEquals("SATISFIED", r.storedOutcome());
    }
    @Test void missingOriginalsAndSavedSuccessStayUnverified() throws Exception {
        var r = inspect(result(), null);
        assertEquals(Outcome.NOT_VERIFIED, r.assessment().outcome());
        assertTrue(r.gaps().contains("recorder-original-bundle-unavailable"));
    }
    @Test void foreignRunResultAndMissingMembershipAreRejected() throws Exception {
        Path r = result();
        assertThrows(IllegalArgumentException.class, () -> ReadSloStoredEvidence.inspect(r, hash(r),
                "run_W9RJ2DKTGE5S5XX6HPE2F8FZE4", CASE, null, null));
        assertThrows(IllegalArgumentException.class, () -> ReadSloStoredEvidence.inspect(r, hash(r), RUN,
                "IIP-IDP17-r-idp-01", null, null));
    }
    @Test void changedResultBytesAreRejected() throws Exception {
        Path r = result(); String hash = hash(r); Files.writeString(r, " ", StandardOpenOption.APPEND);
        assertThrows(IllegalArgumentException.class, () -> ReadSloStoredEvidence.inspect(r, hash, RUN, CASE, null, null));
    }
    @Test void duplicateJsonKeysAndTrailingJsonAreRejected() throws Exception {
        Path r = result();
        Files.writeString(r, "{\"run\":{},\"run\":{}}");
        assertThrows(Exception.class, () -> inspect(r, null));
        Files.writeString(r, "{} {}");
        assertThrows(Exception.class, () -> inspect(r, null));
    }
    @Test void corruptDecodedBytesDiscardEntireGraph() throws Exception {
        Path[] g = graph(request(), response());
        Files.writeString(tmp.resolve(TX2 + ".xml"), response() + " ");
        var r = inspect(result(), g);
        assertTrue(r.messages().isEmpty());
        assertTrue(r.gaps().contains("recorder-original-bundle-invalid"));
        assertEquals(Outcome.NOT_VERIFIED, r.assessment().outcome());
    }
    @Test void foreignRunTranscriptCannotBeRelabelledByExpectedRun() throws Exception {
        Path[] g = graph(request(), response());
        String raw = Files.readString(g[0]).replace(RUN, "run_W9RJ2DKTGE5S5XX6HPE2F8FZE4");
        Files.writeString(g[0], raw);
        assertTrue(inspect(result(), g).messages().isEmpty());
    }
    @Test void wrongInResponseToDoesNotProduceAPair() throws Exception {
        var r = inspect(result(), graph(request(), response().replace("InResponseTo='req'", "InResponseTo='other'")));
        assertEquals(2, r.messages().size());
        assertTrue(r.targetRequestReplyPairs().isEmpty());
    }
    @Test void duplicateMessageIdAndDtdCannotBecomeEvidence() throws Exception {
        assertTrue(inspect(result(), graph(request(), response().replace("ID='reply'", "ID='req'"))).messages().isEmpty());
        String dtd = "<!DOCTYPE p:LogoutRequest [<!ENTITY x SYSTEM 'file:///nonexistent'>]>";
        assertTrue(inspect(result(), graph(dtd + request(), response())).messages().isEmpty());
    }
    @Test void pathTraversalAndSymlinkAreRejected() throws Exception {
        assertThrows(IllegalArgumentException.class, () -> ReadSloStoredEvidence.child(tmp, "../other.xml"));
        Path p = result(); Path link = tmp.resolve("link.json"); Files.createSymbolicLink(link, p);
        assertThrows(IllegalArgumentException.class, () -> ReadSloStoredEvidence.bytes(link));
    }
    String soap(String body) {
        return "<s:Envelope xmlns:s='http://schemas.xmlsoap.org/soap/envelope/'><s:Body>" + body + "</s:Body></s:Envelope>";
    }
    @Test void soapEnvelopeBytesAreCorrelatedWithoutClaimingRedirectConsumption() throws Exception {
        var r = inspect(result(), graph(soap(request()), soap(response())));
        assertEquals(1, r.targetRequestReplyPairs().size());
        assertFalse(r.targetRequestReplyPairs().getFirst().wireBindingProven());
        assertEquals(Outcome.NOT_VERIFIED, r.assessment().outcome());
    }
    @Test void ambiguousSoapBodyIsRejected() throws Exception {
        var r = inspect(result(), graph(soap(request() + request()), soap(response())));
        assertTrue(r.messages().isEmpty());
    }
    @Test void allFourteenLedgerResultsReplayWithoutAdoptingWithdrawnFeedback() throws Exception {
        Path audit = repo.resolve("build/acceptance/reference-20261031/slo/ledger-observations.json");
        var rows = ReadSloStoredEvidence.read(audit);
        assertEquals(14, rows.size());
        int withdrawn = 0;
        for (var row : rows) {
            var inventory = row.path("inventory");
            var r = ReadSloStoredEvidence.inspect(repo.resolve(row.path("resultPath").asText()),
                    inventory.path("result_sha256").asText(), inventory.path("run").asText(),
                    inventory.path("case").asText(), null, null);
            assertEquals(Outcome.NOT_VERIFIED, r.assessment().outcome());
            if (r.storedOutcome().equals("SATISFIED")) {
                withdrawn++;
                assertEquals("IIP-IDP17-b2-idp-01", r.caseId());
                assertEquals("audit.slo-async-session-failure-unproven", inventory.path("reason_code").asText());
            }
        }
        assertEquals(2, withdrawn);
    }
    @Test void realSavedRequestReplyPairsRemainDiagnosticOnly() throws Exception {
        var folders = List.of("reference-20260930/keycloak-target-logout-absence-v158-r7",
                "reference-20260930/shibboleth-slo-correlated-v164-r5", "reference-20260930/ssp-slo-iframe-v131i");
        for (String folder : folders) {
            Path dir = repo.resolve("build/acceptance/" + folder), r = dir.resolve("result.json");
            String run = ReadSloStoredEvidence.read(r).path("run").path("id").asText();
            var inspected = ReadSloStoredEvidence.inspect(r, hash(r), run, CASE,
                    dir.resolve("transcript.json"), dir.resolve("decoded-manifest.json"));
            assertFalse(inspected.messages().isEmpty(), folder);
            assertEquals(1, inspected.targetRequestReplyPairs().size(), folder);
            assertEquals(Outcome.NOT_VERIFIED, inspected.assessment().outcome());
        }
    }
}
