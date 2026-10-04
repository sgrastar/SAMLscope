package com.samlscope.runner.cases;

import com.fasterxml.jackson.databind.JsonNode;
import com.samlscope.core.caseexec.CaseContext;
import com.samlscope.core.evaluation.EvidenceRef;
import com.samlscope.core.transcript.TranscriptEntry;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import org.w3c.dom.Element;

/** Product-owned proof of registration, operative SLO key lookup and request-bound rejection. */
public interface SloRegisteredSignerNativeAdapter {
    String adapter();

    /**
     * Verify original-backed simultaneous peer registration, selected SLO Issuer-to-SP-key
     * path, runtime/configuration epoch and exact restoration. Preparation may omit final
     * restoration only while creating outbox inputs; final proof must require it.
     */
    Session open(CaseContext context, Path folder, JsonNode manifest,
            SloRegisteredSignerEvidence.Originals originals, boolean finalProof) throws Exception;

    enum Decision { REJECTED_SIGNATURE, ACCEPTED, UNPROVEN }
    record NativeUse(Decision decision, Instant startedAt, Instant completedAt,
            List<EvidenceRef> evidence) {
        public NativeUse {
            java.util.Objects.requireNonNull(decision);
            java.util.Objects.requireNonNull(startedAt);
            java.util.Objects.requireNonNull(completedAt);
            if (completedAt.isBefore(startedAt)) throw new IllegalArgumentException("Invalid native operation window");
            evidence = List.copyOf(evidence);
        }
    }
    interface Session {
        List<EvidenceRef> registrationEvidence();
        NativeUse validate(JsonNode observation, String fixtureId, TranscriptEntry request,
                Element requestXml, byte[] requestBytes, TranscriptEntry responseOrNull,
                Element responseXmlOrNull) throws Exception;
    }
}
