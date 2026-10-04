package com.samlscope.runner.cases;

import com.fasterxml.jackson.databind.JsonNode;
import com.samlscope.core.caseexec.CaseContext;
import com.samlscope.core.evaluation.EvidenceRef;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import org.w3c.dom.Element;

/** Native policy and actual consumer proof for a clock campaign; no actions may be sent here. */
public interface ClockSkewNativeAdapter {
    String adapter();
    Session open(CaseContext context, Path folder, JsonNode manifest, byte[] fixedTargetMetadata) throws Exception;

    enum Decision { ACCEPTED, CAUSAL_TIME_REJECTION, INVALID_SIGNATURE_REJECTION, UNPROVEN }
    record NativeUse(String policyId, String consumerId, Duration targetAttestedTolerance,
            Instant nativeStartedAt, Instant nativeCompletedAt, Decision decision,
            List<EvidenceRef> evidence) {
        public NativeUse { evidence = List.copyOf(evidence); }
    }
    interface Session {
        /**
         * Read original-backed native configuration/T, clock and operation results, bind their
         * source/runtime/epoch/restoration to this input, and establish real consumption.
         * API availability, a parser accepting XML, an ignored Extension, an HTTP error, or
         * a declared receipt boolean cannot establish any decision other than UNPROVEN.
         * CAUSAL_TIME_REJECTION requires the actual consumer's time-policy failure for this
         * exact otherwise valid input; invalid signatures and unrelated policy errors differ.
         */
        NativeUse validate(JsonNode observation, String fixtureId, Element originalInput,
                byte[] inputBytes, Element responseOrNull) throws Exception;
    }
}
