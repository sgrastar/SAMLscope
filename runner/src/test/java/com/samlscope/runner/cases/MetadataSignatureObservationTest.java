package com.samlscope.runner.cases;

import static org.junit.jupiter.api.Assertions.assertEquals;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;
import com.samlscope.core.transcript.Direction;
import com.samlscope.core.transcript.TranscriptEntry;

class MetadataSignatureObservationTest {
    private static final String RUN = "run-test";
    private static final String VARIANT = "keyvalue-only";
    private static final String SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success";
    private static final String REJECT = "urn:oasis:names:tc:SAML:2.0:status:Requester";

    @Test void requiresBothResponsesInTheSameCampaignMember() {
        var result = observe(request("bad", "invalid", "group"), response("bad", REJECT),
                request("good", "valid", "group"), response("good", SUCCESS));
        assertEquals(Set.of(VARIANT), result.verified());
        assertEquals(4, result.evidence().size());
        assertEquals(Set.of(), observe(request("bad", "invalid", "old"), response("bad", REJECT),
                request("good", "valid", "new"), response("good", SUCCESS)).verified());
    }

    @Test void silenceAndUnissuedErrorsDoNotProveRejection() {
        assertEquals(Set.of(), observe(request("bad", "invalid", "group"),
                request("good", "valid", "group"), response("good", SUCCESS)).verified());
        assertEquals(Set.of(), observe(response("bad", REJECT),
                request("good", "valid", "group"), response("good", SUCCESS)).verified());
    }

    @Test void invalidAcceptanceAndDuplicateRequestIdsPreventSuccess() {
        var rejected = response("bad", REJECT);
        var accepted = response("bad", SUCCESS);
        var result = observe(request("bad", "invalid", "group"), rejected, accepted,
                request("good", "valid", "group"), response("good", SUCCESS));
        assertEquals(Set.of(), result.verified());
        assertEquals(Set.of(VARIANT), result.acceptedInvalid());
        assertEquals(Set.of(), observe(request("bad", "invalid", "group"), request("bad", "invalid", "group"),
                rejected, request("good", "valid", "group"), response("good", SUCCESS)).verified());
    }

    @Test void wrongRunVariantAndUnrecognizedStatusCannotSupplyControl() {
        for (var wrong : List.of(
                entry("wrong-run", "another-run", Direction.INBOUND, response("bad", REJECT).url(), response("bad", REJECT).samlSummary()),
                entry("wrong-url", RUN, Direction.INBOUND, "https://suite/acs?run=" + RUN + "&mdv=other", response("bad", REJECT).samlSummary()),
                response("bad", "unrecognized"))) {
            assertEquals(Set.of(), observe(request("bad", "invalid", "group"), wrong,
                    request("good", "valid", "group"), response("good", SUCCESS)).verified());
        }
    }

    private MetadataSignatureObservation.Result observe(TranscriptEntry... entries) {
        return MetadataSignatureObservation.observe(RUN, List.of(entries));
    }

    private TranscriptEntry request(String id, String control, String group) {
        return entry(id, RUN, Direction.OUTBOUND, "https://idp/sso", Map.of(
                "type", "AuthnRequest", "id", id, "variant", VARIANT,
                "campaign", "metadata-polling", "metadataSignatureControl", control,
                "metadataSignatureGroup", group));
    }

    private TranscriptEntry response(String id, String status) {
        return entry(id + status, RUN, Direction.INBOUND, "https://suite/acs?run=" + RUN + "&mdv=" + VARIANT,
                Map.of("type", "Response", "metadataProbeAccepted", true, "inResponseTo", id, "statusCode", status));
    }

    private TranscriptEntry entry(String id, String run, Direction direction, String url, Map<String, Object> summary) {
        return new TranscriptEntry(id, run, direction, Instant.parse("2026-09-17T00:00:00Z"),
                null, "POST", url, 200, Map.of(), null, 0, "decoded", 10, null, null, summary);
    }
}
