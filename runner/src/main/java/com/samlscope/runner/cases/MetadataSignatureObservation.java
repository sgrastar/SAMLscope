package com.samlscope.runner.cases;

import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import com.samlscope.core.transcript.Direction;
import com.samlscope.core.transcript.TranscriptEntry;

/** Uses Suite-issued controls and correlated protocol responses, never a submitted verdict. */
final class MetadataSignatureObservation {
    private static final String SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success";
    private static final Set<String> ERRORS = Set.of(
            "urn:oasis:names:tc:SAML:2.0:status:Requester",
            "urn:oasis:names:tc:SAML:2.0:status:Responder");

    static Result observe(String runId, List<TranscriptEntry> entries) {
        var requests = new HashMap<String, TranscriptEntry>();
        var duplicates = new HashSet<String>();
        var positive = new HashSet<String>();
        var rejected = new HashSet<String>();
        var accepted = new HashSet<String>();
        var groups = new HashMap<String, String>();
        var invalidRequestIds = new HashSet<String>();
        var evidence = new HashSet<String>();
        for (var entry : entries) {
            if (!runId.equals(entry.runId())) continue;
            var summary = entry.samlSummary();
            if (entry.direction() == Direction.OUTBOUND && entry.decodedSamlBytes() > 0
                    && "AuthnRequest".equals(summary.get("type"))
                    && "metadata-polling".equals(summary.get("campaign"))
                    && summary.get("id") instanceof String id && !id.isBlank()
                    && summary.get("variant") instanceof String variant && !variant.isBlank()
                    && summary.get("metadataSignatureGroup") instanceof String group && !group.isBlank()) {
                if (requests.putIfAbsent(id, entry) != null) duplicates.add(id);
                if ("invalid".equals(summary.get("metadataSignatureControl"))) invalidRequestIds.add(id);
            }
        }
        for (var entry : entries) {
            if (!runId.equals(entry.runId()) || entry.direction() != Direction.INBOUND
                    || entry.decodedSamlBytes() <= 0
                    || !Boolean.TRUE.equals(entry.samlSummary().get("metadataProbeAccepted"))) continue;
            var id = entry.samlSummary().get("inResponseTo");
            var request = requests.get(id);
            if (request == null || duplicates.contains(id) || entry.timestamp().isBefore(request.timestamp())) continue;
            var variant = (String) request.samlSummary().get("variant");
            if (!MetadataProbeCorrelation.matches(entry.url(), runId, variant)) continue;
            var group = variant + "|" + request.samlSummary().get("metadataSignatureGroup") + "|" + request.url();
            groups.put(group, variant);
            var status = entry.samlSummary().get("statusCode");
            if ("invalid".equals(request.samlSummary().get("metadataSignatureControl"))) {
                if (SUCCESS.equals(status)) accepted.add(group);
                else if (status instanceof String value && ERRORS.contains(value)) rejected.add(group);
                else continue;
            } else if ("valid".equals(request.samlSummary().get("metadataSignatureControl")) && SUCCESS.equals(status)) {
                positive.add(group);
            } else continue;
            evidence.add(request.id());
            evidence.add(entry.id());
        }
        var blocked = new HashSet<String>();
        accepted.forEach(group -> blocked.add(groups.get(group)));
        var verified = new HashSet<String>();
        positive.stream().filter(rejected::contains).map(groups::get)
                .filter(variant -> !blocked.contains(variant)).forEach(verified::add);
        return new Result(Set.copyOf(verified), Set.copyOf(blocked), Set.copyOf(invalidRequestIds), Set.copyOf(evidence));
    }

    record Result(Set<String> verified, Set<String> acceptedInvalid, Set<String> invalidRequestIds, Set<String> evidence) {}
}
