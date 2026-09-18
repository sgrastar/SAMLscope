package com.samlscope.runner.cases;

import java.security.MessageDigest;
import java.time.Instant;
import java.util.*;
import java.util.function.BiFunction;
import com.samlscope.core.caseexec.CaseContext;
import com.samlscope.core.evaluation.EvidenceRef;
import com.samlscope.core.transcript.*;
import com.samlscope.saml.crypto.PlanCredentials;
import com.samlscope.saml.normal.SecureXml;

/** Collects protocol facts only. Preparation/principal binding is required before comparison. */
final class AttributePolicyProtocolEvidence {
    static final List<String> VARIANTS = List.of("control", "attribute-policy-entity-present",
            "attribute-policy-entity-absent", "attribute-policy-requested-required",
            "attribute-policy-requested-optional", "attribute-policy-requested-absent", "attribute-policy-indexed");
    record Observation(String variant, String selector, String metadataFingerprint, String entityId,
                       Instant issued, Instant received, AttributePolicyAttributeReader.Observation attributes,
                       List<EvidenceRef> evidence) {
        Observation { evidence = List.copyOf(evidence); }
    }
    record Collected(List<Observation> observations, List<String> issues) {
        Collected { observations = List.copyOf(observations); issues = List.copyOf(issues); }
    }

    static Collected collect(CaseContext context, TranscriptContentReader content, byte[] targetMetadata,
                             BiFunction<String, String, Optional<PlanCredentials>> keys) {
        var collected = MetadataAlgorithmEvidence.collect(VARIANTS, context, content, targetMetadata);
        var issues = new ArrayList<>(collected.issues());
        var observations = new ArrayList<Observation>();
        try {
            var target = SecureXml.parse(targetMetadata).getDocumentElement().getAttribute("entityID");
            var entries = new HashMap<String, TranscriptEntry>();
            for (var entry : context.transcript().list(context.runId())) {
                if (!context.runId().equals(entry.runId()) || entries.put(entry.id(), entry) != null) {
                    return new Collected(List.of(), List.of("ambiguous_history"));
                }
            }
            for (var exchange : collected.exchanges()) {
                try {
                    if (exchange.evidence().size() != 4) throw new IllegalArgumentException();
                    var prepared = entries.get(exchange.evidence().get(1).reference());
                    var request = entries.get(exchange.evidence().get(2).reference());
                    var response = entries.get(exchange.evidence().get(3).reference());
                    var requestXml = SecureXml.parse(content.readDecodedSaml(request)).getDocumentElement();
                    var selector = requestXml.getAttribute("AttributeConsumingServiceIndex");
                    if ("attribute-policy-indexed".equals(exchange.variant())) {
                        if (!Set.of("0", "1").contains(selector)) {
                            issues.add("indexed_request_selector_unavailable");
                            continue;
                        }
                    } else if (!selector.isEmpty()) {
                        issues.add("unexpected_attribute_service_selector");
                        continue;
                    }
                    var attributes = AttributePolicyAttributeReader.read(context.runId(), exchange.response(), target,
                            exchange.signingKeys(), exchange.metadata(), keys.apply(context.runId(), exchange.variant()));
                    var fingerprint = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                            .digest(content.readDecodedSaml(prepared)));
                    observations.add(new Observation(exchange.variant(), selector, fingerprint,
                            exchange.metadata().getAttribute("entityID"), request.timestamp(), response.timestamp(),
                            attributes, exchange.evidence()));
                } catch (Exception unproven) {
                    issues.add("attribute_protocol_evidence_unproven:" + exchange.variant());
                }
            }
        } catch (Exception unavailable) {
            issues.add("attribute_protocol_collection_unavailable");
        }
        observations.sort(Comparator.comparing(Observation::issued));
        return new Collected(observations, issues.stream().distinct().toList());
    }
}
