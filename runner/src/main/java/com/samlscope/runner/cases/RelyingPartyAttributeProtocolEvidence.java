package com.samlscope.runner.cases;

import static com.samlscope.runner.cases.MetadataAlgorithmEvidence.children;
import java.time.Instant;
import java.security.MessageDigest;
import java.util.*;
import java.util.function.BiFunction;
import org.w3c.dom.Element;
import com.samlscope.core.caseexec.CaseContext;
import com.samlscope.core.evaluation.EvidenceRef;
import com.samlscope.core.transcript.*;
import com.samlscope.saml.crypto.PlanCredentials;
import com.samlscope.saml.normal.SecureXml;

/** Verifies original preloaded metadata and RP-specific signed response evidence; no outcome here. */
final class RelyingPartyAttributeProtocolEvidence {
    private static final String MD = "urn:oasis:names:tc:SAML:2.0:metadata";
    private static final String S = "urn:oasis:names:tc:SAML:2.0:assertion";
    private static final String P = "urn:oasis:names:tc:SAML:2.0:protocol";
    static final Set<String> VARIANTS = Set.of("attribute-policy-entity-absent", "attribute-policy-requested-absent");
    record Observation(String variant, String entityId, String aggregateHash, String metadataHash,
                       Instant issued, Instant received, AttributePolicyAttributeReader.Observation attributes,
                       List<EvidenceRef> evidence) {}
    record Collected(String runId, List<Observation> observations, List<String> issues) {}

    static Collected collect(CaseContext context, TranscriptContentReader content, byte[] targetMetadata,
                             BiFunction<String, String, Optional<PlanCredentials>> keys) {
        var issues = new ArrayList<String>();
        var observations = new ArrayList<Observation>();
        try {
            require(context.transcriptComplete());
            var entries = context.transcript().list(context.runId());
            var byId = new HashMap<String, TranscriptEntry>();
            for (var entry : entries) require(context.runId().equals(entry.runId()) && byId.put(entry.id(), entry) == null);
            var target = SecureXml.parse(targetMetadata).getDocumentElement();
            require(MD.equals(target.getNamespaceURI()) && "EntityDescriptor".equals(target.getLocalName()));
            var signingKeys = MetadataAlgorithmEvidence.signingKeys(target);
            require(!signingKeys.isEmpty());
            var prepared = entries.stream().filter(e -> e.direction() == Direction.OUTBOUND
                    && "MetadataPrepared".equals(e.samlSummary().get("type"))
                    && "preloaded-aggregate".equals(e.samlSummary().get("variant"))).toList();
            // Multiple imports need an explicit binding instead of picking a nearby metadata document.
            require(prepared.size() == 1);
            var metadataEntry = prepared.getFirst();
            var original = content.readDecodedSaml(metadataEntry);
            String aggregateHash = hash(original);
            require(aggregateHash.equals(metadataEntry.samlSummary().get("metadataSha256")));
            var fetch = byId.get(metadataEntry.samlSummary().get("fetchTranscriptId"));
            require(fetch != null && fetch.direction() == Direction.INBOUND
                    && "MetadataFetch".equals(fetch.samlSummary().get("type"))
                    && "preloaded-aggregate".equals(fetch.samlSummary().get("variant"))
                    && !fetch.timestamp().isAfter(metadataEntry.timestamp()));
            var aggregate = SecureXml.parse(original).getDocumentElement();
            require(MD.equals(aggregate.getNamespaceURI()) && "EntitiesDescriptor".equals(aggregate.getLocalName()));
            var entities = new HashMap<String, Element>();
            for (var entity : children(aggregate, MD, "EntityDescriptor")) {
                require(!entity.getAttribute("entityID").isBlank() && entities.put(entity.getAttribute("entityID"), entity) == null);
            }
            var requestIds = new HashSet<String>();
            for (var request : entries) {
                if (request.direction() != Direction.OUTBOUND || !"AuthnRequest".equals(request.samlSummary().get("type"))
                        || !VARIANTS.contains(String.valueOf(request.samlSummary().get("variant")))) continue;
                try {
                    require("metadata-preloaded".equals(request.samlSummary().get("campaign")));
                    var sent = SecureXml.parse(content.readDecodedSaml(request)).getDocumentElement();
                    require(P.equals(sent.getNamespaceURI()) && "AuthnRequest".equals(sent.getLocalName()));
                    String requestId = sent.getAttribute("ID");
                    require(!requestId.isBlank() && requestId.equals(request.samlSummary().get("id")) && requestIds.add(requestId));
                    var issuers = children(sent, S, "Issuer");
                    require(issuers.size() == 1);
                    var entity = entities.get(issuers.getFirst().getTextContent());
                    require(entity != null && metadataEntry.timestamp().isBefore(request.timestamp()));
                    var roles = children(entity, MD, "SPSSODescriptor");
                    require(roles.size() == 1);
                    String acs = sent.getAttribute("AssertionConsumerServiceURL");
                    require(!acs.isBlank() && children(roles.getFirst(), MD, "AssertionConsumerService").stream()
                            .anyMatch(e -> acs.equals(e.getAttribute("Location"))));
                    require(sent.getAttribute("Destination").equals(request.url()));
                    require(children(target, MD, "IDPSSODescriptor").stream().flatMap(role -> children(role, MD, "SingleSignOnService").stream())
                            .anyMatch(e -> request.url().equals(e.getAttribute("Location"))));
                    var responses = new ArrayList<TranscriptEntry>();
                    for (var entry : entries) {
                        if (entry.direction() != Direction.INBOUND || !"Response".equals(entry.samlSummary().get("type"))) continue;
                        var xml = SecureXml.parse(content.readDecodedSaml(entry)).getDocumentElement();
                        if (requestId.equals(xml.getAttribute("InResponseTo"))) responses.add(entry);
                    }
                    require(responses.size() == 1);
                    var response = responses.getFirst();
                    require(request.timestamp().isBefore(response.timestamp()) && acs.equals(response.url()));
                    var responseXml = SecureXml.parse(content.readDecodedSaml(response)).getDocumentElement();
                    String variant = (String) request.samlSummary().get("variant");
                    var attributes = AttributePolicyAttributeReader.readRelyingParty(context.runId(), responseXml,
                            target.getAttribute("entityID"), signingKeys, entity, keys.apply(context.runId(), variant), requestId, acs);
                    var document = SecureXml.newDocument(); document.appendChild(document.importNode(entity, true));
                    observations.add(new Observation(variant, entity.getAttribute("entityID"), aggregateHash,
                            hash(SecureXml.serialize(document)), request.timestamp(), response.timestamp(), attributes,
                            List.of(ref(fetch), ref(metadataEntry), ref(request), ref(response))));
                } catch (Exception unproven) { issues.add("relying_party_exchange_unproven"); }
            }
        } catch (Exception unproven) { issues.add("preloaded_originals_unproven"); }
        observations.sort(Comparator.comparing(Observation::issued));
        return new Collected(context.runId(), List.copyOf(observations), issues.stream().distinct().toList());
    }
    private static String hash(byte[] raw) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(raw));
    }
    private static EvidenceRef ref(TranscriptEntry entry) { return new EvidenceRef("transcript", entry.id()); }
    private static void require(boolean condition) { if (!condition) throw new IllegalArgumentException("Unproven RP evidence"); }
}
