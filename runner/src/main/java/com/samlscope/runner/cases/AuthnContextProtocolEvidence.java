package com.samlscope.runner.cases;

import static com.samlscope.runner.cases.MetadataAlgorithmEvidence.children;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.*;
import java.util.function.BiFunction;
import org.w3c.dom.Element;
import com.samlscope.core.caseexec.CaseContext;
import com.samlscope.core.evaluation.EvidenceRef;
import com.samlscope.core.transcript.*;
import com.samlscope.saml.crypto.PlanCredentials;
import com.samlscope.saml.normal.SecureXml;

/** Explicit original-reference selection: never pick a nearby response or infer a configuration change. */
final class AuthnContextProtocolEvidence {
    private static final String MD="urn:oasis:names:tc:SAML:2.0:metadata";
    private static final String S="urn:oasis:names:tc:SAML:2.0:assertion";
    private static final String P="urn:oasis:names:tc:SAML:2.0:protocol";
    record Exchange(String condition, String metadataReference,
                    String requestReference, String responseReference) {}
    record Observation(String condition, String entityId, String metadataHash, String requestFingerprint,
                       Instant issued, Instant received, com.samlscope.saml.normal.SamlRequestedAuthnContextRequestFactory.ContextRequest request, AuthnContextResponseEvidence.Observation response,
                       List<EvidenceRef> evidence) {}
    record Collected(String runId, List<Observation> observations, List<String> issues) {}

    static Collected collect(CaseContext context, TranscriptContentReader content, byte[] targetMetadata,
            BiFunction<String,String,Optional<PlanCredentials>> keys, List<Exchange> exchanges) {
        var observations=new ArrayList<Observation>();var issues=new ArrayList<String>();
        try {
            require(context.transcriptComplete());
            var entries=context.transcript().list(context.runId());
            var byId=new HashMap<String,TranscriptEntry>();
            for(var entry:entries) require(context.runId().equals(entry.runId()) && byId.put(entry.id(),entry)==null);
            var target=SecureXml.parse(targetMetadata).getDocumentElement();
            require(MD.equals(target.getNamespaceURI()) && "EntityDescriptor".equals(target.getLocalName()));
            require(!target.getAttribute("entityID").isBlank());
            var signingKeys=MetadataAlgorithmEvidence.signingKeys(target);require(!signingKeys.isEmpty());
            var used=new HashSet<String>();
            for(var selected:exchanges) {
                try {
                    require(selected.condition()!=null && !selected.condition().isBlank());
                    var metadata=byId.get(selected.metadataReference());
                    var request=byId.get(selected.requestReference());
                    var response=byId.get(selected.responseReference());
                    require(metadata!=null && request!=null && response!=null);
                    require(used.add(request.id()) && used.add(response.id()));
                    require(metadata.direction()==Direction.OUTBOUND && "MetadataPrepared".equals(metadata.samlSummary().get("type")));
                    require("preloaded-aggregate".equals(metadata.samlSummary().get("variant")));
                    var rawMetadata=content.readDecodedSaml(metadata);
                    String metadataHash=hash(rawMetadata);
                    require(metadataHash.equals(metadata.samlSummary().get("metadataSha256")));
                    var fetch=byId.get(metadata.samlSummary().get("fetchTranscriptId"));
                    require(fetch!=null && fetch.direction()==Direction.INBOUND && "MetadataFetch".equals(fetch.samlSummary().get("type"))
                        && "preloaded-aggregate".equals(fetch.samlSummary().get("variant")) && !fetch.timestamp().isAfter(metadata.timestamp()));
                    require(request.direction()==Direction.OUTBOUND && "AuthnRequest".equals(request.samlSummary().get("type"))
                        && "metadata-preloaded".equals(request.samlSummary().get("campaign")));
                    var sent=SecureXml.parse(content.readDecodedSaml(request)).getDocumentElement();
                    require(P.equals(sent.getNamespaceURI()) && "AuthnRequest".equals(sent.getLocalName()));
                    String requestId=sent.getAttribute("ID");
                    require(!requestId.isBlank() && requestId.equals(request.samlSummary().get("id")));
                    require(entries.stream().filter(e->e.direction()==Direction.OUTBOUND && "AuthnRequest".equals(e.samlSummary().get("type"))
                        && requestId.equals(e.samlSummary().get("id"))).count()==1);
                    var issuers=children(sent,S,"Issuer");require(issuers.size()==1);
                    var aggregate=SecureXml.parse(rawMetadata).getDocumentElement();
                    require(MD.equals(aggregate.getNamespaceURI()) && "EntitiesDescriptor".equals(aggregate.getLocalName()));
                    var entities=new HashMap<String,Element>();
                    for(var entity:children(aggregate,MD,"EntityDescriptor")) {
                        require(!entity.getAttribute("entityID").isBlank() && entities.put(entity.getAttribute("entityID"),entity)==null);
                    }
                    var entity=entities.get(issuers.getFirst().getTextContent());require(entity!=null);
                    var roles=children(entity,MD,"SPSSODescriptor");require(roles.size()==1);
                    String acs=sent.getAttribute("AssertionConsumerServiceURL");
                    require(!acs.isBlank() && children(roles.getFirst(),MD,"AssertionConsumerService").stream()
                        .anyMatch(endpoint->acs.equals(endpoint.getAttribute("Location"))));
                    require(sent.getAttribute("Destination").equals(request.url()) && children(target,MD,"IDPSSODescriptor").stream()
                        .flatMap(role->children(role,MD,"SingleSignOnService").stream()).anyMatch(endpoint->request.url().equals(endpoint.getAttribute("Location"))));
                    require(metadata.timestamp().isBefore(request.timestamp()) && request.timestamp().isBefore(response.timestamp()));
                    require(response.direction()==Direction.INBOUND && "Response".equals(response.samlSummary().get("type")) && acs.equals(response.url()));
                    var matches=new ArrayList<String>();
                    for(var candidate:entries) {
                        if(candidate.direction()!=Direction.INBOUND || !"Response".equals(candidate.samlSummary().get("type"))) continue;
                        var xml=SecureXml.parse(content.readDecodedSaml(candidate)).getDocumentElement();
                        if(requestId.equals(xml.getAttribute("InResponseTo"))) matches.add(candidate.id());
                    }
                    require(matches.equals(List.of(response.id())));
                    String variant=String.valueOf(request.samlSummary().get("variant"));
                    require(!variant.isBlank() && !"null".equals(variant));
                    var observed=AuthnContextResponseEvidence.read(SecureXml.parse(content.readDecodedSaml(response)).getDocumentElement(),
                        target.getAttribute("entityID"),signingKeys,entity,keys.apply(context.runId(),variant),requestId,acs);
                    observations.add(new Observation(selected.condition(),entity.getAttribute("entityID"),metadataHash, requestFingerprint(sent),
                        request.timestamp(),response.timestamp(),AuthnContextRequestEvidence.read(sent),observed,List.of(ref(fetch),ref(metadata),ref(request),ref(response))));
                } catch(Exception unproven) { issues.add("authn_context_exchange_unproven"); }
            }
        } catch(Exception unproven) { issues.add("authn_context_originals_unproven"); }
        observations.sort(Comparator.comparing(Observation::issued));
        return new Collected(context.runId(),List.copyOf(observations),issues.stream().distinct().toList());
    }
    private static String requestFingerprint(Element request) throws Exception {
        var document=SecureXml.newDocument();
        var root=(Element)document.importNode(request,true);document.appendChild(root);
        root.removeAttribute("ID");root.removeAttribute("IssueInstant");
        for(var signature:children(root,"http://www.w3.org/2000/09/xmldsig#","Signature")) root.removeChild(signature);
        for(var context:children(root,P,"RequestedAuthnContext")) root.removeChild(context);
        // The compared context request is read separately. Preserve all unrelated request inputs.
        // Prefix/serialization differences conservatively prevent adoption rather than hiding a change.
        return hash(SecureXml.serialize(document));
    }
    private static EvidenceRef ref(TranscriptEntry entry) { return new EvidenceRef("transcript",entry.id()); }
    private static String hash(byte[] bytes) throws Exception { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes)); }
    private static void require(boolean condition) { if(!condition) throw new IllegalArgumentException("Unproven authentication context exchange"); }
}
