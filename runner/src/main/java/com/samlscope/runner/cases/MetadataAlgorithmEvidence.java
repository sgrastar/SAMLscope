package com.samlscope.runner.cases;

import java.util.*;
import java.security.cert.*;
import java.security.MessageDigest;
import org.w3c.dom.Element;
import com.samlscope.core.caseexec.CaseContext;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.transcript.*;
import com.samlscope.saml.normal.SecureXml;
import com.samlscope.saml.crypto.VerifiedSignatureAlgorithms;

/** Binds original prepared metadata, its fetch, a normal request and a verified target response. */
final class MetadataAlgorithmEvidence {
    private static final String MD="urn:oasis:names:tc:SAML:2.0:metadata", ALG="urn:oasis:names:tc:SAML:metadata:algsupport";
    private static final String SAML="urn:oasis:names:tc:SAML:2.0:assertion", P="urn:oasis:names:tc:SAML:2.0:protocol", DS="http://www.w3.org/2000/09/xmldsig#";
    record Prepared(TranscriptEntry entry,TranscriptEntry fetch,Element xml) {}
    record Exchange(String campaign,String variant,Element metadata,Element response,
                    List<VerifiedSignatureAlgorithms.Observation> signatures,List<X509Certificate> signingKeys,List<EvidenceRef> evidence) {}
    record Collected(List<Exchange> exchanges,List<String> issues) {}
    static CaseOutcome observe(String id,CaseContext context,TranscriptContentReader content,byte[] targetMetadata) {
        var collected=collect(MetadataAlgorithmSelection.required(id),context,content,targetMetadata);
        var samples=collected.exchanges().stream().map(e->new MetadataAlgorithmSelection.Sample(e.campaign(),e.variant(),
                new MetadataAlgorithmSelection.Input(methods(e.metadata()),methods(children(e.metadata(),MD,"SPSSODescriptor").getFirst())),
                e.signatures().stream().map(s->new MetadataAlgorithmSelection.Methods(List.of(s.digestAlgorithm()),List.of(s.signatureAlgorithm()))).toList(),e.evidence())).toList();
        return MetadataAlgorithmSelection.evaluate(id,samples,collected.issues());
    }
    static Collected collect(List<String> required,CaseContext context,TranscriptContentReader content,byte[] targetMetadata) {
        var exchanges=new ArrayList<Exchange>();var issues=new ArrayList<String>();
        try {
            if(!context.transcriptComplete())return new Collected(List.of(),List.of("history_incomplete"));
            var target=SecureXml.parse(targetMetadata).getDocumentElement();
            if(!MD.equals(target.getNamespaceURI()) || !"EntityDescriptor".equals(target.getLocalName()) || target.getAttribute("entityID").isBlank())
                return new Collected(List.of(),List.of("target_entity_unavailable"));
            var certificates=signingKeys(target);
            if(certificates.isEmpty())return new Collected(List.of(),List.of("target_signing_keys_unavailable"));
            var entries=context.transcript().list(context.runId());var byId=new HashMap<String,TranscriptEntry>();
            for(var entry:entries)if(!context.runId().equals(entry.runId()) || byId.put(entry.id(),entry)!=null)
                return new Collected(List.of(),List.of("ambiguous_history"));
            var requests=new HashMap<String,TranscriptEntry>();var requestXml=new HashMap<String,Element>();
            var duplicates=new HashSet<String>();var seenRequestIds=new HashSet<String>();var prepared=new HashMap<String,List<Prepared>>();
            for(var entry:entries) {
                var summary=entry.samlSummary();var variant=String.valueOf(summary.get("variant"));
                if(!required.contains(variant))continue;
                if(entry.direction()==Direction.OUTBOUND && "AuthnRequest".equals(summary.get("type"))) {
                    var xml=SecureXml.parse(content.readDecodedSaml(entry)).getDocumentElement();
                    if(!P.equals(xml.getNamespaceURI()) || !"AuthnRequest".equals(xml.getLocalName()) || xml.getAttribute("ID").isBlank())continue;
                    if(!seenRequestIds.add(xml.getAttribute("ID")))duplicates.add(xml.getAttribute("ID"));
                    if(!"valid".equals(summary.get("metadataSignatureControl")))continue;
                    requests.put(xml.getAttribute("ID"),entry);
                    requestXml.put(entry.id(),xml);
                }
                if(entry.direction()!=Direction.OUTBOUND || !"MetadataPrepared".equals(summary.get("type")))continue;
                var fetch=byId.get(String.valueOf(summary.get("fetchTranscriptId")));
                if(fetch==null || fetch.direction()!=Direction.INBOUND || !"MetadataFetch".equals(fetch.samlSummary().get("type"))
                        || !variant.equals(fetch.samlSummary().get("variant")) || !Objects.equals(fetch.status(),200)
                        || !Objects.equals(entry.status(),200) || !Objects.equals(entry.correlationId(),fetch.id())
                        || !Objects.equals(entry.url(),fetch.url()) || entry.timestamp().isBefore(fetch.timestamp())
                        || !"PREPARED".equals(summary.get("delivery"))) { issues.add("unbound_metadata:"+variant);continue; }
                var bytes=content.readDecodedSaml(entry);
                if(!HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes)).equals(summary.get("metadataSha256"))) {
                    issues.add("metadata_hash_mismatch:"+variant);continue;
                }
                prepared.computeIfAbsent(variant,v->new ArrayList<>()).add(new Prepared(entry,fetch,SecureXml.parse(bytes).getDocumentElement()));
            }
            for(var entry:entries) {
                if(entry.direction()!=Direction.INBOUND || !"Response".equals(entry.samlSummary().get("type"))
                        || !Boolean.TRUE.equals(entry.samlSummary().get("metadataProbeAccepted")))continue;
                var response=SecureXml.parse(content.readDecodedSaml(entry)).getDocumentElement();
                var correlation=response.getAttribute("InResponseTo");var request=requests.get(correlation);
                if(request==null || duplicates.contains(correlation))continue;
                var variant=String.valueOf(request.samlSummary().get("variant"));
                if(entry.timestamp().isBefore(request.timestamp()) || !MetadataProbeCorrelation.matches(entry.url(),context.runId(),variant))continue;
                var status=children(response,P,"Status");
                if(status.size()!=1 || children(status.getFirst(),P,"StatusCode").size()!=1
                        || !"urn:oasis:names:tc:SAML:2.0:status:Success".equals(children(status.getFirst(),P,"StatusCode").getFirst().getAttribute("Value")))continue;
                var available=prepared.getOrDefault(variant,List.of()).stream().filter(p->!p.entry().timestamp().isAfter(request.timestamp()))
                        .sorted(Comparator.comparing((Prepared p)->p.entry().timestamp()).reversed()).toList();
                if(available.isEmpty())continue;
                var original=available.getFirst();
                if(available.stream().anyMatch(p->p.entry().timestamp().equals(original.entry().timestamp())
                        && !Objects.equals(p.entry().samlSummary().get("metadataSha256"),original.entry().samlSummary().get("metadataSha256")))) {
                    issues.add("ambiguous_metadata:"+variant);continue;
                }
                var sent=requestXml.get(request.id());var issuers=children(sent,SAML,"Issuer");var xml=original.xml();var roles=children(xml,MD,"SPSSODescriptor");
                if(!MD.equals(xml.getNamespaceURI()) || !"EntityDescriptor".equals(xml.getLocalName()) || roles.size()!=1 || issuers.size()!=1
                        || !xml.getAttribute("entityID").equals(issuers.getFirst().getTextContent())) { issues.add("metadata_entity_mismatch:"+variant);continue; }
                var destination=sent.getAttribute("AssertionConsumerServiceURL");
                if(destination.isBlank() || !destination.equals(response.getAttribute("Destination")) || !destination.equals(entry.url())
                        || children(roles.getFirst(),MD,"AssertionConsumerService").stream().noneMatch(e->destination.equals(e.getAttribute("Location")))) {
                    issues.add("metadata_endpoint_mismatch:"+variant);continue;
                }
                var signatures=new VerifiedSignatureAlgorithms().read(response,target.getAttribute("entityID"),certificates);
                long signatureCount=children(response,DS,"Signature").size()+children(response,SAML,"Assertion").stream().mapToInt(e->children(e,DS,"Signature").size()).sum();
                if(signatures.stream().noneMatch(s->s.element().equals("Response")) || signatures.size()!=signatureCount) {
                    issues.add("target_signature_unverified:"+variant);continue;
                }
                var group=String.valueOf(request.samlSummary().get("metadataSignatureGroup"));
                int separator=group.lastIndexOf(':');
                if(!group.startsWith("poll_") || separator<6) { issues.add("campaign_unavailable:"+variant);continue; }
                var campaign=group.substring(0,separator);
                exchanges.add(new Exchange(campaign,variant,xml,response,signatures,certificates,
                        List.of(ref(original.fetch()),ref(original.entry()),ref(request),ref(entry))));
            }
        } catch(Exception unavailable) { issues.add("evidence_unreadable"); }
        return new Collected(List.copyOf(exchanges),List.copyOf(issues));
    }
    private static EvidenceRef ref(TranscriptEntry entry) { return new EvidenceRef("transcript",entry.id()); }
    static List<Element> children(Element parent,String ns,String name) {
        var result=new ArrayList<Element>();
        for(var n=parent.getFirstChild();n!=null;n=n.getNextSibling())if(n instanceof Element e && ns.equals(e.getNamespaceURI()) && name.equals(e.getLocalName()))result.add(e);
        return result;
    }
    private static MetadataAlgorithmSelection.Methods methods(Element element) {
        var ext=children(element,MD,"Extensions");
        if(ext.size()>1)throw new IllegalArgumentException("Ambiguous metadata extensions");
        return new MetadataAlgorithmSelection.Methods(ext.isEmpty()?List.of():children(ext.getFirst(),ALG,"DigestMethod").stream().map(e->e.getAttribute("Algorithm")).toList(),
                ext.isEmpty()?List.of():children(ext.getFirst(),ALG,"SigningMethod").stream().map(e->e.getAttribute("Algorithm")).toList());
    }
    static List<X509Certificate> signingKeys(Element target) throws Exception {
        var result=new ArrayList<X509Certificate>();var factory=CertificateFactory.getInstance("X.509");
        for(var role:children(target,MD,"IDPSSODescriptor")) {
            if(!Arrays.asList(role.getAttribute("protocolSupportEnumeration").split("\\s+")).contains(P))continue;
            for(var key:children(role,MD,"KeyDescriptor")) {
                if(!key.getAttribute("use").isBlank() && !"signing".equals(key.getAttribute("use")))continue;
                for(var info:children(key,DS,"KeyInfo"))for(var data:children(info,DS,"X509Data"))for(var cert:children(data,DS,"X509Certificate"))
                    result.add((X509Certificate)factory.generateCertificate(new java.io.ByteArrayInputStream(Base64.getDecoder().decode(cert.getTextContent().replaceAll("\\s+","")))));
            }
        }
        return result;
    }
}
