package com.samlscope.runner.cases;

import static com.samlscope.runner.cases.MetadataAlgorithmEvidence.children;
import java.nio.file.*;
import java.security.*;
import java.security.cert.*;
import java.time.Instant;
import java.util.*;
import com.fasterxml.jackson.databind.JsonNode;
import com.samlscope.core.caseexec.CaseContext;
import com.samlscope.core.evaluation.EvidenceRef;
import com.samlscope.core.transcript.*;
import com.samlscope.saml.crypto.*;
import com.samlscope.saml.normal.SecureXml;
import com.samlscope.store.JsonCodec;
import org.w3c.dom.Element;

/** Local native-event receipt, rechecked against immutable Run originals before any case can use it. */
final class NativeCertificateEvidenceFile {
    private static final String MD="urn:oasis:names:tc:SAML:2.0:metadata", S="urn:oasis:names:tc:SAML:2.0:assertion",
        P="urn:oasis:names:tc:SAML:2.0:protocol", DS="http://www.w3.org/2000/09/xmldsig#";
    private final Path directory;
    NativeCertificateEvidenceFile(Path directory){this.directory=directory.toAbsolutePath().normalize();}
    boolean exists(String runId) {
        return runId != null && runId.matches("run_[0-9A-HJKMNP-TV-Z]{26}")
                && Files.exists(directory.resolve(runId + ".json"), LinkOption.NOFOLLOW_LINKS);
    }
    String receiptSha256(String runId) throws Exception {
        require(exists(runId));
        var file = directory.resolve(runId + ".json");
        require(Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS) && Files.size(file) <= 2097152);
        return hash(Files.readAllBytes(file));
    }
    List<NativeCertificateComparison.Sample> read(CaseContext context, byte[] targetRaw, TranscriptContentReader content)throws Exception {
        require(context.runId().matches("run_[0-9A-HJKMNP-TV-Z]{26}"));
        var file=directory.resolve(context.runId()+".json");if(!Files.exists(file,LinkOption.NOFOLLOW_LINKS))return List.of();
        require(context.transcriptComplete() && Files.isRegularFile(file,LinkOption.NOFOLLOW_LINKS)&&Files.size(file)<=2097152);
        var receipt=new JsonCodec().mapper().readTree(Files.readAllBytes(file));
        require("samlscope-native-certificate-receipt-v1".equals(text(receipt,"schema"))&&context.runId().equals(text(receipt,"runId")));
        require(hash(targetRaw).equals(text(receipt,"targetMetadataSha256"))&&receipt.path("restored").asBoolean(false));
        require(text(receipt,"nativeAuditSha256").matches("[0-9a-f]{64}")&&text(receipt,"observerSourceSha256").matches("[0-9a-f]{64}"));
        var collected=Instant.parse(text(receipt,"collectedAt"));
        var target=SecureXml.parse(targetRaw).getDocumentElement();var trusted=MetadataAlgorithmEvidence.signingKeys(target);require(!trusted.isEmpty());
        var endpoints=new HashSet<String>();for(var role:children(target,MD,"IDPSSODescriptor"))for(var endpoint:children(role,MD,"SingleSignOnService"))endpoints.add(endpoint.getAttribute("Location"));
        var entries=new HashMap<String,TranscriptEntry>();for(var e:context.transcript().list(context.runId()))require(context.runId().equals(e.runId())&&entries.put(e.id(),e)==null);
        var originals=new HashMap<String,Element>();require(receipt.path("rawEvidence").isArray());
        for(var ref:receipt.path("rawEvidence")){
            var entry=entries.get(text(ref,"reference"));require(entry!=null);
            var raw=content.readDecodedSaml(entry);require(hash(raw).equals(text(ref,"sha256")));
            require(originals.put(entry.id(),SecureXml.parse(raw).getDocumentElement())==null);
        }
        require(receipt.path("conditions").isArray()&&receipt.path("conditions").size()==NativeCertificateComparison.ALL.size());
        var samples=new ArrayList<NativeCertificateComparison.Sample>();var variants=new HashSet<String>();var used=new HashSet<String>();
        String entity=null;JsonNode policy=null;
        for(var row:receipt.path("conditions")){
            var variant=text(row,"variant");require(NativeCertificateComparison.ALL.contains(variant)&&variants.add(variant));
            var prepared=entries.get(text(row,"metadataReference"));require(prepared!=null&&prepared.direction()==Direction.OUTBOUND);
            require("MetadataPrepared".equals(prepared.samlSummary().get("type"))&&variant.equals(prepared.samlSummary().get("variant")));
            var fetch=entries.get(String.valueOf(prepared.samlSummary().get("fetchTranscriptId")));
            require(fetch!=null&&fetch.direction()==Direction.INBOUND&&"MetadataFetch".equals(fetch.samlSummary().get("type"))&&variant.equals(fetch.samlSummary().get("variant")));
            require(!fetch.timestamp().isAfter(prepared.timestamp())&&hash(content.readDecodedSaml(prepared)).equals(prepared.samlSummary().get("metadataSha256")));
            var sp=originals.get(prepared.id());require(sp!=null&&MD.equals(sp.getNamespaceURI())&&"EntityDescriptor".equals(sp.getLocalName()));
            if(entity==null)entity=sp.getAttribute("entityID");else require(entity.equals(sp.getAttribute("entityID")));
            var role=one(sp,MD,"SPSSODescriptor");var certificates=new ArrayList<X509Certificate>();
            for(var key:children(role,MD,"KeyDescriptor"))if(!"encryption".equals(key.getAttribute("use")))for(var info:children(key,DS,"KeyInfo"))for(var data:children(info,DS,"X509Data"))for(var cert:children(data,DS,"X509Certificate"))certificates.add(certificate(cert.getTextContent()));
            require(certificates.size()==1);var cert=certificates.getFirst();require("RSA".equals(cert.getPublicKey().getAlgorithm()));
            var nativeClient=row.path("nativeClient");require(entity.equals(text(nativeClient,"clientId"))&&text(nativeClient,"databaseId").matches("[a-f0-9-]{36}"));
            require(nativeClient.path("removed").asBoolean(false));var attrs=nativeClient.path("attributes");require(attrs.isObject()&&"true".equals(text(attrs,"saml.client.signature")));
            require(Arrays.equals(cert.getEncoded(),certificate(text(attrs,"saml.signing.certificate")).getEncoded()));
            var currentPolicy=(com.fasterxml.jackson.databind.node.ObjectNode)attrs.deepCopy();
            currentPolicy.remove(List.of("saml.signing.certificate","saml.encryption.certificate"));
            // Only the Suite campaign marker may differ in native endpoint settings.
            for(var name:List.of("saml_assertion_consumer_url_post", "saml_assertion_consumer_url_redirect",
                    "saml_single_logout_service_url_post", "saml_single_logout_service_url_redirect", "saml_single_logout_service_url_soap")) {
                var value=text(attrs,name); require(!value.isBlank());
                var endpointsForRole=new ArrayList<Element>(children(role,MD,"AssertionConsumerService"));
                endpointsForRole.addAll(children(role,MD,"SingleLogoutService"));
                require(endpointsForRole.stream().anyMatch(e->value.equals(e.getAttribute("Location"))));
                var marker="mdv="+variant; require(value.contains("?"+marker+"&")||value.contains("&"+marker+"&")||value.endsWith("?"+marker)||value.endsWith("&"+marker));
                currentPolicy.put(name,value.replace("?"+marker,"?mdv=control").replace("&"+marker,"&mdv=control"));
            }
            if(policy==null)policy=currentPolicy;else require(policy.equals(currentPolicy));
            var evidence=new ArrayList<EvidenceRef>();evidence.add(new EvidenceRef("transcript",fetch.id()));evidence.add(new EvidenceRef("transcript",prepared.id()));
            var decisions=new EnumMap<Slot,NativeCertificateComparison.Decision>(Slot.class);Instant requested=null;
            for(var slot:Slot.values()){
                var input=row.path(slot==Slot.POSITIVE?"positive":"negative");var sent=entries.get(text(input,"requestReference"));
                require(sent!=null&&used.add(sent.id())&&sent.direction()==Direction.OUTBOUND&&"AuthnRequest".equals(sent.samlSummary().get("type"))&&variant.equals(sent.samlSummary().get("variant")));
                require(prepared.timestamp().isBefore(sent.timestamp())&&MetadataProbeCorrelation.signatureControl(sent)==(slot==Slot.NEGATIVE));
                var request=originals.get(sent.id());require(request!=null&&P.equals(request.getNamespaceURI())&&"AuthnRequest".equals(request.getLocalName()));
                var id=request.getAttribute("ID");require(!id.isBlank()&&id.equals(sent.samlSummary().get("id"))&&entity.equals(one(request,S,"Issuer").getTextContent()));
                require(entries.values().stream().filter(e->e.direction()==Direction.OUTBOUND&&id.equals(e.samlSummary().get("id"))).count()==1);
                require(sent.url().equals(request.getAttribute("Destination"))&&endpoints.contains(sent.url()));
                var acs=request.getAttribute("AssertionConsumerServiceURL");require(children(role,MD,"AssertionConsumerService").stream().anyMatch(e->acs.equals(e.getAttribute("Location"))));
                require("POST".equals(sent.method()));var signature=one(request,DS,"Signature");var signedInfo=one(signature,DS,"SignedInfo");
                require("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256".equals(one(signedInfo,DS,"SignatureMethod").getAttribute("Algorithm")));
                require(new XmlSignatureVerifier().hasValidEnvelopedReferenceDigests(request));
                require(new XmlSignatureVerifier().hasValidEnvelopedSignature(request,cert)==(slot==Slot.POSITIVE));
                var responses=new ArrayList<TranscriptEntry>();
                for(var e:entries.values())if(e.direction()==Direction.INBOUND&&"Response".equals(e.samlSummary().get("type"))){
                    var xml=SecureXml.parse(content.readDecodedSaml(e)).getDocumentElement();if(id.equals(xml.getAttribute("InResponseTo")))responses.add(e);
                }
                NativeCertificateComparison.Decision decision;
                if(responses.isEmpty()){
                    reject(input,id,hash(content.readDecodedSaml(sent)),entity,sent,collected);
                    evidence.add(new EvidenceRef("native-signature-event",context.runId()+".json#"+id));
                    decision=NativeCertificateComparison.Decision.NATIVE_SIGNATURE_REJECTION;
                }else{
                    require(slot==Slot.POSITIVE&&responses.size()==1&&!input.path("nativeEvent").isObject());
                    var received=responses.getFirst();require(received.id().equals(text(input,"responseReference"))&&received.timestamp().isAfter(sent.timestamp())&&!received.timestamp().isAfter(collected));
                    var response=originals.get(received.id());require(response!=null&&acs.equals(received.url())&&acs.equals(response.getAttribute("Destination")));
                    require("urn:oasis:names:tc:SAML:2.0:status:Success".equals(one(one(response,P,"Status"),P,"StatusCode").getAttribute("Value")));
                    require(children(response,S,"Assertion").size()+children(response,S,"EncryptedAssertion").size()==1);
                    require(new VerifiedSignatureAlgorithms().read(response,target.getAttribute("entityID"),trusted).stream().anyMatch(s->"Response".equals(s.element())));
                    decision=NativeCertificateComparison.Decision.SIGNED_SUCCESS;evidence.add(new EvidenceRef("transcript",received.id()));
                }
                if(slot==Slot.POSITIVE)requested=sent.timestamp();decisions.put(slot,decision);evidence.add(new EvidenceRef("transcript",sent.id()));
            }
            require(requested!=null);condition(variant,cert,requested);
            samples.add(new NativeCertificateComparison.Sample(variant,context.runId(),entity,true,true,true,
                decisions.get(Slot.POSITIVE),decisions.get(Slot.NEGATIVE),evidence));
        }
        return List.copyOf(samples);
    }
    private enum Slot{POSITIVE,NEGATIVE}
    private static void condition(String variant,X509Certificate cert,Instant at)throws Exception{
        switch(variant){
            case "certificate-expired" -> require(cert.getNotAfter().toInstant().isBefore(at));
            case "certificate-not-yet-valid" -> require(cert.getNotBefore().toInstant().isAfter(at));
            case "control" -> require(!cert.getNotBefore().toInstant().isAfter(at)&&cert.getNotAfter().toInstant().isAfter(at));
            case "certificate-critical-extension" -> require(cert.getCriticalExtensionOIDs()!=null&&cert.getCriticalExtensionOIDs().contains("1.3.6.1.4.1.57264.1.1"));
            case "certificate-noncritical-extension" -> require(cert.getNonCriticalExtensionOIDs()!=null&&cert.getNonCriticalExtensionOIDs().contains("1.3.6.1.4.1.57264.1.2"));
            case "certificate-no-digital-signature" -> require(cert.getKeyUsage()!=null&&!cert.getKeyUsage()[0]);
            case "certificate-unrelated-eku" -> require(List.of("1.3.6.1.5.5.7.3.3").equals(cert.getExtendedKeyUsage()));
            case "certificate-empty-subject" -> require(cert.getSubjectX500Principal().getName().isEmpty());
            case "certificate-unknown-ca" -> require(new javax.security.auth.x500.X500Principal("O=SAMLscope,CN=Unknown SAMLscope fixture CA").equals(cert.getIssuerX500Principal()));
            default -> throw new IllegalArgumentException("Unknown certificate condition");
        }
    }
    private static void reject(JsonNode input,String id,String digest,String entity,TranscriptEntry sent,Instant collected){
        var http=input.path("nativeHttp");var event=input.path("nativeEvent");
        require(id.equals(text(http,"request_id"))&&digest.equals(text(http,"request_sha256"))&&id.equals(text(event,"request_id"))&&digest.equals(text(event,"request_sha256"))&&entity.equals(text(event,"issuer")));
        require("LOGIN_ERROR".equals(text(event,"event_type"))&&"invalid_signature".equals(text(event,"error")));
        require(sent.url().equals(text(http,"request_url"))&&sent.url().equals(text(http,"response_url"))&&http.path("response_url_exact_match").asBoolean(false));
        require(http.path("response_status").asInt()==400&&!http.path("saml_response_form_present").asBoolean(true)&&text(http,"response_body_sha256").matches("[0-9a-f]{64}"));
        var start=Instant.parse(text(http,"started_at"));var finish=Instant.parse(text(http,"finished_at"));var observed=Instant.parse(text(event,"observed_at"));var emitted=Instant.ofEpochMilli(event.path("event_time").asLong(-1));
        require(!start.isBefore(sent.timestamp())&&!finish.isAfter(collected)&&!finish.isBefore(start)&&!observed.isBefore(start)&&!observed.isAfter(finish));
        require(emitted.toEpochMilli()>=start.toEpochMilli()&&!emitted.isAfter(observed));
        require(!input.path("responseReference").isTextual());
    }
    private static Element one(Element parent,String ns,String name){var list=children(parent,ns,name);require(list.size()==1);return list.getFirst();}
    private static X509Certificate certificate(String raw)throws Exception{return (X509Certificate)CertificateFactory.getInstance("X.509").generateCertificate(new java.io.ByteArrayInputStream(Base64.getMimeDecoder().decode(raw)));}
    private static String text(JsonNode node,String field){return node.path(field).asText("");}
    private static String hash(byte[] raw)throws Exception{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(raw));}
    private static void require(boolean b){if(!b)throw new IllegalArgumentException("Native certificate evidence unproven");}
}
