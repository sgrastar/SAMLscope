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
final class MetadataKeySelectionEvidenceFile {
    private static final String MD="urn:oasis:names:tc:SAML:2.0:metadata", S="urn:oasis:names:tc:SAML:2.0:assertion",
        P="urn:oasis:names:tc:SAML:2.0:protocol", DS="http://www.w3.org/2000/09/xmldsig#";
    private static final String AUDIT_FORMAT="SAMLscope-signature-v1|%I|%SP|%e|%S|%XX|%b|%P|%T",
        AUDIT_PROFILE="http://shibboleth.net/ns/profiles/saml2/sso/browser";
    private final Path directory;
    MetadataKeySelectionEvidenceFile(Path directory){this.directory=directory.toAbsolutePath().normalize();}
    boolean exists(String runId) {
        return runId != null && runId.matches("run_[0-9A-HJKMNP-TV-Z]{26}")
                && Files.exists(directory.resolve(runId + ".json"), LinkOption.NOFOLLOW_LINKS);
    }
    Path receipt(String runId) {require(exists(runId));return directory.resolve(runId+".json");}
    String receiptSha256(String runId) throws Exception {
        require(exists(runId));
        var file = directory.resolve(runId + ".json");
        require(Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS) && Files.size(file) <= 2097152);
        return hash(Files.readAllBytes(file));
    }
    List<MetadataKeySelectionComparison.Sample> read(CaseContext context, byte[] targetRaw, TranscriptContentReader content)throws Exception {
        return read(context,targetRaw,content,MetadataKeySelectionComparison.CONDITIONS.keySet());
    }
    List<MetadataKeySelectionComparison.Sample> read(CaseContext context, byte[] targetRaw,
            TranscriptContentReader content, Set<String> selected)throws Exception {
        require(!selected.isEmpty() && MetadataKeySelectionComparison.CONDITIONS.keySet().containsAll(selected));
        require(context.runId().matches("run_[0-9A-HJKMNP-TV-Z]{26}"));
        var file=directory.resolve(context.runId()+".json");if(!Files.exists(file,LinkOption.NOFOLLOW_LINKS))return List.of();
        require(context.transcriptComplete() && Files.isRegularFile(file,LinkOption.NOFOLLOW_LINKS)&&Files.size(file)<=2097152);
        var receipt=new JsonCodec().mapper().readTree(Files.readAllBytes(file));
        require("samlscope-native-key-selection-receipt-v1".equals(text(receipt,"schema"))&&context.runId().equals(text(receipt,"runId")));
        require(hash(targetRaw).equals(text(receipt,"targetMetadataSha256"))&&receipt.path("restored").asBoolean(false));
        var adapter=receipt.path("evidenceAdapter").asText("keycloak-native-event");
        require(Set.of("keycloak-native-event","simplesamlphp-native-http","shibboleth-audit").contains(adapter));
        boolean simpleSaml="simplesamlphp-native-http".equals(adapter), shibboleth="shibboleth-audit".equals(adapter);
        if(simpleSaml) {
            require(text(receipt,"configurationOriginalSha256").matches("[0-9a-f]{64}"));
            require(text(receipt,"configurationOriginalSha256").equals(text(receipt,"configurationFinalSha256")));
        } else if(shibboleth) {
            require(text(receipt,"nativeAuditSha256").matches("[0-9a-f]{64}")&&text(receipt,"observerSourceSha256").matches("[0-9a-f]{64}"));
            require(AUDIT_FORMAT.equals(text(receipt,"auditFormat")));
            require(text(receipt,"auditOriginalSha256").matches("[0-9a-f]{64}")
                &&text(receipt,"auditConfiguredSha256").matches("[0-9a-f]{64}"));
            require(!text(receipt,"auditOriginalSha256").equals(text(receipt,"auditConfiguredSha256")));
            require(text(receipt,"auditOriginalSha256").equals(text(receipt,"auditFinalSha256")));
        } else require(text(receipt,"nativeAuditSha256").matches("[0-9a-f]{64}")&&text(receipt,"observerSourceSha256").matches("[0-9a-f]{64}"));
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
        require(receipt.path("conditions").isArray()&&!receipt.path("conditions").isEmpty()&&receipt.path("conditions").size()<=MetadataKeySelectionComparison.CONDITIONS.size());
        var samples=new ArrayList<MetadataKeySelectionComparison.Sample>();var variants=new HashSet<String>();var used=new HashSet<String>();
        String entity=null;JsonNode policy=null;
        for(var row:receipt.path("conditions")){
            var variant=text(row,"variant");require(MetadataKeySelectionComparison.CONDITIONS.containsKey(variant)&&variants.add(variant));
            if(!selected.contains(variant))continue;
            if(receipt.path("conditionIssues").isArray())for(var issue:receipt.path("conditionIssues"))
                require(!variant.equals(text(issue,"variant")));
            var prepared=entries.get(text(row,"metadataReference"));require(prepared!=null&&prepared.direction()==Direction.OUTBOUND);
            require("MetadataPrepared".equals(prepared.samlSummary().get("type"))&&variant.equals(prepared.samlSummary().get("variant")));
            var fetch=entries.get(String.valueOf(prepared.samlSummary().get("fetchTranscriptId")));
            require(fetch!=null&&fetch.direction()==Direction.INBOUND&&"MetadataFetch".equals(fetch.samlSummary().get("type"))&&variant.equals(fetch.samlSummary().get("variant")));
            require(!fetch.timestamp().isAfter(prepared.timestamp())&&hash(content.readDecodedSaml(prepared)).equals(prepared.samlSummary().get("metadataSha256")));
            var sp=originals.get(prepared.id());require(sp!=null&&MD.equals(sp.getNamespaceURI())&&"EntityDescriptor".equals(sp.getLocalName()));
            if(entity==null)entity=sp.getAttribute("entityID");else require(entity.equals(sp.getAttribute("entityID")));
            var role=one(sp,MD,"SPSSODescriptor");var certificates=new ArrayList<X509Certificate>();
            for(var key:children(role,MD,"KeyDescriptor"))if(!"encryption".equals(key.getAttribute("use")))for(var info:children(key,DS,"KeyInfo"))for(var data:children(info,DS,"X509Data"))for(var cert:children(data,DS,"X509Certificate"))certificates.add(certificate(cert.getTextContent()));
            if("keyvalue-only".equals(variant)) {
                require(certificates.isEmpty() && children(role,MD,"KeyDescriptor").size()==1);
                var descriptor=one(role,MD,"KeyDescriptor");var info=one(descriptor,DS,"KeyInfo");
                require(children(info,DS,"X509Data").isEmpty());
                var rsa=one(one(info,DS,"KeyValue"),DS,"RSAKeyValue");
                var modulus=new java.math.BigInteger(1,Base64.getMimeDecoder().decode(one(rsa,DS,"Modulus").getTextContent()));
                var exponent=new java.math.BigInteger(1,Base64.getMimeDecoder().decode(one(rsa,DS,"Exponent").getTextContent()));
                var key=KeyFactory.getInstance("RSA").generatePublic(new java.security.spec.RSAPublicKeySpec(modulus,exponent));
                // The root signature's certificate supplies only a verifier wrapper. The role's
                // advertised key is independently reconstructed from KeyValue above.
                var rootCert=certificate(one(one(one(one(sp,DS,"Signature"),DS,"KeyInfo"),DS,"X509Data"),DS,"X509Certificate").getTextContent());
                require(Arrays.equals(key.getEncoded(),rootCert.getPublicKey().getEncoded()));
                certificates.add(rootCert);
            }
            var condition=MetadataKeySelectionComparison.CONDITIONS.get(variant);
            require(certificates.size()==condition.count());
            for(var key:children(role,MD,"KeyDescriptor")) {
                var use=key.getAttribute("use");if("encryption".equals(use))continue;
                require(condition.omittedUse()?use.isEmpty():"signing".equals(use));
                require(children(key,DS,"KeyInfo").size()==1);
                var keyInfo=one(key,DS,"KeyInfo");
                require(children(keyInfo,DS,"KeyName").isEmpty());
                for(var x509:children(keyInfo,DS,"X509Data")) {
                    require(children(x509,DS,"X509SubjectName").isEmpty());
                    require(children(x509,DS,"X509IssuerSerial").isEmpty());
                    require(children(x509,DS,"X509SKI").isEmpty());
                }
            }
            for (var certificate : certificates) require("RSA".equals(certificate.getPublicKey().getAlgorithm()));
            var keyHashes = new ArrayList<String>();
            for (var certificate : certificates) keyHashes.add(hash(certificate.getPublicKey().getEncoded()));
            require(new HashSet<>(keyHashes).size()==condition.count());
            require(new XmlSignatureVerifier().hasValidEnvelopedSignature(sp,certificates.getFirst()));
            var importProof=row.path("nativeImport");
            require(hash(content.readDecodedSaml(prepared)).equals(text(importProof,"fixtureSha256")));
            require(entity.equals(text(importProof,"entityId"))&&importProof.path("readbackVerified").asBoolean(false));
            if(simpleSaml) {
                require("native-parser-cli".equals(text(importProof,"source")));
                var parserBytes=Base64.getDecoder().decode(text(importProof,"parserOutputBase64"));
                require(hash(parserBytes).equals(text(importProof,"parserOutputSha256")));
                var parsed=new JsonCodec().mapper().readTree(parserBytes);
                require(entity.equals(text(parsed,"entity_id"))&&!text(parsed,"php").isBlank());
                require(parsed.path("validate_authnrequest").asBoolean(false)&&importProof.path("signaturePolicy").asBoolean(false));
                require(text(importProof,"configurationSha256").matches("[0-9a-f]{64}"));
            } else if(shibboleth) {
                require("native-filesystem-provider".equals(text(importProof,"source")));
                require(importProof.path("providerReloaded").asBoolean(false)&&importProof.path("signaturePolicy").asBoolean(false));
                require(text(importProof,"configurationSha256").matches("[0-9a-f]{64}"));
            } else {
            require("client-settings-page".equals(text(importProof,"uiStatus")));
            var nativeClient=row.path("nativeClient");require(entity.equals(text(nativeClient,"clientId"))&&text(nativeClient,"databaseId").matches("[a-f0-9-]{36}"));
            require(nativeClient.path("removed").asBoolean(false));var attrs=nativeClient.path("attributes");require(attrs.isObject());
            if(!"true".equals(text(attrs,"saml.client.signature")))
                throw new UnprovenEvidence("native_signature_policy_disabled_after_import",variant);
            require("RSA_SHA256".equals(text(attrs,"saml.signature.algorithm")));
            var nativeCertificate=text(attrs,"saml.signing.certificate");
            if(!nativeCertificate.isBlank()) {
                var importedCertificate=certificate(nativeCertificate);
                require(certificates.stream().anyMatch(c -> Arrays.equals(c.getPublicKey().getEncoded(),importedCertificate.getPublicKey().getEncoded())));
            } else require("keyvalue-only".equals(variant) || condition.omittedUse());
            // A single API attribute is not proof that all metadata keys were retained. The original
            // imported XML and the actual B/C protocol behavior decide the approved obligation.
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
            }
            var evidence=new ArrayList<EvidenceRef>();evidence.add(new EvidenceRef("transcript",fetch.id()));evidence.add(new EvidenceRef("transcript",prepared.id()));
            var decisions=new EnumMap<Slot,MetadataKeySelectionComparison.Decision>(Slot.class);String signerHash=null;
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
                var signer=certificate(one(one(one(signature,DS,"KeyInfo"),DS,"X509Data"),DS,"X509Certificate").getTextContent());
                if(MetadataKeySelectionComparison.SAME_KEY.equals(variant)) {
                    require(!Arrays.equals(signer.getEncoded(),certificates.getFirst().getEncoded()));
                    require(Arrays.equals(signer.getPublicKey().getEncoded(),certificates.getFirst().getPublicKey().getEncoded()));
                }
                if(MetadataKeySelectionComparison.OTHER_KEY.equals(variant)) {
                    require(signer.getSubjectX500Principal().equals(certificates.getFirst().getSubjectX500Principal()));
                    require(signer.getIssuerX500Principal().equals(certificates.getFirst().getIssuerX500Principal()));
                    require(!Arrays.equals(signer.getPublicKey().getEncoded(),certificates.getFirst().getPublicKey().getEncoded()));
                }
                var actualSignerHash=hash(signer.getPublicKey().getEncoded());
                if(signerHash==null)signerHash=actualSignerHash;else require(signerHash.equals(actualSignerHash));
                require(new XmlSignatureVerifier().hasValidEnvelopedSignature(request,signer)==(slot==Slot.POSITIVE));
                for(int keyIndex=0;keyIndex<certificates.size();keyIndex++) {
                    boolean expected=slot==Slot.POSITIVE && keyHashes.get(keyIndex).equals(actualSignerHash);
                    require(new XmlSignatureVerifier().hasValidEnvelopedSignature(request,certificates.get(keyIndex))==expected);
                }
                var responses=new ArrayList<TranscriptEntry>();
                for(var e:entries.values())if(e.direction()==Direction.INBOUND&&"Response".equals(e.samlSummary().get("type"))){
                    var xml=SecureXml.parse(content.readDecodedSaml(e)).getDocumentElement();if(id.equals(xml.getAttribute("InResponseTo")))responses.add(e);
                }
                MetadataKeySelectionComparison.Decision decision;
                if(responses.isEmpty()){
                    if(simpleSaml)rejectSimpleSaml(input,id,hash(content.readDecodedSaml(sent)),sent,collected);
                    else if(shibboleth)rejectShibboleth(input,id,entity,sent,collected);
                    else reject(input,id,hash(content.readDecodedSaml(sent)),entity,sent,collected);
                    evidence.add(new EvidenceRef(simpleSaml?"native-signature-http":shibboleth?"native-signature-audit":"native-signature-event",context.runId()+".json#"+id));
                    decision=MetadataKeySelectionComparison.Decision.NATIVE_SIGNATURE_REJECTION;
                }else{
                    require(slot==Slot.POSITIVE&&responses.size()==1&&!input.path("nativeEvent").isObject());
                    if(shibboleth)requireShibbolethSuccess(input,id,entity,sent,collected);
                    var received=responses.getFirst();require(received.id().equals(text(input,"responseReference"))&&received.timestamp().isAfter(sent.timestamp())&&!received.timestamp().isAfter(collected));
                    var response=originals.get(received.id());require(response!=null&&acs.equals(received.url())&&acs.equals(response.getAttribute("Destination")));
                    require("urn:oasis:names:tc:SAML:2.0:status:Success".equals(one(one(response,P,"Status"),P,"StatusCode").getAttribute("Value")));
                    require(children(response,S,"Assertion").size()+children(response,S,"EncryptedAssertion").size()==1);
                    require(new VerifiedSignatureAlgorithms().read(response,target.getAttribute("entityID"),trusted).stream().anyMatch(s->"Response".equals(s.element())));
                    decision=MetadataKeySelectionComparison.Decision.SIGNED_SUCCESS;evidence.add(new EvidenceRef("transcript",received.id()));
                }
                decisions.put(slot,decision);evidence.add(new EvidenceRef("transcript",sent.id()));
            }
            require(signerHash!=null);
            samples.add(new MetadataKeySelectionComparison.Sample(variant,context.runId(),entity,keyHashes,signerHash,true,true,
                decisions.get(Slot.NEGATIVE)==MetadataKeySelectionComparison.Decision.NATIVE_SIGNATURE_REJECTION,
                decisions.get(Slot.POSITIVE),evidence));
        }
        return List.copyOf(samples);
    }
    static final class UnprovenEvidence extends IllegalArgumentException {
        private final String reason;
        private final String variant;
        UnprovenEvidence(String reason,String variant) {
            super(reason);
            if(!Set.of("native_signature_policy_disabled_after_import").contains(reason)
                    || !MetadataKeySelectionComparison.CONDITIONS.containsKey(variant))
                throw new IllegalArgumentException("Unknown evidence diagnostic");
            this.reason=reason;this.variant=variant;
        }
        String reason(){return reason;}
        String variant(){return variant;}
    }
    private enum Slot{POSITIVE,NEGATIVE}
    private static void rejectSimpleSaml(JsonNode input,String id,String digest,TranscriptEntry sent,Instant collected) {
        var http=input.path("nativeHttp");
        require(id.equals(text(http,"request_id"))&&digest.equals(text(http,"request_sha256")));
        require(sent.url().equals(text(http,"request_url"))&&sent.url().equals(text(http,"response_url")));
        require(http.path("response_status").asInt()==500&&!http.path("saml_response_form_present").asBoolean(true));
        require("signature-value-invalid".equals(text(http,"native_signature_rejection")));
        require(text(http,"response_body_sha256").matches("[0-9a-f]{64}"));
        var observed=Instant.parse(text(http,"observed_at"));
        require(!observed.isBefore(sent.timestamp())&&!observed.isAfter(collected));
        require(!input.path("responseReference").isTextual()&&!input.path("nativeEvent").isObject());
    }
    private static void rejectShibboleth(JsonNode input,String id,String entity,TranscriptEntry sent,Instant collected) {
        requireShibbolethAudit(input,id,entity,sent,collected);
        var audit=input.path("nativeAudit");
        require("MessageAuthenticationError".equals(text(audit,"event"))&&text(audit,"status").isEmpty());
        require(!input.path("responseReference").isTextual());
    }
    private static void requireShibbolethSuccess(JsonNode input,String id,String entity,TranscriptEntry sent,Instant collected) {
        requireShibbolethAudit(input,id,entity,sent,collected);
        var audit=input.path("nativeAudit");
        require(text(audit,"event").isEmpty()&&"Success".equals(text(audit,"status")));
    }
    private static void requireShibbolethAudit(JsonNode input,String id,String entity,TranscriptEntry sent,Instant collected) {
        var audit=input.path("nativeAudit");
        require(id.equals(text(audit,"request_id"))&&entity.equals(text(audit,"sp")));
        require("true".equals(text(audit,"signed_inbound"))&&"POST".equals(text(audit,"binding"))
            &&AUDIT_PROFILE.equals(text(audit,"profile")));
        var observed=Instant.parse(text(audit,"timestamp"));
        require(!observed.isBefore(sent.timestamp())&&!observed.isAfter(collected));
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
    private static void require(boolean b){if(!b)throw new IllegalArgumentException("Native key selection evidence unproven");}
}
