package com.samlscope.runner.cases;

import com.fasterxml.jackson.databind.JsonNode;
import com.samlscope.core.caseexec.CaseContext;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.transcript.*;
import com.samlscope.saml.crypto.*;
import com.samlscope.saml.normal.SecureXml;
import com.samlscope.store.JsonCodec;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.security.cert.*;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.*;
import java.util.function.*;
import org.w3c.dom.Element;

/**
 * A native, accepted B epoch can prove a supersession violation without pretending partial
 * positive coverage proves the complete application obligation. Broader Success remains closed
 * until every applicable binding/profile reflection has its own operational evidence.
 */
final class ShibbolethMetadataSupersessionEvidenceFile {
    private static final String MD="urn:oasis:names:tc:SAML:2.0:metadata";
    private static final String A="urn:oasis:names:tc:SAML:2.0:assertion";
    private static final String P="urn:oasis:names:tc:SAML:2.0:protocol";
    private static final String DS="http://www.w3.org/2000/09/xmldsig#";
    private static final String SUCCESS="urn:oasis:names:tc:SAML:2.0:status:Success";
    private final TranscriptContentReader content;
    private final Path directory;
    private final Function<String,byte[]> target;
    private final BiFunction<String,String,Optional<PlanCredentials>> keys;
    ShibbolethMetadataSupersessionEvidenceFile(TranscriptContentReader content,Path directory,
            Function<String,byte[]> target,BiFunction<String,String,Optional<PlanCredentials>> keys){
        this.content=Objects.requireNonNull(content);this.directory=directory.toAbsolutePath().normalize();
        this.target=Objects.requireNonNull(target);this.keys=Objects.requireNonNull(keys);
    }
    boolean exists(String run){return Files.isRegularFile(folder(run).resolve("manifest.json"),LinkOption.NOFOLLOW_LINKS);}
    CaseOutcome evaluate(String id,CaseContext context){
        String stage="receipt-unavailable";
        try{
            require(MetadataSupersessionProbeTestCase.supports(id)&&context.transcriptComplete());
            Path folder=folder(context.runId());
            byte[] manifestRaw=original(folder,"manifest.json",131072);
            JsonNode manifest=new JsonCodec().mapper().readTree(manifestRaw);
            require("samlscope-shibboleth-metadata-supersession-v1".equals(text(manifest,"schema"))
                &&context.runId().equals(text(manifest,"runId"))
                &&"shibboleth-native-http-supersession-v1".equals(text(manifest,"adapter")));
            byte[] targetRaw=target.apply(context.runId());
            require(hash(targetRaw).equals(text(manifest,"targetMetadataSha256")));
            Path base=directory.resolve(context.runId()+".refresh");
            require(hash(original(base,"manifest.json",131072)).equals(text(manifest,"baseReceiptSha256")));
            stage="accepted-native-epochs-unproven";
            CaseOutcome foundation=new ShibbolethMetadataRefreshEvidenceFile(content,directory).evaluate(context);
            require(foundation.outcome()==Outcome.SATISFIED);
            JsonNode baseManifest=new JsonCodec().mapper().readTree(original(base,"manifest.json",131072));
            Map<String,TranscriptEntry> entries=new LinkedHashMap<>();
            for(var e:context.transcript().list(context.runId()))require(context.runId().equals(e.runId())&&entries.put(e.id(),e)==null);
            byte[] metadataA=original(base,"metadata-a.xml",1048576), metadataB=original(base,"metadata-b.xml",1048576);
            Element rootA=SecureXml.parse(metadataA).getDocumentElement(),rootB=SecureXml.parse(metadataB).getDocumentElement();
            String entity=text(baseManifest,"entityId");
            require(entity.equals(rootA.getAttribute("entityID"))&&entity.equals(rootB.getAttribute("entityID")));
            List<X509Certificate> oldKeys=certificates(rootA,"signing"),newKeys=certificates(rootB,"signing");
            require(!oldKeys.isEmpty()&&!newKeys.isEmpty()&&disjoint(oldKeys,newKeys));
            TranscriptEntry acceptedB=entry(entries,text(baseManifest.path("phaseB"),"responseReference"));
            Element targetRoot=SecureXml.parse(targetRaw).getDocumentElement();
            List<X509Certificate> targetSigning=certificates(targetRoot,"signing");
            String targetEntity=targetRoot.getAttribute("entityID");
            require(!targetEntity.isBlank()&&!targetSigning.isEmpty());
            String oldAcs=MetadataSupersessionProbeTestCase.acs(rootA,0).toString();
            String newAcs=MetadataSupersessionProbeTestCase.acs(rootB,0).toString();
            require(!oldAcs.equals(newAcs));
            Element acceptedBXml=SecureXml.parse(content.readDecodedSaml(acceptedB)).getDocumentElement();
            require(targetEntity.equals(issuer(acceptedBXml))&&newAcs.equals(acceptedBXml.getAttribute("Destination")));
            verifyAssertion(context,acceptedBXml,entity,acceptedBXml.getAttribute("InResponseTo"),newAcs,targetSigning);

            stage="native-runtime-window-unproven";
            var probes=manifest.path("probes");require(probes.isArray()&&!probes.isEmpty());
            var seen=new HashSet<String>();
            var refs=new LinkedHashSet<EvidenceRef>(foundation.evidence());
            Instant first=null,last=null;
            for(JsonNode probe:probes){
                String fixture=text(probe,"fixture");require(MetadataSupersessionProbeTestCase.FIXTURES.contains(fixture)&&seen.add(fixture));
                TranscriptEntry request=entry(entries,text(probe,"requestReference"));
                require(request.timestamp().isAfter(acceptedB.timestamp()));
                if(first==null||request.timestamp().isBefore(first))first=request.timestamp();
                Instant completed=Instant.parse(text(probe,"completedAt"));
                var terminal=entries.values().stream().filter(e->e.direction()==Direction.INBOUND
                    &&(("_"+request.correlationId()).equals(e.samlSummary().get("inResponseTo"))
                       ||("BrowserResponseObservation".equals(e.samlSummary().get("type"))&&request.correlationId().equals(e.correlationId())))).toList();
                require(!terminal.isEmpty()&&!completed.isBefore(request.timestamp()));
                for(var recorded:terminal){require(recorded.timestamp().isAfter(request.timestamp())&&!completed.isBefore(recorded.timestamp()));
                    if(last==null||recorded.timestamp().isAfter(last))last=recorded.timestamp();}
            }
            verifyWindow(folder,manifest,baseManifest,base,first,last);
            // A later native retrieval must not silently replace B before the alleged counterexample.
            for(var recorded:entries.values())if("MetadataPrepared".equals(recorded.samlSummary().get("type"))
                    &&"live".equals(recorded.samlSummary().get("feed"))
                    &&!recorded.timestamp().isBefore(acceptedB.timestamp())&&!recorded.timestamp().isAfter(last)){
                require("no-valid-until".equals(recorded.samlSummary().get("variant"))
                    &&Arrays.equals(metadataB,content.readDecodedSaml(recorded)));
            }
            for(var fetch:entries.values())if("MetadataFetch".equals(fetch.samlSummary().get("type"))
                    &&"live".equals(fetch.samlSummary().get("feed"))
                    &&text(baseManifest,"metadataUrl").equals(fetch.url())
                    &&!fetch.timestamp().isBefore(acceptedB.timestamp())&&!fetch.timestamp().isAfter(last)){
                var prepared=entries.values().stream().filter(e->"MetadataPrepared".equals(e.samlSummary().get("type"))
                    &&fetch.id().equals(e.samlSummary().get("fetchTranscriptId"))).toList();
                require(prepared.size()==1&&!prepared.getFirst().timestamp().isBefore(fetch.timestamp())
                    &&"no-valid-until".equals(prepared.getFirst().samlSummary().get("variant"))
                    &&Arrays.equals(metadataB,content.readDecodedSaml(prepared.getFirst())));
            }

            stage="protocol-counterexample-unproven";
            String counterexample=null;
            byte[] audit=checked(folder,manifest,"native-audit.log","nativeAuditSha256",1048576);
            for(JsonNode probe:probes){
                String fixture=text(probe,"fixture");
                if(!Set.of("old-key-new-acs","new-key-old-acs").contains(fixture))continue;
                TranscriptEntry request=entry(entries,text(probe,"requestReference"));
                require(Direction.OUTBOUND==request.direction()&&"POST".equals(request.method())
                    &&"AuthnRequest".equals(request.samlSummary().get("type"))
                    &&Boolean.TRUE.equals(request.samlSummary().get("active_probe"))
                    &&fixture.equals(request.samlSummary().get("fixture_id"))
                    &&MetadataSupersessionProbeTestCase.supports((String)request.samlSummary().get("scenario_case_id")));
                Element xml=SecureXml.parse(content.readDecodedSaml(request)).getDocumentElement();
                require(P.equals(xml.getNamespaceURI())&&"AuthnRequest".equals(xml.getLocalName())
                    &&("_"+request.correlationId()).equals(xml.getAttribute("ID"))
                    &&entity.equals(issuer(xml))&&request.url().equals(xml.getAttribute("Destination"))
                    &&targetEndpoint(targetRoot,request.url()));
                String requestId=xml.getAttribute("ID");
                if("old-key-new-acs".equals(fixture)){
                    require(newAcs.equals(xml.getAttribute("AssertionConsumerServiceURL"))&&valid(xml,oldKeys)&&!valid(xml,newKeys));
                }else{
                    require(oldAcs.equals(xml.getAttribute("AssertionConsumerServiceURL"))&&valid(xml,newKeys)
                        &&!acsLocations(rootB).contains(oldAcs));
                }
                refs.add(new EvidenceRef("transcript","transcript:"+request.id()));
                List<TranscriptEntry> responses=entries.values().stream().filter(e->e.direction()==Direction.INBOUND
                        &&requestId.equals(e.samlSummary().get("inResponseTo"))).toList();
                if(responses.isEmpty())continue;
                require(responses.size()==1);
                var response=responses.get(0);Element responseXml=SecureXml.parse(content.readDecodedSaml(response)).getDocumentElement();
                if(!success(responseXml))continue;
                String expectedAcs="new-key-old-acs".equals(fixture)?oldAcs:newAcs;
                require(response.timestamp().isAfter(request.timestamp())&&"POST".equals(response.method())
                    &&expectedAcs.equals(response.url())&&expectedAcs.equals(responseXml.getAttribute("Destination"))
                    &&requestId.equals(responseXml.getAttribute("InResponseTo"))&&targetEntity.equals(issuer(responseXml)));
                verifyAssertion(context,responseXml,entity,requestId,expectedAcs,targetSigning);
                require(successAudit(audit,requestId,entity,request.timestamp(),response.timestamp())
                    &&!rejectionAudit(audit,requestId,entity));
                refs.add(new EvidenceRef("transcript","transcript:"+response.id()));counterexample=fixture;
            }
            require(hash(manifestRaw).equals(hash(original(folder,"manifest.json",131072))));
            if(counterexample!=null&&MetadataSupersessionProbeTestCase.SUPERSESSION.equals(id)){
                return new CaseOutcome(Outcome.VIOLATED,null,"metadata.supersession.old-information-retained",
                    "metadata.supersession.old-information-retained",List.copyOf(refs),Map.of("counterexample",counterexample,
                    "accepted_metadata_b_sha256",hash(metadataB),"native_metadata_acceptance_verified",true,
                    "original_signatures_verified",true,"restored",true,"receipt_sha256",hash(manifestRaw)));
            }
            return pending("complete-binding-profile-reflection-unproven",Map.of("counterexample_observed",counterexample!=null,
                "recorded_probes",seen.size(),"accepted_native_epochs_verified",true,"restored",true));
        }catch(Exception unproven){return pending(stage,Map.of());}
    }
    private void verifyWindow(Path folder,JsonNode manifest,JsonNode baseManifest,Path base,Instant first,Instant last)throws Exception{
        require(first!=null&&last!=null);
        var checks=manifest.path("configurationReadBacks");require(checks.isArray()&&checks.size()==4);
        var seen=new HashSet<String>();
        for(var check:checks){String kind=text(check,"kind"),phase=text(check,"phase");
            require(Set.of("providers","audit").contains(kind)&&Set.of("before","after").contains(phase)&&seen.add(kind+phase));
            byte[] raw=original(folder,text(check,"file"),1048576);require(hash(raw).equals(text(check,"sha256"))
                &&Arrays.equals(raw,original(base,"configured-"+kind+".xml",1048576)));
            Instant at=Instant.parse(text(check,"recordedAt"));require("before".equals(phase)?!at.isAfter(first):!at.isBefore(last));
        }
        JsonNode counts=new JsonCodec().mapper().readTree(original(base,"operation-counts.json",131072));
        for(var operation:counts.path("operations")){
            Instant at=Instant.ofEpochMilli((long)(operation.path("recordedAt").asDouble()*1000));
            require(at.isBefore(first)||at.isAfter(last));
        }
        require(hash(original(base,"manifest.json",131072)).equals(text(manifest,"baseReceiptSha256")));
    }
    private void verifyAssertion(CaseContext context,Element response,String entity,String requestId,String destination,
            List<X509Certificate> signing)throws Exception{
        var document=response.getOwnerDocument();
        var encrypted=response.getElementsByTagNameNS(A,"EncryptedAssertion");
        if(encrypted.getLength()>0){require(encrypted.getLength()==1);
            Element wrapper=(Element)encrypted.item(0);
            var key=keys.apply(context.runId(),"no-valid-until").orElseThrow();
            Element plain=new SamlXmlDecrypter().decrypt(wrapper,key.privateKey());
            wrapper.getParentNode().replaceChild(document.importNode(plain,true),wrapper);
        }
        var assertions=response.getElementsByTagNameNS(A,"Assertion");require(assertions.getLength()==1);
        Element assertion=(Element)assertions.item(0);require(valid(assertion,signing)||valid(response,signing));
        var audiences=assertion.getElementsByTagNameNS(A,"Audience");require(audiences.getLength()==1&&entity.equals(audiences.item(0).getTextContent().strip()));
        var confirmations=assertion.getElementsByTagNameNS(A,"SubjectConfirmationData");require(confirmations.getLength()==1);
        Element confirmation=(Element)confirmations.item(0);require(requestId.equals(confirmation.getAttribute("InResponseTo"))&&destination.equals(confirmation.getAttribute("Recipient")));
        require(assertion.getElementsByTagNameNS(A,"AuthnStatement").getLength()==1);
    }
    private static boolean successAudit(byte[] raw,String request,String entity,Instant before,Instant after){
        for(String line:new String(raw,StandardCharsets.UTF_8).split("\\R")){
            if(!line.startsWith("SAMLscope-signature-v1|"))continue;
            String[] f=line.substring("SAMLscope-signature-v1|".length()).split("\\|",-1);
            if(f.length!=8||!request.equals(f[0])||!entity.equals(f[1])||!f[2].isEmpty()||!"Success".equals(f[3])||!"true".equals(f[4])||!"POST".equals(f[5])||!"http://shibboleth.net/ns/profiles/saml2/sso/browser".equals(f[6]))continue;
            Instant at=Instant.parse(f[7]);if(!at.isBefore(before)&&!at.isAfter(after))return true;
        }return false;
    }
    private static boolean rejectionAudit(byte[] raw,String request,String entity){
        for(String line:new String(raw,StandardCharsets.UTF_8).split("\\R")){
            if(!line.startsWith("SAMLscope-signature-v1|"))continue;
            String[] f=line.substring("SAMLscope-signature-v1|".length()).split("\\|",-1);
            if(f.length==8&&request.equals(f[0])&&entity.equals(f[1])&&!f[2].isEmpty())return true;
        }return false;
    }
    private static boolean targetEndpoint(Element target,String value){var n=target.getElementsByTagNameNS(MD,"SingleSignOnService");for(int i=0;i<n.getLength();i++)if(value.equals(((Element)n.item(i)).getAttribute("Location")))return true;return false;}
    private static Set<String> acsLocations(Element root){var result=new HashSet<String>();var n=root.getElementsByTagNameNS(MD,"AssertionConsumerService");for(int i=0;i<n.getLength();i++)result.add(((Element)n.item(i)).getAttribute("Location"));return result;}
    private static List<X509Certificate> certificates(Element root,String use)throws Exception{
        var result=new ArrayList<X509Certificate>();var descriptors=root.getElementsByTagNameNS(MD,"KeyDescriptor");
        for(int i=0;i<descriptors.getLength();i++){Element d=(Element)descriptors.item(i);if(d.hasAttribute("use")&&!use.equals(d.getAttribute("use")))continue;
            var certs=d.getElementsByTagNameNS(DS,"X509Certificate");for(int c=0;c<certs.getLength();c++)result.add((X509Certificate)CertificateFactory.getInstance("X.509").generateCertificate(new java.io.ByteArrayInputStream(Base64.getDecoder().decode(certs.item(c).getTextContent().replaceAll("\\s+","")))));
        }return List.copyOf(result);
    }
    private static boolean disjoint(List<X509Certificate> a,List<X509Certificate> b)throws Exception{var set=new HashSet<String>();for(var k:a)set.add(hash(k.getPublicKey().getEncoded()));for(var k:b)if(set.contains(hash(k.getPublicKey().getEncoded())))return false;return true;}
    private static boolean valid(Element xml,List<X509Certificate> certificates){return certificates.stream().anyMatch(c->new XmlSignatureVerifier().hasValidEnvelopedSignature(xml,c));}
    private static boolean success(Element response){var codes=response.getElementsByTagNameNS(P,"StatusCode");return P.equals(response.getNamespaceURI())&&"Response".equals(response.getLocalName())&&codes.getLength()==1&&SUCCESS.equals(((Element)codes.item(0)).getAttribute("Value"));}
    private static String issuer(Element xml){for(var n=xml.getFirstChild();n!=null;n=n.getNextSibling())if(n instanceof Element e&&A.equals(e.getNamespaceURI())&&"Issuer".equals(e.getLocalName()))return e.getTextContent().strip();throw new IllegalArgumentException("Issuer unavailable");}
    private static TranscriptEntry entry(Map<String,TranscriptEntry> entries,String id){var e=entries.get(id);require(e!=null);return e;}
    private Path folder(String run){require(run.matches("run_[0-9A-HJKMNP-TV-Z]{26}"));return directory.resolve(run+".supersession");}
    private static String text(JsonNode n,String key){var value=n.path(key);require(value.isTextual()&&!value.asText().isBlank());return value.asText();}
    private static byte[] checked(Path folder,JsonNode manifest,String name,String key,int max)throws Exception{byte[] raw=original(folder,name,max);require(hash(raw).equals(text(manifest,key)));return raw;}
    private static byte[] original(Path folder,String name,int max)throws Exception{require(name.matches("[A-Za-z0-9][A-Za-z0-9._-]*")&&!Files.isSymbolicLink(folder));Path file=folder.resolve(name);require(file.getParent().equals(folder)&&Files.isRegularFile(file,LinkOption.NOFOLLOW_LINKS)&&Files.size(file)>0&&Files.size(file)<=max);return Files.readAllBytes(file);}
    private static String hash(byte[] raw)throws Exception{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(raw));}
    private static void require(boolean value){if(!value)throw new IllegalArgumentException("Native supersession evidence unproven");}
    private static CaseOutcome pending(String stage,Map<String,Object> extra){var details=new LinkedHashMap<String,Object>(extra);details.put("evidence_issue",stage);return new CaseOutcome(Outcome.NOT_VERIFIED,"metadata_supersession_unproven","metadata.supersession.evidence-incomplete","metadata.supersession.evidence-incomplete",List.of(),Map.copyOf(details));}
}
