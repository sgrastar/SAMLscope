package com.samlscope.runner.cases;

import static com.samlscope.runner.cases.MetadataAlgorithmEvidence.children;
import com.fasterxml.jackson.databind.JsonNode;
import com.samlscope.core.caseexec.CaseContext;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.transcript.*;
import com.samlscope.saml.binding.RedirectSignatureVerifier;
import com.samlscope.saml.crypto.*;
import com.samlscope.saml.normal.SecureXml;
import com.samlscope.store.JsonCodec;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.cert.*;
import java.time.Instant;
import java.util.*;
import java.util.function.Function;
import org.w3c.dom.Element;

/** Native front-channel propagation proof. The IdP may return its origin response before its
 * browser propagation finishes; native iframe/session originals bind that one processing.
 * Parallel sends do not prove continuation after knowledge of failure, so IDP17.r is excluded.
 */
public final class ShibbolethNativeSloPropagationEvidence {
    public static final String CASE="IIP-IDP17-s-idp-01";
    private static final String SCHEMA="samlscope-shibboleth-native-slo-v1",RUN="run_[0-9A-HJKMNP-TV-Z]{26}",
        MD="urn:oasis:names:tc:SAML:2.0:metadata",P="urn:oasis:names:tc:SAML:2.0:protocol",S="urn:oasis:names:tc:SAML:2.0:assertion",
        DS="http://www.w3.org/2000/09/xmldsig#",SUCCESS=P.replace("protocol","status:Success"),PARTIAL=P.replace("protocol","status:PartialLogout"),
        POST="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
        IMAGE="sha256:3c1b1fa64c58258aefc9e38d4ae60e9f0340731318a472110ea56ce88c18a11a";
    private final Path directory;private final TranscriptContentReader content;
    private final Function<String,byte[]> metadata;private final SamlDecryptionKeyProvider keys;
    public ShibbolethNativeSloPropagationEvidence(Path directory,TranscriptContentReader content,
            Function<String,byte[]> metadata,SamlDecryptionKeyProvider keys) {
        this.directory=Objects.requireNonNull(directory).toAbsolutePath().normalize();this.content=Objects.requireNonNull(content);
        this.metadata=Objects.requireNonNull(metadata);this.keys=Objects.requireNonNull(keys);
    }
    public boolean exists(String run) {return run!=null&&run.matches(RUN)&&Files.exists(directory.resolve(run),LinkOption.NOFOLLOW_LINKS);}
    public Optional<CaseOutcome> read(CaseContext context,String id) {
        if(!CASE.equals(id))return Optional.empty();var evidence=new LinkedHashSet<EvidenceRef>();
        try {
            require(context.transcriptComplete()&&context.runId().matches(RUN));Path folder=directory.resolve(context.runId());
            Path ancestor=folder;while(ancestor!=null){require(!Files.isSymbolicLink(ancestor));ancestor=ancestor.getParent();}
            require(Files.isDirectory(folder,LinkOption.NOFOLLOW_LINKS));JsonNode manifest=JSON.mapper().readTree(original(folder,"manifest.json"));
            require(SCHEMA.equals(text(manifest,"schema"))&&context.runId().equals(text(manifest,"runId")));
            var originalHashes=manifest.path("originals");require(originalHashes.isObject()&&originalHashes.size()>0);
            byte[] targetRaw=metadata.apply(context.runId());require(hash(targetRaw).equals(text(manifest,"targetMetadataSha256")));
            String controlRun=text(manifest,"controlRunId");require(controlRun.matches(RUN)&&!controlRun.equals(context.runId())&&Arrays.equals(targetRaw,metadata.apply(controlRun)));
            var target=SecureXml.parse(targetRaw).getDocumentElement();var targetKeys=MetadataAlgorithmEvidence.signingKeys(target);
            require(!targetKeys.isEmpty());String targetEntity=target.getAttribute("entityID");
            var restoration=json(folder,originalHashes,"restoration.json");require(restoration.path("restored").asBoolean()&&restoration.path("temporaryRemoved").asBoolean());
            require(Arrays.equals(checked(folder,originalHashes,"original-providers.xml"),checked(folder,originalHashes,"final-providers.xml")));
            var runtimeA=json(folder,originalHashes,"target-runtime-start.json").path("binding");var runtimeB=json(folder,originalHashes,"target-runtime-end.json").path("binding");
            for(String field:List.of("container_id","image_id","container_started_at"))require(text(runtimeA,field).equals(text(runtimeB,field)));
            require(IMAGE.equals(text(runtimeA,"image_id"))&&runtimeA.path("running_at_capture").asBoolean()&&runtimeB.path("running_at_capture").asBoolean());
            // Installed native flow/template bytes are pinned separately from the receipt.
            for(var pin:NATIVE_PINS.entrySet())require(hash(checked(folder,originalHashes,pin.getKey())).equals(pin.getValue()));
            for(String kind:CONFIG)require(Arrays.equals(checked(folder,originalHashes,"original-"+kind),checked(folder,originalHashes,"final-"+kind)));
            require(Arrays.equals(checked(folder,originalHashes,"original-session-properties.txt"),checked(folder,originalHashes,"final-session-properties.txt")));
            require(new String(checked(folder,originalHashes,"original-session-properties.txt"),StandardCharsets.UTF_8).contains("idp.session.trackSPSessions=true"));
            var primary=SecureXml.parse(checked(folder,originalHashes,"suite-primary-original.xml")).getDocumentElement();String entity=primary.getAttribute("entityID");
            require(entity.equals("http://localhost:18080/p/"+text(manifest,"planId")));var suiteKeys=spKeys(primary);
            require(!suiteKeys.isEmpty());
            var bad=trial(context,folder,originalHashes,"failure",context.runId(),targetEntity,targetKeys,suiteKeys,entity,evidence);
            var good=trial(context,folder,originalHashes,"all-success",controlRun,targetEntity,targetKeys,suiteKeys,entity,evidence);
            require(bad.failed==1&&good.failed==0&&bad.successful==2&&good.successful==3&&bad.participants.equals(good.participants));
            require(SUCCESS.equals(status(bad.response))&&SUCCESS.equals(status(good.response))&&!hasPartial(good.response));
            evidence.add(new EvidenceRef("native-slo-evidence",context.runId()+"/manifest.json#"+hash(original(folder,"manifest.json"))));
            Outcome outcome=hasPartial(bad.response)?Outcome.SATISFIED:Outcome.VIOLATED;
            String reason=hasPartial(bad.response)?"slo.partial-logout.native-correlated":"slo.partial-logout.native-missing";
            return Optional.of(new CaseOutcome(outcome,null,reason,reason,List.copyOf(evidence),Map.of("product","shibboleth",
                "evidence_adapter",SCHEMA,"participant_count",3,"failure_count",1,"all_success_control_run",controlRun,
                "origin_response_precedes_propagation",bad.responseAt.isBefore(bad.failureAt))));
        }catch(Exception missing){if(Boolean.getBoolean("samlscope.nativeSlo.debug"))missing.printStackTrace();return Optional.empty();}
    }
    private Trial trial(CaseContext context,Path folder,JsonNode hashes,String label,String run,String targetEntity,
            List<X509Certificate> targetKeys,List<X509Certificate> suiteKeys,String entity,Set<EvidenceRef> evidence)throws Exception {
        var browser=json(folder,hashes,label+"/browser-original.json");require(run.equals(text(browser,"runId"))
            &&"completed".equals(text(browser,"status"))&&browser.path("initialCookieCount").asInt(-1)==0);
        var created=json(folder,hashes,label+"/created.json").path("run");require(run.equals(text(created,"id"))&&entity.equals("http://localhost:18080/p/"+text(created,"planId"))
            &&text(created,"planId").equals(text(browser,"planId"))&&Arrays.equals(checked(folder,hashes,label+"/target-metadata.xml"),metadata.apply(run)));
        var entries=new HashMap<String,TranscriptEntry>();for(var entry:context.transcript().list(run)) {
            require(run.equals(entry.runId())&&entry.id().matches("tx_[0-9A-HJKMNP-TV-Z]{26}")&&entries.put(entry.id(),entry)==null);
            if(entry.decodedSamlRef()!=null)require(("transcripts/"+run+"/"+entry.id()+".saml.xml").equals(entry.decodedSamlRef())
                &&content.readDecodedSaml(entry)!=null&&content.readDecodedSaml(entry).length==entry.decodedSamlBytes());
        }
        var origin=entries.values().stream().filter(e->e.direction()==Direction.OUTBOUND&&"LogoutRequest".equals(e.samlSummary().get("type"))).toList();require(origin.size()==1);
        var request=origin.getFirst();byte[] requestRaw=content.readDecodedSaml(request);var requestXml=SecureXml.parse(requestRaw).getDocumentElement();String requestId=requestXml.getAttribute("ID");
        require(P.equals(requestXml.getNamespaceURI())&&"LogoutRequest".equals(requestXml.getLocalName())&&issuer(requestXml).equals(entity)&&valid(request,requestRaw,suiteKeys));
        require(requestXml.getAttribute("Destination").equals("http://localhost:18280/idp/profile/SAML2/POST/SLO")&&"POST".equals(request.method()));
        require(requestXml.getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:protocol:ext:async-slo","Asynchronous").getLength()==0);
        var responses=entries.values().stream().filter(e->e.direction()==Direction.INBOUND&&"LogoutResponse".equals(e.samlSummary().get("type")))
            .filter(e->{try{return requestId.equals(SecureXml.parse(content.readDecodedSaml(e)).getDocumentElement().getAttribute("InResponseTo"));}catch(Exception ignored){return false;}}).toList();
        require(responses.size()==1);var response=responses.getFirst();byte[] responseRaw=content.readDecodedSaml(response);var responseXml=SecureXml.parse(responseRaw).getDocumentElement();
        require(P.equals(responseXml.getNamespaceURI())&&"LogoutResponse".equals(responseXml.getLocalName())&&response.timestamp().isAfter(request.timestamp())&&targetEntity.equals(issuer(responseXml))&&valid(response,responseRaw,targetKeys)
            &&responseXml.getAttribute("Destination").equals(entity+"/sp/slo"));
        var nativeContext=browser.path("nativePropagationContext");var scope=text(nativeContext,"flowScopeSha256");require(scope.matches("[a-f0-9]{64}"));
        require(browser.path("nativeFlowScopes").size()==1&&scope.equals(browser.path("nativeFlowScopes").get(0).asText()));
        byte[] html=checked(folder,hashes,label+"/"+text(nativeContext,"file"));require(hash(html).equals(text(nativeContext,"sha256")));
        var htmlText=new String(html,StandardCharsets.UTF_8);require(htmlText.contains("sessionTracker")&&htmlText.contains("/profile/PropagateLogout")&&htmlText.contains("_eventId=proceed"));
        var resources=browser.path("nativeResources");require(resources.isArray());var start=new ArrayList<JsonNode>();
        for(var row:resources)if(row.path("samlRequest").path("id").asText().equals(requestId))start.add(row);
        require(start.size()==1&&hash(requestRaw).equals(text(start.getFirst().path("samlRequest"),"sha256"))
            &&scope.equals(text(start.getFirst(),"redirectFlowScopeSha256"))&&start.getFirst().path("status").asInt()==302
            &&"http://localhost:18280".equals(text(start.getFirst(),"origin"))&&"/idp/profile/SAML2/POST/SLO".equals(text(start.getFirst(),"path")));
        require(!time(browser,"startedAt").isAfter(request.timestamp())&&time(nativeContext,"recordedAt").isAfter(time(start.getFirst(),"respondedAt")));
        var confirmations=new ArrayList<JsonNode>();for(var row:resources)if(scope.equals(row.path("flowScopeSha256").asText())&&"POST".equals(row.path("method").asText())
            &&row.path("status").asInt()==302&&row.path("samlRequest").isMissingNode())confirmations.add(row);require(confirmations.size()==1);
        int contexts=0;for(var row:resources)if(scope.equals(row.path("flowScopeSha256").asText())&&"GET".equals(row.path("method").asText())
            &&row.path("status").asInt()==200&&!time(row,"requestedAt").isBefore(time(confirmations.getFirst(),"respondedAt"))
            &&!time(row,"respondedAt").isAfter(time(nativeContext,"recordedAt")))contexts++;require(contexts==1);
        var finals=new ArrayList<JsonNode>();for(var row:resources)if(requestId.equals(row.path("samlResponse").path("inResponseTo").asText())&&row.path("sessionKeySha256").isMissingNode())finals.add(row);
        require(finals.size()==1&&responseXml.getAttribute("ID").equals(text(finals.getFirst().path("samlResponse"),"id"))
            &&hash(responseRaw).equals(text(finals.getFirst().path("samlResponse"),"sha256"))&&finals.getFirst().path("status").asInt()==200
            &&"http://localhost:18080".equals(text(finals.getFirst(),"origin"))&&("/p/"+text(browser,"planId")+"/sp/slo").equals(text(finals.getFirst(),"path")));
        var closure=nativeContext.path("participants");require(closure.isArray()&&closure.size()==3);var members=new TreeSet<String>();var sessionKeys=new HashSet<String>();
        var fixture=SecureXml.parse(checked(folder,hashes,label+"/configured-sp-metadata.xml")).getDocumentElement();var expected=new TreeSet<>(List.of(entity+"/sp-fail",entity+"/sp-remain",entity+"/sp-remain2"));
        var before=json(folder,hashes,label+"/before-readback.json");var after=json(folder,hashes,label+"/after-readback.json");
        require(!time(before,"recordedAt").isAfter(request.timestamp())&&!time(after,"recordedAt").isBefore(time(browser,"finishedAt")));
        require(Arrays.equals(checked(folder,hashes,"configured-providers.xml"),checked(folder,hashes,label+"/before-providers.xml"))
            &&Arrays.equals(checked(folder,hashes,"configured-providers.xml"),checked(folder,hashes,label+"/after-providers.xml")));
        require(Arrays.equals(checked(folder,hashes,label+"/configured-sp-metadata.xml"),checked(folder,hashes,label+"/before-fixture.xml"))
            &&Arrays.equals(checked(folder,hashes,label+"/configured-sp-metadata.xml"),checked(folder,hashes,label+"/after-fixture.xml")));
        for(String kind:CONFIG)require(Arrays.equals(checked(folder,hashes,"original-"+kind),checked(folder,hashes,label+"/before-"+kind))
            &&Arrays.equals(checked(folder,hashes,"original-"+kind),checked(folder,hashes,label+"/after-"+kind)));
        int failed=0,successful=0;Instant failureAt=null;
        for(var peer:closure){
            var peerEntity=text(peer,"entityId");String key=text(peer,"sessionKeySha256");require(members.add(peerEntity)&&expected.contains(peerEntity)&&key.matches("[a-f0-9]{64}")&&sessionKeys.add(key));
            String peerHex=HexFormat.of().formatHex(peerEntity.getBytes(StandardCharsets.UTF_8));
            var iframes=java.util.regex.Pattern.compile("<iframe\\b[^>]*>",java.util.regex.Pattern.CASE_INSENSITIVE).matcher(htmlText);int mapped=0;
            while(iframes.find()){String tag=iframes.group();if(tag.contains("result_"+peerHex)&&tag.contains("sender_sha256:"+key)
                    &&tag.contains("SessionKey=sha256:"+key)&&tag.contains("'sha256:"+key+"')"))mapped++;}require(mapped==1);
            var generated=new ArrayList<JsonNode>();for(var row:resources)if(row.path("path").asText().endsWith("/PropagateLogout")&&key.equals(row.path("sessionKeySha256").asText()))generated.add(row);
            require(generated.size()==1&&generated.getFirst().path("status").asInt()==200
                &&time(generated.getFirst(),"requestedAt").isAfter(time(nativeContext,"recordedAt")));var generatedXml=generated.getFirst().path("generatedRequest");String id=text(generatedXml,"id");
            var inbound=entries.values().stream().filter(e->e.direction()==Direction.INBOUND&&Set.of("LogoutRequest","SloFailParticipant").contains(e.samlSummary().get("type")))
                .filter(e->{try{return id.equals(SecureXml.parse(content.readDecodedSaml(e)).getDocumentElement().getAttribute("ID"));}catch(Exception ignored){return false;}}).toList();require(inbound.size()==1);
            var attempt=inbound.getFirst();byte[] raw=content.readDecodedSaml(attempt);var xml=SecureXml.parse(raw).getDocumentElement();
            require(P.equals(xml.getNamespaceURI())&&"LogoutRequest".equals(xml.getLocalName())&&id.equals(xml.getAttribute("ID"))&&hash(raw).equals(text(generatedXml,"sha256"))&&valid(attempt,raw,targetKeys)&&targetEntity.equals(issuer(xml)));
            var operational=children(fixture,MD,"EntityDescriptor").stream().filter(e->peerEntity.equals(e.getAttribute("entityID"))).toList();require(operational.size()==1);
            String suffix=peerEntity.substring(peerEntity.lastIndexOf('-')+1);var effective=SecureXml.parse(checked(folder,hashes,label+"/effective-"+suffix+".xml")).getDocumentElement();
            require(peerEntity.equals(effective.getAttribute("entityID"))&&roleView(operational.getFirst()).equals(roleView(effective)));
            var role=children(operational.getFirst(),MD,"SPSSODescriptor");require(role.size()==1);var endpoints=children(role.getFirst(),MD,"SingleLogoutService");
            require(endpoints.size()==1&&POST.equals(endpoints.getFirst().getAttribute("Binding"))&&endpoints.getFirst().getAttribute("Location").equals(xml.getAttribute("Destination")));
            // Bind the target-generated participant SessionIndex/NameID to an actual authenticated
            // assertion for that exact SP. No browser caption/declaration substitutes for this.
            require(authenticatedSession(entries.values(),run,peerEntity,xml,targetKeys,time(browser,"startedAt"),request.timestamp(),targetEntity));
            var sent=new ArrayList<JsonNode>();for(var row:resources)if(key.equals(row.path("sessionKeySha256").asText())&&id.equals(row.path("samlRequest").path("id").asText())&&"http://localhost:18080".equals(row.path("origin").asText()))sent.add(row);
            require(sent.size()==1&&hash(raw).equals(text(sent.getFirst().path("samlRequest"),"sha256"))&&time(sent.getFirst(),"requestedAt").isAfter(request.timestamp())
                &&text(sent.getFirst(),"path").equals(java.net.URI.create(xml.getAttribute("Destination")).getRawPath())
                &&hash(xml.getAttribute("Destination").getBytes(StandardCharsets.UTF_8)).equals(text(sent.getFirst(),"urlSha256")));
            var delivery=sent.getFirst();int http=delivery.path("status").asInt(-1);
            require(time(delivery,"respondedAt").isAfter(time(delivery,"requestedAt"))&&!time(delivery,"respondedAt").isAfter(time(browser,"finishedAt")));
            if(http==500){require("failure".equals(label)&&peerEntity.endsWith("/sp-fail")&&attempt.status()!=null&&attempt.status()==500
                &&Integer.valueOf(500).equals(attempt.samlSummary().get("http_status")));failed++;failureAt=time(delivery,"respondedAt");}
            else{
                require(http==200);var replies=entries.values().stream().filter(e->e.direction()==Direction.OUTBOUND&&"LogoutResponse".equals(e.samlSummary().get("type")))
                    .filter(e->{try{return id.equals(SecureXml.parse(content.readDecodedSaml(e)).getDocumentElement().getAttribute("InResponseTo"));}catch(Exception ignored){return false;}}).toList();require(replies.size()==1);
                var reply=replies.getFirst();byte[] replyRaw=content.readDecodedSaml(reply);var replyXml=SecureXml.parse(replyRaw).getDocumentElement();
                require(P.equals(replyXml.getNamespaceURI())&&"LogoutResponse".equals(replyXml.getLocalName())&&valid(reply,replyRaw,suiteKeys)&&SUCCESS.equals(status(replyXml)));
                var accepted=new ArrayList<JsonNode>();for(var row:resources)if(key.equals(row.path("sessionKeySha256").asText())&&id.equals(row.path("samlResponse").path("inResponseTo").asText()))accepted.add(row);
                require(accepted.size()==1&&hash(replyRaw).equals(text(accepted.getFirst().path("samlResponse"),"sha256"))&&accepted.getFirst().path("status").asInt()==200
                    &&time(accepted.getFirst(),"requestedAt").isAfter(time(delivery,"respondedAt"))
                    &&!time(accepted.getFirst(),"respondedAt").isAfter(time(browser,"finishedAt")));
                var nativeResult=json(folder,hashes,label+"/"+text(accepted.getFirst(),"bodyFile"));require(nativeResult.size()==1&&"Success".equals(text(nativeResult,"result")));
                require(hash(checked(folder,hashes,label+"/"+text(accepted.getFirst(),"bodyFile"))).equals(text(accepted.getFirst(),"sha256")));successful++;evidence.add(ref(reply));
            }
            evidence.add(ref(attempt));
        }
        require(members.equals(expected));require(authenticatedSession(entries.values(),run,entity,requestXml,targetKeys,time(browser,"startedAt"),request.timestamp(),targetEntity));
        evidence.add(ref(request));evidence.add(ref(response));evidence.add(new EvidenceRef("native-slo-evidence",context.runId()+"/"+label+"/browser-original.json#"+hash(checked(folder,hashes,label+"/browser-original.json"))));
        return new Trial(failed,successful,members,responseXml,response.timestamp(),failureAt);
    }
    private boolean authenticatedSession(Collection<TranscriptEntry> entries,String run,String entity,Element logout,List<X509Certificate> certificates,Instant from,Instant until,String targetEntity)throws Exception {
        var indexes=children(logout,P,"SessionIndex");require(indexes.size()==1&&!indexes.getFirst().getTextContent().isBlank());String index=indexes.getFirst().getTextContent();
        var names=children(logout,S,"NameID");if(names.isEmpty()){var encrypted=children(logout,S,"EncryptedID");require(encrypted.size()==1);names=List.of(new SamlXmlDecrypter().decrypt(encrypted.getFirst(),keys.keyFor(run).orElseThrow()));}require(names.size()==1);
        Element name=names.getFirst();int matched=0;
        for(var entry:entries)if(entry.direction()==Direction.INBOUND&&"Response".equals(entry.samlSummary().get("type"))){
            if(entry.timestamp().isBefore(from)||!entry.timestamp().isBefore(until))continue;
            byte[] raw=content.readDecodedSaml(entry);var response=SecureXml.parse(raw).getDocumentElement();if(!P.equals(response.getNamespaceURI())||!"Response".equals(response.getLocalName())
                ||!targetEntity.equals(issuer(response))||!SUCCESS.equals(status(response))||!valid(entry,raw,certificates))continue;
            var assertions=children(response,S,"Assertion");if(assertions.isEmpty()){var encrypted=children(response,S,"EncryptedAssertion");if(encrypted.size()!=1)continue;assertions=List.of(new SamlXmlDecrypter().decrypt(encrypted.getFirst(),keys.keyFor(run).orElseThrow()));}
            if(assertions.size()!=1)continue;var assertion=assertions.getFirst();var authn=children(assertion,S,"AuthnStatement");if(authn.size()!=1||!index.equals(authn.getFirst().getAttribute("SessionIndex")))continue;
            var audiences=assertion.getElementsByTagNameNS(S,"Audience");boolean audience=false;for(int i=0;i<audiences.getLength();i++)if(entity.equals(audiences.item(i).getTextContent()))audience=true;if(!audience)continue;
            var subject=children(assertion,S,"Subject");if(subject.size()!=1)continue;var peerNames=children(subject.getFirst(),S,"NameID");if(peerNames.size()!=1||!sameName(name,peerNames.getFirst()))continue;matched++;
        }
        return matched==1;
    }
    private static boolean sameName(Element left,Element right) {
        if(!left.getTextContent().equals(right.getTextContent()))return false;
        for(String field:List.of("Format","NameQualifier","SPNameQualifier","SPProvidedID"))if(!left.getAttribute(field).equals(right.getAttribute(field)))return false;
        return true;
    }
    private boolean valid(TranscriptEntry entry,byte[] raw,List<X509Certificate> certificates) {
        if("GET".equals(entry.method()))return certificates.stream().anyMatch(c->new RedirectSignatureVerifier().isValidForMessage(entry.rawQuery(),c,raw));
        var xml=SecureXml.parse(raw).getDocumentElement();var verifier=new XmlSignatureVerifier();
        return verifier.hasValidEnvelopedReferenceDigests(xml)&&certificates.stream().anyMatch(c->verifier.hasValidEnvelopedSignature(xml,c));
    }
    private static List<X509Certificate> spKeys(Element entity)throws Exception {
        var result=new ArrayList<X509Certificate>();var factory=CertificateFactory.getInstance("X.509");
        for(var role:children(entity,MD,"SPSSODescriptor"))for(var key:children(role,MD,"KeyDescriptor"))
            if(key.getAttribute("use").isBlank()||"signing".equals(key.getAttribute("use")))for(var info:children(key,DS,"KeyInfo"))for(var data:children(info,DS,"X509Data"))for(var cert:children(data,DS,"X509Certificate"))
                result.add((X509Certificate)factory.generateCertificate(new java.io.ByteArrayInputStream(Base64.getDecoder().decode(cert.getTextContent().replaceAll("\\s+","")))));
        return result;
    }
    private static List<String> roleView(Element entity)throws Exception {
        var roles=children(entity,MD,"SPSSODescriptor");require(roles.size()==1);var result=new ArrayList<String>();var role=roles.getFirst();
        result.add("protocol="+role.getAttribute("protocolSupportEnumeration"));result.add("authn="+role.getAttribute("AuthnRequestsSigned"));result.add("assertion="+role.getAttribute("WantAssertionsSigned"));
        for(var certificate:spKeys(entity))result.add("key="+hash(certificate.getEncoded()));
        for(String name:List.of("SingleLogoutService","AssertionConsumerService"))for(var endpoint:children(role,MD,name))
            result.add(name+"|"+endpoint.getAttribute("Binding")+"|"+endpoint.getAttribute("Location")+"|"+endpoint.getAttribute("index"));
        return List.copyOf(result);
    }
    private record Trial(int failed,int successful,Set<String> participants,Element response,Instant responseAt,Instant failureAt){}
    private static String issuer(Element xml){var issuers=children(xml,S,"Issuer");require(issuers.size()==1);return issuers.getFirst().getTextContent();}
    private static String status(Element xml){var statuses=children(xml,P,"Status");require(statuses.size()==1);var codes=children(statuses.getFirst(),P,"StatusCode");require(codes.size()==1);return codes.getFirst().getAttribute("Value");}
    private static boolean hasPartial(Element xml){var statuses=children(xml,P,"Status");require(statuses.size()==1);var primary=children(statuses.getFirst(),P,"StatusCode");require(primary.size()==1);
        var secondary=children(primary.getFirst(),P,"StatusCode");require(secondary.size()<=1);return !secondary.isEmpty()&&PARTIAL.equals(secondary.getFirst().getAttribute("Value"));}
    private static final JsonCodec JSON=new JsonCodec();
    private static byte[] original(Path folder,String name)throws Exception {var file=folder.resolve(name).normalize();require(file.startsWith(folder)&&!file.equals(folder));
        var relative=folder.relativize(file);Path cursor=folder;for(Path part:relative){cursor=cursor.resolve(part);require(!Files.isSymbolicLink(cursor));}
        require(Files.isRegularFile(file,LinkOption.NOFOLLOW_LINKS)&&Files.size(file)<=5*1024*1024);return Files.readAllBytes(file);}
    private static byte[] checked(Path folder,JsonNode hashes,String file)throws Exception {var raw=original(folder,file);require(hash(raw).equals(text(hashes,file)));return raw;}
    private static JsonNode json(Path folder,JsonNode hashes,String file)throws Exception{return JSON.mapper().readTree(checked(folder,hashes,file));}
    private static String hash(byte[] raw)throws Exception{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(raw));}
    private static String text(JsonNode node,String key){var value=node.path(key);require(value.isTextual()&&!value.asText().isBlank());return value.asText();}
    private static Instant time(JsonNode node,String key){return Instant.parse(text(node,key));}
    private static EvidenceRef ref(TranscriptEntry entry){return new EvidenceRef("transcript",entry.id());}
    private static void require(boolean condition){if(!condition)throw new IllegalArgumentException("Unproven native SLO processing");}
    private static final Set<String> CONFIG=Set.of("relying-party","authn-properties","global","logout-propagate-view","logout-view","logout-complete-view");
    private static final Map<String,String> NATIVE_PINS=Map.of(
        "native-logout-logout-propagation-beans.xml","337310aaa5d00b18bb8f1ab6028fafd84eaba729b58367af24111d6dbe2e43ec",
        "native-logout-logout-propagation-flow.xml","8df175d442ca7c584558a13854cacfa4e6e9c5a7e4ebc49f298a5b296a0e4e37",
        "native-logout-propagate.vm","a39e4e98eb346181fbd78ebb68ec4280c2179be0d7810827bced4bf61c9507ef",
        "native-saml-logout-saml2-logoutprop-beans.xml","4660c9ac9c2afe5cd855bfb50e61753712a835861de9f876e6352fd06105ed6f",
        "native-saml-logout-saml2-logoutprop-flow.xml","3d0d23d2faf5ae4b46f9df2bdd77088ce7d3852b9ceab0093841038b73b75504",
        "native-saml-saml2-slo-front-abstract-flow.xml","a1031dd5881ebeac3107d9bbe0449811ccb7eca8a74b6536cd47df39e01afdaa",
        "native-saml-saml2-slo-post-beans.xml","1e0dab5a485d93f8c19edd5a5c318886522511dd6112a32654396d853f143cf3",
        "native-saml-saml2-slo-post-flow.xml","191e7cae35715cc4935ccf37a456c869371bae619fb01ac9d8f043192e4df6c4");
}
