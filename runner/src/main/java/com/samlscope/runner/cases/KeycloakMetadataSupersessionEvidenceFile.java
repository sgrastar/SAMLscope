package com.samlscope.runner.cases;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.samlscope.core.caseexec.CaseContext;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.transcript.*;
import com.samlscope.saml.crypto.*;
import com.samlscope.saml.normal.*;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.cert.*;
import java.time.Instant;
import java.util.*;
import java.util.function.BiFunction;
import org.w3c.dom.Element;

/**
 * Original native XML conversion, same-client replacement, and actual protocol behavior.
 * A valid, admitted POST ACS rejected by the native redirect policy is an application
 * counterexample. Partial reflection never proves the full supersession obligation.
 */
final class KeycloakMetadataSupersessionEvidenceFile {
    private static final ObjectMapper JSON=new ObjectMapper();
    private static final String MD="urn:oasis:names:tc:SAML:2.0:metadata",P="urn:oasis:names:tc:SAML:2.0:protocol",
        A="urn:oasis:names:tc:SAML:2.0:assertion",DS="http://www.w3.org/2000/09/xmldsig#",
        POST="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",ADMIN="http://localhost:18180/admin/realms/samlscope";
    private static final List<String> PHASES=List.of("control","multiple-signing-keys-first","multiple-signing-keys","no-valid-until");
    private static final Map<String,String> NATIVE_PATHS=Map.of(
        "org/keycloak/protocol/saml/EntityDescriptorDescriptionConverter.class","f12ac7fc23ddaec03f2b0d61c47368dae8038b478a4972a66d0ff7f3415de4ec",
        "org/keycloak/protocol/saml/SamlService.class","9595db004ef39dfa3e560ae4817d30646c15d117dbff08737283d14f0fbc7f45",
        "org/keycloak/protocol/saml/SamlService$BindingProtocol.class","1567d07d08492c6a80587e50e1db84ce5a4aab8a32ead70f043a7b8648ce172d");
    private final Path directory;private final TranscriptContentReader content;
    private final BiFunction<String,String,Optional<PlanCredentials>> keys;
    KeycloakMetadataSupersessionEvidenceFile(Path directory,TranscriptContentReader content,
            BiFunction<String,String,Optional<PlanCredentials>> keys){this.directory=directory.toAbsolutePath().normalize();this.content=content;this.keys=keys;}
    boolean exists(String run){return run!=null&&run.matches("run_[0-9A-HJKMNP-TV-Z]{26}")&&Files.isRegularFile(receipt(run),LinkOption.NOFOLLOW_LINKS);}
    private Path receipt(String run){return directory.resolve(run+".keycloak-supersession.json");}
    private record Original(TranscriptEntry entry,JsonNode value){}
    private Original original(JsonNode reference,String run,String targetHash,String peer,Map<String,TranscriptEntry> entries,List<EvidenceRef> refs)throws Exception{
        String id=text(reference,"reference");var e=entries.get(id);require(e!=null&&e.direction()==Direction.INBOUND&&run.equals(e.runId()));
        var raw=content.readDecodedSaml(e);require(raw!=null&&raw.length==e.decodedSamlBytes()&&hash(raw).equals(text(reference,"sha256")));
        var value=JSON.readTree(raw);require("samlscope-keycloak-native-supersession-original-v1".equals(text(value,"schema"))
            &&run.equals(text(value,"runId"))&&targetHash.equals(text(value,"targetMetadataSha256"))
            &&peer.equals(text(value,"peerEntityId"))&&"native-metadata-supersession".equals(text(value,"campaignId")));
        require(!Instant.parse(text(value,"recordedAt")).isAfter(e.timestamp()));
        refs.add(new EvidenceRef("transcript",e.id()));return new Original(e,value);
    }
    private static JsonNode nativeBody(JsonNode original,String method,String url)throws Exception{
        var n=original.path("native");require(method.equals(text(n,"method"))&&url.equals(text(n,"url"))&&n.path("status").isInt()&&n.path("status").asInt()==200);
        var raw=Base64.getDecoder().decode(text(n,"responseBase64"));require(hash(raw).equals(text(n,"responseSha256")));
        var value=JSON.readTree(raw);require(!value.has("secret")&&!value.has("registrationAccessToken"));return value;
    }
    CaseOutcome evaluate(String id,CaseContext context,byte[] targetRaw){return read(id,context,targetRaw,false);}
    /** Shared native originals and signature controls; the endpoint counterexample is separate. */
    CaseOutcome trustPrerequisites(CaseContext context,byte[] targetRaw){return read(MetadataSupersessionProbeTestCase.APPLICATION,context,targetRaw,true);}
    private CaseOutcome read(String id,CaseContext context,byte[] targetRaw,boolean trustOnly){String stage="receipt-unavailable";var refs=new ArrayList<EvidenceRef>();
        try{
            require(MetadataSupersessionProbeTestCase.supports(id)&&context.transcriptComplete()&&exists(context.runId()));
            var file=receipt(context.runId());require(Files.size(file)>0&&Files.size(file)<=131072);byte[] receiptRaw=Files.readAllBytes(file);var receipt=JSON.readTree(receiptRaw);
            var target=SecureXml.parse(targetRaw).getDocumentElement();String targetEntity=target.getAttribute("entityID"),targetHash=hash(targetRaw);
            require("http://localhost:18180/realms/samlscope".equals(targetEntity)&&targetEntity.equals(text(receipt,"targetEntityId"))
                &&targetHash.equals(text(receipt,"targetMetadataSha256"))&&context.runId().equals(text(receipt,"runId"))
                &&"samlscope-keycloak-native-supersession-v1".equals(text(receipt,"schema"))
                &&"keycloak-native-converter-same-client-v1".equals(text(receipt,"adapter"))
                &&"native-metadata-supersession".equals(text(receipt,"campaignId")));
            var entries=new LinkedHashMap<String,TranscriptEntry>();for(var e:context.transcript().list(context.runId()))require(context.runId().equals(e.runId())&&entries.put(e.id(),e)==null);
            String peer=text(receipt,"peerEntityId"),client=null;var phases=receipt.path("phases");require(phases.isArray()&&phases.size()==PHASES.size());
            var prepared=new LinkedHashMap<String,Element>();Instant first=null,last=null;JsonNode nativeDefaults=null;
            stage="native-accepted-epochs-unproven";
            for(int i=0;i<PHASES.size();i++){
                var phase=phases.get(i);String variant=text(phase,"variant");require(PHASES.get(i).equals(variant));
                var e=entries.get(text(phase,"preparedReference"));require(e!=null&&e.direction()==Direction.OUTBOUND&&"MetadataPrepared".equals(e.samlSummary().get("type"))
                    &&variant.equals(e.samlSummary().get("variant"))&&"live".equals(e.samlSummary().get("feed"))&&Integer.valueOf(200).equals(e.status()));
                var raw=content.readDecodedSaml(e);require((last==null||e.timestamp().isAfter(last))&&hash(raw).equals(text(phase,"fixtureSha256"))&&hash(raw).equals(e.samlSummary().get("metadataSha256")));
                var fetch=entries.get(String.valueOf(e.samlSummary().get("fetchTranscriptId")));require(fetch!=null&&fetch.direction()==Direction.INBOUND&&Integer.valueOf(200).equals(fetch.status())
                    &&"MetadataFetch".equals(fetch.samlSummary().get("type"))&&variant.equals(fetch.samlSummary().get("variant"))&&fetch.id().equals(e.correlationId())&&!e.timestamp().isBefore(fetch.timestamp()));
                var metadata=SecureXml.parse(raw).getDocumentElement();require(MD.equals(metadata.getNamespaceURI())&&"EntityDescriptor".equals(metadata.getLocalName())
                    &&peer.equals(metadata.getAttribute("entityID"))&&SamlSchemaValidation.isValid(metadata,SamlSchemaValidation.SchemaKind.METADATA));
                verifyMetadataSignature(metadata);prepared.put(variant,metadata);refs.add(new EvidenceRef("transcript",e.id()));refs.add(new EvidenceRef("transcript",fetch.id()));
                var converted=original(phase.path("converter"),context.runId(),targetHash,peer,entries,refs);var persisted=original(phase.path("persisted"),context.runId(),targetHash,peer,entries,refs);
                require("converter".equals(text(converted.value(),"kind"))&&"persisted".equals(text(persisted.value(),"kind")));
                for(var n:List.of(converted,persisted))require(variant.equals(text(n.value(),"variant"))&&hash(raw).equals(text(n.value(),"fixtureSha256"))&&!n.entry().timestamp().isBefore(e.timestamp()));
                require(!persisted.entry().timestamp().isBefore(converted.entry().timestamp())&&hash(raw).equals(text(converted.value().path("native"),"requestSha256")));
                var conversion=nativeBody(converted.value(),"POST",ADMIN+"/client-description-converter");String found=text(persisted.value(),"clientDatabaseId");
                require(found.matches("[0-9a-f-]{36}")&&(client==null||client.equals(found)));client=found;
                var saved=nativeBody(persisted.value(),"GET",ADMIN+"/clients/"+client);require(client.equals(text(saved,"id"))&&peer.equals(text(conversion,"clientId"))&&peer.equals(text(saved,"clientId"))
                    &&"saml".equals(text(conversion,"protocol"))&&"saml".equals(text(saved,"protocol"))&&saved.path("enabled").asBoolean());
                var defaults=nativeAttributes(conversion.path("attributes"),saved.path("attributes"));require((nativeDefaults==null||nativeDefaults.equals(defaults))&&sameSet(conversion.path("redirectUris"),saved.path("redirectUris")));nativeDefaults=defaults;
                var mutation=persisted.value().path("mutation");require((i==0?"POST":"PUT").equals(text(mutation,"method"))
                    &&(ADMIN+"/clients"+(i==0?"":"/"+client)).equals(text(mutation,"url"))&&mutation.path("status").asInt()==(i==0?201:204));
                require(hash(JSON.writeValueAsBytes(conversion)).equals(text(mutation,"requestSha256")));
                var mutationStarted=Instant.parse(text(mutation,"startedAt"));var mutationFinished=Instant.parse(text(mutation,"finishedAt"));require(!mutationStarted.isBefore(converted.entry().timestamp())&&!mutationFinished.isBefore(mutationStarted)&&!mutationFinished.isAfter(persisted.entry().timestamp()));
                require("true".equals(saved.path("attributes").path("saml.client.signature").asText()));
                if(first==null)first=e.timestamp();last=persisted.entry().timestamp();
            }
            var a=prepared.get("control");var b=prepared.get("no-valid-until");var bKeys=certificates(b,"signing");require(!bKeys.isEmpty()&&disjoint(certificates(a,"signing"),bKeys));
            String oldAcs=MetadataSupersessionProbeTestCase.acs(a,0).toString(),acs=MetadataSupersessionProbeTestCase.acs(b,0).toString(),second=MetadataSupersessionProbeTestCase.acs(b,1).toString();require(!oldAcs.equals(acs)&&!acs.equals(second));
            var scopeBefore=original(receipt.path("probeState").path("before"),context.runId(),targetHash,peer,entries,refs);
            var scopeAfter=original(receipt.path("probeState").path("after"),context.runId(),targetHash,peer,entries,refs);
            require("operative-client".equals(text(scopeBefore.value(),"kind"))&&"operative-client".equals(text(scopeAfter.value(),"kind"))&&scopeBefore.entry().timestamp().isAfter(last)&&scopeAfter.entry().timestamp().isAfter(scopeBefore.entry().timestamp()));
            require(scopeBefore.value().path("client").equals(scopeAfter.value().path("client"))&&scopeBefore.value().path("runtime").equals(scopeAfter.value().path("runtime"))&&scopeBefore.value().path("policies").equals(scopeAfter.value().path("policies")));
            var policies=scopeBefore.value().path("policies");require(policies.path("policies").path("policies").isArray()&&policies.path("policies").path("policies").isEmpty()
                &&policies.path("profiles").path("profiles").isArray()&&policies.path("profiles").path("profiles").isEmpty());
            var operative=scopeBefore.value().path("client");require(client.equals(text(operative,"id"))&&peer.equals(text(operative,"clientId"))&&"true".equals(operative.path("attributes").path("saml.client.signature").asText()));
            var finalSaved=nativeBody(original(phases.get(3).path("persisted"),context.runId(),targetHash,peer,entries,refs).value(),"GET",ADMIN+"/clients/"+client);require(finalSaved.equals(operative));
            var configuredKey=certificate(text(operative.path("attributes"),"saml.signing.certificate"));require(bKeys.stream().anyMatch(c->Arrays.equals(c.getPublicKey().getEncoded(),configuredKey.getPublicKey().getEncoded())));
            var before=original(receipt.path("restoration").path("before"),context.runId(),targetHash,peer,entries,refs);var after=original(receipt.path("restoration").path("after"),context.runId(),targetHash,peer,entries,refs);
            require("restoration-state".equals(text(before.value(),"kind"))&&"restoration-state".equals(text(after.value(),"kind"))&&before.value().path("nativePaths").equals(after.value().path("nativePaths")));
            var source=before.value().path("nativePaths");require("213c45bb357e0881ead8284f12308e3c9fd8e09e7f0b6ec816f95f8b0921bea9".equals(text(source,"jarSha256"))&&source.path("classes").isObject()&&source.path("classes").size()==NATIVE_PATHS.size());
            for(var pinned:NATIVE_PATHS.entrySet())require(pinned.getValue().equals(hash(Base64.getDecoder().decode(text(source.path("classes"),pinned.getKey())))));
            require(before.value().path("clients").isArray()&&before.value().path("clients").isEmpty()&&before.value().path("clients").equals(after.value().path("clients"))
                &&before.value().path("runtime").equals(after.value().path("runtime"))&&before.value().path("policies").equals(after.value().path("policies"))
                &&before.value().path("runtime").path("running").asBoolean()&&!before.entry().timestamp().isAfter(first));
            stage="outbox-controls-unproven";var probes=receipt.path("probes");require(probes.isArray()&&probes.size()==MetadataSupersessionProbeTestCase.FIXTURES.size());
            var requests=new HashMap<String,TranscriptEntry>();var xml=new HashMap<String,Element>();var probeRows=new HashMap<String,JsonNode>();Instant finalAt=last;
            for(var probe:probes){String fixture=text(probe,"fixture");require(MetadataSupersessionProbeTestCase.FIXTURES.contains(fixture)&&!requests.containsKey(fixture));var request=entries.get(text(probe,"requestReference"));
                require(request!=null&&request.direction()==Direction.OUTBOUND&&Boolean.TRUE.equals(request.samlSummary().get("active_probe"))&&fixture.equals(request.samlSummary().get("fixture_id"))
                    &&"AuthnRequest".equals(request.samlSummary().get("type"))&&MetadataSupersessionProbeTestCase.supports(String.valueOf(request.samlSummary().get("scenario_case_id")))
                    &&text(probe,"actionId").equals(request.correlationId())&&request.timestamp().isAfter(last)&&!scopeBefore.entry().timestamp().isAfter(request.timestamp()));
                var requestRaw=content.readDecodedSaml(request);var sent=SecureXml.parse(requestRaw).getDocumentElement();require(P.equals(sent.getNamespaceURI())&&"AuthnRequest".equals(sent.getLocalName())
                    &&("_"+request.correlationId()).equals(sent.getAttribute("ID"))&&peer.equals(issuer(sent)));
                String endpoint=sent.getAttribute("Destination");require(endpoint.equals("http://localhost:18180/realms/samlscope/protocol/saml"));
                if("new-key-redirect".equals(fixture))require("GET".equals(request.method())&&request.rawQuery()!=null&&request.url().equals(endpoint+"?"+request.rawQuery())
                    &&bKeys.stream().anyMatch(c->new com.samlscope.saml.binding.RedirectSignatureVerifier().isValidForMessage(request.rawQuery(),c,requestRaw)));
                else require("POST".equals(request.method())&&request.url().equals(endpoint));
                var terminal=entries.values().stream().filter(e->e.direction()==Direction.INBOUND&&(sent.getAttribute("ID").equals(e.samlSummary().get("inResponseTo"))||("BrowserResponseObservation".equals(e.samlSummary().get("type"))&&request.correlationId().equals(e.correlationId())))).toList();
                require(terminal.size()==1&&!terminal.getFirst().timestamp().isBefore(request.timestamp())&&!scopeAfter.entry().timestamp().isBefore(terminal.getFirst().timestamp()));
                if(terminal.getFirst().timestamp().isAfter(finalAt))finalAt=terminal.getFirst().timestamp();requests.put(fixture,request);xml.put(fixture,sent);probeRows.put(fixture,probe);refs.add(new EvidenceRef("transcript",request.id()));
            }
            require(!after.entry().timestamp().isBefore(finalAt));
            var positive=requests.get("new-key-explicit-acs");var positiveXml=xml.get("new-key-explicit-acs");require(acs.equals(positiveXml.getAttribute("AssertionConsumerServiceURL"))&&valid(positiveXml,bKeys));
            verifySuccess(context,positive,positiveXml,acs,peer,target,entries,refs);
            var negative=requests.get("new-key-invalid-signature");var negativeXml=xml.get("new-key-invalid-signature");require(acs.equals(negativeXml.getAttribute("AssertionConsumerServiceURL"))&&!valid(negativeXml,bKeys)&&new XmlSignatureVerifier().hasValidEnvelopedReferenceDigests(negativeXml));
            verifyNativeRejection(context,negative,probeRows.get("new-key-invalid-signature"),targetHash,peer,"Invalid requester",entries,refs);
            if(trustOnly){
                require(hash(receiptRaw).equals(hash(Files.readAllBytes(file))));
                return new CaseOutcome(Outcome.SATISFIED,null,"metadata.native-common-proof.verified","metadata.native-common-proof.verified",refs.stream().distinct().toList(),Map.of("native_originals_verified",true,"restoration_verified",true,"receipt_sha256",hash(receiptRaw)));
            }
            stage="native-endpoint-counterexample-unproven";var request=requests.get("new-key-second-acs");var sent=xml.get("new-key-second-acs");require("POST".equals(request.method())&&second.equals(sent.getAttribute("AssertionConsumerServiceURL"))&&POST.equals(sent.getAttribute("ProtocolBinding"))&&valid(sent,bKeys));
            require(!values(operative.path("redirectUris")).contains(second)&&values(operative.path("redirectUris")).contains(acs));
            verifyNativeRejection(context,request,probeRows.get("new-key-second-acs"),targetHash,peer,"Invalid redirect uri",entries,refs);
            require(hash(receiptRaw).equals(hash(Files.readAllBytes(file))));
            if(MetadataSupersessionProbeTestCase.APPLICATION.equals(id))return new CaseOutcome(Outcome.VIOLATED,null,"metadata.application.accepted-post-endpoint-rejected","metadata.application.accepted-post-endpoint-rejected",refs.stream().distinct().toList(),Map.of("counterexample","accepted-second-post-acs","accepted_metadata_b_sha256",text(phases.get(3),"fixtureSha256"),"native_originals_verified",true,"restoration_verified",true,"receipt_sha256",hash(receiptRaw)));
            // The accepted B endpoint is a counterexample to runtime reflection after
            // in-place A -> B replacement. This does not assert complete successful
            // reflection of every binding/profile or adopt the separate rollover probes.
            return new CaseOutcome(Outcome.VIOLATED,null,"metadata.supersession.accepted-post-endpoint-rejected","metadata.supersession.accepted-post-endpoint-rejected",refs.stream().distinct().toList(),Map.of("counterexample","accepted-second-post-acs-after-same-entity-replacement","accepted_metadata_b_sha256",text(phases.get(3),"fixtureSha256"),"native_originals_verified",true,"restoration_verified",true,"receipt_sha256",hash(receiptRaw),"scope","accepted-B-endpoint-runtime-reflection","violated_variant","IIP-MD06.ab#v-7e4460130e","other_binding_profile_reflection_not_concluded",true));
        }catch(Exception unavailable){return pending(stage);}
    }
    private void verifyNativeRejection(CaseContext context,TranscriptEntry request,JsonNode probe,String targetHash,String peer,String expected,Map<String,TranscriptEntry> entries,List<EvidenceRef> refs)throws Exception{
        var responses=entries.values().stream().filter(e->e.direction()==Direction.INBOUND&&request.correlationId().equals(e.correlationId())&&"BrowserResponseObservation".equals(e.samlSummary().get("type"))).toList();require(responses.size()==1);var response=responses.getFirst();
        require("BROWSER".equals(response.method())&&Integer.valueOf(400).equals(response.status())&&request.url().equals(response.url())&&response.timestamp().isAfter(request.timestamp()));
        require(response.bodyRef().equals("transcripts/"+context.runId()+"/"+response.id()+".body")&&response.bodyBytes()>0&&response.bodyBytes()<=262144);
        var root=directory.getParent();var path=root.resolve(response.bodyRef()).normalize();require(path.startsWith(root)&&Files.isRegularFile(path,LinkOption.NOFOLLOW_LINKS)&&!Files.isSymbolicLink(path.getParent())&&Files.size(path)==response.bodyBytes());
        var raw=Files.readAllBytes(path);var page=new String(raw,StandardCharsets.UTF_8);require(page.contains("id=\"kc-error-message\"")&&page.contains(expected)&&!page.contains("name=\"SAMLResponse\"")&&!page.contains("name='SAMLResponse'"));
        var captured=original(probe.path("nativeHttp"),context.runId(),targetHash,peer,entries,refs);var n=captured.value().path("native");
        require("native-http-response".equals(text(captured.value(),"kind"))&&request.id().equals(text(captured.value(),"requestReference"))&&response.id().equals(text(captured.value(),"responseReference"))&&request.correlationId().equals(text(captured.value(),"actionId"))
            &&"POST".equals(text(n,"method"))&&request.url().equals(text(n,"requestUrl"))&&request.url().equals(text(n,"responseUrl"))&&("_"+request.correlationId()).equals(text(n,"requestId"))
            &&hash(content.readDecodedSaml(request)).equals(text(n,"requestSha256"))&&n.path("responseStatus").asInt()==400&&n.path("responseBodyBytes").asLong()==raw.length&&hash(raw).equals(text(n,"responseBodySha256")));
        var start=Instant.parse(text(n,"startedAt"));var end=Instant.parse(text(n,"finishedAt"));require(!start.isBefore(request.timestamp())&&!end.isBefore(start)&&!end.isAfter(response.timestamp())&&!captured.entry().timestamp().isBefore(response.timestamp()));
        refs.add(new EvidenceRef("transcript",response.id()));
    }
    private void verifySuccess(CaseContext context,TranscriptEntry request,Element sent,String acs,String peer,Element target,Map<String,TranscriptEntry> entries,List<EvidenceRef> refs)throws Exception{
        var matches=entries.values().stream().filter(e->e.direction()==Direction.INBOUND&&sent.getAttribute("ID").equals(e.samlSummary().get("inResponseTo"))).toList();require(matches.size()==1);var entry=matches.getFirst();
        var response=SecureXml.parse(content.readDecodedSaml(entry)).getDocumentElement();require("POST".equals(entry.method())&&acs.equals(entry.url())&&entry.timestamp().isAfter(request.timestamp())&&P.equals(response.getNamespaceURI())&&"Response".equals(response.getLocalName())&&acs.equals(response.getAttribute("Destination"))&&sent.getAttribute("ID").equals(response.getAttribute("InResponseTo"))&&target.getAttribute("entityID").equals(issuer(response)));
        var status=MetadataAlgorithmEvidence.children(response,P,"Status");require(status.size()==1&&MetadataAlgorithmEvidence.children(status.getFirst(),P,"StatusCode").size()==1&&"urn:oasis:names:tc:SAML:2.0:status:Success".equals(MetadataAlgorithmEvidence.children(status.getFirst(),P,"StatusCode").getFirst().getAttribute("Value")));
        var signing=MetadataAlgorithmEvidence.signingKeys(target);require(valid(response,signing));var encrypted=response.getElementsByTagNameNS(A,"EncryptedAssertion");
        if(encrypted.getLength()>0){require(encrypted.getLength()==1);var wrapper=(Element)encrypted.item(0);var key=keys.apply(context.runId(),"no-valid-until").orElseThrow();var plain=new SamlXmlDecrypter().decrypt(wrapper,key.privateKey());wrapper.getParentNode().replaceChild(response.getOwnerDocument().importNode(plain,true),wrapper);}
        var assertions=response.getElementsByTagNameNS(A,"Assertion");require(assertions.getLength()==1);var assertion=(Element)assertions.item(0);require(valid(assertion,signing));
        var audiences=assertion.getElementsByTagNameNS(A,"Audience");require(audiences.getLength()==1&&peer.equals(audiences.item(0).getTextContent().strip()));var confirmations=assertion.getElementsByTagNameNS(A,"SubjectConfirmationData");require(confirmations.getLength()==1);var c=(Element)confirmations.item(0);require(sent.getAttribute("ID").equals(c.getAttribute("InResponseTo"))&&acs.equals(c.getAttribute("Recipient"))&&assertion.getElementsByTagNameNS(A,"AuthnStatement").getLength()==1);refs.add(new EvidenceRef("transcript",entry.id()));
    }
    private static void verifyMetadataSignature(Element root)throws Exception{var signatures=MetadataAlgorithmEvidence.children(root,DS,"Signature");require(signatures.size()==1);var nodes=signatures.getFirst().getElementsByTagNameNS(DS,"X509Certificate");require(nodes.getLength()==1);require(valid(root,List.of(certificate(nodes.item(0).getTextContent()))));}
    private static List<X509Certificate> certificates(Element root,String use)throws Exception{var out=new ArrayList<X509Certificate>();var nodes=root.getElementsByTagNameNS(MD,"KeyDescriptor");for(int i=0;i<nodes.getLength();i++){var key=(Element)nodes.item(i);if(key.hasAttribute("use")&&!use.equals(key.getAttribute("use")))continue;var certs=key.getElementsByTagNameNS(DS,"X509Certificate");for(int c=0;c<certs.getLength();c++)out.add(certificate(certs.item(c).getTextContent()));}return out;}
    private static X509Certificate certificate(String value)throws Exception{return (X509Certificate)CertificateFactory.getInstance("X.509").generateCertificate(new java.io.ByteArrayInputStream(Base64.getMimeDecoder().decode(value)));}
    private static boolean valid(Element e,List<X509Certificate> certs){return certs.stream().anyMatch(c->new XmlSignatureVerifier().hasValidEnvelopedSignature(e,c));}
    private static boolean disjoint(List<X509Certificate>a,List<X509Certificate>b){return a.stream().noneMatch(x->b.stream().anyMatch(y->Arrays.equals(x.getPublicKey().getEncoded(),y.getPublicKey().getEncoded())));}
    private static Set<String> values(JsonNode a){require(a.isArray());var out=new HashSet<String>();for(var n:a){require(n.isTextual());out.add(n.asText());}return out;}
    private static boolean sameSet(JsonNode a,JsonNode b){return values(a).equals(values(b));}
    private static JsonNode nativeAttributes(JsonNode converted,JsonNode saved){
        require(converted.isObject()&&saved.isObject());var generated=JSON.createObjectNode();
        var fields=converted.fields();while(fields.hasNext()){var field=fields.next();require(field.getValue().equals(saved.get(field.getKey())));}
        var defaults=Map.of("saml.force.post.binding","true","realm_client","false","saml_force_name_id_format","false",
            "saml_name_id_format","username","saml.allow.ecp.flow","false","saml_signature_canonicalization_method","http://www.w3.org/2001/10/xml-exc-c14n#");
        var actual=saved.fields();while(actual.hasNext()){var field=actual.next();if(converted.has(field.getKey()))continue;
            String key=field.getKey();require(field.getValue().isTextual());String value=field.getValue().asText();
            if(defaults.containsKey(key))require(defaults.get(key).equals(value));
            else if("client.secret.creation.time".equals(key))require(value.matches("[0-9]{10}"));
            else if("saml.artifact.binding.identifier".equals(key))require(Base64.getDecoder().decode(value).length==20);
            else require(false);generated.set(key,field.getValue());
        }
        require(generated.size()==defaults.size()+2);return generated;
    }
    private static String issuer(Element e){var nodes=MetadataAlgorithmEvidence.children(e,A,"Issuer");require(nodes.size()==1);return nodes.getFirst().getTextContent().strip();}
    private static String text(JsonNode n,String key){var v=n.path(key);require(v.isTextual()&&!v.asText().isBlank());return v.asText();}
    private static String hash(byte[] raw)throws Exception{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(raw));}
    private static void require(boolean value){if(!value)throw new IllegalArgumentException("Native metadata supersession proof incomplete");}
    private static CaseOutcome pending(String stage){return new CaseOutcome(Outcome.NOT_VERIFIED,"native_metadata_supersession_unproven","metadata.supersession.evidence-incomplete","metadata.supersession.evidence-incomplete",List.of(),Map.of("evidence_issue",stage));}
}
