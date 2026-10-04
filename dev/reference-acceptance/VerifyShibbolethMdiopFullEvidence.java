package com.samlscope.runner.cases;

import com.samlscope.core.casedef.CaseDefinitionCatalogMapper;
import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.plan.*;
import com.samlscope.core.run.Reachability;
import com.samlscope.core.transcript.*;
import com.samlscope.runner.DefaultCaseContext;
import com.samlscope.saml.crypto.*;
import com.samlscope.saml.normal.SecureXml;
import com.samlscope.store.JsonCodec;
import java.nio.file.*;
import java.security.*;
import java.security.cert.*;
import java.security.interfaces.*;
import java.security.spec.RSAPublicKeySpec;
import java.time.Clock;
import java.util.*;
import org.w3c.dom.Element;
import static com.samlscope.runner.cases.MetadataAlgorithmEvidence.children;

/** Original signatures plus archived production MDIOP all-of case; no runtime-key judgment. */
public final class VerifyShibbolethMdiopFullEvidence {
    private static final String ID="IIP-MD05-c-idp-01",MD="urn:oasis:names:tc:SAML:2.0:metadata",DS="http://www.w3.org/2000/09/xmldsig#",
        P="urn:oasis:names:tc:SAML:2.0:protocol",S="urn:oasis:names:tc:SAML:2.0:assertion",SUCCESS="urn:oasis:names:tc:SAML:2.0:status:Success";
    private static final JsonCodec JSON=new JsonCodec();
    private static String hash(byte[] raw)throws Exception{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(raw));}
    private static void require(boolean yes,String why){if(!yes)throw new IllegalArgumentException(why);}
    private static Element entity(Element metadata){
        if(MD.equals(metadata.getNamespaceURI())&&"EntityDescriptor".equals(metadata.getLocalName()))return metadata;
        var entities=children(metadata,MD,"EntityDescriptor");require(entities.size()==1,"Ambiguous metadata entity");return entities.getFirst();
    }
    private static X509Certificate cert(String value)throws Exception{return (X509Certificate)CertificateFactory.getInstance("X.509")
        .generateCertificate(new java.io.ByteArrayInputStream(Base64.getMimeDecoder().decode(value)));}
    private static List<X509Certificate> signingKeys(Element metadata)throws Exception{
        var role=children(entity(metadata),MD,"SPSSODescriptor");require(role.size()==1,"SP role unavailable");var keys=new ArrayList<X509Certificate>();
        for(var descriptor:children(role.getFirst(),MD,"KeyDescriptor")) {
            if("encryption".equals(descriptor.getAttribute("use")))continue;
            for(var info:children(descriptor,DS,"KeyInfo")) {
                for(var data:children(info,DS,"X509Data"))for(var certificate:children(data,DS,"X509Certificate"))keys.add(cert(certificate.getTextContent()));
                for(var value:children(info,DS,"KeyValue")) {
                    var rsa=children(value,DS,"RSAKeyValue");require(rsa.size()==1,"Unsupported key value");
                    var modulus=new java.math.BigInteger(1,Base64.getMimeDecoder().decode(children(rsa.getFirst(),DS,"Modulus").getFirst().getTextContent()));
                    var exponent=new java.math.BigInteger(1,Base64.getMimeDecoder().decode(children(rsa.getFirst(),DS,"Exponent").getFirst().getTextContent()));
                    var publicKey=KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(modulus,exponent));
                    var rootSignatures=children(metadata,DS,"Signature");require(rootSignatures.size()==1,"KeyValue verifier wrapper absent");
                    var certificates=rootSignatures.getFirst().getElementsByTagNameNS(DS,"X509Certificate");require(certificates.getLength()==1,"KeyValue certificate ambiguous");
                    var wrapper=cert(certificates.item(0).getTextContent());require(Arrays.equals(publicKey.getEncoded(),wrapper.getPublicKey().getEncoded()),"KeyValue and wrapper differ");keys.add(wrapper);
                }
            }
        }
        require(!keys.isEmpty(),"No advertised signing key");return keys;
    }
    private static CaseOutcome evaluate(TestCase testcase,String run,List<TranscriptEntry> entries){
        var recorder=new TranscriptRecorder(){public List<TranscriptEntry> list(String id){require(id.equals(run),"Foreign requested Run");return entries;}
            public TranscriptEntry record(TranscriptInput input){throw new UnsupportedOperationException();}public TranscriptEntry updateSamlAnalysis(String id,String c,Map<String,Object>s){throw new UnsupportedOperationException();}};
        var context=new DefaultCaseContext(run,TargetRole.IDP,Clock.systemUTC(),TestPlan.Parameters.defaults(),TestPlan.Interaction.defaults(),Reachability.CONFIRMED,recorder,true);
        var state=((CaseStep.AwaitConfig)testcase.start(context)).next();return ((CaseStep.Finish)testcase.resume(context,state,new CaseEvent.ConfigConfirmed())).outcome();
    }
    private static boolean responseValid(Element response,String id,String recipient,String target,List<X509Certificate> keys,boolean success){
        try{
            require(P.equals(response.getNamespaceURI())&&"Response".equals(response.getLocalName())&&id.equals(response.getAttribute("InResponseTo"))&&recipient.equals(response.getAttribute("Destination")),"Response correlation differs");
            var verified=new VerifiedSignatureAlgorithms().read(response,target,keys);
            long expected=children(response,DS,"Signature").size()+children(response,S,"Assertion").stream().mapToInt(a->children(a,DS,"Signature").size()).sum();
            require(verified.size()==expected&&verified.stream().anyMatch(s->"Response".equals(s.element())),"Target signature unavailable");
            var statuses=children(response,P,"Status");require(statuses.size()==1,"Status ambiguous");var codes=children(statuses.getFirst(),P,"StatusCode");require(codes.size()==1,"Status code ambiguous");
            if(success)require(SUCCESS.equals(codes.getFirst().getAttribute("Value")),"Positive response is not Success");
            else require(Set.of("urn:oasis:names:tc:SAML:2.0:status:Requester","urn:oasis:names:tc:SAML:2.0:status:Responder").contains(codes.getFirst().getAttribute("Value"))
                &&children(response,S,"Assertion").isEmpty()&&children(response,S,"EncryptedAssertion").isEmpty(),"Control is not explicit assertion-free error");
            return true;
        }catch(Exception uncertain){return false;}
    }
    public static void main(String[]args)throws Exception{
        var folder=Path.of(args[0]).toAbsolutePath();var output=Path.of(args[1]);require(!Files.exists(output),"Replay must be immutable");
        boolean historicalBaseline=args.length==3&&"historical-baseline".equals(args[2]);
        JSON.mapper().enable(com.fasterxml.jackson.databind.SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS);
        @SuppressWarnings("unchecked") var document=(Map<String,Object>)JSON.mapper().readValue(folder.resolve("approved-cases-projection.json").toFile(),Map.class);
        var catalog=CaseDefinitionCatalogMapper.fromDocument(document);
        var testcase=MetadataConfigCaseFactory.create(catalog.require(ID)).orElseThrow();
        var variants=((MetadataFixtureObservationTestCase)testcase).evidenceActionKeys();require(variants.size()==19,"Expected full current representation family");
        String run=JSON.mapper().readTree(folder.resolve("created.json").toFile()).path("run").path("id").asText();
        var entries=List.of(JSON.mapper().readValue(folder.resolve("transcript.json").toFile(),TranscriptEntry[].class));var byId=new HashMap<String,TranscriptEntry>();
        for(var e:entries)require(run.equals(e.runId())&&byId.put(e.id(),e)==null,"Foreign/duplicate original");
        var originals=new HashMap<String,byte[]>();
        for(var row:JSON.mapper().readTree(folder.resolve("decoded-manifest.json").toFile())){
            var path=folder.resolve(row.path("file").asText()).normalize();require(path.getParent().equals(folder.resolve("decoded")),"Escaped original");
            var raw=Files.readAllBytes(path);var e=byId.get(row.path("id").asText());require(e!=null&&e.decodedSamlBytes()==raw.length&&row.path("sha256").asText().equals(hash(raw))&&originals.put(e.id(),raw)==null,"Original hash/size differs");
        }
        var target=SecureXml.parse(Files.readAllBytes(folder.resolve("target-metadata.xml"))).getDocumentElement();String targetEntity=target.getAttribute("entityID");
        require("http://localhost:18280/idp/shibboleth".equals(targetEntity),"Wrong native target");var targetKeys=MetadataAlgorithmEvidence.signingKeys(target);
        var verified=new LinkedHashMap<String,Object>();var positiveRefs=new HashMap<String,String>();
        for(String variant:variants){
            var directory=folder.resolve(variant);var fixture=Files.readAllBytes(directory.resolve("fixture.xml"));var metadata=SecureXml.parse(fixture).getDocumentElement();
            var prepared=entries.stream().filter(e->e.direction()==Direction.OUTBOUND&&"MetadataPrepared".equals(e.samlSummary().get("type"))&&variant.equals(e.samlSummary().get("variant"))).toList();
            require(prepared.size()==1&&Arrays.equals(fixture,originals.get(prepared.getFirst().id())),"Prepared fixture original differs: "+variant);
            var flow=JSON.mapper().readTree(directory.resolve("flow.json").toFile());require(run.equals(flow.path("run").asText())&&variant.equals(flow.path("variant").asText()),"Flow identity differs");
            var positive=flow.path("positive_exchange");var negative=flow.path("negative_control");require(positive.path("success").asBoolean()&&"suite".equals(negative.path("source").asText())&&!negative.path("correlated_success").asBoolean(true),"Controls unavailable: "+variant);
            var signerKeys=signingKeys(metadata);var observations=JSON.mapper().readTree(directory.resolve("native-http-observations.json").toFile()).path("records");
            for(boolean success:List.of(true,false)){
                var exchange=success?positive:negative.path("exchange");String id=exchange.path("request_id").asText();var requests=entries.stream().filter(e->e.direction()==Direction.OUTBOUND&&id.equals(e.samlSummary().get("id"))).toList();
                require(requests.size()==1,"Ambiguous request");var request=requests.getFirst();var requestBytes=originals.get(request.id());var xml=SecureXml.parse(requestBytes).getDocumentElement();
                require(id.equals(xml.getAttribute("ID"))&&children(xml,S,"Issuer").size()==1&&entity(metadata).getAttribute("entityID").equals(children(xml,S,"Issuer").getFirst().getTextContent()),"Request issuer differs");
                var verifier=new XmlSignatureVerifier();require(verifier.hasValidEnvelopedReferenceDigests(xml),"Control content is not original");
                require(signerKeys.stream().anyMatch(c->verifier.hasValidEnvelopedSignature(xml,c))==success,"Request uses incorrect signing key/control: "+variant);
                var responses=entries.stream().filter(e->e.direction()==Direction.INBOUND&&id.equals(e.samlSummary().get("inResponseTo"))).toList();
                if(!responses.isEmpty()){
                    require(responses.size()==1&&responses.getFirst().timestamp().isAfter(request.timestamp())&&responseValid(SecureXml.parse(originals.get(responses.getFirst().id())).getDocumentElement(),id,xml.getAttribute("AssertionConsumerServiceURL"),targetEntity,targetKeys,success),"Target response not verified: "+variant);
                    if(success)positiveRefs.put(variant,responses.getFirst().id());
                }else{
                    require(!success,"Positive response missing");var matching=new ArrayList<com.fasterxml.jackson.databind.JsonNode>();for(var row:observations)if(id.equals(row.path("requestId").asText()))matching.add(row);
                    require(matching.size()==1&&hash(requestBytes).equals(matching.getFirst().path("requestSha256").asText())&&request.url().equals(matching.getFirst().path("requestUrl").asText())
                        &&request.url().equals(matching.getFirst().path("responseUrl").asText())&&matching.getFirst().path("nativeMessageSecurityError").asBoolean()&&!matching.getFirst().path("samlResponseFormPresent").asBoolean(),"No explicit request-bound native rejection: "+variant);
                    var original=matching.getFirst();String filename=original.path("responseBodyFile").asText();require(filename.matches("native-rejection-[A-Za-z0-9_-]+\\.html"),"Native rejection original missing");
                    var rejection=Files.readAllBytes(directory.resolve(filename));String html=new String(rejection,java.nio.charset.StandardCharsets.UTF_8);
                    require(hash(rejection).equals(original.path("responseBodySha256").asText())&&original.path("responseStatus").asInt()>=400&&html.contains("Message Security Error")
                        &&!html.toLowerCase(Locale.ROOT).contains("<input")&&!html.contains("SAMLResponse"),"Native rejection original differs");
                    var started=java.time.Instant.parse(original.path("startedAt").asText());var completed=java.time.Instant.parse(original.path("completedAt").asText());
                    require(!started.isBefore(request.timestamp())&&!completed.isBefore(started),"Native request-response time differs");
                }
            }
            verified.put(variant,Map.of("metadataOriginal",true,"validRequestSignature",true,"signedSuccess",true,"invalidSignatureRejected",true));
        }
        var base=evaluate(testcase,run,entries);require(base.outcome()==Outcome.SATISFIED,"Production all-of does not satisfy");var controls=new LinkedHashMap<String,String>();
        for(String variant:variants){var selected=entries.stream().filter(e->!e.id().equals(positiveRefs.get(variant))).toList();var outcome=evaluate(testcase,run,selected);require(outcome.outcome()==Outcome.NOT_VERIFIED,"Partial representations adopted: "+variant);controls.put("missing-positive:"+variant,outcome.outcome().name());}
        var cross=entries.stream().map(e->new TranscriptEntry(e.id(),"run_00000000000000000000000000",e.direction(),e.timestamp(),e.correlationId(),e.method(),e.url(),e.status(),e.headers(),e.bodyRef(),e.bodyBytes(),e.decodedSamlRef(),e.decodedSamlBytes(),e.contentType(),e.rawQuery(),e.samlSummary())).toList();
        var foreignOutcome=evaluate(testcase,run,cross).outcome();
        require(historicalBaseline||foreignOutcome==Outcome.NOT_VERIFIED,"Foreign Run adopted");controls.put("foreign-run",foreignOutcome.name());
        var duplicate=new ArrayList<>(entries);duplicate.add(entries.getFirst());
        var duplicateOutcome=evaluate(testcase,run,duplicate).outcome();
        require(historicalBaseline||duplicateOutcome==Outcome.NOT_VERIFIED,"Duplicate Recorder identity adopted");controls.put("duplicate-recorder-id",duplicateOutcome.name());
        JSON.mapper().writerWithDefaultPrettyPrinter().writeValue(output.toFile(),Map.of("schema","samlscope-shibboleth-mdiop-full-production-replay-v1","runId",run,"caseId",ID,"productionOutcome",base.outcome().name(),"productionCaseOutcome",base,"representations",verified,"controls",controls,"runtimeKeyInterpretationProven",false));
    }
}
