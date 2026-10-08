package com.samlscope.api;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.samlscope.core.caseexec.ActionIds;
import com.samlscope.runner.cases.ArtifactBindingEvidence;
import com.samlscope.runner.outbox.ArtifactResolutionOutboundSender;
import com.samlscope.saml.artifact.*;
import com.samlscope.saml.binding.RedirectSignatureVerifier;
import com.samlscope.saml.crypto.XmlSignatureVerifier;
import com.samlscope.saml.metadata.TargetMetadataParser;
import com.samlscope.saml.normal.SecureXml;
import com.samlscope.store.JsonCodec;
import java.net.URI;
import java.nio.file.*;
import java.security.cert.X509Certificate;
import java.util.*;
import org.w3c.dom.Element;

/** Offline Suite calibration of actual public originals; no target judgment or persisted mutation. */
public final class ReplaySyntheticArtifactControls {
    static final String CASE = "IIP-IDP12-f-idp-01", P = ArtifactResolutionProtocol.P, A = ArtifactResolutionProtocol.A;
    static final int MAX_INPUT = 32 * 1024 * 1024;
    @SuppressWarnings("unchecked")
    public static void main(String[] args) throws Exception {
        require(args.length == 2 || args.length == 3, "Usage: <native-export.json> <suite-public-metadata.xml> [public-transcript-index.json]");
        byte[] captureBytes = input(Path.of(args[0])), suiteMetadata = input(Path.of(args[1]));
        var codec = new JsonCodec(); codec.mapper().enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION)
                .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS);
        var capture = codec.mapper().readValue(captureBytes, Map.class); var proof = object(capture.get("runtimeProof"));
        String run = string(capture, "runId"), plan = string(capture, "planId"), mode = string(capture, "fixtureMode");
        require("samlscope-synthetic-artifact-runtime-v1".equals(capture.get("schema")) && Set.of("signed", "unsigned").contains(mode)
                && Boolean.TRUE.equals(capture.get("runtimeProofVerified")), "Unqualified native export");
        require(ReadSyntheticArtifactRuntime.hash(suiteMetadata).equals(proof.get("suitePublicMetadataSha256"))
                && Arrays.equals(suiteMetadata, bytes(proof, "suitePublicMetadataBase64")), "Public Suite metadata differs from capture");
        var entries = new LinkedHashMap<String,Map<String,Object>>();
        for (var value : list(capture.get("transcriptOriginals"))) {
            var entry = object(value); require(run.equals(entry.get("runId")) && entries.put(string(entry, "id"), entry) == null, "Duplicate or foreign original");
            verifyBytes(entry, "body", "computedBodySha256"); verifyBytes(entry, "decodedSaml", "computedDecodedSha256");
            if (entry.get("storedBodySha256") != null) require(entry.get("storedBodySha256").equals(entry.get("computedBodySha256")), "Stored body hash differs");
        }
        var authn = reference(entries, proof, "artifactAuthnRequestReference"); var delivered = reference(entries, proof, "artifactDeliveryReference");
        var request = reference(entries, proof, "requestSoapReference"); var response = reference(entries, proof, "responseSoapReference");
        var normal = reference(entries, proof, "normalResponseReference"); var normalXml = xml(normal);
        var normalRequest = only(entries.values().stream().filter(e -> "OUTBOUND".equals(e.get("direction"))
                && "AuthnRequest".equals(summary(e).get("type")) && Objects.equals(e.get("correlationId"), normal.get("correlationId"))).toList());
        var authnXml = xml(authn); var suite = ReadSyntheticArtifactRuntime.originalCertificate(authnXml);
        var suiteEntity = ReadSyntheticArtifactRuntime.suiteEntity(suiteMetadata, plan, ReadSyntheticArtifactRuntime.single(authnXml, A, "Issuer").getTextContent());
        require(ReadSyntheticArtifactRuntime.matches(suite, ReadSyntheticArtifactRuntime.certificates(suiteEntity))
                && ReadSyntheticArtifactRuntime.hash(suite.getEncoded()).equals(proof.get("suiteCertificateSha256")), "Actual Suite certificate relationship differs");
        byte[] targetMetadata = bytes(proof, "runMetadataSnapshotBase64"); require(ReadSyntheticArtifactRuntime.hash(targetMetadata).equals(proof.get("runMetadataSnapshotSha256")), "Metadata snapshot hash differs");
        String targetEntity = string(capture, "targetEntityId");
        require(targetEntity.equals("http://host.docker.internal:18937/" + mode + "/entity"), "Foreign target entity");
        var targetKeys = new TargetMetadataParser().parse(targetMetadata, targetEntity).signingCertificates(); require(!targetKeys.isEmpty(), "Target certificate absent");
        String authnAction = ActionIds.derive(run, CASE, ArtifactBindingEvidence.PHASE, 0), action = ActionIds.derive(run, CASE, ArtifactResolutionOutboundSender.PHASE, 0);
        URI acs = URI.create(authnXml.getAttribute("AssertionConsumerServiceURL")), endpoint = URI.create(string(proof, "resolutionEndpoint"));
        require(action.equals(proof.get("resolveActionId")) && authnAction.equals(authn.get("correlationId"))
                && action.equals(request.get("correlationId")) && action.equals(response.get("correlationId")), "Deterministic action correlation differs");
        var artifact = ArtifactBindingEvidence.delivery(string(delivered, "method"), string(delivered, "url"), string(delivered, "contentType"),
                bytes(delivered, "bodyBase64"), (String) delivered.get("rawQuery"), run, authnAction, acs).artifact();
        require(endpoint.equals(artifact.resolutionEndpoint(targetMetadata, targetEntity)), "Artifact endpoint differs from target snapshot");
        byte[] requestSoap = bytes(request, "decodedSamlBase64"), responseSoap = bytes(response, "decodedSamlBase64");
        require(Arrays.equals(requestSoap, bytes(request, "bodyBase64")) && Arrays.equals(responseSoap, bytes(response, "bodyBase64")), "SOAP Recorder bodies differ");
        var outbox = only(list(capture.get("outbox")).stream().map(ReplaySyntheticArtifactControls::object)
                .filter(o -> action.equals(object(o.get("action")).get("actionId"))).toList());
        var outAction = object(outbox.get("action")); var send = object(outbox.get("sendResult"));
        require("SENT".equals(outbox.get("status")) && "ARTIFACT_RESOLVE".equals(outAction.get("kind"))
                && endpoint.toString().equals(outAction.get("target")) && Arrays.equals(requestSoap, bytes(outAction, "payload"))
                && response.get("id").equals(outbox.get("transcriptEntryId")) && request.get("id").equals(send.get("request_transcript"))
                && ReadSyntheticArtifactRuntime.hash(responseSoap).equals(send.get("response_sha256")), "Outbox capture differs");
        var receipt = object(send.get("transport_authentication")); require(receipt.equals(summary(response).get("transport_authentication")), "Receipt copies differ");
        var protocol = new ArtifactResolutionProtocol();
        String suiteIssuer = ReadSyntheticArtifactRuntime.single(authnXml, A, "Issuer").getTextContent();
        protocol.verifyResolve(requestSoap, artifact, "_" + action, endpoint, suiteIssuer, suite);
        var tls = ArtifactTlsEvidence.verify(receipt, run, action, endpoint, string(request, "id"), string(response, "id"), requestSoap, responseSoap, suite).orElseThrow();
        var resolved = protocol.verifyResponse(responseSoap, "_" + action, authnXml.getAttribute("ID"), targetEntity, acs, targetKeys, tls);
        require(resolved.authentication().equals("signed".equals(mode) ? "trusted-xml-signature" : "closed-pkix-hostname-tls"), "Actual authentication differs");
        var checks = new ArrayList<Map<String,Object>>();
        accepted(checks, "actual-signed-ArtifactResolve", () -> protocol.verifyResolve(requestSoap, artifact, "_" + action, endpoint, suiteIssuer, suite));
        accepted(checks, "actual-bound-TLS-receipt", () -> require(ArtifactTlsEvidence.verify(receipt, run, action, endpoint, string(request,"id"), string(response,"id"), requestSoap, responseSoap, suite).isPresent(), "Actual receipt rejected"));
        accepted(checks, "actual-ArtifactResponse-origin-and-correlation", () -> protocol.verifyResponse(responseSoap, "_" + action, authnXml.getAttribute("ID"), targetEntity, acs, targetKeys, tls));
        accepted(checks, "actual-M0-Redirect-signature", () -> require(new RedirectSignatureVerifier().isValidForMessage((String)normalRequest.get("rawQuery"), suite, bytes(normalRequest,"decodedSamlBase64")), "M0 Redirect signature rejected"));
        accepted(checks, "actual-M0-Response-outer-signature", () -> require(targetKeys.stream().anyMatch(c -> new XmlSignatureVerifier().hasValidEnvelopedSignature(normalXml,c)), "M0 Response outer signature rejected"));
        require(authnXml.getAttribute("ID").equals("_" + authnAction) && new XmlSignatureVerifier().hasValidEnvelopedSignature(authnXml,suite), "Artifact Authn signature rejected");
        var required = new LinkedHashMap<String,String>();
        required.put("m0AuthnRequest",string(normalRequest,"id")); required.put("m0Response",string(normal,"id"));
        required.put("artifactAuthnRequest",string(authn,"id")); required.put("artifactDelivery",string(delivered,"id"));
        required.put("artifactResolve",string(request,"id")); required.put("artifactResponse",string(response,"id"));
        for (String fixture : List.of("post-binding-control", "redirect-binding", "unsupported-binding")) {
            var sent = only(entries.values().stream().filter(e -> CASE.equals(summary(e).get("scenario_case_id")) && fixture.equals(summary(e).get("fixture_id"))).toList());
            var sentXml = xml(sent); var reply = only(entries.values().stream().filter(e -> "INBOUND".equals(e.get("direction")) && sentXml.getAttribute("ID").equals(summary(e).get("inResponseTo"))).toList());
            var replyXml = xml(reply); require(new XmlSignatureVerifier().hasValidEnvelopedSignature(sentXml,suite)
                    && targetKeys.stream().anyMatch(c -> new XmlSignatureVerifier().hasValidEnvelopedSignature(replyXml,c)), "Binding fixture signature rejected");
            required.put(fixture + "AuthnRequest",string(sent,"id")); required.put(fixture + "Response",string(reply,"id"));
        }
        rejected(checks,"foreign-outer-correlation-context",() -> protocol.verifyResponse(responseSoap,"_foreign_resolve",authnXml.getAttribute("ID"),targetEntity,acs,targetKeys,tls));
        rejected(checks,"foreign-inner-correlation-context",() -> protocol.verifyResponse(responseSoap,"_"+action,"_foreign_authn",targetEntity,acs,targetKeys,tls));
        rejected(checks,"foreign-issuer-context",() -> protocol.verifyResponse(responseSoap,"_"+action,authnXml.getAttribute("ID"),"http://foreign.invalid/entity",acs,targetKeys,tls));
        rejected(checks,"foreign-ACS-context",() -> protocol.verifyResponse(responseSoap,"_"+action,authnXml.getAttribute("ID"),targetEntity,URI.create("http://foreign.invalid/acs"),targetKeys,tls));
        for (String field : List.of("outer-correlation", "inner-correlation", "outer-issuer", "inner-issuer", "ACS")) {
            byte[] mutated = mutation(responseSoap, field);
            rejected(checks,"mutated-"+field+"-original-copy",() -> protocol.verifyResponse(mutated,"_"+action,authnXml.getAttribute("ID"),targetEntity,acs,targetKeys,tls));
        }
        rejected(checks,"foreign-target-metadata-certificate-without-TLS-proof",() -> protocol.verifyResponse(responseSoap,"_"+action,authnXml.getAttribute("ID"),targetEntity,acs,List.of(suite),null));
        rejected(checks,"TLS-foreign-Suite-public-metadata-certificate",() -> require(ArtifactTlsEvidence.verify(receipt,run,action,endpoint,string(request,"id"),string(response,"id"),requestSoap,responseSoap,targetKeys.getFirst()).isPresent(),"Foreign certificate rejected"));
        rejected(checks,"TLS-foreign-Run",() -> require(ArtifactTlsEvidence.verify(receipt,"run_foreign",action,endpoint,string(request,"id"),string(response,"id"),requestSoap,responseSoap,suite).isPresent(),"Foreign Run rejected"));
        rejected(checks,"TLS-foreign-action",() -> require(ArtifactTlsEvidence.verify(receipt,run,"action_foreign",endpoint,string(request,"id"),string(response,"id"),requestSoap,responseSoap,suite).isPresent(),"Foreign action rejected"));
        rejected(checks,"TLS-foreign-request-reference",() -> require(ArtifactTlsEvidence.verify(receipt,run,action,endpoint,"tx_foreign",string(response,"id"),requestSoap,responseSoap,suite).isPresent(),"Foreign request reference rejected"));
        rejected(checks,"TLS-foreign-response-reference",() -> require(ArtifactTlsEvidence.verify(receipt,run,action,endpoint,string(request,"id"),"tx_foreign",requestSoap,responseSoap,suite).isPresent(),"Foreign response reference rejected"));
        rejected(checks,"TLS-foreign-endpoint",() -> require(ArtifactTlsEvidence.verify(receipt,run,action,URI.create("https://foreign.invalid/resolve"),string(request,"id"),string(response,"id"),requestSoap,responseSoap,suite).isPresent(),"Foreign endpoint rejected"));
        byte[] badRequest = requestSoap.clone(); badRequest[badRequest.length-1] ^= 1;
        byte[] badResponse = responseSoap.clone(); badResponse[badResponse.length-1] ^= 1;
        rejected(checks,"TLS-tampered-request-bytes",() -> require(ArtifactTlsEvidence.verify(receipt,run,action,endpoint,string(request,"id"),string(response,"id"),badRequest,responseSoap,suite).isPresent(),"Tampered request rejected"));
        rejected(checks,"TLS-tampered-response-bytes",() -> require(ArtifactTlsEvidence.verify(receipt,run,action,endpoint,string(request,"id"),string(response,"id"),requestSoap,badResponse,suite).isPresent(),"Tampered response rejected"));
        rejected(checks,"TLS-forged-Run-fact-without-resigning",() -> require(ArtifactTlsEvidence.verify(forgedReceipt(receipt,"run_id","run_foreign"),"run_foreign",action,endpoint,string(request,"id"),string(response,"id"),requestSoap,responseSoap,suite).isPresent(),"Forged Run fact rejected"));
        rejected(checks,"TLS-forged-action-fact-without-resigning",() -> require(ArtifactTlsEvidence.verify(forgedReceipt(receipt,"action_id","action_foreign"),run,"action_foreign",endpoint,string(request,"id"),string(response,"id"),requestSoap,responseSoap,suite).isPresent(),"Forged action fact rejected"));
        rejected(checks,"TLS-forged-request-reference-fact-without-resigning",() -> require(ArtifactTlsEvidence.verify(forgedReceipt(receipt,"request_reference","tx_foreign"),run,action,endpoint,"tx_foreign",string(response,"id"),requestSoap,responseSoap,suite).isPresent(),"Forged request reference fact rejected"));
        rejected(checks,"TLS-forged-response-reference-fact-without-resigning",() -> require(ArtifactTlsEvidence.verify(forgedReceipt(receipt,"response_reference","tx_foreign"),run,action,endpoint,string(request,"id"),"tx_foreign",requestSoap,responseSoap,suite).isPresent(),"Forged response reference fact rejected"));
        rejected(checks,"TLS-forged-request-hash-fact-without-resigning",() -> require(ArtifactTlsEvidence.verify(forgedReceipt(receipt,"request_sha256",ReadSyntheticArtifactRuntime.hash(badRequest)),run,action,endpoint,string(request,"id"),string(response,"id"),badRequest,responseSoap,suite).isPresent(),"Forged request hash fact rejected"));
        rejected(checks,"TLS-forged-response-hash-fact-without-resigning",() -> require(ArtifactTlsEvidence.verify(forgedReceipt(receipt,"response_sha256",ReadSyntheticArtifactRuntime.hash(badResponse)),run,action,endpoint,string(request,"id"),string(response,"id"),requestSoap,badResponse,suite).isPresent(),"Forged response hash fact rejected"));
        rejected(checks,"TLS-omitted-receipt",() -> require(ArtifactTlsEvidence.verify(null,run,action,endpoint,string(request,"id"),string(response,"id"),requestSoap,responseSoap,suite).isPresent(),"Omitted receipt rejected"));
        if("unsigned".equals(mode)) rejected(checks,"unsigned-Response-with-omitted-origin-proof",() -> protocol.verifyResponse(responseSoap,"_"+action,authnXml.getAttribute("ID"),targetEntity,acs,targetKeys,null));
        else accepted(checks,"signed-Response-with-independent-trusted-outer-proof",() -> protocol.verifyResponse(responseSoap,"_"+action,authnXml.getAttribute("ID"),targetEntity,acs,targetKeys,null));
        var result = new LinkedHashMap<String,Object>(); result.put("schema","samlscope-synthetic-artifact-offline-controls-v1");
        result.put("label","Suite calibration only / actual product proof false"); result.put("actualProductProof",false);
        result.put("changesActualCaseOutcome",false); result.put("mutations","in-memory copies only"); result.put("networkOperations",0);
        result.put("databaseOperations",0); result.put("privateKeyReads",0); result.put("runId",run); result.put("planId",plan); result.put("fixtureMode",mode);
        result.put("inputExportSha256",ReadSyntheticArtifactRuntime.hash(captureBytes)); result.put("suitePublicMetadataSha256",ReadSyntheticArtifactRuntime.hash(suiteMetadata));
        result.put("actualStoredOutcome",capture.get("storedOutcome")); result.put("actualAuthentication",resolved.authentication());
        result.put("requiredOriginalReferences",required); result.put("requiredOriginalsComplete",true); result.put("allOriginalExportComplete",capture.get("originalExportComplete"));
        result.put("originalExportDiagnostics",capture.get("diagnostics"));
        if(args.length==3) result.put("diagnosticClassification",classify(codec.mapper().readValue(input(Path.of(args[2])),List.class),list(capture.get("diagnostics")),new HashSet<>(required.values()),run));
        result.put("checks",checks); result.put("checkCount",checks.size());
        boolean passed = checks.stream().allMatch(c -> Boolean.TRUE.equals(c.get("passed"))); result.put("allPassed",passed);
        System.out.println(codec.write(result)); require(passed,"Offline calibration controls failed");
    }
    static byte[] mutation(byte[] original,String field) {
        var outer=new ArtifactResolutionProtocol().soapMessage(original,"ArtifactResponse");
        var inner=ReadSyntheticArtifactRuntime.single(outer,P,"Response");
        switch(field) {
            case "outer-correlation" -> outer.setAttribute("InResponseTo","_foreign_resolve");
            case "inner-correlation" -> inner.setAttribute("InResponseTo","_foreign_authn");
            case "outer-issuer" -> ReadSyntheticArtifactRuntime.single(outer,A,"Issuer").setTextContent("http://foreign.invalid/entity");
            case "inner-issuer" -> ReadSyntheticArtifactRuntime.single(inner,A,"Issuer").setTextContent("http://foreign.invalid/entity");
            case "ACS" -> inner.setAttribute("Destination","http://foreign.invalid/acs");
            default -> throw new IllegalArgumentException("Unknown mutation");
        } return SecureXml.serialize(outer.getOwnerDocument());
    }
    static Map<String,Object> forgedReceipt(Map<String,Object> receipt,String field,Object value) {
        var copy=new LinkedHashMap<String,Object>(receipt);var facts=new LinkedHashMap<String,Object>(object(receipt.get("facts")));
        facts.put(field,value);copy.put("facts",facts);return copy;
    }
    static List<Map<String,Object>> classify(List<?> transcript,List<?> diagnostics,Set<String> required,String run) {
        var rows=new ArrayList<Map<String,Object>>();
        for(var diagnostic:diagnostics) {
            String text=String.valueOf(diagnostic),id=text.substring(text.lastIndexOf(": ")+2);
            var matches=transcript.stream().map(ReplaySyntheticArtifactControls::object).filter(e -> id.equals(e.get("id"))).toList();
            if(matches.size()!=1) {rows.add(Map.of("reference",id,"classification","unclassified-export-diagnostic"));continue;}
            var entry=matches.getFirst();require(run.equals(entry.get("runId")),"Diagnostic index foreign Run");var summary=object(entry.get("samlSummary"));
            boolean unrelated= !CASE.equals(summary.get("scenario_case_id")) && !required.contains(id);
            var row=new LinkedHashMap<String,Object>();row.put("reference",id);row.put("scenarioCaseId",summary.get("scenario_case_id"));row.put("fixtureId",summary.get("fixture_id"));
            row.put("selectedArtifactProofReference",required.contains(id));row.put("classification",unrelated && Set.of("dtd-authn-request","dtd-external-entity-authn-request").contains(summary.get("fixture_id"))
                    ? "unselected-DTD-AuthnRequest-refused-by-secure-XML-export-parser" : "unclassified-export-diagnostic"); rows.add(row);
        }return rows;
    }
    interface Check {void run() throws Exception;}
    static void accepted(List<Map<String,Object>> checks,String id,Check check){boolean accepted;try{check.run();accepted=true;}catch(Exception rejection){accepted=false;}checks.add(Map.of("id",id,"expected","accepted","observed",accepted?"accepted":"rejected","passed",accepted));}
    static void rejected(List<Map<String,Object>> checks,String id,Check check){boolean rejected;try{check.run();rejected=false;}catch(Exception rejection){rejected=true;}checks.add(Map.of("id",id,"expected","rejected","observed",rejected?"rejected":"accepted","passed",rejected));}
    static byte[] input(Path path)throws Exception{require(Files.isRegularFile(path,LinkOption.NOFOLLOW_LINKS)&&Files.size(path)>0&&Files.size(path)<=MAX_INPUT,"Bounded public input unavailable");return Files.readAllBytes(path);}
    static void verifyBytes(Map<String,Object> entry,String stem,String hashField){byte[] bytes=bytes(entry,stem+"Base64");require(bytes.length==((Number)entry.get(stem+"Bytes")).intValue()&&ReadSyntheticArtifactRuntime.hash(bytes).equals(entry.get(hashField)),"Export bytes/hash differ");}
    static Map<String,Object> reference(Map<String,Map<String,Object>> entries,Map<String,Object> proof,String name){var entry=entries.get(string(proof,name));require(entry!=null,"Required selected original absent");return entry;}
    static Element xml(Map<String,Object> entry){return SecureXml.parse(bytes(entry,"decodedSamlBase64")).getDocumentElement();}
    static Map<String,Object> summary(Map<String,Object> entry){return object(entry.get("summary"));}
    @SuppressWarnings("unchecked") static Map<String,Object> object(Object value){require(value instanceof Map<?,?>,"Expected JSON object");return (Map<String,Object>)value;}
    static List<?> list(Object value){require(value instanceof List<?>,"Expected JSON list");return (List<?>)value;}
    static byte[] bytes(Map<String,Object> value,String name){return Base64.getDecoder().decode(string(value,name));}
    static String string(Map<String,Object> value,String name){require(value.get(name) instanceof String,"Required public field absent: "+name);return (String)value.get(name);}
    static <T>T only(List<T> values){require(values.size()==1,"Required public evidence ambiguous");return values.getFirst();}
    static void require(boolean value,String reason){if(!value)throw new IllegalArgumentException(reason);}
}
