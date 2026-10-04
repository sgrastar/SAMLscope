package com.samlscope.runner.cases;

import com.fasterxml.jackson.databind.JsonNode;
import com.samlscope.saml.crypto.XmlSignatureVerifier;
import com.samlscope.saml.normal.SecureXml;
import com.samlscope.store.JsonCodec;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.*;
import org.w3c.dom.Element;

/** Verifies original execution material for the isolated, non-adoptable control target. */
final class SloContinuationActorEvidence {
    static final String SCHEMA="samlscope-suite-actor-soap-continuation-v1";
    // Filled from the separately compiled actor before source freeze; empty pins fail closed.
    static final String SOURCE_SHA="54d2fcb6281c7a43d49af4f35d14ec08918d6e35995be11f4bc5f0c6bc8e603b";
    static final Map<String,String> CLASS_SHA=Map.of("SoapContinuationActor$Continuation.class","92cd3104be51815e0ec74dcf363ce7ef13dc1827f594f768fd41ce1c19be3d70","SoapContinuationActor$ContinuingActor.class","8b5bfc92e2bb5eaa9f89b258ebc65e3b9f677d0a3062d5a50903cbbe02ca0c4d","SoapContinuationActor$Session.class","df54dc455a515d27022cbfae52a1e9ece4b6c5f541e2bdbe69a4f9b46cd56a27","SoapContinuationActor$StopAfterErrorActor.class","4229c0222979225684923f172f22b6826cc42760a8613128523b1a6c634e7018","SoapContinuationActor.class","a26510554b63484bc35c6697adfa07ec6fe35345bbf8a339168ad6d57ae671fc");
    private static final String NS="urn:samlscope:diagnostic:continuation",A="urn:oasis:names:tc:SAML:2.0:assertion";
    private static final JsonCodec JSON=new JsonCodec();
    @FunctionalInterface interface Originals {byte[] read(String name)throws Exception;}
    record Session(String entity,String endpoint,String sessionIndexSha256,String nameIdSha256) {}
    record Producer(String sourceSha,String classesSha,String actorClass,String callbackBase) {}
    static Producer producer(JsonNode manifest,Originals originals)throws Exception {
        require(SCHEMA.equals(text(manifest,"schema")));
        String source=text(manifest,"producerSourceFile"),classes=text(manifest,"producerClassesFile");
        require(source.equals("actor/SoapContinuationActor.java")&&classes.equals("actor/classes.json")
                &&SOURCE_SHA.equals(hash(originals.read(source)))&&SOURCE_SHA.equals(text(manifest,"producerSourceSha256")));
        byte[] classRaw=originals.read(classes);var model=JSON.mapper().readTree(classRaw);require(model.isObject()&&model.size()==CLASS_SHA.size()&&!CLASS_SHA.isEmpty());
        for(var entry:CLASS_SHA.entrySet())require(entry.getValue().equals(text(model,entry.getKey()))&&entry.getValue().equals(hash(originals.read("actor/classes/"+entry.getKey()))));
        String actor=text(manifest,"actorClass");require(Set.of("com.samlscope.runner.cases.SoapContinuationActor$ContinuingActor","com.samlscope.runner.cases.SoapContinuationActor$StopAfterErrorActor").contains(actor));
        String callback=text(manifest,"publicCallbackBase");var uri=java.net.URI.create(callback);require("http".equals(uri.getScheme())&&"localhost".equals(uri.getHost())&&uri.getPort()>0&&uri.getRawPath().isEmpty()&&uri.getRawQuery()==null&&uri.getRawUserInfo()==null&&uri.getRawFragment()==null);
        return new Producer(SOURCE_SHA,hash(classRaw),actor,callback);
    }
    static SloContinuationProof.Operation operation(String run,String trial,String targetSha,String preparedSha,
            ShibbolethNativeSloContinuationEvidence.SoapMessage origin,ShibbolethNativeSloContinuationEvidence.SoapMessage finalResponse,
            List<ShibbolethNativeSloContinuationEvidence.Participant> participants,Map<String,Session> sessions,
            List<X509Certificate> targetKeys,Producer producer,JsonNode descriptor,Originals originals,
            SloContinuationProof.Operation protocol)throws Exception {
        byte[] inputRaw=originals.read(text(descriptor,"operationInputFile")),outputRaw=originals.read(text(descriptor,"operationOutputFile"));
        var input=JSON.mapper().readTree(inputRaw);var output=JSON.mapper().readTree(outputRaw);var signed=SecureXml.parse(originals.read(text(descriptor,"operationTraceFile"))).getDocumentElement();
        require(NS.equals(signed.getNamespaceURI())&&"Operation".equals(signed.getLocalName())
                &&targetKeys.stream().anyMatch(k->new XmlSignatureVerifier().hasValidEnvelopedSignature(signed,k)));
        for(var value:List.of(input,output))require(run.equals(text(value,"runId"))&&trial.equals(text(value,"trial"))&&origin.xml().getAttribute("ID").equals(text(value,"originRequestId")));
        require("samlscope-slo-continuation-actor-input-v1".equals(text(input,"schema"))&&"samlscope-slo-continuation-actor-output-v1".equals(text(output,"schema")));
        require(run.equals(signed.getAttribute("runId"))&&trial.equals(signed.getAttribute("trial"))
                &&producer.sourceSha().equals(signed.getAttribute("sourceSha256"))&&producer.classesSha().equals(signed.getAttribute("classesSha256"))
                &&hash(inputRaw).equals(signed.getAttribute("inputSha256"))&&hash(outputRaw).equals(signed.getAttribute("outputSha256"))
                &&Arrays.equals(inputRaw,Base64.getDecoder().decode(single(signed,NS,"Input")))&&Arrays.equals(outputRaw,Base64.getDecoder().decode(single(signed,NS,"Output"))));
        require(targetSha.equals(text(input,"targetMetadataSha256"))&&preparedSha.equals(text(input,"preparedSha256"))
                &&hash(samlBytes(origin.xml())).equals(text(input,"originRequestSha256"))&&producer.actorClass().equals(text(output,"actorClass")));
        var selected=input.path("selectedSessions");require(selected.isArray()&&selected.size()==3&&sessions.keySet().equals(Set.of("fail","remain","remain2")));var labels=new HashSet<String>();
        for(var row:selected){String label=text(row,"label");require(labels.add(label)&&sessions.containsKey(label));var session=sessions.get(label);require(session.entity().equals(text(row,"entity"))&&session.endpoint().equals(text(row,"endpoint"))&&session.sessionIndexSha256().equals(text(row,"sessionIndexSha256"))&&session.nameIdSha256().equals(text(row,"nameIdSha256")));}
        require(labels.equals(sessions.keySet()));
        var ordered=new ArrayList<>(participants);ordered.sort(Comparator.comparing(p->p.request().entry().timestamp()));var events=output.path("events");require(events.isArray()&&events.size()==ordered.size()*2);
        Instant previous=origin.entry().timestamp();
        for(int i=0;i<ordered.size();i++){
            var participant=ordered.get(i);var send=events.get(i*2);var response=events.get(i*2+1);String requestId=participant.request().xml().getAttribute("ID");
            for(var e:List.of(send,response))require(participant.label().equals(text(e,"label"))&&requestId.equals(text(e,"requestId")));
            require("send".equals(text(send,"event"))&&"verified-response".equals(text(response,"event"))
                    &&hash(samlBytes(participant.request().xml())).equals(text(send,"requestSha256"))
                    &&hash(originals.read("soap/"+participant.request().entry().id()+".xml")).equals(text(send,"rawEnvelopeSha256"))
                    &&participant.response().xml().getAttribute("ID").equals(text(response,"responseId"))
                    &&hash(samlBytes(participant.response().xml())).equals(text(response,"responseSha256"))
                    &&hash(originals.read("soap/"+participant.response().entry().id()+".xml")).equals(text(response,"rawEnvelopeSha256"))
                    &&protocol.verifiedStatuses().get(i).equals(text(response,"status")));
            var start=Instant.parse(text(send,"at"));var verified=Instant.parse(text(response,"at"));
            require(start.isAfter(previous)&&!start.isAfter(participant.request().entry().timestamp())
                    &&verified.isAfter(participant.response().entry().timestamp())&&verified.isBefore(finalResponse.entry().timestamp()));previous=verified;
        }
        var terminal=output.path("terminal");require(terminal.isObject());var at=Instant.parse(text(terminal,"at"));require(at.isAfter(previous)&&at.isBefore(finalResponse.entry().timestamp())
                &&finalResponse.xml().getAttribute("ID").equals(text(terminal,"originFinalId"))&&hash(samlBytes(finalResponse.xml())).equals(text(terminal,"originFinalSha256")));
        var selectedLabels=set(terminal.path("selected"));var attempted=set(terminal.path("attempted"));var remaining=set(terminal.path("remaining"));
        require(selectedLabels.equals(sessions.keySet())&&attempted.equals(new HashSet<>(protocol.attempted()))
                &&list(terminal.path("attempted")).equals(protocol.attempted()));
        var expectedRemaining=new HashSet<>(selectedLabels);expectedRemaining.removeAll(attempted);require(remaining.equals(expectedRemaining));
        return new SloContinuationProof.Operation(trial,selectedLabels,protocol.attempted(),attempted,remaining,protocol.verifiedStatuses(),SloContinuationProof.TerminalAuthority.VERIFIED_COMPLETE_EXECUTION);
    }
    static byte[] samlBytes(Element element){var doc=SecureXml.newDocument();doc.appendChild(doc.importNode(element,true));return SecureXml.serialize(doc);}
    static String hash(byte[] raw)throws Exception{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(raw));}
    private static String single(Element root,String ns,String name){var matches=root.getElementsByTagNameNS(ns,name);require(matches.getLength()==1&&matches.item(0).getParentNode()==root);return matches.item(0).getTextContent();}
    private static List<String> list(JsonNode value){require(value.isArray());var list=new ArrayList<String>();for(var row:value){require(row.isTextual()&&!row.asText().isBlank());list.add(row.asText());}require(new HashSet<>(list).size()==list.size());return list;}
    private static Set<String> set(JsonNode value){return new HashSet<>(list(value));}
    private static String text(JsonNode node,String field){require(node.path(field).isTextual()&&!node.path(field).asText().isBlank());return node.path(field).asText();}
    private static void require(boolean condition){if(!condition)throw new IllegalArgumentException("Unproven isolated continuation operation");}
    private SloContinuationActorEvidence() {}
}
