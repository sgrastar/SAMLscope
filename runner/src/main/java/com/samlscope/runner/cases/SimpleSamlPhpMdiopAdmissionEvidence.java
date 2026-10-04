package com.samlscope.runner.cases;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.samlscope.core.caseexec.CaseContext;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.transcript.*;
import com.samlscope.saml.normal.SecureXml;
import com.samlscope.saml.crypto.XmlSignatureVerifier;
import com.samlscope.store.JsonCodec;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.*;

/** Complete native MDIOP representation admission; never a claim about later key use. */
final class SimpleSamlPhpMdiopAdmissionEvidence {
    static final String ID="IIP-MD05-c-idp-01";
    private static final String TARGET="http://localhost:18380/idp";
    private static final Map<String,String> SOURCES=Map.of(
        "parser","8620bb26fd41d2be29d2611883839a4cfde0b6c8458c274e2d40a002678fd93d",
        "metadata-handler","43a0e730d624c5a937f800c4e7e045ff3625eeb0738d81a4ab1dac96f82fe040",
        "flatfile","48fe4682d980e62416c751b7a39406ebf9664bf539e6a1557e7f54df770398c6",
        "xml","4b78b0f27f70fca0e7b0300b21011007b95d686c99709bffbed62cf7bc4fe705");
    private static final Map<String,String> COMMANDS=Map.of("parser","fc6bb05f5c10267c630077851655251daa7a645c8fe338f938bfc555818c8209",
        "readback","f84064049b9bc6ef0339b9b1874e86b6e36e89fe8770a502d5735200b15ed756");
    private final Path directory; private final TranscriptContentReader content;
    SimpleSamlPhpMdiopAdmissionEvidence(Path directory,TranscriptContentReader content){this.directory=directory.toAbsolutePath().normalize();this.content=content;}
    private Path path(String run){return directory.resolve(run+".ssp-mdiop-representation.json");}
    boolean exists(String run){return run!=null&&run.matches("run_[0-9A-HJKMNP-TV-Z]{26}")&&Files.exists(path(run),LinkOption.NOFOLLOW_LINKS);}
    private static void require(boolean value){if(!value)throw new IllegalArgumentException("native_admission_originals_invalid");}
    private static String text(JsonNode node,String name){return node.path(name).asText();}
    private static JsonNode json(byte[] raw)throws Exception{return new JsonCodec().mapper().readTree(raw);}
    private static String sha(byte[] bytes)throws Exception{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));}
    private static byte[] decoded(JsonNode value)throws Exception{require(value.isObject());byte[] raw=Base64.getDecoder().decode(text(value,"base64"));require(sha(raw).equals(text(value,"sha256")));return raw;}
    private record Original(TranscriptEntry entry,JsonNode value){}
    private Original original(JsonNode ref,CaseContext context,String targetHash,Map<String,TranscriptEntry> entries,List<EvidenceRef> evidence)throws Exception{
        require(ref.isObject()&&text(ref,"reference").matches("tx_[0-9A-HJKMNP-TV-Z]{26}"));var entry=entries.get(text(ref,"reference"));
        require(entry!=null&&entry.direction()==Direction.INBOUND&&context.runId().equals(entry.runId()));byte[] raw=content.readDecodedSaml(entry);
        require(raw!=null&&raw.length==entry.decodedSamlBytes()&&sha(raw).equals(text(ref,"sha256")));var value=json(raw);
        require("samlscope-ssp-mdiop-native-original-v1".equals(text(value,"schema"))&&context.runId().equals(text(value,"runId"))&&TARGET.equals(text(value,"targetEntityId"))&&targetHash.equals(text(value,"targetMetadataSha256")));
        require(!Instant.parse(text(value,"recordedAt")).isAfter(entry.timestamp()));evidence.add(new EvidenceRef("transcript",entry.id()));return new Original(entry,value);
    }
    CaseOutcome evaluate(CaseContext context,byte[] target){String stage="native-admission-originals";try{
        require(context.transcriptComplete()&&exists(context.runId())&&Files.isDirectory(directory,LinkOption.NOFOLLOW_LINKS)&&Files.isRegularFile(path(context.runId()),LinkOption.NOFOLLOW_LINKS));
        require(Files.size(path(context.runId()))<=1_048_576);var receipt=json(Files.readAllBytes(path(context.runId())));String targetHash=sha(target);
        require(TARGET.equals(SecureXml.parse(target).getDocumentElement().getAttribute("entityID"))&&"samlscope-ssp-mdiop-representation-v1".equals(text(receipt,"schema"))&&"ssp-native-parser-admission-v1".equals(text(receipt,"adapter"))&&context.runId().equals(text(receipt,"runId"))&&TARGET.equals(text(receipt,"targetEntityId"))&&targetHash.equals(text(receipt,"targetMetadataSha256"))&&"metadata-fixture-refresh".equals(text(receipt,"campaignId")));
        var entries=new HashMap<String,TranscriptEntry>();for(var e:context.transcript().list(context.runId()))require(context.runId().equals(e.runId())&&entries.put(e.id(),e)==null);
        var evidence=new ArrayList<EvidenceRef>();var baseline=original(receipt.path("baseline"),context,targetHash,entries,evidence);var restore=original(receipt.path("restoration"),context,targetHash,entries,evidence);
        require("baseline".equals(text(baseline.value(),"kind"))&&"restoration".equals(text(restore.value(),"kind"))&&restore.value().path("restored").isBoolean()&&restore.value().path("restored").asBoolean());
        byte[] initial=decoded(baseline.value().path("configuration"));require(Arrays.equals(initial,decoded(restore.value().path("configuration"))));
        var runtime=baseline.value().path("runtime");require(runtime.equals(restore.value().path("runtime"))&&runtime.path("running").asBoolean(false)&&"sha256:9ae050473c68ce13c5451839cb64257eaa17be3a4d2c9a3f87996bbe0cebb0aa".equals(text(runtime,"imageId")));
        for(var pin:SOURCES.entrySet())require(pin.getValue().equals(sha(decoded(baseline.value().path("sources").path(pin.getKey()))))&&Arrays.equals(decoded(baseline.value().path("sources").path(pin.getKey())),decoded(restore.value().path("sources").path(pin.getKey()))));
        for(var pin:COMMANDS.entrySet())require(pin.getValue().equals(sha(text(baseline.value().path("commands"),pin.getKey()).getBytes(StandardCharsets.UTF_8))));
        require("55646c31224034bbad0a73d1027cbe2e156b8b548403d591fea4bca98883aa40".equals(text(baseline.value(),"collectorSha256")));
        var normal=MetadataAlgorithmEvidence.collect(List.of("control"),context,content,target);require(normal.issues().isEmpty()&&normal.exchanges().size()==1);evidence.addAll(normal.exchanges().getFirst().evidence());String peer=normal.exchanges().getFirst().metadata().getAttribute("entityID");
        var members=receipt.path("members");require(members.isArray()&&members.size()==KeycloakMdiopRepresentationEvidenceFile.REQUIRED.size());var seen=new HashSet<String>();var preparedIds=new HashSet<String>();var nativeIds=new HashSet<String>();Instant last=baseline.entry().timestamp();byte[] controlFixture=null;
        for(var member:members){String variant=text(member,"variant");stage="native-admission-"+variant;require(KeycloakMdiopRepresentationEvidenceFile.REQUIRED.contains(variant)&&seen.add(variant));
            var prepared=entries.get(text(member,"preparedReference"));require(prepared!=null&&preparedIds.add(prepared.id())&&prepared.direction()==Direction.OUTBOUND&&"MetadataPrepared".equals(prepared.samlSummary().get("type"))&&variant.equals(prepared.samlSummary().get("variant"))&&Integer.valueOf(200).equals(prepared.status()));
            byte[] fixture=content.readDecodedSaml(prepared);String hash=sha(fixture);require(hash.equals(text(member,"fixtureSha256"))&&hash.equals(prepared.samlSummary().get("metadataSha256")));
            var fetch=entries.get(String.valueOf(prepared.samlSummary().get("fetchTranscriptId")));require(fetch!=null&&fetch.direction()==Direction.INBOUND&&"MetadataFetch".equals(fetch.samlSummary().get("type"))&&variant.equals(fetch.samlSummary().get("variant"))&&Integer.valueOf(200).equals(fetch.status())&&fetch.id().equals(prepared.correlationId())&&Objects.equals(fetch.url(),prepared.url())&&!prepared.timestamp().isBefore(fetch.timestamp()));
            KeycloakMdiopRepresentationEvidenceFile.representation(variant,SecureXml.parse(fixture).getDocumentElement(),peer,prepared.timestamp());evidence.add(new EvidenceRef("transcript",fetch.id()));evidence.add(new EvidenceRef("transcript",prepared.id()));
            var nativeOriginal=original(member.path("native"),context,targetHash,entries,evidence);require(nativeIds.add(nativeOriginal.entry().id())&&nativeOriginal.entry().timestamp().isAfter(prepared.timestamp())&&nativeOriginal.entry().timestamp().isAfter(last)&&!baseline.entry().timestamp().isAfter(prepared.timestamp())&&!restore.entry().timestamp().isBefore(nativeOriginal.entry().timestamp()));last=nativeOriginal.entry().timestamp();
            var value=nativeOriginal.value();require("admission".equals(text(value,"kind"))&&variant.equals(text(value,"variant"))&&peer.equals(text(value,"peerEntityId"))&&hash.equals(text(value,"fixtureSha256"))&&value.path("parser").path("returncode").isInt()&&value.path("parser").path("returncode").asInt()==0);
            require(Arrays.equals(fixture,decoded(value.path("parser").path("input")))&&decoded(value.path("parser").path("stderr")).length==0);var parsed=json(decoded(value.path("parser").path("stdout")));
            require(peer.equals(text(parsed,"entity_id"))&&parsed.path("metadata").isObject()&&peer.equals(text(parsed.path("metadata"),"entityid"))&&"saml20-sp-remote".equals(text(parsed.path("metadata"),"metadata-set")));
            byte[] expected=(new String(initial,StandardCharsets.UTF_8)+"\n"+text(parsed,"php")+"\n").getBytes(StandardCharsets.UTF_8);require(Arrays.equals(expected,decoded(value.path("configuration"))));var readback=json(decoded(value.path("readback")));
            require(peer.equals(text(readback,"entityId"))&&sha(expected).equals(text(readback,"remoteSha256"))&&readback.path("metadataSources").equals(json("[{\"type\":\"flatfile\"}]".getBytes(StandardCharsets.UTF_8))));
            var active=readback.path("metadata");require(active.isObject()&&peer.equals(text(active,"metadata-index")));var projected=((ObjectNode)active).deepCopy();projected.remove("metadata-index");require(projected.equals(parsed.path("metadata")));
            require(active.path("AssertionConsumerService").isArray()&&!active.path("AssertionConsumerService").isEmpty()&&active.path("SingleLogoutService").isArray());
            if(variant.equals("control"))controlFixture=fixture;
        }
        require(seen.equals(new HashSet<>(KeycloakMdiopRepresentationEvidenceFile.REQUIRED)));stage="native-admission-parser-controls";var controls=receipt.path("parserControls");require(controls.isArray()&&controls.size()==2);var labels=new HashSet<String>();
        for(var item:controls){String label=text(item,"control");require(Set.of("missing-sp-role","foreign-entity").contains(label)&&labels.add(label));var nativeControl=original(item.path("native"),context,targetHash,entries,evidence);var value=nativeControl.value();
            require("parser-control".equals(text(value,"kind"))&&label.equals(text(value,"control"))&&peer.equals(text(value,"peerEntityId"))&&sha(controlFixture).equals(text(value,"fixtureSha256"))&&value.path("returncode").isInt()&&value.path("returncode").asInt()!=0&&decoded(value.path("stdout")).length==0&&decoded(value.path("stderr")).length>0&&!nativeControl.entry().timestamp().isBefore(baseline.entry().timestamp())&&!restore.entry().timestamp().isBefore(nativeControl.entry().timestamp()));
            byte[] input=decoded(value.path("input"));if(label.equals("foreign-entity"))require(Arrays.equals(controlFixture,input)&&(peer+"/foreign").equals(text(value,"lookupEntityId")));
            else {var root=SecureXml.parse(input).getDocumentElement();require(peer.equals(text(value,"lookupEntityId"))&&peer.equals(root.getAttribute("entityID"))&&"urn:oasis:names:tc:SAML:2.0:metadata".equals(root.getNamespaceURI())&&"EntityDescriptor".equals(root.getLocalName())&&root.getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:metadata","SPSSODescriptor").getLength()==0);}
        }
        stage="native-admission-signed-baseline-control";
        var protocol=original(receipt.path("baselineProtocolControl"),context,targetHash,entries,evidence).value();require("baseline-protocol-control".equals(text(protocol,"kind"))&&"control".equals(text(protocol,"variant"))
            &&"ab017ee6cf9fb66db1037e40ed50feff0b277b1a5d43fd8ca774a3d27ce355d2".equals(sha(decoded(protocol.path("nativeMessageSource"))))
            &&"8a9e742fa99d9b7d5d173fb6b404e115014d9674674d7ae16c9f2020ce5e47fc".equals(sha(decoded(protocol.path("collector")))));
        var negative=entries.values().stream().filter(e->e.direction()==Direction.OUTBOUND&&"AuthnRequest".equals(e.samlSummary().get("type"))&&"control".equals(e.samlSummary().get("variant"))&&MetadataProbeCorrelation.signatureControl(e)).toList();require(negative.size()==1);
        var rejected=negative.getFirst();byte[] rejectedRaw=content.readDecodedSaml(rejected);var rejectedXml=SecureXml.parse(rejectedRaw).getDocumentElement();String requestId=rejectedXml.getAttribute("ID");
        var signerNodes=SecureXml.parse(controlFixture).getDocumentElement().getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#","Signature");require(signerNodes.getLength()==1);var signer=(org.w3c.dom.Element)signerNodes.item(0);
        var certificateNodes=signer.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#","X509Certificate");require(certificateNodes.getLength()==1);var certificate=(java.security.cert.X509Certificate)java.security.cert.CertificateFactory.getInstance("X.509").generateCertificate(new java.io.ByteArrayInputStream(Base64.getMimeDecoder().decode(certificateNodes.item(0).getTextContent())));
        require(new XmlSignatureVerifier().hasValidEnvelopedReferenceDigests(rejectedXml)&&!new XmlSignatureVerifier().hasValidEnvelopedSignature(rejectedXml,certificate));
        var transport=protocol.path("nativeTransport");require(requestId.equals(text(transport,"request_id"))&&sha(rejectedRaw).equals(text(transport,"request_sha256"))&&rejected.url().equals(text(transport,"request_url"))&&rejected.url().equals(text(transport,"response_url"))&&transport.path("response_url_exact_match").asBoolean(false)&&transport.path("redirect_hops").asInt(-1)==0&&transport.path("response_status").asInt()==500&&"signature-value-invalid".equals(text(transport,"native_signature_rejection"))&&!transport.path("saml_response_form_present").asBoolean(true));
        require(Arrays.equals(rejectedRaw,decoded(protocol.path("originals").path("request.xml"))));byte[] submitted=decoded(protocol.path("originals").path("request.body"));require(sha(submitted).equals(text(transport,"request_body_sha256")));var fields=new HashMap<String,String>();
        for(String field:new String(submitted,StandardCharsets.UTF_8).split("&",-1)){String[] pair=field.split("=",2);require(pair.length==2&&fields.put(java.net.URLDecoder.decode(pair[0],StandardCharsets.UTF_8),java.net.URLDecoder.decode(pair[1],StandardCharsets.UTF_8))==null);}require(fields.keySet().contains("SAMLRequest")&&Set.of("SAMLRequest","RelayState").containsAll(fields.keySet())&&Arrays.equals(rejectedRaw,Base64.getDecoder().decode(fields.get("SAMLRequest"))));
        byte[] errorBytes=decoded(protocol.path("originals").path("html"));require(sha(errorBytes).equals(text(transport,"response_body_sha256"))&&sha(errorBytes).equals(text(transport,"persisted_body_sha256"))&&!transport.path("body_sanitized").asBoolean(true));String error=new String(errorBytes,StandardCharsets.UTF_8);
        String marker="<tt>SimpleSAML\\Error\\Error: ";int begin=error.indexOf(marker),end=begin<0?-1:error.indexOf("</tt>",begin);require(begin>=0&&end>begin&&error.contains("SimpleSAML\\Module\\saml\\Message::checkSign"));
        var nativeError=json(error.substring(begin+marker.length(),end).replace("&quot;","\"").replace("&amp;","&").replace("&lt;","<").replace("&gt;",">").getBytes(StandardCharsets.UTF_8));require("NOTVALIDCERTSIGNATURE".equals(text(nativeError,"errorCode"))&&peer.equals(text(nativeError,"%ISSUER%"))&&peer.equals(text(nativeError,"%ENTITYID%"))&&"SAML2\\AuthnRequest".equals(text(nativeError,"%ELEMENT%")));
        var positive=entries.get(normal.exchanges().getFirst().evidence().get(2).reference());Instant started=Instant.parse(text(transport,"started_at")),observed=Instant.parse(text(transport,"observed_at"));require(!started.isBefore(rejected.timestamp())&&!observed.isBefore(started)&&observed.isBefore(positive.timestamp())&&positive.timestamp().isBefore(restore.entry().timestamp()));
        for(var entry:entries.values())if(entry.direction()==Direction.INBOUND&&"Response".equals(entry.samlSummary().get("type")))require(!requestId.equals(SecureXml.parse(content.readDecodedSaml(entry)).getDocumentElement().getAttribute("InResponseTo")));evidence.add(new EvidenceRef("transcript",rejected.id()));
        return new CaseOutcome(Outcome.SATISFIED,null,"metadata.mdiop.native-representation-admission-observed","metadata.mdiop.native-representation-admission-observed",evidence.stream().distinct().toList(),Map.of("native_admitted_variants",KeycloakMdiopRepresentationEvidenceFile.REQUIRED,"runtime_key_interpretation_proven",false,"restoration_verified",true,"product","simplesamlphp","receipt_sha256",sha(Files.readAllBytes(path(context.runId())))));
    }catch(Exception incomplete){return new CaseOutcome(Outcome.NOT_VERIFIED,"native_mdiop_admission_incomplete","metadata.mdiop.native-representation-admission-incomplete","metadata.mdiop.native-representation-admission-incomplete",List.of(),Map.of("runtime_key_interpretation_proven",false,"evidence_stage",stage));}}
}
