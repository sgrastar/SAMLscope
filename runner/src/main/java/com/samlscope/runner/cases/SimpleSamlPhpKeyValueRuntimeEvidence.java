package com.samlscope.runner.cases;

import static com.samlscope.runner.cases.MetadataAlgorithmEvidence.children;
import com.fasterxml.jackson.databind.JsonNode;
import com.samlscope.core.caseexec.CaseContext;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.transcript.*;
import com.samlscope.saml.crypto.XmlSignatureVerifier;
import com.samlscope.saml.normal.SecureXml;
import com.samlscope.store.JsonCodec;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.*;
import java.time.Instant;
import java.util.*;
import org.w3c.dom.Element;

/**
 * Counterexample only: accepted and activated native metadata loses a valid KeyValue.
 * Native parsing/application failure and a generic HTTP error never establish a violation.
 * The actual POST transport pair and installed native error distinguish missing-key
 * resolution from rejection of a cryptographically invalid signature.
 */
final class SimpleSamlPhpKeyValueRuntimeEvidence {
    static final String SCHEMA="samlscope-simplesamlphp-keyvalue-runtime-v1";
    static final Set<String> CASES=Set.of(MetadataKeySelectionComparison.REPRESENTATION,
        MetadataKeySelectionComparison.HINT_FREE,MetadataKeySelectionComparison.NO_ADDITIONAL_CRITERIA);
    private static final String TARGET="http://localhost:18380/idp",MD="urn:oasis:names:tc:SAML:2.0:metadata",
        DS="http://www.w3.org/2000/09/xmldsig#",P="urn:oasis:names:tc:SAML:2.0:protocol",S="urn:oasis:names:tc:SAML:2.0:assertion";
    private static final Map<String,String> PINS=Map.of(
        "native-parser-command.php","5008495fba0e65487a4849cf46f592c577215f96d5b4f3fd87321ebc6930edf9",
        "native-readback-command.php","f84064049b9bc6ef0339b9b1874e86b6e36e89fe8770a502d5735200b15ed756",
        "native-parser.php","8620bb26fd41d2be29d2611883839a4cfde0b6c8458c274e2d40a002678fd93d",
        "native-message.php","ab017ee6cf9fb66db1037e40ed50feff0b277b1a5d43fd8ca774a3d27ce355d2",
        "native-configuration.php","53837359cd60433082d3968843605a864bab97f23be482447bcfef37e7f6946e",
        "native-idp-saml2.php","ae55fc922431d29ca6e87654ae2071500a4c3d7185ed80a6fcc5b26eed12495d",
        "native-web-browser-sso.php","47ddeecace975b77645aa91a4b4551429dc60d02dc1b9baa6c633c30bf1e75f4",
        "native-collector.py","80e8ea33fc0c12f70197fb195d8bcd71446b47466b2ddcd6bce7871307340580",
        "native-signature-client.py","2df41a96b2194577186351eb9a6eddf6588138c3ae16279163fd9c54c6f95485",
        "native-reference-flow.py","a3d1fda57bee9aaad2daf974727510f0abf2df20419f5f27be2163d4fc900360");
    private final Path directory;private final TranscriptContentReader content;
    SimpleSamlPhpKeyValueRuntimeEvidence(Path directory,TranscriptContentReader content){this.directory=directory.toAbsolutePath().normalize();this.content=content;}
    boolean exists(String run){return run!=null&&run.matches("run_[0-9A-HJKMNP-TV-Z]{26}")&&Files.exists(directory.resolve(run),LinkOption.NOFOLLOW_LINKS);}
    Optional<CaseOutcome> evaluate(String caseId,CaseContext context,byte[] targetRaw){
        if(!CASES.contains(caseId)||!exists(context.runId()))return Optional.empty();
        String stage="native-originals-unproven";
        try{
            require(context.transcriptComplete()&&Files.isDirectory(directory,LinkOption.NOFOLLOW_LINKS));
            Path folder=directory.resolve(context.runId());require(Files.isDirectory(folder,LinkOption.NOFOLLOW_LINKS));byte[] manifestRaw=original(folder,"manifest.json");var manifest=json(manifestRaw);var files=manifest.path("files");
            require(SCHEMA.equals(text(manifest,"schema"))&&context.runId().equals(text(manifest,"runId"))
                &&"metadata-fixture-refresh".equals(text(manifest,"campaignId"))&&TARGET.equals(text(manifest,"targetEntityId"))
                &&hash(targetRaw).equals(text(manifest,"targetMetadataSha256"))&&files.isObject());
            var target=SecureXml.parse(targetRaw).getDocumentElement();require(TARGET.equals(target.getAttribute("entityID")));
            for(var pin:PINS.entrySet())require(pin.getValue().equals(hash(checked(folder,files,pin.getKey()))));
            var created=json(checked(folder,files,"created.json")).path("run");require(context.runId().equals(text(created,"id")));
            String entity="http://localhost:18080/p/"+text(created,"planId");require(entity.equals(text(manifest,"spEntityId")));
            var identity=json(checked(folder,files,"native-inspect-before.json"));require(identity.equals(json(checked(folder,files,"native-inspect-after.json")))
                &&identity.path("running").asBoolean(false)&&"sha256:9ae050473c68ce13c5451839cb64257eaa17be3a4d2c9a3f87996bbe0cebb0aa".equals(text(identity,"imageId")));
            var restore=json(checked(folder,files,"restoration.json"));byte[] baseline=checked(folder,files,"original-sp-config.php");
            require(restore.path("restored").asBoolean(false)&&Arrays.equals(baseline,checked(folder,files,"final-sp-config.php"))
                &&hash(baseline).equals(text(restore,"original_sha256"))&&hash(baseline).equals(text(restore,"final_sha256"))
                &&!new String(baseline,StandardCharsets.UTF_8).contains(entity));
            byte[] receiptRaw=checked(folder,files,context.runId()+".json");var receipt=json(receiptRaw);
            var entries=new HashMap<String,TranscriptEntry>();for(var entry:context.transcript().list(context.runId()))require(context.runId().equals(entry.runId())&&entries.put(entry.id(),entry)==null);
            var rows=new HashMap<String,JsonNode>();for(var row:receipt.path("conditions"))require(rows.put(text(row,"variant"),row)==null);
            require(rows.keySet().equals(Set.of("entity-root","keyvalue-only",MetadataKeySelectionComparison.SAME_KEY,MetadataKeySelectionComparison.OTHER_KEY)));
            stage="x509-controls-unproven";
            var common=new MetadataKeySelectionEvidenceFile(folder).read(context,targetRaw,content,MetadataKeySelectionComparison.required(MetadataKeySelectionComparison.PUBLIC_KEY));
            var compared=MetadataKeySelectionComparison.evaluate(MetadataKeySelectionComparison.PUBLIC_KEY,common,List.of());require(compared.outcome()==Outcome.SATISFIED);
            stage="accepted-native-configuration-unproven";
            var operations=json(checked(folder,files,"operations.json"));require(operations.isArray()&&operations.size()==5);
            var operated=new HashSet<String>();for(var operation:operations)require(operated.add(text(operation,"variant"))&&operation.path("nativeParserReturncode").asInt(-1)==0);
            require(operated.containsAll(rows.keySet())&&operated.contains("control"));
            var policies=new HashMap<String,JsonNode>();
            for(var variant:rows.keySet()){
                var row=rows.get(variant);var prepared=entries.get(text(row,"metadataReference"));require(prepared!=null
                    &&"MetadataPrepared".equals(prepared.samlSummary().get("type"))&&variant.equals(prepared.samlSummary().get("variant")));
                byte[] fixture=checked(folder,files,variant+".fixture.xml");require(Arrays.equals(fixture,content.readDecodedSaml(prepared))
                    &&hash(fixture).equals(prepared.samlSummary().get("metadataSha256")));
                byte[] parserRaw=checked(folder,files,variant+".parser.stdout");
                require(Arrays.equals(parserRaw,Base64.getDecoder().decode(text(row.path("nativeImport"),"parserOutputBase64")))&&hash(parserRaw).equals(text(row.path("nativeImport"),"parserOutputSha256")));
                var parsed=json(parserRaw);require(entity.equals(text(parsed,"entity_id"))&&parsed.path("validate_authnrequest").asBoolean(false)
                    &&checked(folder,files,variant+".parser.stderr").length==0);
                byte[] expected=(new String(baseline,StandardCharsets.UTF_8)+"\n"+text(parsed,"php")+"\n").getBytes(StandardCharsets.UTF_8);
                JsonNode nativeReadback=null;
                for(var phase:List.of("before","after")){
                    require(Arrays.equals(expected,checked(folder,files,variant+"."+phase+".configuration.php")));
                    var actual=json(checked(folder,files,variant+"."+phase+".native.json"));require(entity.equals(text(actual,"entityId"))&&hash(expected).equals(text(actual,"remoteSha256"))
                        &&actual.path("metadataSources").size()==1&&"flatfile".equals(text(actual.path("metadataSources").get(0),"type")));
                    if(nativeReadback==null)nativeReadback=actual;else require(nativeReadback.equals(actual));
                }
                var metadata=nativeReadback.path("metadata");require(metadata.isObject()&&entity.equals(text(metadata,"entityid"))
                    &&metadata.path("validate.authnrequest").asBoolean(false)&&metadata.path("saml20.sign.assertion").asBoolean(false));
                requireNativeEndpoints(metadata,SecureXml.parse(fixture).getDocumentElement());
                if("keyvalue-only".equals(variant))require(metadata.path("keys").isMissingNode());
                else {
                    require(metadata.path("keys").isArray()&&metadata.path("keys").size()==2);
                    var nativeKeys=metadata.path("keys");var fixtureRole=one(SecureXml.parse(fixture).getDocumentElement(),MD,"SPSSODescriptor");
                    var descriptors=children(fixtureRole,MD,"KeyDescriptor");require(descriptors.size()==2);
                    for(int i=0;i<2;i++){var actualKey=nativeKeys.get(i);var fixtureKey=descriptors.get(i);require("X509Certificate".equals(text(actualKey,"type"))
                        &&actualKey.path("signing").asBoolean(false)=="signing".equals(fixtureKey.getAttribute("use"))
                        &&actualKey.path("encryption").asBoolean(false)=="encryption".equals(fixtureKey.getAttribute("use")));
                        var advertised=certificate(one(one(one(fixtureKey,DS,"KeyInfo"),DS,"X509Data"),DS,"X509Certificate").getTextContent());
                        require(Arrays.equals(advertised.getEncoded(),certificate(text(actualKey,"X509Certificate")).getEncoded()));}
                }
                var normalized=(com.fasterxml.jackson.databind.node.ObjectNode)metadata.deepCopy();normalized.remove("keys");
                for(var endpointType:List.of("AssertionConsumerService","SingleLogoutService"))for(var endpoint:normalized.path(endpointType)){
                    var item=(com.fasterxml.jackson.databind.node.ObjectNode)endpoint;String value=text(item,"Location");require(value.contains("mdv="+variant+"&run="+context.runId()));
                    item.put("Location",value.replace("mdv="+variant+"&","mdv=control&"));
                }
                policies.put(variant,normalized);
            }
            require(new HashSet<>(policies.values()).size()==1);
            stage="keyvalue-fixture-unproven";
            var keyRow=rows.get("keyvalue-only");var prepared=entries.get(text(keyRow,"metadataReference"));
            var fetch=entries.get(String.valueOf(prepared.samlSummary().get("fetchTranscriptId")));require(fetch!=null&&fetch.direction()==Direction.INBOUND
                &&"MetadataFetch".equals(fetch.samlSummary().get("type"))&&"keyvalue-only".equals(fetch.samlSummary().get("variant"))&&!fetch.timestamp().isAfter(prepared.timestamp()));
            var sp=SecureXml.parse(content.readDecodedSaml(prepared)).getDocumentElement();require(MD.equals(sp.getNamespaceURI())&&"EntityDescriptor".equals(sp.getLocalName())&&entity.equals(sp.getAttribute("entityID")));
            var role=one(sp,MD,"SPSSODescriptor");require(children(role,MD,"KeyDescriptor").size()==1);var descriptor=one(role,MD,"KeyDescriptor");require(descriptor.getAttribute("use").isEmpty());
            var info=one(descriptor,DS,"KeyInfo");require(children(info,DS,"X509Data").isEmpty()&&children(info,DS,"KeyName").isEmpty());
            var rsa=one(one(info,DS,"KeyValue"),DS,"RSAKeyValue");var key=KeyFactory.getInstance("RSA").generatePublic(new java.security.spec.RSAPublicKeySpec(
                new java.math.BigInteger(1,Base64.getMimeDecoder().decode(one(rsa,DS,"Modulus").getTextContent())),new java.math.BigInteger(1,Base64.getMimeDecoder().decode(one(rsa,DS,"Exponent").getTextContent()))));
            var cert=certificate(one(one(one(one(sp,DS,"Signature"),DS,"KeyInfo"),DS,"X509Data"),DS,"X509Certificate").getTextContent());
            require(Arrays.equals(key.getEncoded(),cert.getPublicKey().getEncoded())&&new XmlSignatureVerifier().hasValidEnvelopedSignature(sp,cert)
                &&common.stream().allMatch(sample->sample.advertisedKeyHashes().equals(List.of(hashUnchecked(key.getEncoded())))));
            stage="direct-native-missing-key-unproven";
            var refs=new ArrayList<EvidenceRef>(compared.evidence());refs.add(new EvidenceRef("transcript",prepared.id()));refs.add(new EvidenceRef("transcript",fetch.id()));
            var http=json(checked(folder,files,"native-http-observations.json"));require(context.runId().equals(text(http,"runId"))&&!http.path("productVerdictAssigned").asBoolean(true));
            var used=new HashSet<String>();
            for(var slot:List.of("positive","negative")){
                var input=keyRow.path(slot);var request=entries.get(text(input,"requestReference"));require(request!=null&&used.add(request.id())&&request.direction()==Direction.OUTBOUND
                    &&"AuthnRequest".equals(request.samlSummary().get("type"))&&"keyvalue-only".equals(request.samlSummary().get("variant"))&&"POST".equals(request.method()));
                byte[] requestRaw=content.readDecodedSaml(request);var xml=SecureXml.parse(requestRaw).getDocumentElement();String id=xml.getAttribute("ID");require(!id.isBlank()&&id.equals(request.samlSummary().get("id"))
                    &&P.equals(xml.getNamespaceURI())&&"AuthnRequest".equals(xml.getLocalName())&&entity.equals(one(xml,S,"Issuer").getTextContent())&&request.url().equals(xml.getAttribute("Destination")));
                require(children(target,MD,"IDPSSODescriptor").stream().flatMap(r->children(r,MD,"SingleSignOnService").stream()).anyMatch(e->request.url().equals(e.getAttribute("Location"))));
                require(children(role,MD,"AssertionConsumerService").stream().anyMatch(e->xml.getAttribute("AssertionConsumerServiceURL").equals(e.getAttribute("Location"))));
                require(prepared.timestamp().isBefore(request.timestamp())&&MetadataProbeCorrelation.signatureControl(request)=="negative".equals(slot)
                    &&new XmlSignatureVerifier().hasValidEnvelopedReferenceDigests(xml)&&new XmlSignatureVerifier().hasValidEnvelopedSignature(xml,cert)=="positive".equals(slot));
                require(Arrays.equals(requestRaw,checked(folder,files,id+".request.xml")));byte[] body=checked(folder,files,id+".request.body");
                var fields=form(body);require(fields.containsKey("SAMLRequest")&&Set.of("SAMLRequest","RelayState").containsAll(fields.keySet())
                    &&Arrays.equals(requestRaw,Base64.getDecoder().decode(fields.get("SAMLRequest"))));
                var direct=input.path("nativeHttp");require(id.equals(text(direct,"request_id"))&&hash(requestRaw).equals(text(direct,"request_sha256"))
                    &&hash(body).equals(text(direct,"request_body_sha256"))&&request.url().equals(text(direct,"request_url"))&&request.url().equals(text(direct,"response_url"))
                    &&direct.path("response_url_exact_match").asBoolean(false)&&direct.path("redirect_hops").asInt(-1)==0&&direct.path("response_status").asInt()==500
                    &&!direct.path("saml_response_form_present").asBoolean(true)&&direct.path("native_signature_rejection").isNull());
                var matching=new ArrayList<JsonNode>();http.path("records").forEach(v->{if(id.equals(text(v,"request_id")))matching.add(v);});require(matching.size()==1&&matching.getFirst().equals(direct));
                byte[] error=checked(folder,files,id+".html");require(hash(error).equals(text(direct,"response_body_sha256")));String page=new String(error,StandardCharsets.UTF_8).replace("&#039;","'");
                require(page.contains("Caused by: SimpleSAML\\Error\\Exception: Missing certificate in metadata for '"+entity+"'")
                    &&page.contains("SimpleSAML\\Module\\saml\\Message::checkSign")&&page.contains("SimpleSAML\\Module\\saml\\IdP\\SAML2::receiveAuthnRequest"));
                var start=Instant.parse(text(direct,"started_at"));var end=Instant.parse(text(direct,"observed_at"));
                var before=Instant.parse(text(json(checked(folder,files,"keyvalue-only.before.observed.json")),"recordedAt"));
                var after=Instant.parse(text(json(checked(folder,files,"keyvalue-only.after.observed.json")),"recordedAt"));
                require(!start.isBefore(request.timestamp())&&!start.isBefore(before)&&!end.isBefore(start)&&!end.isAfter(after));
                for(var entry:entries.values())if(entry.direction()==Direction.INBOUND&&"Response".equals(entry.samlSummary().get("type")))
                    require(!id.equals(SecureXml.parse(content.readDecodedSaml(entry)).getDocumentElement().getAttribute("InResponseTo")));
                refs.add(new EvidenceRef("transcript",request.id()));
            }
            require(Arrays.equals(manifestRaw,original(folder,"manifest.json"))&&Arrays.equals(receiptRaw,original(folder,context.runId()+".json")));
            refs.add(new EvidenceRef("native-keyvalue-runtime",context.runId()+"/manifest.json"));
            return Optional.of(new CaseOutcome(Outcome.VIOLATED,null,"metadata.keys.keyvalue-runtime-unavailable","metadata.keys.keyvalue-runtime-unavailable",List.copyOf(refs),
                Map.of("adapter","simplesamlphp-native-keyvalue-runtime","accepted_native_metadata",true,"signature_policy",true,"keyvalue_public_key_verified",true,
                    "x509_public_key_controls",3,"direct_native_missing_certificate",true,"restored",true,"violations",List.of("keyvalue-only:accepted-key-not-consumed"))));
        }catch(Exception incomplete){return Optional.of(new CaseOutcome(Outcome.NOT_VERIFIED,"native_keyvalue_runtime_unproven","metadata.keys.evidence-incomplete","metadata.keys.evidence-incomplete",List.of(),Map.of("evidence_issue",stage)));}
    }
    private static void requireNativeEndpoints(JsonNode value,Element fixture){var role=one(fixture,MD,"SPSSODescriptor");for(var type:List.of("AssertionConsumerService","SingleLogoutService")){
        var expected=children(role,MD,type);require(value.path(type).isArray()&&value.path(type).size()==expected.size());for(int i=0;i<expected.size();i++){
            var row=value.path(type).get(i);var item=expected.get(i);require(item.getAttribute("Binding").equals(text(row,"Binding"))&&item.getAttribute("Location").equals(text(row,"Location")));
            if(item.hasAttribute("index"))require(Integer.parseInt(item.getAttribute("index"))==row.path("index").asInt(-1));}}
    }
    private static Map<String,String> form(byte[] raw){var values=new HashMap<String,String>();for(var field:new String(raw,StandardCharsets.UTF_8).split("&",-1)){
        var pair=field.split("=",2);require(pair.length==2);String name=java.net.URLDecoder.decode(pair[0],StandardCharsets.UTF_8);require(values.put(name,java.net.URLDecoder.decode(pair[1],StandardCharsets.UTF_8))==null);}return values;}
    private static Element one(Element root,String ns,String name){var values=children(root,ns,name);require(values.size()==1);return values.getFirst();}
    private static X509Certificate certificate(String value)throws Exception{return (X509Certificate)CertificateFactory.getInstance("X.509").generateCertificate(new java.io.ByteArrayInputStream(Base64.getMimeDecoder().decode(value)));}
    private static byte[] checked(Path folder,JsonNode files,String name)throws Exception{var bytes=original(folder,name);require(hash(bytes).equals(files.path(name).asText()));return bytes;}
    private static byte[] original(Path folder,String name)throws Exception{require(name.matches("[A-Za-z0-9._-]+")&&!Set.of(".","..").contains(name));Path file=folder.resolve(name);require(Files.isRegularFile(file,LinkOption.NOFOLLOW_LINKS)&&Files.size(file)<=4194304);return Files.readAllBytes(file);}
    private static JsonNode json(byte[] raw)throws Exception{return new JsonCodec().mapper().readTree(raw);}
    private static String text(JsonNode node,String field){var value=node.path(field);require(value.isTextual()&&!value.asText().isBlank());return value.asText();}
    private static String hash(byte[] raw)throws Exception{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(raw));}
    private static String hashUnchecked(byte[] raw){try{return hash(raw);}catch(Exception e){throw new IllegalArgumentException(e);}}
    private static void require(boolean value){if(!value)throw new IllegalArgumentException("Native accepted KeyValue runtime evidence unproven");}
}
