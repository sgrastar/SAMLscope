package com.samlscope.runner.cases;

import com.fasterxml.jackson.databind.JsonNode;
import com.samlscope.core.caseexec.CaseContext;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.transcript.*;
import com.samlscope.saml.binding.RedirectSignatureVerifier;
import com.samlscope.saml.crypto.VerifiedSignatureAlgorithms;
import com.samlscope.saml.normal.SecureXml;
import com.samlscope.store.JsonCodec;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.*;
import java.util.function.Function;
import org.w3c.dom.Element;

/**
 * Native reference accounts and generator originals resolve opaque identifiers to principals.
 * The target's actual signed assertions determine the result; signed diagnostic controls only
 * prove the semantic oracle detects different principals and accepts different Formats.
 * Credential-bearing authentication configuration and native salts are never stored here.
 */
final class SimpleSamlPhpSubjectPrincipalEvidence {
    static final String SCHEMA="samlscope-simplesamlphp-subject-principal-v1";
    static final String CASE=SamlSubjectPrincipalTranscriptTestCase.CASE_ID;
    private static final String TARGET="http://localhost:18380/idp",S=SimpleSamlPhpPrincipalIdentityResolver.S;
    private static final String P="urn:oasis:names:tc:SAML:2.0:protocol",MD="urn:oasis:names:tc:SAML:2.0:metadata",DS="http://www.w3.org/2000/09/xmldsig#";
    private static final Map<String,String> PINS=Map.of(
        "native-persistent-filter.php","f0e71a95f229ba3c361f1314f4d5a8c2692f363e456ac099738f28d0d8837e43",
        "native-base-generator.php","85ac4708eb8324f9e700fa8e8c09f6c33fa40eaab16fc35bc3e31f46423b0fdd",
        "native-userpass.php","8465e71fabec88578369eaf780dfe86c6ab3f0f2cdf4b24eb52bf134918f9b48",
        "native-xml-signer.php","5845e28158c7641d5ce1e6b9205e8005b6d9c090e1888ea46416abb8fdf0018d",
        "native-resolver-command.php","4490955f37c66a41657b209282088e2efdd9f3ad3292a0edd9356221c35784b2",
        "native-producer-command.php","d780ee4b24bb522ec98c73a1444443190e34ac9f20c0bed6be3dab06d4b81c6c");
    private final Path directory;
    private final TranscriptContentReader content;
    private final Function<String,byte[]> metadata;
    SimpleSamlPhpSubjectPrincipalEvidence(Path directory,TranscriptContentReader content,Function<String,byte[]> metadata) {
        this.directory=directory.toAbsolutePath().normalize();this.content=Objects.requireNonNull(content);this.metadata=Objects.requireNonNull(metadata);
    }
    CaseOutcome evaluate(CaseContext context) {
        String stage="receipt-unavailable";
        try {
            require(context.transcriptComplete()&&context.runId().matches("run_[0-9A-HJKMNP-TV-Z]{26}"));
            Path folder=directory.resolve(context.runId());require(Files.isDirectory(folder,LinkOption.NOFOLLOW_LINKS));
            byte[] manifestRaw=original(folder,"manifest.json");var manifest=json(manifestRaw);
            require(SCHEMA.equals(text(manifest,"schema"))&&context.runId().equals(text(manifest,"runId")));
            var files=manifest.path("files");require(files.isObject());
            for(var pin:PINS.entrySet())require(pin.getValue().equals(hash(checked(folder,files,pin.getKey()))));
            byte[] targetRaw=metadata.apply(context.runId());require(hash(targetRaw).equals(text(manifest,"targetMetadataSha256")));
            var target=SecureXml.parse(targetRaw).getDocumentElement();require(TARGET.equals(target.getAttribute("entityID")));
            var signing=MetadataAlgorithmEvidence.signingKeys(target);require(!signing.isEmpty());
            var created=json(checked(folder,files,"created.json")).path("run");require(context.runId().equals(text(created,"id")));
            String entity="http://localhost:18080/p/"+text(created,"planId");
            byte[] spRaw=checked(folder,files,"fixture.xml");var sp=SecureXml.parse(spRaw).getDocumentElement();
            require(MD.equals(sp.getNamespaceURI())&&"EntityDescriptor".equals(sp.getLocalName())&&entity.equals(sp.getAttribute("entityID")));
            var spKeys=MetadataAlgorithmEvidence.signingKeys(sp);require(!spKeys.isEmpty());
            stage="native-configuration-unproven";
            var before=json(checked(folder,files,"before-native-resolution.json"));var after=json(checked(folder,files,"after-native-resolution.json"));
            require(before.equals(after)&&TARGET.equals(text(before,"targetEntityId"))&&entity.equals(text(before,"spEntityId")));
            var resolver=new SimpleSamlPhpPrincipalIdentityResolver(context.runId(),TARGET,entity,before.path("nativeAuthenticatedPrincipals"));
            configuration(folder,files,before,resolver,entity);
            var restoration=json(checked(folder,files,"restoration.json"));
            for(var label:List.of("hosted","remote","salt","authsource")) {
                var row=restoration.path(label);var baseline=json(checked(folder,files,label+"-original-hash.json"));
                require(row.path("restored").asBoolean(false)&&row.path("bytesEqual").asBoolean(false)
                    &&text(row,"original_sha256").equals(text(baseline,"sha256"))&&text(row,"final_sha256").equals(text(baseline,"sha256"))
                    &&text(row,"nativeFinalSha256").equals(text(baseline,"sha256")));
                if(!"authsource".equals(label))require(Arrays.equals(checked(folder,files,label+"-original.php"),checked(folder,files,label+"-final.php")));
            }
            require("ea23df120a13b50435b97c71e1aa5c5194fe619e3d2eeeb24ce9a09cb44c99ad".equals(text(json(checked(folder,files,"authsource-original-hash.json")),"sha256")));
            var counts=json(checked(folder,files,"operation-counts.json"));require(counts.path("restored").asBoolean(false)
                &&counts.path("productConfigurationWriteAttempts").asInt()==8&&counts.path("configurationApplyWrites").asInt()==4&&counts.path("restorationWrites").asInt()==4
                &&counts.path("nativeParserInvocations").asInt()==1&&counts.path("normalFlowsAttempted").asInt()==4&&counts.path("nativeSignedProducerInvocations").asInt()==4
                &&counts.path("runCreations").asInt()==1&&counts.path("productRestarts").asInt(-1)==0&&counts.path("humanOperations").asInt(-1)==0);
            stage="signed-native-exchanges-unproven";
            var entries=new HashMap<String,TranscriptEntry>();
            for(var entry:context.transcript().list(context.runId()))require(context.runId().equals(entry.runId())&&entries.put(entry.id(),entry)==null);
            require(entries.size()==8);var flows=json(checked(folder,files,"flows.json"));require(flows.isArray()&&flows.size()==4);
            var references=new LinkedHashSet<EvidenceRef>();var messages=new ArrayList<TargetTranscriptMessages.Message>();
            var requestIds=new HashSet<String>();var seen=new HashSet<String>();var perPrincipal=new HashMap<String,Integer>();
            Instant first=null,last=null;byte[] controlBase=null;String controlRequest=null,controlRecipient=null;
            for(var flow:flows) {
                require("recorded".equals(text(flow,"receipt")));String expected=text(flow,"principal");require(resolver.principals().contains(expected));
                var refs=flow.path("transcriptIds");require(refs.isArray()&&refs.size()==2);
                TranscriptEntry request=null,response=null;
                for(var ref:refs) {
                    String id=ref.asText();require(seen.add(id));var entry=entries.get(id);require(entry!=null);
                    if(entry.direction()==Direction.OUTBOUND)request=entry;else response=entry;
                }
                require(request!=null&&response!=null&&"GET".equals(request.method())&&"POST".equals(response.method()));
                byte[] requestRaw=content.readDecodedSaml(request);var xml=SecureXml.parse(requestRaw).getDocumentElement();
                String id=xml.getAttribute("ID");require(P.equals(xml.getNamespaceURI())&&"AuthnRequest".equals(xml.getLocalName())
                    &&requestIds.add(id)&&id.equals(request.correlationId())&&entity.equals(issuer(xml))&&children(xml,S,"Subject").isEmpty());
                String rawQuery=request.rawQuery();
                require(spKeys.stream().anyMatch(k->new RedirectSignatureVerifier().isValidForMessage(rawQuery,k,requestRaw)));
                String recipient=xml.getAttribute("AssertionConsumerServiceURL");require(!recipient.isBlank()&&recipient.equals(response.url())
                    &&Boolean.TRUE.equals(response.samlSummary().get("normalFlowAccepted"))&&!request.timestamp().isAfter(response.timestamp()));
                require(entries.values().stream().filter(e->e.direction()==Direction.INBOUND&&id.equals(e.samlSummary().get("inResponseTo"))).count()==1);
                byte[] responseRaw=content.readDecodedSaml(response);var responseXml=SecureXml.parse(responseRaw).getDocumentElement();
                var assertion=VerifiedResponseAssertion.read(responseXml,TARGET,signing,sp,Optional.empty(),id,recipient);
                validateAttributes(assertion,resolver.attributes(expected));
                var subject=children(assertion,S,"Subject");require(subject.size()==1&&children(subject.getFirst(),S,"NameID").size()==1);
                var direct=children(subject.getFirst(),S,"NameID").getFirst();
                var resolved=resolver.resolve(context.runId(),identifier(direct));require(resolved.status()==PrincipalIdentityResolver.Status.RESOLVED&&expected.equals(resolved.principalId()));
                perPrincipal.merge(expected,1,Integer::sum);messages.add(new TargetTranscriptMessages.Message("transcript:"+response.id(),responseRaw));
                references.add(new EvidenceRef("transcript","transcript:"+request.id()));references.add(new EvidenceRef("transcript","transcript:"+response.id()));
                first=first==null||request.timestamp().isBefore(first)?request.timestamp():first;last=last==null||response.timestamp().isAfter(last)?response.timestamp():last;
                if(controlBase==null){controlBase=responseRaw;controlRequest=id;controlRecipient=recipient;}
            }
            require(seen.equals(entries.keySet())&&perPrincipal.keySet().equals(resolver.principals())&&perPrincipal.values().stream().allMatch(v->v==2));
            require(!Instant.parse(text(json(checked(folder,files,"before-observed.json")),"recordedAt")).isAfter(first)
                &&!Instant.parse(text(json(checked(folder,files,"after-observed.json")),"recordedAt")).isBefore(last));
            stage="native-semantic-controls-unproven";
            var producer=json(checked(folder,files,"producer.json"));require(hash(controlBase).equals(text(producer,"baseResponseSha256"))
                &&PINS.get("native-producer-command.php").equals(text(producer,"commandSha256"))
                &&!producer.path("nativePrivateKeyExported").asBoolean(true)&&!producer.path("controlsAdopted").asBoolean(true));
            var semantic=new SamlSubjectPrincipalCase(resolver);
            for(var kind:List.of("same-principal-different-format","multiple-same-principal-confirmations","different-confirmation-principal","different-attribute-principal")) {
                byte[] control=checked(folder,files,kind+".xml");var response=SecureXml.parse(control).getDocumentElement();
                verifyControl(response,sp,TARGET,signing,controlRequest,controlRecipient);
                var result=semantic.evaluate(context.runId(),List.of(new TargetTranscriptMessages.Message("native-control:"+kind,control)));
                require(result.outcome()==(kind.startsWith("different-")?Outcome.VIOLATED:Outcome.SATISFIED));
            }
            var result=semantic.evaluate(context.runId(),messages);require(result.outcome()==Outcome.SATISFIED);
            require(Arrays.equals(manifestRaw,original(folder,"manifest.json")));
            references.add(new EvidenceRef("native-principal-receipt",context.runId()+"/manifest.json"));
            return new CaseOutcome(Outcome.SATISFIED,null,"saml.subject-principal.native-resolved","case.saml.subject-principal.native-resolved",
                List.copyOf(references),Map.of("adapter","simplesamlphp-native-subject-principal","principals",2,"observed_subjects",4,"semantic_controls",4,
                    "identifier_resolution","native-authentication-source-and-persistent-generator","restored",true,"credentials_persisted",false));
        }catch(Exception unproven){return new CaseOutcome(Outcome.NOT_VERIFIED,"native_principal_originals_unproven",
            "saml.subject-principal.native-unproven","case.saml.subject-principal.native-unproven",List.of(),Map.of("evidence_issue",stage));}
    }
    private static void configuration(Path folder,JsonNode files,JsonNode value,SimpleSamlPhpPrincipalIdentityResolver resolver,String entity)throws Exception {
        var auth=value.path("authenticationSource");require("example-userpass".equals(text(auth,"id"))&&"exampleauth:UserPass".equals(text(auth,"class"))&&auth.path("authproc").isNull());
        var users=auth.path("users");require(users.isArray()&&users.size()==2);var seen=new HashSet<String>();
        for(var user:users){String principal=text(user,"principal");require(user.size()==2&&seen.add(principal)&&user.path("attributes").equals(resolver.attributes(principal)));}
        require(seen.equals(resolver.principals()));
        var filter=value.path("hostedAuthproc");require(filter.isObject()&&filter.size()==1&&filter.path("20").size()==2
            &&"saml:PersistentNameID".equals(text(filter.path("20"),"class"))&&"uid".equals(text(filter.path("20"),"identifyingAttribute")));
        require(value.path("hostedNameIDFormat").size()==1&&SimpleSamlPhpPrincipalIdentityResolver.PERSISTENT.equals(value.path("hostedNameIDFormat").get(0).asText()));
        var global=value.path("globalAuthproc");require(global.isObject()&&global.size()==3&&"core:LanguageAdaptor".equals(global.path("30").asText())
            &&"core:AttributeLimit".equals(global.path("50").asText())&&"core:LanguageAdaptor".equals(global.path("99").asText()));
        require(text(value,"saltSha256").matches("[0-9a-f]{64}")&&text(auth,"originalSha256").matches("[0-9a-f]{64}"));
        var parser=json(checked(folder,files,"parser.stdout"));require(entity.equals(text(parser,"entity_id"))&&parser.path("validate_authnrequest").asBoolean(false));
        byte[] remote=checked(folder,files,"remote-original.php");require(!new String(remote,StandardCharsets.UTF_8).contains(entity));
        byte[] expectedRemote=(new String(remote,StandardCharsets.UTF_8)+"\n"+text(parser,"php")+"\n").getBytes(StandardCharsets.UTF_8);
        byte[] host=checked(folder,files,"hosted-original.php");require("559eeba5e28f145f0b0bd9ee8c1c147b155babe73d7c19809affdd2147ce8e49".equals(hash(host)));
        byte[] expectedHost=(new String(host,StandardCharsets.UTF_8)+"\n$metadata['"+TARGET+"'][\"authproc\"] = [20 => [\"class\" => \"saml:PersistentNameID\", \"identifyingAttribute\" => \"uid\"]];\n"
            +"$metadata['"+TARGET+"'][\"NameIDFormat\"] = ['"+SimpleSamlPhpPrincipalIdentityResolver.PERSISTENT+"'];\n").getBytes(StandardCharsets.UTF_8);
        for(var phase:List.of("before","after")) {
            require(Arrays.equals(expectedHost,checked(folder,files,phase+"-hosted.php"))&&Arrays.equals(expectedRemote,checked(folder,files,phase+"-remote.php")));
            require(text(json(checked(folder,files,phase+"-authsource-hash.json")),"sha256").equals(text(auth,"originalSha256")));
        }
        require(value.path("peer").isObject()&&entity.equals(text(value.path("peer"),"entityid"))
            &&value.path("peer").path("authproc").isMissingNode()&&value.path("peer").path("validate.authnrequest").asBoolean(false));
    }
    private static void validateAttributes(Element assertion,JsonNode expected) {
        var actual=new HashMap<String,List<String>>();
        for(var statement:children(assertion,S,"AttributeStatement"))for(var attribute:children(statement,S,"Attribute")) {
            String name=attribute.getAttribute("Name");require(!actual.containsKey(name));var values=new ArrayList<String>();
            for(var value:children(attribute,S,"AttributeValue")){require(children(value,S,"NameID").isEmpty());values.add(value.getTextContent());}actual.put(name,values);
        }
        require(actual.keySet().equals(Set.of("uid","eduPersonAffiliation")));
        for(var name:actual.keySet()){var values=new ArrayList<String>();expected.path(name).forEach(v->values.add(v.asText()));require(actual.get(name).equals(values));}
    }
    private static void verifyControl(Element response,Element sp,String target,List<java.security.cert.X509Certificate> keys,String request,String recipient) {
        require(P.equals(response.getNamespaceURI())&&"Response".equals(response.getLocalName())&&request.equals(response.getAttribute("InResponseTo"))
            &&recipient.equals(response.getAttribute("Destination"))&&target.equals(issuer(response)));
        var signatures=new VerifiedSignatureAlgorithms().read(response,target,keys);require(signatures.size()==2&&signatures.stream().anyMatch(s->"Response".equals(s.element()))&&signatures.stream().anyMatch(s->"Assertion".equals(s.element())));
        var assertions=children(response,S,"Assertion");require(assertions.size()==1&&children(response,S,"EncryptedAssertion").isEmpty());
        var a=assertions.getFirst();require(target.equals(issuer(a))&&a.getElementsByTagNameNS(S,"Audience").getLength()==1
            &&sp.getAttribute("entityID").equals(a.getElementsByTagNameNS(S,"Audience").item(0).getTextContent()));
        var codes=response.getElementsByTagNameNS(P,"StatusCode");require(codes.getLength()==1&&"urn:oasis:names:tc:SAML:2.0:status:Success".equals(((Element)codes.item(0)).getAttribute("Value")));
        var data=a.getElementsByTagNameNS(S,"SubjectConfirmationData");require(data.getLength()>0);
        for(int i=0;i<data.getLength();i++){var item=(Element)data.item(i);require(request.equals(item.getAttribute("InResponseTo"))&&recipient.equals(item.getAttribute("Recipient")));}
    }
    private static PrincipalIdentityResolver.Identifier identifier(Element name){var doc=SecureXml.newDocument();doc.appendChild(doc.importNode(name,true));return new PrincipalIdentityResolver.Identifier("NameID",new String(SecureXml.serialize(doc),StandardCharsets.UTF_8),name.getAttribute("Format"),"native-signed-NameID");}
    private static String issuer(Element root){var values=children(root,S,"Issuer");require(values.size()==1);return values.getFirst().getTextContent();}
    private static List<Element> children(Element root,String ns,String name){return MetadataAlgorithmEvidence.children(root,ns,name);}
    private static JsonNode json(byte[] raw)throws Exception{return new JsonCodec().mapper().readTree(raw);}
    private static byte[] checked(Path folder,JsonNode files,String name)throws Exception{byte[] raw=original(folder,name);require(hash(raw).equals(files.path(name).asText()));return raw;}
    private static byte[] original(Path folder,String name)throws Exception{require(name.matches("[A-Za-z0-9._-]+")&&!name.equals(".")&&!name.equals(".."));Path path=folder.resolve(name);require(Files.isRegularFile(path,LinkOption.NOFOLLOW_LINKS)&&Files.size(path)<=4194304);return Files.readAllBytes(path);}
    private static String text(JsonNode node,String field){var value=node.path(field);require(value.isTextual()&&!value.asText().isBlank());return value.asText();}
    private static String hash(byte[] raw)throws Exception{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(raw));}
    private static void require(boolean value){if(!value)throw new IllegalArgumentException("Native subject principal originals unproven");}
}
