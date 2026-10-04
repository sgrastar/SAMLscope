package com.samlscope.runner.cases;

import static com.samlscope.runner.cases.MetadataAlgorithmEvidence.children;
import com.fasterxml.jackson.databind.JsonNode;
import com.samlscope.core.caseexec.CaseContext;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.transcript.*;
import com.samlscope.saml.crypto.*;
import com.samlscope.saml.normal.SecureXml;
import com.samlscope.store.JsonCodec;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.*;
import java.util.function.Function;
import org.w3c.dom.*;

/**
 * The installed stock factory cannot select a foreign or multiple bearer attester in
 * this exact effective configuration. The approved ordinary-bearer no-opportunity
 * variants receive a note. This makes no claim about arbitrary custom PHP modules.
 * Signed native controls test identifiers and separate confirmations semantically.
 */
final class SimpleSamlPhpSubjectConfirmationEvidence {
    static final String FR="IIP-SSO01-fr-idp-01",GD="IIP-SSO01-gd-idp-01";
    static final String SCHEMA="samlscope-simplesamlphp-subject-confirmation-v1";
    private static final String RUN="run_[0-9A-HJKMNP-TV-Z]{26}",TARGET="http://localhost:18380/idp",
        P="urn:oasis:names:tc:SAML:2.0:protocol",S="urn:oasis:names:tc:SAML:2.0:assertion",MD="urn:oasis:names:tc:SAML:2.0:metadata",
        DS="http://www.w3.org/2000/09/xmldsig#",BEARER="urn:oasis:names:tc:SAML:2.0:cm:bearer",POST="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";
    private static final Map<String,String> PINS=Map.ofEntries(
        Map.entry("native-assertion.php","b935848a17dcfdb4c113618d3460dd1aa1645118f75876dce90ea92d97d33003"),
        Map.entry("native-attribute-limit.php","e3dbf076807713125373a0cf6ab2495e9181685dbd5d29b7344bc31a748f361f"),
        Map.entry("native-auth-processing.php","e6d5023490fbc94dc1a743bb5105f1d093f4eec0a8c48fe030353029e7ea5c5d"),
        Map.entry("native-auth-source.php","5e58ab08d8d03d6720b1bade592119e353fdf8ac1f96a97234575234e57a58d0"),
        Map.entry("native-auth-state.php","59576819feb0d08c19ff34bdee6f239b8edc94e1806fc056ff83b69e6b39ec8a"),
        Map.entry("native-configuration.php","53837359cd60433082d3968843605a864bab97f23be482447bcfef37e7f6946e"),
        Map.entry("native-idp-saml2.php","ae55fc922431d29ca6e87654ae2071500a4c3d7185ed80a6fcc5b26eed12495d"),
        Map.entry("native-idp.php","313760d280f557ffbba61fd4622fbf7e9892b21425d8d24d26d9f08eb9312888"),
        Map.entry("native-language-adaptor.php","f74d170f691a90b5281e77dabfbb026db2ec4eae5ee57a6badf990544622a7ba"),
        Map.entry("native-login-controller.php","56fd31e89b2272e56b08861fc748704a96d0772c3fc4635f11f54967463c8ed5"),
        Map.entry("native-message.php","ab017ee6cf9fb66db1037e40ed50feff0b277b1a5d43fd8ca774a3d27ce355d2"),
        Map.entry("native-parser-command.php","5008495fba0e65487a4849cf46f592c577215f96d5b4f3fd87321ebc6930edf9"),
        Map.entry("native-parser.php","8620bb26fd41d2be29d2611883839a4cfde0b6c8458c274e2d40a002678fd93d"),
        Map.entry("native-policy-command.php","a5801c78f58f96e114e9e76a7e87c3efdf5f59d936bb14787a4e96ff4a949a18"),
        Map.entry("native-producer-command.php","6618854b57939f9207a77d506a313a823b79a491a6cc15f36690a5d410b135a2"),
        Map.entry("native-response.php","27d7f1d4a5ea73b22107b7615c230b156f3dcaa012e843f380d879f53826a64a"),
        Map.entry("native-state-command.php","f3bf3a3f462dd658794b6472cc6bafc1723c3e84beb0f285dbb20616072b3759"),
        Map.entry("native-subject-confirmation-data.php","79ab1c7623b0fa5c0507c55541afdae4e533f35c5664049541c0500220fca048"),
        Map.entry("native-subject-confirmation.php","40746d3785ee55fa4999d49cd19c32625e415d0a37e0f193508138485a5a6a0e"),
        Map.entry("native-userpass-base.php","cb69bac6366c580fd3dd41dcdae37831119cecc8897b62d0b8d22efd129f2169"),
        Map.entry("native-userpass.php","8465e71fabec88578369eaf780dfe86c6ab3f0f2cdf4b24eb52bf134918f9b48"),
        Map.entry("native-web-browser-sso.php","47ddeecace975b77645aa91a4b4551429dc60d02dc1b9baa6c633c30bf1e75f4"),
        Map.entry("native-xml-signer.php","5845e28158c7641d5ce1e6b9205e8005b6d9c090e1888ea46416abb8fdf0018d"),
        Map.entry("collector.py","d4cc95685f333c774b84871829c1a93149ccd2a87dd1023fb6ddbb6df5a72c3c"),
        Map.entry("native-ui-privacy.py","944e9a5345e4c714740bdbf87d69cbb61015d0cd37b8ac61a7109a929851ab05"));
    private final Path directory;private final TranscriptContentReader content;private final Function<String,String> profiles;
    SimpleSamlPhpSubjectConfirmationEvidence(Path directory,TranscriptContentReader content,Function<String,String> profiles){
        this.directory=Objects.requireNonNull(directory).toAbsolutePath().normalize();this.content=Objects.requireNonNull(content);this.profiles=Objects.requireNonNull(profiles);
    }
    boolean exists(String run){return run!=null&&run.matches(RUN)&&Files.exists(directory.resolve(run),LinkOption.NOFOLLOW_LINKS);}
    Optional<CaseOutcome> evaluate(CaseContext context,String id,byte[] targetRaw){
        if(!Set.of(FR,GD).contains(id)||!exists(context.runId()))return Optional.empty();String stage="native-subject-confirmation-originals-unproven";
        try{
            require(context.transcriptComplete()&&"browser_sso_idp".equals(profiles.apply(context.runId())));
            Path folder=directory.resolve(context.runId());for(Path p=folder;p!=null;p=p.getParent())require(!Files.isSymbolicLink(p));require(Files.isDirectory(folder,LinkOption.NOFOLLOW_LINKS));
            var manifest=json(original(folder,"manifest.json"));var files=manifest.path("files");require(files.isObject()&&SCHEMA.equals(text(manifest,"schema"))&&context.runId().equals(text(manifest,"runId"))
                &&"native-subject-confirmation".equals(text(manifest,"campaignId"))&&TARGET.equals(text(manifest,"targetEntityId"))&&hash(targetRaw).equals(text(manifest,"targetMetadataSha256")));
            for(var pin:PINS.entrySet()){
                byte[] raw=checked(folder,files,pin.getKey());require(pin.getValue().equals(hash(raw)));
                if(pin.getKey().startsWith("native-")&&pin.getKey().endsWith(".php")&&!pin.getKey().endsWith("-command.php"))require(Arrays.equals(raw,checked(folder,files,pin.getKey().replace(".php","-after.php"))));
            }
            var identity=json(checked(folder,files,"identity-before.json"));require(identity.equals(json(checked(folder,files,"identity-after.json")))&&identity.path("running").asBoolean(false)
                &&"sha256:9ae050473c68ce13c5451839cb64257eaa17be3a4d2c9a3f87996bbe0cebb0aa".equals(text(identity,"imageId")));
            var created=json(checked(folder,files,"created.json")).path("run");require(context.runId().equals(text(created,"id")));String entity="http://localhost:18080/p/"+text(created,"planId");
            var plan=json(checked(folder,files,"plan.json")).at("/plan/plan");require("browser_sso_idp".equals(text(plan,"profile"))&&text(created,"planId").equals(text(plan,"id")));
            var target=SecureXml.parse(targetRaw).getDocumentElement();require(MD.equals(target.getNamespaceURI())&&"EntityDescriptor".equals(target.getLocalName())&&TARGET.equals(target.getAttribute("entityID")));
            var targetKeys=MetadataAlgorithmEvidence.signingKeys(target);require(!targetKeys.isEmpty());
            var entries=new HashMap<String,TranscriptEntry>();for(var e:context.transcript().list(context.runId())){
                require(context.runId().equals(e.runId())&&e.id().matches("tx_[0-9A-HJKMNP-TV-Z]{26}")&&entries.put(e.id(),e)==null);
                if(e.decodedSamlRef()!=null)require(("transcripts/"+context.runId()+"/"+e.id()+".saml.xml").equals(e.decodedSamlRef())
                    &&content.readDecodedSaml(e)!=null&&content.readDecodedSaml(e).length==e.decodedSamlBytes());
            }
            require(entries.size()==5);var refs=new LinkedHashSet<EvidenceRef>();
            var prepared=entry(entries,manifest,"metadataReference","MetadataPrepared",Direction.OUTBOUND);var fetch=entry(entries,manifest,"fetchReference","MetadataFetch",Direction.INBOUND);
            require(fetch.id().equals(prepared.samlSummary().get("fetchTranscriptId"))&&!prepared.timestamp().isBefore(fetch.timestamp()));
            byte[] fixture=checked(folder,files,"control.fixture.xml");require(Arrays.equals(fixture,content.readDecodedSaml(prepared))&&hash(fixture).equals(prepared.samlSummary().get("metadataSha256")));
            var peer=SecureXml.parse(fixture).getDocumentElement();require(entity.equals(peer.getAttribute("entityID")));var peerKeys=MetadataAlgorithmEvidence.signingKeys(peer);require(!peerKeys.isEmpty()&&signed(peer,peerKeys));
            stage="native-effective-factory-unproven";
            var restore=json(checked(folder,files,"restoration.json"));var baseline=new HashMap<String,byte[]>();
            for(String name:List.of("remote","hosted","override")){
                byte[] raw=checked(folder,files,name+"-original.php");baseline.put(name,raw);require(Arrays.equals(raw,checked(folder,files,name+"-final.php"))&&restore.path(name).path("restored").asBoolean(false)
                    &&hash(raw).equals(text(restore.path(name),"original_sha256"))&&hash(raw).equals(text(restore.path(name),"final_sha256")));
            }
            var parser=json(checked(folder,files,"control.parser.stdout"));require(entity.equals(text(parser,"entity_id"))&&parser.path("validate_authnrequest").asBoolean(false)
                &&parser.path("assertion_encryption").isNull()&&checked(folder,files,"control.parser.stderr").length==0&&json(checked(folder,files,"parser-attempt.json")).path("returncode").asInt(-1)==0);
            byte[] configured=(new String(baseline.get("remote"),StandardCharsets.UTF_8)+"\n"+text(parser,"php")+"\n").getBytes(StandardCharsets.UTF_8);
            var policy=json(checked(folder,files,"before.policy.json"));require(policy.equals(json(checked(folder,files,"after.policy.json"))));validatePolicy(policy,entity,peer);
            for(String phase:List.of("before","after")){
                require(Arrays.equals(configured,checked(folder,files,phase+".remote.php")));
                for(String name:List.of("hosted","override"))require(Arrays.equals(baseline.get(name),checked(folder,files,phase+"."+name+".php")));
            }
            var counts=json(checked(folder,files,"operation-counts.json"));for(var expected:Map.ofEntries(Map.entry("productConfigurationWriteAttempts",2),Map.entry("configurationApplyWrites",1),Map.entry("restorationWrites",1),Map.entry("nativeParserInvocations",1),Map.entry("protocolOperationsAttempted",2),Map.entry("nativeSignedProducerInvocations",4),Map.entry("runCreations",1),Map.entry("credentialPosts",1),Map.entry("productRestarts",0),Map.entry("humanOperations",0)).entrySet())require(counts.path(expected.getKey()).asInt(-1)==expected.getValue());require(counts.path("restored").asBoolean(false));
            stage="native-correlated-signed-response-unproven";
            var request=entry(entries,manifest,"positiveRequestReference","AuthnRequest",Direction.OUTBOUND);var negative=entry(entries,manifest,"negativeRequestReference","AuthnRequest",Direction.OUTBOUND);var response=entry(entries,manifest,"positiveResponseReference","Response",Direction.INBOUND);
            byte[] requestRaw=content.readDecodedSaml(request),negativeRaw=content.readDecodedSaml(negative),responseRaw=content.readDecodedSaml(response);
            var requestXml=SecureXml.parse(requestRaw).getDocumentElement();var negativeXml=SecureXml.parse(negativeRaw).getDocumentElement();
            require(P.equals(requestXml.getNamespaceURI())&&"AuthnRequest".equals(requestXml.getLocalName())&&entity.equals(issuer(requestXml))&&POST.equals(requestXml.getAttribute("ProtocolBinding"))
                &&signed(requestXml,peerKeys)&&!MetadataProbeCorrelation.signatureControl(request)&&MetadataProbeCorrelation.signatureControl(negative)&&!signed(negativeXml,peerKeys)&&new XmlSignatureVerifier().hasValidEnvelopedReferenceDigests(negativeXml));
            String requestId=requestXml.getAttribute("ID"),recipient=requestXml.getAttribute("AssertionConsumerServiceURL");require(!requestId.isBlank()&&!recipient.isBlank()&&requestId.equals(request.correlationId())&&!request.timestamp().isBefore(prepared.timestamp())&&!response.timestamp().isBefore(request.timestamp()));
            Element actual=verifyResponse(responseRaw,targetKeys,entity,requestId,recipient);
            require(ordinaryBearer(actual));
            var states=json(checked(folder,files,"native-state-observations.json"));require(context.runId().equals(text(states,"runId"))&&states.path("observations").size()==1);var stateRow=states.path("observations").get(0);var state=stateRow.path("state");
            require(!stateRow.path("stateHandlePersisted").asBoolean(true)&&requestId.equals(text(state,"requestId"))&&recipient.equals(text(state,"consumerURL"))&&POST.equals(text(state,"binding"))
                &&state.path("responder").equals(json("[\"\\\\SimpleSAML\\\\Module\\\\saml\\\\IdP\\\\SAML2\",\"sendResponse\"]".getBytes(StandardCharsets.UTF_8)))
                &&state.path("returnCall").isNull()&&state.path("idpMetadata").equals(policy.path("hosted"))&&state.path("spMetadata").equals(policy.path("peer"))
                &&state.path("forceAuthn").isBoolean()&&!state.path("forceAuthn").asBoolean(true)&&state.path("isPassive").isBoolean()&&!state.path("isPassive").asBoolean(true));
            Instant observed=Instant.parse(text(stateRow,"recordedAt"));require(observed.isAfter(request.timestamp())&&observed.isBefore(response.timestamp())
                &&Instant.parse(text(json(checked(folder,files,"before.observed.json")),"recordedAt")).isBefore(negative.timestamp())&&Instant.parse(text(json(checked(folder,files,"after.observed.json")),"recordedAt")).isAfter(response.timestamp()));
            validateHttp(folder,files,entries,negative,request,negativeXml,requestRaw,negativeRaw,entity);
            stage="native-semantic-attester-controls-unproven";
            var producer=json(checked(folder,files,"producer.json"));require(response.id().equals(text(producer,"baseResponseReference"))&&hash(responseRaw).equals(text(producer,"baseResponseSha256"))
                &&!producer.path("nativePrivateKeyExported").asBoolean(true)&&!producer.path("controlsAdopted").asBoolean(true)&&hash(checked(folder,files,"native-producer-command.php")).equals(text(producer,"commandSha256")));
            List<String> attesters=List.of("urn:samlscope:attester-control:one","urn:samlscope:attester-control:two");require(producer.path("attesters").equals(json(new JsonCodec().mapper().writeValueAsBytes(attesters))));
            for(String kind:List.of("foreign-positive","foreign-missing-identifier","multiple-positive","multiple-packed-identifiers")){
                var controlled=verifyResponse(checked(folder,files,kind+".xml"),targetKeys,entity,requestId,recipient);require(withoutConfirmations(controlled).equals(withoutConfirmations(actual)));
                boolean expected=kind.endsWith("positive");List<String> permitted=kind.startsWith("foreign")?attesters.subList(0,1):attesters;
                require(identifiesSeparateAttesters(controlled,permitted)==expected);
            }
            for(var e:List.of(fetch,prepared,negative,request,response))refs.add(new EvidenceRef("transcript",e.id()));refs.add(new EvidenceRef("native-subject-confirmation",context.runId()+"/manifest.json#"+hash(original(folder,"manifest.json"))));
            String reason="browser.subject-confirmation.native-no-opportunity";
            return Optional.of(new CaseOutcome(Outcome.SATISFIED_WITH_NOTE,null,reason,
                "The observed stock native bearer factory admits one subject attester; the approved alternate-attester observation is unavailable in this effective configuration.",List.copyOf(refs),Map.of(
                    "product","simplesamlphp","evidence_adapter",SCHEMA,"subject_confirmation_count",1,"attester_identifier_count",0,
                    "no_observation_opportunity",true,"scope","this-run-stock-native-responder-and-effective-configuration","custom_php_capability_asserted",false,
                    "native_signed_semantic_controls",4,"case_id",id)));
        }catch(Exception unproven){if(Boolean.getBoolean("samlscope.nativeSubjectConfirmation.debug"))unproven.printStackTrace();return Optional.of(CaseOutcome.notVerified(stage,"browser.subject-confirmation.native-unproven"));}
    }
    private static void validatePolicy(JsonNode value,String entity,Element peer)throws Exception{
        require(TARGET.equals(text(value,"targetEntityId"))&&entity.equals(text(value,"spEntityId"))&&"a1b218b29003289e01e4154a9d5d7cbffa33a3b9629057d0ae51d652d0393cf3".equals(text(value,"configSha256"))
            &&"ea23df120a13b50435b97c71e1aa5c5194fe619e3d2eeeb24ce9a09cb44c99ad".equals(text(value,"authsourceSha256")));
        require(value.path("globalAuthproc").equals(json("{\"30\":\"core:LanguageAdaptor\",\"50\":\"core:AttributeLimit\",\"99\":\"core:LanguageAdaptor\"}".getBytes(StandardCharsets.UTF_8)))
            &&value.path("authsource").equals(json("{\"id\":\"example-userpass\",\"class\":\"exampleauth:UserPass\",\"authproc\":null}".getBytes(StandardCharsets.UTF_8)))&&!value.path("proxyAuthnContext").asBoolean(true));
        var host=value.path("hosted");require(host.size()==9&&TARGET.equals(text(host,"entityid"))&&"__DEFAULT__".equals(text(host,"host"))&&"server.pem".equals(text(host,"privatekey"))
            &&"server.crt".equals(text(host,"certificate"))&&"example-userpass".equals(text(host,"auth"))&&host.path("saml20.ecp").asBoolean(false)&&host.path("authproc").isMissingNode()&&host.path("saml20.hok.assertion").isMissingNode());
        var remote=value.path("peer");require(remote.size()==9&&entity.equals(text(remote,"entityid"))&&remote.path("authproc").isMissingNode()&&remote.path("validate.authnrequest").asBoolean(false)&&remote.path("saml20.sign.assertion").asBoolean(false)
            &&remote.path("assertion.encryption").isMissingNode()&&remote.path("audience").isMissingNode());
        var keys=MetadataAlgorithmEvidence.signingKeys(peer);require(!keys.isEmpty()&&remote.path("keys").size()==2);
        for(var key:remote.path("keys")){require("X509Certificate".equals(text(key,"type")));var actual=(X509Certificate)java.security.cert.CertificateFactory.getInstance("X.509").generateCertificate(new java.io.ByteArrayInputStream(Base64.getMimeDecoder().decode(text(key,"X509Certificate"))));require(keys.stream().anyMatch(k->Arrays.equals(k.getPublicKey().getEncoded(),actual.getPublicKey().getEncoded())));}
        var roles=children(peer,MD,"SPSSODescriptor");require(roles.size()==1);for(String kind:List.of("AssertionConsumerService","SingleLogoutService")){
            var nativeEndpoints=remote.path(kind);var xmlEndpoints=children(roles.getFirst(),MD,kind);require(nativeEndpoints.size()==xmlEndpoints.size());
            for(int i=0;i<xmlEndpoints.size();i++){var xml=xmlEndpoints.get(i);require(xml.getAttribute("Binding").equals(text(nativeEndpoints.get(i),"Binding"))&&xml.getAttribute("Location").equals(text(nativeEndpoints.get(i),"Location")));}
        }
    }
    private void validateHttp(Path folder,JsonNode files,Map<String,TranscriptEntry> entries,TranscriptEntry negative,TranscriptEntry positive,Element rejected,byte[] positiveRaw,byte[] negativeRaw,String entity)throws Exception{
        var http=json(checked(folder,files,"native-http-observations.json"));require(negative.runId().equals(text(http,"runId"))&&!http.path("productVerdictAssigned").asBoolean(true)&&http.path("records").size()==2);
        for(var e:List.of(negative,positive)){
            byte[] raw=e==negative?negativeRaw:positiveRaw;String id=SecureXml.parse(raw).getDocumentElement().getAttribute("ID");var matches=new ArrayList<JsonNode>();for(var row:http.path("records"))if(id.equals(text(row,"request_id")))matches.add(row);require(matches.size()==1);var row=matches.getFirst();
            require(hash(raw).equals(text(row,"request_sha256"))&&e.url().equals(text(row,"request_url"))&&Arrays.equals(raw,checked(folder,files,"native-http-originals."+id+".request.xml")));
            byte[] body=checked(folder,files,"native-http-originals."+id+".request.body");require(hash(body).equals(text(row,"request_body_sha256")));byte[] decoded=null;
            for(String pair:new String(body,StandardCharsets.UTF_8).split("&")){String[] kv=pair.split("=",2);if("SAMLRequest".equals(java.net.URLDecoder.decode(kv[0],StandardCharsets.UTF_8))){require(kv.length==2&&decoded==null);decoded=Base64.getDecoder().decode(java.net.URLDecoder.decode(kv[1],StandardCharsets.UTF_8));}}
            require(Arrays.equals(decoded,raw));String html=new String(checked(folder,files,"native-http-originals."+id+".html"),StandardCharsets.UTF_8);require(hash(html.getBytes(StandardCharsets.UTF_8)).equals(text(row,"persisted_body_sha256")));
            if(e==negative){require("signature-value-invalid".equals(text(row,"native_signature_rejection"))&&row.path("response_status").asInt()==500&&row.path("redirect_hops").asInt(-1)==0&&e.url().equals(text(row,"response_url"))
                &&html.contains("NOTVALIDCERTSIGNATURE")&&html.replace("\\/","/").contains(entity)&&Instant.parse(text(row,"observed_at")).isBefore(positive.timestamp()));
                for(var candidate:entries.values())if(candidate.direction()==Direction.INBOUND&&"Response".equals(candidate.samlSummary().get("type")))require(!id.equals(SecureXml.parse(content.readDecodedSaml(candidate)).getDocumentElement().getAttribute("InResponseTo")));
            }else require(row.path("response_status").asInt()==200&&row.path("native_signature_rejection").isNull()&&row.path("body_sanitized").asBoolean(false)&&html.contains("[REDACTED]")&&!html.matches("(?s).*_[a-f0-9]{40}.*"));
        }
    }
    static boolean ordinaryBearer(Element assertion){
        var subjects=children(assertion,S,"Subject");if(subjects.size()!=1)return false;var subject=subjects.getFirst();var names=children(subject,S,"NameID");if(names.size()!=1||names.getFirst().getTextContent().isBlank())return false;
        var confirmations=children(subject,S,"SubjectConfirmation");return confirmations.size()==1&&BEARER.equals(confirmations.getFirst().getAttribute("Method"))&&identifiers(confirmations.getFirst()).isEmpty();
    }
    static boolean identifiesSeparateAttesters(Element assertion,List<String> permitted){
        if(permitted.isEmpty()||new HashSet<>(permitted).size()!=permitted.size())return false;var subjects=children(assertion,S,"Subject");if(subjects.size()!=1)return false;var scs=children(subjects.getFirst(),S,"SubjectConfirmation");if(scs.size()!=permitted.size())return false;
        var actual=new HashSet<String>();for(var sc:scs){var ids=identifiers(sc);if(!BEARER.equals(sc.getAttribute("Method"))||ids.size()!=1||!"NameID".equals(ids.getFirst().getLocalName())||ids.getFirst().getTextContent().isBlank()||!actual.add(ids.getFirst().getTextContent()))return false;}
        return actual.equals(new HashSet<>(permitted));
    }
    private static List<Element> identifiers(Element sc){var result=new ArrayList<Element>();for(String kind:List.of("BaseID","NameID","EncryptedID"))result.addAll(children(sc,S,kind));return result;}
    private static Element verifyResponse(byte[] raw,List<X509Certificate> keys,String entity,String request,String recipient){
        var xml=SecureXml.parse(raw).getDocumentElement();require(P.equals(xml.getNamespaceURI())&&"Response".equals(xml.getLocalName())&&request.equals(xml.getAttribute("InResponseTo"))&&recipient.equals(xml.getAttribute("Destination"))&&TARGET.equals(issuer(xml))&&signed(xml,keys));
        var statuses=children(xml,P,"Status");require(statuses.size()==1);var codes=children(statuses.getFirst(),P,"StatusCode");require(codes.size()==1&&"urn:oasis:names:tc:SAML:2.0:status:Success".equals(codes.getFirst().getAttribute("Value")));
        var assertions=children(xml,S,"Assertion");require(assertions.size()==1&&children(xml,S,"EncryptedAssertion").isEmpty());var a=assertions.getFirst();require(TARGET.equals(issuer(a))&&signed(a,keys));
        var audiences=a.getElementsByTagNameNS(S,"Audience");require(audiences.getLength()==1&&entity.equals(audiences.item(0).getTextContent()));var subjects=children(a,S,"Subject");require(subjects.size()==1);
        for(var sc:children(subjects.getFirst(),S,"SubjectConfirmation")){var data=children(sc,S,"SubjectConfirmationData");require(data.size()==1&&request.equals(data.getFirst().getAttribute("InResponseTo"))&&recipient.equals(data.getFirst().getAttribute("Recipient")));}
        return a;
    }
    private static String withoutConfirmations(Element assertion){var clone=(Element)assertion.cloneNode(true);var xp=new ArrayList<Node>();for(String kind:List.of("Signature","SubjectConfirmation")){var nodes=clone.getElementsByTagNameNS(kind.equals("Signature")?DS:S,kind);for(int i=0;i<nodes.getLength();i++)xp.add(nodes.item(i));}for(var node:xp)node.getParentNode().removeChild(node);return structure(clone);}
    private static String structure(Element e){var attrs=new TreeMap<String,String>();for(int i=0;i<e.getAttributes().getLength();i++){var a=e.getAttributes().item(i);if(!"http://www.w3.org/2000/xmlns/".equals(a.getNamespaceURI()))attrs.put("{"+a.getNamespaceURI()+"}"+a.getLocalName(),a.getNodeValue());}
        var parts=new ArrayList<String>();for(Node n=e.getFirstChild();n!=null;n=n.getNextSibling()){if(n instanceof Element child)parts.add(structure(child));else if(n.getNodeType()==Node.TEXT_NODE&&!n.getNodeValue().isBlank())parts.add(n.getNodeValue());}return "{"+e.getNamespaceURI()+"}"+e.getLocalName()+attrs+parts;}
    private static boolean signed(Element e,List<X509Certificate> keys){var verifier=new XmlSignatureVerifier();return verifier.hasValidEnvelopedReferenceDigests(e)&&keys.stream().anyMatch(k->verifier.hasValidEnvelopedSignature(e,k));}
    private static String issuer(Element root){var values=children(root,S,"Issuer");require(values.size()==1);return values.getFirst().getTextContent();}
    private static TranscriptEntry entry(Map<String,TranscriptEntry> entries,JsonNode receipt,String field,String type,Direction direction){var e=entries.get(text(receipt,field));require(e!=null&&e.direction()==direction&&type.equals(e.samlSummary().get("type"))&&("Response".equals(type)||"control".equals(e.samlSummary().get("variant"))));return e;}
    private static byte[] checked(Path folder,JsonNode files,String name)throws Exception{var raw=original(folder,name);require(hash(raw).equals(files.path(name).asText()));return raw;}
    private static byte[] original(Path folder,String name)throws Exception{require(name.matches("[A-Za-z0-9._-]+")&&!Set.of(".","..").contains(name));Path p=folder.resolve(name);require(Files.isRegularFile(p,LinkOption.NOFOLLOW_LINKS)&&Files.size(p)<4194304);return Files.readAllBytes(p);}
    private static JsonNode json(byte[] raw)throws Exception{return new JsonCodec().mapper().readTree(raw);}
    private static String text(JsonNode node,String field){var value=node.path(field);require(value.isTextual()&&!value.asText().isBlank());return value.asText();}
    private static String hash(byte[] raw)throws Exception{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(raw));}
    private static void require(boolean condition){if(!condition)throw new IllegalArgumentException("Native stock bearer factory proof incomplete");}
}
