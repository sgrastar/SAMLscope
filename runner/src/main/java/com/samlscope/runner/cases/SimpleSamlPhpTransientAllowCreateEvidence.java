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
 * Six source-bound native stock transient flows, with a fixed authentication policy.
 * The approved result concerns AllowCreate-driven persistence: ordinary login state and
 * logout associations may exist. The pinned responder generates a transient ID without
 * reading saml:AllowCreate, and its association input contains no AllowCreate. This proof
 * is confined to the configured stock path and is not a claim about arbitrary PHP code.
 */
final class SimpleSamlPhpTransientAllowCreateEvidence {
    static final String CASE="IIP-SSO01-fp-idp-01",SCHEMA="samlscope-simplesamlphp-transient-allow-create-v1";
    static final List<String> KEYS=List.of("transient-allow-create-true","transient-allow-create-false","transient-allow-create-omitted",
        "implicit-transient-allow-create-true","implicit-transient-allow-create-false","implicit-transient-allow-create-omitted");
    private static final String RUN="run_[0-9A-HJKMNP-TV-Z]{26}",TARGET="http://localhost:18380/idp",
        P="urn:oasis:names:tc:SAML:2.0:protocol",S="urn:oasis:names:tc:SAML:2.0:assertion",MD="urn:oasis:names:tc:SAML:2.0:metadata",
        DS="http://www.w3.org/2000/09/xmldsig#",POST="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",TRANSIENT="urn:oasis:names:tc:SAML:2.0:nameid-format:transient";
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
        Map.entry("native-response.php","27d7f1d4a5ea73b22107b7615c230b156f3dcaa012e843f380d879f53826a64a"),
        Map.entry("native-subject-confirmation-data.php","79ab1c7623b0fa5c0507c55541afdae4e533f35c5664049541c0500220fca048"),
        Map.entry("native-subject-confirmation.php","40746d3785ee55fa4999d49cd19c32625e415d0a37e0f193508138485a5a6a0e"),
        Map.entry("native-userpass-base.php","cb69bac6366c580fd3dd41dcdae37831119cecc8897b62d0b8d22efd129f2169"),
        Map.entry("native-userpass.php","8465e71fabec88578369eaf780dfe86c6ab3f0f2cdf4b24eb52bf134918f9b48"),
        Map.entry("native-web-browser-sso.php","47ddeecace975b77645aa91a4b4551429dc60d02dc1b9baa6c633c30bf1e75f4"),
        Map.entry("native-xml-signer.php","5845e28158c7641d5ce1e6b9205e8005b6d9c090e1888ea46416abb8fdf0018d"),
        Map.entry("native-session.php","66dc24f2ceacd6a1754fdba0aeda2adfc1eac4d42c3f3e16f915a2e5d382f435"),
        Map.entry("native-random.php","db1271223858b858928c4ddd0fb70b2f5da51ca4d12cde15274c8cf2bdf1f0ef"),
        Map.entry("native-transient-filter.php","336b67e14dedd49694eb024a2d10bcb046f473d9d68df6ef67be648d9e7bff55"),
        Map.entry("native-nameid-generator.php","85ac4708eb8324f9e700fa8e8c09f6c33fa40eaab16fc35bc3e31f46423b0fdd"),
        Map.entry("native-http-client.py","52ae423938a43026b38d720fe9cbde6681ba21d7511cf33faca6ab2366151f5e"),
        Map.entry("native-state-command.php","f3bf3a3f462dd658794b6472cc6bafc1723c3e84beb0f285dbb20616072b3759"),
        Map.entry("native-session-command.php","157532af001339f73181a38f7ea9c1c71ac53080814b107365cdbf11b3818a4a"),
        Map.entry("native-ui-privacy.py","944e9a5345e4c714740bdbf87d69cbb61015d0cd37b8ac61a7109a929851ab05"));
    private final Path directory;private final TranscriptContentReader content;private final Function<String,byte[]> metadata;private final SamlDecryptionKeyProvider decryptionKeys;
    SimpleSamlPhpTransientAllowCreateEvidence(Path directory,TranscriptContentReader content,Function<String,byte[]> metadata,SamlDecryptionKeyProvider keys){
        this.directory=Objects.requireNonNull(directory).toAbsolutePath().normalize();this.content=Objects.requireNonNull(content);this.metadata=Objects.requireNonNull(metadata);this.decryptionKeys=Objects.requireNonNull(keys);
    }
    boolean exists(String run){return run!=null&&run.matches(RUN)&&Files.exists(directory.resolve(run),LinkOption.NOFOLLOW_LINKS);}
    Optional<CaseOutcome> evaluate(CaseContext context){
        if(!exists(context.runId()))return Optional.empty();String stage="native-transient-originals-unproven";
        try{
            require(context.transcriptComplete());Path folder=directory.resolve(context.runId());for(Path a=folder;a!=null;a=a.getParent())require(!Files.isSymbolicLink(a));require(Files.isDirectory(folder,LinkOption.NOFOLLOW_LINKS));
            var manifest=json(original(folder,"manifest.json"));var files=manifest.path("files");byte[] targetRaw=metadata.apply(context.runId());
            require(files.isObject()&&SCHEMA.equals(text(manifest,"schema"))&&context.runId().equals(text(manifest,"runId"))&&"native-transient-allow-create".equals(text(manifest,"campaignId"))&&TARGET.equals(text(manifest,"targetEntityId"))&&hash(targetRaw).equals(text(manifest,"targetMetadataSha256")));
            for(var pin:PINS.entrySet()){
                byte[] raw=checked(folder,files,pin.getKey());require(pin.getValue().equals(hash(raw)));
                if(pin.getKey().startsWith("native-")&&pin.getKey().endsWith(".php")&&!pin.getKey().endsWith("-command.php"))require(Arrays.equals(raw,checked(folder,files,pin.getKey().replace(".php","-after.php"))));
            }
            var identity=json(checked(folder,files,"identity-before.json"));require(identity.equals(json(checked(folder,files,"identity-after.json")))&&identity.path("running").asBoolean(false)&&"sha256:9ae050473c68ce13c5451839cb64257eaa17be3a4d2c9a3f87996bbe0cebb0aa".equals(text(identity,"imageId")));
            var created=json(checked(folder,files,"created.json")).path("run");require(context.runId().equals(text(created,"id")));String entity="http://localhost:18080/p/"+text(created,"planId");var plan=json(checked(folder,files,"plan.json")).at("/plan/plan");require("browser_sso_idp".equals(text(plan,"profile"))&&text(created,"planId").equals(text(plan,"id")));
            var target=SecureXml.parse(targetRaw).getDocumentElement();require(TARGET.equals(target.getAttribute("entityID")));var targetKeys=MetadataAlgorithmEvidence.signingKeys(target);require(!targetKeys.isEmpty());
            var entries=new HashMap<String,TranscriptEntry>();for(var e:context.transcript().list(context.runId())){
                require(context.runId().equals(e.runId())&&e.id().matches("tx_[0-9A-HJKMNP-TV-Z]{26}")&&entries.put(e.id(),e)==null);
                if(e.decodedSamlRef()!=null)require(("transcripts/"+context.runId()+"/"+e.id()+".saml.xml").equals(e.decodedSamlRef())&&content.readDecodedSaml(e)!=null&&content.readDecodedSaml(e).length==e.decodedSamlBytes());
            }
            var refs=new LinkedHashSet<EvidenceRef>();var prepared=entry(entries,manifest,"metadataReference","MetadataPrepared",Direction.OUTBOUND);var fetch=entry(entries,manifest,"fetchReference","MetadataFetch",Direction.INBOUND);
            require(fetch.id().equals(prepared.samlSummary().get("fetchTranscriptId"))&&!prepared.timestamp().isBefore(fetch.timestamp()));byte[] controlFixture=checked(folder,files,"control.fixture.xml");require(Arrays.equals(controlFixture,content.readDecodedSaml(prepared))&&hash(controlFixture).equals(prepared.samlSummary().get("metadataSha256")));
            var controlPeer=SecureXml.parse(controlFixture).getDocumentElement();require(entity.equals(controlPeer.getAttribute("entityID")));var controlKeys=MetadataAlgorithmEvidence.signingKeys(controlPeer);require(!controlKeys.isEmpty()&&signed(controlPeer,controlKeys));
            stage="native-effective-persistence-path-unproven";var restore=json(checked(folder,files,"restoration.json"));var baseline=new HashMap<String,byte[]>();
            for(String name:List.of("remote","hosted","override")){byte[] raw=checked(folder,files,name+"-original.php");baseline.put(name,raw);require(Arrays.equals(raw,checked(folder,files,name+"-final.php"))&&restore.path(name).path("restored").asBoolean(false)&&hash(raw).equals(text(restore.path(name),"original_sha256"))&&hash(raw).equals(text(restore.path(name),"final_sha256")));}
            var controlPolicy=validatePreparation(folder,files,"control.parser.stdout","control.parser.stderr","control-before","control-after",baseline,entity,controlPeer);
            var peer=SecureXml.parse(checked(folder,files,"suite-sp-metadata.xml")).getDocumentElement();require(entity.equals(peer.getAttribute("entityID")));var peerKeys=MetadataAlgorithmEvidence.signingKeys(peer);require(!peerKeys.isEmpty()&&signed(peer,peerKeys));
            var policy=validatePreparation(folder,files,"parser.stdout","parser.stderr","before","after",baseline,entity,peer);require(policy.path("hosted").equals(controlPolicy.path("hosted"))&&policy.path("globalAuthproc").equals(controlPolicy.path("globalAuthproc"))&&policy.path("authsource").equals(controlPolicy.path("authsource")));
            var positive=entry(entries,manifest,"positiveRequestReference","AuthnRequest",Direction.OUTBOUND);var negative=entry(entries,manifest,"negativeRequestReference","AuthnRequest",Direction.OUTBOUND);var controlResponse=entry(entries,manifest,"positiveResponseReference","Response",Direction.INBOUND);
            byte[] positiveRaw=content.readDecodedSaml(positive),negativeRaw=content.readDecodedSaml(negative);var positiveXml=SecureXml.parse(positiveRaw).getDocumentElement();var negativeXml=SecureXml.parse(negativeRaw).getDocumentElement();
            require(signed(positiveXml,controlKeys)&&!signed(negativeXml,controlKeys)&&new XmlSignatureVerifier().hasValidEnvelopedReferenceDigests(negativeXml)&&MetadataProbeCorrelation.signatureControl(negative));
            var controlAssertion=verifyResponse(content.readDecodedSaml(controlResponse),targetKeys,entity,positiveXml.getAttribute("ID"),positiveXml.getAttribute("AssertionConsumerServiceURL"));require(transientAssertion(controlAssertion));
            var nativeStates=json(checked(folder,files,"native-state-observations.json"));require(context.runId().equals(text(nativeStates,"runId"))&&nativeStates.path("observations").size()==1);var nativeRow=nativeStates.path("observations").get(0);var nativeState=nativeRow.path("state");
            require(!nativeRow.path("stateHandlePersisted").asBoolean(true)&&positiveXml.getAttribute("ID").equals(text(nativeState,"requestId"))&&positiveXml.getAttribute("AssertionConsumerServiceURL").equals(text(nativeState,"consumerURL"))&&POST.equals(text(nativeState,"binding"))&&nativeState.path("returnCall").isNull()
                &&nativeState.path("responder").equals(json("[\"\\\\SimpleSAML\\\\Module\\\\saml\\\\IdP\\\\SAML2\",\"sendResponse\"]".getBytes(StandardCharsets.UTF_8)))&&nativeState.path("idpMetadata").equals(controlPolicy.path("hosted"))&&nativeState.path("spMetadata").equals(controlPolicy.path("peer")));
            Instant stateAt=Instant.parse(text(nativeRow,"recordedAt"));require(stateAt.isAfter(positive.timestamp())&&stateAt.isBefore(controlResponse.timestamp()));
            validateHttp(folder,files,entries,negative,positive,negativeXml,positiveRaw,negativeRaw,entity);require(before(folder,files,"control-before").isBefore(negative.timestamp())&&before(folder,files,"control-after").isAfter(controlResponse.timestamp())&&positive.timestamp().isAfter(negative.timestamp())&&positive.timestamp().isAfter(prepared.timestamp()));
            stage="native-six-allow-create-flows-unproven";require(manifest.path("matrix").size()==6);var seen=new HashSet<String>();var requestIds=new HashSet<String>();String fixedRequest=null,authn=null,uid=null;var assertions=new ArrayList<Element>();
            for(var row:manifest.path("matrix")){
                String key=text(row,"key");require(KEYS.contains(key)&&seen.add(key));int index=KEYS.indexOf(key);
                var request=entries.get(text(row,"requestReference"));var response=entries.get(text(row,"responseReference"));require(request!=null&&response!=null&&request.direction()==Direction.OUTBOUND&&response.direction()==Direction.INBOUND&&"AuthnRequest".equals(request.samlSummary().get("type"))&&"Response".equals(response.samlSummary().get("type"))&&CASE.equals(request.samlSummary().get("scenario_case_id"))&&key.equals(request.samlSummary().get("fixture_id")));
                var rq=SecureXml.parse(content.readDecodedSaml(request)).getDocumentElement();String requestId=rq.getAttribute("ID"),recipient=rq.getAttribute("AssertionConsumerServiceURL");String actionId=String.valueOf(request.samlSummary().get("action_id"));require(actionId.matches("action_[0-9a-f]{32}")&&actionId.equals(request.correlationId())&&("_"+actionId).equals(requestId)&&requestId.equals(response.correlationId()));require(P.equals(rq.getNamespaceURI())&&"AuthnRequest".equals(rq.getLocalName())&&!requestId.isBlank()&&requestIds.add(requestId)&&entity.equals(issuer(rq))&&!request.timestamp().isBefore(controlResponse.timestamp())&&!response.timestamp().isBefore(request.timestamp()));
                require(POST.equals(rq.getAttribute("ProtocolBinding"))&&!truth(rq.getAttribute("ForceAuthn"))&&!truth(rq.getAttribute("IsPassive"))&&children(children(peer,MD,"SPSSODescriptor").getFirst(),MD,"AssertionConsumerService").stream().anyMatch(e->recipient.equals(e.getAttribute("Location"))));
                require(children(target,MD,"IDPSSODescriptor").stream().flatMap(role->children(role,MD,"SingleSignOnService").stream()).anyMatch(endpoint->rq.getAttribute("Destination").equals(endpoint.getAttribute("Location"))));
                boolean validRequest="GET".equals(request.method())?peerKeys.stream().anyMatch(k->new com.samlscope.saml.binding.RedirectSignatureVerifier().isValidForMessage(request.rawQuery(),k,content.readDecodedSaml(request))):signed(rq,peerKeys);require(validRequest&&policyMatchesRequest(rq,key));
                String fixed=fixedRequest(rq);if(fixedRequest==null)fixedRequest=fixed;else require(fixedRequest.equals(fixed));
                var a=verifyResponse(content.readDecodedSaml(response),targetKeys,entity,requestId,recipient);require(transientAssertion(a));assertions.add(a);String ap=authentication(a),up=identifyingUid(a);if(authn==null){authn=ap;uid=up;}else require(authn.equals(ap)&&uid.equals(up));
                require(entries.values().stream().filter(e->e.direction()==Direction.INBOUND&&"Response".equals(e.samlSummary().get("type"))&&requestId.equals(SecureXml.parse(content.readDecodedSaml(e)).getDocumentElement().getAttribute("InResponseTo"))).count()==1);
                Instant dispatch=validateMatrixHttp(folder,files,request,response,content.readDecodedSaml(request),content.readDecodedSaml(response));require(dispatch.equals(Instant.parse(text(row,"dispatchStartedAt"))));Instant completed=Instant.parse(text(row,"dispatchCompletedAt"));require(before(folder,files,"matrix-"+index+"-before").isBefore(dispatch)&&!completed.isBefore(matrixHttpObserved(folder,files,requestId))&&before(folder,files,"matrix-"+index+"-after").isAfter(completed));
                for(String phase:List.of("before","after")){var rowPolicy=json(checked(folder,files,"matrix-"+index+"-"+phase+".policy.json"));require(rowPolicy.equals(policy));for(String name:baseline.keySet())require(Arrays.equals(checked(folder,files,"matrix-"+index+"-"+phase+"."+name+".php"),checked(folder,files,"before."+name+".php")));
                    var session=json(checked(folder,files,"matrix-"+index+"-"+phase+".session.json"));require(session.equals(json(checked(folder,files,"before.session.json")))&&session.equals(json(checked(folder,files,"after.session.json")))&&session.path("authenticated").asBoolean(false)&&text(session,"sessionSha256").matches("[0-9a-f]{64}"));
                    require(session.path("uid").size()==1&&up.equals(session.path("uid").get(0).asText())&&session.path("authnInstant").isIntegralNumber()&&Instant.ofEpochSecond(session.path("authnInstant").asLong()).equals(Instant.parse(children(a,S,"AuthnStatement").getFirst().getAttribute("AuthnInstant"))));
                    require(session.path("associations").size()==1);var association=session.path("associations").get(0);require(entity.equals(text(association,"entity"))&&TRANSIENT.equals(text(association,"nameIdFormat"))&&"\\SimpleSAML\\Module\\saml\\IdP\\SAML2".equals(text(association,"handler")));
                }
                refs.add(new EvidenceRef("transcript",request.id()));refs.add(new EvidenceRef("transcript",response.id()));
            }
            require(seen.equals(new HashSet<>(KEYS))&&authn!=null&&uid!=null);var counts=json(checked(folder,files,"operation-counts.json"));require(counts.path("credentialPosts").asInt(-1)==1&&counts.path("protocolOperationsAttempted").asInt(-1)==8&&counts.path("nativeParserInvocations").asInt(-1)==2&&counts.path("restored").asBoolean(false)&&counts.path("humanOperations").asInt(-1)==0&&counts.path("productRestarts").asInt(-1)==0);
            for(var e:List.of(fetch,prepared,negative,positive,controlResponse))refs.add(new EvidenceRef("transcript",e.id()));refs.add(new EvidenceRef("native-transient-allow-create",context.runId()+"/manifest.json#"+hash(original(folder,"manifest.json"))));
            return Optional.of(new CaseOutcome(Outcome.SATISFIED,null,"browser.nameid.transient-allow-create-ignored","All six fixed-policy native transient flows succeeded; the source-bound stock path does not use AllowCreate to create or associate persistent identifiers.",List.copyOf(refs),Map.of("adapter",SCHEMA,"case_id",CASE,"required_conditions",KEYS,"configuration_restored",true,"allow_create_persistence_dependency_absent",true,"ordinary_session_storage_asserted_absent",false,"scope","this-run-stock-native-transient-factory-and-effective-configuration","attested",false)));
        }catch(Exception unproven){if(Boolean.getBoolean("samlscope.transientAllowCreate.debug"))unproven.printStackTrace();return Optional.of(CaseOutcome.notVerified(stage,"browser.nameid.transient-allow-create-native-unproven"));}
    }
    private JsonNode validatePreparation(Path folder,JsonNode files,String stdout,String stderr,String pre,String post,Map<String,byte[]> baseline,String entity,Element peer)throws Exception{
        var parser=json(checked(folder,files,stdout));require(entity.equals(text(parser,"entity_id"))&&parser.path("validate_authnrequest").asBoolean(false)&&parser.path("assertion_encryption").isNull()&&checked(folder,files,stderr).length==0);
        byte[] configured=(new String(baseline.get("remote"),StandardCharsets.UTF_8)+"\n"+text(parser,"php")+"\n").getBytes(StandardCharsets.UTF_8);var policy=json(checked(folder,files,pre+".policy.json"));require(policy.equals(json(checked(folder,files,post+".policy.json"))));validatePolicy(policy,entity,peer);
        for(String name:baseline.keySet())require(Arrays.equals(checked(folder,files,pre+"."+name+".php"),name.equals("remote")?configured:baseline.get(name))&&Arrays.equals(checked(folder,files,pre+"."+name+".php"),checked(folder,files,post+"."+name+".php")));
        return policy;
    }
    private static boolean truth(String value){return "true".equals(value)||"1".equals(value);}
    static boolean policyMatchesRequest(Element request,String key){
        if(!KEYS.contains(key))return false;var values=children(request,P,"NameIDPolicy");if(values.size()!=1)return false;var policy=values.getFirst();boolean implicit=key.startsWith("implicit-");
        if(implicit?policy.hasAttribute("Format"):!TRANSIENT.equals(policy.getAttribute("Format")))return false;if(policy.hasAttribute("SPNameQualifier"))return false;String suffix=key.substring(key.lastIndexOf('-')+1);
        return suffix.equals("omitted")?!policy.hasAttribute("AllowCreate"):policy.hasAttribute("AllowCreate")&&suffix.equals(policy.getAttribute("AllowCreate"));
    }
    private static String fixedRequest(Element request){var clone=(Element)request.cloneNode(true);clone.removeAttribute("ID");clone.removeAttribute("IssueInstant");for(var node:children(clone,DS,"Signature"))clone.removeChild(node);for(var node:children(clone,P,"NameIDPolicy"))clone.removeChild(node);return structure(clone);}
    static boolean transientAssertion(Element a){var subject=children(a,S,"Subject");if(subject.size()!=1)return false;var names=children(subject.getFirst(),S,"NameID");return names.size()==1&&TRANSIENT.equals(names.getFirst().getAttribute("Format"))&&!names.getFirst().getTextContent().isBlank();}
    private static String authentication(Element a){var statements=children(a,S,"AuthnStatement");require(statements.size()==1);var auth=statements.getFirst();require(!auth.getAttribute("SessionIndex").isBlank()&&!auth.getAttribute("AuthnInstant").isBlank());var contexts=children(auth,S,"AuthnContext");require(contexts.size()==1);var values=children(contexts.getFirst(),S,"AuthnContextClassRef");require(values.size()==1&&"urn:oasis:names:tc:SAML:2.0:ac:classes:Password".equals(values.getFirst().getTextContent()));return auth.getAttribute("AuthnInstant")+"/"+values.getFirst().getTextContent();}
    private static String identifyingUid(Element a){var values=new ArrayList<String>();for(var statement:children(a,S,"AttributeStatement"))for(var attribute:children(statement,S,"Attribute"))if("uid".equals(attribute.getAttribute("Name")))for(var v:children(attribute,S,"AttributeValue"))values.add(v.getTextContent());require(values.size()==1&&!values.getFirst().isBlank());return values.getFirst();}
    private static Instant before(Path folder,JsonNode files,String name)throws Exception{return Instant.parse(text(json(checked(folder,files,name+".observed.json")),"recordedAt"));}
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
        var http=json(checked(folder,files,"native-http-observations.json"));require(negative.runId().equals(text(http,"runId"))&&!http.path("productVerdictAssigned").asBoolean(true)&&http.path("records").size()>=2);
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
    private Instant validateMatrixHttp(Path folder,JsonNode files,TranscriptEntry request,TranscriptEntry response,byte[] requestRaw,byte[] responseRaw)throws Exception{
        String requestId=SecureXml.parse(requestRaw).getDocumentElement().getAttribute("ID");var http=json(checked(folder,files,"native-http-observations.json"));var pairs=new ArrayList<JsonNode>();for(var record:http.path("records"))if(requestId.equals(text(record,"request_id")))pairs.add(record);require(pairs.size()==1);var row=pairs.getFirst();
        require("POST".equals(request.method())&&request.url().equals(text(row,"request_url"))&&request.url().equals(text(row,"response_url"))&&row.path("redirect_hops").asInt(-1)==0&&row.path("response_status").asInt(-1)==200&&row.path("native_signature_rejection").isNull());
        require(hash(requestRaw).equals(text(row,"request_sha256"))&&Arrays.equals(requestRaw,checked(folder,files,"native-http-originals."+requestId+".request.xml")));byte[] body=checked(folder,files,"native-http-originals."+requestId+".request.body");require(hash(body).equals(text(row,"request_body_sha256")));
        byte[] decoded=null;for(String pair:new String(body,StandardCharsets.UTF_8).split("&")){String[] kv=pair.split("=",2);if("SAMLRequest".equals(java.net.URLDecoder.decode(kv[0],StandardCharsets.UTF_8))){require(kv.length==2&&decoded==null);decoded=Base64.getDecoder().decode(java.net.URLDecoder.decode(kv[1],StandardCharsets.UTF_8));}}require(Arrays.equals(decoded,requestRaw));
        byte[] html=checked(folder,files,"native-http-originals."+requestId+".html");require(hash(html).equals(text(row,"persisted_body_sha256"))&&row.path("body_sanitized").asBoolean(false)&&row.path("saml_response_form_present").asBoolean(false));require(nativeResponseProjectionMatches(html,body,responseRaw,text(row,"response_body_sha256")));
        Instant start=Instant.parse(text(row,"started_at")),observed=Instant.parse(text(row,"observed_at"));require(!observed.isBefore(start));return start;
    }
    private static Instant matrixHttpObserved(Path folder,JsonNode files,String requestId)throws Exception{for(var record:json(checked(folder,files,"native-http-observations.json")).path("records"))if(requestId.equals(text(record,"request_id")))return Instant.parse(text(record,"observed_at"));throw new IllegalArgumentException();}
    /** The two public SAML binding inputs were redacted before persistence. Restore only
     * those exact slots in memory and require the hash of the original HTTP body. */
    static boolean nativeResponseProjectionMatches(byte[] projected,byte[] requestBody,byte[] responseRaw,String originalHash){
        try{
            String html=new String(projected,StandardCharsets.UTF_8),responseSlot="name=\"SAMLResponse\" value=\"[REDACTED]\"",relaySlot="name=\"RelayState\" value=\"[REDACTED]\"";
            if(html.indexOf(responseSlot)<0||html.indexOf(responseSlot)!=html.lastIndexOf(responseSlot)||html.indexOf(relaySlot)<0||html.indexOf(relaySlot)!=html.lastIndexOf(relaySlot)||html.split("\\[REDACTED\\]",-1).length!=3)return false;
            String relay=null;int requests=0;for(String pair:new String(requestBody,StandardCharsets.UTF_8).split("&")){
                String[] kv=pair.split("=",2);if(kv.length!=2)return false;String name=java.net.URLDecoder.decode(kv[0],StandardCharsets.UTF_8);
                if("RelayState".equals(name)){if(relay!=null)return false;relay=java.net.URLDecoder.decode(kv[1],StandardCharsets.UTF_8);}else if("SAMLRequest".equals(name))requests++;else return false;
            }
            if(relay==null||requests!=1)return false;String escaped=relay.replace("&","&amp;").replace("<","&lt;").replace(">","&gt;").replace("\"","&quot;").replace("'","&#039;");
            String original=html.replace(responseSlot,"name=\"SAMLResponse\" value=\""+Base64.getEncoder().encodeToString(responseRaw)+"\"").replace(relaySlot,"name=\"RelayState\" value=\""+escaped+"\"");
            return hash(original.getBytes(StandardCharsets.UTF_8)).equals(originalHash);
        }catch(Exception invalid){return false;}
    }
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
    private static byte[] original(Path folder,String name)throws Exception{require(name.matches("[A-Za-z0-9._-]+")&&!Set.of(".","..").contains(name));Path p=folder.resolve(name);for(Path a=p;a!=null;a=a.getParent())require(!Files.isSymbolicLink(a));require(Files.isRegularFile(p,LinkOption.NOFOLLOW_LINKS)&&Files.size(p)<4194304);return Files.readAllBytes(p);}
    private static JsonNode json(byte[] raw)throws Exception{return new JsonCodec().mapper().readTree(raw);}
    private static String text(JsonNode node,String field){var value=node.path(field);require(value.isTextual()&&!value.asText().isBlank());return value.asText();}
    private static String hash(byte[] raw)throws Exception{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(raw));}
    private static void require(boolean condition){if(!condition)throw new IllegalArgumentException("Native stock transient AllowCreate proof incomplete");}
}
