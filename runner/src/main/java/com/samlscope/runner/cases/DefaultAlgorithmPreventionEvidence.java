package com.samlscope.runner.cases;

import com.fasterxml.jackson.databind.JsonNode;
import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.plan.TargetRole;
import com.samlscope.core.transcript.*;
import com.samlscope.saml.crypto.*;
import com.samlscope.saml.normal.*;
import com.samlscope.store.JsonCodec;
import java.net.URI;
import java.nio.file.*;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.*;
import java.util.function.*;
import org.w3c.dom.Element;

/** Original-backed whole default-prevention case. Mathematical weak-input checks are fixture-only. */
public final class DefaultAlgorithmPreventionEvidence {
    public static final String SCHEMA="samlscope-default-algorithm-prevention-v1";
    public static final String CASE=DefaultAlgorithmComparison.CASE,CAMPAIGN=DefaultAlgorithmComparison.CAMPAIGN;
    static final String MD="urn:oasis:names:tc:SAML:2.0:metadata",A="urn:oasis:names:tc:SAML:2.0:assertion",
            P="urn:oasis:names:tc:SAML:2.0:protocol",DS="http://www.w3.org/2000/09/xmldsig#",X="http://www.w3.org/2001/04/xmlenc#";
    static final String POST="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",SUCCESS="urn:oasis:names:tc:SAML:2.0:status:Success";
    private static final String RUN="run_[0-9A-HJKMNP-TV-Z]{26}";
    private final Path directory;private final TranscriptContentReader content;
    private final Function<String,byte[]> targetMetadata;private final Function<String,Optional<PlanCredentials>> keys;
    private final Function<String,String> profiles;private final Map<String,DefaultAlgorithmNativeAdapter> adapters;
    private final boolean offlineCalibrationAllowed;
    public DefaultAlgorithmPreventionEvidence(Path directory,TranscriptContentReader content,Function<String,byte[]> targetMetadata,
            Function<String,Optional<PlanCredentials>> keys,Function<String,String> profiles,DefaultAlgorithmNativeAdapter... adapters) {
        this(directory,content,targetMetadata,keys,profiles,false,adapters);
    }
    DefaultAlgorithmPreventionEvidence(Path directory,TranscriptContentReader content,Function<String,byte[]> targetMetadata,
            Function<String,Optional<PlanCredentials>> keys,Function<String,String> profiles,boolean calibration,DefaultAlgorithmNativeAdapter... adapters) {
        this.directory=Objects.requireNonNull(directory).toAbsolutePath().normalize();this.content=Objects.requireNonNull(content);
        this.targetMetadata=Objects.requireNonNull(targetMetadata);this.keys=Objects.requireNonNull(keys);this.profiles=Objects.requireNonNull(profiles);
        offlineCalibrationAllowed=calibration;var map=new HashMap<String,DefaultAlgorithmNativeAdapter>();
        for(var adapter:adapters)require(adapter!=null&&!adapter.adapter().isBlank()&&map.put(adapter.adapter(),adapter)==null);
        this.adapters=Map.copyOf(map);
    }
    public boolean exists(String run){return run!=null&&run.matches(RUN)&&Files.exists(directory.resolve(run),LinkOption.NOFOLLOW_LINKS);}
    boolean hasPreparationArtifacts(String run) {
        return run != null && run.matches(RUN)
                && (Files.exists(directory.resolve(run + ".preparation.json"), LinkOption.NOFOLLOW_LINKS)
                || Files.exists(directory.resolve(run + ".preparation"), LinkOption.NOFOLLOW_LINKS));
    }
    /** Read-only preparation; an administrator's unchecked declaration never enables a login. */
    Optional<DefaultAlgorithmNativeAdapter.Preparation> preparation(CaseContext context) {
        try {
            require(context.runId().matches(RUN)&&context.targetRole()==TargetRole.IDP&&context.transcriptComplete());
            var folder=directory.resolve(context.runId()+".preparation");safeParents(folder);
            require(Files.isDirectory(folder,LinkOption.NOFOLLOW_LINKS));
            var m=json(original(directory,context.runId()+".preparation.json"));
            require((SCHEMA+"-preparation").equals(text(m,"schema"))&&context.runId().equals(text(m,"runId"))
                    &&CASE.equals(text(m,"caseId"))&&CAMPAIGN.equals(text(m,"campaignId"))
                    &&m.path("counterfactualCalibrationOnly").isBoolean()&&!m.path("counterfactualCalibrationOnly").booleanValue()
                    &&(!m.has("sourceRunId")||context.runId().equals(text(m,"sourceRunId"))));
            verifyFiles(folder,m);var targetBytes=targetMetadata.apply(context.runId());
            require(hash(targetBytes).equals(text(m,"targetMetadataSha256")));
            var target=SecureXml.parse(targetBytes).getDocumentElement();structure(target,MD,"EntityDescriptor");
            require(target.getAttribute("entityID").equals(text(m,"targetEntityId"))
                    &&"browser_sso_idp".equals(profiles.apply(context.runId()))&&"browser_sso_idp".equals(text(m,"profile")));
            var entries=entries(context);var prepared=entry(entries,text(m,"suiteMetadataReference"));
            var suiteBytes=decoded(prepared);require(prepared.direction()==Direction.OUTBOUND
                    &&"MetadataPrepared".equals(prepared.samlSummary().get("type"))&&"control".equals(prepared.samlSummary().get("variant"))
                    &&"live".equals(prepared.samlSummary().get("feed"))&&hash(suiteBytes).equals(text(m,"suiteMetadataSha256"))
                    &&hash(suiteBytes).equals(prepared.samlSummary().get("metadataSha256")));
            var fetch=entry(entries,String.valueOf(prepared.samlSummary().get("fetchTranscriptId")));
            require(fetch.direction()==Direction.INBOUND&&"MetadataFetch".equals(fetch.samlSummary().get("type"))
                    &&Objects.equals(fetch.status(),200)&&Objects.equals(prepared.status(),200)
                    &&Objects.equals(fetch.id(),prepared.correlationId())&&Objects.equals(fetch.url(),prepared.url())
                    &&!prepared.timestamp().isBefore(fetch.timestamp())&&"PREPARED".equals(prepared.samlSummary().get("delivery")));
            validateSuite(SecureXml.parse(suiteBytes).getDocumentElement(),keys.apply(context.runId()).orElseThrow());
            var originals=m.path("nativeOriginals");require(originals.isArray()&&!originals.isEmpty());
            var originalsByReference=new HashMap<String,String>();for(var row:originals) {
                String reference=text(row,"reference"),sha=text(row,"sha256");var nativeEntry=entry(entries,reference);
                require(originalsByReference.put(reference,sha)==null&&hash(decoded(nativeEntry)).equals(sha));
            }
            var adapter=adapters.get(text(m,"adapter"));require(adapter!=null);
            var result=adapter.prepare(context,folder,m,targetBytes,suiteBytes).orElseThrow();
            require(result.policyId()!=null&&!result.policyId().isBlank()&&!result.evidence().isEmpty());
            for(var ref:result.evidence())require("transcript".equals(ref.kind())&&originalsByReference.containsKey(ref.reference()));
            return Optional.of(result);
        }catch(Exception missing){return Optional.empty();}
    }
    public Optional<CaseOutcome> evaluate(CaseContext context) {
        try {
            require(context.runId().matches(RUN)&&context.targetRole()==TargetRole.IDP&&context.transcriptComplete());
            var folder=directory.resolve(context.runId());safeParents(folder);require(Files.isDirectory(folder,LinkOption.NOFOLLOW_LINKS));
            var manifestBytes=original(folder,"manifest.json");var m=json(manifestBytes);
            require(SCHEMA.equals(text(m,"schema"))&&context.runId().equals(text(m,"runId"))
                    &&CASE.equals(text(m,"caseId"))&&CAMPAIGN.equals(text(m,"campaignId")));
            require(m.path("sourceRunId").isMissingNode()||context.runId().equals(text(m,"sourceRunId")));
            require(m.path("counterfactualCalibrationOnly").isBoolean());boolean calibration=m.path("counterfactualCalibrationOnly").booleanValue();
            require(!calibration||offlineCalibrationAllowed);verifyFiles(folder,m);
            String profile=profiles.apply(context.runId());require("browser_sso_idp".equals(profile)&&profile.equals(text(m,"profile")));
            var targetBytes=targetMetadata.apply(context.runId());require(hash(targetBytes).equals(text(m,"targetMetadataSha256")));
            var target=SecureXml.parse(targetBytes).getDocumentElement();structure(target,MD,"EntityDescriptor");
            require(target.getAttribute("entityID").equals(text(m,"targetEntityId")));
            var primary=keys.apply(context.runId()).orElseThrow();var entries=entries(context);
            var suiteEntry=entry(entries,text(m,"suiteMetadataReference"));var suiteBytes=decoded(suiteEntry);
            require(suiteEntry.direction()==Direction.OUTBOUND&&"MetadataPrepared".equals(suiteEntry.samlSummary().get("type"))
                    &&"control".equals(suiteEntry.samlSummary().get("variant"))&&"live".equals(suiteEntry.samlSummary().get("feed"))
                    &&hash(suiteBytes).equals(text(m,"suiteMetadataSha256"))&&hash(suiteBytes).equals(suiteEntry.samlSummary().get("metadataSha256")));
            var fetch=entry(entries,String.valueOf(suiteEntry.samlSummary().get("fetchTranscriptId")));
            require(fetch.direction()==Direction.INBOUND&&"MetadataFetch".equals(fetch.samlSummary().get("type"))
                    &&Objects.equals(fetch.status(),200)&&Objects.equals(suiteEntry.status(),200)
                    &&Objects.equals(fetch.id(),suiteEntry.correlationId())&&Objects.equals(fetch.url(),suiteEntry.url())
                    &&!suiteEntry.timestamp().isBefore(fetch.timestamp())&&"PREPARED".equals(suiteEntry.samlSummary().get("delivery")));
            var suite=SecureXml.parse(suiteBytes).getDocumentElement();validateSuite(suite,primary);
            var session=adapters.get(text(m,"adapter")).open(context,folder,m,targetBytes,suiteBytes);require(session!=null);
            var observations=m.path("observations");require(observations.isArray()&&!observations.isEmpty()&&observations.size()<=6);
            var samples=new ArrayList<DefaultAlgorithmComparison.Sample>();var seen=new HashSet<String>();var used=new HashSet<String>();
            Element authenticatedName=null;List<String> indexes=List.of();Instant previous=suiteEntry.timestamp();
            for(var row:observations) {
                String fixture=text(row,"fixtureId");require(DefaultAlgorithmComparison.REQUIRED.contains(fixture)&&seen.add(fixture));
                var request=entry(entries,text(row,"requestReference"));require(used.add(request.id())&&request.direction()==Direction.OUTBOUND
                        &&!request.timestamp().isBefore(previous)&&!request.timestamp().isBefore(suiteEntry.timestamp()));
                var bytes=decoded(request);require(hash(bytes).equals(text(row,"requestSha256")));var input=SecureXml.parse(bytes).getDocumentElement();
                var refs=new ArrayList<EvidenceRef>();refs.add(ref(request));Element reply=null;
                boolean logout=fixture.equals("rsa15-encrypted-id")||fixture.equals("oaep-encrypted-id-control");
                validateRequest(context,fixture,request,input,bytes,suite,target,primary,logout);
                if(row.path("responseReference").isTextual()&&!row.path("responseReference").textValue().isBlank()) {
                    var response=entry(entries,text(row,"responseReference"));require(used.add(response.id())&&response.direction()==Direction.INBOUND
                            &&(logout?"LogoutResponse":"Response").equals(response.samlSummary().get("type"))
                            &&!response.timestamp().isBefore(request.timestamp()));
                    var responseBytes=decoded(response);require(hash(responseBytes).equals(text(row,"responseSha256")));
                    reply=SecureXml.parse(responseBytes).getDocumentElement();validateReply(response,reply,responseBytes,input,suite,target,logout);refs.add(ref(response));
                    if(!logout&&SUCCESS.equals(status(reply))) {
                        var assertion=assertion(reply,primary,target,suite,input);var names=children(single(assertion,A,"Subject"),A,"NameID");
                        if(names.isEmpty()){for(var cipher:children(single(assertion,A,"Subject"),A,"EncryptedID"))names.add(new SamlXmlDecrypter().decrypt(cipher,primary.privateKey()));}
                        require(names.size()==1);structure(names.getFirst(),A,"NameID");require(!names.getFirst().getTextContent().isBlank());
                        authenticatedName=names.getFirst();indexes=children(assertion,A,"AuthnStatement").stream().map(e->e.getAttribute("SessionIndex")).toList();
                        require(!indexes.isEmpty()&&indexes.stream().noneMatch(String::isBlank));
                    }
                }
                if(logout)require(authenticatedName!=null&&!indexes.isEmpty()
                        &&children(input,P,"SessionIndex").stream().map(Element::getTextContent).toList().equals(indexes));
                var nativeUse=session.validate(row,fixture,input,bytes,reply,authenticatedName,indexes);require(nativeUse!=null);
                for(var nativeRef:nativeUse.evidence())require("transcript".equals(nativeRef.kind())&&entries.containsKey(nativeRef.reference()));
                if(nativeUse.decision()==DefaultAlgorithmNativeAdapter.Decision.CONSUMED_SUCCESS)
                    require(reply!=null&&SUCCESS.equals(status(reply)));
                else if(reply!=null)require(!SUCCESS.equals(status(reply)));
                if(fixture.equals("invalid-sha256-signature"))require(nativeUse.decision()==DefaultAlgorithmNativeAdapter.Decision.INVALID_SIGNATURE_REJECTION);
                samples.add(new DefaultAlgorithmComparison.Sample(fixture,nativeUse,refs));previous=request.timestamp();
            }
            var proof=new ArrayList<EvidenceRef>();proof.add(ref(fetch));proof.add(ref(suiteEntry));
            proof.add(new EvidenceRef("default-algorithm-native-evidence",context.runId()+"/manifest.json#sha256="+hash(manifestBytes)));
            var result=DefaultAlgorithmComparison.evaluate(context.runId(),text(m,"adapter"),samples,proof);
            var details=new LinkedHashMap<String,Object>(result.details());details.put("counterfactual_calibration_only",calibration);
            details.put("target_metadata_sha256",hash(targetBytes));details.put("target_entity_id",target.getAttribute("entityID"));details.put("profile",profile);
            return Optional.of(new CaseOutcome(result.outcome(),result.notVerifiedReason(),result.reasonCode(),result.reasonMessageKey(),result.evidence(),Map.copyOf(details)));
        }catch(Exception unproven){return Optional.empty();}
    }
    static void validateSuite(Element suite,PlanCredentials key)throws Exception {
        structure(suite,MD,"EntityDescriptor");require(!suite.getAttribute("entityID").isBlank());var role=single(suite,MD,"SPSSODescriptor");
        require(Arrays.asList(role.getAttribute("protocolSupportEnumeration").split("\\s+")).contains(P));
        require(new XmlSignatureVerifier().hasValidEnvelopedSignature(suite,key.certificate()));
        var signing=new ArrayList<java.security.cert.X509Certificate>();for(var k:children(role,MD,"KeyDescriptor")) {
            if(!k.getAttribute("use").isBlank()&&!"signing".equals(k.getAttribute("use")))continue;
            for(var info:children(k,DS,"KeyInfo"))for(var data:children(info,DS,"X509Data"))for(var cert:children(data,DS,"X509Certificate"))
                signing.add((java.security.cert.X509Certificate)java.security.cert.CertificateFactory.getInstance("X.509").generateCertificate(
                        new java.io.ByteArrayInputStream(Base64.getDecoder().decode(cert.getTextContent().replaceAll("\\s+","")))));
        }
        require(signing.size()==1&&Arrays.equals(signing.getFirst().getPublicKey().getEncoded(),key.certificate().getPublicKey().getEncoded()));
        endpoint(suite,"SPSSODescriptor","AssertionConsumerService");
    }
    static void validateRequest(CaseContext context,String fixture,TranscriptEntry entry,Element input,byte[] bytes,
            Element suite,Element target,PlanCredentials key,boolean logout)throws Exception {
        structure(input,P,logout?"LogoutRequest":"AuthnRequest");require("2.0".equals(input.getAttribute("Version"))&&!input.getAttribute("ID").isBlank()
                &&entry.url().equals(input.getAttribute("Destination"))&&endpoint(target,"IDPSSODescriptor",logout?"SingleLogoutService":"SingleSignOnService").toString().equals(entry.url())
                &&suite.getAttribute("entityID").equals(single(input,A,"Issuer").getTextContent())
                &&!input.hasAttribute("ForceAuthn")&&!input.hasAttribute("IsPassive")&&children(input,P,"Extensions").isEmpty());
        require(DefaultAlgorithmPreventionProbeTestCase.action(context.runId(),fixture).equals(String.valueOf(entry.samlSummary().get("action_id")))
                &&("_"+DefaultAlgorithmPreventionProbeTestCase.action(context.runId(),fixture)).equals(input.getAttribute("ID"))
                &&CASE.equals(entry.samlSummary().get("scenario_case_id"))&&fixture.equals(entry.samlSummary().get("fixture_id"))
                &&Boolean.TRUE.equals(entry.samlSummary().get("active_probe")));
        if(!logout) {
            require("AuthnRequest".equals(entry.samlSummary().get("type"))&&endpoint(suite,"SPSSODescriptor","AssertionConsumerService").toString().equals(input.getAttribute("AssertionConsumerServiceURL")));
            var expected=new SamlDefaultAlgorithmFixtures().authnRequest(signatureFixture(fixture),input.getAttribute("ID"),URI.create(entry.url()),suite.getAttribute("entityID"),
                    endpoint(suite,"SPSSODescriptor","AssertionConsumerService"),Instant.parse(input.getAttribute("IssueInstant")),key);
            var validator=new SamlDefaultAlgorithmFixtures();var selected=signatureFixture(fixture);
            require(Arrays.equals(bytes,expected));require(validator.hasValidInputDigests(selected,input));
            require(fixture.equals("invalid-sha256-signature")?!validator.hasValidInputSignature(selected,input,key.certificate()):validator.hasValidInputSignature(selected,input,key.certificate()));
        }else {
            require("LogoutRequest".equals(entry.samlSummary().get("type"))&&new XmlSignatureVerifier().hasValidEnvelopedSignature(input,key.certificate())
                    &&new XmlSignatureVerifier().hasValidEnvelopedReferenceDigests(input)&&!input.hasAttribute("NotOnOrAfter")
                    &&children(input,A,"NameID").isEmpty()&&children(input,A,"BaseID").isEmpty());
            var cipher=single(input,A,"EncryptedID");var data=single(cipher,X,"EncryptedData");
            require("http://www.w3.org/2009/xmlenc11#aes128-gcm".equals(single(data,X,"EncryptionMethod").getAttribute("Algorithm")));
            var encryptedKeys=cipher.getElementsByTagNameNS(X,"EncryptedKey");require(encryptedKeys.getLength()==1);
            require((fixture.equals("rsa15-encrypted-id")?SamlEncryptionFixtureFactory.Transport.RSA_1_5:SamlEncryptionFixtureFactory.Transport.RSA_OAEP).uri()
                    .equals(single((Element)encryptedKeys.item(0),X,"EncryptionMethod").getAttribute("Algorithm")));
        }
    }
    static SamlDefaultAlgorithmFixtures.Fixture signatureFixture(String fixture){return switch(fixture){
        case "sha256-control"->SamlDefaultAlgorithmFixtures.Fixture.SHA256_CONTROL;
        case "invalid-sha256-signature"->SamlDefaultAlgorithmFixtures.Fixture.INVALID_SHA256_SIGNATURE;
        case "md5-digest"->SamlDefaultAlgorithmFixtures.Fixture.MD5_DIGEST;
        case "rsa-md5"->SamlDefaultAlgorithmFixtures.Fixture.RSA_MD5;
        default->throw new IllegalArgumentException("Not a signature fixture");};}
    static URI endpoint(Element entity,String name) {
        String role=switch(name) {
            case "AssertionConsumerService"->"SPSSODescriptor";
            case "SingleSignOnService"->"IDPSSODescriptor";
            case "SingleLogoutService"->{
                boolean idp=!children(entity,MD,"IDPSSODescriptor").isEmpty(),sp=!children(entity,MD,"SPSSODescriptor").isEmpty();
                require(idp!=sp);yield idp?"IDPSSODescriptor":"SPSSODescriptor";
            }
            default->throw new IllegalArgumentException("Unsupported endpoint type");
        };
        return endpoint(entity,role,name);
    }
    /** A dual-role entity requires the operation's role; its other role cannot supply an endpoint. */
    static URI endpoint(Element entity,String role,String name) {
        require(Set.of("SPSSODescriptor","IDPSSODescriptor").contains(role));
        var roles=children(entity,MD,role);require(roles.size()==1);
        var candidates=children(roles.getFirst(),MD,name).stream().filter(e->POST.equals(e.getAttribute("Binding"))).toList();
        if(name.equals("AssertionConsumerService"))candidates=candidates.stream().filter(e->"0".equals(e.getAttribute("index"))).toList();
        require(candidates.size()==1);var uri=URI.create(candidates.getFirst().getAttribute("Location"));require(uri.isAbsolute());return uri;
    }
    static void validateReply(TranscriptEntry entry,Element reply,byte[] responseBytes,Element request,Element suite,Element target,boolean logout)throws Exception {
        structure(reply,P,logout?"LogoutResponse":"Response");require("2.0".equals(reply.getAttribute("Version"))
                &&request.getAttribute("ID").equals(reply.getAttribute("InResponseTo"))
                &&target.getAttribute("entityID").equals(single(reply,A,"Issuer").getTextContent()));
        boolean redirect="GET".equals(entry.method());require(redirect?logout:"POST".equals(entry.method()));
        String binding=redirect?"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect":POST;
        var role=single(suite,MD,"SPSSODescriptor");String destination=reply.getAttribute("Destination");
        var endpoints=children(role,MD,logout?"SingleLogoutService":"AssertionConsumerService").stream()
                .filter(e->binding.equals(e.getAttribute("Binding")))
                .filter(e->logout||"0".equals(e.getAttribute("index")))
                .filter(e->destination.equals(logout&&e.hasAttribute("ResponseLocation")?e.getAttribute("ResponseLocation"):e.getAttribute("Location"))).toList();
        require(endpoints.size()==1);
        if(redirect){
            require(redirectCallbackMatches(entry,destination));
            var verifier=new com.samlscope.saml.binding.RedirectSignatureVerifier();
            require(MetadataAlgorithmEvidence.signingKeys(target).stream()
                    .anyMatch(cert->verifier.isValidForMessage(entry.rawQuery(),cert,responseBytes)));
        }else require(destination.equals(entry.url()));
        // Success may authenticate the Assertion alone; assertion() verifies it after decryption.
        if(!redirect&&(logout||!SUCCESS.equals(status(reply))))require(targetTrusted(reply,target));
    }
    /** Compare the original URI and query without decoding or reconstructing signed octets. */
    static boolean redirectCallbackMatches(TranscriptEntry entry,String destination){
        try{
            var actual=URI.create(entry.url());var expected=URI.create(destination);String query=entry.rawQuery(),fixed=expected.getRawQuery();
            return query!=null&&!query.isEmpty()&&Objects.equals(query,actual.getRawQuery())
                    &&actual.getRawFragment()==null&&expected.getRawFragment()==null
                    &&actual.getRawUserInfo()==null&&expected.getRawUserInfo()==null&&expected.isAbsolute()
                    &&Objects.equals(actual.getScheme(),expected.getScheme())
                    &&Objects.equals(actual.getRawAuthority(),expected.getRawAuthority())
                    &&Objects.equals(actual.getRawPath(),expected.getRawPath())
                    &&(fixed==null||fixed.isEmpty()||query.startsWith(fixed+(fixed.endsWith("&")?"":"&")));
        }catch(IllegalArgumentException invalid){return false;}
    }
    static Element assertion(Element response,PlanCredentials key,Element target,Element suite,Element request)throws Exception {
        var assertions=children(response,A,"Assertion");for(var cipher:children(response,A,"EncryptedAssertion"))assertions.add(new SamlXmlDecrypter().decrypt(cipher,key.privateKey()));
        require(assertions.size()==1);var assertion=assertions.getFirst();structure(assertion,A,"Assertion");
        require(target.getAttribute("entityID").equals(single(assertion,A,"Issuer").getTextContent()));
        if(!children(assertion,DS,"Signature").isEmpty())require(targetTrusted(assertion,target));
        require(targetTrusted(response,target)||targetTrusted(assertion,target));
        var audiences=single(single(assertion,A,"Conditions"),A,"AudienceRestriction");
        require(children(audiences,A,"Audience").size()==1&&suite.getAttribute("entityID").equals(single(audiences,A,"Audience").getTextContent()));
        var confirmations=children(single(assertion,A,"Subject"),A,"SubjectConfirmation");
        require(confirmations.stream().anyMatch(c->{var data=children(c,A,"SubjectConfirmationData");return data.size()==1
                &&"urn:oasis:names:tc:SAML:2.0:cm:bearer".equals(c.getAttribute("Method"))
                &&request.getAttribute("ID").equals(data.getFirst().getAttribute("InResponseTo"))
                &&request.getAttribute("AssertionConsumerServiceURL").equals(data.getFirst().getAttribute("Recipient"));}));
        return assertion;
    }
    static boolean targetTrusted(Element element,Element target)throws Exception {return MetadataAlgorithmEvidence.signingKeys(target).stream()
            .anyMatch(cert->new XmlSignatureVerifier().hasValidEnvelopedSignature(element,cert));}
    static String status(Element response){return single(single(response,P,"Status"),P,"StatusCode").getAttribute("Value");}
    private Map<String,TranscriptEntry> entries(CaseContext context){var map=new HashMap<String,TranscriptEntry>();for(var e:context.transcript().list(context.runId())) {
        require(context.runId().equals(e.runId())&&map.put(e.id(),e)==null);if(e.decodedSamlRef()!=null)require(("transcripts/"+context.runId()+"/"+e.id()+".saml.xml").equals(e.decodedSamlRef()));}return map;}
    private byte[] decoded(TranscriptEntry entry){require(entry.decodedSamlRef()!=null&&!entry.samlSummary().containsValue("UNKNOWN_DELIVERY"));return content.readDecodedSaml(entry);}
    private static TranscriptEntry entry(Map<String,TranscriptEntry> entries,String id){var value=entries.get(id);require(value!=null);return value;}
    private static void verifyFiles(Path folder,JsonNode m)throws Exception {var files=m.path("files");require(files.isObject()&&!files.isEmpty());var names=files.fieldNames();while(names.hasNext()){
        String name=names.next();require(!name.equals("manifest.json")&&hash(original(folder,name)).equals(text(files,name)));}}
    static byte[] original(Path folder,String name)throws Exception {require(name.matches("[A-Za-z0-9][A-Za-z0-9_.-]{0,160}"));var file=folder.resolve(name);safeParents(file);
        require(Files.isRegularFile(file,LinkOption.NOFOLLOW_LINKS)&&Files.size(file)>0&&Files.size(file)<=8_388_608);return Files.readAllBytes(file);}
    static void safeParents(Path path){for(var p=path.toAbsolutePath();p!=null;p=p.getParent())require(!Files.isSymbolicLink(p));}
    static JsonNode json(byte[] bytes)throws Exception{return new JsonCodec().mapper().readTree(bytes);}
    static String text(JsonNode node,String name){var value=node.path(name);require(value.isTextual()&&!value.textValue().isBlank());return value.textValue();}
    static String hash(byte[] bytes)throws Exception{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));}
    static List<Element> children(Element e,String ns,String name){return MetadataAlgorithmEvidence.children(e,ns,name);}
    static Element single(Element e,String ns,String name){var values=children(e,ns,name);require(values.size()==1);return values.getFirst();}
    static void structure(Element e,String ns,String name){require(ns.equals(e.getNamespaceURI())&&name.equals(e.getLocalName()));}
    static void require(boolean value){if(!value)throw new IllegalArgumentException("Original default-algorithm evidence unavailable");}
    static EvidenceRef ref(TranscriptEntry entry){return new EvidenceRef("transcript",entry.id());}
}
