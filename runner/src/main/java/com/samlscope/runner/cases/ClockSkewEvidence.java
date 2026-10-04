package com.samlscope.runner.cases;

import com.fasterxml.jackson.databind.JsonNode;
import com.samlscope.core.caseexec.CaseContext;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.plan.TargetRole;
import com.samlscope.core.transcript.*;
import com.samlscope.saml.crypto.*;
import com.samlscope.saml.normal.*;
import com.samlscope.store.JsonCodec;
import java.nio.file.*;
import java.net.URI;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.*;
import java.util.function.*;
import org.w3c.dom.Element;

/**
 * Whole clock-policy proof, with consumer-specific native adapters. No source-Run relabeling,
 * Suite-default tolerance, parser-only acceptance, or ignored-Extension substitution is allowed.
 * A public reader accepts real measurements only. The package-private calibration permission
 * exercises the same algorithm on developer originals without permitting product adoption.
 */
public final class ClockSkewEvidence {
    public static final String SCHEMA="samlscope-target-clock-skew-v1";
    public static final String CASE="IIP-G01-a-idp-01";
    public static final String CAMPAIGN="target-clock-skew";
    private static final String RUN="run_[0-9A-HJKMNP-TV-Z]{26}";
    private static final String P="urn:oasis:names:tc:SAML:2.0:protocol", A="urn:oasis:names:tc:SAML:2.0:assertion";
    private static final String MD="urn:oasis:names:tc:SAML:2.0:metadata",DS="http://www.w3.org/2000/09/xmldsig#";
    private static final String SUCCESS="urn:oasis:names:tc:SAML:2.0:status:Success";
    private final Path directory; private final TranscriptContentReader content;
    private final Function<String,byte[]> metadata;
    private final BiFunction<String,String,Optional<PlanCredentials>> keys;
    private final Map<String,ClockSkewNativeAdapter> adapters;
    private final boolean offlineCalibrationAllowed;

    public ClockSkewEvidence(Path directory,TranscriptContentReader content,Function<String,byte[]> metadata,
            BiFunction<String,String,Optional<PlanCredentials>> keys,ClockSkewNativeAdapter... adapters) {
        this(directory,content,metadata,keys,false,adapters);
    }
    ClockSkewEvidence(Path directory,TranscriptContentReader content,Function<String,byte[]> metadata,
            BiFunction<String,String,Optional<PlanCredentials>> keys,boolean offlineCalibrationAllowed,
            ClockSkewNativeAdapter... adapters) {
        this.directory=Objects.requireNonNull(directory).toAbsolutePath().normalize();
        this.content=Objects.requireNonNull(content);this.metadata=Objects.requireNonNull(metadata);
        this.keys=Objects.requireNonNull(keys);this.offlineCalibrationAllowed=offlineCalibrationAllowed;
        var map=new HashMap<String,ClockSkewNativeAdapter>();
        for(var adapter:Objects.requireNonNull(adapters)) {
            Objects.requireNonNull(adapter);require(!adapter.adapter().isBlank()&&map.put(adapter.adapter(),adapter)==null);
        }
        this.adapters=Map.copyOf(map);
    }
    public boolean exists(String runId) {
        return runId!=null&&runId.matches(RUN)&&Files.exists(directory.resolve(runId),LinkOption.NOFOLLOW_LINKS);
    }
    public Optional<CaseOutcome> evaluate(CaseContext context) {
        try {
            require(context.targetRole()==TargetRole.IDP&&context.transcriptComplete()&&context.runId().matches(RUN));
            var folder=directory.resolve(context.runId());safeParents(folder);
            require(Files.isDirectory(folder,LinkOption.NOFOLLOW_LINKS));
            var manifestBytes=original(folder,"manifest.json");var m=json(manifestBytes);
            require(SCHEMA.equals(text(m,"schema"))&&context.runId().equals(text(m,"runId"))
                    &&CASE.equals(text(m,"caseId"))&&CAMPAIGN.equals(text(m,"campaignId")));
            require(m.path("sourceRunId").isMissingNode()||context.runId().equals(text(m,"sourceRunId")));
            require(m.path("counterfactualCalibrationOnly").isBoolean());
            boolean calibration=m.path("counterfactualCalibrationOnly").booleanValue();
            require(!calibration||offlineCalibrationAllowed);
            verifyOriginals(folder,m);
            var targetBytes=metadata.apply(context.runId());require(hash(targetBytes).equals(text(m,"targetMetadataSha256")));
            var target=SecureXml.parse(targetBytes).getDocumentElement();
            require(MD.equals(target.getNamespaceURI())&&"EntityDescriptor".equals(target.getLocalName())
                    &&text(m,"targetEntityId").equals(target.getAttribute("entityID")));
            String adapterId=text(m,"adapter");var adapter=adapters.get(adapterId);require(adapter!=null);
            var session=adapter.open(context,folder,m,targetBytes);require(session!=null);
            var entries=new HashMap<String,TranscriptEntry>();var requestIds=new HashSet<String>();
            for(var entry:context.transcript().list(context.runId())) {
                require(context.runId().equals(entry.runId())&&entries.put(entry.id(),entry)==null);
                if(entry.decodedSamlRef()!=null)require(("transcripts/"+context.runId()+"/"+entry.id()+".saml.xml").equals(entry.decodedSamlRef()));
                if(entry.direction()==Direction.OUTBOUND&&"AuthnRequest".equals(entry.samlSummary().get("type")))
                    require(requestIds.add(String.valueOf(entry.samlSummary().get("id"))));
            }
            var observations=m.path("observations");require(observations.isArray()&&!observations.isEmpty()&&observations.size()<=ClockSkewComparison.REQUIRED.size());
            var samples=new ArrayList<ClockSkewComparison.Sample>();var usedInputs=new HashSet<String>();
            var selectedKey=keys.apply(context.runId(),"control").orElseThrow();var seen=new HashSet<String>();
            for(var row:observations) {
                var fixture=text(row,"fixtureId");require(ClockSkewComparison.REQUIRED.contains(fixture)&&seen.add(fixture));
                var input=entry(entries,text(row,"inputReference"));require(usedInputs.add(input.id())&&input.direction()==Direction.OUTBOUND);
                var raw=decoded(input);require(hash(raw).equals(text(row,"inputSha256")));
                var xml=SecureXml.parse(raw).getDocumentElement();validateInput(fixture,xml,raw,selectedKey);
                var request=entry(entries,text(row,"requestReference"));
                require(request.direction()==Direction.OUTBOUND&&"AuthnRequest".equals(request.samlSummary().get("type")));
                var requestXml=SecureXml.parse(decoded(request)).getDocumentElement();
                require(P.equals(requestXml.getNamespaceURI())&&"AuthnRequest".equals(requestXml.getLocalName())
                        &&"2.0".equals(requestXml.getAttribute("Version"))&&!requestXml.getAttribute("ID").isBlank()
                        &&requestXml.getAttribute("Destination").equals(request.url())
                        &&target.getElementsByTagNameNS(MD,"SingleSignOnService").getLength()>0);
                var endpoints=target.getElementsByTagNameNS(MD,"SingleSignOnService");boolean registered=false;
                for(int i=0;i<endpoints.getLength();i++){var e=(Element)endpoints.item(i);if(request.url().equals(e.getAttribute("Location"))
                        &&"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST".equals(e.getAttribute("Binding")))registered=true;}
                require(registered);
                if(fixture.startsWith("issue-"))require(input.id().equals(request.id()));
                var refs=new ArrayList<EvidenceRef>();refs.add(ref(input));if(!input.id().equals(request.id()))refs.add(ref(request));
                Element response=null;
                if(row.path("responseReference").isTextual()&&!row.path("responseReference").textValue().isBlank()) {
                    var reply=entry(entries,text(row,"responseReference"));require(reply.direction()==Direction.INBOUND
                            &&"Response".equals(reply.samlSummary().get("type"))&&!reply.timestamp().isBefore(request.timestamp()));
                    response=SecureXml.parse(decoded(reply)).getDocumentElement();validateReplyBinding(reply,response,requestXml);
                    refs.add(ref(reply));
                }
                var use=session.validate(row,fixture,xml,raw,response);require(use!=null&&!use.evidence().isEmpty());
                // Native refs must be actual current-Run Recorder originals. A receipt cannot
                // create a pseudo-transcript, borrow another Run, or substitute naked hashes.
                for(var nativeRef:use.evidence())require("transcript".equals(nativeRef.kind())&&entries.containsKey(nativeRef.reference()));
                if(use.decision()==ClockSkewNativeAdapter.Decision.ACCEPTED) {
                    require(response!=null&&SUCCESS.equals(status(response)));
                    verifySuccess(response,requestXml,target,selectedKey);
                } else if(response!=null) {
                    require(!SUCCESS.equals(status(response)));verifyTargetSignatures(response,target,false);
                }
                if(fixture.equals("issue-invalid-signature"))require(use.decision()==ClockSkewNativeAdapter.Decision.INVALID_SIGNATURE_REJECTION);
                samples.add(new ClockSkewComparison.Sample(fixture,shiftedValue(fixture,xml),use,refs));
            }
            var proof=new EvidenceRef("clock-skew-native-evidence",context.runId()+"/manifest.json#sha256="+hash(manifestBytes));
            var outcome=ClockSkewComparison.evaluate(context.runId(),adapterId,samples,List.of(proof));
            var details=new LinkedHashMap<String,Object>(outcome.details());details.put("counterfactual_calibration_only",calibration);
            details.put("target_metadata_sha256",hash(targetBytes));details.put("target_entity_id",target.getAttribute("entityID"));
            return Optional.of(new CaseOutcome(outcome.outcome(),outcome.notVerifiedReason(),outcome.reasonCode(),outcome.reasonMessageKey(),outcome.evidence(),details));
        } catch(Exception unavailable) { return Optional.empty(); }
    }
    private byte[] decoded(TranscriptEntry entry) {
        require(entry.decodedSamlRef()!=null&&!entry.samlSummary().containsValue("UNKNOWN_DELIVERY"));
        return content.readDecodedSaml(entry);
    }
    private static void validateInput(String fixture,Element input,byte[] inputBytes,PlanCredentials key) {
        String ns=fixture.startsWith("metadata-")?MD:P;
        String name=fixture.startsWith("metadata-")?"EntityDescriptor":fixture.startsWith("conditions-")?"Response":"AuthnRequest";
        require(ns.equals(input.getNamespaceURI())&&name.equals(input.getLocalName())&&!input.getAttribute("ID").isBlank());
        var verifier=new XmlSignatureVerifier();
        require(verifier.hasValidEnvelopedReferenceDigests(input));
        require(fixture.equals("issue-invalid-signature")?!verifier.hasValidEnvelopedSignature(input,key.certificate())
                :verifier.hasValidEnvelopedSignature(input,key.certificate()));
        if(fixture.startsWith("issue-")) {
            require("2.0".equals(input.getAttribute("Version"))
                &&!input.hasAttribute("ForceAuthn")&&!input.hasAttribute("IsPassive")
                &&MetadataAlgorithmEvidence.children(input,P,"Extensions").isEmpty()
                &&MetadataAlgorithmEvidence.children(input,A,"Subject").isEmpty());
            var expected=new SamlSignedRequestFactory().build(fixture.equals("issue-invalid-signature")
                    ?SamlSignedRequestFactory.Fixture.BAD_SIGNATURE_VALUE:SamlSignedRequestFactory.Fixture.VALID,
                    input.getAttribute("ID"),URI.create(input.getAttribute("Destination")),single(input,A,"Issuer").getTextContent(),
                    URI.create(input.getAttribute("AssertionConsumerServiceURL")),Instant.parse(input.getAttribute("IssueInstant")),key);
            require(Arrays.equals(inputBytes,expected));
        }
        if(fixture.startsWith("conditions-")) {
            var assertion=single(input,A,"Assertion");var conditions=single(assertion,A,"Conditions");
            require(Instant.parse(conditions.getAttribute("NotBefore")).isBefore(Instant.parse(conditions.getAttribute("NotOnOrAfter"))));
            require(MetadataAlgorithmEvidence.children(input,A,"EncryptedAssertion").isEmpty());
            require(verifier.hasValidEnvelopedReferenceDigests(assertion)&&verifier.hasValidEnvelopedSignature(assertion,key.certificate()));
        }
    }
    private static Instant shiftedValue(String fixture,Element input) {
        if(fixture.endsWith("control")||fixture.equals("issue-invalid-signature"))return null;
        if(fixture.startsWith("issue-"))return Instant.parse(input.getAttribute("IssueInstant"));
        if(fixture.startsWith("metadata-"))return Instant.parse(input.getAttribute("validUntil"));
        var conditions=single(single(input,A,"Assertion"),A,"Conditions");
        return Instant.parse(conditions.getAttribute(fixture.equals("conditions-not-before")?"NotBefore":"NotOnOrAfter"));
    }
    private static void validateReplyBinding(TranscriptEntry reply,Element response,Element request) {
        require(P.equals(response.getNamespaceURI())&&"Response".equals(response.getLocalName())
                &&"2.0".equals(response.getAttribute("Version"))&&!response.getAttribute("ID").isBlank()
                &&request.getAttribute("ID").equals(response.getAttribute("InResponseTo"))
                &&request.getAttribute("ID").equals(reply.samlSummary().get("inResponseTo"))
                &&!request.getAttribute("AssertionConsumerServiceURL").isBlank()
                &&request.getAttribute("AssertionConsumerServiceURL").equals(response.getAttribute("Destination"))
                &&response.getAttribute("Destination").equals(reply.url()));
    }
    private static void verifySuccess(Element response,Element request,Element target,PlanCredentials receiver)throws Exception {
        boolean signedResponse=verifyTargetSignatures(response,target,true);
        var assertions=new ArrayList<>(MetadataAlgorithmEvidence.children(response,A,"Assertion"));
        for(var cipher:MetadataAlgorithmEvidence.children(response,A,"EncryptedAssertion"))
            assertions.add(new SamlXmlDecrypter().decrypt(cipher,receiver.privateKey()));
        require(assertions.size()==1);var assertion=assertions.getFirst();
        require(A.equals(assertion.getNamespaceURI())&&"Assertion".equals(assertion.getLocalName())
                &&target.getAttribute("entityID").equals(single(assertion,A,"Issuer").getTextContent()));
        boolean signedAssertion=signature(assertion,target);
        require(signedResponse||signedAssertion);
        var audiences=single(single(assertion,A,"Conditions"),A,"AudienceRestriction");
        require(MetadataAlgorithmEvidence.children(audiences,A,"Audience").stream()
                .anyMatch(a->single(request,A,"Issuer").getTextContent().equals(a.getTextContent())));
    }
    private static boolean verifyTargetSignatures(Element response,Element target,boolean allowAssertionOnly)throws Exception {
        require(target.getAttribute("entityID").equals(single(response,A,"Issuer").getTextContent()));
        boolean result=signature(response,target);
        if(!allowAssertionOnly)require(result);return result;
    }
    private static boolean signature(Element element,Element target)throws Exception {
        var signatures=MetadataAlgorithmEvidence.children(element,DS,"Signature");require(signatures.size()<=1);
        if(signatures.isEmpty())return false;var verifier=new XmlSignatureVerifier();
        require(verifier.hasValidEnvelopedReferenceDigests(element)
                &&MetadataAlgorithmEvidence.signingKeys(target).stream().anyMatch(c->verifier.hasValidEnvelopedSignature(element,c)));
        return true;
    }
    private static String status(Element response) {return single(single(response,P,"Status"),P,"StatusCode").getAttribute("Value");}
    private static Element single(Element parent,String ns,String local) {var values=MetadataAlgorithmEvidence.children(parent,ns,local);require(values.size()==1);return values.getFirst();}
    private static TranscriptEntry entry(Map<String,TranscriptEntry> entries,String id) {var e=entries.get(id);require(e!=null);return e;}
    private static EvidenceRef ref(TranscriptEntry entry) {return new EvidenceRef("transcript",entry.id());}
    static JsonNode json(byte[] raw)throws Exception {return new JsonCodec().mapper().readTree(raw);}
    static String text(JsonNode node,String field) {var value=node.path(field);require(value.isTextual()&&!value.textValue().isBlank());return value.textValue();}
    static byte[] original(Path folder,String name)throws Exception {
        require(name.matches("[A-Za-z0-9_.-]+"));safeParents(folder);var file=folder.resolve(name);
        require(Files.isRegularFile(file,LinkOption.NOFOLLOW_LINKS)&&Files.size(file)<=16*1024*1024);return Files.readAllBytes(file);
    }
    static String hash(byte[] raw)throws Exception {return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(raw));}
    private static void verifyOriginals(Path folder,JsonNode manifest)throws Exception {
        var originals=manifest.path("originals");require(originals.isObject()&&!originals.isEmpty());var declared=new HashSet<String>();
        for(var it=originals.fields();it.hasNext();) {var row=it.next();declared.add(row.getKey());require(row.getValue().isTextual()&&hash(original(folder,row.getKey())).equals(row.getValue().textValue()));}
        try(var files=Files.list(folder)) {require(files.filter(p->!p.getFileName().toString().equals("manifest.json"))
                .map(p->p.getFileName().toString()).collect(java.util.stream.Collectors.toSet()).equals(declared));}
    }
    private static void safeParents(Path folder) {for(var p=folder;p!=null;p=p.getParent())require(!Files.isSymbolicLink(p));}
    static void require(boolean condition) {if(!condition)throw new IllegalArgumentException("Target clock consumer evidence unproven");}
}
