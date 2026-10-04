package com.samlscope.runner.cases;

import static com.samlscope.runner.cases.MetadataAlgorithmEvidence.children;
import com.fasterxml.jackson.databind.JsonNode;
import com.samlscope.core.caseexec.CaseContext;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.transcript.*;
import com.samlscope.core.caseexec.ActionIds;
import com.samlscope.saml.crypto.*;
import com.samlscope.saml.normal.SecureXml;
import com.samlscope.store.JsonCodec;
import java.net.URI;
import java.nio.file.*;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.*;
import java.util.function.*;
import org.w3c.dom.Element;

/** Original-backed SLO signer proof. No HTTP result or receipt label is a product conclusion. */
public final class SloRegisteredSignerEvidence {
    public static final String CASE="IIP-IDP17-ab-idp-01", CAMPAIGN="native-slo-registered-signer";
    public static final String SCHEMA="samlscope-slo-registered-signer-v1", KIND="native-slo-registered-signer-evidence";
    static final String MD="urn:oasis:names:tc:SAML:2.0:metadata", S="urn:oasis:names:tc:SAML:2.0:assertion",
            P="urn:oasis:names:tc:SAML:2.0:protocol",DS="http://www.w3.org/2000/09/xmldsig#";
    private final Path directory;
    private final TranscriptContentReader content;
    private final Function<String,byte[]> metadata;
    private final BiFunction<String,String,Optional<PlanCredentials>> keys;
    private final List<SloRegisteredSignerNativeAdapter> adapters;
    private final boolean offlineCalibrationPermission;
    static final String CALIBRATION_SCHEMA="samlscope-slo-registered-signer-calibration-v1", CALIBRATION_PREPARATION_SCHEMA="samlscope-slo-registered-signer-preparation-calibration-v1";
    public SloRegisteredSignerEvidence(Path directory,TranscriptContentReader content,
            Function<String,byte[]> metadata,BiFunction<String,String,Optional<PlanCredentials>> keys,
            SloRegisteredSignerNativeAdapter... adapters) {
        this(directory,content,metadata,keys,false,adapters);
    }
    /** Explicit package-private opt-in for isolated diagnostic replay; never used by production registration. */
    SloRegisteredSignerEvidence(Path directory,TranscriptContentReader content,
            Function<String,byte[]> metadata,BiFunction<String,String,Optional<PlanCredentials>> keys,
            boolean offlineCalibrationPermission,SloRegisteredSignerNativeAdapter... adapters) {
        this.offlineCalibrationPermission=offlineCalibrationPermission;
        this.directory=Objects.requireNonNull(directory).toAbsolutePath().normalize();this.content=Objects.requireNonNull(content);
        this.metadata=Objects.requireNonNull(metadata);this.keys=Objects.requireNonNull(keys);this.adapters=List.of(adapters);
        require(this.adapters.stream().map(SloRegisteredSignerNativeAdapter::adapter).distinct().count()==this.adapters.size());
    }
    public boolean exists(String run){return validRun(run)&&Files.exists(directory.resolve(run),LinkOption.NOFOLLOW_LINKS);}
    public boolean hasFinalProof(String run){return exists(run)&&Files.exists(directory.resolve(run).resolve("manifest.json"),LinkOption.NOFOLLOW_LINKS);}
    public Optional<SloRegisteredSignerProbeInputs> probeInputs(CaseContext context){
        if(!exists(context.runId()))return Optional.empty();
        try {var o=new Originals(context,directory.resolve(context.runId()),content);var raw=o.raw("preparation.json");var m=json(raw);
            require("samlscope-slo-registered-signer-preparation-v1".equals(text(m,"schema"))&&!diagnostic(m));
            var frame=frame(context,o,m);var adapter=adapter(m);var nativeProof=adapter.open(context,o.folder,m,o,false);
            require(!nativeProof.registrationEvidence().isEmpty());return Optional.of(frame.input(hash(raw)));
        }catch(Exception unproven){return Optional.empty();}
    }
    public Optional<CaseOutcome> evaluate(CaseContext context){
        if(!exists(context.runId()))return Optional.empty();String adapterName="unrecognized-native-slo-signer",stage="native-slo-originals-incomplete";
        try {require(context.transcriptComplete());var o=new Originals(context,directory.resolve(context.runId()),content);
            var manifest=o.raw("manifest.json");var m=json(manifest);boolean diagnostic=diagnostic(m);
            require((diagnostic?offlineCalibrationPermission&&CALIBRATION_SCHEMA.equals(text(m,"schema")):SCHEMA.equals(text(m,"schema"))));
            if(diagnostic)calibration(o,m);else stock(m);
            var adapter=adapter(m);adapterName=adapter.adapter();var frame=frame(context,o,m);o.allFiles(m);
            var prep=o.node(m,"preparation.json");require((diagnostic?CALIBRATION_PREPARATION_SCHEMA:"samlscope-slo-registered-signer-preparation-v1").equals(text(prep,"schema")));
            require(diagnostic(prep)==diagnostic);if(diagnostic)require(m.path("calibrationProvenance").equals(prep.path("calibrationProvenance")));
            require(m.path("peers").equals(prep.path("peers"))&&m.path("baseline").equals(prep.path("baseline"))
                    &&m.path("targetMetadataSha256").equals(prep.path("targetMetadataSha256"))&&m.path("adapter").equals(prep.path("adapter")));
            var preparation=frame(context,o,prep);require(Arrays.equals(frame.nameIdXml,preparation.nameIdXml)&&frame.indexes.equals(preparation.indexes));
            stage="operative-slo-key-lookup-unproven";var nativeProof=adapter.open(context,o.folder,m,o,true);
            var evidence=new ArrayList<EvidenceRef>(nativeProof.registrationEvidence());evidence.addAll(frame.baselineEvidence);
            var rows=m.path("probes");require(rows.isArray()&&rows.size()==3);var observations=new ArrayList<SloRegisteredSignerComparison.Sample>();
            Instant previous=frame.baselineAt;var requestIds=new HashSet<String>();
            for(int i=0;i<3;i++) {
                String fixture=SloRegisteredSignerComparison.FIXTURES.get(i);var row=rows.get(i);
                require(fixture.equals(text(row,"fixture"))&&context.runId().equals(text(row,"runId")));
                String action=ActionIds.derive(context.runId(),CASE,"await-fixture-"+fixture,0),id="_"+action;
                var request=o.entry(text(row,"requestReference"));byte[] raw=o.decoded(request);var q=SecureXml.parse(raw).getDocumentElement();
                require(request.direction()==Direction.OUTBOUND&&"POST".equals(request.method())&&action.equals(request.correlationId())
                        &&action.equals(text(row,"actionId"))&&frame.destination.toString().equals(request.url())
                        &&P.equals(q.getNamespaceURI())&&"LogoutRequest".equals(q.getLocalName())&&id.equals(q.getAttribute("ID"))
                        &&requestIds.add(id)&&request.timestamp().isAfter(previous));
                require(o.entries.values().stream().filter(e->e.direction()==Direction.OUTBOUND&&action.equals(e.correlationId())).count()==1);
                Instant issue=Instant.parse(q.getAttribute("IssueInstant"));require(!issue.isAfter(request.timestamp()));
                var expected=SloRegisteredSignerFixtures.build(fixture,id,issue,frame.input(hash(o.file(m,"preparation.json"))),frame.ownKey,frame.otherKey);
                require(Arrays.equals(raw,expected));boolean own=signed(q,frame.ownCertificates),other=signed(q,frame.otherCertificates);
                require(fixture.equals("local-normal")?own&&!other:fixture.equals("local-other-signer")?!own&&other:!own&&!other);
                var matches=new ArrayList<TranscriptEntry>();
                for(var e:o.entries.values())if(e.direction()==Direction.INBOUND&&e.decodedSamlRef()!=null){
                    if("LogoutResponse".equals(e.samlSummary().get("type"))||"LogoutResponse".equals(e.samlSummary().get("messageType"))){
                        var candidate=SecureXml.parse(o.decoded(e)).getDocumentElement();if(id.equals(candidate.getAttribute("InResponseTo")))matches.add(e);
                    }else if(id.equals(e.samlSummary().get("inResponseTo")))matches.add(e);
                }
                require(matches.size()<=1);TranscriptEntry response=matches.isEmpty()?null:matches.getFirst();Element r=null;boolean success=false;
                if(response!=null){r=SecureXml.parse(o.decoded(response)).getDocumentElement();require(P.equals(r.getNamespaceURI())&&"LogoutResponse".equals(r.getLocalName())
                        &&id.equals(r.getAttribute("InResponseTo"))&&frame.responseEndpoint.toString().equals(r.getAttribute("Destination"))
                        &&frame.responseEndpoint.toString().equals(responseEndpoint(response.url(),response.rawQuery(),response.method(),frame.responseEndpoint.toString()))&&frame.targetEntity.equals(issuer(r))&&trustedResponse(o,response,r,frame.targetCertificates)
                        &&response.timestamp().isAfter(request.timestamp()));success=success(r);}
                var nativeUse=nativeProof.validate(row,fixture,request,q,raw,response,r);
                require(!nativeUse.startedAt().isBefore(request.timestamp())&&nativeUse.completedAt().isAfter(nativeUse.startedAt())
                        &&(response==null||!nativeUse.completedAt().isAfter(response.timestamp()))&&!nativeUse.evidence().isEmpty());
                previous=response==null?nativeUse.completedAt():response.timestamp();var refs=new ArrayList<EvidenceRef>(nativeUse.evidence());refs.add(new EvidenceRef("transcript",request.id()));if(response!=null)refs.add(new EvidenceRef("transcript",response.id()));
                observations.add(new SloRegisteredSignerComparison.Sample(fixture,nativeUse.decision(),success,refs));
            }
            // Optional incoming LogoutResponse refers to target consumption, not the response we receive.
            boolean incomingResponseObserved=false;
            for(var e:o.entries.values())if(e.direction()==Direction.OUTBOUND&&e.timestamp().isAfter(frame.baselineAt)
                    &&e.decodedSamlRef()!=null&&e.url().equals(frame.destination.toString())){
                var root=SecureXml.parse(o.decoded(e)).getDocumentElement();if(P.equals(root.getNamespaceURI())&&"LogoutResponse".equals(root.getLocalName()))incomingResponseObserved=true;
            }
            require(m.path("optionalResponseConsumerObserved").isBoolean()&&m.path("optionalResponseConsumerObserved").asBoolean()==incomingResponseObserved);
            // An observed optional consumer requires its own controls; this v1 has none, so retain NV.
            evidence.add(new EvidenceRef(KIND,context.runId()+"/manifest.json#"+hash(manifest)));
            var outcome=SloRegisteredSignerComparison.evaluate(context.runId(),adapterName,observations,evidence,incomingResponseObserved,false);
            if(diagnostic){var details=new HashMap<String,Object>(outcome.details());details.put("counterfactual_calibration_only",true);details.put("actual_product_finding",false);return Optional.of(new CaseOutcome(outcome.outcome(),outcome.notVerifiedReason(),outcome.reasonCode(),outcome.reasonMessageKey(),outcome.evidence(),Map.copyOf(details)));}
            return Optional.of(outcome);
        }catch(Exception unproven){return Optional.of(pending(context.runId(),adapterName,stage));}
    }
    private static boolean diagnostic(JsonNode m){
        if(m.has("calibrationProvenance")||m.has("actualProductFinding")||m.has("derivativeOriginals")||m.has("nativeOperationModel")
                ||m.path("counterfactualCalibrationOnly").asBoolean()||m.path("schema").asText().contains("calibration"))return true;
        var names=m.path("files").fieldNames();while(names.hasNext())if(names.next().startsWith("calibration/"))return true;
        return false;
    }
    private static void stock(JsonNode m){require(!diagnostic(m)&&m.path("counterfactualCalibrationOnly").isBoolean()&&!m.path("counterfactualCalibrationOnly").asBoolean());}
    private static void calibration(Originals o,JsonNode m)throws Exception {
        require(m.path("counterfactualCalibrationOnly").isBoolean()&&m.path("counterfactualCalibrationOnly").asBoolean()
                &&m.path("actualProductFinding").isBoolean()&&!m.path("actualProductFinding").asBoolean());
        var p=m.path("calibrationProvenance");require(p.isObject()&&"known-signer-issuer-mismatch-accepted-v1".equals(text(p,"model")));
        byte[] source=o.file(m,text(p,"sourceManifestFile")),target=o.file(m,text(p,"sourceTargetMetadataFile")),producer=o.file(m,text(p,"producerFile"));
        require(hash(source).equals(text(p,"sourceManifestSha256"))&&hash(target).equals(text(p,"sourceTargetMetadataSha256"))&&hash(producer).equals(text(p,"producerSha256")));
        var original=json(source);stock(original);require(SCHEMA.equals(text(original,"schema"))&&m.path("runId").equals(original.path("runId"))
                &&m.path("caseId").equals(original.path("caseId"))&&m.path("peers").equals(original.path("peers"))&&m.path("baseline").equals(original.path("baseline"))
                &&m.path("adapter").equals(original.path("adapter"))&&m.path("targetEntityId").equals(original.path("targetEntityId"))
                &&hash(target).equals(text(original,"targetMetadataSha256")));
        var input=json(producer);require("samlscope-slo-known-signer-consumer-model-v1".equals(text(input,"schema"))
                &&m.path("runId").equals(input.path("runId"))&&m.path("caseId").equals(input.path("caseId"))
                &&text(p,"sourceManifestSha256").equals(text(input,"sourceManifestSha256"))&&text(p,"sourceTargetMetadataSha256").equals(text(input,"sourceTargetMetadataSha256"))
                &&"accept-known-signer-regardless-of-issuer".equals(text(input,"selectedOperation"))
                &&input.path("counterfactualCalibrationOnly").isBoolean()&&input.path("counterfactualCalibrationOnly").asBoolean()
                &&input.path("actualProductFinding").isBoolean()&&!input.path("actualProductFinding").asBoolean());
    }
    public CaseOutcome pending(String run,String stage){return pending(run,"unrecognized-native-slo-signer",stage);}
    private static CaseOutcome pending(String run,String adapter,String stage){return SloRegisteredSignerComparison.missing(run,adapter,stage,List.of());}
    private SloRegisteredSignerNativeAdapter adapter(JsonNode m){String name=text(m,"adapter");return adapters.stream().filter(a->name.equals(a.adapter())).findFirst().orElseThrow();}
    private record Frame(String run,String otherRun,String entity,URI destination,URI responseEndpoint,
            byte[] nameIdXml,List<String> indexes,Instant baselineAt,List<X509Certificate> ownCertificates,
            List<X509Certificate> otherCertificates,List<X509Certificate> targetCertificates,String targetEntity,
            PlanCredentials ownKey,PlanCredentials otherKey,List<EvidenceRef> baselineEvidence){
        SloRegisteredSignerProbeInputs input(String hash){return new SloRegisteredSignerProbeInputs(run,otherRun,entity,destination,responseEndpoint,nameIdXml,indexes,hash);}
    }
    private Frame frame(CaseContext context,Originals o,JsonNode m)throws Exception {
        require(CAMPAIGN.equals(text(m,"campaignId"))&&CASE.equals(text(m,"caseId"))&&context.runId().equals(text(m,"runId")));
        if(diagnostic(m)){require(offlineCalibrationPermission&&m.path("counterfactualCalibrationOnly").isBoolean()&&m.path("counterfactualCalibrationOnly").asBoolean());}else stock(m);
        o.allFiles(m);var targetBytes=metadata.apply(context.runId());require(targetBytes!=null&&hash(targetBytes).equals(text(m,"targetMetadataSha256"))
                &&Arrays.equals(targetBytes,o.file(m,"target-metadata.xml")));var target=SecureXml.parse(targetBytes).getDocumentElement();
        require(MD.equals(target.getNamespaceURI())&&"EntityDescriptor".equals(target.getLocalName()));String targetEntity=target.getAttribute("entityID");require(targetEntity.equals(text(m,"targetEntityId")));
        var peers=m.path("peers");require(peers.isArray()&&peers.size()==2);var peerMetadata=new ArrayList<Element>();var credentials=new ArrayList<PlanCredentials>();var peerRuns=new HashSet<String>();var entities=new HashSet<String>();
        for(int i=0;i<2;i++) {
            var p=peers.get(i);String label=i==0?"primary":"secondary",run=text(p,"runId"),plan=text(p,"planId"),entity=text(p,"entity");
            require(label.equals(text(p,"label"))&&validRun(run)&&plan.matches("plan_[0-9A-HJKMNP-TV-Z]{26}")&&peerRuns.add(run)&&entities.add(entity));
            var created=o.node(m,label+"/created.json");require(run.equals(created.at("/run/id").asText())&&plan.equals(created.at("/run/planId").asText()));
            var sp=SecureXml.parse(o.file(m,label+"/fixture.xml")).getDocumentElement();require(MD.equals(sp.getNamespaceURI())&&"EntityDescriptor".equals(sp.getLocalName())&&entity.equals(sp.getAttribute("entityID"))
                    &&entity.endsWith("/p/"+plan)&&URI.create(entity).isAbsolute()&&children(sp,MD,"SPSSODescriptor").size()==1);
            var credential=keys.apply(run,"primary").orElseThrow();require(signingKeys(sp).stream().anyMatch(c->Arrays.equals(c.getPublicKey().getEncoded(),credential.certificate().getPublicKey().getEncoded())));
            require(Arrays.equals(metadata.apply(run),targetBytes));peerMetadata.add(sp);credentials.add(credential);
        }
        require(context.runId().equals(text(peers.get(0),"runId")));var own=signingKeys(peerMetadata.get(0));var other=signingKeys(peerMetadata.get(1));require(Collections.disjoint(hashes(own),hashes(other)));
        URI destination=endpoint(target,"IDPSSODescriptor","SingleLogoutService"),responseEndpoint=endpoint(peerMetadata.get(0),"SPSSODescriptor","SingleLogoutService");
        var q=o.entry(text(m.path("baseline"),"requestReference"));var r=o.entry(text(m.path("baseline"),"responseReference"));
        var request=SecureXml.parse(o.decoded(q)).getDocumentElement();var response=SecureXml.parse(o.decoded(r)).getDocumentElement();
        require(q.direction()==Direction.OUTBOUND&&r.direction()==Direction.INBOUND&&P.equals(request.getNamespaceURI())&&"AuthnRequest".equals(request.getLocalName())
                &&baselineSigned(q,request,o.decoded(q),own)&&issuer(request).equals(text(peers.get(0),"entity"))
                &&baselineAdvertised(target,q.method(),request.getAttribute("Destination"))&&r.timestamp().isAfter(q.timestamp()));
        var assertion=VerifiedResponseAssertion.read(response,targetEntity,MetadataAlgorithmEvidence.signingKeys(target),peerMetadata.get(0),Optional.of(credentials.get(0)),request.getAttribute("ID"),r.url());
        require(MetadataSupersessionProbeTestCase.acs(peerMetadata.get(0),0).toString().equals(r.url()));
        var subjects=children(assertion,S,"Subject");require(subjects.size()==1);var identifiers=children(subjects.getFirst(),S,"NameID");require(identifiers.size()==1&&!identifiers.getFirst().getTextContent().isBlank());
        var indexes=new ArrayList<String>();for(var a:children(assertion,S,"AuthnStatement")){require(!a.getAttribute("SessionIndex").isBlank());indexes.add(a.getAttribute("SessionIndex"));}require(!indexes.isEmpty()&&indexes.stream().distinct().count()==indexes.size());
        return new Frame(context.runId(),text(peers.get(1),"runId"),text(peers.get(0),"entity"),destination,responseEndpoint,isolated(identifiers.getFirst()),List.copyOf(indexes),r.timestamp(),own,other,MetadataAlgorithmEvidence.signingKeys(target),targetEntity,credentials.get(0),credentials.get(1),List.of(new EvidenceRef("transcript",q.id()),new EvidenceRef("transcript",r.id())));
    }
    static byte[] isolated(Element e){var d=SecureXml.newDocument();var root=(Element)d.importNode(e,true);d.appendChild(root);for(Element a=e;a!=null;a=a.getParentNode() instanceof Element p?p:null){var attrs=a.getAttributes();for(int i=0;i<attrs.getLength();i++){var v=attrs.item(i);if(javax.xml.XMLConstants.XMLNS_ATTRIBUTE_NS_URI.equals(v.getNamespaceURI())&&!root.hasAttributeNS(v.getNamespaceURI(),v.getLocalName()))root.setAttributeNS(v.getNamespaceURI(),v.getNodeName(),v.getNodeValue());}}return SecureXml.serialize(d);}
    static URI endpoint(Element root,String role,String name){var roles=children(root,MD,role);require(roles.size()==1);var endpoints=children(roles.getFirst(),MD,name).stream().filter(e->"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST".equals(e.getAttribute("Binding"))).toList();require(endpoints.size()==1);var uri=URI.create(endpoints.getFirst().getAttribute("Location"));require(uri.isAbsolute());return uri;}
    static List<X509Certificate> signingKeys(Element sp)throws Exception {var roles=children(sp,MD,"SPSSODescriptor");require(roles.size()==1);var out=new ArrayList<X509Certificate>();for(var kd:children(roles.getFirst(),MD,"KeyDescriptor")){if(!Set.of("","signing").contains(kd.getAttribute("use")))continue;var certs=kd.getElementsByTagNameNS(DS,"X509Certificate");for(int i=0;i<certs.getLength();i++)out.add((X509Certificate)java.security.cert.CertificateFactory.getInstance("X.509").generateCertificate(new java.io.ByteArrayInputStream(Base64.getMimeDecoder().decode(certs.item(i).getTextContent()))));}require(!out.isEmpty());return List.copyOf(out);}
    static Set<String> hashes(List<X509Certificate> certs)throws Exception {var out=new HashSet<String>();for(var c:certs)out.add(hash(c.getEncoded()));return out;}
    static boolean signed(Element e,List<X509Certificate> certs){return certs.stream().anyMatch(c->new XmlSignatureVerifier().hasValidEnvelopedSignature(e,c));}
    static boolean baselineSigned(TranscriptEntry request,Element xml,byte[] raw,List<X509Certificate> certificates){
        String destination=xml.getAttribute("Destination");
        if("POST".equals(request.method()))return request.rawQuery()==null&&destination.equals(request.url())&&signed(xml,certificates);
        if(!"GET".equals(request.method())||request.rawQuery()==null||!request.url().equals(destination+(destination.contains("?")?"&":"?")+request.rawQuery()))return false;
        var verifier=new com.samlscope.saml.binding.RedirectSignatureVerifier();
        return certificates.stream().anyMatch(c->verifier.isValidForMessage(request.rawQuery(),c,raw));
    }
    static boolean baselineAdvertised(Element target,String method,String destination){
        String binding="GET".equals(method)?"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect":"POST".equals(method)?"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST":null;
        var roles=children(target,MD,"IDPSSODescriptor");
        return binding!=null&&roles.size()==1&&children(roles.getFirst(),MD,"SingleSignOnService").stream().anyMatch(e->binding.equals(e.getAttribute("Binding"))&&destination.equals(e.getAttribute("Location")));
    }
    /** Recorder retains a Redirect URL's original query; compare its endpoint without rebuilding those bytes. */
    static String responseEndpoint(String url,String rawQuery,String method,String expectedEndpoint){
        var uri=URI.create(url);require(uri.isAbsolute()&&uri.getRawFragment()==null&&uri.getRawUserInfo()==null);
        if("POST".equals(method))return url;
        require("GET".equals(method)&&rawQuery!=null&&!rawQuery.isBlank()&&rawQuery.equals(uri.getRawQuery()));
        int separator=url.indexOf('?');require(separator>0&&url.equals(url.substring(0,separator)+"?"+rawQuery));
        var registered=URI.create(expectedEndpoint);require(registered.isAbsolute()&&registered.getRawFragment()==null&&registered.getRawUserInfo()==null);
        int fixedSeparator=expectedEndpoint.indexOf('?');String registeredBase=fixedSeparator<0?expectedEndpoint:expectedEndpoint.substring(0,fixedSeparator);
        require(url.substring(0,separator).equals(registeredBase));
        String fixed=registered.getRawQuery();if(fixed!=null&&!fixed.isEmpty())require(rawQuery.startsWith(fixed+"&")&&rawQuery.length()>fixed.length()+1);
        return expectedEndpoint;
    }
    private static boolean trustedResponse(Originals o,TranscriptEntry response,Element root,List<X509Certificate> certs)throws Exception{
        if("POST".equals(response.method()))return signed(root,certs);
        if(!"GET".equals(response.method()))return false;
        byte[] raw=o.decoded(response);var verifier=new com.samlscope.saml.binding.RedirectSignatureVerifier();
        return certs.stream().anyMatch(c->verifier.isValidForMessage(response.rawQuery(),c,raw));
    }
    static String issuer(Element e){var values=children(e,S,"Issuer");require(values.size()==1);return values.getFirst().getTextContent();}
    static boolean success(Element e){var statuses=children(e,P,"Status");require(statuses.size()==1);var codes=children(statuses.getFirst(),P,"StatusCode");require(codes.size()==1);return "urn:oasis:names:tc:SAML:2.0:status:Success".equals(codes.getFirst().getAttribute("Value"));}
    static void require(boolean value){if(!value)throw new IllegalArgumentException("SLO signer originals unavailable");}
    static boolean validRun(String run){return run!=null&&run.matches("run_[0-9A-HJKMNP-TV-Z]{26}");}
    static String hash(byte[] raw)throws Exception{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(raw));}
    static JsonNode json(byte[] raw)throws Exception{return new JsonCodec().mapper().readTree(raw);}
    static String text(JsonNode n,String name){require(n.path(name).isTextual()&&!n.path(name).asText().isBlank());return n.path(name).asText();}
    static Instant at(JsonNode n,String field){return Instant.parse(text(n,field));}

    /** Shared raw-file/transcript boundary; adapters must inspect the actual native material. */
    public static final class Originals {
        final CaseContext context;final Path folder;final TranscriptContentReader content;final Map<String,TranscriptEntry> entries=new LinkedHashMap<>();
        Originals(CaseContext c,Path folder,TranscriptContentReader content){this.context=c;this.folder=folder;this.content=content;for(var e:c.transcript().list(c.runId())){require(c.runId().equals(e.runId())&&entries.put(e.id(),e)==null);if(e.decodedSamlRef()!=null)require(("transcripts/"+c.runId()+"/"+e.id()+".saml.xml").equals(e.decodedSamlRef()));}}
        public byte[] raw(String name)throws Exception {require(!name.isBlank()&&!Path.of(name).isAbsolute());var path=folder.resolve(name).normalize();require(path.startsWith(folder)&&!path.equals(folder));for(var p=path;p!=null;p=p.getParent())require(!Files.isSymbolicLink(p));require(Files.isRegularFile(path,LinkOption.NOFOLLOW_LINKS)&&Files.size(path)<=32*1024*1024);return Files.readAllBytes(path);}
        public byte[] file(JsonNode m,String name)throws Exception {var raw=raw(name);require(hash(raw).equals(text(m.path("files"),name)));return raw;}
        public JsonNode node(JsonNode m,String name)throws Exception{return json(file(m,name));}
        public TranscriptEntry entry(String ref){var e=entries.get(ref);require(e!=null);return e;}
        public byte[] decoded(TranscriptEntry e)throws Exception {require(e.decodedSamlRef()!=null);var b=content.readDecodedSaml(e);require(b!=null&&b.length==e.decodedSamlBytes());return b;}
        public JsonNode original(JsonNode m,String name,String kind)throws Exception {
            var ref=m.path("originals").path(name);var e=entry(text(ref,"reference"));var b=decoded(e);require(hash(b).equals(text(ref,"sha256"))&&Arrays.equals(b,file(m,"native-originals/"+name+".json")));
            var n=json(b);require("samlscope-slo-registered-signer-original-v1".equals(text(n,"schema"))&&context.runId().equals(text(n,"runId"))&&CAMPAIGN.equals(text(n,"campaignId"))
                    &&kind.equals(text(n,"kind"))&&m.path("targetMetadataSha256").equals(n.path("targetMetadataSha256"))&&at(n,"recordedAt").isBefore(e.timestamp()));
            String entity=text(m.path("peers").get(0),"entity");require(e.direction()==Direction.INBOUND&&"POST".equals(e.method())&&Objects.equals(e.status(),204)
                    &&"application/json".equals(e.contentType())&&(entity+"/sp/paos?run="+context.runId()).equals(e.url()));return n;
        }
        public EvidenceRef originalRef(JsonNode m,String name){return new EvidenceRef("transcript",text(m.path("originals").path(name),"reference"));}
        void allFiles(JsonNode m)throws Exception{require(m.path("files").isObject()&&!m.path("files").isEmpty());var it=m.path("files").fieldNames();int count=0;while(it.hasNext()){require(++count<=250);file(m,it.next());}}
    }
}
