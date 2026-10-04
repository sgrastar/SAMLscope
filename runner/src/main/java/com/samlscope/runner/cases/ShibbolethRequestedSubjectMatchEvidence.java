package com.samlscope.runner.cases;

import com.fasterxml.jackson.databind.JsonNode;
import com.samlscope.core.caseexec.CaseContext;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.plan.TargetRole;
import com.samlscope.core.transcript.*;
import com.samlscope.saml.crypto.*;
import com.samlscope.saml.normal.SecureXml;
import com.samlscope.store.JsonCodec;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.cert.*;
import java.time.Instant;
import java.util.*;
import java.util.function.Function;
import java.util.zip.ZipInputStream;
import org.w3c.dom.Element;

/** A native, known-principal counterexample; incomplete variant coverage never establishes satisfaction. */
public final class ShibbolethRequestedSubjectMatchEvidence {
    public static final String CASE="IIP-SSO07-b-idp-01";
    public static final String ADAPTER="shibboleth-native-requested-subject-match";
    public static final String REASON="idp.subject.native-identifier-mismatch";
    private static final String RUN="run_[0-9A-HJKMNP-TV-Z]{26}";
    private static final String P="urn:oasis:names:tc:SAML:2.0:protocol",S="urn:oasis:names:tc:SAML:2.0:assertion",MD="urn:oasis:names:tc:SAML:2.0:metadata",DS="http://www.w3.org/2000/09/xmldsig#";
    private static final String B="http://www.springframework.org/schema/beans",U="http://www.springframework.org/schema/util",PROP="http://www.springframework.org/schema/p";
    private static final String IMAGE="sha256:3c1b1fa64c58258aefc9e38d4ae60e9f0340731318a472110ea56ce88c18a11a";
    private static final String SOURCE="428e389d88bb2abcad19d69bcf759af29f7ce6beb776ccfaa5a6ea76751682ba";
    private final Path directory;private final TranscriptContentReader content;
    private final Function<String,byte[]> metadata;private final SamlDecryptionKeyProvider keys;
    public ShibbolethRequestedSubjectMatchEvidence(Path directory,TranscriptContentReader content,Function<String,byte[]> metadata,SamlDecryptionKeyProvider keys) {
        this.directory=Objects.requireNonNull(directory).toAbsolutePath().normalize();this.content=Objects.requireNonNull(content);
        this.metadata=Objects.requireNonNull(metadata);this.keys=Objects.requireNonNull(keys);
    }
    public boolean exists(String run){return run.matches(RUN)&&Files.exists(directory.resolve(run),LinkOption.NOFOLLOW_LINKS);}
    public Optional<CaseOutcome> read(CaseContext context) {
        try {
            require(context.targetRole()==TargetRole.IDP&&context.transcriptComplete()&&context.runId().matches(RUN));
            var folder=directory.resolve(context.runId());require(Files.isDirectory(folder,LinkOption.NOFOLLOW_LINKS));safeParents(folder);
            var manifest=json(folder,"manifest.json");require("samlscope-shibboleth-requested-subject-match-v1".equals(text(manifest,"schema"))&&context.runId().equals(text(manifest,"runId")));
            var hashes=manifest.path("originals");require(hashes.isObject()&&hashes.size()>0);
            for(var iterator=hashes.fields();iterator.hasNext();) {var pair=iterator.next();require(hash(original(folder,pair.getKey())).equals(pair.getValue().asText()));}
            var targetRaw=metadata.apply(context.runId());require(hash(targetRaw).equals(text(manifest,"targetMetadataSha256")));
            var target=SecureXml.parse(targetRaw).getDocumentElement();require(MD.equals(target.getNamespaceURI())&&"EntityDescriptor".equals(target.getLocalName()));
            var created=json(folder,"created.json").path("run");require(context.runId().equals(text(created,"id")));
            var sp=SecureXml.parse(original(folder,"suite-sp-metadata.xml")).getDocumentElement();
            var entity="http://localhost:18080/p/"+text(created,"planId");require(MD.equals(sp.getNamespaceURI())&&"EntityDescriptor".equals(sp.getLocalName())&&entity.equals(sp.getAttribute("entityID")));
            var binding=json(folder,"native-subject-binding.json");var value=text(binding,"inputValue");var principal=text(binding,"principal");
            require("samlscope-shibboleth-g02-known-subject-v1".equals(text(binding,"schema"))&&target.getAttribute("entityID").equals(text(binding,"targetEntityId"))&&entity.equals(text(binding,"suiteEntityId")));
            var start=readBack(folder,"before-protocol");var end=readBack(folder,"after-protocol");var beforeRun=readBack(folder,"before-run");
            var createdSeconds=created.path("createdAt").decimalValue();var createdAt=Instant.ofEpochSecond(createdSeconds.longValue(),createdSeconds.remainder(java.math.BigDecimal.ONE).movePointRight(9).longValue());
            require(!beforeRun.isAfter(createdAt)&&beforeRun.isBefore(start)&&start.isBefore(end));
            nativeConfiguration(folder,value,principal,entity);
            require(runtime(folder,"target-container-inspect-start.json").equals(runtime(folder,"target-container-inspect-end.json")));
            var entries=context.transcript().list(context.runId());var byId=new HashMap<String,TranscriptEntry>();
            for(var e:entries) {require(context.runId().equals(e.runId())&&e.id().matches("tx_[0-9A-HJKMNP-TV-Z]{26}")&&byId.put(e.id(),e)==null);
                if(e.decodedSamlRef()!=null)require(("transcripts/"+context.runId()+"/"+e.id()+".saml.xml").equals(e.decodedSamlRef())&&content.readDecodedSaml(e).length==e.decodedSamlBytes());}
            var audit=new HashMap<String,String[]>();for(var line:new String(original(folder,"native-request-bound-audit.log"),StandardCharsets.UTF_8).lines().toList()) {
                var fields=line.split("\\|",-1);require(fields.length==7&&"SAMLscope-G02-known-v1".equals(fields[0])&&audit.put(fields[1],fields)==null);}
            var exchanges=manifest.path("exchanges");require(exchanges.isArray()&&exchanges.size()==2);var normal=manifest.path("normalControl");require(normal.isObject());
            var rows=new ArrayList<JsonNode>();rows.add(normal);exchanges.forEach(rows::add);
            var selected=new HashSet<String>();var formats=new HashSet<String>();var evidence=new LinkedHashSet<EvidenceRef>();var mismatches=0;
            var signing=certificates(sp,"signing");var encryption=certificates(sp,"encryption");var targetKeys=MetadataAlgorithmEvidence.signingKeys(target);
            for(var row:rows) {
                var isControl=row==normal;
                var request=byId.get(text(row,"requestReference"));var response=byId.get(text(row,"responseReference"));require(request!=null&&response!=null&&selected.add(request.id())&&selected.add(response.id()));
                require(request.direction()==Direction.OUTBOUND&&response.direction()==Direction.INBOUND&&"POST".equals(request.method())&&"POST".equals(response.method())&&(isControl?"IIP-SSO07-b-idp-01":"IIP-G02-a-idp-01").equals(request.samlSummary().get("scenario_case_id")));
                require(!request.timestamp().isBefore(start)&&request.timestamp().isBefore(response.timestamp())&&!response.timestamp().isAfter(end));
                var req=SecureXml.parse(content.readDecodedSaml(request)).getDocumentElement();require(P.equals(req.getNamespaceURI())&&"AuthnRequest".equals(req.getLocalName())&&"2.0".equals(req.getAttribute("Version")));
                require(("_"+request.correlationId()).equals(req.getAttribute("ID"))&&request.correlationId().equals(request.samlSummary().get("action_id"))&&req.getAttribute("ID").equals(response.correlationId()));
                var verifier=new XmlSignatureVerifier();require(verifier.hasValidEnvelopedReferenceDigests(req)&&signing.stream().anyMatch(c->verifier.hasValidEnvelopedSignature(req,c)));
                require(single(req,S,"Issuer").getTextContent().equals(entity));
                var roles=MetadataAlgorithmEvidence.children(target,MD,"IDPSSODescriptor");require(roles.size()==1&&MetadataAlgorithmEvidence.children(roles.getFirst(),MD,"SingleSignOnService").stream().anyMatch(e->"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST".equals(e.getAttribute("Binding"))&&req.getAttribute("Destination").equals(e.getAttribute("Location"))));
                if(isControl)require(MetadataAlgorithmEvidence.children(req,S,"Subject").isEmpty()&&"baseline-success".equals(request.samlSummary().get("fixture_id")));
                else {var requested=single(single(req,S,"Subject"),S,"NameID");require(value.equals(requested.getTextContent()));
                    require(Set.of("urn:oasis:names:tc:SAML:2.0:nameid-format:persistent","urn:oasis:names:tc:SAML:2.0:nameid-format:transient").contains(requested.getAttribute("Format"))&&formats.add(requested.getAttribute("Format")));}
                // The explicit different-format NameIDPolicy exception is outside this counterexample.
                if(!isControl)require(MetadataAlgorithmEvidence.children(req,P,"NameIDPolicy").isEmpty());
                var fields=audit.get(req.getAttribute("ID"));require(fields!=null&&entity.equals(fields[2])&&principal.equals(fields[3])&&"Success".equals(fields[4])&&"POST".equals(fields[5])&&"http://shibboleth.net/ns/profiles/saml2/sso/browser".equals(fields[6]));
                var recipient=req.getAttribute("AssertionConsumerServiceURL");require(!recipient.isBlank()&&MetadataAlgorithmEvidence.children(single(sp,MD,"SPSSODescriptor"),MD,"AssertionConsumerService").stream().anyMatch(e->recipient.equals(e.getAttribute("Location"))));
                var key=keys.keyFor(context.runId()).orElseThrow();Element assertion=null;
                for(var cert:encryption)try {assertion=VerifiedResponseAssertion.read(SecureXml.parse(content.readDecodedSaml(response)).getDocumentElement(),target.getAttribute("entityID"),targetKeys,sp,Optional.of(new PlanCredentials(key,cert)),req.getAttribute("ID"),recipient);break;}catch(IllegalArgumentException ignored){}
                require(assertion!=null&&MetadataAlgorithmEvidence.children(assertion,DS,"Signature").size()==1);
                var returned=single(single(assertion,S,"Subject"),S,"NameID");
                // Qualifier omission/default equivalence needs canonical semantics. Only an
                // unequal decrypted identifier value is decisive for this native counterexample.
                require(!returned.getTextContent().isBlank());if(!isControl&&decisiveMismatch(req,returned))mismatches++;
                evidence.add(new EvidenceRef("transcript",request.id()));evidence.add(new EvidenceRef("transcript",response.id()));
            }
            require(mismatches>0);
            evidence.add(new EvidenceRef("native-subject-match-evidence",context.runId()+"/manifest.json#"+hash(original(folder,"manifest.json"))));
            return Optional.of(new CaseOutcome(Outcome.VIOLATED,null,REASON,REASON,List.copyOf(evidence),Map.of("adapter",ADAPTER,"run_id",context.runId(),"strong_match_counterexamples",mismatches,"known_principal_proven",true,"different_format_policy_exception",false)));
        }catch(Exception unproven){return Optional.empty();}
    }
    static boolean stronglyMatches(Element a,Element b){return Objects.equals(a.getNamespaceURI(),b.getNamespaceURI())&&Objects.equals(a.getLocalName(),b.getLocalName())&&a.getTextContent().equals(b.getTextContent())&&attributes(a).equals(attributes(b));}
    static boolean decisiveMismatch(Element request,Element returned) {
        if(!MetadataAlgorithmEvidence.children(request,P,"NameIDPolicy").isEmpty())return false;
        var requested=single(single(request,S,"Subject"),S,"NameID");
        return !requested.getTextContent().equals(returned.getTextContent());
    }
    private static Map<String,String> attributes(Element e){var result=new TreeMap<String,String>();var attrs=e.getAttributes();for(int i=0;i<attrs.getLength();i++){var a=attrs.item(i);if(!"http://www.w3.org/2000/xmlns/".equals(a.getNamespaceURI()))result.put(String.valueOf(a.getNamespaceURI())+"|"+a.getLocalName(),a.getNodeValue());}return result;}
    private void nativeConfiguration(Path folder,String value,String principal,String entity)throws Exception {
        var root=SecureXml.parse(original(folder,"configured-c14n.xml")).getDocumentElement();
        var flows=byId(root,U,"list","shibboleth.SAMLSubjectCanonicalizationFlows");require(MetadataAlgorithmEvidence.children(flows,B,"ref").stream().map(e->e.getAttribute("bean")).toList().equals(List.of("c14n/SAML2Transform","c14n/SAML2Transient","c14n/SAML2CryptoTransient","c14n/SAML1Transient","c14n/SAML1CryptoTransient","c14n/SAML1Transform")));
        var formats=byId(root,U,"list","shibboleth.NameTransformFormats");var names=MetadataAlgorithmEvidence.children(formats,B,"value").stream().map(Element::getTextContent).toList();require(names.equals(List.of("urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified","urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress","urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName","urn:oasis:names:tc:SAML:1.1:nameid-format:WindowsDomainQualifiedName","urn:oasis:names:tc:SAML:2.0:nameid-format:kerberos","urn:oasis:names:tc:SAML:2.0:nameid-format:persistent","urn:oasis:names:tc:SAML:2.0:nameid-format:transient")));
        var predicate=byId(root,B,"bean","shibboleth.NameTransformPredicate");require("shibboleth.Conditions.RelyingPartyId".equals(predicate.getAttribute("parent")));var candidates=single(single(predicate,B,"constructor-arg"),B,"list");require(MetadataAlgorithmEvidence.children(candidates,B,"value").size()==1&&entity.equals(single(candidates,B,"value").getTextContent()));
        var transform=single(byId(root,U,"list","shibboleth.NameTransforms"),B,"bean");require("shibboleth.Pair".equals(transform.getAttribute("parent"))&&("^"+value+"$").equals(transform.getAttributeNS(PROP,"first"))&&principal.equals(transform.getAttributeNS(PROP,"second")));
        var audit=SecureXml.parse(original(folder,"configured-audit.xml")).getDocumentElement();var entries=MetadataAlgorithmEvidence.children(byId(audit,U,"map","shibboleth.AuditFormattingMap"),B,"entry");require(entries.size()==1&&"Shibboleth-Audit".equals(entries.getFirst().getAttribute("key"))&&"SAMLscope-G02-known-v1|%I|%SP|%u|%S|%b|%P".equals(entries.getFirst().getAttribute("value")));
        var jar=original(folder,"native-idp-conf-impl.jar");require(SOURCE.equals(hash(jar)));byte[] system=null;try(var zip=new ZipInputStream(new java.io.ByteArrayInputStream(jar))){for(var e=zip.getNextEntry();e!=null;e=zip.getNextEntry())if(e.getName().equals("net/shibboleth/idp/conf/subject-c14n-system.xml")){system=zip.readAllBytes();break;}}
        require(system!=null);var nativeBean=byId(SecureXml.parse(system).getDocumentElement(),B,"bean","c14n/SAML2Transform");require("net.shibboleth.idp.saml.nameid.impl.NameIDCanonicalization".equals(nativeBean.getAttribute("class"))&&nativeBean.getAttributeNS(PROP,"activationCondition").contains("shibboleth.NameTransformPredicate")&&nativeBean.getAttributeNS(PROP,"formats").contains("shibboleth.NameTransformFormats"));
        var restoration=json(folder,"restoration.json");require(restoration.path("restored").asBoolean()&&restoration.path("errors").isArray()&&restoration.path("errors").isEmpty());
        for(var kind:List.of("c14n","audit")){var original=original(folder,"original-"+kind+".xml");require(Arrays.equals(original,original(folder,"final-"+kind+".xml"))&&hash(original).equals(text(restoration.path("original"),kind))&&hash(original).equals(text(restoration.path("final"),kind)));}
    }
    private Instant readBack(Path folder,String phase)throws Exception {var row=json(folder,phase+"-readback.json");for(var kind:List.of("c14n","audit")){var entry=row.path("files").path(kind);var raw=original(folder,text(entry,"file"));require(Arrays.equals(raw,original(folder,"configured-"+kind+".xml"))&&hash(raw).equals(text(entry,"sha256")));}return Instant.parse(text(row,"recordedAt"));}
    private String runtime(Path folder,String file)throws Exception {var rows=json(folder,file);require(rows.isArray()&&rows.size()==1);var row=rows.get(0);require(IMAGE.equals(text(row,"Image"))&&row.path("State").path("Running").asBoolean()&&row.path("Mounts").isArray()&&row.path("Mounts").isEmpty());return text(row,"Id")+"|"+text(row.path("State"),"StartedAt")+"|"+text(row,"Image");}
    private static Element single(Element e,String ns,String local){var values=MetadataAlgorithmEvidence.children(e,ns,local);require(values.size()==1);return values.getFirst();}
    private static Element byId(Element e,String ns,String local,String id){var values=MetadataAlgorithmEvidence.children(e,ns,local).stream().filter(n->id.equals(n.getAttribute("id"))).toList();require(values.size()==1);return values.getFirst();}
    private static List<X509Certificate> certificates(Element e,String purpose)throws Exception {var result=new ArrayList<X509Certificate>();for(var key:MetadataAlgorithmEvidence.children(single(e,MD,"SPSSODescriptor"),MD,"KeyDescriptor")){if(!Set.of("",purpose).contains(key.getAttribute("use")))continue;for(var info:MetadataAlgorithmEvidence.children(key,DS,"KeyInfo"))for(var data:MetadataAlgorithmEvidence.children(info,DS,"X509Data"))for(var cert:MetadataAlgorithmEvidence.children(data,DS,"X509Certificate"))result.add((X509Certificate)CertificateFactory.getInstance("X.509").generateCertificate(new java.io.ByteArrayInputStream(Base64.getMimeDecoder().decode(cert.getTextContent()))));}require(!result.isEmpty());return result;}
    private JsonNode json(Path folder,String file)throws Exception{return new JsonCodec().mapper().readTree(original(folder,file));}
    private byte[] original(Path folder,String file)throws Exception {require(!file.isBlank()&&!file.contains("\\"));var path=folder.resolve(file).normalize();require(path.startsWith(folder)&&!path.equals(folder)&&file.equals(folder.relativize(path).toString()));safeParents(path.getParent());require(Files.isRegularFile(path,LinkOption.NOFOLLOW_LINKS)&&Files.size(path)>0&&Files.size(path)<=20*1024*1024);return Files.readAllBytes(path);}
    private static void safeParents(Path p){for(var parent=p;parent!=null;parent=parent.getParent())require(!Files.isSymbolicLink(parent));}
    private static String text(JsonNode n,String field){var value=n.path(field);require(value.isTextual()&&!value.asText().isBlank());return value.asText();}
    private static String hash(byte[] b)throws Exception{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(b));}
    private static void require(boolean b){if(!b)throw new IllegalArgumentException("Native requested Subject match unproven");}
}
