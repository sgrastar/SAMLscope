package com.samlscope.runner.cases;

import com.fasterxml.jackson.databind.JsonNode;
import com.samlscope.core.caseexec.CaseContext;
import com.samlscope.core.evaluation.EvidenceRef;
import com.samlscope.core.transcript.*;
import com.samlscope.saml.normal.SecureXml;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Instant;
import java.util.*;
import org.w3c.dom.Element;
import static com.samlscope.runner.cases.DefaultAlgorithmPreventionEvidence.*;

/** Stock selected Shibboleth consumers, unchanged policy, and request-bound native originals. */
public final class ShibbolethDefaultAlgorithmNativeAdapter implements DefaultAlgorithmNativeAdapter {
    public static final String ADAPTER="shibboleth-native-default-algorithm-consumers-v1";
    static final String SCOPE="samlscope-shibboleth-default-security-scope-v1";
    static final String USE="samlscope-shibboleth-default-algorithm-use-v1";
    static final String PROFILE="http://shibboleth.net/ns/profiles/saml2/sso/browser";
    static final String LOGOUT="http://shibboleth.net/ns/profiles/saml2/logout";
    static final String FORMAT="SAMLscope-default-algorithm-v1|%I|%SP|%e|%S|%XX|%b|%P|%T|%n|%f|%SPQ|%x";
    static final String BEANS="http://www.springframework.org/schema/beans";
    static final String UTIL="http://www.springframework.org/schema/util";
    static final String AUDIT_CONTEXT_CLASS_SHA256="ef244678b797d5a25653ca5a1a323f9ee5c8ec45bcf5db28555443a55689eaf3";
    static final String CIPHER_SOURCE_SHA256="c6a0511b0b481621239f5bb04fb11f6ca951cd1b9f66c74fae93ee53bb53e8c3";
    static final String CALIBRATION_SOURCE_SHA256="027312995daaca8f7b91e4dc1978111abeec505daf73ed5b3cd4c33e94536000";
    static final String CALIBRATION="samlscope-shibboleth-default-algorithm-calibration-v1",STOCK="stock-policy",MUTANT="developer-missing-default-prevention";
    static final Map<String,String> CALIBRATION_CLASSES=Map.of(
            "org.opensaml.xmlsec.signature.support.impl.SignatureAlgorithmValidator","edff38aa74c00b0c8ddca18673c9145fa2197e081d9774320ef8469909e24560",
            "org.opensaml.xmlsec.config.impl.DefaultSecurityConfigurationBootstrap","96651fd0ab10a3c15e69bf5a40641392e2640e7a5668ee2f258ffaa082508716");
    static final Map<String,String> CONFIG=Map.of(
            "global.xml","ca08485a1b5ef8cf0ac1afb80ff066237759e4fb3d884d087f905d8ca0918bcc",
            "services.xml","0c5de788ebc611af60ebb3bf4071dcd23744f599d64d65bdb0744515d11a77c0",
            "relying-party.xml","64e2a04dfbf2ffa2a582b995bcbf121b634ab7c8766cb8f22d3397d541f31bd5");
    static final Map<String,String> JARS=Map.of(
            "idp-conf-impl","428e389d88bb2abcad19d69bcf759af29f7ce6beb776ccfaa5a6ea76751682ba",
            "idp-profile-impl","aaa769a9ccdfb1428173e3932d598ced0302908fab3b8bfe2100331678c9f405",
            "idp-saml-impl","1a2a9f867d11c50eeaf2a6140bb5de88b0611d694ea6de2bbfe32f72a4a2998b",
            "opensaml-saml-impl","9f04221e172dc426f90fb3873d0148a0744edbf9e7a37de7ee0e6a34f7b74581",
            "opensaml-xmlsec-impl","cc67fc1bd9cb435cdbe7483ef04513c83cc9619a3015c04ad41bb6cc0eb6e68e",
            "opensaml-xmlsec-api","3401e9e309fd170f4b9ea0d8fc68b5b778c2374bf654371378bce21952d6c6b9",
            "opensaml-profile-impl","ed65b8524022fd870b588fedb994a7c4b2f0e4fe63a5d62085ca7c419f6a751f");
    static final Map<String,String> RSA15_CONSUMER_CLASSES=Map.of(
            "org.opensaml.xmlsec.algorithm.AlgorithmSupport","d577368d095f9a187faa5e4ae861f0a5c6d74f9e65b1fee103a3ac9bfb823c0f",
            "org.opensaml.xmlsec.encryption.support.Decrypter","2cc6d250c7b860ffd3661de6f3a77e8ffd3590c273ff6e9bc1a1aa369f5be444",
            "org.opensaml.saml.saml2.profile.impl.DecryptNameIDs","abc1ccd555b2249e0e6eb482fe0e0ad0f67c85ce3026a7deaa0b3b9b90e99188",
            "org.opensaml.profile.action.impl.LogEvent","961f8280d97c2e756911dfff6eadcd9ab0aee60e6ed63b66ad5071d00af5f822");
    static final Map<String,String> MD5_CONSUMER_CLASSES=Map.of(
            "org.opensaml.xmlsec.algorithm.AlgorithmSupport","d577368d095f9a187faa5e4ae861f0a5c6d74f9e65b1fee103a3ac9bfb823c0f",
            "org.opensaml.xmlsec.signature.support.impl.BaseSignatureTrustEngine","90d26c6e68355601f521be68420cf51dc777e6051b8bb213058c586a7ee28382",
            "org.opensaml.saml.common.binding.security.impl.SAMLProtocolMessageXMLSignatureSecurityHandler","b37276d78f06d8267835574c1c170f951dbc43c62290ea8a8c4df62e22fa9643",
            "org.opensaml.profile.action.impl.LogEvent","961f8280d97c2e756911dfff6eadcd9ab0aee60e6ed63b66ad5071d00af5f822");
    private final TranscriptContentReader content;
    private final boolean offlineCalibrationAllowed;
    public ShibbolethDefaultAlgorithmNativeAdapter(TranscriptContentReader content){this(content,false);}
    /** Only the isolated developer replay may select instrumented counterfactual originals. */
    ShibbolethDefaultAlgorithmNativeAdapter(TranscriptContentReader content,boolean offlineCalibrationAllowed){this.content=Objects.requireNonNull(content);this.offlineCalibrationAllowed=offlineCalibrationAllowed;}
    @Override public String adapter(){return ADAPTER;}
    @Override public Optional<Preparation> prepare(CaseContext context,Path folder,JsonNode m,byte[] target,byte[] suite)throws Exception {
        var before=nativeRecord(context,m,"beforeScope",SCOPE);var scope=scope(folder,before,"before",context.runId(),SecureXml.parse(suite).getDocumentElement().getAttribute("entityID"));
        require(hash(target).equals(text(m,"targetMetadataSha256"))&&hash(suite).equals(text(m,"suiteMetadataSha256")));
        registration(folder,m,context.runId(),scope.path("entityId").textValue(),suite);
        var registered=nativeRecord(context,m,"registration","samlscope-shibboleth-default-metadata-registration-v1");
        require(text(m,"suiteMetadataSha256").equals(text(registered,"suiteMetadataSha256"))&&text(m,"targetMetadataSha256").equals(text(registered,"targetMetadataSha256"))
                &&scope.path("entityId").textValue().equals(text(registered,"entityId"))&&registered.path("query").equals(json(original(folder,"native-metadata-query.json"))));
        return Optional.of(new Preparation(policy(scope),true,List.of(reference(m,"beforeScope"),reference(m,"registration"))));
    }
    @Override public Session open(CaseContext context,Path folder,JsonNode m,byte[] target,byte[] suite)throws Exception {
        require(m.path("counterfactualCalibrationOnly").isBoolean()&&(!m.path("counterfactualCalibrationOnly").booleanValue()||offlineCalibrationAllowed));
        String entity=SecureXml.parse(suite).getDocumentElement().getAttribute("entityID");
        var before=scope(folder,nativeRecord(context,m,"beforeScope",SCOPE),"before",context.runId(),entity);
        var after=scope(folder,nativeRecord(context,m,"afterScope",SCOPE),"after",context.runId(),entity);
        for(String name:List.of("runtime","classpath","propertiesSha256","selectedProperties","xmlSha256","overrideSourceInventory"))require(before.path(name).equals(after.path(name)));
        for(String profile:List.of("browser","logout"))require(Arrays.equals(original(folder,text(before.path("profileFiles"),profile)),original(folder,text(after.path("profileFiles"),profile))));
        require(!instant(after,"startedAt").isBefore(instant(before,"completedAt")));
        restoration(folder,m);registration(folder,m,context.runId(),entity,suite);
        var refs=List.of(reference(m,"beforeScope"),reference(m,"afterScope"));
        return new NativeSession(context,folder,m,before,after,entity,hash(suite),target,policy(before),refs);
    }
    private JsonNode nativeRecord(CaseContext c,JsonNode parent,String prefix,String schema)throws Exception {
        String ref=text(parent,prefix+"Reference");var entries=c.transcript().list(c.runId()).stream().filter(e->ref.equals(e.id())).toList();require(entries.size()==1);
        var entry=entries.getFirst();require(c.runId().equals(entry.runId())&&entry.decodedSamlRef()!=null
                &&("transcripts/"+c.runId()+"/"+entry.id()+".saml.xml").equals(entry.decodedSamlRef()));
        byte[] raw=content.readDecodedSaml(entry);require(hash(raw).equals(text(parent,prefix+"Sha256")));var value=json(raw);
        require(schema.equals(text(value,"schema"))&&c.runId().equals(text(value,"runId")));return value;
    }
    private static EvidenceRef reference(JsonNode m,String name){return new EvidenceRef("transcript",text(m,name+"Reference"));}
    static JsonNode scope(Path folder,JsonNode s,String phase,String run,String entity)throws Exception {
        require(SCOPE.equals(text(s,"schema"))&&run.equals(text(s,"runId"))&&entity.equals(text(s,"entityId"))&&phase.equals(text(s,"phase")));
        require(!instant(s,"completedAt").isBefore(instant(s,"startedAt")));
        require(s.path("runtime").path("running").isBoolean()&&s.path("runtime").path("running").booleanValue()
                &&text(s.path("runtime"),"containerId").matches("[0-9a-f]{64}")&&"sha256:3c1b1fa64c58258aefc9e38d4ae60e9f0340731318a472110ea56ce88c18a11a".equals(text(s.path("runtime"),"image"))
                &&s.path("runtime").path("mounts").isArray()&&s.path("runtime").path("mounts").isEmpty());
        require(s.path("overrideSourceInventory").isArray()&&s.path("overrideSourceInventory").isEmpty()
                &&Boolean.TRUE.equals(s.path("nativeJavaProcessObserved").booleanValue())&&!s.path("algorithmProcessOverridePresent").asBoolean(true)
                &&s.path("privateFieldsExported").isBoolean()&&!s.path("privateFieldsExported").booleanValue());
        var fileNames=s.path("files").fieldNames();while(fileNames.hasNext()){String file=fileNames.next();require(hash(original(folder,file)).equals(text(s.path("files"),file)));}
        for(var entry:CONFIG.entrySet())require(hash(original(folder,text(s.path("configurations"),entry.getKey()))).equals(entry.getValue()));
        for(var entry:JARS.entrySet()) {
            require(hash(original(folder,text(s.path("jars"),entry.getKey()))).equals(entry.getValue()));
            require(entry.getValue().equals(text(s.path("classpath"),"/usr/local/tomcat/webapps/idp/WEB-INF/lib/"+entry.getKey()+"-5.2.3.jar")));
        }
        validateAuditFormatter(original(folder,text(s.path("jars"),"idp-profile-impl")),original(folder,text(s.path("jars"),"idp-conf-impl")));
        require(s.path("propertiesSha256").isObject()&&!s.path("propertiesSha256").isEmpty()&&s.path("xmlSha256").isObject()&&!s.path("xmlSha256").isEmpty());
        require("cc02dbb4817127ec83d838fe15113dd165e9e0d55bcc8d9638c3733cc37e21cd".equals(hash(new com.samlscope.store.JsonCodec().mapper().writeValueAsBytes(new TreeMap<>(new com.samlscope.store.JsonCodec().mapper().convertValue(s.path("classpath"),new com.fasterxml.jackson.core.type.TypeReference<Map<String,String>>(){}))))));
        var selected=s.path("selectedProperties");require(selected.isObject());
        require(!selected.has("idp.security.config")||"shibboleth.DefaultSecurityConfiguration".equals(text(selected,"idp.security.config")));
        require(!selected.has("idp.additionalProperties")||"/credentials/secrets.properties".equals(text(selected,"idp.additionalProperties")));
        require(!selected.has("idp.service.relyingparty.resources"));
        for(var profile:Map.of("browser",PROFILE,"logout",LOGOUT).entrySet()) {
            var p=json(original(folder,text(s.path("profileFiles"),profile.getKey())));
            require("shibboleth.DefaultSecurityConfiguration".equals(text(p.path("RelyingPartyConfiguration"),"securityConfiguration"))
                    &&profile.getValue().equals(text(p.path("ProfileConfiguration"),"id")));
        }
        return s;
    }
    static String policy(JsonNode s)throws Exception {
        var selected=new TreeMap<String,JsonNode>();for(String key:List.of("classpath","propertiesSha256","selectedProperties","xmlSha256"))selected.put(key,s.path(key));
        return "native-stock-default:"+hash(new com.samlscope.store.JsonCodec().mapper().writeValueAsBytes(selected));
    }
    static void registration(Path folder,JsonNode m,String run,String entity,byte[] suite)throws Exception {
        require(Arrays.equals(suite,original(folder,text(m,"registeredSuiteMetadataFile"))));
        for(String name:List.of("providers","audit","logback"))require(Arrays.equals(original(folder,"configured-"+name+".xml"),original(folder,text(m,"prepared"+name+"ReadBackFile"))));
        validateLogback(original(folder,"original-logback.xml"),original(folder,"configured-logback.xml"));
        var audit=SecureXml.parse(original(folder,"configured-audit.xml")).getDocumentElement();var formats=audit.getElementsByTagNameNS(BEANS,"entry");int matched=0;
        for(int i=0;i<formats.getLength();i++){var e=(Element)formats.item(i);if("Shibboleth-Audit".equals(e.getAttribute("key"))){require(FORMAT.equals(e.getAttribute("value")));matched++;}}
        require(matched==1);var originalAudit=SecureXml.parse(original(folder,"original-audit.xml")).getDocumentElement();
        var priorEntries=originalAudit.getElementsByTagNameNS(BEANS,"entry");String priorFormat=null;
        for(int i=0;i<priorEntries.getLength();i++){var e=(Element)priorEntries.item(i);if("Shibboleth-Audit".equals(e.getAttribute("key"))){require(priorFormat==null);priorFormat=e.getAttribute("value");}}
        require(priorFormat!=null);for(int i=0;i<formats.getLength();i++){var e=(Element)formats.item(i);if("Shibboleth-Audit".equals(e.getAttribute("key")))e.setAttribute("value",priorFormat);}
        require(structureFingerprint(audit).equals(structureFingerprint(originalAudit)));String source="/opt/reference-idp/metadata/default-algorithm-"+run+".xml";
        var configured=SecureXml.parse(original(folder,"configured-providers.xml")).getDocumentElement();
        var providers=configured.getElementsByTagNameNS("urn:mace:shibboleth:2.0:metadata","MetadataProvider");int found=0;
        for(int i=0;i<providers.getLength();i++){var p=(Element)providers.item(i);if(("DefaultAlgorithm"+run).equals(p.getAttribute("id"))){
            require(source.equals(p.getAttribute("metadataFile"))&&"FilesystemMetadataProvider".equals(p.getAttributeNS("http://www.w3.org/2001/XMLSchema-instance","type")))
                    ;require(p.getAttributes().getLength()==3&&children(p,"urn:mace:shibboleth:2.0:metadata","MetadataFilter").isEmpty()
                            &&p.getElementsByTagName("*").getLength()==0&&p.getParentNode()==configured);
            Element first=null;for(var node=configured.getFirstChild();node!=null;node=node.getNextSibling())if(node instanceof Element element){first=element;break;}require(first==p);
            configured.removeChild(p);found++;}}
        require(found==1&&structureFingerprint(configured).equals(structureFingerprint(SecureXml.parse(original(folder,"original-providers.xml")).getDocumentElement())));
        var accepted=json(original(folder,"native-metadata-query.json"));
        require(entity.equals(text(accepted,"entityId"))&&accepted.path("exitCode").isInt()&&accepted.path("exitCode").intValue()==0
                &&hash(original(folder,text(accepted,"stdoutFile"))).equals(text(accepted,"stdoutSha256")));
        var effective=SecureXml.parse(original(folder,text(accepted,"stdoutFile"))).getDocumentElement();
        require(entity.equals(effective.getAttribute("entityID")));
        validateNativeMetadataReadBack(suite,original(folder,text(accepted,"stdoutFile")));
    }
    /**
     * Compare the stock mdquery public model with the original, separately verified signed
     * document. Its marshaller prints expiration at millisecond precision and may omit the
     * root signature's mathematical values. Neither conversion is evidence of signature or
     * expiration enforcement; all metadata meanings and signature structure must still match.
     */
    static void validateNativeMetadataReadBack(byte[] registered,byte[] readBack) {
        var expected=SecureXml.parse(registered).getDocumentElement();
        var actual=SecureXml.parse(readBack).getDocumentElement();
        structure(expected,MD,"EntityDescriptor");structure(actual,MD,"EntityDescriptor");
        if(expected.hasAttribute("validUntil")) {
            require(actual.hasAttribute("validUntil"));
            Instant expiry=Instant.parse(expected.getAttribute("validUntil"));
            Instant modelExpiry=Instant.parse(actual.getAttribute("validUntil"));
            require(modelExpiry.equals(expiry)||modelExpiry.equals(expiry.truncatedTo(java.time.temporal.ChronoUnit.MILLIS)));
            expected.setAttribute("validUntil",actual.getAttribute("validUntil"));
        }
        var expectedSignature=single(expected,DS,"Signature");
        var actualSignature=single(actual,DS,"Signature");
        normalizeNativeSignatureValue(single(expectedSignature,DS,"SignatureValue"),single(actualSignature,DS,"SignatureValue"));
        var expectedReferences=children(single(expectedSignature,DS,"SignedInfo"),DS,"Reference");
        var actualReferences=children(single(actualSignature,DS,"SignedInfo"),DS,"Reference");
        require(!expectedReferences.isEmpty()&&expectedReferences.size()==actualReferences.size());
        for(int i=0;i<expectedReferences.size();i++)
            normalizeNativeSignatureValue(single(expectedReferences.get(i),DS,"DigestValue"),single(actualReferences.get(i),DS,"DigestValue"));
        require(structureFingerprint(expected).equals(structureFingerprint(actual)));
    }
    private static void normalizeNativeSignatureValue(Element expected,Element actual) {
        require(!expected.getTextContent().isBlank());
        if(actual.getTextContent().isBlank())expected.setTextContent("");
    }
    static void validateLogback(byte[] original,byte[] configured) {
        String text=new String(original,StandardCharsets.UTF_8);
        String old="%date{ISO8601} - %mdc{idp.remote_addr} - %level [%logger:%line] - %msg%n";
        var tags=List.of("pattern","Pattern").stream()
                .filter(tag->text.contains("<"+tag+">%msg%n</"+tag+">")).toList();
        require(text.contains(old)&&tags.size()==1);
        String tag=tags.getFirst();
        String expected=text.replace(old,"%date{ISO8601,UTC} - %mdc{idp.remote_addr} - %level [%thread] [%logger:%line] - %msg%n")
                .replace("<"+tag+">%msg%n</"+tag+">","<"+tag+">%msg|%thread%n</"+tag+">");
        // Process and warn exception depth only; no extra logger or algorithm-policy change.
        expected=expected.replace("%ex{short}","%ex{full}");
        require(Arrays.equals(expected.getBytes(StandardCharsets.UTF_8),configured));
    }
    static void restoration(Path folder,JsonNode m)throws Exception {
        var r=json(original(folder,text(m,"restorationFile")));require(r.path("restored").isBoolean()&&r.path("restored").booleanValue()
                &&r.path("errors").isArray()&&r.path("errors").isEmpty()&&r.path("original").equals(r.path("final")));
        for(String name:List.of("providers","audit","logback")){require(Arrays.equals(original(folder,"original-"+name+".xml"),original(folder,"final-"+name+".xml")));String nativeName=name.equals("providers")?"metadata-providers":name;
            require(hash(original(folder,"original-"+name+".xml")).equals(text(r.path("original"),"/opt/reference-idp/conf/"+nativeName+".xml")));}
        var readiness=json(original(folder,text(m,"restoredReadinessFile")));require(readiness.path("status").isInt()&&readiness.path("status").intValue()==200);
        var counts=json(original(folder,text(m,"operationCountsFile")));require(counts.path("restored").isBoolean()&&counts.path("restored").booleanValue()
                &&counts.path("credentialPosts").isInt()&&counts.path("credentialPosts").intValue()==1
                &&counts.path("personOperations").isInt()&&counts.path("personOperations").intValue()==0);
    }
    private final class NativeSession implements Session {
        final CaseContext context;final Path folder;final JsonNode manifest,before,after;final String entity,suiteHash,targetHash,policy;final Element target;final byte[] targetRaw;final List<EvidenceRef> scopeRefs;
        NativeSession(CaseContext c,Path f,JsonNode m,JsonNode b,JsonNode a,String e,String suite,byte[] targetBytes,String p,List<EvidenceRef> refs)throws Exception{context=c;folder=f;manifest=m;before=b;after=a;entity=e;suiteHash=suite;targetHash=hash(targetBytes);targetRaw=targetBytes.clone();target=SecureXml.parse(targetBytes).getDocumentElement();policy=p;scopeRefs=refs;}
        @Override public Use validate(JsonNode row,String fixture,Element request,byte[] raw,Element response,Element name,List<String> indexes)throws Exception {
            var nativeUse=nativeRecord(context,row,"nativeUse",USE);String requestId=request.getAttribute("ID");
            require(fixture.equals(text(nativeUse,"fixtureId"))&&entity.equals(text(nativeUse,"entityId"))
                    &&suiteHash.equals(text(nativeUse,"suiteMetadataSha256"))&&targetHash.equals(text(nativeUse,"targetMetadataSha256"))
                    &&requestId.equals(text(nativeUse,"requestId"))&&hash(raw).equals(text(nativeUse,"requestSha256")));
            if(calibrationSelected(offlineCalibrationAllowed,manifest,nativeUse)) {
                var output=nativeRecord(context,nativeUse,"calibrationOutput",CALIBRATION);
                var decision=calibration(folder,nativeUse,output,context.runId(),fixture,requestId,raw,row,suiteHash,targetHash,before);
                var refs=new ArrayList<>(scopeRefs);refs.add(reference(row,"nativeUse"));refs.add(reference(nativeUse,"calibrationOutput"));
                return new Use("developer-default-calibration:"+policy,"native-SignatureAlgorithmValidator",decision,refs);
            }
            for(String kind:List.of("providers","audit","logback"))for(String phase:List.of("before","after"))
                require(Arrays.equals(original(folder,"configured-"+kind+".xml"),original(folder,text(nativeUse,kind+phase+"File"))));
            require(Arrays.equals(original(folder,text(manifest,"registeredSuiteMetadataFile")),original(folder,text(nativeUse,"metadataSourceFile"))));
            var http=json(original(folder,text(nativeUse,"httpFile")));var begin=clock(folder,text(nativeUse,"clockBeforeFile"));var end=clock(folder,text(nativeUse,"clockAfterFile"));
            require(!instant(http,"startedAt").isBefore(begin.hostEnd())&&!end.hostStart().isBefore(instant(http,"completedAt"))
                    &&!begin.hostStart().isBefore(instant(before,"completedAt"))&&!end.hostEnd().isAfter(instant(after,"startedAt"))
                    &&!end.nativeAt().isBefore(begin.nativeAt())&&requestId.equals(text(http,"requestId"))&&hash(raw).equals(text(http,"requestSha256"))
                    &&"POST".equals(text(http,"requestMethod"))&&request.getAttribute("Destination").equals(text(http,"requestUrl")));
            if("pre-audit-decoder-rejection".equals(nativeUse.path("auditMode").asText())) {
                require("rsa-md5".equals(fixture)&&response==null);
                var output=nativeRecord(context,nativeUse,"unmarshallerOutput",ShibbolethStockUnmarshallerEvidence.SCHEMA);
                String normalReference=ShibbolethStockUnmarshallerEvidence.validate(folder,context,content,nativeUse,output,before,
                    original(folder,text(manifest,"registeredSuiteMetadataFile")),
                    targetRaw,raw,text(row,"requestReference"),
                    http,begin.nativeAt(),end.nativeAt(),begin.hostEnd(),end.hostStart());
                var refs=new ArrayList<>(scopeRefs);refs.add(reference(row,"nativeUse"));refs.add(reference(nativeUse,"unmarshallerOutput"));
                var normalInput=new EvidenceRef("transcript",normalReference);refs.add(normalInput);
                return new Use(policy,"native-SignatureUnmarshaller-secure-validation",Decision.ALGORITHM_REJECTION,refs,
                        new IngressRejectionProof("native-SignatureAlgorithmValidator",normalInput,reference(nativeUse,"unmarshallerOutput")));
            }
            require(!nativeUse.has("unmarshallerOutputReference")&&!nativeUse.has("unmarshallerOutputSha256")
                &&!nativeUse.has("unmarshallerInvocationFile")
                &&(!nativeUse.has("auditMode")||"request-bound-audit".equals(text(nativeUse,"auditMode"))));
            String audit=new String(original(folder,text(nativeUse,"auditFile")),StandardCharsets.UTF_8);var audits=audit.lines().filter(s->!s.isBlank()).map(s->s.split("\\|",-1)).toList();
            require(audits.size()==1);String[] fields=audits.getFirst();require(fields.length==14&&"SAMLscope-default-algorithm-v1".equals(fields[0])
                    &&requestId.equals(fields[1])&&entity.equals(fields[2])&&"POST".equals(fields[6])
                    &&(fixture.contains("encrypted-id")?LOGOUT:PROFILE).equals(fields[7])&&"true".equals(fields[5])&&fields[13].matches("[A-Za-z0-9_.-]+"));
            Instant auditAt=Instant.parse(fields[8]);require(!auditAt.isBefore(begin.nativeAt())&&!auditAt.isAfter(end.nativeAt()));
            var evidence=new ArrayList<>(scopeRefs);evidence.add(reference(row,"nativeUse"));String consumer=fixture.contains("encrypted-id")?"native-DecryptNameIDs":"native-SignatureAlgorithmValidator";
            if(fixture.contains("encrypted-id")) {
                require(name!=null&&!indexes.isEmpty());
                var validated=nativeRecord(context,nativeUse,"cipherInput","samlscope-shibboleth-cipher-input-validation-v1");
                cipherInvocation(folder,context.runId(),fixture,nativeUse,validated,before,raw);
                validateCipherInput(validated,context.runId(),fixture,requestId,raw,target,name);
                evidence.add(reference(nativeUse,"cipherInput"));
            }
            if(response!=null&&SUCCESS.equals(status(response))) {
                require("Success".equals(fields[4])&&fields[3].isBlank());
                if(fixture.contains("encrypted-id")) {
                    require(name.getTextContent().equals(fields[9])
                            &&renderAuditValue(original(folder,"configured-audit.xml"),name.getAttribute("Format")).equals(fields[10])&&name.getAttribute("SPNameQualifier").equals(fields[11])
                            &&indexes.equals(Arrays.asList(fields[12].split(","))));
                }
                return new Use(policy,consumer,Decision.CONSUMED_SUCCESS,evidence);
            }
            String process=new String(original(folder,text(nativeUse,"processLogFile")),StandardCharsets.UTF_8);
            var range=nativeUse.path("processLogRange");require(range.path("beforeOffset").isIntegralNumber()&&range.path("afterOffset").isIntegralNumber()
                    &&range.path("afterOffset").longValue()-range.path("beforeOffset").longValue()==original(folder,text(nativeUse,"processLogFile")).length
                    &&range.path("inode").isIntegralNumber()&&range.path("beforeOffset").longValue()>=0);
            if(fixture.equals("invalid-sha256-signature")) {
                require("MessageAuthenticationError".equals(fields[3])&&(nativeCause(process,fields[13],begin.nativeAt(),end.nativeAt(),"Signature did not validate","Signature validation failed","Signature was invalid")
                        ||nativeSignatureRejection(process,fields[13],begin.nativeAt(),end.nativeAt(),entity)));
                return new Use(policy,consumer,Decision.INVALID_SIGNATURE_REJECTION,evidence);
            }
            String algorithm=switch(fixture){case "md5-digest"->"http://www.w3.org/2001/04/xmldsig-more#md5";case "rsa-md5"->"http://www.w3.org/2001/04/xmldsig-more#rsa-md5";case "rsa15-encrypted-id"->"http://www.w3.org/2001/04/xmlenc#rsa-1_5";default->null;};
            if(fixture.equals("rsa15-encrypted-id")) {
                validateRsa15ConsumerClasses(folder,before);
                if(nativeRsa15Rejection(response,fields[3],fields[4],process,fields[13],begin.nativeAt(),end.nativeAt()))
                    return new Use(policy,consumer,Decision.ALGORITHM_REJECTION,evidence);
                return new Use(policy,consumer,Decision.UNPROVEN,evidence);
            }
            if(fixture.equals("md5-digest")) {
                validateMd5ConsumerClasses(folder,before);
                return new Use(policy,consumer,nativeMd5DigestRejection(fields[3],process,fields[13],begin.nativeAt(),end.nativeAt(),entity)
                        ?Decision.ALGORITHM_REJECTION:Decision.UNPROVEN,evidence);
            }
            String event=fixture.contains("encrypted-id")?"DecryptNameIDFailed":"MessageAuthenticationError";
            if(algorithm!=null&&event.equals(fields[3])&&nativeCause(process,fields[13],begin.nativeAt(),end.nativeAt(),"Algorithm failed include/exclude validation: "+algorithm))
                return new Use(policy,consumer,Decision.ALGORITHM_REJECTION,evidence);
            return new Use(policy,consumer,Decision.UNPROVEN,evidence);
        }
    }
    static boolean calibrationSelected(boolean permitted,JsonNode manifest,JsonNode use) {
        boolean selected=use.has("calibrationOutputReference")||use.has("calibrationOutputSha256")||use.has("calibrationInvocationFile")
                ||use.has("stockCalibrationOutputFile")||use.path("diagnosticOnly").asBoolean(false);
        if(selected)require(permitted&&manifest.path("counterfactualCalibrationOnly").isBoolean()&&manifest.path("counterfactualCalibrationOnly").booleanValue()
                &&use.path("counterfactualCalibrationOnly").isBoolean()&&use.path("counterfactualCalibrationOnly").booleanValue()
                &&use.path("diagnosticOnly").isBoolean()&&use.path("diagnosticOnly").booleanValue());
        else require(!manifest.path("counterfactualCalibrationOnly").asBoolean(true));
        return selected;
    }
    /** The same consumer decision predicate may read a developer fixture only under constructor permission. */
    static Decision calibration(Path folder,JsonNode use,JsonNode output,String run,String fixture,String requestId,byte[] raw,JsonNode row,String suiteHash,String targetHash,JsonNode scope)throws Exception {
        var selected=calibrationOutput(output,run,MUTANT,suiteHash,targetHash);
        var stock=json(original(folder,text(use,"stockCalibrationOutputFile")));
        require(hash(original(folder,text(use,"stockCalibrationOutputFile"))).equals(text(use,"stockCalibrationOutputSha256")));
        calibrationOutput(stock,run,STOCK,suiteHash,targetHash);
        calibrationInvocation(folder,use,output,run,MUTANT,"calibrationInvocationFile",scope);
        calibrationInvocation(folder,use,stock,run,STOCK,"stockCalibrationInvocationFile",scope);
        require(text(output,"inputSha256").equals(text(stock,"inputSha256"))&&output.path("stockExcludedAlgorithms").equals(stock.path("stockExcludedAlgorithms")));
        var actual=uniqueCalibrationRow(selected,fixture);var prior=uniqueCalibrationRow(stock.path("records"),fixture);
        for(var result:List.of(actual,prior))require(requestId.equals(text(result,"requestId"))&&hash(raw).equals(text(result,"requestSha256")));
        require(actual.path("mathematicalSignatureValid").equals(prior.path("mathematicalSignatureValid")));
        return calibrationDecision(actual,prior,fixture,row.path("responseSha256").isTextual()?row.path("responseSha256").textValue():null);
    }
    static Decision calibrationDecision(JsonNode actual,JsonNode stock,String fixture,String responseSha) {
        require(Set.of("sha256-control","invalid-sha256-signature","md5-digest","rsa-md5").contains(fixture));
        for(var value:List.of(actual,stock))for(String field:List.of("mathematicalSignatureValid","nativeAlgorithmPolicyAccepted","selectedConsumerAccepted"))require(value.path(field).isBoolean());
        boolean mathematical=actual.path("mathematicalSignatureValid").booleanValue();
        require(stock.path("mathematicalSignatureValid").booleanValue()==mathematical
                &&actual.path("selectedConsumerAccepted").booleanValue()==(mathematical&&actual.path("nativeAlgorithmPolicyAccepted").booleanValue())
                &&stock.path("selectedConsumerAccepted").booleanValue()==(mathematical&&stock.path("nativeAlgorithmPolicyAccepted").booleanValue()));
        if(fixture.equals("invalid-sha256-signature")) {
            require(!mathematical&&!actual.path("selectedConsumerAccepted").booleanValue()&&!stock.path("selectedConsumerAccepted").booleanValue()
                    &&actual.path("nativeAlgorithmPolicyAccepted").booleanValue()&&stock.path("nativeAlgorithmPolicyAccepted").booleanValue()
                    &&responseSha==null&&!actual.has("responseBase64")&&!stock.has("responseBase64"));return Decision.INVALID_SIGNATURE_REJECTION;
        }
        require(mathematical&&actual.path("nativeAlgorithmPolicyAccepted").booleanValue()&&actual.path("selectedConsumerAccepted").booleanValue());
        if(fixture.equals("sha256-control"))require(stock.path("nativeAlgorithmPolicyAccepted").booleanValue()&&stock.path("selectedConsumerAccepted").booleanValue());
        else require(!stock.path("nativeAlgorithmPolicyAccepted").booleanValue()&&!stock.path("selectedConsumerAccepted").booleanValue()
                &&text(stock,"nativeAlgorithmPolicyError").contains("Algorithm failed include/exclude validation"));
        require(responseSha!=null&&responseSha.equals(text(actual,"responseSha256")));
        try{require(responseSha.equals(hash(Base64.getDecoder().decode(text(actual,"responseBase64")))));}catch(Exception malformed){throw new IllegalArgumentException("Diagnostic response original unavailable",malformed);}
        return Decision.CONSUMED_SUCCESS;
    }
    static JsonNode calibrationOutput(JsonNode output,String run,String mode,String suiteHash,String targetHash) {
        require(CALIBRATION.equals(text(output,"schema"))&&run.equals(text(output,"runId"))&&mode.equals(text(output,"selectedPath"))
                &&output.path("counterfactualCalibrationOnly").isBoolean()&&output.path("counterfactualCalibrationOnly").booleanValue()==MUTANT.equals(mode)
                &&output.path("diagnosticOnly").isBoolean()&&output.path("diagnosticOnly").booleanValue()
                &&output.path("productFinding").isBoolean()&&!output.path("productFinding").booleanValue()
                &&output.path("privateKeyExported").isBoolean()&&!output.path("privateKeyExported").booleanValue()
                &&CALIBRATION_SOURCE_SHA256.equals(text(output,"producerSourceSha256"))&&suiteHash.equals(text(output,"suiteMetadataSha256"))&&targetHash.equals(text(output,"targetMetadataSha256")));
        require(output.path("nativeClasses").equals(new com.samlscope.store.JsonCodec().mapper().valueToTree(new TreeMap<>(CALIBRATION_CLASSES))));
        var stock=stringSet(output.path("stockExcludedAlgorithms"));var selected=stringSet(output.path("selectedExcludedAlgorithms"));
        var weak=Set.of("http://www.w3.org/2001/04/xmldsig-more#md5","http://www.w3.org/2001/04/xmldsig-more#rsa-md5","http://www.w3.org/2001/04/xmldsig-more#hmac-md5");
        require(stock.containsAll(weak));var expected=new TreeSet<>(stock);if(MUTANT.equals(mode))expected.removeAll(weak);require(expected.equals(selected));
        require(output.path("records").isArray()&&output.path("records").size()==4);var fixtures=new HashSet<String>();
        for(var value:output.path("records"))require(fixtures.add(text(value,"fixtureId")));
        require(fixtures.equals(Set.of("sha256-control","invalid-sha256-signature","md5-digest","rsa-md5")));return output.path("records");
    }
    private static Set<String> stringSet(JsonNode list){require(list.isArray());var set=new TreeSet<String>();for(var v:list)require(v.isTextual()&&!v.textValue().isBlank()&&set.add(v.textValue()));return set;}
    private static JsonNode uniqueCalibrationRow(JsonNode rows,String fixture){JsonNode selected=null;for(var row:rows)if(fixture.equals(text(row,"fixtureId"))){require(selected==null);selected=row;}require(selected!=null);return selected;}
    static void calibrationInvocation(Path folder,JsonNode use,JsonNode output,String run,String mode,String field,JsonNode scope)throws Exception {
        var call=json(original(folder,text(use,field)));String temporary="/tmp/samlscope-default-calibration-"+run;
        require("samlscope-shibboleth-default-calibration-invocation-v1".equals(text(call,"schema"))&&run.equals(text(call,"runId"))&&mode.equals(text(call,"selectedPath"))
                &&call.path("exitCode").isInt()&&call.path("exitCode").intValue()==0&&!instant(call,"completedAt").isBefore(instant(call,"startedAt")));
        var expected=List.of("java","-Dlogback.configurationFile="+temporary+"/logback.xml","-cp",temporary+"/classes:/usr/local/tomcat/webapps/idp/WEB-INF/lib/*","ShibbolethDefaultAlgorithmCalibration",mode,temporary+"/input.json",temporary+"/ShibbolethDefaultAlgorithmCalibration.java");
        require(call.path("command").equals(new com.samlscope.store.JsonCodec().mapper().valueToTree(expected))
                &&hash(original(folder,text(call,"sourceFile"))).equals(CALIBRATION_SOURCE_SHA256)&&CALIBRATION_SOURCE_SHA256.equals(text(call,"sourceSha256")));
        byte[] input=original(folder,text(call,"inputFile")),stdout=original(folder,text(call,"stdoutFile"));
        require(hash(input).equals(text(output,"inputSha256"))&&hash(stdout).equals(text(call,"stdoutSha256"))&&json(stdout).equals(output));
        var arguments=json(input);require(run.equals(text(arguments,"runId"))&&arguments.path("records").isArray()&&arguments.path("records").size()==4);
        require((temporary+"/suite-metadata.xml").equals(text(arguments,"suiteMetadataFile"))
                &&hash(original(folder,"registered-suite-metadata.xml")).equals(text(arguments,"suiteMetadataSha256"))
                &&text(arguments,"suiteMetadataSha256").equals(text(output,"suiteMetadataSha256"))&&text(arguments,"targetMetadataSha256").equals(text(output,"targetMetadataSha256")));
        for(var request:arguments.path("records")) {
            String fixture=text(request,"fixtureId");require((temporary+"/"+fixture+".request.xml").equals(text(request,"requestFile"))
                    &&hash(original(folder,fixture+".request.xml")).equals(text(request,"requestSha256")));
            var checked=uniqueCalibrationRow(output.path("records"),fixture);require(text(checked,"requestId").equals(text(request,"requestId"))&&text(checked,"requestSha256").equals(text(request,"requestSha256")));
        }
        require(text(call,"stderrSha256").equals(hash(new byte[0])));
        var nativeBefore=json(original(folder,text(call,"nativeBeforeFile")));var nativeAfter=json(original(folder,text(call,"nativeAfterFile")));
        require(nativeBefore.equals(nativeAfter)&&text(scope.path("runtime"),"containerId").equals(text(nativeBefore,"containerId"))
                &&text(scope.path("runtime"),"image").equals(text(nativeBefore,"image"))&&nativeBefore.path("running").isBoolean()&&nativeBefore.path("running").booleanValue()
                &&nativeBefore.path("mounts").isArray()&&nativeBefore.path("mounts").isEmpty());
    }
    static Element validateCipherInput(JsonNode value,String run,String fixture,String requestId,byte[] raw,Element target,Element name)throws Exception {
        require("samlscope-shibboleth-cipher-input-validation-v1".equals(text(value,"schema"))&&run.equals(text(value,"runId"))
                &&requestId.equals(text(value,"requestId"))&&hash(raw).equals(text(value,"requestSha256"))
                &&value.path("inputValidationOnly").isBoolean()&&value.path("inputValidationOnly").booleanValue()
                &&value.path("productAlgorithmPolicyEvaluated").isBoolean()&&!value.path("productAlgorithmPolicyEvaluated").booleanValue()
                &&value.path("privateKeyExported").isBoolean()&&!value.path("privateKeyExported").booleanValue()
                &&value.path("authenticatedGcm").isBoolean()&&value.path("authenticatedGcm").booleanValue()
                &&CIPHER_SOURCE_SHA256.equals(text(value,"producerSourceSha256"))
                &&(fixture.equals("rsa15-encrypted-id")?"http://www.w3.org/2001/04/xmlenc#rsa-1_5":"http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p").equals(text(value,"transportAlgorithm")));
        byte[] plaintext=Base64.getDecoder().decode(text(value,"decryptedNameIdBase64"));require(hash(plaintext).equals(text(value,"decryptedNameIdSha256")));
        var clear=SecureXml.parse(plaintext).getDocumentElement();structure(clear,A,"NameID");
        require(structureFingerprint(clear).equals(structureFingerprint(name)));
        boolean found=false;for(var role:children(target,MD,"IDPSSODescriptor"))for(var key:children(role,MD,"KeyDescriptor")) {
            if(!key.getAttribute("use").isBlank()&&!"encryption".equals(key.getAttribute("use")))continue;
            var certs=key.getElementsByTagNameNS(DS,"X509Certificate");for(int i=0;i<certs.getLength();i++) {
                var cert=(java.security.cert.X509Certificate)java.security.cert.CertificateFactory.getInstance("X.509").generateCertificate(new java.io.ByteArrayInputStream(Base64.getDecoder().decode(certs.item(i).getTextContent().replaceAll("\\s+",""))));
                if(hash(cert.getEncoded()).equals(text(value,"nativeEncryptionCertificateSha256"))&&hash(cert.getPublicKey().getEncoded()).equals(text(value,"nativeEncryptionSpkiSha256")))found=true;
            }
        }
        require(found);return clear;
    }
    static void cipherInvocation(Path folder,String run,String fixture,JsonNode use,JsonNode output,JsonNode scope,byte[] request)throws Exception {
        var call=json(original(folder,text(use,"cipherInvocationFile")));String temporary="/tmp/samlscope-default-cipher-"+run;
        require("samlscope-shibboleth-cipher-input-invocation-v1".equals(text(call,"schema"))&&run.equals(text(call,"runId"))&&fixture.equals(text(call,"fixtureId"))
                &&call.path("exitCode").isInt()&&call.path("exitCode").intValue()==0&&!instant(call,"completedAt").isBefore(instant(call,"startedAt")));
        var expected=List.of("java","-cp",temporary+"/classes","ShibbolethDefaultCipherInputValidation",run,temporary+"/"+fixture+".request.xml",temporary+"/ShibbolethDefaultCipherInputValidation.java");
        require(call.path("command").equals(new com.samlscope.store.JsonCodec().mapper().valueToTree(expected))
                &&hash(original(folder,text(call,"sourceFile"))).equals(CIPHER_SOURCE_SHA256)&&CIPHER_SOURCE_SHA256.equals(text(call,"sourceSha256"))
                &&Arrays.equals(request,original(folder,text(call,"inputFile")))) ;
        byte[] stdout=original(folder,text(call,"stdoutFile"));require(hash(stdout).equals(text(call,"stdoutSha256"))&&json(stdout).equals(output));
        require(text(call,"stderrSha256").equals(hash(new byte[0])));
        var nativeBefore=json(original(folder,text(call,"nativeBeforeFile")));var nativeAfter=json(original(folder,text(call,"nativeAfterFile")));
        require(nativeBefore.equals(nativeAfter)&&text(scope.path("runtime"),"containerId").equals(text(nativeBefore,"containerId"))
                &&text(scope.path("runtime"),"image").equals(text(nativeBefore,"image"))&&nativeBefore.path("running").isBoolean()&&nativeBefore.path("running").booleanValue()
                &&nativeBefore.path("mounts").isArray()&&nativeBefore.path("mounts").isEmpty());
    }
    /** A cause from another native request/thread, or outside the actual native clock window, is unusable. */
    static boolean nativeCause(String log,String thread,Instant begin,Instant end,String... causes) {
        var header=java.util.regex.Pattern.compile("^(\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2}[.,]\\d{3}) - [^\\r\\n]*? - (?:WARN|ERROR|INFO|DEBUG) \\[([^]]+)] \\[[^]]+] - .*$");
        boolean selected=false;for(String line:log.lines().toList()) {
            var match=header.matcher(line);if(match.matches()) {
                var time=java.time.LocalDateTime.parse(match.group(1).replace(',','.'),java.time.format.DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss.SSS")).toInstant(java.time.ZoneOffset.UTC);
                // The log explicitly formats UTC. Truncation is bounded by its millisecond precision.
                selected=thread.equals(match.group(2))&&!time.plusMillis(1).isBefore(begin)&&!time.isAfter(end);
            }
            if(selected)for(String cause:causes)if(java.util.regex.Pattern.compile(java.util.regex.Pattern.quote(cause)+"(?=$|[\\s\"\'<>])").matcher(line).find())return true;
        }
        return false;
    }
    /** The stock logout audit may omit errorEvent; only the complete native causal chain closes it. */
    static boolean nativeRsa15Rejection(Element response,String auditError,String auditStatus,String log,
            String thread,Instant begin,Instant end) {
        if(response==null||!P.equals(response.getNamespaceURI())||!"LogoutResponse".equals(response.getLocalName())
                ||!"urn:oasis:names:tc:SAML:2.0:status:Responder".equals(status(response))
                ||!"Responder".equals(auditStatus)||!Set.of("","DecryptNameIDFailed").contains(auditError))return false;
        List<String> loggers=List.of("org.opensaml.xmlsec.algorithm.AlgorithmSupport",
                "org.opensaml.xmlsec.encryption.support.Decrypter",
                "org.opensaml.saml.saml2.profile.impl.DecryptNameIDs","org.opensaml.profile.action.impl.LogEvent");
        List<String> levels=List.of("WARN","ERROR","WARN","WARN");
        List<String> messages=List.of("Algorithm failed exclude list validation: http://www.w3.org/2001/04/xmlenc#rsa-1_5",
                "Failed to decrypt EncryptedKey, valid decryption key could not be resolved",
                "Profile Action DecryptNameIDs: Failure performing decryption",
                "A non-proceed event occurred while processing the request: DecryptNameIDFailed");
        var header=java.util.regex.Pattern.compile("^(\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2}[.,]\\d{3}) - [^\\r\\n]*? - (WARN|ERROR|INFO|DEBUG) \\[([^]]+)] \\[([^]:]+):[0-9]+] - (.*)$");
        int next=0;Instant previous=null;
        for(String line:log.lines().toList()) {
            var match=header.matcher(line);if(!match.matches()||!thread.equals(match.group(3)))continue;
            var time=java.time.LocalDateTime.parse(match.group(1).replace(',','.'),java.time.format.DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss.SSS")).toInstant(java.time.ZoneOffset.UTC);
            if(time.plusMillis(1).isBefore(begin)||time.isAfter(end))continue;
            for(int index=0;index<messages.size();index++)if(loggers.get(index).equals(match.group(4))
                    &&levels.get(index).equals(match.group(2))&&messages.get(index).equals(match.group(5))) {
                if(index!=next||previous!=null&&time.isBefore(previous))return false;
                previous=time;next++;
            }
        }
        return next==messages.size();
    }
    /** Exact stock digest-policy failure, followed by the same request's trust/handler/event chain. */
    static boolean nativeMd5DigestRejection(String auditError,String log,String thread,Instant begin,Instant end,String entity) {
        if(!"MessageAuthenticationError".equals(auditError))return false;
        List<String> loggers=List.of("org.opensaml.xmlsec.algorithm.AlgorithmSupport",
                "org.opensaml.xmlsec.signature.support.impl.BaseSignatureTrustEngine",
                "org.opensaml.saml.common.binding.security.impl.SAMLProtocolMessageXMLSignatureSecurityHandler",
                "org.opensaml.profile.action.impl.LogEvent");
        List<String> messages=List.of("Algorithm failed exclude list validation: http://www.w3.org/2001/04/xmldsig-more#md5",
                "XML signature failed algorithm include/exclude validation",
                "Message Handler: Validation of protocol message signature failed for context issuer '"+entity
                        +"', message type: {urn:oasis:names:tc:SAML:2.0:protocol}AuthnRequest",
                "A non-proceed event occurred while processing the request: MessageAuthenticationError");
        var header=java.util.regex.Pattern.compile("^(\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2}[.,]\\d{3}) - [^\\r\\n]*? - (WARN|ERROR|INFO|DEBUG) \\[([^]]+)] \\[([^]:]+):[0-9]+] - (.*)$");
        int next=0;Instant previous=null;
        for(String line:log.lines().toList()) {
            var match=header.matcher(line);if(!match.matches()||!thread.equals(match.group(3)))continue;
            var time=java.time.LocalDateTime.parse(match.group(1).replace(',','.'),java.time.format.DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss.SSS")).toInstant(java.time.ZoneOffset.UTC);
            if(time.plusMillis(1).isBefore(begin)||time.isAfter(end))continue;
            for(int index=0;index<messages.size();index++)if(loggers.get(index).equals(match.group(4))
                    &&"WARN".equals(match.group(2))&&messages.get(index).equals(match.group(5))) {
                if(index!=next||previous!=null&&time.isBefore(previous))return false;
                previous=time;next++;
            }
        }
        return next==messages.size();
    }
    static void validateMd5ConsumerClasses(Path folder,JsonNode scope)throws Exception {
        for(var entry:MD5_CONSUMER_CLASSES.entrySet()) {
            String group=switch(entry.getKey()) {
                case "org.opensaml.xmlsec.algorithm.AlgorithmSupport"->"opensaml-xmlsec-api";
                case "org.opensaml.xmlsec.signature.support.impl.BaseSignatureTrustEngine"->"opensaml-xmlsec-impl";
                case "org.opensaml.saml.common.binding.security.impl.SAMLProtocolMessageXMLSignatureSecurityHandler"->"opensaml-saml-impl";
                default->"opensaml-profile-impl";
            };
            byte[] jar=original(folder,text(scope.path("jars"),group));
            require(JARS.get(group).equals(hash(jar))&&JARS.get(group).equals(text(scope.path("classpath"),
                    "/usr/local/tomcat/webapps/idp/WEB-INF/lib/"+group+"-5.2.3.jar")));
            require(entry.getValue().equals(hash(jarEntry(jar,entry.getKey().replace('.','/')+".class"))));
        }
    }
    /** Actual code providers are bound to the immutable native scope and its complete classpath. */
    static void validateRsa15ConsumerClasses(Path folder,JsonNode scope)throws Exception {
        for(var entry:RSA15_CONSUMER_CLASSES.entrySet()) {
            String group=entry.getKey().equals("org.opensaml.profile.action.impl.LogEvent")?"opensaml-profile-impl"
                    :entry.getKey().equals("org.opensaml.saml.saml2.profile.impl.DecryptNameIDs")?"opensaml-saml-impl":"opensaml-xmlsec-api";
            byte[] jar=original(folder,text(scope.path("jars"),group));
            require(JARS.get(group).equals(hash(jar))&&JARS.get(group).equals(text(scope.path("classpath"),
                    "/usr/local/tomcat/webapps/idp/WEB-INF/lib/"+group+"-5.2.3.jar")));
            require(entry.getValue().equals(hash(jarEntry(jar,entry.getKey().replace('.','/')+".class"))));
        }
    }
    /** Stock XML verification followed by its protocol handler, for this issuer and native request window. */
    static boolean nativeSignatureRejection(String log,String thread,Instant begin,Instant end,String entity) {
        boolean cryptographicFailure=false;
        String verification="Signature verification failed.";
        String rejection="Message Handler: Validation of protocol message signature failed for context issuer '"+entity
                +"', message type: {urn:oasis:names:tc:SAML:2.0:protocol}AuthnRequest";
        for(String line:log.lines().toList()) {
            if(line.matches(".*\\[org\\.apache\\.xml\\.security\\.signature\\.XMLSignature:[0-9]+] - "+java.util.regex.Pattern.quote(verification))
                    &&nativeCause(line,thread,begin,end,verification))cryptographicFailure=true;
            if(cryptographicFailure&&line.matches(".*\\[org\\.opensaml\\.saml\\.common\\.binding\\.security\\.impl\\.SAMLProtocolMessageXMLSignatureSecurityHandler:[0-9]+] - "+java.util.regex.Pattern.quote(rejection))
                    &&nativeCause(line,thread,begin,end,rejection))return true;
        }
        return false;
    }
    static void validateAuditFormatter(byte[] profileJar,byte[] confJar)throws Exception {
        require(hash(profileJar).equals(JARS.get("idp-profile-impl"))&&hash(confJar).equals(JARS.get("idp-conf-impl")));
        require(hash(jarEntry(profileJar,"net/shibboleth/idp/profile/audit/impl/PopulateAuditContext.class")).equals(AUDIT_CONTEXT_CLASS_SHA256));
        var global=SecureXml.parse(jarEntry(confJar,"net/shibboleth/idp/conf/global-system.xml")).getDocumentElement();
        var beans=global.getElementsByTagNameNS(BEANS,"bean");int found=0;
        for(int i=0;i<beans.getLength();i++){var bean=(Element)beans.item(i);if("shibboleth.AbstractPopulateAuditContext".equals(bean.getAttribute("id"))){
            require("net.shibboleth.idp.profile.audit.impl.PopulateAuditContext".equals(bean.getAttribute("class"))
                    &&"#{getObject('shibboleth.AuditFieldReplacementMap')}".equals(bean.getAttributeNS("http://www.springframework.org/schema/p","fieldReplacements")));found++;
        }}require(found==1);
    }
    /** Preserve the native map's exact value substitution; this never interprets Format as a qualifier. */
    static String renderAuditValue(byte[] auditXml,String value) {
        var audit=SecureXml.parse(auditXml).getDocumentElement();var maps=audit.getElementsByTagNameNS(UTIL,"map");Element selected=null;
        for(int i=0;i<maps.getLength();i++){var map=(Element)maps.item(i);if("shibboleth.AuditFieldReplacementMap".equals(map.getAttribute("id"))){require(selected==null);selected=map;}}
        require(selected!=null);var replacements=new HashMap<String,String>();
        for(var node=selected.getFirstChild();node!=null;node=node.getNextSibling())if(node instanceof Element entry){
            require(BEANS.equals(entry.getNamespaceURI())&&"entry".equals(entry.getLocalName())
                    &&entry.hasAttribute("key")&&entry.hasAttribute("value")&&entry.getElementsByTagName("*").getLength()==0
                    &&!entry.getAttribute("value").contains("#{")&&!entry.getAttribute("value").contains("${")&&!entry.getAttribute("value").contains("%{")
                    &&replacements.put(entry.getAttribute("key"),entry.getAttribute("value"))==null);
        }
        return replacements.getOrDefault(value,value);
    }
    private static byte[] jarEntry(byte[] jar,String name)throws Exception {
        byte[] result=null;
        try(var stream=new java.util.zip.ZipInputStream(new java.io.ByteArrayInputStream(jar))) {
            for(var entry=stream.getNextEntry();entry!=null;entry=stream.getNextEntry())if(name.equals(entry.getName())){
                require(result==null);result=stream.readNBytes(1048577);require(result.length<=1048576);
            }
        }
        require(result!=null);return result;
    }
    private record Clock(Instant nativeAt,Instant hostStart,Instant hostEnd){}
    private static Clock clock(Path folder,String file)throws Exception {var c=json(original(folder,file));byte[] raw=original(folder,text(c,"nativeClockFile"));
        require(hash(raw).equals(text(c,"nativeClockSha256"))&&new String(raw,StandardCharsets.UTF_8).strip().equals(text(c,"nativeInstant")));
        return new Clock(instant(c,"nativeInstant"),instant(c,"hostStartedAt"),instant(c,"hostCompletedAt"));}
    static Instant instant(JsonNode n,String field){return Instant.parse(text(n,field));}
    static String structureFingerprint(Element e){var attrs=new TreeMap<String,String>();for(int i=0;i<e.getAttributes().getLength();i++){var a=e.getAttributes().item(i);if(!"http://www.w3.org/2000/xmlns/".equals(a.getNamespaceURI()))attrs.put("{"+a.getNamespaceURI()+"}"+a.getLocalName(),a.getNodeValue());}
        var children=new ArrayList<String>();StringBuilder value=new StringBuilder();for(int i=0;i<e.getChildNodes().getLength();i++){var c=e.getChildNodes().item(i);if(c instanceof Element child)children.add(structureFingerprint(child));else if(c.getNodeType()==org.w3c.dom.Node.TEXT_NODE&&!c.getNodeValue().isBlank())value.append(c.getNodeValue().strip());}
        return "{"+e.getNamespaceURI()+"}"+e.getLocalName()+attrs+value+children;}
}
