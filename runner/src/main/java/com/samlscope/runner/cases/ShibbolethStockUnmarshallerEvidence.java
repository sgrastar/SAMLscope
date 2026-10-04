package com.samlscope.runner.cases;

import com.fasterxml.jackson.databind.JsonNode;
import com.samlscope.core.caseexec.CaseContext;
import com.samlscope.core.transcript.*;
import com.samlscope.saml.normal.SecureXml;
import com.samlscope.store.JsonCodec;
import java.nio.file.Path;
import java.time.*;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.regex.Pattern;
import static com.samlscope.runner.cases.DefaultAlgorithmPreventionEvidence.*;
import static com.samlscope.runner.cases.ShibbolethDefaultAlgorithmNativeAdapter.instant;

/**
 * Binds a stock decoder diagnostic to the actual HTTP rejection before an audit context exists.
 * A decoder invocation or an empty audit range alone cannot establish a product finding.
 */
final class ShibbolethStockUnmarshallerEvidence {
    static final String SCHEMA="samlscope-shibboleth-stock-unmarshaller-v1";
    static final String SOURCE_SHA="cce9485d6941837e143c5d7c62351ad4270997f895a8fb8cb07198824594a34d";
    static final String RSA_MD5="http://www.w3.org/2001/04/xmldsig-more#rsa-md5";
    static final String RSA_SHA256="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
    static final String CAUSE="It is forbidden to use algorithm "+RSA_MD5+" when secure validation is enabled";
    static final Map<String,String> CLASSES=Map.of(
        "org.opensaml.core.xml.util.XMLObjectSupport","e30a6d71302ec9bec547d1001445055a3d2efcb62d8e6c153e040bda110dbf05",
        "org.opensaml.xmlsec.signature.impl.SignatureUnmarshaller","f5aed049c217f84f4302e065df82207d6a66b73301dda1d0fdac9be9b81a0827",
        "org.apache.xml.security.signature.XMLSignature","5ab5d89c0194f4cf67008c7482341242d7b70ef3c5fce2b9493b9d10a23a0909",
        "org.apache.xml.security.algorithms.SignatureAlgorithm","00c8d46276f920559f4a6df6c1ac875be73463fd6a72c54acccdf0a8b66ce060");
    static final Map<String,String> JARS=Map.of(
        "opensaml-core-api-5.2.3.jar","40ed25f0892dfb833aa2b917bd2be1e10cb7c788efb3276b66b19338b80c29f6",
        "opensaml-xmlsec-impl-5.2.3.jar","cc67fc1bd9cb435cdbe7483ef04513c83cc9619a3015c04ad41bb6cc0eb6e68e",
        "xmlsec-3.0.6.jar","395eccc3496063ac7b1d6af2422a11670ee5ded807f51542818eccd5fbb5e20c");
    private ShibbolethStockUnmarshallerEvidence(){}

    static String validate(Path folder,CaseContext context,TranscriptContentReader content,JsonNode use,
            JsonNode output,JsonNode scope,byte[] suite,byte[] target,byte[] actualRequest,String requestReference,
            JsonNode http,Instant nativeBegin,Instant nativeEnd,Instant hostBegin,Instant hostEnd)throws Exception {
        require("pre-audit-decoder-rejection".equals(text(use,"auditMode"))&&!use.has("auditFile"));
        validateAuditCapture(json(original(folder,text(use,"auditCaptureFile"))),context.runId(),
            text(use,"requestId"),hash(actualRequest),http,hostBegin,hostEnd);
        byte[] process=original(folder,text(use,"processLogFile"));JsonNode range=use.path("processLogRange");
        require("/opt/reference-idp/logs/idp-process.log".equals(text(range,"path"))
            &&range.path("inode").isIntegralNumber()&&range.path("inode").longValue()>0
            &&range.path("beforeOffset").isIntegralNumber()&&range.path("afterOffset").isIntegralNumber()
            &&range.path("beforeOffset").longValue()>=0
            &&range.path("afterOffset").longValue()-range.path("beforeOffset").longValue()==process.length);
        require(http.path("responseStatus").isInt()&&http.path("responseStatus").intValue()==400
            &&decoderRejection(new String(process,java.nio.charset.StandardCharsets.UTF_8),nativeBegin,nativeEnd));
        return validateInvocation(folder,context,content,use,output,scope,suite,target,actualRequest,requestReference);
    }

    static void validateAuditCapture(JsonNode capture,String run,String request,String sha,JsonNode http,
            Instant hostBegin,Instant hostEnd)throws Exception {
        require("samlscope-shibboleth-native-audit-capture-v1".equals(text(capture,"schema"))
            &&run.equals(text(capture,"runId"))&&request.equals(text(capture,"requestId"))
            &&sha.equals(text(capture,"requestSha256"))
            &&"/opt/reference-idp/logs/idp-audit.log".equals(text(capture,"path"))
            &&capture.path("inode").isIntegralNumber()&&capture.path("inode").longValue()>0
            &&capture.path("beforeOffset").isIntegralNumber()&&capture.path("afterOffset").isIntegralNumber()
            &&capture.path("beforeOffset").longValue()>=0
            &&capture.path("beforeOffset").equals(capture.path("afterOffset"))
            &&capture.path("deltaBytes").isInt()&&capture.path("deltaBytes").intValue()==0
            &&hash(new byte[0]).equals(text(capture,"deltaSha256"))
            &&capture.path("matchingAuditCount").isInt()&&capture.path("matchingAuditCount").intValue()==0
            &&isBoolean(capture,"decisionEvidence",false));
        Instant before=instant(capture,"beforeCapturedAt"),after=instant(capture,"afterCapturedAt");
        require(!before.isBefore(hostBegin)&&!instant(http,"startedAt").isBefore(before)
            &&!after.isBefore(instant(http,"completedAt"))&&!hostEnd.isBefore(after));
    }

    /** One ordered cause chain on one thread, inside the contemporaneous native clock window. */
    static boolean decoderRejection(String log,Instant begin,Instant end) {
        Pattern header=Pattern.compile("^(\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2}[.,]\\d{3}) - [^\\r\\n]*? - (ERROR|WARN) \\[([^]]+)] \\[([^]:]+):[0-9]+] - (.*)$");
        String[] classes={"org.opensaml.xmlsec.signature.impl.SignatureUnmarshaller",
            "org.opensaml.messaging.decoder.servlet.BaseHttpServletRequestXMLMessageDecoder",
            "org.opensaml.profile.action.impl.DecodeMessage","org.opensaml.profile.action.impl.LogEvent"};
        String[] messages={"Error constructing Apache XMLSignature instance from Signature element: "+CAUSE,
            "Error unmarshalling message from input stream: Unable to unmarshall Signature with Apache XMLSignature",
            "Profile Action DecodeMessage: Unable to decode incoming request",
            "A non-proceed event occurred while processing the request: UnableToDecode"};
        int stage=0,starts=0;String thread=null;Instant previous=null;
        for(String line:log.lines().toList()) {
            var match=header.matcher(line);if(!match.matches())continue;
            String type=match.group(4);int index=Arrays.asList(classes).indexOf(type);if(index<0)continue;
            if(!match.group(5).equals(messages[index]))return false;
            Instant time=LocalDateTime.parse(match.group(1).replace(',','.'),DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss.SSS")).toInstant(ZoneOffset.UTC);
            if(time.plusMillis(1).isBefore(begin)||time.isAfter(end))return false;
            if(index==0){starts++;thread=match.group(3);}
            if(index!=stage||!Objects.equals(thread,match.group(3))||(previous!=null&&time.isBefore(previous)))return false;
            if(!match.group(2).equals(index==3?"WARN":"ERROR"))return false;
            previous=time;stage++;
        }
        return starts==1&&stage==4;
    }

    static String validateInvocation(Path folder,CaseContext context,TranscriptContentReader content,JsonNode use,
            JsonNode output,JsonNode scope,byte[] suite,byte[] target,byte[] actualRequest,String requestReference)throws Exception {
        String run=context.runId(),temporary="/tmp/samlscope-stock-unmarshaller-"+run;
        JsonNode call=json(original(folder,text(use,"unmarshallerInvocationFile")));
        require("samlscope-shibboleth-stock-unmarshaller-invocation-v1".equals(text(call,"schema"))
            &&run.equals(text(call,"runId"))&&call.path("exitCode").isInt()&&call.path("exitCode").intValue()==0
            &&!instant(call,"completedAt").isBefore(instant(call,"startedAt")));
        List<String> command=List.of("java","-Dlogback.configurationFile="+temporary+"/stock-unmarshaller-logback.xml",
            "-cp",temporary+"/classes:/usr/local/tomcat/webapps/idp/WEB-INF/lib/*","ShibbolethStockUnmarshaller",
            temporary+"/stock-unmarshaller-input.json",temporary+"/ShibbolethStockUnmarshaller.java");
        require(call.path("command").equals(new JsonCodec().mapper().valueToTree(command))
            &&SOURCE_SHA.equals(text(call,"sourceSha256"))&&SOURCE_SHA.equals(hash(original(folder,text(call,"sourceFile")))));
        byte[] inputBytes=original(folder,text(call,"inputFile")),stdout=original(folder,text(call,"stdoutFile"));
        require(hash(inputBytes).equals(text(call,"inputSha256"))&&hash(stdout).equals(text(call,"stdoutSha256"))
            &&json(stdout).equals(output)&&auxiliary(folder,text(call,"stderrFile")).length==0
            &&hash(new byte[0]).equals(text(call,"stderrSha256")));
        JsonNode input=json(inputBytes);
        String entity=SecureXml.parse(suite).getDocumentElement().getAttribute("entityID"),targetEntity=SecureXml.parse(target).getDocumentElement().getAttribute("entityID");
        require(SCHEMA.equals(text(output,"schema"))&&run.equals(text(output,"runId"))
            &&hash(inputBytes).equals(text(output,"inputSha256"))&&SOURCE_SHA.equals(text(output,"producerSourceSha256")));
        for(JsonNode value:List.of(input,output))require(run.equals(text(value,"runId"))
            &&hash(suite).equals(text(value,"suiteMetadataSha256"))&&hash(target).equals(text(value,"targetMetadataSha256"))
            &&entity.equals(text(value,"suiteEntityId"))&&targetEntity.equals(text(value,"targetEntityId")));
        require(text(input,"suiteMetadataFile").equals(temporary+"/stock-unmarshaller-suite.xml")
            &&text(input,"targetMetadataFile").equals(temporary+"/stock-unmarshaller-target.xml")
            &&Arrays.equals(suite,original(folder,"stock-unmarshaller-suite.xml"))
            &&Arrays.equals(target,original(folder,"stock-unmarshaller-target.xml")));
        require(isBoolean(output,"diagnosticOnly",true)&&isBoolean(output,"productFinding",false)
            &&isBoolean(output,"privateKeysRead",false)&&isBoolean(output,"privateKeyExported",false)
            &&isBoolean(output,"algorithmPolicyChanged",false));
        validateClasses(folder,call,output,scope);
        require(input.path("records").isArray()&&input.path("records").size()==2
            &&output.path("records").isArray()&&output.path("records").size()==2);
        Set<String> fixtures=new HashSet<>(),references=new HashSet<>();String positiveControlReference=null;
        for(int i=0;i<2;i++) {
            JsonNode row=input.path("records").get(i),result=output.path("records").get(i);String fixture=text(row,"fixtureId"),reference=text(row,"requestReference");
            require(Set.of("sha256-control","rsa-md5").contains(fixture)&&fixtures.add(fixture)&&references.add(reference));
            var matches=context.transcript().list(run).stream().filter(e->reference.equals(e.id())).toList();require(matches.size()==1);
            TranscriptEntry e=matches.getFirst();require(run.equals(e.runId())&&e.direction()==Direction.OUTBOUND
                &&fixture.equals(e.samlSummary().get("fixture_id"))&&e.decodedSamlRef()!=null
                &&e.decodedSamlRef().equals("transcripts/"+run+"/"+reference+".saml.xml"));
            byte[] raw=content.readDecodedSaml(e);require(raw!=null&&raw.length==e.decodedSamlBytes()
                &&hash(raw).equals(text(row,"requestSha256"))&&e.decodedSamlRef().equals(text(row,"originalPath"))
                &&text(row,"requestFile").equals(temporary+"/"+fixture+"-unmarshaller-request.xml")
                &&Arrays.equals(raw,original(folder,fixture+"-unmarshaller-request.xml")));
            var request=SecureXml.parse(raw).getDocumentElement();structure(request,P,"AuthnRequest");
            require(request.getAttribute("ID").equals(text(row,"requestId"))&&entity.equals(single(request,A,"Issuer").getTextContent()));
            if(fixture.equals("rsa-md5"))require(Arrays.equals(raw,actualRequest)&&reference.equals(requestReference));
            for(String field:List.of("fixtureId","requestReference","requestId","requestSha256"))require(row.path(field).equals(result.path(field)));
            var methods=request.getElementsByTagNameNS(DS,"SignatureMethod");require(methods.getLength()==1);
            String algorithm=((org.w3c.dom.Element)methods.item(0)).getAttribute("Algorithm");
            require((fixture.equals("rsa-md5")?RSA_MD5:RSA_SHA256).equals(algorithm)
                &&algorithm.equals(text(result,"signatureAlgorithm"))&&entity.equals(text(result,"issuer"))
                &&!instant(result,"completedAt").isBefore(instant(result,"startedAt")));
            if(fixture.equals("sha256-control")) {
                require(isBoolean(result,"unmarshalled",true)
                    &&result.path("nativeExceptionClasses").isArray()&&result.path("nativeExceptionClasses").isEmpty()
                    &&result.path("nativeExceptionText").isTextual()&&result.path("nativeExceptionText").textValue().isEmpty());
                positiveControlReference=reference;
            }
            else require(isBoolean(result,"unmarshalled",false)&&result.path("nativeExceptionClasses").isArray()
                &&strings(result.path("nativeExceptionClasses")).contains("org.apache.xml.security.exceptions.XMLSecurityException")
                &&text(result,"nativeExceptionText").contains(CAUSE));
        }
        require(fixtures.equals(Set.of("sha256-control","rsa-md5")));validateOperations(folder,call,scope,temporary);
        require(positiveControlReference!=null);return positiveControlReference;
    }

    static void validateClasses(Path folder,JsonNode call,JsonNode output,JsonNode scope)throws Exception {
        Set<String> classes=new HashSet<>(),originals=new HashSet<>();output.path("nativeClasses").fieldNames().forEachRemaining(classes::add);
        call.path("classOriginals").fieldNames().forEachRemaining(originals::add);require(classes.equals(CLASSES.keySet())&&originals.equals(classes));
        for(var entry:CLASSES.entrySet()) {
            JsonNode origin=output.path("nativeClasses").path(entry.getKey()),files=call.path("classOriginals").path(entry.getKey());
            String path=text(origin,"jarPath");require(path.startsWith("/usr/local/tomcat/webapps/idp/WEB-INF/lib/"));
            String jarName=Path.of(path).getFileName().toString(),jarSha=JARS.get(jarName);require(jarSha!=null
                &&path.equals("/usr/local/tomcat/webapps/idp/WEB-INF/lib/"+jarName)&&jarSha.equals(text(origin,"jarSha256"))
                &&jarSha.equals(text(scope.path("classpath"),path)));
            byte[] jar=original(folder,text(files,"jarFile")),type=original(folder,text(files,"classFile"));
            require(hash(jar).equals(jarSha)&&hash(type).equals(entry.getValue())&&entry.getValue().equals(text(origin,"classSha256"))
                &&Arrays.equals(type,jarEntry(jar,entry.getKey().replace('.','/')+".class")));
        }
    }

    static void validateOperations(Path folder,JsonNode call,JsonNode scope,String temporary)throws Exception {
        JsonNode before=json(original(folder,text(call,"nativeBeforeFile"))),after=json(original(folder,text(call,"nativeAfterFile")));
        require(before.equals(after)&&isBoolean(before,"running",true)&&before.path("mounts").isArray()&&before.path("mounts").isEmpty());
        for(String field:List.of("containerId","image","mounts"))require(before.path(field).equals(scope.path("runtime").path(field)));
        require(!instant(before,"startedAt").isAfter(instant(call,"startedAt")));
        JsonNode compile=json(original(folder,text(call,"compileInvocationFile")));
        require(compile.path("exitCode").isInt()&&compile.path("exitCode").intValue()==0
            &&SOURCE_SHA.equals(text(compile,"sourceSha256"))&&!instant(compile,"completedAt").isBefore(instant(compile,"startedAt"))
            &&!instant(call,"startedAt").isBefore(instant(compile,"completedAt"))
            &&compile.path("command").equals(new JsonCodec().mapper().valueToTree(List.of("javac","-cp",
                "/usr/local/tomcat/webapps/idp/WEB-INF/lib/*","-d",temporary+"/classes",temporary+"/ShibbolethStockUnmarshaller.java")))
            &&hash(auxiliary(folder,"stock-unmarshaller-compile.stdout")).equals(text(compile,"stdoutSha256"))
            &&hash(auxiliary(folder,"stock-unmarshaller-compile.stderr")).equals(text(compile,"stderrSha256")));
        JsonNode operations=json(original(folder,text(call,"operationsFile")));
        require("samlscope-stock-unmarshaller-diagnostic-operations-v1".equals(text(operations,"schema"))
            &&text(call,"runId").equals(text(operations,"runId"))&&isBoolean(operations,"sdkEvidenceOnly",true)
            &&isBoolean(operations,"temporaryRemoved",true)&&operations.path("nativeCompilerCalls").asInt(-1)==1
            &&operations.path("nativeJavaCalls").asInt(-1)==1&&operations.path("attempts").size()==1
            &&operations.path("attempts").get(0).equals(call));
        for(String field:List.of("productSettings","protocolSubmissions","credentialPosts","personOperations","privateKeyReads"))require(operations.path(field).isInt()&&operations.path(field).intValue()==0);
    }
    static boolean isBoolean(JsonNode n,String field,boolean expected){return n.path(field).isBoolean()&&n.path(field).booleanValue()==expected;}
    static List<String> strings(JsonNode n){require(n.isArray());var result=new ArrayList<String>();for(var v:n){require(v.isTextual());result.add(v.textValue());}return result;}
    private static byte[] auxiliary(Path folder,String name)throws Exception {
        require(name.matches("[A-Za-z0-9][A-Za-z0-9_.-]{0,160}"));Path file=folder.resolve(name);safeParents(file);
        require(java.nio.file.Files.isRegularFile(file,java.nio.file.LinkOption.NOFOLLOW_LINKS)&&java.nio.file.Files.size(file)<=2097152);
        return java.nio.file.Files.readAllBytes(file);
    }
    private static byte[] jarEntry(byte[] jar,String name)throws Exception {
        byte[] result=null;try(var stream=new java.util.zip.ZipInputStream(new java.io.ByteArrayInputStream(jar))) {
            for(var e=stream.getNextEntry();e!=null;e=stream.getNextEntry())if(name.equals(e.getName())) {
                require(result==null);result=stream.readNBytes(1048577);require(result.length<=1048576);
            }
        }require(result!=null);return result;
    }
}
