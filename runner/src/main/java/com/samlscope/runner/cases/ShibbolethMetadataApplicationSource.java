package com.samlscope.runner.cases;

import static com.samlscope.runner.cases.ShibbolethMetadataApplicationEvidence.*;
import static com.samlscope.runner.cases.MetadataAlgorithmEvidence.children;
import com.fasterxml.jackson.databind.JsonNode;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.*;
import java.util.zip.*;
import org.w3c.dom.Element;

/** Fixed stock call-path identity and public native execution proofs; no developer verdict input. */
final class ShibbolethMetadataApplicationSource {
 static void validate(byte[] conf,byte[] saml,byte[] opensaml,byte[] xmlsec)throws Exception{
  String beans=entry(conf,"net/shibboleth/idp/flows/saml/saml-abstract-beans.xml"),binding=entry(conf,"net/shibboleth/idp/conf/saml-binding-config.xml");
  require(beans.contains("net.shibboleth.idp.saml.profile.impl.PopulateBindingAndEndpointContexts")&&beans.contains("shibboleth.OutgoingBindingsLookupStrategy")&&beans.contains("p:endpointResolver-ref=\"shibboleth.EndpointResolver\"")&&binding.contains("org.opensaml.saml.common.binding.impl.DefaultEndpointResolver"));
  String ecp=entry(conf,"net/shibboleth/idp/flows/saml/saml2/sso-ecp-beans.xml"),front=entry(conf,"net/shibboleth/idp/flows/saml/saml2/slo-front-abstract-beans.xml"),back=entry(conf,"net/shibboleth/idp/flows/saml/saml2/slo-back-beans.xml");
  require(ecp.contains("shibboleth.OutgoingECPBindings")&&front.contains("SingleLogoutService")&&front.contains("shibboleth.OutgoingSAML2SLOFrontBindings")&&back.contains("SingleLogoutService")&&back.contains("SOAP"));
  byte[] selector=bytes(saml,"net/shibboleth/idp/saml/profile/impl/PopulateBindingAndEndpointContexts.class");
  require(ascii(selector,"bindingDescriptorsLookupStrategy")&&ascii(selector,"resolveSingle")&&ascii(selector,"BindingCriterion")&&ascii(selector,"setEndpoint"));
  byte[] resolver=bytes(opensaml,"org/opensaml/saml/common/binding/impl/DefaultEndpointResolver.class");require(ascii(resolver,"BindingCriterion")&&ascii(resolver,"EndpointCriterion"));
  byte[] metadata=bytes(opensaml,"org/opensaml/saml/metadata/resolver/impl/FileBackedHTTPMetadataResolver.class");require(ascii(metadata,"java/io/FileOutputStream")&&ascii(metadata,"write"));
  require(hash(bytes(opensaml,"org/opensaml/saml/common/binding/security/impl/SAMLProtocolMessageXMLSignatureSecurityHandler.class")).equals("b37276d78f06d8267835574c1c170f951dbc43c62290ea8a8c4df62e22fa9643"));
  require(hash(bytes(opensaml,"org/opensaml/saml/security/impl/MetadataCredentialResolver.class")).equals("2364eed8b664a21326cfe9cbf08aafae286ed16bedb9e654705d97063f716c07"));
  require(hash(bytes(opensaml,"org/opensaml/saml/common/binding/security/impl/BaseSAMLXMLSignatureSecurityHandler.class")).equals("01f227c291ac2336c9c5638a050af4dcee311b974240361ab89fa276ed8babbd"));
 }
 static byte[] bytes(byte[] jar,String name)throws Exception{byte[] selected=null;try(var in=new ZipInputStream(new ByteArrayInputStream(jar))){for(ZipEntry e;(e=in.getNextEntry())!=null;){if(name.equals(e.getName())){require(selected==null);selected=in.readAllBytes();}}}require(selected!=null&&selected.length>0);return selected;}
 static String entry(byte[] jar,String name)throws Exception{return new String(bytes(jar,name),StandardCharsets.UTF_8);}
 static boolean ascii(byte[] raw,String needle){return new String(raw,StandardCharsets.ISO_8859_1).contains(needle);}
 static void validatePaosCause(JsonNode projection,String fixture,String action,String request,String response,String requestSha,String responseSha,String entity,Instant before,Instant after,String audit)throws Exception{
  require("samlscope-shibboleth-metadata-application-public-causes-v1".equals(text(projection,"schema"))&&projection.path("publicCandidateLines").isArray()&&!projection.path("privateLogPersisted").asBoolean(true));
  JsonNode selected=null;for(var op:projection.path("operations"))if(fixture.equals(op.path("fixture").asText())){require(selected==null);selected=op;}require(selected!=null&&action.equals(text(selected,"actionId"))&&request.equals(text(selected,"requestReference"))&&response.equals(text(selected,"responseReference"))&&requestSha.equals(text(selected,"requestSha256"))&&responseSha.equals(text(selected,"responseSha256")));
  require(text(projection,"sourcePrefixSha256").equals(text(projection,"sourcePrefixRecheckedSha256"))&&projection.path("sourcePrefixBytes").asLong(-1)>0&&"/opt/reference-idp/logs/idp-process.log".equals(text(projection,"sourcePath")));
  var sequence=selected.path("nativeEventSequence");long auditNumber=sequence.path("auditLineNumber").asLong(-1);var validations=sequence.path("validationLineNumbers");var errors=sequence.path("errorLineNumbers");require(validations.isArray()&&validations.size()==1&&errors.isArray()&&errors.size()==1);long validationNumber=validations.get(0).asLong(-1),errorNumber=errors.get(0).asLong(-1);require(validationNumber>0&&validationNumber<errorNumber&&errorNumber<auditNumber);
  long previousAudit=0,previousLine=0;JsonNode validation=null,error=null,terminal=null;int actualValidation=0,actualErrors=0;
  for(var line:projection.path("publicCandidateLines")){long n=line.path("lineNumber").asLong(-1);require(n>previousLine);previousLine=n;String raw=text(line,"raw");require(hash(raw.getBytes(StandardCharsets.UTF_8)).equals(text(line,"lineSha256")));Instant at=at(line,"nativeLoggedAt");String kind=text(line,"kind");if(at.plusMillis(1).isBefore(before)||after.isBefore(at))continue;
   if(kind.equals("native-peer-audit")){int pos=raw.indexOf("SAMLscope-application-v1|");require(pos>=0);String value=raw.substring(pos);String[] fields=value.substring("SAMLscope-application-v1|".length()).split("\\|",-1);require(fields.length==11&&entity.equals(fields[3])&&audit.contains(value));if(n<auditNumber)previousAudit=n;if(n==auditNumber){require(("_"+action).equals(fields[0])&&"SOAP".equals(fields[7])&&ECP_PROFILE.equals(fields[9])&&fields[4].isEmpty()&&fields[5].isEmpty()&&fields[6].equals("true"));terminal=line;}}
   else if(kind.equals("native-signature-validation-failure")){require(raw.contains("SAMLProtocolMessageXMLSignatureSecurityHandler")&&raw.endsWith("Validation of protocol message signature failed for context issuer '"+entity+"', message type: {"+P+"}AuthnRequest"));if(n==validationNumber)validation=line;}
   else if(kind.equals("native-message-authentication-error")){require(raw.contains("org.opensaml.profile.action.impl.LogEvent")&&raw.endsWith("A non-proceed event occurred while processing the request: MessageAuthenticationError"));if(n==errorNumber)error=line;}
   else throw new Unproven("foreign-private-projection-line");
  }
  require(validation!=null&&error!=null&&terminal!=null&&previousAudit<validationNumber);for(var line:projection.path("publicCandidateLines")){long n=line.path("lineNumber").asLong(-1);if(n>previousAudit&&n<auditNumber){if(line.path("kind").asText().equals("native-signature-validation-failure"))actualValidation++;if(line.path("kind").asText().equals("native-message-authentication-error"))actualErrors++;}}require(actualValidation==1&&actualErrors==1&&!at(error,"nativeLoggedAt").isBefore(at(validation,"nativeLoggedAt"))&&!at(terminal,"nativeLoggedAt").isBefore(at(error,"nativeLoggedAt")));
 }
 static final String SELECTION_SOURCE_SHA="752445cbb28082a252d8903a9ca58b9c6fdc0253cb8562f7b874164fd0973883";
 static void validateSelection(byte[] inputRaw,byte[] outputRaw,byte[] invocationRaw,byte[] producer,
   byte[] operationsRaw,byte[] nativeBefore,byte[] nativeAfter,byte[] bRaw,Element b,Element a,
   String run,String entity,Map<String,String> requestRefs,Map<String,byte[]> requests,
   byte[] confJar,byte[] idpJar,byte[] resolverJar,byte[] apiJar)throws Exception {
  JsonNode input=json(inputRaw),output=json(outputRaw),invocation=json(invocationRaw),operations=json(operationsRaw);
  require(hash(producer).equals(SELECTION_SOURCE_SHA)&&hash(apiJar).equals("cce72578ec8df5dd18cb71c88bba89bd196c640281c199ce875e2aa44154f93f"));
  require("samlscope-native-metadata-selection-input-v1".equals(text(input,"schema"))&&"stock-native-consumer".equals(text(input,"purpose"))
    &&"samlscope-native-metadata-selection-output-v1".equals(text(output,"schema"))&&"stock-native-consumer".equals(text(output,"purpose"))
    &&run.equals(text(input,"runId"))&&run.equals(text(output,"runId"))&&entity.equals(text(input,"entityId"))&&entity.equals(text(output,"entityId")));
  require("samlscope-native-metadata-selection-invocation-v1".equals(text(invocation,"schema"))
    &&"public-native-selection-replay".equals(text(invocation,"purpose"))&&invocation.path("exitCode").asInt(-1)==0
    &&SELECTION_SOURCE_SHA.equals(text(invocation,"sourceSha256"))&&SELECTION_SOURCE_SHA.equals(text(output,"sourceSha256"))
    &&hash(inputRaw).equals(text(invocation,"inputSha256"))&&hash(inputRaw).equals(text(output,"inputSha256"))
    &&hash(outputRaw).equals(text(invocation,"outputSha256")));
  require(hash(idpJar).equals(text(output,"idpSamlJarSha256"))&&hash(resolverJar).equals(text(output,"resolverJarSha256"))
    &&hash(bytes(confJar,"net/shibboleth/idp/conf/saml-binding-config.xml")).equals(text(output,"bindingConfigurationSha256")));
  Map<String,byte[]> classes=Map.of(
    "net.shibboleth.idp.saml.profile.impl.PopulateBindingAndEndpointContexts",bytes(idpJar,"net/shibboleth/idp/saml/profile/impl/PopulateBindingAndEndpointContexts.class"),
    "org.opensaml.saml.common.binding.AbstractEndpointResolver",bytes(apiJar,"org/opensaml/saml/common/binding/AbstractEndpointResolver.class"),
    "org.opensaml.saml.common.binding.impl.DefaultEndpointResolver",bytes(resolverJar,"org/opensaml/saml/common/binding/impl/DefaultEndpointResolver.class"),
    "org.opensaml.saml.common.binding.BindingDescriptor",bytes(apiJar,"org/opensaml/saml/common/binding/BindingDescriptor.class"));
  require(output.path("selectedNativeClassHashes").size()==classes.size());for(var c:classes.entrySet())require(hash(c.getValue()).equals(text(output.path("selectedNativeClassHashes"),c.getKey())));
  require(Arrays.equals(nativeBefore,nativeAfter));String inventory=new String(nativeBefore,StandardCharsets.UTF_8);
  for(var jar:Map.of("idp-conf-impl",confJar,"idp-saml-impl",idpJar,"opensaml-saml-impl",resolverJar,"opensaml-saml-api",apiJar).entrySet())
    require(inventory.lines().filter(line->line.equals(hashUnchecked(jar.getValue())+"  /usr/local/tomcat/webapps/idp/WEB-INF/lib/"+jar.getKey()+"-5.2.3.jar")).count()==1);
  require(inventory.lines().count()==4&&operations.path("nativeContainerBefore").equals(operations.path("nativeContainerAfter"))
    &&operations.path("nativeContainerBefore").path("running").asBoolean(false)&&operations.path("temporarySourceRemoved").asBoolean(false)
    &&operations.path("nativeCompilerCalls").asInt(-1)==1&&operations.path("nativePublicJavaCalls").asInt(-1)==1);
  for(String field:List.of("productSettings","protocolOperations","credentialPosts","productRestarts","personOperations"))require(operations.path(field).asInt(-1)==0);
  for(String field:List.of("productSettings","protocolOperations","credentialPosts"))require(output.path(field).asInt(-1)==0);require(!output.path("privateKeyRead").asBoolean(true));
  var command=strings(invocation.path("command"));require(command.size()==10&&command.subList(0,5).equals(List.of("docker","exec","samlscope-reference-shibboleth","java",command.get(4)))
    &&command.get(4).matches("-Dlogback.configurationFile=/tmp/shib-application-selection-[0-9a-f]{12}/logback.xml"));
  String temp=command.get(4).substring("-Dlogback.configurationFile=".length()).replace("/logback.xml","");
  require(command.get(5).equals("-cp")&&command.get(6).equals(temp+":/usr/local/tomcat/webapps/idp/WEB-INF/lib/*")
    &&command.get(7).equals("ShibbolethMetadataSelectionProducer")&&command.get(8).equals(temp+"/input.json")
    &&command.get(9).equals(temp+"/ShibbolethMetadataSelectionProducer.java"));
  require(!at(invocation,"completedAt").isBefore(at(invocation,"startedAt"))&&operations.path("commands").isArray()&&operations.path("commands").size()==2);
  var nativeInvocation=operations.path("commands").get(1);require("native-public-java".equals(text(nativeInvocation,"operation"))
    &&nativeInvocation.path("command").equals(invocation.path("command"))&&text(nativeInvocation,"startedAt").equals(text(invocation,"startedAt"))
    &&text(nativeInvocation,"completedAt").equals(text(invocation,"completedAt"))&&text(nativeInvocation,"outputSha256").equals(hash(outputRaw)));
  Map<String,JsonNode> ins=rows(input.path("records")),outs=rows(output.path("records"));require(ins.size()==7&&ins.keySet().equals(outs.keySet())
    &&ins.keySet().equals(Set.of("post-default","post-second","paos","slo-front","old-acs","unsupported-browser-redirect","slo-back-channel")));
  var expected=Map.of("post-default",endpoint(b,"AssertionConsumerService",POST,0),"post-second",endpoint(b,"AssertionConsumerService",POST,1),
    "paos",endpoint(b,"AssertionConsumerService",PAOS,2),"slo-front",endpoint(b,"SingleLogoutService",REDIRECT,-1));
  for(var entry:ins.entrySet()) {
    String label=entry.getKey();JsonNode in=entry.getValue(),out=outs.get(label);
    require(Arrays.equals(bRaw,Base64.getDecoder().decode(text(in,"metadataBase64")))&&hash(bRaw).equals(text(in,"metadataSha256")));
    for(String field:List.of("label","requestReference","requestSha256","metadataSha256","profileId","inboundBinding","outgoingList","observationPurpose"))require(in.path(field).equals(out.path(field)));
    boolean diagnostic=label.equals("unsupported-browser-redirect")||label.equals("slo-back-channel");
    String refLabel=label.equals("unsupported-browser-redirect")?"post-second":label.equals("slo-back-channel")?"slo-front":label;
    require(requestRefs.get(refLabel).equals(text(in,"requestReference")));
    byte[] raw=Base64.getDecoder().decode(text(in,"requestBase64"));require(hash(raw).equals(text(in,"requestSha256")));
    if(label.equals("unsupported-browser-redirect")) {
      require("isolated-binding-applicability-control".equals(text(in,"observationPurpose"))&&hash(requests.get(refLabel)).equals(text(in,"originalRequestSha256")));
      Element changed=xml(raw),original=xml(requests.get(refLabel));require(endpoint(b,"AssertionConsumerService",REDIRECT,3).equals(changed.getAttribute("AssertionConsumerServiceURL"))&&REDIRECT.equals(changed.getAttribute("ProtocolBinding")));
      changed.setAttribute("AssertionConsumerServiceURL",original.getAttribute("AssertionConsumerServiceURL"));changed.setAttribute("ProtocolBinding",original.getAttribute("ProtocolBinding"));require(semantic(original).equals(semantic(changed)));
    }else require(Arrays.equals(raw,requests.get(refLabel))&&text(in,"observationPurpose").equals(diagnostic?"isolated-synchronous-binding-applicability-control":"actual-recorded-request"));
    String profile=label.startsWith("slo-")?LOGOUT:label.equals("paos")?ECP_PROFILE:BROWSER;
    require(profile.equals(text(in,"profileId"))&&(label.equals("paos")||label.equals("slo-back-channel")?SOAP_BINDING:POST).equals(text(in,"inboundBinding")));
    List<String> candidates=label.equals("paos")?List.of(PAOS,"urn:ietf:params:xml:ns:samlec"):
      label.equals("slo-back-channel")?List.of("urn:oasis:names:tc:SAML:1.0:bindings:SOAP-binding",SOAP_BINDING):
      label.startsWith("slo-")?List.of(REDIRECT,POST,"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST-SimpleSign","urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact"):
      List.of(POST,"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST-SimpleSign","urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact");
    require(strings(out.path("candidateBindings")).equals(candidates));
    require(out.path("orderingResults").isArray()&&out.path("orderingResults").size()==2);
    for(int order=0;order<2;order++){var o=out.path("orderingResults").get(order);require(o.path("inMetadataOrder").isBoolean()&&o.path("inMetadataOrder").asBoolean()==(order==0));for(String field:List.of("selectedLocation","selectedBinding","event","candidateBindings"))require(o.path(field).equals(out.path(field)));}
    if(expected.containsKey(label))require(expected.get(label).equals(text(out,"selectedLocation"))&&(label.equals("paos")?PAOS:label.equals("slo-front")?REDIRECT:POST).equals(text(out,"selectedBinding"))&&out.path("event").isNull());
    else if(label.equals("slo-back-channel"))require(out.path("selectedLocation").isNull()&&SOAP_BINDING.equals(text(out,"selectedBinding"))&&out.path("event").isNull());
    else require(out.path("selectedLocation").isNull()&&out.path("selectedBinding").isNull()&&"EndpointResolutionFailed".equals(text(out,"event")));
  }
 }
 static final String CALIBRATION_SOURCE_SHA="1bc415baaae7dacfa3f382e1e61b3fa8b60bd4f79979a0c676e91a2ca7661717";
 static void validateCalibration(byte[] inputRaw,byte[] outputRaw,byte[] invocationRaw,byte[] sourceRaw,
   byte[] operationsRaw,byte[] beforeRaw,byte[] afterRaw,byte[] stockInventory,byte[] stockInputRaw,byte[] stockOutputRaw,
   byte[] oldRaw,Element acceptedB,Element acceptedA,String mode,JsonNode historicalSdk)throws Exception {
  require(Set.of("drop-accepted-b-secondary-acs","retain-conflicting-old-a-acs").contains(mode));
  JsonNode in=json(inputRaw),out=json(outputRaw),inv=json(invocationRaw),ops=json(operationsRaw),stock=json(stockInputRaw),stockOut=json(stockOutputRaw);
  require(hash(sourceRaw).equals(CALIBRATION_SOURCE_SHA)&&"samlscope-native-metadata-application-calibration-input-v1".equals(text(in,"schema"))
    &&"samlscope-native-metadata-application-calibration-output-v1".equals(text(out,"schema"))
    &&"samlscope-native-metadata-application-calibration-invocation-v1".equals(text(inv,"schema")));
  for(var n:List.of(in,out,inv))require("public-native-consumer-calibration-only".equals(text(n,"purpose"))&&mode.equals(text(n,"selectedConsumer")));
  require(out.path("counterfactualCalibrationOnly").isBoolean()&&out.path("counterfactualCalibrationOnly").asBoolean());
  require(Arrays.equals(stockInputRaw,Base64.getDecoder().decode(text(in,"stockSelectionInputBase64")))&&hash(stockInputRaw).equals(text(in,"stockSelectionInputSha256"))
    &&Arrays.equals(oldRaw,Base64.getDecoder().decode(text(in,"oldMetadataBase64")))&&hash(oldRaw).equals(text(in,"oldMetadataSha256"))
    &&text(stock,"runId").equals(text(in,"runId")));
  for(var n:List.of(out,inv))require(CALIBRATION_SOURCE_SHA.equals(text(n,"sourceSha256"))&&SELECTION_SOURCE_SHA.equals(text(n,"stockSourceSha256"))
    &&hash(inputRaw).equals(text(n,"inputSha256")));
  require(inv.path("exitCode").asInt(-1)==0&&hash(outputRaw).equals(text(inv,"outputSha256")));
  byte[] modelRaw=Base64.getDecoder().decode(text(out,"consumerMetadataBase64"));require(hash(modelRaw).equals(text(out,"consumerMetadataSha256")));
  validateConsumerMutation(acceptedB,acceptedA,xml(modelRaw),mode);
  byte[] consumerRaw=Base64.getDecoder().decode(text(out,"consumerInputBase64"));require(hash(consumerRaw).equals(text(out,"consumerInputSha256")));
  JsonNode consumer=json(consumerRaw),nativeOut=out.path("nativeOutput");
  for(String field:List.of("schema","purpose","runId","entityId","originalManifestSha256","targetMetadataSha256"))require(consumer.path(field).equals(stock.path(field)));
  require(hash(consumerRaw).equals(text(nativeOut,"inputSha256"))&&SELECTION_SOURCE_SHA.equals(text(nativeOut,"sourceSha256")));
  for(String field:List.of("schema","purpose","runId","entityId","idpSamlJarSha256","resolverJarSha256","bindingConfigurationSha256","selectedNativeClassHashes","productSettings","protocolOperations","credentialPosts","privateKeyRead"))require(nativeOut.path(field).equals(stockOut.path(field)));
  var originalRows=rows(stock.path("records"));var consumedRows=rows(consumer.path("records"));var producedRows=rows(nativeOut.path("records"));var stockRows=rows(stockOut.path("records"));
  require(originalRows.size()==7&&originalRows.keySet().equals(consumedRows.keySet())&&originalRows.keySet().equals(producedRows.keySet()));
  String trigger=mode.equals("drop-accepted-b-secondary-acs")?"post-second":"old-acs";
  for(var row:originalRows.entrySet()) {
   JsonNode supplied=consumedRows.get(row.getKey()),actual=producedRows.get(row.getKey()),oldOutput=stockRows.get(row.getKey());
   var unchanged=((com.fasterxml.jackson.databind.node.ObjectNode)supplied).deepCopy();
   unchanged.set("metadataBase64",row.getValue().path("metadataBase64"));unchanged.set("metadataSha256",row.getValue().path("metadataSha256"));
   require(unchanged.equals(row.getValue())&&Arrays.equals(modelRaw,Base64.getDecoder().decode(text(supplied,"metadataBase64")))&&hash(modelRaw).equals(text(supplied,"metadataSha256")));
   for(String field:List.of("label","requestReference","requestSha256","metadataSha256","profileId","inboundBinding","outgoingList","observationPurpose"))require(actual.path(field).equals(supplied.path(field)));
   require(actual.path("candidateBindings").equals(oldOutput.path("candidateBindings"))&&actual.path("orderingResults").size()==2);
   for(int order=0;order<2;order++){var o=actual.path("orderingResults").get(order);require(o.path("inMetadataOrder").isBoolean()&&o.path("inMetadataOrder").asBoolean()==(order==0));for(String field:List.of("selectedLocation","selectedBinding","event","candidateBindings"))require(o.path(field).equals(actual.path(field)));}
   if(!row.getKey().equals(trigger))for(String field:List.of("selectedLocation","selectedBinding","event"))require(actual.path(field).equals(oldOutput.path(field)));
   else if(mode.equals("drop-accepted-b-secondary-acs"))require(actual.path("selectedLocation").isNull()&&actual.path("selectedBinding").isNull()&&"EndpointResolutionFailed".equals(text(actual,"event")));
   else require(endpoint(acceptedA,"AssertionConsumerService",POST,0).equals(text(actual,"selectedLocation"))&&POST.equals(text(actual,"selectedBinding"))&&actual.path("event").isNull());
  }
  require(Arrays.equals(beforeRaw,afterRaw)&&Arrays.equals(beforeRaw,stockInventory));String inventory=new String(beforeRaw,StandardCharsets.UTF_8);require(inventory.lines().count()==4);
  for(String name:List.of("idp-conf-impl","idp-saml-impl","opensaml-saml-impl","opensaml-saml-api"))require(inventory.lines().filter(line->line.endsWith("  /usr/local/tomcat/webapps/idp/WEB-INF/lib/"+name+"-5.2.3.jar")).count()==1);
  JsonNode nativeBefore=ops.path("nativeContainerBefore"),nativeAfter=ops.path("nativeContainerAfter");require(nativeBefore.equals(nativeAfter)&&nativeBefore.path("running").asBoolean(false));
  for(String field:List.of("id","image","mounts"))require(nativeBefore.path(field).equals(historicalSdk.path(field)));
  require(ops.path("temporarySourceRemoved").asBoolean(false)&&ops.path("nativeCompilerCalls").asInt(-1)==1&&ops.path("nativePublicJavaCalls").asInt(-1)==3&&ops.path("commands").size()==4);
  for(String field:List.of("productSettings","protocolOperations","credentialPosts","productRestarts","personOperations"))require(ops.path(field).asInt(-1)==0);
  for(String field:List.of("productSettings","protocolOperations","credentialPosts"))require(out.path(field).asInt(-1)==0);require(!out.path("privateKeyRead").asBoolean(true)&&!out.path("controlsAdopted").asBoolean(true));
  var command=strings(inv.path("command"));require(command.size()==11&&command.subList(0,4).equals(List.of("docker","exec","samlscope-reference-shibboleth","java"))
   &&command.get(4).matches("-Dlogback.configurationFile=/tmp/shib-application-calibration-[0-9a-f]{12}/logback.xml"));
  String temp=command.get(4).substring("-Dlogback.configurationFile=".length()).replace("/logback.xml","");
  require(command.get(5).equals("-cp")&&command.get(6).equals(temp+":/usr/local/tomcat/webapps/idp/WEB-INF/lib/*")&&command.get(7).equals("ShibbolethMetadataApplicationCalibration")
   &&command.get(8).equals(temp+"/"+mode+".input.json")&&command.get(9).equals(temp+"/ShibbolethMetadataApplicationCalibration.java")&&command.get(10).equals(temp+"/ShibbolethMetadataSelectionProducer.java"));
  int matches=0;for(var op:ops.path("commands"))if(op.path("command").equals(inv.path("command"))){matches++;for(String field:List.of("operation","command","startedAt","completedAt","exitCode","stdoutSha256","stderrSha256"))require(op.path(field).equals(inv.path(field)));require(hash(outputRaw).equals(text(op,"stdoutSha256")));}
  require(matches==1&&!at(inv,"completedAt").isBefore(at(inv,"startedAt")));
 }
 static void validateConsumerMutation(Element acceptedB,Element acceptedA,Element consumer,String mode) {
  require(Set.of("drop-accepted-b-secondary-acs","retain-conflicting-old-a-acs").contains(mode));
  require(acceptedB.getAttribute("entityID").equals(acceptedA.getAttribute("entityID"))&&acceptedB.getAttribute("entityID").equals(consumer.getAttribute("entityID")));
  Element expected=(Element)acceptedB.cloneNode(true);
  if(mode.equals("drop-accepted-b-secondary-acs")) {
   var found=children(role(expected),MD,"AssertionConsumerService").stream().filter(e->"1".equals(e.getAttribute("index"))).toList();
   role(expected).removeChild(one(found));
  }else {
   var found=children(role(acceptedA),MD,"AssertionConsumerService").stream().filter(e->"0".equals(e.getAttribute("index"))).toList();
   role(expected).appendChild(expected.getOwnerDocument().importNode(one(found),true));
  }
  require(semantic(expected).equals(semantic(consumer)));
 }
 static Map<String,JsonNode> rows(JsonNode n){require(n.isArray());var result=new LinkedHashMap<String,JsonNode>();for(var row:n)require(result.put(text(row,"label"),row)==null);return result;}
}
