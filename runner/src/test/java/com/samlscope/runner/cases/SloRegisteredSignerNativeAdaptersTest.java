package com.samlscope.runner.cases;

import static org.junit.jupiter.api.Assertions.*;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.*;
import org.junit.jupiter.api.Test;

class SloRegisteredSignerNativeAdaptersTest {
    private static final String ENTITY="https://suite.example/registered-primary";
    @Test void shibSignatureRejectionUsesNativeEventRatherThanXmlSignatureBoolean()throws Exception {
        var begin=Instant.parse("2026-10-03T20:42:50.089699846Z");var end=Instant.parse("2026-10-03T20:42:50.688446180Z");
        String row="SAMLscope-signature-v1|_request|"+ENTITY+"|MessageAuthenticationError||true|POST|http://shibboleth.net/ns/profiles/saml2/logout|2026-10-03T20:42:50.417028763Z\n";
        assertTrue(SloRegisteredSignerNativeAdapters.shibSignatureRejectionAudit(row.getBytes(StandardCharsets.UTF_8),"_request",ENTITY,begin,end));
        assertTrue(SloRegisteredSignerNativeAdapters.shibSignatureRejectionAudit(row.replace("|true|","|false|").getBytes(StandardCharsets.UTF_8),"_request",ENTITY,begin,end));
        assertFalse(SloRegisteredSignerNativeAdapters.shibSignatureRejectionAudit(row.getBytes(StandardCharsets.UTF_8),"_different",ENTITY,begin,end));
    }
    @Test void shibSignatureAuditCannotBorrowAnotherEventIssuerProfileOrOperationWindow()throws Exception {
        var begin=Instant.parse("2026-10-03T20:42:50.089699846Z");var end=Instant.parse("2026-10-03T20:42:50.688446180Z");
        String row="SAMLscope-signature-v1|_request|"+ENTITY+"|MessageAuthenticationError||true|POST|http://shibboleth.net/ns/profiles/saml2/logout|2026-10-03T20:42:50.417028763Z\n";
        for(String altered:List.of(row.replace("MessageAuthenticationError","MessageSecurityError"),row.replace("MessageAuthenticationError||true","proceed||MessageSecurityError"),
                row.replace("||true","|Success|true"),row.replace("|true|","|MessageSecurityError|"),row.replace(ENTITY,"https://foreign.example/peer"),
                row.replace("|POST|","|GET|"),row.replace("/logout|","/sso/browser|"),row.replace("20:42:50.417028763Z","20:42:50.688446181Z"),
                row.replace("20:42:50.417028763Z","20:42:50.089699845Z"),row+row))
            assertThrows(IllegalArgumentException.class,()->SloRegisteredSignerNativeAdapters.shibSignatureRejectionAudit(altered.getBytes(StandardCharsets.UTF_8),"_request",ENTITY,begin,end));
    }
    @Test void selectedShibSloTrustCannotComeFromAnotherPeerProfileOrProcess()throws Exception {
        var mapper=new com.fasterxml.jackson.databind.ObjectMapper();var begin=Instant.parse("2026-10-04T00:00:00Z");var end=begin.plusSeconds(10);
        var observed=mapper.createObjectNode().put("entityId",ENTITY).put("profileId","http://shibboleth.net/ns/profiles/saml2/logout").put("recordedAt",begin.plusSeconds(1).toString()).put("privateFieldsExported",false);
        var profile=mapper.createObjectNode();profile.putObject("ProfileConfiguration").put("id","http://shibboleth.net/ns/profiles/saml2/logout").put("ignoreRequestSignatures",false);
        profile.putObject("RelyingPartyConfiguration").put("securityConfiguration","shibboleth.DefaultSecurityConfiguration");
        var properties=mapper.createObjectNode().put("idp.trust.signatures","shibboleth.ExplicitKeySignatureTrustEngine").put("idp.additionalProperties","/credentials/secrets.properties");
        var flags=mapper.createObjectNode().put("nativeJavaProcessObserved",true).put("trustOverridePresent",false).put("customAgentPresent",false).put("privateFieldsExported",false);var overrides=mapper.createArrayNode();
        assertDoesNotThrow(()->SloRegisteredSignerNativeAdapters.requireShibTrustScope(observed,profile,properties,flags,overrides,ENTITY,begin,end));
        assertDoesNotThrow(()->SloRegisteredSignerNativeAdapters.requireShibFlowViewInventory("/opt/reference-idp/views/logout.vm\n".getBytes(StandardCharsets.UTF_8)));
        for(String path:List.of("/opt/reference-idp/views/admin/mdquery.vm","/opt/reference-idp/flows/admin/mdquery-flow.xml","/opt/reference-idp/flows/saml/saml2/slo-front-abstract-flow.xml","/usr/local/tomcat/webapps/idp/WEB-INF/classes/custom.class"))
            assertThrows(IllegalArgumentException.class,()->SloRegisteredSignerNativeAdapters.requireShibFlowViewInventory((path+"\n").getBytes(StandardCharsets.UTF_8)));
        for(String field:List.of("trustOverridePresent","customAgentPresent","privateFieldsExported"))assertThrows(IllegalArgumentException.class,()->SloRegisteredSignerNativeAdapters.requireShibTrustScope(observed,profile,properties,flags.deepCopy().put(field,true),overrides,ENTITY,begin,end));
        assertThrows(IllegalArgumentException.class,()->SloRegisteredSignerNativeAdapters.requireShibTrustScope(observed.deepCopy().put("entityId","https://foreign.example/peer"),profile,properties,flags,overrides,ENTITY,begin,end));
        assertThrows(IllegalArgumentException.class,()->SloRegisteredSignerNativeAdapters.requireShibTrustScope(observed.deepCopy().put("recordedAt",end.plusSeconds(1).toString()),profile,properties,flags,overrides,ENTITY,begin,end));
        var browser=profile.deepCopy();((com.fasterxml.jackson.databind.node.ObjectNode)browser.path("ProfileConfiguration")).put("id","http://shibboleth.net/ns/profiles/saml2/sso/browser");
        assertThrows(IllegalArgumentException.class,()->SloRegisteredSignerNativeAdapters.requireShibTrustScope(observed,browser,properties,flags,overrides,ENTITY,begin,end));
        assertThrows(IllegalArgumentException.class,()->SloRegisteredSignerNativeAdapters.requireShibTrustScope(observed,profile,properties.deepCopy().put("idp.service.relyingparty.resources","other.xml"),flags,overrides,ENTITY,begin,end));
        assertThrows(IllegalArgumentException.class,()->SloRegisteredSignerNativeAdapters.requireShibTrustScope(observed,profile,properties,flags,overrides.deepCopy().add("/custom.class"),ENTITY,begin,end));
    }
    @Test void shibMetadataAbsenceRequiresActualStock404BytesAndSuccessfulNativeQuery()throws Exception {
        var mapper=new com.fasterxml.jackson.databind.ObjectMapper();var begin=Instant.parse("2026-10-04T00:00:00Z");var end=begin.plusSeconds(10);
        String url="http://localhost:8080/idp/profile/admin/mdquery?entityID="+java.net.URLEncoder.encode(ENTITY,StandardCharsets.UTF_8);
        byte[] body="Not Found\n".getBytes(StandardCharsets.UTF_8),stdout="Not Found\n\n404".getBytes(StandardCharsets.UTF_8);
        var query=mapper.createObjectNode().put("entity",ENTITY).put("url",url).put("method","GET").put("exitCode",0).put("responseStatus",404).put("responseBodyBytes",body.length)
            .put("responseBodySha256",SloRegisteredSignerEvidence.hash(body)).put("stdoutSha256",SloRegisteredSignerEvidence.hash(stdout)).put("startedAt",begin.plusSeconds(1).toString()).put("finishedAt",begin.plusSeconds(2).toString());
        query.putArray("command").add("curl").add("--silent").add("--show-error").add("--max-time").add("20").add("--write-out").add("\n%{http_code}").add(url);
        assertDoesNotThrow(()->SloRegisteredSignerNativeAdapters.requireShibMetadataQuery(query,stdout,body,ENTITY,false,begin,end));
        assertThrows(IllegalArgumentException.class,()->SloRegisteredSignerNativeAdapters.requireShibMetadataQuery(query.deepCopy().put("exitCode",1),stdout,body,ENTITY,false,begin,end));
        assertThrows(IllegalArgumentException.class,()->SloRegisteredSignerNativeAdapters.requireShibMetadataQuery(query.deepCopy().put("responseStatus",403),stdout,body,ENTITY,false,begin,end));
        byte[] wrong="<html>missing route</html>".getBytes(StandardCharsets.UTF_8),wrongStdout="<html>missing route</html>\n404".getBytes(StandardCharsets.UTF_8);
        var forged=query.deepCopy().put("responseBodyBytes",wrong.length).put("responseBodySha256",SloRegisteredSignerEvidence.hash(wrong)).put("stdoutSha256",SloRegisteredSignerEvidence.hash(wrongStdout));
        assertThrows(IllegalArgumentException.class,()->SloRegisteredSignerNativeAdapters.requireShibMetadataQuery(forged,wrongStdout,wrong,ENTITY,false,begin,end));
        assertThrows(IllegalArgumentException.class,()->SloRegisteredSignerNativeAdapters.requireShibMetadataQuery(query,stdout,body,"https://foreign.example/peer",false,begin,end));
        byte[] metadata=("<md:EntityDescriptor xmlns:md='urn:oasis:names:tc:SAML:2.0:metadata' entityID='"+ENTITY+"'/>").getBytes(StandardCharsets.UTF_8);
        byte[] actual=(new String(metadata,StandardCharsets.UTF_8)+"\n200").getBytes(StandardCharsets.UTF_8);var present=query.deepCopy().put("responseStatus",200).put("responseBodyBytes",metadata.length).put("responseBodySha256",SloRegisteredSignerEvidence.hash(metadata)).put("stdoutSha256",SloRegisteredSignerEvidence.hash(actual));
        assertDoesNotThrow(()->SloRegisteredSignerNativeAdapters.requireShibMetadataQuery(present,actual,metadata,ENTITY,true,begin,end));
        assertThrows(IllegalArgumentException.class,()->SloRegisteredSignerNativeAdapters.requireShibMetadataQuery(present,actual,metadata,ENTITY,false,begin,end));
    }
    private static byte[] page(String element,String issuer,String error){return ("<html><p>SimpleSAML\\Error\\Error: {\"errorCode\":\""+error+"\",\"%ELEMENT%\":\"SAML2\\\\"+element+"\",\"%ISSUER%\":\""+issuer+"\",\"%ENTITYID%\":\""+issuer+"\"}</p></html>").getBytes(StandardCharsets.UTF_8);}
    private static String languageNavigation(){return "<form id=\"language-form\" class=\"pure-form\" method=\"get\"><div id=\"languageform\"><select aria-label=\"Language\" class=\"pure-input-1-4 language-menu\" name=\"language\" id=\"language-selector\"><option value=\"en\" selected=\"selected\">English</option><option value=\"ja\">\u65e5\u672c\u8a9e</option></select><noscript><button type=\"submit\" class=\"pure-button\"><i class=\"fa fa-arrow-right\"></i></button></noscript></div></form>";}
    @Test void stockLanguageNavigationDoesNotTurnSignatureRejectionIntoAuthentication()throws Exception {
        String error=new String(page("LogoutRequest",ENTITY,"NOTVALIDCERTSIGNATURE"),StandardCharsets.UTF_8),navigation=languageNavigation();
        assertEquals(error,SloRegisteredSignerNativeAdapters.withoutPublicLanguageNavigation(navigation+error));
        assertTrue(SloRegisteredSignerNativeAdapters.simpleSamlPhpSignatureRejection((navigation+error).getBytes(StandardCharsets.UTF_8),ENTITY));
        assertFalse(SloRegisteredSignerNativeAdapters.simpleSamlPhpSignatureRejection((navigation+new String(page("AuthnRequest",ENTITY,"NOTVALIDCERTSIGNATURE"),StandardCharsets.UTF_8)).getBytes(StandardCharsets.UTF_8),ENTITY));
        assertFalse(SloRegisteredSignerNativeAdapters.simpleSamlPhpSignatureRejection((navigation+"<html>HTTP 500</html>").getBytes(StandardCharsets.UTF_8),ENTITY));
    }
    @Test void languageNamedFormCannotHideCredentialsCapabilitiesOrAnotherAction()throws Exception {
        String error=new String(page("LogoutRequest",ENTITY,"NOTVALIDCERTSIGNATURE"),StandardCharsets.UTF_8),navigation=languageNavigation();
        for(String unsafe:List.of(navigation.replace("method=\"get\"","method=\"post\""),navigation.replace("method=\"get\"","method=\"get\" action=\"/auth\""),navigation.replace("name=\"language\"","name=\"csrf\""),navigation.replace("</form>","<input type=\"password\" name=\"password\" value=\"secret\"></form>"),navigation.replace("</form>","<input type=\"hidden\" name=\"session_code\" value=\"secret\"></form>"),navigation.replace("<option value=\"ja\">","<option value=\"secret/capability\">"),navigation+navigation,navigation+"<form><input name=\"token\" value=\"secret\"></form>"))
            assertFalse(SloRegisteredSignerNativeAdapters.simpleSamlPhpSignatureRejection((unsafe+error).getBytes(StandardCharsets.UTF_8),ENTITY));
    }
    private static byte[] hostedOriginal(){return ("<?php\n$metadata['http://localhost:18380/idp']=['host'=>'__DEFAULT__','privatekey'=>'server.pem','certificate'=>'server.crt','auth'=>'example-userpass','saml20.ecp'=>true,'SingleSignOnServiceBinding'=>['urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect','urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST']];\n").getBytes(StandardCharsets.UTF_8);}
    private static com.fasterxml.jackson.databind.node.ObjectNode hostedState(byte[] raw)throws Exception{
        var mapper=new com.fasterxml.jackson.databind.ObjectMapper();var state=mapper.createObjectNode();String digest=SloRegisteredSignerEvidence.hash(raw);
        state.putObject("configurationFiles").put("saml20-idp-hosted.php",digest);
        state.putObject("mountedFileHashes").putObject(SloRegisteredSignerNativeAdapters.SSP_HOSTED_PATH).put("nativeSha256",digest).put("hostSha256",digest);
        state.putObject("hostedIdp").putArray("singleLogoutServiceBindings").add("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect").add("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST");return state;
    }
    @Test void onlyTheExactNativeHostedPostAdvertisementOverlayIsPermitted()throws Exception{
        byte[] original=hostedOriginal(),overlay=SloRegisteredSignerNativeAdapters.sspPostBindingOverlay("http://localhost:18380/idp");
        var configured=Arrays.copyOf(original,original.length+overlay.length);System.arraycopy(overlay,0,configured,original.length,overlay.length);
        assertDoesNotThrow(()->SloRegisteredSignerNativeAdapters.requireSspPostBindingChange(original,configured,"http://localhost:18380/idp",hostedState(original),hostedState(configured)));
        for(String extra:List.of("$metadata['http://localhost:18380/idp']['authproc']=[];","$metadata['http://localhost:18380/idp']['validate.logout']=false;","// different config")){
            byte[] changed=(new String(configured,StandardCharsets.UTF_8)+extra).getBytes(StandardCharsets.UTF_8);
            assertThrows(IllegalArgumentException.class,()->SloRegisteredSignerNativeAdapters.requireSspPostBindingChange(original,changed,"http://localhost:18380/idp",hostedState(original),hostedState(changed)));
        }
        assertThrows(IllegalArgumentException.class,()->SloRegisteredSignerNativeAdapters.sspPostBindingOverlay("http://foreign.example/idp"));
    }
    @Test void hostedPostOverlayNeedsActualConfigurationAndNativeMountedByteHashes()throws Exception{
        byte[] original=hostedOriginal(),overlay=SloRegisteredSignerNativeAdapters.sspPostBindingOverlay("http://localhost:18380/idp");var configured=Arrays.copyOf(original,original.length+overlay.length);System.arraycopy(overlay,0,configured,original.length,overlay.length);
        var before=hostedState(configured);((com.fasterxml.jackson.databind.node.ObjectNode)before.path("mountedFileHashes").path(SloRegisteredSignerNativeAdapters.SSP_HOSTED_PATH)).put("nativeSha256","0".repeat(64));
        assertThrows(IllegalArgumentException.class,()->SloRegisteredSignerNativeAdapters.requireSspPostBindingChange(original,configured,"http://localhost:18380/idp",hostedState(original),before));
        var wrong=hostedState(configured);((com.fasterxml.jackson.databind.node.ObjectNode)wrong.path("hostedIdp")).putArray("singleLogoutServiceBindings").add("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect");
        assertThrows(IllegalArgumentException.class,()->SloRegisteredSignerNativeAdapters.requireSspPostBindingChange(original,configured,"http://localhost:18380/idp",hostedState(original),wrong));
        byte[] changed=new String(original,StandardCharsets.UTF_8).replace("'saml20.ecp'=>true","'saml20.ecp'=>false").getBytes(StandardCharsets.UTF_8);
        assertThrows(IllegalArgumentException.class,()->SloRegisteredSignerNativeAdapters.requireSspPostBindingChange(changed,configured,"http://localhost:18380/idp",hostedState(changed),hostedState(configured)));
    }
    @Test void actualLogoutElementAndExactIssuerAreRequiredForNativeSignatureRefusal(){
        assertTrue(SloRegisteredSignerNativeAdapters.simpleSamlPhpSignatureRejection(page("LogoutRequest",ENTITY,"NOTVALIDCERTSIGNATURE"),ENTITY));
        assertFalse(SloRegisteredSignerNativeAdapters.simpleSamlPhpSignatureRejection(page("AuthnRequest",ENTITY,"NOTVALIDCERTSIGNATURE"),ENTITY));
        assertFalse(SloRegisteredSignerNativeAdapters.simpleSamlPhpSignatureRejection(page("LogoutRequest","https://suite.example/foreign","NOTVALIDCERTSIGNATURE"),ENTITY));
        assertFalse(SloRegisteredSignerNativeAdapters.simpleSamlPhpSignatureRejection(page("LogoutRequest",ENTITY,"UNHANDLEDEXCEPTION"),ENTITY));
        assertFalse(SloRegisteredSignerNativeAdapters.simpleSamlPhpSignatureRejection("<html>HTTP 500 Invalid signature</html>".getBytes(StandardCharsets.UTF_8),ENTITY));
    }
    @Test void duplicateRejectionPayloadAndAuthenticationFormCannotProveSloRefusal(){
        var raw=page("LogoutRequest",ENTITY,"NOTVALIDCERTSIGNATURE");var body=new String(raw,StandardCharsets.UTF_8);
        assertFalse(SloRegisteredSignerNativeAdapters.simpleSamlPhpSignatureRejection((body+body).getBytes(StandardCharsets.UTF_8),ENTITY));
        assertFalse(SloRegisteredSignerNativeAdapters.simpleSamlPhpSignatureRejection((body+"<form><input name='password'></form>").getBytes(StandardCharsets.UTF_8),ENTITY));
    }
    @Test void knownFactoryHasThreeDistinctSloConsumersAndNoSsoAdapter(){
        var adapters=SloRegisteredSignerNativeAdapters.create(e->{throw new AssertionError("No native access for factory");});
        assertEquals(Set.of("keycloak-native-slo-issuer-key-v1","shibboleth-native-slo-issuer-key-v1","simplesamlphp-native-slo-issuer-key-v1"),new HashSet<>(Arrays.stream(adapters).map(SloRegisteredSignerNativeAdapter::adapter).toList()));
        assertThrows(NullPointerException.class,()->new SloRegisteredSignerNativeAdapter.NativeUse(null,Instant.EPOCH,Instant.EPOCH,List.of()));
        assertThrows(IllegalArgumentException.class,()->new SloRegisteredSignerNativeAdapter.NativeUse(SloRegisteredSignerNativeAdapter.Decision.UNPROVEN,Instant.EPOCH,Instant.EPOCH.minusSeconds(1),List.of()));
    }
    @Test void hostedIdentityMustMatchTheActualNativeMetadataOriginalNotOnlyItsLabel()throws Exception {
        var mapper=new com.fasterxml.jackson.databind.ObjectMapper();var readback=mapper.createObjectNode().put("hostedEntityId",ENTITY);
        byte[] same=("<md:EntityDescriptor xmlns:md='urn:oasis:names:tc:SAML:2.0:metadata' entityID='"+ENTITY+"'/>").getBytes(StandardCharsets.UTF_8);
        assertDoesNotThrow(()->SloRegisteredSignerNativeAdapters.requireHostedTarget(readback,ENTITY,same));
        byte[] foreign=new String(same,StandardCharsets.UTF_8).replace(ENTITY,"https://foreign.example/idp").getBytes(StandardCharsets.UTF_8);
        assertThrows(IllegalArgumentException.class,()->SloRegisteredSignerNativeAdapters.requireHostedTarget(readback,ENTITY,foreign));
        assertThrows(IllegalArgumentException.class,()->SloRegisteredSignerNativeAdapters.requireHostedTarget(readback,ENTITY,new String(same,StandardCharsets.UTF_8).replace("urn:oasis:names:tc:SAML:2.0:metadata","urn:foreign").getBytes(StandardCharsets.UTF_8)));
        var wrong=readback.deepCopy().put("hostedEntityId","https://foreign.example/idp");
        assertThrows(IllegalArgumentException.class,()->SloRegisteredSignerNativeAdapters.requireHostedTarget(wrong,ENTITY,same));
        assertThrows(IllegalArgumentException.class,()->SloRegisteredSignerNativeAdapters.requireHostedTarget(mapper.createObjectNode(),ENTITY,same));
    }
    @Test void knownReadonlyRealmImportRequiresHostNativeHashAndRejectsUnknownOrWritableOverrides()throws Exception{
        var mapper=new com.fasterxml.jackson.databind.ObjectMapper();var state=mapper.createObjectNode();var runtime=state.putObject("runtime");var mount=runtime.putArray("mounts").addObject().put("Type","bind").put("Destination","/opt/keycloak/data/import/realm-samlscope.json").put("Source","/reference/dev/keycloak/realm-samlscope.json").put("Mode","ro").put("Propagation","rprivate").put("RW",false);
        state.putObject("mountedFileHashes").putObject("/opt/keycloak/data/import/realm-samlscope.json").put("source",mount.path("Source").asText()).put("hostSha256","fb68fa3129b14ee3c57c41d1f0473984ec4c2acf4cecaaaab683661192d45113").put("nativeSha256","fb68fa3129b14ee3c57c41d1f0473984ec4c2acf4cecaaaab683661192d45113");String image="sha256:9d1f1b2b7261ff53c66cb1092dfcdc34a5fb77e81f9e6a6e75b8b6a795de8067";
        assertDoesNotThrow(()->SloRegisteredSignerNativeAdapters.requireRuntimeBindings(state,image));mount.put("RW",true);assertThrows(IllegalArgumentException.class,()->SloRegisteredSignerNativeAdapters.requireRuntimeBindings(state,image));mount.put("RW",false).put("Destination","/opt/keycloak/providers/unsafe.jar");assertThrows(IllegalArgumentException.class,()->SloRegisteredSignerNativeAdapters.requireRuntimeBindings(state,image));mount.put("Destination","/opt/keycloak/data/import/realm-samlscope.json");((com.fasterxml.jackson.databind.node.ObjectNode)state.path("mountedFileHashes").path("/opt/keycloak/data/import/realm-samlscope.json")).put("nativeSha256","0".repeat(64));assertThrows(IllegalArgumentException.class,()->SloRegisteredSignerNativeAdapters.requireRuntimeBindings(state,image));
    }
    @Test void knownSspMetadataWritableBindDoesNotPermitWritableAuthOrCodeMounts()throws Exception{
        var mapper=new com.fasterxml.jackson.databind.ObjectMapper();var state=mapper.createObjectNode();var mounts=state.putObject("runtime").putArray("mounts");var hashes=state.putObject("mountedFileHashes");com.fasterxml.jackson.databind.node.ObjectNode auth=null;
        for(String destination:List.of("/var/simplesamlphp/cert/server.pem","/var/simplesamlphp/config/authsources.php","/var/simplesamlphp/config/config-override.php","/var/simplesamlphp/metadata/saml20-idp-hosted.php","/var/simplesamlphp/metadata/saml20-sp-remote.php","/etc/apache2/sites-enabled/000-default.conf","/var/simplesamlphp/cert/server.crt")){
            String name=destination.endsWith("000-default.conf")?"http-reference.conf":destination.substring(destination.lastIndexOf('/')+1);boolean rw=destination.endsWith("saml20-sp-remote.php");String source="/reference/ssp-config/"+name;var mount=mounts.addObject().put("Type","bind").put("Destination",destination).put("Source",source).put("Mode",rw?"":"ro").put("Propagation","rprivate").put("RW",rw);if(name.equals("authsources.php"))auth=mount;hashes.putObject(destination).put("source",source).put("hostSha256","1".repeat(64)).put("nativeSha256","1".repeat(64));}
        String image="sha256:9ae050473c68ce13c5451839cb64257eaa17be3a4d2c9a3f87996bbe0cebb0aa";assertDoesNotThrow(()->SloRegisteredSignerNativeAdapters.requireRuntimeBindings(state,image));auth.put("RW",true).put("Mode","rw");assertThrows(IllegalArgumentException.class,()->SloRegisteredSignerNativeAdapters.requireRuntimeBindings(state,image));auth.put("RW",false).put("Mode","ro");mounts.addObject().put("Destination","/var/simplesamlphp/modules/saml/src/IdP/SAML2.php");assertThrows(IllegalArgumentException.class,()->SloRegisteredSignerNativeAdapters.requireRuntimeBindings(state,image));
    }
    @Test void nativePostFormMustContainTheExactResponseAndActualSuiteEndpoint()throws Exception {
        String suite="https://suite.example/sp/slo",nativeUrl="https://idp.example/slo";byte[] response="<LogoutResponse ID='actual'/>".getBytes(StandardCharsets.UTF_8);
        var mapper=new com.fasterxml.jackson.databind.ObjectMapper();var n=mapper.createObjectNode().put("responseStatus",200).put("responseUrl",nativeUrl).put("responseSamlEndpoint",suite);
        String form="<html><form method='post' action='"+suite+"'><input type='hidden' name='SAMLResponse' value='"+Base64.getEncoder().encodeToString(response)+"'></form></html>";
        assertDoesNotThrow(()->SloRegisteredSignerNativeAdapters.requireNativeResponseBinding(n,form.getBytes(StandardCharsets.UTF_8),null,response,suite,null,"POST"));
        for(String wrong:List.of(form.replace(suite,"https://foreign.example/slo"),form.replace(Base64.getEncoder().encodeToString(response),Base64.getEncoder().encodeToString("<LogoutResponse ID='foreign'/>".getBytes(StandardCharsets.UTF_8))),form+form,form.replace("</form>","<input name='SAMLRequest' value='foreign'></form>"),form.replace("method='post'","method='get'"),"<html>"+suite+"</html>"))
            assertThrows(IllegalArgumentException.class,()->SloRegisteredSignerNativeAdapters.requireNativeResponseBinding(n,wrong.getBytes(StandardCharsets.UTF_8),null,response,suite,null,"POST"));
        assertThrows(IllegalArgumentException.class,()->SloRegisteredSignerNativeAdapters.requireNativeResponseBinding(n.deepCopy().put("responseSamlEndpoint","https://foreign.example/slo"),form.getBytes(StandardCharsets.UTF_8),null,response,suite,null,"POST"));
    }
    @Test void nativeRedirectLocationMustPreserveRawQueryAndExactDecodedResponse()throws Exception {
        String suite="https://suite.example/sp/slo",nativeUrl="https://idp.example/slo";byte[] response="<LogoutResponse ID='actual'/>".getBytes(StandardCharsets.UTF_8);
        var deflater=new java.util.zip.Deflater(java.util.zip.Deflater.DEFAULT_COMPRESSION,true);var bytes=new java.io.ByteArrayOutputStream();
        try(var zip=new java.util.zip.DeflaterOutputStream(bytes,deflater)){zip.write(response);}finally{deflater.end();}
        String query="SAMLResponse="+java.net.URLEncoder.encode(Base64.getEncoder().encodeToString(bytes.toByteArray()),StandardCharsets.UTF_8)+"&SigAlg=actual&Signature=actual";
        byte[] location=(suite+"?"+query).getBytes(StandardCharsets.UTF_8);var mapper=new com.fasterxml.jackson.databind.ObjectMapper();var n=mapper.createObjectNode().put("responseStatus",302).put("responseUrl",nativeUrl).put("responseSamlEndpoint",suite);
        assertDoesNotThrow(()->SloRegisteredSignerNativeAdapters.requireNativeResponseBinding(n,new byte[0],location,response,suite+"?"+query,query,"GET"));
        String encodedEndpoint="https://suite.example/sp%20name/slo";var encoded=n.deepCopy().put("responseSamlEndpoint",encodedEndpoint);
        assertDoesNotThrow(()->SloRegisteredSignerNativeAdapters.requireNativeResponseBinding(encoded,new byte[0],(encodedEndpoint+"?"+query).getBytes(StandardCharsets.UTF_8),response,encodedEndpoint+"?"+query,query,"GET"));
        String fixedEndpoint=encodedEndpoint+"?tenant=x&language=en%20GB",fixedQuery="tenant=x&language=en%20GB&"+query;
        var fixed=encoded.deepCopy().put("responseSamlEndpoint",fixedEndpoint);byte[] fixedLocation=(encodedEndpoint+"?"+fixedQuery).getBytes(StandardCharsets.UTF_8);
        assertDoesNotThrow(()->SloRegisteredSignerNativeAdapters.requireNativeResponseBinding(fixed,new byte[0],fixedLocation,response,encodedEndpoint+"?"+fixedQuery,fixedQuery,"GET"));
        assertThrows(IllegalArgumentException.class,()->SloRegisteredSignerNativeAdapters.requireNativeResponseBinding(fixed.deepCopy().put("responseSamlEndpoint",fixedEndpoint.replace("tenant=x","tenant=other")),new byte[0],fixedLocation,response,encodedEndpoint+"?"+fixedQuery,fixedQuery,"GET"));
        assertThrows(IllegalArgumentException.class,()->SloRegisteredSignerNativeAdapters.requireNativeResponseBinding(n,new byte[0],location,response,suite,query,"GET"));
        assertThrows(IllegalArgumentException.class,()->SloRegisteredSignerNativeAdapters.requireNativeResponseBinding(n,new byte[0],location,response,suite,query+"&foreign=1","GET"));
        assertThrows(IllegalArgumentException.class,()->SloRegisteredSignerNativeAdapters.requireNativeResponseBinding(n,new byte[0],location,"<LogoutResponse ID='foreign'/>".getBytes(StandardCharsets.UTF_8),suite+"?"+query,query,"GET"));
        assertThrows(IllegalArgumentException.class,()->SloRegisteredSignerNativeAdapters.requireNativeResponseBinding(n,new byte[0],(new String(location,StandardCharsets.UTF_8).replace(suite,"https://foreign.example/slo")).getBytes(StandardCharsets.UTF_8),response,suite+"?"+query,query,"GET"));
        assertThrows(IllegalArgumentException.class,()->SloRegisteredSignerNativeAdapters.requireNativeResponseBinding(n,new byte[0],null,response,suite+"?"+query,query,"GET"));
    }
}
