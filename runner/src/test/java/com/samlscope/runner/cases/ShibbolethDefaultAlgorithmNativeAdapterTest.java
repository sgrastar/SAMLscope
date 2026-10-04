package com.samlscope.runner.cases;
import static org.junit.jupiter.api.Assertions.*;
import java.time.Instant;
import java.time.Clock;
import java.time.ZoneOffset;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import com.samlscope.store.JsonCodec;
import com.samlscope.saml.crypto.FilePlanKeyStore;
import com.samlscope.saml.normal.SecureXml;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class ShibbolethDefaultAlgorithmNativeAdapterTest {
    @TempDir Path temporary;
    private final Instant begin=Instant.parse("2026-10-03T11:00:00.123400Z"),end=Instant.parse("2026-10-03T11:00:01Z");
    private final String thread="http-nio-8080-exec-12",cause="Algorithm failed include/exclude validation: http://www.w3.org/2001/04/xmlenc#rsa-1_5";
    private String header(String at,String selected){return at+" - 172.21.0.1 - WARN ["+selected+"] [org.opensaml.xmlsec.encryption.support.Decrypter:99] - failure\n";}
    @Test void stockMetadataModelFormattingPreservesTheSeparatelyVerifiedOriginal()throws Exception {
        var original=signedMetadata();
        assertDoesNotThrow(()->ShibbolethDefaultAlgorithmNativeAdapter.validateNativeMetadataReadBack(original,original));
        var model=nativeMetadataModel(original);
        assertDoesNotThrow(()->ShibbolethDefaultAlgorithmNativeAdapter.validateNativeMetadataReadBack(original,SecureXml.serialize(model)));
        var key=new FilePlanKeyStore(temporary.toRealPath().resolve("keys"),Clock.fixed(begin,ZoneOffset.UTC)).getOrCreate(DefaultAlgorithmPreventionProbeTestCaseTest.PLAN);
        assertTrue(new com.samlscope.saml.crypto.XmlSignatureVerifier().hasValidEnvelopedSignature(SecureXml.parse(original).getDocumentElement(),key.certificate()));
        assertFalse(new com.samlscope.saml.crypto.XmlSignatureVerifier().hasValidEnvelopedSignature(model.getDocumentElement(),key.certificate()));
    }
    @Test void nativeMetadataModelCannotChangeEndpointKeyRoleIdentityOrExpiration()throws Exception {
        var original=signedMetadata();
        for(String change:List.of("endpoint","key","protocol","entity","expiry","missing-expiry")) {
            var model=nativeMetadataModel(original);var root=model.getDocumentElement();
            switch(change) {
                case "endpoint"->((org.w3c.dom.Element)root.getElementsByTagNameNS(DefaultAlgorithmPreventionEvidence.MD,"AssertionConsumerService").item(0)).setAttribute("Location","https://other.example/acs");
                case "key"->root.getElementsByTagNameNS(DefaultAlgorithmPreventionEvidence.DS,"X509Certificate").item(1).setTextContent("ZGlmZmVyZW50");
                case "protocol"->((org.w3c.dom.Element)root.getElementsByTagNameNS(DefaultAlgorithmPreventionEvidence.MD,"SPSSODescriptor").item(0)).setAttribute("protocolSupportEnumeration","urn:unsupported");
                case "entity"->root.setAttribute("entityID","https://other.example");
                case "expiry"->root.setAttribute("validUntil","2026-10-04T11:00:00.124Z");
                case "missing-expiry"->root.removeAttribute("validUntil");
            }
            assertThrows(IllegalArgumentException.class,()->ShibbolethDefaultAlgorithmNativeAdapter.validateNativeMetadataReadBack(original,SecureXml.serialize(model)),change);
        }
    }
    @Test void nativeMetadataModelCanOmitOnlyRootSignatureMathValues()throws Exception {
        var original=signedMetadata();
        for(String change:List.of("reference","signature-method","digest-method","missing-signature","nonempty-invalid-value")) {
            var model=nativeMetadataModel(original);var root=model.getDocumentElement();String ds=DefaultAlgorithmPreventionEvidence.DS;
            switch(change) {
                case "reference"->((org.w3c.dom.Element)root.getElementsByTagNameNS(ds,"Reference").item(0)).setAttribute("URI","#other-document");
                case "signature-method"->((org.w3c.dom.Element)root.getElementsByTagNameNS(ds,"SignatureMethod").item(0)).setAttribute("Algorithm","urn:other-algorithm");
                case "digest-method"->((org.w3c.dom.Element)root.getElementsByTagNameNS(ds,"DigestMethod").item(0)).setAttribute("Algorithm","urn:other-digest");
                case "missing-signature"->root.removeChild(root.getElementsByTagNameNS(ds,"Signature").item(0));
                case "nonempty-invalid-value"->root.getElementsByTagNameNS(ds,"SignatureValue").item(0).setTextContent("ZGlmZmVyZW50");
            }
            assertThrows(IllegalArgumentException.class,()->ShibbolethDefaultAlgorithmNativeAdapter.validateNativeMetadataReadBack(original,SecureXml.serialize(model)),change);
        }
    }
    private byte[] signedMetadata()throws Exception {
        var key=new FilePlanKeyStore(temporary.toRealPath().resolve("keys"),Clock.fixed(begin,ZoneOffset.UTC)).getOrCreate(DefaultAlgorithmPreventionProbeTestCaseTest.PLAN);
        String md=DefaultAlgorithmPreventionEvidence.MD,ds=DefaultAlgorithmPreventionEvidence.DS;
        String cert=Base64.getEncoder().encodeToString(key.certificate().getEncoded());
        var doc=SecureXml.parse(("<md:EntityDescriptor xmlns:md='"+md+"' xmlns:ds='"+ds+"' ID='_metadata' entityID='https://suite.example' validUntil='2026-10-04T11:00:00.123456789Z'><md:SPSSODescriptor protocolSupportEnumeration='"+DefaultAlgorithmPreventionEvidence.P+"'><md:KeyDescriptor use='signing'><ds:KeyInfo><ds:X509Data><ds:X509Certificate>"+cert+"</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:AssertionConsumerService Binding='"+DefaultAlgorithmPreventionEvidence.POST+"' Location='https://suite.example/acs' index='0'/></md:SPSSODescriptor></md:EntityDescriptor>").getBytes(StandardCharsets.UTF_8));
        var root=doc.getDocumentElement();new com.samlscope.saml.crypto.XmlSigner().sign(root,key,(org.w3c.dom.Element)root.getFirstChild());return SecureXml.serialize(doc);
    }
    private org.w3c.dom.Document nativeMetadataModel(byte[] original) {
        var model=SecureXml.parse(original);model.getDocumentElement().setAttribute("validUntil","2026-10-04T11:00:00.123Z");
        for(String value:List.of("SignatureValue","DigestValue"))model.getDocumentElement().getElementsByTagNameNS(DefaultAlgorithmPreventionEvidence.DS,value).item(0).setTextContent("");
        return model;
    }
    @Test void nativeAuditPatternTagSpellingIsPreservedWithOnlyPermittedInstrumentationChanges(){
        for(String tag:List.of("pattern","Pattern")){
            String original="<configuration><pattern>%date{ISO8601} - %mdc{idp.remote_addr} - %level [%logger:%line] - %msg%n %ex{short}</pattern><"+tag+">%msg%n</"+tag+"></configuration>";
            String configured=original.replace("%date{ISO8601} - %mdc{idp.remote_addr} - %level [%logger:%line] - %msg%n","%date{ISO8601,UTC} - %mdc{idp.remote_addr} - %level [%thread] [%logger:%line] - %msg%n")
                .replace("<"+tag+">%msg%n</"+tag+">","<"+tag+">%msg|%thread%n</"+tag+">").replace("%ex{short}","%ex{full}");
            assertDoesNotThrow(()->ShibbolethDefaultAlgorithmNativeAdapter.validateLogback(original.getBytes(StandardCharsets.UTF_8),configured.getBytes(StandardCharsets.UTF_8)),tag);
            String modified=configured.replace("</configuration>","<logger name='extra' level='DEBUG'/></configuration>");
            assertThrows(IllegalArgumentException.class,()->ShibbolethDefaultAlgorithmNativeAdapter.validateLogback(original.getBytes(StandardCharsets.UTF_8),modified.getBytes(StandardCharsets.UTF_8)),tag);
        }
    }
    @Test void ambiguousAuditTagAndUnapprovedTagNormalizationCannotProveExactInstrumentation(){
        String old="%date{ISO8601} - %mdc{idp.remote_addr} - %level [%logger:%line] - %msg%n";
        String instrumented="%date{ISO8601,UTC} - %mdc{idp.remote_addr} - %level [%thread] [%logger:%line] - %msg%n";
        String prefix="<configuration><pattern>"+old+"</pattern>";
        String mixed=prefix+"<pattern>%msg%n</pattern><Pattern>%msg%n</Pattern></configuration>";
        String mixedConfigured=mixed.replace(old,instrumented).replace("<pattern>%msg%n</pattern>","<pattern>%msg|%thread%n</pattern>");
        assertThrows(IllegalArgumentException.class,()->ShibbolethDefaultAlgorithmNativeAdapter.validateLogback(mixed.getBytes(StandardCharsets.UTF_8),mixedConfigured.getBytes(StandardCharsets.UTF_8)));
        String uppercase=prefix+"<Pattern>%msg%n</Pattern></configuration>";
        String normalized=uppercase.replace(old,instrumented).replace("<Pattern>%msg%n</Pattern>","<pattern>%msg|%thread%n</pattern>");
        assertThrows(IllegalArgumentException.class,()->ShibbolethDefaultAlgorithmNativeAdapter.validateLogback(uppercase.getBytes(StandardCharsets.UTF_8),normalized.getBytes(StandardCharsets.UTF_8)));
    }
    @Test void exactNativeThreadAndUtcLogWindowBindTheActualCause(){
        assertTrue(ShibbolethDefaultAlgorithmNativeAdapter.nativeCause(header("2026-10-03 11:00:00,123",thread)+"Caused by: "+cause,thread,begin,end,cause));
    }
    @Test void AnotherRequestThreadAndOtherEpochNeverProveRejection(){
        assertFalse(ShibbolethDefaultAlgorithmNativeAdapter.nativeCause(header("2026-10-03 11:00:00,123","other-request")+cause,thread,begin,end,cause));
        assertFalse(ShibbolethDefaultAlgorithmNativeAdapter.nativeCause(header("2026-10-03 10:59:59,999",thread)+cause,thread,begin,end,cause));
        assertFalse(ShibbolethDefaultAlgorithmNativeAdapter.nativeCause(header("2026-10-03 11:00:01,001",thread)+cause,thread,begin,end,cause));
    }
    @Test void AFollowingOtherThreadHeaderCannotDonateItsExceptionStack(){
        assertFalse(ShibbolethDefaultAlgorithmNativeAdapter.nativeCause(header("2026-10-03 11:00:00,123",thread)+header("2026-10-03 11:00:00,124","other-request")+cause,thread,begin,end,cause));
    }
    @Test void AlgorithmUriPrefixDoesNotAcceptAnUnrelatedAlgorithm(){
        assertFalse(ShibbolethDefaultAlgorithmNativeAdapter.nativeCause(header("2026-10-03 11:00:00,123",thread)+cause+"-other",thread,begin,end,cause));
        assertTrue(ShibbolethDefaultAlgorithmNativeAdapter.nativeCause(header("2026-10-03 11:00:00,123",thread)+cause+"\n",thread,begin,end,cause));
    }
    @Test void PlainDeclaredCauseWithoutNativeHeaderOrWithWrongAlgorithmIsUnproven(){
        assertFalse(ShibbolethDefaultAlgorithmNativeAdapter.nativeCause(cause,thread,begin,end,cause));
        assertFalse(ShibbolethDefaultAlgorithmNativeAdapter.nativeCause(header("2026-10-03 11:00:00,123",thread)+"generic HTTP500",thread,begin,end,cause));
        assertFalse(ShibbolethDefaultAlgorithmNativeAdapter.nativeCause(header("2026-10-03 11:00:00,123",thread)+cause,thread,begin,end,"Algorithm failed include/exclude validation: http://www.w3.org/2001/04/xmldsig-more#rsa-md5"));
    }
    private String stockSignatureFailure(String entity,String nativeThread,String time) {
        String crypto=time+" - 172.21.0.1 - WARN ["+nativeThread+"] [org.apache.xml.security.signature.XMLSignature:908] - Signature verification failed.\n";
        String protocol=time+" - 172.21.0.1 - WARN ["+nativeThread+"] [org.opensaml.saml.common.binding.security.impl.SAMLProtocolMessageXMLSignatureSecurityHandler:142] - Message Handler: Validation of protocol message signature failed for context issuer '"+entity+"', message type: {urn:oasis:names:tc:SAML:2.0:protocol}AuthnRequest\n";
        return crypto+protocol;
    }
    @Test void stockNativeSignatureFailureIsBoundToBothConsumerClassesAndItsIssuer() {
        String entity="http://localhost:18080/p/plan_0123456789ABCDEFGHJKMNPQRS";
        String original=stockSignatureFailure(entity,thread,"2026-10-03 11:00:00,123");
        assertTrue(ShibbolethDefaultAlgorithmNativeAdapter.nativeSignatureRejection(original,thread,begin,end,entity));
        for(String changed:List.of(original.replace("XMLSignature:908","ForeignConsumer:908"),
                original.replace("SAMLProtocolMessageXMLSignatureSecurityHandler:142","ForeignHandler:142"),
                original.replace(entity,"http://foreign.example/peer"),original.replace("AuthnRequest","LogoutRequest")))
            assertFalse(ShibbolethDefaultAlgorithmNativeAdapter.nativeSignatureRejection(changed,thread,begin,end,entity));
    }
    @Test void stockNativeSignatureFailureNeedsBothOriginalLinesInOrderWithinItsRequestWindow() {
        String entity="https://actual-suite.example/peer",original=stockSignatureFailure(entity,thread,"2026-10-03 11:00:00,123");
        var lines=original.lines().toList();
        for(String changed:List.of(lines.getFirst(),lines.getLast(),lines.getLast()+"\n"+lines.getFirst(),
                original.replace(thread,"unrelated-thread"),original.replace("11:00:00,123","10:59:59,999"),
                original.replace("11:00:00,123","11:00:01,001")))
            assertFalse(ShibbolethDefaultAlgorithmNativeAdapter.nativeSignatureRejection(changed,thread,begin,end,entity));
    }
    @Test void httpFailureAndUnqualifiedSignatureTextNeverProveStockNativeSignatureRejection() {
        String entity="https://actual-suite.example/peer";
        for(String log:List.of("HTTP 400 MessageAuthenticationError","Signature verification failed.",
                header("2026-10-03 11:00:00,123",thread)+"Signature verification failed."))
            assertFalse(ShibbolethDefaultAlgorithmNativeAdapter.nativeSignatureRejection(log,thread,begin,end,entity));
    }
    private final String md5Entity="https://suite.example/p/plan_0123456789ABCDEFGHJKMNPQRS";
    private String md5Chain() {
        var consumers=List.of("org.opensaml.xmlsec.algorithm.AlgorithmSupport|Algorithm failed exclude list validation: http://www.w3.org/2001/04/xmldsig-more#md5",
                "org.opensaml.xmlsec.signature.support.impl.BaseSignatureTrustEngine|XML signature failed algorithm include/exclude validation",
                "org.opensaml.saml.common.binding.security.impl.SAMLProtocolMessageXMLSignatureSecurityHandler|Message Handler: Validation of protocol message signature failed for context issuer '"+md5Entity+"', message type: {urn:oasis:names:tc:SAML:2.0:protocol}AuthnRequest",
                "org.opensaml.profile.action.impl.LogEvent|A non-proceed event occurred while processing the request: MessageAuthenticationError");
        StringBuilder value=new StringBuilder();for(String consumer:consumers) {
            var fields=consumer.split("\\|",2);value.append("2026-10-03 11:00:00,123 - 172.21.0.1 - WARN [").append(thread)
                    .append("] [").append(fields[0]).append(":99] - ").append(fields[1]).append('\n');
        }return value.toString();
    }
    private boolean md5(String log) {
        return ShibbolethDefaultAlgorithmNativeAdapter.nativeMd5DigestRejection("MessageAuthenticationError",log,thread,begin,end,md5Entity);
    }
    @Test void md5DigestRejectionRequiresTheExactStockExcludeListAndCausalConsumerChain() {
        assertTrue(md5(md5Chain()));
        for(String event:List.of("","Success","DecryptNameIDFailed"))
            assertFalse(ShibbolethDefaultAlgorithmNativeAdapter.nativeMd5DigestRejection(event,md5Chain(),thread,begin,end,md5Entity));
    }
    @Test void md5DigestUriLoggerSeverityAndIncludeExcludeLabelCannotBeSubstituted() {
        String original=md5Chain();
        for(String altered:List.of(original.replace("#md5","#md5-other"),original.replace("#md5","#rsa-md5"),
                original.replace("Algorithm failed exclude list validation","Algorithm failed include/exclude validation"),
                original.replace("AlgorithmSupport:99","ForeignAlgorithm:99"),original.replace("BaseSignatureTrustEngine:99","ForeignTrust:99"),
                original.replace("SAMLProtocolMessageXMLSignatureSecurityHandler:99","ForeignHandler:99"),original.replace("LogEvent:99","ForeignEvent:99"),
                original.replace(" - WARN ["," - INFO [")))assertFalse(md5(altered));
    }
    @Test void md5DigestAllStepsMustBelongToTheSameNativeRequestThreadAndClockWindow() {
        var lines=md5Chain().lines().toList();
        for(int i=0;i<lines.size();i++) {
            var altered=new ArrayList<>(lines);altered.set(i,lines.get(i).replace(thread,"other-request"));assertFalse(md5(String.join("\n",altered)));
            altered=new ArrayList<>(lines);altered.set(i,lines.get(i).replace("11:00:00,123","10:59:59,999"));assertFalse(md5(String.join("\n",altered)));
            altered=new ArrayList<>(lines);altered.set(i,lines.get(i).replace("11:00:00,123","11:00:01,001"));assertFalse(md5(String.join("\n",altered)));
        }
    }
    @Test void md5DigestIncompleteDuplicateReversedOrBackwardsTimeChainsRemainUnproven() {
        var lines=md5Chain().lines().toList();
        for(int i=0;i<lines.size();i++) {
            var altered=new ArrayList<>(lines);altered.remove(i);assertFalse(md5(String.join("\n",altered)));
        }
        assertFalse(md5(md5Chain()+lines.getFirst()));
        var reversed=new ArrayList<>(lines);Collections.reverse(reversed);assertFalse(md5(String.join("\n",reversed)));
        var backwards=new ArrayList<>(lines);backwards.set(0,lines.getFirst().replace("11:00:00,123","11:00:00,124"));
        assertFalse(md5(String.join("\n",backwards)));
    }
    @Test void md5DigestForeignIssuerDifferentMessageAndGenericHttpFailureCannotSupplyCause() {
        assertFalse(md5(md5Chain().replace(md5Entity,"https://foreign.example/peer")));
        assertFalse(md5(md5Chain().replace("AuthnRequest","LogoutRequest")));
        for(String value:List.of("HTTP 400 MessageAuthenticationError","Algorithm failed exclude list validation: http://www.w3.org/2001/04/xmldsig-more#md5",
                header("2026-10-03 11:00:00,123",thread)+"MessageAuthenticationError"))assertFalse(md5(value));
    }
    @Test void md5DigestCauseWithoutFixedNativeJarAndClassProvidersCannotBeAdopted()throws Exception {
        Path folder=temporary.toRealPath();var scope=new JsonCodec().mapper().createObjectNode();
        var jars=scope.putObject("jars");var classpath=scope.putObject("classpath");
        for(String group:List.of("opensaml-xmlsec-api","opensaml-xmlsec-impl","opensaml-saml-impl","opensaml-profile-impl")) {
            Files.writeString(folder.resolve(group+".jar"),"foreign native bytecode");jars.put(group,group+".jar");
            classpath.put("/usr/local/tomcat/webapps/idp/WEB-INF/lib/"+group+"-5.2.3.jar",ShibbolethDefaultAlgorithmNativeAdapter.JARS.get(group));
        }
        assertThrows(IllegalArgumentException.class,()->ShibbolethDefaultAlgorithmNativeAdapter.validateMd5ConsumerClasses(folder,scope));
    }
    @Test void ingressProofRequiresDistinctRecordedControlAndDecoderOriginals() {
        var control=new com.samlscope.core.evaluation.EvidenceRef("transcript","tx_control");
        var decoder=new com.samlscope.core.evaluation.EvidenceRef("transcript","tx_decoder");
        assertDoesNotThrow(()->new DefaultAlgorithmNativeAdapter.IngressRejectionProof("native-SignatureAlgorithmValidator",control,decoder));
        assertThrows(IllegalArgumentException.class,()->new DefaultAlgorithmNativeAdapter.IngressRejectionProof("native-SignatureAlgorithmValidator",control,control));
        assertThrows(IllegalArgumentException.class,()->new DefaultAlgorithmNativeAdapter.IngressRejectionProof("native-SignatureAlgorithmValidator",new com.samlscope.core.evaluation.EvidenceRef("native","declared-control"),decoder));
    }
    private static org.w3c.dom.Element logoutReply(String status) {
        return SecureXml.parse(("<p:LogoutResponse xmlns:p='urn:oasis:names:tc:SAML:2.0:protocol'>"
                +"<p:Status><p:StatusCode Value='urn:oasis:names:tc:SAML:2.0:status:"+status+"'/></p:Status></p:LogoutResponse>").getBytes(StandardCharsets.UTF_8)).getDocumentElement();
    }
    private String rsa15Chain() {
        List<String> consumers=List.of("WARN|org.opensaml.xmlsec.algorithm.AlgorithmSupport|Algorithm failed exclude list validation: http://www.w3.org/2001/04/xmlenc#rsa-1_5",
                "ERROR|org.opensaml.xmlsec.encryption.support.Decrypter|Failed to decrypt EncryptedKey, valid decryption key could not be resolved",
                "WARN|org.opensaml.saml.saml2.profile.impl.DecryptNameIDs|Profile Action DecryptNameIDs: Failure performing decryption",
                "WARN|org.opensaml.profile.action.impl.LogEvent|A non-proceed event occurred while processing the request: DecryptNameIDFailed");
        StringBuilder text=new StringBuilder();for(String value:consumers) {
            var fields=value.split("\\|",3);text.append("2026-10-03 11:00:00,123 - 172.21.0.1 - ").append(fields[0])
                    .append(" [").append(thread).append("] [").append(fields[1]).append(":99] - ").append(fields[2]).append('\n');
        }return text.toString();
    }
    private boolean rsa15(String process) {
        return ShibbolethDefaultAlgorithmNativeAdapter.nativeRsa15Rejection(logoutReply("Responder"),"","Responder",process,thread,begin,end);
    }
    @Test void exactRsa15ChainClosesBlankLogoutErrorEventOnlyWithResponderAuditAndResponse() {
        assertTrue(rsa15(rsa15Chain()));
        assertTrue(ShibbolethDefaultAlgorithmNativeAdapter.nativeRsa15Rejection(logoutReply("Responder"),"DecryptNameIDFailed","Responder",rsa15Chain(),thread,begin,end));
        assertFalse(ShibbolethDefaultAlgorithmNativeAdapter.nativeRsa15Rejection(logoutReply("Responder"),"MessageAuthenticationError","Responder",rsa15Chain(),thread,begin,end));
    }
    @Test void rsa15AlgorithmUriAndCodeProvidersMustMatchExactly() {
        String source=rsa15Chain();
        for(String altered:List.of(source.replace("#rsa-1_5","#rsa-1_5-other"),source.replace("#rsa-1_5","#rsa-oaep-mgf1p"),
                source.replace("AlgorithmSupport:99","ForeignAlgorithm:99"),source.replace("DecryptNameIDs:99","ForeignAction:99"),
                source.replace("exclude list","include/exclude")))assertFalse(rsa15(altered));
    }
    @Test void rsa15OtherNativeRequestThreadCannotSupplyAnyRequiredStep() {
        var lines=rsa15Chain().lines().toList();
        for(int i=0;i<lines.size();i++) {
            var changed=new java.util.ArrayList<>(lines);changed.set(i,lines.get(i).replace(thread,"other-request"));assertFalse(rsa15(String.join("\n",changed)));
        }
    }
    @Test void rsa15ChainMustBeCompleteUniqueAndOrdered() {
        var lines=rsa15Chain().lines().toList();
        for(int i=0;i<lines.size();i++) {var changed=new java.util.ArrayList<>(lines);changed.remove(i);assertFalse(rsa15(String.join("\n",changed)));}
        assertFalse(rsa15(lines.get(1)+"\n"+lines.get(0)+"\n"+lines.get(2)+"\n"+lines.get(3)));
        assertFalse(rsa15(rsa15Chain()+lines.get(0)));assertFalse(rsa15("HTTP400 DecryptNameIDFailed"));
    }
    @Test void rsa15CauseCannotEscapeNativeRequestClockWindowOrReverseTime() {
        assertFalse(rsa15(rsa15Chain().replace("11:00:00,123","10:59:59,999")));
        assertFalse(rsa15(rsa15Chain().replace("11:00:00,123","11:00:01,001")));
        assertFalse(rsa15(rsa15Chain().replaceFirst("11:00:00,123","11:00:00,124")));
    }
    @Test void successfulLogoutOrAbsentReplyCannotBeCalledAnAlgorithmRefusal() {
        assertFalse(ShibbolethDefaultAlgorithmNativeAdapter.nativeRsa15Rejection(logoutReply("Success"),"","Success",rsa15Chain(),thread,begin,end));
        assertFalse(ShibbolethDefaultAlgorithmNativeAdapter.nativeRsa15Rejection(null,"","Responder",rsa15Chain(),thread,begin,end));
        assertFalse(ShibbolethDefaultAlgorithmNativeAdapter.nativeRsa15Rejection(logoutReply("Responder"),"","Success",rsa15Chain(),thread,begin,end));
        assertFalse(ShibbolethDefaultAlgorithmNativeAdapter.nativeRsa15Rejection(logoutReply("Responder"),"","",rsa15Chain(),thread,begin,end));
    }
    @Test void unboundCodeProviderCannotTurnTheDeclaredNativeChainIntoProof()throws Exception {
        Path folder=temporary.toRealPath();var scope=new JsonCodec().mapper().createObjectNode();
        var jars=scope.putObject("jars");var classpath=scope.putObject("classpath");
        for(var group:List.of("opensaml-xmlsec-api","opensaml-saml-impl","opensaml-profile-impl")) {
            String file=group+".jar";Files.write(folder.resolve(file),"unproven-code-provider".getBytes(StandardCharsets.UTF_8));
            jars.put(group,file);classpath.put("/usr/local/tomcat/webapps/idp/WEB-INF/lib/"+group+"-5.2.3.jar",ShibbolethDefaultAlgorithmNativeAdapter.JARS.get(group));
        }
        assertThrows(IllegalArgumentException.class,()->ShibbolethDefaultAlgorithmNativeAdapter.validateRsa15ConsumerClasses(folder,scope));
    }
    private static byte[] auditMap(String entries) {
        return ("<beans xmlns='http://www.springframework.org/schema/beans' xmlns:util='http://www.springframework.org/schema/util'>"
                +"<util:map id='shibboleth.AuditFieldReplacementMap'>"+entries+"</util:map></beans>").getBytes(StandardCharsets.UTF_8);
    }
    @Test void nativeAuditMapRendersTheActualFormatWithoutTreatingItAsAQualifier() {
        String transientUri="urn:oasis:names:tc:SAML:2.0:nameid-format:transient",persistentUri="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent";
        byte[] xml=auditMap("<entry key='"+transientUri+"' value='transient'/><entry key='"+persistentUri+"' value='persistent'/>");
        assertEquals("transient",ShibbolethDefaultAlgorithmNativeAdapter.renderAuditValue(xml,transientUri));
        assertEquals("persistent",ShibbolethDefaultAlgorithmNativeAdapter.renderAuditValue(xml,persistentUri));
        assertEquals("https://actual-suite.example/peer",ShibbolethDefaultAlgorithmNativeAdapter.renderAuditValue(xml,"https://actual-suite.example/peer"));
        assertEquals("transient",ShibbolethDefaultAlgorithmNativeAdapter.renderAuditValue(xml,"transient"));
    }
    @Test void auditRenderingRequiresOneCompleteLiteralMapAndRejectsUnprovenConfiguration() {
        for(byte[] xml:List.of("<beans xmlns='http://www.springframework.org/schema/beans'/>".getBytes(StandardCharsets.UTF_8),
                auditMap("<entry key='format' value='first'/><entry key='format' value='second'/>"),
                auditMap("<entry key='format' value-ref='anotherBean'/>"),auditMap("<entry key='format' value='${hidden}'/>"),
                auditMap("<entry key='format' value='one'><value>another</value></entry>"),
                auditMap("<entry xmlns='' key='format' value='one'/>")))
            assertThrows(IllegalArgumentException.class,()->ShibbolethDefaultAlgorithmNativeAdapter.renderAuditValue(xml,"format"));
        var duplicate=SecureXml.parse(auditMap("<entry key='format' value='one'/>")).getDocumentElement();
        duplicate.appendChild(duplicate.getFirstChild().cloneNode(true));
        assertThrows(IllegalArgumentException.class,()->ShibbolethDefaultAlgorithmNativeAdapter.renderAuditValue(SecureXml.serialize(duplicate.getOwnerDocument()),"format"));
    }
    @Test void aFormatWithoutNativeReplacementRemainsItsOriginalValueAndUnpinnedFormatterCannotProveUse() {
        byte[] xml=auditMap("<entry key='known-format' value='short-name'/>");
        assertEquals("other-format",ShibbolethDefaultAlgorithmNativeAdapter.renderAuditValue(xml,"other-format"));
        assertEquals("",ShibbolethDefaultAlgorithmNativeAdapter.renderAuditValue(xml,""));
        assertThrows(IllegalArgumentException.class,()->ShibbolethDefaultAlgorithmNativeAdapter.validateAuditFormatter("unproven-profile-jar".getBytes(StandardCharsets.UTF_8),"unproven-conf-jar".getBytes(StandardCharsets.UTF_8)));
    }
    @Test void CipherInputMustMatchNativePublishedEncryptionKeyAndAuthenticatedIdentifier()throws Exception {
        var data=cipher();
        assertEquals("known",ShibbolethDefaultAlgorithmNativeAdapter.validateCipherInput(data.output,DefaultAlgorithmPreventionProbeTestCaseTest.RUN,"rsa15-encrypted-id","_request",data.request,data.target,data.name).getTextContent());
        for(String field:List.of("runId","requestId","requestSha256","producerSourceSha256","nativeEncryptionCertificateSha256","nativeEncryptionSpkiSha256","decryptedNameIdSha256","transportAlgorithm")) {
            var wrong=data.output.deepCopy();wrong.put(field,"wrong");assertThrows(Exception.class,()->ShibbolethDefaultAlgorithmNativeAdapter.validateCipherInput(wrong,DefaultAlgorithmPreventionProbeTestCaseTest.RUN,"rsa15-encrypted-id","_request",data.request,data.target,data.name),field);
        }
        var other=SecureXml.parse(("<s:NameID xmlns:s='"+DefaultAlgorithmPreventionEvidence.A+"' Format='known-format'>different</s:NameID>").getBytes()).getDocumentElement();
        assertThrows(Exception.class,()->ShibbolethDefaultAlgorithmNativeAdapter.validateCipherInput(data.output,DefaultAlgorithmPreventionProbeTestCaseTest.RUN,"rsa15-encrypted-id","_request",data.request,data.target,other));
    }
    @Test void InputOnlyLabelsAndTamperedPlaintextNeverStandInForNativeMath()throws Exception {
        var data=cipher();for(String field:List.of("inputValidationOnly","authenticatedGcm")) {
            var wrong=data.output.deepCopy();wrong.put(field,false);assertThrows(Exception.class,()->ShibbolethDefaultAlgorithmNativeAdapter.validateCipherInput(wrong,DefaultAlgorithmPreventionProbeTestCaseTest.RUN,"rsa15-encrypted-id","_request",data.request,data.target,data.name));
        }
        var wrongPolicy=data.output.deepCopy();wrongPolicy.put("productAlgorithmPolicyEvaluated",true);
        assertThrows(Exception.class,()->ShibbolethDefaultAlgorithmNativeAdapter.validateCipherInput(wrongPolicy,DefaultAlgorithmPreventionProbeTestCaseTest.RUN,"rsa15-encrypted-id","_request",data.request,data.target,data.name));
        var exportedKey=data.output.deepCopy();exportedKey.put("privateKeyExported",true);
        assertThrows(Exception.class,()->ShibbolethDefaultAlgorithmNativeAdapter.validateCipherInput(exportedKey,DefaultAlgorithmPreventionProbeTestCaseTest.RUN,"rsa15-encrypted-id","_request",data.request,data.target,data.name));
        var missingExportState=data.output.deepCopy();missingExportState.remove("privateKeyExported");
        assertThrows(Exception.class,()->ShibbolethDefaultAlgorithmNativeAdapter.validateCipherInput(missingExportState,DefaultAlgorithmPreventionProbeTestCaseTest.RUN,"rsa15-encrypted-id","_request",data.request,data.target,data.name));
        var altered=data.output.deepCopy();altered.put("decryptedNameIdBase64",Base64.getEncoder().encodeToString("corrupt".getBytes()));
        assertThrows(Exception.class,()->ShibbolethDefaultAlgorithmNativeAdapter.validateCipherInput(altered,DefaultAlgorithmPreventionProbeTestCaseTest.RUN,"rsa15-encrypted-id","_request",data.request,data.target,data.name));
    }
    @Test void ProductionAdapterRejectsCounterfactualBeforeReadingNativeOrProtocolOriginals()throws Exception {
        var m=new JsonCodec().mapper().createObjectNode().put("counterfactualCalibrationOnly",true);
        var adapter=new ShibbolethDefaultAlgorithmNativeAdapter(e->{throw new AssertionError("Counterfactual reached production content reader");});
        assertThrows(IllegalArgumentException.class,()->adapter.open(ClockSkewEvidenceTestCaseTest.context(true),temporary.toRealPath(),m,new byte[0],new byte[0]));
        var offline=new ShibbolethDefaultAlgorithmNativeAdapter(e->{throw new AssertionError("Missing originals reached content reader");},true);
        assertThrows(Exception.class,()->offline.open(ClockSkewEvidenceTestCaseTest.context(true),temporary.toRealPath(),m,new byte[0],"<md:EntityDescriptor xmlns:md='urn:oasis:names:tc:SAML:2.0:metadata' entityID='https://suite.example'/>".getBytes()));
    }
    @Test void StockOutputRelabelledAsMutantCannotEnableOfflineViolation() {
        var output=calibrationOutput(false);assertDoesNotThrow(()->ShibbolethDefaultAlgorithmNativeAdapter.calibrationOutput(output,DefaultAlgorithmPreventionProbeTestCaseTest.RUN,ShibbolethDefaultAlgorithmNativeAdapter.STOCK,"suite-sha","target-sha"));
        output.put("selectedPath",ShibbolethDefaultAlgorithmNativeAdapter.MUTANT).put("counterfactualCalibrationOnly",true);
        assertThrows(IllegalArgumentException.class,()->ShibbolethDefaultAlgorithmNativeAdapter.calibrationOutput(output,DefaultAlgorithmPreventionProbeTestCaseTest.RUN,ShibbolethDefaultAlgorithmNativeAdapter.MUTANT,"suite-sha","target-sha"));
    }
    @Test void FalsifyingReceiptCalibrationLabelsNeverEnablesTheProductionAdapter() {
        var mapper=new JsonCodec().mapper();var manifest=mapper.createObjectNode().put("counterfactualCalibrationOnly",true);
        var use=mapper.createObjectNode().put("calibrationOutputReference","tx_actual_diagnostic").put("counterfactualCalibrationOnly",true).put("diagnosticOnly",true);
        assertTrue(ShibbolethDefaultAlgorithmNativeAdapter.calibrationSelected(true,manifest,use));
        assertThrows(IllegalArgumentException.class,()->ShibbolethDefaultAlgorithmNativeAdapter.calibrationSelected(false,manifest,use));
        manifest.put("counterfactualCalibrationOnly",false);
        assertThrows(IllegalArgumentException.class,()->ShibbolethDefaultAlgorithmNativeAdapter.calibrationSelected(false,manifest,use));
        assertThrows(IllegalArgumentException.class,()->ShibbolethDefaultAlgorithmNativeAdapter.calibrationSelected(true,manifest,use));
        use.put("counterfactualCalibrationOnly",false).put("diagnosticOnly",false);
        assertThrows(IllegalArgumentException.class,()->ShibbolethDefaultAlgorithmNativeAdapter.calibrationSelected(false,manifest,use));
        assertThrows(IllegalArgumentException.class,()->ShibbolethDefaultAlgorithmNativeAdapter.calibrationSelected(true,manifest,use));
    }
    @Test void ActualSelectedAlgorithmDecisionAndResponseHashDetermineCalibrationUse()throws Exception {
        byte[] response="counterfactual response bytes".getBytes();String hash=DefaultAlgorithmPreventionEvidence.hash(response);
        var stock=decision(true,false,false);stock.put("nativeAlgorithmPolicyError","Algorithm failed include/exclude validation: http://www.w3.org/2001/04/xmldsig-more#md5");
        var selected=decision(true,true,true).put("responseSha256",hash).put("responseBase64",Base64.getEncoder().encodeToString(response));
        assertEquals(DefaultAlgorithmNativeAdapter.Decision.CONSUMED_SUCCESS,ShibbolethDefaultAlgorithmNativeAdapter.calibrationDecision(selected,stock,"md5-digest",hash));
        assertThrows(IllegalArgumentException.class,()->ShibbolethDefaultAlgorithmNativeAdapter.calibrationDecision(selected,selected,"md5-digest",hash));
        assertThrows(IllegalArgumentException.class,()->ShibbolethDefaultAlgorithmNativeAdapter.calibrationDecision(selected,stock,"md5-digest","0".repeat(64)));
        var falseDeclaration=decision(true,false,true).put("responseSha256",hash).put("responseBase64",Base64.getEncoder().encodeToString(response));
        assertThrows(IllegalArgumentException.class,()->ShibbolethDefaultAlgorithmNativeAdapter.calibrationDecision(falseDeclaration,stock,"md5-digest",hash));
    }
    @Test void MathematicalInvalidControlCannotBecomeAnAcceptedWeakInput() {
        var invalid=decision(false,true,false);
        assertEquals(DefaultAlgorithmNativeAdapter.Decision.INVALID_SIGNATURE_REJECTION,ShibbolethDefaultAlgorithmNativeAdapter.calibrationDecision(invalid,invalid,"invalid-sha256-signature",null));
        assertThrows(IllegalArgumentException.class,()->ShibbolethDefaultAlgorithmNativeAdapter.calibrationDecision(invalid,invalid,"md5-digest",null));
        var fakeAccepted=decision(false,true,true);
        assertThrows(IllegalArgumentException.class,()->ShibbolethDefaultAlgorithmNativeAdapter.calibrationDecision(fakeAccepted,invalid,"invalid-sha256-signature",null));
    }
    private ObjectNode decision(boolean mathematical,boolean allowed,boolean accepted){return new JsonCodec().mapper().createObjectNode().put("mathematicalSignatureValid",mathematical).put("nativeAlgorithmPolicyAccepted",allowed).put("selectedConsumerAccepted",accepted);}
    private ObjectNode calibrationOutput(boolean mutant) {
        var mapper=new JsonCodec().mapper();var output=mapper.createObjectNode().put("schema",ShibbolethDefaultAlgorithmNativeAdapter.CALIBRATION).put("runId",DefaultAlgorithmPreventionProbeTestCaseTest.RUN)
                .put("selectedPath",mutant?ShibbolethDefaultAlgorithmNativeAdapter.MUTANT:ShibbolethDefaultAlgorithmNativeAdapter.STOCK).put("counterfactualCalibrationOnly",mutant).put("diagnosticOnly",true)
                .put("productFinding",false).put("privateKeyExported",false).put("producerSourceSha256",ShibbolethDefaultAlgorithmNativeAdapter.CALIBRATION_SOURCE_SHA256).put("suiteMetadataSha256","suite-sha").put("targetMetadataSha256","target-sha");
        output.set("nativeClasses",mapper.valueToTree(new TreeMap<>(ShibbolethDefaultAlgorithmNativeAdapter.CALIBRATION_CLASSES)));
        var algorithms=List.of("http://www.w3.org/2001/04/xmldsig-more#md5","http://www.w3.org/2001/04/xmldsig-more#rsa-md5","http://www.w3.org/2001/04/xmldsig-more#hmac-md5");
        output.set("stockExcludedAlgorithms",mapper.valueToTree(algorithms));output.set("selectedExcludedAlgorithms",mapper.valueToTree(mutant?List.of():algorithms));var records=output.putArray("records");
        for(String fixture:List.of("sha256-control","invalid-sha256-signature","md5-digest","rsa-md5"))records.add(mapper.createObjectNode().put("fixtureId",fixture));return output;
    }
    private record Cipher(ObjectNode output,byte[] request,org.w3c.dom.Element target,org.w3c.dom.Element name){}
    private Cipher cipher()throws Exception {
        var key=new FilePlanKeyStore(temporary.toRealPath().resolve("keys"),Clock.fixed(begin,ZoneOffset.UTC)).getOrCreate(DefaultAlgorithmPreventionProbeTestCaseTest.PLAN);
        byte[] request="public-signed-input".getBytes(StandardCharsets.UTF_8),clear=("<s:NameID xmlns:s='"+DefaultAlgorithmPreventionEvidence.A+"' Format='known-format'>known</s:NameID>").getBytes(StandardCharsets.UTF_8);
        String certificate=Base64.getEncoder().encodeToString(key.certificate().getEncoded());
        var target=SecureXml.parse(("<md:EntityDescriptor xmlns:md='"+DefaultAlgorithmPreventionEvidence.MD+"' xmlns:ds='"+DefaultAlgorithmPreventionEvidence.DS+"' entityID='https://target.example'><md:IDPSSODescriptor><md:KeyDescriptor use='encryption'><ds:KeyInfo><ds:X509Data><ds:X509Certificate>"+certificate+"</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor></md:IDPSSODescriptor></md:EntityDescriptor>").getBytes()).getDocumentElement();
        var value=new JsonCodec().mapper().createObjectNode().put("schema","samlscope-shibboleth-cipher-input-validation-v1").put("runId",DefaultAlgorithmPreventionProbeTestCaseTest.RUN)
                .put("requestId","_request").put("requestSha256",DefaultAlgorithmPreventionEvidence.hash(request)).put("inputValidationOnly",true).put("productAlgorithmPolicyEvaluated",false).put("authenticatedGcm",true)
                .put("privateKeyExported",false).put("producerSourceSha256",ShibbolethDefaultAlgorithmNativeAdapter.CIPHER_SOURCE_SHA256).put("transportAlgorithm","http://www.w3.org/2001/04/xmlenc#rsa-1_5")
                .put("decryptedNameIdBase64",Base64.getEncoder().encodeToString(clear)).put("decryptedNameIdSha256",DefaultAlgorithmPreventionEvidence.hash(clear))
                .put("nativeEncryptionCertificateSha256",DefaultAlgorithmPreventionEvidence.hash(key.certificate().getEncoded())).put("nativeEncryptionSpkiSha256",DefaultAlgorithmPreventionEvidence.hash(key.certificate().getPublicKey().getEncoded()));
        return new Cipher(value,request,target,SecureXml.parse(clear).getDocumentElement());
    }
}
