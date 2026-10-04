package com.samlscope.runner.cases;

import static org.junit.jupiter.api.Assertions.*;
import com.samlscope.core.transcript.*;
import com.samlscope.core.plan.*;
import com.samlscope.core.run.Reachability;
import com.samlscope.core.evaluation.Outcome;
import com.samlscope.runner.DefaultCaseContext;
import com.samlscope.store.JsonCodec;
import java.nio.file.*;
import java.time.*;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class SimpleSamlPhpConsentUriEvidenceTest {
    private static final String RUN="run_00000000000000000000000000";
    @TempDir Path directory;
    private DefaultCaseContext context(){return new DefaultCaseContext(RUN,TargetRole.IDP,Clock.systemUTC(),TestPlan.Parameters.defaults(),TestPlan.Interaction.defaults(),Reachability.CONFIRMED,
        new TranscriptRecorder(){public List<TranscriptEntry> list(String run){return List.of();}public TranscriptEntry record(TranscriptInput input){throw new AssertionError("Reader must not interact with a product");}
            public TranscriptEntry updateSamlAnalysis(String id,String correlation,Map<String,Object> summary){throw new AssertionError("Reader must not modify originals");}},true);}
    @Test void missingProofDoesNotShadowLegacyButOwnedInvalidProofFailsClosed()throws Exception{
        var reader=new SimpleSamlPhpConsentUriEvidence(directory,e->{throw new AssertionError();});assertFalse(reader.exists(RUN));assertTrue(reader.evaluate(context(),new byte[0]).isEmpty());assertTrue(reader.evaluateDiscovery(context(),new byte[0]).isEmpty());
        Path folder=Files.createDirectory(directory.resolve(RUN));Files.writeString(folder.resolve("manifest.json"),"{\"no_discovery_ui\":true,\"restored\":true}");
        assertEquals(Outcome.NOT_VERIFIED,reader.evaluate(context(),new byte[0]).orElseThrow().outcome());assertEquals(Outcome.NOT_VERIFIED,reader.evaluateDiscovery(context(),new byte[0]).orElseThrow().outcome());
    }
    @Test void ownedFileAndSymlinkFolderCannotClaimNativeNonuse()throws Exception{
        var reader=new SimpleSamlPhpConsentUriEvidence(directory,e->{throw new AssertionError();});Path path=Files.writeString(directory.resolve(RUN),"{}");assertTrue(reader.exists(RUN));assertEquals(Outcome.NOT_VERIFIED,reader.evaluate(context(),new byte[0]).orElseThrow().outcome());
        Files.delete(path);Files.createSymbolicLink(path,Files.createDirectory(directory.resolve("foreign")));assertEquals(Outcome.NOT_VERIFIED,reader.evaluateDiscovery(context(),new byte[0]).orElseThrow().outcome());assertFalse(reader.exists("../"+RUN));
    }
    private com.fasterxml.jackson.databind.node.ObjectNode link(String candidate,String kind)throws Exception{
        var mapper=new JsonCodec().mapper();var value=mapper.createObjectNode();value.put("transportAbortPolicy","only-exact-fixture-url-network;native-state-pages-unmodified");var link=value.putObject("nativeLinkUse");
        link.put("element",kind).put("href",candidate).put("anchorOuterHtml","<a href='"+candidate+"'>"+(kind.equals("InformationURL")?"Go to information page for the service":"Privacy policy for the service\n    SAMLscope URL policy control")+"</a>")
            .put("pagePath",kind.equals("InformationURL")?"/simplesaml/module.php/consent/noconsent":"/simplesaml/module.php/consent/getconsent").put("clickedAt","2026-10-01T00:00:01Z").put("completedAt","2026-10-01T00:00:02Z");
        value.putArray("urlRequests");value.putArray("urlNavigations");value.putArray("urlConsole");value.putArray("urlWindowOpens");value.putArray("nativeSecurityBlocks");return value;
    }
    @Test void domAssignmentAloneIsUnobservedAndNativeUserGestureWindowOpenProvesAnAttempt()throws Exception{
        String uri="data:text/plain,control";var value=link(uri,"PrivacyStatementURL");var condition=SimpleSamlPhpConsentUriEvidence.condition("ui-url-privacy-data");Instant at=Instant.parse("2026-10-01T00:00:03Z");
        assertEquals(UiUrlComparison.Use.UNOBSERVED,SimpleSamlPhpConsentUriEvidence.nativeLinkUse(value,uri,condition,at));
        var open=((com.fasterxml.jackson.databind.node.ArrayNode)value.path("urlWindowOpens")).addObject().put("url",uri).put("userGesture",true).put("source","native-chromium-page-window-open").put("recordedAt","2026-10-01T00:00:01.500Z");
        assertEquals(UiUrlComparison.Use.USED,SimpleSamlPhpConsentUriEvidence.nativeLinkUse(value,uri,condition,at));
        open.put("userGesture",false);assertThrows(IllegalArgumentException.class,()->SimpleSamlPhpConsentUriEvidence.nativeLinkUse(value,uri,condition,at));
        open.put("userGesture",true).put("recordedAt","2026-09-30T00:00:01Z");assertThrows(IllegalArgumentException.class,()->SimpleSamlPhpConsentUriEvidence.nativeLinkUse(value,uri,condition,at));
    }
    @Test void nativeJavaScriptSchemeBlockIsAttemptedUseAndNeverProofOfFiltering()throws Exception{
        String uri="javascript:void(0)";var value=link(uri,"InformationURL");var condition=SimpleSamlPhpConsentUriEvidence.condition("ui-url-information-javascript");Instant at=Instant.parse("2026-10-01T00:00:03Z");
        var block=((com.fasterxml.jackson.databind.node.ArrayNode)value.path("nativeSecurityBlocks")).addObject().put("source","native-noconsent-window").put("recordedAt","2026-10-01T00:00:01.500Z").put("message","Running the JavaScript URL violates the Content Security Policy");
        assertEquals(UiUrlComparison.Use.USED,SimpleSamlPhpConsentUriEvidence.nativeLinkUse(value,uri,condition,at));
        block.put("source","isolated-detector-control");assertEquals(UiUrlComparison.Use.UNOBSERVED,SimpleSamlPhpConsentUriEvidence.nativeLinkUse(value,uri,condition,at));
    }
    @Test void nativePrivacyAnchorBindsTheExactDisplayedService()throws Exception{
        String uri="data:text/plain,control";var value=link(uri,"PrivacyStatementURL");var condition=SimpleSamlPhpConsentUriEvidence.condition("ui-url-privacy-data");Instant at=Instant.parse("2026-10-01T00:00:03Z");
        assertEquals(UiUrlComparison.Use.UNOBSERVED,SimpleSamlPhpConsentUriEvidence.nativeLinkUse(value,uri,condition,at));
        ((com.fasterxml.jackson.databind.node.ObjectNode)value.path("nativeLinkUse")).put("anchorOuterHtml","<a href='"+uri+"'>Privacy policy for the service Other service</a>");
        assertThrows(IllegalArgumentException.class,()->SimpleSamlPhpConsentUriEvidence.nativeLinkUse(value,uri,condition,at));
        ((com.fasterxml.jackson.databind.node.ObjectNode)value.path("nativeLinkUse")).put("anchorOuterHtml","<a href='"+uri+"'>Privacy policy for the service</a>");
        assertThrows(IllegalArgumentException.class,()->SimpleSamlPhpConsentUriEvidence.nativeLinkUse(value,uri,condition,at));
    }
    private org.w3c.dom.Element metadata(String variant,String node,String url){return com.samlscope.saml.normal.SecureXml.parse(("<md:EntityDescriptor xmlns:md='urn:oasis:names:tc:SAML:2.0:metadata' xmlns:ds='http://www.w3.org/2000/09/xmldsig#' xmlns:mdui='urn:oasis:names:tc:SAML:metadata:ui' entityID='https://sp.example'><md:SPSSODescriptor><md:Extensions><mdui:UIInfo><mdui:DisplayName xml:lang='en'>SAMLscope URL policy control</mdui:DisplayName><mdui:"+node+">"+url+"</mdui:"+node+"></mdui:UIInfo></md:Extensions><md:KeyDescriptor><ds:KeyInfo><ds:X509Data><ds:X509Certificate>key-"+variant+"</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:AssertionConsumerService Binding='urn:post' Location='https://sp.example/acs?mdv="+variant+"&amp;run="+RUN+"'/></md:SPSSODescriptor></md:EntityDescriptor>").getBytes(java.nio.charset.StandardCharsets.UTF_8)).getDocumentElement();}
    @Test void normalizerOnlyExcludesVerifiedKeysAndIntentionalUrlCondition(){
        String a="ui-url-information-http",b="ui-url-privacy-data";var baseline=SimpleSamlPhpConsentUriEvidence.noUrlFixedMetadata(metadata(a,"InformationURL","http://fixture"),a,RUN);var other=metadata(b,"PrivacyStatementURL","data:text/plain,fixture");
        assertEquals(baseline,SimpleSamlPhpConsentUriEvidence.noUrlFixedMetadata(other,b,RUN));
        ((org.w3c.dom.Element)other.getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:metadata","AssertionConsumerService").item(0)).setAttribute("Binding","unexpected");assertNotEquals(baseline,SimpleSamlPhpConsentUriEvidence.noUrlFixedMetadata(other,b,RUN));
        var unknown=metadata(b,"PrivacyStatementURL","data:text/plain,fixture");unknown.setAttributeNS("urn:unexpected","extra:policy","changed");assertNotEquals(baseline,SimpleSamlPhpConsentUriEvidence.noUrlFixedMetadata(unknown,b,RUN));
        var changed=metadata(b,"PrivacyStatementURL","data:text/plain,fixture");changed.getElementsByTagNameNS("urn:oasis:names:tc:SAML:metadata:ui","DisplayName").item(0).setTextContent("Other service");assertThrows(IllegalArgumentException.class,()->SimpleSamlPhpConsentUriEvidence.noUrlFixedMetadata(changed,b,RUN));
    }
}
