package com.samlscope.runner.cases;
import static org.junit.jupiter.api.Assertions.*;
import com.samlscope.core.transcript.*;
import com.samlscope.core.plan.*;
import com.samlscope.core.run.Reachability;
import com.samlscope.core.evaluation.Outcome;
import com.samlscope.runner.DefaultCaseContext;
import java.nio.file.*;
import java.time.Clock;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class SimpleSamlPhpConsentLogoEvidenceTest {
    private static final String RUN="run_00000000000000000000000000";
    @TempDir Path directory;
    private DefaultCaseContext context(){return new DefaultCaseContext(RUN,TargetRole.IDP,Clock.systemUTC(),TestPlan.Parameters.defaults(),TestPlan.Interaction.defaults(),Reachability.CONFIRMED,
        new TranscriptRecorder(){public List<TranscriptEntry> list(String run){return List.of();}public TranscriptEntry record(TranscriptInput input){throw new AssertionError("Reader must not execute interactions");}
            public TranscriptEntry updateSamlAnalysis(String id,String correlation,Map<String,Object> summary){throw new AssertionError("Reader must not modify originals");}},true);}
    @Test void missingAdapterProofDoesNotShadowLegacy(){
        var reader=new SimpleSamlPhpConsentLogoEvidence(directory,e->{throw new AssertionError();});assertFalse(reader.exists(RUN));assertTrue(reader.evaluate(context(),new byte[0]).isEmpty());}
    @Test void declaredLogoAndRestorationWithoutOriginalsRemainUnverified()throws Exception{
        Path folder=Files.createDirectory(directory.resolve(RUN));Files.writeString(folder.resolve("manifest.json"),"{\"selected\":\"display\",\"restored\":true}");
        var reader=new SimpleSamlPhpConsentLogoEvidence(directory,e->{throw new AssertionError();});assertTrue(reader.exists(RUN));assertEquals(Outcome.NOT_VERIFIED,reader.evaluate(context(),new byte[0]).orElseThrow().outcome());}
    @Test void presentFileAndSymlinkFolderAreOwnedFailClosed()throws Exception{
        Path path=Files.writeString(directory.resolve(RUN),"invalid");var reader=new SimpleSamlPhpConsentLogoEvidence(directory,e->{throw new AssertionError();});assertTrue(reader.exists(RUN));assertEquals(Outcome.NOT_VERIFIED,reader.evaluate(context(),new byte[0]).orElseThrow().outcome());
        Files.delete(path);Path other=Files.createDirectory(directory.resolve("other"));Files.createSymbolicLink(path,other);assertTrue(reader.exists(RUN));assertEquals(Outcome.NOT_VERIFIED,reader.evaluate(context(),new byte[0]).orElseThrow().outcome());}
    @Test void traversalAndSymlinkManifestCannotSupplyNativeEvidence()throws Exception{
        var reader=new SimpleSamlPhpConsentLogoEvidence(directory,e->{throw new AssertionError();});assertFalse(reader.exists("../"+RUN));Path folder=Files.createDirectory(directory.resolve(RUN));Path fake=Files.writeString(directory.resolve("other.json"),"{}");Files.createSymbolicLink(folder.resolve("manifest.json"),fake);assertEquals(Outcome.NOT_VERIFIED,reader.evaluate(context(),new byte[0]).orElseThrow().outcome());}
    private org.w3c.dom.Element metadata(String cert,String language,String variant){return com.samlscope.saml.normal.SecureXml.parse(("<md:EntityDescriptor xmlns:md='urn:oasis:names:tc:SAML:2.0:metadata' xmlns:ds='http://www.w3.org/2000/09/xmldsig#' xmlns:mdui='urn:oasis:names:tc:SAML:metadata:ui' entityID='https://sp.example' validUntil='2026-10-02T00:00:00Z'><md:SPSSODescriptor><md:Extensions><mdui:UIInfo><mdui:Logo height='48' width='180'>data:default</mdui:Logo><mdui:Logo height='48' width='180' xml:lang='"+language+"'>data:localized</mdui:Logo></mdui:UIInfo></md:Extensions><md:KeyDescriptor use='signing'><ds:KeyInfo><ds:X509Data><ds:X509Certificate>"+cert+"</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:AssertionConsumerService Binding='urn:post' Location='https://sp.example/acs?mdv="+variant+"&amp;run="+RUN+"'/></md:SPSSODescriptor></md:EntityDescriptor>").getBytes(java.nio.charset.StandardCharsets.UTF_8)).getDocumentElement();}
    @Test void noDisplayWaiverNormalizerOnlyRemovesExplicitLanguageAndVerifiedCertificateVariation(){
        String a="ui-consumer-logo-localized",b="ui-consumer-logo-fallback";var x=metadata("key-A","en",a);var y=metadata("key-B","ja",b);
        assertEquals(SimpleSamlPhpConsentLogoEvidence.noLogoFixedMetadata(x,a,RUN),SimpleSamlPhpConsentLogoEvidence.noLogoFixedMetadata(y,b,RUN));
    }
    @Test void noDisplayWaiverNormalizerPreservesOtherMetadataInputs(){
        String a="ui-consumer-logo-localized",b="ui-consumer-logo-fallback";var original=SimpleSamlPhpConsentLogoEvidence.noLogoFixedMetadata(metadata("key-A","en",a),a,RUN);
        var endpoint=metadata("key-B","ja",b);((org.w3c.dom.Element)endpoint.getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:metadata","AssertionConsumerService").item(0)).setAttribute("Binding","other");assertNotEquals(original,SimpleSamlPhpConsentLogoEvidence.noLogoFixedMetadata(endpoint,b,RUN));
        var logo=metadata("key-B","ja",b);((org.w3c.dom.Element)logo.getElementsByTagNameNS("urn:oasis:names:tc:SAML:metadata:ui","Logo").item(0)).setAttribute("width","181");assertNotEquals(original,SimpleSamlPhpConsentLogoEvidence.noLogoFixedMetadata(logo,b,RUN));
        var unknown=metadata("key-B","ja",b);unknown.setAttributeNS("urn:extra","extra:policy","changed");assertNotEquals(original,SimpleSamlPhpConsentLogoEvidence.noLogoFixedMetadata(unknown,b,RUN));
        var display=metadata("key-B","ja",b);var text=display.getOwnerDocument().createElementNS("urn:oasis:names:tc:SAML:metadata:ui","mdui:DisplayName");text.setTextContent("Different display");display.appendChild(text);assertThrows(IllegalArgumentException.class,()->SimpleSamlPhpConsentLogoEvidence.noLogoFixedMetadata(display,b,RUN));
    }
}
