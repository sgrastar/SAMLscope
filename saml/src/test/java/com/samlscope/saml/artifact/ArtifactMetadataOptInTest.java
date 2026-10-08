package com.samlscope.saml.artifact;
import static org.junit.jupiter.api.Assertions.*;
import java.net.URI;
import java.nio.file.Path;
import java.time.*;
import java.util.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import com.samlscope.core.plan.*;
import com.samlscope.core.profile.FunctionalProfile;
import com.samlscope.saml.crypto.*;
import com.samlscope.saml.metadata.MetadataService;
import com.samlscope.saml.normal.SecureXml;
import org.w3c.dom.Element;

class ArtifactMetadataOptInTest {
    @TempDir Path folder;
    static final Instant NOW=Instant.parse("2026-10-08T00:00:00Z");
    TestPlan plan(FunctionalProfile profile,Map<String,Boolean> flags){return new TestPlan("plan_0123456789ABCDEFGHJKMNPQRS","Example",profile,new TestPlan.Target(TargetKind.IDP,"https://idp.example/entity",new TestPlan.MetadataSource(MetadataSourceKind.URL,"https://idp.example/metadata")),MetadataDeliveryKind.MANUAL,flags,TestPlan.Parameters.defaults(),TestPlan.Interaction.defaults(),NOW,NOW);}
    @Test void falseAndAbsentPreserveExactOldBytesAndPostDefaults(){var clock=Clock.fixed(NOW,ZoneOffset.UTC);var keys=new FilePlanKeyStore(folder,clock);var metadata=new MetadataService(URI.create("https://suite.example"),keys,new XmlSigner(),clock);var absent=metadata.generateSuiteMetadata(plan(FunctionalProfile.BROWSER_SSO_IDP,Map.of()),MetadataService.Variant.BASELINE,"run_0123456789ABCDEFGHJKMNPQRS");var no=metadata.generateSuiteMetadata(plan(FunctionalProfile.BROWSER_SSO_IDP,Map.of("artifact_binding",false)),MetadataService.Variant.BASELINE,"run_0123456789ABCDEFGHJKMNPQRS");assertArrayEquals(absent,no);var nodes=SecureXml.parse(no).getElementsByTagNameNS(SamlArtifact.MD,"AssertionConsumerService");assertEquals(4,nodes.getLength());assertEquals("true",((Element)nodes.item(0)).getAttribute("isDefault"));}
    @Test void explicitBrowserOptInAddsOneRealNondefaultArtifactAcsAndRetainsSignature(){var clock=Clock.fixed(NOW,ZoneOffset.UTC);var keys=new FilePlanKeyStore(folder,clock);var metadata=new MetadataService(URI.create("https://suite.example"),keys,new XmlSigner(),clock);var p=plan(FunctionalProfile.BROWSER_SSO_IDP,Map.of("artifact_binding",true));var raw=metadata.generateSuiteMetadata(p,MetadataService.Variant.BASELINE,"run_0123456789ABCDEFGHJKMNPQRS");var root=SecureXml.parse(raw).getDocumentElement();var services=root.getElementsByTagNameNS(SamlArtifact.MD,"AssertionConsumerService");assertEquals(5,services.getLength());var artifact=(Element)services.item(4);assertEquals("4",artifact.getAttribute("index"));assertFalse(Set.of("true","1").contains(artifact.getAttribute("isDefault")));assertEquals("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact",artifact.getAttribute("Binding"));assertTrue(artifact.getAttribute("Location").endsWith("/sp/acs/4"));assertEquals("true",((Element)services.item(0)).getAttribute("isDefault"));assertTrue(new XmlSignatureVerifier().hasValidEnvelopedSignature(root,keys.getOrCreate(p.id()).certificate()));}
    @Test void anotherProfileDoesNotAdvertiseAnUnimplementedGenericArtifactFlow(){var clock=Clock.fixed(NOW,ZoneOffset.UTC);var metadata=new MetadataService(URI.create("https://suite.example"),new FilePlanKeyStore(folder,clock),new XmlSigner(),clock);var raw=metadata.generateSuiteMetadata(plan(FunctionalProfile.ECP_IDP,Map.of("artifact_binding",true)),MetadataService.Variant.BASELINE,"run_0123456789ABCDEFGHJKMNPQRS");assertEquals(4,SecureXml.parse(raw).getElementsByTagNameNS(SamlArtifact.MD,"AssertionConsumerService").getLength());}
}
