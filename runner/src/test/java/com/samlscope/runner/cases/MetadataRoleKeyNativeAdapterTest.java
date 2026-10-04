package com.samlscope.runner.cases;

import static org.junit.jupiter.api.Assertions.*;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.samlscope.core.plan.*;
import com.samlscope.core.profile.FunctionalProfile;
import com.samlscope.saml.crypto.*;
import com.samlscope.saml.metadata.MetadataService;
import com.samlscope.saml.normal.SecureXml;
import com.samlscope.store.JsonCodec;
import java.net.URI;
import java.nio.file.Path;
import java.time.*;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.w3c.dom.Element;

class MetadataRoleKeyNativeAdapterTest {
    private static final String MD="urn:oasis:names:tc:SAML:2.0:metadata",DS="http://www.w3.org/2000/09/xmldsig#",RUN="run_0123456789ABCDEFGHJKMNPQRS";
    @TempDir Path data;
    @Test void nativeRolePurposesMustMatchFullDualRoleXmlThroughBothOrdersAndKeySwaps()throws Exception {
        var clock=Clock.fixed(Instant.parse("2026-10-02T00:00:00Z"),ZoneOffset.UTC);var store=new FilePlanKeyStore(data.resolve("keys"),clock);var service=new MetadataService(URI.create("http://suite.example"),store,new XmlSigner(),clock);var plan=plan(clock);
        for(var v:MetadataRoleKeyProbeTestCase.VARIANTS){var entity=SecureXml.parse(service.generatePolling(plan,MetadataService.Variant.parse(v),RUN)).getDocumentElement();var sp=MetadataRoleKeyEvidence.single(entity,MD,"SPSSODescriptor");var idp=MetadataRoleKeyEvidence.single(entity,MD,"IDPSSODescriptor");var correct=nativeRole(sp);var other=nativeRole(idp);
            assertDoesNotThrow(()->SimpleSamlPhpMetadataRoleKeyNativeAdapter.validateParsedRole(correct,sp));assertDoesNotThrow(()->SimpleSamlPhpMetadataRoleKeyNativeAdapter.validateParsedRole(other,idp));
            assertThrows(IllegalArgumentException.class,()->SimpleSamlPhpMetadataRoleKeyNativeAdapter.validateParsedRole(other,sp));
            var missing=correct.deepCopy();missing.remove("keys");assertThrows(IllegalArgumentException.class,()->SimpleSamlPhpMetadataRoleKeyNativeAdapter.validateParsedRole(missing,sp));
            var flattened=correct.deepCopy();other.path("keys").forEach(k->flattened.withArray("keys").add(k));assertThrows(IllegalArgumentException.class,()->SimpleSamlPhpMetadataRoleKeyNativeAdapter.validateParsedRole(flattened,sp));
            var a=attributes(sp);assertDoesNotThrow(()->KeycloakMetadataRoleKeyNativeAdapter.validateCertificates(a,entity));
            var wrong=a.deepCopy();wrong.put("saml.signing.certificate",other.at("/keys/0/X509Certificate").asText());assertThrows(IllegalArgumentException.class,()->KeycloakMetadataRoleKeyNativeAdapter.validateCertificates(wrong,entity));
            var cipher=a.deepCopy();cipher.put("saml.encryption.certificate",other.at("/keys/0/X509Certificate").asText());assertThrows(IllegalArgumentException.class,()->KeycloakMetadataRoleKeyNativeAdapter.validateCertificates(cipher,entity));
            if(v.contains("explicit")){var purpose=correct.deepCopy();((ObjectNode)purpose.path("keys").get(0)).put("encryption",true);assertThrows(IllegalArgumentException.class,()->SimpleSamlPhpMetadataRoleKeyNativeAdapter.validateParsedRole(purpose,sp));}
        }
    }
    @Test void nativeClientPublicProjectionCannotSubstituteCredentialsOrUnknownRedactions()throws Exception {
        var codec=new JsonCodec().mapper();String db="01234567-89ab-cdef-0123-456789abcdef";var n=codec.createObjectNode().put("method","GET").put("url","http://localhost:18180/admin/realms/samlscope/clients/"+db).put("status",200).put("startedAt","2026-10-02T00:00:00Z").put("finishedAt","2026-10-02T00:00:01Z").put("response_projection","native-client-public-readback-v1");n.putArray("redactions").add("$.secret");var safe=("{\"id\":\""+db+"\",\"clientId\":\"https://sp.example\"}").getBytes(java.nio.charset.StandardCharsets.UTF_8);n.put("response_base64",Base64.getEncoder().encodeToString(safe)).put("response_sha256",MetadataRoleKeyEvidence.hash(safe));assertDoesNotThrow(()->KeycloakMetadataRoleKeyNativeAdapter.publicReply(n,db));
        var edited=n.deepCopy();edited.withArray("redactions").add("$.attributes.saml.signing.certificate");assertThrows(IllegalArgumentException.class,()->KeycloakMetadataRoleKeyNativeAdapter.publicReply(edited,db));
        var secret="{\"secret\":\"never-record\"}".getBytes();var unsafe=n.deepCopy().put("response_base64",Base64.getEncoder().encodeToString(secret)).put("response_sha256",MetadataRoleKeyEvidence.hash(secret));assertThrows(IllegalArgumentException.class,()->KeycloakMetadataRoleKeyNativeAdapter.publicReply(unsafe,db));
        var foreign=n.deepCopy().put("url","http://localhost:18180/admin/realms/foreign/clients/"+db);assertThrows(IllegalArgumentException.class,()->KeycloakMetadataRoleKeyNativeAdapter.publicReply(foreign,db));
    }
    @Test void parserOrPageAloneIsNotNativeProtocolEvidence(){assertFalse(KeycloakRegisteredSignerEvidence.nativeSignatureRejectionPage("Invalid requester".getBytes()));assertFalse(SimpleSamlPhpRegisteredSignerEvidence.nativeSignatureRejection("NOTVALIDCERTSIGNATURE","https://sp.example"));}
    private static ObjectNode nativeRole(Element role){var m=new JsonCodec().mapper();var result=m.createObjectNode();var keys=result.putArray("keys");for(var kd:MetadataAlgorithmEvidence.children(role,MD,"KeyDescriptor")){var k=keys.addObject();k.put("type","X509Certificate").put("X509Certificate",kd.getElementsByTagNameNS(DS,"X509Certificate").item(0).getTextContent().replaceAll("\\s",""));String use=kd.getAttribute("use");k.put("signing",use.isEmpty()||"signing".equals(use)).put("encryption",use.isEmpty()||"encryption".equals(use));}return result;}
    private static ObjectNode attributes(Element role){var n=new JsonCodec().mapper().createObjectNode();for(var kd:MetadataAlgorithmEvidence.children(role,MD,"KeyDescriptor")){String cert=kd.getElementsByTagNameNS(DS,"X509Certificate").item(0).getTextContent().replaceAll("\\s","");if(!"encryption".equals(kd.getAttribute("use")))n.put("saml.signing.certificate",cert);if(!"signing".equals(kd.getAttribute("use")))n.put("saml.encryption.certificate",cert);}return n;}
    private static TestPlan plan(Clock clock){return new TestPlan("plan_0123456789ABCDEFGHJKMNPQRS","native roles",FunctionalProfile.METADATA_IDP,new TestPlan.Target(TargetKind.IDP,"http://target.example/idp",new TestPlan.MetadataSource(MetadataSourceKind.URL,"http://target.example/metadata")),MetadataDeliveryKind.HTTP_URL,Map.of(),new TestPlan.Parameters(180,30,"reference",TestPlan.RequestSigningMode.REQUIRED),TestPlan.Interaction.defaults(),clock.instant(),clock.instant());}
}
