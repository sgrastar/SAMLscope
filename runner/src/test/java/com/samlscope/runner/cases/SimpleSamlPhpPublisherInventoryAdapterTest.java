package com.samlscope.runner.cases;

import static org.junit.jupiter.api.Assertions.*;
import static com.samlscope.runner.cases.MetadataPublisherKeyInventoryEvidence.*;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.samlscope.saml.crypto.FilePlanKeyStore;
import com.samlscope.store.JsonCodec;
import java.nio.file.Path;
import java.time.*;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class SimpleSamlPhpPublisherInventoryAdapterTest {
    @TempDir Path data;
    private ObjectNode state()throws Exception {
        var mapper=new JsonCodec().mapper();var n=mapper.createObjectNode().put("schema","samlscope-ssp-public-publisher-state-v1").put("entityId",SimpleSamlPhpPublisherInventoryAdapter.TARGET);
        var m=n.putObject("publicNativeMetadata").put("entityid",SimpleSamlPhpPublisherInventoryAdapter.TARGET).put("metadata-set","saml20-idp-hosted").put("sign.authnrequest",true);
        m.putArray("SingleSignOnService").addObject().put("Binding","urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect").put("Location","http://localhost:18380/simplesaml/sso");
        m.putArray("SingleLogoutService").addObject().put("Binding","urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect").put("Location","http://localhost:18380/simplesaml/slo");
        var store=new FilePlanKeyStore(data.resolve("keys"),Clock.systemUTC());var cert=store.getOrCreate("plan_0123456789ABCDEFGHJKMNPQRS").certificate();
        String encoded=Base64.getEncoder().encodeToString(cert.getEncoded());String pem="-----BEGIN PUBLIC KEY-----\n"+Base64.getMimeEncoder(64,new byte[]{'\n'}).encodeToString(cert.getPublicKey().getEncoded())+"\n-----END PUBLIC KEY-----\n";
        var keys=n.putArray("currentCredentials");keys.addObject().put("prefix","").put("publicCertificatePresent",true).put("privateCredentialPresent",true).put("certificateDerBase64",encoded).put("certificatePublicSpkiPem",pem).put("nativePrivateCredentialPublicSpkiPem",pem);
        keys.addObject().put("prefix","new_").put("publicCertificatePresent",false).put("privateCredentialPresent",false);
        keys.addObject().put("prefix","https.").put("publicCertificatePresent",false).put("privateCredentialPresent",false);
        n.putArray("remotePeers");var flags=n.putObject("roleFeatureFlags");for(String flag:List.of("saml20.ecp","saml20.hok.assertion","saml20.sendartifact","metadata.sign.enable"))flags.put(flag,false);return n;
    }
    @Test void nativeCurrentPublicPrivateJoinProducesOneScopedKeyForEachDeclaredPurpose()throws Exception {
        var inv=SimpleSamlPhpPublisherInventoryAdapter.inventory(state());assertEquals(2,inv.keys().size());assertEquals(inv.keys().get(0).spkiSha256(),inv.keys().get(1).spkiSha256());assertTrue(inv.unresolvedScope().isEmpty());assertTrue(inv.wantAuthnRequestsSigned());
    }
    @Test void wrongNativePrivateKeyCannotBeHiddenBehindCorrectPublicCertificate()throws Exception {
        var n=state();var store=new FilePlanKeyStore(data.resolve("keys"),Clock.systemUTC());var cert=store.getOrCreate("plan_0123456789ABCDEFGHJKMNPQRS","other").certificate();
        ((ObjectNode)n.path("currentCredentials").get(0)).put("nativePrivateCredentialPublicSpkiPem","-----BEGIN PUBLIC KEY-----\n"+Base64.getEncoder().encodeToString(cert.getPublicKey().getEncoded())+"\n-----END PUBLIC KEY-----");
        assertThrows(IllegalArgumentException.class,()->SimpleSamlPhpPublisherInventoryAdapter.inventory(n));
    }
    @Test void configuredFutureKeyIsNotAutomaticallyCalledCurrent()throws Exception {
        var n=state();var row=(ObjectNode)n.path("currentCredentials").get(1);var current=n.path("currentCredentials").get(0);row.put("publicCertificatePresent",true).put("privateCredentialPresent",true).put("certificateDerBase64",current.path("certificateDerBase64").asText()).put("certificatePublicSpkiPem",current.path("certificatePublicSpkiPem").asText()).put("nativePrivateCredentialPublicSpkiPem",current.path("nativePrivateCredentialPublicSpkiPem").asText());
        var inv=SimpleSamlPhpPublisherInventoryAdapter.inventory(n);assertEquals(2,inv.keys().size());assertEquals(List.of("new-credential-current-role-purpose-unproven"),inv.unresolvedScope());
    }
    @Test void configuredHttpsCertificateIsNotProofOfActualSamlTransportUse()throws Exception {
        var n=state();var current=n.path("currentCredentials").get(0);var row=(ObjectNode)n.path("currentCredentials").get(2);row.put("publicCertificatePresent",true).put("privateCredentialPresent",false).put("certificateDerBase64",current.path("certificateDerBase64").asText()).put("certificatePublicSpkiPem",current.path("certificatePublicSpkiPem").asText());
        assertTrue(SimpleSamlPhpPublisherInventoryAdapter.inventory(n).unresolvedScope().contains("configured-https-credential-operative-role-use-unproven"));
    }
    @Test void AdditionalProtocolsRequireOperativeTransportClosure()throws Exception {
        for(String field:List.of("saml20.ecp","saml20.hok.assertion","saml20.sendartifact")) {
            var n=state();((ObjectNode)n.path("roleFeatureFlags")).put(field,true);
            assertTrue(SimpleSamlPhpPublisherInventoryAdapter.inventory(n).unresolvedScope().contains("additional-role-protocol-transport-scope-unproven"));
        }
    }
    @Test void PerPeerSigningAndSharedEncryptionOverridesDoNotDisappearFromInventory()throws Exception {
        var n=state();n.withArray("remotePeers").addObject().put("entityId","https://peer.example").put("signatureOverridePresent",true).put("sharedEncryptionOverridePresent",true);
        var inv=SimpleSamlPhpPublisherInventoryAdapter.inventory(n);assertEquals(2,inv.unresolvedScope().size());
    }
    @Test void PartialCredentialInventoryOrNonBooleanFactsFailClosed()throws Exception {
        var n=state();((ObjectNode)n.path("currentCredentials").get(0)).put("privateCredentialPresent","true");assertThrows(IllegalArgumentException.class,()->SimpleSamlPhpPublisherInventoryAdapter.inventory(n));
        var missing=state();missing.withArray("currentCredentials").remove(2);assertThrows(IllegalArgumentException.class,()->SimpleSamlPhpPublisherInventoryAdapter.inventory(missing));
    }
    @Test void SignatureRequirementKeepsNativeBuilderPrecedence()throws Exception {
        var n=state();((ObjectNode)n.path("publicNativeMetadata")).put("redirect.sign",false);assertTrue(SimpleSamlPhpPublisherInventoryAdapter.inventory(n).wantAuthnRequestsSigned());
        ((ObjectNode)n.path("publicNativeMetadata")).remove("sign.authnrequest");assertFalse(SimpleSamlPhpPublisherInventoryAdapter.inventory(n).wantAuthnRequestsSigned());
    }    @Test void nativeProjectionReproducesOnlyTheBoundPublicMetadataGetContext()throws Exception {
        var mapper=new com.samlscope.store.JsonCodec().mapper();var n=mapper.createObjectNode();var c=n.putObject("publicRequestContext");
        c.put("method","GET").put("scheme","http").put("host","localhost").put("port",18380).put("path","/simplesaml/module.php/saml/idp/metadata");
        SimpleSamlPhpPublisherInventoryAdapter.validatePublicRequestContext(n);
        for(String key:List.of("method","scheme","host","port","path")) {
            var v=n.deepCopy();var context=(com.fasterxml.jackson.databind.node.ObjectNode)v.path("publicRequestContext");
            if(key.equals("port"))context.put(key,80);else context.put(key,"different");
            assertThrows(IllegalArgumentException.class,()->SimpleSamlPhpPublisherInventoryAdapter.validatePublicRequestContext(v));
        }
    }

}
