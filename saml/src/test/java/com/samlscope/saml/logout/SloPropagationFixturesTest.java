package com.samlscope.saml.logout;
import static org.junit.jupiter.api.Assertions.*;
import com.samlscope.saml.crypto.*;
import com.samlscope.saml.metadata.MetadataService;
import com.samlscope.saml.normal.SecureXml;
import java.net.URI;
import java.time.*;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.w3c.dom.Element;

class SloPropagationFixturesTest {
    @TempDir java.nio.file.Path directory;
    @Test void serializedPreparationHasFourEntitiesThreeFixedSoapParticipantsAndValidAggregateSignature() {
        var clock=Clock.fixed(Instant.parse("2026-10-03T00:00:00Z"),ZoneOffset.UTC);var keys=new FilePlanKeyStore(directory,clock);
        var credentials=keys.getOrCreate("plan_0123456789ABCDEFGHJKMNPQRS");var entity=URI.create("https://suite.example/p/plan_0123456789ABCDEFGHJKMNPQRS");
        for(var trial:List.of("failure","all-success")) {
            var raw=SloPropagationFixtures.prepare(entity,URI.create(entity+"/sp/acs/0"),credentials,"run_0123456789ABCDEFGHJKMNPQRS",trial,clock.instant());
            var xml=SecureXml.parse(raw);var root=xml.getDocumentElement();
            assertEquals(4,xml.getElementsByTagNameNS(MetadataService.MD,"EntityDescriptor").getLength());
            assertTrue(new XmlSignatureVerifier().hasValidEnvelopedReferenceDigests(root));
            assertTrue(new XmlSignatureVerifier().hasValidEnvelopedSignature(root,credentials.certificate()));
            var entities=xml.getElementsByTagNameNS(MetadataService.MD,"EntityDescriptor");
            for(int i=1;i<4;i++) {
                var peer=(Element)entities.item(i);var endpoints=peer.getElementsByTagNameNS(MetadataService.MD,"SingleLogoutService");assertEquals(1,endpoints.getLength());
                var endpoint=(Element)endpoints.item(0);assertEquals(MetadataService.SOAP,endpoint.getAttribute("Binding"));
                assertTrue(endpoint.getAttribute("Location").endsWith("participant="+SloPropagationFixtures.PARTICIPANTS.get(i-1)+"&trial="+trial+"&mode="+SloPropagationFixtures.mode(trial)));
            }
            var callback=URI.create("http://host.docker.internal:18080");
            var mapped=SecureXml.parse(SloPropagationFixtures.prepare(entity,URI.create(entity+"/sp/acs/0"),credentials,
                    "run_0123456789ABCDEFGHJKMNPQRS",trial,clock.instant(),callback));
            assertEquals(entity.toString(),((Element)mapped.getElementsByTagNameNS(MetadataService.MD,"EntityDescriptor").item(0)).getAttribute("entityID"));
            assertEquals(entity+"/sp/acs/0",((Element)mapped.getElementsByTagNameNS(MetadataService.MD,"AssertionConsumerService").item(0)).getAttribute("Location"));
            var mappedPeer=(Element)mapped.getElementsByTagNameNS(MetadataService.MD,"EntityDescriptor").item(1);
            assertTrue(((Element)mappedPeer.getElementsByTagNameNS(MetadataService.MD,"SingleLogoutService").item(0)).getAttribute("Location").startsWith(callback.toString()));
        }
    }
    @Test void foreignEntityAcsRunOrTrialCannotCreatePreparedFixture() {
        var keys=new FilePlanKeyStore(directory,Clock.systemUTC());var credentials=keys.getOrCreate("plan_0123456789ABCDEFGHJKMNPQRS");
        var entity=URI.create("https://suite.example/p/plan_0123456789ABCDEFGHJKMNPQRS");var acs=URI.create(entity+"/sp/acs/0");var run="run_0123456789ABCDEFGHJKMNPQRS";
        assertThrows(RuntimeException.class,()->SloPropagationFixtures.prepare(entity,URI.create("https://foreign.example/acs"),credentials,run,"failure",Instant.now()));
        assertThrows(RuntimeException.class,()->SloPropagationFixtures.prepare(URI.create("https://suite.example/p/plan_foreign"),acs,credentials,run,"failure",Instant.now()));
        assertThrows(RuntimeException.class,()->SloPropagationFixtures.prepare(entity,acs,credentials,"run_other","failure",Instant.now()));
        assertThrows(RuntimeException.class,()->SloPropagationFixtures.prepare(entity,acs,credentials,run,"unknown",Instant.now()));
        for(var base:List.of("file:///tmp","ftp://suite.example","https://user:pass@suite.example","https://suite.example?token=x",
                "https://suite.example#fragment","https://suite.example/path","https://suite.example/"))
            assertThrows(RuntimeException.class,()->SloPropagationFixtures.prepare(entity,acs,credentials,run,"failure",Instant.now(),URI.create(base)));
    }
}
