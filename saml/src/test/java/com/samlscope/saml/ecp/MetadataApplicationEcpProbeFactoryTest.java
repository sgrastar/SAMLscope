package com.samlscope.saml.ecp;

import static org.junit.jupiter.api.Assertions.*;
import com.samlscope.core.plan.TestPlan;
import com.samlscope.core.profile.FunctionalProfile;
import com.samlscope.saml.SamlTestFixtures;
import com.samlscope.saml.crypto.FilePlanKeyStore;
import com.samlscope.saml.crypto.XmlSignatureVerifier;
import com.samlscope.saml.crypto.XmlSigner;
import com.samlscope.saml.metadata.MetadataService;
import com.samlscope.saml.normal.SecureXml;
import java.net.URI;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.w3c.dom.Element;

class MetadataApplicationEcpProbeFactoryTest {
    private static final String RUN = "run_0123456789ABCDEFGHJKMNPQRS";
    private static final Instant NOW = Instant.parse("2026-10-03T10:00:00Z");
    @TempDir java.nio.file.Path directory;
    private TestPlan plan() {
        var p = SamlTestFixtures.idpPlan();
        return new TestPlan(p.id(), p.name(), FunctionalProfile.METADATA_IDP, p.target(),
                p.suiteMetadataDelivery(), p.declaredFeatures(), p.parameters(), p.interaction(), NOW, NOW);
    }
    private MetadataService metadata() {
        var clock = Clock.fixed(NOW, ZoneOffset.UTC);
        return new MetadataService(URI.create("https://peer.example"), new FilePlanKeyStore(directory, clock),
                new XmlSigner(), clock);
    }
    private List<MetadataApplicationEcpProbeFactory.Prepared> prepared(MetadataService metadata, MetadataService.Variant variant) {
        return new MetadataApplicationEcpProbeFactory().prepare(plan(), RUN, variant,
                metadata.generatePolling(plan(), variant, RUN), URI.create("https://idp.example/ecp"), NOW,
                v -> metadata.credentialsForPollingVariant(plan(), v));
    }
    private Element request(MetadataApplicationEcpProbeFactory.Prepared prepared) {
        return (Element) SecureXml.parse(prepared.envelope()).getElementsByTagNameNS(
                "urn:oasis:names:tc:SAML:2.0:protocol", "AuthnRequest").item(0);
    }

    @Test void rolloverBothKeysUseTheSameSimultaneouslyAdvertisedConsumerAndStableAction() {
        var m = metadata(); var variant = MetadataService.Variant.MULTIPLE_SIGNING_KEYS_FIRST;
        var first = prepared(m, variant); var repeated = prepared(m, variant);
        assertEquals(3, first.size());
        assertEquals(1, first.stream().map(MetadataApplicationEcpProbeFactory.Prepared::consumer).distinct().count());
        assertEquals(3, first.stream().map(MetadataApplicationEcpProbeFactory.Prepared::actionId).distinct().count());
        for (int i = 0; i < first.size(); i++) {
            var p = first.get(i); var xml = request(p);
            assertArrayEquals(p.envelope(), repeated.get(i).envelope());
            assertEquals("_" + p.actionId(), xml.getAttribute("ID"));
            assertEquals(MetadataService.PAOS, xml.getAttribute("ProtocolBinding"));
            assertEquals(p.consumer().toString(), xml.getAttribute("AssertionConsumerServiceURL"));
            assertTrue(new XmlSignatureVerifier().hasValidEnvelopedSignature(xml,
                    m.credentialsForPollingVariant(plan(), MetadataService.Variant.parse(p.signingVariant())).certificate()));
        }
        assertFalse(Arrays.equals(m.credentialsForPollingVariant(plan(), MetadataService.Variant.MULTIPLE_SIGNING_KEYS_FIRST)
                .certificate().getPublicKey().getEncoded(), m.credentialsForPollingVariant(plan(), MetadataService.Variant.MULTIPLE_SIGNING_KEYS)
                .certificate().getPublicKey().getEncoded()));
    }

    @Test void bNormalAndCorruptedSignatureAndOldKeyRemainSeparateControls() {
        var m = metadata(); var probes = prepared(m, MetadataService.Variant.NO_VALID_UNTIL);
        var b = m.credentialsForPollingVariant(plan(), MetadataService.Variant.NO_VALID_UNTIL).certificate();
        assertTrue(new XmlSignatureVerifier().hasValidEnvelopedSignature(request(probes.get(0)), b));
        assertFalse(new XmlSignatureVerifier().hasValidEnvelopedSignature(request(probes.get(1)), b));
        var old = m.credentialsForPollingVariant(plan(), MetadataService.Variant.CONTROL).certificate();
        assertTrue(new XmlSignatureVerifier().hasValidEnvelopedSignature(request(probes.get(2)), old));
        assertFalse(new XmlSignatureVerifier().hasValidEnvelopedSignature(request(probes.get(2)), b));
    }

    @Test void foreignRunAndPlanMetadataCannotProduceAnyPreparedGroup() {
        var m = metadata(); var v = MetadataService.Variant.NO_VALID_UNTIL;
        for (String raw : List.of(new String(m.generatePolling(plan(), v, RUN)).replace(RUN, "run_1123456789ABCDEFGHJKMNPQRS"),
                new String(m.generatePolling(plan(), v, RUN)).replace(plan().id(), "plan_1123456789ABCDEFGHJKMNPQRS")))
            assertThrows(IllegalArgumentException.class, () -> new MetadataApplicationEcpProbeFactory().prepare(
                    plan(), RUN, v, raw.getBytes(java.nio.charset.StandardCharsets.UTF_8), URI.create("https://idp.example/ecp"), NOW,
                    q -> m.credentialsForPollingVariant(plan(), q)));
    }

    @Test void duplicatePaosOrIncorrectSignerOrUnselectedEpochIsRejectedBeforeCollection() {
        var m = metadata(); var v = MetadataService.Variant.NO_VALID_UNTIL;
        var document = SecureXml.parse(m.generatePolling(plan(), v, RUN));
        var paos = Arrays.stream(new org.w3c.dom.Node[]{ document.getElementsByTagNameNS(MetadataService.MD,
                "AssertionConsumerService").item(2) }).map(n -> (Element)n).findFirst().orElseThrow();
        paos.getParentNode().appendChild(paos.cloneNode(true));
        assertThrows(IllegalArgumentException.class, () -> new MetadataApplicationEcpProbeFactory().prepare(
                plan(), RUN, v, SecureXml.serialize(document), URI.create("https://idp.example/ecp"), NOW,
                q -> m.credentialsForPollingVariant(plan(), q)));
        assertThrows(IllegalArgumentException.class, () -> new MetadataApplicationEcpProbeFactory().prepare(
                plan(), RUN, v, m.generatePolling(plan(), v, RUN), URI.create("https://idp.example/ecp"), NOW,
                q -> m.credentialsForPollingVariant(plan(), MetadataService.Variant.CONTROL)));
        assertThrows(IllegalArgumentException.class, () -> prepared(m, MetadataService.Variant.CONTROL));
    }
}
