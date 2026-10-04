package com.samlscope.saml.metadata;

import static org.junit.jupiter.api.Assertions.*;

import java.net.URI;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.w3c.dom.Element;
import com.samlscope.core.plan.TargetKind;
import com.samlscope.core.plan.TestPlan;
import com.samlscope.core.profile.FunctionalProfile;
import com.samlscope.saml.SamlTestFixtures;
import com.samlscope.saml.crypto.FilePlanKeyStore;
import com.samlscope.saml.crypto.XmlSignatureVerifier;
import com.samlscope.saml.crypto.XmlSigner;
import com.samlscope.saml.normal.SamlSchemaValidation;
import com.samlscope.saml.normal.SecureXml;

class MetadataDefaultAlgorithmConsumerMetadataTest {
    private static final String RUN = "run_0123456789ABCDEFGHJKMNPQRS";
    private static final Clock CLOCK = Clock.fixed(Instant.parse("2026-10-04T00:00:00Z"), ZoneOffset.UTC);
    private static final List<FunctionalProfile> PROFILES = List.of(
            FunctionalProfile.BROWSER_SSO_IDP, FunctionalProfile.ECP_IDP);
    @TempDir Path directory;

    @Test
    void consumerMetadataIsSignedSchemaValidAndDoesNotDeclareSenderSigning() {
        var service = service();
        var verifier = new XmlSignatureVerifier();
        for (var profile : PROFILES) {
            for (var mode : TestPlan.RequestSigningMode.values()) {
                var plan = plan(profile, mode);
                var root = consumer(service, plan);
                var certificate = service.credentialsForPollingVariant(plan, MetadataService.Variant.CONTROL).certificate();
                assertEquals(1, root.getElementsByTagNameNS(MetadataService.DS, "Signature").getLength());
                assertFalse(sp(root).hasAttribute("AuthnRequestsSigned"), profile + " " + mode);
                assertTrue(verifier.hasValidEnvelopedSignature(root, certificate));
                assertTrue(verifier.hasValidEnvelopedReferenceDigests(root));
                assertEquals(java.util.Optional.empty(), SamlSchemaValidation.validationFailure(
                        root, SamlSchemaValidation.SchemaKind.METADATA));

                sp(root).setAttribute("AuthnRequestsSigned", "true");
                assertFalse(verifier.hasValidEnvelopedSignature(root, certificate),
                        "The omitted declaration must be covered by the newly generated signature");
                assertFalse(verifier.hasValidEnvelopedReferenceDigests(root));
            }
        }
    }

    @Test
    void consumerRetainsPollingControlPublicKeysAndCorrelatedAcs() {
        var service = service();
        for (var profile : PROFILES) {
            var plan = plan(profile, TestPlan.RequestSigningMode.REQUIRED);
            var control = control(service, plan);
            var consumer = consumer(service, plan);
            var expectedKeys = sp(control).getElementsByTagNameNS(MetadataService.MD, "KeyDescriptor");
            var actualKeys = sp(consumer).getElementsByTagNameNS(MetadataService.MD, "KeyDescriptor");
            assertTrue(expectedKeys.getLength() > 0);
            assertEquals(expectedKeys.getLength(), actualKeys.getLength());
            for (int index = 0; index < expectedKeys.getLength(); index++) {
                assertTrue(expectedKeys.item(index).isEqualNode(actualKeys.item(index)),
                        "Signing and encryption public material must remain the polling CONTROL originals");
            }
            var expectedAcs = sp(control).getElementsByTagNameNS(MetadataService.MD, "AssertionConsumerService");
            var actualAcs = sp(consumer).getElementsByTagNameNS(MetadataService.MD, "AssertionConsumerService");
            assertTrue(expectedAcs.getLength() > 0);
            assertEquals(expectedAcs.getLength(), actualAcs.getLength());
            for (int index = 0; index < expectedAcs.getLength(); index++) {
                assertTrue(expectedAcs.item(index).isEqualNode(actualAcs.item(index)));
                assertTrue(((Element) actualAcs.item(index)).getAttribute("Location")
                        .contains("mdv=control&run=" + RUN));
            }
            var polling = service.credentialsForPollingVariant(plan, MetadataService.Variant.CONTROL);
            var ordinary = service.credentialsForVariant(plan, MetadataService.Variant.CONTROL);
            assertFalse(java.util.Arrays.equals(polling.certificate().getPublicKey().getEncoded(),
                    ordinary.certificate().getPublicKey().getEncoded()),
                    "The fixture must use the polling control key rather than the Plan primary key");
        }
    }

    @Test
    void onlyTheSignatureAndOptionalSenderDeclarationChange() {
        var service = service();
        for (var profile : PROFILES) {
            for (var mode : TestPlan.RequestSigningMode.values()) {
                var plan = plan(profile, mode);
                var control = control(service, plan);
                var consumer = consumer(service, plan);
                assertNotEquals(control.getElementsByTagNameNS(MetadataService.DS, "DigestValue")
                        .item(0).getTextContent(), consumer.getElementsByTagNameNS(MetadataService.DS, "DigestValue")
                        .item(0).getTextContent());
                removeSignatureAndSenderDeclaration(control);
                removeSignatureAndSenderDeclaration(consumer);
                assertTrue(control.isEqualNode(consumer),
                        "Entity, validity, role attributes, public keys and every endpoint must be unchanged: "
                                + profile + " " + mode);
            }
        }
    }

    @Test
    void ordinaryRequiredAndOptionalSigningDeclarationsRemainUnchanged() {
        var service = service();
        for (var profile : PROFILES) {
            for (var mode : TestPlan.RequestSigningMode.values()) {
                var plan = plan(profile, mode);
                String expected = Boolean.toString(mode == TestPlan.RequestSigningMode.REQUIRED);
                assertEquals(expected, sp(control(service, plan)).getAttribute("AuthnRequestsSigned"));
                assertFalse(sp(consumer(service, plan)).hasAttribute("AuthnRequestsSigned"));
                assertEquals(expected, sp(control(service, plan)).getAttribute("AuthnRequestsSigned"));
                var ordinary = SecureXml.parse(service.generate(plan, MetadataService.Variant.CONTROL, RUN))
                        .getDocumentElement();
                assertEquals(expected, sp(ordinary).getAttribute("AuthnRequestsSigned"));
                assertTrue(new XmlSignatureVerifier().hasValidEnvelopedSignature(ordinary,
                        service.credentialsForVariant(plan, MetadataService.Variant.CONTROL).certificate()));
            }
        }
    }

    @Test
    void unrelatedRolesProfilesAndUnboundRunIdsAreRejected() {
        var service = service();
        for (var profile : FunctionalProfile.values()) {
            if (PROFILES.contains(profile)) continue;
            var plan = plan(profile, TestPlan.RequestSigningMode.OPTIONAL);
            assertThrows(IllegalArgumentException.class,
                    () -> service.generateDefaultAlgorithmConsumerMetadata(plan, RUN), profile.id());
        }
        for (var profile : PROFILES) {
            var plan = plan(profile, TestPlan.RequestSigningMode.OPTIONAL);
            for (String invalid : new String[] {null, "", "run_probe", RUN + "X", RUN.substring(0, RUN.length() - 1),
                    "run_0123456789ABCDEFGHJKMNPQRU", "../" + RUN, RUN.toLowerCase(java.util.Locale.ROOT)}) {
                assertThrows(IllegalArgumentException.class,
                        () -> service.generateDefaultAlgorithmConsumerMetadata(plan, invalid), String.valueOf(invalid));
            }
        }
    }

    @Test
    void explicitStoredControlKeyReplaysWithoutAKeyStore() {
        var service = service();
        var plan = plan(FunctionalProfile.BROWSER_SSO_IDP, TestPlan.RequestSigningMode.REQUIRED);
        var control = service.credentialsForPollingVariant(plan, MetadataService.Variant.CONTROL);
        var replay = new MetadataService(URI.create("https://peer.example"), null, new XmlSigner(), CLOCK);
        assertArrayEquals(service.generateDefaultAlgorithmConsumerMetadata(plan, RUN),
                replay.generateDefaultAlgorithmConsumerMetadata(plan, RUN, control));
        assertFalse(java.util.Arrays.equals(service.generateDefaultAlgorithmConsumerMetadata(plan, RUN),
                replay.generateDefaultAlgorithmConsumerMetadata(plan, RUN,
                        service.credentialsForVariant(plan, MetadataService.Variant.CONTROL))));
        assertThrows(NullPointerException.class,
                () -> replay.generateDefaultAlgorithmConsumerMetadata(plan, RUN, null));
    }

    private MetadataService service() {
        return new MetadataService(URI.create("https://peer.example"),
                new FilePlanKeyStore(directory, CLOCK), new XmlSigner(), CLOCK);
    }

    private static TestPlan plan(FunctionalProfile profile, TestPlan.RequestSigningMode mode) {
        var baseline = SamlTestFixtures.idpPlan();
        var kind = profile.role() == com.samlscope.core.plan.TargetRole.SP ? TargetKind.SP : TargetKind.IDP;
        var target = new TestPlan.Target(kind, baseline.target().entityId(), baseline.target().metadataSource());
        var parameters = baseline.parameters();
        return new TestPlan(baseline.id(), baseline.name(), profile, target, baseline.suiteMetadataDelivery(),
                baseline.declaredFeatures(), new TestPlan.Parameters(parameters.clockSkewToleranceSeconds(),
                        parameters.metadataRefreshWaitSeconds(), parameters.testUserHint(), mode),
                baseline.interaction(), baseline.createdAt(), baseline.updatedAt());
    }

    private static Element control(MetadataService service, TestPlan plan) {
        return SecureXml.parse(service.generatePolling(plan, MetadataService.Variant.CONTROL, RUN)).getDocumentElement();
    }

    private static Element consumer(MetadataService service, TestPlan plan) {
        return SecureXml.parse(service.generateDefaultAlgorithmConsumerMetadata(plan, RUN)).getDocumentElement();
    }

    private static Element sp(Element root) {
        assertEquals(1, root.getElementsByTagNameNS(MetadataService.MD, "SPSSODescriptor").getLength());
        return (Element) root.getElementsByTagNameNS(MetadataService.MD, "SPSSODescriptor").item(0);
    }

    private static void removeSignatureAndSenderDeclaration(Element root) {
        var signatures = root.getElementsByTagNameNS(MetadataService.DS, "Signature");
        assertEquals(1, signatures.getLength());
        var signature = signatures.item(0);
        assertSame(root, signature.getParentNode());
        root.removeChild(signature);
        sp(root).removeAttribute("AuthnRequestsSigned");
    }

}
