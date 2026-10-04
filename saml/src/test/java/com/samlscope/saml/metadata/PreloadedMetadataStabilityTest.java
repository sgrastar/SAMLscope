package com.samlscope.saml.metadata;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.w3c.dom.Element;
import com.samlscope.core.plan.TestPlan;
import com.samlscope.saml.SamlTestFixtures;
import com.samlscope.saml.crypto.FilePlanKeyStore;
import com.samlscope.saml.crypto.XmlSignatureVerifier;
import com.samlscope.saml.crypto.XmlSigner;
import com.samlscope.saml.normal.SecureXml;

class PreloadedMetadataStabilityTest {
    @TempDir Path directory;
    private static final Instant NOW = Instant.parse("2026-08-29T00:00:00Z");

    @Test
    void reusesSignedBytesAndOriginalExpiryDespiteClockAndCallerMutation() {
        var clock = new MutableClock();
        var store = new FilePlanKeyStore(directory, clock);
        var service = new MetadataService(URI.create("https://peer.example"), store, new XmlSigner(), clock);
        var plan = SamlTestFixtures.idpPlan();
        var scope = new ArrayList<>(List.of(MetadataService.Variant.CERT_EXPIRED,
                MetadataService.Variant.ENTITY_CACHE_DURATION));
        var original = service.generatePreloadedCampaign(plan, "run_stable", scope);
        var expected = original.clone();
        var root = root(original);
        assertTrue(new XmlSignatureVerifier().hasValidEnvelopedSignature(root, store.getOrCreate(plan.id()).certificate()));
        assertEquals(NOW.plus(Duration.ofDays(14)), Instant.parse(root.getAttribute("validUntil")));
        assertTrue(new String(original, java.nio.charset.StandardCharsets.UTF_8).contains("cacheDuration=\"PT1H\""));
        original[0] = 0;
        scope.clear();
        clock.now = NOW.plus(Duration.ofDays(15));
        assertArrayEquals(expected, service.generatePreloadedCampaign(plan, "run_stable",
                List.of(MetadataService.Variant.CERT_EXPIRED, MetadataService.Variant.ENTITY_CACHE_DURATION)));
        assertTrue(Instant.parse(root(expected).getAttribute("validUntil")).isBefore(clock.instant()),
                "rearming must not silently renew an expired fixture");

        var ordinary = root(service.generate(plan));
        clock.now = clock.now.plusSeconds(60);
        assertNotEquals(ordinary.getAttribute("validUntil"), root(service.generate(plan)).getAttribute("validUntil"));
        var expired = root(service.generatePolling(plan, MetadataService.Variant.EXPIRED, "run_live"));
        assertTrue(Instant.parse(expired.getAttribute("validUntil")).isBefore(clock.instant()));
        clock.now = clock.now.plusSeconds(60);
        assertNotEquals(expired.getAttribute("validUntil"), root(service.generatePolling(
                plan, MetadataService.Variant.EXPIRED, "run_live")).getAttribute("validUntil"));
    }

    @Test
    void separatesOrderedSubsetsRunsAndPlanInputs() {
        var clock = new MutableClock();
        var service = new MetadataService(URI.create("https://peer.example"),
                new FilePlanKeyStore(directory, clock), new XmlSigner(), clock);
        var plan = SamlTestFixtures.idpPlan();
        var first = MetadataService.Variant.ATTRIBUTE_POLICY_ENTITY_ABSENT;
        var second = MetadataService.Variant.ATTRIBUTE_POLICY_REQUESTED_ABSENT;
        var original = service.generatePreloadedCampaign(plan, "run_one", List.of(first, second));
        var reverse = root(service.generatePreloadedCampaign(plan, "run_one", List.of(second, first)));
        var entities = reverse.getElementsByTagNameNS(MetadataService.MD, "EntityDescriptor");
        assertEquals(service.preloadedEntityId(plan, second), ((Element) entities.item(0)).getAttribute("entityID"));
        assertEquals(1, root(service.generatePreloadedCampaign(plan, "run_one", List.of(first)))
                .getElementsByTagNameNS(MetadataService.MD, "EntityDescriptor").getLength());
        assertFalse(Arrays.equals(original, service.generatePreloadedCampaign(plan, "run_two", List.of(first, second))));
        clock.now = NOW.plusSeconds(60);
        var parameters = new TestPlan.Parameters(180, 600, "");
        var changed = plan(plan, plan.id(), parameters);
        assertEquals(clock.instant().plus(Duration.ofDays(14)).toString(), root(service.generatePreloadedCampaign(
                changed, "run_one", List.of(first, second))).getAttribute("validUntil"));
        var otherPlan = plan(plan, "plan_1123456789ABCDEFGHJKMNPQRS", plan.parameters());
        assertTrue(root(service.generatePreloadedCampaign(otherPlan, "run_one", List.of(first)))
                .getAttribute("ID").contains(otherPlan.id()));
        assertArrayEquals(original, service.generatePreloadedCampaign(plan, "run_one", List.of(first, second)));
    }

    @Test
    void signingCertificateReplacementCreatesASeparatelySignedFixture() throws Exception {
        var clock = new MutableClock();
        var store = new FilePlanKeyStore(directory, clock);
        var service = new MetadataService(URI.create("https://peer.example"), store, new XmlSigner(), clock);
        var plan = SamlTestFixtures.idpPlan();
        var scope = List.of(MetadataService.Variant.ATTRIBUTE_POLICY_ENTITY_ABSENT);
        var original = service.generatePreloadedCampaign(plan, "run_keys", scope);
        var oldCertificate = store.getOrCreate(plan.id()).certificate();
        var replacementDirectory = directory.resolve("replacement");
        var replacementStore = new FilePlanKeyStore(replacementDirectory, clock);
        var replacement = replacementStore.getOrCreate(plan.id());
        for (var file : List.of("signing-key.pk8", "signing-certificate.der")) {
            Files.copy(replacementDirectory.resolve("keys").resolve(plan.id()).resolve(file),
                    directory.resolve("keys").resolve(plan.id()).resolve(file), java.nio.file.StandardCopyOption.REPLACE_EXISTING);
        }
        var refreshed = service.generatePreloadedCampaign(plan, "run_keys", scope);
        assertFalse(Arrays.equals(original, refreshed));
        assertTrue(new XmlSignatureVerifier().hasValidEnvelopedSignature(root(refreshed), replacement.certificate()));
        assertFalse(new XmlSignatureVerifier().hasValidEnvelopedSignature(root(refreshed), oldCertificate));
    }

    @Test
    void storedSecondaryAndEcCertificateReplacementInvalidatesOnlyDependentFixtures() throws Exception {
        for (var dependency : List.of(
                new KeyDependency(MetadataService.Variant.THREE_SIGNING_KEYS_FIRST, "roll2-", false),
                new KeyDependency(MetadataService.Variant.THREE_SIGNING_KEYS_FIRST, "roll3-", false),
                new KeyDependency(MetadataService.Variant.ECDSA_SHA256, "ec-", true))) {
            var clock = new MutableClock();
            var data = directory.resolve(dependency.prefix());
            var store = new FilePlanKeyStore(data, clock);
            var service = new MetadataService(URI.create("https://peer.example"), store, new XmlSigner(), clock);
            var plan = SamlTestFixtures.idpPlan();
            var scope = List.of(dependency.variant());
            var original = service.generatePreloadedCampaign(plan, "run_role_keys", scope);
            var independentScope = List.of(MetadataService.Variant.ATTRIBUTE_POLICY_ENTITY_ABSENT);
            var independent = service.generatePreloadedCampaign(plan, "run_role_keys", independentScope);
            var primary = store.getOrCreate(plan.id());
            var digest = java.security.MessageDigest.getInstance("SHA-256")
                    .digest(primary.certificate().getPublicKey().getEncoded());
            var alias = dependency.prefix() + java.util.HexFormat.of().formatHex(digest, 0, 12);
            var old = dependency.ec() ? store.getOrCreateEc(plan.id(), alias) : store.getOrCreate(plan.id(), alias);
            var replacementData = data.resolve("replacement");
            var replacementStore = new FilePlanKeyStore(replacementData, clock);
            var replacement = dependency.ec()
                    ? replacementStore.getOrCreateEc(plan.id(), alias) : replacementStore.getOrCreate(plan.id(), alias);
            var relative = Path.of("keys", plan.id(), alias);
            if (dependency.ec()) relative = relative.resolve("ec-p256");
            for (var file : List.of("signing-key.pk8", "signing-certificate.der")) {
                Files.copy(replacementData.resolve(relative).resolve(file), data.resolve(relative).resolve(file),
                        java.nio.file.StandardCopyOption.REPLACE_EXISTING);
            }
            clock.now = NOW.plusSeconds(60);
            var refreshed = service.generatePreloadedCampaign(plan, "run_role_keys", scope);
            assertFalse(Arrays.equals(original, refreshed), dependency.prefix());
            assertTrue(new XmlSignatureVerifier().hasValidEnvelopedSignature(root(refreshed), primary.certificate()));
            var encoded = new String(refreshed, java.nio.charset.StandardCharsets.UTF_8);
            assertTrue(encoded.contains(java.util.Base64.getEncoder().encodeToString(replacement.certificate().getEncoded())));
            assertFalse(encoded.contains(java.util.Base64.getEncoder().encodeToString(old.certificate().getEncoded())));
            assertArrayEquals(independent, service.generatePreloadedCampaign(plan, "run_role_keys", independentScope),
                    "changing an unused role key must not regenerate an independent fixture");
            assertArrayEquals(refreshed, service.generatePreloadedCampaign(plan, "run_role_keys", scope));
        }
    }

    private record KeyDependency(MetadataService.Variant variant, String prefix, boolean ec) {}

    private TestPlan plan(TestPlan original, String id, TestPlan.Parameters parameters) {
        return new TestPlan(id, original.name(), original.profile(), original.definitionIdentity(), original.target(),
                original.suiteMetadataDelivery(), original.declaredFeatures(), parameters,
                original.interaction(), original.createdAt(), original.updatedAt());
    }

    private Element root(byte[] xml) { return SecureXml.parse(xml).getDocumentElement(); }

    private static final class MutableClock extends Clock {
        private Instant now = NOW;
        @Override public ZoneId getZone() { return ZoneOffset.UTC; }
        @Override public Clock withZone(ZoneId zone) { return Clock.fixed(now, zone); }
        @Override public Instant instant() { return now; }
    }
}
