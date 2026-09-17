package com.samlscope.saml.metadata;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URI;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import org.apache.xml.security.signature.XMLSignature;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import com.samlscope.saml.SamlTestFixtures;
import com.samlscope.saml.crypto.FilePlanKeyStore;
import com.samlscope.saml.crypto.XmlSigner;
import com.samlscope.saml.normal.OpenSamlReader;
import com.samlscope.saml.normal.SecureXml;

class MetadataServiceTest {
    @TempDir java.nio.file.Path directory;

    @Test
    void multiKeyProbesActuallyExerciseEveryAdvertisedKeyInBothIngestionModes() throws Exception {
        var clock = Clock.fixed(Instant.parse("2026-08-29T00:00:00Z"), ZoneOffset.UTC);
        var store = new FilePlanKeyStore(directory, clock);
        var plan = SamlTestFixtures.idpPlan();
        var service = new MetadataService(URI.create("https://peer.example"), store, new XmlSigner(), clock);
        var selected = java.util.Map.of(
                MetadataService.Variant.MULTIPLE_SIGNING_KEYS_FIRST, 0,
                MetadataService.Variant.MULTIPLE_SIGNING_KEYS, 1,
                MetadataService.Variant.MULTIPLE_OMITTED_KEYS_FIRST, 0,
                MetadataService.Variant.MULTIPLE_OMITTED_KEYS_SECOND, 1,
                MetadataService.Variant.THREE_SIGNING_KEYS_FIRST, 0,
                MetadataService.Variant.THREE_SIGNING_KEYS_SECOND, 1,
                MetadataService.Variant.THREE_SIGNING_KEYS, 2);
        for (boolean polling : new boolean[] {false, true}) {
            for (var item : selected.entrySet()) {
                var variant = item.getKey();
                var metadata = SecureXml.parse(polling
                        ? service.generatePolling(plan, variant, "run_probe")
                        : service.generate(plan, variant, "run_probe"));
                var role = (org.w3c.dom.Element) metadata.getElementsByTagNameNS(
                        MetadataService.MD, "SPSSODescriptor").item(0);
                var descriptors = role.getElementsByTagNameNS(MetadataService.MD, "KeyDescriptor");
                var keys = new java.util.ArrayList<java.security.cert.X509Certificate>();
                for (int i = 0; i < descriptors.getLength(); i++) {
                    var descriptor = (org.w3c.dom.Element) descriptors.item(i);
                    if (descriptor.getAttribute("use").equals("encryption")) continue;
                    assertEquals(variant.id().contains("omitted") ? "" : "signing", descriptor.getAttribute("use"));
                    var encoded = descriptor.getElementsByTagNameNS(MetadataService.DS, "X509Certificate")
                            .item(0).getTextContent();
                    keys.add((java.security.cert.X509Certificate) java.security.cert.CertificateFactory
                            .getInstance("X.509").generateCertificate(new java.io.ByteArrayInputStream(
                                    java.util.Base64.getMimeDecoder().decode(encoded))));
                }
                assertEquals(variant.id().startsWith("three") ? 3 : 2, keys.size());
                var credentials = polling ? service.credentialsForPollingVariant(plan, variant)
                        : service.credentialsForVariant(plan, variant);
                var request = SecureXml.parse(new com.samlscope.saml.normal.SamlSignedRequestFactory().build(
                        com.samlscope.saml.normal.SamlSignedRequestFactory.Fixture.VALID,
                        "_probe", URI.create("https://idp.example/sso"), "https://peer.example",
                        URI.create("https://peer.example/acs"), clock.instant(), credentials));
                request.getDocumentElement().setIdAttribute("ID", true);
                var signature = new XMLSignature((org.w3c.dom.Element) request.getElementsByTagNameNS(
                        MetadataService.DS, "Signature").item(0), "");
                for (int i = 0; i < keys.size(); i++) {
                    assertEquals(i == item.getValue(), signature.checkSignatureValue(keys.get(i)),
                            variant.id() + " polling=" + polling + " key=" + i);
                }
            }
        }
    }

    @Test
    void runtimeCertificateDiffersFromMetadataButPublicKeyIsIdentical() throws Exception {
        var clock = Clock.fixed(Instant.parse("2026-08-29T00:00:00Z"), ZoneOffset.UTC);
        var store = new FilePlanKeyStore(directory, clock);
        var plan = SamlTestFixtures.idpPlan();
        var service = new MetadataService(URI.create("https://peer.example"), store, new XmlSigner(), clock);
        for (boolean polling : new boolean[] {false, true}) {
            for (var variant : MetadataService.Variant.values()) {
                if (!variant.certificateVariant()) continue;
                var document = SecureXml.parse(polling ? service.generatePolling(plan, variant, "run_probe")
                        : service.generate(plan, variant, "run_probe"));
                var role = (org.w3c.dom.Element) document.getElementsByTagNameNS(MetadataService.MD, "SPSSODescriptor").item(0);
                var encoded = role.getElementsByTagNameNS(MetadataService.DS, "X509Certificate").item(0).getTextContent();
                var certificate = (java.security.cert.X509Certificate) java.security.cert.CertificateFactory.getInstance("X.509")
                        .generateCertificate(new java.io.ByteArrayInputStream(java.util.Base64.getMimeDecoder().decode(encoded)));
                var runtime = polling ? service.credentialsForPollingVariant(plan, variant) : service.credentialsForVariant(plan, variant);
                org.junit.jupiter.api.Assertions.assertArrayEquals(certificate.getPublicKey().getEncoded(), runtime.certificate().getPublicKey().getEncoded());
                assertFalse(java.util.Arrays.equals(certificate.getEncoded(), runtime.certificate().getEncoded()), variant.id());
            }
        }
    }

    @Test
    void pollingRolloverKeysCannotBeReusedFromAnEarlierFixture() {
        var clock = Clock.fixed(Instant.parse("2026-08-29T00:00:00Z"), ZoneOffset.UTC);
        var store = new FilePlanKeyStore(directory, clock);
        var plan = SamlTestFixtures.idpPlan();
        var service = new MetadataService(URI.create("https://peer.example"), store, new XmlSigner(), clock);
        var seen = new java.util.HashSet<String>();
        for (var variant : java.util.List.of(MetadataService.Variant.MULTIPLE_SIGNING_KEYS,
                MetadataService.Variant.MULTIPLE_OMITTED_KEYS_SECOND,
                MetadataService.Variant.THREE_SIGNING_KEYS_SECOND,
                MetadataService.Variant.THREE_SIGNING_KEYS)) {
            var credentials = service.credentialsForPollingVariant(plan, variant);
            assertTrue(seen.add(java.util.Base64.getEncoder().encodeToString(credentials.certificate().getPublicKey().getEncoded())), variant.id());
        }
    }

    @Test
    void defaultAcsFixturesChangeOnlyTheMetadataSelection() {
        var clock = Clock.fixed(Instant.parse("2026-08-29T00:00:00Z"), ZoneOffset.UTC);
        var store = new FilePlanKeyStore(directory, clock);
        var plan = SamlTestFixtures.idpPlan();
        var service = new MetadataService(URI.create("https://peer.example"), store, new XmlSigner(), clock);
        for (var variant : java.util.List.of(MetadataService.Variant.DEFAULT_ACS_FIRST,
                MetadataService.Variant.DEFAULT_ACS_SECOND, MetadataService.Variant.DEFAULT_ACS_IMPLICIT)) {
            var document = SecureXml.parse(service.generate(plan, variant, "run_probe"));
            var endpoints = document.getElementsByTagNameNS(MetadataService.MD, "AssertionConsumerService");
            var defaults = new java.util.ArrayList<String>();
            for (int i = 0; i < endpoints.getLength(); i++) {
                var endpoint = (org.w3c.dom.Element) endpoints.item(i);
                if (endpoint.getAttribute("isDefault").equals("true")) defaults.add(endpoint.getAttribute("index"));
            }
            assertEquals(variant == MetadataService.Variant.DEFAULT_ACS_IMPLICIT ? java.util.List.of()
                    : java.util.List.of(variant == MetadataService.Variant.DEFAULT_ACS_FIRST ? "0" : "1"), defaults);
            assertEquals("0", ((org.w3c.dom.Element) endpoints.item(0)).getAttribute("index"));
        }
    }

    @Test
    void emitsSignedAllInOneMetadata() throws Exception {
        var clock = Clock.fixed(Instant.parse("2026-08-29T00:00:00Z"), ZoneOffset.UTC);
        var keyStore = new FilePlanKeyStore(directory, clock);
        var plan = SamlTestFixtures.idpPlan();
        var xml = new MetadataService(URI.create("https://peer.example"), keyStore, new XmlSigner(), clock)
                .generate(plan);
        var parsed = new OpenSamlReader().read(xml);
        assertEquals("EntityDescriptor", parsed.openSamlObject().getElementQName().getLocalPart());
        var document = SecureXml.parse(xml);
        document.getDocumentElement().setIdAttribute("ID", true);
        assertEquals(1, document.getElementsByTagNameNS(MetadataService.MD, "SPSSODescriptor").getLength());
        assertEquals(1, document.getElementsByTagNameNS(MetadataService.MD, "IDPSSODescriptor").getLength());
        var acs = document.getElementsByTagNameNS(MetadataService.MD, "AssertionConsumerService");
        assertEquals(4, acs.getLength());
        assertEquals("0", ((org.w3c.dom.Element) acs.item(0)).getAttribute("index"));
        assertEquals("1", ((org.w3c.dom.Element) acs.item(1)).getAttribute("index"));
        assertEquals(MetadataService.REDIRECT,
                ((org.w3c.dom.Element) acs.item(3)).getAttribute("Binding"));
        assertEquals("3", ((org.w3c.dom.Element) acs.item(3)).getAttribute("index"));
        var signatureElement = (org.w3c.dom.Element) document
                .getElementsByTagNameNS(MetadataService.DS, "Signature").item(0);
        var signature = new XMLSignature(signatureElement, "");
        assertTrue(signature.checkSignatureValue(keyStore.getOrCreate(plan.id()).certificate()));
    }

    @Test
    void emitsCryptographicallyValidMetadataVariantsWithCorrelatedEndpoints() throws Exception {
        var clock = Clock.fixed(Instant.parse("2026-08-29T00:00:00Z"), ZoneOffset.UTC);
        var keyStore = new FilePlanKeyStore(directory, clock);
        var plan = SamlTestFixtures.idpPlan();
        var service = new MetadataService(URI.create("https://peer.example"), keyStore, new XmlSigner(), clock);
        var runId = "run_0123456789ABCDEFGHJKMNPQRS";

        for (var variant : MetadataService.Variant.values()) {
            if (variant == MetadataService.Variant.BASELINE) continue;
            var xml = service.generate(plan, variant, runId);
            var document = SecureXml.parse(xml);
            document.getDocumentElement().setIdAttribute("ID", true);
            var signatures = document.getElementsByTagNameNS(MetadataService.DS, "Signature");
            if (variant == MetadataService.Variant.UNSIGNED) {
                assertEquals(0, signatures.getLength(), variant.name());
            } else {
                var signature = new XMLSignature((org.w3c.dom.Element) signatures.item(0), "");
                if (variant == MetadataService.Variant.BAD_SIGNATURE) {
                    assertFalse(signature.checkSignatureValue(keyStore.getOrCreate(plan.id()).certificate()),
                            variant.name());
                } else if (variant == MetadataService.Variant.SIGNED_OTHER_KEY
                        || variant == MetadataService.Variant.SIGNED_OTHER_KEY_PRIMARY_KEYINFO) {
                    assertTrue(signature.checkSignatureValue(
                            keyStore.getOrCreate(plan.id(), "metadata-other").certificate()), variant.name());
                    assertFalse(signature.checkSignatureValue(keyStore.getOrCreate(plan.id()).certificate()),
                            variant.name());
                } else {
                    assertTrue(signature.checkSignatureValue(keyStore.getOrCreate(plan.id()).certificate()),
                            variant.name());
                }
            }
            assertTrue(new String(xml, java.nio.charset.StandardCharsets.UTF_8)
                    .contains("mdv=" + variant.id() + "&amp;run=" + runId), variant.name());
        }
    }

    @Test
    void pollingFixturesUseDeterministicDistinctRoleKeysThatMatchSignedRequests() throws Exception {
        var clock = Clock.fixed(Instant.parse("2026-08-29T00:00:00Z"), ZoneOffset.UTC);
        var keyStore = new FilePlanKeyStore(directory, clock);
        var plan = SamlTestFixtures.idpPlan();
        var service = new MetadataService(
                URI.create("https://peer.example"), keyStore, new XmlSigner(), clock);
        var control = service.credentialsForPollingVariant(plan, MetadataService.Variant.CONTROL);
        var extension = service.credentialsForPollingVariant(
                plan, MetadataService.Variant.UNKNOWN_EXTENSION);

        assertNotEquals(
                java.util.Base64.getEncoder().encodeToString(control.certificate().getEncoded()),
                java.util.Base64.getEncoder().encodeToString(extension.certificate().getEncoded()));
        assertEquals(
                java.util.Base64.getEncoder().encodeToString(control.certificate().getEncoded()),
                java.util.Base64.getEncoder().encodeToString(service.credentialsForPollingVariant(
                        plan, MetadataService.Variant.CONTROL).certificate().getEncoded()));

        var document = SecureXml.parse(service.generatePolling(
                plan, MetadataService.Variant.CONTROL, "run_0123456789ABCDEFGHJKMNPQRS"));
        document.getDocumentElement().setIdAttribute("ID", true);
        var signature = new XMLSignature((org.w3c.dom.Element) document
                .getElementsByTagNameNS(MetadataService.DS, "Signature").item(0), "");
        assertTrue(signature.checkSignatureValue(control.certificate()));
        var certificateText = document.getElementsByTagNameNS(MetadataService.DS, "X509Certificate")
                .item(0).getTextContent().replaceAll("\\s+", "");
        assertEquals(java.util.Base64.getEncoder().encodeToString(control.certificate().getEncoded()),
                certificateText);
    }

    @Test
    void preloadedCampaignCombinesOnlyCompatiblePositiveFixturesUnderOneSignature() throws Exception {
        var clock = Clock.fixed(Instant.parse("2026-08-29T00:00:00Z"), ZoneOffset.UTC);
        var keyStore = new FilePlanKeyStore(directory, clock);
        var plan = SamlTestFixtures.idpPlan();
        var service = new MetadataService(
                URI.create("https://peer.example"), keyStore, new XmlSigner(), clock);
        var runId = "run_0123456789ABCDEFGHJKMNPQRS";

        var document = SecureXml.parse(service.generatePreloadedCampaign(plan, runId));
        var root = document.getDocumentElement();
        root.setIdAttribute("ID", true);
        assertEquals("EntitiesDescriptor", root.getLocalName());
        assertEquals(1, document.getElementsByTagNameNS(MetadataService.DS, "Signature").getLength(),
                "the aggregate has one trust root; child fixture signatures must not survive");
        var signature = new XMLSignature((org.w3c.dom.Element) document
                .getElementsByTagNameNS(MetadataService.DS, "Signature").item(0), "");
        assertTrue(signature.checkSignatureValue(keyStore.getOrCreate(plan.id()).certificate()));

        var xml = new String(SecureXml.serialize(document), java.nio.charset.StandardCharsets.UTF_8);
        for (var variant : MetadataService.preloadedCampaignVariants()) {
            var expectedEntity = service.preloadedEntityId(plan, variant);
            int matches = 0;
            var entities = document.getElementsByTagNameNS(MetadataService.MD, "EntityDescriptor");
            for (int index = 0; index < entities.getLength(); index++) {
                if (expectedEntity.equals(((org.w3c.dom.Element) entities.item(index)).getAttribute("entityID"))) {
                    matches++;
                }
            }
            assertEquals(1, matches, variant.id());
            assertTrue(xml.contains("mdv=" + variant.id() + "&amp;run=" + runId), variant.id());
        }
        var roles = document.getElementsByTagNameNS(MetadataService.MD, "SPSSODescriptor");
        for (int index = 0; index < roles.getLength(); index++) {
            assertEquals("true", ((org.w3c.dom.Element) roles.item(index))
                    .getAttribute("AuthnRequestsSigned"));
        }
        assertFalse(MetadataService.preloadedCampaignVariants().contains(MetadataService.Variant.UNSIGNED));
        assertFalse(MetadataService.preloadedCampaignVariants().contains(MetadataService.Variant.BAD_SIGNATURE));
        assertFalse(MetadataService.preloadedCampaignVariants().contains(MetadataService.Variant.EXPIRED));
        assertFalse(MetadataService.preloadedCampaignVariants().contains(
                MetadataService.Variant.CONFLICTING_DUPLICATE_ENTITY_IDS));
    }

    @Test
    void keyDescriptorFixturesExposeOnlyTheIntendedStandardKeyForms() {
        var clock = Clock.fixed(Instant.parse("2026-08-29T00:00:00Z"), ZoneOffset.UTC);
        var service = new MetadataService(
                URI.create("https://peer.example"), new FilePlanKeyStore(directory, clock),
                new XmlSigner(), clock);
        var plan = SamlTestFixtures.idpPlan();
        var runId = "run_0123456789ABCDEFGHJKMNPQRS";

        var keyValue = SecureXml.parse(service.generate(
                plan, MetadataService.Variant.KEYVALUE_ONLY, runId));
        assertEquals(2, keyValue.getElementsByTagNameNS(MetadataService.DS, "RSAKeyValue").getLength());
        assertEquals(1, keyValue.getElementsByTagNameNS(MetadataService.DS, "X509Data").getLength(),
                "only the root signature KeyInfo retains X509Data");

        var omitted = SecureXml.parse(service.generate(
                plan, MetadataService.Variant.KEY_USE_OMITTED, runId));
        var descriptors = omitted.getElementsByTagNameNS(MetadataService.MD, "KeyDescriptor");
        assertFalse(((org.w3c.dom.Element) descriptors.item(0)).hasAttribute("use"));

        var three = SecureXml.parse(service.generate(
                plan, MetadataService.Variant.THREE_SIGNING_KEYS, runId));
        var sp = (org.w3c.dom.Element) three
                .getElementsByTagNameNS(MetadataService.MD, "SPSSODescriptor").item(0);
        int signing = 0;
        var keys = sp.getElementsByTagNameNS(MetadataService.MD, "KeyDescriptor");
        for (int i = 0; i < keys.getLength(); i++) {
            if ("signing".equals(((org.w3c.dom.Element) keys.item(i)).getAttribute("use"))) signing++;
        }
        assertEquals(3, signing);
    }

    @Test
    void outOfBandKeyFixtureDoesNotAdvertiseTheActualSignatureKey() throws Exception {
        var clock = Clock.fixed(Instant.parse("2026-08-29T00:00:00Z"), ZoneOffset.UTC);
        var keyStore = new FilePlanKeyStore(directory, clock);
        var plan = SamlTestFixtures.idpPlan();
        var xml = new MetadataService(URI.create("https://peer.example"), keyStore, new XmlSigner(), clock)
                .generate(plan, MetadataService.Variant.SIGNED_OTHER_KEY_PRIMARY_KEYINFO,
                        "run_0123456789ABCDEFGHJKMNPQRS");
        var document = SecureXml.parse(xml);
        document.getDocumentElement().setIdAttribute("ID", true);
        var signatureElement = (org.w3c.dom.Element) document
                .getElementsByTagNameNS(MetadataService.DS, "Signature").item(0);
        var signature = new XMLSignature(signatureElement, "");
        assertTrue(signature.checkSignatureValue(keyStore.getOrCreate(plan.id(), "metadata-other").certificate()));
        var advertised = signatureElement.getElementsByTagNameNS(MetadataService.DS, "X509Certificate")
                .item(0).getTextContent().replaceAll("\\s", "");
        assertEquals(java.util.Base64.getEncoder().encodeToString(
                keyStore.getOrCreate(plan.id()).certificate().getEncoded()), advertised);
    }

    @Test
    void noKeyInfoVariantOmitsOnlyKeyInfoFromTheSignature() {
        var clock = Clock.fixed(Instant.parse("2026-08-29T00:00:00Z"), ZoneOffset.UTC);
        var keyStore = new FilePlanKeyStore(directory, clock);
        var plan = SamlTestFixtures.idpPlan();
        var xml = new MetadataService(URI.create("https://peer.example"), keyStore, new XmlSigner(), clock)
                .generate(plan, MetadataService.Variant.NO_KEY_INFO, "run_0123456789ABCDEFGHJKMNPQRS");
        var document = SecureXml.parse(xml);
        var signature = (org.w3c.dom.Element) document
                .getElementsByTagNameNS(MetadataService.DS, "Signature").item(0);
        assertEquals(0, signature.getElementsByTagNameNS(MetadataService.DS, "KeyInfo").getLength());
        assertTrue(document.getElementsByTagNameNS(MetadataService.DS, "KeyInfo").getLength() > 0,
                "metadata role KeyDescriptors remain intact");
    }

    @Test
    void structuralFixturesPutTheCorrelatedEntityAtTheRequiredDepthAndPreserveSignatures() {
        var clock = Clock.fixed(Instant.parse("2026-08-29T00:00:00Z"), ZoneOffset.UTC);
        var keyStore = new FilePlanKeyStore(directory, clock);
        var plan = SamlTestFixtures.idpPlan();
        var service = new MetadataService(URI.create("https://peer.example"), keyStore, new XmlSigner(), clock);
        var runId = "run_0123456789ABCDEFGHJKMNPQRS";

        var fifty = SecureXml.parse(service.generate(
                plan, MetadataService.Variant.ENTITIES_ROOT_FIFTY, runId));
        assertEquals("EntitiesDescriptor", fifty.getDocumentElement().getLocalName());
        assertEquals(50, fifty.getElementsByTagNameNS(MetadataService.MD, "EntityDescriptor").getLength());
        var last = (org.w3c.dom.Element) fifty
                .getElementsByTagNameNS(MetadataService.MD, "EntityDescriptor").item(49);
        assertEquals("https://peer.example/p/" + plan.id(), last.getAttribute("entityID"));

        var nested = SecureXml.parse(service.generate(
                plan, MetadataService.Variant.NESTED_ENTITIES, runId));
        assertEquals(2, nested.getElementsByTagNameNS(MetadataService.MD, "EntitiesDescriptor").getLength());
        var ids = new java.util.HashSet<String>();
        var all = nested.getElementsByTagName("*");
        for (var index = 0; index < all.getLength(); index++) {
            var element = (org.w3c.dom.Element) all.item(index);
            if (element.hasAttribute("ID")) {
                assertTrue(ids.add(element.getAttribute("ID")), "duplicate XML ID: " + element.getAttribute("ID"));
            }
        }

        var cacheOnly = SecureXml.parse(service.generate(
                plan, MetadataService.Variant.ENTITIES_CACHE_DURATION, runId)).getDocumentElement();
        assertEquals("PT1H", cacheOnly.getAttribute("cacheDuration"));
        assertTrue(!cacheOnly.hasAttribute("validUntil"));
    }

    @Test
    void extensionFixturesCoverEntityRoleEndpointAndInvalidNamespaceCases() {
        var clock = Clock.fixed(Instant.parse("2026-08-29T00:00:00Z"), ZoneOffset.UTC);
        var service = new MetadataService(
                URI.create("https://peer.example"), new FilePlanKeyStore(directory, clock),
                new XmlSigner(), clock);
        var plan = SamlTestFixtures.idpPlan();
        var runId = "run_0123456789ABCDEFGHJKMNPQRS";

        var entity = SecureXml.parse(service.generate(plan, MetadataService.Variant.UNKNOWN_EXTENSION, runId));
        assertEquals(1, entity.getElementsByTagNameNS(
                "urn:samlscope:test:metadata-extension", "Probe").getLength());
        var role = SecureXml.parse(service.generate(plan, MetadataService.Variant.UNKNOWN_ROLE_EXTENSION, runId));
        var sp = (org.w3c.dom.Element) role
                .getElementsByTagNameNS(MetadataService.MD, "SPSSODescriptor").item(0);
        assertEquals(1, sp.getElementsByTagNameNS(
                "urn:samlscope:test:metadata-extension", "Probe").getLength());
        var endpoint = SecureXml.parse(service.generate(
                plan, MetadataService.Variant.UNKNOWN_ENDPOINT_EXTENSION, runId));
        var acs = (org.w3c.dom.Element) endpoint
                .getElementsByTagNameNS(MetadataService.MD, "AssertionConsumerService").item(0);
        assertEquals("endpoint-attribute", acs.getAttributeNS(
                "urn:samlscope:test:metadata-extension", "probe"));
        var invalid = SecureXml.parse(service.generate(
                plan, MetadataService.Variant.INVALID_SAML_EXTENSION, runId));
        assertEquals(1, invalid.getElementsByTagNameNS(MetadataService.SAML, "Attribute").getLength());
    }

    @Test
    void additionalExtensionPointsKeepSchemaRequiredParentsAndNegativeLocation() {
        var clock = Clock.fixed(Instant.parse("2026-08-29T00:00:00Z"), ZoneOffset.UTC);
        var service = new MetadataService(URI.create("https://peer.example"),
                new FilePlanKeyStore(directory, clock), new XmlSigner(), clock);
        var variants = java.util.Map.of(
                MetadataService.Variant.UNKNOWN_ORGANIZATION_EXTENSION, "Organization",
                MetadataService.Variant.UNKNOWN_CONTACT_EXTENSION, "ContactPerson",
                MetadataService.Variant.UNKNOWN_AFFILIATION_EXTENSION, "AffiliationDescriptor",
                MetadataService.Variant.INVALID_ORGANIZATION_SAML_EXTENSION, "Organization");
        for (var pair : variants.entrySet()) {
            var doc = SecureXml.parse(service.generate(SamlTestFixtures.idpPlan(), pair.getKey(), "run_probe"));
            var invalid = pair.getKey() == MetadataService.Variant.INVALID_ORGANIZATION_SAML_EXTENSION;
            var probe = (org.w3c.dom.Element) doc.getElementsByTagNameNS(
                    invalid ? MetadataService.SAML : "urn:samlscope:test:metadata-extension",
                    invalid ? "Attribute" : "Probe").item(0);
            assertEquals("Extensions", probe.getParentNode().getLocalName());
            assertEquals(pair.getValue(), probe.getParentNode().getParentNode().getLocalName());
            assertEquals(0, doc.getElementsByTagNameNS(MetadataExtensionAttributeFixtures.FOREIGN, "*").getLength());
            if (pair.getValue().equals("Organization")) {
                assertEquals(1, doc.getElementsByTagNameNS(MetadataService.MD, "OrganizationName").getLength());
                assertEquals(1, doc.getElementsByTagNameNS(MetadataService.MD, "OrganizationDisplayName").getLength());
                assertEquals(1, doc.getElementsByTagNameNS(MetadataService.MD, "OrganizationURL").getLength());
            }
            if (pair.getValue().equals("AffiliationDescriptor")) {
                var parent = (org.w3c.dom.Element) probe.getParentNode().getParentNode().getParentNode();
                assertEquals(0, parent.getElementsByTagNameNS(MetadataService.MD, "SPSSODescriptor").getLength());
                assertEquals(1, doc.getElementsByTagNameNS(MetadataService.MD, "SPSSODescriptor").getLength());
                assertEquals(1, parent.getElementsByTagNameNS(MetadataService.MD, "AffiliateMember").getLength());
            }
        }
    }

    @Test
    void defaultAcsFixturesDistinguishFalseOmittedAndDuplicateIndex() {
        var clock = Clock.fixed(Instant.parse("2026-08-29T00:00:00Z"), ZoneOffset.UTC);
        var service = new MetadataService(URI.create("https://peer.example"),
                new FilePlanKeyStore(directory, clock), new XmlSigner(), clock);
        for (var variant : java.util.List.of(MetadataService.Variant.DEFAULT_ACS_FIRST_OMITTED,
                MetadataService.Variant.DEFAULT_ACS_ALL_FALSE, MetadataService.Variant.DEFAULT_ACS_MULTIPLE_TRUE,
                MetadataService.Variant.DEFAULT_ACS_DUPLICATE_INDEX)) {
            var doc = SecureXml.parse(service.generate(SamlTestFixtures.idpPlan(), variant, "run_probe"));
            var endpoints = doc.getElementsByTagNameNS(MetadataService.MD, "AssertionConsumerService");
            var first = (org.w3c.dom.Element) endpoints.item(0);
            var second = (org.w3c.dom.Element) endpoints.item(1);
            assertEquals(variant == MetadataService.Variant.DEFAULT_ACS_MULTIPLE_TRUE ? "true" : "false", first.getAttribute("isDefault"));
            assertEquals(variant != MetadataService.Variant.DEFAULT_ACS_FIRST_OMITTED, second.hasAttribute("isDefault"));
            assertEquals(variant == MetadataService.Variant.DEFAULT_ACS_DUPLICATE_INDEX ? "0" : "1", second.getAttribute("index"));
            assertTrue(variant.defaultAcsProbe());
            assertEquals(com.samlscope.saml.normal.SamlSignedRequestFactory.Fixture.DEFAULT_ACS, variant.requestFixture());
        }
    }

    @Test
    void secondaryIdpUsesADistinctEntityAndSigningKey() throws Exception {
        var clock = Clock.fixed(Instant.parse("2026-08-29T00:00:00Z"), ZoneOffset.UTC);
        var keyStore = new FilePlanKeyStore(directory, clock);
        var plan = SamlTestFixtures.idpPlan();
        var xml = new MetadataService(URI.create("https://peer.example"), keyStore, new XmlSigner(), clock)
                .generateSecondaryIdp(plan);
        var document = SecureXml.parse(xml);
        var root = document.getDocumentElement();
        root.setIdAttribute("ID", true);
        assertEquals("https://peer.example/p/plan_0123456789ABCDEFGHJKMNPQRS/idp/secondary",
                root.getAttribute("entityID"));
        assertEquals(0, document.getElementsByTagNameNS(MetadataService.MD, "SPSSODescriptor").getLength());
        assertEquals(1, document.getElementsByTagNameNS(MetadataService.MD, "IDPSSODescriptor").getLength());
        var secondary = keyStore.getOrCreate(plan.id(), "secondary-idp").certificate();
        assertNotEquals(keyStore.getOrCreate(plan.id()).certificate(), secondary);
        var signatureElement = (org.w3c.dom.Element) document
                .getElementsByTagNameNS(MetadataService.DS, "Signature").item(0);
        assertTrue(new XMLSignature(signatureElement, "").checkSignatureValue(secondary));
    }
}
