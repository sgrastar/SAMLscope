package com.samlscope.saml.metadata;

import java.net.URI;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import javax.xml.XMLConstants;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import com.samlscope.core.plan.TestPlan;
import com.samlscope.saml.crypto.FilePlanKeyStore;
import com.samlscope.saml.crypto.PlanCredentials;
import com.samlscope.saml.crypto.XmlSigner;
import com.samlscope.saml.normal.SecureXml;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

public final class MetadataService {
    public static final String MD = "urn:oasis:names:tc:SAML:2.0:metadata";
    public static final String SAML = "urn:oasis:names:tc:SAML:2.0:assertion";
    public static final String DS = "http://www.w3.org/2000/09/xmldsig#";
    public static final String REDIRECT = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect";
    public static final String POST = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";
    public static final String SOAP = "urn:oasis:names:tc:SAML:2.0:bindings:SOAP";
    public static final String PAOS = "urn:oasis:names:tc:SAML:2.0:bindings:PAOS";
    private static final List<Variant> PRELOADED_CAMPAIGN_VARIANTS = List.of(
            Variant.UNKNOWN_EXTENSION,
            Variant.UNKNOWN_ROLE_EXTENSION,
            Variant.UNKNOWN_ENDPOINT_EXTENSION,
            Variant.MDRPI_REGISTRATION_INFO,
            Variant.ENTITY_CACHE_DURATION,
            Variant.ENTITIES_CACHE_DURATION,
            Variant.ENTITIES_VALID_UNTIL,
            Variant.NESTED_ENTITIES,
            Variant.KEYVALUE_ONLY,
            Variant.CERT_EXPIRED,
            Variant.CERT_NOT_YET_VALID,
            Variant.CERT_NO_DIGITAL_SIGNATURE,
            Variant.CERT_CRITICAL_EXTENSION,
            Variant.CERT_NONCRITICAL_EXTENSION,
            Variant.CERT_UNRELATED_EKU,
            Variant.CERT_SHA1,
            Variant.CERT_SHA512,
            Variant.CERT_EMPTY_SUBJECT,
            Variant.CERT_LONG_VALIDITY,
            Variant.CERT_UNKNOWN_CA);

    private final URI peerBase;
    private final FilePlanKeyStore keyStore;
    private final XmlSigner signer;
    private final Clock clock;

    public MetadataService(URI peerBase, FilePlanKeyStore keyStore, XmlSigner signer, Clock clock) {
        this.peerBase = peerBase;
        this.keyStore = keyStore;
        this.signer = signer;
        this.clock = clock;
    }

    public byte[] generate(TestPlan plan) {
        return generate(plan, Variant.BASELINE, null);
    }

    public byte[] generateSecondaryIdp(TestPlan plan) {
        var credentials = keyStore.getOrCreate(plan.id(), "secondary-idp");
        var document = SecureXml.newDocument();
        var root = element(document, MD, "md:EntityDescriptor");
        root.setAttributeNS(XMLConstants.XMLNS_ATTRIBUTE_NS_URI, "xmlns:md", MD);
        root.setAttributeNS(XMLConstants.XMLNS_ATTRIBUTE_NS_URI, "xmlns:ds", DS);
        root.setAttribute("ID", "_" + plan.id() + "_secondary_idp");
        root.setAttribute("entityID", endpoint(plan, "/idp/secondary"));
        root.setAttribute("validUntil", DateTimeFormatter.ISO_INSTANT.format(clock.instant().plus(Duration.ofDays(14))));
        document.appendChild(root);

        var idp = element(document, MD, "md:IDPSSODescriptor");
        idp.setAttribute("protocolSupportEnumeration", "urn:oasis:names:tc:SAML:2.0:protocol");
        idp.setAttribute("WantAuthnRequestsSigned", "false");
        keyDescriptor(document, idp, credentials.certificate(), "signing");
        service(document, idp, "SingleSignOnService", REDIRECT,
                endpoint(plan, "/idp/secondary/sso"), null, false);
        service(document, idp, "SingleSignOnService", POST,
                endpoint(plan, "/idp/secondary/sso"), null, false);
        nameIdFormat(document, idp, "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent");
        nameIdFormat(document, idp, "urn:oasis:names:tc:SAML:2.0:nameid-format:transient");
        root.appendChild(idp);

        signer.sign(root, credentials, idp, XmlSigner.SignatureOptions.standard());
        return SecureXml.serialize(document);
    }

    /**
     * Generates one signed aggregate containing only mutually compatible positive-consumption
     * fixtures. Document-wide negative controls remain separate because combining them would lose
     * the reason for rejection and therefore the case's detection power.
     */
    public byte[] generatePreloadedCampaign(TestPlan plan, String runId) {
        if (runId == null || runId.isBlank()) throw new IllegalArgumentException("runId is required");
        var document = SecureXml.newDocument();
        var root = element(document, MD, "md:EntitiesDescriptor");
        root.setAttributeNS(XMLConstants.XMLNS_ATTRIBUTE_NS_URI, "xmlns:md", MD);
        root.setAttributeNS(XMLConstants.XMLNS_ATTRIBUTE_NS_URI, "xmlns:ds", DS);
        root.setAttribute("ID", "_" + plan.id() + "_preloaded_campaign");
        root.setAttribute("validUntil", DateTimeFormatter.ISO_INSTANT.format(
                clock.instant().plus(Duration.ofDays(14))));
        document.appendChild(root);

        for (var variant : PRELOADED_CAMPAIGN_VARIANTS) {
            var fixture = SecureXml.parse(generate(plan, variant, runId));
            var fixtureRoot = fixture.getDocumentElement();
            removeSignatures(fixtureRoot);
            rewritePreloadedIdentity(fixtureRoot, plan, variant);
            markSignedRequestsRequired(fixtureRoot);
            root.appendChild(document.importNode(fixtureRoot, true));
        }
        signer.sign(root, keyStore.getOrCreate(plan.id()),
                root.getFirstChild() instanceof Element child ? child : null,
                XmlSigner.SignatureOptions.standard());
        return SecureXml.serialize(document);
    }

    public static List<Variant> preloadedCampaignVariants() {
        return PRELOADED_CAMPAIGN_VARIANTS;
    }

    public String preloadedEntityId(TestPlan plan, Variant variant) {
        if (!PRELOADED_CAMPAIGN_VARIANTS.contains(variant)) {
            throw new IllegalArgumentException("Variant is not safe for the preloaded campaign: " + variant.id());
        }
        return endpoint(plan, "/metadata-peer/" + variant.id());
    }

    public PlanCredentials credentialsForVariant(TestPlan plan, Variant variant) {
        var primary = keyStore.getOrCreate(plan.id());
        return roleCredentials(plan, primary, variant);
    }

    /**
     * Generates a fixture with a deterministic per-variant test key. A metadata consumer that
     * refreshes its configured URL on an unknown signing key can therefore advance a polling
     * campaign without any vendor administration API.
     */
    public byte[] generatePolling(TestPlan plan, Variant variant, String runId) {
        return generate(plan, variant, runId, pollingBaseCredentials(plan, variant));
    }

    /** Credentials matching the role key in {@link #generatePolling}. */
    public PlanCredentials credentialsForPollingVariant(TestPlan plan, Variant variant) {
        var primary = pollingBaseCredentials(plan, variant);
        return roleCredentials(plan, primary, variant);
    }

    public byte[] generate(TestPlan plan, Variant variant, String runId) {
        return generate(plan, variant, runId, keyStore.getOrCreate(plan.id()));
    }

    private byte[] generate(
            TestPlan plan, Variant variant, String runId, PlanCredentials primary) {
        var signingCredentials = signingCredentials(plan, primary, variant);
        var roleCredentials = roleCredentials(plan, primary, variant);
        var document = SecureXml.newDocument();
        var root = element(document, MD, "md:EntityDescriptor");
        root.setAttributeNS(XMLConstants.XMLNS_ATTRIBUTE_NS_URI, "xmlns:md", MD);
        root.setAttributeNS(XMLConstants.XMLNS_ATTRIBUTE_NS_URI, "xmlns:ds", DS);
        var id = "_" + plan.id();
        root.setAttribute("ID", id);
        root.setAttribute("entityID", endpoint(plan, ""));
        root.setAttribute("validUntil", DateTimeFormatter.ISO_INSTANT.format(clock.instant().plus(Duration.ofDays(14))));
        document.appendChild(root);

        var sp = element(document, MD, "md:SPSSODescriptor");
        sp.setAttribute("protocolSupportEnumeration", "urn:oasis:names:tc:SAML:2.0:protocol");
        sp.setAttribute("AuthnRequestsSigned", Boolean.toString(
                plan.parameters().requestSigningMode() == TestPlan.RequestSigningMode.REQUIRED));
        sp.setAttribute("WantAssertionsSigned", "true");
        roleKeyDescriptors(document, sp, plan, roleCredentials, variant);
        service(document, sp, "SingleLogoutService", REDIRECT, endpoint(plan, "/sp/slo", variant, runId), null, false);
        service(document, sp, "SingleLogoutService", POST, endpoint(plan, "/sp/slo", variant, runId), null, false);
        service(document, sp, "SingleLogoutService", SOAP, endpoint(plan, "/sp/slo/soap", variant, runId), null, false);
        service(document, sp, "AssertionConsumerService", POST, endpoint(plan, "/sp/acs/0", variant, runId), 0, true);
        service(document, sp, "AssertionConsumerService", POST, endpoint(plan, "/sp/acs/1", variant, runId), 1, false);
        service(document, sp, "AssertionConsumerService", PAOS, endpoint(plan, "/sp/paos", variant, runId), 2, false);
        // Deliberately advertise a Redirect ACS so SSO01.x can detect a target that emits a
        // advertising it never turns the binding into an allowed target behavior.
        service(document, sp, "AssertionConsumerService", REDIRECT, endpoint(plan, "/sp/acs/3", variant, runId), 3, false);
        root.appendChild(sp);

        var idp = element(document, MD, "md:IDPSSODescriptor");
        idp.setAttribute("protocolSupportEnumeration", "urn:oasis:names:tc:SAML:2.0:protocol");
        idp.setAttribute("WantAuthnRequestsSigned", "false");
        roleKeyDescriptors(document, idp, plan, roleCredentials, variant);
        service(document, idp, "SingleSignOnService", REDIRECT, endpoint(plan, "/idp/sso", variant, runId), null, false);
        service(document, idp, "SingleSignOnService", POST, endpoint(plan, "/idp/sso", variant, runId), null, false);
        service(document, idp, "SingleLogoutService", REDIRECT, endpoint(plan, "/idp/slo", variant, runId), null, false);
        service(document, idp, "SingleLogoutService", POST, endpoint(plan, "/idp/slo", variant, runId), null, false);
        service(document, idp, "SingleLogoutService", SOAP, endpoint(plan, "/idp/slo/soap", variant, runId), null, false);
        nameIdFormat(document, idp, "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent");
        nameIdFormat(document, idp, "urn:oasis:names:tc:SAML:2.0:nameid-format:transient");
        root.appendChild(idp);

        addExtensionFixture(document, root, variant);
        root = applyStructureFixture(document, root, plan, variant, runId);
        applyValidityFixture(root, variant);
        if (variant != Variant.UNSIGNED) {
            signer.sign(root, signingCredentials, root.getFirstChild() instanceof Element e ? e : null,
                    signatureOptions(variant));
            if (variant == Variant.SIGNED_OTHER_KEY_PRIMARY_KEYINFO) {
                replaceSignatureCertificate(root, primary.certificate());
            }
            if (variant == Variant.BAD_SIGNATURE) {
                root.setAttribute("entityID", root.getAttribute("entityID") + "/tampered-after-signing");
            }
        }
        return SecureXml.serialize(document);
    }

    private PlanCredentials pollingBaseCredentials(TestPlan plan, Variant variant) {
        try {
            var digest = MessageDigest.getInstance("SHA-256")
                    .digest(variant.id().getBytes(StandardCharsets.UTF_8));
            var alias = "poll-" + java.util.HexFormat.of().formatHex(digest, 0, 8);
            return keyStore.getOrCreate(plan.id(), alias);
        } catch (java.security.NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-256 is unavailable", impossible);
        }
    }

    private PlanCredentials roleCredentials(
            TestPlan plan, PlanCredentials primary, Variant variant) {
        return variant.certificateVariant()
                ? signingCredentials(plan, primary, variant)
                : primary;
    }

    private PlanCredentials signingCredentials(TestPlan plan, PlanCredentials primary, Variant variant) {
        if (variant == Variant.SIGNED_OTHER_KEY || variant == Variant.SIGNED_OTHER_KEY_PRIMARY_KEYINFO) {
            return keyStore.getOrCreate(plan.id(), "metadata-other");
        }
        var certificate = certificateVariant(primary, variant);
        return certificate == primary.certificate() ? primary : new PlanCredentials(primary.privateKey(), certificate);
    }

    private void removeSignatures(Element root) {
        var signatures = root.getElementsByTagNameNS(DS, "Signature");
        var values = new java.util.ArrayList<org.w3c.dom.Node>();
        for (var index = 0; index < signatures.getLength(); index++) values.add(signatures.item(index));
        values.forEach(value -> value.getParentNode().removeChild(value));
    }

    private void rewritePreloadedIdentity(Element root, TestPlan plan, Variant variant) {
        var entities = elementsIncludingRoot(root, "EntityDescriptor");
        for (var index = 0; index < entities.size(); index++) {
            var entity = entities.get(index);
            entity.setAttribute("ID", "_" + plan.id() + "_preloaded_"
                    + variant.id().replace('-', '_') + "_" + index);
            entity.setAttribute("entityID", index == entities.size() - 1
                    ? preloadedEntityId(plan, variant)
                    : preloadedEntityId(plan, variant) + "/child/" + index);
        }
        var groups = elementsIncludingRoot(root, "EntitiesDescriptor");
        for (var index = 0; index < groups.size(); index++) {
            groups.get(index).setAttribute(
                    "ID", "_" + plan.id() + "_preloaded_group_"
                            + variant.id().replace('-', '_') + "_" + index);
        }
    }

    private List<Element> elementsIncludingRoot(Element root, String localName) {
        var result = new java.util.ArrayList<Element>();
        if (MD.equals(root.getNamespaceURI()) && localName.equals(root.getLocalName())) result.add(root);
        var descendants = root.getElementsByTagNameNS(MD, localName);
        for (var index = 0; index < descendants.getLength(); index++) {
            result.add((Element) descendants.item(index));
        }
        return result;
    }

    private void markSignedRequestsRequired(Element root) {
        var roles = root.getElementsByTagNameNS(MD, "SPSSODescriptor");
        for (var index = 0; index < roles.getLength(); index++) {
            ((Element) roles.item(index)).setAttribute("AuthnRequestsSigned", "true");
        }
    }

    private java.security.cert.X509Certificate certificateVariant(PlanCredentials primary, Variant variant) {
        if (!variant.certificateVariant()) return primary.certificate();
        try {
            var now = clock.instant();
            var subject = variant == Variant.CERT_EMPTY_SUBJECT
                    ? new X500Name("") : new X500Name("CN=SAMLscope metadata fixture,O=SAMLscope");
            var issuer = variant == Variant.CERT_UNKNOWN_CA
                    ? new X500Name("CN=Unknown SAMLscope fixture CA,O=SAMLscope")
                    : variant == Variant.CERT_EMPTY_SUBJECT
                            ? new X500Name("CN=SAMLscope empty-subject issuer,O=SAMLscope") : subject;
            var notBefore = variant == Variant.CERT_NOT_YET_VALID
                    ? now.plus(Duration.ofDays(30)) : now.minus(Duration.ofDays(1));
            var notAfter = variant == Variant.CERT_EXPIRED
                    ? now.minus(Duration.ofHours(1))
                    : variant == Variant.CERT_LONG_VALIDITY
                            ? now.plus(Duration.ofDays(365L * 20))
                            : variant == Variant.CERT_NOT_YET_VALID
                                    ? now.plus(Duration.ofDays(395)) : now.plus(Duration.ofDays(365));
            var builder = new JcaX509v3CertificateBuilder(
                    issuer, new BigInteger(160, new SecureRandom()).abs(),
                    Date.from(notBefore), Date.from(notAfter), subject,
                    primary.certificate().getPublicKey());
            builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
            var usage = variant == Variant.CERT_NO_DIGITAL_SIGNATURE
                    ? KeyUsage.keyEncipherment : KeyUsage.digitalSignature | KeyUsage.keyEncipherment;
            builder.addExtension(Extension.keyUsage, true, new KeyUsage(usage));
            if (variant == Variant.CERT_EMPTY_SUBJECT) {
                builder.addExtension(Extension.subjectAlternativeName, true,
                        new GeneralNames(new GeneralName(GeneralName.uniformResourceIdentifier,
                                "https://peer.samlscope.com/fixtures/empty-subject")));
            }
            if (variant == Variant.CERT_CRITICAL_EXTENSION) {
                builder.addExtension(new ASN1ObjectIdentifier("1.3.6.1.4.1.57264.1.1"), true,
                        new DEROctetString(new byte[] { 1 }));
            }
            if (variant == Variant.CERT_NONCRITICAL_EXTENSION) {
                builder.addExtension(new ASN1ObjectIdentifier("1.3.6.1.4.1.57264.1.2"), false,
                        new DEROctetString(new byte[] { 2 }));
            }
            if (variant == Variant.CERT_UNRELATED_EKU) {
                builder.addExtension(Extension.extendedKeyUsage, false,
                        new ExtendedKeyUsage(KeyPurposeId.id_kp_codeSigning));
            }
            var algorithm = variant == Variant.CERT_SHA1 ? "SHA1withRSA"
                    : variant == Variant.CERT_SHA512 ? "SHA512withRSA" : "SHA256withRSA";
            var signed = new JcaContentSignerBuilder(algorithm)
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                    .build(primary.privateKey());
            return new JcaX509CertificateConverter()
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                    .getCertificate(builder.build(signed));
        } catch (Exception e) {
            throw new IllegalStateException("Could not generate metadata certificate fixture " + variant.id(), e);
        }
    }

    private void roleKeyDescriptors(
            Document document, Element role, TestPlan plan, PlanCredentials credentials, Variant variant) {
        if (variant == Variant.KEYVALUE_ONLY) {
            keyValueDescriptor(document, role, credentials.certificate().getPublicKey(), null);
            return;
        }
        var signingUse = variant == Variant.KEY_USE_OMITTED ? null : "signing";
        keyDescriptor(document, role, credentials.certificate(), signingUse);
        keyDescriptor(document, role, credentials.certificate(), "encryption");
        if (variant == Variant.MULTIPLE_SIGNING_KEYS || variant == Variant.THREE_SIGNING_KEYS) {
            keyDescriptor(document, role,
                    keyStore.getOrCreate(plan.id(), "metadata-rollover").certificate(), "signing");
        }
        if (variant == Variant.THREE_SIGNING_KEYS) {
            keyDescriptor(document, role,
                    keyStore.getOrCreate(plan.id(), "metadata-rollover-third").certificate(), "signing");
        }
    }

    private void keyValueDescriptor(
            Document document, Element parent, java.security.PublicKey publicKey, String use) {
        if (!(publicKey instanceof java.security.interfaces.RSAPublicKey rsa)) {
            throw new IllegalArgumentException("Only RSA KeyValue fixtures are supported");
        }
        var descriptor = element(document, MD, "md:KeyDescriptor");
        if (use != null) descriptor.setAttribute("use", use);
        var keyInfo = element(document, DS, "ds:KeyInfo");
        var keyValue = element(document, DS, "ds:KeyValue");
        var rsaKeyValue = element(document, DS, "ds:RSAKeyValue");
        var modulus = element(document, DS, "ds:Modulus");
        modulus.setTextContent(Base64.getEncoder().encodeToString(unsigned(rsa.getModulus())));
        var exponent = element(document, DS, "ds:Exponent");
        exponent.setTextContent(Base64.getEncoder().encodeToString(unsigned(rsa.getPublicExponent())));
        rsaKeyValue.appendChild(modulus);
        rsaKeyValue.appendChild(exponent);
        keyValue.appendChild(rsaKeyValue);
        keyInfo.appendChild(keyValue);
        descriptor.appendChild(keyInfo);
        parent.appendChild(descriptor);
    }

    private byte[] unsigned(BigInteger value) {
        var encoded = value.toByteArray();
        return encoded.length > 1 && encoded[0] == 0
                ? java.util.Arrays.copyOfRange(encoded, 1, encoded.length) : encoded;
    }

    private void replaceSignatureCertificate(Element root, java.security.cert.X509Certificate certificate) {
        try {
            var signatures = root.getElementsByTagNameNS(DS, "Signature");
            if (signatures.getLength() != 1) throw new IllegalStateException("Expected one metadata signature");
            var certificates = ((Element) signatures.item(0)).getElementsByTagNameNS(DS, "X509Certificate");
            if (certificates.getLength() != 1) throw new IllegalStateException("Expected one signature certificate");
            certificates.item(0).setTextContent(Base64.getEncoder().encodeToString(certificate.getEncoded()));
        } catch (java.security.cert.CertificateEncodingException e) {
            throw new IllegalStateException("Could not replace signature certificate", e);
        }
    }

    private XmlSigner.SignatureOptions signatureOptions(Variant variant) {
        var standard = XmlSigner.SignatureOptions.standard().transforms();
        return switch (variant) {
            case NO_KEY_INFO -> new XmlSigner.SignatureOptions(false, standard);
            case XPATH_IDENTITY -> new XmlSigner.SignatureOptions(true, List.of(
                    XmlSigner.TransformSpec.algorithm(org.apache.xml.security.transforms.Transforms.TRANSFORM_ENVELOPED_SIGNATURE),
                    XmlSigner.TransformSpec.xpath("true()"),
                    XmlSigner.TransformSpec.algorithm(org.apache.xml.security.transforms.Transforms.TRANSFORM_C14N_EXCL_OMIT_COMMENTS)));
            case XPATH_EXCLUDE_ROLE_DESCRIPTORS -> xpathExclusion(
                    "not(ancestor-or-self::md:SPSSODescriptor or ancestor-or-self::md:IDPSSODescriptor)");
            case XPATH_EXCLUDE_ENDPOINTS -> xpathExclusion(
                    "not(ancestor-or-self::md:AssertionConsumerService or ancestor-or-self::md:SingleSignOnService or ancestor-or-self::md:SingleLogoutService)");
            case XPATH_EXCLUDE_KEY_DESCRIPTORS -> xpathExclusion(
                    "not(ancestor-or-self::md:KeyDescriptor)");
            default -> XmlSigner.SignatureOptions.standard();
        };
    }

    private Element applyStructureFixture(
            Document document, Element entity, TestPlan plan, Variant variant, String runId) {
        return switch (variant) {
            case ENTITIES_ROOT_ONE, ENTITIES_VALID_UNTIL, ENTITIES_CACHE_DURATION ->
                    wrapEntities(document, entity, plan, 1, false, variant, runId);
            case ENTITIES_ROOT_TWO -> wrapEntities(document, entity, plan, 2, false, variant, runId);
            case ENTITIES_ROOT_FIFTY -> wrapEntities(document, entity, plan, 50, false, variant, runId);
            case NESTED_ENTITIES -> wrapEntities(document,
                    wrapEntities(document, entity, plan, 1, false, variant, runId, "_inner"),
                    plan, 1, true, variant, runId);
            case DISTINCT_ENTITY_IDS -> wrapEntities(document, entity, plan, 2, false, variant, runId);
            case DUPLICATE_ENTITY_IDS, CONFLICTING_DUPLICATE_ENTITY_IDS ->
                    wrapEntities(document, entity, plan, 2, true, variant, runId);
            default -> entity;
        };
    }

    private Element wrapEntities(
            Document document,
            Element child,
            TestPlan plan,
            int childCount,
            boolean duplicateEntityId,
            Variant variant,
            String runId) {
        return wrapEntities(document, child, plan, childCount, duplicateEntityId, variant, runId, "");
    }

    private Element wrapEntities(
            Document document,
            Element child,
            TestPlan plan,
            int childCount,
            boolean duplicateEntityId,
            Variant variant,
            String runId,
            String idSuffix) {
        document.removeChild(child);
        var wrapper = element(document, MD, "md:EntitiesDescriptor");
        wrapper.setAttributeNS(XMLConstants.XMLNS_ATTRIBUTE_NS_URI, "xmlns:md", MD);
        wrapper.setAttributeNS(XMLConstants.XMLNS_ATTRIBUTE_NS_URI, "xmlns:ds", DS);
        wrapper.setAttribute(
                "ID", "_" + plan.id() + "_entities_" + variant.id().replace('-', '_') + idSuffix);
        wrapper.setAttribute("validUntil", DateTimeFormatter.ISO_INSTANT.format(
                clock.instant().plus(Duration.ofDays(14))));
        for (var index = 1; index < childCount; index++) {
            var copy = (Element) child.cloneNode(true);
            copy.setAttribute("ID", "_" + plan.id() + "_fixture_" + index);
            if (!duplicateEntityId) {
                copy.setAttribute("entityID", endpoint(plan, "/fixture/entity/" + index));
            } else if (variant == Variant.CONFLICTING_DUPLICATE_ENTITY_IDS) {
                rewriteLocations(copy, endpoint(plan, "/fixture/conflict/" + index, variant, runId));
            }
            wrapper.appendChild(copy);
        }
        wrapper.appendChild(child);
        document.appendChild(wrapper);
        return wrapper;
    }

    private void rewriteLocations(Element root, String location) {
        var elements = root.getElementsByTagNameNS(MD, "*");
        for (var index = 0; index < elements.getLength(); index++) {
            var element = (Element) elements.item(index);
            if (element.hasAttribute("Location")) element.setAttribute("Location", location);
            if (element.hasAttribute("ResponseLocation")) element.setAttribute("ResponseLocation", location);
        }
    }

    private void applyValidityFixture(Element root, Variant variant) {
        switch (variant) {
            case NO_VALID_UNTIL -> root.removeAttribute("validUntil");
            case EXPIRED -> root.setAttribute(
                    "validUntil", DateTimeFormatter.ISO_INSTANT.format(clock.instant().minus(Duration.ofDays(1))));
            case ENTITY_CACHE_DURATION, ENTITIES_CACHE_DURATION -> {
                root.removeAttribute("validUntil");
                root.setAttribute("cacheDuration", "PT1H");
            }
            default -> { }
        }
    }

    private void addExtensionFixture(Document document, Element entity, Variant variant) {
        if (variant != Variant.UNKNOWN_EXTENSION
                && variant != Variant.UNKNOWN_ROLE_EXTENSION
                && variant != Variant.UNKNOWN_ENDPOINT_EXTENSION
                && variant != Variant.INVALID_SAML_EXTENSION
                && variant != Variant.MDRPI_REGISTRATION_INFO) return;
        if (variant == Variant.UNKNOWN_ROLE_EXTENSION) {
            var role = (Element) entity.getElementsByTagNameNS(MD, "SPSSODescriptor").item(0);
            var extensions = element(document, MD, "md:Extensions");
            extensions.appendChild(probeExtension(document, "role-extension"));
            role.insertBefore(extensions, role.getFirstChild());
            return;
        }
        if (variant == Variant.UNKNOWN_ENDPOINT_EXTENSION) {
            var endpoint = (Element) entity.getElementsByTagNameNS(MD, "AssertionConsumerService").item(0);
            endpoint.setAttributeNS(
                    "urn:samlscope:test:metadata-extension", "samlscope:probe", "endpoint-attribute");
            endpoint.setAttributeNS(XMLConstants.XMLNS_ATTRIBUTE_NS_URI,
                    "xmlns:samlscope", "urn:samlscope:test:metadata-extension");
            endpoint.appendChild(probeExtension(document, "endpoint-element"));
            return;
        }
        var extensions = element(document, MD, "md:Extensions");
        if (variant == Variant.UNKNOWN_EXTENSION) {
            extensions.appendChild(probeExtension(document, "entity-extension"));
        } else if (variant == Variant.INVALID_SAML_EXTENSION) {
            var invalid = element(document, SAML, "saml:Attribute");
            invalid.setAttributeNS(XMLConstants.XMLNS_ATTRIBUTE_NS_URI, "xmlns:saml", SAML);
            invalid.setAttribute("Name", "invalid-at-this-extension-point");
            extensions.appendChild(invalid);
        } else {
            var registration = element(document,
                    "urn:oasis:names:tc:SAML:metadata:rpi", "mdrpi:RegistrationInfo");
            registration.setAttributeNS(XMLConstants.XMLNS_ATTRIBUTE_NS_URI,
                    "xmlns:mdrpi", "urn:oasis:names:tc:SAML:metadata:rpi");
            registration.setAttribute("registrationAuthority", "https://samlscope.com");
            extensions.appendChild(registration);
        }
        entity.insertBefore(extensions, entity.getFirstChild());
    }

    private Element probeExtension(Document document, String value) {
        var extension = element(document, "urn:samlscope:test:metadata-extension", "samlscope:Probe");
        extension.setAttributeNS(XMLConstants.XMLNS_ATTRIBUTE_NS_URI,
                "xmlns:samlscope", "urn:samlscope:test:metadata-extension");
        extension.setTextContent(value);
        return extension;
    }

    private XmlSigner.SignatureOptions xpathExclusion(String expression) {
        return new XmlSigner.SignatureOptions(true, List.of(
                XmlSigner.TransformSpec.algorithm(org.apache.xml.security.transforms.Transforms.TRANSFORM_ENVELOPED_SIGNATURE),
                XmlSigner.TransformSpec.xpath(expression),
                XmlSigner.TransformSpec.algorithm(org.apache.xml.security.transforms.Transforms.TRANSFORM_C14N_EXCL_OMIT_COMMENTS)));
    }

    private void keyDescriptor(Document document, Element parent, java.security.cert.X509Certificate certificate, String use) {
        try {
            var descriptor = element(document, MD, "md:KeyDescriptor");
            if (use != null) descriptor.setAttribute("use", use);
            var keyInfo = element(document, DS, "ds:KeyInfo");
            var x509Data = element(document, DS, "ds:X509Data");
            var x509Certificate = element(document, DS, "ds:X509Certificate");
            x509Certificate.setTextContent(Base64.getEncoder().encodeToString(certificate.getEncoded()));
            x509Data.appendChild(x509Certificate);
            keyInfo.appendChild(x509Data);
            descriptor.appendChild(keyInfo);
            parent.appendChild(descriptor);
        } catch (Exception e) {
            throw new IllegalStateException("Could not encode metadata certificate", e);
        }
    }

    private void service(Document document, Element parent, String localName, String binding, String location,
                         Integer index, boolean isDefault) {
        var service = element(document, MD, "md:" + localName);
        service.setAttribute("Binding", binding);
        service.setAttribute("Location", location);
        if (index != null) service.setAttribute("index", index.toString());
        if (isDefault) service.setAttribute("isDefault", "true");
        parent.appendChild(service);
    }

    private void nameIdFormat(Document document, Element parent, String format) {
        var element = element(document, MD, "md:NameIDFormat");
        element.setTextContent(format);
        parent.appendChild(element);
    }

    private String endpoint(TestPlan plan, String suffix) {
        return peerBase.resolve("/p/" + plan.id() + suffix).toString();
    }

    private String endpoint(TestPlan plan, String suffix, Variant variant, String runId) {
        var base = endpoint(plan, suffix);
        if (variant == Variant.BASELINE) return base;
        if (runId == null || runId.isBlank()) throw new IllegalArgumentException("runId is required for metadata variants");
        return base + "?mdv=" + variant.id() + "&run=" + runId;
    }

    public enum Variant {
        BASELINE("baseline"),
        CONTROL("control"),
        REDIRECT_301("redirect-301"),
        REDIRECT_302("redirect-302"),
        REDIRECT_307("redirect-307"),
        ENTITY_ROOT("entity-root"),
        ENTITIES_ROOT_ONE("entities-root-one"),
        ENTITIES_ROOT_TWO("entities-root-two"),
        ENTITIES_ROOT_FIFTY("entities-root-fifty"),
        NESTED_ENTITIES("nested-entities"),
        DISTINCT_ENTITY_IDS("distinct-entity-ids"),
        DUPLICATE_ENTITY_IDS("duplicate-entity-ids"),
        CONFLICTING_DUPLICATE_ENTITY_IDS("conflicting-duplicate-entity-ids"),
        NO_VALID_UNTIL("no-valid-until"),
        EXPIRED("expired"),
        ENTITY_CACHE_DURATION("entity-cache-duration"),
        ENTITIES_CACHE_DURATION("entities-cache-duration"),
        ENTITIES_VALID_UNTIL("entities-valid-until"),
        UNKNOWN_EXTENSION("unknown-extension"),
        UNKNOWN_ROLE_EXTENSION("unknown-role-extension"),
        UNKNOWN_ENDPOINT_EXTENSION("unknown-endpoint-extension"),
        INVALID_SAML_EXTENSION("invalid-saml-extension"),
        MDRPI_REGISTRATION_INFO("mdrpi-registration-info"),
        XPATH_IDENTITY("xpath-identity"),
        XPATH_EXCLUDE_ROLE_DESCRIPTORS("xpath-exclude-role-descriptors"),
        XPATH_EXCLUDE_ENDPOINTS("xpath-exclude-endpoints"),
        XPATH_EXCLUDE_KEY_DESCRIPTORS("xpath-exclude-key-descriptors"),
        NO_KEY_INFO("no-key-info"),
        SIGNED_OTHER_KEY("signed-other-key"),
        SIGNED_OTHER_KEY_PRIMARY_KEYINFO("signed-other-key-primary-keyinfo"),
        BAD_SIGNATURE("bad-signature"),
        UNSIGNED("unsigned"),
        KEY_USE_OMITTED("key-use-omitted"),
        KEYVALUE_ONLY("keyvalue-only"),
        MULTIPLE_SIGNING_KEYS("multiple-signing-keys"),
        THREE_SIGNING_KEYS("three-signing-keys"),
        CERT_EXPIRED("certificate-expired"),
        CERT_NOT_YET_VALID("certificate-not-yet-valid"),
        CERT_NO_DIGITAL_SIGNATURE("certificate-no-digital-signature"),
        CERT_CRITICAL_EXTENSION("certificate-critical-extension"),
        CERT_NONCRITICAL_EXTENSION("certificate-noncritical-extension"),
        CERT_UNRELATED_EKU("certificate-unrelated-eku"),
        CERT_SHA1("certificate-sha1"),
        CERT_SHA512("certificate-sha512"),
        CERT_EMPTY_SUBJECT("certificate-empty-subject"),
        CERT_LONG_VALIDITY("certificate-long-validity"),
        CERT_UNKNOWN_CA("certificate-unknown-ca");

        private final String id;
        Variant(String id) { this.id = id; }
        public String id() { return id; }

        boolean certificateVariant() {
            return switch (this) {
                case CERT_EXPIRED, CERT_NOT_YET_VALID, CERT_NO_DIGITAL_SIGNATURE,
                        CERT_CRITICAL_EXTENSION, CERT_NONCRITICAL_EXTENSION,
                        CERT_UNRELATED_EKU, CERT_SHA1, CERT_SHA512, CERT_EMPTY_SUBJECT,
                        CERT_LONG_VALIDITY, CERT_UNKNOWN_CA -> true;
                default -> false;
            };
        }

        public static Variant parse(String value) {
            if (value == null || value.isBlank() || "baseline".equals(value)) return BASELINE;
            return java.util.Arrays.stream(values()).filter(item -> item.id.equals(value)).findFirst()
                    .orElseThrow(() -> new IllegalArgumentException("Unknown metadata variant: " + value));
        }
    }

    private Element element(Document document, String namespace, String qualifiedName) {
        return document.createElementNS(namespace, qualifiedName);
    }
}
