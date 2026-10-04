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
    public static final String UI = "urn:oasis:names:tc:SAML:metadata:ui";
    public static final String MDATTR = "urn:oasis:names:tc:SAML:metadata:attribute";
    public static final String REDIRECT = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect";
    public static final String POST = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";
    public static final String SOAP = "urn:oasis:names:tc:SAML:2.0:bindings:SOAP";
    public static final String PAOS = "urn:oasis:names:tc:SAML:2.0:bindings:PAOS";
    private static final List<Variant> PRELOADED_CAMPAIGN_VARIANTS = List.of(
            Variant.UI_SAFETY_LOGO_DATA,
            Variant.UI_SAFETY_INFORMATION_JAVASCRIPT,
            Variant.UI_SAFETY_PRIVACY_JAVASCRIPT,
            Variant.UI_URL_LOGO_HTTP, Variant.UI_URL_LOGO_HTTPS, Variant.UI_URL_LOGO_DATA,
            Variant.UI_URL_LOGO_JAVASCRIPT, Variant.UI_URL_LOGO_FILE,
            Variant.UI_URL_INFORMATION_HTTP, Variant.UI_URL_INFORMATION_HTTPS, Variant.UI_URL_INFORMATION_DATA,
            Variant.UI_URL_INFORMATION_JAVASCRIPT, Variant.UI_URL_INFORMATION_FILE,
            Variant.UI_URL_PRIVACY_HTTP, Variant.UI_URL_PRIVACY_HTTPS, Variant.UI_URL_PRIVACY_DATA,
            Variant.UI_URL_PRIVACY_JAVASCRIPT, Variant.UI_URL_PRIVACY_FILE,
            Variant.UI_CONSUMER_DISPLAY_ALL,
            Variant.UI_CONSUMER_DISPLAY_SERVICE,
            Variant.UI_CONSUMER_DISPLAY_ENTITY,
            Variant.UI_CONSUMER_LOGO_LOCALIZED,
            Variant.UI_CONSUMER_LOGO_FALLBACK,
            Variant.NAMEID_OMISSION,
            Variant.ATTRIBUTE_POLICY_ENTITY_PRESENT,
            Variant.ATTRIBUTE_POLICY_ENTITY_ABSENT,
            Variant.ATTRIBUTE_POLICY_REQUESTED_REQUIRED,
            Variant.ATTRIBUTE_POLICY_REQUESTED_OPTIONAL,
            Variant.ATTRIBUTE_POLICY_REQUESTED_ABSENT,
            Variant.ATTRIBUTE_POLICY_INDEXED,
            Variant.ALGORITHM_ENTITY_SHA256,
            Variant.ALGORITHM_ENTITY_SHA384,
            Variant.ALGORITHM_ENTITY_ORDER_256_384,
            Variant.ALGORITHM_ENTITY_ORDER_384_256,
            Variant.ALGORITHM_ROLE_ORDER_256_384,
            Variant.ALGORITHM_ROLE_ORDER_384_256,
            Variant.ALGORITHM_ROLE_SIGNING_384,
            Variant.ALGORITHM_ROLE_DIGEST_384,
            Variant.ALGORITHM_ROLE_BOTH_384,
            Variant.ALGORITHM_ROLE_BOTH_256,
            Variant.ALGORITHM_UNSUPPORTED_FIRST,
            Variant.ALGORITHM_ABSENT,
            Variant.ALGORITHM_ENCRYPTION_AES128_CBC,
            Variant.ALGORITHM_ENCRYPTION_AES256_CBC,
            Variant.ALGORITHM_ENCRYPTION_AES128_GCM,
            Variant.ALGORITHM_ENCRYPTION_AES256_GCM,
            Variant.ALGORITHM_ENCRYPTION_ORDER_128_256,
            Variant.ALGORITHM_ENCRYPTION_ORDER_256_128,
            Variant.ALGORITHM_ENCRYPTION_KEYSIZE_128,
            Variant.ALGORITHM_ENCRYPTION_KEYSIZE_256,
            Variant.ALGORITHM_OAEP_10_SHA1,
            Variant.ALGORITHM_OAEP_10_SHA256,
            Variant.ALGORITHM_OAEP_11_SHA1,
            Variant.ALGORITHM_OAEP_11_SHA256,
            Variant.ALGORITHM_OAEP_11_DEFAULT_MGF,
            Variant.ALGORITHM_SIGNING_256_KEYSIZE_EXCLUDED,
            Variant.ALGORITHM_SIGNING_384_KEYSIZE_EXCLUDED,
            Variant.UNKNOWN_EXTENSION,
            Variant.UNKNOWN_ROLE_EXTENSION,
            Variant.UNKNOWN_ORGANIZATION_EXTENSION,
            Variant.UNKNOWN_CONTACT_EXTENSION,
            Variant.UNKNOWN_AFFILIATION_EXTENSION,
            Variant.UNKNOWN_ENDPOINT_EXTENSION,
            Variant.MDRPI_REGISTRATION_INFO,
            Variant.ENTITY_CACHE_DURATION,
            Variant.ENTITIES_CACHE_DURATION,
            Variant.ENTITIES_VALID_UNTIL,
            Variant.NESTED_ENTITIES,
            Variant.KEYVALUE_ONLY,
            Variant.ENTITY_ROOT,
            Variant.MULTIPLE_SIGNING_KEYS_FIRST,
            Variant.MULTIPLE_SIGNING_KEYS,
            Variant.MULTIPLE_SIGNING_KEYS_UNADVERTISED,
            Variant.CERT_RUNTIME_SAME_KEY,
            Variant.CERT_RUNTIME_OTHER_KEY,
            Variant.THREE_SIGNING_KEYS_FIRST,
            Variant.THREE_SIGNING_KEYS_SECOND,
            Variant.THREE_SIGNING_KEYS,
            Variant.MULTIPLE_OMITTED_KEYS_FIRST,
            Variant.MULTIPLE_OMITTED_KEYS_SECOND,
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
            Variant.CERT_UNKNOWN_CA,
            Variant.FOREIGN_ATTRIBUTE_ENTITY,
            Variant.FOREIGN_ATTRIBUTE_ORGANIZATION,
            Variant.FOREIGN_ATTRIBUTE_CONTACT,
            Variant.FOREIGN_ATTRIBUTE_ROLE,
            Variant.FOREIGN_ATTRIBUTE_SINGLE_LOGOUT,
            Variant.FOREIGN_ATTRIBUTE_SINGLE_SIGN_ON,
            Variant.FOREIGN_ATTRIBUTE_MANAGE_NAMEID,
            Variant.FOREIGN_ATTRIBUTE_NAMEID_MAPPING,
            Variant.FOREIGN_ATTRIBUTE_ASSERTION_ID,
            Variant.FOREIGN_ATTRIBUTE_AUTHN_QUERY,
            Variant.FOREIGN_ATTRIBUTE_AUTHZ,
            Variant.FOREIGN_ATTRIBUTE_ATTRIBUTE_SERVICE,
            Variant.FOREIGN_ATTRIBUTE_AFFILIATION,
            Variant.ECDSA_SHA256);

    private final URI peerBase;
    private final FilePlanKeyStore keyStore;
    private final XmlSigner signer;
    private final Clock clock;
    private final MetadataUiAssetLocations uiAssets;

    public MetadataService(URI peerBase, FilePlanKeyStore keyStore, XmlSigner signer, Clock clock) {
        this(peerBase, keyStore, signer, clock, MetadataUiAssetLocations.forPeer(peerBase));
    }

    public MetadataService(URI peerBase, FilePlanKeyStore keyStore, XmlSigner signer, Clock clock,
            MetadataUiAssetLocations uiAssets) {
        this.peerBase = peerBase;
        this.keyStore = keyStore;
        this.signer = signer;
        this.clock = clock;
        this.uiAssets = java.util.Objects.requireNonNull(uiAssets);
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
        return generatePreloadedCampaign(plan, runId, PRELOADED_CAMPAIGN_VARIANTS);
    }

    public byte[] generatePreloadedCampaign(TestPlan plan, String runId, List<Variant> variants) {
        if (variants == null || variants.isEmpty() || variants.stream().anyMatch(java.util.Objects::isNull)
                || new java.util.HashSet<>(variants).size() != variants.size()
                || !PRELOADED_CAMPAIGN_VARIANTS.containsAll(variants)) {
            throw new IllegalArgumentException("Invalid preloaded campaign subset");
        }
        if (runId == null || runId.isBlank()) throw new IllegalArgumentException("runId is required");
        var document = SecureXml.newDocument();
        var root = element(document, MD, "md:EntitiesDescriptor");
        root.setAttributeNS(XMLConstants.XMLNS_ATTRIBUTE_NS_URI, "xmlns:md", MD);
        root.setAttributeNS(XMLConstants.XMLNS_ATTRIBUTE_NS_URI, "xmlns:ds", DS);
        root.setAttribute("ID", "_" + plan.id() + "_preloaded_campaign");
        root.setAttribute("validUntil", DateTimeFormatter.ISO_INSTANT.format(
                clock.instant().plus(Duration.ofDays(14))));
        document.appendChild(root);

        for (var variant : variants) {
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

    /** Request-signing credentials advertised for signing by the ordinary fixture. */
    public PlanCredentials credentialsForVariant(TestPlan plan, Variant variant) {
        var primary = keyStore.getOrCreate(plan.id());
        return requestSigningCredentials(plan, primary, variant);
    }

    /** Receiver credentials retain the last advertised encryption key when testing multiple keys. */
    public PlanCredentials decryptionCredentialsForVariant(TestPlan plan, Variant variant) {
        return probeCredentials(plan, keyStore.getOrCreate(plan.id()), variant);
    }

    /**
     * Generates a fixture with a deterministic per-variant test key. A metadata consumer that
     * refreshes its configured URL on an unknown signing key can therefore advance a polling
     * campaign without any vendor administration API.
     */
    public byte[] generatePolling(TestPlan plan, Variant variant, String runId) {
        if (variant == Variant.SIGNATURE_MODES_OPTIONAL) {
            throw new IllegalArgumentException("Signature mode metadata uses the ordinary SSO campaign");
        }
        return generate(plan, variant, runId, pollingBaseCredentials(plan, variant));
    }

    /** Request-signing credentials advertised for signing by {@link #generatePolling}. */
    public PlanCredentials credentialsForPollingVariant(TestPlan plan, Variant variant) {
        var primary = pollingBaseCredentials(plan, variant);
        return requestSigningCredentials(plan, primary, variant);
    }

    /** Receiver credentials for polling; multiple encryption keys retain the last key. */
    public PlanCredentials decryptionCredentialsForPollingVariant(TestPlan plan, Variant variant) {
        return probeCredentials(plan, pollingBaseCredentials(plan, variant), variant);
    }

    public byte[] generate(TestPlan plan, Variant variant, String runId) {
        return generate(plan, variant, runId, keyStore.getOrCreate(plan.id()));
    }

    /**
     * Generates the Suite peer metadata that the target itself consumes. A metadata variant may only
     * advertise attributes (for example an encryption method); the endpoint locations stay baseline
     * so a normal correlated response is not mistaken for a fixture probe.
     */
    public byte[] generateSuiteMetadata(TestPlan plan, Variant variant, String runId) {
        return generate(plan, variant, runId, keyStore.getOrCreate(plan.id()), false);
    }

    private byte[] generate(
            TestPlan plan, Variant variant, String runId, PlanCredentials primary) {
        return generate(plan, variant, runId, primary, true);
    }

    private byte[] generate(
            TestPlan plan, Variant variant, String runId, PlanCredentials primary, boolean correlateEndpoints) {
        var endpointVariant = correlateEndpoints ? variant : Variant.BASELINE;
        // The structural contrast changes EndpointType extension support only; its signed
        // public metadata retains the exact key material and endpoint URLs of the test input.
        if (endpointVariant == Variant.SCHEMA_SSO_ENDPOINT_WITHOUT_FOREIGN
                || endpointVariant == Variant.SCHEMA_INVALID_ENDPOINT_LOCATION)
            endpointVariant = Variant.SCHEMA_SSO_ENDPOINT_SET;
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
        sp.setAttribute("WantAssertionsSigned", Boolean.toString(variant != Variant.SIGNATURE_MODES_OPTIONAL));
        roleKeyDescriptors(document, sp, plan, roleCredentials, variant);
        service(document, sp, "SingleLogoutService", REDIRECT, endpoint(plan, "/sp/slo", endpointVariant, runId), null, false);
        service(document, sp, "SingleLogoutService", POST, endpoint(plan, "/sp/slo", endpointVariant, runId), null, false);
        service(document, sp, "SingleLogoutService", SOAP, endpoint(plan, "/sp/slo/soap", endpointVariant, runId), null, false);
        service(document, sp, "AssertionConsumerService", POST, endpoint(plan, "/sp/acs/0", endpointVariant, runId), 0,
                variant != Variant.DEFAULT_ACS_SECOND && variant != Variant.DEFAULT_ACS_IMPLICIT);
        service(document, sp, "AssertionConsumerService", POST, endpoint(plan, "/sp/acs/1", endpointVariant, runId), 1, variant == Variant.DEFAULT_ACS_SECOND);
        service(document, sp, "AssertionConsumerService", PAOS, endpoint(plan, "/sp/paos", endpointVariant, runId), 2, false);
        // Deliberately advertise a Redirect ACS so SSO01.x can detect a target that emits a
        // advertising it never turns the binding into an allowed target behavior.
        service(document, sp, "AssertionConsumerService", REDIRECT, endpoint(plan, "/sp/acs/3", endpointVariant, runId), 3, false);
        applyDefaultAcsFixture(sp, variant);
        root.appendChild(sp);

        var idp = element(document, MD, "md:IDPSSODescriptor");
        idp.setAttribute("protocolSupportEnumeration", "urn:oasis:names:tc:SAML:2.0:protocol");
        idp.setAttribute("WantAuthnRequestsSigned", "false");
        roleKeyDescriptors(document, idp, plan, roleCredentials, variant);
        service(document, idp, "SingleLogoutService", REDIRECT, endpoint(plan, "/idp/slo", endpointVariant, runId), null, false);
        service(document, idp, "SingleLogoutService", POST, endpoint(plan, "/idp/slo", endpointVariant, runId), null, false);
        service(document, idp, "SingleLogoutService", SOAP, endpoint(plan, "/idp/slo/soap", endpointVariant, runId), null, false);
        nameIdFormat(document, idp, "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent");
        nameIdFormat(document, idp, "urn:oasis:names:tc:SAML:2.0:nameid-format:transient");
        service(document, idp, "SingleSignOnService", REDIRECT, endpoint(plan, "/idp/sso", endpointVariant, runId), null, false);
        service(document, idp, "SingleSignOnService", POST, endpoint(plan, "/idp/sso", endpointVariant, runId), null, false);
        root.appendChild(idp);

        if (variant.roleKeyProbe()) {
            root = MetadataRoleKeyFixtures.apply(document, root, primary,
                    rolloverCredentials(plan, primary, 2), rolloverCredentials(plan, primary, 3), variant);
        }
        addExtensionFixture(document, root, variant);
        root = applyStructureFixture(document, root, plan, variant, runId);
        addEntityAttributesFixture(document, root, variant, signingCredentials);
        root = MetadataExtensionAttributeFixtures.apply(document, root, variant);
        root = MetadataExtensionPlacementFixtures.apply(document, root, variant);
        root = MetadataAttributePolicyFixtures.apply(document, root, variant);
        root = MetadataUiConsumerFixtures.apply(document, root, variant);
        if (variant == Variant.FULL_UI_INFO) root = MetadataUiConsumerFixtures.applyFullUi(document, root);
        root = MetadataSchemaCoverageFixtures.apply(document, root, variant);
        root = MetadataUiUrlFixtures.apply(document, root, variant, uiAssets);
        root = MetadataUiSafetyFixtures.apply(document, root, variant);
        root = MetadataAlgorithmFixtures.apply(document, root, variant);
        root = MetadataEncryptionAlgorithmFixtures.apply(document, root, variant);
        root = MetadataRevocationFixtures.apply(document, root, primary, variant, clock.instant());
        applyValidityFixture(root, variant);
        root = MetadataLiveValidityFixtures.apply(document, root, variant, clock.instant(),
                plan.parameters().metadataRefreshWaitSeconds());
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
            // The negative request changes the signature, not the target's trusted EC key.
            var keyVariant = switch (variant) {
                case ECDSA_SHA256_INVALID_SIGNATURE -> Variant.ECDSA_SHA256;
                case SCHEMA_SSO_ENDPOINT_WITHOUT_FOREIGN, SCHEMA_INVALID_ENDPOINT_LOCATION -> Variant.SCHEMA_SSO_ENDPOINT_SET;
                case KEYVALUE_ONLY, KEYVALUE_AND_X509, CERT_RUNTIME_SAME_KEY, CERT_RUNTIME_OTHER_KEY -> Variant.ENTITY_ROOT;
                // Compare signer selection against one unchanged advertised key set.
                case MULTIPLE_SIGNING_KEYS, MULTIPLE_SIGNING_KEYS_UNADVERTISED -> Variant.MULTIPLE_SIGNING_KEYS_FIRST;
                case MULTIPLE_OMITTED_KEYS_SECOND -> Variant.MULTIPLE_OMITTED_KEYS_FIRST;
                case THREE_SIGNING_KEYS_SECOND, THREE_SIGNING_KEYS -> Variant.THREE_SIGNING_KEYS_FIRST;
                // Keep the same three keys while changing only role, use and role order.
                case ROLE_KEYS_SP_FIRST_EXPLICIT_A, ROLE_KEYS_IDP_FIRST_EXPLICIT_B,
                        ROLE_KEYS_SP_FIRST_OMITTED_A, ROLE_KEYS_IDP_FIRST_OMITTED_B ->
                        Variant.THREE_SIGNING_KEYS_FIRST;
                // Display precedence changes only the advertised name candidates. Rotating the
                // trusted key between those conditions confounds the native UI comparison.
                case UI_CONSUMER_DISPLAY_SERVICE, UI_CONSUMER_DISPLAY_ENTITY -> Variant.UI_CONSUMER_DISPLAY_ALL;
                default -> variant;
            };
            // URL consumption comparisons vary the UI URL, not the trust anchor. Their
            // native adapters explicitly reload metadata; key rotation is not their trigger.
            if (variant.id().startsWith("ui-url-") || variant.id().startsWith("ui-safety-")) {
                keyVariant = Variant.UI_URL_LOGO_HTTP;
            }
            var digest = MessageDigest.getInstance("SHA-256")
                    .digest(keyVariant.id().getBytes(StandardCharsets.UTF_8));
            var alias = "poll-" + java.util.HexFormat.of().formatHex(digest, 0, 8);
            return keyStore.getOrCreate(plan.id(), alias);
        } catch (java.security.NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-256 is unavailable", impossible);
        }
    }

    private PlanCredentials requestSigningCredentials(TestPlan plan, PlanCredentials primary, Variant variant) {
        if (variant.roleKeyProbe()) {
            return variant == Variant.ROLE_KEYS_IDP_FIRST_EXPLICIT_B
                    || variant == Variant.ROLE_KEYS_IDP_FIRST_OMITTED_B
                    ? rolloverCredentials(plan, primary, 2) : primary;
        }
        // The second encryption-only key is not a signing credential. Keep the metadata
        // representation unchanged and retain that receiver through the separate accessors.
        return variant == Variant.MULTIPLE_ENCRYPTION_KEYS ? primary : probeCredentials(plan, primary, variant);
    }

    // Probe with the last advertised key, so a consumer that only reads the first key
    // cannot satisfy a multi-key fixture. Certificate fixtures deliberately use the
    // original certificate at runtime: only the public key must agree with metadata.
    private PlanCredentials probeCredentials(TestPlan plan, PlanCredentials primary, Variant variant) {
        return switch (variant) {
            case ROLE_KEYS_SP_FIRST_EXPLICIT_A, ROLE_KEYS_IDP_FIRST_EXPLICIT_B ->
                    rolloverCredentials(plan, primary, 3);
            case ROLE_KEYS_IDP_FIRST_OMITTED_B -> rolloverCredentials(plan, primary, 2);
            case CERT_RUNTIME_SAME_KEY -> runtimeCertificate(primary, primary);
            case CERT_RUNTIME_OTHER_KEY -> runtimeCertificate(primary, rolloverCredentials(plan, primary, 2));
            case ECDSA_SHA256, ECDSA_SHA256_INVALID_SIGNATURE -> ecCredentials(plan, primary);
            case MULTIPLE_SIGNING_KEYS, MULTIPLE_ENCRYPTION_KEYS, MULTIPLE_OMITTED_KEYS_SECOND, THREE_SIGNING_KEYS_SECOND ->
                    rolloverCredentials(plan, primary, 2);
            case THREE_SIGNING_KEYS, MULTIPLE_SIGNING_KEYS_UNADVERTISED -> rolloverCredentials(plan, primary, 3);
            default -> primary;
        };
    }

    /** Keep certificate names fixed while independently varying the runtime public key. */
    private PlanCredentials runtimeCertificate(PlanCredentials metadata, PlanCredentials signer) {
        try {
            var original=metadata.certificate();
            var builder=new JcaX509v3CertificateBuilder(
                    X500Name.getInstance(original.getIssuerX500Principal().getEncoded()),
                    original.getSerialNumber().add(BigInteger.ONE), original.getNotBefore(), original.getNotAfter(),
                    X500Name.getInstance(original.getSubjectX500Principal().getEncoded()), signer.certificate().getPublicKey());
            builder.addExtension(Extension.basicConstraints,true,new BasicConstraints(false));
            builder.addExtension(Extension.keyUsage,true,new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment));
            var certificate=new JcaX509CertificateConverter().getCertificate(builder.build(
                    new JcaContentSignerBuilder("SHA256withRSA").build(signer.privateKey())));
            return new PlanCredentials(signer.privateKey(),certificate);
        } catch(Exception invalid) {
            throw new IllegalStateException("Cannot create runtime certificate comparison fixture",invalid);
        }
    }

    private PlanCredentials ecCredentials(TestPlan plan, PlanCredentials primary) {
        try {
            var digest = MessageDigest.getInstance("SHA-256").digest(primary.certificate().getPublicKey().getEncoded());
            return keyStore.getOrCreateEc(plan.id(), "ec-" + java.util.HexFormat.of().formatHex(digest, 0, 12));
        } catch (java.security.NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-256 is unavailable", impossible);
        }
    }

    private PlanCredentials rolloverCredentials(TestPlan plan, PlanCredentials primary, int position) {
        try {
            var digest = MessageDigest.getInstance("SHA-256").digest(primary.certificate().getPublicKey().getEncoded());
            return keyStore.getOrCreate(plan.id(), "roll" + position + "-"
                    + java.util.HexFormat.of().formatHex(digest, 0, 12));
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
        if (MetadataRevocationFixtures.supports(variant)) {
            return MetadataRevocationFixtures.certificate(primary, variant, clock.instant());
        }
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
        if (variant == Variant.ECDSA_SHA256 || variant == Variant.ECDSA_SHA256_INVALID_SIGNATURE) {
            keyDescriptor(document, role, ecCredentials(plan, credentials).certificate(), "signing");
            keyDescriptor(document, role, credentials.certificate(), "encryption");
            return;
        }
        if (variant == Variant.KEYVALUE_ONLY || variant == Variant.KEYVALUE_AND_X509) {
            keyValueDescriptor(document, role, credentials.certificate().getPublicKey(), null);
            if (variant == Variant.KEYVALUE_AND_X509) {
                var keyInfo = (Element) role.getLastChild().getFirstChild();
                var x509 = element(document, DS, "ds:X509Data");
                var certificate = element(document, DS, "ds:X509Certificate");
                try {
                    certificate.setTextContent(Base64.getEncoder().encodeToString(credentials.certificate().getEncoded()));
                } catch (java.security.cert.CertificateEncodingException invalid) {
                    throw new IllegalStateException("Could not encode mixed KeyInfo certificate", invalid);
                }
                x509.appendChild(certificate); keyInfo.appendChild(x509);
            }
            return;
        }
        var signingUse = variant == Variant.KEY_USE_OMITTED
                || variant == Variant.MULTIPLE_OMITTED_KEYS_FIRST
                || variant == Variant.MULTIPLE_OMITTED_KEYS_SECOND ? null : "signing";
        keyDescriptor(document, role, credentials.certificate(), signingUse);
        keyDescriptor(document, role, credentials.certificate(), "encryption");
        if (variant == Variant.MULTIPLE_ENCRYPTION_KEYS) {
            keyDescriptor(document, role, rolloverCredentials(plan, credentials, 2).certificate(), "encryption");
        }
        if (variant == Variant.MULTIPLE_SIGNING_KEYS || variant == Variant.MULTIPLE_SIGNING_KEYS_UNADVERTISED
                || variant == Variant.THREE_SIGNING_KEYS
                || variant == Variant.THREE_SIGNING_KEYS_FIRST || variant == Variant.THREE_SIGNING_KEYS_SECOND
                || variant == Variant.MULTIPLE_SIGNING_KEYS_FIRST
                || variant == Variant.MULTIPLE_OMITTED_KEYS_FIRST
                || variant == Variant.MULTIPLE_OMITTED_KEYS_SECOND) {
            keyDescriptor(document, role,
                    rolloverCredentials(plan, credentials, 2).certificate(), signingUse);
        }
        if (variant == Variant.THREE_SIGNING_KEYS || variant == Variant.THREE_SIGNING_KEYS_FIRST
                || variant == Variant.THREE_SIGNING_KEYS_SECOND) {
            keyDescriptor(document, role,
                    rolloverCredentials(plan, credentials, 3).certificate(), "signing");
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
                    "not(ancestor-or-self::mdx:SPSSODescriptor or ancestor-or-self::mdx:IDPSSODescriptor)");
            case XPATH_EXCLUDE_ENDPOINTS -> xpathExclusion(
                    "not(ancestor-or-self::mdx:AssertionConsumerService or ancestor-or-self::mdx:SingleSignOnService or ancestor-or-self::mdx:SingleLogoutService)");
            case XPATH_EXCLUDE_KEY_DESCRIPTORS -> xpathExclusion(
                    "not(ancestor-or-self::mdx:KeyDescriptor)");
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
            // MD05.ap/aq: the child states a shorter effective lifetime than the parent. The
            // consumer must apply the shorter value; a consumer that adopts the parent's longer
            // value as the effective lifetime has not applied the profile.
            case NESTED_VALID_UNTIL_CHILD_SHORTER -> {
                var child = wrapEntities(document, entity, plan, 1, false, variant, runId, "_inner");
                child.setAttribute("validUntil", DateTimeFormatter.ISO_INSTANT.format(
                        clock.instant().plus(Duration.ofDays(3))));
                yield wrapEntities(document, child, plan, 1, true, variant, runId);
            }
            case NESTED_CACHE_DURATION_PARENT_SHORTER -> {
                var child = wrapEntities(document, entity, plan, 1, false, variant, runId, "_inner");
                child.setAttribute("cacheDuration", "PT12H");
                child.removeAttribute("validUntil");
                var parent = wrapEntities(document, child, plan, 1, true, variant, runId);
                parent.setAttribute("cacheDuration", "PT1H");
                parent.removeAttribute("validUntil");
                yield parent;
            }
            // MD05.ar: one level's validUntil has been reached. The consumer must treat the whole
            // document as invalid at the earlier effective validUntil.
            case NESTED_VALID_UNTIL_EXPIRED_PARENT -> {
                var child = wrapEntities(document, entity, plan, 1, false, variant, runId, "_inner");
                child.setAttribute("validUntil", DateTimeFormatter.ISO_INSTANT.format(
                        clock.instant().plus(Duration.ofDays(7))));
                var parent = wrapEntities(document, child, plan, 1, true, variant, runId);
                parent.setAttribute("validUntil", DateTimeFormatter.ISO_INSTANT.format(
                        clock.instant().minus(Duration.ofDays(1))));
                yield parent;
            }
            case NESTED_VALID_UNTIL_EXPIRED_CHILD -> {
                var child = wrapEntities(document, entity, plan, 1, false, variant, runId, "_inner");
                child.setAttribute("validUntil", DateTimeFormatter.ISO_INSTANT.format(
                        clock.instant().minus(Duration.ofDays(1))));
                var parent = wrapEntities(document, child, plan, 1, true, variant, runId);
                parent.setAttribute("validUntil", DateTimeFormatter.ISO_INSTANT.format(
                        clock.instant().plus(Duration.ofDays(7))));
                yield parent;
            }
            // MD05.c2 variant 2: the tested SP role must not be the first role descriptor, so a
            // consumer that inspects only the first role cannot resolve the peer.
            case ROLES_SP_SECOND -> reorderSpAfterIdp(entity);
            // MD05.d variant 1 places the EntityAttributes on the group root, so the tested entity
            // must be wrapped in an EntitiesDescriptor first.
            case ENTITY_ATTRIBUTES_DIRECT -> wrapEntities(document, entity, plan, 1, false, variant, runId);
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
            // MD04.c boundary fixtures: the Run's test threshold is T=20 days and delta=1 day, so a
            // near root (T-delta) must be accepted and a far root (T+delta) rejected by a product
            // whose configured validUntil upper limit is T. The Run result records T and delta.
            case VALID_UNTIL_NEAR -> root.setAttribute(
                    "validUntil", DateTimeFormatter.ISO_INSTANT.format(
                            clock.instant().plus(Duration.ofDays(19))));
            case VALID_UNTIL_FAR -> root.setAttribute(
                    "validUntil", DateTimeFormatter.ISO_INSTANT.format(
                            clock.instant().plus(Duration.ofDays(21))));
            default -> { }
        }
    }

    private void applyDefaultAcsFixture(Element role, Variant variant) {
        if (!java.util.Set.of(Variant.DEFAULT_ACS_FIRST_OMITTED, Variant.DEFAULT_ACS_ALL_FALSE,
                Variant.DEFAULT_ACS_MULTIPLE_TRUE, Variant.DEFAULT_ACS_DUPLICATE_INDEX).contains(variant)) return;
        // Only the ACS set participates: another indexed endpoint type is independent.
        var endpoints = role.getElementsByTagNameNS(MD, "AssertionConsumerService");
        for (int index = 0; index < endpoints.getLength(); index++) {
            var endpoint = (Element) endpoints.item(index);
            endpoint.setAttribute("isDefault", "false");
            if (variant == Variant.DEFAULT_ACS_FIRST_OMITTED && index > 0) endpoint.removeAttribute("isDefault");
            if (variant == Variant.DEFAULT_ACS_MULTIPLE_TRUE && index < 2) endpoint.setAttribute("isDefault", "true");
            if (variant == Variant.DEFAULT_ACS_DUPLICATE_INDEX && index < 2) endpoint.setAttribute("index", "0");
        }
    }

    private void addExtensionFixture(Document document, Element entity, Variant variant) {
        if (variant != Variant.UNKNOWN_EXTENSION
                && variant != Variant.UNKNOWN_ROLE_EXTENSION
                && variant != Variant.UNKNOWN_ENDPOINT_EXTENSION
                && variant != Variant.INVALID_SAML_EXTENSION
                && variant != Variant.MDRPI_REGISTRATION_INFO
                && variant != Variant.DISCO_HINTS_IPV6_CIDR
                && variant != Variant.DISCO_HINTS_IPV4_CIDR) return;
        if (variant == Variant.DISCO_HINTS_IPV6_CIDR || variant == Variant.DISCO_HINTS_IPV4_CIDR) {
            // MD05.ff: a published DiscoHints IPHint must survive consumption as a CIDR literal.
            var hints = element(document, UI, "mdui:DiscoHints");
            hints.setAttributeNS(XMLConstants.XMLNS_ATTRIBUTE_NS_URI, "xmlns:mdui", UI);
            var ipHint = element(document, UI, "mdui:IPHint");
            ipHint.setTextContent(variant == Variant.DISCO_HINTS_IPV6_CIDR ? "2001:db8::/32" : "192.0.2.0/24");
            hints.appendChild(ipHint);
            var container = element(document, MD, "md:Extensions");
            container.appendChild(hints);
            entity.insertBefore(container, entity.getFirstChild());
            return;
        }
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

    private void addEntityAttributesFixture(
            Document document, Element root, Variant variant, PlanCredentials credentials) {
        if (variant != Variant.ENTITY_ATTRIBUTES_DIRECT
                && variant != Variant.ENTITY_ATTRIBUTES_ASSERTION
                && variant != Variant.ENTITY_ATTRIBUTES_ASSERTION_CONDITIONS
                && variant != Variant.ENTITY_ATTRIBUTES_MULTIPLE
                && variant != Variant.ENTITY_ATTRIBUTES_ASSERTION_EXPIRED) return;
        var container = element(document, MD, "md:Extensions");
        container.setAttributeNS(XMLConstants.XMLNS_ATTRIBUTE_NS_URI, "xmlns:md", MD);
        var attributes = element(document, MDATTR, "mdattr:EntityAttributes");
        attributes.setAttributeNS(XMLConstants.XMLNS_ATTRIBUTE_NS_URI, "xmlns:mdattr", MDATTR);
        attributes.setAttributeNS(XMLConstants.XMLNS_ATTRIBUTE_NS_URI, "xmlns:saml", SAML);
        container.appendChild(attributes);
        root.insertBefore(container, root.getFirstChild());
        if (variant == Variant.ENTITY_ATTRIBUTES_ASSERTION
                || variant == Variant.ENTITY_ATTRIBUTES_ASSERTION_CONDITIONS
                || variant == Variant.ENTITY_ATTRIBUTES_ASSERTION_EXPIRED) {
            var assertion = entityAttributesAssertion(document, variant);
            attributes.appendChild(assertion);
            // The signature is created only after the Assertion is attached: the enveloped
            // reference resolves the ID through the owning document.
            signer.sign(assertion, credentials, directChild(assertion, SAML, "Subject"));
        } else {
            attributes.appendChild(entityAttribute(document, "urn:oid:1.3.6.1.4.1.5923.1.1.1.1", "member"));
            if (variant == Variant.ENTITY_ATTRIBUTES_MULTIPLE) {
                attributes.appendChild(entityAttribute(document, "urn:oid:2.5.4.3", "Example Organization"));
                attributes.appendChild(entityAttribute(document, "urn:oid:1.3.6.1.4.1.5923.1.1.1.9", "staff"));
            }
        }
    }

    private Element reorderSpAfterIdp(Element entity) {
        Element sp = null;
        Element idp = null;
        for (var child = entity.getFirstChild(); child != null; child = child.getNextSibling()) {
            if (!(child instanceof Element element)) continue;
            if (MD.equals(element.getNamespaceURI()) && "SPSSODescriptor".equals(element.getLocalName())) sp = element;
            if (MD.equals(element.getNamespaceURI()) && "IDPSSODescriptor".equals(element.getLocalName())) idp = element;
        }
        if (sp != null && idp != null) {
            entity.removeChild(sp);
            entity.insertBefore(sp, idp.getNextSibling());
        }
        return entity;
    }

    private Element directChild(Element parent, String namespace, String localName) {
        for (var child = parent.getFirstChild(); child != null; child = child.getNextSibling()) {
            if (child instanceof Element element && namespace.equals(element.getNamespaceURI())
                    && localName.equals(element.getLocalName())) return element;
        }
        return null;
    }

    private Element entityAttribute(Document document, String name, String value) {
        var attribute = element(document, SAML, "saml:Attribute");
        attribute.setAttribute("Name", name);
        attribute.setAttribute("NameFormat", "urn:oasis:names:tc:SAML:2.0:attrname-format:uri");
        var attributeValue = element(document, SAML, "saml:AttributeValue");
        attributeValue.setAttributeNS(XMLConstants.XMLNS_ATTRIBUTE_NS_URI, "xmlns:xs", "http://www.w3.org/2001/XMLSchema");
        attributeValue.setAttributeNS(XMLConstants.XMLNS_ATTRIBUTE_NS_URI, "xmlns:xsi", "http://www.w3.org/2001/XMLSchema-instance");
        attributeValue.setAttributeNS("http://www.w3.org/2001/XMLSchema-instance", "xsi:type", "xs:string");
        attributeValue.setTextContent(value);
        attribute.appendChild(attributeValue);
        return attribute;
    }

    private Element entityAttributesAssertion(Document document, Variant variant) {
        var assertion = element(document, SAML, "saml:Assertion");
        assertion.setAttribute("ID", "_" + java.util.UUID.nameUUIDFromBytes(
                variant.id().getBytes(java.nio.charset.StandardCharsets.UTF_8)));
        assertion.setAttribute("IssueInstant", DateTimeFormatter.ISO_INSTANT.format(clock.instant()));
        assertion.setAttribute("Version", "2.0");
        var issuer = element(document, SAML, "saml:Issuer");
        issuer.setTextContent("https://samlscope.com");
        assertion.appendChild(issuer);
        var subject = element(document, SAML, "saml:Subject");
        var nameId = element(document, SAML, "saml:NameID");
        nameId.setTextContent("urn:samlscope:entity-attribute-assertion");
        subject.appendChild(nameId);
        assertion.appendChild(subject);
        if (variant == Variant.ENTITY_ATTRIBUTES_ASSERTION_CONDITIONS) {
            var conditions = element(document, SAML, "saml:Conditions");
            conditions.setAttribute("NotBefore", DateTimeFormatter.ISO_INSTANT.format(clock.instant().minus(Duration.ofMinutes(5))));
            conditions.setAttribute("NotOnOrAfter", DateTimeFormatter.ISO_INSTANT.format(clock.instant().plus(Duration.ofDays(1))));
            assertion.appendChild(conditions);
        }
        if (variant == Variant.ENTITY_ATTRIBUTES_ASSERTION_EXPIRED) {
            // A valid signature over Conditions already in the past: the consumer must apply the
            // standard Conditions window and refuse the assertion.
            var conditions = element(document, SAML, "saml:Conditions");
            conditions.setAttribute("NotBefore", DateTimeFormatter.ISO_INSTANT.format(clock.instant().minus(Duration.ofDays(2))));
            conditions.setAttribute("NotOnOrAfter", DateTimeFormatter.ISO_INSTANT.format(clock.instant().minus(Duration.ofDays(1))));
            assertion.appendChild(conditions);
        }
        var statement = element(document, SAML, "saml:AttributeStatement");
        statement.appendChild(entityAttribute(document, "urn:oid:1.3.6.1.4.1.5923.1.1.1.1", "member"));
        assertion.appendChild(statement);
        return assertion;
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
        if (variant == Variant.BASELINE || variant == Variant.SIGNATURE_MODES_OPTIONAL) return base;
        if (runId == null || runId.isBlank()) throw new IllegalArgumentException("runId is required for metadata variants");
        return base + "?mdv=" + variant.id() + "&run=" + runId;
    }

    public enum Variant {
        ECDSA_SHA256("ecdsa-sha256"),
        ECDSA_SHA256_INVALID_SIGNATURE("ecdsa-sha256-invalid-signature"),
        BASELINE("baseline"),
        SIGNATURE_MODES_OPTIONAL("signature-modes-optional"),
        FOREIGN_ATTRIBUTE_ENTITY("foreign-attribute-entity"),
        FOREIGN_ATTRIBUTE_ORGANIZATION("foreign-attribute-organization"),
        FOREIGN_ATTRIBUTE_CONTACT("foreign-attribute-contact"),
        FOREIGN_ATTRIBUTE_ROLE("foreign-attribute-role"),
        FOREIGN_ATTRIBUTE_SINGLE_LOGOUT("foreign-attribute-single-logout"),
        FOREIGN_ATTRIBUTE_SINGLE_SIGN_ON("foreign-attribute-single-sign-on"),
        FOREIGN_ATTRIBUTE_MANAGE_NAMEID("foreign-attribute-manage-nameid"),
        FOREIGN_ATTRIBUTE_NAMEID_MAPPING("foreign-attribute-nameid-mapping"),
        FOREIGN_ATTRIBUTE_ASSERTION_ID("foreign-attribute-assertion-id"),
        FOREIGN_ATTRIBUTE_AUTHN_QUERY("foreign-attribute-authn-query"),
        FOREIGN_ATTRIBUTE_AUTHZ("foreign-attribute-authz"),
        FOREIGN_ATTRIBUTE_ATTRIBUTE_SERVICE("foreign-attribute-attribute-service"),
        FOREIGN_ATTRIBUTE_AFFILIATION("foreign-attribute-affiliation"),

        CONTROL("control"),
        REDIRECT_301("redirect-301"),
        REDIRECT_302("redirect-302"),
        REDIRECT_307("redirect-307"),
        ENTITY_ROOT("entity-root"),
        DEFAULT_ACS_FIRST("default-acs-first"),
        DEFAULT_ACS_SECOND("default-acs-second"),
        DEFAULT_ACS_IMPLICIT("default-acs-implicit"),
        DEFAULT_ACS_FIRST_OMITTED("default-acs-first-omitted"),
        DEFAULT_ACS_ALL_FALSE("default-acs-all-false"),
        DEFAULT_ACS_MULTIPLE_TRUE("default-acs-multiple-true"),
        DEFAULT_ACS_DUPLICATE_INDEX("default-acs-duplicate-index"),
        ENTITIES_ROOT_ONE("entities-root-one"),
        ENTITIES_ROOT_TWO("entities-root-two"),
        ENTITIES_ROOT_FIFTY("entities-root-fifty"),
        NESTED_ENTITIES("nested-entities"),
        DISTINCT_ENTITY_IDS("distinct-entity-ids"),
        DUPLICATE_ENTITY_IDS("duplicate-entity-ids"),
        CONFLICTING_DUPLICATE_ENTITY_IDS("conflicting-duplicate-entity-ids"),
        NO_VALID_UNTIL("no-valid-until"),
        EXPIRED("expired"),
        // Campaign-only live inputs preserve every existing validity fixture's bytes.
        LIVE_VALIDITY_ROOT("live-validity-root"),
        LIVE_VALIDITY_PARENT("live-validity-parent"),
        LIVE_VALIDITY_CHILD("live-validity-child"),
        ENTITY_CACHE_DURATION("entity-cache-duration"),
        ENTITIES_CACHE_DURATION("entities-cache-duration"),
        ENTITIES_VALID_UNTIL("entities-valid-until"),
        VALID_UNTIL_NEAR("valid-until-near"),
        VALID_UNTIL_FAR("valid-until-far"),
        UI_URL_LOGO_HTTP("ui-url-logo-http"), UI_URL_LOGO_HTTPS("ui-url-logo-https"),
        UI_SAFETY_LOGO_DATA("ui-safety-logo-data"),
        UI_SAFETY_INFORMATION_JAVASCRIPT("ui-safety-information-javascript"),
        UI_SAFETY_PRIVACY_JAVASCRIPT("ui-safety-privacy-javascript"),
        UI_URL_LOGO_DATA("ui-url-logo-data"), UI_URL_LOGO_JAVASCRIPT("ui-url-logo-javascript"), UI_URL_LOGO_FILE("ui-url-logo-file"),
        UI_URL_INFORMATION_HTTP("ui-url-information-http"), UI_URL_INFORMATION_HTTPS("ui-url-information-https"),
        UI_URL_INFORMATION_DATA("ui-url-information-data"), UI_URL_INFORMATION_JAVASCRIPT("ui-url-information-javascript"), UI_URL_INFORMATION_FILE("ui-url-information-file"),
        UI_URL_PRIVACY_HTTP("ui-url-privacy-http"), UI_URL_PRIVACY_HTTPS("ui-url-privacy-https"),
        UI_URL_PRIVACY_DATA("ui-url-privacy-data"), UI_URL_PRIVACY_JAVASCRIPT("ui-url-privacy-javascript"), UI_URL_PRIVACY_FILE("ui-url-privacy-file"),
        UI_CONSUMER_DISPLAY_ALL("ui-consumer-display-all"),
        UI_CONSUMER_DISPLAY_SERVICE("ui-consumer-display-service"),
        UI_CONSUMER_DISPLAY_ENTITY("ui-consumer-display-entity"),
        UI_CONSUMER_LOGO_LOCALIZED("ui-consumer-logo-localized"),
        UI_CONSUMER_LOGO_FALLBACK("ui-consumer-logo-fallback"),
        ATTRIBUTE_POLICY_ENTITY_PRESENT("attribute-policy-entity-present"),
        NAMEID_OMISSION("nameid-omission"),
        ATTRIBUTE_POLICY_ENTITY_ABSENT("attribute-policy-entity-absent"),
        ATTRIBUTE_POLICY_REQUESTED_REQUIRED("attribute-policy-requested-required"),
        ATTRIBUTE_POLICY_REQUESTED_OPTIONAL("attribute-policy-requested-optional"),
        ATTRIBUTE_POLICY_REQUESTED_ABSENT("attribute-policy-requested-absent"),
        ATTRIBUTE_POLICY_INDEXED("attribute-policy-indexed"),
        ALGORITHM_ENTITY_SHA256("algorithm-entity-sha256"),
        ALGORITHM_ENTITY_SHA384("algorithm-entity-sha384"),
        ALGORITHM_ENTITY_SHA512("algorithm-entity-sha512"),
        ALGORITHM_ENTITY_ORDER_256_384("algorithm-entity-order-256-384"),
        ALGORITHM_ENTITY_ORDER_384_256("algorithm-entity-order-384-256"),
        ALGORITHM_ENTITY_ORDER_256_512("algorithm-entity-order-256-512"),
        ALGORITHM_ENTITY_ORDER_512_256("algorithm-entity-order-512-256"),
        ALGORITHM_ENTITY_DIGEST_ORDER_256_512("algorithm-entity-digest-order-256-512"),
        ALGORITHM_ENTITY_DIGEST_ORDER_512_256("algorithm-entity-digest-order-512-256"),
        ALGORITHM_ENTITY_SIGNING_ORDER_256_512("algorithm-entity-signing-order-256-512"),
        ALGORITHM_ENTITY_SIGNING_ORDER_512_256("algorithm-entity-signing-order-512-256"),
        ALGORITHM_ROLE_ORDER_256_384("algorithm-role-order-256-384"),
        ALGORITHM_ROLE_ORDER_384_256("algorithm-role-order-384-256"),
        ALGORITHM_ROLE_ORDER_256_512("algorithm-role-order-256-512"),
        ALGORITHM_ROLE_ORDER_512_256("algorithm-role-order-512-256"),
        ALGORITHM_ROLE_SIGNING_384("algorithm-role-signing-384"),
        ALGORITHM_ROLE_DIGEST_384("algorithm-role-digest-384"),
        ALGORITHM_ROLE_BOTH_384("algorithm-role-both-384"),
        ALGORITHM_ROLE_BOTH_256("algorithm-role-both-256"),
        ALGORITHM_UNSUPPORTED_FIRST("algorithm-unsupported-first"),
        ALGORITHM_ABSENT("algorithm-absent"),
        ALGORITHM_ENCRYPTION_AES128_CBC("algorithm-encryption-aes128-cbc"),
        ALGORITHM_ENCRYPTION_AES256_CBC("algorithm-encryption-aes256-cbc"),
        ALGORITHM_ENCRYPTION_AES128_GCM("algorithm-encryption-aes128-gcm"),
        ALGORITHM_ENCRYPTION_AES256_GCM("algorithm-encryption-aes256-gcm"),
        ALGORITHM_ENCRYPTION_ORDER_128_256("algorithm-encryption-order-128-256"),
        ALGORITHM_ENCRYPTION_ORDER_256_128("algorithm-encryption-order-256-128"),
        ALGORITHM_ENCRYPTION_MULTIPLE("algorithm-encryption-multiple"),
        ALGORITHM_ENCRYPTION_KEYSIZE_128("algorithm-encryption-keysize-128"),
        ALGORITHM_ENCRYPTION_KEYSIZE_256("algorithm-encryption-keysize-256"),
        ALGORITHM_OAEP_10_SHA1("algorithm-oaep-10-sha1"),
        ALGORITHM_OAEP_10_SHA256("algorithm-oaep-10-sha256"),
        ALGORITHM_OAEP_11_SHA1("algorithm-oaep-11-sha1"),
        ALGORITHM_OAEP_11_SHA256("algorithm-oaep-11-sha256"),
        ALGORITHM_OAEP_11_DEFAULT_MGF("algorithm-oaep-11-default-mgf"),
        ALGORITHM_SIGNING_256_KEYSIZE_EXCLUDED("algorithm-signing-256-keysize-excluded"),
        ALGORITHM_SIGNING_384_KEYSIZE_EXCLUDED("algorithm-signing-384-keysize-excluded"),
        ALGORITHM_SIGNING_256_512_KEYSIZE_EXCLUDED("algorithm-signing-256-512-keysize-excluded"),
        ALGORITHM_SIGNING_512_256_KEYSIZE_EXCLUDED("algorithm-signing-512-256-keysize-excluded"),
        UNKNOWN_EXTENSION("unknown-extension"),
        UNKNOWN_ROLE_EXTENSION("unknown-role-extension"),
        UNKNOWN_ORGANIZATION_EXTENSION("unknown-organization-extension"),
        UNKNOWN_CONTACT_EXTENSION("unknown-contact-extension"),
        UNKNOWN_AFFILIATION_EXTENSION("unknown-affiliation-extension"),
        UNKNOWN_ENDPOINT_EXTENSION("unknown-endpoint-extension"),
        INVALID_SAML_EXTENSION("invalid-saml-extension"),
        INVALID_ORGANIZATION_SAML_EXTENSION("invalid-organization-saml-extension"),
        MDRPI_REGISTRATION_INFO("mdrpi-registration-info"),
        DISCO_HINTS_IPV6_CIDR("disco-hints-ipv6-cidr"),
        DISCO_HINTS_IPV4_CIDR("disco-hints-ipv4-cidr"),
        ROLES_SP_SECOND("roles-sp-second"),
        FULL_UI_INFO("full-ui-info"),
        SCHEMA_GLOBAL_ELEMENT_FAMILIES("schema-global-element-families"),
        SCHEMA_AFFILIATION_ONLY("schema-affiliation-only"),
        SCHEMA_ADDITIONAL_METADATA_LOCATION("schema-additional-metadata-location"),
        SCHEMA_LOCALIZED_NAME_BOUNDARY("schema-localized-name-boundary"),
        SCHEMA_ATTRIBUTE_CONSUMING_SERVICE("schema-attribute-consuming-service"),
        SCHEMA_SSO_ENDPOINT_SET("schema-sso-endpoint-set"),
        SCHEMA_SSO_ENDPOINT_WITHOUT_FOREIGN("schema-sso-endpoint-without-foreign"),
        SCHEMA_INVALID_ENDPOINT_LOCATION("schema-invalid-endpoint-location"),
        NESTED_VALID_UNTIL_CHILD_SHORTER("nested-valid-until-child-shorter"),
        NESTED_CACHE_DURATION_PARENT_SHORTER("nested-cache-duration-parent-shorter"),
        NESTED_VALID_UNTIL_EXPIRED_PARENT("nested-valid-until-expired-parent"),
        NESTED_VALID_UNTIL_EXPIRED_CHILD("nested-valid-until-expired-child"),
        ENTITY_ATTRIBUTES_DIRECT("entity-attributes-direct"),
        ENTITY_ATTRIBUTES_ASSERTION("entity-attributes-assertion"),
        ENTITY_ATTRIBUTES_ASSERTION_CONDITIONS("entity-attributes-assertion-conditions"),
        ENTITY_ATTRIBUTES_MULTIPLE("entity-attributes-multiple"),
        ENTITY_ATTRIBUTES_ASSERTION_EXPIRED("entity-attributes-assertion-expired"),
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
        KEYVALUE_AND_X509("keyvalue-and-x509"),
        MULTIPLE_ENCRYPTION_KEYS("multiple-encryption-keys"),
        MULTIPLE_SIGNING_KEYS_FIRST("multiple-signing-keys-first"),
        MULTIPLE_SIGNING_KEYS("multiple-signing-keys"),
        MULTIPLE_SIGNING_KEYS_UNADVERTISED("multiple-signing-keys-unadvertised"),
        CERT_RUNTIME_SAME_KEY("certificate-runtime-same-key"),
        CERT_RUNTIME_OTHER_KEY("certificate-runtime-other-key"),
        MULTIPLE_OMITTED_KEYS_FIRST("multiple-omitted-keys-first"),
        MULTIPLE_OMITTED_KEYS_SECOND("multiple-omitted-keys-second"),
        THREE_SIGNING_KEYS_FIRST("three-signing-keys-first"),
        THREE_SIGNING_KEYS_SECOND("three-signing-keys-second"),
        THREE_SIGNING_KEYS("three-signing-keys"),
        ROLE_KEYS_SP_FIRST_EXPLICIT_A("role-keys-sp-first-explicit-a"),
        ROLE_KEYS_IDP_FIRST_EXPLICIT_B("role-keys-idp-first-explicit-b"),
        ROLE_KEYS_SP_FIRST_OMITTED_A("role-keys-sp-first-omitted-a"),
        ROLE_KEYS_IDP_FIRST_OMITTED_B("role-keys-idp-first-omitted-b"),
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
        CERT_UNKNOWN_CA("certificate-unknown-ca"),
        CERT_REVOKED("certificate-revoked"),
        CERT_REVOCATION_UNREACHABLE("certificate-revocation-unreachable");

        private final String id;
        Variant(String id) { this.id = id; }
        public String id() { return id; }

        public boolean roleKeyProbe() {
            return this == ROLE_KEYS_SP_FIRST_EXPLICIT_A || this == ROLE_KEYS_IDP_FIRST_EXPLICIT_B
                    || this == ROLE_KEYS_SP_FIRST_OMITTED_A || this == ROLE_KEYS_IDP_FIRST_OMITTED_B;
        }

        public boolean defaultAcsProbe() {
            return this == DEFAULT_ACS_FIRST || this == DEFAULT_ACS_SECOND || this == DEFAULT_ACS_IMPLICIT
                    || this == DEFAULT_ACS_FIRST_OMITTED || this == DEFAULT_ACS_ALL_FALSE
                    || this == DEFAULT_ACS_MULTIPLE_TRUE || this == DEFAULT_ACS_DUPLICATE_INDEX;
        }

        public com.samlscope.saml.normal.SamlSignedRequestFactory.Fixture requestFixture() {
            if (this == NAMEID_OMISSION) return com.samlscope.saml.normal.SamlSignedRequestFactory.Fixture.VALID_NO_NAMEID_POLICY;
            if (defaultAcsProbe()) return com.samlscope.saml.normal.SamlSignedRequestFactory.Fixture.DEFAULT_ACS;
            return this == ECDSA_SHA256_INVALID_SIGNATURE
                    ? com.samlscope.saml.normal.SamlSignedRequestFactory.Fixture.BAD_SIGNATURE_VALUE
                    : com.samlscope.saml.normal.SamlSignedRequestFactory.Fixture.VALID;
        }

        boolean certificateVariant() {
            return switch (this) {
                case CERT_EXPIRED, CERT_NOT_YET_VALID, CERT_NO_DIGITAL_SIGNATURE,
                        CERT_CRITICAL_EXTENSION, CERT_NONCRITICAL_EXTENSION,
                        CERT_UNRELATED_EKU, CERT_SHA1, CERT_SHA512, CERT_EMPTY_SUBJECT,
                        CERT_LONG_VALIDITY, CERT_UNKNOWN_CA, CERT_REVOKED, CERT_REVOCATION_UNREACHABLE -> true;
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
