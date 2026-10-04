package com.samlscope.saml.ecp;

import com.samlscope.core.caseexec.ActionIds;
import com.samlscope.core.plan.TargetKind;
import com.samlscope.core.plan.TestPlan;
import com.samlscope.core.profile.FunctionalProfile;
import com.samlscope.saml.crypto.PlanCredentials;
import com.samlscope.saml.crypto.XmlSignatureVerifier;
import com.samlscope.saml.crypto.XmlSigner;
import com.samlscope.saml.metadata.MetadataService;
import com.samlscope.saml.normal.SecureXml;
import java.net.URI;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.function.Function;
import javax.xml.XMLConstants;
import org.w3c.dom.Element;

/** Non-evaluative, deterministic requests for the two explicitly selected metadata epochs. */
public final class MetadataApplicationEcpProbeFactory {
    public static final String PHASE = "send-baseline";
    public static final String R_FIRST = "fixture-ecp-metadata-rollover-first-paos";
    public static final String R_SECOND = "fixture-ecp-metadata-rollover-second-paos";
    public static final String R_UNADVERTISED = "fixture-ecp-metadata-rollover-unadvertised-paos";
    public static final String B_NORMAL = "fixture-ecp-metadata-b-paos";
    public static final String B_INVALID = "fixture-ecp-metadata-b-invalid-signature-paos";
    public static final String B_OLD = "fixture-ecp-metadata-b-old-key-paos";
    public static final List<String> FIXTURES = List.of(R_FIRST, R_SECOND, R_UNADVERTISED,
            B_NORMAL, B_INVALID, B_OLD);
    private static final String P = "urn:oasis:names:tc:SAML:2.0:protocol";
    private static final String A = "urn:oasis:names:tc:SAML:2.0:assertion";

    public record Prepared(String fixtureId, String actionId, String requestId, String metadataVariant,
            String signingVariant, URI consumer, byte[] envelope) {
        public Prepared { envelope = envelope.clone(); }
        @Override public byte[] envelope() { return envelope.clone(); }
    }

    public List<Prepared> prepare(TestPlan plan, String runId, MetadataService.Variant advertisedVariant,
            byte[] advertisedMetadata, URI destination, Instant issueInstant,
            Function<MetadataService.Variant, PlanCredentials> credentials) {
        require(plan.profile() == FunctionalProfile.METADATA_IDP && plan.target().kind() == TargetKind.IDP,
                "Metadata ECP fixtures require a metadata — IdP Plan");
        require(runId != null && runId.matches("run_[0-9A-HJKMNP-TV-Z]{26}"), "Invalid Run");
        require(destination != null && List.of("http", "https").contains(destination.getScheme())
                && destination.getHost() != null && destination.getUserInfo() == null
                && destination.getFragment() == null, "Invalid native SOAP endpoint");
        require(issueInstant != null, "Metadata selection time is required");
        var specs = specs(advertisedVariant);
        Element root = SecureXml.parse(advertisedMetadata).getDocumentElement();
        require(MetadataService.MD.equals(root.getNamespaceURI()) && "EntityDescriptor".equals(root.getLocalName()),
                "One original metadata entity is required");
        String entity = root.getAttribute("entityID");
        require(!entity.isBlank(), "Missing entityID");
        var roles = children(root, MetadataService.MD, "SPSSODescriptor");
        require(roles.size() == 1 && List.of(roles.getFirst().getAttribute("protocolSupportEnumeration").split("\\s+"))
                .contains(P), "SAML 2 SP role is required");
        var endpoints = children(roles.getFirst(), MetadataService.MD, "AssertionConsumerService").stream()
                .filter(e -> MetadataService.PAOS.equals(e.getAttribute("Binding"))).toList();
        require(endpoints.size() == 1, "Exactly one advertised PAOS ACS is required");
        URI consumer = URI.create(endpoints.getFirst().getAttribute("Location"));
        require(List.of("http", "https").contains(consumer.getScheme()) && consumer.getHost() != null
                && consumer.getUserInfo() == null && consumer.getFragment() == null,
                "Invalid advertised PAOS ACS");
        URI entityUri = URI.create(entity);
        require(entityUri.getPath().endsWith("/p/" + plan.id()) && entityUri.getRawQuery() == null
                && entityUri.getUserInfo() == null && entityUri.getFragment() == null
                && consumer.equals(URI.create(entity + "/sp/paos?mdv=" + advertisedVariant.id() + "&run=" + runId)),
                "The advertised ACS must belong to this Plan, Run and metadata epoch");
        var result = new ArrayList<Prepared>();
        // Every request is prepared and checked before the caller persists or sends the first one.
        for (var spec : specs) {
            var signer = credentials.apply(spec.signer());
            require(signer != null, "Signing key unavailable");
            boolean advertised = signingKeys(roles.getFirst()).stream()
                    .anyMatch(bytes -> java.util.Arrays.equals(bytes, signer.certificate().getPublicKey().getEncoded()));
            require(advertised == spec.advertisedSigner(), "Signing key does not match the intended control");
            String action = ActionIds.derive(runId, spec.id(), PHASE, 0);
            String id = "_" + action;
            var document = SecureXml.newDocument();
            var request = document.createElementNS(P, "samlp:AuthnRequest");
            request.setAttributeNS(XMLConstants.XMLNS_ATTRIBUTE_NS_URI, "xmlns:samlp", P);
            request.setAttributeNS(XMLConstants.XMLNS_ATTRIBUTE_NS_URI, "xmlns:saml", A);
            request.setAttribute("ID", id); request.setAttribute("Version", "2.0");
            request.setAttribute("IssueInstant", issueInstant.toString());
            request.setAttribute("Destination", destination.toString());
            request.setAttribute("AssertionConsumerServiceURL", consumer.toString());
            request.setAttribute("ProtocolBinding", MetadataService.PAOS);
            var issuer = document.createElementNS(A, "saml:Issuer");
            issuer.setTextContent(entity); request.appendChild(issuer); document.appendChild(request);
            new XmlSigner().sign(request, signer, null);
            if (spec.invalidSignature()) {
                var values = request.getElementsByTagNameNS(MetadataService.DS, "SignatureValue");
                require(values.getLength() == 1, "Missing signature value");
                String value = values.item(0).getTextContent().strip();
                values.item(0).setTextContent((value.startsWith("A") ? "B" : "A") + value.substring(1));
            }
            byte[] xml = SecureXml.serialize(document);
            require(new XmlSignatureVerifier().hasValidEnvelopedSignature(
                    SecureXml.parse(xml).getDocumentElement(), signer.certificate()) != spec.invalidSignature(),
                    "The signature control could not be constructed");
            result.add(new Prepared(spec.id(), action, id, advertisedVariant.id(), spec.signer().id(),
                    consumer, new EcpProbeEnvelopeFactory().baseline(xml)));
        }
        return List.copyOf(result);
    }

    private record Spec(String id, MetadataService.Variant signer, boolean advertisedSigner,
            boolean invalidSignature) {}
    private static List<Spec> specs(MetadataService.Variant variant) {
        if (variant == MetadataService.Variant.MULTIPLE_SIGNING_KEYS_FIRST) return List.of(
                new Spec(R_FIRST, MetadataService.Variant.MULTIPLE_SIGNING_KEYS_FIRST, true, false),
                new Spec(R_SECOND, MetadataService.Variant.MULTIPLE_SIGNING_KEYS, true, false),
                new Spec(R_UNADVERTISED, MetadataService.Variant.MULTIPLE_SIGNING_KEYS_UNADVERTISED, false, false));
        if (variant == MetadataService.Variant.NO_VALID_UNTIL) return List.of(
                new Spec(B_NORMAL, MetadataService.Variant.NO_VALID_UNTIL, true, false),
                new Spec(B_INVALID, MetadataService.Variant.NO_VALID_UNTIL, true, true),
                new Spec(B_OLD, MetadataService.Variant.CONTROL, false, false));
        throw new IllegalArgumentException("Select the explicit rollover or B metadata epoch before ECP probing");
    }
    private static List<byte[]> signingKeys(Element role) {
        var keys = new ArrayList<byte[]>();
        try {
            var factory = java.security.cert.CertificateFactory.getInstance("X.509");
            for (var descriptor : children(role, MetadataService.MD, "KeyDescriptor")) {
                if (descriptor.hasAttribute("use") && !"signing".equals(descriptor.getAttribute("use"))) continue;
                var certificates = descriptor.getElementsByTagNameNS(MetadataService.DS, "X509Certificate");
                require(certificates.getLength() == 1, "Exactly one signing certificate per key is required");
                var certificate = factory.generateCertificate(new java.io.ByteArrayInputStream(
                        Base64.getMimeDecoder().decode(certificates.item(0).getTextContent())));
                keys.add(certificate.getPublicKey().getEncoded());
            }
            return List.copyOf(keys);
        } catch (java.security.cert.CertificateException invalid) {
            throw new IllegalArgumentException("Invalid advertised signing certificate", invalid);
        }
    }
    private static List<Element> children(Element parent, String namespace, String name) {
        var result = new ArrayList<Element>();
        for (var node = parent.getFirstChild(); node != null; node = node.getNextSibling())
            if (node instanceof Element e && namespace.equals(e.getNamespaceURI()) && name.equals(e.getLocalName()))
                result.add(e);
        return List.copyOf(result);
    }
    private static void require(boolean condition, String message) {
        if (!condition) throw new IllegalArgumentException(message);
    }
}
