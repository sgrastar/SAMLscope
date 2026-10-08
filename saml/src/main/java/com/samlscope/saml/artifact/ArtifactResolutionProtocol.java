package com.samlscope.saml.artifact;

import java.net.URI;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.*;
import javax.xml.XMLConstants;
import org.w3c.dom.Element;
import com.samlscope.saml.crypto.*;
import com.samlscope.saml.normal.SecureXml;

/**
 * OASIS SAML Core §3.5 / Profiles §5 / Bindings §3.2, scoped to an AuthnRequest Response.
 * This reader produces evidence, not a Verdict. Missing proof is rejected without labelling
 * unsigned or otherwise unsupported products nonconforming.
 */
public final class ArtifactResolutionProtocol {
    public static final String P = SamlArtifact.P;
    public static final String A = "urn:oasis:names:tc:SAML:2.0:assertion";
    public static final String SOAP = "http://schemas.xmlsoap.org/soap/envelope/";
    public static final String SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success";
    public static final String DS = "http://www.w3.org/2000/09/xmldsig#";

    public byte[] resolve(SamlArtifact artifact, String requestId, URI endpoint,
            String suiteEntityId, Instant issueInstant, PlanCredentials signer) {
        SamlArtifact.require(artifact != null && signer != null && requestId != null
                && requestId.matches("_[A-Za-z0-9_.-]+") && suiteEntityId != null && !suiteEntityId.isBlank(),
                "ArtifactResolve inputs unavailable");
        Objects.requireNonNull(endpoint); Objects.requireNonNull(issueInstant);
        var d = SecureXml.newDocument();
        var envelope = d.createElementNS(SOAP, "soap:Envelope");
        envelope.setAttributeNS(XMLConstants.XMLNS_ATTRIBUTE_NS_URI, "xmlns:soap", SOAP); d.appendChild(envelope);
        var body = d.createElementNS(SOAP, "soap:Body"); envelope.appendChild(body);
        var request = d.createElementNS(P, "samlp:ArtifactResolve");
        request.setAttributeNS(XMLConstants.XMLNS_ATTRIBUTE_NS_URI, "xmlns:samlp", P);
        request.setAttributeNS(XMLConstants.XMLNS_ATTRIBUTE_NS_URI, "xmlns:saml", A);
        request.setAttribute("ID", requestId); request.setAttribute("Version", "2.0");
        request.setAttribute("IssueInstant", issueInstant.toString());
        request.setAttribute("Destination", endpoint.toString()); body.appendChild(request);
        var issuer = d.createElementNS(A, "saml:Issuer"); issuer.setTextContent(suiteEntityId); request.appendChild(issuer);
        var value = d.createElementNS(P, "samlp:Artifact"); value.setTextContent(artifact.base64()); request.appendChild(value);
        new XmlSigner().sign(request, signer, value);
        return SecureXml.serialize(d);
    }

    /** Direct Body child only; duplicate bodies, faults, nested/wrapped protocol nodes are refused. */
    public Element soapMessage(byte[] bytes, String name) {
        var root = SecureXml.parse(bytes).getDocumentElement();
        SamlArtifact.require(SOAP.equals(root.getNamespaceURI()) && "Envelope".equals(root.getLocalName()), "Not SOAP 1.1");
        var body = single(root, SOAP, "Body");
        var direct = elements(body);
        SamlArtifact.require(direct.size() == 1 && P.equals(direct.getFirst().getNamespaceURI())
                && name.equals(direct.getFirst().getLocalName()), "Ambiguous SOAP protocol message");
        for (var child : elements(root)) SamlArtifact.require(SOAP.equals(child.getNamespaceURI())
                && Set.of("Header", "Body").contains(child.getLocalName()), "Unexpected SOAP envelope element");
        SamlArtifact.require(SamlArtifact.children(root, SOAP, "Header").size() <= 1, "Duplicate SOAP header");
        uniqueIds(root);
        return direct.getFirst();
    }

    public void verifyResolve(byte[] bytes, SamlArtifact expectedArtifact, String resolveId,
            URI endpoint, String suiteEntityId, X509Certificate suiteCertificate) {
        var root = soapMessage(bytes, "ArtifactResolve");
        SamlArtifact.require(resolveId.equals(root.getAttribute("ID")) && "2.0".equals(root.getAttribute("Version"))
                && endpoint.toString().equals(root.getAttribute("Destination"))
                && suiteEntityId.equals(single(root, A, "Issuer").getTextContent())
                && expectedArtifact.base64().equals(single(root, P, "Artifact").getTextContent())
                && SamlArtifact.children(root, P, "Extensions").isEmpty()
                && SamlArtifact.children(root, DS, "Signature").size() == 1
                && new XmlSignatureVerifier().hasValidEnvelopedSignature(root, suiteCertificate), "Unbound ArtifactResolve");
        Instant.parse(root.getAttribute("IssueInstant"));
        for (var e : elements(root)) SamlArtifact.require((A.equals(e.getNamespaceURI()) && "Issuer".equals(e.getLocalName()))
                || (DS.equals(e.getNamespaceURI()) && "Signature".equals(e.getLocalName()))
                || (P.equals(e.getNamespaceURI()) && "Artifact".equals(e.getLocalName())), "Unexpected ArtifactResolve field");
    }

    public ResolvedResponse verifyResponse(byte[] originalSoap, String resolveId, String authnRequestId,
            String targetEntityId, URI artifactAcs, List<X509Certificate> targetCertificates) {
        return verifyResponse(originalSoap,resolveId,authnRequestId,targetEntityId,artifactAcs,targetCertificates,null);
    }
    public ResolvedResponse verifyResponse(byte[] originalSoap, String resolveId, String authnRequestId,
            String targetEntityId, URI artifactAcs, List<X509Certificate> targetCertificates,
            ArtifactTlsEvidence verifiedTls) {
        var outer = soapMessage(originalSoap, "ArtifactResponse");
        checkResponse(outer, resolveId, targetEntityId);
        SamlArtifact.require(SUCCESS.equals(status(outer)), "Artifact resolution unsuccessful");
        var certificates = List.copyOf(targetCertificates);
        boolean signedOuter = certificates.stream().anyMatch(cert ->
                new XmlSignatureVerifier().hasValidEnvelopedSignature(outer, cert));
        SamlArtifact.require(signedOuter || (verifiedTls != null && verifiedTls.coversResponse(originalSoap)),
                "Artifact response origin or integrity unproven");
        var inner = single(outer, P, "Response");
        for (var e : elements(outer)) SamlArtifact.require((A.equals(e.getNamespaceURI()) && "Issuer".equals(e.getLocalName()))
                || (DS.equals(e.getNamespaceURI()) && "Signature".equals(e.getLocalName()))
                || (P.equals(e.getNamespaceURI()) && Set.of("Status", "Response", "Extensions").contains(e.getLocalName())),
                "Unexpected ArtifactResponse payload");
        SamlArtifact.require(SamlArtifact.children(outer, P, "Extensions").size() <= 1, "Duplicate ArtifactResponse extensions");
        checkResponse(inner, authnRequestId, targetEntityId);
        SamlArtifact.require(artifactAcs.toString().equals(inner.getAttribute("Destination")), "Unbound resolved destination");
        // The outer signature or authenticated protected binding covers the entire wrapped
        // message. An additional inner signature is optional but, if present, must be valid.
        if (!SamlArtifact.children(inner, DS, "Signature").isEmpty()) SamlArtifact.require(certificates.stream()
                .anyMatch(cert -> new XmlSignatureVerifier().hasValidEnvelopedSignature(inner, cert)), "Invalid inner signature");
        String top = status(inner);
        SamlArtifact.require(Set.of(SUCCESS, "urn:oasis:names:tc:SAML:2.0:status:Requester",
                "urn:oasis:names:tc:SAML:2.0:status:Responder", "urn:oasis:names:tc:SAML:2.0:status:VersionMismatch")
                .contains(top), "Unknown resolved status");
        var extracted = SecureXml.newDocument();
        var derived = (Element)extracted.importNode(inner, true);
        extracted.appendChild(derived);
        // Signature verification above uses the original SOAP DOM. This standalone analysis
        // document retains inherited QName/xml context, but is never represented as raw evidence.
        for (var node=inner;node!=null;node=node.getParentNode() instanceof Element e?e:null) {
            var attributes=node.getAttributes();
            for(int i=0;i<attributes.getLength();i++) {
                var attribute=attributes.item(i);var ns=attribute.getNamespaceURI();var local=attribute.getLocalName();
                if(XMLConstants.XMLNS_ATTRIBUTE_NS_URI.equals(ns)
                        || (XMLConstants.XML_NS_URI.equals(ns) && Set.of("lang","space").contains(local))) {
                    if(!derived.hasAttributeNS(ns,local))derived.setAttributeNS(ns,attribute.getNodeName(),attribute.getNodeValue());
                }
            }
        }
        if(inner.getBaseURI()!=null)derived.setAttributeNS(XMLConstants.XML_NS_URI,"xml:base",inner.getBaseURI());
        return new ResolvedResponse(SecureXml.serialize(extracted), top, outer.getAttribute("ID"),
                inner.getAttribute("ID"), signedOuter ? "trusted-xml-signature" : "closed-pkix-hostname-tls",
                SamlArtifact.hash("SHA-256", originalSoap));
    }

    private static void checkResponse(Element root, String inResponseTo, String entityId) {
        SamlArtifact.require("2.0".equals(root.getAttribute("Version")) && !root.getAttribute("ID").isBlank()
                && inResponseTo.equals(root.getAttribute("InResponseTo"))
                && entityId.equals(single(root, A, "Issuer").getTextContent()), "Unbound artifact response");
        Instant.parse(root.getAttribute("IssueInstant"));
        var issuer = single(root, A, "Issuer");
        SamlArtifact.require(!issuer.hasAttribute("Format") || "urn:oasis:names:tc:SAML:2.0:nameid-format:entity"
                .equals(issuer.getAttribute("Format")), "Non-entity artifact issuer");
        SamlArtifact.require(SamlArtifact.children(root, DS, "Signature").size() <= 1, "Duplicate response signature");
    }
    private static String status(Element root) { return single(single(root, P, "Status"), P, "StatusCode").getAttribute("Value"); }
    private static Element single(Element root, String ns, String name) {
        var values = SamlArtifact.children(root, ns, name); SamlArtifact.require(values.size() == 1, "Missing or duplicate " + name); return values.getFirst();
    }
    private static List<Element> elements(Element root) {
        var values = new ArrayList<Element>(); for (var n = root.getFirstChild(); n != null; n = n.getNextSibling()) if (n instanceof Element e) values.add(e); return values;
    }
    private static void uniqueIds(Element root) {
        var ids = new HashSet<String>(); checkIds(root, ids);
    }
    private static void checkIds(Element root, Set<String> ids) {
        if (root.hasAttribute("ID")) SamlArtifact.require(!root.getAttribute("ID").isBlank() && ids.add(root.getAttribute("ID")), "Duplicate XML ID");
        for (var e : elements(root)) checkIds(e, ids);
    }
    /** responseXml is derived analysis XML; originalSoapSha256 identifies the verified raw SOAP. */
    public record ResolvedResponse(byte[] responseXml, String status, String artifactResponseId,
            String responseId, String authentication, String originalSoapSha256) {
        public ResolvedResponse { responseXml = responseXml.clone(); }
        @Override public byte[] responseXml() { return responseXml.clone(); }
    }
}
