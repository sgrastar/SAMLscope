package com.samlscope.saml.normal;

import java.net.URI;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import javax.xml.XMLConstants;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/** Builds deterministic AuthnRequest fixtures for the approved IdP error probes and their control. */
public final class SamlErrorProbeRequestFactory {
    private static final String PROTOCOL = "urn:oasis:names:tc:SAML:2.0:protocol";
    private static final String ASSERTION = "urn:oasis:names:tc:SAML:2.0:assertion";

    public enum Probe {
        PASSIVE_WITHOUT_SESSION,
        PASSIVE_WITH_SESSION,
        FORCE_AUTHN_PASSIVE,
        FORCE_AUTHN_FALSE,
        FORCE_AUTHN_TRUE,
        SUBMILLISECOND_ISSUE_INSTANT,
        VERSION_1_1,
        VERSION_3_0,
        BASELINE_SUCCESS,
        UNKNOWN_NAMEID_FORMAT,
        UNKNOWN_EXTENSION,
        UNKNOWN_ANY_ATTRIBUTE,
        STRING_BOUNDARY_255,
        STRING_BOUNDARY_256,
        STRING_ASCII_255,
        STRING_ASCII_256,
        STRING_CJK_255,
        STRING_CJK_256,
        STRING_COMBINING_255,
        STRING_COMBINING_256,
        STRING_XML_SPECIAL_255,
        STRING_XML_SPECIAL_256,
        STRING_TAB_REFERENCE_255,
        STRING_TAB_REFERENCE_256,
        STRING_LF_REFERENCE_255,
        STRING_LF_REFERENCE_256,
        STRING_SUPPLEMENTARY_255,
        STRING_SUPPLEMENTARY_256,
        STRING_TAB_LITERAL_255, STRING_TAB_LITERAL_256, STRING_LF_LITERAL_255, STRING_LF_LITERAL_256,

        DTD_AUTHN_REQUEST,
        DTD_EXTERNAL_ENTITY_AUTHN_REQUEST,
        ACS_SELECTION_OMITTED,
        ISSUER_TRAILING_WHITESPACE,
        PERSISTENT_NAMEID_POLICY,
        UNRECOGNIZED_SUBJECT,
        UNSATISFIABLE_AUTHN_CONTEXT
    }

    public byte[] build(
            Probe probe, String requestId, URI destination, String issuer, URI acs, Instant issueInstant) {
        if (probe == null) throw new IllegalArgumentException("probe is required");
        requireText(requestId, "requestId");
        requireText(issuer, "issuer");
        java.util.Objects.requireNonNull(destination, "destination");
        java.util.Objects.requireNonNull(acs, "acs");
        java.util.Objects.requireNonNull(issueInstant, "issueInstant");
        var document = SecureXml.newDocument();
        var request = element(document, PROTOCOL, "samlp:AuthnRequest");
        request.setAttributeNS(XMLConstants.XMLNS_ATTRIBUTE_NS_URI, "xmlns:samlp", PROTOCOL);
        request.setAttributeNS(XMLConstants.XMLNS_ATTRIBUTE_NS_URI, "xmlns:saml", ASSERTION);
        request.setAttribute("ID", requestId);
        request.setAttribute("Version", switch (probe) {
            case VERSION_1_1 -> "1.1";
            case VERSION_3_0 -> "3.0";
            default -> "2.0";
        });
        request.setAttribute("IssueInstant", DateTimeFormatter.ISO_INSTANT.format(
                probe == Probe.SUBMILLISECOND_ISSUE_INSTANT
                        ? issueInstant.plusNanos(123_456) : issueInstant));
        request.setAttribute("Destination", destination.toString());
        if (probe != Probe.ACS_SELECTION_OMITTED) {
            request.setAttribute("AssertionConsumerServiceURL", acs.toString());
            request.setAttribute("ProtocolBinding", "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST");
        }
        if (stringProbes().contains(probe)) {
            request.setAttribute("ProviderName", stringValue(probe));
        }
        if (probe == Probe.PASSIVE_WITHOUT_SESSION || probe == Probe.PASSIVE_WITH_SESSION
                || probe == Probe.FORCE_AUTHN_PASSIVE) request.setAttribute("IsPassive", "true");
        if (probe == Probe.FORCE_AUTHN_PASSIVE) request.setAttribute("ForceAuthn", "true");
        if (probe == Probe.FORCE_AUTHN_FALSE) request.setAttribute("ForceAuthn", "false");
        if (probe == Probe.FORCE_AUTHN_TRUE) request.setAttribute("ForceAuthn", "true");
        document.appendChild(request);
        var issuerElement = element(document, ASSERTION, "saml:Issuer");
        issuerElement.setTextContent(probe == Probe.ISSUER_TRAILING_WHITESPACE ? issuer + " " : issuer);
        request.appendChild(issuerElement);
        switch (probe) {
            case UNKNOWN_NAMEID_FORMAT -> {
                var policy = element(document, PROTOCOL, "samlp:NameIDPolicy");
                policy.setAttribute("Format", unknownNameIdFormat(requestId));
                policy.setAttribute("AllowCreate", "true");
                request.appendChild(policy);
            }
            case UNSATISFIABLE_AUTHN_CONTEXT -> {
                var requested = element(document, PROTOCOL, "samlp:RequestedAuthnContext");
                requested.setAttribute("Comparison", "exact");
                var classRef = element(document, ASSERTION, "saml:AuthnContextClassRef");
                classRef.setTextContent(unavailableAuthnContext(requestId));
                requested.appendChild(classRef);
                request.appendChild(requested);
            }
            case UNKNOWN_EXTENSION -> {
                var extensions = element(document, PROTOCOL, "samlp:Extensions");
                var unknown = element(document, "urn:samlscope:probe:unknown-extension", "probe:UnknownExtension");
                unknown.setAttributeNS(XMLConstants.XMLNS_ATTRIBUTE_NS_URI, "xmlns:probe",
                        "urn:samlscope:probe:unknown-extension");
                unknown.setAttribute("fixture", token(requestId));
                extensions.appendChild(unknown);
                request.appendChild(extensions);
            }
            case UNKNOWN_ANY_ATTRIBUTE -> {
                var subject = element(document, ASSERTION, "saml:Subject");
                var confirmation = element(document, ASSERTION, "saml:SubjectConfirmation");
                confirmation.setAttribute("Method", "urn:samlscope:probe:confirmation-method");
                var data = element(document, ASSERTION, "saml:SubjectConfirmationData");
                data.setAttributeNS(XMLConstants.XMLNS_ATTRIBUTE_NS_URI, "xmlns:probe",
                        "urn:samlscope:probe:unknown-attribute");
                data.setAttributeNS(
                        "urn:samlscope:probe:unknown-attribute", "probe:fixture", token(requestId));
                confirmation.appendChild(data);
                subject.appendChild(confirmation);
                request.appendChild(subject);
            }
            case PERSISTENT_NAMEID_POLICY -> {
                var policy = element(document, PROTOCOL, "samlp:NameIDPolicy");
                policy.setAttribute("Format", "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent");
                policy.setAttribute("AllowCreate", "true");
                request.appendChild(policy);
            }
            case UNRECOGNIZED_SUBJECT -> {
                var subject = element(document, ASSERTION, "saml:Subject");
                var nameId = element(document, ASSERTION, "saml:NameID");
                nameId.setAttribute("Format", "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent");
                nameId.setTextContent("urn:samlscope:probe:unknown-subject:" + token(requestId));
                subject.appendChild(nameId);
                request.appendChild(subject);
            }
            case PASSIVE_WITHOUT_SESSION -> { }
            case PASSIVE_WITH_SESSION -> { }
            case FORCE_AUTHN_PASSIVE -> { }
            case FORCE_AUTHN_FALSE -> { }
            case FORCE_AUTHN_TRUE -> { }
            case SUBMILLISECOND_ISSUE_INSTANT -> { }
            case VERSION_1_1 -> { }
            case VERSION_3_0 -> { }
            case BASELINE_SUCCESS -> { }
            case STRING_BOUNDARY_255 -> { }
            case STRING_BOUNDARY_256 -> { }
            case STRING_ASCII_255 -> { }
            case STRING_ASCII_256 -> { }
            case STRING_CJK_255 -> { }
            case STRING_CJK_256 -> { }
            case STRING_COMBINING_255 -> { }
            case STRING_COMBINING_256 -> { }
            case STRING_XML_SPECIAL_255 -> { }
            case STRING_XML_SPECIAL_256 -> { }
            case STRING_TAB_REFERENCE_255 -> { }
            case STRING_TAB_REFERENCE_256 -> { }
            case STRING_LF_REFERENCE_255 -> { }
            case STRING_LF_REFERENCE_256 -> { }
            case STRING_SUPPLEMENTARY_255 -> { }
            case STRING_SUPPLEMENTARY_256 -> { }
            case STRING_TAB_LITERAL_255, STRING_TAB_LITERAL_256, STRING_LF_LITERAL_255, STRING_LF_LITERAL_256 -> { }

            case DTD_AUTHN_REQUEST -> { }
            case DTD_EXTERNAL_ENTITY_AUTHN_REQUEST -> { }
            case ACS_SELECTION_OMITTED -> { }
            case ISSUER_TRAILING_WHITESPACE -> { }
        }
        var serialized = SecureXml.serialize(document);
        if (probe == Probe.DTD_AUTHN_REQUEST || probe == Probe.DTD_EXTERNAL_ENTITY_AUTHN_REQUEST) {
            var xml = new String(serialized, java.nio.charset.StandardCharsets.UTF_8);
            var declarationEnd = xml.indexOf("?>");
            var insertion = probe == Probe.DTD_AUTHN_REQUEST
                    ? "<!DOCTYPE samlp:AuthnRequest>"
                    : "<!DOCTYPE samlp:AuthnRequest [<!ENTITY samlscope SYSTEM \"https://invalid.example/samlscope.dtd\">]>";
            xml = declarationEnd >= 0
                    ? xml.substring(0, declarationEnd + 2) + insertion + xml.substring(declarationEnd + 2)
                    : insertion + xml;
            return xml.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        }
        return probe.name().contains("_LITERAL_") ? ProviderNameWireFormat.literalWhitespace(serialized) : serialized;
    }

    /** Every category spans the boundary; Java UTF-16 units are not character counts. */
    public static java.util.List<Probe> stringProbes() {
        return java.util.Arrays.stream(Probe.values()).filter(value -> value.name().startsWith("STRING_")).toList();
    }

    public static String parsedStringValue(Probe probe) {
        var value = stringValue(probe);
        return probe.name().contains("_LITERAL_") ? value.replace('\t', ' ').replace('\n', ' ') : value;
    }

    public static String stringValue(Probe probe) {
        if (!stringProbes().contains(probe)) throw new IllegalArgumentException("Not a string fixture");
        var length = probe.name().endsWith("_255") ? 255 : 256;
        var category = probe.name().substring("STRING_".length(), probe.name().length() - 4);
        var sample = switch (category) {
            case "BOUNDARY" -> "\u0416";
            case "ASCII" -> "aZ09";
            case "CJK" -> "漢字";
            case "COMBINING" -> "e\u0301";
            case "XML_SPECIAL" -> "<&\"'>";
            case "TAB_REFERENCE", "TAB_LITERAL" -> "a\tb";
            case "LF_REFERENCE", "LF_LITERAL" -> "a\nb";
            case "SUPPLEMENTARY" -> "\uD83D\uDE00\uD840\uDC00";
            default -> throw new IllegalArgumentException("Unknown string category: " + category);
        };
        var points = sample.codePoints().toArray();
        var value = new StringBuilder();
        for (int index = 0; index < length; index++) value.appendCodePoint(points[index % points.length]);
        return value.toString();
    }

    public String unknownNameIdFormat(String requestId) {
        return "urn:samlscope:probe:unknown-nameid-format:" + token(requestId);
    }

    public String unavailableAuthnContext(String requestId) {
        return "urn:samlscope:probe:unavailable-authn-context:" + token(requestId);
    }

    private String token(String requestId) {
        return requestId.startsWith("_") ? requestId.substring(1) : requestId;
    }

    private Element element(Document document, String namespace, String qualifiedName) {
        return document.createElementNS(namespace, qualifiedName);
    }

    private void requireText(String value, String name) {
        if (value == null || value.isBlank()) throw new IllegalArgumentException(name + " must not be blank");
    }
}
