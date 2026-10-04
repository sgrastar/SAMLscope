package com.samlscope.saml.normal;

import com.samlscope.saml.crypto.PlanCredentials;
import com.samlscope.saml.crypto.XmlSigner;
import java.net.URI;
import java.time.Duration;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.Objects;
import org.w3c.dom.Element;

/**
 * Temporal inputs for the approved clock campaign. T is an explicit target policy input,
 * never the Suite's validation tolerance. Creating a fixture does not prove its consumption.
 * Conditions are standalone assertion inputs for a real assertion consumer: placing these
 * assertions in an ignored AuthnRequest Extension is deliberately not a supported shortcut.
 */
public final class SamlClockSkewFixtures {
    private static final String P = "urn:oasis:names:tc:SAML:2.0:protocol";
    private static final String A = "urn:oasis:names:tc:SAML:2.0:assertion";
    private static final String MD = "urn:oasis:names:tc:SAML:2.0:metadata";
    private static final String DS = "http://www.w3.org/2000/09/xmldsig#";

    public enum IssueInstantShift { CONTROL, WITHIN_PAST, WITHIN_FUTURE, OUTSIDE_PAST, OUTSIDE_FUTURE }
    public enum ConditionShift { CONTROL, NOT_BEFORE_WITHIN_FUTURE, NOT_ON_OR_AFTER_WITHIN_PAST }

    public byte[] request(IssueInstantShift shift, String requestId, URI destination,
            String issuer, URI acs, Instant nativeReference, Duration targetTolerance,
            Duration delta, PlanCredentials credentials) {
        Objects.requireNonNull(shift);
        var within = within(targetTolerance, delta);
        var outside = targetTolerance.plus(delta);
        var instant = switch (shift) {
            case CONTROL -> nativeReference;
            case WITHIN_PAST -> nativeReference.minus(within);
            case WITHIN_FUTURE -> nativeReference.plus(within);
            case OUTSIDE_PAST -> nativeReference.minus(outside);
            case OUTSIDE_FUTURE -> nativeReference.plus(outside);
        };
        return new SamlSignedRequestFactory().build(SamlSignedRequestFactory.Fixture.VALID,
                requestId, destination, issuer, acs, instant, credentials);
    }

    /** Change exactly the temporal fields on a complete assertion template, then sign it. */
    public byte[] assertion(byte[] completeTemplate, ConditionShift shift, Instant nativeReference,
            Duration targetTolerance, Duration delta, PlanCredentials credentials) {
        Objects.requireNonNull(shift);
        var within = within(targetTolerance, delta);
        var extent = targetTolerance.multipliedBy(2).plus(delta);
        var document = SecureXml.parse(completeTemplate);
        var assertion = document.getDocumentElement();
        require(A.equals(assertion.getNamespaceURI()) && "Assertion".equals(assertion.getLocalName()));
        require("2.0".equals(assertion.getAttribute("Version")) && !assertion.getAttribute("ID").isBlank());
        var conditions = one(assertion, A, "Conditions");
        assertion.setAttribute("IssueInstant", iso(nativeReference));
        conditions.setAttribute("NotBefore", iso(shift == ConditionShift.NOT_BEFORE_WITHIN_FUTURE
                ? nativeReference.plus(within) : nativeReference.minus(extent)));
        conditions.setAttribute("NotOnOrAfter", iso(shift == ConditionShift.NOT_ON_OR_AFTER_WITHIN_PAST
                ? nativeReference.minus(within) : nativeReference.plus(extent)));
        // Each independent boundary has a valid interval; changing both at once would create
        // an impossible NotBefore >= NotOnOrAfter interval and test a different obligation.
        require(Instant.parse(conditions.getAttribute("NotBefore"))
                .isBefore(Instant.parse(conditions.getAttribute("NotOnOrAfter"))));
        resign(assertion, credentials, afterIssuer(assertion));
        return SecureXml.serialize(document);
    }

    /** A real metadata resolver must receive this whole original, including its signature. */
    public byte[] metadata(byte[] completeTemplate, boolean withinExpired, Instant nativeReference,
            Duration targetTolerance, Duration delta, PlanCredentials credentials) {
        var within = within(targetTolerance, delta);
        var document = SecureXml.parse(completeTemplate);
        var root = document.getDocumentElement();
        require(MD.equals(root.getNamespaceURI()) && "EntityDescriptor".equals(root.getLocalName()));
        require(!root.getAttribute("ID").isBlank() && !root.getAttribute("entityID").isBlank());
        root.setAttribute("validUntil", iso(withinExpired ? nativeReference.minus(within)
                : nativeReference.plus(targetTolerance.multipliedBy(2).plus(delta))));
        resign(root, credentials, firstElement(root));
        return SecureXml.serialize(document);
    }

    static Duration within(Duration targetTolerance, Duration delta) {
        Objects.requireNonNull(targetTolerance); Objects.requireNonNull(delta);
        require(!targetTolerance.isNegative() && !targetTolerance.isZero()
                && !delta.isNegative() && !delta.isZero() && delta.compareTo(targetTolerance) < 0);
        return targetTolerance.minus(delta);
    }
    private static String iso(Instant value) { return DateTimeFormatter.ISO_INSTANT.format(Objects.requireNonNull(value)); }
    private static Element one(Element parent, String ns, String local) {
        Element selected = null;
        for (var n = parent.getFirstChild(); n != null; n = n.getNextSibling())
            if (n instanceof Element e && ns.equals(e.getNamespaceURI()) && local.equals(e.getLocalName())) {
                require(selected == null); selected = e;
            }
        require(selected != null); return selected;
    }
    private static Element afterIssuer(Element assertion) {
        var issuer = one(assertion, A, "Issuer");
        for (var n = issuer.getNextSibling(); n != null; n = n.getNextSibling())
            if (n instanceof Element e && !(DS.equals(e.getNamespaceURI()) && "Signature".equals(e.getLocalName()))) return e;
        return null;
    }
    private static Element firstElement(Element parent) {
        for (var n = parent.getFirstChild(); n != null; n = n.getNextSibling())
            if (n instanceof Element e && !(DS.equals(e.getNamespaceURI()) && "Signature".equals(e.getLocalName()))) return e;
        return null;
    }
    private static void resign(Element root, PlanCredentials key, Element before) {
        int count = 0;
        for (var n = root.getFirstChild(); n != null;) {
            var next = n.getNextSibling();
            if (n instanceof Element e && DS.equals(e.getNamespaceURI()) && "Signature".equals(e.getLocalName())) {
                require(++count <= 1); root.removeChild(n);
            }
            n = next;
        }
        new XmlSigner().sign(root, Objects.requireNonNull(key), before);
    }
    private static void require(boolean condition) {
        if (!condition) throw new IllegalArgumentException("Clock fixture prerequisite unavailable");
    }
}
