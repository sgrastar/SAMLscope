package com.samlscope.runner.cases;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import com.samlscope.core.evaluation.CaseOutcome;
import com.samlscope.core.evaluation.EvidenceRef;
import com.samlscope.core.evaluation.Outcome;
import com.samlscope.saml.normal.SamlException;
import com.samlscope.saml.normal.SecureXml;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

/** Detects multiple semantic principals without comparing identifier strings. */
public final class SamlSubjectPrincipalCase {
    private static final String ASSERTION = "urn:oasis:names:tc:SAML:2.0:assertion";
    private final PrincipalIdentityResolver resolver;

    public SamlSubjectPrincipalCase(PrincipalIdentityResolver resolver) {
        this.resolver = java.util.Objects.requireNonNull(resolver, "resolver");
    }

    public CaseOutcome evaluate(String runId, List<TargetTranscriptMessages.Message> messages) {
        messages = List.copyOf(messages == null ? List.of() : messages);
        if (messages.isEmpty()) return CaseOutcome.notVerified(
                "no_target_generated_saml_messages", "transcript.no-target-generated-saml");
        var inspected = new ArrayList<EvidenceRef>();
        var unknown = new ArrayList<EvidenceRef>();
        var violations = new ArrayList<String>();
        var subjects = 0;
        for (var message : messages) {
            try {
                var document = SecureXml.parse(message.xml());
                var opaque = document.getElementsByTagNameNS(ASSERTION, "EncryptedAssertion");
                for (var index = 0; index < opaque.getLength(); index++) {
                    unknown.add(new EvidenceRef("transcript", message.evidenceRef() + "#EncryptedAssertion[" + index + "]"));
                }
                var nodes = document.getElementsByTagNameNS(ASSERTION, "Subject");
                for (var index = 0; index < nodes.getLength(); index++) {
                    subjects++;
                    inspectSubject(runId, (Element) nodes.item(index),
                            message.evidenceRef() + "#Subject[" + index + "]", inspected, unknown, violations);
                }
            } catch (SamlException malformed) {
                unknown.add(new EvidenceRef("transcript", message.evidenceRef()));
            }
        }
        if (!violations.isEmpty()) return new CaseOutcome(
                Outcome.VIOLATED, null, "saml.subject-principal.violated", "case.saml.subject-principal.violated",
                inspected, java.util.Map.of("observed_subjects", subjects, "violations", violations));
        if (!unknown.isEmpty()) return new CaseOutcome(
                Outcome.NOT_VERIFIED, "principal_identity_undetermined", "saml.subject-principal.undetermined",
                "case.saml.subject-principal.undetermined", unknown,
                java.util.Map.of("observed_subjects", subjects, "unresolved_identifiers", unknown.size()));
        return new CaseOutcome(
                subjects == 0 ? Outcome.SATISFIED_WITH_NOTE : Outcome.SATISFIED,
                null, "saml.subject-principal.satisfied", "case.saml.subject-principal.satisfied",
                inspected, java.util.Map.of("observed_subjects", subjects));
    }

    private void inspectSubject(
            String runId,
            Element subject,
            String subjectRef,
            List<EvidenceRef> inspected,
            List<EvidenceRef> unknown,
            List<String> violations) {
        var direct = directIdentifiers(subject);
        if (direct.size() != 1) violations.add(subjectRef + ":direct-identifier-count=" + direct.size());
        var principalIds = new LinkedHashSet<String>();
        for (var identifier : direct) resolve(runId, identifier, principalIds, inspected, unknown);

        var confirmations = directChildren(subject, "SubjectConfirmation");
        for (var confirmationIndex = 0; confirmationIndex < confirmations.size(); confirmationIndex++) {
            var identifiers = directIdentifiers(confirmations.get(confirmationIndex));
            for (var identifier : identifiers) resolve(runId, identifier, principalIds, inspected, unknown);
        }

        var assertion = nearestAncestor(subject, "Assertion");
        if (assertion != null) {
            var attributes = assertion.getElementsByTagNameNS(ASSERTION, "Attribute");
            for (var index = 0; index < attributes.getLength(); index++) {
                var attribute = (Element) attributes.item(index);
                var values = attribute.getElementsByTagNameNS(ASSERTION, "AttributeValue");
                for (var valueIndex = 0; valueIndex < values.getLength(); valueIndex++) {
                    var value = (Element) values.item(valueIndex);
                    var ref = subjectRef + ":Attribute[" + index + "]/Value[" + valueIndex + "]";
                    resolve(runId, new PrincipalIdentityResolver.Identifier(
                            "Attribute:" + attribute.getAttribute("Name"),
                            serializedValue(value), attribute.getAttribute("NameFormat"), ref),
                            principalIds, inspected, unknown);
                }
            }
        }
        if (principalIds.size() > 1) violations.add(subjectRef + ":multiple-principals=" + principalIds.size());
    }

    private void resolve(
            String runId,
            PrincipalIdentityResolver.Identifier identifier,
            LinkedHashSet<String> principals,
            List<EvidenceRef> inspected,
            List<EvidenceRef> unknown) {
        var evidence = new EvidenceRef("principal-identity", identifier.evidenceRef());
        var result = resolver.resolve(runId, identifier);
        switch (result.status()) {
            case RESOLVED -> {
                principals.add(result.principalId());
                inspected.add(evidence);
            }
            case NOT_SUBJECT_IDENTIFYING -> inspected.add(evidence);
            case UNKNOWN -> unknown.add(evidence);
        }
    }

    private List<PrincipalIdentityResolver.Identifier> directIdentifiers(Element parent) {
        var result = new ArrayList<PrincipalIdentityResolver.Identifier>();
        var ordinal = 0;
        for (var child = parent.getFirstChild(); child != null; child = child.getNextSibling()) {
            if (child.getNodeType() != Node.ELEMENT_NODE) continue;
            var element = (Element) child;
            if (!ASSERTION.equals(element.getNamespaceURI())
                    || !List.of("BaseID", "NameID", "EncryptedID").contains(element.getLocalName())) continue;
            result.add(new PrincipalIdentityResolver.Identifier(
                    element.getLocalName(), serializedValue(element), element.getAttribute("Format"),
                    parent.getLocalName() + "/" + element.getLocalName() + "[" + ordinal++ + "]"));
        }
        return result;
    }

    private List<Element> directChildren(Element parent, String localName) {
        var result = new ArrayList<Element>();
        for (var child = parent.getFirstChild(); child != null; child = child.getNextSibling()) {
            if (child.getNodeType() == Node.ELEMENT_NODE
                    && ASSERTION.equals(child.getNamespaceURI())
                    && localName.equals(child.getLocalName())) result.add((Element) child);
        }
        return result;
    }

    private Element nearestAncestor(Element element, String localName) {
        for (var parent = element.getParentNode(); parent instanceof Element ancestor; parent = parent.getParentNode()) {
            if (ASSERTION.equals(ancestor.getNamespaceURI()) && localName.equals(ancestor.getLocalName())) return ancestor;
        }
        return null;
    }

    private String serializedValue(Element element) {
        if (!element.hasChildNodes()) return element.getTextContent();
        var document = SecureXml.newDocument();
        document.appendChild(document.importNode(element, true));
        return new String(SecureXml.serialize(document), StandardCharsets.UTF_8);
    }
}
