package com.samlscope.runner.cases;

import static com.samlscope.runner.cases.MetadataAlgorithmEvidence.children;
import java.util.*;
import java.security.cert.X509Certificate;
import com.samlscope.core.caseexec.CaseContext;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.transcript.*;
import com.samlscope.saml.crypto.*;
import com.samlscope.saml.normal.SecureXml;
import org.w3c.dom.Element;

/** Existence of each independently signed producer configuration requires authentic protocol output. */
final class SignatureModesObservation {
    static final String ID = "IIP-SSO04-a-idp-01";
    static final List<String> REQUIRED = List.of("both", "assertion-only", "response-only");
    private static final String S = "urn:oasis:names:tc:SAML:2.0:assertion";
    private static final String P = "urn:oasis:names:tc:SAML:2.0:protocol";
    private static final String MD = "urn:oasis:names:tc:SAML:2.0:metadata";
    private static final String DS = "http://www.w3.org/2000/09/xmldsig#";
    record Sample(String mode, String issuer, String peer, List<EvidenceRef> evidence) {}

    static CaseOutcome observe(CaseContext context, TranscriptContentReader content, byte[] metadata,
            SamlDecryptionKeyProvider keys) {
        var samples = new ArrayList<Sample>();
        var issues = new ArrayList<String>();
        if (!context.transcriptComplete()) return evaluate(samples, List.of("transcript_incomplete"));
        try {
            var target = SecureXml.parse(metadata).getDocumentElement();
            var issuer = target.getAttribute("entityID");
            var trusted = MetadataAlgorithmEvidence.signingKeys(target);
            require(!issuer.isBlank() && !trusted.isEmpty());
            var endpoints = new HashSet<String>();
            for (var role : children(target, MD, "IDPSSODescriptor"))
                for (var endpoint : children(role, MD, "SingleSignOnService")) endpoints.add(endpoint.getAttribute("Location"));
            var requests = new HashMap<String, List<TranscriptEntry>>();
            var entries = context.transcript().list(context.runId());
            for (var entry : entries) {
                require(context.runId().equals(entry.runId()));
                if (entry.direction() == Direction.OUTBOUND && "AuthnRequest".equals(entry.samlSummary().get("type"))) {
                    var id = String.valueOf(entry.samlSummary().get("id"));
                    requests.computeIfAbsent(id, ignored -> new ArrayList<>()).add(entry);
                }
            }
            var responses = new HashMap<String, Integer>();
            for (var entry : entries) if (entry.direction() == Direction.INBOUND && "Response".equals(entry.samlSummary().get("type"))) {
                try {
                    var response = SecureXml.parse(content.readDecodedSaml(entry)).getDocumentElement();
                    responses.merge(response.getAttribute("InResponseTo"), 1, Integer::sum);
                } catch (Exception unavailable) { issues.add("unreadable_response:" + entry.id()); }
            }
            for (var received : entries) {
                if (received.direction() != Direction.INBOUND || !"Response".equals(received.samlSummary().get("type"))) continue;
                try {
                    var response = SecureXml.parse(content.readDecodedSaml(received)).getDocumentElement();
                    var id = response.getAttribute("InResponseTo");
                    var matching = requests.getOrDefault(id, List.of());
                    // Unrelated active probes cannot establish a normal-flow capability.
                    if (matching.size() != 1 || responses.getOrDefault(id, 0) != 1) continue;
                    var sent = matching.getFirst();
                    if (sent.url().contains("mdv=") || MetadataProbeCorrelation.signatureControl(sent)) continue;
                    var request = SecureXml.parse(content.readDecodedSaml(sent)).getDocumentElement();
                    require(P.equals(request.getNamespaceURI()) && "AuthnRequest".equals(request.getLocalName()));
                    require(id.equals(request.getAttribute("ID")) && endpoints.contains(request.getAttribute("Destination")));
                    require(received.timestamp().isAfter(sent.timestamp()));
                    var peer = one(request, S, "Issuer").getTextContent();
                    var acs = request.getAttribute("AssertionConsumerServiceURL");
                    require(!peer.isBlank() && !acs.isBlank() && acs.equals(received.url()));
                    require(acs.equals(response.getAttribute("Destination")) && "POST".equals(received.method()));
                    samples.add(inspect(response, issuer, peer, id, acs, trusted, keys, context.runId(),
                            List.of(new EvidenceRef("transcript", sent.id()), new EvidenceRef("transcript", received.id()))));
                } catch (Exception unavailable) {
                    issues.add("signature_modes_evidence_unproven:" + received.id());
                }
            }
        } catch (Exception unavailable) { issues.add("signature_modes_inputs_unavailable"); }
        return evaluate(samples, issues);
    }

    static Sample inspect(Element response, String issuer, String peer, String requestId, String acs,
            List<X509Certificate> trusted, SamlDecryptionKeyProvider keys, String runId, List<EvidenceRef> evidence) {
        require(P.equals(response.getNamespaceURI()) && "Response".equals(response.getLocalName()));
        var ids = new HashSet<String>();
        var elements = response.getOwnerDocument().getElementsByTagName("*");
        for (int index = 0; index < elements.getLength(); index++) {
            var element = (Element) elements.item(index);
            if (element.hasAttribute("ID")) require(!element.getAttribute("ID").isBlank() && ids.add(element.getAttribute("ID")));
        }
        require(!response.getAttribute("ID").isBlank());
        require(issuer.equals(one(response, S, "Issuer").getTextContent()));
        require("urn:oasis:names:tc:SAML:2.0:status:Success".equals(one(one(response, P, "Status"), P, "StatusCode").getAttribute("Value")));
        var clear = children(response, S, "Assertion");
        var encrypted = children(response, S, "EncryptedAssertion");
        require(clear.size() + encrypted.size() == 1);
        var responseSignatures = children(response, DS, "Signature");
        require(responseSignatures.size() <= 1);
        var verified = new VerifiedSignatureAlgorithms().read(response, issuer, trusted);
        boolean responseSigned = responseSignatures.size() == 1;
        require(!responseSigned || verified.stream().anyMatch(s -> "Response".equals(s.element())));
        var assertion = clear.isEmpty()
                ? new SamlXmlDecrypter().decrypt(encrypted.getFirst(), keys.keyFor(runId).orElseThrow())
                : clear.getFirst();
        require(S.equals(assertion.getNamespaceURI()) && "Assertion".equals(assertion.getLocalName()));
        require(issuer.equals(one(assertion, S, "Issuer").getTextContent()));
        var assertionSignatures = children(assertion, DS, "Signature");
        require(assertionSignatures.size() <= 1);
        boolean assertionSigned = assertionSignatures.size() == 1;
        // Independently verify the Assertion; an authentic outer Response cannot hide a broken inner signature.
        if (assertionSigned && !clear.isEmpty()) {
            // Keep the original ancestor namespace context: moving a clear Assertion can invalidate inclusive canonicalization.
            require(verified.stream().anyMatch(s -> "Assertion".equals(s.element()) && assertion.getAttribute("ID").equals(s.id())));
        } else if (assertionSigned) {
            var holder = SecureXml.parse(("<p:Response xmlns:p=\"" + P + "\"/>").getBytes(java.nio.charset.StandardCharsets.UTF_8));
            holder.getDocumentElement().appendChild(holder.importNode(assertion, true));
            require(new VerifiedSignatureAlgorithms().read(holder.getDocumentElement(), issuer, trusted).stream()
                    .anyMatch(s -> "Assertion".equals(s.element()) && assertion.getAttribute("ID").equals(s.id())));
        }
        require(responseSigned || assertionSigned);
        var subject = one(assertion, S, "Subject");
        boolean correlated = children(subject, S, "SubjectConfirmation").stream()
                .filter(c -> "urn:oasis:names:tc:SAML:2.0:cm:bearer".equals(c.getAttribute("Method")))
                .flatMap(c -> children(c, S, "SubjectConfirmationData").stream())
                .anyMatch(c -> requestId.equals(c.getAttribute("InResponseTo")) && acs.equals(c.getAttribute("Recipient")));
        require(correlated);
        var conditions = one(assertion, S, "Conditions");
        var restrictions = children(conditions, S, "AudienceRestriction");
        require(!restrictions.isEmpty() && restrictions.stream().allMatch(r -> children(r, S, "Audience").stream()
                .anyMatch(a -> peer.equals(a.getTextContent()))));
        return new Sample(responseSigned ? assertionSigned ? "both" : "response-only" : "assertion-only", issuer, peer, evidence);
    }

    static CaseOutcome evaluate(List<Sample> samples, List<String> issues) {
        var modes = new LinkedHashSet<String>();
        var identities = new HashSet<List<String>>();
        var evidence = new LinkedHashSet<EvidenceRef>();
        for (var sample : samples) {
            modes.add(sample.mode()); identities.add(List.of(sample.issuer(), sample.peer())); evidence.addAll(sample.evidence());
        }
        boolean complete = modes.containsAll(REQUIRED) && identities.size() == 1;
        var missing = REQUIRED.stream().filter(m -> !modes.contains(m)).toList();
        // A missing configuration, even after a failed attempt, is not evidence that support is absent.
        var code = complete ? "browser.signature-modes.observed" : "browser.signature-modes.incomplete";
        return new CaseOutcome(complete ? Outcome.SATISFIED : Outcome.NOT_VERIFIED,
                complete ? null : "signature_modes_unproven", code, code, List.copyOf(evidence),
                Map.of("observed_modes", List.copyOf(modes), "missing_modes", missing,
                        "collection_issues", List.copyOf(issues), "producer_scope", "same-run-same-target-same-peer"));
    }
    private static Element one(Element root, String ns, String name) {
        var list = children(root, ns, name); require(list.size() == 1); return list.getFirst();
    }
    private static void require(boolean value) { if (!value) throw new IllegalArgumentException("Signature modes evidence unproven"); }
}
