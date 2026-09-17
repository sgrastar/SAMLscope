package com.samlscope.runner.cases;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import com.samlscope.core.caseexec.CaseContext;
import com.samlscope.core.caseexec.CaseEvent;
import com.samlscope.core.caseexec.CaseState;
import com.samlscope.core.caseexec.CaseStep;
import com.samlscope.core.caseexec.TestCase;
import com.samlscope.core.evaluation.CaseOutcome;
import com.samlscope.core.evaluation.EvidenceRef;
import com.samlscope.core.plan.TargetRole;
import com.samlscope.core.transcript.Direction;
import com.samlscope.core.transcript.TranscriptContentReader;
import com.samlscope.core.transcript.TranscriptEntry;
import com.samlscope.saml.crypto.SamlElementDecrypter;
import com.samlscope.saml.crypto.SamlXmlDecrypter;
import com.samlscope.saml.normal.SamlException;
import com.samlscope.saml.normal.SecureXml;
import org.w3c.dom.Element;

/**
 * Produces IIP-ALG04/ALG06 outcomes from an EncryptedAssertion the target generated in a
 * successful, correlated browser SSO response. The Suite must decrypt it with its own key;
 * metadata algorithm declarations alone never produce a satisfied outcome.
 */
public final class EncryptionAlgorithmBrowserEvidenceTestCase
        implements TestCase, BrowserPrompt, ProtocolEvidenceCase, com.samlscope.runner.EvidenceCampaignCase {
    private static final String SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success";
    private static final String PROTOCOL = "urn:oasis:names:tc:SAML:2.0:protocol";
    private final BrowserEvidenceTestCase fallback;
    private final TranscriptContentReader content;
    private final SamlDecryptionKeyProvider decryptionKeys;
    private final SamlElementDecrypter decrypter;

    public EncryptionAlgorithmBrowserEvidenceTestCase(
            BrowserEvidenceTestCase fallback,
            TranscriptContentReader content,
            SamlDecryptionKeyProvider decryptionKeys) {
        this(fallback, content, decryptionKeys, new SamlXmlDecrypter());
    }

    EncryptionAlgorithmBrowserEvidenceTestCase(
            BrowserEvidenceTestCase fallback,
            TranscriptContentReader content,
            SamlDecryptionKeyProvider decryptionKeys,
            SamlElementDecrypter decrypter) {
        this.fallback = Objects.requireNonNull(fallback, "fallback");
        this.content = Objects.requireNonNull(content, "content");
        this.decryptionKeys = Objects.requireNonNull(decryptionKeys, "decryptionKeys");
        this.decrypter = Objects.requireNonNull(decrypter, "decrypter");
        if (!EncryptionAlgorithmObservation.supports(fallback.id())) {
            throw new IllegalArgumentException("No encryption algorithm oracle for " + fallback.id());
        }
    }

    @Override public String id() { return fallback.id(); }
    @Override public TargetRole role() { return fallback.role(); }
    @Override public String browserInstructionsEn() { return fallback.browserInstructionsEn(); }
    @Override public String evidenceCampaignId() { return "ordinary-sso-transcript"; }
    @Override public String evidenceCampaignTitle() { return "Ordinary browser SSO transcript"; }
    @Override public com.samlscope.runner.RunCampaignQuery.ActionKind evidenceActionKind() {
        return com.samlscope.runner.RunCampaignQuery.ActionKind.LOGIN;
    }

    @Override
    public CaseStep start(CaseContext context) {
        var outcome = transcriptOutcome(context);
        return outcome.<CaseStep>map(CaseStep.Finish::new).orElseGet(() -> fallback.start(context));
    }

    @Override
    public CaseStep resume(CaseContext context, CaseState state, CaseEvent event) {
        if (event instanceof CaseEvent.TranscriptReady) {
            return transcriptOutcome(context).<CaseStep>map(CaseStep.Finish::new)
                    .orElseThrow(() -> new IllegalStateException("Encrypted assertion evidence is not ready"));
        }
        return fallback.resume(context, state, event);
    }

    @Override
    public EvidenceStatus evidenceStatus(CaseContext context) {
        var observations = transcriptObservations(context);
        var outcome = EncryptionAlgorithmObservation.evaluate(id(), observations);
        var required = List.of("decrypted-target-assertion:" + id());
        return new EvidenceStatus(outcome.isPresent(), required,
                outcome.isPresent() ? required : List.of(),
                EncryptionAlgorithmObservation.diagnostics(observations, outcome.isPresent()));
    }

    private Optional<CaseOutcome> transcriptOutcome(CaseContext context) {
        return EncryptionAlgorithmObservation.evaluate(id(), transcriptObservations(context));
    }

    private List<EncryptionAlgorithmObservation.Observation> transcriptObservations(CaseContext context) {
        var key = decryptionKeys.keyFor(context.runId()).orElse(null);
        var sharedKey = decryptionKeys.sharedKeyFor(context.runId()).orElse(null);
        if (key == null && sharedKey == null) return List.of();
        var requests = new LinkedHashMap<String, TranscriptEntry>();
        var byCorrelation = new LinkedHashMap<String, TranscriptEntry>();
        for (var entry : context.transcript().list(context.runId())) {
            if (!context.runId().equals(entry.runId()) || entry.direction() != Direction.OUTBOUND || entry.decodedSamlRef() == null) continue;
            if (entry.correlationId() != null) byCorrelation.put(entry.correlationId(), entry);
            if (!"AuthnRequest".equals(entry.samlSummary().get("type"))) continue;
            var id = requestId(entry);
            if (id != null) requests.put(id, entry);
        }
        var observations = new ArrayList<EncryptionAlgorithmObservation.Observation>();
        for (var entry : context.transcript().list(context.runId())) {
            if (!context.runId().equals(entry.runId()) || entry.direction() != Direction.INBOUND || !"Response".equals(entry.samlSummary().get("type"))
                    || entry.decodedSamlRef() == null) continue;
            if (entry.url() != null && entry.url().contains("mdv=")) continue;
            var active = entry.correlationId() != null
                    && (entry.correlationId().startsWith("action_") || entry.correlationId().startsWith("_action_"));
            if (active && !Boolean.TRUE.equals(entry.samlSummary().get("activeProbeAccepted"))) continue;
            if (!active && !Boolean.TRUE.equals(entry.samlSummary().get("normalFlowAccepted"))) continue;
            byte[] xml;
            try {
                xml = content.readDecodedSaml(entry);
            } catch (RuntimeException unavailable) {
                continue;
            }
            org.w3c.dom.Document document;
            try {
                document = SecureXml.parse(xml);
            } catch (RuntimeException unreadable) {
                continue;
            }
            var inResponseTo = document.getDocumentElement().getAttribute("InResponseTo");
            var request = requests.get(inResponseTo);
            // ECP probe responses correlate to the outbox action rather than an AuthnRequest ID.
            if (request == null && inResponseTo.startsWith("_"))
                request = byCorrelation.get(inResponseTo.substring(1));
            if (request == null || entry.timestamp().isBefore(request.timestamp())) continue;
            if (!SUCCESS.equals(firstAttribute(document.getDocumentElement(), PROTOCOL, "StatusCode", "Value")))
                continue;
            var wrappers = document.getElementsByTagNameNS(EncryptionAlgorithmObservation.ASSERTION, "EncryptedAssertion");
            for (var index = 0; index < wrappers.getLength(); index++) {
                var wrapper = (Element) wrappers.item(index);
                var decrypted = decrypted(wrapper, key, sharedKey);
                observations.add(EncryptionAlgorithmObservation.inspect(
                        new EvidenceRef("transcript", request.id()),
                        new EvidenceRef("transcript", entry.id()), wrapper, decrypted));
            }
        }
        return List.copyOf(observations);
    }

    private String requestId(TranscriptEntry entry) {
        try {
            var document = SecureXml.parse(content.readDecodedSaml(entry));
            var requests = document.getElementsByTagNameNS(PROTOCOL, "AuthnRequest");
            if (requests.getLength() == 0) return null;
            var id = ((Element) requests.item(0)).getAttribute("ID");
            return id == null || id.isBlank() ? null : id;
        } catch (RuntimeException unavailable) {
            return null;
        }
    }

    private boolean decrypted(Element wrapper, java.security.PrivateKey key, javax.crypto.SecretKey sharedKey) {
        if (key != null) {
            try { decrypter.decrypt(wrapper, key); return true; }
            catch (SamlException unavailable) { /* A supplied Run shared key may be the direct data key. */ }
        }
        if (sharedKey != null) {
            try { decrypter.decryptSharedKey(wrapper, sharedKey); return true; }
            catch (SamlException unavailable) { return false; }
        }
        return false;
    }

    private static String firstAttribute(Element root, String namespace, String localName, String attribute) {
        var values = root.getElementsByTagNameNS(namespace, localName);
        return values.getLength() == 0 ? "" : ((Element) values.item(0)).getAttribute(attribute);
    }
}
