package com.samlscope.runner.cases;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Function;
import java.security.cert.X509Certificate;
import com.samlscope.saml.crypto.SamlElementDecrypter;
import com.samlscope.saml.crypto.SamlXmlDecrypter;
import com.samlscope.saml.normal.SamlException;
import com.samlscope.saml.normal.SecureXml;
import com.samlscope.core.caseexec.CaseContext;
import com.samlscope.core.caseexec.CaseEvent;
import com.samlscope.core.caseexec.CaseState;
import com.samlscope.core.caseexec.CaseStep;
import com.samlscope.core.caseexec.TestCase;
import com.samlscope.core.plan.TargetRole;
import com.samlscope.core.transcript.Direction;
import com.samlscope.core.transcript.TranscriptContentReader;

/** Finishes from an ordinary SSO Transcript when conclusive; otherwise waits for more evidence. */
public final class AutoBrowserEvidenceTestCase
        implements TestCase, BrowserPrompt, ProtocolEvidenceCase, com.samlscope.runner.EvidenceCampaignCase {
    private final BrowserEvidenceTestCase fallback;
    private final TranscriptContentReader content;
    private final SamlDecryptionKeyProvider decryptionKeys;
    private final Function<String, Optional<String>> targetEntityIds;
    private final Function<String, List<X509Certificate>> targetSigningCertificates;
    private final SamlElementDecrypter decrypter;

    public AutoBrowserEvidenceTestCase(BrowserEvidenceTestCase fallback, TranscriptContentReader content) {
        this(fallback, content, ignored -> Optional.empty(), ignored -> Optional.empty(),
                ignored -> List.of(), new SamlXmlDecrypter());
    }

    public AutoBrowserEvidenceTestCase(
            BrowserEvidenceTestCase fallback,
            TranscriptContentReader content,
            SamlDecryptionKeyProvider decryptionKeys) {
        this(fallback, content, decryptionKeys, ignored -> Optional.empty(),
                ignored -> List.of(), new SamlXmlDecrypter());
    }

    public AutoBrowserEvidenceTestCase(
            BrowserEvidenceTestCase fallback,
            TranscriptContentReader content,
            SamlDecryptionKeyProvider decryptionKeys,
            Function<String, Optional<String>> targetEntityIds) {
        this(fallback, content, decryptionKeys, targetEntityIds, ignored -> List.of(), new SamlXmlDecrypter());
    }

    public AutoBrowserEvidenceTestCase(
            BrowserEvidenceTestCase fallback,
            TranscriptContentReader content,
            SamlDecryptionKeyProvider decryptionKeys,
            Function<String, Optional<String>> targetEntityIds,
            Function<String, List<X509Certificate>> targetSigningCertificates) {
        this(fallback, content, decryptionKeys, targetEntityIds,
                targetSigningCertificates, new SamlXmlDecrypter());
    }

    AutoBrowserEvidenceTestCase(
            BrowserEvidenceTestCase fallback,
            TranscriptContentReader content,
            SamlDecryptionKeyProvider decryptionKeys,
            Function<String, Optional<String>> targetEntityIds,
            SamlElementDecrypter decrypter) {
        this(fallback, content, decryptionKeys, targetEntityIds, ignored -> List.of(), decrypter);
    }

    AutoBrowserEvidenceTestCase(
            BrowserEvidenceTestCase fallback,
            TranscriptContentReader content,
            SamlDecryptionKeyProvider decryptionKeys,
            Function<String, Optional<String>> targetEntityIds,
            Function<String, List<X509Certificate>> targetSigningCertificates,
            SamlElementDecrypter decrypter) {
        this.fallback = Objects.requireNonNull(fallback, "fallback");
        this.content = Objects.requireNonNull(content, "content");
        this.decryptionKeys = Objects.requireNonNull(decryptionKeys, "decryptionKeys");
        this.targetEntityIds = Objects.requireNonNull(targetEntityIds, "targetEntityIds");
        this.targetSigningCertificates = Objects.requireNonNull(
                targetSigningCertificates, "targetSigningCertificates");
        this.decrypter = Objects.requireNonNull(decrypter, "decrypter");
        if (!NormalFlowBrowserObservation.supports(fallback.id())) {
            throw new IllegalArgumentException("No normal-flow oracle for " + fallback.id());
        }
    }

    @Override public String id() { return fallback.id(); }
    @Override public TargetRole role() { return fallback.role(); }
    @Override public String evidenceCampaignId() { return "ordinary-sso-transcript"; }
    @Override public String evidenceCampaignTitle() { return "Ordinary browser SSO transcript"; }
    @Override public com.samlscope.runner.RunCampaignQuery.ActionKind evidenceActionKind() {
        return com.samlscope.runner.RunCampaignQuery.ActionKind.LOGIN;
    }
    @Override public String browserInstructionsEn() { return fallback.browserInstructionsEn(); }

    @Override
    public CaseStep start(CaseContext context) {
        Objects.requireNonNull(context, "context");
        var outcome = transcriptOutcome(context);
        if (outcome.isPresent()) return new CaseStep.Finish(outcome.orElseThrow());
        return fallback.start(context);
    }

    @Override
    public CaseStep resume(CaseContext context, CaseState state, CaseEvent event) {
        if (event instanceof CaseEvent.TranscriptReady) {
            return transcriptOutcome(context)
                    .<CaseStep>map(CaseStep.Finish::new)
                    .orElseThrow(() -> new IllegalStateException("Transcript evidence is not ready"));
        }
        return fallback.resume(context, state, event);
    }

    @Override
    public EvidenceStatus evidenceStatus(CaseContext context) {
        var outcome = transcriptOutcome(context);
        var required = List.of("conclusive-transcript:" + id());
        return new EvidenceStatus(
                outcome.isPresent(), required, outcome.isPresent() ? required : List.of(),
                outcome.<java.util.Map<String, Object>>map(value -> java.util.Map.of(
                        "outcome", value.outcome().name(),
                        "evidence_count", value.evidence().size())).orElseGet(java.util.Map::of));
    }

    private java.util.Optional<com.samlscope.core.evaluation.CaseOutcome> transcriptOutcome(CaseContext context) {
        var messages = new ArrayList<NormalFlowBrowserObservation.Message>();
        var key = decryptionKeys.keyFor(context.runId()).orElse(null);
        for (var entry : context.transcript().list(context.runId())) {
            if (MetadataProbeCorrelation.signatureControl(entry)) continue;
            if (entry.decodedSamlRef() == null || entry.decodedSamlBytes() <= 0) continue;
            // Inbound SAML is recorded before protocol parsing and then updated atomically with
            // the validated summary. Never conclude from the durable-but-unvalidated first form.
            var parsedType = entry.samlSummary().get("type");
            var activeScenario = isActiveScenarioCorrelation(entry.correlationId());
            var metadataScenario = Boolean.TRUE.equals(entry.samlSummary().get("metadataProbeAccepted"));
            if (activeScenario && !NormalFlowBrowserObservation.acceptsActiveScenarioEvidence(id())) continue;
            if (entry.direction() == Direction.INBOUND
                    && (!"Response".equals(parsedType)
                    || !Boolean.TRUE.equals(entry.samlSummary().get(activeScenario
                    ? "activeProbeAccepted"
                    : metadataScenario ? "metadataProbeAccepted" : "normalFlowAccepted")))) continue;
            if (entry.direction() == Direction.OUTBOUND && !"AuthnRequest".equals(parsedType)) continue;
            if (entry.url() != null && entry.url().contains("mdv=") && !acceptsMetadataScenarioEvidence()) continue;
            var xml = content.readDecodedSaml(entry);
            // These rules inspect the signed/encrypted envelope itself. Replacing an
            // EncryptedAssertion would both erase the encryption signal and invalidate an
            // otherwise valid Response signature in the in-memory observation document.
            var preserveEnvelope = id().equals("IIP-SSO01-h1-idp-01")
                    || id().equals("IIP-SSO01-v-idp-01")
                    || id().equals("IIP-SSO01-au-idp-01")
                    || id().equals("IIP-SSO01-es-idp-01")
                    || id().equals("IIP-SSO01-et-idp-01");
            messages.add(new NormalFlowBrowserObservation.Message(
                    "transcript:" + entry.id(), entry.method(), entry.url(), entry.timestamp(),
                    key == null || preserveEnvelope ? xml : decryptAssertions(xml, key),
                    entry.direction() == Direction.INBOUND));
        }
        return NormalFlowBrowserObservation.evaluate(
                id(), messages, targetEntityIds.apply(context.runId()).orElse(null),
                targetSigningCertificates.apply(context.runId()));
    }

    private static boolean isActiveScenarioCorrelation(String correlationId) {
        if (correlationId == null) return false;
        return correlationId.startsWith("action_") || correlationId.startsWith("_action_");
    }

    private boolean acceptsMetadataScenarioEvidence() {
        return id().equals("IIP-SSO01-g-idp-01")
                || id().equals("IIP-SSO01-y-idp-01")
                || id().equals("IIP-SSO01-z-idp-01");
    }

    /** Produces an in-memory observation view; plaintext is never submitted to TranscriptRecorder. */
    private byte[] decryptAssertions(byte[] xml, java.security.PrivateKey key) {
        try {
            var document = SecureXml.parse(xml);
            var nodes = document.getElementsByTagNameNS(
                    NormalFlowBrowserObservation.ASSERTION, "EncryptedAssertion");
            var wrappers = new ArrayList<org.w3c.dom.Element>();
            for (var index = 0; index < nodes.getLength(); index++) {
                wrappers.add((org.w3c.dom.Element) nodes.item(index));
            }
            for (var wrapper : wrappers) {
                var plaintext = decrypter.decrypt(wrapper, key);
                wrapper.getParentNode().replaceChild(document.importNode(plaintext, true), wrapper);
            }
            return wrappers.isEmpty() ? xml : SecureXml.serialize(document);
        } catch (SamlException unavailable) {
            // Keep the encrypted original. The oracle remains inconclusive until evidence arrives or the wait expires.
            return xml;
        }
    }
}
