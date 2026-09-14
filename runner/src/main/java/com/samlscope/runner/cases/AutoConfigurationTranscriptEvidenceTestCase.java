package com.samlscope.runner.cases;

import java.util.ArrayList;
import java.util.Objects;
import com.samlscope.core.caseexec.CaseContext;
import com.samlscope.core.caseexec.CaseEvent;
import com.samlscope.core.caseexec.CaseState;
import com.samlscope.core.caseexec.CaseStep;
import com.samlscope.core.caseexec.TestCase;
import com.samlscope.core.plan.TargetRole;
import com.samlscope.core.transcript.Direction;
import com.samlscope.core.transcript.TranscriptContentReader;
import com.samlscope.saml.crypto.SamlXmlDecrypter;

/** Uses target-generated SAML first and preserves the approved CONFIG questionnaire as fallback. */
public final class AutoConfigurationTranscriptEvidenceTestCase
        implements TestCase, ConfigurationPrompt, AttestationPrompt,
        com.samlscope.runner.EvidenceCampaignCase, com.samlscope.runner.FallbackEvidenceCase, ProtocolEvidenceCase {
    private final TestCase fallback;
    private final TranscriptContentReader content;
    private final SamlDecryptionKeyProvider decryptionKeys;

    public AutoConfigurationTranscriptEvidenceTestCase(
            TestCase fallback,
            TranscriptContentReader content,
            SamlDecryptionKeyProvider decryptionKeys) {
        this.fallback = Objects.requireNonNull(fallback, "fallback");
        this.content = Objects.requireNonNull(content, "content");
        this.decryptionKeys = Objects.requireNonNull(decryptionKeys, "decryptionKeys");
        if (!TranscriptConfigurationObservation.supports(fallback.id())) {
            throw new IllegalArgumentException("No Transcript CONFIG oracle for " + fallback.id());
        }
        if (!(fallback instanceof ConfigurationPrompt) || !(fallback instanceof AttestationPrompt)) {
            throw new IllegalArgumentException("CONFIG fallback must expose both approved prompts");
        }
    }

    @Override public String id() { return fallback.id(); }
    @Override public TargetRole role() { return fallback.role(); }
    @Override public String evidenceCampaignId() { return "ordinary-sso-transcript"; }
    @Override public String evidenceCampaignTitle() { return "Ordinary browser SSO transcript"; }
    @Override public com.samlscope.runner.RunCampaignQuery.ActionKind evidenceActionKind() {
        return com.samlscope.runner.RunCampaignQuery.ActionKind.LOGIN;
    }
    @Override public String instructionEn() { return ((ConfigurationPrompt) fallback).instructionEn(); }
    @Override public String promptEn() { return ((AttestationPrompt) fallback).promptEn(); }
    @Override public java.util.List<AttestationOption> options() {
        return ((AttestationPrompt) fallback).options();
    }

    @Override
    public boolean resolvedFromExternalEvidence(com.samlscope.core.caseexec.CaseExecution execution) {
        return execution.outcome() != null && execution.outcome().evidence().stream()
                .anyMatch(value -> "transcript".equals(value.kind()));
    }

    @Override
    public CaseStep start(CaseContext context) {
        var observed = observe(context);
        if (!observed.issues().isEmpty()) return new CaseStep.Finish(incomplete(observed));
        return observed.outcome().<CaseStep>map(CaseStep.Finish::new)
                .orElseGet(() -> fallback.start(context));
    }

    private record Observation(java.util.Optional<com.samlscope.core.evaluation.CaseOutcome> outcome,
                               java.util.List<String> issues) {}

    private static Observation unavailable(String issue) {
        return new Observation(java.util.Optional.empty(), java.util.List.of(issue));
    }

    private static com.samlscope.core.evaluation.CaseOutcome incomplete(Observation observation) {
        return new com.samlscope.core.evaluation.CaseOutcome(
                com.samlscope.core.evaluation.Outcome.NOT_VERIFIED, "configuration_transcript_incomplete",
                "configuration.transcript-incomplete", "configuration.transcript-incomplete",
                java.util.List.of(), java.util.Map.of("evidence_issues", observation.issues()));
    }

    private Observation observe(CaseContext context) {
        if (!context.transcriptComplete()) return unavailable("history_incomplete");
        final java.util.List<com.samlscope.core.transcript.TranscriptEntry> entries;
        try { entries = context.transcript().list(context.runId()); }
        catch (RuntimeException unavailable) { return unavailable("history_unavailable"); }
        var ids = new java.util.HashSet<String>();
        var messages = new ArrayList<TranscriptConfigurationObservation.Message>();
        for (var entry : entries) {
            if (!context.runId().equals(entry.runId())) return unavailable("run_mismatch");
            if (!ids.add(entry.id())) return unavailable("ambiguous_entry_id");
            if (entry.direction() != Direction.INBOUND
                    || !"Response".equals(entry.samlSummary().get("type"))
                    || !(Boolean.TRUE.equals(entry.samlSummary().get("normalFlowAccepted"))
                    || Boolean.TRUE.equals(entry.samlSummary().get("metadataProbeAccepted"))
                    || Boolean.TRUE.equals(entry.samlSummary().get("activeProbeAccepted")))) continue;
            if (entry.decodedSamlRef() == null || entry.decodedSamlBytes() <= 0)
                return unavailable("decoded_content_missing");
            final byte[] xml;
            try { xml = content.readDecodedSaml(entry); }
            catch (RuntimeException unreadable) { return unavailable("decoded_content_unreadable"); }
            if (xml == null || xml.length == 0) return unavailable("decoded_content_missing");
            if (xml.length != entry.decodedSamlBytes()) return unavailable("decoded_content_size_mismatch");
            try {
                var root = com.samlscope.saml.normal.SecureXml.parse(xml).getDocumentElement();
                if (!"urn:oasis:names:tc:SAML:2.0:protocol".equals(root.getNamespaceURI()) || !"Response".equals(root.getLocalName()))
                    return unavailable("response_type_mismatch");
            } catch (RuntimeException malformed) { return unavailable("decoded_content_invalid_xml"); }
            messages.add(new TranscriptConfigurationObservation.Message("transcript:" + entry.id(), xml));
        }
        final java.security.PrivateKey key;
        try { key = decryptionKeys.keyFor(context.runId()).orElse(null); }
        catch (RuntimeException unavailable) { return unavailable("target-encryption-key"); }
        return new Observation(TranscriptConfigurationObservation.evaluate(id(), messages, key, new SamlXmlDecrypter()), java.util.List.of());
    }

    @Override
    public CaseStep resume(CaseContext context, CaseState state, CaseEvent event) {
        if (event instanceof CaseEvent.TranscriptReady) {
            var observed = observe(context);
            return new CaseStep.Finish(observed.outcome().orElseGet(() -> incomplete(observed)));
        }
        if (event instanceof CaseEvent.ConfigConfirmed) {
            var observed = observe(context);
            return new CaseStep.Finish(observed.outcome().orElseGet(() -> incomplete(observed)));
        }
        return fallback.resume(context, state, event);
    }

    @Override public EvidenceStatus evidenceStatus(CaseContext context) {
        var observed = observe(context);
        var outcome = observed.outcome();
        var required = java.util.List.of("conclusive-transcript:" + id());
        return new EvidenceStatus(outcome.isPresent(), required,
                outcome.isPresent() ? required : java.util.List.of(),
                java.util.Map.of("automatic_observation", true, "evidence_issues", observed.issues()));
    }
}
