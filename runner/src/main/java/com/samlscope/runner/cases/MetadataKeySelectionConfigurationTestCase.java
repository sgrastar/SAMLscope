package com.samlscope.runner.cases;

import java.nio.file.Path;
import java.util.*;
import java.util.function.Function;
import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.plan.TargetRole;
import com.samlscope.core.transcript.TranscriptContentReader;
import com.samlscope.runner.RecordedEvidenceReevaluation;

/** Native request-bound evidence augments the approved metadata fixture campaign. */
public final class MetadataKeySelectionConfigurationTestCase implements TestCase, ConfigurationPrompt,
        ProtocolEvidenceCase, AttestationPrompt, com.samlscope.runner.EvidenceCampaignCase, RecordedEvidenceReevaluation {
    private final TestCase fallback;
    private final TranscriptContentReader content;
    private final Function<String, byte[]> metadata;
    private final MetadataKeySelectionEvidenceFile evidence;
    private final SimpleSamlPhpKeyValueRuntimeEvidence nativeKeyValue;
    private final Path directory;
    public MetadataKeySelectionConfigurationTestCase(TestCase fallback, TranscriptContentReader content,
            Function<String, byte[]> metadata, Path directory) {
        this.fallback = Objects.requireNonNull(fallback); this.content = Objects.requireNonNull(content);
        this.metadata = Objects.requireNonNull(metadata); this.directory=directory.toAbsolutePath().normalize();
        this.evidence = new MetadataKeySelectionEvidenceFile(directory);
        this.nativeKeyValue = new SimpleSamlPhpKeyValueRuntimeEvidence(
                this.directory.resolveSibling("metadata-keyvalue-evidence"), content);
        if (!supports(fallback.id())) throw new IllegalArgumentException("Unsupported metadata key selection case");
    }
    public static boolean supports(String id) {
        return MetadataKeySelectionComparison.CASES.contains(id) || MetadataRoleSigningTransportEvidence.ID.equals(id);
    }
    @Override public String promptEn() { return fallback instanceof AttestationPrompt prompt ? prompt.promptEn() : instructionEn(); }
    @Override public List<AttestationOption> options() { return fallback instanceof AttestationPrompt prompt ? prompt.options() : List.of(); }
    @Override public String id() { return fallback.id(); }
    @Override public TargetRole role() { return fallback.role(); }
    @Override public String instructionEn() { return ((ConfigurationPrompt) fallback).instructionEn(); }
    @Override public String evidenceCampaignId() { return "metadata-fixture-refresh"; }
    @Override public String evidenceCampaignTitle() { return "Refresh or re-import Suite metadata fixtures"; }
    @Override public com.samlscope.runner.RunCampaignQuery.ActionKind evidenceActionKind() {
        return com.samlscope.runner.RunCampaignQuery.ActionKind.METADATA_REFRESH;
    }
    @Override public List<String> evidenceActionKeys() {
        return MetadataKeySelectionComparison.required(comparisonId()).stream().sorted().toList();
    }
    @Override public CaseStep start(CaseContext context) { return fallback.start(context); }
    @Override public CaseStep resume(CaseContext context, CaseState state, CaseEvent event) {
        if (event instanceof CaseEvent.ConfigConfirmed && MetadataRoleSigningTransportEvidence.ID.equals(id())
                && !evidence.exists(context.runId())) {
            var observed=observe(context);
            if(observed.outcome()!=Outcome.NOT_VERIFIED)return new CaseStep.Finish(observed);
        }
        if (event instanceof CaseEvent.ConfigConfirmed && (evidence.exists(context.runId()) || hasNativeKeyValue(context))) {
            return new CaseStep.Finish(observe(context));
        }
        return fallback.resume(context, state, event);
    }
    private String comparisonId() { return MetadataRoleSigningTransportEvidence.ID.equals(id())
            ? MetadataKeySelectionComparison.PUBLIC_KEY : id(); }
    private boolean hasNativeKeyValue(CaseContext context) {
        return SimpleSamlPhpKeyValueRuntimeEvidence.CASES.contains(id()) && nativeKeyValue.exists(context.runId());
    }
    CaseOutcome observe(CaseContext context) {
        try {
            if (hasNativeKeyValue(context)) {
                // A present native receipt owns this path, including incomplete/invalid proof.
                // Never let a rejected native counterexample fall through to legacy evidence.
                return nativeKeyValue.evaluate(id(), context, metadata.apply(context.runId()))
                        .orElseGet(() -> CaseOutcome.notVerified("native_keyvalue_runtime_unproven",
                                "metadata.keys.runtime-keyvalue-unproven"));
            }
            if(MetadataRoleSigningTransportEvidence.ID.equals(id())) {
                var shibboleth=new ShibbolethRoleSigningTransportEvidenceFile(directory.resolveSibling("metadata-rejection-evidence"),content)
                        .evaluate(context,metadata.apply(context.runId()));
                if(shibboleth.isPresent())return shibboleth.get();
            }
            var before = evidence.receiptSha256(context.runId());
            var result = MetadataKeySelectionComparison.evaluate(comparisonId(), evidence.read(context, metadata.apply(context.runId()), content, MetadataKeySelectionComparison.required(comparisonId())), List.of());
            if (!before.equals(evidence.receiptSha256(context.runId()))) throw new IllegalArgumentException("Receipt changed during evaluation");
            var details = new LinkedHashMap<String, Object>(result.details());
            details.put("native_receipt_sha256", before);
            details.put("original_signatures_verified", true);
            if (MetadataRoleSigningTransportEvidence.ID.equals(id()) && result.outcome()!=Outcome.NOT_VERIFIED) {
                var receiptPath=evidence.receipt(context.runId());
                var receipt=new com.samlscope.store.JsonCodec().mapper().readTree(java.nio.file.Files.readAllBytes(receiptPath));
                var ref=MetadataRoleSigningTransportEvidence.verify(context,metadata.apply(context.runId()),content,receipt);
                var refs=new ArrayList<>(result.evidence());refs.add(ref);
                details.put("xml_signature_path_verified",true);details.put("tls_server_authentication","not_used");
                details.put("mutual_tls_authentication","not_used");
                var observed=result.outcome()==Outcome.SATISFIED?Outcome.SATISFIED_WITH_NOTE:result.outcome();
                var code="metadata.role-signing."+(observed==Outcome.VIOLATED?"signature-violated":"http-transport-observed");
                if(!before.equals(evidence.receiptSha256(context.runId())))throw new IllegalArgumentException("Receipt changed during transport evaluation");
                return new CaseOutcome(observed,null,code,code,List.copyOf(refs),details);
            }
            return new CaseOutcome(result.outcome(), result.notVerifiedReason(), result.reasonCode(),
                    result.reasonMessageKey(), result.evidence(), details);
        } catch (MetadataKeySelectionEvidenceFile.UnprovenEvidence unproven) {
            var result=MetadataKeySelectionComparison.evaluate(comparisonId(),List.of(),List.of(unproven.reason()));
            var details=new LinkedHashMap<String,Object>(result.details());
            details.put("unproven_variant",unproven.variant());
            return new CaseOutcome(result.outcome(),result.notVerifiedReason(),result.reasonCode(),
                    result.reasonMessageKey(),result.evidence(),details);
        } catch (Exception unproven) {
            return MetadataKeySelectionComparison.evaluate(comparisonId(), List.of(), List.of("native_key_selection_originals_unproven"));
        }
    }
    @Override public EvidenceStatus evidenceStatus(CaseContext context) {
        if (!evidence.exists(context.runId()) && !hasNativeKeyValue(context) && !MetadataRoleSigningTransportEvidence.ID.equals(id()) && fallback instanceof ProtocolEvidenceCase observer)
            return observer.evidenceStatus(context);
        var result = observe(context);
        boolean ready = result.outcome() == Outcome.SATISFIED || result.outcome() == Outcome.SATISFIED_WITH_NOTE || result.outcome() == Outcome.VIOLATED;
        return new EvidenceStatus(ready, evidenceActionKeys(), ready ? evidenceActionKeys() : List.of(), result.details());
    }
    @Override public boolean supportsRecordedEvidenceReevaluation(CaseOutcome previous) {
        return previous != null && previous.outcome() == Outcome.NOT_VERIFIED
                && Set.of("attestation.interaction-disallowed", "configuration.evidence-unavailable",
                        "metadata.keys.evidence-incomplete", "metadata.fixture-probe.incomplete").contains(previous.reasonCode());
    }
    @Override public Optional<CaseOutcome> reevaluateRecordedEvidence(CaseContext context, CaseOutcome previous) {
        if (!supportsRecordedEvidenceReevaluation(previous)) return Optional.empty();
        if (evidence.exists(context.runId()) || hasNativeKeyValue(context) || MetadataRoleSigningTransportEvidence.ID.equals(id()))
            return RecordedEvidenceReevaluation.conclusiveUpdate(previous, observe(context));
        return fallback instanceof RecordedEvidenceReevaluation observer
                ? observer.reevaluateRecordedEvidence(context,previous) : Optional.empty();
    }
}
