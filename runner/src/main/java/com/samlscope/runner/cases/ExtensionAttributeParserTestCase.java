package com.samlscope.runner.cases;

import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.plan.TargetRole;
import com.samlscope.core.transcript.TranscriptContentReader;
import com.samlscope.runner.*;
import java.nio.file.Path;
import java.util.*;
import java.util.function.Function;

/** Supplemental original-backed parser evidence, retaining the approved browser scenario. */
public final class ExtensionAttributeParserTestCase implements TestCase, BrowserFrontChannelScenario,
        BrowserPrompt, ProtocolEvidenceCase, RecordedEvidenceReevaluation {
    private static final List<String> REQUIRED = List.of("three-active-attribute-fixtures", "twelve-metadata-attribute-fixtures",
            "normal-metadata-control", "native-affiliation-parser-control", "complete-original-history");
    private final TestCase fallback;
    private final BrowserFrontChannelScenario browser;
    private final ExtensionAttributeParserEvidence evidence;
    private final Function<String,byte[]> metadata;
    public static TestCase wrap(TestCase fallback, TranscriptContentReader content,
            Function<String,byte[]> metadata, Path directory) {
        return new ExtensionAttributeParserTestCase(fallback, content, metadata, directory);
    }
    public ExtensionAttributeParserTestCase(TestCase fallback, TranscriptContentReader content,
            Function<String,byte[]> metadata, Path directory) {
        this.fallback = Objects.requireNonNull(fallback);
        if (!ExtensionAttributeParserEvidence.ID.equals(fallback.id()) || fallback.role() != TargetRole.IDP
                || !(fallback instanceof BrowserFrontChannelScenario scenario)
                || !(fallback instanceof BrowserPrompt) || !(fallback instanceof ProtocolEvidenceCase)
                || !(fallback instanceof RecordedEvidenceReevaluation))
            throw new IllegalArgumentException("Approved extension attribute browser case required");
        browser = scenario; this.metadata = Objects.requireNonNull(metadata);
        evidence = new ExtensionAttributeParserEvidence(directory, content);
    }
    @Override public String id() { return fallback.id(); }
    @Override public TargetRole role() { return fallback.role(); }
    @Override public String browserInstructionsEn() { return ((BrowserPrompt) fallback).browserInstructionsEn(); }
    @Override public String instructionsEn(CaseState state) { return browser.instructionsEn(state); }
    @Override public Binding outboundBinding(CaseState state) { return browser.outboundBinding(state); }
    @Override public boolean requiresFreshSession(CaseState state) { return browser.requiresFreshSession(state); }
    @Override public boolean plansFreshSessionBoundary() { return browser.plansFreshSessionBoundary(); }
    @Override public int plannedDeliberateActions() { return browser.plannedDeliberateActions(); }
    @Override public String evidenceCampaignId() { return browser.evidenceCampaignId(); }
    @Override public String evidenceCampaignTitle() { return browser.evidenceCampaignTitle(); }
    @Override public RunCampaignQuery.ActionKind evidenceActionKind() { return browser.evidenceActionKind(); }
    @Override public RunCampaignQuery.ActionKind evidenceActionKind(CaseExecution execution) { return browser.evidenceActionKind(execution); }
    @Override public boolean sharesDeliberateAction() { return browser.sharesDeliberateAction(); }
    @Override public List<String> evidenceActionKeys() { return browser.evidenceActionKeys(); }
    @Override public List<EvidenceCampaignCase> supplementalEvidenceCampaigns() { return browser.supplementalEvidenceCampaigns(); }
    @Override public CaseStep start(CaseContext context) { return fallback.start(context); }
    @Override public CaseStep resume(CaseContext context, CaseState state, CaseEvent event) {
        return fallback.resume(context, state, event);
    }
    private Optional<CaseOutcome> observe(CaseContext context) {
        if (!evidence.exists(context.runId())) return Optional.empty();
        try { return Optional.of(evidence.evaluate(context, metadata.apply(context.runId()))); }
        catch (RuntimeException unavailable) {
            return Optional.of(CaseOutcome.notVerified("extension_attribute_parser_original_unproven", "browser_fixture_partial"));
        }
    }
    @Override public EvidenceStatus evidenceStatus(CaseContext context) {
        var observed = observe(context);
        if (observed.isEmpty()) return ((ProtocolEvidenceCase) fallback).evidenceStatus(context);
        boolean ready = observed.get().outcome() == Outcome.SATISFIED;
        return new EvidenceStatus(ready, REQUIRED, ready ? REQUIRED : List.of(), observed.get().details());
    }
    @Override public boolean requiresPreparationConfirmation() { return ((ProtocolEvidenceCase) fallback).requiresPreparationConfirmation(); }
    @Override public boolean supportsRecordedEvidenceReevaluation(CaseOutcome previous) {
        return previous != null && previous.outcome() == Outcome.NOT_VERIFIED && "browser_fixture_partial".equals(previous.reasonCode());
    }
    @Override public Optional<CaseOutcome> reevaluateRecordedEvidence(CaseContext context, CaseOutcome previous) {
        if (!supportsRecordedEvidenceReevaluation(previous) || !context.transcriptComplete()) return Optional.empty();
        var observed = observe(context);
        if (observed.isPresent()) return RecordedEvidenceReevaluation.conclusiveUpdate(previous, observed.get());
        return ((RecordedEvidenceReevaluation) fallback).reevaluateRecordedEvidence(context, previous);
    }
}
