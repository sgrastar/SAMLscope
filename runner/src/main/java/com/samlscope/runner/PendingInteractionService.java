package com.samlscope.runner;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import com.samlscope.core.caseexec.CaseExecutionRepository;
import com.samlscope.core.caseexec.CaseExecutionStatus;
import com.samlscope.runner.cases.AttestationPrompt;
import com.samlscope.runner.cases.ConfigurationPrompt;
import com.samlscope.runner.cases.BrowserPrompt;
import com.samlscope.runner.cases.ProtocolEvidenceCase;

/** Projects persisted user waits without exposing restart state or any client-writable outcome. */
public final class PendingInteractionService implements InteractionQuery {
    private static final List<String> CONFIGURATION_ANSWERS = List.of(
            "confirmed", "capability_absent", "target_config_unavailable", "capability_undetermined");
    private static final List<String> PROTOCOL_UNAVAILABILITY_ANSWERS = List.of(
            "capability_absent", "target_config_unavailable", "capability_undetermined");

    private final CaseExecutionRepository executions;
    private final TestCaseRegistry registry;

    public PendingInteractionService(CaseExecutionRepository executions, TestCaseRegistry registry) {
        this.executions = Objects.requireNonNull(executions, "executions");
        this.registry = Objects.requireNonNull(registry, "registry");
    }

    @Override
    public List<PendingInteraction> pending(String runId) {
        if (runId == null || runId.isBlank()) throw new IllegalArgumentException("runId must not be blank");
        var result = new ArrayList<PendingInteraction>();
        for (var execution : executions.list(runId)) {
            // Old Runs may retain a browser wait after the evidence-only implementation
            // replaces its former scenario. That wait cannot collect useful user input.
            if (registry.find(execution.caseId()).orElse(null)
                    instanceof com.samlscope.runner.cases.InteractionFreeEvidenceCase) continue;
            var wait = execution.waitCondition();
            if (execution.status() == CaseExecutionStatus.WAITING_BROWSER) {
                var testCase = registry.require(execution.caseId());
                if (!(testCase instanceof BrowserPrompt browser)) {
                    throw new IllegalStateException(
                            "Browser case does not expose server-defined instructions: " + execution.caseId());
                }
                var completionMode = testCase instanceof ProtocolEvidenceCase
                        ? CompletionMode.TRANSCRIPT : CompletionMode.OPERATOR;
                result.add(new PendingInteraction(
                        execution.caseId(), Kind.BROWSER, null, browser.browserInstructionsEn(),
                        wait.startUrl(), wait.expiresAt(),
                        completionMode == CompletionMode.TRANSCRIPT
                                ? List.of() : List.of("completed"),
                        completionMode));
            } else if (execution.status() == CaseExecutionStatus.WAITING_CONFIG) {
                var testCase = registry.require(execution.caseId());
                if (!(testCase instanceof ConfigurationPrompt configuration)) {
                    throw new IllegalStateException(
                            "Configuration case does not expose server-defined instructions: " + execution.caseId());
                }
                result.add(new PendingInteraction(
                        execution.caseId(), Kind.CONFIGURATION, wait.promptKey(), configuration.instructionEn(),
                        null, wait.expiresAt(),
                        testCase instanceof ProtocolEvidenceCase protocol && !protocol.requiresPreparationConfirmation()
                                ? PROTOCOL_UNAVAILABILITY_ANSWERS : CONFIGURATION_ANSWERS,
                        testCase instanceof ProtocolEvidenceCase
                                ? CompletionMode.TRANSCRIPT_OR_OPERATOR : CompletionMode.OPERATOR));
            } else if (execution.status() == CaseExecutionStatus.WAITING_ATTESTATION) {
                var testCase = registry.require(execution.caseId());
                if (!(testCase instanceof AttestationPrompt attested)) {
                    throw new IllegalStateException(
                            "Attestation case does not expose server-defined options: " + execution.caseId());
                }
                result.add(new PendingInteraction(
                        execution.caseId(), Kind.ATTESTATION, wait.promptKey(), attested.promptEn(),
                        null, wait.expiresAt(),
                        attested.options().stream().map(option -> option.value()).toList(),
                        CompletionMode.OPERATOR));
            }
        }
        return List.copyOf(result);
    }
}
