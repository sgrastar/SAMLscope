package com.samlscope.runner;

import java.util.Objects;
import com.samlscope.runner.cases.ProtocolEvidenceCase;

/** Resumes the shared configuration branch using a fixed answer vocabulary. */
public final class ConfigurationService implements ConfigurationExecutor {
    private final TestCaseRegistry registry;
    private final CaseExecutionService executions;
    private final CaseContextProvider contexts;

    public ConfigurationService(
            TestCaseRegistry registry,
            CaseExecutionService executions,
            CaseContextProvider contexts) {
        this.registry = Objects.requireNonNull(registry, "registry");
        this.executions = Objects.requireNonNull(executions, "executions");
        this.contexts = Objects.requireNonNull(contexts, "contexts");
    }

    @Override
    public Result answer(String runId, String caseId, String value, String note) {
        text(runId, "runId");
        text(caseId, "caseId");
        var testCase = registry.require(caseId);
        var answer = ConfigurationAnswer.parse(value);
        if (testCase instanceof ProtocolEvidenceCase protocol && !protocol.requiresPreparationConfirmation() && answer == ConfigurationAnswer.CONFIRMED) {
            throw new IllegalStateException(
                    "Transcript-driven configuration cases cannot be confirmed by an operator");
        }
        var event = answer.event(note);
        var execution = executions.resume(
                runId, testCase, contexts.contextFor(runId), event);
        return new Result(runId, caseId, execution.status(), execution.outcome());
    }

    private static void text(String value, String name) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(name + " must not be blank");
        }
    }
}
