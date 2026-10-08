package com.samlscope.runner;

import com.samlscope.core.caseexec.*;
import com.samlscope.runner.cases.AdditionalMetadataLocationConfigurationTestCase;
import com.samlscope.runner.outbox.OutboundDispatcher;
import java.util.*;

/** Pumps already persisted a8 GET intents; it supplies no operator answer or target outcome. */
public final class MetadataFetchAutomationService {
    private final CaseExecutionRepository executions;
    private final TestCaseRegistry registry;
    private final OutboundDispatcher dispatcher;
    private final CaseContextProvider contexts;
    public MetadataFetchAutomationService(CaseExecutionRepository executions, TestCaseRegistry registry,
            OutboundDispatcher dispatcher, CaseContextProvider contexts) {
        this.executions = Objects.requireNonNull(executions); this.registry = Objects.requireNonNull(registry);
        this.dispatcher = Objects.requireNonNull(dispatcher); this.contexts = Objects.requireNonNull(contexts);
    }
    public synchronized CollectionResult collect(String runId) {
        var context = contexts.contextFor(runId);
        if (context == null || !runId.equals(context.runId())) throw new IllegalArgumentException("Another Run context");
        var sent = new ArrayList<String>(); var uncertain = new ArrayList<String>(); var blocked = new ArrayList<String>();
        for (var execution : executions.list(runId)) {
            var candidate = registry.find(execution.caseId()).orElse(null);
            if (!(candidate instanceof AdditionalMetadataLocationConfigurationTestCase testCase)
                    || execution.status() != CaseExecutionStatus.WAITING_CONFIG || execution.waitCondition() == null
                    || !context.transcriptComplete() || context.clock().instant().isAfter(execution.waitCondition().expiresAt())) continue;
            for (var entry : executions.listOutbox(runId)) {
                if (!testCase.ownsAction(context, execution, entry) || entry.status() == OutboxStatus.SENT
                        || entry.status() == OutboxStatus.SENDING || entry.status() == OutboxStatus.BLOCKED_ON_CREDENTIAL) continue;
                try {
                    var dispatched = dispatcher.dispatch(entry.action().actionId());
                    if (dispatched.state() == OutboundDispatcher.State.SENT) sent.add(entry.action().actionId());
                    else uncertain.add(entry.action().actionId());
                } catch (IllegalArgumentException policyBlocked) { blocked.add(entry.action().actionId()); }
            }
            testCase.produceControls(context);
        }
        return new CollectionResult(sent, uncertain, blocked);
    }
    public record CollectionResult(List<String> sent, List<String> uncertain, List<String> policyBlocked) {
        public CollectionResult { sent = List.copyOf(sent); uncertain = List.copyOf(uncertain); policyBlocked = List.copyOf(policyBlocked); }
    }
}
