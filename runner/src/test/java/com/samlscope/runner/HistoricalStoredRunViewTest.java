package com.samlscope.runner;

import static org.junit.jupiter.api.Assertions.*;
import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.*;
import java.time.Instant;
import java.util.*;
import org.junit.jupiter.api.Test;

class HistoricalStoredRunViewTest {
    static final String RUN="run_0123456789ABCDEFGHJKMNPQRS";
    @Test void retiredCaseAndSecretInternalStateCannotTriggerCurrentLookupOrPublicStateExport() {
        var old = execution(RUN,"retired-old-case",CaseExecutionStatus.FINISHED,
                CaseOutcome.notVerified("old_scope_held","old-hold"));
        var view=HistoricalStoredRunView.from(RUN,List.of(old));
        assertEquals("retired-old-case",view.slots().getFirst().caseId());
        assertEquals("NOT_VERIFIED",view.slots().getFirst().storedOutcome());
        assertFalse(view.toString().contains("owned-secret-state-sentinel"));
        var status=view.activeStatus("plan_owned","Stored state only");
        assertEquals(ActiveProbeCoordinator.State.FINISHED,status.state()); assertNull(status.actionId());assertNull(status.startUrl());assertNull(status.outcome());
    }
    @Test void queuedAndEmptyHistoricalViewsNeverActivateOutboxOrInventCaseMembership() {
        var queued=execution(RUN,"unavailable-old-queued-case",CaseExecutionStatus.RUNNING,null);
        var view=HistoricalStoredRunView.from(RUN,List.of(queued));
        assertEquals(ActiveProbeCoordinator.State.UNAVAILABLE,view.activeStatus("plan_owned","Stored only").state());
        var empty=HistoricalStoredRunView.from(RUN,List.of());
        assertEquals(ActiveProbeCoordinator.State.NOT_STARTED,empty.activeStatus("plan_owned","Stored only").state());
        assertTrue(empty.slots().isEmpty());
    }
    @Test void duplicateAndForeignPhysicalRowsAreRejected() {
        var owned=execution(RUN,"old",CaseExecutionStatus.RUNNING,null);
        assertThrows(IllegalArgumentException.class,()->HistoricalStoredRunView.from(RUN,List.of(owned,owned)));
        assertThrows(IllegalArgumentException.class,()->HistoricalStoredRunView.from(RUN,List.of(execution("run_1123456789ABCDEFGHJKMNPQRS","old",CaseExecutionStatus.RUNNING,null))));
    }
    static CaseExecution execution(String run,String id,CaseExecutionStatus status,CaseOutcome outcome) {
        return new CaseExecution(run,id,1,status,new CaseState("stored",Map.of("internal","owned-secret-state-sentinel")),null,outcome,Instant.EPOCH);
    }
}
