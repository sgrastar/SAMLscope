package com.samlscope.core.plan;

/** Existing Run evidence fixes every execution-relevant Plan field. */
public final class PlanConfigurationConflict extends IllegalArgumentException {
    public PlanConfigurationConflict() {
        super("This Plan has Run history. Create a new Plan to change its test configuration.");
    }
}
