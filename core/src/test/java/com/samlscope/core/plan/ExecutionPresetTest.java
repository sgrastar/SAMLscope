package com.samlscope.core.plan;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class ExecutionPresetTest {
    @Test void quickCannotEnableOperatorEvidenceOrAttestation() {
        var interaction = new TestPlan.Interaction(true, true, TestPlan.ExecutionPreset.quick);
        assertTrue(interaction.allowBrowserSteps());
        assertFalse(interaction.allowOperatorEvidence());
        assertFalse(interaction.allowAttestation());
        assertEquals(TestPlan.ExecutionPreset.quick, TestPlan.Interaction.defaults().preset());
    }

    @Test void assistanceDoesNotImplicitlyEnableSelfAttestation() {
        var assisted = new TestPlan.Interaction(true, true, TestPlan.ExecutionPreset.assisted);
        assertTrue(assisted.allowOperatorEvidence());
        assertFalse(assisted.allowAttestation());
        assertTrue(new TestPlan.Interaction(true, true,
                TestPlan.ExecutionPreset.assisted_with_attestation).allowAttestation());
        assertFalse(new TestPlan.Interaction(true, false,
                TestPlan.ExecutionPreset.assisted_with_attestation).allowAttestation());
    }
}
