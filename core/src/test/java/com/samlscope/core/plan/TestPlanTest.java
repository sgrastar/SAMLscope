package com.samlscope.core.plan;

import static org.junit.jupiter.api.Assertions.assertThrows;

import java.time.Instant;
import java.util.Map;
import org.junit.jupiter.api.Test;

class TestPlanTest {
    @Test
    void rejectsRequiredAuthnRequestSigningForSpTargets() {
        var target = new TestPlan.Target(TargetKind.SP, "https://sp.example/entity",
                new TestPlan.MetadataSource(MetadataSourceKind.URL, "https://sp.example/metadata"));
        assertThrows(IllegalArgumentException.class, () -> new TestPlan("plan", "SP", PlanProfile.SP_CORE,
                target, MetadataDeliveryKind.MANUAL, Map.of(),
                new TestPlan.Parameters(180, 300, "", TestPlan.RequestSigningMode.REQUIRED),
                TestPlan.Interaction.defaults(), Instant.EPOCH, Instant.EPOCH));
    }

    @Test
    void rejectsRoleMismatch() {
        var target = new TestPlan.Target(
                TargetKind.SP,
                "https://sp.example/entity",
                new TestPlan.MetadataSource(MetadataSourceKind.URL, "https://sp.example/metadata"));

        assertThrows(IllegalArgumentException.class, () -> new TestPlan(
                "plan_0123456789ABCDEFGHJKMNPQRS",
                "Wrong role",
                PlanProfile.IDP_CORE,
                target,
                MetadataDeliveryKind.MANUAL,
                Map.of(),
                TestPlan.Parameters.defaults(),
                TestPlan.Interaction.defaults(),
                Instant.EPOCH,
                Instant.EPOCH));
    }
}
