package com.samlscope.core.plan;

import static org.junit.jupiter.api.Assertions.*;
import com.samlscope.core.profile.FunctionalDefinitionIdentity;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.time.Instant;
import com.samlscope.core.profile.FunctionalProfile;
import java.util.Map;
import org.junit.jupiter.api.Test;

class TestPlanTest {
    @Test
    void rejectsRequiredAuthnRequestSigningForSpTargets() {
        var target = new TestPlan.Target(TargetKind.SP, "https://sp.example/entity",
                new TestPlan.MetadataSource(MetadataSourceKind.URL, "https://sp.example/metadata"));
        assertThrows(IllegalArgumentException.class, () -> new TestPlan("plan", "SP", FunctionalProfile.BROWSER_SSO_SP,
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
                FunctionalProfile.BROWSER_SSO_IDP,
                target,
                MetadataDeliveryKind.MANUAL,
                Map.of(),
                TestPlan.Parameters.defaults(),
                TestPlan.Interaction.defaults(),
                Instant.EPOCH,
                Instant.EPOCH));
    }
    @ParameterizedTest
    @EnumSource(FunctionalProfile.class)
    void fixesExactDefinitionAndSharedMetadataForEveryProfile(FunctionalProfile profile) {
        var target = new TestPlan.Target(profile.role() == TargetRole.IDP ? TargetKind.IDP : TargetKind.SP,
                "urn:fixture:target",new TestPlan.MetadataSource(MetadataSourceKind.SNAPSHOT_BASE64,"PHgvPg=="),
                "shared-target","immutable-revision");
        var identity = new FunctionalDefinitionIdentity(profile,"definition-v1","sha256:" + "a".repeat(64));
        var plan = new TestPlan("plan","Name",profile,identity,target,MetadataDeliveryKind.MANUAL,Map.of(),
                TestPlan.Parameters.defaults(),TestPlan.Interaction.defaults(),Instant.EPOCH,Instant.EPOCH);
        var renamed = new TestPlan("plan","Renamed",profile,identity,target,MetadataDeliveryKind.MANUAL,Map.of(),
                TestPlan.Parameters.defaults(),TestPlan.Interaction.defaults(),Instant.EPOCH,Instant.EPOCH.plusSeconds(1));
        assertTrue(plan.sameExecutionConfiguration(renamed));
        assertEquals("shared-target",plan.target().connectionId());
        var changedDefinition = new TestPlan("plan","Name",profile,
                new FunctionalDefinitionIdentity(profile,"definition-v2","sha256:" + "b".repeat(64)),
                target,MetadataDeliveryKind.MANUAL,Map.of(),TestPlan.Parameters.defaults(),
                TestPlan.Interaction.defaults(),Instant.EPOCH,Instant.EPOCH);
        assertFalse(plan.sameExecutionConfiguration(changedDefinition));
        for (var other : FunctionalProfile.values()) {
            if (other == profile) continue;
            var wrong = new FunctionalDefinitionIdentity(other,"definition-v1","sha256:" + "a".repeat(64));
            assertThrows(IllegalArgumentException.class,() -> new TestPlan("plan","Name",profile,wrong,target,
                    MetadataDeliveryKind.MANUAL,Map.of(),TestPlan.Parameters.defaults(),
                    TestPlan.Interaction.defaults(),Instant.EPOCH,Instant.EPOCH));
        }
    }

}
