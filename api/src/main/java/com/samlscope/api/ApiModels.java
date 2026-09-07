package com.samlscope.api;

import java.util.Map;
import com.samlscope.core.plan.MetadataDeliveryKind;
import com.samlscope.core.plan.MetadataSourceKind;
import com.samlscope.core.plan.PlanProfile;
import com.samlscope.core.plan.TargetKind;
import com.samlscope.core.plan.TestPlan;

final class ApiModels {
    private ApiModels() {}

    record PlanWrite(
            String name,
            PlanProfile profile,
            TargetKind targetKind,
            String targetEntityId,
            MetadataSourceKind metadataSourceKind,
            String metadataSourceLocation,
            MetadataDeliveryKind suiteMetadataDelivery,
            Map<String, Boolean> declaredFeatures,
            TestPlan.Parameters parameters,
            TestPlan.Interaction interaction,
            boolean authorizedTarget) {}

    record PlanView(
            PlanSummary plan,
            String entityId,
            String metadataUrl,
            String mdqUrl,
            String secondaryIdpEntityId,
            String secondaryIdpMetadataUrl) {}
    record PlanSummary(String id, String name, PlanProfile profile, TargetSummary target,
            TestPlan.RequestSigningMode requestSigningMode) {}
    record TargetSummary(TargetKind kind, String entityId) {}
    record PlanCreated(PlanView plan, RunCreated initialRun) {}
    record RunCreated(com.samlscope.core.run.TestRun run, String managementUrl) {}
    record ErrorView(String error, String message) {}
}
