package com.samlscope.saml;

import java.time.Instant;
import java.util.Map;
import com.samlscope.core.plan.MetadataDeliveryKind;
import com.samlscope.core.plan.MetadataSourceKind;
import com.samlscope.core.profile.FunctionalProfile;
import com.samlscope.core.plan.TargetKind;
import com.samlscope.core.plan.TestPlan;

public final class SamlTestFixtures {
    private SamlTestFixtures() {}

    public static TestPlan idpPlan() {
        var now = Instant.parse("2026-08-29T00:00:00Z");
        return new TestPlan("plan_0123456789ABCDEFGHJKMNPQRS", "IdP", FunctionalProfile.BROWSER_SSO_IDP,
                new TestPlan.Target(TargetKind.IDP, "https://idp.example/entity",
                        new TestPlan.MetadataSource(MetadataSourceKind.URL, "https://idp.example/metadata")),
                MetadataDeliveryKind.HTTP_URL, Map.of(), TestPlan.Parameters.defaults(),
                TestPlan.Interaction.defaults(), now, now);
    }
}
