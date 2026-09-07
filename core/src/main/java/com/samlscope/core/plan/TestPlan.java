package com.samlscope.core.plan;

import java.net.URI;
import java.time.Instant;
import java.util.Map;
import java.util.Objects;

public record TestPlan(
        String id,
        String name,
        PlanProfile profile,
        Target target,
        MetadataDeliveryKind suiteMetadataDelivery,
        Map<String, Boolean> declaredFeatures,
        Parameters parameters,
        Interaction interaction,
        Instant createdAt,
        Instant updatedAt) {

    public TestPlan {
        requireText(id, "id");
        requireText(name, "name");
        Objects.requireNonNull(profile, "profile");
        Objects.requireNonNull(target, "target");
        Objects.requireNonNull(suiteMetadataDelivery, "suiteMetadataDelivery");
        declaredFeatures = Map.copyOf(declaredFeatures == null ? Map.of() : declaredFeatures);
        parameters = parameters == null ? Parameters.defaults() : parameters;
        interaction = interaction == null ? Interaction.defaults() : interaction;
        if (profile.role() != TargetRole.IDP && parameters.requestSigningMode() == RequestSigningMode.REQUIRED) {
            throw new IllegalArgumentException("Required AuthnRequest signing is available only for IdP test Plans");
        }
        Objects.requireNonNull(createdAt, "createdAt");
        Objects.requireNonNull(updatedAt, "updatedAt");
        if (profile.role() == TargetRole.IDP && target.kind() == TargetKind.SP) {
            throw new IllegalArgumentException("An IdP profile requires an IdP target");
        }
        if (profile.role() == TargetRole.SP && target.kind() != TargetKind.SP) {
            throw new IllegalArgumentException("An SP profile requires an SP target");
        }
    }

    public record Target(TargetKind kind, String entityId, MetadataSource metadataSource) {
        public Target {
            Objects.requireNonNull(kind, "kind");
            requireText(entityId, "target.entityId");
            Objects.requireNonNull(metadataSource, "target.metadataSource");
            URI.create(entityId);
        }
    }

    public record MetadataSource(MetadataSourceKind kind, String location) {
        public MetadataSource {
            Objects.requireNonNull(kind, "kind");
            requireText(location, "target.metadataSource.location");
            if (kind != MetadataSourceKind.UPLOAD) {
                URI.create(location);
            }
        }
    }

    public record Parameters(
            int clockSkewToleranceSeconds,
            int metadataRefreshWaitSeconds,
            String testUserHint,
            RequestSigningMode requestSigningMode) {
        public Parameters(int clockSkewToleranceSeconds, int metadataRefreshWaitSeconds, String testUserHint) {
            this(clockSkewToleranceSeconds, metadataRefreshWaitSeconds, testUserHint, RequestSigningMode.OPTIONAL);
        }

        public Parameters {
            requestSigningMode = requestSigningMode == null ? RequestSigningMode.OPTIONAL : requestSigningMode;
            if (clockSkewToleranceSeconds < 0 || metadataRefreshWaitSeconds < 1) {
                throw new IllegalArgumentException("Plan timing parameters are out of range");
            }
            testUserHint = testUserHint == null ? "" : testUserHint;
        }

        public static Parameters defaults() { return new Parameters(180, 300, ""); }
    }

    public enum RequestSigningMode { REQUIRED, OPTIONAL }

    public record Interaction(boolean allowBrowserSteps, boolean allowAttestation) {
        public static Interaction defaults() { return new Interaction(true, true); }
    }

    private static void requireText(String value, String name) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(name + " must not be blank");
        }
    }
}
