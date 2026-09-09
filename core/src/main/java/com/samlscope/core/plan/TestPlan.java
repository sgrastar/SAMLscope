package com.samlscope.core.plan;

import java.net.URI;
import com.samlscope.core.profile.FunctionalProfile;
import com.samlscope.core.profile.FunctionalDefinitionIdentity;
import java.time.Instant;
import java.util.Map;
import java.util.Objects;

public record TestPlan(
        String id,
        String name,
        FunctionalProfile profile,
        FunctionalDefinitionIdentity definitionIdentity,
        Target target,
        MetadataDeliveryKind suiteMetadataDelivery,
        Map<String, Boolean> declaredFeatures,
        Parameters parameters,
        Interaction interaction,
        Instant createdAt,
        Instant updatedAt) {

    public TestPlan(String id, String name, FunctionalProfile profile, Target target,
            MetadataDeliveryKind suiteMetadataDelivery, Map<String, Boolean> declaredFeatures,
            Parameters parameters, Interaction interaction, Instant createdAt, Instant updatedAt) {
        this(id,name,profile,null,target,suiteMetadataDelivery,declaredFeatures,parameters,interaction,createdAt,updatedAt);
    }

    public TestPlan {
        requireText(id, "id");
        requireText(name, "name");
        Objects.requireNonNull(profile, "profile");
        if (definitionIdentity != null && definitionIdentity.profile() != profile)
            throw new IllegalArgumentException("Plan profile does not match its definition");
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

    public record Target(TargetKind kind, String entityId, MetadataSource metadataSource,
                         String connectionId, String metadataRevisionId) {
        public Target(TargetKind kind, String entityId, MetadataSource metadataSource) {
            this(kind, entityId, metadataSource, null, null);
        }
        public Target {
            Objects.requireNonNull(kind, "kind");
            requireText(entityId, "target.entityId");
            Objects.requireNonNull(metadataSource, "target.metadataSource");
            URI.create(entityId);
            if ((connectionId == null) != (metadataRevisionId == null)) {
                throw new IllegalArgumentException("Connection and revision references must be supplied together");
            }
            if (connectionId == null && metadataSource.kind() == MetadataSourceKind.SNAPSHOT_BASE64)
                throw new IllegalArgumentException("Metadata snapshot requires connection and revision references");
            if (connectionId != null) {
                requireText(connectionId, "connectionId");
                requireText(metadataRevisionId, "metadataRevisionId");
                if (metadataSource.kind() != MetadataSourceKind.SNAPSHOT_BASE64) {
                    throw new IllegalArgumentException("Reusable metadata must be a fixed snapshot");
                }
            }
        }
    }

    /** Fields that determine execution and evidence provenance; display names are not configuration. */
    public boolean sameExecutionConfiguration(TestPlan other) {
        return other != null && profile == other.profile && Objects.equals(definitionIdentity,other.definitionIdentity) && target.equals(other.target)
                && suiteMetadataDelivery == other.suiteMetadataDelivery
                && declaredFeatures.equals(other.declaredFeatures) && parameters.equals(other.parameters)
                && interaction.equals(other.interaction);
    }

    public record MetadataSource(MetadataSourceKind kind, String location) {
        public MetadataSource {
            Objects.requireNonNull(kind, "kind");
            requireText(location, "target.metadataSource.location");
            if (kind == MetadataSourceKind.SNAPSHOT_BASE64 && java.util.Base64.getDecoder().decode(location).length == 0)
                throw new IllegalArgumentException("Metadata snapshot is empty");
            if (kind != MetadataSourceKind.UPLOAD && kind != MetadataSourceKind.SNAPSHOT_BASE64) {
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

    /** Assistance changes input availability, never the profile membership or denominator. */
    public enum ExecutionPreset { quick, assisted, assisted_with_attestation }

    public record Interaction(boolean allowBrowserSteps, boolean allowAttestation, ExecutionPreset preset) {
        public Interaction(boolean allowBrowserSteps, boolean allowAttestation) {
            this(allowBrowserSteps, allowAttestation,
                    allowAttestation ? ExecutionPreset.assisted_with_attestation : ExecutionPreset.assisted);
        }
        public Interaction {
            preset = preset == null ? ExecutionPreset.quick : preset;
            allowAttestation = allowAttestation && preset == ExecutionPreset.assisted_with_attestation;
        }
        public boolean allowOperatorEvidence() { return preset != ExecutionPreset.quick; }
        public static Interaction defaults() { return new Interaction(true, false, ExecutionPreset.quick); }
    }

    private static void requireText(String value, String name) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(name + " must not be blank");
        }
    }
}
