package com.samlscope.core.profile;

/** Exact configuration identity shared by a Plan and its Runs; not proof of approval. */
public record FunctionalDefinitionIdentity(FunctionalProfile profile, String version, String digest) {
    public FunctionalDefinitionIdentity {
        if (profile == null || version == null || version.isBlank())
            throw new IllegalArgumentException("Functional profile and definition version are required");
        if (digest == null || !digest.matches("sha256:[0-9a-f]{64}"))
            throw new IllegalArgumentException("An immutable definition digest is required");
    }
}
