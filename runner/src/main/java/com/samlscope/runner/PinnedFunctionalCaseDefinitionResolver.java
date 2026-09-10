package com.samlscope.runner;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.samlscope.core.casedef.CaseDefinitionCatalog;
import com.samlscope.core.evaluation.CoverageCatalog;
import com.samlscope.core.profile.FunctionalCaseDefinition;
import com.samlscope.core.profile.FunctionalCaseDefinitionLoader;
import com.samlscope.core.profile.FunctionalDefinitionIdentity;
import com.samlscope.core.profile.FunctionalProfile;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.EnumMap;
import java.util.HexFormat;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/** Resolves only release-pinned case-set definitions. It does not confer approval. */
public final class PinnedFunctionalCaseDefinitionResolver {
    private final Map<FunctionalProfile,Release> releases;

    public PinnedFunctionalCaseDefinitionResolver(
            Map<FunctionalProfile,byte[]> artifacts,
            Map<FunctionalProfile,String> approvedArtifactDigests,
            Map<String,byte[]> sourceDocuments,
            CaseDefinitionCatalog approvedCases,
            CoverageCatalog coverage) {
        Objects.requireNonNull(artifacts, "artifacts");
        Objects.requireNonNull(approvedArtifactDigests, "approvedArtifactDigests");
        if (!artifacts.keySet().equals(approvedArtifactDigests.keySet())) {
            throw new IllegalArgumentException("Installed definitions and release pins differ");
        }
        var loaded = new EnumMap<FunctionalProfile,Release>(FunctionalProfile.class);
        artifacts.forEach((profile, bytes) -> {
            var snapshot = Objects.requireNonNull(bytes, "definition artifact").clone();
            var artifactDigest = digest(snapshot);
            if (!artifactDigest.equals(approvedArtifactDigests.get(profile))) {
                throw new IllegalArgumentException("Functional definition artifact digest mismatch: " + profile.id());
            }
            var document = parse(snapshot);
            var definition = FunctionalCaseDefinitionLoader.load(document, sourceDocuments, approvedCases, coverage);
            if (definition.profile() != profile) {
                throw new IllegalArgumentException("Functional definition installed for another profile");
            }
            loaded.put(profile, new Release(definition, artifactDigest));
        });
        releases = Map.copyOf(loaded);
    }

    public Set<FunctionalProfile> profiles() { return releases.keySet(); }

    public FunctionalDefinitionIdentity identity(FunctionalProfile profile) {
        var release = require(profile);
        return new FunctionalDefinitionIdentity(profile, release.definition().version(), release.artifactDigest());
    }

    public FunctionalCaseDefinition resolve(FunctionalDefinitionIdentity identity) {
        Objects.requireNonNull(identity, "identity");
        var release = require(identity.profile());
        if (!release.definition().version().equals(identity.version())
                || !release.artifactDigest().equals(identity.digest())) {
            throw new IllegalArgumentException("Requested functional definition is unavailable");
        }
        return release.definition();
    }

    private Release require(FunctionalProfile profile) {
        var release = releases.get(profile);
        if (release == null) throw new IllegalArgumentException("Functional profile is not installed");
        return release;
    }

    private static Map<String,Object> parse(byte[] document) {
        try {
            return new ObjectMapper()
                    .enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION)
                    .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS)
                    .readValue(document, new TypeReference<Map<String,Object>>() {});
        } catch (IOException invalid) {
            throw new IllegalArgumentException("Invalid functional definition JSON", invalid);
        }
    }

    private static String digest(byte[] bytes) {
        try {
            return "sha256:" + HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException(impossible);
        }
    }

    private record Release(FunctionalCaseDefinition definition, String artifactDigest) {}
}
