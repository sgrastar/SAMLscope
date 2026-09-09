package com.samlscope.api;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.samlscope.api.auth.OidcClient;
import com.samlscope.core.casedef.CaseDefinitionCatalogMapper;
import com.samlscope.core.evaluation.CoverageCatalog;
import com.samlscope.core.evaluation.CoverageCatalogMapper;
import com.samlscope.core.profile.FunctionalProfile;
import io.javalin.Javalin;
import java.security.MessageDigest;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Installs a broad synthetic IdP case set for HTTP plumbing tests; it is never a release definition. */
final class FunctionalProfileTestInstallation {
    private FunctionalProfileTestInstallation() {}

    static Javalin create(AppConfig config) {
        return create(config, null);
    }

    static Javalin create(AppConfig config, OidcClient oidcClient) {
        try {
            var documents = CatalogDocuments.load();
            var definitions = CaseDefinitionCatalogMapper.fromDocument(
                    documents.parsed("tests/cases.yaml"));
            var coverage = CoverageCatalogMapper.fromDocument(
                    documents.parsed("tests/coverage.yaml"));
            var sources = new LinkedHashMap<String,String>();
            for (var path : List.of("tests/coverage.yaml", "tests/cases.yaml", "tests/predicates.yaml")) {
                sources.put(path, digest(documents.bytes(path)));
            }
            var artifacts = new java.util.EnumMap<FunctionalProfile,byte[]>(FunctionalProfile.class);
            var pins = new java.util.EnumMap<FunctionalProfile,String>(FunctionalProfile.class);
            for (var profile : FunctionalProfile.values()) {
                var selectedCases = definitions.cases().stream()
                        .filter(value -> value.role() == profile.role())
                        .map(value -> Map.of("id", value.id(), "digest", value.caseDigest()))
                        .toList();
                var selectedNonExecutable = coverage.obligations().stream()
                        .filter(value -> value.testability() == CoverageCatalog.Testability.NOT_OBSERVABLE)
                        .filter(value -> value.roles().contains(profile.role()))
                        .map(CoverageCatalog.Obligation::key)
                        .toList();
                var document = new LinkedHashMap<String,Object>();
                document.put("schema_version", 1);
                document.put("version", "api-test-only");
                document.put("profile", profile.id());
                document.put("source_digests", sources);
                document.put("cases", selectedCases);
                document.put("non_executable_obligations", selectedNonExecutable);
                var artifact = new ObjectMapper().writeValueAsBytes(document);
                artifacts.put(profile, artifact);
                pins.put(profile, digest(artifact));
            }
            return SamlScopeApplication.create(config, oidcClient, artifacts, pins);
        } catch (Exception error) {
            throw new IllegalStateException("Could not build API functional-profile fixture", error);
        }
    }

    /** Installs the checked-in review candidates without changing the production release allowlist. */
    static Javalin createWithCandidates(AppConfig config) {
        try {
            var artifacts = new java.util.EnumMap<FunctionalProfile,byte[]>(FunctionalProfile.class);
            var pins = new java.util.EnumMap<FunctionalProfile,String>(FunctionalProfile.class);
            for (var profile : FunctionalProfile.values()) {
                try (var stream = FunctionalProfileTestInstallation.class.getResourceAsStream(
                        "/profiles/" + profile.id() + ".json")) {
                    if (stream == null) throw new IllegalStateException("Missing profile candidate: " + profile.id());
                    var artifact = stream.readAllBytes();
                    artifacts.put(profile, artifact);
                    pins.put(profile, digest(artifact));
                }
            }
            return SamlScopeApplication.create(config, null, artifacts, pins);
        } catch (Exception error) {
            throw new IllegalStateException("Could not install functional profile candidates", error);
        }
    }

    private static String digest(byte[] value) throws Exception {
        return "sha256:" + java.util.HexFormat.of().formatHex(
                MessageDigest.getInstance("SHA-256").digest(value));
    }
}
