package com.samlscope.core.profile;

import com.samlscope.core.casedef.CaseDefinitionCatalog;
import com.samlscope.core.evaluation.CoverageCatalog;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Strict loader for a release-pinned case-set definition. */
public final class FunctionalCaseDefinitionLoader {
    private FunctionalCaseDefinitionLoader() {}

    public static FunctionalCaseDefinition load(
            Map<String, ?> document,
            Map<String, byte[]> sourceDocuments,
            CaseDefinitionCatalog approvedCases,
            CoverageCatalog coverage) {
        fields(document, Set.of("schema_version", "version", "profile", "source_digests", "cases",
                "non_executable_obligations"));
        if (!Integer.valueOf(1).equals(document.get("schema_version"))) {
            throw new IllegalArgumentException("Unsupported functional case definition schema");
        }
        var digests = object(document.get("source_digests"));
        if (!digests.keySet().equals(sourceDocuments.keySet())
                || !digests.keySet().containsAll(Set.of("tests/coverage.yaml", "tests/cases.yaml"))) {
            throw new IllegalArgumentException("Definition source inventory mismatch");
        }
        var verifiedDigests = new LinkedHashMap<String, String>();
        digests.forEach((path, expectedValue) -> {
            var expected = text(expectedValue);
            var actual = "sha256:" + sha256(sourceDocuments.get(path));
            if (!actual.equals(expected)) throw new IllegalArgumentException("Definition source digest mismatch: " + path);
            verifiedDigests.put(path, expected);
        });

        var references = new ArrayList<FunctionalCaseDefinition.CaseReference>();
        for (var value : list(document.get("cases"))) {
            var entry = object(value);
            fields(entry, Set.of("id", "digest"));
            references.add(new FunctionalCaseDefinition.CaseReference(text(entry.get("id")), text(entry.get("digest"))));
        }
        var nonExecutable = new LinkedHashSet<String>();
        for (var value : list(document.get("non_executable_obligations"))) {
            if (!nonExecutable.add(text(value))) throw new IllegalArgumentException("Duplicate non-executable obligation");
        }
        return new FunctionalCaseDefinition(
                text(document.get("version")),
                FunctionalProfile.fromId(text(document.get("profile"))),
                verifiedDigests,
                references,
                nonExecutable,
                approvedCases,
                coverage);
    }

    private static void fields(Map<String, ?> value, Set<String> allowed) {
        if (!allowed.equals(value.keySet())) throw new IllegalArgumentException("Definition fields do not match schema");
    }
    private static String text(Object value) {
        if (!(value instanceof String text) || text.isBlank()) throw new IllegalArgumentException("Expected definition text");
        return text;
    }
    private static List<?> list(Object value) {
        if (!(value instanceof List<?> values)) throw new IllegalArgumentException("Expected definition list");
        return values;
    }
    private static Map<String, ?> object(Object value) {
        if (!(value instanceof Map<?, ?> map)) throw new IllegalArgumentException("Expected definition object");
        var result = new LinkedHashMap<String, Object>();
        map.forEach((key, item) -> result.put(text(key), item));
        return result;
    }
    private static String sha256(byte[] bytes) {
        if (bytes == null) throw new IllegalArgumentException("Missing definition source document");
        try { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes)); }
        catch (NoSuchAlgorithmException impossible) { throw new IllegalStateException(impossible); }
    }
}
