package com.samlscope.api;

import static com.samlscope.api.ReplayOwnedKeycloakNameIdAcceptance.*;
import static com.samlscope.api.ReadSyntheticArtifactRuntime.*;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;

/** Loader controls derived from one immutable public campaign, in an owned temporary directory.
 * Original files are copied only for bounded corruption tests; no live state is queried. */
public final class OwnedKeycloakNameIdReplayControls {
    static final List<Map<String,Object>> CHECKS = new ArrayList<>();
    interface Check { void run() throws Exception; }
    interface Mutation { void apply(ObjectNode runtime, ObjectNode manifest); }

    public static void main(String[] args) throws Exception {
        require(args.length == 2, "Usage: <runtime.json> <portable/manifest.json>");
        var actual = load(Path.of(args[0]), Path.of(args[1]));
        Path directory = Files.createTempDirectory(Path.of("build"), "owned-nameid-replay-controls-").toAbsolutePath();
        Path portable = Files.createDirectory(directory.resolve("portable")); Path runtime = directory.resolve("runtime.json"), manifest = portable.resolve("manifest.json");
        try {
            for (var file : actual.physical()) Files.copy(Path.of(args[1]).toAbsolutePath().getParent().resolve((String) file.get("file")), portable.resolve((String) file.get("file")));
            write(runtime, actual.runtime()); write(manifest, actual.manifest()); load(runtime, manifest); accepted("physical-public-originals-baseline");
            mutation(actual, runtime, manifest, "foreign-runtime-run", (r,m) -> r.put("runId", "run_00000000000000000000000000"));
            mutation(actual, runtime, manifest, "foreign-runtime-plan", (r,m) -> r.put("planId", "plan_00000000000000000000000000"));
            mutation(actual, runtime, manifest, "foreign-case-digest", (r,m) -> r.put("caseDigest", "sha256:" + "0".repeat(64)));
            mutation(actual, runtime, manifest, "foreign-profile-digest", (r,m) -> ((ObjectNode) r.get("definitionIdentity")).put("digest", "sha256:" + "0".repeat(64)));
            mutation(actual, runtime, manifest, "false-native-verified-token", (r,m) -> r.put("qualificationOutcome", "NOT_VERIFIED"));
            mutation(actual, runtime, manifest, "false-native-canonical-adoption", (r,m) -> r.put("canonicalAdoption", true));
            mutation(actual, runtime, manifest, "false-browser-byte-equality", (r,m) -> m.put("browserByteEqualityClaimed", true));
            mutation(actual, runtime, manifest, "false-browser-original-availability", (r,m) -> m.put("browserOriginalsAvailable", true));
            mutation(actual, runtime, manifest, "foreign-manifest-run", (r,m) -> m.put("runId", "run_00000000000000000000000000"));
            mutation(actual, runtime, manifest, "duplicate-original-row", (r,m) -> ((ObjectNode) r.get("transcriptOriginals").get(1)).put("id", r.get("transcriptOriginals").get(0).get("id").textValue()));
            mutation(actual, runtime, manifest, "foreign-original-run", (r,m) -> ((ObjectNode) r.get("transcriptOriginals").get(0)).put("runId", "run_00000000000000000000000000"));
            mutation(actual, runtime, manifest, "foreign-native-physical-reference", (r,m) -> ((ObjectNode) r.get("transcriptOriginals").get(0)).put("decodedSamlRef", "transcripts/foreign/row.saml.xml"));
            mutation(actual, runtime, manifest, "exported-header-not-in-public-schema", (r,m) -> ((ObjectNode) r.get("transcriptOriginals").get(0)).putObject("headers").put("Cookie", "forbidden"));
            mutation(actual, runtime, manifest, "declared-decoded-hash-mismatch", (r,m) -> ((ObjectNode) r.get("transcriptOriginals").get(0)).put("computedDecodedSha256", "0".repeat(64)));
            mutation(actual, runtime, manifest, "declared-body-byte-count-mismatch", (r,m) -> ((ObjectNode) r.get("transcriptOriginals").get(0)).put("bodyBytes", 1));
            mutation(actual, runtime, manifest, "duplicate-selected-action", (r,m) -> ((ObjectNode) r.get("selectedActionPairs").get(1)).put("actionId", r.get("selectedActionPairs").get(0).get("actionId").textValue()));
            mutation(actual, runtime, manifest, "foreign-selected-response-evidence", (r,m) -> ((com.fasterxml.jackson.databind.node.ArrayNode) r.get("selectedCaseEvidence")).set(0, CODEC.mapper().getNodeFactory().textNode("tx_00000000000000000000000000")));
            mutation(actual, runtime, manifest, "portable-path-traversal", (r,m) -> ((ObjectNode) m.get("originals").get(0).get("physical").get("body")).put("file", "../outside.body"));
            write(runtime, actual.runtime()); write(manifest, actual.manifest());
            String normalFile = actual.normalRequest() + ".saml.xml"; byte[] normal = Files.readAllBytes(portable.resolve(normalFile));
            Files.write(portable.resolve(normalFile), "<tampered/>".getBytes(StandardCharsets.UTF_8)); reject("physical-decoded-byte-tamper", () -> load(runtime, manifest)); Files.write(portable.resolve(normalFile), normal);
            Files.delete(portable.resolve(normalFile)); reject("missing-physical-original", () -> load(runtime, manifest)); Files.write(portable.resolve(normalFile), normal);
            Path linkTarget = directory.resolve("symlink-control-public.xml"); Files.write(linkTarget, normal); Files.delete(portable.resolve(normalFile));
            Files.createSymbolicLink(portable.resolve(normalFile), linkTarget); reject("physical-symlink-original", () -> load(runtime, manifest)); Files.delete(portable.resolve(normalFile)); Files.write(portable.resolve(normalFile), normal);
            String text = CODEC.write(actual.runtime()); Files.writeString(runtime, text.substring(0, text.length() - 1) + ",\"runId\":\"" + RUN + "\"}"); reject("duplicate-JSON-run-key", () -> load(runtime, manifest));
            Files.writeString(runtime, text + "{}"); reject("multiple-JSON-documents", () -> load(runtime, manifest));
            write(runtime, actual.runtime()); load(runtime, manifest); accepted("original-restored-after-corruption-controls");
            System.out.println(CODEC.write(Map.of("schema", "owned-keycloak-nameid-offline-loader-controls-v1", "checks", CHECKS,
                    "checksPassed", CHECKS.size(), "protocolSubmissions", 0, "privateKeyReads", 0, "canonicalAdoption", false)));
        } finally {
            try (var files = Files.walk(directory)) { for (var file : files.sorted(Comparator.reverseOrder()).toList()) Files.delete(file); }
        }
    }
    static void mutation(Loaded source, Path runtime, Path manifest, String id, Mutation mutation) throws Exception {
        ObjectNode r = source.runtime().deepCopy(), m = source.manifest().deepCopy(); mutation.apply(r,m); write(runtime,r); write(manifest,m); reject(id, () -> load(runtime,manifest));
    }
    static void write(Path file, JsonNode value) throws Exception { Files.writeString(file, CODEC.write(value)); }
    static void accepted(String id) { CHECKS.add(Map.of("id", id, "expected", "ACCEPTED", "observed", "ACCEPTED", "passed", true)); }
    static void reject(String id, Check check) throws Exception {
        try { check.run(); } catch (IllegalArgumentException | java.io.IOException rejected) { CHECKS.add(Map.of("id", id, "expected", "REJECTED", "observed", "REJECTED", "passed", true)); return; }
        throw new IllegalArgumentException("Offline loader accepted forbidden input: " + id);
    }
}
