package com.samlscope.runner.cases;

import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.plan.*;
import com.samlscope.core.run.Reachability;
import com.samlscope.core.transcript.*;
import com.samlscope.runner.DefaultCaseContext;
import com.samlscope.store.JsonCodec;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.ByteArrayInputStream;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.util.*;
import javax.xml.stream.*;

/** Independent no-send replay of the complete native and protocol originals. */
public final class VerifyExtensionAttributeParserEvidence {
    static final JsonCodec JSON = new JsonCodec();
    static DefaultCaseContext context(String run, List<TranscriptEntry> entries) {
        var recorder = new TranscriptRecorder() {
            public List<TranscriptEntry> list(String ignored) { return entries; }
            public TranscriptEntry record(TranscriptInput input) { throw new AssertionError("Replay cannot send"); }
            public TranscriptEntry updateSamlAnalysis(String id, String correlation, Map<String,Object> summary) { throw new AssertionError("Replay cannot edit"); }
        };
        return new DefaultCaseContext(run, TargetRole.IDP, Clock.systemUTC(), TestPlan.Parameters.defaults(),
                TestPlan.Interaction.defaults(), Reachability.CONFIRMED, recorder, true);
    }
    static TranscriptEntry body(TranscriptEntry entry, byte[] bytes) {
        return new TranscriptEntry(entry.id(), entry.runId(), entry.direction(), entry.timestamp(), entry.correlationId(),
                entry.method(), entry.url(), entry.status(), entry.headers(), entry.bodyRef(), entry.bodyBytes(),
                entry.decodedSamlRef(), bytes.length, entry.contentType(), entry.rawQuery(), entry.samlSummary());
    }
    static void reject(String label, String run, Path directory, ObjectNode receipt, List<TranscriptEntry> entries,
            Map<String,byte[]> bodies, byte[] target, String actualProfile, List<String> passed) throws Exception {
        var path = directory.resolve(run + ExtensionAttributeParserEvidence.SUFFIX); var previous = Files.readAllBytes(path);
        try {
            Files.write(path, JSON.mapper().writeValueAsBytes(receipt));
            var reader = new ExtensionAttributeParserEvidence(directory, entry -> bodies.get(entry.id()), ignored -> actualProfile);
            var actual = reader.evaluate(context(run, entries), target);
            if (actual.outcome() != Outcome.NOT_VERIFIED) throw new IllegalStateException("Calibration mutation concluded: " + label);
            passed.add(label);
        } finally { Files.write(path, previous); }
    }
    static boolean failureMutant(byte[] input) throws Exception {
        var factory = XMLInputFactory.newFactory(); factory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
        factory.setProperty("javax.xml.stream.isSupportingExternalEntities", false);
        var reader = factory.createXMLEventReader(new ByteArrayInputStream(input));
        try {
            while (reader.hasNext()) {
                var event = reader.nextEvent(); if (!event.isStartElement()) continue;
                var start = event.asStartElement();
                if (!"AffiliationDescriptor".equals(start.getName().getLocalPart())) continue;
                var attribute = start.getAttributeByName(new javax.xml.namespace.QName("urn:samlscope:fixture:foreign-attribute", "undefined"));
                if (attribute != null) throw new IllegalStateException("calibration_mutant_foreign_attribute_software_failure");
            }
            return false;
        } catch (IllegalStateException expected) {
            if (!"calibration_mutant_foreign_attribute_software_failure".equals(expected.getMessage())) throw expected;
            return true;
        } finally { reader.close(); }
    }
    static List<String> controls(String run, Path directory, ObjectNode receipt, List<TranscriptEntry> entries,
            Map<String,byte[]> bodies, byte[] target, String profile) throws Exception {
        var passed = new ArrayList<String>();
        var owned = directory.resolve(run + ".extension-attribute-parser");
        // This deliberate receiver mutant is calibration only. Its failure is never relabelled as product evidence.
        var control = Files.readAllBytes(owned.resolve("control.xml")); var input = Files.readAllBytes(owned.resolve("input.xml"));
        if (failureMutant(control) || !failureMutant(input)) throw new IllegalStateException("Role-specific failure mutant has no detection power");
        passed.add("same_prerequisites_mutant_fails_only_foreign_affiliation_attribute");
        var missingActive = entries.stream().filter(entry -> !(entry.direction() == Direction.OUTBOUND
                && "unknown-attribute-any-attribute".equals(entry.samlSummary().get("fixture_id")))).toList();
        reject("missing_active_attribute_member", run, directory, receipt.deepCopy(), missingActive, bodies, target, profile, passed);
        var missingMetadata = entries.stream().filter(entry -> !(entry.direction() == Direction.OUTBOUND
                && "AuthnRequest".equals(entry.samlSummary().get("type"))
                && "foreign-attribute-single-sign-on".equals(entry.samlSummary().get("variant")))).toList();
        reject("missing_metadata_attribute_member", run, directory, receipt.deepCopy(), missingMetadata, bodies, target, profile, passed);
        var missingPrepared = entries.stream().filter(entry -> !entry.id().equals(receipt.path("preparedReference").asText())).toList();
        reject("missing_affiliation_prepared_original", run, directory, receipt.deepCopy(), missingPrepared, bodies, target, profile, passed);
        var duplicate = new ArrayList<>(entries); duplicate.add(entries.getFirst());
        reject("duplicate_original", run, directory, receipt.deepCopy(), duplicate, bodies, target, profile, passed);
        var other = new ArrayList<>(entries); var entry = entries.getFirst();
        other.add(new TranscriptEntry("foreign-original", "run_00000000000000000000000001", entry.direction(), entry.timestamp(), entry.correlationId(),
                entry.method(), entry.url(), entry.status(), entry.headers(), entry.bodyRef(), entry.bodyBytes(), entry.decodedSamlRef(),
                entry.decodedSamlBytes(), entry.contentType(), entry.rawQuery(), entry.samlSummary()));
        reject("foreign_run_original", run, directory, receipt.deepCopy(), other, bodies, target, profile, passed);
        reject("actual_plan_profile_mismatch", run, directory, receipt.deepCopy(), entries, bodies, target,
                profile.equals("metadata_idp") ? "browser_sso_idp" : "metadata_idp", passed);
        var wrongSource = receipt.deepCopy(); wrongSource.put("sourceRunId", "run_00000000000000000000000001");
        reject("unbound_source_run", run, directory, wrongSource, entries, bodies, target, profile, passed);
        var wrongTarget = receipt.deepCopy(); wrongTarget.put("targetMetadataSha256", "0".repeat(64));
        reject("target_snapshot_mismatch", run, directory, wrongTarget, entries, bodies, target, profile, passed);
        var invocationId = receipt.path("invocation").path("reference").asText();
        var invocation = (ObjectNode) JSON.mapper().readTree(bodies.get(invocationId));
        var failedInvocation = invocation.deepCopy(); failedInvocation.put("exitCode", 1);
        rejectInvocation("mutant_native_failure_output", run, directory, receipt.deepCopy(), entries, bodies, target, profile, failedInvocation, passed);
        // Two identical claimed trees must fail unless every byte matches a fresh native parser invocation.
        var cachedTrees = invocation.deepCopy(); cachedTrees.put("inputTreeBase64", Base64.getEncoder().encodeToString("claimed-same-tree".getBytes(StandardCharsets.UTF_8)));
        cachedTrees.put("controlTreeBase64", cachedTrees.path("inputTreeBase64").asText());
        var outputPath = owned.resolve("native-output.json"); var originalOutput = Files.readAllBytes(outputPath);
        try {
            var output = (ObjectNode) JSON.mapper().readTree(originalOutput);
            output.put("inputTreeBase64", cachedTrees.path("inputTreeBase64").asText()); output.put("controlTreeBase64", cachedTrees.path("controlTreeBase64").asText());
            var bytes = JSON.mapper().writeValueAsBytes(output); Files.write(outputPath, bytes);
            var changedReceipt = receipt.deepCopy(); ((ObjectNode) changedReceipt.path("files")).put("native-output.json", ExtensionAttributeParserEvidence.sha(bytes));
            rejectInvocation("identical_cached_output_cannot_replace_native_replay", run, directory, changedReceipt, entries, bodies, target, profile, cachedTrees, passed);
        } finally { Files.write(outputPath, originalOutput); }
        var controlPath = owned.resolve("control.xml"); var originalControl = Files.readAllBytes(controlPath);
        try {
            var bytes = new String(originalControl, StandardCharsets.UTF_8).replace("AffiliateMember>", "AffiliateMember changed='true'>").getBytes(StandardCharsets.UTF_8);
            Files.write(controlPath, bytes); var changedReceipt = receipt.deepCopy();
            ((ObjectNode) changedReceipt.path("files")).put("control.xml", ExtensionAttributeParserEvidence.sha(bytes));
            reject("control_differs_beyond_the_foreign_attribute", run, directory, changedReceipt, entries, bodies, target, profile, passed);
        } finally { Files.write(controlPath, originalControl); }
        var jarName = "org.keycloak.keycloak-saml-core-26.7.2.jar"; var jarPath = owned.resolve(jarName); var originalJar = Files.readAllBytes(jarPath);
        try {
            var bytes = originalJar.clone(); bytes[0] ^= 1; Files.write(jarPath, bytes); var changedReceipt = receipt.deepCopy();
            ((ObjectNode) changedReceipt.path("files")).put(jarName, ExtensionAttributeParserEvidence.sha(bytes));
            reject("changed_native_parser_artifact", run, directory, changedReceipt, entries, bodies, target, profile, passed);
        } finally { Files.write(jarPath, originalJar); }
        var activeRequest = entries.stream().filter(value -> value.direction() == Direction.OUTBOUND
                && ExtensionAttributeParserEvidence.ID.equals(value.samlSummary().get("scenario_case_id"))).findFirst().orElseThrow();
        var activeResponse = entries.stream().filter(value -> value.direction() == Direction.INBOUND
                && Boolean.TRUE.equals(value.samlSummary().get("activeProbeAccepted"))
                && ("_" + activeRequest.samlSummary().get("action_id")).equals(value.samlSummary().get("inResponseTo"))).findFirst().orElseThrow();
        var responseText = new String(bodies.get(activeResponse.id()), StandardCharsets.UTF_8);
        var signatureValue = java.util.regex.Pattern.compile("<(?:[\\w.-]+:)?SignatureValue\\b[^>]*>\\s*([A-Za-z0-9+/])").matcher(responseText);
        if (!signatureValue.find()) throw new IllegalArgumentException("Signature control is absent");
        var index = signatureValue.start(1);
        var response = (responseText.substring(0, index) + (responseText.charAt(index) == 'A' ? "B" : "A")
                + responseText.substring(index + 1)).getBytes(StandardCharsets.UTF_8);
        if (Arrays.equals(response, bodies.get(activeResponse.id()))) throw new IllegalStateException("Signature mutation did not change the original");
        var changedBodies = new HashMap<>(bodies); changedBodies.put(activeResponse.id(), response);
        var changedEntries = entries.stream().map(value -> value.id().equals(activeResponse.id()) ? body(value, response) : value).toList();
        reject("unverified_target_response_signature", run, directory, receipt.deepCopy(), changedEntries, changedBodies, target, profile, passed);
        return List.copyOf(passed);
    }
    static void rejectInvocation(String label, String run, Path directory, ObjectNode receipt, List<TranscriptEntry> entries,
            Map<String,byte[]> bodies, byte[] target, String profile, ObjectNode invocation, List<String> passed) throws Exception {
        var id = receipt.path("invocation").path("reference").asText(); var bytes = JSON.mapper().writeValueAsBytes(invocation);
        var changedBodies = new HashMap<>(bodies); changedBodies.put(id, bytes);
        var changedEntries = entries.stream().map(entry -> entry.id().equals(id) ? body(entry, bytes) : entry).toList();
        ((ObjectNode) receipt.path("invocation")).put("sha256", ExtensionAttributeParserEvidence.sha(bytes));
        reject(label, run, directory, receipt, changedEntries, changedBodies, target, profile, passed);
    }
    public static void main(String[] args) throws Exception {
        var folder = Path.of(args[0]); var receipt = JSON.mapper().readTree(folder.resolve("manifest.json").toFile());
        var run = receipt.path("runId").asText(); var directory = Path.of(args[1]);
        var entries = new ArrayList<>(List.of(JSON.mapper().readValue(folder.resolve("transcript.json").toFile(), TranscriptEntry[].class)));
        var bodies = new HashMap<String,byte[]>();
        for (var row : JSON.mapper().readTree(folder.resolve("decoded-manifest.json").toFile())) {
            var path = folder.resolve(row.path("file").asText()).normalize();
            if (!path.startsWith(folder.resolve("decoded"))) throw new IllegalArgumentException("Original path escaped");
            var bytes = Files.readAllBytes(path);
            if (!ExtensionAttributeParserEvidence.sha(bytes).equals(row.path("sha256").asText())) throw new IllegalArgumentException("Original hash differs");
            bodies.put(row.path("id").asText(), bytes);
        }
        var target = Files.readAllBytes(folder.resolve("target-metadata.xml"));
        var plan = JSON.mapper().readTree(folder.resolve("plan.json").toFile());
        var created = JSON.mapper().readTree(folder.resolve("created.json").toFile()).path("run");
        if (!run.equals(created.path("id").asText()) || !plan.path("id").asText().equals(created.path("planId").asText()))
            throw new IllegalArgumentException("Source Run/Plan binding differs");
        var reader = new ExtensionAttributeParserEvidence(directory, entry -> bodies.get(entry.id()), ignored -> plan.path("profile").asText());
        var actual = reader.evaluate(context(run, entries), target);
        var output = new TreeMap<String,Object>(); output.put("runId", run); output.put("profile", receipt.path("profile").asText());
        output.put("outcome", actual); output.put("targetConfigurationWrites", 0); output.put("protocolSubmissions", 0);
        if (actual.outcome() != Outcome.SATISFIED) throw new IllegalStateException("Complete originals remain unverified");
        output.put("calibrationMutationsRejected", controls(run, directory, (ObjectNode) receipt, entries, bodies, target, plan.path("profile").asText()));
        output.put("controlsAreProductObservations", false);
        output.put("restoredReceiptSha256", ExtensionAttributeParserEvidence.sha(Files.readAllBytes(directory.resolve(run + ExtensionAttributeParserEvidence.SUFFIX))));
        new JsonCodec().mapper().writerWithDefaultPrettyPrinter().writeValue(Path.of(args[2]).toFile(), output);
    }
}
