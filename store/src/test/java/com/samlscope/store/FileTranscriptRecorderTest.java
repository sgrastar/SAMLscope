package com.samlscope.store;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import com.samlscope.core.plan.MetadataDeliveryKind;
import com.samlscope.core.plan.MetadataSourceKind;
import com.samlscope.core.profile.FunctionalProfile;
import com.samlscope.core.plan.TargetKind;
import com.samlscope.core.plan.TestPlan;
import com.samlscope.core.run.Reachability;
import com.samlscope.core.run.RunStatus;
import com.samlscope.core.run.TestRun;
import com.samlscope.core.transcript.Direction;
import com.samlscope.core.transcript.TranscriptInput;
import com.samlscope.core.transcript.TranscriptHistoryLimitExceeded;

class FileTranscriptRecorderTest {
    @TempDir java.nio.file.Path directory;

    @Test
    void credentialsNeverReachPersistentStorage() throws Exception {
        var database = new SqliteDatabase(directory);
        var json = new JsonCodec();
        var now = Instant.parse("2026-08-29T00:00:00Z");
        var plan = new TestPlan("plan_0123456789ABCDEFGHJKMNPQRS", "Example", FunctionalProfile.BROWSER_SSO_IDP,
                new TestPlan.Target(TargetKind.IDP, "https://idp.example/entity",
                        new TestPlan.MetadataSource(MetadataSourceKind.URL, "https://idp.example/metadata")),
                MetadataDeliveryKind.MANUAL, Map.of(), TestPlan.Parameters.defaults(),
                TestPlan.Interaction.defaults(), now, now);
        new SqlitePlanRepository(database, json).save(plan);
        var run = new TestRun("run_0123456789ABCDEFGHJKMNPQRS", plan.id(), RunStatus.RUNNING,
                Reachability.UNKNOWN, Map.of(), now, now);
        new SqliteRunRepository(database, json).save(run);
        var recorder = new FileTranscriptRecorder(database, json, directory);
        var secret = "correct horse battery staple";
        recorder.record(new TranscriptInput(run.id(), Direction.INBOUND, now, "corr", "POST",
                "https://suite.example/ecp?token=" + secret, 200,
                Map.of("Authorization", List.of("Basic " + secret), "Cookie", List.of("sid=" + secret)),
                ("username=test&password=" + secret).getBytes(StandardCharsets.UTF_8),
                "application/x-www-form-urlencoded", "token=" + secret, new byte[0], Map.of()));

        var allBytes = new String(readAll(directory), StandardCharsets.ISO_8859_1);
        assertFalse(allBytes.contains(secret));
        assertTrue(allBytes.contains("redacted"));
    }

    @Test
    void readsOnlyTheDecodedSamlBoundToATranscriptEntry() {
        var database = new SqliteDatabase(directory);
        var json = new JsonCodec();
        var now = Instant.parse("2026-08-29T00:00:00Z");
        var plan = new TestPlan("plan_0123456789ABCDEFGHJKMNPQRS", "Example", FunctionalProfile.BROWSER_SSO_IDP,
                new TestPlan.Target(TargetKind.IDP, "https://idp.example/entity",
                        new TestPlan.MetadataSource(MetadataSourceKind.URL, "https://idp.example/metadata")),
                MetadataDeliveryKind.MANUAL, Map.of(), TestPlan.Parameters.defaults(),
                TestPlan.Interaction.defaults(), now, now);
        new SqlitePlanRepository(database, json).save(plan);
        var run = new TestRun("run_0123456789ABCDEFGHJKMNPQRS", plan.id(), RunStatus.RUNNING,
                Reachability.UNKNOWN, Map.of(), now, now);
        new SqliteRunRepository(database, json).save(run);
        var recorder = new FileTranscriptRecorder(database, json, directory);
        var xml = "<samlp:Response xmlns:samlp='urn:oasis:names:tc:SAML:2.0:protocol'/>"
                .getBytes(StandardCharsets.UTF_8);
        var entry = recorder.record(new TranscriptInput(
                run.id(), Direction.INBOUND, now, "corr", "POST", "https://suite.example/acs", 200,
                Map.of(), new byte[0], "application/xml", null, xml, Map.of()));

        assertArrayEquals(xml, recorder.readDecodedSaml(entry));
    }

    @Test
    void boundedListingFailsInsteadOfReturningPartialEvidence() {
        var database = new SqliteDatabase(directory);
        var json = new JsonCodec();
        var now = Instant.parse("2026-08-29T00:00:00Z");
        var plan = new TestPlan("plan_0123456789ABCDEFGHJKMNPQRS", "Example", FunctionalProfile.BROWSER_SSO_IDP,
                new TestPlan.Target(TargetKind.IDP, "https://idp.example/entity",
                        new TestPlan.MetadataSource(MetadataSourceKind.URL, "https://idp.example/metadata")),
                MetadataDeliveryKind.MANUAL, Map.of(), TestPlan.Parameters.defaults(),
                TestPlan.Interaction.defaults(), now, now);
        new SqlitePlanRepository(database, json).save(plan);
        var run = new TestRun("run_0123456789ABCDEFGHJKMNPQRS", plan.id(), RunStatus.RUNNING,
                Reachability.UNKNOWN, Map.of(), now, now);
        new SqliteRunRepository(database, json).save(run);
        var recorder = new FileTranscriptRecorder(database, json, directory);
        var input = new TranscriptInput(run.id(), Direction.INBOUND, now, "corr", "POST",
                "https://suite.example/acs", 200, Map.of(), new byte[0], "application/xml", null,
                "<Response/>".getBytes(StandardCharsets.UTF_8), Map.of());
        recorder.record(input);
        recorder.record(input);

        assertThrows(TranscriptHistoryLimitExceeded.class, () -> recorder.listBounded(run.id(), 1));
        assertTrue(recorder.list(run.id()).size() == 2, "the complete Transcript remains available");
    }

    @Test
    void persistentCapacityRejectsBeforeWritingAndSurvivesModeChanges() throws Exception {
        var database = new SqliteDatabase(directory);
        var json = new JsonCodec();
        var now = Instant.parse("2026-08-29T00:00:00Z");
        var plan = new TestPlan("plan_0123456789ABCDEFGHJKMNPQRS", "Example", FunctionalProfile.BROWSER_SSO_IDP,
                new TestPlan.Target(TargetKind.IDP, "https://idp.example/entity",
                        new TestPlan.MetadataSource(MetadataSourceKind.URL, "https://idp.example/metadata")),
                MetadataDeliveryKind.MANUAL, Map.of(), TestPlan.Parameters.defaults(),
                TestPlan.Interaction.defaults(), now, now);
        new SqlitePlanRepository(database, json).save(plan);
        var run = new TestRun("run_0123456789ABCDEFGHJKMNPQRS", plan.id(), RunStatus.RUNNING,
                Reachability.UNKNOWN, Map.of(), now, now);
        new SqliteRunRepository(database, json).save(run);
        var input = new TranscriptInput(run.id(), Direction.INBOUND, now, "corr", "POST",
                "https://suite.example/acs", 200, Map.of(), new byte[0], "application/xml", null,
                "<Response/>".getBytes(StandardCharsets.UTF_8), Map.of());

        new FileTranscriptRecorder(database, json, directory).record(input);
        var limited = new FileTranscriptRecorder(
                database, json, directory,
                new FileTranscriptRecorder.Limits(1, 1_024, 100, 100_000, 100, 1_000));
        var publications = new SqlitePublicationRepository(database);
        assertTrue(publications.publish(run.id(), now));

        assertThrows(FileTranscriptRecorder.CapacityExceeded.class, () -> limited.record(input));
        assertEquals(1, limited.list(run.id()).size());
        assertFalse(publications.isPublished(run.id()));
        assertFalse(publications.publish(run.id(), now.plusSeconds(1)));
        try (var paths = Files.list(directory.resolve("transcripts").resolve(run.id()))) {
            assertEquals(1, paths.filter(Files::isRegularFile).count());
        }

        var afterRestart = new FileTranscriptRecorder(
                new SqliteDatabase(directory), json, directory,
                new FileTranscriptRecorder.Limits(1, 1_024, 100, 100_000, 100, 1_000));
        assertThrows(FileTranscriptRecorder.CapacityExceeded.class, () -> afterRestart.record(input));
        assertEquals(1, afterRestart.list(run.id()).size());
    }

    @Test
    void globalCapacityCannotBeBypassedWithAnotherRun() {
        var database = new SqliteDatabase(directory);
        var json = new JsonCodec();
        var now = Instant.parse("2026-08-29T00:00:00Z");
        var plan = new TestPlan("plan_0123456789ABCDEFGHJKMNPQRS", "Example", FunctionalProfile.BROWSER_SSO_IDP,
                new TestPlan.Target(TargetKind.IDP, "https://idp.example/entity",
                        new TestPlan.MetadataSource(MetadataSourceKind.URL, "https://idp.example/metadata")),
                MetadataDeliveryKind.MANUAL, Map.of(), TestPlan.Parameters.defaults(),
                TestPlan.Interaction.defaults(), now, now);
        new SqlitePlanRepository(database, json).save(plan);
        var firstRun = new TestRun("run_0123456789ABCDEFGHJKMNPQRS", plan.id(), RunStatus.RUNNING,
                Reachability.UNKNOWN, Map.of(), now, now);
        var secondRun = new TestRun("run_1123456789ABCDEFGHJKMNPQRS", plan.id(), RunStatus.RUNNING,
                Reachability.UNKNOWN, Map.of(), now, now);
        var runs = new SqliteRunRepository(database, json);
        runs.save(firstRun);
        runs.save(secondRun);
        var recorder = new FileTranscriptRecorder(
                database, json, directory,
                new FileTranscriptRecorder.Limits(10, 10_000, 1, 10_000, 100, 1_000));

        recorder.record(inputFor(firstRun.id(), now));

        assertThrows(FileTranscriptRecorder.CapacityExceeded.class,
                () -> recorder.record(inputFor(secondRun.id(), now)));
        assertEquals(1, recorder.list(firstRun.id()).size());
        assertTrue(recorder.list(secondRun.id()).isEmpty());
        assertFalse(new SqlitePublicationRepository(database).publish(secondRun.id(), now));
    }

    @Test
    void ingressRateRejectionAndPublicationRevocationAreAtomic() {
        var database = new SqliteDatabase(directory);
        var json = new JsonCodec();
        var now = Instant.parse("2026-08-29T00:00:00Z");
        var plan = new TestPlan("plan_0123456789ABCDEFGHJKMNPQRS", "Example", FunctionalProfile.BROWSER_SSO_IDP,
                new TestPlan.Target(TargetKind.IDP, "https://idp.example/entity",
                        new TestPlan.MetadataSource(MetadataSourceKind.URL, "https://idp.example/metadata")),
                MetadataDeliveryKind.MANUAL, Map.of(), TestPlan.Parameters.defaults(),
                TestPlan.Interaction.defaults(), now, now);
        new SqlitePlanRepository(database, json).save(plan);
        var run = new TestRun("run_0123456789ABCDEFGHJKMNPQRS", plan.id(), RunStatus.RUNNING,
                Reachability.UNKNOWN, Map.of(), now, now);
        new SqliteRunRepository(database, json).save(run);
        var recorder = new FileTranscriptRecorder(
                database, json, directory,
                new FileTranscriptRecorder.Limits(10, 10_000, 100, 100_000, 2, 100));
        var publications = new SqlitePublicationRepository(database);

        recorder.record(inputFor(run.id(), now));
        recorder.record(inputFor(run.id(), now));
        assertTrue(publications.publish(run.id(), now));

        assertThrows(FileTranscriptRecorder.AdmissionRateExceeded.class,
                () -> recorder.record(inputFor(run.id(), now)));
        assertEquals(2, recorder.list(run.id()).size());
        assertFalse(publications.isPublished(run.id()));
        assertFalse(publications.publish(run.id(), now.plusSeconds(1)));
    }

    @Test
    void deletingAPlanRemovesEvidenceAndReleasesItsGlobalCapacity() throws Exception {
        var database = new SqliteDatabase(directory);
        var json = new JsonCodec();
        var now = Instant.parse("2026-08-29T00:00:00Z");
        var plan = new TestPlan("plan_0123456789ABCDEFGHJKMNPQRS", "Example", FunctionalProfile.BROWSER_SSO_IDP,
                new TestPlan.Target(TargetKind.IDP, "https://idp.example/entity",
                        new TestPlan.MetadataSource(MetadataSourceKind.URL, "https://idp.example/metadata")),
                MetadataDeliveryKind.MANUAL, Map.of(), TestPlan.Parameters.defaults(),
                TestPlan.Interaction.defaults(), now, now);
        var plans = new SqlitePlanRepository(database, json);
        plans.save(plan);
        var run = new TestRun("run_0123456789ABCDEFGHJKMNPQRS", plan.id(), RunStatus.RUNNING,
                Reachability.UNKNOWN, Map.of(), now, now);
        new SqliteRunRepository(database, json).save(run);
        var recorder = new FileTranscriptRecorder(
                database, json, directory,
                new FileTranscriptRecorder.Limits(10, 10_000, 10, 10_000, 10, 10));
        recorder.record(inputFor(run.id(), now));
        var runDirectory = directory.resolve("transcripts").resolve(run.id());
        assertTrue(Files.exists(runDirectory));

        var artifacts = new FileRunArtifactRepository(directory);
        artifacts.saveResult(run.id(), "result".getBytes(StandardCharsets.UTF_8));
        artifacts.saveReport(run.id(), "report".getBytes(StandardCharsets.UTF_8));
        var metadata = new MetadataCache(directory);
        metadata.put(plan.id(), "plan metadata".getBytes(StandardCharsets.UTF_8));
        metadata.putIfAbsent(run.id(), "run metadata".getBytes(StandardCharsets.UTF_8));
        var keyDirectory = directory.resolve("keys").resolve(plan.id());
        Files.createDirectories(keyDirectory.resolve("rollover"));
        Files.writeString(keyDirectory.resolve("rollover/signing-key.pk8"), "test fixture");
        var unrelated = directory.resolve("keys/unrelated/signing-key.pk8");
        Files.createDirectories(unrelated.getParent());
        Files.writeString(unrelated, "preserve");

        assertTrue(recorder.deletePlanAndEvidence(plan.id()));

        assertTrue(plans.find(plan.id()).isEmpty());
        assertFalse(Files.exists(runDirectory));
        assertTrue(artifacts.findResult(run.id()).isEmpty());
        assertTrue(artifacts.findReport(run.id()).isEmpty());
        assertFalse(Files.exists(directory.resolve("target-metadata").resolve(run.id() + ".xml")));
        assertFalse(Files.exists(directory.resolve("target-metadata").resolve(plan.id() + ".xml")));
        assertFalse(Files.exists(keyDirectory));
        assertEquals("preserve", Files.readString(unrelated));
        try (var connection = database.open();
             var usage = connection.createStatement().executeQuery(
                     "SELECT entry_count, stored_bytes FROM transcript_global_usage")) {
            assertTrue(usage.next());
            assertEquals(0, usage.getLong(1));
            assertEquals(0, usage.getLong(2));
        }
        assertFalse(recorder.deletePlanAndEvidence(plan.id()));
    }

    private static TranscriptInput inputFor(String runId, Instant now) {
        return new TranscriptInput(runId, Direction.INBOUND, now, "corr", "POST",
                "https://suite.example/acs", 200, Map.of(), new byte[0], "application/xml", null,
                "<Response/>".getBytes(StandardCharsets.UTF_8), Map.of());
    }

    private byte[] readAll(java.nio.file.Path root) throws Exception {
        var output = new java.io.ByteArrayOutputStream();
        try (var paths = Files.walk(root)) {
            for (var path : paths.filter(Files::isRegularFile).toList()) {
                output.write(Files.readAllBytes(path));
            }
        }
        return output.toByteArray();
    }
}
