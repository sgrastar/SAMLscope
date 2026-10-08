package com.samlscope.runner;

import static org.junit.jupiter.api.Assertions.*;
import com.samlscope.core.plan.*;
import com.samlscope.core.profile.FunctionalProfile;
import com.samlscope.core.run.*;
import com.samlscope.core.transcript.*;
import com.samlscope.store.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;

class TranscriptAutomationOriginalBodyTest {
    static final String RUN = "run_0123456789ABCDEFGHJKMNPQRS";
    static final Instant NOW = Instant.parse("2026-10-08T00:00:00Z");
    @TempDir Path folder;
    FileTranscriptRecorder stored;
    @BeforeEach void setup() {
        var db = new SqliteDatabase(folder); var json = new JsonCodec();
        var plan = new TestPlan("plan_0123456789ABCDEFGHJKMNPQRS", "Example", FunctionalProfile.METADATA_IDP,
                new TestPlan.Target(TargetKind.IDP, "https://target.example/entity", new TestPlan.MetadataSource(MetadataSourceKind.URL, "https://target.example/metadata")),
                MetadataDeliveryKind.MANUAL, Map.of(), TestPlan.Parameters.defaults(), TestPlan.Interaction.defaults(), NOW, NOW);
        new SqlitePlanRepository(db, json).save(plan); new SqliteRunRepository(db, json).save(new TestRun(RUN, plan.id(), RunStatus.COMPLETED, Reachability.CONFIRMED, Map.of(), NOW, NOW));
        stored = new FileTranscriptRecorder(db, json, folder);
    }
    TranscriptInput input(String type) { return new TranscriptInput(RUN, Direction.INBOUND, NOW, "action", "GET", "https://target.example/reference", 200,
            Map.of(), "<x:document xmlns:x='urn:test:reference'/>".getBytes(StandardCharsets.UTF_8), "application/xml", null, new byte[0], Map.of("type", type)); }
    @Test void actualRecorderWrapperReadsMetadataAndArtifactOriginalsWithoutRecordingOrScheduling() {
        var queued = new ArrayDeque<Runnable>(); var calls = new AtomicInteger();
        try (var wrapper = new TranscriptAutomationRecorder(stored, stored, queued::add)) {
            wrapper.onRecorded(ignored -> calls.incrementAndGet());
            for (String type : List.of("MetadataFetchResponse", "SuiteMetadataNamespaceControl", "ArtifactReceived", "ArtifactResolve", "ArtifactResponse")) {
                var original = stored.record(input(type));
                byte[] bytes = wrapper.readBody(original); assertArrayEquals(stored.readBody(original), bytes);
            }
            assertEquals(5, stored.list(RUN).size()); assertEquals(0, calls.get()); assertTrue(queued.isEmpty());
        }
    }
    @Test void wrapperPropagatesTamperingAndUnsupportedReadersWithoutSchedulingReconciliation() throws Exception {
        var queued = new ArrayDeque<Runnable>(); var calls = new AtomicInteger();
        var original = stored.record(input("MetadataFetchResponse"));
        try (var wrapper = new TranscriptAutomationRecorder(stored, stored, queued::add)) {
            wrapper.onRecorded(ignored -> calls.incrementAndGet());
            byte[] changed = Files.readAllBytes(folder.resolve(original.bodyRef())); changed[0] = 'x'; Files.write(folder.resolve(original.bodyRef()), changed);
            assertThrows(StoreException.class, () -> wrapper.readBody(original)); assertEquals(1, stored.list(RUN).size());
        }
        TranscriptContentReader unsupported = entry -> new byte[0];
        try (var wrapper = new TranscriptAutomationRecorder(stored, unsupported, queued::add)) {
            wrapper.onRecorded(ignored -> calls.incrementAndGet());
            assertThrows(UnsupportedOperationException.class, () -> wrapper.readBody(original));
        }
        assertEquals(0, calls.get()); assertTrue(queued.isEmpty());
    }
}
