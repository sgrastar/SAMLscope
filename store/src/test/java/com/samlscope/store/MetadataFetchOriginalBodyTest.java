package com.samlscope.store;

import static org.junit.jupiter.api.Assertions.*;
import com.samlscope.core.plan.*;
import com.samlscope.core.profile.FunctionalProfile;
import com.samlscope.core.run.*;
import com.samlscope.core.transcript.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;

class MetadataFetchOriginalBodyTest {
    @TempDir Path folder;
    static final String RUN = "run_0123456789ABCDEFGHJKMNPQRS";
    static final Instant NOW = Instant.parse("2026-10-08T00:00:00Z");
    FileTranscriptRecorder recorder;
    @BeforeEach void setup() {
        var db = new SqliteDatabase(folder); var json = new JsonCodec();
        var plan = new TestPlan("plan_0123456789ABCDEFGHJKMNPQRS", "Example", FunctionalProfile.METADATA_IDP,
                new TestPlan.Target(TargetKind.IDP, "https://idp.example/entity", new TestPlan.MetadataSource(MetadataSourceKind.URL, "https://idp.example/metadata")),
                MetadataDeliveryKind.MANUAL, Map.of(), TestPlan.Parameters.defaults(), TestPlan.Interaction.defaults(), NOW, NOW);
        new SqlitePlanRepository(db, json).save(plan); new SqliteRunRepository(db, json).save(new TestRun(RUN, plan.id(), RunStatus.COMPLETED, Reachability.CONFIRMED, Map.of(), NOW, NOW));
        recorder = new FileTranscriptRecorder(db, json, folder);
    }
    @Test void metadataAndSuiteControlHashesAreComputedFromExactlyTheStoredBytes() throws Exception {
        byte[] body = "password=secret-sentinel&other=public".getBytes(StandardCharsets.UTF_8);
        String original = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(body));
        for (String type : List.of("MetadataFetchResponse", "SuiteMetadataNamespaceControl")) {
            var row = recorder.record(new TranscriptInput(RUN, Direction.INBOUND, NOW, "action", "GET", "https://idp.example/reference", 200,
                    Map.of(), body, "application/x-www-form-urlencoded", null, new byte[0], Map.of("type", type, "original_body_sha256", original, "body_sha256", "forged")));
            byte[] stored = recorder.readBody(row); assertFalse(new String(stored, StandardCharsets.UTF_8).contains("secret-sentinel"));
            assertNotEquals(original, row.samlSummary().get("body_sha256"));
            assertEquals(original, row.samlSummary().get("original_body_sha256"));
            assertEquals(HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(stored)), row.samlSummary().get("body_sha256"));
        }
    }
    @Test void noHashOrSameLengthSubstitutionCannotBeReadAsAnOriginal() throws Exception {
        byte[] body = "<x:document xmlns:x='urn:test:reference'/>".getBytes(StandardCharsets.UTF_8);
        var legacy = recorder.record(new TranscriptInput(RUN, Direction.INBOUND, NOW, "action", "GET", "https://idp.example/reference", 200,
                Map.of(), body, "application/xml", null, new byte[0], Map.of("type", "Unhashed")));
        assertThrows(StoreException.class, () -> recorder.readBody(legacy));
        var row = recorder.record(new TranscriptInput(RUN, Direction.INBOUND, NOW, "action", "GET", "https://idp.example/reference", 200,
                Map.of(), body, "application/xml", null, new byte[0], Map.of("type", "MetadataFetchResponse")));
        body[0] = 'x'; Files.write(folder.resolve(row.bodyRef()), body);
        assertThrows(StoreException.class, () -> recorder.readBody(row));
    }
}
