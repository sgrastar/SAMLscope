package com.samlscope.store;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.samlscope.core.plan.MetadataDeliveryKind;
import com.samlscope.core.plan.MetadataSourceKind;
import com.samlscope.core.plan.TargetKind;
import com.samlscope.core.plan.TestPlan;
import com.samlscope.core.profile.FunctionalProfile;
import com.samlscope.core.run.Reachability;
import com.samlscope.core.run.RunStatus;
import com.samlscope.core.run.TestRun;
import com.samlscope.core.transcript.Direction;
import com.samlscope.core.transcript.TranscriptEntry;
import com.samlscope.core.transcript.TranscriptInput;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class TranscriptOriginalDigestReaderTest {
    private static final String RUN = "run_0123456789ABCDEFGHJKMNPQRS";
    private static final String OTHER_RUN = "run_00000000000000000000000000";
    private static final String MISSING_TX = "tx_00000000000000000000000000";
    private static final String PROTOCOL = "urn:oasis:names:tc:SAML:2.0:protocol";
    private static final Instant NOW = Instant.parse("2026-10-08T00:00:00Z");
    private static final byte[] RESPONSE = xml("Response", "_reply-a");
    private static final int MAXIMUM_BYTES = 4 * 1024 * 1024;

    @TempDir Path temporary;
    private Path directory;
    private SqliteDatabase database;
    private JsonCodec json;
    private FileTranscriptRecorder recorder;
    private TranscriptOriginalDigestReader reader;

    @BeforeEach
    void prepareOwnedRecorder() throws Exception {
        directory = temporary.toRealPath();
        database = new SqliteDatabase(directory);
        json = new JsonCodec();
        var plan = new TestPlan("plan_0123456789ABCDEFGHJKMNPQRS", "Digest reader test",
                FunctionalProfile.BROWSER_SSO_IDP,
                new TestPlan.Target(TargetKind.IDP, "https://idp.example/entity",
                        new TestPlan.MetadataSource(MetadataSourceKind.URL, "https://idp.example/metadata")),
                MetadataDeliveryKind.MANUAL, Map.of(), TestPlan.Parameters.defaults(),
                TestPlan.Interaction.defaults(), NOW, NOW);
        new SqlitePlanRepository(database, json).save(plan);
        var runs = new SqliteRunRepository(database, json);
        for (var run : List.of(RUN, OTHER_RUN)) {
            runs.save(new TestRun(run, plan.id(), RunStatus.RUNNING, Reachability.UNKNOWN, Map.of(), NOW, NOW));
        }
        recorder = new FileTranscriptRecorder(database, json, directory);
        reader = new TranscriptOriginalDigestReader(database, json, directory);
    }

    @Test
    void recorderResponseReturnsOnlyTheDigestContract() throws Exception {
        var entry = record("Response", RESPONSE);
        var value = reader.read(RUN, entry.id());
        assertEquals("samlscope-transcript-original-digest-v1", value.schema());
        assertEquals(RUN, value.runId());
        assertEquals(entry.id(), value.txId());
        assertEquals(sha(RESPONSE), value.decodedSamlSha256());
        assertEquals(RESPONSE.length, value.decodedSamlBytes());
        var output = json.mapper().readTree(json.write(value));
        var fields = new java.util.HashSet<String>();
        output.fieldNames().forEachRemaining(fields::add);
        assertEquals(Set.of("schema", "runId", "txId", "decodedSamlSha256", "decodedSamlBytes"), fields);
        assertFalse(output.toString().contains("_reply-a"));
        assertFalse(output.toString().contains("private-header-value"));
    }

    @Test
    void recorderAuthnRequestIsSupportedWithoutReserializingItsOriginal() throws Exception {
        var original = ("<?xml version='1.0'?>\n<p:AuthnRequest xmlns:p='" + PROTOCOL
                + "' ID='_request'><p:Extensions><!-- preserved bytes --></p:Extensions></p:AuthnRequest>")
                .getBytes(StandardCharsets.UTF_8);
        var entry = record("AuthnRequest", original);
        assertEquals(sha(original), reader.read(RUN, entry.id()).decodedSamlSha256());
    }

    @Test
    void recorderLogoutRequestReturnsItsExactNativeDigestWithoutDatabaseMutation() throws Exception {
        protocolRoundTrip("LogoutRequest");
    }

    @Test
    void recorderLogoutResponseReturnsItsExactNativeDigestWithoutDatabaseMutation() throws Exception {
        protocolRoundTrip("LogoutResponse");
    }

    @Test
    void recorderArtifactResolveReturnsItsExactNativeDigestWithoutSoapExtraction() throws Exception {
        protocolRoundTrip("ArtifactResolve");
    }

    @Test
    void recorderArtifactResponseReturnsItsExactNativeDigestWithoutSoapExtraction() throws Exception {
        protocolRoundTrip("ArtifactResponse");
    }

    @Test
    void logoutSummaryCannotSubstituteForAnotherProtocolXmlType() {
        for (var type : List.of("LogoutRequest", "LogoutResponse")) {
            var entry = record(type, xml("Response", "_mismatched"));
            unavailable(RUN, entry.id());
        }
    }

    @Test
    void logoutAndArtifactSummariesCannotQualifyNativeConfigurationJson() {
        for (var type : List.of("LogoutRequest", "LogoutResponse", "ArtifactResolve", "ArtifactResponse")) {
            var entry = record(type, "{\"password\":\"private-configuration-sentinel\"}"
                    .getBytes(StandardCharsets.UTF_8));
            unavailable(RUN, entry.id());
        }
    }

    @Test
    void artifactSoapEnvelopeIsNotExtractedOrReserializedIntoADifferentOriginal() {
        for (var type : List.of("ArtifactResolve", "ArtifactResponse")) {
            var wrapped = "<soap:Envelope xmlns:soap='http://schemas.xmlsoap.org/soap/envelope/'><soap:Body>"
                    + new String(xml(type, "_artifact"), StandardCharsets.UTF_8)
                    + "</soap:Body></soap:Envelope>";
            var entry = record(type, wrapped.getBytes(StandardCharsets.UTF_8));
            unavailable(RUN, entry.id());
        }
    }

    private void protocolRoundTrip(String type) throws Exception {
        var original = ("<?xml version='1.0'?>\n<p:" + type + " xmlns:p='" + PROTOCOL
                + "' ID='_protocol-original'><!-- native bytes --></p:" + type + ">")
                .getBytes(StandardCharsets.UTF_8);
        var entry = record(type, original);
        var before = databaseState();
        var digest = reader.read(RUN, entry.id());
        assertEquals(sha(original), digest.decodedSamlSha256());
        assertEquals(original.length, digest.decodedSamlBytes());
        assertEquals(RUN, digest.runId()); assertEquals(entry.id(), digest.txId());
        assertEquals(before, databaseState());
    }

    @Test
    void invalidIdentifiersNeverSelectAnOriginal() {
        var entry = record("Response", RESPONSE);
        for (var invalid : java.util.Arrays.asList(null, "", "../" + RUN, RUN.toLowerCase(),
                "run_" + "I".repeat(26), RUN + "/../" + OTHER_RUN)) {
            unavailable(invalid, entry.id());
        }
        for (var invalid : java.util.Arrays.asList(null, "", "../" + entry.id(), "TX_" + entry.id().substring(3),
                "tx_" + "O".repeat(26), entry.id() + ".saml.xml")) {
            unavailable(RUN, invalid);
        }
    }

    @Test
    void missingRecorderRowCannotUseAPhysicalFile() throws Exception {
        var path = directory.resolve("transcripts/" + RUN + "/" + MISSING_TX + ".saml.xml");
        Files.createDirectories(path.getParent());
        Files.write(path, RESPONSE);
        unavailable(RUN, MISSING_TX);
    }

    @Test
    void anEntryInAnotherRunCannotBeReadUsingThisRun() {
        var entry = record("Response", RESPONSE);
        unavailable(OTHER_RUN, entry.id());
    }

    @Test
    void recorderJsonCannotClaimAnotherRunOrTransaction() throws Exception {
        var entry = record("Response", RESPONSE);
        replaceRow(entry, OTHER_RUN, entry.id(), entry.decodedSamlRef(), entry.decodedSamlBytes(), entry.samlSummary());
        unavailable(RUN, entry.id());
        replaceRow(entry, RUN, MISSING_TX, entry.decodedSamlRef(), entry.decodedSamlBytes(), entry.samlSummary());
        unavailable(RUN, entry.id());
    }

    @Test
    void malformedRecorderJsonHasOnlyTheFixedPublicError() throws Exception {
        var entry = record("Response", RESPONSE);
        setRowJson(entry, "{private-content-that-must-not-be-reported");
        unavailable(RUN, entry.id());
    }

    @Test
    void duplicateMatchingRowsAreUnavailableEvenInADamagedOwnedTestDatabase() throws Exception {
        var entry = record("Response", RESPONSE);
        try (var connection = database.open(); var statement = connection.createStatement()) {
            statement.execute("DROP TABLE transcript_entries");
            statement.execute("CREATE TABLE transcript_entries(id TEXT, run_id TEXT, timestamp TEXT, document_json TEXT)");
            try (var insert = connection.prepareStatement(
                    "INSERT INTO transcript_entries(id, run_id, timestamp, document_json) VALUES(?, ?, ?, ?)")) {
                insert.setString(1, entry.id()); insert.setString(2, RUN);
                insert.setString(3, NOW.toString()); insert.setString(4, json.write(entry));
                insert.executeUpdate(); insert.executeUpdate();
            }
        }
        unavailable(RUN, entry.id());
    }

    @Test
    void referencesCannotBorrowAnotherRunTransactionBodyOrNormalizedPath() throws Exception {
        var entry = record("Response", RESPONSE);
        for (var ref : java.util.Arrays.asList(null, "", "transcripts/" + OTHER_RUN + "/" + entry.id() + ".saml.xml",
                "transcripts/" + RUN + "/" + MISSING_TX + ".saml.xml",
                "transcripts/" + RUN + "/" + entry.id() + ".body",
                "transcripts/" + RUN + "/../" + RUN + "/" + entry.id() + ".saml.xml",
                originalPath(entry).toString())) {
            replaceRow(entry, RUN, entry.id(), ref, entry.decodedSamlBytes(), entry.samlSummary());
            unavailable(RUN, entry.id());
        }
    }

    @Test
    void missingPhysicalOriginalIsUnavailable() throws Exception {
        var entry = record("Response", RESPONSE);
        Files.delete(originalPath(entry));
        unavailable(RUN, entry.id());
    }

    @Test
    void aDirectoryCannotReplaceTheOriginal() throws Exception {
        var entry = record("Response", RESPONSE);
        Files.delete(originalPath(entry));
        Files.createDirectory(originalPath(entry));
        unavailable(RUN, entry.id());
    }

    @Test
    void leafSymlinkIsRefusedEvenWhenItsBytesWouldMatch() throws Exception {
        var entry = record("Response", RESPONSE);
        var target = directory.resolve("matching-original.xml");
        Files.move(originalPath(entry), target);
        Files.createSymbolicLink(originalPath(entry), target);
        unavailable(RUN, entry.id());
    }

    @Test
    void runDirectorySymlinkIsRefusedEvenWhenItsBytesWouldMatch() throws Exception {
        var entry = record("Response", RESPONSE);
        var runDirectory = originalPath(entry).getParent();
        var target = directory.resolve("matching-run-directory");
        Files.move(runDirectory, target);
        Files.createSymbolicLink(runDirectory, target);
        unavailable(RUN, entry.id());
    }

    @Test
    void transcriptDirectorySymlinkIsRefused() throws Exception {
        var entry = record("Response", RESPONSE);
        var transcripts = directory.resolve("transcripts");
        var target = directory.resolve("matching-transcript-directory");
        Files.move(transcripts, target);
        Files.createSymbolicLink(transcripts, target);
        unavailable(RUN, entry.id());
    }

    @Test
    void symlinkAboveTheDataDirectoryIsRefused() throws Exception {
        var entry = record("Response", RESPONSE);
        var linkedRoot = directory.resolve("linked-root");
        Files.createSymbolicLink(linkedRoot, directory);
        var linkedReader = new TranscriptOriginalDigestReader(database, json, linkedRoot);
        var error = assertThrows(TranscriptOriginalDigestReader.Unavailable.class,
                () -> linkedReader.read(RUN, entry.id()));
        fixedError(error);
    }

    @Test
    void oversizedDeclaredOriginalIsRefusedBeforeItsTinyFileCanBeUsed() throws Exception {
        var entry = record("Response", RESPONSE);
        replaceRow(entry, RUN, entry.id(), entry.decodedSamlRef(), MAXIMUM_BYTES + 1, entry.samlSummary());
        unavailable(RUN, entry.id());
    }

    @Test
    void oversizedPhysicalOriginalCannotMatchASmallRecorderDeclaration() throws Exception {
        var entry = record("Response", RESPONSE);
        Files.write(originalPath(entry), new byte[MAXIMUM_BYTES + 1]);
        unavailable(RUN, entry.id());
    }

    @Test
    void zeroNegativeAndWrongDeclaredLengthsAreUnavailable() throws Exception {
        var entry = record("Response", RESPONSE);
        for (var bytes : List.of(0, -1, RESPONSE.length - 1, RESPONSE.length + 1)) {
            replaceRow(entry, RUN, entry.id(), entry.decodedSamlRef(), bytes, entry.samlSummary());
            unavailable(RUN, entry.id());
        }
    }

    @Test
    void theMaximumBoundIsInclusiveForValidSaml() throws Exception {
        var prefix = ("<p:Response xmlns:p='" + PROTOCOL + "'><!--").getBytes(StandardCharsets.UTF_8);
        var suffix = "--></p:Response>".getBytes(StandardCharsets.UTF_8);
        var bytes = new byte[MAXIMUM_BYTES];
        java.util.Arrays.fill(bytes, (byte) 'a');
        System.arraycopy(prefix, 0, bytes, 0, prefix.length);
        System.arraycopy(suffix, 0, bytes, bytes.length - suffix.length, suffix.length);
        var entry = record("Response", bytes);
        var value = reader.read(RUN, entry.id());
        assertEquals(MAXIMUM_BYTES, value.decodedSamlBytes());
        assertEquals(sha(bytes), value.decodedSamlSha256());
    }

    @Test
    void summaryMustDeclareOneOfTheSupportedSamlMessages() throws Exception {
        var entry = record("Response", RESPONSE);
        for (var summary : List.<Map<String, Object>>of(Map.of(), Map.of("type", "MetadataPrepared"),
                Map.of("type", "MetadataSignatureArtifact"), Map.of("type", 1))) {
            replaceRow(entry, RUN, entry.id(), entry.decodedSamlRef(), entry.decodedSamlBytes(), summary);
            unavailable(RUN, entry.id());
        }
        replaceRow(entry, RUN, entry.id(), entry.decodedSamlRef(), entry.decodedSamlBytes(), null);
        unavailable(RUN, entry.id());
    }

    @Test
    void anAllowedSummaryCannotSubstituteForTheMatchingXmlRoot() {
        for (var xml : List.of(new String(xml("AuthnRequest", "_request"), StandardCharsets.UTF_8),
                "<Response/>", "<p:Response xmlns:p='urn:wrong'/>",
                "<p:LogoutResponse xmlns:p='" + PROTOCOL + "'/>",
                "<wrapper><p:Response xmlns:p='" + PROTOCOL + "'/></wrapper>",
                "<md:EntityDescriptor xmlns:md='urn:oasis:names:tc:SAML:2.0:metadata'/>",
                "<p:Response xmlns:p='" + PROTOCOL + "'/><extra/>")) {
            var entry = record("Response", xml.getBytes(StandardCharsets.UTF_8));
            unavailable(RUN, entry.id());
        }
    }

    @Test
    void nativeJsonPhpHtmlAndMalformedXmlAreUnavailable() {
        for (var original : List.of("{\"artifact\":\"metadata-signature-native-validation\"}",
                "<?php $config['password'] = 'private-value';", "<html><body>private-value</body></html>",
                "<p:Response xmlns:p='" + PROTOCOL + "'>", "")) {
            var entry = record("Response", original.getBytes(StandardCharsets.UTF_8));
            unavailable(RUN, entry.id());
        }
    }

    @Test
    void everyDoctypeIsRefusedIncludingLocalAndExternalEntities() throws Exception {
        var secret = directory.resolve("not-saml.txt");
        Files.writeString(secret, "private-external-content");
        for (var declaration : List.of("<!DOCTYPE p:Response>",
                "<!DOCTYPE p:Response [<!ENTITY secret 'private-content'>]>",
                "<!DOCTYPE p:Response [<!ENTITY secret SYSTEM '" + secret.toUri() + "'>]>",
                "<!DOCTYPE p:Response SYSTEM 'http://127.0.0.1:1/never-requested.dtd'>")) {
            var entry = record("Response", (declaration + new String(RESPONSE, StandardCharsets.UTF_8))
                    .getBytes(StandardCharsets.UTF_8));
            unavailable(RUN, entry.id());
        }
    }

    @Test
    void aChangedSameSizeOriginalProducesANewDigestWithoutChangingDatabaseState() throws Exception {
        var entry = record("Response", RESPONSE);
        var before = databaseState();
        var first = reader.read(RUN, entry.id());
        var changed = xml("Response", "_reply-b");
        assertEquals(RESPONSE.length, changed.length);
        Files.write(originalPath(entry), changed);
        var second = reader.read(RUN, entry.id());
        assertNotEquals(first.decodedSamlSha256(), second.decodedSamlSha256());
        assertEquals(sha(changed), second.decodedSamlSha256());
        assertEquals(before, databaseState());
    }

    @Test
    void aSameSizeChangeToInvalidXmlCannotReuseThePreviousDigest() throws Exception {
        var entry = record("Response", RESPONSE);
        reader.read(RUN, entry.id());
        var invalid = RESPONSE.clone();
        invalid[0] = (byte) '!';
        Files.write(originalPath(entry), invalid);
        unavailable(RUN, entry.id());
    }

    @Test
    void failedReadsDoNotChangeRecorderRowsUsagePublicationOrOtherDatabaseState() throws Exception {
        var entry = record("Response", RESPONSE);
        new SqlitePublicationRepository(database).publish(RUN, NOW);
        var before = databaseState();
        unavailable(OTHER_RUN, entry.id());
        Files.write(originalPath(entry), "not xml".getBytes(StandardCharsets.UTF_8));
        unavailable(RUN, entry.id());
        assertEquals(before, databaseState());
    }

    private TranscriptEntry record(String type, byte[] original) {
        return recorder.record(new TranscriptInput(RUN, Direction.INBOUND, NOW, "owned-correlation", "POST",
                "https://suite.example/acs", 200, Map.of("X-Private-Test", List.of("private-header-value")),
                "private-body-value".getBytes(StandardCharsets.UTF_8), "application/xml", null, original,
                Map.of("type", type)));
    }

    private void replaceRow(TranscriptEntry entry, String runId, String txId, String reference,
            int bytes, Map<String, Object> summary) throws Exception {
        setRowJson(entry, json.write(new TranscriptEntry(txId, runId, entry.direction(), entry.timestamp(),
                entry.correlationId(), entry.method(), entry.url(), entry.status(), entry.headers(), entry.bodyRef(),
                entry.bodyBytes(), reference, bytes, entry.contentType(), entry.rawQuery(), summary)));
    }

    private void setRowJson(TranscriptEntry entry, String document) throws Exception {
        try (var connection = database.open(); var update = connection.prepareStatement(
                "UPDATE transcript_entries SET document_json = ? WHERE run_id = ? AND id = ?")) {
            update.setString(1, document); update.setString(2, RUN); update.setString(3, entry.id());
            assertEquals(1, update.executeUpdate());
        }
    }

    private Path originalPath(TranscriptEntry entry) { return directory.resolve(entry.decodedSamlRef()); }

    private void unavailable(String runId, String txId) {
        fixedError(assertThrows(TranscriptOriginalDigestReader.Unavailable.class, () -> reader.read(runId, txId)));
    }

    private static void fixedError(TranscriptOriginalDigestReader.Unavailable error) {
        assertEquals("Transcript original digest is unavailable", error.getMessage());
        assertNull(error.getCause());
        assertEquals(0, error.getSuppressed().length);
    }

    private List<String> databaseState() throws Exception {
        var state = new ArrayList<String>();
        try (var connection = database.open(); var statement = connection.createStatement()) {
            statement.execute("PRAGMA query_only = ON");
            var names = new ArrayList<String>();
            try (var tables = statement.executeQuery("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name")) {
                while (tables.next()) names.add(tables.getString(1));
            }
            for (var name : names) {
                try (var rows = statement.executeQuery("SELECT * FROM \"" + name.replace("\"", "\"\"") + "\"")) {
                    var metadata = rows.getMetaData();
                    var table = new ArrayList<String>();
                    while (rows.next()) {
                        var values = new ArrayList<String>();
                        for (var index = 1; index <= metadata.getColumnCount(); index++) values.add(rows.getString(index));
                        table.add(json.write(values));
                    }
                    table.sort(String::compareTo);
                    state.add(name + ":" + json.write(table));
                }
            }
        }
        return List.copyOf(state);
    }

    private static byte[] xml(String type, String id) {
        return ("<p:" + type + " xmlns:p='" + PROTOCOL + "' ID='" + id + "'/>")
                .getBytes(StandardCharsets.UTF_8);
    }

    private static String sha(byte[] bytes) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
    }
}
