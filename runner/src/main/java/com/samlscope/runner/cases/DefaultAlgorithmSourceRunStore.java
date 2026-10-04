package com.samlscope.runner.cases;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.samlscope.core.caseexec.*;
import com.samlscope.core.plan.*;
import com.samlscope.core.run.TestRun;
import com.samlscope.core.transcript.*;
import com.samlscope.runner.DefaultCaseContext;
import com.samlscope.store.JsonCodec;
import java.nio.file.*;
import java.sql.*;
import java.time.Clock;
import java.util.*;
import java.util.function.Function;

/** Read-only source identity and installed approved membership; stored verdicts are never evidence. */
public final class DefaultAlgorithmSourceRunStore {
    private final Path data;
    private final String approvedCaseDigest;
    private final String caseId;
    private final Function<String,byte[]> resources;
    private final JsonCodec json = new JsonCodec();

    public DefaultAlgorithmSourceRunStore(Path data, String approvedCaseDigest) {
        this(data, DefaultAlgorithmComparison.CASE, approvedCaseDigest);
    }

    public DefaultAlgorithmSourceRunStore(Path data, String caseId, String approvedCaseDigest) {
        this(data, caseId, approvedCaseDigest, path -> {
            try (var input = DefaultAlgorithmSourceRunStore.class.getResourceAsStream(path)) {
                if (input == null) throw new IllegalArgumentException("Installed release resource unavailable");
                return input.readAllBytes();
            } catch (java.io.IOException missing) { throw new IllegalArgumentException("Installed release unavailable", missing); }
        });
    }

    DefaultAlgorithmSourceRunStore(Path data, String approvedCaseDigest, Function<String,byte[]> resources) {
        this(data, DefaultAlgorithmComparison.CASE, approvedCaseDigest, resources);
    }

    DefaultAlgorithmSourceRunStore(Path data, String caseId, String approvedCaseDigest, Function<String,byte[]> resources) {
        require(caseId != null && caseId.matches("[A-Z0-9]+-[A-Za-z0-9-]+"));
        this.caseId = caseId;
        this.data = Objects.requireNonNull(data).toAbsolutePath().normalize();
        require(approvedCaseDigest != null && approvedCaseDigest.matches("sha256:[0-9a-f]{64}"));
        this.approvedCaseDigest = approvedCaseDigest;
        this.resources = Objects.requireNonNull(resources);
        json.mapper().enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION)
                .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS);
    }

    /** Allows membership preflight before cases have been started. */
    public Binding planned(String runId) { return read(runId, false); }

    public Binding execution(String runId) { return read(runId, true); }

    private Binding read(String runId, boolean requireExecution) {
        try {
            require(runId != null && runId.matches("run_[0-9A-HJKMNP-TV-Z]{26}"));
            Path database = data.resolve("samlscope.db");
            DefaultAlgorithmPreventionEvidence.safeParents(database);
            require(Files.isRegularFile(database, LinkOption.NOFOLLOW_LINKS));
            try (var connection = DriverManager.getConnection("jdbc:sqlite:file:" + database + "?mode=ro")) {
                connection.setAutoCommit(false);
                TestRun run; TestPlan plan; String runRaw, planRaw;
                try (var query = connection.prepareStatement("SELECT r.plan_id,r.document_json,p.document_json FROM runs r JOIN plans p ON p.id=r.plan_id WHERE r.id=?")) {
                    query.setString(1, runId);
                    try (var rows = query.executeQuery()) {
                        require(rows.next()); String planId = rows.getString(1);
                        runRaw = rows.getString(2); planRaw = rows.getString(3);
                        run = json.read(runRaw, TestRun.class); plan = json.read(planRaw, TestPlan.class);
                        require(!rows.next() && runId.equals(run.id()) && planId.equals(run.planId()) && planId.equals(plan.id()));
                    }
                }
                approvedMembership(plan);
                var digest = new TreeMap<String,Object>();
                digest.put("runId", run.id()); digest.put("planId", plan.id());
                digest.put("runDocumentSha256", hash(runRaw)); digest.put("planDocumentSha256", hash(planRaw));
                digest.put("caseDigest", approvedCaseDigest); digest.put("definitionIdentity", plan.definitionIdentity());
                boolean executionPresent = false;
                try (var query = connection.prepareStatement("SELECT revision,status,document_json FROM case_executions WHERE run_id=? AND case_id=?")) {
                    query.setString(1, runId); query.setString(2, caseId);
                    try (var rows = query.executeQuery()) {
                        if (rows.next()) {
                            String raw = rows.getString(3); var execution = json.read(raw, CaseExecution.class);
                            require(execution.runId().equals(runId) && execution.caseId().equals(caseId)
                                    && execution.revision() == rows.getLong(1) && execution.status().name().equals(rows.getString(2)) && !rows.next());
                            digest.put("caseExecutionSha256", hash(raw)); executionPresent = true;
                        }
                    }
                }
                require(!requireExecution || executionPresent);
                var outbox = new ArrayList<SourceAction>(); var allRows = new ArrayList<Map<String,Object>>();
                try (var query = connection.prepareStatement("SELECT action_id,case_id,kind,status,action_json,send_result_json,transcript_entry_id,created_at,updated_at FROM outbox_actions WHERE run_id=? ORDER BY action_id")) {
                    query.setString(1, runId);
                    try (var rows = query.executeQuery()) {
                        while (rows.next()) {
                            require(allRows.size() < 10_000); var row = new TreeMap<String,Object>();
                            for (String name : List.of("action_id","case_id","kind","status","transcript_entry_id","created_at","updated_at")) row.put(name, rows.getString(name));
                            row.put("actionSha256", hash(rows.getString("action_json")));
                            row.put("sendResultSha256", hash(rows.getString("send_result_json"))); allRows.add(row);
                            if (caseId.equals(rows.getString("case_id"))) {
                                var action = json.read(rows.getString("action_json"), OutboundAction.class);
                                require(action.actionId().equals(rows.getString("action_id")) && action.kind().name().equals(rows.getString("kind")));
                                outbox.add(new SourceAction(action, rows.getString("status"), rows.getString("transcript_entry_id")));
                            }
                        }
                    }
                }
                digest.put("outbox", allRows); connection.rollback();
                return new Binding(run, plan, List.copyOf(outbox), json.mapper().valueToTree(digest));
            }
        } catch (Exception missing) { throw new IllegalArgumentException("Approved source Run binding unavailable", missing); }
    }

    private void approvedMembership(TestPlan plan) throws Exception {
        require(plan.definitionIdentity() != null && plan.profile().role() == TargetRole.IDP);
        var pins = new Properties(); pins.load(new java.io.ByteArrayInputStream(resources.apply("/profiles/release-pins.properties")));
        String pin = pins.getProperty(plan.profile().id());
        byte[] raw = resources.apply("/profiles/" + plan.profile().id() + ".json");
        require(pin != null && pin.equals("sha256:" + DefaultAlgorithmPreventionEvidence.hash(raw)) && pin.equals(plan.definitionIdentity().digest()));
        JsonNode definition = json.mapper().readTree(raw);
        require(definition.path("schema_version").asInt(-1) == 1 && plan.profile().id().equals(text(definition,"profile"))
                && plan.definitionIdentity().version().equals(text(definition,"version")));
        var sources = definition.path("source_digests");
        require(sources.isObject() && sources.size() == 3);
        for (String path : List.of("tests/coverage.yaml","tests/cases.yaml","tests/predicates.yaml"))
            require(("sha256:" + DefaultAlgorithmPreventionEvidence.hash(resources.apply("/catalog/" + path))).equals(text(sources,path)));
        require(definition.path("cases").isArray()); int matched = 0; var ids = new HashSet<String>();
        for (var item : definition.path("cases")) {
            require(ids.add(text(item,"id")));
            if (caseId.equals(text(item,"id"))) { require(approvedCaseDigest.equals(text(item,"digest"))); matched++; }
        }
        require(matched == 1);
    }

    public String approvedCaseDigest() { return approvedCaseDigest; }
    public String approvedCaseId() { return caseId; }
    /** Hash every saved original, including unused history, without exporting message bodies. */
    public JsonNode history(String runId, List<TranscriptEntry> entries, TranscriptContentReader content) throws Exception {
        require(entries.size() <= 10_000); var ids = new HashSet<String>(); var rows = new ArrayList<Map<String,Object>>();
        for (var entry : entries) {
            require(runId.equals(entry.runId()) && entry.id().matches("tx_[0-9A-HJKMNP-TV-Z]{26}") && ids.add(entry.id()));
            var row = new TreeMap<String,Object>(); row.put("id",entry.id());
            row.put("entrySha256",DefaultAlgorithmPreventionEvidence.hash(json.mapper().writeValueAsBytes(entry)));
            if (entry.decodedSamlRef() != null) {
                require(("transcripts/"+runId+"/"+entry.id()+".saml.xml").equals(entry.decodedSamlRef()));
                byte[] raw = content.readDecodedSaml(entry); require(raw != null && raw.length == entry.decodedSamlBytes() && raw.length <= 1_048_576);
                row.put("decodedSha256",DefaultAlgorithmPreventionEvidence.hash(raw));
            } else require(entry.decodedSamlBytes() == 0);
            if (entry.bodyRef() != null) {
                require(("transcripts/"+runId+"/"+entry.id()+".body").equals(entry.bodyRef()) && entry.bodyBytes() >= 0 && entry.bodyBytes() <= 8_388_608);
                var path = data.resolve(entry.bodyRef()); DefaultAlgorithmPreventionEvidence.safeParents(path);
                require(Files.isRegularFile(path,LinkOption.NOFOLLOW_LINKS) && Files.size(path) == entry.bodyBytes());
                row.put("bodySha256",DefaultAlgorithmPreventionEvidence.hash(Files.readAllBytes(path)));
            } else require(entry.bodyBytes() == 0);
            rows.add(row);
        }
        return json.mapper().valueToTree(rows);
    }
    public record SourceAction(OutboundAction action, String status, String transcriptId) {}
    public record Binding(TestRun run, TestPlan plan, List<SourceAction> actions, JsonNode snapshot) {
        public CaseContext context(Clock clock, List<TranscriptEntry> originals) {
            var copy = List.copyOf(originals);
            var recorder = new TranscriptRecorder() {
                public List<TranscriptEntry> list(String id) { require(run.id().equals(id)); return copy; }
                public TranscriptEntry record(TranscriptInput input) { throw new UnsupportedOperationException("Source originals are read-only"); }
                public TranscriptEntry updateSamlAnalysis(String id,String correlation,Map<String,Object> summary) { throw new UnsupportedOperationException("Source originals are read-only"); }
            };
            return new DefaultCaseContext(run.id(), plan.profile().role(), clock, plan.parameters(), plan.interaction(), run.targetToSuiteReachability(), recorder, true);
        }
    }
    private static String hash(String value) throws Exception { return DefaultAlgorithmPreventionEvidence.hash(value.getBytes(java.nio.charset.StandardCharsets.UTF_8)); }
    private static String text(JsonNode node,String key) { return DefaultAlgorithmPreventionEvidence.text(node,key); }
    private static void require(boolean value) { DefaultAlgorithmPreventionEvidence.require(value); }
}
