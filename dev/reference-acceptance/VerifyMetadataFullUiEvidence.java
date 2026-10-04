package com.samlscope.runner.cases;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.plan.*;
import com.samlscope.core.run.Reachability;
import com.samlscope.core.transcript.*;
import com.samlscope.runner.*;
import com.samlscope.saml.normal.SecureXml;
import com.samlscope.store.JsonCodec;
import java.nio.file.*;
import java.time.Clock;
import java.util.*;

/** Archived production replay, including the real native whole-extension-ignore model mutant.
 * Every altered proof lives only in the temporary local replay folder. */
public final class VerifyMetadataFullUiEvidence {
    private static final JsonCodec JSON = new JsonCodec();
    private static void require(boolean value, String message) { if (!value) throw new IllegalArgumentException(message); }
    private static String sha(byte[] bytes) throws Exception { return ShibbolethMetadataFullUiEvidence.sha(bytes); }
    private static CaseContext context(String run, List<TranscriptEntry> history, Map<String, byte[]> decoded, boolean complete) {
        var normalized = history.stream().map(e -> {
            var raw = decoded.get(e.id());
            return raw == null || raw.length == e.decodedSamlBytes() ? e : new TranscriptEntry(e.id(), e.runId(), e.direction(),
                    e.timestamp(), e.correlationId(), e.method(), e.url(), e.status(), e.headers(), e.bodyRef(), e.bodyBytes(),
                    e.decodedSamlRef(), raw.length, e.contentType(), e.rawQuery(), e.samlSummary());
        }).toList();
        var recorder = new TranscriptRecorder() {
            public List<TranscriptEntry> list(String id) { require(run.equals(id), "Foreign Run context"); return normalized; }
            public TranscriptEntry record(TranscriptInput input) { throw new UnsupportedOperationException(); }
            public TranscriptEntry updateSamlAnalysis(String id, String correlation, Map<String,Object> value) { throw new UnsupportedOperationException(); }
        };
        return new DefaultCaseContext(run, TargetRole.IDP, Clock.systemUTC(), TestPlan.Parameters.defaults(),
                TestPlan.Interaction.defaults(), Reachability.CONFIRMED, recorder, complete);
    }
    private static void write(Path folder, ObjectNode m) throws Exception {
        Files.write(folder.resolve("manifest.json"), JSON.mapper().writeValueAsBytes(m));
    }
    private static void replaceOriginal(Path folder, ObjectNode m, Map<String, byte[]> decoded, String kind, ObjectNode value) throws Exception {
        var bytes = JSON.mapper().writeValueAsBytes(value); var ref = (ObjectNode)m.path("originals").path(kind);
        decoded.put(ref.path("reference").asText(), bytes); ref.put("sha256", sha(bytes));
        String name = "native-originals/" + kind + ".json"; Files.write(folder.resolve(name), bytes);
        ((ObjectNode)m.path("files")).put(name, sha(bytes));
    }
    private static ObjectNode original(ObjectNode m, Map<String, byte[]> decoded, String kind) throws Exception {
        return (ObjectNode) JSON.mapper().readTree(decoded.get(m.path("originals").path(kind).path("reference").asText()));
    }
    private static CaseOutcome observe(Path directory, String run, List<TranscriptEntry> history,
            Map<String, byte[]> decoded, byte[] target, boolean offline, boolean complete) {
        return new ShibbolethMetadataFullUiEvidence(directory, e -> decoded.get(e.id()), offline)
                .evaluate(context(run, history, decoded, complete), target).orElseThrow();
    }
    private static void copy(Path source, Path target) throws Exception {
        try (var files = Files.walk(source)) {
            for (var file : files.toList()) {
                var destination = target.resolve(source.relativize(file));
                if (Files.isDirectory(file)) Files.createDirectories(destination);
                else { require(!Files.isSymbolicLink(file), "Symbolic original"); Files.copy(file, destination, StandardCopyOption.REPLACE_EXISTING); }
            }
        }
    }
    public static void main(String[] args) throws Exception {
        require(args.length == 2, "campaign and new report required"); Path source = Path.of(args[0]); Path report = Path.of(args[1]);
        require(!Files.exists(report), "Immutable report exists");
        String run = JSON.mapper().readTree(source.resolve("created.json").toFile()).at("/run/id").asText();
        var history = new ArrayList<>(List.of(JSON.mapper().readValue(source.resolve("transcript.json").toFile(), TranscriptEntry[].class)));
        var byId = new HashMap<String, TranscriptEntry>(); for (var e : history) require(run.equals(e.runId()) && byId.put(e.id(), e) == null, "Foreign or ambiguous history");
        var decoded = new HashMap<String, byte[]>();
        for (var row : JSON.mapper().readTree(source.resolve("decoded-manifest.json").toFile())) {
            String id = row.path("id").asText(); var file = source.resolve(row.path("file").asText()).normalize();
            require(file.getParent().equals(source.resolve("decoded")), "Foreign decoded original");
            var bytes = Files.readAllBytes(file); require(byId.containsKey(id) && sha(bytes).equals(row.path("sha256").asText())
                    && bytes.length == byId.get(id).decodedSamlBytes(), "Decoded original changed"); decoded.put(id, bytes);
        }
        byte[] target = Files.readAllBytes(source.resolve("target-metadata.xml"));
        var stock = (ObjectNode)JSON.mapper().readTree(source.resolve("receipt/manifest.json").toFile());
        var temp = Files.createTempDirectory("full-ui-replay-").toRealPath(); var directory = temp.resolve("metadata-full-ui-evidence");
        var folder = directory.resolve(run); Files.createDirectories(folder);
        try {
            copy(source.resolve("receipt"), folder);
            var outcome = observe(directory, run, history, decoded, target, false, true);
            require(outcome.outcome() == Outcome.SATISFIED, "Actual full UI native proof incomplete " + outcome);
            var controls = new TreeMap<String, String>();
            for (String name : List.of("foreign-receipt-run", "foreign-peer", "foreign-target", "wrong-adapter", "wrong-campaign",
                    "duplicate-transcript", "foreign-decoded-reference", "missing-original", "missing-fixture",
                    "unrestored-provider", "runtime-epoch-replaced", "native-http-only", "query-other-entity", "query-before-input",
                    "missing-language", "wrong-logo-dimensions", "ignored-whole-ui", "source-hash-changed", "override-view-added",
                    "hidden-operation-attempt", "calibration-label-only", "incomplete-history")) {
                copy(source.resolve("receipt"), folder); var m = stock.deepCopy(); var data = new HashMap<>(decoded); var h = new ArrayList<>(history);
                switch (name) {
                    case "foreign-receipt-run" -> m.put("runId", "run_00000000000000000000000000");
                    case "foreign-peer" -> m.put("peerEntityId", "https://different.example/p/" + m.path("planId").asText());
                    case "foreign-target" -> m.put("targetMetadataSha256", "0".repeat(64));
                    case "wrong-adapter" -> m.put("adapter", "unqualified-adapter");
                    case "wrong-campaign" -> m.put("campaignId", "unrelated-campaign");
                    case "duplicate-transcript" -> h.add(history.getFirst());
                    case "foreign-decoded-reference" -> { var e = h.getFirst(); int index = 0;
                        for (int i = 0; i < h.size(); i++) if (h.get(i).decodedSamlRef() != null) { e = h.get(i); index = i; break; }
                        h.set(index, new TranscriptEntry(e.id(), e.runId(), e.direction(), e.timestamp(), e.correlationId(), e.method(),
                            e.url(), e.status(), e.headers(), e.bodyRef(), e.bodyBytes(), "transcripts/run_00000000000000000000000000/" + e.id() + ".saml.xml",
                            e.decodedSamlBytes(), e.contentType(), e.rawQuery(), e.samlSummary())); }
                    case "missing-original" -> data.remove(m.path("originals").path("full-ui-readback").path("reference").asText());
                    case "missing-fixture" -> h.removeIf(e -> "MetadataPrepared".equals(e.samlSummary().get("type")) && "full-ui-info".equals(e.samlSummary().get("variant")));
                    case "unrestored-provider" -> { var v = original(m,data,"after"); v.put("providersBase64", Base64.getEncoder().encodeToString("<wrong/>".getBytes())); replaceOriginal(folder,m,data,"after",v); }
                    case "runtime-epoch-replaced" -> { var v = original(m,data,"full-ui-readback"); ((ObjectNode)v.path("runtime")).put("containerId", "0".repeat(64)); replaceOriginal(folder,m,data,"full-ui-readback",v); }
                    case "native-http-only" -> { var v=original(m,data,"full-ui-readback"); ((ObjectNode)v.path("query")).put("exitCode",1); replaceOriginal(folder,m,data,"full-ui-readback",v); }
                    case "query-other-entity" -> { var v=original(m,data,"full-ui-readback"); var q=(ObjectNode)v.path("query"); var a=(com.fasterxml.jackson.databind.node.ArrayNode)q.path("command"); a.set(a.size()-1,JSON.mapper().getNodeFactory().textNode("https://foreign.example/sp")); replaceOriginal(folder,m,data,"full-ui-readback",v); }
                    case "query-before-input" -> { var v=original(m,data,"full-ui-readback"); ((ObjectNode)v.path("query")).put("startedAt","2020-01-01T00:00:00Z"); replaceOriginal(folder,m,data,"full-ui-readback",v); }
                    case "missing-language", "wrong-logo-dimensions", "ignored-whole-ui" -> {
                        var v=original(m,data,"full-ui-readback"); var q=(ObjectNode)v.path("query"); var xml=SecureXml.parse(Base64.getDecoder().decode(q.path("stdoutBase64").asText()));
                        String ui=MetadataFullUiComparison.UI;
                        if(name.equals("ignored-whole-ui")) { for(String kind:List.of("UIInfo","DiscoHints")){var n=xml.getElementsByTagNameNS(ui,kind).item(0);n.getParentNode().removeChild(n);} }
                        else if(name.equals("wrong-logo-dimensions")) ((org.w3c.dom.Element)xml.getElementsByTagNameNS(ui,"Logo").item(0)).setAttribute("width","181");
                        else { var n=xml.getElementsByTagNameNS(ui,"Description").item(1); n.getParentNode().removeChild(n); }
                        var bytes=SecureXml.serialize(xml);q.put("stdoutBase64",Base64.getEncoder().encodeToString(bytes));q.put("stdoutSha256",sha(bytes));replaceOriginal(folder,m,data,"full-ui-readback",v);
                    }
                    case "source-hash-changed" -> { var bytes=Files.readAllBytes(folder.resolve("native-saml.jar"));bytes[100]^=1;Files.write(folder.resolve("native-saml.jar"),bytes);((ObjectNode)m.path("files")).put("native-saml.jar",sha(bytes)); }
                    case "override-view-added" -> { var bytes="/opt/reference-idp/views/admin/mdquery.vm\n".getBytes();Files.write(folder.resolve("native-override-inventory.txt"),bytes);((ObjectNode)m.path("files")).put("native-override-inventory.txt",sha(bytes)); }
                    case "hidden-operation-attempt" -> { var v=original(m,data,"operations");v.put("configurationWriteAttempts",0);replaceOriginal(folder,m,data,"operations",v); }
                    case "calibration-label-only" -> m.set("calibration",JSON.mapper().createObjectNode().put("counterfactualCalibrationOnly",true));
                    default -> { }
                }
                write(folder,m); var next=observe(directory,run,h,data,target,false,!name.equals("incomplete-history"));
                require(next.outcome()==Outcome.NOT_VERIFIED,name+" false conclusion "+next);controls.put(name,next.outcome().name());
            }
            copy(source.resolve("receipt"),folder); var calibrated=stock.deepCopy();
            var cal=JSON.mapper().readTree(source.resolve("calibration/receipt-calibration.json").toFile());
            calibrated.set("calibration",cal.path("calibration"));
            var calFiles=cal.path("files").fields(); while(calFiles.hasNext()){var e=calFiles.next();var src=source.resolve("calibration").resolve(e.getKey());var dst=folder.resolve(e.getKey());Files.createDirectories(dst.getParent());Files.copy(src,dst,StandardCopyOption.REPLACE_EXISTING);((ObjectNode)calibrated.path("files")).set(e.getKey(),e.getValue());}
            write(folder,calibrated); var publicMutant=observe(directory,run,history,decoded,target,false,true);
            var mutant=observe(directory,run,history,decoded,target,true,true);
            require(publicMutant.outcome()==Outcome.NOT_VERIFIED&&mutant.outcome()==Outcome.VIOLATED,"Native detector or offline boundary incomplete");
            copy(source.resolve("receipt"),folder); var reader=new ShibbolethMetadataFullUiEvidence(directory,e->decoded.get(e.id()));
            var delegate=new TestCase(){public String id(){return MetadataFullUiConfigurationTestCase.CASE;}public TargetRole role(){return TargetRole.IDP;}public CaseStep start(CaseContext c){throw new AssertionError("Old import delegate called");}public CaseStep resume(CaseContext c,CaseState s,CaseEvent e){throw new AssertionError("Old import delegate called");}};
            var wrapper=new MetadataFullUiConfigurationTestCase(delegate,reader,r->target);var c=context(run,history,decoded,true);var lifecycle=new TreeMap<String,Object>();
            lifecycle.put("start",((CaseStep.Finish)wrapper.start(c)).outcome().equals(outcome));
            lifecycle.put("confirm",((CaseStep.Finish)wrapper.resume(c,new CaseState("old-import-phase",Map.of()),new CaseEvent.ConfigConfirmed())).outcome().equals(outcome));
            lifecycle.put("status-ready",wrapper.evidenceStatus(c).ready());
            lifecycle.put("nv-reevaluation",wrapper.reevaluateRecordedEvidence(c,CaseOutcome.notVerified("pending","case.pending-interaction")).orElseThrow().equals(outcome));
            lifecycle.put("conclusive-unchanged",wrapper.reevaluateRecordedEvidence(c,outcome).isEmpty());
            lifecycle.put("configuration-unavailable-nv",((CaseStep.Finish)wrapper.resume(c,new CaseState("old",Map.of()),new CaseEvent.ConfigUnavailable(CaseEvent.ConfigurationIssue.CAPABILITY_ABSENT,"native export unavailable"))).outcome().outcome()==Outcome.NOT_VERIFIED);
            require(lifecycle.values().stream().allMatch(Boolean.TRUE::equals),"Full UI wrapper lifecycle differs");
            var result=new LinkedHashMap<String,Object>(); result.put("runId",run);result.put("targetMetadataSha256",sha(target));result.put("outcome",outcome);result.put("negativeControls",controls);result.put("approvedMutant",mutant);result.put("productionMutantOutcome",publicMutant);result.put("wrapperLifecycle",lifecycle);result.put("settings",0);result.put("saml",0);result.put("credentials",0);result.put("counterfactualAdopted",false);
            Files.write(report,JSON.mapper().writerWithDefaultPrettyPrinter().writeValueAsBytes(result));
        } finally { try(var files=Files.walk(temp)){for(var file:files.sorted(Comparator.reverseOrder()).toList())Files.delete(file);} }
    }
}
