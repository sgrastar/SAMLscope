package com.samlscope.runner.cases;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.*;
import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.plan.TargetRole;
import com.samlscope.core.transcript.*;
import com.samlscope.saml.normal.SecureXml;
import com.samlscope.store.JsonCodec;
import java.nio.file.*;
import java.util.*;
import java.util.function.Function;

/** Explicit cross-Run adoption for ALG08.c only; every source original/control is replayed per read. */
public final class DefaultAlgorithmSourceRunEvidence {
    public static final String SCHEMA="samlscope-default-algorithm-source-run-v1";
    public static final String SCOPE="transport-independent-unchanged-default-algorithm-prevention";
    private final Path directory,sourceDirectory;
    private final DefaultAlgorithmSourceRunStore store;
    private final TranscriptContentReader content;
    private final Function<String,byte[]> metadata;
    private final DefaultAlgorithmPreventionEvidence sourceReader;
    private final Map<String,DefaultAlgorithmSourceRunPolicy> policies;
    private final ObjectMapper json = new JsonCodec().mapper().enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION)
            .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS);
    public DefaultAlgorithmSourceRunEvidence(Path directory,Path sourceDirectory,DefaultAlgorithmSourceRunStore store,
            TranscriptContentReader content,Function<String,byte[]> metadata,DefaultAlgorithmPreventionEvidence sourceReader,
            DefaultAlgorithmSourceRunPolicy... policies) {
        this.directory=Objects.requireNonNull(directory).toAbsolutePath().normalize();
        this.sourceDirectory=Objects.requireNonNull(sourceDirectory).toAbsolutePath().normalize();
        this.store=Objects.requireNonNull(store);this.content=Objects.requireNonNull(content);
        this.metadata=Objects.requireNonNull(metadata);this.sourceReader=Objects.requireNonNull(sourceReader);
        var map=new HashMap<String,DefaultAlgorithmSourceRunPolicy>();
        for(var policy:policies)require(policy!=null&&map.put(policy.adapter(),policy)==null);this.policies=Map.copyOf(map);
    }
    public boolean exists(String run) { return run!=null&&run.matches("run_[0-9A-HJKMNP-TV-Z]{26}")&&Files.exists(directory.resolve(run),LinkOption.NOFOLLOW_LINKS); }
    public Optional<CaseOutcome> evaluate(CaseContext destination) {
        try { return Optional.of(verified(destination)); } catch(Exception missing) { return Optional.empty(); }
    }
    CaseOutcome verified(CaseContext destination) throws Exception {
            require(exists(destination.runId())&&destination.transcriptComplete()&&destination.targetRole()==TargetRole.IDP);
            var folder=directory.resolve(destination.runId()); byte[] raw=original(folder,"manifest.json"); var m=json.readTree(raw);
            require(SCHEMA.equals(text(m,"schema"))&&destination.runId().equals(text(m,"runId"))
                    &&DefaultAlgorithmComparison.CASE.equals(text(m,"caseId"))&&SCOPE.equals(text(m,"scope"))
                    &&"ecp_idp".equals(text(m,"profile"))&&"browser_sso_idp".equals(text(m,"sourceProfile"))
                    &&m.path("counterfactualCalibrationOnly").isBoolean()&&!m.path("counterfactualCalibrationOnly").booleanValue()
                    &&m.path("ecpProtocolTrafficVerified").isBoolean()&&!m.path("ecpProtocolTrafficVerified").booleanValue()
                    &&store.approvedCaseDigest().equals(text(m,"caseDigest")));
            String sourceRun=text(m,"sourceRunId");require(!sourceRun.equals(destination.runId()));
            var current=store.execution(destination.runId());var source=store.execution(sourceRun);
            require("ecp_idp".equals(current.plan().profile().id())&&"browser_sso_idp".equals(source.plan().profile().id())
                    &&current.plan().parameters().equals(destination.parameters())&&current.plan().interaction().equals(destination.interaction())
                    &&current.run().targetToSuiteReachability()==destination.reachability()
                    &&current.plan().target().entityId().equals(text(m,"targetEntityId"))
                    &&source.plan().target().entityId().equals(text(m,"targetEntityId"))
                    &&current.plan().id().equals(text(m,"planId"))&&source.plan().id().equals(text(m,"sourcePlanId"))
                    &&source.snapshot().equals(json.readTree(original(folder,text(m,"sourceStoreSnapshotFile")))));
            var files=m.path("files");require(files.isObject()&&!files.isEmpty());
            var names=files.fieldNames();while(names.hasNext()){String name=names.next();require(hash(original(folder,name)).equals(text(files,name)));}
            byte[] currentTarget=metadata.apply(destination.runId()),sourceTarget=metadata.apply(sourceRun);
            require(Arrays.equals(currentTarget,sourceTarget)&&hash(currentTarget).equals(text(m,"targetMetadataSha256")));
            require(text(m,"targetEntityId").equals(SecureXml.parse(currentTarget).getDocumentElement().getAttribute("entityID")));
            var sourceFolder=sourceDirectory.resolve(sourceRun);byte[] sourceManifestRaw=original(sourceFolder,"manifest.json");
            require(hash(sourceManifestRaw).equals(text(m,"sourceManifestSha256")));var sourceManifest=json.readTree(sourceManifestRaw);
            require(sourceRun.equals(text(sourceManifest,"runId"))&&text(m,"targetMetadataSha256").equals(text(sourceManifest,"targetMetadataSha256")));
            var history=destination.transcript().listBounded(sourceRun,10_000);
            require(store.history(sourceRun,history,content).equals(json.readTree(original(folder,text(m,"sourceTranscriptSnapshotFile")))));
            validateOutbox(source,history,sourceManifest);
            var policy=policies.get(text(m,"adapter"));require(policy!=null);
            var nativeRefs=policy.verify(destination,folder,m,sourceFolder,sourceManifest);require(!nativeRefs.isEmpty());
            // Keep the original browser Run identity, parameters, interaction, signing key, and Recorder history.
            var observed=sourceReader.evaluate(source.context(destination.clock(),history)).orElseThrow();
            require(Set.of(Outcome.SATISFIED,Outcome.VIOLATED).contains(observed.outcome())
                    &&Boolean.FALSE.equals(observed.details().get("counterfactual_calibration_only"))
                    &&new HashSet<>(DefaultAlgorithmComparison.REQUIRED).equals(new HashSet<>((Collection<?>)observed.details().get("completed_observations"))));
            var refs=new ArrayList<EvidenceRef>();refs.addAll(nativeRefs);
            refs.add(new EvidenceRef("default-algorithm-source-run-evidence",destination.runId()+"/manifest.json#sha256="+hash(raw)));
            for(var ref:observed.evidence())refs.add(new EvidenceRef("source-run-"+ref.kind(),
                    ref.reference().startsWith(sourceRun+"/")?ref.reference():sourceRun+"/"+ref.reference()));
            var details=new LinkedHashMap<>(observed.details());details.put("run_id",destination.runId());details.put("profile","ecp_idp");
            details.put("source_run_id",sourceRun);details.put("source_plan_id",source.plan().id());details.put("source_profile","browser_sso_idp");
            details.put("source_manifest_sha256",hash(sourceManifestRaw));details.put("source_run_binding_scope",SCOPE);
            details.put("ecp_protocol_traffic_verified",false);details.put("approved_case_digest",store.approvedCaseDigest());
            return new CaseOutcome(observed.outcome(),null,observed.reasonCode(),observed.reasonMessageKey(),refs,details);
    }
    private void validateOutbox(DefaultAlgorithmSourceRunStore.Binding source,List<TranscriptEntry> history,JsonNode manifest)throws Exception {
        require(source.actions().size()==DefaultAlgorithmComparison.REQUIRED.size()); var seen=new HashSet<String>();
        for(String fixture:DefaultAlgorithmComparison.REQUIRED) {
            String id=DefaultAlgorithmPreventionProbeTestCase.action(source.run().id(),fixture);
            var actions=source.actions().stream().filter(a->id.equals(a.action().actionId())).toList();require(actions.size()==1&&seen.add(id));
            var row=actions.getFirst();require("SENT".equals(row.status())&&!row.action().requiresEphemeralCredential());
            var observations=new ArrayList<JsonNode>();for(var observation:manifest.path("observations"))if(fixture.equals(text(observation,"fixtureId")))observations.add(observation);
            require(observations.size()==1);var observation=observations.getFirst();
            var requests=history.stream().filter(e->e.direction()==Direction.OUTBOUND&&id.equals(e.samlSummary().get("action_id"))).toList();
            require(requests.size()==1);var entry=requests.getFirst();require(entry.id().equals(text(observation,"requestReference")));
            require(id.equals(entry.correlationId()));
            require(id.equals(entry.samlSummary().get("action_id")));
            require(row.action().target().toString().equals(entry.url()));
            require(Arrays.equals(row.action().payload(),content.readDecodedSaml(entry)));
            // A SENT front-channel row points to its inbound completion, rather than its outbound intent.
            var completions=history.stream().filter(e->Objects.equals(row.transcriptId(),e.id())).toList();require(completions.size()==1);
            var completion=completions.getFirst();require(completion.direction()==Direction.INBOUND&&!completion.timestamp().isBefore(entry.timestamp()));
            if(observation.path("responseReference").isTextual()) {
                require(row.transcriptId().equals(text(observation,"responseReference"))
                        &&("_"+id).equals(completion.samlSummary().get("inResponseTo"))
                        &&Boolean.TRUE.equals(completion.samlSummary().get("activeProbeAccepted"))
                        &&Set.of(id,"_"+id).contains(completion.correlationId()));
            } else require("BROWSER".equals(completion.method())&&id.equals(completion.correlationId())
                    &&"BrowserResponseObservation".equals(completion.samlSummary().get("type"))
                    &&completion.url().equals(entry.url())&&completion.status()!=null
                    &&completion.samlSummary().get("http_status") instanceof Number status&&status.intValue()==completion.status());
        }
    }
    static byte[] original(Path folder,String name)throws Exception{return DefaultAlgorithmPreventionEvidence.original(folder,name);}
    static String text(JsonNode node,String key){return DefaultAlgorithmPreventionEvidence.text(node,key);}
    static String hash(byte[] raw)throws Exception{return DefaultAlgorithmPreventionEvidence.hash(raw);}
    static void require(boolean value){DefaultAlgorithmPreventionEvidence.require(value);}
}
