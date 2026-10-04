package com.samlscope.runner.cases;

import com.samlscope.core.evaluation.CaseOutcome;
import com.samlscope.core.evaluation.Outcome;
import com.samlscope.core.plan.TargetRole;
import com.samlscope.core.plan.TestPlan;
import com.samlscope.core.run.Reachability;
import com.samlscope.core.transcript.*;
import com.samlscope.runner.DefaultCaseContext;
import com.samlscope.saml.crypto.FilePlanKeyStore;
import com.samlscope.saml.crypto.PlanCredentials;
import com.samlscope.saml.normal.SecureXml;
import com.samlscope.store.JsonCodec;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.time.Clock;
import java.util.*;

/** Run inside Suite: replay original signatures and decryption using its unexported keys. */
public final class VerifyMetadataIntersectionCapabilityEvidence {
    private static final JsonCodec JSON=new JsonCodec();
    private static String sha(byte[] raw) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(raw));
    }
    private static TranscriptEntry replacement(TranscriptEntry e,String run,Map<String,Object> summary) {
        return new TranscriptEntry(e.id(),run,e.direction(),e.timestamp(),e.correlationId(),e.method(),e.url(),e.status(),
                e.headers(),e.bodyRef(),e.bodyBytes(),e.decodedSamlRef(),e.decodedSamlBytes(),e.contentType(),e.rawQuery(),summary);
    }
    private static CaseOutcome observe(String run,List<TranscriptEntry> entries,Map<String,byte[]> bodies,byte[] target,
            String plan,Path data,boolean wrongControlKey) {
        var recorder=new TranscriptRecorder() {
            public List<TranscriptEntry> list(String id) { if(!run.equals(id))throw new IllegalArgumentException();return entries; }
            public TranscriptEntry record(TranscriptInput input) {throw new UnsupportedOperationException();}
            public TranscriptEntry updateSamlAnalysis(String id,String correlation,Map<String,Object> summary) {throw new UnsupportedOperationException();}
        };
        var context=new DefaultCaseContext(run,TargetRole.IDP,Clock.systemUTC(),TestPlan.Parameters.defaults(),
                TestPlan.Interaction.defaults(),Reachability.CONFIRMED,recorder,true);
        var store=new FilePlanKeyStore(data,Clock.systemUTC());
        java.util.function.BiFunction<String,String,Optional<PlanCredentials>> keys=(id,variant)-> {
            try {
                if(!run.equals(id))return Optional.empty();
                if(wrongControlKey&&variant.equals("control"))variant="algorithm-entity-sha256";
                var alias="poll-"+sha(variant.getBytes(StandardCharsets.UTF_8)).substring(0,16);
                if(!Files.isRegularFile(data.resolve("keys").resolve(plan).resolve(alias).resolve("signing-key.pk8")))
                    return Optional.empty();
                return Optional.of(store.getOrCreate(plan,alias));
            } catch(Exception unavailable) {return Optional.empty();}
        };
        return MetadataIntersectionEvidence.observe(context,entry->bodies.get(entry.id()),target,keys);
    }
    public static void main(String[] args) throws Exception {
        if(args.length!=3)throw new IllegalArgumentException("folder data output required");
        var folder=Path.of(args[0]).toAbsolutePath();var data=Path.of(args[1]);var output=Path.of(args[2]);
        if(Files.exists(output))throw new IllegalArgumentException("Immutable output exists");
        var created=JSON.mapper().readTree(folder.resolve("created.json").toFile());
        var run=created.at("/run/id").asText();var plan=created.at("/run/planId").asText();
        var entries=List.of(JSON.mapper().readValue(folder.resolve("transcript.json").toFile(),TranscriptEntry[].class));
        var prefix=List.of(JSON.mapper().readValue(folder.resolve("transcript-before.json").toFile(),TranscriptEntry[].class));
        if(entries.size()<=prefix.size()||!entries.subList(0,prefix.size()).equals(prefix))throw new IllegalArgumentException("Original prefix differs");
        var bodies=new HashMap<String,byte[]>();
        var byId=new HashMap<String,TranscriptEntry>();for(var e:entries)if(byId.put(e.id(),e)!=null)throw new IllegalArgumentException("Duplicate entry");
        for(var row:JSON.mapper().readTree(folder.resolve("decoded-manifest.json").toFile())) {
            var path=folder.resolve(row.path("file").asText()).normalize();
            if(!path.getParent().equals(folder.resolve("decoded")))throw new IllegalArgumentException("Unsafe original");
            var raw=Files.readAllBytes(path);var id=row.path("id").asText();var e=byId.get(id);
            if(!sha(raw).equals(row.path("sha256").asText())||e==null||e.decodedSamlBytes()!=raw.length||bodies.put(id,raw)!=null)
                throw new IllegalArgumentException("Original hash/identity differs");
        }
        var target=Files.readAllBytes(folder.resolve("target-metadata.xml"));
        var base=observe(run,entries,bodies,target,plan,data,false);
        if(base.outcome()!=Outcome.VIOLATED)throw new IllegalStateException("Unexpected complete outcome "+base.outcome()+" "+base.details());
        var checks=new TreeMap<String,String>();checks.put("complete-native-campaign",base.outcome().name());
        var control=entries.subList(prefix.size(),entries.size()).stream().filter(e->e.direction()==Direction.INBOUND
                && "Response".equals(e.samlSummary().get("type"))).reduce((a,b)->b).orElseThrow();
        for(var name:List.of("without-capability-controls","missing-sha384-control","foreign-run-control",
                "foreign-target-metadata","foreign-target-key","corrupt-control-signature","uncorrelated-control-response",
                "wrong-control-decryption-key","missing-matrix-member","split-matrix-campaigns","unconfirmed-preparation")) {
            var changedEntries=new ArrayList<>(entries);var changedBodies=new HashMap<>(bodies);var changedTarget=target;
            boolean wrongKey=false;
            switch(name) {
                case "without-capability-controls" -> changedEntries=new ArrayList<>(prefix);
                case "missing-sha384-control" -> changedEntries.removeIf(e->e.id().equals(control.id()));
                case "foreign-run-control" -> changedEntries.set(changedEntries.indexOf(control),replacement(control,"run_00000000000000000000000000",control.samlSummary()));
                case "foreign-target-metadata" -> changedTarget=new String(target,StandardCharsets.UTF_8)
                        .replace("http://localhost:18380/idp","https://other.example/idp").getBytes(StandardCharsets.UTF_8);
                case "foreign-target-key" -> {
                    var document=SecureXml.parse(target);var certs=document.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#","X509Certificate");
                    var alias="poll-"+sha("control".getBytes(StandardCharsets.UTF_8)).substring(0,16);
                    var cert=new FilePlanKeyStore(data,Clock.systemUTC()).getOrCreate(plan,alias).certificate();
                    for(int i=0;i<certs.getLength();i++)certs.item(i).setTextContent(Base64.getEncoder().encodeToString(cert.getEncoded()));
                    changedTarget=SecureXml.serialize(document);
                }
                case "corrupt-control-signature","uncorrelated-control-response" -> {
                    var document=SecureXml.parse(bodies.get(control.id()));
                    if(name.equals("corrupt-control-signature")) {
                        var signature=document.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#","SignatureValue").item(0);
                        var decoded=Base64.getMimeDecoder().decode(signature.getTextContent());decoded[0]^=1;
                        signature.setTextContent(Base64.getEncoder().encodeToString(decoded));
                    } else document.getDocumentElement().setAttribute("InResponseTo","_unrelated-request");
                    changedBodies.put(control.id(),SecureXml.serialize(document));
                }
                case "wrong-control-decryption-key" -> wrongKey=true;
                case "missing-matrix-member" -> changedEntries.removeIf(e->e.direction()==Direction.INBOUND
                        && "Response".equals(e.samlSummary().get("type"))&&prefix.contains(e)
                        && String.valueOf(e.samlSummary().get("inResponseTo")).equals(prefix.stream().filter(q->
                            "algorithm-entity-sha256".equals(q.samlSummary().get("variant"))
                            &&"valid".equals(q.samlSummary().get("metadataSignatureControl")))
                            .findFirst().orElseThrow().samlSummary().get("id")));
                case "split-matrix-campaigns" -> {
                    var request=prefix.stream().filter(e->"algorithm-entity-sha256".equals(e.samlSummary().get("variant"))
                            && "valid".equals(e.samlSummary().get("metadataSignatureControl"))).findFirst().orElseThrow();
                    var summary=new HashMap<>(request.samlSummary());summary.put("metadataSignatureGroup","poll_other:1");
                    changedEntries.set(changedEntries.indexOf(request),replacement(request,run,summary));
                }
                case "unconfirmed-preparation" -> {
                    var fallback=new InformationalChoiceTestCase(MetadataIntersectionEvidence.ID,TargetRole.IDP);
                    var testCase=new MetadataAlgorithmConfigurationTestCase(fallback,e->bodies.get(e.id()),id->target);
                    var previous=new CaseOutcome(Outcome.NOT_VERIFIED,"missing","metadata.algorithms.intersection-evidence-incomplete",
                            "missing",List.of(),Map.of("configuration_confirmed",false));
                    if(testCase.supportsRecordedEvidenceReevaluation(previous))throw new IllegalStateException("Unconfirmed adoption allowed");
                    checks.put(name,"NOT_VERIFIED");continue;
                }
                default -> throw new IllegalStateException(name);
            }
            var result=observe(run,changedEntries,changedBodies,changedTarget,plan,data,wrongKey);
            if(result.outcome()!=Outcome.NOT_VERIFIED)throw new IllegalStateException("Invalid evidence accepted: "+name+" "+result.details());
            checks.put(name,result.outcome().name());
        }
        var report=new TreeMap<String,Object>();report.put("runId",run);report.put("outcome",base.outcome().name());
        report.put("reasonCode",base.reasonCode());report.put("details",base.details());report.put("evidence",base.evidence());
        report.put("checks",checks);report.put("privateKeyExported",false);report.put("plaintextPersisted",false);
        Files.write(output,JSON.mapper().writerWithDefaultPrettyPrinter().writeValueAsBytes(report));
        System.out.println("Production intersection VIOLATED; "+(checks.size()-1)+" invalid controls rejected");
    }
}
