package com.samlscope.runner.cases;

import static org.junit.jupiter.api.Assertions.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.time.*;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import com.samlscope.core.transcript.*;
import com.samlscope.core.evaluation.EvidenceRef;
import com.samlscope.core.plan.*;
import com.samlscope.core.run.Reachability;
import com.samlscope.runner.DefaultCaseContext;
import com.samlscope.store.JsonCodec;

class AttributePolicyPreparationFileTest {
    @TempDir Path directory;
    private static final String RUN="run_00000000000000000000000000", HASH="a".repeat(64);
    private final byte[] target="<EntityDescriptor entityID='https://idp.example'/>".getBytes(StandardCharsets.UTF_8);
    private final Map<String,byte[]> raw=new HashMap<>();
    private final List<TranscriptEntry> entries=new ArrayList<>();
    private DefaultCaseContext context() {
        return new DefaultCaseContext(RUN,TargetRole.IDP,Clock.systemUTC(),TestPlan.Parameters.defaults(),TestPlan.Interaction.defaults(),Reachability.CONFIRMED,new TranscriptRecorder(){
            public List<TranscriptEntry> list(String run){return entries;}
            public TranscriptEntry record(TranscriptInput input){throw new UnsupportedOperationException();}
            public TranscriptEntry updateSamlAnalysis(String id,String correlation,Map<String,Object>summary){throw new UnsupportedOperationException();}
        },true);
    }
    private String hash(byte[] bytes)throws Exception{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));}
    private AttributePolicyProtocolEvidence.Collected protocol(){
        var refs=List.of("fetch","prepared","request","response").stream().map(id->new EvidenceRef("transcript",id)).toList();
        return new AttributePolicyProtocolEvidence.Collected(RUN,List.of(new AttributePolicyProtocolEvidence.Observation("control","",HASH,"https://sp.example",Instant.EPOCH,Instant.EPOCH.plusSeconds(1),new AttributePolicyAttributeReader.Observation(Set.of("anchor"),HASH),refs)),List.of());
    }
    private Map<String,Object> receipt()throws Exception{
        raw.clear();entries.clear();var digests=new ArrayList<Map<String,String>>();
        for(String id:List.of("prepared","request","response")){
            var bytes=("<original id='"+id+"'/>").getBytes(StandardCharsets.UTF_8);raw.put(id,bytes);
            entries.add(new TranscriptEntry(id,RUN,Direction.OUTBOUND,Instant.EPOCH,null,"POST","https://suite.example",200,Map.of(),null,0,id,bytes.length,null,null,Map.of()));
            digests.add(Map.of("reference",id,"sha256",hash(bytes)));
        }
        var binding=new AttributePolicyExperimentBinding.ExchangePreparation(AttributePolicyComparison.Condition.BASELINE,"request","response",HASH,HASH,HASH);
        return new HashMap<>(Map.of("schema","samlscope-native-attribute-policy-receipt-v1","runId",RUN,"targetEntityId","https://idp.example","targetMetadataSha256",hash(target),"preparation",new AttributePolicyExperimentBinding.Preparation(RUN,"experiment",List.of(binding)),"rawEvidence",digests));
    }
    private void save(Map<String,Object> receipt)throws Exception{new JsonCodec().mapper().writeValue(directory.resolve(RUN+".json").toFile(),receipt);}
    @Test void acceptsOnlyTheMatchingTargetAndOriginalHashes()throws Exception{
        var loader=new AttributePolicyPreparationFile(directory);
        assertTrue(loader.read(context(),target,e->raw.get(e.id()),protocol()).isEmpty());
        save(receipt());assertTrue(loader.read(context(),target,e->raw.get(e.id()),protocol()).isPresent());
        raw.put("request","<changed/>".getBytes(StandardCharsets.UTF_8));
        assertThrows(IllegalArgumentException.class,()->loader.read(context(),target,e->raw.get(e.id()),protocol()));
        for(String field:List.of("runId","targetEntityId","targetMetadataSha256")){
            var receipt=receipt();receipt.put(field,"wrong");save(receipt);
            assertThrows(IllegalArgumentException.class,()->loader.read(context(),target,e->raw.get(e.id()),protocol()),field);
        }
    }
    @Test void receiptCannotSupplyMissingOriginalsOrSubstituteASymlink()throws Exception{
        var loader=new AttributePolicyPreparationFile(directory);var receipt=receipt();receipt.put("rawEvidence",List.of());save(receipt);
        assertThrows(IllegalArgumentException.class,()->loader.read(context(),target,e->raw.get(e.id()),protocol()));
        save(receipt());var original=directory.resolve(RUN+".json");var other=directory.resolve("other.json");Files.move(original,other);Files.createSymbolicLink(original,other);
        assertThrows(IllegalArgumentException.class,()->loader.read(context(),target,e->raw.get(e.id()),protocol()));
    }
}
