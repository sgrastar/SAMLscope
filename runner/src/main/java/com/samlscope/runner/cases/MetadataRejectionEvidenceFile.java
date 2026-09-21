package com.samlscope.runner.cases;

import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
import com.samlscope.core.caseexec.CaseContext;
import com.samlscope.core.transcript.*;
import com.samlscope.store.JsonCodec;

/**
 * Local trusted-adapter input for native metadata rejection. A product that refuses a fixture through
 * its own metadata path can satisfy an approved reject obligation, but only when the receipt is bound
 * to the Run's fetched original for that variant. Silence is never accepted here.
 */
final class MetadataRejectionEvidenceFile {
    private final Path directory;
    MetadataRejectionEvidenceFile(Path directory){this.directory=directory.toAbsolutePath().normalize();}
    boolean exists(String runId){return runId!=null&&runId.matches("run_[0-9A-HJKMNP-TV-Z]{26}")
            &&Files.exists(directory.resolve(runId+".json"),LinkOption.NOFOLLOW_LINKS);}

    /** Returns variant -> native evidence source for every reject fixture the product refused. */
    Map<String,String> rejectedVariants(CaseContext context, byte[] target, TranscriptContentReader content)throws Exception{
        require(context.runId().matches("run_[0-9A-HJKMNP-TV-Z]{26}"));
        var path=directory.resolve(context.runId()+".json");
        if(!Files.exists(path,LinkOption.NOFOLLOW_LINKS))return Map.of();
        require(Files.isRegularFile(path,LinkOption.NOFOLLOW_LINKS)&&Files.size(path)<=1048576&&context.transcriptComplete());
        var receipt=new JsonCodec().mapper().readTree(Files.readAllBytes(path));
        require("samlscope-native-metadata-rejection-receipt-v1".equals(text(receipt,"schema"))
                &&context.runId().equals(text(receipt,"runId")));
        require(receipt.path("restored").asBoolean(false));
        require(hash(target).equals(text(receipt,"targetMetadataSha256")));
        var adapter=text(receipt,"evidenceAdapter");
        require(Set.of("shibboleth-resolver","simplesamlphp-parser","keycloak-import").contains(adapter));
        var entries=new HashMap<String,TranscriptEntry>();
        var preparedByVariant=new HashMap<String,TranscriptEntry>();
        var originals=new HashMap<String,String>();
        for(var e:context.transcript().list(context.runId())){
            require(context.runId().equals(e.runId())&&entries.put(e.id(),e)==null);
            if(e.direction()==Direction.OUTBOUND&&"MetadataPrepared".equals(e.samlSummary().get("type"))
                    &&e.samlSummary().get("variant") instanceof String variant)preparedByVariant.put(variant,e);
        }
        require(receipt.path("rawEvidence").isArray());
        for(var ref:receipt.path("rawEvidence")){
            var entry=entries.get(text(ref,"reference"));require(entry!=null);
            var digest=hash(content.readDecodedSaml(entry));require(digest.equals(text(ref,"sha256")));
            require(originals.put(entry.id(),digest)==null);
        }
        require(receipt.path("rejections").isArray()&&!receipt.path("rejections").isEmpty());
        var result=new LinkedHashMap<String,String>();
        for(var rejection:receipt.path("rejections")){
            var variant=text(rejection,"variant");
            var prepared=preparedByVariant.get(variant);require(prepared!=null);
            require(hash(content.readDecodedSaml(prepared)).equals(text(rejection,"fixtureSha256")));
            require(originals.containsKey(prepared.id()));
            var nativeRecord=rejection.path("nativeRejection");require(nativeRecord.isObject());
            require(text(nativeRecord,"source").equals(adapter));
            require(text(nativeRecord,"detailSha256").matches("[0-9a-f]{64}"));
            require(result.put(variant,adapter)==null);
        }
        if(receipt.path("conditionIssues").isArray())require(receipt.path("conditionIssues").isEmpty());
        return Map.copyOf(result);
    }
    private static String text(com.fasterxml.jackson.databind.JsonNode node,String field){return node.path(field).asText("");}
    private static String hash(byte[] bytes)throws Exception{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));}
    private static void require(boolean condition){if(!condition)throw new IllegalArgumentException("Native metadata rejection unproven");}
}
