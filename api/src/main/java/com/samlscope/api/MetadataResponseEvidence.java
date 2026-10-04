package com.samlscope.api;

import java.time.Clock;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import com.samlscope.core.transcript.Direction;
import com.samlscope.core.transcript.TranscriptEntry;
import com.samlscope.core.transcript.TranscriptInput;
import com.samlscope.core.transcript.TranscriptRecorder;

/** Captures the exact prepared metadata body; this does not assert successful delivery or consumption. */
final class MetadataResponseEvidence {
    private MetadataResponseEvidence() {}
    static void record(TranscriptRecorder recorder, TranscriptEntry fetch, byte[] payload, Clock clock) {
        if(fetch.direction()!=Direction.INBOUND || !List.of("MetadataFetch","MetadataExport").contains(fetch.samlSummary().get("type")))
            throw new IllegalArgumentException("Expected a metadata fetch or export entry");
        if(payload==null || payload.length==0)throw new IllegalArgumentException("Metadata body is empty");
        var summary=new LinkedHashMap<String,Object>();
        summary.put("type","MetadataPrepared");
        summary.put("fetchTranscriptId",fetch.id());
        summary.put("sourceType",fetch.samlSummary().get("type"));
        for(var key:List.of("variant","variants","feed"))
            if(fetch.samlSummary().containsKey(key))summary.put(key,fetch.samlSummary().get(key));
        try {
            summary.put("metadataSha256",java.util.HexFormat.of().formatHex(
                    java.security.MessageDigest.getInstance("SHA-256").digest(payload)));
        } catch(java.security.NoSuchAlgorithmException impossible) { throw new IllegalStateException(impossible); }
        summary.put("delivery","PREPARED");
        recorder.record(new TranscriptInput(fetch.runId(),Direction.OUTBOUND,clock.instant(),fetch.id(),
                "GET",fetch.url(),200,Map.of("Content-Type",List.of("application/samlmetadata+xml")),
                payload,"application/samlmetadata+xml",null,payload,summary));
    }
}
