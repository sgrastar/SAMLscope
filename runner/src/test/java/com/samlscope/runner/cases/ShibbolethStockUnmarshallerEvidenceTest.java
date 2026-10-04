package com.samlscope.runner.cases;

import com.fasterxml.jackson.databind.node.ObjectNode;
import com.samlscope.store.JsonCodec;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class ShibbolethStockUnmarshallerEvidenceTest {
    final Instant begin=Instant.parse("2026-10-03T15:51:11Z"),end=Instant.parse("2026-10-03T15:51:12Z");
    final String thread="http-nio-8080-exec-2";
    String chain() {
        return line("org.opensaml.xmlsec.signature.impl.SignatureUnmarshaller",87,"ERROR",
                "Error constructing Apache XMLSignature instance from Signature element: "+ShibbolethStockUnmarshallerEvidence.CAUSE)
            +line("org.opensaml.messaging.decoder.servlet.BaseHttpServletRequestXMLMessageDecoder",137,"ERROR",
                "Error unmarshalling message from input stream: Unable to unmarshall Signature with Apache XMLSignature")
            +line("org.opensaml.profile.action.impl.DecodeMessage",97,"ERROR","Profile Action DecodeMessage: Unable to decode incoming request")
            +line("org.opensaml.profile.action.impl.LogEvent",94,"WARN","A non-proceed event occurred while processing the request: UnableToDecode");
    }
    String line(String type,int sourceLine,String level,String message) {
        return "2026-10-03 15:51:11,025 - 172.21.0.1 - "+level+" ["+thread+"] ["+type+":"+sourceLine+"] - "+message+"\n";
    }
    boolean accepts(String log){return ShibbolethStockUnmarshallerEvidence.decoderRejection(log,begin,end);}
    @Test void orderedActualStockDecoderChainIsUsable(){assertTrue(accepts(chain()));}
    @Test void absentAuditAndHttpErrorDoNotSupplyACause(){
        assertFalse(accepts(""));assertFalse(accepts("HTTP 400 "+ShibbolethStockUnmarshallerEvidence.CAUSE));
        assertFalse(accepts(line("org.opensaml.xmlsec.signature.impl.SignatureUnmarshaller",87,"ERROR",ShibbolethStockUnmarshallerEvidence.CAUSE)));
    }
    @Test void anotherThreadAndConcurrentDecoderRequestAreUnproven(){
        assertFalse(accepts(chain().replace("["+thread+"] [org.opensaml.profile.action.impl.DecodeMessage", "[http-nio-8080-exec-9] [org.opensaml.profile.action.impl.DecodeMessage")));
        assertFalse(accepts(chain()+chain()));
    }
    @Test void everyStageAndItsOrderAreRequired(){
        var lines=chain().lines().toList();
        for(int omitted=0;omitted<4;omitted++){var copy=new java.util.ArrayList<>(lines);copy.remove(omitted);assertFalse(accepts(String.join("\n",copy)));}
        assertFalse(accepts(lines.get(1)+"\n"+lines.get(0)+"\n"+lines.get(2)+"\n"+lines.get(3)));
    }
    @Test void OtherAlgorithmConsumerAndCauseTextCannotBeSubstituted(){
        assertFalse(accepts(chain().replace(ShibbolethStockUnmarshallerEvidence.RSA_MD5,ShibbolethStockUnmarshallerEvidence.RSA_SHA256)));
        assertFalse(accepts(chain().replace("SignatureUnmarshaller:","SignatureAlgorithmValidator:")));
        assertFalse(accepts(chain().replace("secure validation is enabled","secure validation is enabled for unrelated input")));
    }
    @Test void staleLogAndTimeReversalAreUnproven(){
        assertFalse(accepts(chain().replace("15:51:11,025","15:51:10,025")));
        assertFalse(accepts(chain().replace("15:51:11,025","15:51:12,025")));
        assertFalse(accepts(chain().replace("15:51:11,025 - 172.21.0.1 - WARN","15:51:11,024 - 172.21.0.1 - WARN")));
    }
    ObjectNode capture()throws Exception {
        var n=new JsonCodec().mapper().createObjectNode();
        n.put("schema","samlscope-shibboleth-native-audit-capture-v1").put("runId","run_00000000000000000000000001")
            .put("requestId","_actual_request").put("requestSha256","a".repeat(64))
            .put("path","/opt/reference-idp/logs/idp-audit.log").put("inode",17).put("beforeOffset",1024).put("afterOffset",1024)
            .put("beforeCapturedAt","2026-10-03T15:51:11.001Z").put("afterCapturedAt","2026-10-03T15:51:11.090Z")
            .put("deltaBytes",0).put("deltaSha256",DefaultAlgorithmPreventionEvidence.hash(new byte[0]))
            .put("matchingAuditCount",0).put("decisionEvidence",false);return n;
    }
    void check(ObjectNode n)throws Exception {
        var http=new JsonCodec().mapper().createObjectNode().put("startedAt","2026-10-03T15:51:11.010Z").put("completedAt","2026-10-03T15:51:11.080Z");
        ShibbolethStockUnmarshallerEvidence.validateAuditCapture(n,"run_00000000000000000000000001","_actual_request","a".repeat(64),http,begin,end);
    }
    @Test void emptyCaptureRequiresActualRunRequestRangeAndTimeWindow()throws Exception {
        assertDoesNotThrow(()->check(capture()));
        for(String field:List.of("schema","runId","requestId","requestSha256","path","deltaSha256")){
            var n=capture();n.put(field,"foreign");assertThrows(IllegalArgumentException.class,()->check(n));
        }
        for(String field:List.of("inode","beforeOffset","afterOffset","deltaBytes","matchingAuditCount")){
            var n=capture();n.put(field,-1);assertThrows(IllegalArgumentException.class,()->check(n));
        }
        var declared=capture();declared.put("decisionEvidence",true);assertThrows(IllegalArgumentException.class,()->check(declared));
    }
    @Test void laterCaptureCannotInventEarlierOperationOffsets()throws Exception {
        for(var entry:List.of(java.util.Map.entry("beforeCapturedAt","2026-10-03T15:51:11.020Z"),
            java.util.Map.entry("afterCapturedAt","2026-10-03T15:51:11.070Z"),
            java.util.Map.entry("beforeCapturedAt","2026-10-03T15:51:10Z"),
            java.util.Map.entry("afterCapturedAt","2026-10-03T15:51:13Z"))) {
            var n=capture();n.put(entry.getKey(),entry.getValue());assertThrows(IllegalArgumentException.class,()->check(n));
        }
    }
}
