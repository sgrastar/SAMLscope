package com.samlscope.runner.cases;

import com.fasterxml.jackson.databind.node.ObjectNode;
import com.samlscope.core.caseexec.*;
import com.samlscope.core.plan.*;
import com.samlscope.core.run.Reachability;
import com.samlscope.core.transcript.*;
import com.samlscope.runner.DefaultCaseContext;
import com.samlscope.store.JsonCodec;
import java.nio.file.*;
import java.time.*;
import java.util.*;
import static com.samlscope.runner.cases.DefaultAlgorithmPreventionEvidence.*;

/** Read-only replay of decoder SDK originals; this helper never adopts a product finding. */
public final class VerifyShibbolethStockUnmarshaller {
    static final JsonCodec J=new JsonCodec();
    static ObjectNode node(Path file)throws Exception{return (ObjectNode)J.mapper().readTree(Files.readAllBytes(file));}
    static void save(Path file,ObjectNode n)throws Exception{Files.write(file,J.mapper().writeValueAsBytes(n));}
    public static void main(String[] args)throws Exception {
        require(args.length==3);Path parent=Path.of(args[0]),diagnostic=Path.of(args[1]),report=Path.of(args[2]);
        var entries=List.of(J.mapper().readValue(parent.resolve("transcript.json").toFile(),TranscriptEntry[].class));
        var decoded=new HashMap<String,byte[]>();for(var row:J.mapper().readTree(parent.resolve("decoded-manifest.json").toFile())) {
            byte[] bytes=Files.readAllBytes(parent.resolve(text(row,"file")));require(hash(bytes).equals(text(row,"sha256")));require(decoded.put(text(row,"id"),bytes)==null);
        }
        var input=node(diagnostic.resolve("stock-unmarshaller-input.json"));String run=text(input,"runId");
        var rsa=entries.stream().filter(e->"rsa-md5".equals(e.samlSummary().get("fixture_id"))).toList();require(rsa.size()==1);
        String reference=rsa.getFirst().id();byte[] actual=decoded.get(reference);
        TranscriptRecorder recorder=new TranscriptRecorder(){
            public List<TranscriptEntry> list(String r){return run.equals(r)?entries:List.of();}
            public TranscriptEntry record(TranscriptInput i){throw new AssertionError("Original replay cannot write Recorder");}
            public TranscriptEntry updateSamlAnalysis(String id,String c,Map<String,Object>s){throw new AssertionError("Original replay cannot update Recorder");}
        };
        var context=new DefaultCaseContext(run,TargetRole.IDP,Clock.systemUTC(),new TestPlan.Parameters(180,45,"reference"),
            new TestPlan.Interaction(true,false),Reachability.CONFIRMED,recorder,true);
        TranscriptContentReader content=e->decoded.get(e.id());var scope=node(parent.resolve("receipt/before-scope-original.json"));
        byte[] suite=Files.readAllBytes(diagnostic.resolve("stock-unmarshaller-suite.xml")),target=Files.readAllBytes(parent.resolve("target-metadata.xml"));
        var use=J.mapper().createObjectNode().put("unmarshallerInvocationFile","stock-unmarshaller-invocation.json");
        var files=new LinkedHashMap<String,byte[]>();try(var paths=Files.list(diagnostic)){for(var f:paths.toList())if(Files.isRegularFile(f,LinkOption.NOFOLLOW_LINKS))files.put(f.getFileName().toString(),Files.readAllBytes(f));}
        Path temporary=Files.createTempDirectory("stock-unmarshaller-reader-replay-").toRealPath();var controls=new TreeMap<String,String>();
        try {
            for(String control:List.of("stock","foreign-run","foreign-reference","foreign-original-path","request-hash","normal-rejected",
                    "rsa-accepted","unrelated-exception","false-class-fingerprint","false-jar-origin","native-runtime-changed",
                    "policy-changed","private-key-read","temporary-not-removed","wrong-consumer-command","producer-replaced")) {
                for(var f:files.entrySet())Files.write(temporary.resolve(f.getKey()),f.getValue());
                var call=node(temporary.resolve("stock-unmarshaller-invocation.json"));var out=node(temporary.resolve(text(call,"stdoutFile")));
                var in=node(temporary.resolve(text(call,"inputFile")));var operations=node(temporary.resolve(text(call,"operationsFile")));
                ObjectNode normal=(ObjectNode)out.path("records").get(0),weak=(ObjectNode)out.path("records").get(1);
                switch(control) {
                    case "foreign-run"->out.put("runId","run_00000000000000000000000000");
                    case "foreign-reference"->((ObjectNode)in.path("records").get(1)).put("requestReference","tx_00000000000000000000000000");
                    case "foreign-original-path"->((ObjectNode)in.path("records").get(1)).put("originalPath","transcripts/other/foreign.saml.xml");
                    case "request-hash"->((ObjectNode)in.path("records").get(1)).put("requestSha256","0".repeat(64));
                    case "normal-rejected"->normal.put("unmarshalled",false);
                    case "rsa-accepted"->weak.put("unmarshalled",true);
                    case "unrelated-exception"->weak.put("nativeExceptionText","Unrelated decoding error");
                    case "false-class-fingerprint"->((ObjectNode)out.path("nativeClasses").path("org.opensaml.xmlsec.signature.impl.SignatureUnmarshaller")).put("classSha256","0".repeat(64));
                    case "false-jar-origin"->((ObjectNode)out.path("nativeClasses").path("org.apache.xml.security.signature.XMLSignature")).put("jarPath","/tmp/foreign.jar");
                    case "native-runtime-changed"->{var n=node(temporary.resolve(text(call,"nativeAfterFile")));n.put("image","sha256:"+"0".repeat(64));save(temporary.resolve(text(call,"nativeAfterFile")),n);}
                    case "policy-changed"->out.put("algorithmPolicyChanged",true);
                    case "private-key-read"->out.put("privateKeysRead",true);
                    case "temporary-not-removed"->operations.put("temporaryRemoved",false);
                    case "wrong-consumer-command"->((com.fasterxml.jackson.databind.node.ArrayNode)call.path("command")).set(4,J.mapper().getNodeFactory().textNode("ForeignConsumer"));
                    case "producer-replaced"->Files.writeString(temporary.resolve(text(call,"sourceFile")),"class ForeignConsumer {}");
                }
                if(!control.equals("stock")) {
                    byte[] inBytes=J.mapper().writeValueAsBytes(in);Files.write(temporary.resolve(text(call,"inputFile")),inBytes);
                    call.put("inputSha256",hash(inBytes));out.put("inputSha256",hash(inBytes));byte[] outBytes=J.mapper().writeValueAsBytes(out);
                    Files.write(temporary.resolve(text(call,"stdoutFile")),outBytes);call.put("stdoutSha256",hash(outBytes));
                    ((com.fasterxml.jackson.databind.node.ArrayNode)operations.path("attempts")).set(0,call.deepCopy());
                    save(temporary.resolve("stock-unmarshaller-invocation.json"),call);save(temporary.resolve(text(call,"operationsFile")),operations);
                }
                boolean accepted=true;String failure="";
                try {ShibbolethStockUnmarshallerEvidence.validateInvocation(temporary,context,content,use,out,scope,suite,target,actual,reference);}
                catch(Exception unproven){accepted=false;failure=unproven.getClass().getSimpleName()+": "+unproven.getMessage();if(control.equals("stock"))unproven.printStackTrace(System.err);}
                if(control.equals("stock")&&!accepted)throw new IllegalArgumentException("Native SDK reader rejected actual originals: "+failure);
                if(!control.equals("stock"))require(!accepted);
                controls.put(control,accepted?"SDK_ORIGINALS_VERIFIED":failure);
            }
            J.mapper().writerWithDefaultPrettyPrinter().writeValue(report.toFile(),Map.of("runId",run,"controls",controls,
                "diagnosticOnly",true,"productFinding",false,"settings",0,"saml",0,"credentialPosts",0,"personOperations",0,
                "readerCodeSource",ShibbolethStockUnmarshallerEvidence.class.getProtectionDomain().getCodeSource().getLocation().toString()));
        }finally{try(var paths=Files.list(temporary)){for(var f:paths.toList())Files.delete(f);}Files.delete(temporary);}
    }
}
