package com.samlscope.runner.cases;

import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.*;
import com.fasterxml.jackson.databind.JsonNode;
import com.samlscope.core.caseexec.CaseContext;
import com.samlscope.core.evaluation.EvidenceRef;
import com.samlscope.core.transcript.*;
import com.samlscope.runner.scenario.TargetHttpObservation;
import com.samlscope.store.JsonCodec;

/** Public, request-bound terminal evidence. A bare HTTP error or missing callback is never proof. */
public final class VersionMismatchTerminalEvidence {
    public static final String SCHEMA = "samlscope-native-version-terminal-v1";
    static final String SSP_UTILS_SHA = "5845e28158c7641d5ce1e6b9205e8005b6d9c090e1888ea46416abb8fdf0018d";
    static final String SSP_MESSAGE_SHA = "42334f0f2d0590a82371552bccea01ffc5bb73cc8fe3849a190d62f0809d481e";
    private final Path directory;
    private final TranscriptContentReader content;
    public VersionMismatchTerminalEvidence(Path directory,TranscriptContentReader content) {
        this.directory=directory.toAbsolutePath().normalize();this.content=Objects.requireNonNull(content);
    }
    public boolean exists(String run) { return Files.exists(directory.resolve(run+".json"),LinkOption.NOFOLLOW_LINKS)
            || Files.exists(directory.resolve(run),LinkOption.NOFOLLOW_LINKS); }
    record Proof(List<EvidenceRef> evidence) {}
    Optional<Proof> read(CaseContext c, TranscriptEntry request, String requestId,
            TranscriptEntry browser, byte[] requestBytes, byte[] targetMetadata) {
        try {
            require(c.runId().matches("run_[0-9A-HJKMNP-TV-Z]{26}"));
            Path folder=directory.resolve(c.runId()); byte[] raw=read(directory.resolve(c.runId()+".json"),1048576);
            JsonNode m=new JsonCodec().mapper().readTree(raw);
            require(SCHEMA.equals(text(m,"schema")) && c.runId().equals(text(m,"runId"))
                    && IdpVersionMismatchScenarioTestCase.CASE_ID.equals(text(m,"caseId"))
                    && m.path("counterfactualCalibrationOnly").isBoolean() && !m.path("counterfactualCalibrationOnly").booleanValue()
                    && hash(targetMetadata).equals(text(m,"targetMetadataSha256")));
            String fixture=String.valueOf(request.samlSummary().get("fixture_id"));
            require(Set.of("version-1-1","invalid-issue-instant").contains(fixture) && m.path("terminals").isArray());
            var matches=new ArrayList<JsonNode>();for(var row:m.path("terminals"))if(fixture.equals(row.path("fixtureId").asText()))matches.add(row);
            require(matches.size()==1);var row=matches.getFirst();
            require(request.id().equals(text(row,"requestReference")) && browser.id().equals(text(row,"browserReference")));
            require(browser.direction()==Direction.INBOUND && "BROWSER".equals(browser.method())
                    && request.correlationId().equals(browser.correlationId()) && !browser.timestamp().isBefore(request.timestamp())
                    && browser.status()!=null && TargetHttpObservation.isSameOriginError(java.net.URI.create(request.url()),browser.status(),browser.url())
                    && "BrowserResponseObservation".equals(browser.samlSummary().get("type"))
                    && browser.status().equals(((Number)browser.samlSummary().get("http_status")).intValue())
                    && browser.url().equals(browser.samlSummary().get("url")) && browser.decodedSamlRef()==null
                    && browser.decodedSamlBytes()==0 && ("transcripts/"+c.runId()+"/"+browser.id()+".body").equals(browser.bodyRef()));
            require(m.path("files").isArray());var files=new HashMap<String,JsonNode>();
            for(var f:m.path("files")) require(files.put(text(f,"file"),f)==null);
            byte[] body=original(folder,files,text(row,"bodyFile")); require(body.length==browser.bodyBytes()
                    && Arrays.equals(body,read(directory.getParent().resolve(browser.bodyRef()),4194304)));
            byte[] httpOriginal=original(folder,files,text(row,"nativeHttpFile"));
            var http=new JsonCodec().mapper().readTree(httpOriginal);
            require(c.runId().equals(text(http,"runId")) && requestId.equals(text(http,"requestId"))
                    && request.correlationId().equals(text(http,"actionId")) && hash(requestBytes).equals(text(http,"requestSha256"))
                    && !request.samlSummary().containsValue("UNKNOWN_DELIVERY") && "POST".equals(text(http,"method"))
                    && request.url().equals(text(http,"requestUrl")) && browser.url().equals(text(http,"responseUrl"))
                    && http.path("responseStatus").asInt(-1)==browser.status()
                    && hash(body).equals(text(http,"responseBodySha256")) && http.path("responseBodyBytes").asLong(-1)==body.length
                    && http.path("samlResponseFormPresent").isBoolean() && !http.path("samlResponseFormPresent").booleanValue());
            var begin=Instant.parse(text(http,"startedAt"));var end=Instant.parse(text(http,"completedAt"));
            require(!begin.isBefore(request.timestamp()) && !end.isBefore(begin) && !browser.timestamp().isBefore(end));
            var entries=c.transcript().list(c.runId());
            require(entries.stream().filter(e->e.id().equals(browser.id())).count()==1
                    && entries.stream().filter(e->e.direction()==Direction.INBOUND && request.correlationId().equals(e.correlationId())
                        && "BrowserResponseObservation".equals(e.samlSummary().get("type"))).count()==1);
            // Only the independently reviewed native parser is currently qualified. Unknown adapters cannot borrow its proof.
            require("simplesamlphp-native-message-version".equals(text(m,"adapter")));
            byte[] before=original(folder,files,text(m,"sourceBeforeFile"));byte[] after=original(folder,files,text(m,"sourceAfterFile"));
            require(Arrays.equals(before,after) && SSP_MESSAGE_SHA.equals(hash(before)));
            byte[] runtimeBefore=original(folder,files,text(m,"runtimeBeforeFile"));byte[] runtimeAfter=original(folder,files,text(m,"runtimeAfterFile"));
            var runtime=new JsonCodec().mapper().readTree(runtimeBefore);var finalRuntime=new JsonCodec().mapper().readTree(runtimeAfter);
            require(normalizedRuntime(runtime).equals(normalizedRuntime(finalRuntime)));
            require(text(runtime,"containerId").matches("[0-9a-f]{64}") && text(runtime,"imageId").matches("sha256:[0-9a-f]{64}")
                    && runtime.path("mounts").isArray()
                    && SSP_MESSAGE_SHA.equals(text(runtime,"messageClassSourceSha256"))
                    && "/var/simplesamlphp/vendor/simplesamlphp/saml2-legacy/src/SAML2/Message.php".equals(text(runtime,"messageClassFile")));
            byte[] utilsBefore=original(folder,files,text(m,"utilsBeforeFile"));byte[] utilsAfter=original(folder,files,text(m,"utilsAfterFile"));
            require(Arrays.equals(utilsBefore,utilsAfter) && SSP_UTILS_SHA.equals(hash(utilsBefore))
                    && SSP_UTILS_SHA.equals(text(runtime,"utilsClassSourceSha256"))
                    && "/var/simplesamlphp/vendor/simplesamlphp/saml2-legacy/src/SAML2/Utils.php".equals(text(runtime,"utilsClassFile")));
            var rendered=new String(body,StandardCharsets.UTF_8);
            String cause=fixture.equals("version-1-1")?"Unsupported version: 1.1":"Invalid SAML2 timestamp passed to xsDateTimeToTimestamp: not-a-saml-timestamp";
            require(rendered.contains(cause) && !rendered.contains("SAMLResponse")
                    && !rendered.contains(fixture.equals("version-1-1")?"Invalid SAML2 timestamp passed":"Unsupported version:"));
            byte[] captureRaw=original(folder,files,text(row,"captureFile"));
            String captureReference=text(row,"captureReference");
            var captures=entries.stream().filter(e->e.id().equals(captureReference)).toList();require(captures.size()==1);
            var capture=captures.getFirst();require(c.runId().equals(capture.runId()) && capture.direction()==Direction.INBOUND
                    && !capture.timestamp().isBefore(browser.timestamp()) && capture.decodedSamlBytes()==captureRaw.length
                    && ("transcripts/"+c.runId()+"/"+capture.id()+".saml.xml").equals(capture.decodedSamlRef())
                    && Arrays.equals(captureRaw,content.readDecodedSaml(capture)));
            var recorded=new JsonCodec().mapper().readTree(captureRaw);
            require("samlscope-native-version-terminal-capture-v1".equals(text(recorded,"schema"))
                    && c.runId().equals(text(recorded,"runId")) && IdpVersionMismatchScenarioTestCase.CASE_ID.equals(text(recorded,"caseId"))
                    && fixture.equals(text(recorded,"fixtureId")) && request.id().equals(text(recorded,"requestReference"))
                    && requestId.equals(text(recorded,"requestId")) && hash(requestBytes).equals(text(recorded,"requestSha256"))
                    && browser.id().equals(text(recorded,"browserReference")) && hash(targetMetadata).equals(text(recorded,"targetMetadataSha256"))
                    && hash(httpOriginal).equals(text(recorded,"nativeHttpSha256")) && hash(body).equals(text(recorded,"bodySha256"))
                    && SSP_MESSAGE_SHA.equals(text(recorded,"messageSourceSha256")) && SSP_UTILS_SHA.equals(text(recorded,"utilsSourceSha256"))
                    && hash(runtimeBefore).equals(text(recorded,"runtimeBeforeSha256")) && hash(runtimeAfter).equals(text(recorded,"runtimeAfterSha256")));
            return Optional.of(new Proof(List.of(new EvidenceRef("transcript",captureReference),new EvidenceRef("transcript",browser.id()),
                    new EvidenceRef("native-version-terminal-evidence",c.runId()+".json#sha256="+hash(raw)))));
        } catch(Exception invalid) { return Optional.empty(); }
    }
    static JsonNode normalizedRuntime(JsonNode input){
        require(input.isObject()&&input.path("mounts").isArray());
        var copy=((com.fasterxml.jackson.databind.node.ObjectNode)input).deepCopy();var mounts=new TreeMap<String,JsonNode>();
        for(var mount:input.path("mounts")){
            String destination=text(mount,"Destination"),source=text(mount,"Source");
            require(destination.startsWith("/")&&source.startsWith("/")&&mount.path("RW").isBoolean()
                    && mount.path("Mode").isTextual()&&mount.path("Propagation").isTextual()
                    && !text(mount,"Type").isBlank()&&mounts.put(destination,mount)==null);
            for(String nativeSource:List.of("/var/simplesamlphp/vendor/simplesamlphp/saml2-legacy/src/SAML2/Message.php",
                    "/var/simplesamlphp/vendor/simplesamlphp/saml2-legacy/src/SAML2/Utils.php"))
                require(!nativeSource.equals(destination)&&!nativeSource.startsWith(destination.endsWith("/")?destination:destination+"/"));
        }
        var ordered=new JsonCodec().mapper().createArrayNode();mounts.values().forEach(ordered::add);copy.set("mounts",ordered);return copy;
    }
    private static byte[] original(Path folder,Map<String,JsonNode> files,String name)throws Exception {
        require(name.matches("[A-Za-z0-9][A-Za-z0-9._-]{0,127}") && files.containsKey(name));
        byte[] raw=read(folder.resolve(name),4194304);var f=files.get(name);
        require(f.path("size").asLong(-1)==raw.length && hash(raw).equals(text(f,"sha256")));return raw;
    }
    private static byte[] read(Path file,int limit)throws Exception {
        for(Path p=file.toAbsolutePath().normalize();p!=null;p=p.getParent()) require(!Files.isSymbolicLink(p));
        require(Files.isRegularFile(file,LinkOption.NOFOLLOW_LINKS) && Files.size(file)>0 && Files.size(file)<=limit);return Files.readAllBytes(file);
    }
    static String hash(byte[] raw)throws Exception {return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(raw));}
    static String text(JsonNode n,String key) {require(n.path(key).isTextual()&&!n.path(key).textValue().isBlank());return n.path(key).textValue();}
    static void require(boolean v) {if(!v)throw new IllegalArgumentException("Unproven version mismatch evidence");}
}
