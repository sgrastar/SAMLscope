package com.samlscope.runner.cases;

import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
import com.samlscope.core.caseexec.CaseContext;
import com.samlscope.core.transcript.*;
import com.samlscope.store.JsonCodec;
import com.samlscope.saml.normal.SecureXml;

/** Local native-adapter receipt only. An operator confirmation is not a substitute for this evidence. */
final class AuthnContextPreparationFile {
    private final Path directory;
    AuthnContextPreparationFile(Path directory) { this.directory=directory.toAbsolutePath().normalize(); }

    Optional<AuthnContextExperimentBinding.Preparation> read(String caseId, CaseContext context, byte[] target,
            TranscriptContentReader content) throws Exception {
        require(AuthnContextConfigurationTestCase.supports(caseId));
        require(context.runId().matches("run_[0-9A-HJKMNP-TV-Z]{26}"));
        var path=directory.resolve(context.runId()+"-"+caseId+".json");
        if(!Files.exists(path,LinkOption.NOFOLLOW_LINKS)) return Optional.empty();
        require(Files.isRegularFile(path,LinkOption.NOFOLLOW_LINKS) && Files.size(path)<=1_048_576);
        var json=new JsonCodec().mapper();var receipt=json.readTree(Files.readAllBytes(path));
        require("samlscope-native-authn-context-receipt-v1".equals(receipt.path("schema").asText()));
        require(context.runId().equals(receipt.path("runId").asText()));
        require(hash(target).equals(receipt.path("targetMetadataSha256").asText()));
        require(SecureXml.parse(target).getDocumentElement().getAttribute("entityID").equals(receipt.path("targetEntityId").asText()));
        var preparation=json.treeToValue(receipt.path("preparation"),AuthnContextExperimentBinding.Preparation.class);
        require(context.runId().equals(preparation.runId()) && preparation.exchanges().size()==4 && caseId.equals(preparation.caseId()));
        require(preparation.nativeContext()!=null);
        var entries=new HashMap<String,TranscriptEntry>();
        for(var entry:context.transcript().list(context.runId())) {
            require(context.runId().equals(entry.runId()) && entries.put(entry.id(),entry)==null);
        }
        var digests=new HashMap<String,String>();
        require(receipt.path("rawEvidence").isArray());
        for(var original:receipt.path("rawEvidence")) {
            String ref=original.path("reference").asText(),digest=original.path("sha256").asText();
            require(digest.matches("[0-9a-f]{64}") && digests.put(ref,digest)==null);
            var entry=entries.get(ref);
            require(entry!=null && entry.decodedSamlRef()!=null && hash(content.readDecodedSaml(entry)).equals(digest));
        }
        var conditions=new HashSet<String>();var requests=new HashSet<String>();
        var responses=new HashSet<String>();
        for(var exchange:preparation.allExchanges()) {
            require(exchange.condition()!=null && conditions.add(exchange.condition()));
            require(requests.add(exchange.requestReference()) && responses.add(exchange.responseReference()));
            for(var ref:List.of(exchange.metadataReference(),exchange.requestReference(),exchange.responseReference())) {
                require(digests.containsKey(ref));
            }
        }
        require(Collections.disjoint(requests,responses));
        return Optional.of(preparation);
    }
    private static String hash(byte[] raw) throws Exception { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(raw)); }
    private static void require(boolean value) { if(!value) throw new IllegalArgumentException("Unbound authentication context preparation"); }
}
