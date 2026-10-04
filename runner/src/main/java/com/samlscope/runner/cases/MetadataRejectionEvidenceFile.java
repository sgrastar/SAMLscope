package com.samlscope.runner.cases;

import java.nio.file.*;
import java.security.MessageDigest;
import java.time.*;
import java.time.format.*;
import java.util.regex.*;
import java.util.*;
import com.samlscope.core.caseexec.CaseContext;
import com.samlscope.core.transcript.*;
import com.samlscope.saml.normal.SecureXml;
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
        require(Set.of("shibboleth-resolver","simplesamlphp-parser","keycloak-import",
                "shibboleth-idp", "simplesamlphp-native-mdq",
                "simplesamlphp-native-mdq-positive", "simplesamlphp-native-mdq-signature").contains(adapter));
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
        if (receipt.path("conditionIssues").isArray()) require(receipt.path("conditionIssues").isEmpty());
        if ("simplesamlphp-native-mdq-signature".equals(adapter)) {
            for (var rejection : receipt.path("rejections")) {
                var prepared = preparedByVariant.get(text(rejection, "variant"));
                require(prepared != null && originals.containsKey(prepared.id()));
            }
            return new MetadataSignatureVerificationEvidenceFile(directory).rejectedNativeVariants(
                    context, target, content, receipt.path("rejections"));
        }
        var result=new LinkedHashMap<String,String>();
        for(var rejection:receipt.path("rejections")){
            var variant=text(rejection,"variant");
            var prepared=preparedByVariant.get(variant);require(prepared!=null);
            require(hash(content.readDecodedSaml(prepared)).equals(text(rejection,"fixtureSha256")));
            require(originals.containsKey(prepared.id()));
            var nativeRecord=rejection.path("nativeRejection");require(nativeRecord.isObject());
            require(text(nativeRecord,"source").equals(adapter));
            require(text(nativeRecord,"detailSha256").matches("[0-9a-f]{64}"));
            if ("simplesamlphp-native-mdq".equals(adapter))
                verifyNativeMdqExpiry(context, entries, content, prepared, variant, nativeRecord);
            if ("simplesamlphp-native-mdq-positive".equals(adapter))
                verifyNativeMdqPositiveRefusal(context, entries, content, prepared, variant, nativeRecord);
            require(result.put(variant,adapter)==null);
        }
        if(receipt.path("conditionIssues").isArray())require(receipt.path("conditionIssues").isEmpty());
        return Map.copyOf(result);
    }
    private static final Pattern MDQ_EXPIRY = Pattern.compile("^\\[([^]]+)] .*?Metadata for the entity \\[([^]]+)] expired [0-9]+ seconds ago\\.$");
    private static final Pattern MDQ_PDP = Pattern.compile("^\\[([^]]+)] .*?\\[critical] Uncaught Exception: Must have at least one AuthzService in PDPDescriptor\\.$");
    private static final DateTimeFormatter APACHE_TIME = DateTimeFormatter.ofPattern("EEE MMM d HH:mm:ss.SSSSSS uuuu", Locale.ENGLISH);

    /** Product log, not silence, proves this one native MDQ rejection. */
    private static void verifyNativeMdqExpiry(CaseContext context, Map<String,TranscriptEntry> entries,
            TranscriptContentReader content, TranscriptEntry prepared, String variant,
            com.fasterxml.jackson.databind.JsonNode record) throws Exception {
        require("expired".equals(variant));
        var raw = content.readDecodedSaml(prepared);
        var root = SecureXml.parse(raw).getDocumentElement();
        require("EntityDescriptor".equals(root.getLocalName()));
        var entity = root.getAttribute("entityID");
        require(entity.startsWith("http://localhost:18080/p/plan_"));
        var validUntil = Instant.parse(root.getAttribute("validUntil"));
        require(validUntil.isBefore(prepared.timestamp()));
        var log = text(record,"logRecord");
        require(log.length() < 2048 && hash(log.getBytes(java.nio.charset.StandardCharsets.UTF_8))
                .equals(text(record,"detailSha256")));
        var match = MDQ_EXPIRY.matcher(log);
        require(match.matches() && entity.equals(match.group(2)));
        var rejectedAt = LocalDateTime.parse(match.group(1), APACHE_TIME).toInstant(ZoneOffset.UTC);
        var request = entries.get(text(record,"requestReference"));
        require(request != null && request.direction() == Direction.OUTBOUND
                && "AuthnRequest".equals(request.samlSummary().get("type"))
                && variant.equals(request.samlSummary().get("variant")));
        require(!rejectedAt.isBefore(request.timestamp()) && !rejectedAt.isBefore(prepared.timestamp())
                && rejectedAt.isBefore(prepared.timestamp().plusSeconds(10)));
        require(context.runId().equals(request.runId()));
        var fetchId = prepared.samlSummary().get("fetchTranscriptId");
        var fetch = entries.get(fetchId);
        require(fetch != null && fetch.direction() == Direction.INBOUND
                && "MetadataFetch".equals(fetch.samlSummary().get("type"))
                && variant.equals(fetch.samlSummary().get("variant"))
                && !fetch.timestamp().isBefore(request.timestamp()));
    }
    private static void verifyNativeMdqPositiveRefusal(CaseContext context, Map<String,TranscriptEntry> entries,
            TranscriptContentReader content, TranscriptEntry prepared, String variant,
            com.fasterxml.jackson.databind.JsonNode record) throws Exception {
        require("schema-global-element-families".equals(variant));
        var root = SecureXml.parse(content.readDecodedSaml(prepared)).getDocumentElement();
        require("EntityDescriptor".equals(root.getLocalName()));
        var pdps = root.getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:metadata", "PDPDescriptor");
        require(pdps.getLength() == 1 && ((org.w3c.dom.Element)pdps.item(0)).getElementsByTagNameNS(
                "urn:oasis:names:tc:SAML:2.0:metadata", "AuthzService").getLength() > 0);
        var log = text(record,"logRecord");
        require(log.length() < 2048 && hash(log.getBytes(java.nio.charset.StandardCharsets.UTF_8))
                .equals(text(record,"detailSha256")));
        var match = MDQ_PDP.matcher(log);
        require(match.matches());
        var rejectedAt = LocalDateTime.parse(match.group(1), APACHE_TIME).toInstant(ZoneOffset.UTC);
        var request = entries.get(text(record,"requestReference"));
        require(request != null && request.direction() == Direction.OUTBOUND
                && "AuthnRequest".equals(request.samlSummary().get("type"))
                && variant.equals(request.samlSummary().get("variant")));
        require(context.runId().equals(request.runId()) && !rejectedAt.isBefore(request.timestamp())
                && !rejectedAt.isBefore(prepared.timestamp())
                && rejectedAt.isBefore(prepared.timestamp().plusSeconds(10)));
        var fetch = entries.get(prepared.samlSummary().get("fetchTranscriptId"));
        require(fetch != null && fetch.direction() == Direction.INBOUND
                && "MetadataFetch".equals(fetch.samlSummary().get("type"))
                && variant.equals(fetch.samlSummary().get("variant"))
                && !fetch.timestamp().isBefore(request.timestamp()));
    }
    private static String text(com.fasterxml.jackson.databind.JsonNode node,String field){return node.path(field).asText("");}
    private static String hash(byte[] bytes)throws Exception{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));}
    private static void require(boolean condition){if(!condition)throw new IllegalArgumentException("Native metadata rejection unproven");}
}
