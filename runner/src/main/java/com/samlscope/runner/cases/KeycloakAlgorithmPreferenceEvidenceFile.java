package com.samlscope.runner.cases;

import static com.samlscope.runner.cases.MetadataAlgorithmEvidence.children;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
import com.fasterxml.jackson.databind.JsonNode;
import com.samlscope.core.caseexec.CaseContext;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.transcript.*;
import com.samlscope.saml.normal.SecureXml;
import com.samlscope.store.JsonCodec;

/** Diagnostic native default-selector observations; never a capability-only preference verdict.
 * Both native capabilities and selector/storage originals can prove usability and a field's
 * absence, but the pinned SamlClient itself retains the RSA_SHA256 fallback. They cannot prove
 * absence of local selection criteria under the approved local-policy exception. MD05.e7 also
 * requires producer preference evidence; Suite-authored input order is not producer evidence.
 * The current native version therefore remains NOT_VERIFIED after a complete diagnostic run.
 * Other products and native versions continue through their approved evidence fallback.
 */
final class KeycloakAlgorithmPreferenceEvidenceFile {
    static final Set<String> CASES=Set.of("IIP-MD05-e7-idp-01","IIP-MD05-e9-idp-01","IIP-MD05-ea-idp-01");
    static final List<String> REQUIRED=List.of("control","algorithm-entity-sha256","algorithm-entity-sha512",
        "algorithm-entity-order-256-512","algorithm-entity-order-512-256",
        "algorithm-role-order-256-512","algorithm-role-order-512-256","algorithm-unsupported-first",
        "algorithm-entity-digest-order-256-512","algorithm-entity-digest-order-512-256",
        "algorithm-entity-signing-order-256-512","algorithm-entity-signing-order-512-256");
    static final Map<String,String> NATIVE_CLASSES=Map.of(
        "org/keycloak/protocol/saml/SamlClient.class","b06ad9303baf1ca1a8702604b3424cf6a82497d6eb72fb29d60ce33baa3b3fa6",
        "org/keycloak/models/ClientConfigResolver.class","fc0fee4551737b6fbcff082a7a7afc88d3d8c941f14244b121faa2fb29e8007a",
        "org/keycloak/models/jpa/ClientAdapter.class","6b8e71a25e5cabc5104645e4c0a869cd15bb702639e465ec9b9b7f81b9856454");
    private static final String MD="urn:oasis:names:tc:SAML:2.0:metadata", ALG="urn:oasis:names:tc:SAML:metadata:algsupport";
    private static final String D256="http://www.w3.org/2001/04/xmlenc#sha256",D512="http://www.w3.org/2001/04/xmlenc#sha512";
    private static final String S256="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",S512="http://www.w3.org/2001/04/xmldsig-more#rsa-sha512";
    private final Path directory;
    private final TranscriptContentReader content;
    KeycloakAlgorithmPreferenceEvidenceFile(Path directory,TranscriptContentReader content) {
        this.directory=directory.toAbsolutePath().normalize();this.content=content;
    }
    boolean exists(String run) {return run!=null&&run.matches("run_[0-9A-HJKMNP-TV-Z]{26}")
        &&Files.isRegularFile(directory.resolve(run+".algorithm-preference.json"),LinkOption.NOFOLLOW_LINKS);}
    CaseOutcome evaluate(String id,CaseContext context,byte[] target) {
        try {
            require(CASES.contains(id)&&context.transcriptComplete()&&exists(context.runId()));
            var path=directory.resolve(context.runId()+".algorithm-preference.json");
            require(Files.size(path)<262144);var receiptRaw=Files.readAllBytes(path);
            var receipt=new JsonCodec().mapper().readTree(receiptRaw);
            var targetXml=SecureXml.parse(target).getDocumentElement();
            require("samlscope-keycloak-algorithm-preference-v1".equals(receipt.path("schema").asText())
                &&"keycloak-native-default-selector-v1".equals(receipt.path("adapter").asText())
                &&context.runId().equals(receipt.path("runId").asText())
                &&"metadata-fixture-refresh".equals(receipt.path("campaignId").asText())
                &&targetXml.getAttribute("entityID").equals(receipt.path("targetEntityId").asText())
                &&hash(target).equals(receipt.path("targetMetadataSha256").asText()));
            var entries=new HashMap<String,TranscriptEntry>();
            for(var e:context.transcript().list(context.runId()))require(context.runId().equals(e.runId())&&entries.put(e.id(),e)==null);
            var refs=new LinkedHashSet<EvidenceRef>();
            var before=original(receipt.path("policyBefore"),context,entries,refs);
            var after=original(receipt.path("policyAfter"),context,entries,refs);
            require(before.equals(after));
            policy(before,context,target);
            var firstTime=entries.get(receipt.path("policyBefore").path("reference").asText()).timestamp();
            var lastTime=entries.get(receipt.path("policyAfter").path("reference").asText()).timestamp();
            var collected=MetadataAlgorithmEvidence.collect(REQUIRED,context,content,target);
            require(collected.issues().isEmpty());
            var exchanges=new HashMap<String,MetadataAlgorithmEvidence.Exchange>();
            for(var exchange:collected.exchanges()) {
                var response=exchange.evidence().getLast().reference();require(exchanges.put(response,exchange)==null);
            }
            var samples=new LinkedHashMap<String,MetadataAlgorithmEvidence.Exchange>();
            var campaigns=new HashSet<String>();var clientIds=new HashSet<String>();
            JsonNode controlAttributes=null;
            require(receipt.path("matrix").isArray()&&receipt.path("matrix").size()==REQUIRED.size());
            for(var row:receipt.path("matrix")) {
                var variant=row.path("variant").asText();require(REQUIRED.contains(variant)&&!samples.containsKey(variant));
                var exchange=exchanges.get(row.path("responseReference").asText());require(exchange!=null&&variant.equals(exchange.variant()));
                var readback=original(row.path("configuration"),context,entries,refs);
                var attrs=client(readback,context,target,exchange,row,clientIds,entries,firstTime,lastTime);
                require(!attrs.has("saml.signature.algorithm"));
                if("control".equals(variant))controlAttributes=attrs;
                exactInput(variant,exchange.metadata());
                campaigns.add(exchange.campaign());samples.put(variant,exchange);refs.addAll(exchange.evidence());
            }
            require(campaigns.size()==1&&samples.keySet().containsAll(REQUIRED)&&controlAttributes!=null);
            require(receipt.path("capabilities").isArray()&&receipt.path("capabilities").size()==2);
            var observed=new HashSet<String>();var signerHashes=new HashSet<String>();
            for(var row:receipt.path("capabilities")) {
                var algorithm=row.path("algorithm").asText();require(Set.of("RSA_SHA256","RSA_SHA512").contains(algorithm)&&observed.add(algorithm));
                var exchange=exchanges.get(row.path("responseReference").asText());require(exchange!=null&&"control".equals(exchange.variant())&&!campaigns.contains(exchange.campaign()));
                var readback=original(row.path("configuration"),context,entries,refs);
                var attrs=client(readback,context,target,exchange,row,clientIds,entries,firstTime,lastTime);
                var expected=controlAttributes.deepCopy();((com.fasterxml.jackson.databind.node.ObjectNode)expected).put("saml.signature.algorithm",algorithm);
                require(expected.equals(attrs));
                var signatures=exchange.signatures().stream().filter(s->"Response".equals(s.element())).toList();
                require(signatures.size()==1&&signatures.getFirst().signatureAlgorithm().equals(algorithm.equals("RSA_SHA256")?S256:S512)
                    &&signatures.getFirst().digestAlgorithm().equals(algorithm.equals("RSA_SHA256")?D256:D512));
                signerHashes.add(signatures.getFirst().signingKeySha256());refs.addAll(exchange.evidence());
            }
            require(observed.equals(Set.of("RSA_SHA256","RSA_SHA512"))&&signerHashes.size()==1&&clientIds.size()==14);
            for(var sample:samples.values())require(sample.signatures().stream().allMatch(s->signerHashes.contains(s.signingKeySha256())));
            var restoration=original(receipt.path("restoration"),context,entries,refs);
            require("samlscope-keycloak-preference-restoration-v1".equals(restoration.path("schema").asText())
                &&context.runId().equals(restoration.path("runId").asText())
                &&receipt.path("targetEntityId").asText().equals(restoration.path("targetEntityId").asText())
                &&restoration.path("remainingClients").isArray()&&restoration.path("remainingClients").isEmpty()
                &&restoration.path("originalClients").isArray()&&restoration.path("originalClients").isEmpty()
                &&entries.get(receipt.path("restoration").path("reference").asText()).timestamp().isAfter(lastTime));
            var mismatches=preferenceMismatches(id,samples);
            var details=new LinkedHashMap<String,Object>();details.put("required_variants",REQUIRED);details.put("observed_variants",REQUIRED);
            details.put("local_policy_verified",false);details.put("local_policy_verification","native_builtin_default_is_not_absence");
            details.put("explicit_signature_selector","absent");details.put("signature_capability_controls_verified",true);
            details.put("separate_digest_and_signature_orders_verified",true);details.put("selection_mismatches",mismatches);
            details.put("producer_preference_scope_verified",false);
            details.put("native_default_signature_algorithm","RSA_SHA256");
            details.put("campaigns",campaigns.stream().sorted().toList());details.put("native_receipt_sha256",hash(receiptRaw));
            require(Arrays.equals(receiptRaw,Files.readAllBytes(path)));
            // A missing per-client field does not remove the selector's compiled default.
            // Neither observed capability nor empty policies proves that this default is
            // prohibited as local criteria. Do not turn the diagnostic mismatch into FAIL.
            var code=id.equals("IIP-MD05-e7-idp-01")?"metadata.algorithms.producer-preference-unproven":
                "metadata.algorithms.local-policy-unverified";
            return new CaseOutcome(Outcome.NOT_VERIFIED,"native_preference_applicability_unproven",code,code,List.copyOf(refs),details);
        } catch(Exception unproven) {
            return new CaseOutcome(Outcome.NOT_VERIFIED,"native_algorithm_preference_unproven","metadata.algorithms.native-preference-incomplete",
                "metadata.algorithms.native-preference-incomplete",List.of(),Map.of("evidence_issue",unproven.getClass().getSimpleName()));
        }
    }
    private JsonNode original(JsonNode ref,CaseContext context,Map<String,TranscriptEntry> entries,Set<EvidenceRef> refs)throws Exception {
        var entry=entries.get(ref.path("reference").asText());require(entry!=null&&entry.direction()==Direction.INBOUND
            &&"POST".equals(entry.method())&&Integer.valueOf(204).equals(entry.status()));
        var raw=content.readDecodedSaml(entry);require(hash(raw).equals(ref.path("sha256").asText()));
        var json=new JsonCodec().mapper().readTree(raw);require(context.runId().equals(json.path("runId").asText()));
        refs.add(new EvidenceRef("transcript",entry.id()));return json;
    }
    private static void policy(JsonNode json,CaseContext context,byte[] target)throws Exception {
        require("samlscope-keycloak-preference-native-policy-v1".equals(json.path("schema").asText())
            &&"metadata-fixture-refresh".equals(json.path("campaignId").asText())
            &&json.path("targetMetadataSha256").asText().equals(hash(target))
            &&json.path("clientPolicies").isObject()&&json.path("clientPolicies").size()==1
            &&json.path("clientPolicies").path("policies").isArray()&&json.path("clientPolicies").path("policies").isEmpty()
            &&json.path("clientProfiles").isObject()&&json.path("clientProfiles").size()==1
            &&json.path("clientProfiles").path("profiles").isArray()&&json.path("clientProfiles").path("profiles").isEmpty()
            &&json.path("nativeClasses").isObject()&&json.path("nativeClasses").size()==NATIVE_CLASSES.size());
        for(var row:NATIVE_CLASSES.entrySet())require(hash(Base64.getDecoder().decode(json.path("nativeClasses").path(row.getKey()).asText())).equals(row.getValue()));
    }
    private static JsonNode client(JsonNode json,CaseContext context,byte[] target,MetadataAlgorithmEvidence.Exchange exchange,
            JsonNode row,Set<String> clientIds,Map<String,TranscriptEntry> entries,java.time.Instant first,java.time.Instant last)throws Exception {
        require("samlscope-keycloak-preference-native-client-v1".equals(json.path("schema").asText())
            &&"GET".equals(json.path("method").asText())&&json.path("httpStatus").asInt()==200
            &&json.path("targetMetadataSha256").asText().equals(hash(target))
            &&json.path("targetEntityId").asText().equals(SecureXml.parse(target).getDocumentElement().getAttribute("entityID"))
            &&json.path("fixtureSha256").asText().equals(entries.get(exchange.evidence().get(1).reference()).samlSummary().get("metadataSha256"))
            &&json.path("client").path("clientId").asText().equals(exchange.metadata().getAttribute("entityID"))
            &&json.path("client").path("protocol").asText().equals("saml")
            &&json.path("path").asText().equals("/clients/"+json.path("client").path("id").asText())
            &&clientIds.add(json.path("client").path("id").asText()));
        var reference=entries.get(row.path("configuration").path("reference").asText());
        var request=entries.get(exchange.evidence().get(2).reference());var response=entries.get(exchange.evidence().get(3).reference());
        require(first.isBefore(reference.timestamp())&&reference.timestamp().isBefore(request.timestamp())&&response.timestamp().isBefore(last));
        var attrs=json.path("client").path("samlAttributes");require(attrs.isObject()
            &&"true".equals(attrs.path("saml.encrypt").asText())&&"true".equals(attrs.path("saml.client.signature").asText())
            &&"true".equals(attrs.path("saml.server.signature").asText()));
        return attrs;
    }
    static List<String> preferenceMismatches(String id,Map<String,MetadataAlgorithmEvidence.Exchange> samples) {
        var selected=Set.of("IIP-MD05-e7-idp-01").contains(id)?List.of("algorithm-entity-digest-order-256-512","algorithm-entity-digest-order-512-256",
            "algorithm-entity-signing-order-256-512","algorithm-entity-signing-order-512-256"):
            id.equals("IIP-MD05-e9-idp-01")?List.of("algorithm-entity-order-256-512","algorithm-entity-order-512-256",
                "algorithm-role-order-256-512","algorithm-role-order-512-256","algorithm-unsupported-first"):
            List.of("algorithm-entity-order-256-512","algorithm-entity-order-512-256","algorithm-role-order-256-512","algorithm-role-order-512-256");
        var issues=new ArrayList<String>();
        for(var variant:selected) {
            var expected=advertised(variant);var ds=expected.get(0);var ss=expected.get(1);
            for(var signature:samples.get(variant).signatures()) {
                if(!ds.isEmpty()&&!signature.digestAlgorithm().equals(variant.equals("algorithm-unsupported-first")?D256:ds.getFirst()))issues.add(variant+":digest-not-first-permitted");
                if(!ss.isEmpty()&&!signature.signatureAlgorithm().equals(variant.equals("algorithm-unsupported-first")?S256:ss.getFirst()))issues.add(variant+":signature-not-first-permitted");
            }
        }
        return issues.stream().distinct().toList();
    }
    private static List<List<String>> advertised(String variant) {
        if(variant.equals("control"))return List.of(List.of(),List.of());
        if(variant.equals("algorithm-unsupported-first"))return List.of(List.of("urn:samlscope:test:unsupported-digest",D256),List.of("urn:samlscope:test:unsupported-signature",S256));
        if(variant.equals("algorithm-entity-sha256"))return List.of(List.of(D256),List.of(S256));
        if(variant.equals("algorithm-entity-sha512"))return List.of(List.of(D512),List.of(S512));
        var first512=variant.endsWith("512-256");var ds=first512?List.of(D512,D256):List.of(D256,D512);var ss=first512?List.of(S512,S256):List.of(S256,S512);
        return List.of(variant.contains("-signing-")?List.of():ds,variant.contains("-digest-")?List.of():ss);
    }
    private static void exactInput(String variant,org.w3c.dom.Element root) {
        var roles=children(root,MD,"SPSSODescriptor");require(roles.size()==1);var role=roles.getFirst();
        var entityMethods=methods(root);var roleMethods=methods(role);var expected=advertised(variant);
        require(variant.startsWith("algorithm-role-")?entityMethods.equals(List.of(List.of(),List.of()))&&roleMethods.equals(expected):
            entityMethods.equals(expected)&&roleMethods.equals(List.of(List.of(),List.of())));
    }
    private static List<List<String>> methods(org.w3c.dom.Element root) {
        var ext=children(root,MD,"Extensions");require(ext.size()<=1);if(ext.isEmpty())return List.of(List.of(),List.of());
        return List.of(children(ext.getFirst(),ALG,"DigestMethod").stream().map(e->e.getAttribute("Algorithm")).toList(),
            children(ext.getFirst(),ALG,"SigningMethod").stream().map(e->e.getAttribute("Algorithm")).toList());
    }
    private static String hash(byte[] raw)throws Exception {return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(raw));}
    private static void require(boolean value) {if(!value)throw new IllegalArgumentException("Native preference original unproven");}
}
