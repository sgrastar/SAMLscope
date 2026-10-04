package com.samlscope.runner.cases;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.samlscope.core.caseexec.CaseContext;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.transcript.*;
import com.samlscope.saml.crypto.*;
import com.samlscope.saml.normal.SecureXml;
import java.nio.file.*;
import java.security.MessageDigest;
import java.security.cert.*;
import java.util.*;
import java.util.function.BiFunction;
import java.util.zip.ZipFile;
import org.w3c.dom.Element;

/**
 * MD06.c native signature/encryption trust proof, scoped to the recorded fresh metadata client.
 * This proves that the observed operation needed no additional trust input. It neither asserts
 * that every trust store is empty nor substitutes a declaration for cryptographic controls.
 */
final class KeycloakSelfContainedTrustEvidenceFile {
    static final String ID="IIP-MD06-c-idp-01";
    private static final ObjectMapper JSON=new ObjectMapper();
    private static final String MD="urn:oasis:names:tc:SAML:2.0:metadata",A="urn:oasis:names:tc:SAML:2.0:assertion",
            DS="http://www.w3.org/2000/09/xmldsig#",P="urn:oasis:names:tc:SAML:2.0:protocol";
    static final String SERVICES_HASH="213c45bb357e0881ead8284f12308e3c9fd8e09e7f0b6ec816f95f8b0921bea9";
    static final String SAML_CORE_HASH="191794d8be9289121c628f5e69380771b67f72ea869207248c2bbda253979e84";
    private static final Map<String,String> SERVICE_CLASSES=Map.of(
            "org/keycloak/protocol/saml/SamlProtocolUtils.class","c739a9e125462591a0d697fc38d5b7754b36b11d86dbe9f85ef0e397ef65be35",
            "org/keycloak/protocol/saml/SamlClient.class","b06ad9303baf1ca1a8702604b3424cf6a82497d6eb72fb29d60ce33baa3b3fa6",
            "org/keycloak/protocol/saml/SamlProtocol.class","4ad89b08f6d37e00a02e3cb0a4563883935f7d66b3f3bb717f9da8c316104100",
            "org/keycloak/protocol/saml/SamlService$PostBindingProtocol.class","04d7a04ab56a3ffd515e3b77623b7f7dc7812d43fe8d07a4f193bec8159960db");
    private static final Map<String,String> LOCATOR_CLASSES=Map.of(
            "org/keycloak/rotation/HardcodedKeyLocator.class","57eafbd9bb2e50166f3fd1093f9f1c0bdd2c922397b1aaefa73c2084c0322d1c");
    private final Path directory;
    private final TranscriptContentReader content;
    private final BiFunction<String,String,Optional<PlanCredentials>> keys;

    KeycloakSelfContainedTrustEvidenceFile(Path directory,TranscriptContentReader content,
            BiFunction<String,String,Optional<PlanCredentials>> keys) {
        this.directory=Objects.requireNonNull(directory).toAbsolutePath().normalize();
        this.content=Objects.requireNonNull(content);this.keys=Objects.requireNonNull(keys);
    }
    boolean exists(String run) { return validRun(run)&&Files.exists(receiptFile(run),LinkOption.NOFOLLOW_LINKS); }
    private Path receiptFile(String run) { return directory.resolve(run+".native-trust.json"); }

    CaseOutcome evaluate(CaseContext context,byte[] targetRaw) {
        String stage="native-trust-receipt-unavailable";
        try {
            require(context.transcriptComplete()&&exists(context.runId()));var file=receiptFile(context.runId());
            regular(file);require(Files.size(file)<=32768);var raw=Files.readAllBytes(file);var receipt=JSON.readTree(raw);
            String run=context.runId(),targetHash=hash(targetRaw);var target=SecureXml.parse(targetRaw).getDocumentElement();
            require("samlscope-keycloak-self-contained-trust-v1".equals(text(receipt,"schema"))
                    &&ID.equals(text(receipt,"caseId"))&&run.equals(text(receipt,"runId"))
                    &&"native-metadata-trust".equals(text(receipt,"campaignId"))
                    &&targetHash.equals(text(receipt,"targetMetadataSha256"))
                    &&target.getAttribute("entityID").equals(text(receipt,"targetEntityId")));
            var nativeFile=directory.resolve(run+".keycloak-supersession.json");regular(nativeFile);
            var nativeRaw=Files.readAllBytes(nativeFile);require(hash(nativeRaw).equals(text(receipt,"nativeCampaignReceiptSha256")));
            var nativeReceipt=JSON.readTree(nativeRaw);require(text(receipt,"peerEntityId").equals(text(nativeReceipt,"peerEntityId")));
            stage="native-originals-and-signature-control-unproven";
            var common=new KeycloakMetadataSupersessionEvidenceFile(directory,content,keys).trustPrerequisites(context,targetRaw);
            require(common.outcome()==Outcome.SATISFIED&&hash(nativeRaw).equals(common.details().get("receipt_sha256")));
            var entries=new LinkedHashMap<String,TranscriptEntry>();
            for(var e:context.transcript().list(run))require(run.equals(e.runId())&&entries.put(e.id(),e)==null);
            var metadataA=prepared(nativeReceipt,"control",entries);var metadataB=prepared(nativeReceipt,"no-valid-until",entries);
            var operative=original(nativeReceipt.path("probeState").path("before"),entries).path("client");
            var attrs=operative.path("attributes");
            require("true".equals(text(attrs,"saml.client.signature"))&&"true".equals(text(attrs,"saml.encrypt")));
            // The audited branch uses only the metadata-derived client certificates. External
            // metadata loaders or any separate client trust input are outside this proof.
            require(!attrs.has("saml.metadataDescriptorUrl")&&!attrs.has("saml.useMetadataDescriptorUrl"));
            var signing=certificate(text(attrs,"saml.signing.certificate"));var encrypting=certificate(text(attrs,"saml.encryption.certificate"));
            require(matches(signing,certificates(metadataB,"signing"))&&matches(encrypting,certificates(metadataB,"encryption")));
            stage="native-source-locator-unproven";
            var before=original(nativeReceipt.path("restoration").path("before"),entries);
            var after=original(nativeReceipt.path("restoration").path("after"),entries);
            require(SERVICES_HASH.equals(text(before.path("nativePaths"),"jarSha256"))
                    &&SERVICES_HASH.equals(text(after.path("nativePaths"),"jarSha256")));
            var source=directory.resolve(run+".native-trust");
            verifyJar(source.resolve("native-services.jar"),SERVICES_HASH,SERVICE_CLASSES);
            verifyJar(source.resolve("native-saml-core.jar"),SAML_CORE_HASH,LOCATOR_CLASSES);
            require(SERVICES_HASH.equals(text(receipt,"nativeServicesSha256"))&&SAML_CORE_HASH.equals(text(receipt,"nativeSamlCoreSha256")));
            stage="metadata-key-encryption-unproven";
            var probe=stream(nativeReceipt.path("probes")).stream().filter(p->"new-key-explicit-acs".equals(p.path("fixture").asText())).toList();
            require(probe.size()==1);var request=entries.get(text(probe.getFirst(),"requestReference"));require(request!=null);
            String requestId="_"+request.correlationId();
            var responses=entries.values().stream().filter(e->e.direction()==Direction.INBOUND&&requestId.equals(e.samlSummary().get("inResponseTo"))).toList();
            require(responses.size()==1);var response=responses.getFirst();var responseRaw=content.readDecodedSaml(response);
            var bKey=keys.apply(run,"no-valid-until").orElseThrow();var aKey=keys.apply(run,"control").orElseThrow();
            require(matches(bKey.certificate(),certificates(metadataB,"encryption"))
                    &&matches(aKey.certificate(),certificates(metadataA,"encryption"))
                    &&!Arrays.equals(aKey.certificate().getPublicKey().getEncoded(),bKey.certificate().getPublicKey().getEncoded()));
            var plaintext=new SamlXmlDecrypter().decrypt(encrypted(responseRaw),bKey.privateKey());
            require(A.equals(plaintext.getNamespaceURI())&&"Assertion".equals(plaintext.getLocalName())
                    &&MetadataAlgorithmEvidence.signingKeys(target).stream().anyMatch(c->new XmlSignatureVerifier().hasValidEnvelopedSignature(plaintext,c)));
            stage="unrelated-key-decryption-control-unproven";
            boolean wrongKeyRejected=false;
            try { new SamlXmlDecrypter().decrypt(encrypted(responseRaw),aKey.privateKey()); }
            catch(RuntimeException expected) { wrongKeyRejected=true; }
            require(wrongKeyRejected);
            require(hash(raw).equals(hash(Files.readAllBytes(file)))&&hash(nativeRaw).equals(hash(Files.readAllBytes(nativeFile))));
            var details=new LinkedHashMap<String,Object>();
            details.put("native_originals_verified",true);details.put("restoration_verified",true);
            details.put("native_key_locator_source_verified",true);details.put("signature_verification_observed",true);
            details.put("metadata_key_encryption_decryption_observed",true);details.put("unrelated_key_decryption_rejected",true);
            details.put("additional_trust_input_required",false);details.put("proof_scope","recorded-native-signature-encryption-flow");
            details.put("receipt_sha256",hash(raw));details.put("native_campaign_receipt_sha256",hash(nativeRaw));
            details.put("native_services_sha256",SERVICES_HASH);details.put("native_saml_core_sha256",SAML_CORE_HASH);
            details.put("private_key_exported",false);details.put("plaintext_persisted",false);
            return new CaseOutcome(Outcome.SATISFIED,null,"metadata.trust.self-contained-native-observed",
                    "metadata.trust.self-contained-native-observed",common.evidence(),details);
        } catch(Exception unproven) { return pending(stage); }
    }

    private Element prepared(JsonNode receipt,String variant,Map<String,TranscriptEntry> entries) {
        var found=stream(receipt.path("phases")).stream().filter(p->variant.equals(p.path("variant").asText())).toList();require(found.size()==1);
        var entry=entries.get(text(found.getFirst(),"preparedReference"));require(entry!=null);
        return SecureXml.parse(content.readDecodedSaml(entry)).getDocumentElement();
    }
    private JsonNode original(JsonNode reference,Map<String,TranscriptEntry> entries)throws Exception {
        var entry=entries.get(text(reference,"reference"));require(entry!=null);var raw=content.readDecodedSaml(entry);
        require(hash(raw).equals(text(reference,"sha256")));return JSON.readTree(raw);
    }
    private static Element encrypted(byte[] responseRaw) {
        var response=SecureXml.parse(responseRaw).getDocumentElement();
        require(P.equals(response.getNamespaceURI())&&"Response".equals(response.getLocalName())
                &&response.getElementsByTagNameNS(A,"Assertion").getLength()==0);
        var encrypted=response.getElementsByTagNameNS(A,"EncryptedAssertion");require(encrypted.getLength()==1);return (Element)encrypted.item(0);
    }
    private void verifyJar(Path path,String expected,Map<String,String> classes)throws Exception {
        regular(path);require(Files.size(path)>0&&Files.size(path)<=32*1024*1024&&hash(Files.readAllBytes(path)).equals(expected));
        try(var zip=new ZipFile(path.toFile())) {
            for(var pin:classes.entrySet()) {
                var entry=zip.getEntry(pin.getKey());require(entry!=null&&!entry.isDirectory()&&entry.getSize()>0&&entry.getSize()<=262144);
                try(var input=zip.getInputStream(entry)) { require(hash(input.readAllBytes()).equals(pin.getValue())); }
            }
        }
    }
    private void regular(Path path)throws Exception {
        require(path.normalize().startsWith(directory)&&Files.isRegularFile(path,LinkOption.NOFOLLOW_LINKS));
        for(Path current=path;current!=null&&current.startsWith(directory.getParent());current=current.getParent())require(!Files.isSymbolicLink(current));
    }
    private static List<X509Certificate> certificates(Element root,String use)throws Exception {
        var out=new ArrayList<X509Certificate>();var keys=root.getElementsByTagNameNS(MD,"KeyDescriptor");
        for(int i=0;i<keys.getLength();i++) { var key=(Element)keys.item(i);if(key.hasAttribute("use")&&!use.equals(key.getAttribute("use")))continue;
            var certs=key.getElementsByTagNameNS(DS,"X509Certificate");for(int c=0;c<certs.getLength();c++)out.add(certificate(certs.item(c).getTextContent())); }
        return out;
    }
    private static boolean matches(X509Certificate certificate,List<X509Certificate> expected)throws Exception {
        for(var candidate:expected)if(Arrays.equals(candidate.getEncoded(),certificate.getEncoded()))return true;return false;
    }
    private static X509Certificate certificate(String value)throws Exception { return (X509Certificate)CertificateFactory.getInstance("X.509")
            .generateCertificate(new java.io.ByteArrayInputStream(Base64.getMimeDecoder().decode(value))); }
    private static List<JsonNode> stream(JsonNode array) { require(array.isArray());var out=new ArrayList<JsonNode>();array.forEach(out::add);return out; }
    private static String text(JsonNode value,String field) { var item=value.path(field);require(item.isTextual()&&!item.asText().isBlank());return item.asText(); }
    private static String hash(byte[] bytes)throws Exception { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes)); }
    private static boolean validRun(String run) { return run!=null&&run.matches("run_[0-9A-HJKMNP-TV-Z]{26}"); }
    private static void require(boolean yes) { if(!yes)throw new IllegalArgumentException("Native metadata trust proof incomplete"); }
    private static CaseOutcome pending(String stage) { return new CaseOutcome(Outcome.NOT_VERIFIED,"native_metadata_trust_unproven",
            "metadata.trust.native-evidence-incomplete","metadata.trust.native-evidence-incomplete",List.of(),Map.of("evidence_issue",stage)); }
}
