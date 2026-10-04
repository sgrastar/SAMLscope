package com.samlscope.runner.cases;

import static com.samlscope.runner.cases.MetadataAlgorithmEvidence.children;
import com.fasterxml.jackson.databind.JsonNode;
import com.samlscope.core.caseexec.CaseContext;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.plan.TargetRole;
import com.samlscope.core.transcript.*;
import com.samlscope.saml.normal.SecureXml;
import com.samlscope.store.JsonCodec;
import java.io.ByteArrayInputStream;
import java.nio.file.*;
import java.security.MessageDigest;
import java.security.KeyFactory;
import java.security.cert.*;
import java.security.spec.RSAPublicKeySpec;
import java.math.BigInteger;
import java.time.Instant;
import java.util.*;
import java.util.function.Function;
import org.w3c.dom.Element;

/** Compares a native role inventory with actual publications in the same Run.
 * Publisher models used to calibrate the detector are never product findings.
 * This observer does not issue requests or alter a target's configuration. */
public final class MetadataPublisherKeyInventoryEvidence {
    public static final String SCHEMA = "samlscope-native-metadata-publisher-key-inventory-v1";
    public static final String CAMPAIGN = "native-metadata-publisher-key-inventory";
    public static final String KIND = "native-metadata-publisher-key-evidence";
    public static final String C1 = "IIP-MD05-c1-idp-01", C3 = "IIP-MD05-c3-idp-01";
    public static final String UNPROVEN = "metadata.publisher.key-inventory-unproven";
    static final String MD = "urn:oasis:names:tc:SAML:2.0:metadata", DS = "http://www.w3.org/2000/09/xmldsig#";
    static final String P = "urn:oasis:names:tc:SAML:2.0:protocol";
    private final Path directory;
    private final TranscriptContentReader content;
    private final Function<String, byte[]> targetMetadata;
    private final boolean calibrationPermission;
    public MetadataPublisherKeyInventoryEvidence(Path directory, TranscriptContentReader content,
            Function<String, byte[]> targetMetadata) { this(directory, content, targetMetadata, false); }
    MetadataPublisherKeyInventoryEvidence(Path directory, TranscriptContentReader content,
            Function<String, byte[]> targetMetadata, boolean calibrationPermission) {
        this.directory = Objects.requireNonNull(directory).toAbsolutePath().normalize();
        this.content = Objects.requireNonNull(content); this.targetMetadata = Objects.requireNonNull(targetMetadata);
        this.calibrationPermission = calibrationPermission;
    }
    public static boolean supports(String caseId) { return Set.of(C1, C3).contains(caseId); }
    public boolean exists(String runId) {
        return validRun(runId) && Files.exists(directory.resolve(runId), LinkOption.NOFOLLOW_LINKS);
    }
    public CaseOutcome evaluate(String caseId, CaseContext context) {
        if (!supports(caseId)) throw new IllegalArgumentException("Unsupported publisher case");
        try {
            require(exists(context.runId()) && context.targetRole() == TargetRole.IDP && context.transcriptComplete());
            Frame f = new Frame(directory.resolve(context.runId()), context, content, targetMetadata);
            require(SCHEMA.equals(text(f.manifest, "schema")) && CAMPAIGN.equals(text(f.manifest, "campaignId"))
                    && context.runId().equals(text(f.manifest, "runId")));
            byte[] initial = targetMetadata.apply(context.runId());
            require(initial != null && Arrays.equals(initial, f.file("target-metadata.xml"))
                    && hash(initial).equals(text(f.manifest, "targetMetadataSha256")));
            Element snapshot = role(initial, text(f.manifest, "entityId"));
            require(!snapshot.getAttribute("protocolSupportEnumeration").isBlank());
            String path = text(f.manifest, "selectedPath");
            require(Set.of("stock-current-role", "developer-omitted-transport-key").contains(path));
            boolean diagnostic = path.startsWith("developer-");
            require(f.manifest.path("counterfactualCalibrationOnly").isBoolean()
                    && f.manifest.path("counterfactualCalibrationOnly").asBoolean() == diagnostic
                    && (!diagnostic || calibrationPermission));
            NativeMetadataPublisherInventoryAdapter adapter = adapter(text(f.manifest, "adapter"));
            var epochs = f.manifest.path("epochs"); require(epochs.isArray() && !epochs.isEmpty());
            List<String> missing = new ArrayList<>(), unresolved = new ArrayList<>();
            boolean multiple = false, signing = false, encryption = false;
            Instant last = null;
            Set<String> names = new HashSet<>();
            for (var epoch : epochs) {
                require(names.add(text(epoch, "id")));
                Instant from = at(epoch, "startedAt"), until = at(epoch, "finishedAt");
                require(from.isBefore(until) && (last == null || !from.isBefore(last))); last = until;
                var inventory = adapter.validate(f, epoch);
                unresolved.addAll(inventory.unresolvedScope());
                byte[] raw = f.file(text(epoch, "publicationFile"));
                var publication = f.original(text(epoch, "publicationOriginal"), "native-publication");
                require(hash(raw).equals(text(publication, "publicationSha256"))
                        && text(epoch, "id").equals(text(publication, "epochId"))
                        && within(at(publication, "nativeStartedAt"), from, until)
                        && within(at(publication, "nativeFinishedAt"), from, until)
                        && at(publication, "nativeStartedAt").isBefore(at(publication, "nativeFinishedAt")));
                require("GET".equals(text(publication, "method"))
                        && publication.path("responseStatus").isIntegralNumber() && publication.path("responseStatus").asInt() == 200);
                Element published = role(raw, text(f.manifest, "entityId"));
                missing.addAll(compare(published, inventory, caseId));
                for (String purpose : List.of("signing", "encryption")) {
                    long count = inventory.keys().stream().filter(k -> k.purpose().equals(purpose))
                            .map(NativeMetadataPublisherInventoryAdapter.RoleKey::spkiSha256).distinct().count();
                    multiple |= count >= 2; signing |= purpose.equals("signing") && count > 0;
                    encryption |= purpose.equals("encryption") && count > 0;
                }
                adapter.validateTransition(f, epoch, initial);
            }
            List<String> controlOmissions = adapter.validateControls(f, caseId);
            adapter.validateRestoration(f);
            if (diagnostic) {
                var omission = controlOmissions;
                require(!omission.isEmpty());
                return new CaseOutcome(Outcome.VIOLATED, null, C1.equals(caseId) ? "metadata.publisher.role-description-incomplete" : "metadata.publisher.current-key-omitted",
                    "metadata.publisher.detector-calibration", f.evidence(), Map.of("evidence_adapter", adapter.id(), "native_run_id", context.runId(),
                    "case_id", caseId, "selected_path", path, "missing_metadata_items", omission, "counterfactual_calibration_only", true));
            }
            // A verified, actually used role key missing from the publication is a
            // counterexample to all_of. An unresolved different purpose prevents
            // full success, but does not erase that independently proven omission.
            if (stockOutcome(caseId,missing,unresolved,multiple,signing,encryption)==Outcome.NOT_VERIFIED
                    && !unresolved.isEmpty()) return pending(caseId, context.runId(), "native-role-scope-incomplete", unresolved);
            // Every full success includes the declared multi-current and current-purpose scenarios.
            // A conclusive actual omission can falsify all_of without every success scenario.
            if (missing.isEmpty() && C3.equals(caseId) && !(multiple && signing && encryption))
                return pending(caseId, context.runId(), "required-current-key-variants-missing", List.of("multiple/current-signing/current-encryption"));
            String reason = missing.isEmpty() ? C1.equals(caseId) ? "metadata.publisher.role-description-complete"
                    : "metadata.publisher.current-key-inventory-complete" : C1.equals(caseId)
                    ? "metadata.publisher.role-description-incomplete" : "metadata.publisher.current-key-omitted";
            var details = new LinkedHashMap<String, Object>();
            details.put("evidence_adapter", adapter.id()); details.put("native_run_id", context.runId());
            details.put("case_id", caseId); details.put("selected_path", path); details.put("scope", "current-idp-saml2-role");
            details.put("missing_metadata_items", List.copyOf(missing));
            details.put("unresolved_scope", List.copyOf(unresolved));
            details.put("counterfactual_calibration_only", diagnostic);
            return new CaseOutcome(missing.isEmpty() ? Outcome.SATISFIED : Outcome.VIOLATED, null, reason, reason,
                    f.evidence(), details);
        } catch (Exception unavailable) { return pending(caseId, context.runId(), "native-publisher-proof-incomplete", List.of()); }
    }
    private static NativeMetadataPublisherInventoryAdapter adapter(String id) {
        if (SimpleSamlPhpPublisherInventoryAdapter.ID.equals(id)) return new SimpleSamlPhpPublisherInventoryAdapter();
        if (ShibbolethPublisherEndpointInventoryAdapter.ID.equals(id)) return new ShibbolethPublisherEndpointInventoryAdapter();
        throw new IllegalArgumentException("Unknown native publisher adapter");
    }
    static Outcome stockOutcome(String caseId,List<String> missing,List<String> unresolved,boolean multiple,boolean signing,boolean encryption) {
        require(supports(caseId));
        if(!missing.isEmpty()) return Outcome.VIOLATED;
        if(!unresolved.isEmpty() || C3.equals(caseId)&&!(multiple&&signing&&encryption)) return Outcome.NOT_VERIFIED;
        return Outcome.SATISFIED;
    }
    static void validateSimpleSamlPhpEpochTransition(Frame f, JsonNode epoch, byte[] target) throws Exception {
        String kind = text(epoch, "transition");
        if (kind.equals("run-snapshot")) require(Arrays.equals(target, f.file(text(epoch, "publicationFile"))));
        else if (kind.equals("explicit-native-peer-signers")) {
            var transition = f.original(text(epoch, "transitionOriginal"), "native-configuration-transition");
            var initial = f.original("initial", "native-role-inventory");
            var current = f.original(text(epoch,"beforeOriginal"), "native-role-inventory");
            var before = f.node(text(initial,"readbackFile")); var after = f.node(text(current,"readbackFile"));
            String path = "/var/simplesamlphp/metadata/saml20-sp-remote.php";
            require(Arrays.equals(target, f.file(text(epoch,"publicationFile")))
                    && text(epoch,"id").equals(text(transition,"epochId"))
                    && path.equals(text(transition,"path"))
                    && "per-peer-current-signers".equals(text(transition,"configurationPurpose"))
                    && at(transition,"startedAt").isAfter(at(initial,"nativeFinishedAt"))
                    && at(transition,"startedAt").isBefore(at(transition,"completedAt"))
                    && at(transition,"completedAt").isBefore(at(current,"nativeStartedAt"))
                    && configurationHash(before,path).equals(text(transition,"beforeConfigurationSha256"))
                    && configurationHash(after,path).equals(text(transition,"afterConfigurationSha256"))
                    && !configurationHash(before,path).equals(configurationHash(after,path))
                    && initial.path("runtime").equals(current.path("runtime")));
            for (String other : List.of("/var/simplesamlphp/config/config.php", "/var/simplesamlphp/metadata/saml20-idp-hosted.php"))
                require(configurationHash(before,other).equals(configurationHash(after,other)));
            for (String field : List.of("publicNativeMetadata", "currentCredentials", "loadedClasses", "roleFeatureFlags", "metadataSources"))
                require(before.path(field).equals(after.path(field)));
        }
        else {
            require(kind.equals("explicit-native-configuration"));
            var transition = f.original(text(epoch, "transitionOriginal"), "native-configuration-transition");
            var initial = f.original("initial", "native-role-inventory");
            var current = f.original(text(epoch,"beforeOriginal"),"native-role-inventory");
            var before = f.node(text(initial,"readbackFile")); var after = f.node(text(current,"readbackFile"));
            String path = "/var/simplesamlphp/metadata/saml20-idp-hosted.php";
            require(text(epoch, "id").equals(text(transition, "epochId")) && path.equals(text(transition,"path"))
                    && at(transition,"startedAt").isAfter(at(initial,"nativeFinishedAt"))
                    && at(transition,"startedAt").isBefore(at(transition,"completedAt"))
                    && at(transition,"completedAt").isBefore(at(current,"nativeStartedAt"))
                    && at(transition, "completedAt").isBefore(at(epoch, "startedAt"))
                    && configurationHash(before,path).equals(text(transition, "beforeConfigurationSha256"))
                    && configurationHash(after,path).equals(text(transition, "afterConfigurationSha256"))
                    && !text(transition, "beforeConfigurationSha256").equals(text(transition, "afterConfigurationSha256"))
                    && initial.path("runtime").equals(current.path("runtime")));
            for (String other : List.of("/var/simplesamlphp/config/config.php","/var/simplesamlphp/metadata/saml20-sp-remote.php"))
                require(configurationHash(before,other).equals(configurationHash(after,other)));
            require("browser-role-no-ecp".equals(text(transition,"configurationPurpose"))
                    && before.path("roleFeatureFlags").path("saml20.ecp").asBoolean(false)
                    && after.path("roleFeatureFlags").path("saml20.ecp").isBoolean()
                    && !after.path("roleFeatureFlags").path("saml20.ecp").asBoolean());
        }
    }
    static String configurationHash(JsonNode state,String path) {
        String result=null;
        for(var row:state.path("configurationHashes")) if(path.equals(row.path("file").asText())) {
            require(result==null);result=text(row,"sha256");
        }
        require(result!=null&&result.matches("[a-f0-9]{64}"));return result;
    }
    /** The omission control changes only the native selected producer; it is not an observed product publication. */
    static void validateSimpleSamlPhpControls(Frame f, String caseId) throws Exception {
        var controls = f.manifest.path("controls"); require(controls.isObject());
        var input = f.file(text(controls, "inputFile")); var p = f.file(text(controls, "positiveOutputFile"));
        var n = f.file(text(controls, "negativeOutputFile"));
        var original = f.original(text(controls, "original"), "native-publisher-detector-control");
        validateControlIds(original);
        require("oracle-calibration-only".equals(text(original, "purpose"))
                && hash(input).equals(text(original, "inputSha256"))
                && hash(p).equals(text(original, "positiveOutputSha256")) && hash(n).equals(text(original, "negativeOutputSha256")));
        SimpleSamlPhpPublisherInventoryAdapter.validateProducerControl(f, controls, input, p, n);
    }
    static void validateControlIds(JsonNode original) throws Exception {
        require(original.path("positiveControlIds").equals(json("[\"iip-md05-c1-idp-01-positive\",\"iip-md05-c3-idp-01-positive\"]".getBytes(java.nio.charset.StandardCharsets.UTF_8)))
                && original.path("negativeControlIds").equals(json("[\"iip-md05-c1-idp-01-negative\",\"iip-md05-c3-idp-01-negative\"]".getBytes(java.nio.charset.StandardCharsets.UTF_8))));
    }
    static void validateSimpleSamlPhpRestoration(Frame f) throws Exception {
        var r = f.original("restoration", "native-publisher-restoration");
        require(r.path("restored").isBoolean() && r.path("restored").asBoolean());
        var initial = SimpleSamlPhpPublisherInventoryAdapter.state(f,"initial","initial");
        var restored = SimpleSamlPhpPublisherInventoryAdapter.state(f,"restored","restored");
        var b=f.node(text(initial,"readbackFile"));var a=f.node(text(restored,"readbackFile"));
        require(initial.path("runtime").equals(restored.path("runtime"))
                && b.path("configurationHashes").equals(a.path("configurationHashes"))
                && b.path("publicNativeMetadata").equals(a.path("publicNativeMetadata"))
                && b.path("currentCredentials").equals(a.path("currentCredentials"))
                && b.path("remotePeers").equals(a.path("remotePeers"))
                && b.path("loadedClasses").equals(a.path("loadedClasses"))
                && b.path("roleFeatureFlags").equals(a.path("roleFeatureFlags"))
                && b.path("metadataSources").equals(a.path("metadataSources")));
        SimpleSamlPhpPublisherInventoryAdapter.validateSources(f,b);
        SimpleSamlPhpPublisherInventoryAdapter.validateSources(f,a);
        var last=f.manifest.path("epochs").get(f.manifest.path("epochs").size()-1);
        var lastAfter=f.original(text(last,"afterOriginal"),"native-role-inventory");
        require(lastAfter.path("runtime").equals(restored.path("runtime"))
                && at(restored,"nativeStartedAt").isAfter(at(lastAfter,"nativeFinishedAt"))
                && at(r,"recordedAt").isAfter(at(restored,"nativeFinishedAt")));
        byte[] publication=f.file(text(r,"restoredPublicationFile"));
        require(hash(publication).equals(text(r,"restoredPublicationSha256"))
                && hash(publication).equals(text(f.manifest,"targetMetadataSha256"))
                && hash(publication).equals(text(a,"nativeProducedMetadataSha256"))
                && Arrays.equals(publication,Base64.getDecoder().decode(text(a,"nativeProducedMetadataXmlBase64"))));
        var hashes = r.path("configurationHashes"); require(hashes.isArray() && hashes.size()==3);
        var paths = new HashSet<String>();
        for (var row : hashes) require(paths.add(text(row, "path"))
                && configurationHash(b,text(row,"path")).equals(text(row, "originalSha256"))
                && configurationHash(a,text(row,"path")).equals(text(row, "finalSha256"))
                && text(row, "originalSha256").equals(text(row, "finalSha256")));
        var counts = r.path("operationCounts"); require(counts.isObject());
        for (String key : List.of("productSettings", "configurationRestorations", "nativePublicCalls", "credentialPosts", "samlSubmissions", "personOperations"))
            require(counts.path(key).isIntegralNumber() && counts.path(key).asLong(-1) >= 0);
        boolean changed=false, usedSigners=false;for(var epoch:f.manifest.path("epochs")) {
            changed|="explicit-native-configuration".equals(text(epoch,"transition")) || "explicit-native-peer-signers".equals(text(epoch,"transition"));
            usedSigners|="explicit-native-peer-signers".equals(text(epoch,"transition"));
        }
        require(counts.path("personOperations").asInt(-1) == 0 && counts.path("credentialPosts").asInt(-1)==(usedSigners?1:0)
                && counts.path("samlSubmissions").asInt(-1)==(usedSigners?3:0) && counts.path("productSettings").asInt(-1)==(changed?2:0)
                && counts.path("configurationRestorations").asInt(-1)==(changed?1:0));
        if (usedSigners) {
            require(counts.path("nativeEphemeralKeyCreations").asInt(-1)==1
                    && counts.path("nativeEphemeralKeyRemovals").asInt(-1)==1);
            var material=f.original("ephemeral-material", "native-public-signing-material");
            var removal=f.original("ephemeral-removal", "native-public-signing-material-removal");
            require(text(material,"certificateSha256").equals(text(removal,"certificateSha256"))
                    && removal.path("absent").isBoolean() && removal.path("absent").asBoolean()
                    && at(removal,"nativeStartedAt").isAfter(at(lastAfter,"nativeFinishedAt"))
                    && at(removal,"nativeFinishedAt").isBefore(at(r,"recordedAt")));
        }
    }
    static List<String> compare(Element role, NativeMetadataPublisherInventoryAdapter.Inventory inventory, String caseId) throws Exception {
        var result = new ArrayList<String>(); var published = roleKeys(role);
        for (var key : inventory.keys()) {
            String purpose = key.purpose().equals("transport-authentication") ? "signing" : key.purpose();
            if (!published.get(purpose).contains(key.spkiSha256())) result.add("key:" + key.purpose() + ":" + key.spkiSha256());
        }
        if (C1.equals(caseId)) {
            var actual = new HashSet<NativeMetadataPublisherInventoryAdapter.Endpoint>();
            for (var endpoint : inventory.endpoints()) {
                for (var e : children(role, MD, endpoint.kind())) actual.add(new NativeMetadataPublisherInventoryAdapter.Endpoint(
                        endpoint.kind(), e.getAttribute("Binding"), e.getAttribute("Location"), e.getAttribute("ResponseLocation")));
                if (!actual.contains(endpoint)) result.add("endpoint:" + endpoint.kind() + ":" + endpoint.binding() + ":" + endpoint.location());
            }
            var protocols = new HashSet<>(Arrays.asList(role.getAttribute("protocolSupportEnumeration").trim().split("\\s+")));
            if (!protocols.containsAll(inventory.protocols())) result.add("supported-protocol");
            if (inventory.wantAuthnRequestsSigned() != null) {
                String value = role.getAttribute("WantAuthnRequestsSigned");
                boolean present = Set.of("true", "1").contains(value), valid = Set.of("true", "1", "false", "0", "").contains(value);
                if (!valid || present != inventory.wantAuthnRequestsSigned()) result.add("request-signature-requirement");
            }
        }
        return List.copyOf(result);
    }
    static Map<String, Set<String>> roleKeys(Element role) throws Exception {
        var result = new LinkedHashMap<String, Set<String>>(); result.put("signing", new HashSet<>()); result.put("encryption", new HashSet<>());
        for (var kd : children(role, MD, "KeyDescriptor")) {
            String use = kd.getAttribute("use"); require(Set.of("", "signing", "encryption").contains(use));
            var infos = children(kd, DS, "KeyInfo"); require(infos.size() == 1);
            Set<String> material = new HashSet<>();
            for (var xd : children(infos.getFirst(), DS, "X509Data")) {
                var certs = children(xd, DS, "X509Certificate"); require(certs.size() == 1);
                material.add(certificateSpki(certs.getFirst().getTextContent()));
            }
            for (var kv : children(infos.getFirst(), DS, "KeyValue")) {
                var rsa = children(kv, DS, "RSAKeyValue"); require(rsa.size() == 1);
                var mod = children(rsa.getFirst(), DS, "Modulus"); var exp = children(rsa.getFirst(), DS, "Exponent");
                require(mod.size() == 1 && exp.size() == 1);
                var key = KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(
                        new BigInteger(1, Base64.getMimeDecoder().decode(mod.getFirst().getTextContent())),
                        new BigInteger(1, Base64.getMimeDecoder().decode(exp.getFirst().getTextContent())))); material.add(hash(key.getEncoded()));
            }
            require(material.size() == 1); String key = material.iterator().next();
            if (!use.equals("encryption")) result.get("signing").add(key);
            if (!use.equals("signing")) result.get("encryption").add(key);
        }
        return result;
    }
    static String certificateSpki(String value) throws Exception {
        byte[] der = Base64.getMimeDecoder().decode(value); var in = new ByteArrayInputStream(der);
        var cert = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(in);
        require(in.available() == 0); return hash(cert.getPublicKey().getEncoded());
    }
    static String publicPemSpki(String value) throws Exception {
        require(value.startsWith("-----BEGIN PUBLIC KEY-----") && value.trim().endsWith("-----END PUBLIC KEY-----"));
        return hash(Base64.getMimeDecoder().decode(value.replace("-----BEGIN PUBLIC KEY-----", "").replace("-----END PUBLIC KEY-----", "")));
    }
    static Element role(byte[] raw, String entity) throws Exception {
        var root = SecureXml.parse(raw).getDocumentElement();
        require(MD.equals(root.getNamespaceURI()) && "EntityDescriptor".equals(root.getLocalName()) && entity.equals(root.getAttribute("entityID")));
        var roles = children(root, MD, "IDPSSODescriptor"); require(roles.size() == 1); return roles.getFirst();
    }
    static final class Frame {
        final Path folder; final CaseContext context; final TranscriptContentReader content; final JsonNode manifest;
        final Map<String, TranscriptEntry> history = new LinkedHashMap<>(); final Set<String> used = new LinkedHashSet<>(); final String manifestHash;
        final Function<String,byte[]> targetMetadata;
        Frame(Path folder, CaseContext context, TranscriptContentReader content, Function<String,byte[]> targetMetadata) throws Exception {
            this.folder = folder; this.context = context; this.content = content; this.targetMetadata=targetMetadata;
            byte[] raw = raw("manifest.json"); manifest = json(raw); manifestHash = hash(raw);
            require(manifest.isObject() && !sensitive(manifest));
            for (var e : context.transcript().list(context.runId())) {
                require(context.runId().equals(e.runId()) && history.put(e.id(), e) == null);
                if (e.decodedSamlRef() != null) require(("transcripts/" + context.runId() + "/" + e.id() + ".saml.xml").equals(e.decodedSamlRef()));
            }
        }
        byte[] raw(String name) throws Exception {
            require(!name.isBlank() && !Path.of(name).isAbsolute()); Path p = folder.resolve(name).normalize();
            require(p.startsWith(folder) && !p.equals(folder));
            for (var parent = p; parent != null; parent = parent.getParent()) require(!Files.isSymbolicLink(parent));
            require(Files.isRegularFile(p, LinkOption.NOFOLLOW_LINKS)); return Files.readAllBytes(p);
        }
        byte[] file(String name) throws Exception { byte[] raw = raw(name); require(hash(raw).equals(text(manifest.path("files"), name))); return raw; }
        JsonNode node(String name) throws Exception { JsonNode n = json(file(name)); require(!sensitive(n)); return n; }
        TranscriptEntry peerTranscript(String run, String id) {
            require(validRun(run)); TranscriptEntry found=null;
            var ids=new HashSet<String>();
            for(var entry:context.transcript().list(run)) {
                require(run.equals(entry.runId()) && ids.add(entry.id()));
                if(id.equals(entry.id())) { require(found==null); found=entry; }
            }
            require(found!=null && ("transcripts/"+run+"/"+id+".saml.xml").equals(found.decodedSamlRef()));
            return found;
        }
        byte[] decoded(TranscriptEntry entry) throws Exception {
            byte[] raw=content.readDecodedSaml(entry); require(raw!=null && raw.length==entry.decodedSamlBytes());
            return raw;
        }
        JsonNode original(String name, String kind) throws Exception {
            var ref = manifest.path("originals").path(name); String id = text(ref, "reference"); var tx = history.get(id);
            require(tx != null && tx.direction() == Direction.INBOUND && "POST".equals(tx.method())
                    && Integer.valueOf(204).equals(tx.status()) && "application/json".equals(tx.contentType()) && tx.decodedSamlRef() != null);
            String plan = text(manifest, "planId"); require(plan.matches("plan_[0-9A-HJKMNP-TV-Z]{26}"));
            require(tx.url().equals("http://localhost:18080/p/" + plan + "/sp/paos?run=" + context.runId())
                    && tx.url().equals(text(manifest, "recorderUrl")));
            byte[] raw = content.readDecodedSaml(tx); require(raw != null && raw.length == tx.decodedSamlBytes()
                    && hash(raw).equals(text(ref, "sha256")) && Arrays.equals(raw, file(text(ref, "file"))));
            JsonNode n = json(raw); require(!sensitive(n)
                    && "samlscope-native-publisher-original-v1".equals(text(n, "schema")) && kind.equals(text(n, "kind"))
                    && context.runId().equals(text(n, "runId")) && CAMPAIGN.equals(text(n, "campaignId"))
                    && text(manifest, "targetMetadataSha256").equals(text(n, "targetMetadataSha256"))
                    && !at(n, "recordedAt").isAfter(tx.timestamp())); used.add(id); return n;
        }
        List<EvidenceRef> evidence() {
            var refs = new ArrayList<EvidenceRef>();
            refs.add(new EvidenceRef(KIND, context.runId() + "/manifest.json#" + manifestHash));
            for (String id : used) refs.add(new EvidenceRef("transcript", id)); return List.copyOf(refs);
        }
    }
    static boolean sensitive(JsonNode n) {
        if (n.isObject()) for (var it = n.fields(); it.hasNext();) {
            var entry = it.next(); String key = entry.getKey().toLowerCase(Locale.ROOT).replaceAll("[-_.]", "");
            if (key.contains("cookie") || key.contains("authorization") || key.contains("password") || key.contains("passwd")
                    || key.contains("secret") || key.contains("token") || key.contains("privatekey")
                    || (key.contains("credentials") && !key.equals("currentcredentials"))
                    || sensitive(entry.getValue())) return true;
        } else if (n.isArray()) { for (var item : n) if (sensitive(item)) return true; }
        else if (n.isTextual() && n.asText().matches("(?s).*-----BEGIN (?:RSA |EC |ENCRYPTED )?PRIVATE KEY-----.*")) return true;
        return false;
    }
    static boolean validRun(String run) { return run != null && run.matches("run_[0-9A-HJKMNP-TV-Z]{26}"); }
    static void require(boolean condition) { if (!condition) throw new IllegalArgumentException("Native publisher inventory unavailable"); }
    static String text(JsonNode n, String key) { require(n.path(key).isTextual() && !n.path(key).asText().isBlank()); return n.path(key).asText(); }
    static Instant at(JsonNode n, String key) { return Instant.parse(text(n, key)); }
    static boolean within(Instant t, Instant from, Instant until) { return !t.isBefore(from) && !t.isAfter(until); }
    static String hash(byte[] raw) throws Exception { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(raw)); }
    static JsonNode json(byte[] raw) throws Exception { return new JsonCodec().mapper().readTree(raw); }
    private static CaseOutcome pending(String caseId, String run, String cause, List<String> gaps) {
        return new CaseOutcome(Outcome.NOT_VERIFIED, cause, UNPROVEN, UNPROVEN, List.of(),
                Map.of("case_id", caseId, "native_run_id", run, "native_receipt_owned", true, "unresolved_scope", gaps));
    }
}
