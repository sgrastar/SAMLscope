package com.samlscope.runner.cases;

import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.cert.*;
import java.time.*;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.function.Function;
import java.util.regex.Pattern;
import com.fasterxml.jackson.databind.JsonNode;
import com.samlscope.core.caseexec.CaseContext;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.plan.TargetRole;
import com.samlscope.core.transcript.*;
import com.samlscope.runner.DefaultCaseContext;
import com.samlscope.saml.crypto.XmlSignatureVerifier;
import com.samlscope.saml.normal.SecureXml;
import com.samlscope.store.JsonCodec;
import org.w3c.dom.Element;

/** Native duplicate conflict plus actual distinct peers; import success alone is insufficient. */
public final class ShibbolethEntityIdUniquenessEvidence {
    public static final String CASE="IIP-MD05-a1-idp-01";
    private static final String SCHEMA="samlscope-shibboleth-entityid-uniqueness-v1";
    private static final String RUN="run_[0-9A-HJKMNP-TV-Z]{26}";
    private static final String MD="urn:oasis:names:tc:SAML:2.0:metadata",P="urn:oasis:names:tc:SAML:2.0:protocol";
    private static final String DS="http://www.w3.org/2000/09/xmldsig#";
    private static final String SHIB="urn:mace:shibboleth:2.0:metadata",XSI="http://www.w3.org/2001/XMLSchema-instance";
    private static final String IMAGE="sha256:3c1b1fa64c58258aefc9e38d4ae60e9f0340731318a472110ea56ce88c18a11a";
    private static final String CLASS_HASH="99584e841536ae78ab7a54b89f0e1e679aa12c22c13b8922eb6b1faa531fcf4b";
    private static final String JAR_HASH="9f04221e172dc426f90fb3873d0148a0744edbf9e7a37de7ee0e6a34f7b74581";
    private final Path directory;
    private final TranscriptContentReader content;
    private final Function<String,byte[]> metadata;
    private final SamlDecryptionKeyProvider keys;

    public ShibbolethEntityIdUniquenessEvidence(Path directory,TranscriptContentReader content,
            Function<String,byte[]> metadata,SamlDecryptionKeyProvider keys) {
        this.directory=Objects.requireNonNull(directory).toAbsolutePath().normalize();
        this.content=Objects.requireNonNull(content);this.metadata=Objects.requireNonNull(metadata);this.keys=Objects.requireNonNull(keys);
    }
    /** An owned malformed proof must shadow the older fixture observation. */
    public boolean exists(String run) {
        if(!run.matches(RUN))return false;
        return Files.exists(directory.resolve(run),LinkOption.NOFOLLOW_LINKS);
    }
    public Optional<CaseOutcome> read(CaseContext context) {
        try {
            require(context.targetRole()==TargetRole.IDP&&context.transcriptComplete()&&context.runId().matches(RUN));
            var folder=directory.resolve(context.runId());safeDirectory(folder);
            var manifest=json(folder,"manifest.json");
            require(SCHEMA.equals(text(manifest,"schema"))&&context.runId().equals(text(manifest,"runId")));
            var targetRaw=metadata.apply(context.runId());
            require(hash(targetRaw).equals(text(manifest,"targetMetadataSha256")));
            var target=SecureXml.parse(targetRaw).getDocumentElement();
            require(MD.equals(target.getNamespaceURI())&&"EntityDescriptor".equals(target.getLocalName())
                &&text(manifest,"targetEntityId").equals(target.getAttribute("entityID")));
            var hashes=manifest.path("originals");require(hashes.isObject()&&hashes.size()>0);
            var names=new HashSet<String>();hashes.fields().forEachRemaining(pair->names.add(pair.getKey()));
            for(var name:names)require(hash(original(folder,name)).equals(hashes.path(name).asText()));
            // Actual native classes and immutable target image close both historical epochs.
            require(hash(original(folder,"native-abstract-metadata-resolver.class")).equals(CLASS_HASH)
                &&hash(original(folder,"native-opensaml-saml-impl.jar")).equals(JAR_HASH));
            var source=json(folder,"native-resolver-source.json");
            require(CLASS_HASH.equals(text(source,"classSha256"))&&JAR_HASH.equals(text(source,"jarSha256"))
                &&JAR_HASH.equals(text(source,"finalJarSha256"))&&source.path("unchanged").asBoolean());
            var current=runtime(folder,"target-container-inspect-start.json");
            require(current.equals(runtime(folder,"target-container-inspect-end.json")));
            var distinctRun=text(manifest,"distinctRunId");require(distinctRun.matches(RUN)&&!distinctRun.equals(context.runId()));
            var distinctFolder=folder.resolve("distinct-proof").resolve(distinctRun);safeDirectory(distinctFolder);
            var pair=json(folder,"distinct-proof/"+distinctRun+"/manifest.json");
            require(distinctRun.equals(text(pair,"runId"))&&Arrays.equals(targetRaw,metadata.apply(distinctRun)));
            var peers=pair.path("peers");require(peers.isArray()&&peers.size()==2);
            var selectedRuns=new HashSet<String>();
            for(var peer:peers)require(selectedRuns.add(text(peer,"runId"))&&text(peer,"runId").matches(RUN)
                &&Arrays.equals(targetRaw,metadata.apply(text(peer,"runId"))));
            require(selectedRuns.contains(distinctRun)&&!selectedRuns.contains(context.runId()));
            var runtimeFiles=manifest.path("distinctRuntimeFiles");require(runtimeFiles.isArray()&&runtimeFiles.size()==6);
            for(var file:runtimeFiles)require(current.equals(runtimeIdentity(folder,file.asText())));
            // This existing strict native proof validates actual effective metadata, both signed
            // requests/responses, different entity IDs, four provider readbacks and exact restore.
            // No new product action is required to reuse these already recorded distinct entities.
            var distinctContext=new DefaultCaseContext(distinctRun,context.targetRole(),context.clock(),
                context.parameters(),context.interaction(),context.reachability(),context.transcript(),context.transcriptComplete());
            checkEntries(context,context.runId());for(var run:selectedRuns)checkEntries(context,run);
            var pairProof=new PersistentPairwiseNameIdEvidence(folder.resolve("distinct-proof"),content,metadata,keys)
                .evaluate(distinctContext).orElseThrow();
            require(pairProof.outcome()==Outcome.SATISFIED);
            var created=json(folder,"created.json").path("run");
            require(context.runId().equals(text(created,"id")));
            var entity="http://localhost:18080/p/"+text(created,"planId");
            var prepared=new HashMap<String,TranscriptEntry>();
            var byId=new HashMap<String,TranscriptEntry>();for(var entry:context.transcript().list(context.runId()))byId.put(entry.id(),entry);
            for(var entry:context.transcript().list(context.runId())) {
                var variant=String.valueOf(entry.samlSummary().get("variant"));
                if(entry.direction()==Direction.OUTBOUND&&"MetadataPrepared".equals(entry.samlSummary().get("type"))
                    &&List.of("control","duplicate-entity-ids").contains(variant)) {
                    require(prepared.put(variant,entry)==null);
                    var raw=content.readDecodedSaml(entry);
                    require(Arrays.equals(raw,original(folder,variant+"/fixture.xml"))
                        &&hash(raw).equals(entry.samlSummary().get("metadataSha256")));
                    var fetch=byId.get(String.valueOf(entry.samlSummary().get("fetchTranscriptId")));
                    require(fetch!=null&&fetch.direction()==Direction.INBOUND&&"MetadataFetch".equals(fetch.samlSummary().get("type"))
                        &&variant.equals(fetch.samlSummary().get("variant"))&&Objects.equals(fetch.status(),200)
                        &&Objects.equals(entry.status(),200)&&Objects.equals(entry.correlationId(),fetch.id())
                        &&Objects.equals(entry.url(),fetch.url())&&!entry.timestamp().isBefore(fetch.timestamp())
                        &&"PREPARED".equals(entry.samlSummary().get("delivery")));
                }
            }
            require(prepared.keySet().equals(Set.of("control","duplicate-entity-ids")));
            var normal=MetadataAlgorithmEvidence.collect(List.of("control"),context,content,targetRaw);
            require(normal.issues().isEmpty()&&normal.exchanges().size()==1);
            var normalMetadata=normal.exchanges().getFirst().metadata();
            require(entity.equals(normalMetadata.getAttribute("entityID")));
            var duplicate=SecureXml.parse(original(folder,"duplicate-entity-ids/fixture.xml")).getDocumentElement();
            require(MD.equals(duplicate.getNamespaceURI())&&"EntitiesDescriptor".equals(duplicate.getLocalName()));
            var descriptors=MetadataAlgorithmEvidence.children(duplicate,MD,"EntityDescriptor");
            require(descriptors.size()==2&&descriptors.stream().allMatch(e->entity.equals(e.getAttribute("entityID"))));
            var configured=original(folder,"configured-providers-readback.xml");
            require(Arrays.equals(configured,original(folder,"configured-providers.xml")));
            var providers=SecureXml.parse(configured).getDocumentElement();
            var provider=MetadataAlgorithmEvidence.children(providers,SHIB,"MetadataProvider").stream()
                .filter(e->("Algorithm"+context.runId()).equals(e.getAttribute("id"))).toList();
            require(provider.size()==1&&"FilesystemMetadataProvider".equals(localType(provider.getFirst()))
                &&("/opt/reference-idp/metadata/algorithm-"+context.runId()+".xml").equals(provider.getFirst().getAttribute("metadataFile")));
            var epochs=json(folder,"native-resolver-epochs.json");require(epochs.isArray()&&epochs.size()==4);
            var closure=new HashSet<String>();
            for(var epoch:epochs) {
                var variant=text(epoch,"variant");var phase=text(epoch,"phase");
                require(List.of("control","duplicate-entity-ids").contains(variant)&&List.of("reload","protocol").contains(phase)
                    &&closure.add(variant+"/"+phase));
                var begin=Instant.parse(text(epoch,"startedAt"));var end=Instant.parse(text(epoch,"finishedAt"));
                require(!begin.isAfter(end)&&!prepared.get(variant).timestamp().isAfter(begin));
                for(var side:List.of("before","after")) {
                    var read=epoch.path(side);require(context.runId().equals(text(read,"runId")));
                    require(Arrays.equals(configured,checked(folder,variant+"/",read,"providerFile","providerSha256"))
                        &&Arrays.equals(original(folder,variant+"/fixture.xml"),checked(folder,variant+"/",read,"fixtureFile","fixtureSha256")));
                    var at=Instant.parse(text(read,"recordedAt"));
                    require(side.equals("before")?!at.isAfter(begin):!at.isBefore(end));
                }
                if(phase.equals("reload")) {
                    var log=new String(checked(folder,variant+"/",epoch,"nativeLogFile","nativeLogSha256"),StandardCharsets.UTF_8);
                    require(epoch.path("nativeLogOffset").canConvertToLong()&&epoch.path("nativeLogEnd").asLong()>=epoch.path("nativeLogOffset").asLong());
                    var marker="FilesystemMetadataResolver Algorithm"+context.runId()+": Detected duplicate EntityDescriptor for entityID: "+entity;
                    if(variant.equals("control"))require(log.isBlank());
                    else {
                        var lines=log.lines().filter(s->!s.isBlank()).toList();require(lines.size()==1);
                        var line=lines.getFirst();require(line.contains("WARN [org.opensaml.saml.metadata.resolver.impl.AbstractMetadataResolver:662] - ")&&line.endsWith(marker));
                        var at=LocalDateTime.parse(line.substring(0,23),DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss,SSS")).toInstant(ZoneOffset.UTC);
                        require(!at.isBefore(begin)&&!at.isAfter(end)&&epoch.path("nativeLogEnd").asLong()>epoch.path("nativeLogOffset").asLong());
                    }
                } else {
                    var entries=context.transcript().list(context.runId());
                    var sends=entries.stream().filter(e->e.direction()==Direction.OUTBOUND&&"AuthnRequest".equals(e.samlSummary().get("type"))
                        &&variant.equals(e.samlSummary().get("variant"))).toList();
                    require(!sends.isEmpty()&&sends.stream().allMatch(e->!e.timestamp().isBefore(begin)&&!e.timestamp().isAfter(end)));
                    if(variant.equals("control")) {
                        var exchange=normal.exchanges().getFirst();
                        for(var reference:exchange.evidence())if(reference.kind().equals("transcript")) {
                            var e=entries.stream().filter(t->t.id().equals(reference.reference())).findFirst().orElseThrow();
                            if("AuthnRequest".equals(e.samlSummary().get("type"))||"Response".equals(e.samlSummary().get("type")))
                                require(!e.timestamp().isBefore(begin)&&!e.timestamp().isAfter(end));
                        }
                        var valid=sends.stream().filter(e->"valid".equals(e.samlSummary().get("metadataSignatureControl"))).toList();require(valid.size()==1);
                        var request=SecureXml.parse(content.readDecodedSaml(valid.getFirst())).getDocumentElement();
                        var verifier=new XmlSignatureVerifier();var signing=spSigningKeys(normalMetadata);
                        require(verifier.hasValidEnvelopedReferenceDigests(request)&&signing.stream().anyMatch(c->verifier.hasValidEnvelopedSignature(request,c)));
                    }
                }
            }
            require(Arrays.equals(original(folder,"original-providers.xml"),original(folder,"final-providers.xml")));
            var restoration=json(folder,"restoration.json");
            require(restoration.path("restored").asBoolean()&&restoration.path("temporary_file_removed").asBoolean()
                &&hash(original(folder,"original-providers.xml")).equals(text(restoration,"original_sha256"))
                &&hash(original(folder,"final-providers.xml")).equals(text(restoration,"final_sha256")));
            var evidence=new LinkedHashSet<EvidenceRef>(normal.exchanges().getFirst().evidence());evidence.addAll(pairProof.evidence());
            evidence.add(new EvidenceRef("transcript",prepared.get("duplicate-entity-ids").id()));
            evidence.add(new EvidenceRef("native-entityid-evidence",context.runId()+"/duplicate-entity-ids/native-resolver-warn.log#"+hash(original(folder,"duplicate-entity-ids/native-resolver-warn.log"))));
            evidence.add(new EvidenceRef("native-entityid-evidence",context.runId()+"/manifest.json#"+hash(original(folder,"manifest.json"))));
            return Optional.of(new CaseOutcome(Outcome.SATISFIED,null,"metadata.entityid.native-conflict-and-distinct-peers",
                "metadata.entityid.native-conflict-and-distinct-peers",List.copyOf(evidence),Map.of("adapter","shibboleth-native-entityid-uniqueness",
                "distinct_peer_count",2,"distinct_primary_run",distinctRun,"duplicate_behavior","native-resolver-conflict")));
        }catch(Exception unproven){return Optional.empty();}
    }
    private void checkEntries(CaseContext context,String run)throws Exception {
        var ids=new HashSet<String>();for(var entry:context.transcript().list(run)) {
            require(run.equals(entry.runId())&&entry.id().matches("tx_[0-9A-HJKMNP-TV-Z]{26}")&&ids.add(entry.id()));
            if(entry.decodedSamlRef()!=null)require(("transcripts/"+run+"/"+entry.id()+".saml.xml").equals(entry.decodedSamlRef())
                &&content.readDecodedSaml(entry).length==entry.decodedSamlBytes());
        }
        require(!ids.isEmpty());
    }
    private String runtime(Path folder,String file)throws Exception {
        var root=json(folder,file);require(root.isArray()&&root.size()==1);
        var row=root.get(0);require(row.path("State").path("Running").asBoolean());
        return runtimeRow(row);
    }
    private String runtimeIdentity(Path folder,String file)throws Exception {
        var root=json(folder,file);return runtimeRow(root.isArray()?root.get(0):root);
    }
    private String runtimeRow(JsonNode row) {
        require(IMAGE.equals(text(row,"Image"))&&row.path("Mounts").isArray()&&row.path("Mounts").isEmpty());
        return text(row,"Id")+"|"+text(row,"Image");
    }
    private static String localType(Element element) {
        var type=element.getAttributeNS(XSI,"type");var parts=type.split(":",2);
        require(SHIB.equals(element.lookupNamespaceURI(parts.length==2?parts[0]:null)));
        return parts[parts.length-1];
    }
    private static List<X509Certificate> spSigningKeys(Element entity)throws Exception {
        var certificates=new ArrayList<X509Certificate>();
        var roles=MetadataAlgorithmEvidence.children(entity,MD,"SPSSODescriptor");require(roles.size()==1);
        for(var key:MetadataAlgorithmEvidence.children(roles.getFirst(),MD,"KeyDescriptor")) {
            if(!List.of("","signing").contains(key.getAttribute("use")))continue;
            for(var info:MetadataAlgorithmEvidence.children(key,DS,"KeyInfo"))
                for(var data:MetadataAlgorithmEvidence.children(info,DS,"X509Data"))
                    for(var certificate:MetadataAlgorithmEvidence.children(data,DS,"X509Certificate"))
                        certificates.add((X509Certificate)CertificateFactory.getInstance("X.509").generateCertificate(
                            new java.io.ByteArrayInputStream(Base64.getMimeDecoder().decode(certificate.getTextContent()))));
        }
        require(!certificates.isEmpty());return certificates;
    }
    private byte[] checked(Path folder,String prefix,JsonNode row,String file,String digest)throws Exception {
        var name=text(row,file);require(!name.contains("/")&&!name.contains("\\")&&!name.equals(".")&&!name.equals(".."));
        var raw=original(folder,prefix+name);require(hash(raw).equals(text(row,digest)));return raw;
    }
    private JsonNode json(Path folder,String file)throws Exception{return new JsonCodec().mapper().readTree(original(folder,file));}
    private byte[] original(Path folder,String file)throws Exception {
        require(!file.isBlank()&&!file.contains("\\"));var path=folder.resolve(file).normalize();
        require(path.startsWith(folder)&&!path.equals(folder)&&file.equals(folder.relativize(path).toString()));
        for(var parent=path.getParent();parent!=null;parent=parent.getParent())require(!Files.isSymbolicLink(parent));
        require(Files.isRegularFile(path,LinkOption.NOFOLLOW_LINKS)&&Files.size(path)>0&&Files.size(path)<=20*1024*1024);
        return Files.readAllBytes(path);
    }
    private void safeDirectory(Path folder)throws Exception {
        require(Files.isDirectory(folder,LinkOption.NOFOLLOW_LINKS));
        for(var parent=folder;parent!=null;parent=parent.getParent())require(!Files.isSymbolicLink(parent));
    }
    private static String text(JsonNode node,String name) {var value=node.path(name);require(value.isTextual()&&!value.asText().isBlank());return value.asText();}
    private static String hash(byte[] raw)throws Exception {return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(raw));}
    private static void require(boolean value){if(!value)throw new IllegalArgumentException("Unproven native entityID uniqueness");}
}
