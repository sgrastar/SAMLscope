package com.samlscope.runner.cases;

import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.*;
import java.util.*;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.plan.*;
import com.samlscope.core.run.*;
import com.samlscope.core.transcript.*;
import com.samlscope.runner.DefaultCaseContext;
import com.samlscope.saml.crypto.*;
import com.samlscope.saml.normal.SecureXml;
import com.samlscope.store.JsonCodec;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.*;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.w3c.dom.Element;

/** Replay inside the Suite only: native keys and decrypted/mutated assertions remain in memory. */
public final class VerifyShibbolethPersistentPairwiseEvidence {
    private static final JsonCodec JSON = new JsonCodec();
    private static final String P = "urn:oasis:names:tc:SAML:2.0:protocol";
    private static final String S = "urn:oasis:names:tc:SAML:2.0:assertion";
    private static final String DS = "http://www.w3.org/2000/09/xmldsig#";
    private static String hash(byte[] raw) throws Exception { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(raw)); }
    private static byte[] original(TranscriptEntry entry) throws Exception {
        if (!entry.runId().matches("run_[0-9A-HJKMNP-TV-Z]{26}") || !entry.id().matches("tx_[0-9A-HJKMNP-TV-Z]{26}")
                || !("transcripts/"+entry.runId()+"/"+entry.id()+".saml.xml").equals(entry.decodedSamlRef()))
            throw new IllegalArgumentException("Unsafe native original");
        var value=Files.readAllBytes(Path.of("/data").resolve(entry.decodedSamlRef()));
        if(value.length!=entry.decodedSamlBytes())throw new IllegalArgumentException("Original size differs");
        return value;
    }
    private static Optional<CaseOutcome> evaluate(Path root, ObjectNode manifest,
            Map<String,List<TranscriptEntry>> entries,Map<String,byte[]> bodies,Map<String,byte[]> targets,
            Map<String,PrivateKey> keys,String primary)throws Exception {
        Files.write(root.resolve(primary).resolve("manifest.json"),JSON.mapper().writeValueAsBytes(manifest));
        var recorder=new TranscriptRecorder(){
            @Override public List<TranscriptEntry> list(String run){return entries.getOrDefault(run,List.of());}
            @Override public TranscriptEntry record(TranscriptInput input){throw new UnsupportedOperationException();}
            @Override public TranscriptEntry updateSamlAnalysis(String id,String correlation,Map<String,Object> summary){throw new UnsupportedOperationException();}
        };
        var context=new DefaultCaseContext(primary,TargetRole.IDP,Clock.systemUTC(),new TestPlan.Parameters(180,300,"",TestPlan.RequestSigningMode.REQUIRED),
                TestPlan.Interaction.defaults(),Reachability.CONFIRMED,recorder,true);
        return new PersistentPairwiseNameIdEvidence(root,entry->bodies.get(entry.id()),targets::get,run->Optional.ofNullable(keys.get(run))).evaluate(context);
    }
    private static PlanCredentials fixtureCredentials()throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        var generator=KeyPairGenerator.getInstance("RSA");generator.initialize(2048);var pair=generator.generateKeyPair();
        var subject=new X500Name("CN=Memory-only semantic control");var now=Instant.now();
        var cert=new JcaX509v3CertificateBuilder(subject,java.math.BigInteger.ONE,Date.from(now.minusSeconds(86400)),Date.from(now.plusSeconds(86400)),subject,pair.getPublic())
                .build(new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC").build(pair.getPrivate()));
        return new PlanCredentials(pair.getPrivate(),new JcaX509CertificateConverter().setProvider("BC").getCertificate(cert));
    }
    private static void removeSignatures(Element root){
        for(var node:MetadataAlgorithmEvidence.children(root,DS,"Signature"))root.removeChild(node);
    }
    private static Map<String,byte[]> semanticBodies(ObjectNode manifest,Map<String,byte[]> bodies,
            Map<String,PrivateKey> keys,PlanCredentials fixture,String mutation)throws Exception {
        var result=new HashMap<>(bodies);String firstValue=null;
        for(var peer:manifest.path("peers")) {
            var run=peer.path("runId").asText();
            var exchange=peer.path("exchanges").get(0);var reference=exchange.path("responseReference").asText();
            var document=SecureXml.parse(bodies.get(reference));var response=document.getDocumentElement();
            var encrypted=MetadataAlgorithmEvidence.children(response,S,"EncryptedAssertion");
            var assertion=new SamlXmlDecrypter().decrypt(encrypted.getFirst(),keys.get(run));
            var imported=(Element)document.importNode(assertion,true);response.replaceChild(imported,encrypted.getFirst());
            removeSignatures(imported);removeSignatures(response);
            var name=(Element)imported.getElementsByTagNameNS(S,"NameID").item(0);
            if(firstValue==null)firstValue=name.getTextContent();
            if(peer==manifest.path("peers").get(1)) {
                switch(mutation){
                    case "equal-persistent-values" -> name.setTextContent(firstValue);
                    case "wrong-name-qualifier" -> name.setAttribute("NameQualifier","https://wrong-idp.example");
                    case "wrong-sp-name-qualifier" -> name.setAttribute("SPNameQualifier","https://wrong-sp.example");
                    case "unexpected-sp-provided-id" -> name.setAttribute("SPProvidedID","unassigned-alternative-id");
                    case "wrong-audience" -> ((Element)imported.getElementsByTagNameNS(S,"Audience").item(0)).setTextContent("https://wrong-audience.example");
                }
            }
            new XmlSigner().sign(response,fixture,MetadataAlgorithmEvidence.children(response,P,"Status").getFirst());
            result.put(reference,SecureXml.serialize(document));
        }
        return result;
    }
    private static Map<String,byte[]> fixtureTargets(ObjectNode manifest,Map<String,byte[]> targets,PlanCredentials fixture)throws Exception {
        var result=new HashMap<String,byte[]>();byte[] first=null;
        for(var peer:manifest.path("peers")) {
            var run=peer.path("runId").asText();var document=SecureXml.parse(targets.get(run));
            var certs=document.getElementsByTagNameNS(DS,"X509Certificate");
            for(int i=0;i<certs.getLength();i++)certs.item(i).setTextContent(Base64.getEncoder().encodeToString(fixture.certificate().getEncoded()));
            var raw=SecureXml.serialize(document);result.put(run,raw);if(first==null)first=raw;
        }
        manifest.put("targetMetadataSha256",hash(first));return result;
    }
    private static void replaceFile(Path folder,ObjectNode row,String fileField,String hashField,byte[] raw)throws Exception {
        Files.write(folder.resolve(row.path(fileField).asText()),raw);row.put(hashField,hash(raw));
    }
    private static void replaceConfigured(Path folder,ObjectNode row,byte[] raw)throws Exception {
        replaceFile(folder,row,"configuredFile","configuredSha256",raw);
        for(var value:row.path("readBacks"))replaceFile(folder,(ObjectNode)value,"file","sha256",raw);
    }
    public static void main(String[] args)throws Exception {
        java.util.logging.Logger.getLogger("org.apache.xml.security.signature.XMLSignature").setLevel(java.util.logging.Level.SEVERE);
        if(args.length!=2)throw new IllegalArgumentException("receipt-directory output-report required");
        var source=Path.of(args[0]);var base=(ObjectNode)JSON.mapper().readTree(source.resolve("manifest.json").toFile());
        var primary=base.path("runId").asText();var targets=new HashMap<String,byte[]>();var entries=new HashMap<String,List<TranscriptEntry>>();
        var bodies=new HashMap<String,byte[]>();var keys=new HashMap<String,PrivateKey>();
        for(int index=0;index<2;index++){
            var peer=base.path("peers").get(index);var run=peer.path("runId").asText();
            var label=index==0?"primary":"secondary";
            var list=List.of(JSON.mapper().readValue(source.resolve(label+"-transcript.json").toFile(),TranscriptEntry[].class));
            var expected=new HashMap<String,String>();
            for(var row:JSON.mapper().readTree(source.resolve(label+"-decoded-manifest.json").toFile()))
                if(expected.put(row.path("id").asText(),row.path("sha256").asText())!=null)throw new IllegalArgumentException("Duplicate decoded original");
            entries.put(run,list);for(var entry:list)if(entry.decodedSamlRef()!=null){
                var raw=original(entry);if(!hash(raw).equals(expected.remove(entry.id())))throw new IllegalArgumentException("Native original hash differs");
                bodies.put(entry.id(),raw);
            }
            if(!expected.isEmpty())throw new IllegalArgumentException("Unbound decoded originals");
            targets.put(run,Files.readAllBytes(Path.of("/data/target-metadata").resolve(run+".xml")));
            var entity=peer.path("entityId").asText();var plan=entity.substring(entity.lastIndexOf('/')+1);
            if(!plan.matches("plan_[0-9A-HJKMNP-TV-Z]{26}"))throw new IllegalArgumentException("Unsafe Plan key source");
            keys.put(run,KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(Files.readAllBytes(Path.of("/data/keys").resolve(plan).resolve("signing-key.pk8")))));
        }
        var files=new HashMap<String,byte[]>();try(var paths=Files.list(source)){for(var p:paths.filter(Files::isRegularFile).toList())files.put(p.getFileName().toString(),Files.readAllBytes(p));}
        var temp=Files.createTempDirectory("samlscope-persistent-replay-");var folder=temp.resolve(primary);Files.createDirectory(folder);
        var checks=new LinkedHashMap<String,String>();
        try {
            for(var item:files.entrySet())Files.write(folder.resolve(item.getKey()),item.getValue());
            if(evaluate(temp,base.deepCopy(),entries,bodies,targets,keys,primary).map(CaseOutcome::outcome).orElse(Outcome.NOT_VERIFIED)!=Outcome.SATISFIED)
                throw new IllegalStateException("Actual native campaign rejected by production Reader");
            var fixture=fixtureCredentials();var semanticManifest=base.deepCopy();var semanticTargets=fixtureTargets(semanticManifest,targets,fixture);
            if(evaluate(temp,semanticManifest.deepCopy(),entries,semanticBodies(semanticManifest,bodies,keys,fixture,"baseline"),semanticTargets,keys,primary)
                    .map(CaseOutcome::outcome).orElse(Outcome.NOT_VERIFIED)!=Outcome.SATISFIED)
                throw new IllegalStateException("Cryptographically valid semantic control fixture rejected");
            for(var mutation:List.of("equal-persistent-values","wrong-name-qualifier","wrong-sp-name-qualifier","unexpected-sp-provided-id","wrong-audience",
                    "different-principal","forged-audit-request","wrong-target","wrong-run","wrong-decryption-key","missing-peer","wrong-request-reference",
                    "wrong-native-sp-metadata","wrong-restoration","missing-readback","late-before-readback","wrong-readback","missing-original","wrong-uid-resolver-qname","disabled-generator","foreign-run-transcript")) {
                for(var item:files.entrySet())Files.write(folder.resolve(item.getKey()),item.getValue());
                var manifest=base.deepCopy();var changedBodies=new HashMap<>(bodies);var changedTargets=new HashMap<>(targets);var changedKeys=new HashMap<>(keys);
                var changedEntries=new HashMap<>(entries);var secondary=(ObjectNode)manifest.path("peers").get(1);var secondaryRun=secondary.path("runId").asText();
                if(List.of("equal-persistent-values","wrong-name-qualifier","wrong-sp-name-qualifier","unexpected-sp-provided-id","wrong-audience").contains(mutation)) {
                    changedTargets=new HashMap<>(fixtureTargets(manifest,targets,fixture));changedBodies=new HashMap<>(semanticBodies(manifest,bodies,keys,fixture,mutation));
                }else switch(mutation){
                    case "different-principal","forged-audit-request" -> {
                        var value=new String(files.get(secondary.path("auditFile").asText()),StandardCharsets.UTF_8);
                        value=mutation.equals("different-principal")?value.replace("|samlscope-m0-user|","|different-principal|"):
                            value.replace("_action_", "_forged_action_");
                        replaceFile(folder,secondary,"auditFile","auditSha256",value.getBytes(StandardCharsets.UTF_8));
                    }
                    case "wrong-target" -> manifest.put("targetMetadataSha256","0".repeat(64));
                    case "wrong-run" -> manifest.put("runId","run_00000000000000000000000000");
                    case "wrong-decryption-key" -> changedKeys.put(secondaryRun,keys.get(primary));
                    case "missing-peer" -> ((ArrayNode)manifest.path("peers")).remove(1);
                    case "wrong-request-reference" -> ((ObjectNode)secondary.path("exchanges").get(0)).put("requestReference",manifest.path("peers").get(0).path("exchanges").get(0).path("requestReference").asText());
                    case "wrong-native-sp-metadata" -> {
                        var document=SecureXml.parse(files.get(secondary.path("nativeMetadataFile").asText()));document.getDocumentElement().setAttribute("entityID","https://foreign-sp.example");
                        replaceFile(folder,secondary,"nativeMetadataFile","nativeMetadataSha256",SecureXml.serialize(document));
                    }
                    case "wrong-restoration","missing-readback","late-before-readback","wrong-readback","missing-original","wrong-uid-resolver-qname","disabled-generator" -> {
                        var kind=mutation.equals("wrong-uid-resolver-qname")?"attribute-resolver-xml":"nameid-xml";
                        ObjectNode row=null;for(var candidate:manifest.path("configurationFiles"))if(kind.equals(candidate.path("kind").asText()))row=(ObjectNode)candidate;
                        if(row==null)throw new IllegalStateException();
                        switch(mutation){
                            case "wrong-restoration" -> replaceFile(folder,row,"finalFile","finalSha256","changed state".getBytes(StandardCharsets.UTF_8));
                            case "missing-readback" -> ((ArrayNode)row.path("readBacks")).remove(0);
                            case "late-before-readback" -> ((ObjectNode)row.path("readBacks").get(0)).put("recordedAt","2099-01-01T00:00:00Z");
                            case "wrong-readback" -> replaceFile(folder,(ObjectNode)row.path("readBacks").get(0),"file","sha256","changed state".getBytes(StandardCharsets.UTF_8));
                            case "missing-original" -> Files.delete(folder.resolve(row.path("originalFile").asText()));
                            case "disabled-generator" -> replaceConfigured(folder,row,new String(files.get(row.path("configuredFile").asText()),StandardCharsets.UTF_8)
                                    .replace("shibboleth.SAML2PersistentGenerator","shibboleth.DisabledPersistentGenerator").getBytes(StandardCharsets.UTF_8));
                            case "wrong-uid-resolver-qname" -> {
                                var doc=SecureXml.parse(files.get(row.path("configuredFile").asText()));var nodes=doc.getElementsByTagNameNS("urn:mace:shibboleth:2.0:resolver","AttributeDefinition");
                                for(int i=0;i<nodes.getLength();i++){var node=(Element)nodes.item(i);if("uid".equals(node.getAttribute("id"))){node.setAttributeNS("http://www.w3.org/2000/xmlns/","xmlns:foreign","https://foreign.example");node.setAttributeNS("http://www.w3.org/2001/XMLSchema-instance","xsi:type","foreign:PrincipalName");}}
                                replaceConfigured(folder,row,SecureXml.serialize(doc));
                            }
                        }
                    }
                    case "foreign-run-transcript" -> {
                        var list=new ArrayList<>(entries.get(secondaryRun));var old=list.get(0);list.set(0,new TranscriptEntry(old.id(),primary,old.direction(),old.timestamp(),old.correlationId(),old.method(),old.url(),old.status(),old.headers(),old.bodyRef(),old.bodyBytes(),old.decodedSamlRef(),old.decodedSamlBytes(),old.contentType(),old.rawQuery(),old.samlSummary()));changedEntries.put(secondaryRun,List.copyOf(list));
                    }
                }
                var outcome=evaluate(temp,manifest,changedEntries,changedBodies,changedTargets,changedKeys,primary).map(CaseOutcome::outcome).orElse(Outcome.NOT_VERIFIED);
                if(outcome==Outcome.SATISFIED)throw new IllegalStateException("Invalid control adopted: "+mutation);
                checks.put(mutation,outcome.name());
            }
            var report=new LinkedHashMap<String,Object>();report.put("schema","samlscope-shibboleth-persistent-production-replay-v1");report.put("runId",primary);
            report.put("nativeOriginals",Outcome.SATISFIED.name());report.put("memoryOnlySemanticBaseline",Outcome.SATISFIED.name());report.put("controls",checks);
            Files.write(Path.of(args[1]),JSON.mapper().writerWithDefaultPrettyPrinter().writeValueAsBytes(report));
        } finally {
            try(var paths=Files.walk(temp)){for(var p:paths.sorted(Comparator.reverseOrder()).toList())Files.delete(p);}
        }
    }
}
