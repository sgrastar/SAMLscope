package com.samlscope.runner.cases;

import com.fasterxml.jackson.databind.node.ObjectNode;
import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.plan.*;
import com.samlscope.core.run.Reachability;
import com.samlscope.core.transcript.*;
import com.samlscope.runner.DefaultCaseContext;
import com.samlscope.saml.crypto.*;
import com.samlscope.saml.normal.SecureXml;
import com.samlscope.store.JsonCodec;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.*;
import java.util.*;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.*;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.w3c.dom.Element;

/** Actual archived Reader replay inside the Suite. All private keys and plaintext stay in memory. */
public final class VerifyShibbolethMetadataSupersessionEvidence {
    private static final JsonCodec JSON=new JsonCodec();
    private static final String P="urn:oasis:names:tc:SAML:2.0:protocol",A="urn:oasis:names:tc:SAML:2.0:assertion",DS="http://www.w3.org/2000/09/xmldsig#";
    private static String hash(byte[] raw)throws Exception{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(raw));}
    private static CaseOutcome evaluate(Path root,String run,ObjectNode manifest,List<TranscriptEntry> entries,
            Map<String,byte[]> bodies,byte[] target,PlanCredentials bKey,int wait,String id)throws Exception{
        Files.write(root.resolve(run+".supersession/manifest.json"),JSON.mapper().writeValueAsBytes(manifest));
        TranscriptRecorder recorder=new TranscriptRecorder(){public List<TranscriptEntry> list(String r){if(!run.equals(r))throw new IllegalArgumentException("Wrong Run");return entries;}
            public TranscriptEntry record(TranscriptInput i){throw new UnsupportedOperationException();}public TranscriptEntry updateSamlAnalysis(String i,String c,Map<String,Object>s){throw new UnsupportedOperationException();}};
        var context=new DefaultCaseContext(run,TargetRole.IDP,Clock.systemUTC(),new TestPlan.Parameters(180,wait,"",TestPlan.RequestSigningMode.REQUIRED),TestPlan.Interaction.defaults(),Reachability.CONFIRMED,recorder,true);
        return new ShibbolethMetadataSupersessionEvidenceFile(e->bodies.get(e.id()),root,r->target,
            (r,v)->"no-valid-until".equals(v)?Optional.of(bKey):Optional.empty()).evaluate(id,context);
    }
    private static PlanCredentials memoryCredentials()throws Exception{
        Security.addProvider(new BouncyCastleProvider());var generator=KeyPairGenerator.getInstance("RSA");generator.initialize(2048);var pair=generator.generateKeyPair();
        var subject=new X500Name("CN=Memory-only supersession counterexample");var now=Instant.now();
        var cert=new JcaX509v3CertificateBuilder(subject,java.math.BigInteger.ONE,Date.from(now.minusSeconds(86400)),Date.from(now.plusSeconds(86400)),subject,pair.getPublic())
            .build(new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC").build(pair.getPrivate()));
        return new PlanCredentials(pair.getPrivate(),new JcaX509CertificateConverter().setProvider("BC").getCertificate(cert));
    }
    private static void signatures(Element e){var children=new ArrayList<Element>();for(var n=e.getFirstChild();n!=null;n=n.getNextSibling())if(n instanceof Element child&&DS.equals(child.getNamespaceURI())&&"Signature".equals(child.getLocalName()))children.add(child);for(var child:children)e.removeChild(child);}
    private static byte[] resign(byte[] raw,PlanCredentials decrypt,PlanCredentials signer,String request,String destination,String mutation)throws Exception{
        var document=SecureXml.parse(raw);var response=document.getDocumentElement();var encrypted=response.getElementsByTagNameNS(A,"EncryptedAssertion");
        if(encrypted.getLength()==1){Element wrapper=(Element)encrypted.item(0);var plain=new SamlXmlDecrypter().decrypt(wrapper,decrypt.privateKey());wrapper.getParentNode().replaceChild(document.importNode(plain,true),wrapper);}
        Element assertion=(Element)response.getElementsByTagNameNS(A,"Assertion").item(0);signatures(response);signatures(assertion);
        if(request!=null){response.setAttribute("ID","_semantic_supersession_response");assertion.setAttribute("ID","_semantic_supersession_assertion");response.setAttribute("InResponseTo",request);response.setAttribute("Destination",destination);
            Element data=(Element)assertion.getElementsByTagNameNS(A,"SubjectConfirmationData").item(0);data.setAttribute("InResponseTo",request);data.setAttribute("Recipient",destination);}
        if("wrong-audience".equals(mutation))assertion.getElementsByTagNameNS(A,"Audience").item(0).setTextContent("https://other.example/sp");
        if("missing-authn-profile".equals(mutation)){var n=assertion.getElementsByTagNameNS(A,"AuthnStatement").item(0);n.getParentNode().removeChild(n);}
        if("wrong-response-correlation".equals(mutation))response.setAttribute("InResponseTo","_other_request");
        if("wrong-response-destination".equals(mutation))response.setAttribute("Destination","https://other.example/acs");
        if(!"unsigned-response".equals(mutation))new XmlSigner().sign(assertion,signer,(Element)assertion.getElementsByTagNameNS(A,"Subject").item(0));
        return SecureXml.serialize(document);
    }
    private static TranscriptEntry body(TranscriptEntry e,byte[] raw){return new TranscriptEntry(e.id(),e.runId(),e.direction(),e.timestamp(),e.correlationId(),e.method(),e.url(),e.status(),e.headers(),e.bodyRef(),e.bodyBytes(),e.decodedSamlRef(),raw.length,e.contentType(),e.rawQuery(),e.samlSummary());}
    private static void reset(Path base,Path extra,Map<String,byte[]> files)throws Exception{for(var e:files.entrySet()){Files.write(base.resolve(e.getKey()),e.getValue());Files.write(extra.resolve(e.getKey()),e.getValue());}Files.write(base.resolve("manifest.json"),files.get("metadata-refresh-manifest.json"));Files.write(extra.resolve("native-audit.log"),files.get("native-signature-audit.log"));}
    public static void main(String[] args)throws Exception{
        if(args.length!=2)throw new IllegalArgumentException("campaign-folder report required");
        Path source=Path.of(args[0]),output=Path.of(args[1]);if(Files.exists(output))throw new IllegalArgumentException("Do not overwrite retained report");
        var baseManifest=(ObjectNode)JSON.mapper().readTree(source.resolve("metadata-refresh-manifest.json").toFile());
        var manifest=(ObjectNode)JSON.mapper().readTree(source.resolve("metadata-supersession-manifest.json").toFile());String run=manifest.path("runId").asText();
        var entries=new ArrayList<>(List.of(JSON.mapper().readValue(source.resolve("transcript.json").toFile(),TranscriptEntry[].class)));var bodies=new HashMap<String,byte[]>();
        for(var row:JSON.mapper().readTree(source.resolve("decoded-manifest.json").toFile())){
            Path path=source.resolve(row.path("file").asText()).normalize();if(!path.getParent().equals(source.resolve("decoded")))throw new IllegalArgumentException("Unsafe original");
            byte[] raw=Files.readAllBytes(path);if(!hash(raw).equals(row.path("sha256").asText()))throw new IllegalArgumentException("Original hash changed");bodies.put(row.path("id").asText(),raw);
        }
        byte[] target=Files.readAllBytes(source.resolve("target-metadata.xml"));
        String plan=baseManifest.path("entityId").asText().substring(baseManifest.path("entityId").asText().lastIndexOf('/')+1);
        if(!plan.matches("plan_[0-9A-HJKMNP-TV-Z]{26}"))throw new IllegalArgumentException("Unsafe key source");
        String alias="poll-"+hash("no-valid-until".getBytes(StandardCharsets.UTF_8)).substring(0,16);Path keyDirectory=Path.of("/data/keys").resolve(plan).resolve(alias);
        var bKey=new PlanCredentials(KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(Files.readAllBytes(keyDirectory.resolve("signing-key.pk8")))),
            (X509Certificate)CertificateFactory.getInstance("X.509").generateCertificate(Files.newInputStream(keyDirectory.resolve("signing-certificate.der"))));
        var files=new HashMap<String,byte[]>();try(var paths=Files.list(source)){for(var file:paths.filter(Files::isRegularFile).toList())if(!file.getFileName().toString().endsWith(".jar"))files.put(file.getFileName().toString(),Files.readAllBytes(file));}
        Path root=Files.createTempDirectory("shib-supersession-reader-");Path base=root.resolve(run+".refresh"),extra=root.resolve(run+".supersession");Files.createDirectories(base);Files.createDirectories(extra);
        int wait=baseManifest.path("refreshWaitSeconds").asInt();var checks=new LinkedHashMap<String,String>();
        try{
            reset(base,extra,files);
            var nativeAb=evaluate(root,run,manifest.deepCopy(),entries,bodies,target,bKey,wait,MetadataSupersessionProbeTestCase.SUPERSESSION);
            var nativeA=evaluate(root,run,manifest.deepCopy(),entries,bodies,target,bKey,wait,MetadataSupersessionProbeTestCase.APPLICATION);
            if(nativeAb.outcome()==Outcome.SATISFIED||nativeA.outcome()!=Outcome.NOT_VERIFIED)throw new IllegalStateException("Partial coverage incorrectly adopted");
            var fixture=memoryCredentials();var targetDocument=SecureXml.parse(target);var certs=targetDocument.getElementsByTagNameNS(DS,"X509Certificate");for(int i=0;i<certs.getLength();i++)certs.item(i).setTextContent(Base64.getEncoder().encodeToString(fixture.certificate().getEncoded()));byte[] semanticTarget=SecureXml.serialize(targetDocument);
            var semanticManifest=manifest.deepCopy().put("targetMetadataSha256",hash(semanticTarget));
            var semanticBodies=new HashMap<>(bodies);String positiveId=baseManifest.path("phaseB").path("responseReference").asText();
            byte[] positive=resign(bodies.get(positiveId),bKey,fixture,null,null,"baseline");semanticBodies.put(positiveId,positive);
            var semanticEntries=new ArrayList<>(entries);for(int i=0;i<semanticEntries.size();i++)if(semanticEntries.get(i).id().equals(positiveId))semanticEntries.set(i,body(semanticEntries.get(i),positive));
            JsonNodeHolder oldProbe=new JsonNodeHolder(semanticManifest.path("probes"));String requestReference=oldProbe.find("new-key-old-acs").path("requestReference").asText();
            var request=entries.stream().filter(e->e.id().equals(requestReference)).findFirst().orElseThrow();Element requestXml=SecureXml.parse(bodies.get(requestReference)).getDocumentElement();String requestId=requestXml.getAttribute("ID"),acs=requestXml.getAttribute("AssertionConsumerServiceURL");
            Instant at=request.timestamp().plusNanos(1);String fakeId="tx_00000000000000000000000000";
            byte[] counterexample=resign(bodies.get(positiveId),bKey,fixture,requestId,acs,"baseline");semanticBodies.put(fakeId,counterexample);
            semanticEntries.removeIf(e->e.direction()==Direction.INBOUND&&requestId.equals(e.samlSummary().get("inResponseTo")));
            var response=new TranscriptEntry(fakeId,run,Direction.INBOUND,at,request.correlationId(),"POST",acs,200,Map.of(),null,0,"memory-only",counterexample.length,"application/xml",null,Map.of("type","Response","inResponseTo",requestId,"statusCode","urn:oasis:names:tc:SAML:2.0:status:Success"));semanticEntries.add(response);
            String entity=baseManifest.path("entityId").asText();String audit=new String(files.get("native-signature-audit.log"),StandardCharsets.UTF_8).lines().filter(line->!line.startsWith("SAMLscope-signature-v1|"+requestId+"|")).collect(java.util.stream.Collectors.joining("\n"))+"\nSAMLscope-signature-v1|"+requestId+"|"+entity+"||Success|true|POST|http://shibboleth.net/ns/profiles/saml2/sso/browser|"+at+"\n";
            Files.writeString(extra.resolve("native-audit.log"),audit);semanticManifest.put("nativeAuditSha256",hash(audit.getBytes(StandardCharsets.UTF_8)));
            var valid=evaluate(root,run,semanticManifest.deepCopy(),semanticEntries,semanticBodies,semanticTarget,bKey,wait,MetadataSupersessionProbeTestCase.SUPERSESSION);
            if(valid.outcome()!=Outcome.VIOLATED)throw new IllegalStateException("Memory-only genuine old-ACS counterexample was not detected: "+valid.details());
            for(String mutation:List.of("wrong-run","wrong-target","missing-readback","late-before-readback","wrong-restoration","wrong-native-audit-request","native-rejection-contradiction","wrong-response-correlation","wrong-response-destination","unsigned-response","wrong-audience","missing-authn-profile","later-metadata-a","unpaired-later-native-fetch","foreign-run-request")){
                reset(base,extra,files);var changed=semanticManifest.deepCopy();var changedBodies=new HashMap<>(semanticBodies);var changedEntries=new ArrayList<>(semanticEntries);String changedAudit=audit;
                switch(mutation){
                    case "wrong-run"->changed.put("runId","run_00000000000000000000000000");
                    case "wrong-target"->changed.put("targetMetadataSha256","0".repeat(64));
                    case "missing-readback"->((com.fasterxml.jackson.databind.node.ArrayNode)changed.path("configurationReadBacks")).remove(0);
                    case "late-before-readback"->((ObjectNode)changed.path("configurationReadBacks").get(0)).put("recordedAt",at.plusSeconds(10).toString());
                    case "wrong-restoration"->Files.writeString(base.resolve("final-providers.xml"),"<wrong/>");
                    case "wrong-native-audit-request"->changedAudit=audit.replace(requestId,"_other_request");
                    case "native-rejection-contradiction"->changedAudit=audit+"SAMLscope-signature-v1|"+requestId+"|"+entity+"|EndpointResolutionFailed||true|POST|http://shibboleth.net/ns/profiles/saml2/sso/browser|"+at+"\n";
                    case "wrong-response-correlation","wrong-response-destination","unsigned-response","wrong-audience","missing-authn-profile"->changedBodies.put(fakeId,resign(bodies.get(positiveId),bKey,fixture,requestId,acs,mutation));
                    case "later-metadata-a","unpaired-later-native-fetch"->{
                        String fetchId="tx_10000000000000000000000000",preparedId="tx_20000000000000000000000000";Instant fetchedAt=request.timestamp().minusNanos(1);
                        changedEntries.add(new TranscriptEntry(fetchId,run,Direction.INBOUND,fetchedAt,null,"GET",baseManifest.path("metadataUrl").asText(),null,Map.of(),null,0,null,0,null,null,Map.of("type","MetadataFetch","variant","control","feed","live")));
                        if("later-metadata-a".equals(mutation)){byte[] raw=files.get("metadata-a.xml");changedBodies.put(preparedId,raw);changedEntries.add(new TranscriptEntry(preparedId,run,Direction.OUTBOUND,fetchedAt,null,"GET",baseManifest.path("metadataUrl").asText(),200,Map.of(),null,0,"memory-only",raw.length,"application/xml",null,Map.of("type","MetadataPrepared","variant","control","feed","live","fetchTranscriptId",fetchId)));}
                    }
                    case "foreign-run-request"->{for(int i=0;i<changedEntries.size();i++){var e=changedEntries.get(i);if(e.id().equals(requestReference))changedEntries.set(i,new TranscriptEntry(e.id(),"run_00000000000000000000000000",e.direction(),e.timestamp(),e.correlationId(),e.method(),e.url(),e.status(),e.headers(),e.bodyRef(),e.bodyBytes(),e.decodedSamlRef(),e.decodedSamlBytes(),e.contentType(),e.rawQuery(),e.samlSummary()));}}
                }
                Files.writeString(extra.resolve("native-audit.log"),changedAudit);changed.put("nativeAuditSha256",hash(changedAudit.getBytes(StandardCharsets.UTF_8)));
                var result=evaluate(root,run,changed,changedEntries,changedBodies,semanticTarget,bKey,wait,MetadataSupersessionProbeTestCase.SUPERSESSION);
                if(result.outcome()!=Outcome.NOT_VERIFIED)throw new IllegalStateException("Tamper control accepted: "+mutation+" / "+result.outcome());checks.put(mutation,result.outcome().name());
            }
            JSON.mapper().writeValue(output.toFile(),Map.of("runId",run,"nativeApplication",nativeA.outcome().name(),"nativeSupersession",nativeAb.outcome().name(),"nativeEvidenceIssue",nativeAb.details().getOrDefault("evidence_issue","none"),"memoryOnlyCounterexample",valid.outcome().name(),"controls",checks));
        }finally{try(var paths=Files.walk(root)){for(var path:paths.sorted(Comparator.reverseOrder()).toList())Files.delete(path);}}
    }
    private record JsonNodeHolder(com.fasterxml.jackson.databind.JsonNode rows){com.fasterxml.jackson.databind.JsonNode find(String fixture){for(var row:rows)if(fixture.equals(row.path("fixture").asText()))return row;throw new IllegalArgumentException("Fixture missing");}}
}
