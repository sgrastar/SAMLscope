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

/** Production-reader replay inside Suite; private keys and decrypted assertions stay in memory. */
public final class VerifyShibbolethAuthenticationIdentityEvidence {
    private static final JsonCodec JSON=new JsonCodec();
    private static final String P="urn:oasis:names:tc:SAML:2.0:protocol",S="urn:oasis:names:tc:SAML:2.0:assertion",DS="http://www.w3.org/2000/09/xmldsig#";
    private static String hash(byte[] raw)throws Exception{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(raw));}
    private static CaseOutcome evaluate(Path root,ObjectNode manifest,List<TranscriptEntry> entries,Map<String,byte[]> bodies,
            byte[] target,PrivateKey key,String user)throws Exception {
        String run=manifest.path("runId").asText();Files.write(root.resolve(run).resolve("manifest.json"),JSON.mapper().writeValueAsBytes(manifest));
        TranscriptRecorder recorder=new TranscriptRecorder(){
            @Override public List<TranscriptEntry> list(String r){return entries;}
            @Override public TranscriptEntry record(TranscriptInput i){throw new UnsupportedOperationException();}
            @Override public TranscriptEntry updateSamlAnalysis(String i,String c,Map<String,Object>s){throw new UnsupportedOperationException();}
        };
        var context=new DefaultCaseContext(run,TargetRole.IDP,Clock.systemUTC(),new TestPlan.Parameters(180,300,user,TestPlan.RequestSigningMode.REQUIRED),
            TestPlan.Interaction.defaults(),Reachability.CONFIRMED,recorder,true);
        return new ShibbolethAuthenticationIdentityEvidenceFile(root,e->bodies.get(e.id()),r->target,r->Optional.of(key)).evaluate(context);
    }
    private static PlanCredentials fixture()throws Exception {
        Security.addProvider(new BouncyCastleProvider());var generator=KeyPairGenerator.getInstance("RSA");generator.initialize(2048);
        var pair=generator.generateKeyPair();var name=new X500Name("CN=Memory-only identity detection control");var now=Instant.now();
        var holder=new JcaX509v3CertificateBuilder(name,java.math.BigInteger.ONE,Date.from(now.minusSeconds(86400)),Date.from(now.plusSeconds(86400)),name,pair.getPublic())
            .build(new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC").build(pair.getPrivate()));
        return new PlanCredentials(pair.getPrivate(),new JcaX509CertificateConverter().setProvider("BC").getCertificate(holder));
    }
    private static List<TranscriptEntry> sized(List<TranscriptEntry> entries,Map<String,byte[]> bodies) {
        return entries.stream().map(old->{var body=bodies.get(old.id());return body==null?old:new TranscriptEntry(old.id(),old.runId(),old.direction(),old.timestamp(),old.correlationId(),
            old.method(),old.url(),old.status(),old.headers(),old.bodyRef(),old.bodyBytes(),old.decodedSamlRef(),body.length,old.contentType(),old.rawQuery(),old.samlSummary());}).toList();
    }
    private static Map<String,byte[]> semantic(ObjectNode manifest,Map<String,byte[]> source,PrivateKey key,PlanCredentials fixture,String mutation)throws Exception {
        var bodies=new HashMap<>(source);
        for(String kind:List.of("positive","unable")) {
            String reference=manifest.path(kind).path("responseReference").asText();var document=SecureXml.parse(source.get(reference));var response=document.getDocumentElement();
            var encrypted=MetadataAlgorithmEvidence.children(response,S,"EncryptedAssertion");
            if(!encrypted.isEmpty()) {
                var assertion=new SamlXmlDecrypter().decrypt(encrypted.getFirst(),key);response.replaceChild(document.importNode(assertion,true),encrypted.getFirst());
            }
            for(var signature:MetadataAlgorithmEvidence.children(response,DS,"Signature"))response.removeChild(signature);
            var assertions=MetadataAlgorithmEvidence.children(response,S,"Assertion");
            for(var assertion:assertions)for(var signature:MetadataAlgorithmEvidence.children(assertion,DS,"Signature"))assertion.removeChild(signature);
            if(kind.equals("positive")&&mutation.equals("positive-error")) {
                for(var assertion:assertions)response.removeChild(assertion);
                var code=(Element)response.getElementsByTagNameNS(P,"StatusCode").item(0);code.setAttribute("Value","urn:oasis:names:tc:SAML:2.0:status:Requester");
            }
            if(kind.equals("positive")&&mutation.equals("non-password-method"))((Element)response.getElementsByTagNameNS(S,"AuthnContextClassRef").item(0))
                .setTextContent("urn:oasis:names:tc:SAML:2.0:ac:classes:X509");
            if(kind.equals("unable")&&mutation.equals("always-success")) {
                var code=(Element)response.getElementsByTagNameNS(P,"StatusCode").item(0);code.setAttribute("Value","urn:oasis:names:tc:SAML:2.0:status:Success");
                for(var sub:MetadataAlgorithmEvidence.children(code,P,"StatusCode"))code.removeChild(sub);
            }
            if(kind.equals("unable")&&mutation.equals("error-with-assertion")) {
                var doc=SecureXml.parse(bodies.get(manifest.path("positive").path("responseReference").asText()));
                var assertion=MetadataAlgorithmEvidence.children(doc.getDocumentElement(),S,"Assertion").getFirst();response.appendChild(document.importNode(assertion,true));
            }
            if(kind.equals("unable")&&mutation.equals("wrong-correlation"))response.setAttribute("InResponseTo","_unrelated-request");
            if(kind.equals("unable")&&mutation.equals("wrong-destination"))response.setAttribute("Destination","https://wrong-sp.example/acs");
            if(kind.equals("positive")&&mutation.equals("wrong-audience"))((Element)response.getElementsByTagNameNS(S,"Audience").item(0)).setTextContent("https://wrong-sp.example");
            if(!mutation.equals("unsigned-response")||!kind.equals("unable"))new XmlSigner().sign(response,fixture,MetadataAlgorithmEvidence.children(response,P,"Status").getFirst());
            bodies.put(reference,SecureXml.serialize(document));
        }
        return bodies;
    }
    private static byte[] target(byte[] source,PlanCredentials fixture)throws Exception {
        var doc=SecureXml.parse(source);var certs=doc.getElementsByTagNameNS(DS,"X509Certificate");
        for(int i=0;i<certs.getLength();i++)certs.item(i).setTextContent(Base64.getEncoder().encodeToString(fixture.certificate().getEncoded()));return SecureXml.serialize(doc);
    }
    private static void replace(Path folder,ObjectNode row,String file,String digest,byte[] bytes)throws Exception {
        Files.write(folder.resolve(row.path(file).asText()),bytes);row.put(digest,hash(bytes));
    }
    private static void configured(Path folder,ObjectNode row,byte[] bytes)throws Exception {
        replace(folder,row,"configuredFile","configuredSha256",bytes);
        for(var back:row.path("readBacks"))replace(folder,(ObjectNode)back,"file","sha256",bytes);
    }
    public static void main(String[] args)throws Exception {
        var source=Path.of(args[0]);var base=(ObjectNode)JSON.mapper().readTree(Files.readAllBytes(source.resolve("manifest.json")));
        String run=base.path("runId").asText();if(!run.matches("run_[0-9A-HJKMNP-TV-Z]{26}"))throw new IllegalArgumentException("Unsafe Run");
        var entries=JSON.mapper().readValue(Files.readAllBytes(source.resolve("transcript.json")),JSON.mapper().getTypeFactory().constructCollectionType(List.class,TranscriptEntry.class));
        @SuppressWarnings("unchecked") var transcript=(List<TranscriptEntry>)entries;
        var bodies=new HashMap<String,byte[]>();for(var entry:transcript)if(entry.decodedSamlRef()!=null) {
            byte[] raw=Files.readAllBytes(source.resolve("decoded").resolve(entry.id()+".xml"));if(raw.length!=entry.decodedSamlBytes())throw new IllegalArgumentException("Original size changed");bodies.put(entry.id(),raw);
        }
        var originalTarget=Files.readAllBytes(source.resolve("target-metadata.xml"));
        var plan=JSON.mapper().readTree(Files.readAllBytes(source.resolve("plan.json"))).path("plan").path("plan");
        String id=plan.path("id").asText(),user;
        var parameters=source.resolve("context-parameters.json");
        if(!Files.isRegularFile(parameters)) {
            try(var connection=java.sql.DriverManager.getConnection("jdbc:sqlite:file:/data/samlscope.db?mode=ro");
                    var statement=connection.prepareStatement("SELECT document_json FROM plans WHERE id=?")) {
                statement.setString(1,id);
                try(var rows=statement.executeQuery()) {
                    if(!rows.next())throw new IllegalArgumentException("Native Plan original unavailable");
                    var nativePlan=JSON.read(rows.getString(1),TestPlan.class);
                    Files.write(parameters,JSON.mapper().writeValueAsBytes(nativePlan.parameters()));
                }
            }
        }
        user=JSON.mapper().readTree(Files.readAllBytes(parameters)).path("testUserHint").asText();
        if(!id.matches("plan_[0-9A-HJKMNP-TV-Z]{26}")||user.isBlank())throw new IllegalArgumentException("Unsafe Plan input");
        var key=KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(Files.readAllBytes(Path.of("/data/keys").resolve(id).resolve("signing-key.pk8"))));
        var files=new HashMap<String,byte[]>();try(var paths=Files.list(source)){for(var p:paths.filter(Files::isRegularFile).toList())files.put(p.getFileName().toString(),Files.readAllBytes(p));}
        var root=Files.createTempDirectory("samlscope-identity-reader-replay-");var folder=root.resolve(run);Files.createDirectory(folder);
        var controls=new LinkedHashMap<String,String>();
        try {
            for(var item:files.entrySet())Files.write(folder.resolve(item.getKey()),item.getValue());
            var actual=evaluate(root,base.deepCopy(),transcript,bodies,originalTarget,key,user);
            if(actual.outcome()!=Outcome.SATISFIED)throw new IllegalStateException("Actual native identity originals not accepted: "+actual.details());
            var fixture=fixture();byte[] semanticTarget=target(originalTarget,fixture);var valid=base.deepCopy();valid.put("targetMetadataSha256",hash(semanticTarget));
            var validBodies=semantic(valid,bodies,key,fixture,"baseline");
            if(evaluate(root,valid.deepCopy(),sized(transcript,validBodies),validBodies,semanticTarget,key,user).outcome()!=Outcome.SATISFIED)
                throw new IllegalStateException("Signed memory-only control baseline rejected");
            for(String mutation:List.of("always-success","positive-error","non-password-method","error-with-assertion","wrong-correlation","wrong-destination","wrong-audience","unsigned-response",
                    "ambient-flow-enabled","session-enabled","session-reuse-enabled","native-sso-reuse","wrong-principal","forged-native-request","wrong-restoration","missing-readback","late-before-readback",
                    "missing-native-source","wrong-target","missing-error-original","foreign-run-transcript","declaration-only",
                    "missing-native-challenge","wrong-challenge-request","wrong-challenge-source","credential-before-challenge","challenge-password-input-missing","challenge-after-success",
                    "altered-custom-condition-flow","custom-global-authentication-override")) {
                for(var item:files.entrySet())Files.write(folder.resolve(item.getKey()),item.getValue());
                var manifest=base.deepCopy();var changedBodies=new HashMap<>(bodies);var changedEntries=transcript;byte[] changedTarget=originalTarget;
                if(List.of("always-success","positive-error","non-password-method","error-with-assertion","wrong-correlation","wrong-destination","wrong-audience","unsigned-response").contains(mutation)) {
                    changedTarget=semanticTarget;manifest.put("targetMetadataSha256",hash(semanticTarget));changedBodies=new HashMap<>(semantic(manifest,bodies,key,fixture,mutation));changedEntries=sized(transcript,changedBodies);
                }else switch(mutation) {
                    case "ambient-flow-enabled","session-enabled","session-reuse-enabled","wrong-restoration","missing-readback","late-before-readback" -> {
                        ObjectNode row=null;for(var value:manifest.path("configurationFiles"))if("authn-properties".equals(value.path("kind").asText()))row=(ObjectNode)value;
                        if(row==null)throw new IllegalStateException();
                        String text=new String(files.get(row.path("configuredFile").asText()),StandardCharsets.UTF_8);
                        switch(mutation) {
                            case "ambient-flow-enabled" -> configured(folder,row,text.replace("idp.authn.flows = Password","idp.authn.flows = Password|IPAddress").getBytes(StandardCharsets.UTF_8));
                            case "session-enabled" -> configured(folder,row,text.replace("idp.session.enabled = false","idp.session.enabled = true").getBytes(StandardCharsets.UTF_8));
                            case "session-reuse-enabled" -> configured(folder,row,text.replace("idp.authn.Password.reuseCondition = shibboleth.Conditions.FALSE","idp.authn.Password.reuseCondition = shibboleth.Conditions.TRUE").getBytes(StandardCharsets.UTF_8));
                            case "wrong-restoration" -> replace(folder,row,"finalFile","finalSha256","changed-state".getBytes(StandardCharsets.UTF_8));
                            case "missing-readback" -> ((ArrayNode)row.path("readBacks")).remove(0);
                            case "late-before-readback" -> ((ObjectNode)row.path("readBacks").get(0)).put("recordedAt","2099-01-01T00:00:00Z");
                        }
                    }
                    case "native-sso-reuse","wrong-principal","forged-native-request" -> {
                        String text=new String(files.get(manifest.path("auditFile").asText()),StandardCharsets.UTF_8);
                        text=mutation.equals("native-sso-reuse")?text.replace("|authn/Password|false|","|authn/Password|true|"):
                            mutation.equals("wrong-principal")?text.replace("|"+user+"|","|different-user|"):text.replace("_saml_","_forged_saml_");
                        replace(folder,manifest,"auditFile","auditSha256",text.getBytes(StandardCharsets.UTF_8));
                    }
                    case "missing-native-source" -> Files.delete(folder.resolve(manifest.path("flowSelectionFile").asText()));
                    case "missing-native-challenge","wrong-challenge-request","wrong-challenge-source","credential-before-challenge","challenge-password-input-missing","challenge-after-success" -> {
                        var observation=(ObjectNode)JSON.mapper().readTree(files.get(manifest.path("challengeFile").asText()));
                        switch(mutation) {
                            case "missing-native-challenge" -> Files.delete(folder.resolve(observation.path("response").path("bodyFile").asText()));
                            case "wrong-challenge-request" -> ((ObjectNode)observation.path("request")).put("requestId","_unrelated-request");
                            case "wrong-challenge-source" -> ((ObjectNode)observation.path("request")).put("targetUrl","https://wrong-idp.example/login");
                            case "credential-before-challenge" -> ((ObjectNode)observation.path("credentialSubmissions").get(0)).put("observedAt","1970-01-01T00:00:00Z");
                            case "challenge-after-success" -> ((ObjectNode)observation.path("response")).put("recordedAt","2099-01-01T00:00:00Z");
                            case "challenge-password-input-missing" -> {
                                var row=(ObjectNode)observation.path("response");String text=new String(files.get(row.path("bodyFile").asText()),StandardCharsets.UTF_8);
                                replace(folder,row,"bodyFile","bodySha256",text.replace("j_password","other-input").getBytes(StandardCharsets.UTF_8));
                            }
                        }
                        replace(folder,manifest,"challengeFile","challengeSha256",JSON.mapper().writeValueAsBytes(observation));
                    }
                    case "altered-custom-condition-flow","custom-global-authentication-override" -> {
                        String kind=mutation.equals("altered-custom-condition-flow")?"condition-base":"global";ObjectNode row=null;
                        for(var value:manifest.path("configurationFiles"))if(kind.equals(value.path("kind").asText()))row=(ObjectNode)value;
                        if(row==null)throw new IllegalStateException();
                        String text=new String(files.get(row.path("configuredFile").asText()),StandardCharsets.UTF_8);
                        String changed=mutation.equals("altered-custom-condition-flow")?text.replace("</flow>","<end-state id=\"EstablishAmbientIdentity\"/></flow>"):
                            text.replace("</beans>","<bean id=\"PotentialFlowsLookup\" class=\"java.lang.Object\"/></beans>");
                        if(changed.equals(text))throw new IllegalStateException("Mutation did not alter original: "+mutation);
                        configured(folder,row,changed.getBytes(StandardCharsets.UTF_8));
                    }
                    case "wrong-target" -> manifest.put("targetMetadataSha256","0".repeat(64));
                    case "missing-error-original" -> changedBodies.remove(manifest.path("unable").path("responseReference").asText());
                    case "foreign-run-transcript" -> {
                        var values=new ArrayList<>(transcript);var old=values.getFirst();values.set(0,new TranscriptEntry(old.id(),"run_00000000000000000000000000",old.direction(),old.timestamp(),old.correlationId(),old.method(),old.url(),old.status(),old.headers(),old.bodyRef(),old.bodyBytes(),old.decodedSamlRef(),old.decodedSamlBytes(),old.contentType(),old.rawQuery(),old.samlSummary()));changedEntries=values;
                    }
                    case "declaration-only" -> {manifest.remove("configurationFiles");manifest.put("ambientAuthenticationDisabled",true);manifest.put("restored",true);}
                }
                var result=evaluate(root,manifest,changedEntries,changedBodies,changedTarget,key,user);
                if(result.outcome()!=Outcome.NOT_VERIFIED)throw new IllegalStateException("Invalid control adopted: "+mutation);
                controls.put(mutation,result.outcome().name());
            }
            var report=new LinkedHashMap<String,Object>();report.put("schema","samlscope-shibboleth-authentication-identity-production-replay-v1");report.put("runId",run);
            report.put("nativeOriginals",actual.outcome().name());report.put("memoryOnlySignedBaseline",Outcome.SATISFIED.name());report.put("controls",controls);
            Files.write(Path.of(args[1]),JSON.mapper().writerWithDefaultPrettyPrinter().writeValueAsBytes(report));
        }finally{try(var paths=Files.walk(root)){for(var p:paths.sorted(Comparator.reverseOrder()).toList())Files.delete(p);}}
    }
}
