package com.samlscope.runner.cases;

import com.samlscope.core.plan.TestPlan;
import com.samlscope.core.transcript.*;
import com.samlscope.saml.crypto.XmlSigner;
import com.samlscope.saml.metadata.MetadataService;
import com.samlscope.store.*;
import java.net.URI;
import java.nio.file.*;
import java.sql.DriverManager;
import java.time.*;
import java.security.MessageDigest;
import java.util.*;

/** Records the actual public factory return. This never claims an HTTP metadata fetch or native import. */
public final class PrepareSimpleSamlPhpDefaultAlgorithmConsumerMetadata {
    public static void main(String[] args)throws Exception {
        if(args.length!=3||!args[1].matches("run_[0-9A-HJKMNP-TV-Z]{26}"))throw new IllegalArgumentException("Data, Run, public source path required");
        var data=Path.of(args[0]).toRealPath();String run=args[1];var source=Path.of(args[2]).toRealPath();var json=new JsonCodec();TestPlan plan;
        try(var db=DriverManager.getConnection("jdbc:sqlite:file:"+data.resolve("samlscope.db")+"?mode=ro");var q=db.prepareStatement("SELECT p.document_json FROM runs r JOIN plans p ON r.plan_id=p.id WHERE r.id=?")) {
            q.setString(1,run);try(var rows=q.executeQuery()){if(!rows.next())throw new IllegalArgumentException("Missing actual Run");plan=json.read(rows.getString(1),TestPlan.class);if(rows.next())throw new IllegalArgumentException("Ambiguous Run");}
        }
        if(!"browser_sso_idp".equals(plan.profile().id())||!"http://localhost:18380/idp".equals(plan.target().entityId()))throw new IllegalArgumentException("Wrong native role/profile/target");
        var bridge=new KeycloakNativeRunEvidenceBridge(data);var control=bridge.key(run,"control").orElseThrow();
        Instant at=Instant.now();var factory=new MetadataService(URI.create("http://localhost:18080"),null,new XmlSigner(),Clock.fixed(at,ZoneOffset.UTC));
        byte[] xml=factory.generateDefaultAlgorithmConsumerMetadata(plan,run,control);var summary=new LinkedHashMap<String,Object>();
        summary.put("type","MetadataPrepared");summary.put("variant","control");summary.put("feed","native-default-consumer");
        summary.put("factoryMethod","MetadataService.generateDefaultAlgorithmConsumerMetadata");summary.put("factoryPreparedAt",at.toString());
        summary.put("factorySourceSha256",sha(Files.readAllBytes(source)));summary.put("metadataSha256",sha(xml));
        var jar=Path.of(MetadataService.class.getProtectionDomain().getCodeSource().getLocation().toURI());if(!Files.isRegularFile(jar))throw new IllegalArgumentException("Actual factory archive required");
        summary.put("factoryJarSha256",sha(Files.readAllBytes(jar)));try(var classes=MetadataService.class.getResourceAsStream("/com/samlscope/saml/metadata/MetadataService.class")){if(classes==null)throw new IllegalStateException("Factory class missing");summary.put("factoryClassSha256",sha(classes.readAllBytes()));}
        var recorder=new FileTranscriptRecorder(new SqliteDatabase(data),json,data);
        var entry=recorder.record(new TranscriptInput(run,Direction.OUTBOUND,at,null,"FACTORY","urn:samlscope:native-default-consumer-metadata",null,
            Map.of("Content-Type",List.of("application/samlmetadata+xml")),xml,"application/samlmetadata+xml",null,xml,summary));
        if(!Arrays.equals(xml,recorder.readDecodedSaml(entry)))throw new IllegalStateException("Factory Recorder readback mismatch");
        System.out.println(json.write(Map.of("schema","samlscope-ssp-recorded-default-consumer-factory-v1","runId",run,"planId",plan.id(),"entry",entry,"metadata",Base64.getEncoder().encodeToString(xml),"metadataSha256",sha(xml),"factoryCodeSource",jar.toString(),"actualHttpFetchClaimed",false,"privateBytesExported",false)));
    }
    private static String sha(byte[] bytes)throws Exception{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));}
}
