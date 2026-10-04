package com.samlscope.runner.cases;

import com.samlscope.core.plan.TestPlan;
import com.samlscope.saml.crypto.FilePlanKeyStore;
import com.samlscope.saml.crypto.XmlSigner;
import com.samlscope.saml.metadata.MetadataService;
import com.samlscope.saml.normal.SamlDefaultAlgorithmFixtures;
import com.samlscope.saml.normal.SecureXml;
import com.samlscope.store.JsonCodec;
import java.net.URI;
import java.nio.file.*;
import java.sql.DriverManager;
import java.security.MessageDigest;
import java.nio.charset.StandardCharsets;
import java.time.*;
import java.util.*;

/** Public diagnostic inputs only. Existing Suite private keys never leave their store. */
public final class ExportSimpleSamlPhpDefaultAlgorithmConsumerFixtures {
    public static void main(String[] args) throws Exception {
        if (args.length != 2 || !args[1].matches("run_[0-9A-HJKMNP-TV-Z]{26}"))
            throw new IllegalArgumentException("Data root and existing Run required");
        var data=Path.of(args[0]).toRealPath();String run=args[1];var json=new JsonCodec();TestPlan plan;
        try(var db=DriverManager.getConnection("jdbc:sqlite:file:"+data.resolve("samlscope.db")+"?mode=ro");
                var q=db.prepareStatement("SELECT p.document_json FROM runs r JOIN plans p ON r.plan_id=p.id WHERE r.id=?")) {
            q.setString(1,run);try(var rows=q.executeQuery()) {
                if(!rows.next())throw new IllegalArgumentException("Run missing");plan=json.read(rows.getString(1),TestPlan.class);
                if(rows.next())throw new IllegalArgumentException("Ambiguous Run");
            }
        }
        var controlDigest=MessageDigest.getInstance("SHA-256")
                .digest(MetadataService.Variant.CONTROL.id().getBytes(StandardCharsets.UTF_8));
        var controlAlias="poll-"+HexFormat.of().formatHex(controlDigest,0,8);
        for(String alias:List.of("primary",controlAlias)) {
            var key=data.resolve("keys").resolve(plan.id());if(!alias.equals("primary"))key=key.resolve(alias);
            if(!Files.isRegularFile(key.resolve("signing-key.pk8"),LinkOption.NOFOLLOW_LINKS)
                    ||!Files.isRegularFile(key.resolve("signing-certificate.der"),LinkOption.NOFOLLOW_LINKS))
                throw new IllegalArgumentException("Existing public fixture's stored key prerequisite missing");
        }
        Instant at=Instant.now();var clock=Clock.fixed(at,ZoneOffset.UTC);var keys=new FilePlanKeyStore(data,clock);
        var service=new MetadataService(URI.create("http://localhost:18080"),keys,new XmlSigner(),clock);
        byte[] metadata=service.generateDefaultAlgorithmConsumerMetadata(plan,run);
        byte[] control=service.generatePolling(plan,MetadataService.Variant.CONTROL,run);
        var root=SecureXml.parse(metadata).getDocumentElement();String entity=root.getAttribute("entityID");
        var acs=(org.w3c.dom.Element)root.getElementsByTagNameNS(MetadataService.MD,"AssertionConsumerService").item(0);
        var credentials=service.credentialsForPollingVariant(plan,MetadataService.Variant.CONTROL);
        var inputs=new TreeMap<String,Object>();var factory=new SamlDefaultAlgorithmFixtures();
        for(var fixture:SamlDefaultAlgorithmFixtures.Fixture.values()) {
            String id="_public_alg08_preflight_"+fixture.name().toLowerCase(Locale.ROOT);
            byte[] input=factory.authnRequest(fixture,id,URI.create("http://localhost:18380/simplesaml/module.php/saml/idp/singleSignOn"),
                    entity,URI.create(acs.getAttribute("Location")),at,credentials);
            inputs.put(fixture.name().toLowerCase(Locale.ROOT),Base64.getEncoder().encodeToString(input));
        }
        var result=new TreeMap<String,Object>();result.put("schema","samlscope-ssp-default-consumer-factory-inputs-v1");
        result.put("runId",run);result.put("planId",plan.id());result.put("profile",plan.profile().id());result.put("issueInstant",at.toString());
        result.put("targetEntityId",plan.target().entityId());result.put("metadata",Base64.getEncoder().encodeToString(metadata));
        result.put("normalControlMetadata",Base64.getEncoder().encodeToString(control));result.put("inputs",inputs);
        var bindings=new TreeMap<String,Object>();
        for(Class<?> type:List.of(MetadataService.class,Class.forName("com.samlscope.saml.metadata.BoundedMetadataFixtureCache"))) {
            Path jar=Path.of(type.getProtectionDomain().getCodeSource().getLocation().toURI());
            try(var stream=type.getResourceAsStream("/"+type.getName().replace('.','/')+".class")) {
                if(stream==null||!Files.isRegularFile(jar))throw new IllegalStateException("Actual archive CodeSource required");
                bindings.put(type.getName(),Map.of("codeSource",jar.toString(),
                    "jarSha256",HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(jar))),
                    "classSha256",HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(stream.readAllBytes()))));
            }
        }
        result.put("classBindings",bindings);
        result.put("scope","native public API diagnostic only; no target request or Run conclusion");
        System.out.println(json.write(result));
    }
}
