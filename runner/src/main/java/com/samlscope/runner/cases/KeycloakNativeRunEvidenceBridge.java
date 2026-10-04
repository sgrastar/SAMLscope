package com.samlscope.runner.cases;

import com.samlscope.core.transcript.TranscriptEntry;
import com.samlscope.saml.crypto.PlanCredentials;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.sql.DriverManager;
import java.util.*;

/** Read-only bridge for ATTESTED native observers; never creates keys or records evidence. */
final class KeycloakNativeRunEvidenceBridge {
    private final Path data;

    KeycloakNativeRunEvidenceBridge(Path data) { this.data=Objects.requireNonNull(data).toAbsolutePath().normalize(); }
    Path evidenceDirectory() { return data.resolve("metadata-rejection-evidence"); }

    byte[] content(TranscriptEntry entry) {
        try {
            require(entry!=null&&validRun(entry.runId())&&entry.id().matches("tx_[0-9A-HJKMNP-TV-Z]{26}"));
            String expected="transcripts/"+entry.runId()+"/"+entry.id()+".saml.xml";
            require(expected.equals(entry.decodedSamlRef())&&entry.decodedSamlBytes()>0&&entry.decodedSamlBytes()<=1_048_576);
            var path=data.resolve(expected);regular(path);require(Files.size(path)==entry.decodedSamlBytes());
            return Files.readAllBytes(path);
        } catch(Exception unavailable) { throw new IllegalArgumentException("Native decoded original unavailable"); }
    }

    Optional<PlanCredentials> key(String run,String variant) {
        try {
            require(validRun(run)&&Set.of("control","no-valid-until","primary").contains(variant));
            String alias="poll-"+HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(variant.getBytes(StandardCharsets.UTF_8))).substring(0,16);
            return readKey(run,"primary".equals(variant)?null:alias);
        } catch(Exception unavailable) { return Optional.empty(); }
    }

    /** Bounded read-only aliases used by the shared role/purpose proof; never creates a key. */
    Optional<PlanCredentials> metadataRoleKey(String run,String variant) {
        try {
            require(validRun(run)&&Set.of("three-signing-keys-first","three-signing-keys-second","three-signing-keys").contains(variant));
            String first="poll-"+HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest("three-signing-keys-first".getBytes(StandardCharsets.UTF_8))).substring(0,16);
            var primary=readKey(run,first);
            if("three-signing-keys-first".equals(variant)||primary.isEmpty())return primary;
            String suffix=HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(primary.get().certificate().getPublicKey().getEncoded())).substring(0,24);
            return readKey(run,("three-signing-keys-second".equals(variant)?"roll2-":"roll3-")+suffix);
        } catch(Exception unavailable) { return Optional.empty(); }
    }

    private Optional<PlanCredentials> readKey(String run,String alias) {
        try {
            require(validRun(run));
            var database=data.resolve("samlscope.db");regular(database);
            String plan;
            try(var connection=DriverManager.getConnection("jdbc:sqlite:file:"+database+"?mode=ro");
                    var statement=connection.prepareStatement("SELECT r.plan_id FROM runs r JOIN plans p ON p.id = r.plan_id WHERE r.id = ?")) {
                statement.setString(1,run);
                try(var rows=statement.executeQuery()) {
                    require(rows.next());plan=rows.getString(1);require(!rows.next()&&plan!=null&&plan.matches("plan_[0-9A-HJKMNP-TV-Z]{26}"));
                }
            }
            var directory=data.resolve("keys").resolve(plan);
            if(alias!=null)directory=directory.resolve(alias);
            var keyFile=directory.resolve("signing-key.pk8");var certificateFile=directory.resolve("signing-certificate.der");
            regular(keyFile);regular(certificateFile);require(Files.size(keyFile)<=16384&&Files.size(certificateFile)<=16384);
            var encoded=Files.readAllBytes(keyFile);
            try {
                var privateKey=KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(encoded));
                var certificate=(X509Certificate)CertificateFactory.getInstance("X.509")
                        .generateCertificate(new ByteArrayInputStream(Files.readAllBytes(certificateFile)));
                return Optional.of(new PlanCredentials(privateKey,certificate));
            } finally { Arrays.fill(encoded,(byte)0); }
        } catch(Exception unavailable) { return Optional.empty(); }
    }

    Optional<PrivateKey> primaryKey(String run) {
        return key(run,"primary").map(PlanCredentials::privateKey);
    }

    byte[] targetMetadata(String run) {
        try {
            require(validRun(run));
            var path=data.resolve("target-metadata").resolve(run+".xml");regular(path);
            require(Files.size(path)>0&&Files.size(path)<=5_242_880);
            return Files.readAllBytes(path);
        } catch(Exception unavailable) { throw new IllegalArgumentException("Run metadata original unavailable"); }
    }

    private void regular(Path path) throws Exception {
        require(path.normalize().startsWith(data)&&Files.isRegularFile(path,LinkOption.NOFOLLOW_LINKS));
        for(Path current=path;current!=null&&current.startsWith(data);current=current.getParent())
            require(!Files.isSymbolicLink(current));
    }
    private static boolean validRun(String run) { return run!=null&&run.matches("run_[0-9A-HJKMNP-TV-Z]{26}"); }
    private static void require(boolean yes) { if(!yes)throw new IllegalArgumentException("Native Run scope unavailable"); }
}
