package com.samlscope.runner.cases;

import static org.junit.jupiter.api.Assertions.*;
import com.samlscope.core.transcript.*;
import com.samlscope.saml.crypto.FilePlanKeyStore;
import java.nio.file.*;
import java.sql.DriverManager;
import java.time.*;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class KeycloakNativeRunEvidenceBridgeTest {
    static final String RUN="run_00000000000000000000000000",PLAN="plan_00000000000000000000000000",TX="tx_00000000000000000000000000";
    @TempDir Path data;
    void database()throws Exception{try(var c=DriverManager.getConnection("jdbc:sqlite:"+data.resolve("samlscope.db"));var s=c.createStatement()){s.execute("CREATE TABLE runs (id TEXT,plan_id TEXT)");s.execute("CREATE TABLE plans (id TEXT)");s.execute("INSERT INTO plans VALUES ('"+PLAN+"')");s.execute("INSERT INTO runs VALUES ('"+RUN+"','"+PLAN+"')");}}
    @Test void unknownRunAndAbsentKeysNeverCreateKeyFiles()throws Exception{
        database();var bridge=new KeycloakNativeRunEvidenceBridge(data);var before=Files.readAllBytes(data.resolve("samlscope.db"));
        assertTrue(bridge.key(RUN,"control").isEmpty());assertTrue(bridge.key("run_11111111111111111111111111","control").isEmpty());
        assertTrue(bridge.key(RUN,"../outside").isEmpty());assertFalse(Files.exists(data.resolve("keys")));
        assertArrayEquals(before,Files.readAllBytes(data.resolve("samlscope.db")));
    }
    @Test void existingKeyIsReadOnlyAndSymlinkCannotSupplyPrivateKey()throws Exception{
        database();String alias="poll-"+HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256").digest("control".getBytes(java.nio.charset.StandardCharsets.UTF_8))).substring(0,16);
        var store=new FilePlanKeyStore(data,Clock.systemUTC());var expected=store.getOrCreate(PLAN,alias);
        var bridge=new KeycloakNativeRunEvidenceBridge(data);assertArrayEquals(expected.certificate().getEncoded(),bridge.key(RUN,"control").orElseThrow().certificate().getEncoded());
        try(var c=DriverManager.getConnection("jdbc:sqlite:"+data.resolve("samlscope.db"));var q=c.createStatement()){q.execute("DELETE FROM plans");}
        assertTrue(bridge.key(RUN,"control").isEmpty());
        try(var c=DriverManager.getConnection("jdbc:sqlite:"+data.resolve("samlscope.db"));var q=c.createStatement()){q.execute("INSERT INTO plans VALUES ('"+PLAN+"')");}
        var key=data.resolve("keys").resolve(PLAN).resolve(alias).resolve("signing-key.pk8");var original=Files.readAllBytes(key);
        var elsewhere=data.resolve("elsewhere.pk8");Files.write(elsewhere,original);Files.delete(key);Files.createSymbolicLink(key,elsewhere);
        assertTrue(bridge.key(RUN,"control").isEmpty());assertArrayEquals(original,Files.readAllBytes(elsewhere));
    }
    @Test void roleAliasesReadOnlyExistingBoundKeysAndPreserveTheLegacyAllowlist()throws Exception {
        database();var bridge=new KeycloakNativeRunEvidenceBridge(data);
        assertTrue(bridge.metadataRoleKey(RUN,"three-signing-keys-first").isEmpty());
        assertFalse(Files.exists(data.resolve("keys")));
        var digest=java.security.MessageDigest.getInstance("SHA-256");
        String first="poll-"+HexFormat.of().formatHex(digest.digest("three-signing-keys-first".getBytes(java.nio.charset.StandardCharsets.UTF_8))).substring(0,16);
        var store=new FilePlanKeyStore(data,Clock.systemUTC());var a=store.getOrCreate(PLAN,first);
        String suffix=HexFormat.of().formatHex(digest.digest(a.certificate().getPublicKey().getEncoded())).substring(0,24);
        var b=store.getOrCreate(PLAN,"roll2-"+suffix);var c=store.getOrCreate(PLAN,"roll3-"+suffix);
        var expected=Map.of("three-signing-keys-first",a,"three-signing-keys-second",b,"three-signing-keys",c);
        var before=Files.readAllBytes(data.resolve("samlscope.db"));
        for(var row:expected.entrySet()) {
            assertArrayEquals(row.getValue().certificate().getEncoded(),bridge.metadataRoleKey(RUN,row.getKey()).orElseThrow().certificate().getEncoded());
            assertTrue(bridge.key(RUN,row.getKey()).isEmpty());
        }
        assertTrue(bridge.metadataRoleKey(RUN,"primary").isEmpty());
        assertTrue(bridge.metadataRoleKey(RUN,"../outside").isEmpty());
        assertTrue(bridge.metadataRoleKey("run_11111111111111111111111111","three-signing-keys-first").isEmpty());
        assertArrayEquals(before,Files.readAllBytes(data.resolve("samlscope.db")));
    }
    @Test void decodedOriginalRequiresExactRunPathSizeAndNoSymlink()throws Exception{
        var file=data.resolve("transcripts").resolve(RUN).resolve(TX+".saml.xml");Files.createDirectories(file.getParent());Files.write(file,new byte[]{1,2});
        var bridge=new KeycloakNativeRunEvidenceBridge(data);
        var entry=new TranscriptEntry(TX,RUN,Direction.INBOUND,Instant.now(),null,"POST","http://localhost",200,Map.of(),null,0,"transcripts/"+RUN+"/"+TX+".saml.xml",2,"text/xml",null,Map.of());
        assertArrayEquals(new byte[]{1,2},bridge.content(entry));
        var foreign=new TranscriptEntry(TX,"run_11111111111111111111111111",entry.direction(),entry.timestamp(),null,entry.method(),entry.url(),entry.status(),entry.headers(),null,0,entry.decodedSamlRef(),2,entry.contentType(),null,Map.of());
        assertThrows(IllegalArgumentException.class,()->bridge.content(foreign));
        Files.delete(file);Files.createSymbolicLink(file,data.resolve("samlscope.db"));assertThrows(IllegalArgumentException.class,()->bridge.content(entry));
    }
    @Test void primaryRunKeyAndMetadataAreReadOnlyAndDoNotUseOtherRunSnapshots()throws Exception {
        database();var bridge=new KeycloakNativeRunEvidenceBridge(data);
        assertTrue(bridge.primaryKey(RUN).isEmpty());assertFalse(Files.exists(data.resolve("keys")));
        var expected=new FilePlanKeyStore(data,Clock.systemUTC()).getOrCreate(PLAN);
        var key=data.resolve("keys").resolve(PLAN).resolve("signing-key.pk8");var before=Files.readAllBytes(key);
        assertArrayEquals(expected.privateKey().getEncoded(),bridge.primaryKey(RUN).orElseThrow().getEncoded());
        assertArrayEquals(before,Files.readAllBytes(key));
        assertThrows(IllegalArgumentException.class,()->bridge.targetMetadata(RUN));
        var directory=Files.createDirectory(data.resolve("target-metadata"));
        var snapshot=directory.resolve(RUN+".xml");Files.writeString(snapshot,"<EntityDescriptor/>");
        assertArrayEquals(Files.readAllBytes(snapshot),bridge.targetMetadata(RUN));
        assertThrows(IllegalArgumentException.class,()->bridge.targetMetadata("run_11111111111111111111111111"));
        Files.delete(snapshot);Files.createSymbolicLink(snapshot,directory.resolve("other.xml"));
        assertThrows(IllegalArgumentException.class,()->bridge.targetMetadata(RUN));
        Files.delete(key);Files.createSymbolicLink(key,directory.resolve("other.pk8"));
        assertTrue(bridge.primaryKey(RUN).isEmpty());
    }

}
