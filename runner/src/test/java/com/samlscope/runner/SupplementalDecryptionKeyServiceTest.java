package com.samlscope.runner;
import static org.junit.jupiter.api.Assertions.*;
import java.nio.file.Path;
import java.security.*;
import java.time.*;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import com.samlscope.store.*;
class SupplementalDecryptionKeyServiceTest {
    @TempDir Path directory;
    static final String HASH="a".repeat(64),ENTITY="https://idp.example";
    @Test void orderDeduplicationAndImmutableInputAcrossPublishedAndSupplementalCombinations() throws Exception {
        var generator=KeyPairGenerator.getInstance("RSA");generator.initialize(2048);
        var a=generator.generateKeyPair().getPublic();var b=generator.generateKeyPair().getPublic();var c=generator.generateKeyPair().getPublic();
        int scenario=0;
        for(var published:List.of(List.<PublicKey>of(),List.of(a),List.of(a,b),List.of(a,a)))
        for(var supplemental:List.of(List.of(b),List.of(b,c),List.of(c,b)))
        for(var mutation:List.of("source","keys","entity","metadata")) {
            var database=database(directory.resolve("scenario-"+scenario++));
            var repository=new SqliteSupplementalDecryptionKeys(database,new JsonCodec());
            var scope=new SupplementalDecryptionKeyService.Scope(ENTITY,HASH,false,published);
            var service=new SupplementalDecryptionKeyService(repository,ignored->scope,Clock.fixed(Instant.EPOCH,ZoneOffset.UTC));
            assertTrue(service.inspect("run").isEmpty());assertTrue(repository.find("run").isEmpty());
            var input=submission(ENTITY,HASH,"https://idp.example/admin/keys",supplemental);
            var saved=service.submit("run",input);
            var expected=new ArrayList<String>();
            for(var key:published)if(!expected.contains(encoded(key)))expected.add(encoded(key));
            for(var key:supplemental)if(!expected.contains(encoded(key)))expected.add(encoded(key));
            assertEquals(expected,service.effectiveKeys("run").stream().map(SupplementalDecryptionKeyServiceTest::encoded).toList());
            var later=new SupplementalDecryptionKeyService(repository,ignored->scope,Clock.fixed(Instant.EPOCH.plusSeconds(60),ZoneOffset.UTC));
            assertEquals(saved,later.submit("run",input));
            var changed=submission(mutation.equals("entity")?"other":ENTITY,mutation.equals("metadata")?"b".repeat(64):HASH,
                    mutation.equals("source")?"https://other.example/keys":input.sourceUri(),mutation.equals("keys")?List.of(a):supplemental);
            assertThrows(RuntimeException.class,()->service.submit("run",changed));
            assertEquals(saved,service.inspect("run").orElseThrow());
        }
        assertEquals(48,scenario);
    }
    @Test void freezingAbsenceAndLegacyStartedRunsRejectLateInputsWithoutChangingPublishedKeys() throws Exception {
        var generator=KeyPairGenerator.getInstance("RSA");generator.initialize(2048);var key=generator.generateKeyPair().getPublic();
        for(boolean started:List.of(false,true)) {
            var database=database(directory.resolve("started-"+started));var repository=new SqliteSupplementalDecryptionKeys(database,new JsonCodec());
            var scope=new SupplementalDecryptionKeyService.Scope(ENTITY,HASH,started,List.of(key));
            var service=new SupplementalDecryptionKeyService(repository,ignored->scope,Clock.systemUTC());
            if(!started)assertTrue(service.freeze("run").publicKeys().isEmpty());
            assertThrows(IllegalStateException.class,()->service.submit("run",submission(ENTITY,HASH,"https://idp.example/keys",List.of(key))));
            assertTrue(service.inspect("run").orElseThrow().publicKeys().isEmpty());
            assertEquals(List.of(encoded(key)),service.effectiveKeys("run").stream().map(SupplementalDecryptionKeyServiceTest::encoded).toList());
            var mismatch=new SupplementalDecryptionKeyService(repository,ignored->new SupplementalDecryptionKeyService.Scope("other",HASH,true,List.of()),Clock.systemUTC());
            assertThrows(IllegalArgumentException.class,()->mismatch.inspect("run"));
            assertThrows(StoreException.class,()->mismatch.effectiveKeys("run"));
        }
    }
    @Test void keySetReportsPublishedAndSupplementalProvenanceOfTheFixedInput() throws Exception {
        var generator=KeyPairGenerator.getInstance("RSA");generator.initialize(2048);
        var a=generator.generateKeyPair().getPublic();var b=generator.generateKeyPair().getPublic();
        var database=database(directory.resolve("provenance"));var repository=new SqliteSupplementalDecryptionKeys(database,new JsonCodec());
        var scope=new SupplementalDecryptionKeyService.Scope(ENTITY,HASH,false,List.of(a));
        var service=new SupplementalDecryptionKeyService(repository,ignored->scope,Clock.systemUTC());
        assertTrue(service.inspect("run").isEmpty());
        assertTrue(repository.find("run").isEmpty());
        var saved=service.submit("run",submission(ENTITY,HASH,"https://idp.example/keys",List.of(b)));
        assertFalse(saved.publicKeys().isEmpty());
        var fixed=service.keySet("run");
        assertEquals(List.of(encoded(a),encoded(b)),fixed.effective().stream().map(SupplementalDecryptionKeyServiceTest::encoded).toList());
        assertEquals(List.of("published-metadata","supplemental-input"),fixed.sources());
        assertEquals("published-metadata",fixed.sourceOf(a));
        assertEquals("supplemental-input",fixed.sourceOf(b));
    }
    @Test void keySetFreezesAbsenceAndKeepsPublishedOrderWithoutSupplementalSource() throws Exception {
        var generator=KeyPairGenerator.getInstance("RSA");generator.initialize(2048);var key=generator.generateKeyPair().getPublic();
        var database=database(directory.resolve("absent"));var repository=new SqliteSupplementalDecryptionKeys(database,new JsonCodec());
        var service=new SupplementalDecryptionKeyService(repository,
                ignored->new SupplementalDecryptionKeyService.Scope(ENTITY,HASH,false,List.of(key)),Clock.systemUTC());
        assertTrue(service.inspect("run").isEmpty());
        var fixed=service.keySet("run");
        assertEquals(List.of(encoded(key)),fixed.effective().stream().map(SupplementalDecryptionKeyServiceTest::encoded).toList());
        assertEquals(List.of("published-metadata"),fixed.sources());
        assertTrue(service.inspect("run").orElseThrow().publicKeys().isEmpty());
        assertThrows(TestInputFixed.class,()->service.submit("run",submission(ENTITY,HASH,"https://idp.example/keys",List.of(key))));
    }
    @Test void aSupplementalKeyThatRepeatsPublishedMaterialRetainsThePublishedSource() throws Exception {
        var generator=KeyPairGenerator.getInstance("RSA");generator.initialize(2048);var key=generator.generateKeyPair().getPublic();
        var database=database(directory.resolve("repeated"));var repository=new SqliteSupplementalDecryptionKeys(database,new JsonCodec());
        var service=new SupplementalDecryptionKeyService(repository,
                ignored->new SupplementalDecryptionKeyService.Scope(ENTITY,HASH,false,List.of(key)),Clock.systemUTC());
        service.submit("run",submission(ENTITY,HASH,"https://idp.example/keys",List.of(key)));
        var fixed=service.keySet("run");
        assertEquals(List.of(encoded(key)),fixed.effective().stream().map(SupplementalDecryptionKeyServiceTest::encoded).toList());
        assertEquals(List.of("published-metadata"),fixed.sources());
    }
    @Test void concurrentFirstInsertAndStartupFreezeLeaveOneConsistentSnapshot() throws Exception {
        var generator=KeyPairGenerator.getInstance("RSA");generator.initialize(2048);var key=generator.generateKeyPair().getPublic();
        for(int attempt=0;attempt<20;attempt++) {
            var database=database(directory.resolve("race-"+attempt));var repository=new SqliteSupplementalDecryptionKeys(database,new JsonCodec());
            var service=new SupplementalDecryptionKeyService(repository,
                    ignored->new SupplementalDecryptionKeyService.Scope(ENTITY,HASH,false,List.of()),Clock.systemUTC());
            var ready=new java.util.concurrent.CountDownLatch(1);
            var submitter=java.util.concurrent.CompletableFuture.runAsync(()->{
                try { ready.await(); service.submit("run",submission(ENTITY,HASH,"https://idp.example/keys",List.of(key))); }
                catch(Exception fixed) { /* losing the first-insert race rejects the submission */ }
            });
            var freezer=java.util.concurrent.CompletableFuture.runAsync(()->{
                try { ready.await(); service.freeze("run"); }
                catch(Exception unavailable) { throw new AssertionError(unavailable); }
            });
            ready.countDown();submitter.join();freezer.join();
            var snapshot=repository.find("run").orElseThrow();
            assertTrue(snapshot.publicKeysSpkiBase64().isEmpty()
                    || snapshot.publicKeysSpkiBase64().equals(List.of(encoded(key))),"attempt "+attempt);
            assertEquals(ENTITY,snapshot.targetEntityId());
            assertEquals(HASH,snapshot.metadataSha256());
            var expectedEffective=snapshot.publicKeysSpkiBase64().isEmpty()?List.<String>of():List.of(encoded(key));
            assertEquals(expectedEffective,
                    service.effectiveKeys("run").stream().map(SupplementalDecryptionKeyServiceTest::encoded).toList());
        }
    }
    private static String encoded(PublicKey key) { return Base64.getEncoder().encodeToString(key.getEncoded()); }
    private static SupplementalDecryptionKeyService.Submission submission(String entity,String hash,String source,List<PublicKey> keys) {
        return new SupplementalDecryptionKeyService.Submission(entity,hash,source,keys.stream().map(SupplementalDecryptionKeyServiceTest::encoded).toList());
    }
    private static SqliteDatabase database(Path path) throws Exception {
        var database=new SqliteDatabase(path);
        try(var connection=database.open();var statement=connection.createStatement()) {
            statement.executeUpdate("INSERT INTO plans(id,document_json,created_at,updated_at) VALUES('plan','{}','now','now')");
            statement.executeUpdate("INSERT INTO runs(id,plan_id,status,document_json,created_at,updated_at) VALUES('run','plan','CREATED','{}','now','now')");
        }
        return database;
    }
}
