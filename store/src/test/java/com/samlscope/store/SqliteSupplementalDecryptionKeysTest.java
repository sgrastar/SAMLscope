package com.samlscope.store;
import static org.junit.jupiter.api.Assertions.*;
import java.nio.file.Path;
import java.security.KeyPairGenerator;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import com.samlscope.core.caseexec.SupplementalDecryptionKeys;
class SqliteSupplementalDecryptionKeysTest {
    @TempDir Path directory;
    static final String HASH="a".repeat(64);
    @Test void snapshotsAreImmutableIncludingAbsentKeysAndSurviveReopen() throws Exception {
        var database=database();var repository=new SqliteSupplementalDecryptionKeys(database,new JsonCodec());
        var generator=KeyPairGenerator.getInstance("RSA");generator.initialize(2048);
        var key=Base64.getEncoder().encodeToString(generator.generateKeyPair().getPublic().getEncoded());
        var input=new SupplementalDecryptionKeys("run","entity",HASH,"https://idp.example/admin/keys",List.of(key),Instant.EPOCH);
        var absent=SupplementalDecryptionKeys.absent("run","entity",HASH,Instant.EPOCH);
        assertTrue(repository.insertIfAbsent(input));assertFalse(repository.insertIfAbsent(absent));
        assertEquals(input,repository.freezeAbsent(absent));
        assertEquals(input,new SqliteSupplementalDecryptionKeys(new SqliteDatabase(directory),new JsonCodec()).find("run").orElseThrow());
        assertThrows(StoreException.class,()->repository.freezeAbsent(SupplementalDecryptionKeys.absent("run","other",HASH,Instant.EPOCH)));
        assertThrows(StoreException.class,()->repository.freezeAbsent(SupplementalDecryptionKeys.absent("run","entity","b".repeat(64),Instant.EPOCH)));
        assertThrows(StoreException.class,()->repository.insertIfAbsent(SupplementalDecryptionKeys.absent("unknown","entity",HASH,Instant.EPOCH)));
        try(var connection=database.open();var statement=connection.createStatement()) { statement.executeUpdate("DELETE FROM runs WHERE id='run'"); }
        assertTrue(repository.find("run").isEmpty());
    }
    @Test void concurrentEmptyAndPopulatedInputCannotReplaceTheWinner() throws Exception {
        var database=database();var generator=KeyPairGenerator.getInstance("RSA");generator.initialize(2048);
        var key=Base64.getEncoder().encodeToString(generator.generateKeyPair().getPublic().getEncoded());
        var input=new SupplementalDecryptionKeys("run","entity",HASH,"https://idp.example/admin/keys",List.of(key),Instant.EPOCH);
        var absent=SupplementalDecryptionKeys.absent("run","entity",HASH,Instant.EPOCH);
        var start=new CountDownLatch(1);
        try(var executor=Executors.newFixedThreadPool(8)) {
            var tasks=new ArrayList<Future<Boolean>>();
            for(int i=0;i<8;i++) { var selected=i%2==0?input:absent;tasks.add(executor.submit(()->{start.await();return new SqliteSupplementalDecryptionKeys(database,new JsonCodec()).insertIfAbsent(selected);})); }
            start.countDown();int winners=0;for(var task:tasks)if(task.get(10,TimeUnit.SECONDS))winners++;
            assertEquals(1,winners);
        }
        var repository=new SqliteSupplementalDecryptionKeys(database,new JsonCodec());var winner=repository.find("run").orElseThrow();
        assertTrue(winner.equals(input)||winner.equals(absent));
        assertFalse(repository.insertIfAbsent(input));assertFalse(repository.insertIfAbsent(absent));assertEquals(winner,repository.find("run").orElseThrow());
    }
    private SqliteDatabase database() throws Exception {
        var database=new SqliteDatabase(directory);
        try(var connection=database.open();var statement=connection.createStatement()) {
            statement.executeUpdate("INSERT INTO plans(id,document_json,created_at,updated_at) VALUES('plan','{}','now','now')");
            statement.executeUpdate("INSERT INTO runs(id,plan_id,status,document_json,created_at,updated_at) VALUES('run','plan','CREATED','{}','now','now')");
        }
        return database;
    }
}
