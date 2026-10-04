package com.samlscope.store;

import java.sql.SQLException;
import java.util.*;
import com.samlscope.core.caseexec.SupplementalDecryptionKeys;

/** First insertion wins across processes, including an explicit snapshot of absent test keys. */
public final class SqliteSupplementalDecryptionKeys {
    private final SqliteDatabase database;
    private final JsonCodec json;
    public SqliteSupplementalDecryptionKeys(SqliteDatabase database,JsonCodec json) {
        this.database=Objects.requireNonNull(database);this.json=Objects.requireNonNull(json);
    }
    public Optional<SupplementalDecryptionKeys> find(String runId) {
        try(var connection=database.open();var statement=connection.prepareStatement(
                "SELECT document_json FROM supplemental_decryption_keys WHERE run_id = ?")) {
            statement.setString(1,runId);
            try(var rows=statement.executeQuery()) {
                return rows.next()?Optional.of(json.read(rows.getString(1),SupplementalDecryptionKeys.class)):Optional.empty();
            }
        } catch(SQLException error) { throw new StoreException("Could not read supplemental public-key input",error); }
    }
    /** Does not update an existing record, even if the incoming key list is empty. */
    public boolean insertIfAbsent(SupplementalDecryptionKeys input) {
        Objects.requireNonNull(input);
        try(var connection=database.open();var statement=connection.prepareStatement(
                "INSERT INTO supplemental_decryption_keys(run_id,document_json) VALUES(?,?) ON CONFLICT(run_id) DO NOTHING")) {
            statement.setString(1,input.runId());statement.setString(2,json.write(input));
            return statement.executeUpdate()==1;
        } catch(SQLException error) { throw new StoreException("Could not record supplemental public-key input",error); }
    }
    /** Call before constructing any dependent test input. Concurrent submission cannot replace this snapshot. */
    public SupplementalDecryptionKeys freezeAbsent(SupplementalDecryptionKeys absence) {
        if(!absence.publicKeysSpkiBase64().isEmpty()) throw new IllegalArgumentException("Expected an absent-key snapshot");
        insertIfAbsent(absence);
        var frozen=find(absence.runId()).orElseThrow(()->new StoreException("Supplemental input disappeared"));
        if(!frozen.targetEntityId().equals(absence.targetEntityId()) || !frozen.metadataSha256().equals(absence.metadataSha256()))
            throw new StoreException("Supplemental public-key input belongs to different target metadata");
        return frozen;
    }
}
