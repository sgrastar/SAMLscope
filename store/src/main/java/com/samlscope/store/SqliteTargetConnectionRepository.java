package com.samlscope.store;

import com.samlscope.core.plan.TargetConnection;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/** All reads and revision writes require the caller's established owner identity. */
public final class SqliteTargetConnectionRepository {
    public record RevisionSummary(String id, java.util.Set<com.samlscope.core.plan.TargetRole> roles,
                                  String sha256, boolean refreshable) {
        public RevisionSummary { roles = java.util.Set.copyOf(roles); }
        static RevisionSummary from(TargetConnection.Revision revision) {
            return new RevisionSummary(revision.id(),revision.roles(),revision.sha256(),revision.privateSourceUrl() != null);
        }
    }
    private final SqliteDatabase database;
    private final JsonCodec json;
    public SqliteTargetConnectionRepository(SqliteDatabase database, JsonCodec json) {
        this.database = database;
        this.json = json;
    }
    public void createWithRevision(TargetConnection target, TargetConnection.Revision revision) {
        if (!target.id().equals(revision.connectionId())) throw new IllegalArgumentException("Revision belongs to another target");
        try (var connection = database.open()) {
            connection.setAutoCommit(false);
            try (var insert = connection.prepareStatement("INSERT INTO target_connections(id, owner_id, document_json) VALUES(?,?,?)");
                 var metadata = connection.prepareStatement("INSERT INTO target_metadata_revisions(connection_id,id,document_json,summary_json) VALUES(?,?,?,?)")) {
                insert.setString(1,target.id()); insert.setString(2,target.ownerId()); insert.setString(3,json.write(target)); insert.executeUpdate();
                metadata.setString(1,target.id()); metadata.setString(2,revision.id()); metadata.setString(3,json.write(revision));
                metadata.setString(4,json.write(RevisionSummary.from(revision))); metadata.executeUpdate();
                connection.commit();
            } catch (SQLException e) { connection.rollback(); throw e; }
        } catch (SQLException e) { throw new StoreException("Could not register target metadata",e); }
    }
    public List<TargetConnection.Revision> revisions(String ownerId, String targetId) {
        var result = new ArrayList<TargetConnection.Revision>();
        try (var connection = database.open(); var query = connection.prepareStatement("SELECT r.document_json FROM target_metadata_revisions r JOIN target_connections c ON c.id=r.connection_id WHERE c.owner_id=? AND c.id=? ORDER BY r.rowid DESC")) {
            query.setString(1,ownerId); query.setString(2,targetId);
            try(var rows=query.executeQuery()) { while(rows.next()) result.add(json.read(rows.getString(1),TargetConnection.Revision.class)); }
            return List.copyOf(result);
        } catch(SQLException e) { throw new StoreException("Could not list metadata revisions",e); }
    }
    /** List display reads only cached public fields, never deserializing historical metadata XML. */
    public List<RevisionSummary> revisionSummaries(String ownerId, String targetId) {
        var result = new ArrayList<RevisionSummary>();
        try (var connection = database.open(); var query = connection.prepareStatement("""
                SELECT r.summary_json FROM target_metadata_revisions r JOIN target_connections c ON c.id=r.connection_id
                WHERE c.owner_id=? AND c.id=? ORDER BY r.rowid DESC
                """)) {
            query.setString(1,ownerId); query.setString(2,targetId);
            try (var rows = query.executeQuery()) {
                while (rows.next()) result.add(json.read(rows.getString(1),RevisionSummary.class));
            }
            return List.copyOf(result);
        } catch (SQLException error) { throw new StoreException("Could not list revision summaries",error); }
    }
    public Optional<TargetConnection.Revision> latestRevision(String ownerId, String targetId) {
        try (var connection = database.open(); var query = connection.prepareStatement("""
                SELECT r.document_json FROM target_metadata_revisions r JOIN target_connections c ON c.id=r.connection_id
                WHERE c.owner_id=? AND c.id=? ORDER BY r.rowid DESC LIMIT 1
                """)) {
            query.setString(1,ownerId); query.setString(2,targetId);
            try (var rows = query.executeQuery()) {
                return rows.next() ? Optional.of(json.read(rows.getString(1),TargetConnection.Revision.class)) : Optional.empty();
            }
        } catch (SQLException error) { throw new StoreException("Could not read latest revision",error); }
    }
    static void backfillSummaries(java.sql.Connection connection, JsonCodec json) throws SQLException {
        try (var query = connection.createStatement(); var rows = query.executeQuery(
                "SELECT connection_id,id,document_json FROM target_metadata_revisions");
             var update = connection.prepareStatement("UPDATE target_metadata_revisions SET summary_json=? WHERE connection_id=? AND id=?")) {
            while (rows.next()) {
                var revision = json.read(rows.getString(3),TargetConnection.Revision.class);
                update.setString(1,json.write(RevisionSummary.from(revision)));
                update.setString(2,rows.getString(1)); update.setString(3,rows.getString(2)); update.executeUpdate();
            }
        }
    }
    public void create(TargetConnection target) {
        try (var connection = database.open(); var query = connection.prepareStatement(
                "INSERT INTO target_connections(id, owner_id, document_json) VALUES(?, ?, ?)")) {
            query.setString(1, target.id()); query.setString(2, target.ownerId()); query.setString(3, json.write(target));
            query.executeUpdate();
        } catch (SQLException e) { throw new StoreException("Could not create target connection", e); }
    }
    public List<TargetConnection> list(String ownerId) {
        var result = new ArrayList<TargetConnection>();
        try (var connection = database.open(); var query = connection.prepareStatement(
                "SELECT document_json FROM target_connections WHERE owner_id = ? ORDER BY id")) {
            query.setString(1, ownerId);
            try (var rows = query.executeQuery()) {
                while (rows.next()) result.add(json.read(rows.getString(1), TargetConnection.class));
            }
            return List.copyOf(result);
        } catch (SQLException e) { throw new StoreException("Could not list target connections", e); }
    }
    public void appendRevision(String ownerId, TargetConnection.Revision revision) {
        try (var connection = database.open(); var query = connection.prepareStatement("""
                INSERT INTO target_metadata_revisions(connection_id, id, document_json, summary_json)
                SELECT id, ?, ?, ? FROM target_connections WHERE id = ? AND owner_id = ?
                """)) {
            query.setString(1, revision.id()); query.setString(2, json.write(revision));
            query.setString(3,json.write(RevisionSummary.from(revision)));
            query.setString(4, revision.connectionId()); query.setString(5, ownerId);
            if (query.executeUpdate() != 1) throw new IllegalArgumentException("Target connection unavailable");
        } catch (SQLException e) { throw new StoreException("Could not append immutable metadata revision", e); }
    }
    public Optional<TargetConnection.Revision> findRevision(String ownerId, String connectionId, String revisionId) {
        try (var connection = database.open(); var query = connection.prepareStatement("""
                SELECT r.document_json FROM target_metadata_revisions r
                JOIN target_connections c ON c.id = r.connection_id
                WHERE c.owner_id = ? AND c.id = ? AND r.id = ?
                """)) {
            query.setString(1, ownerId); query.setString(2, connectionId); query.setString(3, revisionId);
            try (var rows = query.executeQuery()) {
                return rows.next() ? Optional.of(json.read(rows.getString(1), TargetConnection.Revision.class)) : Optional.empty();
            }
        } catch (SQLException e) { throw new StoreException("Could not load metadata revision", e); }
    }
}
