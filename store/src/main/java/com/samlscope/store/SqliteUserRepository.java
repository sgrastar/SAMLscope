package com.samlscope.store;

import java.sql.*;
import java.time.Instant;
import java.util.*;

/** Local account roles are authoritative until a verified provider lifecycle integration is installed. */
public final class SqliteUserRepository {
    public enum Role { ANONYMOUS, USER, ADMIN }
    public record User(String id, String displayName, Role role, String status,
                       String createdAt, String lastUsedAt, long version) {}
    private final SqliteDatabase database;
    public SqliteUserRepository(SqliteDatabase database) { this.database = database; }

    public synchronized User enroll(String id, String name, boolean bootstrapAdmin, Instant now) {
        return transaction(c -> {
            if (exists(c, "SELECT 1 FROM deleted_user_ids WHERE id = ?", id)) throw new SecurityException("Account deleted");
            try (var s = c.prepareStatement("INSERT OR IGNORE INTO application_users(id, role, created_at) VALUES(?, 'USER', ?)")) {
                s.setString(1, id); s.setString(2, now.toString()); s.executeUpdate();
            }
            // Bootstrap only at the first login, never undo an administrator's later role change.
            try (var s = c.prepareStatement("UPDATE application_users SET display_name = ?, role = ?, enrolled = 1 WHERE id = ? AND enrolled = 0 AND status = 'ACTIVE'")) {
                var providerName = name == null ? "" : name.replaceAll("[\\p{Cntrl}]", "");
                s.setString(1, providerName.substring(0, Math.min(200, providerName.length()))); s.setString(2, bootstrapAdmin ? "ADMIN" : "USER"); s.setString(3, id); s.executeUpdate();
            }
            return active(find(c, id));
        });
    }
    public User requireActive(String id) { return active(find(id)); }
    private static User active(User user) {
        if (!user.status().equals("ACTIVE")) throw new SecurityException("Account unavailable");
        return user;
    }
    public User find(String id) {
        try (var c = database.open()) { return find(c, id); }
        catch (SQLException e) { throw new StoreException("Could not read account", e); }
    }
    public List<User> list() {
        try (var c = database.open(); var s = c.prepareStatement("SELECT * FROM application_users ORDER BY created_at, id"); var r = s.executeQuery()) {
            var users = new ArrayList<User>(); while (r.next()) users.add(read(r)); return List.copyOf(users);
        } catch (SQLException e) { throw new StoreException("Could not list accounts", e); }
    }
    /** Only successful authenticated management use calls this; login and public-report views do not. */
    public void touch(String id, Instant now) {
        try (var c = database.open(); var s = c.prepareStatement("UPDATE application_users SET last_used_at = ? WHERE id = ? AND status = 'ACTIVE' AND (last_used_at IS NULL OR last_used_at < ?)")) {
            s.setString(1, now.toString()); s.setString(2, id); s.setString(3, now.toString()); s.executeUpdate();
        } catch (SQLException e) { throw new StoreException("Could not record account activity", e); }
    }
    public synchronized User update(String id, String name, Role role, long version, Instant now) {
        if (role == null) throw new IllegalArgumentException("Role is required");
        var displayName = validName(name);
        return transaction(c -> {
            var existing = active(find(c, id)); checkVersion(existing, version);
            protectLastAdmin(c, existing, role == Role.ADMIN);
            try (var s = c.prepareStatement("UPDATE application_users SET display_name = ?, role = ?, enrolled = 1, version = version + 1, "
                    + "last_used_at = CASE WHEN role <> 'ANONYMOUS' AND ? = 'ANONYMOUS' THEN ? ELSE last_used_at END WHERE id = ?")) {
                s.setString(1, displayName); s.setString(2, role.name()); s.setString(3, role.name());
                s.setString(4, now.toString()); s.setString(5, id); s.executeUpdate();
            }
            return find(c, id);
        });
    }
    public synchronized void beginDeletion(String id, long version) {
        transaction(c -> {
            var existing = find(c, id); checkVersion(existing, version);
            protectLastAdmin(c, existing, false);
            try (var s = c.prepareStatement("UPDATE application_users SET status = 'DELETING' WHERE id = ?")) {
                s.setString(1, id); s.executeUpdate();
            }
            return null;
        });
    }
    public synchronized void finishDeletion(String id) {
        transaction(c -> {
            if (!find(c, id).status().equals("DELETING")) throw new IllegalArgumentException("Deletion was not started");
            if (exists(c, "SELECT 1 FROM hosted_plan_owners WHERE owner_id = ?", id)) throw new IllegalStateException("Delete owned Plans first");
            for (var sql : List.of(
                    "DELETE FROM target_metadata_revisions WHERE connection_id IN (SELECT id FROM target_connections WHERE owner_id = ?)",
                    "DELETE FROM target_connections WHERE owner_id = ?",
                    "INSERT OR IGNORE INTO deleted_user_ids(id) VALUES(?)",
                    "DELETE FROM application_users WHERE id = ?")) {
                try (var s = c.prepareStatement(sql)) { s.setString(1, id); s.executeUpdate(); }
            }
            return null;
        });
    }
    private static void checkVersion(User user, long expected) {
        if (user.version() != expected) throw new Conflict("Account changed; reload before trying again");
    }
    private static void protectLastAdmin(Connection c, User user, boolean staysAdmin) throws SQLException {
        if (user.role() != Role.ADMIN || !user.status().equals("ACTIVE") || staysAdmin) return;
        try (var s = c.createStatement(); var r = s.executeQuery("SELECT COUNT(*) FROM application_users WHERE role = 'ADMIN' AND status = 'ACTIVE'")) {
            if (r.next() && r.getInt(1) <= 1) throw new Conflict("At least one active admin must remain");
        }
    }
    private static String validName(String value) {
        if (value == null) value = "";
        if (value.length() > 200 || value.chars().anyMatch(Character::isISOControl)) throw new IllegalArgumentException("Display name must be at most 200 characters without control characters");
        return value;
    }
    private static User find(Connection c, String id) throws SQLException {
        try (var s = c.prepareStatement("SELECT * FROM application_users WHERE id = ?")) {
            s.setString(1, id); try (var r = s.executeQuery()) {
                if (!r.next()) throw new SecurityException("Account unavailable"); return read(r);
            }
        }
    }
    private static User read(ResultSet r) throws SQLException {
        return new User(r.getString("id"), r.getString("display_name"), Role.valueOf(r.getString("role")),
                r.getString("status"), r.getString("created_at"), r.getString("last_used_at"), r.getLong("version"));
    }
    private static boolean exists(Connection c, String sql, String id) throws SQLException {
        try (var s = c.prepareStatement(sql)) { s.setString(1, id); try (var r = s.executeQuery()) { return r.next(); } }
    }
    private <T> T transaction(Operation<T> work) {
        try (var c = database.open(); var s = c.createStatement()) {
            s.execute("BEGIN IMMEDIATE");
            try { var result = work.run(c); s.execute("COMMIT"); return result; }
            catch (SQLException | RuntimeException e) { s.execute("ROLLBACK"); throw e; }
        } catch (SQLException e) { throw new StoreException("Could not update account", e); }
    }
    @FunctionalInterface private interface Operation<T> { T run(Connection c) throws SQLException; }
    public static final class Conflict extends RuntimeException { public Conflict(String message) { super(message); } }
}
