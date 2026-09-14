package com.samlscope.store;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.Path;
import java.time.Instant;
import static org.junit.jupiter.api.Assertions.*;
import static com.samlscope.store.SqliteUserRepository.Role.*;

class SqliteUserRepositoryTest {
    @TempDir Path data;
    final Instant now = Instant.parse("2026-09-11T00:00:00Z");
    final String alice = "oidc:" + "a".repeat(64), bob = "oidc:" + "b".repeat(64);
    @Test void loginDoesNotExtendActivityOrOverwriteLocalRolesAndProfiles() {
        var users = new SqliteUserRepository(new SqliteDatabase(data));
        var enrolled = users.enroll(alice, "Alice", true, now);
        assertEquals(ADMIN, enrolled.role()); assertNull(enrolled.lastUsedAt());
        users.enroll(bob, "Bob", true, now);
        var updated = users.update(alice, "Local name", ANONYMOUS, 0, now);
        assertEquals(now.toString(), updated.lastUsedAt());
        users.enroll(alice, "Provider name", true, now.plusSeconds(100));
        var persisted = new SqliteUserRepository(new SqliteDatabase(data)).requireActive(alice);
        assertEquals(ANONYMOUS, persisted.role()); assertEquals("Local name", persisted.displayName());
        assertEquals(now.toString(), persisted.lastUsedAt());
        users.touch(alice, now.plusSeconds(200));
        assertEquals(now.plusSeconds(200).toString(), users.find(alice).lastUsedAt());
        assertThrows(SqliteUserRepository.Conflict.class, () -> users.update(alice, "Stale", ADMIN, 0, now));
        users.update(alice, "Registered", USER, 1, now.plusSeconds(300));
        assertEquals(USER, users.find(alice).role());
    }
    @Test void editingAMigratedOwnerBeforeFirstLoginPreservesTheAdminDecision() throws Exception {
        var db = new SqliteDatabase(data);
        try (var c = db.open(); var s = c.prepareStatement("INSERT INTO application_users(id, role, created_at) VALUES(?, 'USER', ?)")) {
            s.setString(1, alice); s.setString(2, now.toString()); s.executeUpdate();
        }
        var users = new SqliteUserRepository(db);
        users.update(alice, "Reviewed account", ANONYMOUS, 0, now);
        users.enroll(alice, "Provider name", true, now.plusSeconds(10));
        assertEquals(ANONYMOUS, users.find(alice).role());
        assertEquals("Reviewed account", users.find(alice).displayName());
    }
    @Test void interruptedAdminDeletionCanBeRetriedWhileAnotherAdminRemains() {
        var users = new SqliteUserRepository(new SqliteDatabase(data));
        users.enroll(alice, "Admin A", true, now);
        users.enroll(bob, "Admin B", true, now);
        users.beginDeletion(alice, 0);
        users.beginDeletion(alice, 0);
        users.finishDeletion(alice);
        assertEquals(ADMIN, users.requireActive(bob).role());
    }
    @Test void lastAdminAndDeletedIdentityAreProtected() {
        var users = new SqliteUserRepository(new SqliteDatabase(data));
        users.enroll(alice, "Admin", true, now);
        assertThrows(SqliteUserRepository.Conflict.class, () -> users.beginDeletion(alice, 0));
        assertThrows(SqliteUserRepository.Conflict.class, () -> users.update(alice, "Admin", USER, 0, now));
        users.enroll(bob, "Bob", false, now);
        users.beginDeletion(bob, 0);
        assertThrows(SecurityException.class, () -> users.requireActive(bob));
        assertThrows(SecurityException.class, () -> users.enroll(bob, "Bob", false, now));
        users.finishDeletion(bob);
        assertEquals(1, users.list().size());
        assertThrows(SecurityException.class, () -> users.enroll(bob, "Bob", true, now));
    }
}
