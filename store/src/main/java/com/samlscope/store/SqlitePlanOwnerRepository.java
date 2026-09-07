package com.samlscope.store;

import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

/** Reads the persisted owner fingerprint. Only an OIDC-derived identity can authorize an account. */
public final class SqlitePlanOwnerRepository {
    private final SqliteDatabase database;
    public SqlitePlanOwnerRepository(SqliteDatabase database) { this.database = database; }
    public List<String> ownedPlans(String oidcOwnerId) {
        if (oidcOwnerId == null || !oidcOwnerId.matches("oidc:[0-9a-f]{64}")) {
            throw new IllegalArgumentException("An OIDC owner fingerprint is required");
        }
        try (var connection = database.open();
             var statement = connection.prepareStatement("SELECT plan_id FROM hosted_plan_owners WHERE owner_id = ?")) {
            statement.setString(1, oidcOwnerId);
            try (var rows = statement.executeQuery()) {
                var result = new ArrayList<String>();
                while (rows.next()) result.add(rows.getString(1));
                return List.copyOf(result);
            }
        } catch (SQLException error) {
            throw new StoreException("Could not read owned Plans", error);
        }
    }
}
