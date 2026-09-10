package com.samlscope.store;

import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import com.samlscope.core.plan.PlanRepository;
import com.samlscope.core.plan.TestPlan;

public final class SqlitePlanRepository implements PlanRepository {
    private final SqliteDatabase database;
    private final JsonCodec json;

    public SqlitePlanRepository(SqliteDatabase database, JsonCodec json) {
        this.database = database;
        this.json = json;
    }

    @Override
    public List<TestPlan> list() {
        var plans = new ArrayList<TestPlan>();
        try (var connection = database.open();
             var statement = connection.prepareStatement("SELECT document_json FROM plans ORDER BY created_at DESC");
             var rows = statement.executeQuery()) {
            while (rows.next()) plans.add(json.read(rows.getString(1), TestPlan.class));
            return List.copyOf(plans);
        } catch (SQLException e) {
            throw new StoreException("Could not list plans", e);
        }
    }

    @Override
    public Optional<TestPlan> find(String id) {
        try (var connection = database.open();
             var statement = connection.prepareStatement("SELECT document_json FROM plans WHERE id = ?")) {
            statement.setString(1, id);
            try (var rows = statement.executeQuery()) {
                return rows.next() ? Optional.of(json.read(rows.getString(1), TestPlan.class)) : Optional.empty();
            }
        } catch (SQLException e) {
            throw new StoreException("Could not load plan", e);
        }
    }

    @Override
    public void save(TestPlan plan) {
        var sql = """
                INSERT INTO plans(id, document_json, created_at, updated_at) VALUES(?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET document_json=excluded.document_json, updated_at=excluded.updated_at
                WHERE COALESCE(json_extract(plans.document_json, '$.parameters.requestSigningMode'), 'OPTIONAL')
                    = COALESCE(json_extract(excluded.document_json, '$.parameters.requestSigningMode'), 'OPTIONAL')
                """;
        try (var connection = database.open(); var transaction = connection.createStatement()) {
            transaction.execute("BEGIN IMMEDIATE");
            try {
                try (var query = connection.prepareStatement(
                        "SELECT document_json FROM plans WHERE id = ?")) {
                    query.setString(1, plan.id());
                    try (var rows = query.executeQuery()) {
                        if (rows.next()) PlanWritePolicy.requireAllowed(
                                connection, json.read(rows.getString(1), TestPlan.class), plan);
                    }
                }
                try (var statement = connection.prepareStatement(sql)) {
                    statement.setString(1, plan.id());
                    statement.setString(2, json.write(plan));
                    statement.setString(3, plan.createdAt().toString());
                    statement.setString(4, plan.updatedAt().toString());
                    statement.executeUpdate();
                }
                transaction.execute("COMMIT");
            } catch (SQLException | RuntimeException error) {
                try { transaction.execute("ROLLBACK"); }
                catch (SQLException rollback) { error.addSuppressed(rollback); }
                throw error;
            }
        } catch (SQLException e) {
            throw new StoreException("Could not save plan", e);
        }
    }

    @Override
    public boolean delete(String id) {
        try (var connection = database.open(); var statement = connection.prepareStatement("DELETE FROM plans WHERE id = ?")) {
            statement.setString(1, id);
            return statement.executeUpdate() == 1;
        } catch (SQLException e) {
            throw new StoreException("Could not delete plan", e);
        }
    }
}
