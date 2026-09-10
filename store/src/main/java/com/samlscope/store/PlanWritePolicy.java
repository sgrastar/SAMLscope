package com.samlscope.store;

import com.samlscope.core.plan.PlanConfigurationConflict;
import com.samlscope.core.plan.TestPlan;
import java.sql.Connection;
import java.sql.SQLException;

/** Enforces Plan immutability inside the transaction serialized with Run creation. */
final class PlanWritePolicy {
    private PlanWritePolicy() {}

    static void requireAllowed(Connection connection, TestPlan existing, TestPlan updated)
            throws SQLException {
        if (!existing.id().equals(updated.id()) || !existing.createdAt().equals(updated.createdAt())) {
            throw new IllegalArgumentException("Plan identity is fixed");
        }
        if (!existing.sameExecutionConfiguration(updated)) {
            try (var query = connection.prepareStatement(
                    "SELECT 1 FROM runs WHERE plan_id = ? LIMIT 1")) {
                query.setString(1, existing.id());
                try (var rows = query.executeQuery()) {
                    if (rows.next()) throw new PlanConfigurationConflict();
                }
            }
        }
        if (existing.parameters().requestSigningMode()
                != updated.parameters().requestSigningMode()) {
            throw new IllegalArgumentException(
                    "Request signing mode is fixed; create a separate Test Plan");
        }
        if (existing.target().connectionId() != null && !existing.target().equals(updated.target())) {
            throw new IllegalArgumentException(
                    "Create a new Plan to change its metadata revision");
        }
    }
}
