package com.samlscope.runner.cases;

import com.fasterxml.jackson.databind.JsonNode;
import com.samlscope.core.caseexec.CaseContext;
import java.nio.file.Path;
import java.time.Instant;
import org.w3c.dom.Element;

/**
 * Product-native setup and observation checks for the shared role/key campaign.
 * The common reader owns all fixture, signature, decryption, correlation and control checks.
 * A session must validate original-backed native state, its restoration, and each actual
 * request-bound product observation; parser acceptance or an HTTP status alone is insufficient.
 */
public interface MetadataRoleKeyNativeAdapter {
    String adapter();

    Session open(CaseContext context, Path folder, JsonNode manifest, String entity) throws Exception;

    enum Disposition { NORMAL_SUCCESS, SIGNATURE_REJECTED, CROSS_ROLE_SUCCESS }

    interface Session {
        Instant validateEpoch(JsonNode row, byte[] fixture, Element peer,
                Instant startedAt, Instant completedAt) throws Exception;

        void validateExchange(JsonNode row, JsonNode exchange, Element request,
                byte[] requestBytes, JsonNode http, Instant preparedAt,
                Instant startedAt, Instant completedAt, Disposition disposition) throws Exception;
    }
}
