package com.samlscope.api;

import io.javalin.config.JavalinConfig;
import java.util.Objects;
import java.util.function.Function;
import com.samlscope.runner.ProtocolEvidenceAutomationService;

/** Readiness and evaluation endpoints for cases backed by recorded protocol evidence. */
public final class ProtocolEvidenceRoutes {
    private ProtocolEvidenceRoutes() {}

    public static void register(
            JavalinConfig javalin,
            Function<String, ProtocolEvidenceAutomationService.Status> status,
            java.util.function.BiFunction<String, byte[], ProtocolEvidenceAutomationService.Evaluation> evaluate,
            Function<String, ProtocolEvidenceAutomationService.Evaluation> confirmAttempts) {
        Objects.requireNonNull(javalin, "javalin");
        Objects.requireNonNull(status, "status");
        Objects.requireNonNull(evaluate, "evaluate");
        Objects.requireNonNull(confirmAttempts, "confirmAttempts");
        javalin.routes.get("/api/runs/{id}/protocol-evidence", ctx ->
                ctx.json(status.apply(ctx.pathParam("id"))));
        javalin.routes.post("/api/runs/{id}/protocol-evidence/evaluate", ctx -> {
            ctx.header("Cache-Control", "no-store");
            byte[] key = sharedKey(ctx.body());
            try { ctx.json(evaluate.apply(ctx.pathParam("id"), key)); }
            finally { if (key != null) java.util.Arrays.fill(key, (byte) 0); }
        });
        javalin.routes.post("/api/runs/{id}/protocol-evidence/confirm-attempts", ctx ->
                ctx.json(confirmAttempts.apply(ctx.pathParam("id"))));
    }
    static byte[] sharedKey(String body) {
        if (body == null || body.isBlank()) return null;
        // Never include the request body or decoder exceptions in errors or diagnostic output.
        try {
            var values = new com.fasterxml.jackson.databind.ObjectMapper().readTree(body);
            if (!values.isObject()) throw new IllegalArgumentException();
            if (values.isEmpty()) return null;
            if (values.size() != 1 || !values.has("sharedKeyBase64") || !values.get("sharedKeyBase64").isTextual())
                throw new IllegalArgumentException();
            String encoded = values.get("sharedKeyBase64").textValue();
            if (encoded.length() > 44) throw new IllegalArgumentException();
            byte[] key = java.util.Base64.getDecoder().decode(encoded);
            if (key.length == 16 || key.length == 24 || key.length == 32) return key;
            java.util.Arrays.fill(key, (byte) 0);
        } catch (Exception invalid) { /* Return only a fixed message. */ }
        throw new IllegalArgumentException("Expected an AES sharedKeyBase64 input or an empty object");
    }
}
