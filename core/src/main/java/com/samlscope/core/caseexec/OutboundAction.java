package com.samlscope.core.caseexec;

import java.net.URI;
import java.util.Objects;

public record OutboundAction(
        String actionId,
        OutboundKind kind,
        byte[] payload,
        URI target,
        boolean requiresEphemeralCredential,
        RequestSigning requestSigning) {

    public OutboundAction(
            String actionId,
            OutboundKind kind,
            byte[] payload,
            URI target,
            boolean requiresEphemeralCredential) {
        this(actionId, kind, payload, target, requiresEphemeralCredential, RequestSigning.PLAN_DEFAULT);
    }

    public OutboundAction {
        requireText(actionId, "actionId");
        Objects.requireNonNull(kind, "kind");
        payload = payload == null ? new byte[0] : payload.clone();
        Objects.requireNonNull(target, "target");
        requestSigning = requestSigning == null ? RequestSigning.PLAN_DEFAULT : requestSigning;
        if (!target.isAbsolute()) throw new IllegalArgumentException("target must be absolute");
        if (requestSigning != RequestSigning.PLAN_DEFAULT && kind != OutboundKind.AUTHN_REQUEST) {
            throw new IllegalArgumentException("Per-action request signing applies only to AuthnRequest actions");
        }
    }

    @Override
    public byte[] payload() {
        return payload.clone();
    }

    private static void requireText(String value, String name) {
        if (value == null || value.isBlank()) throw new IllegalArgumentException(name + " must not be blank");
    }

    /**
     * A narrowly scoped transport directive for approved fixtures that must compare signed and
     * unsigned AuthnRequests in one Run. Ordinary actions always inherit the Plan policy.
     */
    public enum RequestSigning {
        PLAN_DEFAULT,
        REQUIRE,
        OMIT_FOR_IDP12_B
    }
}
