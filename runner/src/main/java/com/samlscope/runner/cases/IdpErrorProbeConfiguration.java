package com.samlscope.runner.cases;

import java.net.URI;
import java.time.Duration;

public record IdpErrorProbeConfiguration(
        URI ssoEndpoint,
        String suiteIssuer,
        URI registeredAcs,
        Duration responseTimeout,
        boolean userAgentAvailable,
        boolean acceptableResponseLocationKnown,
        boolean freshSessionGateAvailable,
        java.util.List<java.security.PublicKey> encryptionKeys) {

    public IdpErrorProbeConfiguration(URI ssoEndpoint, String suiteIssuer, URI registeredAcs,
            Duration responseTimeout, boolean userAgentAvailable, boolean acceptableResponseLocationKnown,
            boolean freshSessionGateAvailable) {
        this(ssoEndpoint, suiteIssuer, registeredAcs, responseTimeout, userAgentAvailable,
                acceptableResponseLocationKnown, freshSessionGateAvailable, java.util.List.of());
    }

    public IdpErrorProbeConfiguration {
        encryptionKeys = java.util.List.copyOf(encryptionKeys);
        java.util.Objects.requireNonNull(ssoEndpoint, "ssoEndpoint");
        java.util.Objects.requireNonNull(registeredAcs, "registeredAcs");
        java.util.Objects.requireNonNull(responseTimeout, "responseTimeout");
        if (!ssoEndpoint.isAbsolute() || !registeredAcs.isAbsolute()) {
            throw new IllegalArgumentException("Probe endpoints must be absolute");
        }
        if (suiteIssuer == null || suiteIssuer.isBlank()) throw new IllegalArgumentException("suiteIssuer must not be blank");
        if (responseTimeout.isZero() || responseTimeout.isNegative()) {
            throw new IllegalArgumentException("responseTimeout must be positive");
        }
    }

    public boolean preconditionsSatisfied() {
        return userAgentAvailable && acceptableResponseLocationKnown && freshSessionGateAvailable;
    }
}
