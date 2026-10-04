package com.samlscope.runner.cases;

import java.net.URI;
import java.util.List;
import java.util.Objects;

/** Public session material reconstructed from an authenticated, same-Run SAML assertion. */
public record SloRegisteredSignerProbeInputs(String localRunId, String otherRunId, String entity,
        URI destination, URI responseEndpoint, byte[] nameIdXml, List<String> sessionIndexes,
        String preparationSha256) {
    public SloRegisteredSignerProbeInputs {
        Objects.requireNonNull(localRunId); Objects.requireNonNull(otherRunId); Objects.requireNonNull(entity);
        Objects.requireNonNull(destination); Objects.requireNonNull(responseEndpoint);
        nameIdXml = Objects.requireNonNull(nameIdXml).clone();
        sessionIndexes = List.copyOf(sessionIndexes);
        if (!localRunId.matches("run_[0-9A-HJKMNP-TV-Z]{26}")
                || !otherRunId.matches("run_[0-9A-HJKMNP-TV-Z]{26}") || localRunId.equals(otherRunId)
                || entity.isBlank() || !destination.isAbsolute() || !responseEndpoint.isAbsolute()
                || nameIdXml.length == 0 || sessionIndexes.isEmpty() || sessionIndexes.stream().anyMatch(String::isBlank)
                || !preparationSha256.matches("[0-9a-f]{64}"))
            throw new IllegalArgumentException("Unproven registered SLO session");
    }
    @Override public byte[] nameIdXml() { return nameIdXml.clone(); }
}
