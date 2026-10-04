package com.samlscope.runner.cases;

import java.net.URI;
import java.util.Objects;

/** Public, nonsecret setup identity for one local outbox chain and its registered peer. */
public record RegisteredSignerProbeInputs(String localRunId,String otherRunId,String entity,
        URI destination,URI acs,String frameSha256) {
    public RegisteredSignerProbeInputs {
        Objects.requireNonNull(localRunId);Objects.requireNonNull(otherRunId);Objects.requireNonNull(entity);
        Objects.requireNonNull(destination);Objects.requireNonNull(acs);Objects.requireNonNull(frameSha256);
        if(localRunId.equals(otherRunId)||!localRunId.matches("run_[0-9A-HJKMNP-TV-Z]{26}")
                ||!otherRunId.matches("run_[0-9A-HJKMNP-TV-Z]{26}")||entity.isBlank()
                ||!destination.isAbsolute()||!acs.isAbsolute()||!frameSha256.matches("[0-9a-f]{64}"))
            throw new IllegalArgumentException("Invalid registered signer preparation identity");
    }
}
