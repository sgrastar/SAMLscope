package com.samlscope.core.caseexec;

/** Retry safety is fixed by Runner policy; individual cases cannot override it. */
public enum OutboundKind {
    METADATA_FETCH(Retry.SAFE),
    MDQ_FETCH(Retry.SAFE),
    AUTHN_REQUEST(Retry.UNSAFE),
    LOGOUT_REQUEST(Retry.UNSAFE),
    LOGOUT_PROBE(Retry.UNSAFE),
    ECP_SOAP(Retry.UNSAFE),
    SOAP_SLO(Retry.UNSAFE),
    ARTIFACT_RESOLVE(Retry.UNSAFE);

    private final Retry retry;

    OutboundKind(Retry retry) {
        this.retry = retry;
    }

    public Retry retry() {
        return retry;
    }

    public enum Retry { SAFE, UNSAFE }
}
