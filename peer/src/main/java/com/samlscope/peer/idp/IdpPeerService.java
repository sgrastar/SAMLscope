package com.samlscope.peer.idp;

import java.net.URI;
import java.time.Clock;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import com.samlscope.core.plan.PlanRepository;
import com.samlscope.core.plan.TargetRole;
import com.samlscope.core.run.RunRepository;
import com.samlscope.core.run.RunStatus;
import com.samlscope.core.run.TestRun;
import com.samlscope.core.transcript.Direction;
import com.samlscope.core.transcript.TranscriptInput;
import com.samlscope.core.transcript.TranscriptRecorder;
import com.samlscope.runner.RunService;
import com.samlscope.saml.metadata.TargetMetadataParser;
import com.samlscope.saml.normal.SamlException;
import com.samlscope.saml.normal.SamlProtocolService;
import com.samlscope.store.MetadataCache;

public final class IdpPeerService {
    private final PlanRepository plans;
    private final RunRepository runs;
    private final RunService runService;
    private final MetadataCache metadataCache;
    private final TargetMetadataParser metadataParser;
    private final SamlProtocolService saml;
    private final TranscriptRecorder transcript;
    private final Clock clock;
    private final boolean secondary;
    private final java.util.function.Consumer<String> receiptExecutionPolicy;

    public IdpPeerService(PlanRepository plans, RunRepository runs, RunService runService,
                          MetadataCache metadataCache, TargetMetadataParser metadataParser,
                          SamlProtocolService saml, TranscriptRecorder transcript, Clock clock) {
        this(plans, runs, runService, metadataCache, metadataParser, saml, transcript, clock, false);
    }

    public IdpPeerService(PlanRepository plans, RunRepository runs, RunService runService,
                          MetadataCache metadataCache, TargetMetadataParser metadataParser,
                          SamlProtocolService saml, TranscriptRecorder transcript, Clock clock,
                          boolean secondary) {
        this(plans, runs, runService, metadataCache, metadataParser, saml, transcript, clock,
                secondary, runId -> { });
    }

    public IdpPeerService(PlanRepository plans, RunRepository runs, RunService runService,
                          MetadataCache metadataCache, TargetMetadataParser metadataParser,
                          SamlProtocolService saml, TranscriptRecorder transcript, Clock clock,
                          boolean secondary, java.util.function.Consumer<String> receiptExecutionPolicy) {
        this.plans = plans;
        this.runs = runs;
        this.runService = runService;
        this.metadataCache = metadataCache;
        this.metadataParser = metadataParser;
        this.saml = saml;
        this.transcript = transcript;
        this.clock = clock;
        this.secondary = secondary;
        this.receiptExecutionPolicy = java.util.Objects.requireNonNull(receiptExecutionPolicy, "receiptExecutionPolicy");
    }

    public SamlProtocolService.ResponseMessage consume(
            String planId, String method, String rawQuery, byte[] rawBody,
            Map<String, List<String>> headers, String requestUrl) {
        var plan = plans.find(planId).orElseThrow(() -> new IllegalArgumentException("Unknown Test Plan"));
        if (plan.profile().role() != TargetRole.SP) throw new IllegalArgumentException("This plan does not test an SP");
        var variant = queryParameter(requestUrl, "mdv");
        var correlatedRun = queryParameter(requestUrl, "run");
        var probe = variant != null && correlatedRun != null;
        var run = probe ? requireRun(planId, correlatedRun) : activeRun(planId);
        var rawRequest = "GET".equalsIgnoreCase(method)
                ? saml.decodeRedirectRaw(rawQuery, "SAMLRequest")
                : saml.decodePostRaw(rawBody, "SAMLRequest");
        var transcriptEntry = transcript.record(new TranscriptInput(run.id(), Direction.INBOUND, clock.instant(), run.id(),
                method, requestUrl, 200, headers, rawBody,
                "GET".equalsIgnoreCase(method) ? null : "application/x-www-form-urlencoded",
                rawQuery, rawRequest.xml(), Map.of("type", "SAMLRequest", "parseStatus", "not-yet-parsed")));
        var request = saml.parse(rawRequest);
        var requestRoot = request.parsed().document().getDocumentElement();
        transcript.updateSamlAnalysis(
                transcriptEntry.id(), requestRoot.getAttribute("ID"), request.parsed().summary());
        // A late historical request remains recorded; it must not issue a new signed response.
        receiptExecutionPolicy.accept(run.id());
        var metadata = metadataParser.parse(
                metadataCache.getRunSnapshot(run.id(), plan.id()), plan.target().entityId());
        var requestedAcs = requestRoot.getAttribute("AssertionConsumerServiceURL");
        URI acs;
        if (!requestedAcs.isBlank()) {
            acs = URI.create(requestedAcs);
            var registered = metadata.assertionConsumerServices().stream()
                    .anyMatch(endpoint -> endpoint.location().equals(acs));
            if (!registered) throw new SamlException("AuthnRequest ACS is not registered in target metadata");
        } else {
            acs = metadata.assertionConsumerServices().stream()
                    .filter(TargetMetadataParserEndpoint::isPreferred)
                    .findFirst()
                    .or(() -> metadata.assertionConsumerServices().stream().findFirst())
                    .orElseThrow(() -> new SamlException("Target metadata has no AssertionConsumerService"))
                    .location();
        }
        var response = secondary
                ? saml.buildSecondaryIdpResponse(plan, request, acs, "samlscope-m0-user")
                : saml.buildResponse(plan, request, acs, "samlscope-m0-user");
        transcript.record(new TranscriptInput(run.id(), Direction.OUTBOUND, clock.instant(), response.id(), "POST",
                acs.toString(), null, Map.of(), new byte[0], "application/x-www-form-urlencoded", null,
                response.xml(), Map.of("type", "Response", "id", response.id(), "destination", acs.toString())));
        if (!probe) {
            var context = new LinkedHashMap<String, Object>(run.context());
            context.put("m0RoundTrip", "response-issued");
            context.put("requestSummary", request.parsed().summary());
            runService.update(run, RunStatus.COMPLETED, run.targetToSuiteReachability(), context);
        }
        return response;
    }

    private TestRun requireRun(String planId, String runId) {
        var run = runs.find(runId).orElseThrow(() -> new SamlException("Unknown correlated Run"));
        if (!planId.equals(run.planId())) throw new SamlException("Correlated Run belongs to another Test Plan");
        return run;
    }

    private TestRun activeRun(String planId) {
        return runs.listForPlan(planId).stream()
                .filter(run -> run.status() != RunStatus.COMPLETED && run.status() != RunStatus.ABORTED)
                .findFirst()
                .orElseThrow(() -> new SamlException("Create a Run before starting login at the target SP"));
    }

    private String queryParameter(String requestUrl, String name) {
        var query = URI.create(requestUrl).getRawQuery();
        if (query == null) return null;
        for (var part : query.split("&")) {
            var separator = part.indexOf('=');
            var key = separator < 0 ? part : part.substring(0, separator);
            if (name.equals(java.net.URLDecoder.decode(key, java.nio.charset.StandardCharsets.UTF_8))) {
                return separator < 0 ? "" : java.net.URLDecoder.decode(
                        part.substring(separator + 1), java.nio.charset.StandardCharsets.UTF_8);
            }
        }
        return null;
    }

    private static final class TargetMetadataParserEndpoint {
        private static boolean isPreferred(com.samlscope.saml.metadata.TargetMetadata.Endpoint endpoint) {
            return endpoint.isDefault() || Integer.valueOf(0).equals(endpoint.index());
        }
    }
}
