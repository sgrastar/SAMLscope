package com.samlscope.peer.sp;

import java.net.URI;
import java.time.Clock;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import com.samlscope.core.plan.PlanRepository;
import com.samlscope.core.plan.TargetRole;
import com.samlscope.core.run.Reachability;
import com.samlscope.core.run.RunRepository;
import com.samlscope.core.run.RunStatus;
import com.samlscope.core.transcript.Direction;
import com.samlscope.core.transcript.TranscriptInput;
import com.samlscope.core.transcript.TranscriptRecorder;
import com.samlscope.runner.RunService;
import com.samlscope.runner.ActiveProbeCorrelation;
import com.samlscope.runner.TargetInitiatedIntents;
import com.samlscope.core.evaluation.EvidenceRef;
import com.samlscope.saml.metadata.MetadataService;
import com.samlscope.saml.metadata.TargetMetadataParser;
import com.samlscope.saml.normal.SamlException;
import com.samlscope.saml.normal.SamlProtocolService;
import com.samlscope.store.MetadataCache;

public final class SpPeerService {
    private final PlanRepository plans;
    private final RunRepository runs;
    private final RunService runService;
    private final MetadataCache metadataCache;
    private final TargetMetadataParser metadataParser;
    private final SamlProtocolService saml;
    private final TranscriptRecorder transcript;
    private final Clock clock;
    private final ActiveProbeResponseHandler activeProbeResponses;
    private final TargetInitiatedIntents targetInitiated;

    public SpPeerService(PlanRepository plans, RunRepository runs, RunService runService,
                         MetadataCache metadataCache, TargetMetadataParser metadataParser,
                         SamlProtocolService saml, TranscriptRecorder transcript, Clock clock) {
        this(plans, runs, runService, metadataCache, metadataParser, saml, transcript, clock,
                (runId, actionId, decodedSaml, evidence) -> { });
    }

    public SpPeerService(PlanRepository plans, RunRepository runs, RunService runService,
                         MetadataCache metadataCache, TargetMetadataParser metadataParser,
                         SamlProtocolService saml, TranscriptRecorder transcript, Clock clock,
                         ActiveProbeResponseHandler activeProbeResponses) {
        this(plans, runs, runService, metadataCache, metadataParser, saml, transcript, clock,
                activeProbeResponses, new TargetInitiatedIntents());
    }

    public SpPeerService(PlanRepository plans, RunRepository runs, RunService runService,
                         MetadataCache metadataCache, TargetMetadataParser metadataParser,
                         SamlProtocolService saml, TranscriptRecorder transcript, Clock clock,
                         ActiveProbeResponseHandler activeProbeResponses,
                         TargetInitiatedIntents targetInitiated) {
        this.plans = plans;
        this.runs = runs;
        this.runService = runService;
        this.metadataCache = metadataCache;
        this.metadataParser = metadataParser;
        this.saml = saml;
        this.transcript = transcript;
        this.clock = clock;
        this.activeProbeResponses = java.util.Objects.requireNonNull(
                activeProbeResponses, "activeProbeResponses");
        this.targetInitiated = java.util.Objects.requireNonNull(targetInitiated, "targetInitiated");
    }

    public URI start(String planId, String runId) {
        var plan = plans.find(planId).orElseThrow(() -> new IllegalArgumentException("Unknown Test Plan"));
        if (plan.profile().role() != TargetRole.IDP) throw new IllegalArgumentException("This plan does not test an IdP");
        var run = runs.find(runId).orElseThrow(() -> new IllegalArgumentException("Unknown Run"));
        if (!run.planId().equals(planId)) throw new IllegalArgumentException("Run belongs to another Test Plan");
        var metadata = metadataParser.parse(
                metadataCache.getRunSnapshot(run.id(), plan.id()), plan.target().entityId());
        var destination = metadata.singleSignOnServices().stream()
                .filter(endpoint -> MetadataService.REDIRECT.equals(endpoint.binding()))
                .findFirst()
                .or(() -> metadata.singleSignOnServices().stream().findFirst())
                .orElseThrow(() -> new SamlException("Target metadata has no SingleSignOnService"))
                .location();
        var message = saml.buildAuthnRequest(plan, destination, run.id());
        var context = new LinkedHashMap<String, Object>(run.context());
        context.put("authnRequestId", message.id());
        context.put("authnRequestDestination", destination.toString());
        runService.update(run, RunStatus.WAITING_BROWSER, run.targetToSuiteReachability(), context);
        transcript.record(new TranscriptInput(run.id(), Direction.OUTBOUND, clock.instant(), message.id(), "GET",
                message.redirect().toString(), null, Map.of(), new byte[0], null,
                message.redirect().getRawQuery(), message.xml(), Map.of("type", "AuthnRequest", "id", message.id())));
        return message.redirect();
    }

    public Map<String, Object> consume(String planId, byte[] rawBody, Map<String, List<String>> headers, String requestUrl) {
        return consumeDetailed(planId, rawBody, headers, requestUrl).summary();
    }

    public ConsumeResult consumeDetailed(
            String planId, byte[] rawBody, Map<String, List<String>> headers, String requestUrl) {
        return consumeRaw(
                planId, saml.decodePostRaw(rawBody, "SAMLResponse"), "POST", rawBody,
                "application/x-www-form-urlencoded", null, headers, requestUrl);
    }

    /** Records a Redirect-bound Response without reconstructing its signature-covered query. */
    public ConsumeResult consumeRedirectDetailed(
            String planId, String rawQuery, Map<String, List<String>> headers, String requestUrl) {
        if (rawQuery == null || rawQuery.isBlank()) throw new SamlException("Redirect Response has no query");
        return consumeRaw(
                planId, saml.decodeRedirectRaw(rawQuery, "SAMLResponse"), "GET", new byte[0],
                null, rawQuery, headers, requestUrl);
    }

    private ConsumeResult consumeRaw(
            String planId,
            SamlProtocolService.RawDecodedMessage rawMessage,
            String method,
            byte[] rawBody,
            String contentType,
            String rawQuery,
            Map<String, List<String>> headers,
            String requestUrl) {
        var variant = queryParameter(requestUrl, "mdv");
        var correlatedRun = queryParameter(requestUrl, "run");
        var metadataProbe = variant != null && correlatedRun != null;
        var activeProbe = ActiveProbeCorrelation.parse(rawMessage.relayState());
        var runId = activeProbe.map(ActiveProbeCorrelation.Value::runId)
                .orElse(metadataProbe ? correlatedRun : rawMessage.relayState());
        var unsolicitedByPlan = false;
        if (runId == null && !metadataProbe && activeProbe.isEmpty()) {
            // Some targets do not return a RelayState for an IdP-initiated message. Accept it
            // only when exactly one Run of this Plan has prepared the single-use intent.
            var intent = targetInitiated.peekPlan(planId, TargetInitiatedIntents.Kind.UNSOLICITED_SSO, clock);
            if (intent.isPresent()) {
                runId = intent.orElseThrow().runId();
                unsolicitedByPlan = true;
            }
        }
        if (runId == null) throw new SamlException("SAMLResponse has no RelayState correlation");
        var run = runs.find(runId).orElseThrow(() -> new SamlException("Unknown RelayState"));
        if (!run.planId().equals(planId)) throw new SamlException("RelayState belongs to another Test Plan");
        var transcriptCorrelation = activeProbe.map(ActiveProbeCorrelation.Value::actionId).orElse(run.id());
        var transcriptEntry = transcript.record(new TranscriptInput(run.id(), Direction.INBOUND, clock.instant(), transcriptCorrelation, method,
                requestUrl, 200, headers, rawBody, contentType, rawQuery,
                rawMessage.xml(), Map.of("type", "SAMLResponse", "parseStatus", "not-yet-parsed")));
        com.samlscope.saml.normal.SamlProtocolService.DecodedMessage message;
        try {
            message = saml.parse(rawMessage);
        } catch (SamlException malformed) {
            if (activeProbe.isEmpty()) throw malformed;
            var summary = Map.<String, Object>of(
                    "parseStatus", "error",
                    "errorCategory", "malformed-saml-response");
            transcript.updateSamlAnalysis(transcriptEntry.id(), transcriptCorrelation, summary);
            activeProbeResponses.accept(
                    run.id(), activeProbe.orElseThrow().actionId(), rawMessage.xml(),
                    new EvidenceRef("transcript", transcriptEntry.id()));
            return new ConsumeResult(
                    summary,
                    activeProbe.orElseThrow().runId(),
                    activeProbe.orElseThrow().actionId(),
                    null, null, rawMessage.relayState(), run.id());
        }
        var expected = String.valueOf(run.context().getOrDefault("authnRequestId", ""));
        var actual = String.valueOf(message.parsed().summary().getOrDefault("inResponseTo", ""));
        var analyzedSummary = new LinkedHashMap<String, Object>(message.parsed().summary());
        var unsolicitedAccepted = false;
        if (activeProbe.isPresent()) {
            // Active browser scenarios use a request ID derived from the action ID. This is
            // protocol correlation evidence only; the scenario case remains the owner of the
            // target outcome, and other oracles must explicitly opt in before reusing it.
            analyzedSummary.put(
                    "activeProbeAccepted",
                    ("_" + activeProbe.orElseThrow().actionId()).equals(actual));
        } else if (metadataProbe) {
            // The Run and fixture are correlated by the Suite-generated ACS URL. This flag says
            // only that a syntactically valid SAML Response reached that controlled endpoint; it
            // does not claim that the target accepted metadata or satisfied any obligation.
            analyzedSummary.put("metadataProbeAccepted",
                    matchesMetadataProbeRequest(run.context(), variant, actual));
        } else {
            var correlated = !expected.isBlank() && expected.equals(actual);
            var relayMatched = run.id().equals(message.relayState());
            if (!correlated && actual.isBlank() && (relayMatched || unsolicitedByPlan)
                    && unsolicitedResponseAllowed(run, planId, requestUrl, message, relayMatched)) {
                // Explicitly prepared IdP-initiated check. The intent is single use and the
                // message must still carry the run-specific RelayState, the target Issuer and
                // the exact ACS Destination.
                unsolicitedAccepted = true;
                analyzedSummary.put("unsolicited", true);
            }
            analyzedSummary.put("normalFlowAccepted", correlated || unsolicitedAccepted);
        }
        transcript.updateSamlAnalysis(transcriptEntry.id(), actual, analyzedSummary);
        if (!metadataProbe && activeProbe.isEmpty() && !unsolicitedAccepted
                && (expected.isBlank() || !expected.equals(actual))) {
            throw new SamlException("SAMLResponse InResponseTo does not match the active AuthnRequest");
        }
        if (activeProbe.isPresent()) {
            activeProbeResponses.accept(
                    run.id(), activeProbe.orElseThrow().actionId(), rawMessage.xml(),
                    new EvidenceRef("transcript", transcriptEntry.id()));
        } else if (metadataProbe && Boolean.TRUE.equals(analyzedSummary.get("metadataProbeAccepted"))
                && actual.equals(run.context().get("active_metadata_request_id"))
                && run.status() == RunStatus.WAITING_BROWSER) {
            // Completing this correlated exchange releases the browser wait. The next
            // campaign member enters WAITING_BROWSER when dispatched; this is no verdict.
            runService.update(run, RunStatus.COMPLETED, run.targetToSuiteReachability(), run.context());
        } else if (!metadataProbe) {
            var context = new LinkedHashMap<String, Object>(run.context());
            context.put("m0RoundTrip", "completed");
            context.put("responseSummary", message.parsed().summary());
            runService.update(run, RunStatus.COMPLETED, run.targetToSuiteReachability(), context);
        }
        return new ConsumeResult(
                analyzedSummary,
                activeProbe.map(ActiveProbeCorrelation.Value::runId).orElse(null),
                activeProbe.map(ActiveProbeCorrelation.Value::actionId).orElse(null),
                metadataProbe ? correlatedRun : null,
                metadataProbe ? variant : null,
                rawMessage.relayState(), run.id());
    }

    private boolean unsolicitedResponseAllowed(
            com.samlscope.core.run.TestRun run, String planId, String requestUrl,
            SamlProtocolService.DecodedMessage message, boolean relayMatched) {
        if (message.relayState() != null && !relayMatched) return false;
        var plan = plans.find(planId).orElse(null);
        if (plan == null || !plan.target().entityId().equals(
                String.valueOf(message.parsed().summary().getOrDefault("issuer", "")))) return false;
        if (!"urn:oasis:names:tc:SAML:2.0:status:Success".equals(
                String.valueOf(message.parsed().summary().getOrDefault("statusCode", "")))) return false;
        var destination = String.valueOf(message.parsed().summary().getOrDefault("destination", ""));
        if (destination.isBlank() || !sameOriginAndPath(destination, requestUrl)) return false;
        return targetInitiated.consumeForRun(run.id(), TargetInitiatedIntents.Kind.UNSOLICITED_SSO, clock);
    }

    private static boolean sameOriginAndPath(String left, String right) {
        if (right.isBlank()) return false;
        try {
            var a = URI.create(left);
            var b = URI.create(right);
            return a.getScheme() != null && a.getScheme().equals(b.getScheme())
                    && a.getHost() != null && a.getHost().equals(b.getHost())
                    && Objects.equals(a.getPort(), b.getPort())
                    && a.getRawPath().equals(b.getRawPath());
        } catch (RuntimeException invalid) {
            return false;
        }
    }

    private boolean matchesMetadataProbeRequest(
            Map<String, Object> context, String variant, String actual) {
        if (actual == null || actual.isBlank()) return false;
        // Both ingestion modes may have issued this variant in the same Run. An older
        // preloaded request must not shadow a later polling request (or vice versa).
        // Only the active request may release the browser wait; that check is separate.
        for (var key : java.util.List.of("metadata_preloaded_requests", "metadata_polling_requests")) {
            var value = context.get(key);
            if (!(value instanceof Map<?, ?> requests)) continue;
            if (actual.equals(requests.get(variant))) return true;
        }
        return false;
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

    @FunctionalInterface
    public interface ActiveProbeResponseHandler {
        void accept(String runId, String actionId, byte[] decodedSaml, EvidenceRef evidence);
    }

    public record ConsumeResult(
            Map<String, Object> summary,
            String activeProbeRunId,
            String activeProbeActionId,
            String metadataProbeRunId,
            String metadataProbeVariant,
            String relayState,
            String runId) {
        public ConsumeResult { summary = Map.copyOf(summary); }
        public boolean activeProbe() { return activeProbeRunId != null; }
        public boolean metadataProbe() { return metadataProbeRunId != null; }
    }
}
