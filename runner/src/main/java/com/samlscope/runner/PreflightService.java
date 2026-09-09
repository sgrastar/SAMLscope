package com.samlscope.runner;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.ByteArrayOutputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Clock;
import java.time.Duration;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.Map;
import com.samlscope.core.plan.MetadataSourceKind;
import com.samlscope.core.plan.PlanRepository;
import com.samlscope.core.run.PreflightReport;
import com.samlscope.core.run.Reachability;
import com.samlscope.core.run.RunRepository;
import com.samlscope.core.run.RunStatus;
import com.samlscope.saml.metadata.TargetMetadataParser;
import com.samlscope.store.MetadataCache;

public final class PreflightService {
    private static final int MAX_METADATA_BYTES = 5 * 1024 * 1024;
    private final URI publicBase;
    private final PlanRepository plans;
    private final RunRepository runs;
    private final RunService runService;
    private final MetadataCache metadataCache;
    private final TargetMetadataParser metadataParser;
    private final OutboundPolicy outboundPolicy;
    private final HttpClient http;
    private final Clock clock;
    private final ObjectMapper mapper;

    public PreflightService(URI publicBase, PlanRepository plans, RunRepository runs, RunService runService,
                            MetadataCache metadataCache, TargetMetadataParser metadataParser,
                            OutboundPolicy outboundPolicy, Clock clock, ObjectMapper mapper) {
        this.publicBase = publicBase;
        this.plans = plans;
        this.runs = runs;
        this.runService = runService;
        this.metadataCache = metadataCache;
        this.metadataParser = metadataParser;
        this.outboundPolicy = outboundPolicy;
        this.clock = clock;
        this.mapper = mapper;
        this.http = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(5))
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();
    }

    public PreflightReport execute(String runId) {
        var run = runs.find(runId).orElseThrow(() -> new IllegalArgumentException("Unknown Run"));
        var plan = plans.find(run.planId()).orElseThrow(() -> new IllegalStateException("Run has no Test Plan"));
        var priorStatus = run.status();
        run = runService.update(run, RunStatus.PREFLIGHT, run.targetToSuiteReachability(), run.context());
        var checks = new ArrayList<PreflightReport.Check>();
        var observations = new LinkedHashMap<String, Object>();
        observations.put("reachabilityProbeUrl",
                publicBase.resolve("/p/" + plan.id() + "/metadata?probe=" + run.id()).toString());
        checkPublicBase(checks);
        byte[] targetMetadata = null;
        if (plan.target().metadataSource().kind() == MetadataSourceKind.SNAPSHOT_BASE64) {
            try {
                targetMetadata = java.util.Base64.getDecoder().decode(
                        plan.target().metadataSource().location());
                var parsed = metadataParser.parse(targetMetadata, plan.target().entityId());
                metadataCache.put(plan.id(), targetMetadata);
                metadataCache.putIfAbsent(run.id(), targetMetadata);
                observations.put("targetEntityId", parsed.entityId());
                observations.put("singleSignOnServices", parsed.singleSignOnServices().size());
                observations.put("assertionConsumerServices", parsed.assertionConsumerServices().size());
                observations.put("metadataRevisionId", plan.target().metadataRevisionId());
                checks.add(check("target_metadata", PreflightReport.Status.PASS,
                        "Saved target metadata revision was parsed"));
            } catch (Exception error) {
                checks.add(check("target_metadata", PreflightReport.Status.FAIL, error.getMessage()));
            }
        } else if (plan.target().metadataSource().kind() == MetadataSourceKind.URL) {
            try {
                var response = fetch(URI.create(plan.target().metadataSource().location()), 0);
                targetMetadata = response.body();
                var parsed = metadataParser.parse(targetMetadata, plan.target().entityId());
                metadataCache.put(plan.id(), targetMetadata);
                // A Plan-level copy supports peer operations, while the Run-scoped copy is the
                // immutable input for conformance evaluation. A later Run must not rewrite the
                // evidence used by an earlier Run.
                metadataCache.putIfAbsent(run.id(), targetMetadata);
                observations.put("targetEntityId", parsed.entityId());
                observations.put("singleSignOnServices", parsed.singleSignOnServices().size());
                observations.put("assertionConsumerServices", parsed.assertionConsumerServices().size());
                response.headers().firstValue("Date").ifPresent(date -> recordClockDifference(date, observations));
                checks.add(check("target_metadata", PreflightReport.Status.PASS,
                        "Target metadata was retrieved and parsed"));
            } catch (Exception e) {
                checks.add(check("target_metadata", PreflightReport.Status.FAIL, e.getMessage()));
            }
        } else {
            checks.add(check("target_metadata", PreflightReport.Status.NOT_CHECKED,
                    "M0 automatically retrieves URL metadata only"));
        }
        var reachability = Reachability.ASSERTED;
        checks.add(check("target_to_suite", PreflightReport.Status.WARNING,
                "Target-to-Suite reachability is asserted only; inbound traffic is required to confirm it"));
        var report = new PreflightReport(run.id(), clock.instant(), reachability, checks, observations);
        var context = new LinkedHashMap<String, Object>(run.context());
        context.put("preflight", mapper.convertValue(report, Map.class));
        // Re-running preflight refreshes configuration evidence; it must not erase an already
        // completed protocol round trip. Quick checks and browser scenarios intentionally require
        // COMPLETED, so regressing the lifecycle here would strand a valid Run.
        var nextStatus = priorStatus == RunStatus.COMPLETED
                ? RunStatus.COMPLETED
                : report.hasFailure() ? RunStatus.CREATED : RunStatus.RUNNING;
        runService.update(run, nextStatus, reachability, context);
        return report;
    }

    private void checkPublicBase(ArrayList<PreflightReport.Check> checks) {
        var local = publicBase.getHost() != null && (publicBase.getHost().equals("localhost")
                || publicBase.getHost().equals("127.0.0.1") || publicBase.getHost().equals("::1"));
        if (!"https".equalsIgnoreCase(publicBase.getScheme()) && !local) {
            checks.add(check("public_base_https", PreflightReport.Status.WARNING,
                    "The public base URL is not HTTPS; many SAML products will reject it"));
        } else {
            checks.add(check("public_base_https", PreflightReport.Status.PASS,
                    local ? "Local development base URL" : "The public base URL uses HTTPS"));
        }
    }

    /** Uses the same bounded, redirect-checked outbound path as Run preflight. */
    public byte[] retrieveMetadata(URI uri) throws Exception {
        return fetch(uri, 0).body();
    }

    private HttpResponse<byte[]> fetch(URI uri, int redirects) throws Exception {
        if (redirects > 3) throw new IllegalArgumentException("Metadata redirect limit exceeded");
        outboundPolicy.requireAllowed(uri);
        var request = HttpRequest.newBuilder(uri).GET().timeout(Duration.ofSeconds(30))
                .header("Accept", "application/samlmetadata+xml, application/xml, text/xml").build();
        var response = http.send(request, HttpResponse.BodyHandlers.ofInputStream());
        if (response.statusCode() == 301 || response.statusCode() == 302 || response.statusCode() == 307) {
            var location = response.headers().firstValue("Location")
                    .orElseThrow(() -> new IllegalArgumentException("Metadata redirect has no Location"));
            response.body().close();
            return fetch(uri.resolve(location), redirects + 1);
        }
        if (response.statusCode() < 200 || response.statusCode() >= 300) {
            response.body().close();
            throw new IllegalArgumentException("Metadata endpoint returned HTTP " + response.statusCode());
        }
        var output = new ByteArrayOutputStream();
        try (var body = response.body()) {
            var buffer = new byte[8192];
            int read;
            while ((read = body.read(buffer)) >= 0) {
                if (output.size() + read > MAX_METADATA_BYTES) {
                    throw new IllegalArgumentException("Target metadata exceeds 5 MiB");
                }
                output.write(buffer, 0, read);
            }
        }
        return new ByteArrayResponse(response, output.toByteArray());
    }

    private void recordClockDifference(String date, Map<String, Object> observations) {
        try {
            var remote = ZonedDateTime.parse(date, DateTimeFormatter.RFC_1123_DATE_TIME).toInstant();
            observations.put("targetDateOffsetSeconds", Duration.between(clock.instant(), remote).toSeconds());
        } catch (Exception ignored) {
            observations.put("targetDateHeader", date);
        }
    }

    private PreflightReport.Check check(String code, PreflightReport.Status status, String message) {
        return new PreflightReport.Check(code, status, message == null ? "Unknown preflight error" : message);
    }

    private record ByteArrayResponse(HttpResponse<?> source, byte[] body) implements HttpResponse<byte[]> {
        @Override public int statusCode() { return source.statusCode(); }
        @Override public HttpRequest request() { return source.request(); }
        @Override public java.util.Optional<HttpResponse<byte[]>> previousResponse() { return java.util.Optional.empty(); }
        @Override public java.net.http.HttpHeaders headers() { return source.headers(); }
        @Override public java.util.Optional<javax.net.ssl.SSLSession> sslSession() { return source.sslSession(); }
        @Override public URI uri() { return source.uri(); }
        @Override public HttpClient.Version version() { return source.version(); }
    }
}
