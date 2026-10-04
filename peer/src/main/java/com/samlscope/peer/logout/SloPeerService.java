package com.samlscope.peer.logout;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.util.List;
import java.util.Map;
import com.samlscope.core.plan.PlanRepository;
import com.samlscope.core.run.RunRepository;
import com.samlscope.core.transcript.Direction;
import com.samlscope.core.transcript.TranscriptInput;
import com.samlscope.core.transcript.TranscriptRecorder;
import com.samlscope.core.evaluation.EvidenceRef;
import com.samlscope.runner.ActiveProbeCorrelation;
import com.samlscope.runner.TargetInitiatedIntents;
import com.samlscope.saml.metadata.MetadataService;
import com.samlscope.saml.metadata.TargetMetadataParser;
import com.samlscope.saml.normal.SamlException;
import com.samlscope.saml.normal.SamlProtocolService;
import com.samlscope.saml.normal.SecureXml;
import com.samlscope.store.MetadataCache;
import org.w3c.dom.Element;

/** Role-neutral SLO receiving endpoint for the Suite SP and Suite IdP. */
public final class SloPeerService {
    public enum Transport { FRONT_CHANNEL, SOAP }
    public record Result(
            String runId,
            String messageType,
            SamlProtocolService.ResponseMessage response,
            String responseBinding,
            String activeProbeActionId,
            Map<String, Object> summary) {
        public Result(String runId, String messageType, SamlProtocolService.ResponseMessage response, String responseBinding) {
            this(runId, messageType, response, responseBinding, null, Map.of());
        }
        public Result { summary = Map.copyOf(summary); }
        public boolean activeProbe() { return activeProbeActionId != null; }
    }

    @FunctionalInterface
    public interface ActiveProbeResponseHandler {
        void accept(String runId, String actionId, byte[] xml, EvidenceRef evidence);
    }

    private final PlanRepository plans;
    private final RunRepository runs;
    private final MetadataCache metadata;
    private final TargetMetadataParser parser;
    private final SamlProtocolService saml;
    private final TranscriptRecorder transcript;
    private final Clock clock;
    private final ActiveProbeResponseHandler activeProbeResponses;
    private final TargetInitiatedIntents targetInitiated;
    private final com.samlscope.core.transcript.TranscriptContentReader content;
    // Locks protect only one prepared trial; the durable claim itself is its Recorder original.
    private final java.util.concurrent.ConcurrentHashMap<PropagationScope, Object> propagationLocks = new java.util.concurrent.ConcurrentHashMap<>();

    public SloPeerService(
            PlanRepository plans,
            RunRepository runs,
            MetadataCache metadata,
            TargetMetadataParser parser,
            SamlProtocolService saml,
            TranscriptRecorder transcript,
            Clock clock) {
        this(plans, runs, metadata, parser, saml, transcript, clock,
                (run, action, xml, evidence) -> { throw new IllegalStateException("SLO active-probe handler is not configured"); });
    }

    public SloPeerService(PlanRepository plans, RunRepository runs, MetadataCache metadata,
            TargetMetadataParser parser, SamlProtocolService saml, TranscriptRecorder transcript,
            Clock clock, ActiveProbeResponseHandler activeProbeResponses) {
        this(plans, runs, metadata, parser, saml, transcript, clock, activeProbeResponses,
                new TargetInitiatedIntents());
    }

    public SloPeerService(PlanRepository plans, RunRepository runs, MetadataCache metadata,
            TargetMetadataParser parser, SamlProtocolService saml, TranscriptRecorder transcript,
            Clock clock, ActiveProbeResponseHandler activeProbeResponses,
            TargetInitiatedIntents targetInitiated) {
        this.plans = java.util.Objects.requireNonNull(plans, "plans");
        this.runs = java.util.Objects.requireNonNull(runs, "runs");
        this.metadata = java.util.Objects.requireNonNull(metadata, "metadata");
        this.parser = java.util.Objects.requireNonNull(parser, "parser");
        this.saml = java.util.Objects.requireNonNull(saml, "saml");
        this.transcript = java.util.Objects.requireNonNull(transcript, "transcript");
        this.clock = java.util.Objects.requireNonNull(clock, "clock");
        this.activeProbeResponses = java.util.Objects.requireNonNull(activeProbeResponses, "activeProbeResponses");
        this.targetInitiated = java.util.Objects.requireNonNull(targetInitiated, "targetInitiated");
        this.content = transcript instanceof com.samlscope.core.transcript.TranscriptContentReader reader ? reader : null;
    }

    public Result consume(
            String planId,
            Transport transport,
            String method,
            String rawQuery,
            byte[] rawBody,
            Map<String, List<String>> headers,
            String requestUrl) {
        // Ingress precedes parsing and any scoped lock. Concurrent arrivals cannot acquire invented later times.
        var arrivedAt = clock.instant();
        var plan = plans.find(planId).orElseThrow(() -> new IllegalArgumentException("Unknown Test Plan"));
        final Decoded decoded;
        try {
            decoded = transport == Transport.SOAP ? decodeSoap(rawBody) : decodeFront(method, rawQuery, rawBody);
        } catch (SamlException invalid) {
            if (transport == Transport.SOAP) {
                var candidate = queryParameter(requestUrl, "run");
                if (candidate != null && runs.find(candidate).filter(run -> planId.equals(run.planId())).isPresent())
                    transcript.record(new TranscriptInput(candidate, Direction.INBOUND, clock.instant(), null,
                            method, requestUrl, null, sanitized(headers), rawBody, "text/xml", rawQuery, rawBody,
                            Map.of("type", "unparsed", "transport", "SOAP", "parseStatus", "invalid-soap-message-scope")));
            }
            throw invalid;
        }
        var activeProbe = ActiveProbeCorrelation.parse(decoded.message().relayState());
        var runId = queryParameter(requestUrl, "run");
        if (activeProbe.isPresent()) {
            if (runId != null && !runId.equals(activeProbe.orElseThrow().runId()))
                throw new SamlException("SLO Run parameter conflicts with active-probe correlation");
            runId = activeProbe.orElseThrow().runId();
        }
        if (runId == null) runId = decoded.message().relayState();
        var targetInitiatedLogout = false;
        if (runId == null || runId.isBlank()) {
            // A target-initiated LogoutRequest carries no Suite correlation. Accept it only
            // when exactly one Run of this plan has explicitly prepared the check, and verify
            // the issuer before consuming the single-use intent.
            var intent = targetInitiated.resolvePlan(planId, TargetInitiatedIntents.Kind.TARGET_LOGOUT, clock);
            if (intent.isEmpty()) throw new SamlException("SLO message has no Run correlation");
            var issuer = decodedIssuer(decoded);
            var targetPlan = plans.find(planId).orElseThrow(() -> new SamlException("Unknown Test Plan"));
            if (!targetPlan.target().entityId().equals(issuer)) {
                throw new SamlException("Target-initiated logout issuer does not match the Test Plan target");
            }
            runId = intent.orElseThrow().runId();
            targetInitiatedLogout = true;
        }
        var run = runs.find(runId).orElseThrow(() -> new SamlException("Unknown correlated Run"));
        if (!planId.equals(run.planId())) throw new SamlException("Correlated Run belongs to another Test Plan");

        // Retain abnormal responses before parsing. The waiting case owns InResponseTo/status judgments.
        if (activeProbe.isPresent()) {
            var correlation = activeProbe.orElseThrow();
            var entry = transcript.record(new TranscriptInput(run.id(), Direction.INBOUND, clock.instant(),
                    correlation.actionId(), method, requestUrl, 200, sanitized(headers), rawBody, contentType(method),
                    rawQuery, decoded.message().xml(), Map.of("type", "SAMLResponse", "parseStatus", "not-yet-parsed")));
            Map<String, Object> summary;
            String type;
            try {
                var parsed = saml.parse(decoded.message());
                var root = parsed.parsed().document().getDocumentElement();
                type = root.getLocalName();
                var values = new java.util.LinkedHashMap<String, Object>(parsed.parsed().summary());
                values.put("transport", transport.name());
                values.put("activeProbeAccepted", "urn:oasis:names:tc:SAML:2.0:protocol".equals(root.getNamespaceURI())
                        && "LogoutResponse".equals(type)
                        && ("_" + correlation.actionId()).equals(root.getAttribute("InResponseTo")));
                summary = Map.copyOf(values);
            } catch (SamlException malformed) {
                type = "unparsed";
                summary = Map.of("parseStatus", "error", "errorCategory", "malformed-slo-response");
            }
            transcript.updateSamlAnalysis(entry.id(), correlation.actionId(), summary);
            activeProbeResponses.accept(run.id(), correlation.actionId(), decoded.message().xml(),
                    new EvidenceRef("transcript", entry.id()));
            return new Result(run.id(), type, null, null, correlation.actionId(), summary);
        }

        var parsed = saml.parse(decoded.message());
        var root = parsed.parsed().document().getDocumentElement();
        var messageType = root.getLocalName();
        if (!"urn:oasis:names:tc:SAML:2.0:protocol".equals(root.getNamespaceURI())
                || (!"LogoutRequest".equals(messageType) && !"LogoutResponse".equals(messageType))) {
            throw new SamlException("Not a SAML logout message");
        }
        var propagation = propagationPreparation(plan, run.id(), transport, method, requestUrl, root, arrivedAt);
        var inboundSummary = new java.util.LinkedHashMap<String, Object>();
        inboundSummary.put("type", messageType); inboundSummary.put("transport", transport.name());
        inboundSummary.putAll(propagation);
        var transcriptXml = transport == Transport.SOAP ? rawBody : decoded.message().xml();
        if (propagation.isEmpty()) {
            transcript.record(new TranscriptInput(run.id(), Direction.INBOUND, arrivedAt, root.getAttribute("ID"), method,
                    requestUrl, 200, sanitized(headers), rawBody, transport == Transport.SOAP ? "text/xml" : contentType(method),
                    rawQuery, transcriptXml, inboundSummary));
        } else {
            propagation = claimPropagation(run.id(), root, arrivedAt, method, requestUrl, headers, rawBody,
                    rawQuery, transcriptXml, propagation);
        }
        if ("LogoutResponse".equals(messageType)) return new Result(run.id(), messageType, null, null);
        if (targetInitiatedLogout) { /* single-use intent already consumed by resolvePlan */ }

        var target = parser.parse(propagation.isEmpty() ? metadata.get(plan.id())
                : metadata.getRunSnapshot(run.id(), plan.id()), plan.target().entityId());
        var preparedPropagation = !propagation.isEmpty();
        var preferredBinding = transport == Transport.SOAP ? MetadataService.SOAP
                : "GET".equalsIgnoreCase(method) ? MetadataService.REDIRECT : MetadataService.POST;
        var endpoint = target.singleLogoutServices().stream()
                .filter(value -> preferredBinding.equals(value.binding())).findFirst()
                .or(() -> !preparedPropagation ? target.singleLogoutServices().stream().findFirst() : java.util.Optional.empty())
                .orElse(null);
        if (!propagation.isEmpty() && endpoint == null)
            throw new SamlException("Prepared SOAP propagation needs a target SOAP response endpoint");
        if (endpoint == null) return new Result(run.id(), messageType, null, null);
        var response = propagation.isEmpty() ? saml.buildLogoutResponse(plan, parsed, endpoint.location())
                : saml.buildSloPropagationResponse(plan, parsed, endpoint.location(),
                        (String) propagation.get("propagationTrial"), (String) propagation.get("propagationParticipant"),
                        "first-arrival".equals(propagation.get("propagationMode")) && Integer.valueOf(1).equals(propagation.get("propagationOrdinal")));
        if (!propagation.isEmpty()) {
            // The HTTP route invokes soapResponse. Keep the actual returned-envelope producer
            // separate from merely receiving a request or constructing an in-memory response.
            return new Result(run.id(), messageType, response, endpoint.binding(), null, propagation);
        }
        transcript.record(new TranscriptInput(
                run.id(), Direction.OUTBOUND, clock.instant(), response.id(), "POST",
                endpoint.location().toString(), null, Map.of(), new byte[0],
                transport == Transport.SOAP ? "text/xml" : "application/x-www-form-urlencoded",
                null, transport == Transport.SOAP ? soap(response.xml()) : response.xml(),
                Map.of("type", "LogoutResponse", "transport", transport.name(),
                        "binding", endpoint.binding())));
        return new Result(run.id(), messageType, response, endpoint.binding());
    }

    public URI redirectResponse(Result result) {
        requireResponse(result);
        return saml.redirectResponse(result.response());
    }

    public byte[] soapResponse(Result result) {
        requireResponse(result);
        var envelope = soap(result.response().xml());
        if (com.samlscope.saml.logout.SloPropagationFixtures.MARKER.equals(result.summary().get("propagationFixture"))) {
            var summary = new java.util.LinkedHashMap<String, Object>(result.summary());
            summary.put("type", "LogoutResponse"); summary.put("transport", "SOAP"); summary.put("binding", MetadataService.SOAP);
            summary.put("producerBoundary", "soapResponse-return");
            var xml = SecureXml.parse(result.response().xml()).getDocumentElement();
            var statuses = xml.getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:protocol", "StatusCode");
            summary.put("responseStatus", ((Element) statuses.item(0)).getAttribute("Value"));
            synchronized (propagationLock(result.runId(), summary)) {
                if (transcript.listBounded(result.runId(), 20_000).stream().anyMatch(e -> e.direction() == Direction.OUTBOUND
                        && result.response().id().equals(e.correlationId())))
                    throw new SamlException("Propagation response return was already recorded");
                transcript.record(new TranscriptInput(result.runId(), Direction.OUTBOUND, clock.instant(), result.response().id(),
                        "POST", result.response().destination().toString(), 200, Map.of(), envelope,
                        "text/xml", null, envelope, summary));
            }
        }
        return envelope;
    }

    private Map<String, Object> propagationPreparation(com.samlscope.core.plan.TestPlan plan, String run,
            Transport transport, String method, String url, Element request, java.time.Instant arrivedAt) {
        var marker = queryParameter(url, "propagation");
        if (marker == null && queryParameter(url, "participant") == null && queryParameter(url, "trial") == null
                && queryParameter(url, "mode") == null)
            return Map.of();
        if (!com.samlscope.saml.logout.SloPropagationFixtures.MARKER.equals(marker)
                || transport != Transport.SOAP || !"POST".equals(method) || !"LogoutRequest".equals(request.getLocalName())
                || content == null) throw new SamlException("Unprepared SOAP propagation participant");
        var trial = queryParameter(url, "trial"); var participant = queryParameter(url, "participant");
        if (!com.samlscope.saml.logout.SloPropagationFixtures.mode(trial).equals(queryParameter(url, "mode")))
            throw new SamlException("SOAP propagation mode is not the prepared mode");
        var expected = saml.sloPropagationEndpoint(plan, run, trial, participant).toString();
        if (!expected.equals(url) || !expected.equals(request.getAttribute("Destination")))
            throw new SamlException("SOAP propagation endpoint is not the prepared endpoint");
        var issuers = childElements(request).stream().filter(e ->
                "urn:oasis:names:tc:SAML:2.0:assertion".equals(e.getNamespaceURI()) && "Issuer".equals(e.getLocalName())).toList();
        if (issuers.size() != 1 || !plan.target().entityId().equals(issuers.getFirst().getTextContent()))
            throw new SamlException("SOAP propagation issuer is not the Run target");
        var variant = com.samlscope.saml.logout.SloPropagationFixtures.variant(trial);
        var candidates = transcript.listBounded(run, 20_000).stream().filter(e -> e.direction() == Direction.OUTBOUND
                && "MetadataPrepared".equals(e.samlSummary().get("type")) && variant.equals(e.samlSummary().get("variant"))).toList();
        if (candidates.size() != 1) throw new SamlException("SOAP propagation preparation is missing or ambiguous");
        var prepared = candidates.getFirst(); var fields = prepared.samlSummary();
        if (!com.samlscope.saml.logout.SloPropagationFixtures.CASE.equals(fields.get("case_id"))
                || !run.equals(fields.get("run_id")) || !plan.id().equals(fields.get("plan_id")))
            throw new SamlException("SOAP propagation preparation has another scope");
        try {
            var at = java.time.Instant.parse(String.valueOf(fields.get("prepared_at")));
            var original = content.readDecodedSaml(prepared);
            if (at.isAfter(prepared.timestamp()) || prepared.timestamp().isAfter(arrivedAt)
                    || !saml.matchesSloPropagationMetadata(original, plan, run, trial, at))
                throw new SamlException("SOAP propagation preparation bytes do not match the shared factory");
            var target = parser.parse(metadata.getRunSnapshot(run, plan.id()), plan.target().entityId());
            var verifier = new com.samlscope.saml.crypto.XmlSignatureVerifier();
            if (request.getAttribute("ID").isBlank() || !verifier.hasValidEnvelopedReferenceDigests(request)
                    || target.signingCertificates().stream().noneMatch(cert -> verifier.hasValidEnvelopedSignature(request, cert)))
                throw new SamlException("SOAP propagation request is not signed by the Run target");
            var action = com.samlscope.core.caseexec.ActionIds.derive(run, com.samlscope.saml.logout.SloPropagationFixtures.CASE,
                    "slo-basic-v6-soap-propagation-" + trial + "-logout", 0);
            var origins = transcript.listBounded(run, 20_000).stream().filter(e -> e.direction() == Direction.OUTBOUND
                    && action.equals(e.correlationId()) && action.equals(e.samlSummary().get("action_id"))
                    && "LogoutRequest".equals(e.samlSummary().get("type")) && "direct-soap".equals(e.samlSummary().get("probe_transport"))).toList();
            if (origins.size() != 1 || origins.getFirst().timestamp().isAfter(arrivedAt))
                throw new SamlException("SOAP propagation requires exactly one original trial origin");
            return Map.of("propagationFixture", marker, "propagationTrial", trial, "propagationParticipant", participant,
                    "preparedMetadataRef", prepared.id(), "preparedMetadataSha256", java.util.HexFormat.of().formatHex(
                            java.security.MessageDigest.getInstance("SHA-256").digest(original)),
                    "propagationMode", com.samlscope.saml.logout.SloPropagationFixtures.mode(trial));
        } catch (SamlException invalid) { throw invalid; }
        catch (Exception invalid) { throw new SamlException("SOAP propagation preparation is unavailable", invalid); }
    }

    private Object propagationLock(String run, Map<String, Object> summary) {
        return propagationLocks.computeIfAbsent(new PropagationScope(run, (String) summary.get("propagationTrial"),
                (String) summary.get("preparedMetadataSha256")), ignored -> new Object());
    }

    private Map<String, Object> claimPropagation(String run, Element request, java.time.Instant arrivedAt,
            String method, String url, Map<String, List<String>> headers, byte[] rawBody, String rawQuery,
            byte[] transcriptXml, Map<String, Object> prepared) {
        synchronized (propagationLock(run, prepared)) {
            var originals = transcript.listBounded(run, 20_000);
            var claims = originals.stream().filter(e -> e.direction() == Direction.INBOUND
                    && "LogoutRequest".equals(e.samlSummary().get("type"))
                    && com.samlscope.saml.logout.SloPropagationFixtures.MARKER.equals(e.samlSummary().get("propagationFixture"))
                    && prepared.get("propagationTrial").equals(e.samlSummary().get("propagationTrial"))
                    && prepared.get("preparedMetadataSha256").equals(e.samlSummary().get("preparedMetadataSha256"))).toList();
            if (claims.size() >= 3 || originals.stream().anyMatch(e -> e.direction() == Direction.INBOUND
                    && com.samlscope.saml.logout.SloPropagationFixtures.MARKER.equals(e.samlSummary().get("propagationFixture"))
                    && request.getAttribute("ID").equals(e.correlationId()))
                    || claims.stream().anyMatch(e -> prepared.get("propagationParticipant").equals(e.samlSummary().get("propagationParticipant"))))
                throw new SamlException("SOAP propagation request or participant was already claimed");
            if ("first-arrival".equals(prepared.get("propagationMode")) && claims.stream().anyMatch(q -> originals.stream().noneMatch(a ->
                    a.direction() == Direction.OUTBOUND && "soapResponse-return".equals(a.samlSummary().get("producerBoundary"))
                    && q.samlSummary().get("preparedMetadataRef").equals(a.samlSummary().get("preparedMetadataRef"))
                    && q.samlSummary().get("propagationParticipant").equals(a.samlSummary().get("propagationParticipant"))
                    && !a.timestamp().isAfter(arrivedAt))))
                throw new SamlException("Concurrent SOAP propagation cannot establish sequential continuation");
            var summary = new java.util.LinkedHashMap<String, Object>(prepared);
            summary.put("propagationOrdinal", claims.size() + 1);
            var inbound = new java.util.LinkedHashMap<String, Object>(summary);
            inbound.put("type", "LogoutRequest"); inbound.put("transport", "SOAP");
            transcript.record(new TranscriptInput(run, Direction.INBOUND, arrivedAt, request.getAttribute("ID"), method,
                    url, 200, sanitized(headers), rawBody, "text/xml", rawQuery, transcriptXml, inbound));
            return Map.copyOf(summary);
        }
    }

    private record PropagationScope(String run, String trial, String preparedSha256) {}

    private void requireResponse(Result result) {
        if (result == null || result.response() == null) {
            throw new IllegalArgumentException("SLO result has no response");
        }
    }

    private String decodedIssuer(Decoded decoded) {
        try {
            return String.valueOf(saml.parse(decoded.message()).parsed().summary().getOrDefault("issuer", ""));
        } catch (RuntimeException unavailable) {
            return "";
        }
    }

    private Decoded decodeFront(String method, String rawQuery, byte[] rawBody) {
        for (var parameter : List.of("SAMLRequest", "SAMLResponse")) {
            try {
                var value = "GET".equalsIgnoreCase(method)
                        ? saml.decodeRedirectRaw(rawQuery, parameter)
                        : saml.decodePostRaw(rawBody, parameter);
                return new Decoded(value);
            } catch (SamlException ignored) {
                // Try the other legal message parameter.
            }
        }
        throw new SamlException("SLO transport has no decodable SAMLRequest or SAMLResponse");
    }

    private Decoded decodeSoap(byte[] body) {
        var document = SecureXml.parse(body);
        var envelope = document.getDocumentElement();
        var soap = "http://schemas.xmlsoap.org/soap/envelope/";
        if (!soap.equals(envelope.getNamespaceURI()) || !"Envelope".equals(envelope.getLocalName()))
            throw new SamlException("SLO SOAP transport requires a SOAP 1.1 Envelope");
        var bodies = childElements(envelope).stream()
                .filter(e -> soap.equals(e.getNamespaceURI()) && "Body".equals(e.getLocalName())).toList();
        if (bodies.size() != 1) throw new SamlException("SLO SOAP Envelope must have one direct Body");
        var messages = childElements(bodies.getFirst());
        if (messages.size() != 1) throw new SamlException("SLO SOAP Body must have one direct message");
        var message = messages.getFirst();
        if (!"urn:oasis:names:tc:SAML:2.0:protocol".equals(message.getNamespaceURI())
                || !List.of("LogoutRequest", "LogoutResponse").contains(message.getLocalName()))
            throw new SamlException("SLO SOAP Body does not contain a direct logout message");
        var inner = SecureXml.newDocument();
        var copied = (Element) inner.importNode(message, true);
        // Keep in-scope names, including prefixes used only in QName-valued content.
        for (var ancestor = message; ancestor != null;
                ancestor = ancestor.getParentNode() instanceof Element parent ? parent : null) {
            var attributes = ancestor.getAttributes();
            for (int i = 0; i < attributes.getLength(); i++) {
                var attr = attributes.item(i);
                if ((javax.xml.XMLConstants.XMLNS_ATTRIBUTE_NS_URI.equals(attr.getNamespaceURI())
                        || javax.xml.XMLConstants.XML_NS_URI.equals(attr.getNamespaceURI()))
                        && !copied.hasAttributeNS(attr.getNamespaceURI(), attr.getLocalName()))
                    copied.setAttributeNS(attr.getNamespaceURI(), attr.getNodeName(), attr.getNodeValue());
            }
        }
        inner.appendChild(copied);
        return new Decoded(new SamlProtocolService.RawDecodedMessage(SecureXml.serialize(inner), null));
    }

    private List<Element> childElements(Element parent) {
        var children = new java.util.ArrayList<Element>();
        for (var node = parent.getFirstChild(); node != null; node = node.getNextSibling())
            if (node instanceof Element element) children.add(element);
        return List.copyOf(children);
    }

    private byte[] soap(byte[] message) {
        var messageDocument = SecureXml.parse(message);
        var document = SecureXml.newDocument();
        var envelope = document.createElementNS("http://schemas.xmlsoap.org/soap/envelope/", "S:Envelope");
        envelope.setAttributeNS("http://www.w3.org/2000/xmlns/", "xmlns:S",
                "http://schemas.xmlsoap.org/soap/envelope/");
        var body = document.createElementNS("http://schemas.xmlsoap.org/soap/envelope/", "S:Body");
        body.appendChild(document.importNode(messageDocument.getDocumentElement(), true));
        envelope.appendChild(body); document.appendChild(envelope);
        return SecureXml.serialize(document);
    }

    private String queryParameter(String requestUrl, String name) {
        var query = URI.create(requestUrl).getRawQuery();
        if (query == null) return null;
        String result = null;
        for (var part : query.split("&")) {
            var separator = part.indexOf('=');
            var key = separator < 0 ? part : part.substring(0, separator);
            if (name.equals(java.net.URLDecoder.decode(key, StandardCharsets.UTF_8))) {
                if (result != null) throw new SamlException("Duplicate SLO Run correlation parameter");
                result = separator < 0 ? "" : java.net.URLDecoder.decode(
                        part.substring(separator + 1), StandardCharsets.UTF_8);
            }
        }
        return result;
    }
    private Map<String, List<String>> sanitized(Map<String, List<String>> headers) {
        var result = new java.util.LinkedHashMap<String, List<String>>();
        headers.forEach((name, values) -> {
            if (!"Authorization".equalsIgnoreCase(name) && !"Cookie".equalsIgnoreCase(name))
                result.put(name, List.copyOf(values));
        });
        return Map.copyOf(result);
    }
    private String contentType(String method) {
        return "GET".equalsIgnoreCase(method) ? null : "application/x-www-form-urlencoded";
    }
    private record Decoded(SamlProtocolService.RawDecodedMessage message) {}
}
