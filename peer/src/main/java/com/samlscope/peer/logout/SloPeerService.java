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
    }

    public Result consume(
            String planId,
            Transport transport,
            String method,
            String rawQuery,
            byte[] rawBody,
            Map<String, List<String>> headers,
            String requestUrl) {
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
        var transcriptXml = transport == Transport.SOAP ? rawBody : decoded.message().xml();
        transcript.record(new TranscriptInput(
                run.id(), Direction.INBOUND, clock.instant(), root.getAttribute("ID"), method,
                requestUrl, 200, sanitized(headers), rawBody,
                transport == Transport.SOAP ? "text/xml" : contentType(method),
                rawQuery, transcriptXml, Map.of("type", messageType, "transport", transport.name())));
        if ("LogoutResponse".equals(messageType)) return new Result(run.id(), messageType, null, null);
        if (targetInitiatedLogout) { /* single-use intent already consumed by resolvePlan */ }

        var target = parser.parse(metadata.get(plan.id()), plan.target().entityId());
        var preferredBinding = transport == Transport.SOAP ? MetadataService.SOAP
                : "GET".equalsIgnoreCase(method) ? MetadataService.REDIRECT : MetadataService.POST;
        var endpoint = target.singleLogoutServices().stream()
                .filter(value -> preferredBinding.equals(value.binding())).findFirst()
                .or(() -> target.singleLogoutServices().stream().findFirst())
                .orElse(null);
        if (endpoint == null) return new Result(run.id(), messageType, null, null);
        var response = saml.buildLogoutResponse(plan, parsed, endpoint.location());
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
        return soap(result.response().xml());
    }

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
