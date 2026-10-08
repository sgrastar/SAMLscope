package com.samlscope.runner.cases;

import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.*;
import java.util.function.Function;
import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.EvidenceRef;
import com.samlscope.core.transcript.*;
import com.samlscope.runner.ActiveProbeCorrelation;
import com.samlscope.runner.outbox.ArtifactResolutionOutboundSender;
import com.samlscope.saml.artifact.*;
import com.samlscope.saml.crypto.*;
import com.samlscope.saml.normal.SecureXml;
import org.w3c.dom.Element;

/** Original-backed conditional binding-switch evidence for approved IDP12.f only. */
public final class ArtifactBindingEvidence {
    public static final String CASE = ArtifactResolutionOutboundSender.CASE;
    public static final String FIXTURE = "artifact-binding";
    public static final String PHASE = "await-fixture-artifact-binding";
    private final TranscriptContentReader content;
    private final Function<String,byte[]> metadata;
    private final SamlPlanCredentialsProvider suiteKeys;
    private final Function<String,Optional<String>> targetEntityIds;
    public ArtifactBindingEvidence(TranscriptContentReader content, Function<String,byte[]> metadata,
            SamlPlanCredentialsProvider suiteKeys) {
        this(content,metadata,suiteKeys,ignored->Optional.empty());
    }
    public ArtifactBindingEvidence(TranscriptContentReader content, Function<String,byte[]> metadata,
            SamlPlanCredentialsProvider suiteKeys, Function<String,Optional<String>> targetEntityIds) {
        this.content = Objects.requireNonNull(content); this.metadata = Objects.requireNonNull(metadata);
        this.suiteKeys = Objects.requireNonNull(suiteKeys);
        this.targetEntityIds=Objects.requireNonNull(targetEntityIds);
    }
    public String metadataSha256(String runId) { return sha256(metadata.apply(runId)); }
    public SamlArtifact receivedArtifact(CaseContext context, TranscriptEntry original, URI acs) {
        require(entries(context).stream().filter(e -> e.id().equals(original.id())).toList().equals(List.of(original)));
        return recordedDelivery(context,original,acs).artifact();
    }

    public record Delivery(SamlArtifact artifact, String relayState) {}
    public static Delivery delivery(String method, String url, String contentType, byte[] body,
            String rawQuery, String runId, String authnActionId, URI artifactAcs) {
        require(Set.of("GET", "POST").contains(method) && body != null && body.length <= 8192);
        var actual = URI.create(url); require(actual.getRawFragment() == null && actual.getRawUserInfo() == null);
        String raw;
        if ("GET".equals(method)) {
            require(body.length == 0 && rawQuery != null && rawQuery.length() <= 8192
                    && Objects.equals(rawQuery, actual.getRawQuery()) && artifactAcs.getRawQuery() == null);
            int at = url.indexOf('?'); require(at > 0 && URI.create(url.substring(0,at)).equals(artifactAcs)); raw = rawQuery;
        } else {
            require(url.equals(artifactAcs.toString()) && rawQuery == null && form(contentType));
            raw = new String(body, StandardCharsets.UTF_8);
            require(Arrays.equals(body, raw.getBytes(StandardCharsets.UTF_8)));
        }
        var values = new HashMap<String,String>();
        for (var pair : raw.split("&", -1)) {
            int at = pair.indexOf('='); require(at > 0);
            var name = URLDecoder.decode(pair.substring(0,at), StandardCharsets.UTF_8);
            require(Set.of("SAMLart", "RelayState").contains(name));
            require(values.putIfAbsent(name, URLDecoder.decode(pair.substring(at+1), StandardCharsets.UTF_8)) == null);
        }
        require(values.keySet().equals(Set.of("SAMLart", "RelayState")));
        var expected = ActiveProbeCorrelation.encode(runId,authnActionId);
        require(expected.equals(values.get("RelayState")));
        return new Delivery(SamlArtifact.parse(values.get("SAMLart")), expected);
    }

    /** No HTTP or Recorder writes. The caller persists this deterministic unsafe action. */
    public OutboundAction prepare(CaseContext context, TranscriptEntry received, URI artifactAcs) {
        require(entries(context).stream().filter(e -> e.id().equals(received.id())).toList().equals(List.of(received)));
        var input = recordedDelivery(context, received, artifactAcs);
        var targetMetadata = metadata.apply(context.runId());
        var target = target(context.runId(),targetMetadata);
        require(sha256(targetMetadata).equals(received.samlSummary().get("target_metadata_sha256")));
        var endpoint = input.artifact().resolutionEndpoint(targetMetadata, target.getAttribute("entityID"));
        var action = ActionIds.derive(context.runId(), CASE, ArtifactResolutionOutboundSender.PHASE, 0);
        var key = suiteKeys.credentialsFor(context.runId()).orElseThrow();
        var authn = authn(context, artifactAcs);
        require(!received.timestamp().isBefore(authn.entry().timestamp()));
        var issuer = single(authn.xml(), ArtifactResolutionProtocol.A, "Issuer").getTextContent();
        var payload = new ArtifactResolutionProtocol().resolve(input.artifact(), "_"+action, endpoint,
                issuer, context.clock().instant(), key);
        return new OutboundAction(action, OutboundKind.ARTIFACT_RESOLVE, payload, endpoint, false);
    }

    public record Proof(ArtifactResolutionProtocol.ResolvedResponse resolved, List<EvidenceRef> evidence,
            String targetMetadataSha256, String artifactSha256, boolean recommendedSourceIdMapping) {
        public Proof { evidence = List.copyOf(evidence); }
    }
    public Optional<Proof> read(CaseContext context, OutboxEntry resolveOutbox, URI artifactAcs) {
        try {
            var entries = entries(context);
            var authn = authn(context, artifactAcs);
            var received = entries.stream().filter(e -> e.direction() == Direction.INBOUND
                    && "ArtifactReceived".equals(e.samlSummary().get("type"))
                    && authn.entry().correlationId().equals(e.correlationId())).toList();
            require(received.size() == 1);
            var original = received.getFirst(); var delivery = recordedDelivery(context, original, artifactAcs);
            require(!original.timestamp().isBefore(authn.entry().timestamp()));
            var targetMetadata = metadata.apply(context.runId()); var target = target(context.runId(),targetMetadata);
            var epoch = sha256(targetMetadata); require(epoch.equals(original.samlSummary().get("target_metadata_sha256")));
            var endpoint = delivery.artifact().resolutionEndpoint(targetMetadata,target.getAttribute("entityID"));
            var action = ActionIds.derive(context.runId(), CASE, ArtifactResolutionOutboundSender.PHASE,0);
            require(resolveOutbox != null && context.runId().equals(resolveOutbox.runId()) && CASE.equals(resolveOutbox.caseId())
                    && resolveOutbox.status() == OutboxStatus.SENT && action.equals(resolveOutbox.action().actionId())
                    && resolveOutbox.action().kind() == OutboundKind.ARTIFACT_RESOLVE && !resolveOutbox.action().requiresEphemeralCredential()
                    && endpoint.equals(resolveOutbox.action().target()) && !resolveOutbox.createdAt().isBefore(original.timestamp()));
            var request = entries.stream().filter(e -> e.direction() == Direction.OUTBOUND && action.equals(e.correlationId())).toList();
            var responses = entries.stream().filter(e -> e.direction() == Direction.INBOUND && action.equals(e.correlationId())
                    && "ArtifactResponse".equals(e.samlSummary().get("type"))).toList();
            require(request.size() == 1 && responses.size() == 1);
            var sent = request.getFirst(); var reply = responses.getFirst();
            require("ArtifactResolve".equals(sent.samlSummary().get("type")) && CASE.equals(sent.samlSummary().get("scenario_case_id"))
                    && action.equals(sent.samlSummary().get("action_id")) && "POST".equals(sent.method())
                    && endpoint.toString().equals(sent.url()) && xml(sent.contentType()) && sent.rawQuery() == null
                    && !sent.timestamp().isBefore(original.timestamp()));
            var requestBytes = decoded(sent); require(Arrays.equals(requestBytes,resolveOutbox.action().payload())
                    && sha256(requestBytes).equals(sent.samlSummary().get("request_sha256"))
                    && Arrays.equals(requestBytes,content.readBody(sent)));
            var protocol = new ArtifactResolutionProtocol(); var suite = suiteKeys.credentialsFor(context.runId()).orElseThrow();
            protocol.verifyResolve(requestBytes,delivery.artifact(),"_"+action,endpoint,
                    single(authn.xml(),ArtifactResolutionProtocol.A,"Issuer").getTextContent(),suite.certificate());
            var sentXml = protocol.soapMessage(requestBytes,"ArtifactResolve");
            require(!Instant.parse(sentXml.getAttribute("IssueInstant")).isAfter(sent.timestamp()));
            require(resolveOutbox.transcriptEntryId().equals(reply.id()) && "POST".equals(reply.method())
                    && Objects.equals(reply.status(),200) && endpoint.toString().equals(reply.url()) && xml(reply.contentType())
                    && reply.rawQuery() == null && !reply.timestamp().isBefore(sent.timestamp())
                    && sent.id().equals(reply.samlSummary().get("request_transcript"))
                    && CASE.equals(reply.samlSummary().get("scenario_case_id")) && action.equals(reply.samlSummary().get("action_id")));
            var raw = decoded(reply); require(Arrays.equals(raw,content.readBody(reply))
                    && sha256(raw).equals(reply.samlSummary().get("response_sha256"))
                    && sha256(raw).equals(resolveOutbox.sendResult().get("response_sha256"))
                    && sent.id().equals(resolveOutbox.sendResult().get("request_transcript"))
                    && Objects.equals(resolveOutbox.sendResult().get("http_status"),200));
            ArtifactTlsEvidence tlsProof = null;
            var capture = resolveOutbox.sendResult().get("transport_authentication");
            if (capture instanceof Map<?,?> map && capture.equals(reply.samlSummary().get("transport_authentication"))) {
                var value = new LinkedHashMap<String,Object>();
                for (var item : map.entrySet()) { require(item.getKey() instanceof String); value.put((String)item.getKey(),item.getValue()); }
                tlsProof = ArtifactTlsEvidence.verify(value,context.runId(),action,endpoint,sent.id(),reply.id(),requestBytes,raw,suite.certificate()).orElse(null);
            }
            var resolved = protocol.verifyResponse(raw,"_"+action,authn.xml().getAttribute("ID"),
                    target.getAttribute("entityID"),artifactAcs,MetadataAlgorithmEvidence.signingKeys(target),tlsProof);
            return Optional.of(new Proof(resolved,List.of(ref(authn.entry()),ref(original),ref(sent),ref(reply)),
                    epoch,delivery.artifact().sha256(),delivery.artifact().usesRecommendedSourceId(target.getAttribute("entityID"))));
        } catch (Exception unavailable) { return Optional.empty(); }
    }

    private record Authn(TranscriptEntry entry, Element xml) {}
    private Authn authn(CaseContext context, URI artifactAcs) {
        var action = ActionIds.derive(context.runId(),CASE,PHASE,0);
        var sent = entries(context).stream().filter(e -> e.direction() == Direction.OUTBOUND && action.equals(e.correlationId())).toList();
        require(sent.size() == 1); var original = sent.getFirst();
        require(CASE.equals(original.samlSummary().get("scenario_case_id")) && FIXTURE.equals(original.samlSummary().get("fixture_id"))
                && action.equals(original.samlSummary().get("action_id")) && "AuthnRequest".equals(original.samlSummary().get("type")));
        var root = SecureXml.parse(decoded(original)).getDocumentElement();
        require(ArtifactResolutionProtocol.P.equals(root.getNamespaceURI()) && "AuthnRequest".equals(root.getLocalName())
                && ("_"+action).equals(root.getAttribute("ID")) && "2.0".equals(root.getAttribute("Version"))
                && artifactAcs.toString().equals(root.getAttribute("AssertionConsumerServiceURL"))
                && "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact".equals(root.getAttribute("ProtocolBinding"))
                && !root.hasAttribute("AssertionConsumerServiceIndex")
                && new XmlSignatureVerifier().hasValidEnvelopedSignature(root,suiteKeys.credentialsFor(context.runId()).orElseThrow().certificate()));
        return new Authn(original,root);
    }
    private Delivery recordedDelivery(CaseContext context, TranscriptEntry entry, URI acs) {
        require(context.runId().equals(entry.runId()) && entry.direction() == Direction.INBOUND
                && "ArtifactReceived".equals(entry.samlSummary().get("type")) && CASE.equals(entry.samlSummary().get("scenario_case_id")));
        String action = ActionIds.derive(context.runId(),CASE,PHASE,0); require(action.equals(entry.correlationId())
                && action.equals(entry.samlSummary().get("authn_action_id")));
        byte[] body = "GET".equals(entry.method()) ? new byte[0] : content.readBody(entry);
        require(body.length == entry.bodyBytes());
        var input = delivery(entry.method(),entry.url(),entry.contentType(),body,entry.rawQuery(),context.runId(),action,acs);
        require(input.artifact().sha256().equals(entry.samlSummary().get("artifact_sha256")));
        return input;
    }
    private List<TranscriptEntry> entries(CaseContext c) {
        var entries = c.transcript().listBounded(c.runId(),10000); var seen = new HashSet<String>();
        for (var entry : entries) require(c.runId().equals(entry.runId()) && seen.add(entry.id())); return entries;
    }
    private byte[] decoded(TranscriptEntry e) { var raw = content.readDecodedSaml(e); require(raw != null && raw.length == e.decodedSamlBytes() && raw.length > 0); return raw; }
    private Element target(String runId,byte[] bytes) {
        var root=SecureXml.parse(bytes).getDocumentElement();
        require(SamlArtifact.MD.equals(root.getNamespaceURI()) && Set.of("EntityDescriptor","EntitiesDescriptor").contains(root.getLocalName()));
        var configured=targetEntityIds.apply(runId).filter(id->!id.isBlank());
        String id=configured.orElseGet(()->{require("EntityDescriptor".equals(root.getLocalName()));return root.getAttribute("entityID");});
        require(!id.isBlank());var found=new ArrayList<Element>();collect(root,id,found);require(found.size()==1);return found.getFirst();
    }
    private static void collect(Element root,String id,List<Element> found) {
        if("EntityDescriptor".equals(root.getLocalName()) && id.equals(root.getAttribute("entityID")))found.add(root);
        if("EntitiesDescriptor".equals(root.getLocalName()))for(var node=root.getFirstChild();node!=null;node=node.getNextSibling())
            if(node instanceof Element child && SamlArtifact.MD.equals(child.getNamespaceURI())
                    && Set.of("EntityDescriptor","EntitiesDescriptor").contains(child.getLocalName()))collect(child,id,found);
    }
    private static Element single(Element root,String ns,String name) { var values = MetadataAlgorithmEvidence.children(root,ns,name); require(values.size()==1); return values.getFirst(); }
    private static boolean form(String value) { return value != null && "application/x-www-form-urlencoded".equals(value.split(";",2)[0].trim().toLowerCase(Locale.ROOT)); }
    private static boolean xml(String value) { return value != null && Set.of("text/xml","application/xml").contains(value.split(";",2)[0].trim().toLowerCase(Locale.ROOT)); }
    private static EvidenceRef ref(TranscriptEntry entry) { return new EvidenceRef("transcript",entry.id()); }
    private static void require(boolean value) { if (!value) throw new IllegalArgumentException("Artifact original evidence is unbound or incomplete"); }
    public static String sha256(byte[] bytes) { try { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes)); } catch (Exception impossible) { throw new IllegalStateException(impossible); } }
}
