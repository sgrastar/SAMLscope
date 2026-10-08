package com.samlscope.runner.cases;

import com.samlscope.core.casedef.CaseDefinitionCatalog.*;
import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.plan.TargetRole;
import com.samlscope.core.transcript.*;
import com.samlscope.runner.outbox.MetadataFetchOutboundSender;
import com.samlscope.saml.normal.SecureXml;
import java.net.URI;
import java.util.*;
import java.util.function.Function;
import org.w3c.dom.Element;

/** Publisher observations use immutable Run input and actual outbox GET originals, never receipts. */
public final class AdditionalMetadataLocationEvidence {
    static final String MD = "urn:oasis:names:tc:SAML:2.0:metadata";
    static final String PHASE = "await-configuration";
    static final String MATCH = "IIP-MD05.a8#v-37403b861f", DIFFERENT = "IIP-MD05.a8#v-34181f3e0f";
    static final String REASON = "metadata.additional-location";
    private final CaseDefinition definition;
    private final TranscriptContentReader content;
    private final Function<String, byte[]> metadata;
    private final CaseExecutionRepository executions;
    private final Function<String, Scope> scopes;

    public record Scope(String runId, String profile, String entityId) {}
    public record Request(int index, URI url, String namespace, String snapshotHash, String actionId) {}
    record Original(Request request, TranscriptEntry response, byte[] body, String rootNamespace) {}
    public record Observation(CaseOutcome outcome, List<String> required, List<String> completed) {
        public boolean ready() { return outcome.outcome() == Outcome.SATISFIED || outcome.outcome() == Outcome.VIOLATED; }
    }

    public AdditionalMetadataLocationEvidence(CaseDefinition definition, TranscriptContentReader content,
            Function<String, byte[]> metadata, CaseExecutionRepository executions, Function<String, Scope> scopes) {
        this.definition = Objects.requireNonNull(definition); this.content = Objects.requireNonNull(content);
        this.metadata = Objects.requireNonNull(metadata); this.executions = Objects.requireNonNull(executions);
        this.scopes = Objects.requireNonNull(scopes);
        require(supports(definition.id()) && definition.mode() == ExecutionMode.CONFIG
                && "IIP-MD05.a8".equals(definition.obligation())
                && definition.configurationFailureSemantics() == ConfigurationFailureSemantics.TEST_PRECONDITION
                && Set.copyOf(definition.coversVariants()).equals(Set.of(MATCH, DIFFERENT))
                && definition.coversVariants().size() == 2 && definition.variantPlan().size() == 2
                && definition.variantPlan().stream().allMatch(v -> v.applicability() == VariantScope.OWNER_CONDITION
                        && v.treatment() == VariantTreatment.VERDICT)
                && definition.variantScopes().equals(Map.of(MATCH, VariantScope.OWNER_CONDITION, DIFFERENT, VariantScope.OWNER_CONDITION))
                && definition.variantGroups().size() == 1 && definition.variantGroups().getFirst().kind() == GroupKind.ALL_OF
                && Set.copyOf(definition.variantGroups().getFirst().members()).equals(Set.of(MATCH, DIFFERENT)));
        require(definition.controls().size() == 2);
        for (var kind : List.of(ControlKind.POSITIVE, ControlKind.NEGATIVE)) {
            var controls = definition.controls().stream().filter(c -> c.kind() == kind).toList();
            require(controls.size() == 1 && controls.getFirst().id().equals(controlId(kind))
                    && controls.getFirst().fixture().equals(fixtureId(kind)));
        }
    }

    public static boolean supports(String id) {
        return Set.of("IIP-MD05-a8-idp-01", "IIP-MD05-a8-sp-01").contains(id);
    }

    public List<Request> requests(CaseContext context) {
        var scope = scopes.apply(context.runId());
        require(scope != null && context.runId().equals(scope.runId())
                && context.targetRole() == definition.role()
                && (definition.role() == TargetRole.IDP ? "METADATA_IDP" : "METADATA_SP").equals(scope.profile()));
        byte[] input = metadata.apply(context.runId());
        require(input != null && input.length > 0);
        var document = SecureXml.parse(input);
        var root = document.getDocumentElement();
        require(MD.equals(root.getNamespaceURI()) && Set.of("EntityDescriptor", "EntitiesDescriptor").contains(root.getLocalName()));
        var entities = new ArrayList<Element>();
        if ("EntityDescriptor".equals(root.getLocalName())) entities.add(root);
        else {
            var nodes = root.getElementsByTagNameNS(MD, "EntityDescriptor");
            for (int i = 0; i < nodes.getLength(); i++) entities.add((Element) nodes.item(i));
        }
        var selected = entities.stream().filter(e -> scope.entityId().equals(e.getAttribute("entityID"))).toList();
        require(selected.size() == 1);
        var locations = children(selected.getFirst(), "AdditionalMetadataLocation");
        // An implementation observation budget is uncertainty, never a new normative threshold.
        require(locations.size() <= 64);
        var requests = new ArrayList<Request>();
        var sequences = new LinkedHashMap<URI, Integer>();
        for (var location : locations) {
            var url = URI.create(location.getTextContent().strip());
            require(MetadataFetchOutboundSender.supported(url));
            int index = requests.size();
            int sequence = sequences.computeIfAbsent(url, ignored -> sequences.size());
            requests.add(new Request(index, url, location.hasAttribute("namespace") ? location.getAttribute("namespace") : null, hash(input),
                    ActionIds.derive(context.runId(), definition.id(), PHASE, sequence)));
        }
        return List.copyOf(requests);
    }

    public List<OutboundAction> actions(CaseContext context) {
        var actions = new LinkedHashMap<String, OutboundAction>();
        for (var r : requests(context)) actions.putIfAbsent(r.actionId(), new OutboundAction(r.actionId(), OutboundKind.METADATA_FETCH,
                new byte[0], r.url(), false));
        return List.copyOf(actions.values());
    }

    public boolean owns(CaseContext context, OutboxEntry entry) {
        try {
            return entry != null && context.runId().equals(entry.runId()) && definition.id().equals(entry.caseId())
                    && actions(context).stream().anyMatch(a -> sameAction(a, entry.action()));
        } catch (RuntimeException unavailable) { return false; }
    }

    public void produceControls(CaseContext context) {
        if (!context.transcriptComplete()) return;
        try {
            var issued = new HashSet<String>();
            for (var request : requests(context)) {
                var original = original(context, request);
                for (var kind : List.of(ControlKind.POSITIVE, ControlKind.NEGATIVE)) {
                    if (!issued.add(original.response().id() + ":" + kind)) continue;
                    byte[] bytes = AdditionalMetadataLocationControlProducer.bytes(definition.role(), original, kind);
                    var matching = controlEntries(context, original, kind);
                    if (matching.isEmpty()) {
                        context.transcript().record(new TranscriptInput(context.runId(), Direction.OUTBOUND,
                                context.clock().instant(), request.actionId(), "SUITE_CONTROL",
                                "urn:samlscope:calibration:additional-metadata-location", null, Map.of(), bytes,
                                "application/samlmetadata+xml", null, new byte[0], Map.of(
                                        "type", AdditionalMetadataLocationControlProducer.TYPE,
                                        "case_id", definition.id(), "case_digest", definition.caseDigest(),
                                        "control_id", controlId(kind), "fixture_id", fixtureId(kind),
                                        "variant", kind == ControlKind.POSITIVE ? MATCH : DIFFERENT,
                                        "reference_response", original.response().id(), "calibration_only", true)));
                    }
                }
            }
        } catch (RuntimeException unproven) { /* Incomplete originals and control writes cannot create a conclusion. */ }
    }

    public Observation observe(CaseContext context) {
        var required = new ArrayList<String>(); var completed = new ArrayList<String>();
        var evidence = new ArrayList<EvidenceRef>(); var mismatches = new ArrayList<Integer>();
        String failure = "additional_metadata_location_evidence_incomplete";
        try {
            require(context.transcriptComplete());
            var requests = requests(context);
            if (requests.isEmpty()) return pending("additional_metadata_location_setup_unavailable", required, completed, evidence);
            var entries = context.transcript().list(context.runId()); var ids = new HashSet<String>();
            require(entries.stream().allMatch(e -> e != null && context.runId().equals(e.runId()) && ids.add(e.id())));
            for (var request : requests) {
                required.add("retrieved-original:" + request.index());
                required.add("positive-control:" + request.index()); required.add("negative-control:" + request.index());
            }
            for (var request : requests) {
                failure = "additional_metadata_location_unreachable";
                var original = original(context, request);
                completed.add("retrieved-original:" + request.index());
                evidence.add(new EvidenceRef("transcript", original.response().id()));
                failure = "additional_metadata_location_controls_incomplete";
                for (var kind : List.of(ControlKind.POSITIVE, ControlKind.NEGATIVE)) {
                    var controls = controlEntries(context, original, kind); require(controls.size() == 1);
                    var control = controls.getFirst();
                    byte[] bytes = readOriginal(control);
                    require(Arrays.equals(bytes, AdditionalMetadataLocationControlProducer.bytes(definition.role(), original, kind)));
                    var publication = SecureXml.parse(bytes).getDocumentElement();
                    var locations = children(publication, "AdditionalMetadataLocation"); require(locations.size() == 1);
                    var location = locations.getFirst();
                    require(request.url().toString().equals(location.getTextContent())
                            && matches(location.getAttribute("namespace"), original.body()) == (kind == ControlKind.POSITIVE));
                    completed.add((kind == ControlKind.POSITIVE ? "positive-control:" : "negative-control:") + request.index());
                    evidence.add(new EvidenceRef("suite-calibration", control.id()));
                }
                if (!matches(request.namespace(), original.body())) mismatches.add(request.index());
            }
            evidence.add(new EvidenceRef("target-metadata", "sha256:" + requests.getFirst().snapshotHash()));
            var details = new LinkedHashMap<String, Object>();
            details.put("case_id", definition.id()); details.put("run_id", context.runId());
            details.put("approved_case_digest", definition.caseDigest()); details.put("snapshot_sha256", requests.getFirst().snapshotHash());
            details.put("checked_location_indices", requests.stream().map(Request::index).toList());
            details.put("mismatched_location_indices", List.copyOf(mismatches));
            details.put("suite_calibration_is_target_evidence", false); details.put("observed_variants", definition.coversVariants());
            String reason = REASON + (mismatches.isEmpty() ? ".satisfied" : ".violated");
            return new Observation(new CaseOutcome(mismatches.isEmpty() ? Outcome.SATISFIED : Outcome.VIOLATED,
                    null, reason, reason, List.copyOf(new LinkedHashSet<>(evidence)), details), required, completed);
        } catch (RuntimeException unavailable) { return pending(failure, required, completed, evidence); }
    }

    private Original original(CaseContext context, Request request) {
        var execution = executions.find(context.runId(), definition.id()).orElseThrow();
        require(PHASE.equals(execution.state().phase()) && request.snapshotHash().equals(
                execution.state().data().get("additional_metadata_snapshot_sha256")));
        var outbox = executions.findOutbox(request.actionId()).orElseThrow();
        require(owns(context, outbox) && outbox.status() == OutboxStatus.SENT);
        var entries = context.transcript().list(context.runId());
        var responses = entries.stream().filter(e -> e != null && Objects.equals(outbox.transcriptEntryId(), e.id())).toList();
        require(responses.size() == 1);
        var response = responses.getFirst();
        require(context.runId().equals(response.runId()) && response.direction() == Direction.INBOUND
                && "GET".equals(response.method()) && request.url().toString().equals(response.url())
                && request.actionId().equals(response.correlationId()) && Integer.valueOf(200).equals(response.status())
                && MetadataFetchOutboundSender.RESPONSE.equals(response.samlSummary().get("type"))
                && OutboundKind.METADATA_FETCH.name().equals(response.samlSummary().get("kind"))
                && request.url().toString().equals(response.samlSummary().get("response_url")));
        var outbound = entries.stream().filter(e -> e != null
                && Objects.equals(response.samlSummary().get("request_transcript"), e.id())).toList();
        require(outbound.size() == 1);
        var sent = outbound.getFirst();
        require(context.runId().equals(sent.runId()) && sent.direction() == Direction.OUTBOUND
                && "GET".equals(sent.method()) && sent.status() == null && sent.bodyBytes() == 0
                && request.url().toString().equals(sent.url()) && request.actionId().equals(sent.correlationId())
                && MetadataFetchOutboundSender.REQUEST.equals(sent.samlSummary().get("type"))
                && !response.timestamp().isBefore(sent.timestamp()));
        require(noCredentials(sent.headers()) && noCredentials(response.headers()));
        byte[] body = readOriginal(response);
        // Recorder hashes sanitized stored bytes. A changed body is not complete retrieval proof.
        require(hash(body).equals(response.samlSummary().get("original_body_sha256")));
        return new Original(request, response, body, namespace(body));
    }

    private byte[] readOriginal(TranscriptEntry entry) {
        byte[] body = content.readBody(entry);
        require(body != null && body.length > 0 && body.length == entry.bodyBytes()
                && hash(body).equals(entry.samlSummary().get("body_sha256")));
        return body;
    }

    private List<TranscriptEntry> controlEntries(CaseContext context, Original original, ControlKind kind) {
        return context.transcript().list(context.runId()).stream().filter(e -> e != null
                && context.runId().equals(e.runId()) && e.direction() == Direction.OUTBOUND
                && "SUITE_CONTROL".equals(e.method()) && e.status() == null
                && "urn:samlscope:calibration:additional-metadata-location".equals(e.url())
                && original.request().actionId().equals(e.correlationId())
                && AdditionalMetadataLocationControlProducer.TYPE.equals(e.samlSummary().get("type"))
                && definition.id().equals(e.samlSummary().get("case_id"))
                && definition.caseDigest().equals(e.samlSummary().get("case_digest"))
                && controlId(kind).equals(e.samlSummary().get("control_id"))
                && fixtureId(kind).equals(e.samlSummary().get("fixture_id"))
                && (kind == ControlKind.POSITIVE ? MATCH : DIFFERENT).equals(e.samlSummary().get("variant"))
                && original.response().id().equals(e.samlSummary().get("reference_response"))
                && Boolean.TRUE.equals(e.samlSummary().get("calibration_only"))
                && !e.timestamp().isBefore(original.response().timestamp())).toList();
    }

    private String controlId(ControlKind kind) { return definition.id().toLowerCase(Locale.ROOT) + (kind == ControlKind.POSITIVE ? "-positive" : "-negative"); }
    private String fixtureId(ControlKind kind) { return kind == ControlKind.POSITIVE
            ? definition.role() == TargetRole.IDP ? "idp-core-no-ecp" : "sp-core-minimal"
            : "mut-iip-md05-a8-" + definition.role().name().toLowerCase(Locale.ROOT); }
    static boolean matches(String declared, byte[] body) { return Objects.equals(declared, namespace(body)); }
    static String namespace(byte[] body) { return Objects.toString(MetadataFetchOutboundSender.root(body).getNamespaceURI(), ""); }
    static String hash(byte[] body) { return MetadataFetchOutboundSender.hash(body); }
    private static boolean noCredentials(Map<String, List<String>> headers) { return headers.keySet().stream()
            .noneMatch(k -> Set.of("authorization", "proxy-authorization", "cookie", "set-cookie").contains(k.toLowerCase(Locale.ROOT))); }
    private static boolean sameAction(OutboundAction a, OutboundAction b) { return a.actionId().equals(b.actionId())
            && a.kind() == b.kind() && a.target().equals(b.target()) && b.payload().length == 0 && !b.requiresEphemeralCredential(); }
    private Observation pending(String reason, List<String> required, List<String> completed, List<EvidenceRef> evidence) {
        return new Observation(new CaseOutcome(Outcome.NOT_VERIFIED, reason, REASON + ".incomplete", REASON + ".incomplete",
                evidence, Map.of("case_id", definition.id(), "suite_calibration_is_target_evidence", false)), required, completed);
    }
    private static List<Element> children(Element element, String name) {
        var result = new ArrayList<Element>();
        for (var child = element.getFirstChild(); child != null; child = child.getNextSibling())
            if (child instanceof Element e && MD.equals(e.getNamespaceURI()) && name.equals(e.getLocalName())) result.add(e);
        return result;
    }
    private static void require(boolean valid) { if (!valid) throw new IllegalArgumentException("Additional metadata original evidence is incomplete"); }
}
