package com.samlscope.runner.cases;

import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.plan.TargetRole;
import com.samlscope.core.transcript.*;
import com.samlscope.runner.BrowserFrontChannelScenario;
import com.samlscope.runner.OperatorAssistedCase;
import com.samlscope.runner.RecordedEvidenceReevaluation;
import com.samlscope.saml.logout.SloPropagationFixtures;
import com.samlscope.saml.normal.SecureXml;
import java.net.URI;
import java.time.Duration;
import java.util.*;
import java.util.function.Function;
import org.w3c.dom.Element;

/** Collects two real SOAP logout windows; only the original-backed observer can conclude r. */
public final class SoapSloPropagationTestCase implements TestCase, BrowserFrontChannelScenario,
        BrowserPrompt, ConfigurationPrompt, ProtocolEvidenceCase, RecordedEvidenceReevaluation, OperatorAssistedCase {
    public static final String ID = "IIP-IDP17-r-idp-01";
    private static final String VERSION = "soap-slo-propagation-v1";
    private final TestCase observer;
    private final Function<String, IdpBasicLogoutScenarioTestCase.Configuration> configurations;
    private final TranscriptContentReader content;
    private final Function<String, byte[]> targetMetadata;
    public SoapSloPropagationTestCase(TestCase observer,
            Function<String, IdpBasicLogoutScenarioTestCase.Configuration> configurations, TranscriptContentReader content) {
        this(observer, configurations, content, null);
    }
    private SoapSloPropagationTestCase(TestCase observer,
            Function<String, IdpBasicLogoutScenarioTestCase.Configuration> configurations, TranscriptContentReader content,
            Function<String, byte[]> metadata) {
        this.observer = Objects.requireNonNull(observer); this.configurations = Objects.requireNonNull(configurations);
        this.content = Objects.requireNonNull(content); this.targetMetadata = metadata;
        if (!ID.equals(observer.id())) throw new IllegalArgumentException("SOAP propagation owns only r");
    }
    public SoapSloPropagationTestCase withTargetMetadata(Function<String, byte[]> metadata) {
        return new SoapSloPropagationTestCase(observer, configurations, content, Objects.requireNonNull(metadata));
    }
    @Override public String id() { return ID; }
    @Override public TargetRole role() { return TargetRole.IDP; }
    @Override public boolean plansFreshSessionBoundary() { return true; }
    @Override public boolean requiresFreshSession(CaseState state) {
        return "primary".equals(state.data().get("soap_phase")) && "login".equals(state.data().get("stage"));
    }
    @Override public Binding outboundBinding(CaseState state) { return Binding.HTTP_POST; }
    @Override public String instructionsEn(CaseState state) { return browserInstructionsEn(); }
    @Override public String instructionEn() { return "Apply the MetadataPrepared original for the current SOAP trial to the target, and verify that all four participant entities and their SOAP endpoints are registered. Confirm only after the native metadata read-back matches that trial. Preserve the original configuration for exact restoration; do not enter a verdict."; }
    @Override public String browserInstructionsEn() { return "Apply the prepared three-participant SOAP metadata, then use one browser session for all four registrations. The Suite sends the origin logout through its outbox. The two trials and native continuation originals are required; do not enter a verdict."; }
    @Override public boolean requiresPreparationConfirmation() { return true; }
    @Override public CaseStep start(CaseContext context) {
        if (observer instanceof LogoutBrowserEvidenceTestCase logout && logout.nativeOwned(context)) return observer.start(context);
        if (evidenceStatus(context).ready()) return observer.start(context);
        if (!context.transcriptComplete() || !context.interaction().allowBrowserSteps() || targetMetadata == null)
            return finish("slo.propagation.soap-preparation-unavailable");
        try {
            var c = configuration(context);
            var at = context.clock().instant();
            for (var trial : List.of("failure", "all-success")) {
                var xml = SloPropagationFixtures.prepare(URI.create(c.login().suiteIssuer()), c.login().registeredAcs(),
                        c.suiteCredentials(), context.runId(), trial, at);
                var plan = URI.create(c.login().suiteIssuer()).getPath(); plan = plan.substring(plan.lastIndexOf('/') + 1);
                var entry = context.transcript().record(new TranscriptInput(context.runId(), Direction.OUTBOUND, at,
                        null, "PREPARE", c.login().suiteIssuer(), null, Map.of(), xml, "application/samlmetadata+xml", null, xml,
                        Map.of("type", "MetadataPrepared", "variant", SloPropagationFixtures.variant(trial), "case_id", ID,
                                "run_id", context.runId(), "plan_id", plan, "prepared_at", at.toString(),
                                "backchannel_base", callbackBase(c).toString())));
                if (!context.runId().equals(entry.runId()) || entry.decodedSamlBytes() != xml.length)
                    throw new IllegalArgumentException("Preparation recording is unbound");
            }
            return prepare("failure");
        } catch (IllegalArgumentException | com.samlscope.saml.normal.SamlException invalid) {
            return finish("slo.propagation.soap-preparation-unavailable");
        }
    }
    private static URI callbackBase(IdpBasicLogoutScenarioTestCase.Configuration c) {
        var issuer = c.login().suiteIssuer();
        return SloPropagationFixtures.configuredBackchannelBase(URI.create(issuer.substring(0, issuer.lastIndexOf("/p/"))));
    }
    private IdpBasicLogoutScenarioTestCase.Configuration configuration(CaseContext context) {
        var c = configurations.apply(context.runId());
        if (c == null || !c.login().preconditionsSatisfied() || c.suiteCredentials() == null || c.targetSigningCertificates().isEmpty())
            throw new IllegalArgumentException("SOAP setup incomplete");
        var root = SecureXml.parse(targetMetadata.apply(context.runId())).getDocumentElement();
        if (!"EntityDescriptor".equals(root.getLocalName()) || !c.targetIssuer().equals(root.getAttribute("entityID")))
            throw new IllegalArgumentException("Foreign target metadata");
        var endpoints = root.getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:metadata", "SingleLogoutService");
        var selected = new ArrayList<URI>();
        for (int i = 0; i < endpoints.getLength(); i++) {
            var e = (Element) endpoints.item(i);
            if ("IDPSSODescriptor".equals(e.getParentNode().getLocalName())
                    && "urn:oasis:names:tc:SAML:2.0:bindings:SOAP".equals(e.getAttribute("Binding")))
                selected.add(URI.create(e.getAttribute("Location")));
        }
        if (selected.size() != 1 || !selected.getFirst().isAbsolute() || selected.getFirst().getRawUserInfo() != null)
            throw new IllegalArgumentException("Target SOAP endpoint not uniquely advertised");
        var issuer = c.login().suiteIssuer();
        var suffix = issuer.substring(issuer.lastIndexOf("/p/"));
        return new IdpBasicLogoutScenarioTestCase.Configuration(c.login(), selected.getFirst(),
                URI.create(callbackBase(c) + suffix + "/sp/slo/soap"), c.targetIssuer(), c.suiteCredentials(), c.targetSigningCertificates());
    }
    private IdpBasicLogoutScenarioTestCase delegate(CaseContext context, String trial, String participant) {
        var c = configuration(context);
        if (!"primary".equals(participant)) {
            var old = c.login();
            var login = new IdpErrorProbeConfiguration(old.ssoEndpoint(), old.suiteIssuer() + "/sp-" + participant,
                    old.registeredAcs(), old.responseTimeout(), old.userAgentAvailable(), old.acceptableResponseLocationKnown(), old.freshSessionGateAvailable(), old.encryptionKeys());
            c = new IdpBasicLogoutScenarioTestCase.Configuration(login, c.logoutEndpoint(), c.suiteLogoutEndpoint(), c.targetIssuer(), c.suiteCredentials(), c.targetSigningCertificates());
        }
        var selected = c;
        return IdpBasicLogoutScenarioTestCase.soapPropagation(ignored -> selected, content,
                trial + ("primary".equals(participant) ? "" : "-" + participant));
    }
    @Override public CaseStep resume(CaseContext context, CaseState state, CaseEvent event) {
        if (observer instanceof LogoutBrowserEvidenceTestCase logout && logout.nativeOwned(context)) return observer.start(context);
        if (!VERSION.equals(state.data().get("soap_definition")) || !List.of("failure", "all-success").contains(state.data().get("soap_trial")))
            return finish("slo.propagation.soap-state-unavailable");
        var trial = (String) state.data().get("soap_trial");
        if (event instanceof CaseEvent.Aborted || event instanceof CaseEvent.TimedOut || event instanceof CaseEvent.InboundUnavailable)
            return finish("slo.propagation.soap-trial-incomplete");
        try {
            if ("configure".equals(state.data().get("soap_phase"))) {
                if (!(event instanceof CaseEvent.ConfigConfirmed)) return finish("slo.propagation.soap-configuration-unconfirmed");
                return wrap(delegate(context, trial, "primary").start(context), trial, "primary", Map.of());
            }
            var phase = (String) state.data().get("soap_phase");
            var participant = "origin".equals(phase) ? "primary" : phase;
            if (!(event instanceof CaseEvent.InboundMessage inbound)) return finish("slo.propagation.soap-inbound-unavailable");
            var step = delegate(context, trial, participant).resume(context, state, event);
            if ("origin".equals(phase)) {
                if (!(step instanceof CaseStep.Finish f) || !"slo.propagation.native-chain-pending".equals(f.outcome().reasonCode())) return step;
                return "failure".equals(trial) ? prepare("all-success") : finish("slo.propagation.native-chain-pending");
            }
            if (!(step instanceof CaseStep.AwaitInbound waiting) || !"logout".equals(waiting.next().data().get("stage"))) return step;
            var carry = new LinkedHashMap<String,Object>();
            if ("primary".equals(phase)) {
                carry.put("soap_primary_state", state.data()); carry.put("soap_primary_phase", state.phase());
                carry.put("soap_primary_reference", inbound.evidence().reference());
            } else for (var key : List.of("soap_primary_state", "soap_primary_phase", "soap_primary_reference")) carry.put(key, state.data().get(key));
            if (!"remain2".equals(phase)) {
                var next = switch (phase) { case "primary" -> "fail"; case "fail" -> "remain"; case "remain" -> "remain2"; default -> throw new IllegalArgumentException("Unknown participant"); };
                return wrap(delegate(context, trial, next).start(context), trial, next, carry);
            }
            var primary = primaryState(carry);
            var refs = context.transcript().list(context.runId()).stream().filter(e -> carry.get("soap_primary_reference").equals(e.id())).toList();
            if (refs.size() != 1 || !context.runId().equals(refs.getFirst().runId()) || refs.getFirst().direction() != Direction.INBOUND)
                return finish("slo.propagation.soap-primary-original-unavailable");
            var original = content.readDecodedSaml(refs.getFirst());
            if (original.length != refs.getFirst().decodedSamlBytes()) return finish("slo.propagation.soap-primary-original-unavailable");
            var origin = delegate(context, trial, "primary").resume(context, primary,
                    new CaseEvent.InboundMessage(original, new EvidenceRef("transcript", refs.getFirst().id())));
            return wrap(origin, trial, "origin", carry);
        } catch (IllegalArgumentException | com.samlscope.saml.normal.SamlException invalid) {
            return finish("slo.propagation.soap-state-unavailable");
        }
    }
    private static CaseState primaryState(Map<String,Object> data) {
        if (!(data.get("soap_primary_state") instanceof Map<?,?> source) || !(data.get("soap_primary_phase") instanceof String phase))
            throw new IllegalArgumentException("Primary state missing");
        var map = new LinkedHashMap<String,Object>();
        for (var e : source.entrySet()) { if (!(e.getKey() instanceof String key)) throw new IllegalArgumentException("Bad state"); map.put(key,e.getValue()); }
        return new CaseState(phase, map);
    }
    private static CaseStep wrap(CaseStep step, String trial, String phase, Map<String,Object> carry) {
        if (!(step instanceof CaseStep.AwaitInbound waiting)) return step;
        var data = new LinkedHashMap<String,Object>(waiting.next().data()); data.putAll(carry);
        data.put("soap_definition", VERSION); data.put("soap_trial", trial); data.put("soap_phase", phase);
        return new CaseStep.AwaitInbound(new CaseState(waiting.next().phase(),data), waiting.actions(),waiting.matcher(),waiting.ttl());
    }
    private static CaseStep prepare(String trial) {
        return new CaseStep.AwaitConfig(new CaseState(VERSION + "-" + trial, Map.of("soap_definition", VERSION,
                "soap_trial", trial, "soap_phase", "configure")), List.of(), "slo.propagation.soap.apply-prepared-metadata", Duration.ofMinutes(15));
    }
    private static CaseStep finish(String reason) { return new CaseStep.Finish(CaseOutcome.notVerified("native_soap_continuation_originals_required", reason)); }
    @Override public EvidenceStatus evidenceStatus(CaseContext context) {
        if (observer instanceof LogoutBrowserEvidenceTestCase logout && logout.nativeOwned(context)
                && observer instanceof ProtocolEvidenceCase p) return p.evidenceStatus(context);
        // Partial browser evidence cannot confirm the next native metadata preparation.
        return new EvidenceStatus(false,List.of("native-soap-continuation"),List.of(),Map.of());
    }
    @Override public boolean supportsRecordedEvidenceReevaluation(CaseOutcome previous) {
        return observer instanceof RecordedEvidenceReevaluation r && r.supportsRecordedEvidenceReevaluation(previous);
    }
    @Override public Optional<CaseOutcome> reevaluateRecordedEvidence(CaseContext context, CaseOutcome previous) {
        return observer instanceof RecordedEvidenceReevaluation r ? r.reevaluateRecordedEvidence(context, previous) : Optional.empty();
    }
}
