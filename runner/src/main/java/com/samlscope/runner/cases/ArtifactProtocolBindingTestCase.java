package com.samlscope.runner.cases;

import java.net.URI;
import java.util.*;
import java.util.function.Function;
import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.plan.TargetRole;
import com.samlscope.core.transcript.*;
import com.samlscope.runner.BrowserFrontChannelScenario;
import com.samlscope.runner.outbox.ArtifactResolutionOutboundSender;
import com.samlscope.saml.artifact.*;
import com.samlscope.saml.normal.*;

/** Opt-in, approved conditional Artifact leg; the installed B matrix is the same generic delegate. */
public final class ArtifactProtocolBindingTestCase implements TestCase, BrowserFrontChannelScenario, BrowserPrompt {
    private static final String SCHEMA="samlscope-protocol-binding-artifact-state-v1";
    private final IdpAcsSelectionScenarioTestCase bindings;
    private final Function<String,IdpErrorProbeConfiguration> configurations;
    private final ArtifactBindingEvidence artifacts;
    private final Function<String,Optional<OutboxEntry>> outbox;
    private final TranscriptContentReader content;
    public ArtifactProtocolBindingTestCase(IdpAcsSelectionScenarioTestCase bindings,
            Function<String,IdpErrorProbeConfiguration> configurations, ArtifactBindingEvidence artifacts,
            Function<String,Optional<OutboxEntry>> outbox, TranscriptContentReader content) {
        if(!IdpAcsSelectionScenarioTestCase.BINDING_CASE.equals(bindings.id()))throw new IllegalArgumentException("Artifact observation is scoped to IDP12.f");
        this.bindings=Objects.requireNonNull(bindings);this.configurations=Objects.requireNonNull(configurations);
        this.artifacts=Objects.requireNonNull(artifacts);this.outbox=Objects.requireNonNull(outbox);this.content=Objects.requireNonNull(content);
    }
    @Override public String id(){return bindings.id();}
    @Override public TargetRole role(){return TargetRole.IDP;}
    @Override public String browserInstructionsEn(){return "Use the same browser session for POST, unsupported-binding controls and the conditional Artifact request. SAMLscope resolves the Artifact through its outbox and checks the original response; do not submit a verdict.";}
    @Override public String instructionsEn(CaseState state){return browserInstructionsEn();}
    @Override public CaseStep start(CaseContext context){return bindings.start(context);}
    @Override public CaseStep resume(CaseContext context,CaseState state,CaseEvent event){
        if(!SCHEMA.equals(state.data().get("artifact_schema"))){
            var next=bindings.resume(context,state,event);
            if(next instanceof CaseStep.Finish finish && "B".equals(finish.outcome().details().get("positive_protocol_binding_evidence"))) {
                return artifactRequest(context,finish.outcome());
            }
            return next;
        }
        try{
            require(artifacts.metadataSha256(context.runId()).equals(state.data().get("target_metadata_sha256")));
            var config=configurations.apply(context.runId());var acs=config.registeredAcs().resolve("4");
            require(acs.toString().equals(state.data().get("artifact_acs")));
            var authnAction=ActionIds.derive(context.runId(),id(),ArtifactBindingEvidence.PHASE,0);
            var resolveAction=ActionIds.derive(context.runId(),id(),ArtifactResolutionOutboundSender.PHASE,0);
            require(authnAction.equals(state.data().get("artifact_authn_action")));
            if(ArtifactBindingEvidence.PHASE.equals(state.phase()) && event instanceof CaseEvent.InboundMessage received){
                require("transcript".equals(received.evidence().kind()));
                var reference=received.evidence().reference();
                var entries=context.transcript().listBounded(context.runId(),10000).stream().filter(e->reference.equals(e.id())).toList();require(entries.size()==1);
                require(Arrays.equals(received.decodedSaml(),artifacts.receivedArtifact(context,entries.getFirst(),acs).bytes()));
                var action=artifacts.prepare(context,entries.getFirst(),acs);require(resolveAction.equals(action.actionId()));
                var data=new LinkedHashMap<>(state.data());data.put("artifact_receipt_reference",reference);data.put("artifact_resolve_action",resolveAction);
                return new CaseStep.AwaitInbound(new CaseState(ArtifactResolutionOutboundSender.PHASE,data),List.of(action),
                        new InboundMatcher("saml-response",Map.of("ScenarioActionId",resolveAction)),config.responseTimeout());
            }
            if(ArtifactResolutionOutboundSender.PHASE.equals(state.phase()) && event instanceof CaseEvent.InboundMessage message){
                require(resolveAction.equals(state.data().get("artifact_resolve_action")) && "transcript".equals(message.evidence().kind()));
                var entry=outbox.apply(resolveAction).orElseThrow();require(message.evidence().reference().equals(entry.transcriptEntryId()));
                var initial=outbox.apply(authnAction).orElseThrow();
                require(context.runId().equals(initial.runId()) && id().equals(initial.caseId())
                        && initial.status()==OutboxStatus.SENT && initial.action().kind()==OutboundKind.AUTHN_REQUEST
                        && config.ssoEndpoint().equals(initial.action().target()));
                var source=context.transcript().listBounded(context.runId(),10000).stream().filter(e->e.direction()==Direction.OUTBOUND
                        && authnAction.equals(e.correlationId())).toList();
                require(source.size()==1 && Arrays.equals(initial.action().payload(),content.readDecodedSaml(source.getFirst())));
                var originals=context.transcript().listBounded(context.runId(),10000).stream().filter(e->entry.transcriptEntryId().equals(e.id())).toList();require(originals.size()==1
                        && Arrays.equals(message.decodedSaml(),content.readDecodedSaml(originals.getFirst())));
                var proof=artifacts.read(context,entry,acs).orElseThrow();require(proof.evidence().stream().anyMatch(e->e.reference().equals(state.data().get("artifact_receipt_reference"))));
                if(!ArtifactResolutionProtocol.SUCCESS.equals(proof.resolved().status()))return unavailable(state,"idp.binding-probe.artifact-success-unobserved");
                var root=SecureXml.parse(proof.resolved().responseXml()).getDocumentElement();
                require(!MetadataAlgorithmEvidence.children(root,ArtifactResolutionProtocol.A,"Assertion").isEmpty()
                        || !MetadataAlgorithmEvidence.children(root,ArtifactResolutionProtocol.A,"EncryptedAssertion").isEmpty());
                require(bindings.stillProvesBindingB(context,references(state)));
                var refs=new LinkedHashSet<>(references(state));refs.addAll(proof.evidence());
                return new CaseStep.Finish(new CaseOutcome(Outcome.SATISFIED,null,"idp.acs-probe.satisfied","case.idp.acs-probe.satisfied",List.copyOf(refs),
                        Map.of("completed_binding_fixtures",List.of("post-binding-control","redirect-binding","unsupported-binding",ArtifactBindingEvidence.FIXTURE),
                                "positive_protocol_binding_evidence",List.of("A","B"),"artifact_applicability","observed_supported",
                                "artifact_switch_variant","observed","artifact_authentication",proof.resolved().authentication(),
                                "recommended_source_id_mapping",proof.recommendedSourceIdMapping(),"operator_verdict_requested",false)));
            }
            return unavailable(state,event instanceof CaseEvent.TimedOut || event instanceof CaseEvent.InboundUnavailable
                    ? "idp.binding-probe.artifact-delivery-unknown" : "idp.binding-probe.artifact-observation-unavailable");
        }catch(Exception unbound){return unavailable(state,"idp.binding-probe.artifact-evidence-unbound");}
    }
    private CaseStep artifactRequest(CaseContext context,CaseOutcome b){
        var config=configurations.apply(context.runId());var acs=config.registeredAcs().resolve("4");
        var action=ActionIds.derive(context.runId(),id(),ArtifactBindingEvidence.PHASE,0);
        var request=new SamlAcsSelectionRequestFactory().build(SamlAcsSelectionRequestFactory.Fixture.ARTIFACT_BINDING,
                "_"+action,config.ssoEndpoint(),config.suiteIssuer(),acs,config.registeredAcs().resolve("1"),context.clock().instant());
        var data=Map.<String,Object>of("artifact_schema",SCHEMA,"fixture_id",ArtifactBindingEvidence.FIXTURE,"artifact_acs",acs.toString(),"artifact_authn_action",action,
                "target_metadata_sha256",artifacts.metadataSha256(context.runId()),"binding_b_evidence",b.evidence().stream().map(EvidenceRef::reference).toList());
        return new CaseStep.AwaitInbound(new CaseState(ArtifactBindingEvidence.PHASE,data),
                List.of(new OutboundAction(action,OutboundKind.AUTHN_REQUEST,request,config.ssoEndpoint(),false,OutboundAction.RequestSigning.REQUIRE)),
                new InboundMatcher("saml-artifact",Map.of("ScenarioActionId",action)),config.responseTimeout());
    }
    private static List<EvidenceRef> references(CaseState state){
        require(state.data().get("binding_b_evidence") instanceof List<?> values && values.stream().allMatch(v->v instanceof String));
        return ((List<?>)state.data().get("binding_b_evidence")).stream().map(v->new EvidenceRef("transcript",(String)v)).toList();
    }
    private static CaseStep unavailable(CaseState state,String reason){
        List<EvidenceRef> refs;try{refs=references(state);}catch(Exception invalid){refs=List.of();}
        return new CaseStep.Finish(new CaseOutcome(Outcome.NOT_VERIFIED,reason,reason,"idp.acs-probe.inconclusive",refs,
                Map.of("artifact_applicability","unknown","artifact_switch_variant","unproven","operator_verdict_requested",false)));
    }
    private static void require(boolean value){if(!value)throw new IllegalArgumentException("Unbound Artifact case state");}
}
