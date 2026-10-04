package com.samlscope.runner.cases;

import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.plan.TargetRole;
import com.samlscope.core.transcript.TranscriptContentReader;
import com.samlscope.runner.BrowserFrontChannelScenario;
import com.samlscope.runner.RecordedEvidenceReevaluation;
import com.samlscope.runner.scenario.*;
import com.samlscope.saml.crypto.PlanCredentials;
import com.samlscope.saml.normal.*;
import java.net.URI;
import java.nio.file.Path;
import java.util.*;
import java.util.function.*;
import org.w3c.dom.Element;

/** Outbox collection only: native role/purpose originals, not browser completion, decide the case. */
public final class MetadataRoleKeyProbeTestCase implements TestCase, BrowserFrontChannelScenario,
        ConfigurationPrompt, ProtocolEvidenceCase, RecordedEvidenceReevaluation {
    public static final String CASE="IIP-MD06-a2-idp-01";
    static final List<String> VARIANTS=List.of("role-keys-sp-first-explicit-a","role-keys-idp-first-explicit-b",
            "role-keys-sp-first-omitted-a","role-keys-idp-first-omitted-b");
    static final List<String> FIXTURES=List.of("explicit-a-normal","explicit-a-peer-key","explicit-a-encryption-key","explicit-a-invalid-signature",
            "explicit-b-normal","explicit-b-peer-key","explicit-b-encryption-key","omitted-a-normal","omitted-a-peer-key","omitted-b-normal","omitted-b-peer-key");
    private final TestCase fallback;private final Function<String,byte[]> metadata;
    private final TranscriptContentReader content;private final BiFunction<String,String,Optional<PlanCredentials>> keys;
    private final MetadataRoleKeyEvidence evidence;
    public MetadataRoleKeyProbeTestCase(TestCase fallback,Function<String,byte[]> metadata,
            TranscriptContentReader content,BiFunction<String,String,Optional<PlanCredentials>> keys,Path directory) {
        this(fallback,metadata,content,keys,directory,new MetadataRoleKeyNativeAdapter[0]);
    }
    public MetadataRoleKeyProbeTestCase(TestCase fallback,Function<String,byte[]> metadata,
            TranscriptContentReader content,BiFunction<String,String,Optional<PlanCredentials>> keys,Path directory,
            MetadataRoleKeyNativeAdapter... adapters) {
        if(!CASE.equals(fallback.id()))throw new IllegalArgumentException("Unsupported role-key case");
        this.fallback=Objects.requireNonNull(fallback);this.metadata=Objects.requireNonNull(metadata);this.content=Objects.requireNonNull(content);this.keys=Objects.requireNonNull(keys);
        evidence=new MetadataRoleKeyEvidence(directory,content,metadata,keys,adapters);
    }
    @Override public String id(){return fallback.id();}
    @Override public TargetRole role(){return fallback.role();}
    @Override public String instructionEn(){return "Prepare the four dual-role metadata fixtures through the product's native consumer; reuse one authenticated browser for normal and role/purpose controls, then restore the original configuration.";}
    @Override public String instructionsEn(CaseState state){return "Execute the recorded role-key fixture using the same authenticated browser. Native metadata preparation and restoration must be automated or completed by the administrator.";}
    @Override public String evidenceCampaignId(){return "native-role-key-consumption";}
    @Override public String evidenceCampaignTitle(){return "Role and purpose key consumption";}
    // The shared BrowserFrontChannelScenario login key deliberately remains one. Eleven protocol
    // controls do not mean eleven user logins and none introduces a fresh-session boundary.
    private CaseOutcome pending(){return CaseOutcome.notVerified("native_role_key_originals_unavailable","metadata.role-keys.native-unproven");}
    private CaseOutcome observed(CaseContext context){return evidence.evaluate(context).orElseGet(this::pending);}
    @Override public CaseStep start(CaseContext context) {
        if(evidence.exists(context.runId()))return new CaseStep.Finish(observed(context));
        try{return scenario(context).start(context);}catch(RuntimeException missing){return fallback.start(context);}
    }
    @Override public CaseStep resume(CaseContext context,CaseState state,CaseEvent event) {
        if(evidence.exists(context.runId()))return new CaseStep.Finish(observed(context));
        if(state.phase().startsWith("await-fixture-")) {
            try{var next=scenario(context).resume(context,state,event);return next instanceof CaseStep.Finish?new CaseStep.Finish(pending()):next;}
            catch(RuntimeException unavailable){return new CaseStep.Finish(pending());}
        }
        if(event instanceof CaseEvent.ConfigConfirmed){try{return scenario(context).start(context);}catch(RuntimeException missing){return new CaseStep.Finish(pending());}}
        return fallback.resume(context,state,event);
    }
    @Override public EvidenceStatus evidenceStatus(CaseContext context) {
        var result=observed(context);boolean ready=result.outcome()==Outcome.SATISFIED||result.outcome()==Outcome.VIOLATED;
        return new EvidenceStatus(ready,FIXTURES,ready?FIXTURES:List.of(),result.details());
    }
    @Override public boolean supportsRecordedEvidenceReevaluation(CaseOutcome before){return before!=null&&before.outcome()==Outcome.NOT_VERIFIED;}
    @Override public Optional<CaseOutcome> reevaluateRecordedEvidence(CaseContext context,CaseOutcome before) {
        return supportsRecordedEvidenceReevaluation(before)?RecordedEvidenceReevaluation.conclusiveUpdate(before,observed(context)):Optional.empty();
    }
    private FixtureScenarioTestCase scenario(CaseContext context) {
        require(context.targetRole()==TargetRole.IDP);
        var prepared=new HashMap<String,Element>();
        for(var variant:VARIANTS){var entries=context.transcript().list(context.runId()).stream().filter(e->"MetadataPrepared".equals(e.samlSummary().get("type"))&&variant.equals(e.samlSummary().get("variant"))&&"live".equals(e.samlSummary().get("feed"))).toList();require(entries.size()==1&&context.runId().equals(entries.getFirst().runId()));var raw=SecureXml.parse(content.readDecodedSaml(entries.getFirst())).getDocumentElement();try{MetadataRoleKeyEvidence.validatePrepared(raw,variant,context.runId(),keys);}catch(Exception unavailable){throw new IllegalStateException("Approved dual-role preparation unavailable",unavailable);}prepared.put(variant,raw);}
        var target=SecureXml.parse(metadata.apply(context.runId())).getDocumentElement();var destination=sso(target);var fixtures=new ArrayList<ScenarioFixture>();
        for(var fixture:FIXTURES){String variant=variant(fixture);var peer=prepared.get(variant);String entity=peer.getAttribute("entityID");var acs=MetadataSupersessionProbeTestCase.acs(peer,0);
            String selected=fixture.endsWith("encryption-key")?"three-signing-keys":fixture.endsWith("peer-key")?(variant.contains("idp-first")?"three-signing-keys-first":"three-signing-keys-second"):(variant.contains("idp-first")?"three-signing-keys-second":"three-signing-keys-first");
            var key=keys.apply(context.runId(),selected).orElseThrow();var kind=fixture.endsWith("invalid-signature")?SamlSignedRequestFactory.Fixture.BAD_SIGNATURE_VALUE:SamlSignedRequestFactory.Fixture.VALID;
            fixtures.add(new Probe(fixture,entity,destination,acs,selected,key,kind));}
        return new FixtureScenarioTestCase(id(),TargetRole.IDP,fixtures,ignored->true,new FixtureScenarioTestCase.Vocabulary("native_preparation_unavailable","metadata.role-keys.native-unproven","delivery_unknown","metadata.role-keys.delivery-unknown","aborted","metadata.role-keys.aborted","metadata.role-keys.control-failed","metadata.role-keys.native-unproven","metadata.role-keys.native-unproven","native_originals_pending","metadata.role-keys.native-unproven","metadata.role-keys.native-unproven","metadata.role-keys.native-unproven","metadata.role-keys.native-unproven"));
    }
    static String variant(String fixture) {
        if(fixture.startsWith("explicit-a-"))return VARIANTS.get(0);if(fixture.startsWith("explicit-b-"))return VARIANTS.get(1);if(fixture.startsWith("omitted-a-"))return VARIANTS.get(2);if(fixture.startsWith("omitted-b-"))return VARIANTS.get(3);throw new IllegalArgumentException("Unknown fixture");
    }
    private static URI sso(Element target){var values=target.getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:metadata","SingleSignOnService");for(int i=0;i<values.getLength();i++){var e=(Element)values.item(i);if("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST".equals(e.getAttribute("Binding")))return URI.create(e.getAttribute("Location"));}throw new IllegalStateException("POST endpoint unavailable");}
    private static void require(boolean condition){if(!condition)throw new IllegalStateException("Native fixture precondition unavailable");}
    private record Probe(String id,String entity,URI destination,URI acs,String keyVariant,PlanCredentials key,SamlSignedRequestFactory.Fixture kind) implements ScenarioFixture {
        @Override public Prepared prepare(CaseContext context,String actionId){var requestId="_"+actionId;var request=new SamlSignedRequestFactory().build(kind,requestId,destination,entity,acs,context.clock().instant(),key);return new Prepared(new OutboundAction(actionId,OutboundKind.AUTHN_REQUEST,request,destination,false),requestId);}
        @Override public FixtureObservation observe(String correlation,byte[] raw){return FixtureObservation.NOT_VERIFIED;}
        @Override public String definitionKey(){return "native-role-key-consumption-v1|"+id+"|"+entity+"|"+destination+"|"+acs+"|"+keyVariant+"|"+kind;}
    }
}
