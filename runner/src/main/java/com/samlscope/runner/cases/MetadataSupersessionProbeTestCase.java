package com.samlscope.runner.cases;

import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.CaseOutcome;
import com.samlscope.core.plan.TargetRole;
import com.samlscope.core.transcript.TranscriptContentReader;
import com.samlscope.runner.BrowserFrontChannelScenario;
import com.samlscope.runner.RecordedEvidenceReevaluation;
import com.samlscope.runner.ScenarioRedirectCredentials;
import com.samlscope.runner.scenario.*;
import com.samlscope.saml.crypto.PlanCredentials;
import com.samlscope.saml.normal.SamlSignedRequestFactory;
import com.samlscope.saml.normal.SamlLogoutRequestFactory;
import com.samlscope.saml.normal.SecureXml;
import java.net.URI;
import java.nio.file.Path;
import java.util.*;
import java.util.function.BiFunction;
import java.util.function.Function;
import org.w3c.dom.Element;

/**
 * Collects immutable outbox controls after native A/B metadata preparation. The browser transition
 * never determines conformance: only restored native originals and the final evidence reader do.
 */
public final class MetadataSupersessionProbeTestCase implements TestCase, BrowserFrontChannelScenario,
        ScenarioRedirectCredentials, ConfigurationPrompt, ProtocolEvidenceCase, RecordedEvidenceReevaluation {
    public static final String APPLICATION = "IIP-MD06-a-idp-01";
    public static final String SUPERSESSION = "IIP-MD06-ab-idp-01";
    private static final String MD = "urn:oasis:names:tc:SAML:2.0:metadata";
    private static final String P = "urn:oasis:names:tc:SAML:2.0:protocol";
    private static final String POST = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";
    private static final String REDIRECT = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect";
    private static final String SOAP = "urn:oasis:names:tc:SAML:2.0:bindings:SOAP";
    static final List<String> FIXTURES = List.of("new-key-explicit-acs", "new-key-default-acs",
            "new-key-second-acs", "new-key-redirect", "old-key-new-acs", "rollover-first-key-new-acs",
            "rollover-second-key-new-acs", "new-key-old-acs", "new-key-invalid-signature");
    static final List<String> SLO_FIXTURES = List.of("new-key-slo-route", "old-key-slo-route",
            "new-key-invalid-signature-slo-route");
    private final TestCase fallback;
    private final Function<String,byte[]> targetMetadata;
    private final TranscriptContentReader content;
    private final BiFunction<String,String,Optional<PlanCredentials>> keys;
    private final ShibbolethMetadataSupersessionEvidenceFile evidence;
    private final KeycloakMetadataSupersessionEvidenceFile keycloakEvidence;
    private final ShibbolethMetadataApplicationEvidence applicationEvidence;

    public MetadataSupersessionProbeTestCase(TestCase fallback, Function<String,byte[]> targetMetadata,
            TranscriptContentReader content, BiFunction<String,String,Optional<PlanCredentials>> keys, Path directory) {
        this(fallback,targetMetadata,content,keys,directory,run->Optional.empty());
    }
    public MetadataSupersessionProbeTestCase(TestCase fallback, Function<String,byte[]> targetMetadata,
            TranscriptContentReader content, BiFunction<String,String,Optional<PlanCredentials>> keys, Path directory,
            SamlDecryptionKeyProvider primaryKeys) {
        this.fallback=Objects.requireNonNull(fallback); this.targetMetadata=Objects.requireNonNull(targetMetadata);
        this.content=Objects.requireNonNull(content); this.keys=Objects.requireNonNull(keys);
        this.evidence=new ShibbolethMetadataSupersessionEvidenceFile(content,directory,targetMetadata,keys);
        this.keycloakEvidence=new KeycloakMetadataSupersessionEvidenceFile(directory,content,keys);
        this.applicationEvidence=new ShibbolethMetadataApplicationEvidence(
            directory.toAbsolutePath().normalize().getParent().resolve("shibboleth-metadata-application-evidence"),
            content,targetMetadata,keys,primaryKeys==null?run->Optional.empty():primaryKeys);
        if(!supports(fallback.id()))throw new IllegalArgumentException("Unsupported metadata supersession case");
    }
    public static boolean supports(String id){return APPLICATION.equals(id)||SUPERSESSION.equals(id);}
    @Override public String id(){return fallback.id();}
    @Override public TargetRole role(){return fallback.role();}
    @Override public String instructionEn(){return "Prepare native recurring metadata A, simultaneous signing-key rollover, and B; execute the outbox controls, capture original native evidence, and restore the product before evaluation.";}
    @Override public String instructionsEn(CaseState state){return "Exercise the accepted B metadata and the superseded key/ACS controls. Each request is generated and recorded by the Suite outbox.";}
    @Override public String evidenceCampaignId(){return "native-metadata-supersession";}
    @Override public String evidenceCampaignTitle(){return "Native metadata replacement and simultaneous rollover controls";}
    @Override public List<String> evidenceActionKeys(){return FIXTURES;}
    @Override public Binding outboundBinding(CaseState state){return "new-key-redirect".equals(state.data().get("fixture_id"))?Binding.SIGNED_REDIRECT:Binding.HTTP_POST;}
    @Override public Optional<PlanCredentials> redirectCredentials(String runId,CaseState state){
        return "new-key-redirect".equals(state.data().get("fixture_id"))?keys.apply(runId,"no-valid-until"):Optional.empty();
    }
    @Override public CaseStep start(CaseContext context){
        if(hasNativeEvidence(context.runId()))return new CaseStep.Finish(observe(context));
        try{return scenario(context).start(context);}catch(RuntimeException unavailable){return fallback.start(context);}
    }
    @Override public CaseStep resume(CaseContext context,CaseState state,CaseEvent event){
        if(state.phase().startsWith("await-fixture-")){
            try{
                var step=scenario(context).resume(context,state,event);
                if(step instanceof CaseStep.Finish)return new CaseStep.Finish(pending());
                return step;
            }catch(RuntimeException unavailable){return new CaseStep.Finish(pending());}
        }
        if(event instanceof CaseEvent.ConfigConfirmed){
            if(hasNativeEvidence(context.runId()))return new CaseStep.Finish(observe(context));
            try{return scenario(context).start(context);}catch(RuntimeException unavailable){return new CaseStep.Finish(pending());}
        }
        return fallback.resume(context,state,event);
    }
    private static CaseOutcome pending(){return CaseOutcome.notVerified("native_metadata_supersession_originals_unavailable","metadata.supersession.awaiting-native-receipt");}
    private boolean hasNativeEvidence(String runId){return evidence.exists(runId)||keycloakEvidence.exists(runId)||applicationEvidence.exists(runId);}
    private CaseOutcome observe(CaseContext context){
        boolean shibboleth=evidence.exists(context.runId()),keycloak=keycloakEvidence.exists(context.runId());
        boolean application=applicationEvidence.exists(context.runId());
        if((shibboleth?1:0)+(keycloak?1:0)+(application?1:0)!=1)return pending();
        try{return application?applicationEvidence.evaluate(id(),context):
            keycloak?keycloakEvidence.evaluate(id(),context,targetMetadata.apply(context.runId())):evidence.evaluate(id(),context);}
        catch(RuntimeException unavailable){return pending();}
    }
    @Override public EvidenceStatus evidenceStatus(CaseContext context){
        var result=observe(context);
        boolean ready=result.outcome()!=com.samlscope.core.evaluation.Outcome.NOT_VERIFIED;
        return new EvidenceStatus(ready,FIXTURES,ready?FIXTURES:List.of(),result.details());
    }
    @Override public boolean supportsRecordedEvidenceReevaluation(CaseOutcome previous){return previous!=null&&previous.outcome()==com.samlscope.core.evaluation.Outcome.NOT_VERIFIED;}
    @Override public Optional<CaseOutcome> reevaluateRecordedEvidence(CaseContext context,CaseOutcome previous){
        return supportsRecordedEvidenceReevaluation(previous)?RecordedEvidenceReevaluation.conclusiveUpdate(previous,observe(context)):Optional.empty();
    }
    private FixtureScenarioTestCase scenario(CaseContext context){
        var a=prepared(context,"control"); var b=prepared(context,"no-valid-until");
        String entity=a.getAttribute("entityID");
        if(entity.isBlank()||!entity.equals(b.getAttribute("entityID")))throw new IllegalStateException("Same entity originals required");
        var target=SecureXml.parse(targetMetadata.apply(context.runId())).getDocumentElement();
        URI post=sso(target,POST), redirect=sso(target,REDIRECT);
        URI old=acs(a,0), current=acs(b,0), second=acs(b,1);
        if(old.equals(current))throw new IllegalStateException("ACS must change");
        var specs=new ArrayList<ScenarioFixture>();
        for(String fixture:FIXTURES){
            String variant=switch(fixture){case "old-key-new-acs"->"control";case "rollover-first-key-new-acs"->"multiple-signing-keys-first";case "rollover-second-key-new-acs"->"multiple-signing-keys";default->"no-valid-until";};
            var credentials=keys.apply(context.runId(),variant).orElseThrow();
            URI destination="new-key-redirect".equals(fixture)?redirect:post;
            URI responseEndpoint="new-key-old-acs".equals(fixture)?old:"new-key-second-acs".equals(fixture)?second:current;
            var kind="new-key-default-acs".equals(fixture)?SamlSignedRequestFactory.Fixture.DEFAULT_ACS:
                    "new-key-invalid-signature".equals(fixture)?SamlSignedRequestFactory.Fixture.BAD_SIGNATURE_VALUE:SamlSignedRequestFactory.Fixture.VALID;
            specs.add(new Probe(fixture,entity,destination,responseEndpoint,variant,credentials,kind));
        }
        // The new full-profile collection is explicitly scoped by the target's original SOAP
        // SSO advertisement. Historical browser-only campaigns retain the exact nine inputs.
        // A deliberately unknown session can exercise SLO endpoint selection without logging
        // out the shared browser. Its response never proves successful session termination.
        if(hasService(target,"SingleSignOnService",SOAP)) {
            URI destination=service(target,"SingleLogoutService",POST);
            for(String binding:List.of(POST,REDIRECT,SOAP))service(b,"SingleLogoutService",binding);
            for(String fixture:SLO_FIXTURES) {
                String variant="old-key-slo-route".equals(fixture)?"control":"no-valid-until";
                specs.add(new SloRouteProbe(fixture,entity,destination,variant,
                    keys.apply(context.runId(),variant).orElseThrow(),fixture.startsWith("new-key-invalid-signature")));
            }
        }
        return new FixtureScenarioTestCase(id(),TargetRole.IDP,specs,ignored->true,
            new FixtureScenarioTestCase.Vocabulary("metadata_preparation_unavailable","metadata.supersession.preparation-unavailable",
                "delivery_unknown","metadata.supersession.delivery-unknown","aborted","metadata.supersession.aborted",
                "metadata.supersession.control-failed","metadata.supersession.awaiting-native-receipt","metadata.supersession.awaiting-native-receipt",
                "native_originals_pending","metadata.supersession.awaiting-native-receipt","metadata.supersession.awaiting-native-receipt",
                "metadata.supersession.awaiting-native-receipt","metadata.supersession.awaiting-native-receipt"));
    }
    private Element prepared(CaseContext context,String variant){
        var originals=context.transcript().list(context.runId()).stream().filter(entry->
            "MetadataPrepared".equals(entry.samlSummary().get("type"))&&variant.equals(entry.samlSummary().get("variant"))
            &&"live".equals(entry.samlSummary().get("feed"))).toList();
        if(originals.isEmpty())throw new IllegalStateException("Native preparation missing");
        return SecureXml.parse(content.readDecodedSaml(originals.get(0))).getDocumentElement();
    }
    static URI acs(Element metadata,int index){
        var nodes=metadata.getElementsByTagNameNS(MD,"AssertionConsumerService");
        for(int i=0;i<nodes.getLength();i++){var e=(Element)nodes.item(i);if(Integer.toString(index).equals(e.getAttribute("index"))&&POST.equals(e.getAttribute("Binding")))return URI.create(e.getAttribute("Location"));}
        throw new IllegalStateException("POST ACS unavailable");
    }
    private static URI sso(Element metadata,String binding){
        return service(metadata,"SingleSignOnService",binding);
    }
    private static boolean hasService(Element metadata,String local,String binding){
        var nodes=metadata.getElementsByTagNameNS(MD,local);
        for(int i=0;i<nodes.getLength();i++)if(binding.equals(((Element)nodes.item(i)).getAttribute("Binding")))return true;
        return false;
    }
    private static URI service(Element metadata,String local,String binding){
        var nodes=metadata.getElementsByTagNameNS(MD,local);
        for(int i=0;i<nodes.getLength();i++){var e=(Element)nodes.item(i);if(binding.equals(e.getAttribute("Binding")))return URI.create(e.getAttribute("Location"));}
        throw new IllegalStateException(local+" binding unavailable");
    }
    private record SloRouteProbe(String id,String entity,URI destination,String keyVariant,
            PlanCredentials credentials,boolean invalidSignature) implements ScenarioFixture {
        @Override public Prepared prepare(CaseContext context,String actionId){
            var doc=SecureXml.newDocument();var name=doc.createElementNS(SamlLogoutRequestFactory.ASSERTION,"saml:NameID");
            name.setAttributeNS(javax.xml.XMLConstants.XMLNS_ATTRIBUTE_NS_URI,"xmlns:saml",SamlLogoutRequestFactory.ASSERTION);
            name.setAttribute("Format","urn:oasis:names:tc:SAML:2.0:nameid-format:unspecified");
            name.setTextContent("samlscope-unregistered-session-"+actionId);
            var factory=new SamlLogoutRequestFactory();String requestId="_"+actionId;
            byte[] raw=factory.sign(factory.build(requestId,destination,entity,name,
                List.of("samlscope-unregistered-index-"+actionId),context.clock().instant(),null,false),credentials);
            if(invalidSignature){
                var xml=SecureXml.parse(raw);var values=xml.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#","SignatureValue");
                if(values.getLength()!=1)throw new IllegalStateException("Unique signature value required");
                String value=values.item(0).getTextContent().strip();values.item(0).setTextContent((value.startsWith("A")?"B":"A")+value.substring(1));
                raw=SecureXml.serialize(xml);
            }
            return new Prepared(new OutboundAction(actionId,OutboundKind.LOGOUT_REQUEST,raw,destination,false),requestId);
        }
        @Override public FixtureObservation observe(String correlation,byte[] raw){return FixtureObservation.NOT_VERIFIED;}
        @Override public String definitionKey(){return "native-metadata-slo-route-v1|"+id+"|"+entity+"|"+destination+"|"+keyVariant+"|"+invalidSignature;}
    }
    private record Probe(String id,String entity,URI destination,URI acs,String keyVariant,PlanCredentials credentials,
            SamlSignedRequestFactory.Fixture kind) implements ScenarioFixture {
        @Override public Prepared prepare(CaseContext context,String actionId){
            String requestId="_"+actionId;
            byte[] raw=new SamlSignedRequestFactory().build(kind,requestId,destination,entity,acs,context.clock().instant(),credentials);
            return new Prepared(new OutboundAction(actionId,OutboundKind.AUTHN_REQUEST,raw,destination,false),requestId);
        }
        @Override public FixtureObservation observe(String correlation,byte[] raw){
            // Collection only. A SAML response and a browser error have no conformance meaning here.
            return FixtureObservation.NOT_VERIFIED;
        }
        @Override public String definitionKey(){return "native-supersession-v1|"+id+"|"+entity+"|"+destination+"|"+acs+"|"+keyVariant+"|"+kind;}
    }
}
