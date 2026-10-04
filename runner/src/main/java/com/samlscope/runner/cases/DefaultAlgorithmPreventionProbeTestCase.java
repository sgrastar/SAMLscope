package com.samlscope.runner.cases;

import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.plan.TargetRole;
import com.samlscope.core.transcript.*;
import com.samlscope.runner.*;
import com.samlscope.saml.crypto.*;
import com.samlscope.saml.normal.*;
import java.net.URI;
import java.nio.file.Path;
import java.time.Duration;
import java.util.*;
import java.util.function.*;
import org.w3c.dom.Element;

/** Six outbox inputs share one login; the native receipt, never browser completion, decides ALG08.c. */
public final class DefaultAlgorithmPreventionProbeTestCase implements TestCase,BrowserFrontChannelScenario,
        ConfigurationPrompt,AttestationPrompt,ProtocolEvidenceCase,RecordedEvidenceReevaluation,FallbackEvidenceCase {
    public static final String CASE=DefaultAlgorithmComparison.CASE;
    static final String VERSION="default-prevention-probe-v1";
    private final TestCase fallback;private final TranscriptContentReader content;
    private final Function<String,byte[]> metadata;private final Function<String,Optional<PlanCredentials>> keys;
    private final Function<String,String> profiles;private final DefaultAlgorithmPreventionEvidence evidence;
    public DefaultAlgorithmPreventionProbeTestCase(TestCase fallback,TranscriptContentReader content,
            Function<String,byte[]> fixedTargetMetadata,Function<String,Optional<PlanCredentials>> advertisedSuiteKeys,
            Function<String,String> runProfiles,Path directory,DefaultAlgorithmNativeAdapter... adapters) {
        this(fallback,content,fixedTargetMetadata,advertisedSuiteKeys,runProfiles,
                new DefaultAlgorithmPreventionEvidence(directory,content,fixedTargetMetadata,advertisedSuiteKeys,runProfiles,adapters));
    }
    DefaultAlgorithmPreventionProbeTestCase(TestCase fallback,TranscriptContentReader content,Function<String,byte[]> metadata,
            Function<String,Optional<PlanCredentials>> keys,Function<String,String> profiles,DefaultAlgorithmPreventionEvidence evidence) {
        this.fallback=Objects.requireNonNull(fallback);this.content=Objects.requireNonNull(content);this.metadata=Objects.requireNonNull(metadata);
        this.keys=Objects.requireNonNull(keys);this.profiles=Objects.requireNonNull(profiles);this.evidence=Objects.requireNonNull(evidence);
        if(!CASE.equals(fallback.id())||fallback.role()!=TargetRole.IDP||!(fallback instanceof AttestationPrompt))
            throw new IllegalArgumentException("Approved ATTESTED ALG08.c fallback required");
    }
    @Override public String id(){return fallback.id();}
    @Override public TargetRole role(){return fallback.role();}
    @Override public String promptEn(){return ((AttestationPrompt)fallback).promptEn();}
    @Override public List<AttestationOption> options(){return ((AttestationPrompt)fallback).options();}
    @Override public String instructionEn(){return "The administrator must prepare the original SP metadata and record the target's unchanged default algorithm policy. Do not change algorithm allow/block settings. One authenticated browser can execute the six controls.";}
    @Override public String instructionsEn(CaseState state){return "Execute this recorded request using the same authenticated browser; the native algorithm-consumer evidence decides the result.";}
    @Override public boolean requiresPreparationConfirmation(){return true;}
    @Override public String evidenceCampaignId(){return DefaultAlgorithmComparison.CAMPAIGN;}
    @Override public String evidenceCampaignTitle(){return "Unchanged default algorithm prevention";}
    @Override public RunCampaignQuery.ActionKind evidenceActionKind(){return RunCampaignQuery.ActionKind.CONFIGURATION;}
    @Override public RunCampaignQuery.ActionKind evidenceActionKind(CaseExecution execution){
        if(execution!=null&&execution.status()==CaseExecutionStatus.FINISHED)return RunCampaignQuery.ActionKind.NONE;
        if(execution!=null&&execution.state()!=null&&"await-attestation".equals(execution.state().phase()))
            return RunCampaignQuery.ActionKind.SELF_CHECK;
        return execution!=null&&execution.state()!=null&&VERSION.equals(execution.state().data().get("definition"))
                ?RunCampaignQuery.ActionKind.LOGIN:RunCampaignQuery.ActionKind.CONFIGURATION;
    }
    private CaseOutcome observed(CaseContext context){return evidence.evaluate(context).orElseGet(()->DefaultAlgorithmComparison.missing("native_default_algorithm_originals_unavailable",List.of()));}
    @Override public CaseStep start(CaseContext context){
        if(evidence.exists(context.runId()))return new CaseStep.Finish(observed(context));
        try {configuration(context);return new CaseStep.AwaitConfig(new CaseState("await-default-algorithm-preparation",Map.of("case_id",id())),
                List.of(),"algorithm.default-prevention.prepare",Duration.ofMinutes(15));}
        catch(Exception missing){
            if(manualFallbackAvailable(context))return fallback.start(context);
            return new CaseStep.Finish(DefaultAlgorithmComparison.missing("default_algorithm_prerequisites_unavailable",List.of()));
        }
    }
    @Override public CaseStep resume(CaseContext context,CaseState state,CaseEvent event){
        if(evidence.exists(context.runId()))return new CaseStep.Finish(observed(context));
        if(state!=null&&"await-attestation".equals(state.phase())) {
            if(manualFallbackAvailable(context))return fallback.resume(context,state,event);
            return new CaseStep.Finish(DefaultAlgorithmComparison.missing("default_algorithm_prerequisites_unavailable",List.of()));
        }
        if(event instanceof CaseEvent.ConfigConfirmed&&"await-default-algorithm-preparation".equals(state.phase())&&CASE.equals(state.data().get("case_id"))) {
            try{return prepare(context,0,null,List.of());}catch(Exception missing){return new CaseStep.Finish(DefaultAlgorithmComparison.missing("default_algorithm_prerequisites_unavailable",List.of()));}
        }
        if(!VERSION.equals(state.data().get("definition"))||!CASE.equals(state.data().get("case_id")))
            return new CaseStep.Finish(DefaultAlgorithmComparison.missing("default_algorithm_scenario_changed",List.of()));
        if(event instanceof CaseEvent.TimedOut||event instanceof CaseEvent.Aborted)
            return new CaseStep.Finish(DefaultAlgorithmComparison.missing("default_algorithm_operation_incomplete",List.of()));
        try {
            int index=((Number)state.data().get("fixture_index")).intValue();require(index>=0&&index<6);
            String fixture=DefaultAlgorithmComparison.REQUIRED.get(index);require(fixture.equals(state.data().get("fixture_id")));
            var refs=new ArrayList<String>();if(state.data().get("responses") instanceof List<?> list)for(var value:list)refs.add((String)value);
            String normal=state.data().get("authenticated_response") instanceof String s?s:null;
            if(event instanceof CaseEvent.InboundMessage inbound) {
                var originals=context.transcript().list(context.runId()).stream().filter(e->e.id().equals(inbound.evidence().reference())).toList();
                require("transcript".equals(inbound.evidence().kind())&&originals.size()==1&&context.runId().equals(originals.getFirst().runId())
                        &&originals.getFirst().direction()==Direction.INBOUND&&Arrays.equals(inbound.decodedSaml(),content.readDecodedSaml(originals.getFirst())));
                var root=SecureXml.parse(inbound.decodedSaml()).getDocumentElement();require(state.data().get("request_id").equals(root.getAttribute("InResponseTo")));
                refs.add(inbound.evidence().reference());
                if(index<4&&DefaultAlgorithmPreventionEvidence.SUCCESS.equals(DefaultAlgorithmPreventionEvidence.status(root))) {
                    require(index!=1);var c=configuration(context);validateNormal(context,root,c,state,originals.getFirst());normal=inbound.evidence().reference();
                }else if(index==0)throw new IllegalArgumentException("Normal signature control did not succeed");
            }else if(event instanceof CaseEvent.BrowserObservation browser) {
                if(index==0)throw new IllegalArgumentException("Normal signature control unavailable");
                require(browser.evidence()!=null&&"transcript".equals(browser.evidence().kind()));
                validateBrowserObservation(context,state,fixture,browser);
                refs.add(browser.evidence().reference());
            }else if(event instanceof CaseEvent.InboundUnavailable) {
                if(index==0)throw new IllegalArgumentException("Normal signature control unavailable");
            }else throw new IllegalArgumentException("Recorded probe observation required");
            if(index==5||(index==3&&!configuration(context).keyTransport()))return new CaseStep.Finish(DefaultAlgorithmComparison.missing("native_default_algorithm_originals_pending",
                    refs.stream().map(r->new EvidenceRef("transcript",r)).toList()));
            return prepare(context,index+1,normal,refs);
        }catch(Exception missing){return new CaseStep.Finish(DefaultAlgorithmComparison.missing("default_algorithm_control_or_binding_unproven",List.of()));}
    }
    private record Configuration(Element suite,Element target,PlanCredentials key,URI sso,URI slo,URI acs,URI suiteSlo,java.security.PublicKey recipient,boolean keyTransport){}
    private boolean manualFallbackAvailable(CaseContext context) {
        return context.interaction().allowAttestation() && !evidence.exists(context.runId())
                && !evidence.hasPreparationArtifacts(context.runId());
    }
    private Configuration configuration(CaseContext context)throws Exception {
        require(context.interaction().allowBrowserSteps());
        require(context.transcriptComplete()&&context.targetRole()==TargetRole.IDP&&"browser_sso_idp".equals(profiles.apply(context.runId())));
        var preparation=evidence.preparation(context).orElseThrow();
        var key=keys.apply(context.runId()).orElseThrow();var prepared=context.transcript().list(context.runId()).stream()
                .filter(e->"MetadataPrepared".equals(e.samlSummary().get("type"))&&"control".equals(e.samlSummary().get("variant"))&&"live".equals(e.samlSummary().get("feed"))).toList();
        require(prepared.size()==1&&context.runId().equals(prepared.getFirst().runId()));
        var bytes=content.readDecodedSaml(prepared.getFirst());require(DefaultAlgorithmPreventionEvidence.hash(bytes).equals(prepared.getFirst().samlSummary().get("metadataSha256")));
        var suite=SecureXml.parse(bytes).getDocumentElement();DefaultAlgorithmPreventionEvidence.validateSuite(suite,key);
        var target=SecureXml.parse(metadata.apply(context.runId())).getDocumentElement();DefaultAlgorithmPreventionEvidence.structure(target,DefaultAlgorithmPreventionEvidence.MD,"EntityDescriptor");
        require(!target.getAttribute("entityID").isBlank()&&!MetadataAlgorithmEvidence.signingKeys(target).isEmpty());
        var recipients=new ArrayList<java.security.PublicKey>();for(var role:DefaultAlgorithmPreventionEvidence.children(target,DefaultAlgorithmPreventionEvidence.MD,"IDPSSODescriptor"))
            for(var descriptor:DefaultAlgorithmPreventionEvidence.children(role,DefaultAlgorithmPreventionEvidence.MD,"KeyDescriptor")) {
                if(!descriptor.getAttribute("use").isBlank()&&!"encryption".equals(descriptor.getAttribute("use")))continue;
                var certs=descriptor.getElementsByTagNameNS(DefaultAlgorithmPreventionEvidence.DS,"X509Certificate");for(int i=0;i<certs.getLength();i++) {
                    var cert=(java.security.cert.X509Certificate)java.security.cert.CertificateFactory.getInstance("X.509").generateCertificate(new java.io.ByteArrayInputStream(Base64.getDecoder().decode(certs.item(i).getTextContent().replaceAll("\\s+",""))));
                    if("RSA".equals(cert.getPublicKey().getAlgorithm())&&!Arrays.equals(cert.getPublicKey().getEncoded(),key.certificate().getPublicKey().getEncoded()))recipients.add(cert.getPublicKey());
                }
            }
        boolean keyTransport=preparation.keyTransportConsumerAvailable();
        if(keyTransport)require(!recipients.isEmpty());return new Configuration(suite,target,key,DefaultAlgorithmPreventionEvidence.endpoint(target,"IDPSSODescriptor","SingleSignOnService"),
                keyTransport?DefaultAlgorithmPreventionEvidence.endpoint(target,"IDPSSODescriptor","SingleLogoutService"):null,DefaultAlgorithmPreventionEvidence.endpoint(suite,"SPSSODescriptor","AssertionConsumerService"),
                keyTransport?DefaultAlgorithmPreventionEvidence.endpoint(suite,"SPSSODescriptor","SingleLogoutService"):null,keyTransport?recipients.getFirst():null,keyTransport);
    }
    private CaseStep prepare(CaseContext context,int index,String normal,List<String> responses)throws Exception {
        var c=configuration(context);String fixture=DefaultAlgorithmComparison.REQUIRED.get(index),action=action(context.runId(),fixture),requestId="_"+action;
        byte[] request;URI destination;OutboundKind kind;
        if(index<4) {
            request=new SamlDefaultAlgorithmFixtures().authnRequest(DefaultAlgorithmPreventionEvidence.signatureFixture(fixture),requestId,c.sso(),c.suite().getAttribute("entityID"),c.acs(),context.clock().instant(),c.key());destination=c.sso();kind=OutboundKind.AUTHN_REQUEST;
        }else {
            require(c.keyTransport()&&normal!=null);var entries=context.transcript().list(context.runId()).stream().filter(e->e.id().equals(normal)).toList();
            require(entries.size()==1&&context.runId().equals(entries.getFirst().runId())&&entries.getFirst().direction()==Direction.INBOUND);
            var reply=SecureXml.parse(content.readDecodedSaml(entries.getFirst())).getDocumentElement();
            var authn=recordedAuthnRequest(context,reply.getAttribute("InResponseTo"),entries.getFirst(),c);
            var assertion=DefaultAlgorithmPreventionEvidence.assertion(reply,c.key(),c.target(),c.suite(),authn);
            var subject=DefaultAlgorithmPreventionEvidence.single(assertion,DefaultAlgorithmPreventionEvidence.A,"Subject");var names=DefaultAlgorithmPreventionEvidence.children(subject,DefaultAlgorithmPreventionEvidence.A,"NameID");
            for(var cipher:DefaultAlgorithmPreventionEvidence.children(subject,DefaultAlgorithmPreventionEvidence.A,"EncryptedID"))names.add(new SamlXmlDecrypter().decrypt(cipher,c.key().privateKey()));
            require(names.size()==1);var indexes=DefaultAlgorithmPreventionEvidence.children(assertion,DefaultAlgorithmPreventionEvidence.A,"AuthnStatement").stream().map(e->e.getAttribute("SessionIndex")).toList();require(!indexes.isEmpty()&&indexes.stream().noneMatch(String::isBlank));
            var factory=new SamlLogoutRequestFactory();var identifier=factory.encryptedIdentifier(names.getFirst(),c.recipient(),new SamlEncryptionFixtureFactory.Algorithms(
                    SamlEncryptionFixtureFactory.Content.AES128_GCM,index==4?SamlEncryptionFixtureFactory.Transport.RSA_1_5:SamlEncryptionFixtureFactory.Transport.RSA_OAEP,
                    SamlEncryptionFixtureFactory.Digest.DEFAULT,SamlEncryptionFixtureFactory.Mgf.DEFAULT));
            request=factory.sign(factory.build(requestId,c.slo(),c.suite().getAttribute("entityID"),identifier,indexes,context.clock().instant(),null,false),c.key());destination=c.slo();kind=OutboundKind.LOGOUT_REQUEST;
        }
        var data=new LinkedHashMap<String,Object>();data.put("case_id",CASE);data.put("definition",VERSION);data.put("fixture_id",fixture);
        data.put("fixture_index",index);data.put("request_id",requestId);data.put("outbound_binding",Binding.HTTP_POST.name());data.put("responses",responses);
        if(normal!=null)data.put("authenticated_response",normal);
        return new CaseStep.AwaitInbound(new CaseState(VERSION+"-"+fixture,Map.copyOf(data)),List.of(new OutboundAction(action,kind,request,destination,false)),
                new InboundMatcher("saml-response",Map.of("ScenarioActionId",action)),Duration.ofMinutes(5));
    }
    private void validateNormal(CaseContext context,Element root,Configuration c,CaseState state,TranscriptEntry response)throws Exception {
        DefaultAlgorithmPreventionEvidence.structure(root,DefaultAlgorithmPreventionEvidence.P,"Response");require(c.acs().toString().equals(root.getAttribute("Destination"))
                &&c.target().getAttribute("entityID").equals(DefaultAlgorithmPreventionEvidence.single(root,DefaultAlgorithmPreventionEvidence.A,"Issuer").getTextContent()));
        var request=recordedAuthnRequest(context,(String)state.data().get("request_id"),response,c);
        DefaultAlgorithmPreventionEvidence.assertion(root,c.key(),c.target(),c.suite(),request);
    }
    private Element recordedAuthnRequest(CaseContext context,String requestId,TranscriptEntry response,Configuration c)throws Exception {
        // Recorder identifies outbox actions in the summary; the SAML ID belongs to the original XML.
        var fixtures=DefaultAlgorithmComparison.REQUIRED.subList(0,4).stream()
                .filter(fixture->("_"+action(context.runId(),fixture)).equals(requestId)).toList();
        require(fixtures.size()==1);String fixture=fixtures.getFirst();
        return recordedRequest(context,fixture,response,c);
    }
    private Element recordedRequest(CaseContext context,String fixture,TranscriptEntry response,Configuration c)throws Exception {
        String expectedAction=action(context.runId(),fixture);
        var requests=context.transcript().list(context.runId()).stream()
                .filter(e->e.direction()==Direction.OUTBOUND&&expectedAction.equals(e.samlSummary().get("action_id"))).toList();
        require(requests.size()==1);var entry=requests.getFirst();
        require(context.runId().equals(entry.runId())&&expectedAction.equals(entry.correlationId())
                &&!response.timestamp().isBefore(entry.timestamp()));
        byte[] bytes=content.readDecodedSaml(entry);require(bytes!=null&&bytes.length==entry.decodedSamlBytes());
        var request=SecureXml.parse(bytes).getDocumentElement();
        DefaultAlgorithmPreventionEvidence.validateRequest(context,fixture,entry,request,bytes,c.suite(),c.target(),c.key(),fixture.endsWith("encrypted-id")||fixture.equals("oaep-encrypted-id-control"));
        return request;
    }
    private void validateBrowserObservation(CaseContext context,CaseState state,String fixture,CaseEvent.BrowserObservation browser)throws Exception {
        String expectedAction=action(context.runId(),fixture);
        var all=context.transcript().list(context.runId());
        var originals=all.stream().filter(e->e.id().equals(browser.evidence().reference())).toList();
        require(originals.size()==1);var original=originals.getFirst();var summary=original.samlSummary();
        require(context.runId().equals(original.runId())&&original.direction()==Direction.INBOUND
                &&"BROWSER".equals(original.method())&&expectedAction.equals(original.correlationId())
                &&"BrowserResponseObservation".equals(summary.get("type"))
                &&original.status()!=null&&original.status()==browser.httpStatus()
                &&summary.get("http_status") instanceof Number n&&n.intValue()==browser.httpStatus()
                &&browser.url().equals(summary.get("url"))
                &&original.decodedSamlRef()==null&&original.decodedSamlBytes()==0
                &&("transcripts/"+context.runId()+"/"+original.id()+".body").equals(original.bodyRef())
                &&original.bodyBytes()==browser.body().getBytes(java.nio.charset.StandardCharsets.UTF_8).length);
        // Browser Recorder binds the action through correlationId. An optional hint may not contradict it.
        require(!summary.containsKey("action_id")||expectedAction.equals(summary.get("action_id")));
        require(all.stream().filter(e->e.direction()==Direction.INBOUND&&expectedAction.equals(e.correlationId())
                &&"BrowserResponseObservation".equals(e.samlSummary().get("type"))).count()==1);
        var request=recordedRequest(context,fixture,original,configuration(context));
        require(state.data().get("request_id").equals(request.getAttribute("ID"))
                &&original.url().equals(browser.url().isBlank()?request.getAttribute("Destination"):browser.url()));
    }
    static String action(String run,String fixture){return ActionIds.derive(run,CASE,VERSION+"-"+fixture,0);}
    @Override public EvidenceStatus evidenceStatus(CaseContext context){var result=observed(context);boolean ready=Set.of(Outcome.SATISFIED,Outcome.VIOLATED).contains(result.outcome());return new EvidenceStatus(ready,DefaultAlgorithmComparison.REQUIRED,ready?DefaultAlgorithmComparison.REQUIRED:List.of(),result.details());}
    @Override public boolean supportsRecordedEvidenceReevaluation(CaseOutcome previous){return previous!=null&&previous.outcome()==Outcome.NOT_VERIFIED;}
    @Override public Optional<CaseOutcome> reevaluateRecordedEvidence(CaseContext context,CaseOutcome previous){return supportsRecordedEvidenceReevaluation(previous)&&context.transcriptComplete()?RecordedEvidenceReevaluation.conclusiveUpdate(previous,observed(context)):Optional.empty();}
    @Override public boolean resolvedFromExternalEvidence(CaseExecution execution){return execution!=null&&CASE.equals(execution.caseId())&&execution.outcome()!=null
            &&Set.of(Outcome.SATISFIED,Outcome.VIOLATED).contains(execution.outcome().outcome())&&Boolean.FALSE.equals(execution.outcome().details().get("counterfactual_calibration_only"))
            &&execution.outcome().evidence().stream().anyMatch(r->"default-algorithm-native-evidence".equals(r.kind())&&r.reference().startsWith(execution.runId()+"/manifest.json#sha256="));}
    @Override public RunCampaignQuery.EvidenceClass evidenceClass(CaseExecution execution) {
        if(execution!=null&&((execution.state()!=null&&"await-attestation".equals(execution.state().phase()))
                ||(execution.outcome()!=null&&Boolean.TRUE.equals(execution.outcome().details().get("attested")))))
            return RunCampaignQuery.EvidenceClass.SELF_ATTESTED;
        return RunCampaignQuery.EvidenceClass.OPERATOR_ASSISTED;
    }
    private static void require(boolean value){DefaultAlgorithmPreventionEvidence.require(value);}
}
