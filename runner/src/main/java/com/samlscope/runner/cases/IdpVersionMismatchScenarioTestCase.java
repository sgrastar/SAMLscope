package com.samlscope.runner.cases;

import java.nio.file.Path;
import java.time.*;
import java.util.*;
import java.util.function.Function;
import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.plan.TargetRole;
import com.samlscope.core.transcript.*;
import com.samlscope.runner.BrowserFrontChannelScenario;
import com.samlscope.runner.RecordedEvidenceReevaluation;
import com.samlscope.runner.scenario.*;
import com.samlscope.saml.crypto.*;
import com.samlscope.saml.normal.*;
import org.w3c.dom.Element;

/** Approved version-status check, including an original-backed explicit native HTTP termination. */
public final class IdpVersionMismatchScenarioTestCase implements TestCase, BrowserFrontChannelScenario,
        BrowserPrompt, ProtocolEvidenceCase, RecordedEvidenceReevaluation {
    public static final String CASE_ID="IIP-SSO01-ep-idp-01";
    static final String P="urn:oasis:names:tc:SAML:2.0:protocol", A="urn:oasis:names:tc:SAML:2.0:assertion", MD="urn:oasis:names:tc:SAML:2.0:metadata";
    static final String STATUS="urn:oasis:names:tc:SAML:2.0:status:";
    static final List<String> REQUIRED=List.of("baseline-success","invalid-issue-instant","version-1-1");
    private final Function<String,IdpErrorProbeConfiguration> configurations;
    private final SamlPlanCredentialsProvider keys;
    private final TranscriptContentReader content;
    private final Function<String,byte[]> metadata;
    private final SamlDecryptionKeyProvider decrypt;
    private final VersionMismatchTerminalEvidence terminal;
    public IdpVersionMismatchScenarioTestCase(Function<String,IdpErrorProbeConfiguration> configurations,
            SamlPlanCredentialsProvider keys,TranscriptContentReader content,Function<String,byte[]> targetMetadata,
            SamlDecryptionKeyProvider decrypt,Path terminalDirectory) {
        this.configurations=Objects.requireNonNull(configurations);this.keys=Objects.requireNonNull(keys);
        this.content=Objects.requireNonNull(content);this.metadata=Objects.requireNonNull(targetMetadata);
        this.decrypt=Objects.requireNonNull(decrypt);this.terminal=terminalDirectory==null?null:new VersionMismatchTerminalEvidence(terminalDirectory,content);
    }
    public IdpVersionMismatchScenarioTestCase(Function<String,IdpErrorProbeConfiguration> configurations,
            SamlPlanCredentialsProvider keys,TranscriptContentReader content,SamlDecryptionKeyProvider decrypt){
        this(configurations,keys,content,run->null,decrypt,null);
    }
    public IdpVersionMismatchScenarioTestCase withNativeEvidence(Path directory,TranscriptContentReader content,
            Function<String,byte[]> targetMetadata){
        return new IdpVersionMismatchScenarioTestCase(configurations,keys,content,targetMetadata,decrypt,Objects.requireNonNull(directory));
    }
    @Override public String id(){return CASE_ID;}
    @Override public TargetRole role(){return TargetRole.IDP;}
    @Override public String browserInstructionsEn(){return "Use one ordinary login for the control. The Suite then checks a non-version error and Version 1.1. Terminal HTTP errors require original native evidence; do not submit a verdict.";}
    @Override public String instructionsEn(CaseState state){return browserInstructionsEn();}
    @Override public CaseStep start(CaseContext c){var ready=observe(c);if(ready.isPresent())return new CaseStep.Finish(ready.get());return configured(c)?scenario(c).start(c):new CaseStep.Finish(nv("version_preconditions_unmet"));}
    @Override public CaseStep resume(CaseContext c,CaseState state,CaseEvent event){
        // Older browser cases persisted only case_id. Never feed that state (or a
        // partial current state) into the scenario engine's list/index readers.
        if(!currentScenarioState(c,state))return new CaseStep.Finish(nv("version_state_schema_incompatible"));
        if(event instanceof CaseEvent.TranscriptReady)return observe(c).<CaseStep>map(CaseStep.Finish::new).orElseGet(()->new CaseStep.Finish(nv("version_evidence_incomplete")));
        if(event instanceof CaseEvent.InboundMessage inbound || event instanceof CaseEvent.BrowserObservation){
            try {var fixture=String.valueOf(state.data().get("fixture_id"));var request=request(c,fixture);
                if(event instanceof CaseEvent.InboundMessage in){var original=entry(c,in.evidence().reference());require(original.direction()==Direction.INBOUND
                        && !original.timestamp().isBefore(request.entry().timestamp()) && Arrays.equals(in.decodedSaml(),decoded(original)));
                    var replies=responses(c,request);require(replies.size()==1 && replies.getFirst().id().equals(original.id()));}
                else {var browser=(CaseEvent.BrowserObservation)event;require(browser.evidence()!=null);var original=entry(c,browser.evidence().reference());
                    require(original.direction()==Direction.INBOUND && "BROWSER".equals(original.method()) && request.entry().correlationId().equals(original.correlationId())
                        && browser.url().equals(original.url()) && Objects.equals(browser.httpStatus(),original.status())
                        && browser.body().getBytes(java.nio.charset.StandardCharsets.UTF_8).length==original.bodyBytes());}
            }catch(Exception invalid){return new CaseStep.Finish(nv("version_observation_unbound"));}
        }
        if(!configured(c))return new CaseStep.Finish(nv("version_preconditions_unmet"));
        var step=scenario(c).resume(c,state,event);
        if(step instanceof CaseStep.Finish){var outcome=observe(c);if(outcome.isPresent())return new CaseStep.Finish(outcome.get());}
        return step;
    }
    private boolean currentScenarioState(CaseContext c,CaseState state){
        if(state==null)return false;
        var data=state.data();
        if(!CASE_ID.equals(data.get("scenario_case_id"))
                ||!(data.get("scenario_fingerprint") instanceof String fingerprint)
                ||!fingerprint.matches("sha256:[a-f0-9]{64}"))return false;
        var index=stateInteger(data.get("fixture_index"));var attempt=stateInteger(data.get("fixture_attempt"));
        if(index==null||index<0||index>=REQUIRED.size()||attempt==null||attempt<0||attempt>3)return false;
        var fixture=REQUIRED.get(index);
        var phase="await-fixture-"+fixture+(attempt==0?"":"-retry-"+attempt);
        if(!fixture.equals(data.get("fixture_id"))||!phase.equals(state.phase())
                ||!("_"+ActionIds.derive(c.runId(),CASE_ID,phase,0)).equals(data.get("expected_response_correlation")))return false;
        for(String key:List.of("violations","violating_action_ids","unverifiable","evidence"))
            if(!(data.get(key) instanceof List<?> values)||values.stream().anyMatch(value->!(value instanceof String)))return false;
        return true;
    }
    private static Integer stateInteger(Object value){
        if(value instanceof Integer n)return n;
        if(value instanceof Long n&&n>=Integer.MIN_VALUE&&n<=Integer.MAX_VALUE)return n.intValue();
        return null;
    }
    private boolean configured(CaseContext c){try{return configurations.apply(c.runId())!=null&&keys.credentialsFor(c.runId()).isPresent()&&metadata.apply(c.runId())!=null;}catch(Exception missing){return false;}}
    private FixtureScenarioTestCase scenario(CaseContext c){
        var config=configurations.apply(c.runId());var credential=keys.credentialsFor(c.runId()).orElse(null);
        return new FixtureScenarioTestCase(CASE_ID,TargetRole.IDP,REQUIRED.stream().<ScenarioFixture>map(f->new ScenarioFixture(){
            public String id(){return f;}
            public Prepared prepare(CaseContext context,String action){return new Prepared(new OutboundAction(action,OutboundKind.AUTHN_REQUEST,
                    fixture(f,"_"+action,config,context.clock().instant(),credential),config.ssoEndpoint(),false,OutboundAction.RequestSigning.REQUIRE),"_"+action);}
            public FixtureObservation observe(String expected,byte[] raw){return observed(c,f).orElse(FixtureObservation.NOT_VERIFIED);}
            public FixtureObservation observeBrowser(String expected,int status,String url,String body){return observed(c,f).orElse(FixtureObservation.NOT_VERIFIED);}
            public Duration timeout(){return config.responseTimeout();}
            public String definitionKey(){return f+"|"+config.ssoEndpoint()+"|"+config.registeredAcs()+"|version-originals-v1";}
        }).toList(),context->context.interaction().allowBrowserSteps() && config.userAgentAvailable()
                && config.acceptableResponseLocationKnown() && credential!=null,
                new FixtureScenarioTestCase.Vocabulary("version_preconditions_unmet","idp.version-mismatch.preconditions-unmet",
                    "delivery_or_response_unknown","idp.version-mismatch.delivery-unknown","scenario_aborted","idp.version-mismatch.aborted",
                    "idp.version-mismatch.control-failed","idp.version-mismatch.violated","idp.version-mismatch.violated",
                    "version_evidence_incomplete","idp.version-mismatch.inconclusive","idp.version-mismatch.inconclusive",
                    "idp.version-mismatch.satisfied","idp.version-mismatch.satisfied"));
    }
    static byte[] fixture(String f,String id,IdpErrorProbeConfiguration config,Instant at,PlanCredentials key){
        var probe=f.equals("invalid-issue-instant")?SamlErrorProbeRequestFactory.Probe.BASELINE_SUCCESS:SamlErrorProbeRequestFactory.Probe.valueOf(f.toUpperCase(Locale.ROOT).replace('-','_'));
        var root=SecureXml.parse(new SamlErrorProbeRequestFactory().build(probe,id,config.ssoEndpoint(),config.suiteIssuer(),config.registeredAcs(),at)).getDocumentElement();
        if(f.equals("invalid-issue-instant"))root.setAttribute("IssueInstant","not-a-saml-timestamp");
        new XmlSigner().sign(root,key,null);return SecureXml.serialize(root.getOwnerDocument());
    }
    private record Request(TranscriptEntry entry,Element xml,byte[] bytes){}
    private Request request(CaseContext c,String fixture)throws Exception{
        require(REQUIRED.contains(fixture));var action=ActionIds.derive(c.runId(),CASE_ID,"await-fixture-"+fixture,0);
        var all=entries(c).stream().filter(e->e.direction()==Direction.OUTBOUND&&action.equals(e.correlationId())).toList();require(all.size()==1);
        var e=all.getFirst();var s=e.samlSummary();require(action.equals(s.get("action_id")) && CASE_ID.equals(s.get("scenario_case_id"))
                && fixture.equals(s.get("fixture_id")) && "AuthnRequest".equals(s.get("type")) && !s.containsValue("UNKNOWN_DELIVERY"));
        byte[] bytes=decoded(e);Element root=SecureXml.parse(bytes).getDocumentElement();var config=configurations.apply(c.runId());var key=keys.credentialsFor(c.runId()).orElseThrow();
        require(P.equals(root.getNamespaceURI())&&"AuthnRequest".equals(root.getLocalName())&&("_"+action).equals(root.getAttribute("ID"))
                && config.ssoEndpoint().toString().equals(e.url()) && Arrays.equals(bytes,fixture(fixture,root.getAttribute("ID"),config,fixture.equals("invalid-issue-instant")?Instant.EPOCH:Instant.parse(root.getAttribute("IssueInstant")),key))
                && new XmlSignatureVerifier().hasValidEnvelopedSignature(root,key.certificate()));return new Request(e,root,bytes);
    }
    private List<TranscriptEntry> responses(CaseContext c,Request request)throws Exception{
        var result=new ArrayList<TranscriptEntry>();for(var e:entries(c))if(e.direction()==Direction.INBOUND && e.decodedSamlRef()!=null && e.decodedSamlBytes()>0 && "Response".equals(e.samlSummary().get("type"))){
            var root=SecureXml.parse(decoded(e)).getDocumentElement();if(P.equals(root.getNamespaceURI())&&"Response".equals(root.getLocalName())
                    && request.xml().getAttribute("ID").equals(root.getAttribute("InResponseTo"))) {
                // Recorder correlates a SAML reply to the original XML request ID;
                // the outbox uses the separately derived action ID.
                require(request.xml().getAttribute("ID").equals(e.correlationId()) && "Response".equals(e.samlSummary().get("type")));result.add(e);}
        }return result;
    }
    private Optional<FixtureObservation> observed(CaseContext c,String fixture){try{
        var r=request(c,fixture);var responses=responses(c,r);if(responses.size()>1)return Optional.empty();
        if(responses.size()==1){var e=responses.getFirst();require(!e.timestamp().isBefore(r.entry().timestamp()));var root=SecureXml.parse(decoded(e)).getDocumentElement();require("2.0".equals(root.getAttribute("Version"))&&!root.getAttribute("ID").isBlank());
            var target=SecureXml.parse(metadata.apply(c.runId())).getDocumentElement();require(MD.equals(target.getNamespaceURI())&&"EntityDescriptor".equals(target.getLocalName()));
            require(configurations.apply(c.runId()).registeredAcs().toString().equals(root.getAttribute("Destination"))
                    && root.getAttribute("Destination").equals(e.url()) && target.getAttribute("entityID").equals(single(root,A,"Issuer").getTextContent()));
            var certs=MetadataAlgorithmEvidence.signingKeys(target);boolean outer=certs.stream().anyMatch(k->new XmlSignatureVerifier().hasValidEnvelopedSignature(root,k));
            var top=single(single(root,P,"Status"),P,"StatusCode").getAttribute("Value");
            if(fixture.equals("baseline-success")){require((STATUS+"Success").equals(top));
                var assertions=MetadataAlgorithmEvidence.children(root,A,"Assertion");var encrypted=MetadataAlgorithmEvidence.children(root,A,"EncryptedAssertion");
                require(assertions.size()+encrypted.size()==1);var assertion=assertions.isEmpty()?new SamlXmlDecrypter().decrypt(encrypted.getFirst(),decrypt.keyFor(c.runId()).orElseThrow()):assertions.getFirst();
                require(target.getAttribute("entityID").equals(single(assertion,A,"Issuer").getTextContent())
                        && (outer||certs.stream().anyMatch(k->new XmlSignatureVerifier().hasValidEnvelopedSignature(assertion,k))));return Optional.of(FixtureObservation.SATISFIED);}
            require(outer);
            if(fixture.equals("invalid-issue-instant"))return Optional.of((STATUS+"VersionMismatch").equals(top)?FixtureObservation.CONTROL_FAILED:
                    Set.of(STATUS+"Requester",STATUS+"Responder").contains(top)?FixtureObservation.SATISFIED:FixtureObservation.CONTROL_FAILED);
            return Optional.of((STATUS+"VersionMismatch").equals(top)?FixtureObservation.SATISFIED:FixtureObservation.VIOLATED);
        }
        if(fixture.equals("baseline-success")||terminal==null)return Optional.empty();
        var browser=entries(c).stream().filter(e->e.direction()==Direction.INBOUND&&"BROWSER".equals(e.method())&&r.entry().correlationId().equals(e.correlationId())).toList();
        require(browser.size()==1);return terminal.read(c,r.entry(),r.xml().getAttribute("ID"),browser.getFirst(),r.bytes(),metadata.apply(c.runId())).map(p->FixtureObservation.SATISFIED);
    }catch(Exception invalid){return Optional.empty();}}
    private Optional<CaseOutcome> observe(CaseContext c){try{
        var refs=new LinkedHashSet<EvidenceRef>();boolean terminalUsed=false;boolean violation=false;
        for(String fixture:REQUIRED){var result=observed(c,fixture);if(result.isEmpty()||result.get()==FixtureObservation.CONTROL_FAILED)return Optional.empty();
            var r=request(c,fixture);refs.add(new EvidenceRef("transcript",r.entry().id()));var replies=responses(c,r);
            if(replies.isEmpty()){var b=entries(c).stream().filter(e->e.direction()==Direction.INBOUND&&"BROWSER".equals(e.method())&&r.entry().correlationId().equals(e.correlationId())).toList();
                var proof=terminal.read(c,r.entry(),r.xml().getAttribute("ID"),b.getFirst(),r.bytes(),metadata.apply(c.runId())).orElseThrow();refs.addAll(proof.evidence());terminalUsed=true;
            }else refs.add(new EvidenceRef("transcript",replies.getFirst().id()));
            violation|=result.get()==FixtureObservation.VIOLATED;
        }
        return Optional.of(new CaseOutcome(violation?Outcome.VIOLATED:terminalUsed?Outcome.SATISFIED_WITH_NOTE:Outcome.SATISFIED,null,
                violation?"idp.version-mismatch.violated":"idp.version-mismatch.satisfied","idp.version-mismatch.observed",List.copyOf(refs),
                Map.of("completed_fixtures",REQUIRED,"http_terminal_exception_used",terminalUsed,"operator_verdict_requested",false)));
    }catch(Exception unavailable){return Optional.empty();}}
    private List<TranscriptEntry> entries(CaseContext c){var entries=c.transcript().list(c.runId());var seen=new HashSet<String>();for(var e:entries)require(c.runId().equals(e.runId())&&seen.add(e.id()));return entries;}
    private TranscriptEntry entry(CaseContext c,String id){var e=entries(c).stream().filter(x->x.id().equals(id)).toList();require(e.size()==1);return e.getFirst();}
    private byte[] decoded(TranscriptEntry e){require(e.decodedSamlRef()!=null&&e.decodedSamlBytes()>0);byte[] raw=content.readDecodedSaml(e);require(raw!=null&&raw.length==e.decodedSamlBytes());return raw;}
    static Element single(Element parent,String ns,String local){var values=MetadataAlgorithmEvidence.children(parent,ns,local);require(values.size()==1);return values.getFirst();}
    static void require(boolean v){VersionMismatchTerminalEvidence.require(v);}
    private static CaseOutcome nv(String reason){return CaseOutcome.notVerified(reason,"idp.version-mismatch.inconclusive");}
    @Override public EvidenceStatus evidenceStatus(CaseContext c){var result=observe(c);return new EvidenceStatus(result.isPresent(),REQUIRED,result.isPresent()?REQUIRED:List.of(),result.map(CaseOutcome::details).orElse(Map.of()));}
    @Override public boolean supportsRecordedEvidenceReevaluation(CaseOutcome previous){return previous!=null&&previous.outcome()==Outcome.NOT_VERIFIED;}
    @Override public Optional<CaseOutcome> reevaluateRecordedEvidence(CaseContext c,CaseOutcome previous){return c.transcriptComplete()&&supportsRecordedEvidenceReevaluation(previous)?observe(c).flatMap(n->RecordedEvidenceReevaluation.conclusiveUpdate(previous,n)):Optional.empty();}
}
