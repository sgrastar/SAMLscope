package com.samlscope.runner.cases;

import java.nio.file.Path;
import java.util.*;
import java.util.function.Function;
import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.plan.TargetRole;
import com.samlscope.core.transcript.TranscriptContentReader;
import com.samlscope.runner.RecordedEvidenceReevaluation;

/** Original-bound URL diagnostics; a browser completion click cannot assert native nonuse. */
public final class UiUrlBrowserEvidenceTestCase implements TestCase, QueuedProtocolEvidenceCase,
        com.samlscope.runner.EvidenceCampaignCase, RecordedEvidenceReevaluation {
    private final TranscriptContentReader content;
    private final Function<String,byte[]> metadata;
    private final UiUrlEvidenceFile evidence;
    private final ShibbolethUiConsumerEvidence nativeShibboleth;
    private final KeycloakNativeUiConsumerEvidence nativeKeycloak;
    private final SimpleSamlPhpConsentUriEvidence nativeSimpleSamlPhp;
    public UiUrlBrowserEvidenceTestCase(TranscriptContentReader content,Function<String,byte[]> metadata,Path directory) {
        this.content=Objects.requireNonNull(content);this.metadata=Objects.requireNonNull(metadata);
        this.evidence=new UiUrlEvidenceFile(directory);
        this.nativeShibboleth=new ShibbolethUiConsumerEvidence(directory,content);
        this.nativeKeycloak=new KeycloakNativeUiConsumerEvidence(directory.resolveSibling("ui-native-feature-absence"),content);
        this.nativeSimpleSamlPhp=new SimpleSamlPhpConsentUriEvidence(directory.resolveSibling("ui-consent-uri-evidence"),content);
    }
    @Override public String id(){return UiUrlComparison.CASE_ID;}
    @Override public TargetRole role(){return TargetRole.IDP;}
    @Override public String evidenceCampaignId(){return "metadata-ui-url-comparison";}
    @Override public String evidenceCampaignTitle(){return "Native UI URL consumption";}
    @Override public com.samlscope.runner.RunCampaignQuery.ActionKind evidenceActionKind(){
        return com.samlscope.runner.RunCampaignQuery.ActionKind.METADATA_REFRESH;
    }
    @Override public List<String> evidenceActionKeys(){
        var keys=new ArrayList<String>();
        for(var element:UiUrlComparison.Element.values())for(var scheme:UiUrlComparison.Scheme.values())
            keys.add("ui-url-"+element.name().toLowerCase(Locale.ROOT)+"-"+scheme.name().toLowerCase(Locale.ROOT));
        return List.copyOf(keys);
    }
    @Override public CaseStep start(CaseContext context){return new CaseStep.Finish(observe(context));}
    @Override public CaseStep resume(CaseContext context,CaseState state,CaseEvent event){
        if(!(event instanceof CaseEvent.TranscriptReady))throw new IllegalArgumentException("Recorded browser evidence required");
        return new CaseStep.Finish(observe(context));
    }
    private CaseOutcome observe(CaseContext context){
        try {
            boolean keycloakOwned=nativeKeycloak.exists(context.runId());
            boolean shibbolethOwned=nativeShibboleth.exists(context.runId());
            boolean simpleSamlPhpOwned=nativeSimpleSamlPhp.exists(context.runId());
            if((keycloakOwned?1:0)+(shibbolethOwned?1:0)+(simpleSamlPhpOwned?1:0)>1)
                throw new IllegalArgumentException("Ambiguous native URL product");
            if(keycloakOwned)return nativeKeycloak.read(context,metadata.apply(context.runId()),id()).orElseThrow();
            if(simpleSamlPhpOwned)return nativeSimpleSamlPhp.evaluate(context,metadata.apply(context.runId())).orElseThrow();
            if(shibbolethOwned) {
                return nativeShibboleth.read(context,metadata.apply(context.runId()),id()).orElseThrow();
            }
            var collected=evidence.read(context,metadata.apply(context.runId()),content);
            return UiUrlComparison.evaluate(collected.samples(),collected.issues());
        } catch(Exception unproven) {
            return UiUrlComparison.evaluate(List.of(),List.of("native_ui_url_evidence_unproven"));
        }
    }
    @Override public CaseOutcome queuedEvidenceOutcome(CaseContext context){return observe(context);}
    @Override public EvidenceStatus evidenceStatus(CaseContext context){
        var outcome=observe(context);boolean ready=outcome.outcome()!=Outcome.NOT_VERIFIED;
        return new EvidenceStatus(ready,evidenceActionKeys(),ready?evidenceActionKeys():List.of(),outcome.details());
    }
    @Override public boolean supportsRecordedEvidenceReevaluation(CaseOutcome previous){
        return previous!=null&&previous.outcome()==Outcome.NOT_VERIFIED&&Set.of(
                "browser.ui-url.evidence-incomplete","browser.oracle-unavailable","attestation.interaction-disallowed")
                .contains(String.valueOf(previous.reasonCode()));
    }
    @Override public Optional<CaseOutcome> reevaluateRecordedEvidence(CaseContext context,CaseOutcome previous){
        if(!context.transcriptComplete()||!supportsRecordedEvidenceReevaluation(previous))return Optional.empty();
        return RecordedEvidenceReevaluation.conclusiveUpdate(previous,observe(context));
    }
}
