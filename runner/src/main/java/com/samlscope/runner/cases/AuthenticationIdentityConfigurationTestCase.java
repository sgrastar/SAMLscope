package com.samlscope.runner.cases;

import java.nio.file.Path;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.util.*;
import java.util.function.Function;
import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.plan.TargetRole;
import com.samlscope.core.transcript.TranscriptContentReader;
import com.samlscope.runner.RecordedEvidenceReevaluation;

/** Native evidence gate for the approved ambient-authentication exclusion prerequisite. */
public final class AuthenticationIdentityConfigurationTestCase implements TestCase,ConfigurationPrompt,
        AttestationPrompt,ProtocolEvidenceCase,RecordedEvidenceReevaluation {
    public static final String ID="IIP-SSO01-ae-idp-01";
    private final TestCase fallback;
    private final ShibbolethAuthenticationIdentityEvidenceFile evidence;
    private final SimpleSamlPhpAuthenticationIdentityEvidence simpleSamlPhp;
    private final KeycloakAuthenticationIdentityEvidence keycloak;
    private final Path directory;
    public AuthenticationIdentityConfigurationTestCase(TestCase fallback,TranscriptContentReader content,
            Function<String,byte[]> metadata,SamlDecryptionKeyProvider keys,Path directory) {
        this.fallback=Objects.requireNonNull(fallback);
        if(!ID.equals(fallback.id())||!(fallback instanceof ConfigurationPrompt)||!(fallback instanceof AttestationPrompt))
            throw new IllegalArgumentException("Approved identity CONFIG fallback required");
        evidence=new ShibbolethAuthenticationIdentityEvidenceFile(directory,content,metadata,keys);
        this.directory=directory.toAbsolutePath().normalize();
        simpleSamlPhp=new SimpleSamlPhpAuthenticationIdentityEvidence(
                this.directory.resolveSibling("simplesamlphp-authentication-identity-evidence"),content,metadata,keys);
        keycloak=new KeycloakAuthenticationIdentityEvidence(
                this.directory.resolveSibling("keycloak-authentication-identity-evidence"),content,metadata,keys);
    }
    @Override public String id(){return ID;}
    @Override public TargetRole role(){return fallback.role();}
    @Override public String instructionEn(){return ((ConfigurationPrompt)fallback).instructionEn();}
    @Override public String promptEn(){return ((AttestationPrompt)fallback).promptEn();}
    @Override public List<AttestationOption> options(){return ((AttestationPrompt)fallback).options();}
    private static CaseOutcome unproven(){return CaseOutcome.notVerified(
            "native_authentication_identity_originals_unproven","browser.authentication-identity.native-unproven");}
    private Optional<CaseOutcome> observed(CaseContext context){
        if(!context.runId().matches("run_[0-9A-HJKMNP-TV-Z]{26}"))return Optional.of(unproven());
        boolean shibboleth=Files.exists(directory.resolve(context.runId()),LinkOption.NOFOLLOW_LINKS);
        boolean ssp=simpleSamlPhp.exists(context.runId());
        boolean kc=keycloak.exists(context.runId());
        int owned=(shibboleth?1:0)+(ssp?1:0)+(kc?1:0);
        if(owned==0)return Optional.empty();
        if(owned!=1||!context.transcriptComplete())return Optional.of(unproven());
        try{return Optional.of(shibboleth?evidence.evaluate(context):(ssp?simpleSamlPhp.evaluate(context):keycloak.evaluate(context))
                .orElseGet(AuthenticationIdentityConfigurationTestCase::unproven));}
        catch(RuntimeException invalid){return Optional.of(unproven());}
    }
    @Override public CaseStep start(CaseContext context){return observed(context).<CaseStep>map(CaseStep.Finish::new).orElseGet(()->fallback.start(context));}
    @Override public CaseStep resume(CaseContext context,CaseState state,CaseEvent event){
        var nativeResult=observed(context);
        if(nativeResult.isPresent())return new CaseStep.Finish(nativeResult.get());
        // The approved case explicitly forbids a declaration-only SATISFIED conclusion.
        if(event instanceof CaseEvent.ConfigConfirmed||event instanceof CaseEvent.TranscriptReady
                ||event instanceof CaseEvent.Attested)return new CaseStep.Finish(evidence.evaluate(context));
        return fallback.resume(context,state,event);
    }
    @Override public EvidenceStatus evidenceStatus(CaseContext context){
        var result=observed(context).orElseGet(()->evidence.evaluate(context));boolean ready=result.outcome()==Outcome.SATISFIED;
        var required=List.of("native-ambient-authentication-disabled","correct-authentication-positive-control",
            "identity-unavailable-signed-error-no-assertion","configuration-byte-exact-restored");
        return new EvidenceStatus(ready,required,ready?required:List.of(),result.details());
    }
    @Override public boolean supportsRecordedEvidenceReevaluation(CaseOutcome previous){return previous!=null&&previous.outcome()==Outcome.NOT_VERIFIED;}
    @Override public Optional<CaseOutcome> reevaluateRecordedEvidence(CaseContext context,CaseOutcome previous){
        return supportsRecordedEvidenceReevaluation(previous)?observed(context).flatMap(next->RecordedEvidenceReevaluation.conclusiveUpdate(previous,next)):Optional.empty();
    }
}
