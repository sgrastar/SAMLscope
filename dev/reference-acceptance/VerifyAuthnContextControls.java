package com.samlscope.runner.cases;

import java.nio.file.*;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.*;
import com.samlscope.core.evaluation.*;
import com.samlscope.saml.normal.SamlRequestedAuthnContextRequestFactory.*;
import com.samlscope.store.JsonCodec;

/** Paired synthetic detection controls through the production aggregator, separate from product evidence. */
public final class VerifyAuthnContextControls {
    public static void main(String[] args) throws Exception {
        var cases = new ArrayList<String>();
        for (var suffix : List.of("ga", "gb", "gc", "gj")) {
            String id = "IIP-SSO01-" + suffix + "-idp-01";
            var contexts = new EnumMap<ReferenceKind, AuthnContextComparison.NativeContext>(ReferenceKind.class);
            for (var kind : ReferenceKind.values()) {
                String p = kind.name();
                var refs = new AuthnContextComparisonInputs.References(p+"low",p+"medium",p+"high",p+"unavailable");
                contexts.put(kind,new AuthnContextComparison.NativeContext(refs,
                    new AuthnContextSelectionRule.PreparedOrdering(Map.of(refs.low(),0,refs.medium(),1,refs.high(),2,p+"weaker",-1),
                        Set.of(refs.low(),refs.medium()),true),Set.of(refs.low(),refs.medium(),refs.high()),Set.of(refs.unavailable())));
            }
            var preparation = new AuthnContextComparison.Preparation("control", "control-entity", "a".repeat(64), "b".repeat(64),
                contexts, AuthnContextComparison.Controls.VERIFIED);
            var positive = samples(id, preparation);
            require(AuthnContextComparison.evaluate(id,preparation,positive,List.of()).outcome()==Outcome.SATISFIED);
            for (var kind : ReferenceKind.values()) {
                var mutant = new ArrayList<>(positive);
                for (int index=0; index<mutant.size(); index++) {
                    var s=mutant.get(index);
                    if (s.request().kind()!=kind || s.response().kind()!=AuthnContextResponseEvidence.ResponseKind.SUCCESS) continue;
                    var refs=contexts.get(kind).references();
                    String wrong=suffix.equals("ga")?kind.name()+"weaker":suffix.equals("gj")?s.request().references().getLast():refs.low();
                    var response=new AuthnContextResponseEvidence.Observation(AuthnContextResponseEvidence.ResponseKind.SUCCESS,
                        kind==ReferenceKind.CLASS?Optional.of(wrong):Optional.empty(),kind==ReferenceKind.DECLARATION?Optional.of(wrong):Optional.empty(),false);
                    mutant.set(index,new AuthnContextComparison.Sample(s.condition(),s.experiment(),s.entityId(),s.loginFingerprint(),
                        s.configurationFingerprint(),s.request(),s.issued(),s.received(),response,s.evidence()));
                    break;
                }
                require(AuthnContextComparison.evaluate(id,preparation,mutant,List.of()).outcome()==Outcome.VIOLATED);
            }
            var missing=new ArrayList<>(positive);missing.removeLast();
            require(AuthnContextComparison.evaluate(id,preparation,missing,List.of()).outcome()==Outcome.NOT_VERIFIED);
            var untrusted=new AuthnContextComparison.Preparation(preparation.experiment(),preparation.entityId(),preparation.loginFingerprint(),
                preparation.configurationFingerprint(),contexts,AuthnContextComparison.Controls.UNVERIFIED);
            require(AuthnContextComparison.evaluate(id,untrusted,positive,List.of()).outcome()==Outcome.NOT_VERIFIED);
            cases.add(suffix);
        }
        var protocol=Files.readAllBytes(Path.of(args[0]));
        new JsonCodec().mapper().writerWithDefaultPrettyPrinter().writeValue(Path.of(args[1]).toFile(),Map.of(
            "protocol_sha256",HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(protocol)),
            "verified_cases",cases,"positive_cases",4,"reference_kind_mutants",8,"incomplete_controls",4,"unverified_controls",4,
            "product_verdict_assigned",false));
        System.out.println("Paired aggregator controls verified for all four cases and both reference kinds");
    }
    private static List<AuthnContextComparison.Sample> samples(String id,AuthnContextComparison.Preparation preparation) {
        var result=new ArrayList<AuthnContextComparison.Sample>();int index=0;
        for(var kind:ReferenceKind.values()) for(var input:AuthnContextComparisonInputs.forCase(id,kind,preparation.contexts().get(kind).references())) {
            boolean error=input.condition().endsWith("unachievable");
            String selected=id.contains("-gj-")?input.request().references().getFirst():preparation.contexts().get(kind).references().medium();
            var response=new AuthnContextResponseEvidence.Observation(error?AuthnContextResponseEvidence.ResponseKind.ERROR:AuthnContextResponseEvidence.ResponseKind.SUCCESS,
                !error && kind==ReferenceKind.CLASS?Optional.of(selected):Optional.empty(),!error && kind==ReferenceKind.DECLARATION?Optional.of(selected):Optional.empty(),false);
            result.add(new AuthnContextComparison.Sample(input.condition(),preparation.experiment(),preparation.entityId(),preparation.loginFingerprint(),
                preparation.configurationFingerprint(),input.request(),Instant.ofEpochSecond(index*2),Instant.ofEpochSecond(index*2+1),response,
                List.of(new EvidenceRef("transcript","req"+index),new EvidenceRef("transcript","res"+index))));index++;
        }
        return result;
    }
    private static void require(boolean result) { if(!result)throw new IllegalStateException("Authentication comparison control failed"); }
}
