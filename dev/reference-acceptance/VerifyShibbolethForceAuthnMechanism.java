package com.samlscope.runner.cases;
import java.nio.file.*;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.*;
import java.util.*;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.plan.*;
import com.samlscope.core.run.*;
import com.samlscope.core.transcript.*;
import com.samlscope.runner.DefaultCaseContext;
import com.samlscope.store.JsonCodec;
public final class VerifyShibbolethForceAuthnMechanism {
 static final JsonCodec J=new JsonCodec();
 static String sha(byte[] b)throws Exception{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(b));}
 public static void main(String[]args)throws Exception{
  Path root=Path.of(args[0]),baseline=Path.of(args[1]);String run=J.mapper().readTree(Files.readAllBytes(baseline.resolve("receipt/manifest.json"))).path("runId").asText();
  var entries=J.mapper().readValue(Files.readAllBytes(baseline.resolve("browser/transcript.json")),J.mapper().getTypeFactory().constructCollectionType(List.class,TranscriptEntry.class));
  @SuppressWarnings("unchecked") var transcript=(List<TranscriptEntry>)entries;
  var plan=J.mapper().readTree(Files.readAllBytes(baseline.resolve("browser/created.json"))).path("run").path("planId").asText();
  var parameters=J.read(Files.readString(baseline.resolve("context-parameters.json")),TestPlan.Parameters.class);
  var key=KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(Files.readAllBytes(Path.of("/data/keys").resolve(plan).resolve("signing-key.pk8"))));
  var target=Files.readAllBytes(baseline.resolve("browser/target-metadata.xml"));
  TranscriptRecorder recorder=new TranscriptRecorder(){public List<TranscriptEntry> list(String id){return transcript;}public TranscriptEntry record(TranscriptInput i){throw new AssertionError();}public TranscriptEntry updateSamlAnalysis(String id,String c,Map<String,Object>s){throw new AssertionError();}};
  var context=new DefaultCaseContext(run,TargetRole.IDP,Clock.systemUTC(),parameters,TestPlan.Interaction.defaults(),Reachability.CONFIRMED,recorder,true);
  TranscriptContentReader content=e->{try{return Files.readAllBytes(baseline.resolve("browser/decoded").resolve(e.id()+".xml"));}catch(java.io.IOException ex){throw new java.io.UncheckedIOException(ex);}};
  var evidence=new ShibbolethForceAuthnMechanismEvidence(root,content,r->target,r->Optional.of(key));
  var outcome=evidence.read(context).orElseThrow();if(outcome.outcome()!=Outcome.SATISFIED)throw new IllegalStateException("Actual native originals unproven: "+outcome);
  var receipt=root.resolve(run+".shibboleth-force-authn-mechanism.json");var folder=root.resolve(run+".shibboleth-force-authn-mechanism");
  byte[] receiptRaw=Files.readAllBytes(receipt);var base=(ObjectNode)J.mapper().readTree(receiptRaw);byte[] traceRaw=Files.readAllBytes(folder.resolve("native-trace.json"));
  var mutations=new LinkedHashMap<String,String>();
  for(String mutation:List.of("true-context-lost","false-flag-lost","native-initializer-lost","misbound-native-context","input-hash","request-id","issuer","missing-negative","duplicate-positive","unknown-mutant","native-class","native-expression","false-live-ui-claim","scope")){
   var trace=(ObjectNode)J.mapper().readTree(traceRaw);var rows=trace.withArray("traces");var forced=(ObjectNode)rows.get(1);var normal=(ObjectNode)rows.get(0);
   switch(mutation){case "true-context-lost"->forced.put("mechanismForceAuthn",false);case "false-flag-lost"->normal.put("mechanismForceAuthn",true);case "native-initializer-lost"->forced.put("nativeInitializerForceAuthn",false);case "misbound-native-context"->forced.put("sameNativeContextObject",false);
    case "input-hash"->forced.put("inputSha256","0".repeat(64));case "request-id"->forced.put("requestId","_wrong-request");case "issuer"->forced.put("issuer","urn:wrong");case "missing-negative"->rows.remove(5);case "duplicate-positive"->rows.set(1,normal.deepCopy());case "unknown-mutant"->((ObjectNode)rows.get(2)).put("mutation","unknown");case "native-class"->((ObjectNode)trace.withArray("classes").get(0)).put("classSha256","0".repeat(64));case "native-expression"->trace.put("nativeExpression","fake");case "false-live-ui-claim"->trace.put("trueLivePasswordUiExecutionClaimed",true);case "scope"->trace.put("scope","live");}
   byte[] changed=J.mapper().writeValueAsBytes(trace);Files.write(folder.resolve("native-trace.json"),changed);var m=base.deepCopy();m.put("traceSha256",sha(changed));Files.write(receipt,J.mapper().writeValueAsBytes(m));
   var failed=evidence.read(context).orElseThrow();if(failed.outcome()!=Outcome.NOT_VERIFIED)throw new IllegalStateException("Mutation adopted "+mutation);mutations.put(mutation,failed.outcome().name());
  }
  Files.write(folder.resolve("native-trace.json"),traceRaw);Files.write(receipt,receiptRaw);
  var fallback=new IdpForceAuthnScenarioTestCase(IdpForceAuthnScenarioTestCase.MECHANISM_ACCESS_CASE,r->{throw new AssertionError("Owned proof must not dispatch");});
  var wrapper=new ForceAuthnMechanismEvidenceTestCase(fallback,evidence);
  if(((CaseStep.Finish)wrapper.start(context)).outcome().outcome()!=Outcome.SATISFIED||wrapper.queuedEvidenceOutcome(context).outcome()!=Outcome.SATISFIED||!wrapper.evidenceStatus(context).ready())throw new IllegalStateException("Wrapper incomplete");
  if(wrapper.withDecryptionKeys(r->Optional.empty()).queuedEvidenceOutcome(context).outcome()!=Outcome.NOT_VERIFIED)throw new IllegalStateException("Missing actual Plan key adopted");
  var report=new LinkedHashMap<String,Object>();report.put("runId",run);report.put("outcome",outcome);report.put("manifestSha256",sha(receiptRaw));report.put("negativeControls",mutations);report.put("privateCredentialsPersisted",false);report.put("productOperations",0);report.put("nativeTraceScope","isolated-native-stock-password-boundary-capability");report.put("trueLiveNoPassiveRetained",true);
  Files.write(Path.of(args[2]),J.mapper().writerWithDefaultPrettyPrinter().writeValueAsBytes(report));System.out.println("native mechanism original-backed production candidate SATISFIED; "+mutations.size()+" mutation controls NOT_VERIFIED");
 }
}
