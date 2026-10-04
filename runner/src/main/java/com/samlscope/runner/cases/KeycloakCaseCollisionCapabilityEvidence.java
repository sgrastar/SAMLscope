package com.samlscope.runner.cases;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.*;
import com.samlscope.core.caseexec.CaseContext;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.plan.TargetRole;
import com.samlscope.core.transcript.*;
import com.samlscope.store.JsonCodec;
import java.nio.file.*;
import java.util.*;
import java.util.function.Function;

/** Provisional, unregistered construction proof; normative selector controls and recipient transcript are unfinished. */
public final class KeycloakCaseCollisionCapabilityEvidence {
    public static final String CASE="IIP-IDP21-a-idp-01",DIGEST="sha256:a7252257701b0427cd6bb9eea917624135a3344042e2135501cfb4f4a41b23f8";
    public static final String SCHEMA="samlscope-keycloak-case-collision-capability-v1",SCOPE="selectable-native-persistent-canonical-construction-only";
    private static final String RESOURCE="/com/samlscope/runner/cases/native-uuid-canonical-formatter-contract.json",RESOURCE_SHA="ab6dfa9c6a777714dd5089a234dc059c4e5e77b8a573bbb268e3a51eae1b2b25";
    private final Path directory,sourceDirectory;private final TranscriptContentReader content;private final Function<String,byte[]> metadata;
    private final DefaultAlgorithmSourceRunStore destinationStore;private final Map<String,DefaultAlgorithmSourceRunStore> sourceStores;private final KeycloakPersistentIdentifierEvidence sourceReader;
    private final ObjectMapper json=new JsonCodec().mapper().enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION).enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS);
    public KeycloakCaseCollisionCapabilityEvidence(Path directory,Path data,TranscriptContentReader content,Function<String,byte[]> metadata){this(directory,data,data.toAbsolutePath().normalize().resolve("persistent-identifier-evidence"),content,metadata);}
    KeycloakCaseCollisionCapabilityEvidence(Path directory,Path data,Path sourceDirectory,TranscriptContentReader content,Function<String,byte[]> metadata){
        this.directory=directory.toAbsolutePath().normalize();this.sourceDirectory=sourceDirectory.toAbsolutePath().normalize();this.content=Objects.requireNonNull(content);this.metadata=Objects.requireNonNull(metadata);
        destinationStore=new DefaultAlgorithmSourceRunStore(data,CASE,DIGEST);var stores=new TreeMap<String,DefaultAlgorithmSourceRunStore>();KeycloakPersistentIdentifierEvidence.DIGESTS.forEach((id,digest)->stores.put(id,new DefaultAlgorithmSourceRunStore(data,id,digest)));sourceStores=Map.copyOf(stores);
        sourceReader=new KeycloakPersistentIdentifierEvidence(sourceDirectory,content,metadata,sourceStores);
    }
    public boolean exists(String run){return run!=null&&run.matches("run_[0-9A-HJKMNP-TV-Z]{26}")&&Files.exists(directory.resolve(run+".keycloak-case-policy"),LinkOption.NOFOLLOW_LINKS);}
    public Optional<CaseOutcome> read(CaseContext context){
        if(!exists(context.runId()))return Optional.empty();String stage="source-and-recipient-membership";
        try{
            require(context.transcriptComplete()&&context.targetRole()==TargetRole.IDP);Path folder=directory.resolve(context.runId()+".keycloak-case-policy");byte[] manifestRaw=raw(folder,"manifest.json");var m=json.readTree(manifestRaw);var files=m.path("files");
            require(SCHEMA.equals(text(m,"schema"))&&SCOPE.equals(text(m,"scope"))&&CASE.equals(text(m,"caseId"))&&DIGEST.equals(text(m,"caseDigest"))&&context.runId().equals(text(m,"runId"))&&files.isObject()&&files.size()>12&&files.size()<64);
            for(var names=files.fieldNames();names.hasNext();)checked(folder,files,names.next());
            String sourceRun=text(m,"sourceRunId");require(sourceRun.matches("run_[0-9A-HJKMNP-TV-Z]{26}")&&!sourceRun.equals(context.runId()));
            var destination=destinationStore.execution(context.runId());require("single_logout_idp".equals(destination.plan().profile().id())&&destination.plan().id().equals(text(m,"planId"))&&destination.plan().parameters().equals(context.parameters())&&destination.plan().interaction().equals(context.interaction())&&destination.run().targetToSuiteReachability()==context.reachability());
            require(KeycloakPersistentIdentifierEvidence.stable(destination.snapshot()).equals(node(folder,files,"destination-store.json"))&&destinationStore.history(context.runId(),context.transcript().list(context.runId()),content).equals(node(folder,files,"destination-history.json")));
            var sourceSnapshots=node(folder,files,"source-stores.json");require(sourceSnapshots.isObject()&&sourceSnapshots.size()==2);var sourceOutcomes=new TreeMap<String,CaseOutcome>();DefaultAlgorithmSourceRunStore.Binding source=null;
            var history=context.transcript().listBounded(sourceRun,10_000);
            for(var row:sourceStores.entrySet()){
                var binding=row.getValue().execution(sourceRun);if(source==null)source=binding;
                require("browser_sso_idp".equals(binding.plan().profile().id())&&binding.plan().id().equals(text(m,"sourcePlanId"))&&KeycloakPersistentIdentifierEvidence.stable(binding.snapshot()).equals(sourceSnapshots.path(row.getKey()))
                    &&row.getValue().history(sourceRun,history,content).equals(node(folder,files,"source-history.json")));
                // Reexecute the native producer and all signed/source/restoration checks. Stored SAT is not proof.
                var observed=sourceReader.read(binding.context(context.clock(),history),row.getKey()).orElseThrow();require(observed.outcome()==Outcome.SATISFIED&&Boolean.TRUE.equals(observed.details().get("native_producer_replayed")));sourceOutcomes.put(row.getKey(),observed);
            }
            require(source!=null&&destination.plan().target().entityId().equals(source.plan().target().entityId())&&source.plan().target().entityId().equals(text(m,"targetEntityId")));
            byte[] sourceMetadata=metadata.apply(sourceRun),targetMetadata=metadata.apply(context.runId());require(Arrays.equals(sourceMetadata,targetMetadata)&&hash(sourceMetadata).equals(text(m,"targetMetadataSha256")));
            Path sourceFolder=sourceDirectory.resolve(sourceRun+".keycloak-native-identifier");require(hash(raw(sourceFolder,"manifest.json")).equals(text(m,"sourceManifestSha256")));
            stage="same-native-product-epoch";
            var sourceEnvironment=json.readTree(raw(sourceFolder,"originals/before.environment.json"));var sourceAfter=json.readTree(raw(sourceFolder,"originals/after.environment.json"));require(sourceEnvironment.path("runtime").equals(sourceAfter.path("runtime")));
            var recipientEpoch=node(folder,files,"recipient-native-epoch.json");var epochRecord=node(folder,files,"recipient-native-epoch-record.json");
            require(context.runId().equals(text(epochRecord,"runId"))&&text(m,"targetMetadataSha256").equals(text(epochRecord,"targetMetadataSha256"))&&hash(checked(folder,files,"recipient-native-epoch.json")).equals(text(epochRecord,"nativeReadbackSha256"))
                &&"native-readbacks/initial.json".equals(text(epochRecord,"nativeReadbackFile"))&&java.time.Instant.parse(text(epochRecord,"nativeStartedAt")).isBefore(java.time.Instant.parse(text(sourceEnvironment,"recordedAt"))));
            require(text(m,"targetEntityId").equals(text(recipientEpoch,"hostedEntityId"))&&text(m,"targetMetadataSha256").equals(text(recipientEpoch.path("hostedMetadataReadback"),"rawBodySha256"))&&epoch(sourceEnvironment.path("runtime")).equals(epoch(recipientEpoch.path("runtime"))));
            String before=new String(checked(folder,files,"runtime-before.stdout.txt"),java.nio.charset.StandardCharsets.UTF_8),after=new String(checked(folder,files,"runtime-after.stdout.txt"),java.nio.charset.StandardCharsets.UTF_8);
            require(before.equals(after)&&before.trim().equals('"'+text(sourceEnvironment.path("runtime"),"containerId")+"\" \""+text(sourceEnvironment.path("runtime"),"image")+"\" \""+text(sourceEnvironment.path("runtime"),"startedAt")+'"'));
            stage="general-native-formatter-derivation";var formatter=verifyFormatter(folder,files);
            var process=node(folder,files,"native-formatter-process.json");require(text(process,"sourceSha256").equals(text(contract(),"helperSha256"))&&process.path("helperWrites").asInt(-1)==1&&process.path("helperRemovals").asInt(-1)==1&&process.path("operations").isArray()&&process.path("operations").size()==8);
            for(String field:List.of("productSettingsWrites","httpRequests","samlRequests","credentialSubmissions","principalSessionChanges"))require(process.path(field).isInt()&&process.path(field).asInt(-1)==0);
            require("isolated-helper-JVM-only-finally-restored".equals(text(process,"nativeDigitTableMutationScope"))&&hash(checked(folder,files,"native-formatter-helper.java")).equals(text(contract(),"helperSha256")));
            verifyProcess(process,java.time.Instant.parse(text(sourceAfter,"recordedAt")),context.clock().instant());
            for(var operation:process.path("operations")){require(operation.path("exitCode").asInt(-1)==0&&hash(checked(folder,files,text(operation,"stdoutFile"))).equals(text(operation,"stdoutSha256"))&&hash(checked(folder,files,text(operation,"stderrFile"))).equals(text(operation,"stderrSha256")));}
            var refs=new ArrayList<EvidenceRef>();refs.add(new EvidenceRef("native-case-collision-capability",context.runId()+".keycloak-case-policy/manifest.json#sha256="+hash(manifestRaw)));
            for(var outcome:sourceOutcomes.values())for(var ref:outcome.evidence())refs.add(new EvidenceRef("source-run-"+ref.kind(),sourceRun+"/"+ref.reference()));
            var details=new LinkedHashMap<String,Object>();details.put("evidence_adapter",SCHEMA);details.put("approved_mode","ATTESTED");details.put("attested",false);details.put("run_id",context.runId());details.put("source_run_id",sourceRun);details.put("source_plan_id",source.plan().id());details.put("source_profile","browser_sso_idp");details.put("profile","single_logout_idp");details.put("source_run_binding_scope",SCOPE);details.put("approved_case_digest",DIGEST);
            details.put("selected_native_format","persistent");details.put("canonical_construction_alphabet","fixed-G-prefix-and-lowercase-hex");details.put("native_producer_replayed",true);details.put("general_formatter_bytecode_derived",true);details.put("formatter_control_count",formatter);details.put("slo_protocol_traffic_verified",false);details.put("universal_stored_identifier_policy_claimed",false);details.put("native_mutated_table_diagnostic_only",true);details.put("configuration_restored",true);
            details.put("normativeControlsVerified",false);details.put("recipient_transcript_verified",false);
            // Lower/upper formatter sensitivity is diagnostic only. It is not the approved same-policy,
            // different-subject negative fixture, and source transcripts cannot replace a recipient original.
            return Optional.of(new CaseOutcome(Outcome.NOT_VERIFIED,"native-case-policy.control-unproven","native-case-policy.control-unproven","native-case-policy.control-unproven",refs,details));
        }catch(Exception unavailable){return Optional.of(new CaseOutcome(Outcome.NOT_VERIFIED,"native_case_policy_unproven","native_case_policy_unproven","idp.identifier.case-policy-unproven",List.of(),Map.of("stage",stage,"scope",SCOPE)));}
    }
    int verifyFormatter(Path folder,JsonNode files)throws Exception{
        var c=contract();var models=new HashMap<String,NativeUuidFormatterDerivation.Model>();
        for(var names=c.path("classes").fieldNames();names.hasNext();){String name=names.next();byte[] bytes=checked(folder,files,"native-jre-classes/"+name.replace('.','/')+".class");require(hash(bytes).equals(text(c.path("classes"),name)));var model=new NativeUuidFormatterDerivation.Model(bytes);require(model.owner.equals(name.replace('.','/')));models.put(model.owner,model);}
        for(var names=c.path("methods").fieldNames();names.hasNext();){String name=names.next();int split=name.lastIndexOf('.',name.indexOf('('));require(split>0);require(hash(models.get(name.substring(0,split)).method(name.substring(split+1)).code()).equals(text(c.path("methods"),name)));}
        var uuid=models.get("java/util/UUID");byte[] route=uuid.method("toString()Ljava/lang/String;").code();require(route.length==17&&route[0]==(byte)178&&route[3]==42&&route[4]==(byte)180&&route[7]==42&&route[8]==(byte)180&&route[11]==(byte)185&&route[14]==5&&route[15]==0&&route[16]==(byte)176
            &&uuid.member(NativeUuidFormatterDerivation.two(route,1)).equals(new NativeUuidFormatterDerivation.Member("java/util/UUID","jla","Ljdk/internal/access/JavaLangAccess;"))
            &&uuid.member(NativeUuidFormatterDerivation.two(route,5)).equals(new NativeUuidFormatterDerivation.Member("java/util/UUID","leastSigBits","J"))
            &&uuid.member(NativeUuidFormatterDerivation.two(route,9)).equals(new NativeUuidFormatterDerivation.Member("java/util/UUID","mostSigBits","J"))
            &&uuid.member(NativeUuidFormatterDerivation.two(route,12)).equals(new NativeUuidFormatterDerivation.Member("jdk/internal/access/JavaLangAccess","fastUUID","(JJ)Ljava/lang/String;")));
        var system=models.get("java/lang/System$2");byte[] delegate=system.method("fastUUID(JJ)Ljava/lang/String;").code();require(delegate.length==6&&delegate[0]==31&&delegate[1]==33&&delegate[2]==(byte)184&&delegate[5]==(byte)176&&system.member(NativeUuidFormatterDerivation.two(delegate,3)).equals(new NativeUuidFormatterDerivation.Member("java/lang/Long","fastUUID","(JJ)Ljava/lang/String;")));
        var strings=models.get("java/lang/String");byte[] constructor=strings.method("<init>([BB)V").code();
        require(constructor.length==15&&constructor[0]==42&&constructor[1]==(byte)183&&constructor[4]==42&&constructor[5]==43&&constructor[6]==(byte)181&&constructor[9]==42&&constructor[10]==28&&constructor[11]==(byte)181&&constructor[14]==(byte)177
            &&strings.member(NativeUuidFormatterDerivation.two(constructor,2)).equals(new NativeUuidFormatterDerivation.Member("java/lang/Object","<init>","()V"))
            &&strings.member(NativeUuidFormatterDerivation.two(constructor,7)).equals(new NativeUuidFormatterDerivation.Member("java/lang/String","value","[B"))
            &&strings.member(NativeUuidFormatterDerivation.two(constructor,12)).equals(new NativeUuidFormatterDerivation.Member("java/lang/String","coder","B")));
        var utf=models.get("java/lang/StringUTF16");byte[] writer=utf.method("putChar([BII)V").code();
        require(writer.length==54&&writer[28]==27&&writer[29]==4&&writer[30]==120&&writer[31]==60&&writer[32]==42&&writer[33]==27&&writer[34]==(byte)132&&writer[35]==1&&writer[36]==1&&writer[37]==28&&writer[38]==(byte)178&&writer[41]==122&&writer[42]==(byte)145&&writer[43]==84&&writer[44]==42&&writer[45]==27&&writer[46]==28&&writer[47]==(byte)178&&writer[50]==122&&writer[51]==(byte)145&&writer[52]==84&&writer[53]==(byte)177
            &&utf.member(NativeUuidFormatterDerivation.two(writer,39)).equals(new NativeUuidFormatterDerivation.Member("java/lang/StringUTF16","HI_BYTE_SHIFT","I"))
            &&utf.member(NativeUuidFormatterDerivation.two(writer,48)).equals(new NativeUuidFormatterDerivation.Member("java/lang/StringUTF16","LO_BYTE_SHIFT","I")));
        char[] digits=models.get("java/lang/Integer").digits();require(new String(digits,0,16).equals("0123456789abcdef"));int controls=0;
        for(String mode:List.of("compact","utf16")){
            var lines=new String(checked(folder,files,mode+".stdout.txt"),java.nio.charset.StandardCharsets.UTF_8).lines().toList();require(lines.size()<1024);
            require(lines.contains("RUNTIME\t21.0.12.1+1-LTS\tRed Hat, Inc.\t/usr/lib/jvm/java-21-openjdk-21.0.12.1.1-1.2.el9.aarch64")&&lines.contains("ACTUAL_JLA\tjava.lang.System$2\tjava.base")&&lines.contains("ACTUAL_COMPACT_STRINGS\t"+mode.equals("compact"))&&lines.contains("ALPHABET\t0123456789abcdef")&&lines.contains("CLAIMS\tproductClassOverridden=false\trandomnessUsed=false\ttargetSettingsWrites=0\thttpRequests=0\tnativeIdentifierProducerInvoked=false\tproductFailureClaimed=false"));
            var nativeValues=new HashMap<String,String>();int high=-1,low=-1;var origins=new HashSet<String>();String diagnostic=null;
            for(String line:lines){String[] values=line.split("\t",-1);switch(values[0]){
                case "FIELD"->{require(values.length==3);if(values[1].equals("HI_BYTE_SHIFT"))high=Integer.parseInt(values[2]);else if(values[1].equals("LO_BYTE_SHIFT"))low=Integer.parseInt(values[2]);else throw new IllegalArgumentException();}
                case "CLASS"->{require(values.length==6&&origins.add(values[1])&&values[2].equals("java.base")&&values[3].equals("jrt:/java.base/"+values[1].replace('.','/')+".class")&&text(c.path("classes"),values[1]).equals(values[4]));byte[] bytes=Base64.getDecoder().decode(values[5]);require(Arrays.equals(bytes,checked(folder,files,"native-jre-classes/"+values[1].replace('.','/')+".class")));}
                case "NIBBLE"->{require(values.length==4&&nativeValues.put(values[1]+":"+values[2],values[3])==null);}
                case "NATIVE_DIAGNOSTIC"->{require(values.length==5&&diagnostic==null&&values[3].equals("tableRestored=true")&&values[4].equals("productJvmMutated=false")&&caseOnlyPair(values[1],values[2]));diagnostic=line;}
                default->{}
            }}
            require(origins.size()==10&&nativeValues.size()==512&&diagnostic!=null&&Set.of(high,low).equals(Set.of(0,8)));
            var interpreter=new NativeUuidFormatterDerivation(models.get("java/lang/Long"),digits,mode.equals("compact"),high,low);
            for(int position=0;position<32;position++)for(int digit=0;digit<16;digit++){
                long most=position<16?(long)digit<<((15-position)*4):0,least=position>=16?(long)digit<<((31-position)*4):0;
                String value=interpreter.format(most,least);require(canonical(value)&&value.equals(nativeValues.get(position+":"+digit)));controls++;
            }
            for(long[] edge:List.of(new long[]{0,0},new long[]{-1,-1},new long[]{Long.MIN_VALUE,Long.MAX_VALUE},new long[]{Long.MAX_VALUE,Long.MIN_VALUE})){
                String value=interpreter.format(edge[0],edge[1]);require(canonical(value)&&lines.contains("EDGE\t"+edge[0]+"\t"+edge[1]+"\t"+value));controls++;
            }
            // Reexercise the lookup-table mutant through original bytecodes; never adopt it as product FAIL.
            char[] alternate=digits.clone();for(int i=10;i<16;i++)alternate[i]=Character.toUpperCase(alternate[i]);long bits=0xabcdefabcdefabcdL;
            String actual=interpreter.format(bits,bits),mutant=new NativeUuidFormatterDerivation(models.get("java/lang/Long"),alternate,mode.equals("compact"),high,low).format(bits,bits);
            require(caseOnlyPair(actual,mutant)&&diagnostic.equals("NATIVE_DIAGNOSTIC\t"+actual+"\t"+mutant+"\ttableRestored=true\tproductJvmMutated=false"));controls++;
        }return controls;
    }
    /** Captured process originals are a closed invocation sequence, never arbitrary JVM commands. */
    static void verifyProcess(JsonNode process,java.time.Instant notBefore,java.time.Instant notAfter){
        var operations=process.path("operations");require(operations.isArray()&&operations.size()==8);
        String container="samlscope-reference-keycloak",helper=operations.get(1).path("command").path(6).asText();
        require(helper.matches("/tmp/samlscope-idp21-canonical-[0-9]{8}\\.java"));
        var inspection=List.of("docker","inspect","--format","{{json .Id}} {{json .Image}} {{json .State.StartedAt}}",container);
        var absence=List.of("docker","exec",container,"test","!","-e",helper);
        var compact=List.of("docker","exec",container,"java","-XX:-UsePerfData","--add-opens","java.base/java.lang=ALL-UNNAMED","--add-opens","java.base/java.util=ALL-UNNAMED",helper);
        var utf16=List.of("docker","exec",container,"java","-XX:-UsePerfData","-XX:-CompactStrings","--add-opens","java.base/java.lang=ALL-UNNAMED","--add-opens","java.base/java.util=ALL-UNNAMED",helper);
        var expected=List.of(inspection,absence,List.of("docker","cp","dev/reference-acceptance/ProbeKeycloakCanonicalUuidFormatter.java",container+":"+helper),compact,utf16,List.of("docker","exec","--user","0",container,"rm","--",helper),absence,inspection);
        var names=List.of("runtime-before","helper-absence-before","helper-copy","compact","utf16","helper-remove","helper-absence-after","runtime-after");
        java.time.Instant previous=notBefore;require(!notBefore.isAfter(notAfter));
        for(int index=0;index<8;index++){
            var row=operations.get(index);var command=row.path("command");require(command.isArray()&&command.size()==expected.get(index).size());
            for(int argument=0;argument<command.size();argument++)require(command.get(argument).isTextual()&&expected.get(index).get(argument).equals(command.get(argument).asText()));
            require((names.get(index)+".stdout.txt").equals(text(row,"stdoutFile"))&&(names.get(index)+".stderr.txt").equals(text(row,"stderrFile"))&&row.path("exitCode").asInt(-1)==0);
            var start=java.time.Instant.parse(text(row,"startedAt"));var finish=java.time.Instant.parse(text(row,"finishedAt"));
            require(!start.isBefore(previous)&&!finish.isBefore(start)&&!finish.isAfter(notAfter));previous=finish;
        }
    }
    static boolean caseOnlyPair(String a,String b){return a!=null&&b!=null&&!a.equals(b)&&a.equalsIgnoreCase(b);}
    private static boolean canonical(String value){return value.matches("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}");}
    private JsonNode contract()throws Exception{try(var in=getClass().getResourceAsStream(RESOURCE)){require(in!=null);byte[] bytes=in.readAllBytes();require(hash(bytes).equals(RESOURCE_SHA));return json.readTree(bytes);}}
    private Map<String,String> epoch(JsonNode value){return Map.of("id",value.has("containerId")?text(value,"containerId"):text(value,"id"),"image",text(value,"image"),"startedAt",text(value,"startedAt"));}
    private JsonNode node(Path folder,JsonNode files,String name)throws Exception{return json.readTree(checked(folder,files,name));}
    private static byte[] checked(Path folder,JsonNode files,String name)throws Exception{byte[] bytes=raw(folder,name);require(hash(bytes).equals(text(files,name)));return bytes;}
    private static byte[] raw(Path folder,String name)throws Exception{require(name!=null&&name.matches("[A-Za-z0-9_.$/-]+")&&!Path.of(name).isAbsolute());Path base=folder.toAbsolutePath().normalize(),path=base.resolve(name).normalize();require(path.startsWith(base)&&!path.equals(base));for(Path at=path;at!=null;at=at.getParent())require(!Files.isSymbolicLink(at));require(Files.isRegularFile(path,LinkOption.NOFOLLOW_LINKS)&&Files.size(path)<=2_097_152);return Files.readAllBytes(path);}
    private static String text(JsonNode value,String name){return DefaultAlgorithmPreventionEvidence.text(value,name);}
    private static String hash(byte[] bytes)throws Exception{return DefaultAlgorithmPreventionEvidence.hash(bytes);}
    private static void require(boolean value){DefaultAlgorithmPreventionEvidence.require(value);}
}
