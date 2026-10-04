package com.samlscope.runner.cases;

import com.fasterxml.jackson.databind.JsonNode;
import com.samlscope.core.caseexec.CaseContext;
import com.samlscope.core.evaluation.CaseOutcome;
import com.samlscope.core.evaluation.EvidenceRef;
import com.samlscope.core.evaluation.Outcome;
import com.samlscope.core.transcript.Direction;
import com.samlscope.core.transcript.TranscriptContentReader;
import com.samlscope.core.transcript.TranscriptEntry;
import com.samlscope.saml.crypto.XmlSignatureVerifier;
import com.samlscope.saml.normal.SecureXml;
import com.samlscope.store.JsonCodec;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.*;
import java.util.function.Function;
import java.util.zip.ZipInputStream;
import org.w3c.dom.Element;

/**
 * Original-backed SOAP continuation observer for approved IDP17.r. The legacy HTTP500
 * and front-channel partial-logout observers are separate. A Responder is an error even
 * when its HTTP transport succeeds. Production proof requires both actual trials in this
 * Run, installed Prepared bytes, selected native SLO scope, and complete restoration.
 */
public final class ShibbolethNativeSloContinuationEvidence {
    public static final String CASE="IIP-IDP17-r-idp-01";
    public static final String SCHEMA="samlscope-shibboleth-native-soap-continuation-v1";
    public static final String ADAPTER="shibboleth-native-soap-sequential-continuation-v1";
    private static final String RUN="run_[0-9A-HJKMNP-TV-Z]{26}", TX="tx_[0-9A-HJKMNP-TV-Z]{26}",
        MD="urn:oasis:names:tc:SAML:2.0:metadata", P="urn:oasis:names:tc:SAML:2.0:protocol",
        A="urn:oasis:names:tc:SAML:2.0:assertion", DS="http://www.w3.org/2000/09/xmldsig#",
        SOAP="http://schemas.xmlsoap.org/soap/envelope/", BINDING="urn:oasis:names:tc:SAML:2.0:bindings:SOAP",
        PROFILE="http://shibboleth.net/ns/profiles/saml2/logout", SUCCESS="urn:oasis:names:tc:SAML:2.0:status:Success",
        RESPONDER="urn:oasis:names:tc:SAML:2.0:status:Responder";
    private static final Map<String,String> NATIVE=Map.of(
        "idp-conf-impl.jar","428e389d88bb2abcad19d69bcf759af29f7ce6beb776ccfaa5a6ea76751682ba",
        "slo-back-flow.xml","150176e47e15b5a18af6711aef66e4a5b38b0a90c24e2f9a5f3838915d70b759",
        "slo-back-beans.xml","7171d665edd7a1f2210c067c06822abc78825285c4cf845c5e67961b3c778208");
    private static final Map<String,String> CONFIG=Map.of(
        "global","ca08485a1b5ef8cf0ac1afb80ff066237759e4fb3d884d087f905d8ca0918bcc",
        "services","0c5de788ebc611af60ebb3bf4071dcd23744f599d64d65bdb0744515d11a77c0",
        "relying-party","64e2a04dfbf2ffa2a582b995bcbf121b634ab7c8766cb8f22d3397d541f31bd5");
    private static final JsonCodec JSON=new JsonCodec();
    static final List<String> STOCK_AUTHN_FLOWS=List.of("conditions-flow.xml","account-locked/account-locked-flow.xml","expired-password/expired-password-flow.xml","expiring-password/expiring-password-flow.xml");
    private static final String AUTHN_FLOW_ROOT="/opt/reference-idp/flows/authn/conditions/",AUTHN_RESOURCE_ROOT="net/shibboleth/idp/module/flows/authn/conditions/";
    private final Path directory; private final TranscriptContentReader content;
    private final Function<String,byte[]> metadata; private final SamlDecryptionKeyProvider keys;
    private final boolean diagnosticPermission;
    public ShibbolethNativeSloContinuationEvidence(Path directory,TranscriptContentReader content,
            Function<String,byte[]> targetMetadata,SamlDecryptionKeyProvider keys) {
        this(directory,content,targetMetadata,keys,false);
    }
    ShibbolethNativeSloContinuationEvidence(Path directory,TranscriptContentReader content,
            Function<String,byte[]> targetMetadata,SamlDecryptionKeyProvider keys,boolean diagnosticPermission) {
        this.directory=Objects.requireNonNull(directory).toAbsolutePath().normalize();this.content=Objects.requireNonNull(content);
        this.metadata=Objects.requireNonNull(targetMetadata);this.keys=Objects.requireNonNull(keys);
        this.diagnosticPermission=diagnosticPermission;
    }
    public boolean exists(String run) {return run!=null&&run.matches(RUN)&&Files.exists(directory.resolve(run),LinkOption.NOFOLLOW_LINKS);}
    public Optional<CaseOutcome> read(CaseContext context,String caseId) {
        if(!CASE.equals(caseId))return Optional.empty();if(!exists(context.runId()))return Optional.empty();
        var evidence=new LinkedHashSet<EvidenceRef>();
        try {
            require(context.transcriptComplete());var folder=directory.resolve(context.runId());
            byte[] manifestRaw=raw(folder,"manifest.json");var manifest=json(manifestRaw);
            boolean actor=SloContinuationActorEvidence.SCHEMA.equals(text(manifest,"schema"));
            require((actor?diagnosticPermission:SCHEMA.equals(text(manifest,"schema")))&&context.runId().equals(text(manifest,"runId")));
            require(!ShibbolethRegisteredSignerEvidence.sensitive(manifest));
            for(String flag:List.of("diagnosticOnly","calibrationOnly","counterfactual","developerBehavior"))require(!manifest.has(flag)||manifest.path(flag).isBoolean()&&!manifest.path(flag).asBoolean());var files=manifest.path("files");require(files.isObject()&&!files.isEmpty());
            for(var it=files.fields();it.hasNext();){var row=it.next();require(row.getValue().isTextual()&&row.getValue().asText().matches("[a-f0-9]{64}"));checked(folder,files,row.getKey());}
            byte[] targetBytes=metadata.apply(context.runId());require(hash(targetBytes).equals(text(manifest,"targetMetadataSha256")));
            if(!actor){validateRestorationBytes(checked(folder,files,"original-target-metadata.xml"),checked(folder,files,"final-target-metadata.xml"),
                    checked(folder,files,"configured-target-metadata.xml"),targetBytes);
            require(Arrays.equals(checked(folder,files,"original-audit.xml"),checked(folder,files,"final-audit.xml")));}
            SloContinuationActorEvidence.Originals originals=name->checked(folder,files,name);
            var actorProducer=actor?SloContinuationActorEvidence.producer(manifest,originals):null;
            var target=SecureXml.parse(targetBytes).getDocumentElement();var targetKeys=MetadataAlgorithmEvidence.signingKeys(target);require(!targetKeys.isEmpty());
            String targetEntity=target.getAttribute("entityID"),plan=text(manifest,"planId"),entity="http://localhost:18080/p/"+plan;
            require(plan.matches("plan_[0-9A-HJKMNP-TV-Z]{26}"));
            var byId=new LinkedHashMap<String,TranscriptEntry>();
            for(var e:context.transcript().list(context.runId()))require(context.runId().equals(e.runId())&&e.id().matches(TX)&&byId.put(e.id(),e)==null);
            if(!actor){for(var pin:NATIVE.entrySet())require(pin.getValue().equals(hash(checked(folder,files,"native/"+pin.getKey()))));
            var jar=checked(folder,files,"native/idp-conf-impl.jar");
            for(String name:List.of("slo-back-flow.xml","slo-back-beans.xml"))require(Arrays.equals(zip(jar,"net/shibboleth/idp/flows/saml/saml2/"+name),checked(folder,files,"native/"+name)));
            var restore=json(checked(folder,files,"restoration.json"));require(bool(restore,"restored")&&bool(restore,"temporaryRemoved"));
            require(Arrays.equals(checked(folder,files,"original-providers.xml"),checked(folder,files,"final-providers.xml")));
            for(String name:CONFIG.keySet())require(Arrays.equals(checked(folder,files,"original-"+name+".xml"),checked(folder,files,"final-"+name+".xml"))
                    &&CONFIG.get(name).equals(hash(checked(folder,files,"original-"+name+".xml"))));}
            var trials=manifest.path("trials");require(trials.isArray()&&trials.size()==2);var labels=new HashSet<String>();var windows=new ArrayList<Window>();
            Outcome failureOutcome=Outcome.NOT_VERIFIED;
            for(var t:trials){String trial=text(t,"trial");require(Set.of("failure","all-success").contains(trial)&&labels.add(trial));
                var prepared=entry(byId,text(t,"preparedReference"));require(prepared.direction()==Direction.OUTBOUND&&"MetadataPrepared".equals(prepared.samlSummary().get("type"))
                    &&("slo-propagation-soap-"+trial).equals(prepared.samlSummary().get("variant"))&&CASE.equals(prepared.samlSummary().get("case_id"))
                    &&context.runId().equals(prepared.samlSummary().get("run_id"))&&plan.equals(prepared.samlSummary().get("plan_id")));
                byte[] preparedRaw=decoded(prepared,context.runId());var preparedXml=SecureXml.parse(preparedRaw).getDocumentElement();
                var preparedAt=Instant.parse(Objects.toString(prepared.samlSummary().get("prepared_at"),""));require(!preparedAt.isAfter(prepared.timestamp()));
                var peers=preparedPeers(preparedXml,entity,context.runId(),trial);var suiteKeys=spKeys(peers.get("primary"));require(!suiteKeys.isEmpty()&&valid(preparedXml,suiteKeys));
                var credentials=new com.samlscope.saml.crypto.PlanCredentials(keys.keyFor(context.runId()).orElseThrow(),suiteKeys.getFirst());
                var expected=actor?com.samlscope.saml.logout.SloPropagationFixtures.prepare(java.net.URI.create(entity),java.net.URI.create(entity+"/sp/acs/0"),credentials,context.runId(),trial,preparedAt,java.net.URI.create(actorProducer.callbackBase()))
                    :com.samlscope.saml.logout.SloPropagationFixtures.prepare(java.net.URI.create(entity),java.net.URI.create(entity+"/sp/acs/0"),credentials,context.runId(),trial,preparedAt);
                var expectedXml=SecureXml.parse(expected).getDocumentElement();removeSignatures(expectedXml);var actualCopy=SecureXml.parse(preparedRaw).getDocumentElement();removeSignatures(actualCopy);require(metadataView(expectedXml).equals(metadataView(actualCopy)));
                JsonNode before=null,after=null;
                if(!actor){before=state(folder,files,text(t,"beforeFile"),context.runId(),trial,entity,preparedRaw);
                    after=state(folder,files,text(t,"afterFile"),context.runId(),trial,entity,preparedRaw);
                    require(before.path("runtime").equals(after.path("runtime"))&&time(before,"finishedAt").isBefore(time(after,"startedAt")));}
                var origin=message(folder,files,byId,text(t,"originRequestReference"),context.runId());
                var finalResponse=message(folder,files,byId,text(t,"originResponseReference"),context.runId());
                require(prepared.timestamp().isBefore(origin.entry.timestamp())&&(actor||(time(before,"finishedAt").isBefore(origin.entry.timestamp())
                    &&finalResponse.entry.timestamp().isBefore(time(after,"startedAt")))));
                var rows=t.path("participants");require(rows.isArray()&&!rows.isEmpty()&&rows.size()<=3&&(actor||rows.size()==3));var participants=new ArrayList<Participant>();var used=new HashSet<String>();
                for(var row:rows){String label=text(row,"label");require(Set.of("fail","remain","remain2").contains(label)&&used.add(label));
                    var nativePeer=SecureXml.parse(checked(folder,files,text(row,"nativeMetadataFile"))).getDocumentElement();
                    require(metadataView(nativePeer).equals(metadataView(peers.get(label))));
                    participants.add(new Participant(label,message(folder,files,byId,text(row,"requestReference"),context.runId()),
                        message(folder,files,byId,text(row,"responseReference"),context.runId())));
                }
                var operation=inspectTrial(context.runId(),trial,entity,targetEntity,prepared.id(),hash(preparedRaw),peers,origin,finalResponse,participants,suiteKeys,targetKeys);
                var window=new Window(origin.xml.getAttribute("ID"),origin.entry.timestamp(),finalResponse.entry.timestamp());
                require(windows.stream().noneMatch(window::overlaps));windows.add(window);
                var baselineRows=t.path("baselines");require(baselineRows.isArray()&&baselineRows.size()==4);var baselines=new LinkedHashMap<String,TranscriptEntry>();
                for(var b:baselineRows){String label=text(b,"label");require(peers.containsKey(label)&&baselines.put(label,entry(byId,text(b,"responseReference")))==null);}
                requireSession(List.of(baselines.get("primary")),byId.values(),context.runId(),entity,targetEntity,origin.xml,targetKeys,origin.entry.timestamp());
                for(var participant:participants)requireSession(List.of(baselines.get(participant.label)),byId.values(),context.runId(),entity+"/sp-"+participant.label,targetEntity,participant.request.xml,targetKeys,origin.entry.timestamp());
                if(actor){var sessions=new LinkedHashMap<String,SloContinuationActorEvidence.Session>();for(String label:List.of("fail","remain","remain2"))sessions.put(label,
                        actorSession(baselines.get(label),byId.values(),context.runId(),entity+"/sp-"+label,targetEntity,soapEndpoint(peers.get(label)),targetKeys,suiteKeys,origin.entry.timestamp()));
                    operation=SloContinuationActorEvidence.operation(context.runId(),trial,hash(targetBytes),hash(preparedRaw),origin,finalResponse,participants,sessions,targetKeys,actorProducer,t,originals,operation);}
                Outcome observed=SloContinuationProof.computeOutcome(operation);
                if("all-success".equals(trial))require(observed==Outcome.SATISFIED);else failureOutcome=observed;
                for(var b:baselines.values())evidence.add(ref(b));
                for(var e:List.of(prepared,origin.entry,finalResponse.entry))evidence.add(ref(e));
                for(var p:participants){evidence.add(ref(p.request.entry));evidence.add(ref(p.response.entry));}
            }
            var usedOrigins=windows.stream().map(w->w.requestId).collect(java.util.stream.Collectors.toSet());
            long actualOrigins=byId.values().stream().filter(e->e.direction()==Direction.OUTBOUND&&"LogoutRequest".equals(e.samlSummary().get("type"))).count();
            require(actualOrigins==2&&usedOrigins.size()==2);
            require(failureOutcome==Outcome.SATISFIED||failureOutcome==Outcome.VIOLATED);
            evidence.add(new EvidenceRef("native-slo-continuation-evidence",context.runId()+"/manifest.json#"+hash(manifestRaw)));
            String reason=failureOutcome==Outcome.VIOLATED?"slo.propagation.stopped-after-error":"slo.propagation.native-soap-continue-after-error";
            return Optional.of(new CaseOutcome(failureOutcome,null,reason,reason,List.copyOf(evidence),Map.of("evidence_adapter",ADAPTER,"native_run_id",context.runId(),
                    "participant_count",3,"remaining_participant_count",2,"failure_transport_status",200,"failure_saml_status",RESPONDER,
                    "counterfactual_calibration_only",actor,"proof_scope",actor?"isolated-case-scoped-control-target":"stock-native-soap-propagation")));
        }catch(Exception invalid){return Optional.of(CaseOutcome.notVerified("native_soap_continuation_unproven","slo.propagation.native-soap-evidence-incomplete"));}
    }
    static void validateRestorationBytes(byte[] original,byte[] restored,byte[] configured,byte[] runSnapshot){
        require(original!=null&&original.length>0&&Arrays.equals(original,restored)&&configured!=null&&configured.length>0&&Arrays.equals(configured,runSnapshot));
    }
    private JsonNode state(Path folder,JsonNode files,String file,String run,String trial,String entity,byte[] prepared)throws Exception {
        var s=json(checked(folder,files,file));require(run.equals(text(s,"runId"))&&trial.equals(text(s,"trial"))&&time(s,"startedAt").isBefore(time(s,"finishedAt")));
        var runtime=s.path("runtime");require(text(runtime,"id").matches("[a-f0-9]{64}")&&text(runtime,"image").matches("sha256:[a-f0-9]{64}")&&bool(runtime,"running")
                &&runtime.path("mounts").isArray());Instant.parse(text(runtime,"startedAt"));
        require(Arrays.equals(prepared,checked(folder,files,text(s,"metadataFile"))));
        require(Arrays.equals(checked(folder,files,"configured-providers.xml"),checked(folder,files,text(s,"providersFile"))));
        String prefix=text(s,"scopePrefix");var observed=json(checked(folder,files,prefix+"observed.json"));
        var jars=observed.path("nativeJars");require(jars.isObject()&&jars.size()==4);
        for(var pin:Map.of("idp-conf-impl",NATIVE.get("idp-conf-impl.jar"),"idp-saml-impl","1a2a9f867d11c50eeaf2a6140bb5de88b0611d694ea6de2bbfe32f72a4a2998b",
            "opensaml-saml-impl","9f04221e172dc426f90fb3873d0148a0744edbf9e7a37de7ee0e6a34f7b74581","opensaml-xmlsec-impl","cc67fc1bd9cb435cdbe7483ef04513c83cc9619a3015c04ad41bb6cc0eb6e68e").entrySet())require(pin.getValue().equals(text(jars,pin.getKey())));
        require("1fcd492d07b1ca59600b763c0cddc3be85dc223841a2298bf3719274b66c4cb3".equals(hash(checked(folder,files,prefix+"classpath-sha256.json"))));
        SloRegisteredSignerNativeAdapters.requireShibTrustScope(observed,json(checked(folder,files,prefix+"native-effective-profile.json")),
            json(checked(folder,files,prefix+"selected-properties.json")),json(checked(folder,files,prefix+"process-overrides.json")),
            json(checked(folder,files,prefix+"override-source-inventory.json")),entity,time(s,"startedAt"),time(s,"finishedAt"));
        for(var config:CONFIG.entrySet())require(config.getValue().equals(hash(checked(folder,files,prefix+config.getKey()+".xml"))));
        var flowOriginals=s.path("nativeFlowOriginals");require(flowOriginals.isObject()&&flowOriginals.size()==4);var originals=new LinkedHashMap<String,byte[]>();var expected=new LinkedHashMap<String,byte[]>();
        byte[] nativeJar=checked(folder,files,"native/idp-conf-impl.jar");
        for(String flow:STOCK_AUTHN_FLOWS){String path=AUTHN_FLOW_ROOT+flow;originals.put(path,checked(folder,files,text(flowOriginals,path)));expected.put(path,zip(nativeJar,AUTHN_RESOURCE_ROOT+flow));}
        validateFlowOverrides(checked(folder,files,text(s,"flowOverrideInventoryFile")),originals,expected);
        require("true".equals(text(json(checked(folder,files,text(s,"sessionPropertiesFile"))),"idp.session.trackSPSessions")));
        return s;
    }
    static void validateFlowOverrides(byte[] inventory,Map<String,byte[]> originals,Map<String,byte[]> stock){
        var allowed=new HashSet<String>();for(String flow:STOCK_AUTHN_FLOWS)allowed.add(AUTHN_FLOW_ROOT+flow);
        require(originals.keySet().equals(allowed)&&stock.keySet().equals(allowed));for(String path:allowed)require(originals.get(path)!=null&&originals.get(path).length>0&&Arrays.equals(originals.get(path),stock.get(path)));
        var observed=new HashSet<String>();
        for(String path:new String(inventory,StandardCharsets.UTF_8).lines().toList()){
            require(path.startsWith("/opt/reference-idp/")&&!path.contains("..")&&!path.endsWith(".class")&&!path.endsWith(".jar"));
            if(path.contains("/flows/"))require(allowed.contains(path)&&observed.add(path));
        }
        require(observed.equals(allowed));
    }
    static String originActionId(String run,String trial){return com.samlscope.core.caseexec.ActionIds.derive(run,CASE,"slo-basic-v6-soap-propagation-"+trial+"-logout",0);}
    static Window validateTrial(String run,String trial,String entity,String target,String preparedRef,String preparedSha,
            Map<String,Element> peers,SoapMessage origin,SoapMessage finalResponse,List<Participant> participants,
            List<X509Certificate> suiteKeys,List<X509Certificate> targetKeys) {
        var operation=inspectTrial(run,trial,entity,target,preparedRef,preparedSha,peers,origin,finalResponse,participants,suiteKeys,targetKeys);
        require(operation.attempted().size()==3&&SloContinuationProof.computeOutcome(operation)==Outcome.SATISFIED);
        return new Window(origin.xml.getAttribute("ID"),origin.entry.timestamp(),finalResponse.entry.timestamp());
    }
    static SloContinuationProof.Operation inspectTrial(String run,String trial,String entity,String target,String preparedRef,String preparedSha,
            Map<String,Element> peers,SoapMessage origin,SoapMessage finalResponse,List<Participant> participants,
            List<X509Certificate> suiteKeys,List<X509Certificate> targetKeys) {
        require(Set.of("failure","all-success").contains(trial)&&!participants.isEmpty()&&participants.size()<=3);
        require(origin.entry.direction()==Direction.OUTBOUND&&is(origin.xml,"LogoutRequest")&&entity.equals(issuer(origin.xml))&&valid(origin.xml,suiteKeys));
        require(origin.entry.url().equals(origin.xml.getAttribute("Destination"))&&origin.entry.url().endsWith("/idp/profile/SAML2/SOAP/SLO")
            &&"direct-soap".equals(origin.entry.samlSummary().get("probe_transport"))&&"LOGOUT_PROBE".equals(origin.entry.samlSummary().get("kind")));
        String action=originActionId(run,trial);require(action.equals(origin.entry.correlationId())&&action.equals(origin.entry.samlSummary().get("action_id"))
            &&("_"+action).equals(origin.xml.getAttribute("ID")));
        require(origin.xml.getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:protocol:ext:async-slo","Asynchronous").getLength()==0);
        require(finalResponse.entry.direction()==Direction.INBOUND&&is(finalResponse.xml,"LogoutResponse")&&valid(finalResponse.xml,targetKeys)
            &&target.equals(issuer(finalResponse.xml))&&origin.xml.getAttribute("ID").equals(finalResponse.xml.getAttribute("InResponseTo"))
            &&origin.entry.timestamp().isBefore(finalResponse.entry.timestamp())&&Integer.valueOf(200).equals(finalResponse.entry.status())
            &&origin.entry.id().equals(finalResponse.entry.samlSummary().get("request_transcript"))&&action.equals(finalResponse.entry.correlationId())
            &&origin.entry.url().equals(finalResponse.entry.url()));
        require((finalResponse.xml.getAttribute("Destination").isBlank()||finalResponse.xml.getAttribute("Destination").equals(soapEndpoint(peers.get("primary"))))
                &&Set.of(SUCCESS,RESPONDER).contains(status(finalResponse.xml)));
        var sorted=new ArrayList<>(participants);sorted.sort(Comparator.comparing(p->p.request.entry.timestamp()));
        var ids=new HashSet<String>(List.of(origin.xml.getAttribute("ID"),finalResponse.xml.getAttribute("ID")));var endpoints=new HashSet<String>();var labels=new HashSet<String>();
        var attempted=new ArrayList<String>();var statuses=new ArrayList<String>();
        Instant previous=origin.entry.timestamp();
        for(int i=0;i<sorted.size();i++){
            var p=sorted.get(i);require(labels.add(p.label)&&peers.containsKey(p.label));var q=p.request;var a=p.response;
            require(q.entry.direction()==Direction.INBOUND&&a.entry.direction()==Direction.OUTBOUND&&is(q.xml,"LogoutRequest")&&is(a.xml,"LogoutResponse")
                &&target.equals(issuer(q.xml))&&valid(q.xml,targetKeys)&&valid(a.xml,suiteKeys)&&ids.add(q.xml.getAttribute("ID"))&&ids.add(a.xml.getAttribute("ID")));
            require(q.xml.getAttribute("Destination").equals(soapEndpoint(peers.get(p.label)))&&q.entry.url().equals(q.xml.getAttribute("Destination"))
                &&endpoints.add(q.entry.url())&&a.xml.getAttribute("InResponseTo").equals(q.xml.getAttribute("ID"))&&issuer(a.xml).equals(entity+"/sp-"+p.label)
                &&a.entry.url().equals(a.xml.getAttribute("Destination"))&&a.xml.getAttribute("Destination").equals(origin.entry.url()));
            require(q.entry.timestamp().isAfter(previous)&&a.entry.timestamp().isAfter(q.entry.timestamp())&&a.entry.timestamp().isBefore(finalResponse.entry.timestamp()));
            for(var e:List.of(q.entry,a.entry)){var m=e.samlSummary();require("error-v2".equals(m.get("propagationFixture"))&&trial.equals(m.get("propagationTrial"))
                    &&p.label.equals(m.get("propagationParticipant"))&&preparedRef.equals(m.get("preparedMetadataRef"))&&preparedSha.equals(m.get("preparedMetadataSha256"))
                    &&com.samlscope.saml.logout.SloPropagationFixtures.mode(trial).equals(m.get("propagationMode"))
                    &&m.get("propagationOrdinal") instanceof Number n&&n.intValue()==i+1&&n.doubleValue()==i+1);}
            String expected="failure".equals(trial)&&i==0?RESPONDER:SUCCESS;
            require(expected.equals(status(a.xml))&&expected.equals(a.entry.samlSummary().get("responseStatus"))&&"soapResponse-return".equals(a.entry.samlSummary().get("producerBoundary"))&&Integer.valueOf(200).equals(a.entry.status()));
            attempted.add(p.label);statuses.add(status(a.xml));
            previous=a.entry.timestamp();
        }
        var remaining=new HashSet<>(Set.of("fail","remain","remain2"));remaining.removeAll(labels);
        return new SloContinuationProof.Operation(trial,Set.of("fail","remain","remain2"),attempted,labels,remaining,statuses,
                remaining.isEmpty()?SloContinuationProof.TerminalAuthority.REACHED_ALL_SELECTED:SloContinuationProof.TerminalAuthority.UNPROVEN);
    }
    private SoapMessage message(Path folder,JsonNode files,Map<String,TranscriptEntry> entries,String ref,String run)throws Exception {
        var e=entry(entries,ref);byte[] decoded=decoded(e,run);String envelopeFile="soap/"+e.id()+".xml";byte[] envelope=checked(folder,files,envelopeFile);
        require(e.bodyRef()!=null&&e.bodyRef().equals("transcripts/"+run+"/"+e.id()+".body")&&e.bodyBytes()==envelope.length);
        return message(e,decoded,envelope,run);
    }
    static SoapMessage message(TranscriptEntry e,byte[] decoded,byte[] envelope,String run) {
        require(run.equals(e.runId())&&"POST".equals(e.method())&&("SOAP".equals(e.samlSummary().get("transport"))||"direct-soap".equals(e.samlSummary().get("probe_transport")))
            &&Objects.equals(e.rawQuery(),java.net.URI.create(e.url()).getRawQuery()));
        var outer=SecureXml.parse(envelope).getDocumentElement();require(SOAP.equals(outer.getNamespaceURI())&&"Envelope".equals(outer.getLocalName()));
        var bodies=children(outer,SOAP,"Body");require(bodies.size()==1&&elements(bodies.getFirst()).size()==1);
        var inner=elements(bodies.getFirst()).getFirst();require(is(inner,"LogoutRequest")||is(inner,"LogoutResponse"));
        var root=SecureXml.parse(decoded).getDocumentElement();if(SOAP.equals(root.getNamespaceURI())){var b=children(root,SOAP,"Body");require(b.size()==1&&elements(b.getFirst()).size()==1);root=elements(b.getFirst()).getFirst();}
        Object recordedType=e.samlSummary().get("type");if("SloProbeHttpResponse".equals(recordedType)){require("direct-soap".equals(e.samlSummary().get("probe_transport")));recordedType=e.samlSummary().get("saml_message");}
        require(view(root).equals(view(inner))&&root.getLocalName().equals(recordedType)&&!root.getAttribute("ID").isBlank());
        return new SoapMessage(e,inner);
    }
    static Map<String,Element> preparedPeers(Element root,String entity,String run,String trial) {
        require(MD.equals(root.getNamespaceURI())&&"EntitiesDescriptor".equals(root.getLocalName()));var result=new LinkedHashMap<String,Element>();
        for(var peer:children(root,MD,"EntityDescriptor")){String id=peer.getAttribute("entityID"),label=id.equals(entity)?"primary":id.startsWith(entity+"/sp-")?id.substring((entity+"/sp-").length()):"";
            require(Set.of("primary","fail","remain","remain2").contains(label)&&result.put(label,peer)==null&&!spKeys(peer).isEmpty());
            var uri=java.net.URI.create(soapEndpoint(peer));if(!"primary".equals(label))require(uri.getRawQuery()!=null&&run.equals(query(uri,"run"))&&trial.equals(query(uri,"trial"))
                    &&label.equals(query(uri,"participant"))&&"error-v2".equals(query(uri,"propagation"))
                    &&com.samlscope.saml.logout.SloPropagationFixtures.mode(trial).equals(query(uri,"mode"))&&uri.getUserInfo()==null&&uri.getFragment()==null);
        }
        require(result.keySet().equals(Set.of("primary","fail","remain","remain2")));return result;
    }
    private void requireSession(Collection<TranscriptEntry> entries,Collection<TranscriptEntry> all,String run,String entity,String targetEntity,Element logout,List<X509Certificate> targetKeys,Instant until)throws Exception {
        var indexes=children(logout,P,"SessionIndex");require(indexes.size()==1&&!indexes.getFirst().getTextContent().isBlank());String index=indexes.getFirst().getTextContent();
        Element logoutName=name(logout,run);int found=0;
        for(var e:entries)if(e.direction()==Direction.INBOUND&&"Response".equals(e.samlSummary().get("type"))&&e.timestamp().isBefore(until)){
            var response=SecureXml.parse(decoded(e,run)).getDocumentElement();if(!SUCCESS.equals(status(response))||!valid(response,targetKeys)||!targetEntity.equals(issuer(response)))continue;
            var requests=new ArrayList<TranscriptEntry>();for(var q:all)if(q.direction()==Direction.OUTBOUND&&"AuthnRequest".equals(q.samlSummary().get("type"))&&q.timestamp().isBefore(e.timestamp())){var xml=SecureXml.parse(decoded(q,run)).getDocumentElement();if(entity.equals(issuer(xml))&&xml.getAttribute("ID").equals(response.getAttribute("InResponseTo")))requests.add(q);}require(requests.size()==1);
            var assertions=children(response,A,"Assertion");if(assertions.isEmpty())for(var encrypted:children(response,A,"EncryptedAssertion"))assertions.add(new com.samlscope.saml.crypto.SamlXmlDecrypter().decrypt(encrypted,keys.keyFor(run).orElseThrow()));
            for(var assertion:assertions){if(!targetIssuer(assertion,issuer(response)))continue;var audiences=assertion.getElementsByTagNameNS(A,"Audience");boolean audience=false;
                for(int i=0;i<audiences.getLength();i++)if(entity.equals(audiences.item(i).getTextContent()))audience=true;
                var statements=children(assertion,A,"AuthnStatement");if(!audience||statements.stream().noneMatch(s->index.equals(s.getAttribute("SessionIndex"))))continue;
                var subject=children(assertion,A,"Subject");if(subject.size()==1&&view(name(subject.getFirst(),run)).equals(view(logoutName)))found++;
            }
        }
        require(found==1);
    }
    private SloContinuationActorEvidence.Session actorSession(TranscriptEntry responseEntry,Collection<TranscriptEntry> all,
            String run,String entity,String targetEntity,String endpoint,List<X509Certificate> targetKeys,List<X509Certificate> suiteKeys,Instant until)throws Exception {
        require(responseEntry.direction()==Direction.INBOUND&&"Response".equals(responseEntry.samlSummary().get("type"))&&responseEntry.timestamp().isBefore(until));
        var response=SecureXml.parse(decoded(responseEntry,run)).getDocumentElement();require(SUCCESS.equals(status(response))&&valid(response,targetKeys)&&targetEntity.equals(issuer(response)));
        var requests=new ArrayList<Element>();for(var entry:all)if(entry.direction()==Direction.OUTBOUND&&"AuthnRequest".equals(entry.samlSummary().get("type"))&&entry.timestamp().isBefore(responseEntry.timestamp())) {
            var request=SecureXml.parse(decoded(entry,run)).getDocumentElement();if(entity.equals(issuer(request))&&request.getAttribute("ID").equals(response.getAttribute("InResponseTo")))requests.add(request);
        }
        require(requests.size()==1&&valid(requests.getFirst(),suiteKeys));
        var assertions=children(response,A,"Assertion");if(assertions.isEmpty())for(var encrypted:children(response,A,"EncryptedAssertion"))assertions.add(new com.samlscope.saml.crypto.SamlXmlDecrypter().decrypt(encrypted,keys.keyFor(run).orElseThrow()));
        require(assertions.size()==1&&targetIssuer(assertions.getFirst(),targetEntity));var assertion=assertions.getFirst();
        var audiences=assertion.getElementsByTagNameNS(A,"Audience");require(audiences.getLength()==1&&entity.equals(audiences.item(0).getTextContent()));
        var statements=children(assertion,A,"AuthnStatement");require(statements.size()==1&&!statements.getFirst().getAttribute("SessionIndex").isBlank());
        var subjects=children(assertion,A,"Subject");require(subjects.size()==1);var principal=name(subjects.getFirst(),run);
        return new SloContinuationActorEvidence.Session(entity,endpoint,hash(statements.getFirst().getAttribute("SessionIndex").getBytes(StandardCharsets.UTF_8)),hash(view(principal).getBytes(StandardCharsets.UTF_8)));
    }
    private Element name(Element parent,String run) {var names=children(parent,A,"NameID");if(names.isEmpty()){var encrypted=children(parent,A,"EncryptedID");require(encrypted.size()==1);names.add(new com.samlscope.saml.crypto.SamlXmlDecrypter().decrypt(encrypted.getFirst(),keys.keyFor(run).orElseThrow()));}require(names.size()==1);return names.getFirst();}
    private static boolean targetIssuer(Element assertion,String expected){return expected.equals(issuer(assertion));}
    private byte[] decoded(TranscriptEntry e,String run){require(run.equals(e.runId())&&("transcripts/"+run+"/"+e.id()+".saml.xml").equals(e.decodedSamlRef()));byte[] b=content.readDecodedSaml(e);require(b!=null&&b.length==e.decodedSamlBytes()&&b.length>0);return b;}
    private static List<X509Certificate> spKeys(Element entity){var roles=children(entity,MD,"SPSSODescriptor");require(roles.size()==1);var result=new ArrayList<X509Certificate>();for(var key:children(roles.getFirst(),MD,"KeyDescriptor"))if(!"encryption".equals(key.getAttribute("use")))for(var info:children(key,DS,"KeyInfo"))for(var data:children(info,DS,"X509Data"))for(var cert:children(data,DS,"X509Certificate"))try{result.add((X509Certificate)java.security.cert.CertificateFactory.getInstance("X.509").generateCertificate(new java.io.ByteArrayInputStream(Base64.getMimeDecoder().decode(cert.getTextContent()))));}catch(Exception invalid){throw new IllegalArgumentException(invalid);}return result;}
    private static String soapEndpoint(Element entity){var role=children(entity,MD,"SPSSODescriptor");require(role.size()==1);var s=children(role.getFirst(),MD,"SingleLogoutService").stream().filter(e->BINDING.equals(e.getAttribute("Binding"))).toList();require(s.size()==1);return s.getFirst().getAttribute("Location");}
    private static void removeSignatures(Element root){var n=root.getElementsByTagNameNS(DS,"Signature");for(int i=n.getLength()-1;i>=0;i--){var el=n.item(i);el.getParentNode().removeChild(el);}}
    private static String query(java.net.URI uri,String name){String found=null;for(String field:uri.getRawQuery().split("&")){var p=field.split("=",2);if(name.equals(p[0])){require(found==null&&p.length==2);found=java.net.URLDecoder.decode(p[1],StandardCharsets.UTF_8);}}require(found!=null);return found;}
    static String view(Element e){var b=new StringBuilder("{").append(e.getNamespaceURI()).append('}').append(e.getLocalName());var a=new TreeMap<String,String>();for(int i=0;i<e.getAttributes().getLength();i++){var n=e.getAttributes().item(i);if(!"http://www.w3.org/2000/xmlns/".equals(n.getNamespaceURI()))a.put("{"+n.getNamespaceURI()+"}"+n.getLocalName(),n.getNodeValue());}b.append(a);for(var n=e.getFirstChild();n!=null;n=n.getNextSibling())if(n instanceof Element el)b.append('[').append(view(el)).append(']');else if(n.getNodeType()==org.w3c.dom.Node.TEXT_NODE)b.append(n.getNodeValue());return b.toString();}
    /** Only the native metadata marshaller's typed projection; SOAP and NameID keep view(). */
    static String metadataView(Element e){
        var b=new StringBuilder("{").append(e.getNamespaceURI()).append('}').append(e.getLocalName());
        var attributes=new TreeMap<String,String>();
        for(int i=0;i<e.getAttributes().getLength();i++){
            var n=e.getAttributes().item(i);if("http://www.w3.org/2000/xmlns/".equals(n.getNamespaceURI()))continue;
            String local=n.getLocalName()==null?n.getNodeName():n.getLocalName(),value=n.getNodeValue();
            if(MD.equals(e.getNamespaceURI())&&Set.of("EntityDescriptor","EntitiesDescriptor").contains(e.getLocalName())
                    &&n.getNamespaceURI()==null&&"validUntil".equals(local))value=Long.toString(Instant.parse(value).toEpochMilli());
            attributes.put("{"+n.getNamespaceURI()+"}"+local,value);
        }
        b.append(attributes);
        if(DS.equals(e.getNamespaceURI())&&"X509Certificate".equals(e.getLocalName())){
            require(elements(e).isEmpty());String text=e.getTextContent().replaceAll("[\\t\\r\\n ]","");
            b.append(HexFormat.of().formatHex(Base64.getDecoder().decode(text)));return b.toString();
        }
        boolean interElement=!elements(e).isEmpty();
        for(var n=e.getFirstChild();n!=null;n=n.getNextSibling()){
            if(n instanceof Element child)b.append('[').append(metadataView(child)).append(']');
            else if(n.getNodeType()==org.w3c.dom.Node.TEXT_NODE&&!(interElement&&n.getNodeValue().matches("[\\t\\r\\n ]*")))b.append(n.getNodeValue());
        }
        return b.toString();
    }
    private static String issuer(Element e){var v=children(e,A,"Issuer");require(v.size()==1&&!v.getFirst().getTextContent().isBlank());return v.getFirst().getTextContent();}
    private static String status(Element e){var v=children(e,P,"Status");require(v.size()==1);var codes=children(v.getFirst(),P,"StatusCode");require(codes.size()==1);return codes.getFirst().getAttribute("Value");}
    private static boolean valid(Element e,List<X509Certificate> certs){return certs.stream().anyMatch(c->new XmlSignatureVerifier().hasValidEnvelopedSignature(e,c));}
    private static List<Element> elements(Element e){var r=new ArrayList<Element>();for(var n=e.getFirstChild();n!=null;n=n.getNextSibling())if(n instanceof Element el)r.add(el);return r;}
    private static List<Element> children(Element e,String ns,String name){return elements(e).stream().filter(n->ns.equals(n.getNamespaceURI())&&name.equals(n.getLocalName())).collect(java.util.stream.Collectors.toCollection(ArrayList::new));}
    private static boolean is(Element e,String name){return P.equals(e.getNamespaceURI())&&name.equals(e.getLocalName());}
    private static TranscriptEntry entry(Map<String,TranscriptEntry> entries,String id){require(id.matches(TX)&&entries.containsKey(id));return entries.get(id);}
    private static EvidenceRef ref(TranscriptEntry e){return new EvidenceRef("transcript",e.id());}
    private static String text(JsonNode n,String field){require(n.path(field).isTextual()&&!n.path(field).asText().isBlank());return n.path(field).asText();}
    private static Instant time(JsonNode n,String field){return Instant.parse(text(n,field));}
    private static boolean bool(JsonNode n,String field){require(n.path(field).isBoolean());return n.path(field).asBoolean();}
    private static JsonNode json(byte[] bytes)throws Exception{return JSON.mapper().readTree(bytes);}
    private static byte[] checked(Path folder,JsonNode files,String name)throws Exception{require(files.has(name));byte[] bytes=raw(folder,name);require(hash(bytes).equals(text(files,name)));return bytes;}
    private static byte[] raw(Path folder,String name)throws Exception{var p=folder.resolve(name).normalize();require(!Path.of(name).isAbsolute()&&p.startsWith(folder)&&!p.equals(folder));for(Path a=p;a!=null;a=a.getParent())require(!Files.isSymbolicLink(a));require(Files.isRegularFile(p,LinkOption.NOFOLLOW_LINKS)&&Files.size(p)<=32*1024*1024);return Files.readAllBytes(p);}
    private static byte[] zip(byte[] jar,String name)throws Exception{try(var z=new ZipInputStream(new java.io.ByteArrayInputStream(jar))){for(var e=z.getNextEntry();e!=null;e=z.getNextEntry())if(name.equals(e.getName()))return z.readAllBytes();}throw new IllegalArgumentException("Missing pinned resource");}
    private static String hash(byte[] raw){try{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(raw));}catch(Exception e){throw new IllegalArgumentException(e);}}
    private static void require(boolean condition){if(!condition)throw new IllegalArgumentException("Unproven native SOAP continuation");}
    record SoapMessage(TranscriptEntry entry,Element xml){}
    record Participant(String label,SoapMessage request,SoapMessage response){}
    record Window(String requestId,Instant begin,Instant end){boolean overlaps(Window other){return begin.isBefore(other.end)&&other.begin.isBefore(end);}}
}
