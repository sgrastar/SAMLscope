package com.samlscope.runner.cases;

import static org.junit.jupiter.api.Assertions.*;

import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.plan.*;
import com.samlscope.core.profile.FunctionalProfile;
import com.samlscope.core.run.Reachability;
import com.samlscope.core.transcript.*;
import com.samlscope.runner.DefaultCaseContext;
import com.samlscope.saml.crypto.*;
import com.samlscope.saml.metadata.MetadataService;
import com.samlscope.saml.normal.SecureXml;
import com.samlscope.store.JsonCodec;
import java.net.URI;
import java.nio.file.*;
import java.time.*;
import java.util.*;
import com.fasterxml.jackson.databind.JsonNode;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class DefaultAlgorithmBoundPreparationTest {
    private static final String RUN="run_0123456789ABCDEFGHJKMNPQRS",PLAN="plan_0123456789ABCDEFGHJKMNPQRS";
    private static final String SSP="simplesamlphp-native-default-algorithm-post-consumer-v1";
    private static final Instant NOW=Instant.parse("2026-10-04T10:00:00Z");
    private static final String FACTORY="tx_factory",ORDINARY="tx_ordinary",NATIVE="tx_native";
    @TempDir Path directory;

    @Test void exactFactoryOriginalCoexistsWithOrdinaryControlAndItsBytesAreDefensivelyCopied()throws Exception {
        var h=new Harness();h.bind(FACTORY,SSP);
        var bound=h.reader.boundPreparation(h.context()).orElseThrow();
        assertEquals(FACTORY,bound.metadataEntry().id());assertArrayEquals(h.factory,bound.metadataBytes());
        assertEquals(bound.nativePreparation(),h.reader.preparation(h.context()).orElseThrow());
        byte[] original=h.factory.clone();
        var copied=new DefaultAlgorithmPreventionEvidence.BoundPreparation(bound.nativePreparation(),bound.metadataEntry(),original);
        original[0]^=1;byte[] exposed=copied.metadataBytes();exposed[0]^=1;
        assertArrayEquals(h.factory,copied.metadataBytes());
        var ready=assertInstanceOf(CaseStep.AwaitConfig.class,h.probe.start(h.context()));assertTrue(ready.actions().isEmpty());
        var waiting=assertInstanceOf(CaseStep.AwaitInbound.class,h.probe.resume(h.context(),ready.next(),new CaseEvent.ConfigConfirmed()));
        assertEquals(1,waiting.actions().size());
        var request=SecureXml.parse(waiting.actions().getFirst().payload()).getDocumentElement();
        var metadata=SecureXml.parse(h.factory).getDocumentElement();
        assertEquals(metadata.getAttribute("entityID"),DefaultAlgorithmPreventionEvidence.single(request,
                DefaultAlgorithmPreventionEvidence.A,"Issuer").getTextContent());
        assertEquals(DefaultAlgorithmPreventionEvidence.endpoint(metadata,"AssertionConsumerService").toString(),
                request.getAttribute("AssertionConsumerServiceURL"));
        assertEquals("sha256-control",waiting.next().data().get("fixture_id"));
    }

    @Test void changedOriginalAfterConfirmationCannotEmitTheNextOutbox()throws Exception {
        var h=new Harness();h.bind(FACTORY,SSP);
        var ready=assertInstanceOf(CaseStep.AwaitConfig.class,h.probe.start(h.context()));
        h.decoded.put(FACTORY,"changed original".getBytes(java.nio.charset.StandardCharsets.UTF_8));
        int calls=h.nativeCalls;
        var stopped=assertInstanceOf(CaseStep.Finish.class,h.probe.resume(h.context(),ready.next(),new CaseEvent.ConfigConfirmed()));
        assertEquals(Outcome.NOT_VERIFIED,stopped.outcome().outcome());assertEquals(calls,h.nativeCalls);
    }

    @Test void factoryBoundaryRejectsForeignRunWrongPurposeFakeFetchAndMalformedProvenanceBeforeNativeQualification()throws Exception {
        var h=new Harness();h.bind(FACTORY,SSP);var baseline=List.copyOf(h.entries);var factory=h.find(FACTORY);
        for(String defect:List.of("foreign-run","foreign-path","duplicate","missing","wrong-direction","wrong-method",
                "http-status","wrong-type","wrong-variant","wrong-feed","wrong-factory","missing-source","bad-source",
                "bad-class","bad-jar","missing-time","noncanonical-time","wrong-time","fake-fetch","fake-delivery","fake-correlation")) {
            h.entries.clear();h.entries.addAll(baseline);var summary=new HashMap<String,Object>(factory.samlSummary());
            String run=RUN,path=factory.decodedSamlRef(),method="FACTORY",correlation=null;Integer status=null;
            Direction direction=Direction.OUTBOUND;
            switch(defect) {
                case "foreign-run"->run="run_11111111111111111111111111";
                case "foreign-path"->path="transcripts/run_11111111111111111111111111/"+FACTORY+".saml.xml";
                case "duplicate"->h.entries.add(factory);
                case "missing"->h.entries.remove(factory);
                case "wrong-direction"->direction=Direction.INBOUND;
                case "wrong-method"->method="GET";
                case "http-status"->status=200;
                case "wrong-type"->summary.put("type","MetadataFetch");
                case "wrong-variant"->summary.put("variant","baseline");
                case "wrong-feed"->summary.put("feed","live");
                case "wrong-factory"->summary.put("factoryMethod","MetadataService.generatePolling");
                case "missing-source"->summary.remove("factorySourceSha256");
                case "bad-source"->summary.put("factorySourceSha256","f".repeat(63));
                case "bad-class"->summary.put("factoryClassSha256","A".repeat(64));
                case "bad-jar"->summary.put("factoryJarSha256",true);
                case "missing-time"->summary.remove("factoryPreparedAt");
                case "noncanonical-time"->summary.put("factoryPreparedAt","2026-10-04T10:00:00+00:00");
                case "wrong-time"->summary.put("factoryPreparedAt",NOW.plusSeconds(1).toString());
                case "fake-fetch"->summary.put("fetchTranscriptId","tx_fetch");
                case "fake-delivery"->summary.put("delivery","PREPARED");
                case "fake-correlation"->correlation="tx_fetch";
                default->throw new AssertionError(defect);
            }
            if(!Set.of("missing","duplicate").contains(defect)) {
                h.entries.set(h.entries.indexOf(factory),new TranscriptEntry(FACTORY,run,direction,NOW,correlation,method,
                        factory.url(),status,Map.of(),null,0,path,h.factory.length,"application/samlmetadata+xml",null,summary));
            }
            int calls=h.nativeCalls;
            assertTrue(h.reader.boundPreparation(h.context()).isEmpty(),defect);
            assertEquals(Outcome.NOT_VERIFIED,assertInstanceOf(CaseStep.Finish.class,h.probe.start(h.context())).outcome().outcome(),defect);
            assertEquals(calls,h.nativeCalls,defect);
        }
        h.entries.clear();h.entries.addAll(baseline);
        h.bind(FACTORY,"shibboleth-native-default-algorithm-consumers-v1");
        assertTrue(h.reader.boundPreparation(h.context()).isEmpty(),"Factory originals are available only to the SSP adapter");
    }

    @Test void ordinaryControlFetchStillQualifiesAndSelectionUsesItsExactManifestReference()throws Exception {
        var h=new Harness();h.bind(ORDINARY,"shibboleth-native-default-algorithm-consumers-v1");
        // A second authentic ordinary CONTROL document must not make the selected original ambiguous.
        var duplicateSummary=new HashMap<String,Object>(h.find(ORDINARY).samlSummary());
        h.put("tx_ordinary_second",h.ordinary,Direction.OUTBOUND,NOW,"GET",200,"tx_fetch",duplicateSummary);
        var bound=h.reader.boundPreparation(h.context()).orElseThrow();assertEquals(ORDINARY,bound.metadataEntry().id());
        assertArrayEquals(h.ordinary,bound.metadataBytes());
        assertInstanceOf(CaseStep.AwaitConfig.class,h.probe.start(h.context()));
        var manifest=h.manifest.deepCopy();manifest.put("suiteMetadataReference",FACTORY);h.save(manifest);
        assertTrue(h.reader.boundPreparation(h.context()).isEmpty(),"A foreign purpose is not a replacement for the bound ordinary original");
    }

    @Test void correctlyRehashedWrongKeyAndWrongFactoryValidityCannotQualify()throws Exception {
        var h=new Harness();
        for(String defect:List.of("wrong-envelope-key","wrong-advertised-key","wrong-validity")) {
            var xml=SecureXml.parse(h.factory);var root=xml.getDocumentElement();
            root.removeChild(DefaultAlgorithmPreventionEvidence.single(root,DefaultAlgorithmPreventionEvidence.DS,"Signature"));
            if(defect.equals("wrong-advertised-key")) {
                var role=DefaultAlgorithmPreventionEvidence.single(root,DefaultAlgorithmPreventionEvidence.MD,"SPSSODescriptor");
                for(var key:DefaultAlgorithmPreventionEvidence.children(role,DefaultAlgorithmPreventionEvidence.MD,"KeyDescriptor")) {
                    if(!"signing".equals(key.getAttribute("use")))continue;
                    key.getElementsByTagNameNS(DefaultAlgorithmPreventionEvidence.DS,"X509Certificate").item(0)
                            .setTextContent(Base64.getEncoder().encodeToString(h.primary.certificate().getEncoded()));
                }
            }
            if(defect.equals("wrong-validity"))root.setAttribute("validUntil",NOW.plus(Duration.ofDays(13)).toString());
            new XmlSigner().sign(root,defect.equals("wrong-envelope-key")?h.primary:h.control,
                    DefaultAlgorithmPreventionEvidence.single(root,DefaultAlgorithmPreventionEvidence.MD,"SPSSODescriptor"));
            byte[] changed=SecureXml.serialize(xml);h.entries.removeIf(e->e.id().equals(FACTORY));
            h.put(FACTORY,changed,Direction.OUTBOUND,NOW,"FACTORY",null,null,h.factorySummary(changed));
            h.bind(FACTORY,SSP);int calls=h.nativeCalls;
            assertTrue(h.reader.boundPreparation(h.context()).isEmpty(),defect);assertEquals(calls,h.nativeCalls,defect);
        }
    }

    private final class Harness {
        final List<TranscriptEntry> entries=new ArrayList<>();final Map<String,byte[]> decoded=new HashMap<>();
        final Path proof;final PlanCredentials control,primary;final byte[] factory,ordinary,target;
        final DefaultAlgorithmPreventionEvidence reader;final DefaultAlgorithmPreventionProbeTestCase probe;
        com.fasterxml.jackson.databind.node.ObjectNode manifest;int nativeCalls;
        Harness()throws Exception {
            var root=directory.toRealPath();proof=root.resolve("proof");Files.createDirectories(proof.resolve(RUN+".preparation"));
            var clock=Clock.fixed(NOW,ZoneOffset.UTC);var keys=new FilePlanKeyStore(root.resolve("keys"),clock);
            var plan=new TestPlan(PLAN,"default consumer",FunctionalProfile.BROWSER_SSO_IDP,
                    new TestPlan.Target(TargetKind.IDP,"https://target.example/idp",new TestPlan.MetadataSource(MetadataSourceKind.URL,"https://target.example/metadata")),
                    MetadataDeliveryKind.HTTP_URL,Map.of(),TestPlan.Parameters.defaults(),TestPlan.Interaction.defaults(),NOW,NOW);
            var metadata=new MetadataService(URI.create("https://peer.example"),keys,new XmlSigner(),clock);
            control=metadata.credentialsForPollingVariant(plan,MetadataService.Variant.CONTROL);
            primary=metadata.credentialsForVariant(plan,MetadataService.Variant.CONTROL);
            factory=metadata.generateDefaultAlgorithmConsumerMetadata(plan,RUN);ordinary=metadata.generatePolling(plan,MetadataService.Variant.CONTROL,RUN);
            var targetKey=keys.getOrCreate(PLAN,"target");String certificate=Base64.getEncoder().encodeToString(targetKey.certificate().getEncoded());
            target=("<md:EntityDescriptor xmlns:md='"+MetadataService.MD+"' xmlns:ds='"+MetadataService.DS+"' entityID='https://target.example/idp'><md:IDPSSODescriptor protocolSupportEnumeration='"+DefaultAlgorithmPreventionEvidence.P+"'><md:KeyDescriptor use='signing'><ds:KeyInfo><ds:X509Data><ds:X509Certificate>"+certificate+"</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:SingleSignOnService Binding='"+MetadataService.POST+"' Location='https://target.example/sso'/></md:IDPSSODescriptor></md:EntityDescriptor>").getBytes(java.nio.charset.StandardCharsets.UTF_8);
            put("tx_fetch",new byte[]{1},Direction.INBOUND,NOW.minusSeconds(1),"GET",200,null,Map.of("type","MetadataFetch"));
            put(ORDINARY,ordinary,Direction.OUTBOUND,NOW,"GET",200,"tx_fetch",Map.of("type","MetadataPrepared","variant","control","feed","live",
                    "metadataSha256",DefaultAlgorithmPreventionEvidence.hash(ordinary),"fetchTranscriptId","tx_fetch","delivery","PREPARED"));
            put(FACTORY,factory,Direction.OUTBOUND,NOW,"FACTORY",null,null,factorySummary(factory));
            var adapter=new DefaultAlgorithmNativeAdapter() {
                public String adapter(){return SSP;}
                public Optional<Preparation> prepare(CaseContext context,Path folder,JsonNode m,byte[] targetBytes,byte[] suiteBytes)throws Exception {
                    nativeCalls++;var original=new JsonCodec().mapper().readTree(decoded.get(NATIVE));
                    if(!RUN.equals(original.path("runId").asText())||!DefaultAlgorithmPreventionEvidence.hash(suiteBytes).equals(original.path("suiteHash").asText())
                            ||!DefaultAlgorithmPreventionEvidence.hash(targetBytes).equals(original.path("targetHash").asText()))return Optional.empty();
                    return Optional.of(new Preparation("native-default-policy",false,List.of(new EvidenceRef("transcript",NATIVE))));
                }
                public Session open(CaseContext c,Path f,JsonNode m,byte[] t,byte[] s){throw new AssertionError("Preparation cannot determine a product outcome");}
            };
            var ordinaryAdapter=new DefaultAlgorithmNativeAdapter() {
                public String adapter(){return "shibboleth-native-default-algorithm-consumers-v1";}
                public Optional<Preparation> prepare(CaseContext c,Path f,JsonNode m,byte[] t,byte[] s)throws Exception{return adapter.prepare(c,f,m,t,s);}
                public Session open(CaseContext c,Path f,JsonNode m,byte[] t,byte[] s){return adapter.open(c,f,m,t,s);}
            };
            reader=new DefaultAlgorithmPreventionEvidence(proof,e->decoded.get(e.id()),r->target,r->Optional.of(control),r->"browser_sso_idp",adapter,ordinaryAdapter);
            probe=new DefaultAlgorithmPreventionProbeTestCase(new Fallback(),e->decoded.get(e.id()),r->target,r->Optional.of(control),r->"browser_sso_idp",reader);
        }
        Map<String,Object> factorySummary(byte[] bytes)throws Exception {
            return Map.of("type","MetadataPrepared","variant","control","feed","native-default-consumer","metadataSha256",DefaultAlgorithmPreventionEvidence.hash(bytes),
                    "factoryMethod","MetadataService.generateDefaultAlgorithmConsumerMetadata","factoryPreparedAt",NOW.toString(),
                    "factorySourceSha256","1".repeat(64),"factoryClassSha256","2".repeat(64),"factoryJarSha256","3".repeat(64));
        }
        void bind(String selected,String adapter)throws Exception {
            byte[] bytes=decoded.get(selected);var codec=new JsonCodec().mapper();
            byte[] raw=codec.writeValueAsBytes(Map.of("runId",RUN,"suiteHash",DefaultAlgorithmPreventionEvidence.hash(bytes),"targetHash",DefaultAlgorithmPreventionEvidence.hash(target)));
            entries.removeIf(e->e.id().equals(NATIVE));put(NATIVE,raw,Direction.INBOUND,NOW,"NATIVE",null,null,Map.of("type","NativePreparation"));
            Files.write(proof.resolve(RUN+".preparation").resolve("native.json"),raw);
            manifest=codec.createObjectNode();manifest.put("schema",DefaultAlgorithmPreventionEvidence.SCHEMA+"-preparation");
            manifest.put("runId",RUN);manifest.put("caseId",DefaultAlgorithmPreventionEvidence.CASE);manifest.put("campaignId",DefaultAlgorithmPreventionEvidence.CAMPAIGN);
            manifest.put("profile","browser_sso_idp");manifest.put("counterfactualCalibrationOnly",false);manifest.put("adapter",adapter);
            manifest.put("targetMetadataSha256",DefaultAlgorithmPreventionEvidence.hash(target));manifest.put("targetEntityId","https://target.example/idp");
            manifest.put("suiteMetadataReference",selected);manifest.put("suiteMetadataSha256",DefaultAlgorithmPreventionEvidence.hash(bytes));
            manifest.set("files",codec.valueToTree(Map.of("native.json",DefaultAlgorithmPreventionEvidence.hash(raw))));
            manifest.set("nativeOriginals",codec.valueToTree(List.of(Map.of("reference",NATIVE,"sha256",DefaultAlgorithmPreventionEvidence.hash(raw)))));save(manifest);
        }
        void save(JsonNode m)throws Exception {Files.write(proof.resolve(RUN+".preparation.json"),new JsonCodec().mapper().writeValueAsBytes(m));}
        TranscriptEntry find(String id){return entries.stream().filter(e->e.id().equals(id)).findFirst().orElseThrow();}
        void put(String id,byte[] bytes,Direction direction,Instant at,String method,Integer status,String correlation,Map<String,Object> summary) {
            decoded.put(id,bytes);entries.add(new TranscriptEntry(id,RUN,direction,at,correlation,method,"https://peer.example/metadata",status,Map.of(),null,0,
                    "transcripts/"+RUN+"/"+id+".saml.xml",bytes.length,"application/samlmetadata+xml",null,summary));
        }
        CaseContext context(){return new DefaultCaseContext(RUN,TargetRole.IDP,Clock.fixed(NOW,ZoneOffset.UTC),TestPlan.Parameters.defaults(),TestPlan.Interaction.defaults(),
                Reachability.CONFIRMED,new TranscriptRecorder(){public List<TranscriptEntry> list(String run){return RUN.equals(run)?entries:List.of();}
                    public TranscriptEntry record(TranscriptInput input){throw new AssertionError("Preparation must not write");}
                    public TranscriptEntry updateSamlAnalysis(String id,String correlation,Map<String,Object> summary){throw new AssertionError("Preparation must not change originals");}},true);}
    }
    private static final class Fallback implements TestCase,AttestationPrompt {
        public String id(){return DefaultAlgorithmPreventionEvidence.CASE;}public TargetRole role(){return TargetRole.IDP;}
        public String promptEn(){return "Approved ALG08.c";}public List<AttestationOption> options(){return List.of();}
        public CaseStep start(CaseContext c){throw new AssertionError("Preparation cannot use declarations");}
        public CaseStep resume(CaseContext c,CaseState s,CaseEvent e){throw new AssertionError("Preparation cannot use declarations");}
    }
}
