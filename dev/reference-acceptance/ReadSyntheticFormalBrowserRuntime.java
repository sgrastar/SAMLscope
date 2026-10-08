package com.samlscope.api;

import static com.samlscope.api.ReadSyntheticArtifactRuntime.*;
import com.samlscope.core.casedef.*;
import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.plan.*;
import com.samlscope.core.profile.FunctionalProfile;
import com.samlscope.core.run.*;
import com.samlscope.core.transcript.*;
import com.samlscope.runner.PinnedFunctionalCaseDefinitionResolver;
import com.samlscope.saml.binding.RedirectSignatureVerifier;
import com.samlscope.saml.crypto.XmlSignatureVerifier;
import com.samlscope.saml.metadata.TargetMetadataParser;
import com.samlscope.saml.normal.SecureXml;
import com.samlscope.store.JsonCodec;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.sql.*;
import java.time.Instant;
import java.util.*;
import org.w3c.dom.Element;

/** Read-only exact selected formal case + M0 originals; never exports another queued case's payload. */
public final class ReadSyntheticFormalBrowserRuntime {
    static final String SELECTED="IIP-IDP12-a-idp-01", DIGEST="sha256:748673ea5bb9515a0e5fed25087bfd4033dd9299fb9ceacb6dac86a74ca5dc80";
    static final Set<String> VARIANTS=Set.of("IIP-IDP12.a#v-36498b67e0","IIP-IDP12.a#v-85d98fa8a5","IIP-IDP12.a#v-d051803f2c");
    static final List<String> FIXTURES=List.of("default-control","non-default-index");
    public static void main(String[] args)throws Exception {
        require(args.length==4&&args[1].matches("run_[0-9A-HJKMNP-TV-Z]{26}")&&Set.of("scope","runtime").contains(args[2]),"Bound owned Run, scope and public Suite metadata required");
        Path data=Path.of(args[0]).toAbsolutePath();require(data.equals(data.normalize()),"Noncanonical data root");rejectSymlinkAncestors(data);
        var codec=new JsonCodec();var result=new LinkedHashMap<String,Object>();
        try(var db=readOnlyDatabase(data.resolve("samlscope.db"))) {
            var run=codec.read(single(db,"SELECT document_json FROM runs WHERE id=?",args[1]),TestRun.class);
            var plan=codec.read(single(db,"SELECT document_json FROM plans WHERE id=?",run.planId()),TestPlan.class);
            require(run.id().equals(args[1])&&run.planId().equals(plan.id())&&plan.profile()==FunctionalProfile.BROWSER_SSO_IDP&&plan.target().kind()==TargetKind.IDP&&plan.definitionIdentity()!=null,"Foreign Run/Plan/profile");
            String entity=plan.target().entityId();require(Set.of("http://host.docker.internal:18946/entity/honor","http://host.docker.internal:18946/entity/ignore").contains(entity),"Foreign owned target");
            String mode=entity.substring(entity.lastIndexOf('/')+1);require(plan.name().equals("Synthetic formal browser runtime "+mode+"; no adoption"),"Foreign Plan name");
            var docs=CatalogDocuments.load();var bundle=FunctionalProfileDocuments.load();
            var cases=CaseDefinitionCatalogMapper.fromDocument(docs.parsed("tests/cases.yaml"));var coverage=CoverageCatalogMapper.fromDocument(docs.parsed("tests/coverage.yaml"));
            var resolver=new PinnedFunctionalCaseDefinitionResolver(bundle.artifacts(),bundle.digests(),Map.of("tests/coverage.yaml",docs.bytes("tests/coverage.yaml"),"tests/cases.yaml",docs.bytes("tests/cases.yaml"),"tests/predicates.yaml",docs.bytes("tests/predicates.yaml")),cases,coverage);
            var slot=only(resolver.resolve(plan.definitionIdentity()).cases().stream().filter(c->SELECTED.equals(c.id())).toList(),"Actual selected membership");
            require(DIGEST.equals(slot.caseDigest())&&Set.copyOf(slot.coversVariants()).equals(VARIANTS)&&slot.role()==TargetRole.IDP&&slot.mode()==CaseDefinitionCatalog.ExecutionMode.BROWSER&&slot.milestone()==CaseDefinitionCatalog.Milestone.M1&&slot.controls().size()==2,"Approved case differs");
            require(slot.controls().stream().anyMatch(c->c.fixture().equals("idp-core-no-ecp"))&&slot.controls().stream().anyMatch(c->c.fixture().equals("mut-iip-idp12-a-idp")),"Approved control boundary differs");
            int executions=ReadSyntheticNormalBrowserScope.count(db,"case_executions",run.id()), allActions=ReadSyntheticNormalBrowserScope.count(db,"outbox_actions",run.id());
            result.put("schema","owned-synthetic-formal-browser-native-v1");result.put("runId",run.id());result.put("planId",plan.id());result.put("fixtureMode",mode);result.put("definitionIdentity",plan.definitionIdentity());result.put("approvedSelectedCase",slot);
            result.put("actualCaseExecutions",executions);result.put("actualOutboxActions",allActions);result.put("databaseAccess","URI-escaped-mode-ro-query-only");result.put("canonicalAdoption",false);result.put("realUserAuthenticationQualified",false);result.put("privateKeyReads",0);
            if(args[2].equals("scope")) {
                require(Set.of(RunStatus.CREATED,RunStatus.RUNNING).contains(run.status())&&!run.context().containsKey("authnRequestId")&&executions==0&&allActions==0&&ReadSyntheticNormalBrowserScope.count(db,"transcript_entries",run.id())==0,"Cold scope is not empty");
                result.put("qualificationOutcome","SCOPE_VERIFIED");result.put("selectedCaseOutcome","NOT_STARTED");result.put("transcriptOriginals",List.of());
            }else {
                var stored=codec.read(single(db,"SELECT document_json FROM case_executions WHERE run_id=? AND case_id=?",run.id(),SELECTED),CaseExecution.class);
                require(stored.runId().equals(run.id())&&stored.caseId().equals(SELECTED)&&stored.status()==CaseExecutionStatus.FINISHED&&stored.outcome()!=null,"Actual selected case not finished");
                Outcome expected=mode.equals("honor")?Outcome.SATISFIED:Outcome.VIOLATED;require(stored.outcome().outcome()==expected,"Stored selected outcome differs from owned control mode");
                var entries=formalEntries(db,codec,run.id());var actions=selectedOutbox(db,codec,run.id());require(actions.size()==2,"Selected outbox requires both fixtures");
                var normalRequest=only(entries.stream().filter(e->e.direction()==Direction.OUTBOUND&&"AuthnRequest".equals(e.samlSummary().get("type"))&&Objects.equals(e.correlationId(),run.context().get("authnRequestId"))).toList(),"Normal request");
                var normalResponse=only(entries.stream().filter(e->e.direction()==Direction.INBOUND&&Boolean.TRUE.equals(e.samlSummary().get("normalFlowAccepted"))).toList(),"Normal accepted response");
                var scoped=new ArrayList<TranscriptEntry>();scoped.add(normalRequest);scoped.add(normalResponse);
                var pairs=new ArrayList<Map<String,Object>>();
                for(String fixture:FIXTURES) {
                    var request=only(entries.stream().filter(e->e.direction()==Direction.OUTBOUND&&SELECTED.equals(e.samlSummary().get("scenario_case_id"))&&fixture.equals(e.samlSummary().get("fixture_id"))).toList(),"Selected fixture request");
                    String action=String.valueOf(request.samlSummary().get("action_id"));var outbox=only(actions.stream().filter(a->a.action().actionId().equals(action)).toList(),"Selected exact outbox action");
                    var response=only(entries.stream().filter(e->e.direction()==Direction.INBOUND&&("_"+action).equals(e.correlationId())&&Boolean.TRUE.equals(e.samlSummary().get("activeProbeAccepted"))).toList(),"Selected correlated response");
                    require(outbox.status()==OutboxStatus.SENT&&outbox.action().kind()==OutboundKind.AUTHN_REQUEST&&!outbox.action().requiresEphemeralCredential()&&action.equals(request.correlationId())&&!response.timestamp().isBefore(request.timestamp()),"Selected action/arrival unbound");
                    scoped.add(request);scoped.add(response);pairs.add(Map.of("fixture",fixture,"actionId",action,"requestReference",request.id(),"responseReference",response.id()));
                }
                require(scoped.stream().map(TranscriptEntry::id).distinct().count()==6,"Exact six selected originals required");
                var requiredResponses=pairs.stream().map(p->String.valueOf(p.get("responseReference"))).collect(java.util.stream.Collectors.toSet());
                var storedResponses=stored.outcome().evidence().stream().map(EvidenceRef::reference).collect(java.util.stream.Collectors.toSet());
                require(stored.outcome().evidence().size()==2&&storedResponses.size()==2&&storedResponses.equals(requiredResponses)
                    && stored.outcome().evidence().stream().allMatch(e->e.kind().equals("transcript")),"Stored outcome refs differ from both fixture responses");
                var originals=new LinkedHashMap<String,Original>();for(var e:scoped)originals.put(e.id(),readOriginal(data,e));
                byte[] suiteMetadata=publicFile(Path.of(args[3])), targetMetadata=publicFile(data.resolve("target-metadata").resolve(run.id()+".xml"));
                var normalXml=saml(originals,normalRequest);String issuer=single(normalXml,A,"Issuer").getTextContent();var suiteEntity=suiteEntity(suiteMetadata,plan.id(),issuer);
                var suiteCerts=certificates(suiteEntity);var target=new TargetMetadataParser().parse(targetMetadata,entity);var targetCerts=target.signingCertificates();require(!targetCerts.isEmpty(),"Target certificate unavailable");
                require(plan.parameters().requestSigningMode()==TestPlan.RequestSigningMode.REQUIRED&&normalXml.getAttribute("ID").equals(run.context().get("authnRequestId")),"Normal request scope differs");
                verifyRequest(originals,normalRequest,suiteCerts);verifyResponse(originals,normalResponse,normalXml,entity,targetCerts,issuer+"/sp/acs/0");
                String session=session(saml(originals,normalResponse));require(!session.isBlank(),"Normal protocol session unavailable");
                for(var pair:pairs) {
                    var request=scoped.stream().filter(e->e.id().equals(pair.get("requestReference"))).findFirst().orElseThrow();var response=scoped.stream().filter(e->e.id().equals(pair.get("responseReference"))).findFirst().orElseThrow();
                    var authn=saml(originals,request);String fixture=String.valueOf(pair.get("fixture"));require(authn.getAttribute("ID").equals("_"+pair.get("actionId"))&&issuer.equals(single(authn,A,"Issuer").getTextContent()),"Selected AuthnRequest scope differs");
                    require(fixture.equals("default-control")?!authn.hasAttribute("AssertionConsumerServiceIndex")&&!authn.hasAttribute("AssertionConsumerServiceURL"):authn.getAttribute("AssertionConsumerServiceIndex").equals("1")&&!authn.hasAttribute("AssertionConsumerServiceURL"),"Actual fixture attributes differ");
                    require(target.singleSignOnServices().stream().anyMatch(e->e.location().toString().equals(URI.create(request.url()).getScheme()+"://"+URI.create(request.url()).getAuthority()+URI.create(request.url()).getPath())),"Request outside actual target snapshot endpoint");
                    String acs=issuer+"/sp/acs/"+(fixture.equals("non-default-index")&&mode.equals("honor")?"1":"0");require(registeredAcs(suiteEntity,acs,POST),"Observed ACS not registered");
                    verifyRequest(originals,request,suiteCerts);verifyResponse(originals,response,authn,entity,targetCerts,acs);require(session.equals(session(saml(originals,response))),"Selected response did not preserve protocol session");
                }
                result.put("qualificationOutcome","VERIFIED");result.put("selectedCaseOutcome",stored.outcome().outcome().name());result.put("selectedCaseReasonCode",stored.outcome().reasonCode());result.put("selectedCaseEvidence",stored.outcome().evidence());result.put("selectedOutboxActions",actions.size());
                result.put("normalRequestReference",normalRequest.id());result.put("normalResponseReference",normalResponse.id());result.put("selectedFixturePairs",pairs);result.put("portableEvidenceReferences",scoped.stream().map(TranscriptEntry::id).toList());result.put("transcriptOriginals",originals.values().stream().map(Original::export).toList());
                result.put("originalExportScope","only-normal-and-selected-case");result.put("globalOriginalExportClaimed",false);result.put("actualCaseAndRequiredControlsProven",true);result.put("actualRequestSignaturesVerified",true);result.put("actualResponseAndAssertionSignaturesVerified",true);result.put("protocolSessionReused",true);result.put("browserCookieReuseRequiresSeparateHostEvidence",true);
                result.put("suitePublicMetadataSha256",hash(suiteMetadata));result.put("runMetadataSnapshotSha256",hash(targetMetadata));result.put("wholeRunConformance","NOT_QUALIFIED");result.put("allOtherCaseOutcomesUnchangedByReader",true);result.put("ownedRedactedCookieMetadataOmitted",true);
            }
        }
        System.out.println(codec.write(result));
    }
    /** Only this fixture's exact already-redacted cookie metadata is omitted in RAM.
     * The stored row and every original byte remain unchanged; raw/foreign credential headers fail closed. */
    static Map<String,List<String>> publicFormalHeaders(Map<String,List<String>> headers) {
        require(headers!=null,"Header boundary unavailable");var clean=new LinkedHashMap<String,List<String>>();int owned=0;
        for(var field:headers.entrySet()){
            if(field.getKey().equalsIgnoreCase("Cookie")){
                require(++owned==1&&field.getValue()!=null&&field.getValue().size()==1
                    &&field.getValue().getFirst().equals(SyntheticFormalBrowserFixture.OWNED_COOKIE+"=<redacted: 32 bytes>"),"Unproven owned redacted cookie metadata");
            }else clean.put(field.getKey(),List.copyOf(field.getValue()));
        }
        require(noCredentials(clean),"Foreign credential header boundary invalid");return Map.copyOf(clean);
    }
    static List<TranscriptEntry> formalEntries(Connection db,JsonCodec codec,String runId)throws Exception {
        var result=new ArrayList<TranscriptEntry>();var ids=new HashSet<String>();
        try(var query=db.prepareStatement("SELECT id,document_json FROM transcript_entries WHERE run_id=? ORDER BY timestamp,id LIMIT ?")){
            query.setString(1,runId);query.setInt(2,MAX_ENTRIES+1);
            try(var rows=query.executeQuery()){while(rows.next()){
                var entry=codec.read(rows.getString(2),TranscriptEntry.class);
                require(rows.getString(1).equals(entry.id())&&runId.equals(entry.runId())&&ids.add(entry.id())&&result.size()<MAX_ENTRIES,"Transcript row/Run identity or size differs");
                var headers=publicFormalHeaders(entry.headers());
                result.add(new TranscriptEntry(entry.id(),entry.runId(),entry.direction(),entry.timestamp(),entry.correlationId(),entry.method(),entry.url(),entry.status(),headers,
                    entry.bodyRef(),entry.bodyBytes(),entry.decodedSamlRef(),entry.decodedSamlBytes(),entry.contentType(),entry.rawQuery(),entry.samlSummary()));
            }}
        }return List.copyOf(result);
    }
    static List<OutboxEntry> selectedOutbox(Connection db,JsonCodec codec,String run)throws Exception {
        var result=new ArrayList<OutboxEntry>();try(var query=db.prepareStatement("SELECT action_json,status,send_result_json,transcript_entry_id,created_at,updated_at FROM outbox_actions WHERE run_id=? AND case_id=? ORDER BY action_id LIMIT 4")){query.setString(1,run);query.setString(2,SELECTED);try(var rows=query.executeQuery()){while(rows.next()){require(result.size()<3,"Selected outbox exceeds scope");var action=codec.read(rows.getString(1),OutboundAction.class);require(action.kind()==OutboundKind.AUTHN_REQUEST&&!action.requiresEphemeralCredential()&&publicXml(action.payload()),"Unowned outbox payload");Map<String,Object> send=rows.getString(3)==null?Map.of():codec.read(rows.getString(3),Map.class);result.add(new OutboxEntry(run,SELECTED,action,OutboxStatus.valueOf(rows.getString(2)),send,rows.getString(4),Instant.parse(rows.getString(5)),Instant.parse(rows.getString(6))));}}}return List.copyOf(result);
    }
    static void verifyRequest(Map<String,Original> originals,TranscriptEntry entry,List<java.security.cert.X509Certificate> certs) {
        var xml=saml(originals,entry);boolean valid;
        if(entry.method().equals("GET"))valid=entry.rawQuery()!=null&&Objects.equals(URI.create(entry.url()).getRawQuery(),entry.rawQuery())&&certs.stream().anyMatch(c->new RedirectSignatureVerifier().isValidForMessage(entry.rawQuery(),c,original(originals,entry).decoded()));
        else valid=entry.method().equals("POST")&&certs.stream().anyMatch(c->new XmlSignatureVerifier().hasValidEnvelopedReferenceDigests(xml)&&new XmlSignatureVerifier().hasValidEnvelopedSignature(xml,c));
        require(valid&&P.equals(xml.getNamespaceURI())&&xml.getLocalName().equals("AuthnRequest")&&xml.getAttribute("Version").equals("2.0"),"Actual signed request unproven");
    }
    static void verifyResponse(Map<String,Original> originals,TranscriptEntry entry,Element request,String entity,List<java.security.cert.X509Certificate> certs,String acs) {
        var root=saml(originals,entry);require(entry.method().equals("POST")&&entry.url().equals(acs)&&root.getAttribute("Destination").equals(acs)&&root.getAttribute("InResponseTo").equals(request.getAttribute("ID"))&&entry.correlationId().equals(request.getAttribute("ID"))&&entity.equals(single(root,A,"Issuer").getTextContent())&&"Response".equals(root.getLocalName())&&P.equals(root.getNamespaceURI())&&root.getAttribute("Version").equals("2.0")&&"urn:oasis:names:tc:SAML:2.0:status:Success".equals(status(root)),"Actual response scope/status differs");
        require(certs.stream().anyMatch(c->new XmlSignatureVerifier().hasValidEnvelopedSignature(root,c)),"Response signature unproven");var assertion=single(root,A,"Assertion");require(certs.stream().anyMatch(c->new XmlSignatureVerifier().hasValidEnvelopedSignature(assertion,c)),"Assertion signature unproven");
        byte[] body=original(originals,entry).body();var fields=SyntheticAdditionalMetadataFixture.fields(new String(body,StandardCharsets.UTF_8));require(Arrays.equals(Base64.getDecoder().decode(fields.get("SAMLResponse")),original(originals,entry).decoded()),"Raw recorded POST form differs from Response original");
    }
    static String session(Element reply){return single(single(reply,A,"Assertion"),A,"AuthnStatement").getAttribute("SessionIndex");}
}
