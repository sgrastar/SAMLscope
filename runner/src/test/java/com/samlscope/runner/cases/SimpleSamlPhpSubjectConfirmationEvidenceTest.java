package com.samlscope.runner.cases;
import static org.junit.jupiter.api.Assertions.*;
import com.samlscope.core.transcript.*;
import com.samlscope.core.plan.*;
import com.samlscope.core.run.Reachability;
import com.samlscope.core.evaluation.Outcome;
import com.samlscope.runner.DefaultCaseContext;
import com.samlscope.saml.normal.SecureXml;
import java.nio.file.*;
import java.time.Clock;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class SimpleSamlPhpSubjectConfirmationEvidenceTest {
    private static final String RUN="run_00000000000000000000000000",S="urn:oasis:names:tc:SAML:2.0:assertion";
    @TempDir Path directory;
    private DefaultCaseContext context(){return new DefaultCaseContext(RUN,TargetRole.IDP,Clock.systemUTC(),TestPlan.Parameters.defaults(),TestPlan.Interaction.defaults(),Reachability.CONFIRMED,
        new TranscriptRecorder(){public List<TranscriptEntry> list(String run){return List.of();}public TranscriptEntry record(TranscriptInput input){throw new AssertionError("Reader cannot execute interactions");}
            public TranscriptEntry updateSamlAnalysis(String id,String correlation,Map<String,Object> summary){throw new AssertionError("Reader cannot change originals");}},true);}
    private org.w3c.dom.Element assertion(String confirmations){return SecureXml.parse(("<Assertion xmlns='"+S+"'><Subject><NameID>ordinary-subject</NameID>"+confirmations+"</Subject></Assertion>").getBytes(java.nio.charset.StandardCharsets.UTF_8)).getDocumentElement();}
    private String confirmation(String names){return "<SubjectConfirmation Method='urn:oasis:names:tc:SAML:2.0:cm:bearer'>"+names+"<SubjectConfirmationData/></SubjectConfirmation>";}
    @Test void ordinaryBearerDoesNotRequireTheSpAudienceAsAnAttester(){
        var normal=assertion(confirmation(""));assertTrue(SimpleSamlPhpSubjectConfirmationEvidence.ordinaryBearer(normal));
        assertFalse(SimpleSamlPhpSubjectConfirmationEvidence.identifiesSeparateAttesters(normal,List.of("destination-sp")));
    }
    @Test void foreignAttesterNeedsItsOwnIdentifier(){
        var identified=assertion(confirmation("<NameID>other-attester</NameID>"));assertFalse(SimpleSamlPhpSubjectConfirmationEvidence.ordinaryBearer(identified));
        assertTrue(SimpleSamlPhpSubjectConfirmationEvidence.identifiesSeparateAttesters(identified,List.of("other-attester")));
        assertFalse(SimpleSamlPhpSubjectConfirmationEvidence.identifiesSeparateAttesters(identified,List.of("unrelated")));
    }
    @Test void multipleAttestersNeedSeparateIdentifyingConfirmations(){
        var separate=assertion(confirmation("<NameID>one</NameID>")+confirmation("<NameID>two</NameID>"));
        assertTrue(SimpleSamlPhpSubjectConfirmationEvidence.identifiesSeparateAttesters(separate,List.of("one","two")));
        assertFalse(SimpleSamlPhpSubjectConfirmationEvidence.identifiesSeparateAttesters(assertion(confirmation("<NameID>one</NameID><NameID>two</NameID>")),List.of("one","two")));
        assertFalse(SimpleSamlPhpSubjectConfirmationEvidence.identifiesSeparateAttesters(assertion(confirmation("<NameID>one</NameID>")+confirmation("<NameID>unrelated</NameID>")),List.of("one","two")));
        assertFalse(SimpleSamlPhpSubjectConfirmationEvidence.identifiesSeparateAttesters(assertion(confirmation("<NameID>one</NameID>")+confirmation("<NameID>one</NameID>")),List.of("one","two")));
    }
    @Test void ordinaryOrDeclaredAbsenceWithoutOriginalsCannotConclude()throws Exception{
        var reader=new SimpleSamlPhpSubjectConfirmationEvidence(directory,e->{throw new AssertionError();},r->"browser_sso_idp");assertFalse(reader.exists(RUN));assertTrue(reader.evaluate(context(),SimpleSamlPhpSubjectConfirmationEvidence.FR,new byte[0]).isEmpty());
        Path path=Files.createDirectory(directory.resolve(RUN));Files.writeString(path.resolve("manifest.json"),"{\"no_observation_opportunity\":true,\"restored\":true}");assertTrue(reader.exists(RUN));assertEquals(Outcome.NOT_VERIFIED,reader.evaluate(context(),SimpleSamlPhpSubjectConfirmationEvidence.FR,new byte[0]).orElseThrow().outcome());
    }
    @Test void invalidOwnedFileSymlinkAndWrongProfileFailClosed()throws Exception{
        var reader=new SimpleSamlPhpSubjectConfirmationEvidence(directory,e->{throw new AssertionError();},r->"metadata_idp");Path path=Files.writeString(directory.resolve(RUN),"{}");assertTrue(reader.exists(RUN));assertEquals(Outcome.NOT_VERIFIED,reader.evaluate(context(),SimpleSamlPhpSubjectConfirmationEvidence.GD,new byte[0]).orElseThrow().outcome());
        Files.delete(path);Files.createSymbolicLink(path,Files.createDirectory(directory.resolve("foreign")));assertTrue(reader.exists(RUN));assertEquals(Outcome.NOT_VERIFIED,reader.evaluate(context(),SimpleSamlPhpSubjectConfirmationEvidence.GD,new byte[0]).orElseThrow().outcome());
        assertFalse(reader.exists("../"+RUN));assertTrue(reader.evaluate(context(),"other-case",new byte[0]).isEmpty());
    }
}
