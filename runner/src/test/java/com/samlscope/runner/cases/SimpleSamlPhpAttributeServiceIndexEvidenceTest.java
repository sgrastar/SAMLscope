package com.samlscope.runner.cases;

import static org.junit.jupiter.api.Assertions.*;
import com.samlscope.core.transcript.*;
import com.samlscope.core.plan.*;
import com.samlscope.core.run.Reachability;
import com.samlscope.core.evaluation.Outcome;
import com.samlscope.runner.DefaultCaseContext;
import com.samlscope.saml.normal.SecureXml;
import java.nio.file.*;
import java.time.*;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class SimpleSamlPhpAttributeServiceIndexEvidenceTest {
    @TempDir Path directory;
    private static final String RUN="run_00000000000000000000000000", UID="urn:oid:0.9.2342.19200300.100.1.1", SURNAME="urn:oid:2.5.4.4";
    private DefaultCaseContext context(){return new DefaultCaseContext(RUN,TargetRole.IDP,Clock.systemUTC(),TestPlan.Parameters.defaults(),TestPlan.Interaction.defaults(),Reachability.CONFIRMED,new TranscriptRecorder(){public List<TranscriptEntry> list(String run){return List.of();}public TranscriptEntry record(TranscriptInput input){throw new AssertionError();}public TranscriptEntry updateSamlAnalysis(String id,String correlation,Map<String,Object> summary){throw new AssertionError();}},true);}
    @Test void absentPreservesLegacyButOwnedClaimsCannotManufactureProof()throws Exception{
        var reader=new SimpleSamlPhpAttributeServiceIndexEvidence(directory,e->{throw new AssertionError();},run->new byte[0],(run,variant)->Optional.empty());
        assertFalse(reader.exists(RUN));assertTrue(reader.evaluate(context()).isEmpty());var folder=Files.createDirectory(directory.resolve(RUN));Files.writeString(folder.resolve("manifest.json"),"{\"restored\":true,\"configuration_confirmed\":true}");
        assertTrue(reader.exists(RUN));assertEquals(Outcome.NOT_VERIFIED,reader.evaluate(context()).orElseThrow().outcome());
    }
    @Test void fileAndSymlinkRemainOwnedAndFailClosed()throws Exception{
        var reader=new SimpleSamlPhpAttributeServiceIndexEvidence(directory,e->{throw new AssertionError();},run->new byte[0],(run,variant)->Optional.empty());
        var folder=Files.writeString(directory.resolve(RUN),"{}");assertEquals(Outcome.NOT_VERIFIED,reader.evaluate(context()).orElseThrow().outcome());Files.delete(folder);Files.createSymbolicLink(folder,Files.createDirectory(directory.resolve("foreign")));assertEquals(Outcome.NOT_VERIFIED,reader.evaluate(context()).orElseThrow().outcome());assertFalse(reader.exists("../"+RUN));
    }
    @Test void selectorOracleDistinguishesCorrectWrongAndUnknownAttributes(){
        var uid=Map.of(UID,List.of("known-user"));var surname=Map.of(SURNAME,List.of("samlscope-reference-surname"));
        assertEquals(Outcome.SATISFIED,SimpleSamlPhpAttributeServiceIndexEvidence.selectionOutcome(0,uid,"known-user"));assertEquals(Outcome.SATISFIED,SimpleSamlPhpAttributeServiceIndexEvidence.selectionOutcome(1,surname,"known-user"));
        assertEquals(Outcome.VIOLATED,SimpleSamlPhpAttributeServiceIndexEvidence.selectionOutcome(1,uid,"known-user"));assertEquals(Outcome.VIOLATED,SimpleSamlPhpAttributeServiceIndexEvidence.selectionOutcome(0,surname,"known-user"));
        assertEquals(Outcome.NOT_VERIFIED,SimpleSamlPhpAttributeServiceIndexEvidence.selectionOutcome(1,Map.of(),"known-user"));assertEquals(Outcome.NOT_VERIFIED,SimpleSamlPhpAttributeServiceIndexEvidence.selectionOutcome(1,Map.of(UID,List.of("other-user")),"known-user"));
    }
    @Test void fixedMetadataPreservesUnapprovedEndpointAndKeyUseChanges(){
        String xml="<EntityDescriptor xmlns='urn:oasis:names:tc:SAML:2.0:metadata' entityID='https://sp.example'><SPSSODescriptor protocolSupportEnumeration='urn:oasis:names:tc:SAML:2.0:protocol'><KeyDescriptor use='signing'/><AssertionConsumerService Binding='post' Location='https://sp.example/acs?mdv=control&amp;run=known' index='0'/></SPSSODescriptor></EntityDescriptor>";
        var original=SecureXml.parse(xml.getBytes()).getDocumentElement();var variant=SecureXml.parse(xml.replace("mdv=control","mdv=attribute-policy-indexed").getBytes()).getDocumentElement();
        assertEquals(SimpleSamlPhpAttributeServiceIndexEvidence.metadataFixed(original),SimpleSamlPhpAttributeServiceIndexEvidence.metadataFixed(variant));
        var changed=SecureXml.parse(xml.replace("sp.example/acs","evil.example/acs").getBytes()).getDocumentElement();assertNotEquals(SimpleSamlPhpAttributeServiceIndexEvidence.metadataFixed(original),SimpleSamlPhpAttributeServiceIndexEvidence.metadataFixed(changed));
        var keyChanged=SecureXml.parse(xml.replace("use='signing'","use='encryption'").getBytes()).getDocumentElement();assertNotEquals(SimpleSamlPhpAttributeServiceIndexEvidence.metadataFixed(original),SimpleSamlPhpAttributeServiceIndexEvidence.metadataFixed(keyChanged));
    }
    @Test void fixedRequestRemovesSelectorButPreservesOtherPolicyInputs(){
        String xml="<AuthnRequest xmlns='urn:oasis:names:tc:SAML:2.0:protocol' ID='_a' IssueInstant='2026-01-01T00:00:00Z' Destination='https://idp.example/sso' AttributeConsumingServiceIndex='0'><NameIDPolicy AllowCreate='true'/></AuthnRequest>";
        var original=SecureXml.parse(xml.getBytes()).getDocumentElement();var selector=SecureXml.parse(xml.replace("Index='0'","Index='1'").replace("ID='_a'","ID='_b'").getBytes()).getDocumentElement();assertEquals(SimpleSamlPhpAttributeServiceIndexEvidence.fixedRequest(original),SimpleSamlPhpAttributeServiceIndexEvidence.fixedRequest(selector));
        var changed=SecureXml.parse(xml.replace("AllowCreate='true'","AllowCreate='false'").getBytes()).getDocumentElement();assertNotEquals(SimpleSamlPhpAttributeServiceIndexEvidence.fixedRequest(original),SimpleSamlPhpAttributeServiceIndexEvidence.fixedRequest(changed));
    }
}
