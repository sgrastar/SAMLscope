package com.samlscope.runner.cases;

import com.samlscope.core.transcript.TranscriptEntry;
import com.samlscope.saml.normal.SecureXml;
import com.samlscope.store.JsonCodec;
import java.nio.file.*;
import java.util.*;

/** Read-only response predicate replay; this does not complete the six-stage product case. */
public final class VerifyDefaultAlgorithmRedirectReply {
    public static void main(String[] args)throws Exception {
        Path folder=Path.of(args[0]).toRealPath(),jar=Path.of(args[1]).toRealPath();
        if(!Path.of(DefaultAlgorithmPreventionEvidence.class.getProtectionDomain().getCodeSource().getLocation().toURI()).toRealPath().equals(jar))throw new IllegalStateException("Wrong candidate Reader");
        var mapper=new JsonCodec().mapper();var raw=mapper.readTree(Files.readAllBytes(folder.resolve("transcript.json")));
        var rows=new ArrayList<TranscriptEntry>();for(var item:raw)rows.add(mapper.treeToValue(item,TranscriptEntry.class));
        var request=rows.stream().filter(e->"rsa15-encrypted-id".equals(e.samlSummary().get("fixture_id"))).findFirst().orElseThrow();
        var response=rows.stream().filter(e->"LogoutResponse".equals(e.samlSummary().get("type"))&&("_"+request.correlationId()).equals(e.samlSummary().get("inResponseTo"))).findFirst().orElseThrow();
        var prepared=rows.stream().filter(e->"MetadataPrepared".equals(e.samlSummary().get("type"))&&"control".equals(e.samlSummary().get("variant"))&&"live".equals(e.samlSummary().get("feed"))).findFirst().orElseThrow();
        if(!request.runId().equals(response.runId())||!request.runId().equals(prepared.runId()))throw new IllegalStateException("Mixed source Run");
        byte[] requestBytes=read(folder,request),responseBytes=read(folder,response),suiteBytes=read(folder,prepared),targetBytes=Files.readAllBytes(folder.resolve("target-metadata.xml"));
        if(!DefaultAlgorithmPreventionEvidence.hash(suiteBytes).equals(prepared.samlSummary().get("metadataSha256")))throw new IllegalStateException("Metadata original changed");
        var q=SecureXml.parse(requestBytes).getDocumentElement();var suite=SecureXml.parse(suiteBytes).getDocumentElement();var target=SecureXml.parse(targetBytes).getDocumentElement();
        DefaultAlgorithmPreventionEvidence.validateReply(response,SecureXml.parse(responseBytes).getDocumentElement(),responseBytes,q,suite,target,true);
        String changed=response.rawQuery().replace("Signature=","Signature=AAAA");
        reject(()->DefaultAlgorithmPreventionEvidence.validateReply(copy(response,response.url().replace(response.rawQuery(),changed),changed),SecureXml.parse(responseBytes).getDocumentElement(),responseBytes,q,suite,target,true));
        var different=SecureXml.parse(responseBytes);different.getDocumentElement().setAttribute("ID","_foreign_response");byte[] changedXml=SecureXml.serialize(different);
        reject(()->DefaultAlgorithmPreventionEvidence.validateReply(response,different.getDocumentElement(),changedXml,q,suite,target,true));
        reject(()->DefaultAlgorithmPreventionEvidence.validateReply(copy(response,response.url().replace("/sp/slo","/foreign/slo"),response.rawQuery()),SecureXml.parse(responseBytes).getDocumentElement(),responseBytes,q,suite,target,true));
        reject(()->DefaultAlgorithmPreventionEvidence.validateReply(copy(response,response.url(),null),SecureXml.parse(responseBytes).getDocumentElement(),responseBytes,q,suite,target,true));
        System.out.println(mapper.writeValueAsString(Map.of("runId",request.runId(),"requestReference",request.id(),"responseReference",response.id(),"actualRedirectReplyVerified",true,"negativeControlsRejected",4,"newSaml",0,"newCredentialPosts",0,"actualProductCaseAdopted",false,"missingApprovedStage","oaep-encrypted-id-control")));
    }
    private static byte[] read(Path folder,TranscriptEntry e)throws Exception{return Files.readAllBytes(folder.resolve("decoded").resolve(e.id()+".xml"));}
    private static TranscriptEntry copy(TranscriptEntry e,String url,String query){return new TranscriptEntry(e.id(),e.runId(),e.direction(),e.timestamp(),e.correlationId(),e.method(),url,e.status(),e.headers(),e.bodyRef(),e.bodyBytes(),e.decodedSamlRef(),e.decodedSamlBytes(),e.contentType(),query,e.samlSummary());}
    private interface Checked {void run()throws Exception;}
    private static void reject(Checked action)throws Exception {try{action.run();}catch(IllegalArgumentException expected){return;}throw new IllegalStateException("Contaminated original passed");}
}
