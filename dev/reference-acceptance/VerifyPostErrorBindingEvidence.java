package com.samlscope.runner.cases;

import com.samlscope.core.evaluation.*;
import com.samlscope.core.transcript.*;
import com.samlscope.saml.crypto.XmlSignatureVerifier;
import com.samlscope.saml.normal.SecureXml;
import com.samlscope.store.JsonCodec;
import java.io.ByteArrayInputStream;
import java.nio.file.*;
import java.security.MessageDigest;
import java.security.cert.*;
import java.util.*;
import org.w3c.dom.Element;

/** Replay the production POST-error oracle on original Run-scoped native SAML bytes. */
public final class VerifyPostErrorBindingEvidence {
    private static final JsonCodec JSON=new JsonCodec();
    private static final String CASE="IIP-SSO03-b-idp-01",P="urn:oasis:names:tc:SAML:2.0:protocol",S="urn:oasis:names:tc:SAML:2.0:assertion",DS="http://www.w3.org/2000/09/xmldsig#";
    private static void require(boolean ok,String why){if(!ok)throw new IllegalArgumentException(why);}
    private static String sha(byte[] raw)throws Exception{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(raw));}
    private static Optional<CaseOutcome> evaluate(List<NormalFlowBrowserObservation.Message> rows){return NormalFlowBrowserObservation.evaluate(CASE,rows);}
    public static void main(String[]args)throws Exception {
        var folder=Path.of(args[0]).toAbsolutePath();var output=Path.of(args[2]);require(!Files.exists(output),"Replay output exists");
        var created=JSON.mapper().readTree(folder.resolve("created.json").toFile());var run=created.at("/run/id").asText();
        var entries=List.of(JSON.mapper().readValue(folder.resolve("transcript.json").toFile(),TranscriptEntry[].class));
        var byId=new HashMap<String,TranscriptEntry>();for(var e:entries)require(e.runId().equals(run)&&byId.put(e.id(),e)==null,"Foreign/duplicate transcript");
        var bodies=new HashMap<String,byte[]>();
        for(var row:JSON.mapper().readTree(folder.resolve("decoded-manifest.json").toFile())){
            var path=folder.resolve(row.path("file").asText()).normalize();require(path.getParent().equals(folder.resolve("decoded")),"Original path escaped");
            var e=byId.get(row.path("id").asText());var raw=Files.readAllBytes(path);
            require(e!=null&&e.decodedSamlBytes()==raw.length&&sha(raw).equals(row.path("sha256").asText())&&bodies.put(e.id(),raw)==null,"Original hash/length differs");
        }
        var target=SecureXml.parse(Files.readAllBytes(folder.resolve("target-metadata.xml"))).getDocumentElement();
        var certs=new ArrayList<X509Certificate>();var descriptors=target.getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:metadata","KeyDescriptor");
        for(int i=0;i<descriptors.getLength();i++){
            var descriptor=(Element)descriptors.item(i);if(!Set.of("","signing").contains(descriptor.getAttribute("use")))continue;
            var nodes=descriptor.getElementsByTagNameNS(DS,"X509Certificate");for(int j=0;j<nodes.getLength();j++)certs.add((X509Certificate)CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(Base64.getMimeDecoder().decode(nodes.item(j).getTextContent()))));
        }
        require(!certs.isEmpty(),"Target signing keys unavailable");
        var messages=new ArrayList<NormalFlowBrowserObservation.Message>();
        for(var e:entries){
            if(MetadataProbeCorrelation.signatureControl(e)||e.decodedSamlRef()==null||e.decodedSamlBytes()<=0)continue;
            var type=e.samlSummary().get("type");var active=e.correlationId()!=null&&(e.correlationId().startsWith("action_")||e.correlationId().startsWith("_action_"));
            if(e.direction()==Direction.INBOUND&&(!"Response".equals(type)||!Boolean.TRUE.equals(e.samlSummary().get(active?"activeProbeAccepted":"normalFlowAccepted"))))continue;
            if(e.direction()==Direction.OUTBOUND&&!"AuthnRequest".equals(type))continue;
            if(e.url()!=null&&e.url().contains("mdv="))continue;
            require(bodies.containsKey(e.id()),"Required original unavailable");
            messages.add(new NormalFlowBrowserObservation.Message("transcript:"+e.id(),e.method(),e.url(),e.timestamp(),bodies.get(e.id()),e.direction()==Direction.INBOUND));
        }
        var base=evaluate(messages).orElseThrow(()->new IllegalArgumentException("Original production reader inconclusive"));require(base.outcome()==Outcome.SATISFIED,"Original result not satisfied");
        var evidenceIds=new HashSet<String>();for(var ref:base.evidence())evidenceIds.add(ref.reference().replace("transcript:",""));
        var verified=new TreeMap<String,String>();var signatureVerifier=new XmlSignatureVerifier();
        for(var id:evidenceIds){
            var e=byId.get(id);var root=SecureXml.parse(bodies.get(id)).getDocumentElement();
            if(!"Response".equals(root.getLocalName()))continue;
            require(target.getAttribute("entityID").equals(root.getElementsByTagNameNS(S,"Issuer").item(0).getTextContent()),"Response issuer differs");
            require(certs.stream().anyMatch(c->signatureVerifier.hasValidEnvelopedSignature(root,c)),"Native Response signature unproven "+id);
            verified.put(id,sha(bodies.get(id)));
        }
        require(verified.size()>=2,"Normal and error signed controls unavailable");
        var checks=new TreeMap<String,String>();checks.put("native-normal-and-post-error",base.outcome().name());
        for(var name:List.of("get-error-mutant","error-only","success-only","uncorrelated-error","missing-error-status")){
            var changed=new ArrayList<NormalFlowBrowserObservation.Message>();
            for(var m:messages){
                Element root;try{root=SecureXml.parse(m.xml()).getDocumentElement();}catch(RuntimeException bad){changed.add(m);continue;}
                var codes=root.getElementsByTagNameNS(P,"StatusCode");var response=P.equals(root.getNamespaceURI())&&"Response".equals(root.getLocalName());
                var success=response&&codes.getLength()>0&&NormalFlowBrowserObservation.SUCCESS.equals(((Element)codes.item(0)).getAttribute("Value"));
                var error=response&&codes.getLength()>0&&!success;
                if(name.equals("error-only")&&success||name.equals("success-only")&&error)continue;
                var method=m.method();var raw=m.xml();
                if(error&&name.equals("get-error-mutant"))method="GET";
                if(error&&name.equals("uncorrelated-error")){root.setAttribute("InResponseTo","_different-run-request");raw=SecureXml.serialize(root.getOwnerDocument());}
                if(error&&name.equals("missing-error-status")){var status=(Element)root.getElementsByTagNameNS(P,"Status").item(0);status.getParentNode().removeChild(status);raw=SecureXml.serialize(root.getOwnerDocument());}
                changed.add(new NormalFlowBrowserObservation.Message(m.evidenceRef(),method,m.url(),m.timestamp(),raw,m.inbound()));
            }
            var outcome=evaluate(changed);var actual=outcome.map(v->v.outcome().name()).orElse("NOT_VERIFIED");
            require(actual.equals(name.equals("get-error-mutant")?"VIOLATED":"NOT_VERIFIED"),"False conclusion on "+name+": "+actual);checks.put(name,actual);
        }
        var result=new TreeMap<String,Object>();result.put("runId",run);result.put("caseId",CASE);result.put("outcome",base.outcome().name());result.put("reasonCode",base.reasonCode());result.put("details",base.details());result.put("evidence",base.evidence());result.put("checks",checks);result.put("verifiedNativeResponses",verified);result.put("configurationWrites",0);result.put("privateKeyExported",false);
        JSON.mapper().writerWithDefaultPrettyPrinter().writeValue(output.toFile(),result);
    }
}
