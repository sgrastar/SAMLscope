package com.samlscope.api;

import static com.samlscope.api.ReadSyntheticArtifactRuntime.*;
import com.samlscope.saml.binding.SignedRedirectEncoder;
import com.samlscope.saml.crypto.*;
import com.samlscope.saml.normal.SecureXml;
import com.samlscope.core.transcript.*;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.*;

/** Pure original-reader controls, never a substitute for an actual Suite Run or its outcome. */
public final class SyntheticFormalBrowserReaderControls {
    static int checks;
    interface Operation{void run()throws Exception;}
    static void reject(Operation operation)throws Exception{try{operation.run();throw new IllegalStateException("Invalid original accepted");}catch(IllegalArgumentException|IllegalStateException expected){if(expected.getMessage().equals("Invalid original accepted"))throw expected;checks++;}}
    static TranscriptEntry entry(String id,String method,String url,String correlation,byte[] body,byte[] xml){return new TranscriptEntry(id,SyntheticFormalBrowserFixtureControls.RUN,Direction.INBOUND,Instant.parse("2026-10-08T00:00:00Z"),correlation,method,url,200,Map.of(),null,body.length,null,xml.length,"application/x-www-form-urlencoded",null,Map.of());}
    static byte[] form(byte[] xml){return ("SAMLResponse="+java.net.URLEncoder.encode(Base64.getEncoder().encodeToString(xml),StandardCharsets.UTF_8)).getBytes(StandardCharsets.UTF_8);}
    public static void main(String[] args)throws Exception {
        if(args.length!=0)throw new IllegalArgumentException("No arguments");
        var suite=SyntheticAdditionalMetadataFixture.credentials();byte[] md=SyntheticFormalBrowserFixtureControls.metadata(suite);var fixture=new SyntheticFormalBrowserFixture("http://host.docker.internal:18946","http://localhost:18080",x->md);
        String query=SyntheticFormalBrowserFixtureControls.query(suite,"honor","_normal_reader",SyntheticFormalBrowserFixtureControls.RUN,"AssertionConsumerServiceURL='"+SyntheticFormalBrowserFixtureControls.ISSUER+"/sp/acs/0'");
        var normal=fixture.reply("honor",query,null);byte[] response=normal.response();
        var fields=SyntheticAdditionalMetadataFixture.fields(query);var inflated=new java.util.zip.Inflater(true);byte[] request;
        try(var input=new java.util.zip.InflaterInputStream(new java.io.ByteArrayInputStream(Base64.getDecoder().decode(fields.get("SAMLRequest"))),inflated)){request=input.readAllBytes();}finally{inflated.end();}
        var authn=SecureXml.parse(request).getDocumentElement();byte[] body=form(response);var e=entry("tx_0123456789ABCDEFGHJKMNPQRS","POST",normal.acs(),authn.getAttribute("ID"),body,response);
        var originals=new LinkedHashMap<String,Original>();originals.put(e.id(),new Original(e,body,response));var certs=List.of(fixture.key.certificate());String entity=fixture.entity("honor");
        ReadSyntheticFormalBrowserRuntime.verifyResponse(originals,e,authn,entity,certs,normal.acs());checks++;
        for(String change:List.of("wrong-request","wrong-entity","wrong-acs","wrong-cert","wrong-method","wrong-row-correlation","wrong-post-body","wrong-signed-status","wrong-signed-issuer","wrong-signed-destination")){
            var incoming=e;var map=new LinkedHashMap<String,Original>(originals);var requested=authn;String expectedEntity=entity,acs=normal.acs();var trusted=certs;
            switch(change){
                case "wrong-request" -> {requested=SecureXml.parse(request).getDocumentElement();requested.setAttribute("ID","_different");}
                case "wrong-entity" -> expectedEntity="https://foreign.invalid/entity";
                case "wrong-acs" -> acs=SyntheticFormalBrowserFixtureControls.ISSUER+"/sp/acs/1";
                case "wrong-cert" -> trusted=List.of(SyntheticAdditionalMetadataFixture.credentials().certificate());
                case "wrong-method" -> incoming=entry(e.id(),"GET",normal.acs(),authn.getAttribute("ID"),body,response);
                case "wrong-row-correlation" -> incoming=entry(e.id(),"POST",normal.acs(),"_other",body,response);
                case "wrong-post-body" -> map.put(e.id(),new Original(e,form("<other/>".getBytes(StandardCharsets.UTF_8)),response));
                default -> {
                    var doc=SecureXml.parse(response);var root=doc.getDocumentElement();
                    for(var child:children(root,DS,"Signature"))root.removeChild(child);
                    if(change.equals("wrong-signed-status"))((org.w3c.dom.Element)root.getElementsByTagNameNS(P,"StatusCode").item(0)).setAttribute("Value","urn:oasis:names:tc:SAML:2.0:status:Responder");
                    if(change.equals("wrong-signed-issuer"))single(root,A,"Issuer").setTextContent("https://foreign.invalid/entity");
                    if(change.equals("wrong-signed-destination"))root.setAttribute("Destination",SyntheticFormalBrowserFixtureControls.ISSUER+"/sp/acs/1");
                    new XmlSigner().sign(root,fixture.key,single(root,P,"Status"));byte[] changed=SecureXml.serialize(doc);map.put(e.id(),new Original(e,form(changed),changed));
                }
            }
            final var checkedEntry=incoming;final var checkedRequest=requested;final var checkedCerts=trusted;final String checkedEntity=expectedEntity,checkedAcs=acs;
            reject(()->ReadSyntheticFormalBrowserRuntime.verifyResponse(map,checkedEntry,checkedRequest,checkedEntity,checkedCerts,checkedAcs));
        }
        String cookie=SyntheticFormalBrowserFixture.OWNED_COOKIE;
        var header=Map.of("Cookie",List.of(cookie+"=<redacted: 32 bytes>"),"Content-Type",List.of("application/x-www-form-urlencoded"));
        var projected=ReadSyntheticFormalBrowserRuntime.publicFormalHeaders(header);
        require(projected.equals(Map.of("Content-Type",List.of("application/x-www-form-urlencoded")))&&header.containsKey("Cookie"),"Stored header input changed or projection failed");checks++;
        for(var invalid:List.of(
                Map.of("Cookie",List.of(cookie+"="+"a".repeat(32))),
                Map.of("Cookie",List.of("foreign=<redacted: 32 bytes>")),
                Map.of("Cookie",List.of(cookie+"=<redacted: 31 bytes>")),
                Map.of("Cookie",List.of(cookie+"=<redacted: 32 bytes>",cookie+"=<redacted: 32 bytes>")),
                Map.of("Cookie",List.of(cookie+"=<redacted: 32 bytes>; foreign=<redacted: 32 bytes>")),
                Map.of("Cookie",List.of(cookie+"=<redacted: 32 bytes>"),"cOoKiE",List.of(cookie+"=<redacted: 32 bytes>")),
                Map.of("Authorization",List.of("<redacted: Basic, 32 bytes>")),
                Map.of("Proxy-Authorization",List.of("<redacted: Basic, 32 bytes>")),
                Map.of("Set-Cookie",List.of(cookie+"=<redacted: 32 bytes>"))))reject(()->ReadSyntheticFormalBrowserRuntime.publicFormalHeaders(invalid));
        System.out.println("{\"schema\":\"synthetic-formal-reader-controls-v1\",\"checksPassed\":"+checks+",\"networkOperations\":0,\"databaseReads\":0,\"actualSuiteProof\":false,\"privateKeysPersisted\":false,\"canonicalAdoption\":false}");
    }
}
