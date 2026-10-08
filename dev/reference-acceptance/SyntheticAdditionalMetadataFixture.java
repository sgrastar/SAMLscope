package com.samlscope.api;

import com.samlscope.saml.crypto.PlanCredentials;
import com.samlscope.saml.crypto.XmlSigner;
import com.samlscope.saml.crypto.XmlSignatureVerifier;
import com.samlscope.saml.normal.OpenSamlReader;
import com.samlscope.saml.normal.SecureXml;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.zip.Inflater;
import java.util.zip.InflaterInputStream;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.w3c.dom.Element;

/** Owned loopback synthetic publisher/IdP. It never invokes the Suite API or saves a private key. */
public final class SyntheticAdditionalMetadataFixture {
    static final String MD="urn:oasis:names:tc:SAML:2.0:metadata", P="urn:oasis:names:tc:SAML:2.0:protocol";
    static final String A="urn:oasis:names:tc:SAML:2.0:assertion", NS="urn:samlscope:synthetic:additional", SUCCESS="urn:oasis:names:tc:SAML:2.0:status:Success";
    static final List<String> SCENARIOS=List.of("match","mismatch","html","redirect","unreachable","unknown");
    final String base, suiteOrigin;
    final PlanCredentials key;
    final Map<String,AtomicInteger> operations=new ConcurrentHashMap<>();
    final AtomicInteger credentialHeaders=new AtomicInteger(), ssoReplies=new AtomicInteger();
    SyntheticAdditionalMetadataFixture(String base,String suiteOrigin)throws Exception {
        this.base=base;this.suiteOrigin=suiteOrigin;key=credentials();
    }
    public static void main(String[] args)throws Exception {
        if(args.length==1&&"--self-check".equals(args[0])) {selfCheck();return;}
        if((args.length!=3&&args.length!=4)||!"--serve".equals(args[0]))throw new IllegalArgumentException("--self-check or --serve <port> <Suite loopback origin> [host.docker.internal]");
        int port=Integer.parseInt(args[1]);if(port<1024||port>65535)throw new IllegalArgumentException("Invalid fixture port");
        var suite=URI.create(args[2]);
        if(!List.of("http","https").contains(suite.getScheme())||!List.of("localhost","127.0.0.1","::1").contains(suite.getHost())
                ||suite.getUserInfo()!=null||suite.getRawQuery()!=null||suite.getRawFragment()!=null||!List.of("","/").contains(suite.getPath()))throw new IllegalArgumentException("Explicit Suite loopback origin required");
        String publicHost=args.length==4?args[3]:"127.0.0.1";
        if(!List.of("127.0.0.1","host.docker.internal").contains(publicHost))throw new IllegalArgumentException("Owned host alias required");
        var fixture=new SyntheticAdditionalMetadataFixture("http://"+publicHost+":"+port,suite.toString().replaceAll("/$",""));
        var server=HttpServer.create(new InetSocketAddress("host.docker.internal".equals(publicHost)?"0.0.0.0":"127.0.0.1",port),0);
        server.createContext("/",e->fixture.handle(e));
        server.setExecutor(java.util.concurrent.Executors.newVirtualThreadPerTaskExecutor());
        Runtime.getRuntime().addShutdownHook(new Thread(()->server.stop(0)));
        server.start();System.out.println("Synthetic fixture listening at "+fixture.base+"; private keys are in memory");
    }
    void handle(HttpExchange e)throws java.io.IOException {
        String path=e.getRequestURI().getPath();operations.computeIfAbsent(e.getRequestMethod()+" "+path,k->new AtomicInteger()).incrementAndGet();
        if(e.getRequestHeaders().getFirst("Authorization")!=null||e.getRequestHeaders().getFirst("Cookie")!=null)credentialHeaders.incrementAndGet();
        try {
            if(!"GET".equals(e.getRequestMethod())) {send(e,405,"text/plain",new byte[0]);return;}
            if(path.startsWith("/metadata/")){String scenario=path.substring(10);requireScenario(scenario);send(e,200,"application/samlmetadata+xml",metadata(scenario));}
            else if(path.equals("/additional/match")||path.equals("/additional/mismatch")){e.getResponseHeaders().set("Set-Cookie","synthetic-cookie-sentinel=must-be-removed");send(e,200,"application/xml",additional());}
            else if(path.equals("/additional/html"))send(e,200,"text/html",("<html><input value='synthetic-html-sentinel-must-not-be-retained'/></html>").getBytes(StandardCharsets.UTF_8));
            else if(path.equals("/additional/redirect")){e.getResponseHeaders().set("Location",base+"/additional/match");send(e,302,"text/plain",new byte[0]);}
            else if(path.equals("/additional/unreachable"))send(e,503,"application/xml","<unavailable xmlns='urn:unavailable'/>".getBytes(StandardCharsets.UTF_8));
            else if(path.equals("/additional/unknown"))e.close();
            else if(path.equals("/sso")) {
                var fields=fields(e.getRequestURI().getRawQuery());
                String encoded=fields.get("SAMLRequest"),relay=fields.get("RelayState");
                if(encoded==null||relay==null||!relay.matches("run_[0-9A-HJKMNP-TV-Z]{26}"))throw new IllegalArgumentException("Unique normal M0 request and Run RelayState required");
                byte[] raw;
                try(var stream=new InflaterInputStream(new ByteArrayInputStream(Base64.getDecoder().decode(encoded)),new Inflater(true))){raw=stream.readNBytes(1024*1024+1);}
                if(raw.length>1024*1024)throw new IllegalArgumentException("Oversize request");
                var request=SecureXml.parse(raw).getDocumentElement();
                var response=response(request);ssoReplies.incrementAndGet();
                String html="<!doctype html><form method='post' action='"+escape(request.getAttribute("AssertionConsumerServiceURL"))+"'><input type='hidden' name='SAMLResponse' value='"+Base64.getEncoder().encodeToString(response)+"'/><input type='hidden' name='RelayState' value='"+escape(relay)+"'/></form>";
                send(e,200,"text/html",html.getBytes(StandardCharsets.UTF_8));
            } else if(path.equals("/stats")) {
                var json=new com.samlscope.store.JsonCodec();var counts=new java.util.TreeMap<String,Integer>();operations.forEach((name,count)->counts.put(name,count.get()));
                send(e,200,"application/json",json.write(Map.of("schema","synthetic-additional-fixture-v1","operations",counts,"credentialHeaders",credentialHeaders.get(),"ssoReplies",ssoReplies.get(),"privateKeysPersisted",false,"productSettingWrites",0,"productCredentialPosts",0)).getBytes(StandardCharsets.UTF_8));
            } else send(e,404,"text/plain",new byte[0]);
        }catch(Exception invalid){send(e,400,"text/plain","Invalid synthetic fixture request".getBytes(StandardCharsets.UTF_8));}
    }
    byte[] metadata(String scenario)throws Exception {
        requireScenario(scenario);String url=base+"/additional/"+scenario;
        String ns="mismatch".equals(scenario)?"urn:samlscope:synthetic:wrong":NS;
        // Duplicate URLs exercise dedup while preserving both independently checked declarations.
        String locations="<md:AdditionalMetadataLocation namespace='"+NS+"'>"+url+"</md:AdditionalMetadataLocation><md:AdditionalMetadataLocation namespace='"+ns+"'>"+url+"</md:AdditionalMetadataLocation>";
        String cert=Base64.getEncoder().encodeToString(key.certificate().getEncoded());
        String xml="<md:EntityDescriptor xmlns:md='"+MD+"' xmlns:ds='http://www.w3.org/2000/09/xmldsig#' entityID='"+entity()+"'><md:IDPSSODescriptor protocolSupportEnumeration='"+P+"' WantAuthnRequestsSigned='true'><md:KeyDescriptor use='signing'><ds:KeyInfo><ds:X509Data><ds:X509Certificate>"+cert+"</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat><md:SingleSignOnService Binding='urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect' Location='"+base+"/sso'/></md:IDPSSODescriptor>"+locations+"</md:EntityDescriptor>";
        return xml.getBytes(StandardCharsets.UTF_8);
    }
    byte[] response(Element request) {
        if(!P.equals(request.getNamespaceURI())||!"AuthnRequest".equals(request.getLocalName())||request.getAttribute("ID").isBlank())throw new IllegalArgumentException("AuthnRequest required");
        String acs=request.getAttribute("AssertionConsumerServiceURL"),audience=children(request,A,"Issuer").getFirst().getTextContent();
        if(!acs.startsWith(suiteOrigin+"/p/")||!acs.substring((suiteOrigin+"/p/").length()).matches("plan_[0-9A-HJKMNP-TV-Z]{26}/sp/acs/0")||!audience.startsWith(suiteOrigin+"/p/"))throw new IllegalArgumentException("Actual loopback Suite normal ACS required");
        var now=Instant.now();String at=now.toString(),expiry=now.plusSeconds(300).toString(),id=request.getAttribute("ID");
        String xml="<p:Response xmlns:p='"+P+"' xmlns:a='"+A+"' ID='_synthetic_response_"+random()+"' Version='2.0' IssueInstant='"+at+"' InResponseTo='"+escape(id)+"' Destination='"+escape(acs)+"'><a:Issuer>"+entity()+"</a:Issuer><p:Status><p:StatusCode Value='"+SUCCESS+"'/></p:Status><a:Assertion ID='_synthetic_assertion_"+random()+"' Version='2.0' IssueInstant='"+at+"'><a:Issuer>"+entity()+"</a:Issuer><a:Subject><a:NameID Format='urn:oasis:names:tc:SAML:2.0:nameid-format:transient'>synthetic-public-principal</a:NameID><a:SubjectConfirmation Method='urn:oasis:names:tc:SAML:2.0:cm:bearer'><a:SubjectConfirmationData Recipient='"+escape(acs)+"' InResponseTo='"+escape(id)+"' NotOnOrAfter='"+expiry+"'/></a:SubjectConfirmation></a:Subject><a:Conditions NotBefore='"+now.minusSeconds(60)+"' NotOnOrAfter='"+expiry+"'><a:AudienceRestriction><a:Audience>"+escape(audience)+"</a:Audience></a:AudienceRestriction></a:Conditions><a:AuthnStatement AuthnInstant='"+at+"' SessionIndex='_synthetic_session_"+random()+"'><a:AuthnContext><a:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</a:AuthnContextClassRef></a:AuthnContext></a:AuthnStatement></a:Assertion></p:Response>";
        var document=SecureXml.parse(xml.getBytes(StandardCharsets.UTF_8));var root=document.getDocumentElement();var assertion=children(root,A,"Assertion").getFirst();
        var signer=new XmlSigner();signer.sign(assertion,key,children(assertion,A,"Subject").getFirst());signer.sign(root,key,children(root,P,"Status").getFirst());
        return SecureXml.serialize(document);
    }
    String entity(){return base+"/entity";}
    static byte[] additional(){return ("<x:document xmlns:x='"+NS+"'><x:public>owned synthetic fixture</x:public></x:document>").getBytes(StandardCharsets.UTF_8);}
    static void send(HttpExchange e,int status,String type,byte[] body)throws java.io.IOException {e.getResponseHeaders().set("Content-Type",type);e.getResponseHeaders().set("Cache-Control","no-store");e.sendResponseHeaders(status,body.length==0?-1:body.length);if(body.length>0)e.getResponseBody().write(body);e.close();}
    static void requireScenario(String scenario){if(!SCENARIOS.contains(scenario))throw new IllegalArgumentException("Unknown scenario");}
    static List<Element> children(Element root,String ns,String local){var out=new java.util.ArrayList<Element>();for(var n=root.getFirstChild();n!=null;n=n.getNextSibling())if(n instanceof Element e&&ns.equals(e.getNamespaceURI())&&local.equals(e.getLocalName()))out.add(e);return out;}
    static Map<String,String> fields(String raw){var result=new LinkedHashMap<String,String>();if(raw==null)throw new IllegalArgumentException("Query required");for(String part:raw.split("&")){int equal=part.indexOf('=');if(equal<0)throw new IllegalArgumentException("Bad query");String name=URLDecoder.decode(part.substring(0,equal),StandardCharsets.UTF_8),value=URLDecoder.decode(part.substring(equal+1),StandardCharsets.UTF_8);if(result.putIfAbsent(name,value)!=null)throw new IllegalArgumentException("Duplicate field");}return result;}
    static String escape(String text){return text.replace("&","&amp;").replace("'","&apos;").replace("<","&lt;").replace(">","&gt;").replace("\"","&quot;");}
    static String random(){byte[] bytes=new byte[16];new SecureRandom().nextBytes(bytes);return java.util.HexFormat.of().formatHex(bytes);}
    static PlanCredentials credentials()throws Exception {
        if(Security.getProvider("BC")==null)Security.addProvider(new BouncyCastleProvider());
        var generator=KeyPairGenerator.getInstance("RSA");generator.initialize(2048);var pair=generator.generateKeyPair();var now=Instant.now();
        var name=new X500Name("CN=Synthetic SAMLscope fixture (DO NOT TRUST)");
        var builder=new JcaX509v3CertificateBuilder(name,new BigInteger(128,new SecureRandom()).abs(),Date.from(now.minusSeconds(300)),Date.from(now.plusSeconds(86400)),name,pair.getPublic());
        builder.addExtension(Extension.basicConstraints,true,new BasicConstraints(false));builder.addExtension(Extension.keyUsage,true,new KeyUsage(KeyUsage.digitalSignature));
        var certificate=new JcaX509CertificateConverter().setProvider("BC").getCertificate(builder.build(new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC").build(pair.getPrivate())));
        return new PlanCredentials(pair.getPrivate(),certificate);
    }
    static void selfCheck()throws Exception {
        var fixture=new SyntheticAdditionalMetadataFixture("http://127.0.0.1:18936","http://localhost:18080");
        for(String scenario:SCENARIOS){var metadata=SecureXml.parse(fixture.metadata(scenario)).getDocumentElement();if(children(metadata,MD,"AdditionalMetadataLocation").size()!=2)throw new AssertionError("Both declarations required");new com.samlscope.saml.metadata.TargetMetadataParser().parse(fixture.metadata(scenario),fixture.entity());}
        var request=SecureXml.parse(("<p:AuthnRequest xmlns:p='"+P+"' xmlns:a='"+A+"' ID='_synthetic_request' Version='2.0' IssueInstant='"+Instant.now()+"' AssertionConsumerServiceURL='http://localhost:18080/p/plan_0123456789ABCDEFGHJKMNPQRS/sp/acs/0'><a:Issuer>http://localhost:18080/p/plan_0123456789ABCDEFGHJKMNPQRS</a:Issuer></p:AuthnRequest>").getBytes(StandardCharsets.UTF_8));
        byte[] response=fixture.response(request.getDocumentElement());var root=SecureXml.parse(response).getDocumentElement();var verifier=new XmlSignatureVerifier();
        if(!verifier.hasValidEnvelopedSignature(root,fixture.key.certificate())||!verifier.hasValidEnvelopedSignature(children(root,A,"Assertion").getFirst(),fixture.key.certificate()))throw new AssertionError("Synthetic original signatures invalid");
        new OpenSamlReader().read(response);
        if(!SUCCESS.equals(children(children(root,P,"Status").getFirst(),P,"StatusCode").getFirst().getAttribute("Value")))throw new AssertionError("Success URI differs");
        if(verifier.hasValidEnvelopedSignature(root,credentials().certificate()))throw new AssertionError("Foreign signing key accepted");
        request.getDocumentElement().setAttribute("AssertionConsumerServiceURL","https://foreign.invalid/acs");
        try {fixture.response(request.getDocumentElement());throw new AssertionError("Foreign ACS accepted");}catch(IllegalArgumentException expected){}
        System.out.println("{\"selfCheck\":\"passed\",\"networkOperations\":0,\"runsCreated\":0,\"privateKeysPersisted\":false,\"signedResponseAndAssertion\":true}");
    }
}
