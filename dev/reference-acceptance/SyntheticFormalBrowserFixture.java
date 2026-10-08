package com.samlscope.api;

import com.samlscope.runner.ActiveProbeCorrelation;
import com.samlscope.saml.binding.RedirectSignatureVerifier;
import com.samlscope.saml.crypto.*;
import com.samlscope.saml.metadata.*;
import com.samlscope.saml.normal.*;
import com.sun.net.httpserver.*;
import java.io.*;
import java.net.*;
import java.net.http.*;
import java.nio.charset.StandardCharsets;
import java.time.*;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Function;
import java.util.zip.*;
import org.w3c.dom.Element;

/** Owned session-bearing IdP calibration only; it never saves keys, cookies or user credentials. */
public final class SyntheticFormalBrowserFixture {
    static final String MD=MetadataService.MD, P="urn:oasis:names:tc:SAML:2.0:protocol", A="urn:oasis:names:tc:SAML:2.0:assertion";
    static final String POST=MetadataService.POST, SUCCESS="urn:oasis:names:tc:SAML:2.0:status:Success";
    static final String OWNED_COOKIE="samlscope_owned_formal_session";
    static final List<String> MODES=List.of("honor","ignore");
    final String base,suite;
    final PlanCredentials key;
    final Function<String,byte[]> suiteMetadata;
    final Map<String,Session> sessions=new ConcurrentHashMap<>();
    final Set<String> seenRequests=ConcurrentHashMap.newKeySet();
    final Map<String,Map<String,AtomicInteger>> counts=new ConcurrentHashMap<>();
    final Map<String,byte[]> publicMetadata=new ConcurrentHashMap<>();
    record Session(String run,String issuer,String mode,String sessionIndex) {}
    record Reply(byte[] response,String relay,String acs,String issuedSession) {}

    SyntheticFormalBrowserFixture(String base,String suite,Function<String,byte[]> metadata)throws Exception {
        this.base=base;this.suite=suite;this.suiteMetadata=metadata;key=SyntheticAdditionalMetadataFixture.credentials();
        for(String mode:MODES){var initial=new ConcurrentHashMap<String,AtomicInteger>();
            for(String count:List.of("metadataReads","normalReplies","formalReplies","newSessions","reusedSessions","missingSessionRejects","foreignSessionRejects"))initial.put(count,new AtomicInteger());
            counts.put(mode,initial);}
    }
    public static void main(String[] args)throws Exception {
        if(args.length==1&&args[0].equals("--self-check")){selfCheck();return;}
        if(args.length!=4||!args[0].equals("--serve"))throw new IllegalArgumentException("--serve <port> <loopback Suite origin> host.docker.internal");
        int port=Integer.parseInt(args[1]);if(port<1024||port>65535)throw new IllegalArgumentException("Invalid fixture port");
        URI origin=URI.create(args[2]);
        if(!Set.of("http","https").contains(origin.getScheme())||!Set.of("localhost","127.0.0.1","::1").contains(origin.getHost())
                ||origin.getUserInfo()!=null||origin.getRawQuery()!=null||origin.getRawFragment()!=null||!Set.of("","/").contains(origin.getPath())||!args[3].equals("host.docker.internal"))throw new IllegalArgumentException("Owned loopback scope required");
        String suite=origin.toString().replaceAll("/$","");
        var fixture=new SyntheticFormalBrowserFixture("http://host.docker.internal:"+port,suite,null);
        var server=HttpServer.create(new java.net.InetSocketAddress("0.0.0.0",port),0);
        server.createContext("/",e->fixture.handle(e));server.setExecutor(java.util.concurrent.Executors.newVirtualThreadPerTaskExecutor());
        Runtime.getRuntime().addShutdownHook(new Thread(()->server.stop(0)));
        server.start();System.out.println("Synthetic formal fixture listening; keys and sessions remain in RAM");
    }
    void increment(String mode,String name){counts.get(mode).computeIfAbsent(name,k->new AtomicInteger()).incrementAndGet();}
    String entity(String mode){return base+"/entity/"+mode;}
    void handle(HttpExchange exchange)throws IOException {
        try {
            if(!Set.of("GET","POST").contains(exchange.getRequestMethod())||exchange.getRequestHeaders().getFirst("Authorization")!=null){send(exchange,405,"text/plain",new byte[0]);return;}
            String path=exchange.getRequestURI().getPath();
            if(path.equals("/stats")&&exchange.getRequestMethod().equals("GET")) {
                var facts=new TreeMap<String,Object>();for(var mode:MODES){var modeCounts=new TreeMap<String,Integer>();counts.get(mode).forEach((k,v)->modeCounts.put(k,v.get()));facts.put(mode,modeCounts);}
                send(exchange,200,"application/json",new com.samlscope.store.JsonCodec().write(Map.of("schema","synthetic-formal-fixture-v1","modes",facts,"sessionValuesExported",false,"privateKeysPersisted",false,"realUserAuthenticationQualified",false)).getBytes(StandardCharsets.UTF_8));return;
            }
            String mode=path.substring(path.lastIndexOf('/')+1);if(!MODES.contains(mode))throw new IllegalArgumentException("Unknown owned mode");
            if(path.equals("/metadata/"+mode)&&exchange.getRequestMethod().equals("GET")){increment(mode,"metadataReads");send(exchange,200,"application/samlmetadata+xml",metadata(mode));return;}
            if(!path.equals("/sso/"+mode))throw new IllegalArgumentException("Unknown owned endpoint");
            var cookieHeaders=exchange.getRequestHeaders().get("Cookie");
            String cookie=cookieHeaders==null?null:cookieHeaders.size()==1?ownedSession(cookieHeaders.getFirst()):invalidCookie();
            byte[] body=exchange.getRequestBody().readNBytes(1024*1024+1);
            if(body.length>1024*1024||exchange.getRequestMethod().equals("POST")
                    && !validFormContentType(exchange.getRequestHeaders().getFirst("Content-Type")))throw new IllegalArgumentException("Bound raw POST form required");
            var reply=reply(mode,exchange.getRequestMethod(),exchange.getRequestURI().getRawQuery(),body,cookie);
            if(reply.issuedSession()!=null)exchange.getResponseHeaders().set("Set-Cookie",OWNED_COOKIE+"="+reply.issuedSession()+"; HttpOnly; SameSite=Lax; Path=/");
            String html="<!doctype html><form method='post' action='"+escape(reply.acs())+"'><input type='hidden' name='SAMLResponse' value='"+Base64.getEncoder().encodeToString(reply.response())+"'/><input type='hidden' name='RelayState' value='"+escape(reply.relay())+"'/></form>";
            send(exchange,200,"text/html",html.getBytes(StandardCharsets.UTF_8));
        }catch(Exception invalid){send(exchange,400,"text/plain","Owned synthetic scope or existing session is unproven".getBytes(StandardCharsets.UTF_8));}
    }
    static String invalidCookie(){throw new IllegalArgumentException("Duplicate session header");}
    static boolean validFormContentType(String value){return value!=null&&value.matches("(?i)application/x-www-form-urlencoded(?:;\\s*charset=utf-8)?");}
    static String ownedSession(String header){
        if(header==null)return null;
        if(!header.matches(OWNED_COOKIE+"=[0-9a-f]{32}"))throw new IllegalArgumentException("Only exact owned session header is accepted");
        return header.substring(OWNED_COOKIE.length()+1);
    }
    byte[] metadata(String mode)throws Exception {
        String cert=Base64.getEncoder().encodeToString(key.certificate().getEncoded());
        return ("<md:EntityDescriptor xmlns:md='"+MD+"' xmlns:ds='"+MetadataService.DS+"' entityID='"+entity(mode)+"'><md:IDPSSODescriptor protocolSupportEnumeration='"+P+"' WantAuthnRequestsSigned='true'><md:KeyDescriptor use='signing'><ds:KeyInfo><ds:X509Data><ds:X509Certificate>"+cert+"</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat><md:SingleSignOnService Binding='"+MetadataService.REDIRECT+"' Location='"+base+"/sso/"+mode+"'/><md:SingleSignOnService Binding='"+POST+"' Location='"+base+"/sso/"+mode+"'/></md:IDPSSODescriptor></md:EntityDescriptor>").getBytes(StandardCharsets.UTF_8);
    }
    Reply reply(String mode,String rawQuery,String cookie)throws Exception {
        return reply(mode,"GET",rawQuery,new byte[0],cookie);
    }
    Reply reply(String mode,String method,String rawQuery,byte[] body,String cookie)throws Exception {
        if(!MODES.contains(mode)||!Set.of("GET","POST").contains(method))throw new IllegalArgumentException("Unknown mode/transport");
        if(body.length>1024*1024)throw new IllegalArgumentException("Oversize request body");
        var fields=SyntheticAdditionalMetadataFixture.fields(method.equals("GET")?rawQuery:new String(body,StandardCharsets.UTF_8));
        String relay=fields.get("RelayState"),encoded=fields.get("SAMLRequest");
        if(relay==null||encoded==null)throw new IllegalArgumentException("Bound request required");
        byte[] raw;
        if(method.equals("GET")){
            var inflater=new Inflater(true);
            try(var stream=new InflaterInputStream(new ByteArrayInputStream(Base64.getDecoder().decode(encoded)),inflater)){raw=stream.readNBytes(1024*1024+1);if(!inflater.finished()||raw.length>1024*1024)throw new IllegalArgumentException("Bad bounded compression");}finally{inflater.end();}
        }else{raw=Base64.getDecoder().decode(encoded);if(raw.length>1024*1024)throw new IllegalArgumentException("Oversize decoded request");}
        var request=SecureXml.parse(raw).getDocumentElement();
        if(!P.equals(request.getNamespaceURI())||!request.getLocalName().equals("AuthnRequest")||!request.getAttribute("Version").equals("2.0")||request.getAttribute("ID").isBlank())throw new IllegalArgumentException("SAML2 request required");
        String issuer=only(children(request,A,"Issuer")).getTextContent();URI issuerUri=URI.create(issuer);
        if(!issuer.equals(suite+issuerUri.getPath())||!issuerUri.getPath().matches("/p/plan_[0-9A-HJKMNP-TV-Z]{26}"))throw new IllegalArgumentException("Foreign Suite Plan issuer");
        byte[] metadata=publicMetadata.computeIfAbsent(issuer,i->suiteMetadata==null?fetchPublic(i):suiteMetadata.apply(i));
        var target=new TargetMetadataParser().parse(metadata,issuer);var verifier=new RedirectSignatureVerifier();
        boolean signature=method.equals("GET")
                ? target.signingCertificates().stream().anyMatch(c->verifier.isValidForMessage(rawQuery,c,raw))
                : target.signingCertificates().stream().anyMatch(c->new XmlSignatureVerifier().hasValidEnvelopedReferenceDigests(request)
                    && new XmlSignatureVerifier().hasValidEnvelopedSignature(request,c));
        if(!signature)throw new IllegalArgumentException("Actual Suite request signature unproven");
        var probe=ActiveProbeCorrelation.parse(relay);String run=probe.map(ActiveProbeCorrelation.Value::runId).orElse(relay);
        if(!run.matches("run_[0-9A-HJKMNP-TV-Z]{26}")||probe.isPresent()&&(!probe.get().actionId().matches("action_[0-9a-f]{32}")||!request.getAttribute("ID").equals("_"+probe.get().actionId())))throw new IllegalArgumentException("Foreign Run/action");
        Session session=cookie==null?null:sessions.get(cookie);String issue=null;
        if(probe.isPresent()) {
            if(session==null){increment(mode,"missingSessionRejects");throw new IllegalArgumentException("Formal action needs existing owned session");}
            if(!session.run().equals(run)||!session.issuer().equals(issuer)||!session.mode().equals(mode)){increment(mode,"foreignSessionRejects");throw new IllegalArgumentException("Owned session belongs to another scope");}
        } else if(session!=null) {
            if(!session.run().equals(run)||!session.issuer().equals(issuer)||!session.mode().equals(mode))throw new IllegalArgumentException("Foreign normal session");
        } else {
            issue=random();session=new Session(run,issuer,mode,"_owned_protocol_session_"+random());sessions.put(issue,session);increment(mode,"newSessions");
        }
        var services=target.assertionConsumerServices().stream().filter(e->POST.equals(e.binding())).toList();
        if(services.size()!=2||services.stream().noneMatch(e->Integer.valueOf(0).equals(e.index()))||services.stream().noneMatch(e->Integer.valueOf(1).equals(e.index())))throw new IllegalArgumentException("Exact two POST ACS endpoints needed");
        var defaultAcs=services.stream().filter(e->e.isDefault()).findFirst().orElse(services.getFirst());
        String index=request.getAttribute("AssertionConsumerServiceIndex"),explicit=request.getAttribute("AssertionConsumerServiceURL");
        if(!index.isBlank()&&!explicit.isBlank())throw new IllegalArgumentException("Conflicting ACS fields");
        var selected=index.isBlank()||mode.equals("ignore")?defaultAcs:services.stream().filter(e->Integer.toString(e.index()).equals(index)).findFirst().orElseThrow();
        if(!explicit.isBlank())selected=services.stream().filter(e->e.location().toString().equals(explicit)).findFirst().orElseThrow();
        String acs=selected.location().toString();
        if(!acs.matches(java.util.regex.Pattern.quote(issuer)+"/sp/acs/[01]"))throw new IllegalArgumentException("Foreign ACS");
        if(!seenRequests.add(run+":"+request.getAttribute("ID")))throw new IllegalArgumentException("Duplicate one-use request");
        byte[] response=response(mode,request,acs,issuer,session.sessionIndex());
        increment(mode,probe.isPresent()?"formalReplies":"normalReplies");if(probe.isPresent())increment(mode,"reusedSessions");
        return new Reply(response,relay,acs,issue);
    }
    byte[] fetchPublic(String issuer) {
        try {
            URI url=URI.create(issuer+"/metadata");var client=HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).connectTimeout(Duration.ofSeconds(10)).build();
            var response=client.send(HttpRequest.newBuilder(url).timeout(Duration.ofSeconds(15)).GET().build(),HttpResponse.BodyHandlers.ofInputStream());
            try(var input=response.body()){byte[] bytes=input.readNBytes(1024*1024+1);if(response.statusCode()!=200||bytes.length>1024*1024||!issuer.equals(SecureXml.parse(bytes).getDocumentElement().getAttribute("entityID")))throw new IllegalArgumentException("Actual public Suite metadata unavailable");return bytes;}
        }catch(Exception failure){throw new IllegalArgumentException("Actual public Suite metadata unavailable");}
    }
    byte[] response(String mode,Element request,String acs,String issuer,String session) {
        var now=Instant.now();String at=now.toString(),expires=now.plusSeconds(300).toString(),id=request.getAttribute("ID");
        String xml="<p:Response xmlns:p='"+P+"' xmlns:a='"+A+"' ID='_owned_response_"+random()+"' Version='2.0' IssueInstant='"+at+"' InResponseTo='"+escape(id)+"' Destination='"+escape(acs)+"'><a:Issuer>"+entity(mode)+"</a:Issuer><p:Status><p:StatusCode Value='"+SUCCESS+"'/></p:Status><a:Assertion ID='_owned_assertion_"+random()+"' Version='2.0' IssueInstant='"+at+"'><a:Issuer>"+entity(mode)+"</a:Issuer><a:Subject><a:NameID Format='urn:oasis:names:tc:SAML:2.0:nameid-format:transient'>synthetic-public-principal</a:NameID><a:SubjectConfirmation Method='urn:oasis:names:tc:SAML:2.0:cm:bearer'><a:SubjectConfirmationData Recipient='"+escape(acs)+"' InResponseTo='"+escape(id)+"' NotOnOrAfter='"+expires+"'/></a:SubjectConfirmation></a:Subject><a:Conditions NotBefore='"+now.minusSeconds(60)+"' NotOnOrAfter='"+expires+"'><a:AudienceRestriction><a:Audience>"+escape(issuer)+"</a:Audience></a:AudienceRestriction></a:Conditions><a:AuthnStatement AuthnInstant='"+at+"' SessionIndex='"+escape(session)+"'><a:AuthnContext><a:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</a:AuthnContextClassRef></a:AuthnContext></a:AuthnStatement></a:Assertion></p:Response>";
        var doc=SecureXml.parse(xml.getBytes(StandardCharsets.UTF_8));var root=doc.getDocumentElement();var assertion=only(children(root,A,"Assertion"));var signer=new XmlSigner();signer.sign(assertion,key,only(children(assertion,A,"Subject")));signer.sign(root,key,only(children(root,P,"Status")));return SecureXml.serialize(doc);
    }
    static List<Element> children(Element e,String ns,String name){return SyntheticAdditionalMetadataFixture.children(e,ns,name);}
    static Element only(List<Element> elements){if(elements.size()!=1)throw new IllegalArgumentException("Unique element required");return elements.getFirst();}
    static String escape(String text){return SyntheticAdditionalMetadataFixture.escape(text);}
    static String random(){return SyntheticAdditionalMetadataFixture.random();}
    static void send(HttpExchange e,int status,String type,byte[] body)throws IOException{SyntheticAdditionalMetadataFixture.send(e,status,type,body);}
    static void selfCheck()throws Exception {SyntheticFormalBrowserFixtureControls.run();}
}
