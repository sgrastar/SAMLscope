package com.samlscope.api;

import com.samlscope.runner.ActiveProbeCorrelation;
import com.samlscope.saml.artifact.ArtifactResolutionProtocol;
import com.samlscope.saml.artifact.SamlArtifact;
import com.samlscope.saml.crypto.PlanCredentials;
import com.samlscope.saml.crypto.XmlSignatureVerifier;
import com.samlscope.saml.crypto.XmlSigner;
import com.samlscope.saml.metadata.TargetMetadataParser;
import com.samlscope.saml.normal.OpenSamlReader;
import com.samlscope.saml.normal.SecureXml;
import com.samlscope.store.JsonCodec;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;
import java.io.ByteArrayInputStream;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.zip.Inflater;
import java.util.zip.InflaterInputStream;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.w3c.dom.Element;

/** Synthetic public-API fixture. Preparation does not bind sockets or call any Suite API. */
public final class SyntheticArtifactFixture {
    static final String MD=SamlArtifact.MD, P=SamlArtifact.P, A=ArtifactResolutionProtocol.A;
    static final String DS=ArtifactResolutionProtocol.DS, SUCCESS=ArtifactResolutionProtocol.SUCCESS;
    static final String POST="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";
    static final String REDIRECT="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect";
    static final String ARTIFACT="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact";
    static final String PUBLIC_STORE_PASSWORD="fixture-public-only";
    static final int MAX_BYTES=1024*1024;
    static final List<String> MODES=List.of("signed","unsigned");
    final String httpBase,tlsBase,suiteOrigin;
    final PlanCredentials signing,tls;
    final Map<String,Pending> pending=new ConcurrentHashMap<>();
    final Map<String,AtomicInteger> operations=new ConcurrentHashMap<>();
    final AtomicInteger credentialHeaders=new AtomicInteger(),ssoReplies=new AtomicInteger(),resolutions=new AtomicInteger();
    HttpServer http;HttpsServer https;
    java.util.concurrent.ExecutorService executor;
    record Pending(String mode,String requestId,String issuer,String acs,X509Certificate suiteCertificate,Instant expires) {}

    SyntheticArtifactFixture(int httpPort,int tlsPort,String host,String suiteOrigin)throws Exception {
        require(httpPort>=1024&&httpPort<=65535&&tlsPort>=1024&&tlsPort<=65535&&httpPort!=tlsPort,"Distinct fixture ports required");
        require(Set.of("host.docker.internal","localhost","127.0.0.1").contains(host),"Explicit owned fixture host required");
        this.suiteOrigin=checkedSuiteOrigin(suiteOrigin);
        httpBase="http://"+host+":"+httpPort;tlsBase="https://"+host+":"+tlsPort;
        signing=credentials(false);tls=credentials(true);
    }

    public static void main(String[] args)throws Exception {
        if(args.length==1&&"--self-check".equals(args[0])) {selfCheck();return;}
        if(args.length!=6||!"--prepare".equals(args[0]))throw new IllegalArgumentException("--self-check or --prepare <httpPort> <tlsPort> <publicHost> <Suite origin> <fresh output directory>");
        int httpPort=Integer.parseInt(args[1]),tlsPort=Integer.parseInt(args[2]);
        var fixture=new SyntheticArtifactFixture(httpPort,tlsPort,args[3],args[4]);
        var output=Path.of(args[5]).toAbsolutePath().normalize();fixture.prepare(output);
        System.out.println("READY "+output+"; public files only; no sockets bound; stdin 'serve' required; keys exist only in this process");
        try(var input=new BufferedReader(new InputStreamReader(System.in,StandardCharsets.UTF_8))) {
            String command;
            while((command=input.readLine())!=null) {
                if("serve".equals(command)) {
                    require(fixture.http==null,"Fixture already serving");fixture.serve(httpPort,tlsPort);
                    System.out.println("SERVING "+fixture.httpBase+" "+fixture.tlsBase);
                } else if("stats".equals(command))System.out.println(new JsonCodec().write(fixture.stats()));
                else if("stop".equals(command))break;
                else throw new IllegalArgumentException("Expected serve, stats, or stop");
            }
        } finally {fixture.stop();}
    }

    void prepare(Path output)throws Exception {
        if(Files.exists(output))try(var entries=Files.list(output)){require(entries.findAny().isEmpty(),"Fresh empty preparation directory required");}
        Files.createDirectories(output);
        var store=publicTrustStore(tls.certificate());
        try(var stream=Files.newOutputStream(output.resolve("transport-trust.p12"),StandardOpenOption.CREATE_NEW)) {store.store(stream,PUBLIC_STORE_PASSWORD.toCharArray());}
        var loaded=KeyStore.getInstance("PKCS12");
        try(var stream=Files.newInputStream(output.resolve("transport-trust.p12"))) {loaded.load(stream,PUBLIC_STORE_PASSWORD.toCharArray());}
        requirePublicOnly(loaded,tls.certificate());
        write(output.resolve("transport-certificate.der"),tls.certificate().getEncoded());
        var modes=new LinkedHashMap<String,Object>();
        for(String mode:MODES) {
            var bytes=metadata(mode);write(output.resolve("metadata-"+mode+".xml"),bytes);
            modes.put(mode,Map.of("entityId",entity(mode),"metadataUrl",httpBase+"/"+mode+"/metadata","ssoUrl",httpBase+"/"+mode+"/sso","resolutionUrl",tlsBase+"/"+mode+"/resolve","metadataSha256",hash(bytes)));
        }
        var facts=new LinkedHashMap<String,Object>();facts.put("schema","synthetic-artifact-preparation-v1");facts.put("suiteOrigin",suiteOrigin);facts.put("modes",modes);facts.put("transportCertificateSha256",hash(tls.certificate().getEncoded()));facts.put("trustStoreSha256",hash(Files.readAllBytes(output.resolve("transport-trust.p12"))));facts.put("trustStoreType","PKCS12");facts.put("trustStorePassword",PUBLIC_STORE_PASSWORD);facts.put("trustStoreEntries",loaded.size());facts.put("privateKeyEntries",0);facts.put("privateKeysPersisted",false);facts.put("networkOperations",0);
        write(output.resolve("preparation.json"),new JsonCodec().write(facts).getBytes(StandardCharsets.UTF_8));
    }

    void serve(int httpPort,int tlsPort)throws Exception {
        var memory=KeyStore.getInstance("PKCS12");memory.load(null,null);
        char[] memoryPassword=new char[32];Arrays.fill(memoryPassword,'x');
        memory.setKeyEntry("ephemeral-transport",tls.privateKey(),memoryPassword,new java.security.cert.Certificate[]{tls.certificate()});
        var managers=KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());managers.init(memory,memoryPassword);Arrays.fill(memoryPassword,'\0');
        var context=SSLContext.getInstance("TLS");context.init(managers.getKeyManagers(),null,null);
        executor=Executors.newVirtualThreadPerTaskExecutor();
        http=HttpServer.create(new InetSocketAddress("0.0.0.0",httpPort),0);
        try {
            https=HttpsServer.create(new InetSocketAddress("0.0.0.0",tlsPort),0);https.setHttpsConfigurator(new HttpsConfigurator(context));
            http.createContext("/",this::handle);https.createContext("/",this::handle);http.setExecutor(executor);https.setExecutor(executor);
            Runtime.getRuntime().addShutdownHook(new Thread(this::stop));http.start();https.start();
        } catch(Exception failure){stop();throw failure;}
    }
    synchronized void stop(){if(http!=null)http.stop(0);if(https!=null)https.stop(0);if(executor!=null)executor.close();pending.clear();}

    void handle(HttpExchange exchange)throws java.io.IOException {
        var path=exchange.getRequestURI().getPath();operations.computeIfAbsent(exchange.getRequestMethod()+" "+path,k->new AtomicInteger()).incrementAndGet();
        if(List.of("Authorization","Proxy-Authorization","Cookie").stream().anyMatch(name->exchange.getRequestHeaders().getFirst(name)!=null)) {
            credentialHeaders.incrementAndGet();send(exchange,400,"text/plain","Credentials are not accepted".getBytes(StandardCharsets.UTF_8));return;
        }
        try {
            require(exchange.getRequestURI().getRawQuery()==null||path.endsWith("/sso"),"Unexpected query");
            if("/stats".equals(path)&&"GET".equals(exchange.getRequestMethod())&&!(exchange instanceof com.sun.net.httpserver.HttpsExchange)) {
                send(exchange,200,"application/json",new JsonCodec().write(stats()).getBytes(StandardCharsets.UTF_8));return;
            }
            var segments=path.split("/",-1);require(segments.length==3&&MODES.contains(segments[1]),"Unknown fixture route");String mode=segments[1];
            if("metadata".equals(segments[2])&&"GET".equals(exchange.getRequestMethod())&&!(exchange instanceof com.sun.net.httpserver.HttpsExchange))send(exchange,200,"application/samlmetadata+xml",metadata(mode));
            else if("sso".equals(segments[2])&&!(exchange instanceof com.sun.net.httpserver.HttpsExchange))sso(exchange,mode);
            else if("resolve".equals(segments[2])&&"POST".equals(exchange.getRequestMethod())&&exchange instanceof com.sun.net.httpserver.HttpsExchange)resolve(exchange,mode);
            else send(exchange,405,"text/plain",new byte[0]);
        } catch(Exception invalid){send(exchange,400,"text/plain","Invalid synthetic fixture request".getBytes(StandardCharsets.UTF_8));}
    }

    void sso(HttpExchange exchange,String mode)throws Exception {
        var method=exchange.getRequestMethod();require(Set.of("GET","POST").contains(method),"SSO method unsupported");
        Map<String,String> fields;
        if("GET".equals(method))fields=fields(exchange.getRequestURI().getRawQuery());
        else {
            require(exchange.getRequestURI().getRawQuery()==null&&form(exchange.getRequestHeaders().getFirst("Content-Type")),"POST form required");
            fields=fields(new String(boundedBody(exchange),StandardCharsets.UTF_8));
        }
        require(fields.keySet().containsAll(Set.of("SAMLRequest","RelayState"))&&Set.of("SAMLRequest","RelayState","SigAlg","Signature").containsAll(fields.keySet()),"Unexpected SSO fields");
        var bytes=Base64.getDecoder().decode(fields.get("SAMLRequest"));
        if("GET".equals(method))try(var inflater=new InflaterInputStream(new ByteArrayInputStream(bytes),new Inflater(true))) {bytes=inflater.readNBytes(MAX_BYTES+1);}
        require(bytes.length>0&&bytes.length<=MAX_BYTES,"Invalid AuthnRequest size");
        var request=SecureXml.parse(bytes).getDocumentElement();var relay=fields.get("RelayState");
        String issuer=requestIssuer(request),acs=request.getAttribute("AssertionConsumerServiceURL"),binding=request.getAttribute("ProtocolBinding");
        require(P.equals(request.getNamespaceURI())&&"AuthnRequest".equals(request.getLocalName())&&"2.0".equals(request.getAttribute("Version"))&&!request.getAttribute("ID").isBlank(),"AuthnRequest required");
        require((httpBase+"/"+mode+"/sso").equals(request.getAttribute("Destination")),"Wrong synthetic Destination");
        checkSuite(issuer,acs);var active=ActiveProbeCorrelation.parse(relay);
        if(active.isPresent())require(("_"+active.orElseThrow().actionId()).equals(request.getAttribute("ID")),"Wrong active correlation");
        else require(relay.matches("run_[0-9A-HJKMNP-TV-Z]{26}"),"Run RelayState required");
        byte[] response;
        if(active.isPresent()) {
            var suiteCertificate=embeddedCertificate(request);require(new XmlSignatureVerifier().hasValidEnvelopedSignature(request,suiteCertificate),"Signed active request required");
            if(ARTIFACT.equals(binding)) {
                require(acs.endsWith("/sp/acs/4"),"Artifact ACS required");
                var artifact=artifact(mode);var slot=new Pending(mode,request.getAttribute("ID"),issuer,acs,suiteCertificate,Instant.now().plusSeconds(600));
                require(pending.putIfAbsent(artifact.base64(),slot)==null,"Artifact collision");
                response=page(acs,"SAMLart",artifact.base64(),relay);ssoReplies.incrementAndGet();send(exchange,200,"text/html; charset=utf-8",response);return;
            }
            require(acs.endsWith("/sp/acs/0"),"Binding control ACS required");
            response=response(mode,request.getAttribute("ID"),issuer,acs,POST.equals(binding),true);
        } else response=response(mode,request.getAttribute("ID"),issuer,acs,true,true);
        ssoReplies.incrementAndGet();send(exchange,200,"text/html; charset=utf-8",page(acs,"SAMLResponse",Base64.getEncoder().encodeToString(response),relay));
    }

    void resolve(HttpExchange exchange,String mode)throws Exception {
        require("\"http://www.oasis-open.org/committees/security\"".equals(exchange.getRequestHeaders().getFirst("SOAPAction")),"SOAPAction required");
        var raw=boundedBody(exchange);var protocol=new ArtifactResolutionProtocol();var request=protocol.soapMessage(raw,"ArtifactResolve");
        var artifact=SamlArtifact.parse(single(request,P,"Artifact").getTextContent());var slot=pending.remove(artifact.base64());
        require(slot!=null&&mode.equals(slot.mode())&&Instant.now().isBefore(slot.expires()),"Unknown or consumed Artifact");
        var endpoint=URI.create(tlsBase+"/"+mode+"/resolve");
        protocol.verifyResolve(raw,artifact,request.getAttribute("ID"),endpoint,slot.issuer(),slot.suiteCertificate());
        var reply=artifactResponse(slot,request.getAttribute("ID"));resolutions.incrementAndGet();send(exchange,200,"text/xml; charset=utf-8",reply);
    }

    byte[] metadata(String mode)throws Exception {
        require(MODES.contains(mode),"Unknown mode");String cert=Base64.getEncoder().encodeToString(signing.certificate().getEncoded());
        return ("<md:EntityDescriptor xmlns:md='"+MD+"' xmlns:ds='"+DS+"' entityID='"+entity(mode)+"'><md:IDPSSODescriptor protocolSupportEnumeration='"+P+"' WantAuthnRequestsSigned='true'><md:KeyDescriptor use='signing'><ds:KeyInfo><ds:X509Data><ds:X509Certificate>"+cert+"</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:ArtifactResolutionService index='7' Binding='"+SamlArtifact.SOAP+"' Location='"+tlsBase+"/"+mode+"/resolve'/><md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat><md:SingleSignOnService Binding='"+POST+"' Location='"+httpBase+"/"+mode+"/sso'/><md:SingleSignOnService Binding='"+REDIRECT+"' Location='"+httpBase+"/"+mode+"/sso'/></md:IDPSSODescriptor></md:EntityDescriptor>").getBytes(StandardCharsets.UTF_8);
    }
    String entity(String mode){return httpBase+"/"+mode+"/entity";}
    SamlArtifact artifact(String mode)throws Exception {return SamlArtifact.parse(Base64.getEncoder().encodeToString(ByteBuffer.allocate(44).putShort((short)4).putShort((short)7).put(MessageDigest.getInstance("SHA-1").digest(entity(mode).getBytes(StandardCharsets.UTF_8))).put(randomBytes(20)).array()));}

    byte[] response(String mode,String requestId,String issuer,String acs,boolean success,boolean signed) {
        var now=Instant.now();var expires=now.plusSeconds(300).toString();String id="_synthetic_response_"+random();
        String assertion=success?"<a:Assertion ID='_synthetic_assertion_"+random()+"' Version='2.0' IssueInstant='"+now+"'><a:Issuer>"+escape(entity(mode))+"</a:Issuer><a:Subject><a:NameID Format='urn:oasis:names:tc:SAML:2.0:nameid-format:transient'>synthetic-public-principal</a:NameID><a:SubjectConfirmation Method='urn:oasis:names:tc:SAML:2.0:cm:bearer'><a:SubjectConfirmationData Recipient='"+escape(acs)+"' InResponseTo='"+escape(requestId)+"' NotOnOrAfter='"+expires+"'/></a:SubjectConfirmation></a:Subject><a:Conditions NotBefore='"+now.minusSeconds(60)+"' NotOnOrAfter='"+expires+"'><a:AudienceRestriction><a:Audience>"+escape(issuer)+"</a:Audience></a:AudienceRestriction></a:Conditions><a:AuthnStatement AuthnInstant='"+now+"' SessionIndex='_synthetic_session_"+random()+"'><a:AuthnContext><a:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</a:AuthnContextClassRef></a:AuthnContext></a:AuthnStatement></a:Assertion>":"";
        var document=SecureXml.parse(("<p:Response xmlns:p='"+P+"' xmlns:a='"+A+"' ID='"+id+"' Version='2.0' IssueInstant='"+now+"' InResponseTo='"+escape(requestId)+"' Destination='"+escape(acs)+"'><a:Issuer>"+escape(entity(mode))+"</a:Issuer><p:Status><p:StatusCode Value='"+(success?SUCCESS:"urn:oasis:names:tc:SAML:2.0:status:Responder")+"'/></p:Status>"+assertion+"</p:Response>").getBytes(StandardCharsets.UTF_8));
        if(signed)new XmlSigner().sign(document.getDocumentElement(),signing,single(document.getDocumentElement(),P,"Status"));
        return SecureXml.serialize(document);
    }
    byte[] artifactResponse(Pending slot,String resolveId) {
        var document=SecureXml.parse(("<soap:Envelope xmlns:soap='"+ArtifactResolutionProtocol.SOAP+"' xmlns:p='"+P+"' xmlns:a='"+A+"'><soap:Body><p:ArtifactResponse ID='_synthetic_artifact_response_"+random()+"' Version='2.0' IssueInstant='"+Instant.now()+"' InResponseTo='"+escape(resolveId)+"'><a:Issuer>"+escape(entity(slot.mode()))+"</a:Issuer><p:Status><p:StatusCode Value='"+SUCCESS+"'/></p:Status></p:ArtifactResponse></soap:Body></soap:Envelope>").getBytes(StandardCharsets.UTF_8));
        var outer=single(single(document.getDocumentElement(),ArtifactResolutionProtocol.SOAP,"Body"),P,"ArtifactResponse");
        outer.appendChild(document.importNode(SecureXml.parse(response(slot.mode(),slot.requestId(),slot.issuer(),slot.acs(),true,false)).getDocumentElement(),true));
        if("signed".equals(slot.mode()))new XmlSigner().sign(outer,signing,single(outer,P,"Status"));
        return SecureXml.serialize(document);
    }
    Map<String,Object> stats(){var counts=new TreeMap<String,Integer>();operations.forEach((name,count)->counts.put(name,count.get()));return Map.of("schema","synthetic-artifact-fixture-v1","operations",counts,"credentialHeaders",credentialHeaders.get(),"ssoReplies",ssoReplies.get(),"resolutions",resolutions.get(),"pendingArtifacts",pending.size(),"privateKeysPersisted",false,"productSettingWrites",0,"productCredentialPosts",0);}

    static String checkedSuiteOrigin(String value) {var uri=URI.create(value);require(Set.of("http","https").contains(uri.getScheme())&&Set.of("localhost","127.0.0.1").contains(uri.getHost())&&uri.getRawUserInfo()==null&&uri.getRawQuery()==null&&uri.getRawFragment()==null&&Set.of("","/").contains(uri.getPath()),"Explicit Suite loopback origin required");return value.replaceAll("/$","");}
    void checkSuite(String issuer,String acs){require(issuer.startsWith(suiteOrigin+"/p/")&&issuer.substring((suiteOrigin+"/p/").length()).matches("plan_[0-9A-HJKMNP-TV-Z]{26}")&&acs.matches(java.util.regex.Pattern.quote(issuer)+"/sp/acs/(0|4)"),"Actual Suite Plan and ACS required");}
    static String requestIssuer(Element request){return single(request,A,"Issuer").getTextContent();}
    static X509Certificate embeddedCertificate(Element request)throws Exception {var signature=single(request,DS,"Signature");var value=single(single(single(signature,DS,"KeyInfo"),DS,"X509Data"),DS,"X509Certificate").getTextContent().replaceAll("\\s","");return (X509Certificate)CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(Base64.getDecoder().decode(value)));}
    static byte[] boundedBody(HttpExchange exchange)throws Exception {var raw=exchange.getRequestBody().readNBytes(MAX_BYTES+1);require(raw.length>0&&raw.length<=MAX_BYTES,"Invalid request size");return raw;}
    static boolean form(String type){return type!=null&&"application/x-www-form-urlencoded".equalsIgnoreCase(type.split(";",2)[0].trim());}
    static Map<String,String> fields(String raw){require(raw!=null&&raw.length()<=2*MAX_BYTES,"Form required");var fields=new LinkedHashMap<String,String>();for(String pair:raw.split("&",-1)){int at=pair.indexOf('=');require(at>0,"Malformed form");String name=URLDecoder.decode(pair.substring(0,at),StandardCharsets.UTF_8),value=URLDecoder.decode(pair.substring(at+1),StandardCharsets.UTF_8);require(fields.putIfAbsent(name,value)==null,"Duplicate field");}return fields;}
    static byte[] page(String acs,String field,String value,String relay){String html="<!doctype html><meta charset='utf-8'><form method='post' action='"+escape(acs)+"'><input type='hidden' name='"+field+"' value='"+escape(value)+"'><input type='hidden' name='RelayState' value='"+escape(relay)+"'><button type='submit'>Return synthetic response to Suite</button></form>";return html.getBytes(StandardCharsets.UTF_8);}
    static void send(HttpExchange exchange,int status,String type,byte[] body)throws java.io.IOException {exchange.getResponseHeaders().set("Content-Type",type);exchange.getResponseHeaders().set("Cache-Control","no-store");exchange.sendResponseHeaders(status,body.length==0?-1:body.length);if(body.length>0)exchange.getResponseBody().write(body);exchange.close();}
    static Element single(Element root,String ns,String local){var nodes=new ArrayList<Element>();for(var node=root.getFirstChild();node!=null;node=node.getNextSibling())if(node instanceof Element child&&ns.equals(child.getNamespaceURI())&&local.equals(child.getLocalName()))nodes.add(child);require(nodes.size()==1,"Missing or duplicate "+local);return nodes.getFirst();}
    static String escape(String value){return value.replace("&","&amp;").replace("'","&apos;").replace("\"","&quot;").replace("<","&lt;").replace(">","&gt;");}
    static byte[] randomBytes(int count){var bytes=new byte[count];new SecureRandom().nextBytes(bytes);return bytes;}
    static String random(){return HexFormat.of().formatHex(randomBytes(16));}
    static String hash(byte[] bytes)throws Exception {return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));}
    static void write(Path file,byte[] bytes)throws Exception {Files.write(file,bytes,StandardOpenOption.CREATE_NEW);}
    static void require(boolean value,String message){if(!value)throw new IllegalArgumentException(message);}
    static KeyStore publicTrustStore(X509Certificate certificate)throws Exception {var store=KeyStore.getInstance("PKCS12");store.load(null,null);store.setCertificateEntry("synthetic-artifact-transport-public",certificate);requirePublicOnly(store,certificate);return store;}
    static void requirePublicOnly(KeyStore store,X509Certificate certificate)throws Exception {require(store.size()==1,"Unexpected truststore entries");for(var names=store.aliases();names.hasMoreElements();){String name=names.nextElement();require(!store.isKeyEntry(name)&&store.isCertificateEntry(name)&&Arrays.equals(certificate.getEncoded(),store.getCertificate(name).getEncoded()),"Truststore must contain only the public transport certificate");}}
    static PlanCredentials credentials(boolean transport)throws Exception {
        if(Security.getProvider("BC")==null)Security.addProvider(new BouncyCastleProvider());
        var generator=KeyPairGenerator.getInstance("RSA");generator.initialize(2048);var pair=generator.generateKeyPair();var now=Instant.now();
        var name=new X500Name("CN=Synthetic SAMLscope "+(transport?"TLS":"SAML")+" fixture (DO NOT TRUST)");
        var builder=new JcaX509v3CertificateBuilder(name,new BigInteger(160,new SecureRandom()).abs(),Date.from(now.minusSeconds(300)),Date.from(now.plusSeconds(86400)),name,pair.getPublic());
        builder.addExtension(Extension.basicConstraints,true,new BasicConstraints(false));builder.addExtension(Extension.keyUsage,true,new KeyUsage(transport?KeyUsage.digitalSignature|KeyUsage.keyEncipherment:KeyUsage.digitalSignature));
        if(transport){builder.addExtension(Extension.extendedKeyUsage,false,new ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth));builder.addExtension(Extension.subjectAlternativeName,false,new GeneralNames(new GeneralName[]{new GeneralName(GeneralName.dNSName,"host.docker.internal"),new GeneralName(GeneralName.dNSName,"localhost"),new GeneralName(GeneralName.iPAddress,"127.0.0.1")}));}
        var certificate=new JcaX509CertificateConverter().setProvider("BC").getCertificate(builder.build(new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC").build(pair.getPrivate())));certificate.verify(pair.getPublic());
        return new PlanCredentials(pair.getPrivate(),certificate);
    }

    static void selfCheck()throws Exception {
        var fixture=new SyntheticArtifactFixture(18937,18938,"host.docker.internal","http://localhost:18080");
        var store=publicTrustStore(fixture.tls.certificate());var managers=TrustManagerFactory.getInstance("PKIX");managers.init(store);
        ((X509TrustManager)managers.getTrustManagers()[0]).checkServerTrusted(new X509Certificate[]{fixture.tls.certificate()},"RSA");
        var alternatives=fixture.tls.certificate().getSubjectAlternativeNames();require(alternatives.contains(List.of(2,"host.docker.internal"))&&alternatives.contains(List.of(2,"localhost"))&&alternatives.contains(List.of(7,"127.0.0.1")),"TLS SANs missing");
        var directory=Files.createTempDirectory("samlscope-public-artifact-selfcheck-");
        try {
            fixture.prepare(directory);
            for(String mode:MODES){var metadata=fixture.metadata(mode);new TargetMetadataParser().parse(metadata,fixture.entity(mode));var artifact=fixture.artifact(mode);require(artifact.resolutionEndpoint(metadata,fixture.entity(mode)).equals(URI.create(fixture.tlsBase+"/"+mode+"/resolve")),"Artifact endpoint mismatch");
                var slot=new Pending(mode,"_authn","http://localhost:18080/p/plan_0123456789ABCDEFGHJKMNPQRS","http://localhost:18080/p/plan_0123456789ABCDEFGHJKMNPQRS/sp/acs/4",fixture.signing.certificate(),Instant.now().plusSeconds(600));var raw=fixture.artifactResponse(slot,"_resolve");var protocol=new ArtifactResolutionProtocol();
                if("signed".equals(mode)){var proof=protocol.verifyResponse(raw,"_resolve","_authn",fixture.entity(mode),URI.create(slot.acs()),List.of(fixture.signing.certificate()));require("trusted-xml-signature".equals(proof.authentication()),"Signed proof missing");new OpenSamlReader().read(proof.responseXml());}
                else {require(single(protocol.soapMessage(raw,"ArtifactResponse"),P,"Response").getElementsByTagNameNS(DS,"Signature").getLength()==0,"TLS mode must have no inner signature");try{protocol.verifyResponse(raw,"_resolve","_authn",fixture.entity(mode),URI.create(slot.acs()),List.of(fixture.signing.certificate()));throw new AssertionError("Unsigned response accepted without actual TLS evidence");}catch(IllegalArgumentException expected){}}
            }
            require(fixture.http==null&&fixture.https==null&&fixture.operations.isEmpty(),"Self-check bound a socket or sent HTTP");
            System.out.println("{\"selfCheck\":\"passed\",\"networkOperations\":0,\"runsCreated\":0,\"privateKeysPersisted\":false,\"certificateOnlyTrustStore\":true,\"actualTlsNotExercised\":true}");
        } finally {try(var entries=Files.list(directory)){for(var file:entries.toList())Files.delete(file);}Files.delete(directory);}
    }
}
