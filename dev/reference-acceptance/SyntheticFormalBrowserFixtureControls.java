package com.samlscope.api;

import com.samlscope.runner.ActiveProbeCorrelation;
import com.samlscope.saml.binding.SignedRedirectEncoder;
import com.samlscope.saml.crypto.*;
import com.samlscope.saml.metadata.MetadataService;
import com.samlscope.saml.normal.SecureXml;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.*;

/** Offline controls using only freshly generated RAM credentials and public synthetic messages. */
public final class SyntheticFormalBrowserFixtureControls {
    static final String ISSUER="http://localhost:18080/p/plan_0123456789ABCDEFGHJKMNPQRS", RUN="run_0123456789ABCDEFGHJKMNPQRS";
    static int checks;
    static void check(boolean value,String message){if(!value)throw new IllegalStateException(message);checks++;}
    interface Checked {void run()throws Exception;}
    static void reject(Checked operation,String message)throws Exception{try{operation.run();throw new IllegalStateException(message);}catch(IllegalArgumentException|NoSuchElementException expected){checks++;}}
    static byte[] metadata(PlanCredentials keys)throws Exception {
        String cert=Base64.getEncoder().encodeToString(keys.certificate().getEncoded());
        return ("<md:EntityDescriptor xmlns:md='"+MetadataService.MD+"' xmlns:ds='"+MetadataService.DS+"' entityID='"+ISSUER+"'><md:SPSSODescriptor protocolSupportEnumeration='"+SyntheticFormalBrowserFixture.P+"'><md:KeyDescriptor use='signing'><ds:KeyInfo><ds:X509Data><ds:X509Certificate>"+cert+"</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:AssertionConsumerService Binding='"+MetadataService.POST+"' Location='"+ISSUER+"/sp/acs/0' index='0' isDefault='true'/><md:AssertionConsumerService Binding='"+MetadataService.POST+"' Location='"+ISSUER+"/sp/acs/1' index='1'/></md:SPSSODescriptor></md:EntityDescriptor>").getBytes(StandardCharsets.UTF_8);
    }
    static String query(PlanCredentials suite,String mode,String id,String relay,String fields)throws Exception {
        byte[] xml=("<p:AuthnRequest xmlns:p='"+SyntheticFormalBrowserFixture.P+"' xmlns:a='"+SyntheticFormalBrowserFixture.A+"' ID='"+id+"' Version='2.0' IssueInstant='2026-10-08T00:00:00Z' "+fields+"><a:Issuer>"+ISSUER+"</a:Issuer></p:AuthnRequest>").getBytes(StandardCharsets.UTF_8);
        return new SignedRedirectEncoder().encode(URI.create("http://host.docker.internal:18946/sso/"+mode),xml,relay,suite).rawQuery();
    }
    static byte[] post(PlanCredentials keys,char token,String attributes)throws Exception {
        var doc=SecureXml.parse(("<p:AuthnRequest xmlns:p='"+SyntheticFormalBrowserFixture.P+"' xmlns:a='"+SyntheticFormalBrowserFixture.A+"' ID='"+id(token)+"' Version='2.0' IssueInstant='2026-10-08T00:00:00Z' "+attributes+"><a:Issuer>"+ISSUER+"</a:Issuer></p:AuthnRequest>").getBytes(StandardCharsets.UTF_8));
        new XmlSigner().sign(doc.getDocumentElement(),keys,(org.w3c.dom.Element)doc.getDocumentElement().getFirstChild());
        return ("SAMLRequest="+java.net.URLEncoder.encode(Base64.getEncoder().encodeToString(SecureXml.serialize(doc)),StandardCharsets.UTF_8)+"&RelayState="+java.net.URLEncoder.encode(relay(token),StandardCharsets.UTF_8)).getBytes(StandardCharsets.UTF_8);
    }
    static String relay(char ch){return ActiveProbeCorrelation.encode(RUN,"action_"+String.valueOf(ch).repeat(32));}
    static String id(char ch){return "_action_"+String.valueOf(ch).repeat(32);}
    static String session(SyntheticFormalBrowserFixture.Reply reply){var root=SecureXml.parse(reply.response()).getDocumentElement();return ((org.w3c.dom.Element)root.getElementsByTagNameNS(SyntheticFormalBrowserFixture.A,"AuthnStatement").item(0)).getAttribute("SessionIndex");}
    public static void main(String[] args)throws Exception {if(args.length!=0)throw new IllegalArgumentException("No arguments");run();}
    static void run()throws Exception {
        var suite=SyntheticAdditionalMetadataFixture.credentials();byte[] md=metadata(suite);var fixture=new SyntheticFormalBrowserFixture("http://host.docker.internal:18946","http://localhost:18080",issuer->{check(issuer.equals(ISSUER),"Foreign metadata lookup");return md;});
        for(String mode:SyntheticFormalBrowserFixture.MODES){
            var target=new com.samlscope.saml.metadata.TargetMetadataParser().parse(fixture.metadata(mode),fixture.entity(mode));
            var inactive=URI.create(ISSUER+"/inactive-idp-probe");
            var endpoint=target.singleSignOnServices().stream().filter(e->MetadataService.POST.equals(e.binding())).map(com.samlscope.saml.metadata.TargetMetadata.Endpoint::location).findFirst().orElse(inactive);
            check(endpoint.equals(URI.create("http://host.docker.internal:18946/sso/"+mode))&&!endpoint.equals(inactive)
                &&target.singleSignOnServices().stream().anyMatch(e->MetadataService.REDIRECT.equals(e.binding())&&e.location().equals(endpoint)),"Native metadata did not expose actual POST scenario and Redirect M0 endpoints");
        }
        var normal=fixture.reply("honor",query(suite,"honor","_normal",RUN,"AssertionConsumerServiceURL='"+ISSUER+"/sp/acs/0'"),null);
        check(normal.acs().endsWith("/0")&&normal.issuedSession()!=null,"Normal fixture did not establish owned session");
        var control=fixture.reply("honor",query(suite,"honor",id('a'),relay('a'),""),normal.issuedSession());
        var positive=fixture.reply("honor",query(suite,"honor",id('b'),relay('b'),"AssertionConsumerServiceIndex='1'"),normal.issuedSession());
        check(control.acs().endsWith("/0")&&positive.acs().endsWith("/1"),"Index detection control failed");
        check(session(normal).equals(session(control))&&session(normal).equals(session(positive)),"Existing owned session was not reused");
        check(control.issuedSession()==null&&positive.issuedSession()==null,"Formal requests established new login");
        for(var reply:List.of(normal,control,positive)) {
            var root=SecureXml.parse(reply.response()).getDocumentElement();var assertion=(org.w3c.dom.Element)root.getElementsByTagNameNS(SyntheticFormalBrowserFixture.A,"Assertion").item(0);
            check(new XmlSignatureVerifier().hasValidEnvelopedSignature(root,fixture.key.certificate())&&new XmlSignatureVerifier().hasValidEnvelopedSignature(assertion,fixture.key.certificate()),"Signed originals invalid");
            check(!new String(reply.response(),StandardCharsets.UTF_8).contains(normal.issuedSession()),"Session credential appeared in SAML");
        }
        var postDefault=fixture.reply("honor","POST",null,post(suite,'5',""),normal.issuedSession());
        var postIndex=fixture.reply("honor","POST",null,post(suite,'6',"AssertionConsumerServiceIndex='1'"),normal.issuedSession());
        check(postDefault.acs().endsWith("/0")&&postIndex.acs().endsWith("/1"),"Actual formal POST path does not distinguish index");
        check(session(normal).equals(session(postDefault))&&session(normal).equals(session(postIndex)),"POST did not reuse existing session");
        reject(()->fixture.reply("honor","POST",null,post(SyntheticAdditionalMetadataFixture.credentials(),'7',""),normal.issuedSession()),"Foreign POST signature accepted");
        reject(()->fixture.reply("honor","POST",null,post(suite,'8',""),null),"POST without existing session accepted");
        var fresh=fixture.reply("honor",query(suite,"honor","_fresh_normal",RUN,"AssertionConsumerServiceURL='"+ISSUER+"/sp/acs/0'"),null);
        check(!normal.issuedSession().equals(fresh.issuedSession())&&!session(normal).equals(session(fresh)),"Fresh context mimicked session reuse");
        reject(()->fixture.reply("honor",query(suite,"honor",id('c'),relay('c'),"AssertionConsumerServiceIndex='1'"),null),"Missing session accepted");
        reject(()->fixture.reply("ignore",query(suite,"ignore",id('d'),relay('d'),"AssertionConsumerServiceIndex='1'"),normal.issuedSession()),"Cross-mode session accepted");
        reject(()->fixture.reply("honor",query(suite,"honor",id('e'),ActiveProbeCorrelation.encode("run_1123456789ABCDEFGHJKMNPQRS","action_"+"e".repeat(32)),"AssertionConsumerServiceIndex='1'"),normal.issuedSession()),"Foreign Run session accepted");
        reject(()->fixture.reply("honor",query(suite,"honor",id('b'),relay('b'),"AssertionConsumerServiceIndex='1'"),normal.issuedSession()),"Duplicate one-use request accepted");
        reject(()->fixture.reply("honor",query(SyntheticAdditionalMetadataFixture.credentials(),"honor",id('f'),relay('f'),""),normal.issuedSession()),"Foreign request signature accepted");
        reject(()->fixture.reply("honor",query(suite,"honor",id('1'),relay('1'),"AssertionConsumerServiceIndex='9'"),normal.issuedSession()),"Unknown index accepted");
        reject(()->fixture.reply("honor",query(suite,"honor",id('2'),relay('2'),"AssertionConsumerServiceURL='https://foreign.invalid/acs'"),normal.issuedSession()),"Foreign ACS accepted");
        reject(()->fixture.reply("honor",query(suite,"honor",id('3'),relay('3'),"AssertionConsumerServiceIndex='1' AssertionConsumerServiceURL='"+ISSUER+"/sp/acs/0'"),normal.issuedSession()),"Conflicting ACS accepted");
        reject(()->SyntheticFormalBrowserFixture.ownedSession("other-cookie=secret"),"Foreign cookie accepted");
        reject(()->SyntheticFormalBrowserFixture.ownedSession(SyntheticFormalBrowserFixture.OWNED_COOKIE+"=bad"),"Malformed owned cookie accepted");
        var ignored=fixture.reply("ignore",query(suite,"ignore","_ignore_normal",RUN,"AssertionConsumerServiceURL='"+ISSUER+"/sp/acs/0'"),null);
        var negative=fixture.reply("ignore",query(suite,"ignore",id('4'),relay('4'),"AssertionConsumerServiceIndex='1'"),ignored.issuedSession());
        check(negative.acs().endsWith("/0")&&session(ignored).equals(session(negative)),"Always-default mutant did not preserve controls and violate index selection");
        System.out.println("{\"schema\":\"synthetic-formal-fixture-controls-v1\",\"checksPassed\":"+checks+",\"networkOperations\":0,\"realCredentialReads\":0,\"sessionValuesExported\":false,\"privateKeysPersisted\":false,\"canonicalAdoption\":false}");
    }
}
