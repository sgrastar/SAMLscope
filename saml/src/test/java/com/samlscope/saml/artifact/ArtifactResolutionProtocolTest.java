package com.samlscope.saml.artifact;

import static org.junit.jupiter.api.Assertions.*;
import java.net.URI;
import java.nio.file.Path;
import java.time.*;
import java.util.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import com.samlscope.saml.crypto.*;
import com.samlscope.saml.normal.SecureXml;
import org.w3c.dom.Element;

class ArtifactResolutionProtocolTest {
    @TempDir Path folder;
    final ArtifactResolutionProtocol protocol=new ArtifactResolutionProtocol();
    static final String TARGET=SamlArtifactTest.TARGET;
    static final URI ENDPOINT=URI.create("https://idp.example/resolve"),ACS=URI.create("https://suite.example/sp/acs/4");
    static final Instant NOW=Instant.parse("2026-10-08T00:00:00Z");
    PlanCredentials suite,target,foreign;
    @BeforeEach void setup(){var store=new FilePlanKeyStore(folder,Clock.fixed(NOW,ZoneOffset.UTC));suite=store.getOrCreate("plan_0123456789ABCDEFGHJKMNPQRS");target=store.getOrCreate("plan_0123456789ABCDEFGHJKMNPQRS","target");foreign=store.getOrCreate("plan_0123456789ABCDEFGHJKMNPQRS","foreign");}
    @Test void resolveIsSignedAndBindsTheExactArtifactRecipientAndDestination()throws Exception{
        var a=SamlArtifact.parse(SamlArtifactTest.artifact(3,true));var bytes=protocol.resolve(a,"_resolve",ENDPOINT,"https://suite.example/sp",NOW,suite);
        protocol.verifyResolve(bytes,a,"_resolve",ENDPOINT,"https://suite.example/sp",suite.certificate());
        assertThrows(IllegalArgumentException.class,()->protocol.verifyResolve(bytes,a,"_other",ENDPOINT,"https://suite.example/sp",suite.certificate()));
        assertThrows(IllegalArgumentException.class,()->protocol.verifyResolve(bytes,a,"_resolve",URI.create("https://other.example"),"https://suite.example/sp",suite.certificate()));
        assertThrows(IllegalArgumentException.class,()->protocol.verifyResolve(bytes,a,"_resolve",ENDPOINT,"https://suite.example/sp",foreign.certificate()));
    }
    @Test void authenticatedArtifactWrapperBindsTwoDistinctResponseCorrelations(){
        var raw=response("_resolve","_authn",ACS,TARGET,"Success",true,false);
        var proof=verify(raw);assertEquals(ArtifactResolutionProtocol.SUCCESS,proof.status());assertEquals("trusted-xml-signature",proof.authentication());
        assertEquals("_authn",SecureXml.parse(proof.responseXml()).getDocumentElement().getAttribute("InResponseTo"));assertTrue(proof.originalSoapSha256().matches("[0-9a-f]{64}"));
    }
    @Test void wrongResolveAuthnDestinationIssuerOrSigningKeyCannotBeAdopted(){
        assertThrows(IllegalArgumentException.class,()->verify(response("_other","_authn",ACS,TARGET,"Success",true,false)));
        assertThrows(IllegalArgumentException.class,()->verify(response("_resolve","_other",ACS,TARGET,"Success",true,false)));
        assertThrows(IllegalArgumentException.class,()->verify(response("_resolve","_authn",URI.create("https://other.example/acs"),TARGET,"Success",true,false)));
        assertThrows(IllegalArgumentException.class,()->verify(response("_resolve","_authn",ACS,"https://other.example/entity","Success",true,false)));
        var original=target;target=foreign;var raw=response("_resolve","_authn",ACS,TARGET,"Success",true,false);target=original;assertThrows(IllegalArgumentException.class,()->verify(raw));
    }
    @Test void unsignedOrCorruptedRepliesAndEmptyArtifactsStayUnproven(){
        assertThrows(IllegalArgumentException.class,()->verify(response("_resolve","_authn",ACS,TARGET,"Success",false,false)));
        var raw=response("_resolve","_authn",ACS,TARGET,"Success",true,false);var root=protocol.soapMessage(raw,"ArtifactResponse");root.setAttribute("ID","_tampered");assertThrows(IllegalArgumentException.class,()->verify(SecureXml.serialize(root.getOwnerDocument())));
        assertThrows(IllegalArgumentException.class,()->verify(response("_resolve","_authn",ACS,TARGET,"Success",true,true)));
    }
    @Test void nestedDuplicateBodiesIdsAndMessagesAreRejectedBeforeTheyCanMaskAResponse(){
        var raw=response("_resolve","_authn",ACS,TARGET,"Success",true,false);
        var doc=SecureXml.parse(raw);var envelope=doc.getDocumentElement();envelope.appendChild(envelope.getFirstChild().cloneNode(true));assertThrows(IllegalArgumentException.class,()->verify(SecureXml.serialize(doc)));
        var outer=protocol.soapMessage(raw,"ArtifactResponse");var inner=SamlArtifact.children(outer,ArtifactResolutionProtocol.P,"Response").getFirst();inner.setAttribute("ID",outer.getAttribute("ID"));assertThrows(IllegalArgumentException.class,()->verify(SecureXml.serialize(outer.getOwnerDocument())));
    }
    @Test void derivedResponsePreservesAncestorQNameAndXmlContextAfterOriginalSignatureVerification(){
        var raw=response("_resolve","_authn",ACS,TARGET,"Success",false,false);
        var outer=protocol.soapMessage(raw,"ArtifactResponse");var envelope=outer.getOwnerDocument().getDocumentElement();
        envelope.setAttributeNS("http://www.w3.org/2000/xmlns/","xmlns:choice","urn:fixture:choice");
        envelope.setAttributeNS("http://www.w3.org/XML/1998/namespace","xml:lang","ja");
        envelope.setAttributeNS("http://www.w3.org/XML/1998/namespace","xml:base","https://idp.example/context/");
        var extensions=outer.getOwnerDocument().createElementNS(ArtifactResolutionProtocol.P,"samlp:Extensions");outer.insertBefore(extensions,outer.getFirstChild());
        new XmlSigner().sign(outer,target,null);raw=SecureXml.serialize(outer.getOwnerDocument());
        var proof=verify(raw);var derived=SecureXml.parse(proof.responseXml()).getDocumentElement();
        assertEquals("urn:fixture:choice",derived.lookupNamespaceURI("choice"));
        assertEquals("ja",derived.getAttributeNS("http://www.w3.org/XML/1998/namespace","lang"));
        assertEquals("https://idp.example/context/",derived.getBaseURI());
        assertEquals(SamlArtifact.hash("SHA-256",raw),proof.originalSoapSha256());
    }
    private ArtifactResolutionProtocol.ResolvedResponse verify(byte[] raw){return protocol.verifyResponse(raw,"_resolve","_authn",TARGET,ACS,List.of(target.certificate()));}
    byte[] response(String resolve,String authn,URI acs,String issuer,String status,boolean sign,boolean empty){
        var d=SecureXml.newDocument();var env=d.createElementNS(ArtifactResolutionProtocol.SOAP,"soap:Envelope");env.setAttributeNS("http://www.w3.org/2000/xmlns/","xmlns:soap",ArtifactResolutionProtocol.SOAP);d.appendChild(env);var body=d.createElementNS(ArtifactResolutionProtocol.SOAP,"soap:Body");env.appendChild(body);
        var outer=d.createElementNS(ArtifactResolutionProtocol.P,"samlp:ArtifactResponse");outer.setAttributeNS("http://www.w3.org/2000/xmlns/","xmlns:samlp",ArtifactResolutionProtocol.P);outer.setAttributeNS("http://www.w3.org/2000/xmlns/","xmlns:saml",ArtifactResolutionProtocol.A);body.appendChild(outer);attributes(outer,"_outer",resolve);issuer(outer,issuer);status(outer,"Success");
        if(!empty){var inner=d.createElementNS(ArtifactResolutionProtocol.P,"samlp:Response");outer.appendChild(inner);attributes(inner,"_inner",authn);inner.setAttribute("Destination",acs.toString());issuer(inner,issuer);status(inner,status);var assertion=d.createElementNS(ArtifactResolutionProtocol.A,"saml:Assertion");assertion.setAttribute("ID","_assertion");inner.appendChild(assertion);}
        if(sign)new XmlSigner().sign(outer,target,null);return SecureXml.serialize(d);
    }
    void attributes(Element e,String id,String response){e.setAttribute("ID",id);e.setAttribute("Version","2.0");e.setAttribute("InResponseTo",response);e.setAttribute("IssueInstant",NOW.toString());}
    void issuer(Element e,String value){var issuer=e.getOwnerDocument().createElementNS(ArtifactResolutionProtocol.A,"saml:Issuer");issuer.setTextContent(value);e.appendChild(issuer);}
    void status(Element e,String value){var status=e.getOwnerDocument().createElementNS(ArtifactResolutionProtocol.P,"samlp:Status");e.appendChild(status);var code=e.getOwnerDocument().createElementNS(ArtifactResolutionProtocol.P,"samlp:StatusCode");code.setAttribute("Value","urn:oasis:names:tc:SAML:2.0:status:"+value);status.appendChild(code);}
}
