package com.samlscope.runner.cases;

import static org.junit.jupiter.api.Assertions.*;
import static com.samlscope.runner.cases.ShibbolethPublisherEndpointInventoryAdapter.*;
import com.samlscope.saml.normal.SecureXml;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

class ShibbolethPublisherEndpointInventoryAdapterTest {
    static final String RUN="run_0123456789ABCDEFGHJKMNPQRS",ENTITY="http://localhost:18080/p/plan_0123456789ABCDEFGHJKMNPQRS";
    static byte[] bytes(String s){return s.getBytes(StandardCharsets.UTF_8);}
    static String rp(String extra){return "<beans xmlns='"+BEANS+"' xmlns:util='"+UTIL+"' xmlns:c='http://www.springframework.org/schema/c' xmlns:p='http://www.springframework.org/schema/p'><bean id='existing' parent='RelyingParty'/><util:list id='shibboleth.RelyingPartyOverrides'>"+extra+"</util:list></beans>";}
    static String peer(){return "<bean id='PublisherEndpointPeer' parent='RelyingPartyByName' c:relyingPartyIds='"+ENTITY+"'><property name='profileConfigurations'><list><bean parent='SAML2.SSO' p:signResponses='true'/><ref bean='SAML2.ECP'/><ref bean='SAML2.Logout'/><ref bean='SAML2.ArtifactResolution'/></list></property></bean>";}
    static String providers(String extra){return "<MetadataProvider xmlns='urn:mace:shibboleth:2.0:metadata' xmlns:xsi='http://www.w3.org/2001/XMLSchema-instance' id='chain' xsi:type='ChainingMetadataProvider'>"+extra+"<MetadataProvider id='existing' xsi:type='FilesystemMetadataProvider' metadataFile='/existing.xml'/></MetadataProvider>";}
    static String registration(){return "<MetadataProvider id='PublisherEndpoint"+RUN+"' xsi:type='FilesystemMetadataProvider' metadataFile='"+ROOT+"metadata/publisher-endpoint-"+RUN+".xml'/>";}
    static void validate(String newRp,String newProviders)throws Exception {validateMinimalPeerTransition(bytes(rp("")),bytes(newRp),bytes(providers("")),bytes(newProviders),ENTITY,RUN);}
    @Test void onlyFreshPeerSigningAndRegistrationAreAllowed()throws Exception {validate(rp(peer()),providers(registration()));}
    @Test void unrelatedRelyingPartyChangeCannotHideBehindFreshRegistration(){assertThrows(IllegalArgumentException.class,()->validate(rp(peer()).replace("parent='RelyingParty'","parent='UnverifiedParty'"),providers(registration())));}
    @Test void peerEndpointOrSecurityOverrideIsRejected(){assertThrows(IllegalArgumentException.class,()->validate(rp(peer().replace("parent='RelyingPartyByName'","parent='RelyingPartyByName' p:securityConfiguration='other'")),providers(registration())));}
    @Test void onlyApprovedNativeProfileSetIsAllowed(){assertThrows(IllegalArgumentException.class,()->validate(rp(peer().replace("SAML2.ECP","SAML2.Other")),providers(registration())));}
    @Test void foreignPeerFileDoesNotProveTheSuiteRegisteredPeer(){assertThrows(IllegalArgumentException.class,()->validate(rp(peer()),providers(registration().replace("publisher-endpoint-"+RUN,"foreign"))));}
    @Test void additionalMetadataProviderIsNotARegistrationOnlyTransition(){assertThrows(IllegalArgumentException.class,()->validate(rp(peer()),providers(registration()+"<MetadataProvider id='unbounded' xsi:type='FilesystemMetadataProvider' metadataFile='/other.xml'/>")));}
    @Test void duplicateFreshPeerCannotSelectAnAmbiguousConfiguration(){assertThrows(IllegalArgumentException.class,()->validate(rp(peer()+peer()),providers(registration())));}
    @Test void projectionPreservesNamespacesAttributesOrderAndText()throws Exception {
        var a=SecureXml.parse(bytes("<a xmlns='urn:test' x='1'><b>value</b><c/></a>")).getDocumentElement();
        var same=SecureXml.parse(bytes("<n:a xmlns:n='urn:test' x='1'>\n<n:b>value</n:b><n:c/>\n</n:a>")).getDocumentElement();assertEquals(tree(a),tree(same));
        for(String s:new String[]{"<a xmlns='urn:other' x='1'><b>value</b><c/></a>","<a xmlns='urn:test' x='2'><b>value</b><c/></a>","<a xmlns='urn:test' x='1'><c/><b>value</b></a>","<a xmlns='urn:test' x='1'><b>changed</b><c/></a>"})assertNotEquals(tree(a),tree(SecureXml.parse(bytes(s)).getDocumentElement()));
    }
    @Test void projectionCannotConfuseOneDelimitedTextValueWithTwoNodes()throws Exception {
        var a=SecureXml.parse(bytes("<a>first, second</a>")).getDocumentElement();var b=SecureXml.parse(bytes("<a>first<!-- split -->second</a>")).getDocumentElement();assertNotEquals(tree(a),tree(b));
    }
}
