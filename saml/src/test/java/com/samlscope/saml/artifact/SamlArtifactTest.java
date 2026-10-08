package com.samlscope.saml.artifact;

import static org.junit.jupiter.api.Assertions.*;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.net.URI;
import java.util.*;
import org.junit.jupiter.api.Test;

class SamlArtifactTest {
    static final String TARGET="https://idp.example/entity";
    static String artifact(int index, boolean recommended) throws Exception {
        var source = MessageDigest.getInstance("SHA-1").digest(TARGET.getBytes(StandardCharsets.UTF_8));
        if (!recommended) Arrays.fill(source,(byte)7);
        var handle = new byte[20]; Arrays.fill(handle,(byte)11);
        return Base64.getEncoder().encodeToString(ByteBuffer.allocate(44).putShort((short)4).putShort((short)index).put(source).put(handle).array());
    }
    static byte[] metadata(String endpoint) {
        return ("<md:EntityDescriptor xmlns:md=\""+SamlArtifact.MD+"\" entityID=\""+TARGET+"\"><md:IDPSSODescriptor protocolSupportEnumeration=\""+SamlArtifact.P+"\">"+endpoint+"</md:IDPSSODescriptor></md:EntityDescriptor>").getBytes(StandardCharsets.UTF_8);
    }
    static String endpoint(int index,String binding,String location) {return "<md:ArtifactResolutionService index=\""+index+"\" Binding=\""+binding+"\" Location=\""+location+"\"/>";}
    @Test void type0004Has44BytesAndAnUnsignedNetworkOrderIndex() throws Exception {
        for(int index:List.of(0,1,255,256,32768,65535)){
            var value=SamlArtifact.parse(artifact(index,true)); assertEquals(44,value.bytes().length);assertEquals(60,value.base64().length());assertEquals(index,value.endpointIndex());assertEquals(20,value.sourceId().length);assertEquals(20,value.messageHandle().length);assertTrue(value.usesRecommendedSourceId(TARGET));
            var copy=value.bytes();copy[0]=5;assertEquals(0,value.bytes()[0]);
        }
    }
    @Test void unsupportedTypesLengthsAndInvalidBase64FailWithoutAVerdict() throws Exception {
        var valid=Base64.getDecoder().decode(artifact(0,true));
        for(int size:List.of(0,42,43,45,46))assertThrows(IllegalArgumentException.class,()->SamlArtifact.parse(Base64.getEncoder().encodeToString(Arrays.copyOf(valid,size))));
        valid[1]=1;assertThrows(IllegalArgumentException.class,()->SamlArtifact.parse(Base64.getEncoder().encodeToString(valid)));
        assertThrows(IllegalArgumentException.class,()->SamlArtifact.parse("!".repeat(60)));
    }
    @Test void opaqueSourceIdDoesNotInventAMandatorySha1Mapping() throws Exception {
        var a=SamlArtifact.parse(artifact(2,false));assertFalse(a.usesRecommendedSourceId(TARGET));
        assertEquals(URI.create("https://idp.example/resolve"),a.resolutionEndpoint(metadata(endpoint(2,SamlArtifact.SOAP,"https://idp.example/resolve")),TARGET));
    }
    @Test void endpointIndexCannotFallBackToDefaultOrAnotherRoleOrEntity() throws Exception {
        var a=SamlArtifact.parse(artifact(3,true));
        assertThrows(IllegalArgumentException.class,()->a.resolutionEndpoint(metadata(endpoint(0,SamlArtifact.SOAP,"https://idp.example/resolve")),TARGET));
        assertThrows(IllegalArgumentException.class,()->a.resolutionEndpoint(metadata(endpoint(3,SamlArtifact.SOAP,"https://idp.example/one")+endpoint(3,SamlArtifact.SOAP,"https://idp.example/two")),TARGET));
        assertThrows(IllegalArgumentException.class,()->a.resolutionEndpoint(metadata(endpoint(3,"urn:wrong","https://idp.example/resolve")),TARGET));
        assertThrows(IllegalArgumentException.class,()->a.resolutionEndpoint(metadata(endpoint(3,SamlArtifact.SOAP,"https://idp.example/resolve")),"https://other.example/entity"));
    }
    @Test void unsafeEndpointUrisAndResponseLocationAreNotResolutionAuthorities() throws Exception {
        var a=SamlArtifact.parse(artifact(3,true));
        for(String uri:List.of("file:///tmp/no","https://user:password@idp.example/resolve","https://idp.example/resolve#fragment","/relative"))assertThrows(IllegalArgumentException.class,()->a.resolutionEndpoint(metadata(endpoint(3,SamlArtifact.SOAP,uri)),TARGET));
        String e=endpoint(3,SamlArtifact.SOAP,"https://idp.example/resolve").replace("/>"," ResponseLocation=\"https://other.example\"/>");
        assertThrows(IllegalArgumentException.class,()->a.resolutionEndpoint(metadata(e),TARGET));
    }
}
