package com.samlscope.saml.binding;

import static org.junit.jupiter.api.Assertions.*;
import java.io.ByteArrayInputStream;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Clock;
import java.util.*;
import java.util.zip.Inflater;
import java.util.zip.InflaterInputStream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.w3c.dom.Element;
import com.samlscope.saml.crypto.*;
import com.samlscope.saml.normal.SecureXml;

class SignedRedirectEncoderTest {
    @TempDir Path directory;
    private static final String P="urn:oasis:names:tc:SAML:2.0:protocol", A="urn:oasis:names:tc:SAML:2.0:assertion";
    @Test void messageRelayEndpointAndSignatureMatrixPreservesWireEvidence() throws Exception {
        var keys=new FilePlanKeyStore(directory,Clock.systemUTC());
        var key=keys.getOrCreate("plan_0123456789ABCDEFGHJKMNPQRS","sender");
        var wrong=keys.getOrCreate("plan_0123456789ABCDEFGHJKMNPQRS","wrong");
        var encoder=new SignedRedirectEncoder();
        for(var type:List.of("AuthnRequest","LogoutRequest","Response","LogoutResponse"))
        for(var relay:Arrays.asList(null,"", "a +/%&=😀"))
        for(var suffix:List.of("","?","?tenant=a%2fb","?tenant=a+b&x=%20","?tenant=x&"))
        for(var signed:List.of(false,true)) {
            var doc=SecureXml.parse(("<p:"+type+" xmlns:p='"+P+"' xmlns:a='"+A+"' ID='_root'><a:Issuer>suite</a:Issuer></p:"+type+">").getBytes(StandardCharsets.UTF_8));
            var root=doc.getDocumentElement();
            if(type.equals("Response")) {
                var assertion=doc.createElementNS(A,"a:Assertion");assertion.setAttribute("ID","_assertion");root.appendChild(assertion);
                new XmlSigner().sign(assertion,key,null);
            }
            if(signed)new XmlSigner().sign(root,key,null);
            var xml=SecureXml.serialize(doc);var original=xml.clone();
            var result=encoder.encode(URI.create("https://idp.example/slo"+suffix),xml,relay,key);
            assertArrayEquals(original,xml);
            assertEquals(result.destination().getRawQuery(),result.rawQuery());
            var decoded=new LinkedHashMap<String,String>();
            for(var pair:result.rawQuery().split("&")) {if(pair.isEmpty())continue;var kv=pair.split("=",2);decoded.put(URLDecoder.decode(kv[0],StandardCharsets.UTF_8),URLDecoder.decode(kv[1],StandardCharsets.UTF_8));}
            var name=type.endsWith("Request")?"SAMLRequest":"SAMLResponse";
            var inflater=new Inflater(true);byte[] wire;
            try(var stream=new InflaterInputStream(new ByteArrayInputStream(Base64.getDecoder().decode(decoded.get(name))),inflater)){wire=stream.readAllBytes();}finally{inflater.end();}
            assertArrayEquals(wire,result.decodedXml());
            var parsed=SecureXml.parse(wire).getDocumentElement();
            for(var n=parsed.getFirstChild();n!=null;n=n.getNextSibling())if(n instanceof Element e)assertFalse("Signature".equals(e.getLocalName()));
            if(type.equals("Response"))assertTrue(new XmlSignatureVerifier().hasValidEnvelopedSignature((Element)parsed.getElementsByTagNameNS(A,"Assertion").item(0),key.certificate()));
            assertEquals(relay,decoded.get("RelayState"));assertEquals(relay!=null,decoded.containsKey("RelayState"));
            assertTrue(new RedirectSignatureVerifier().isValid(result.rawQuery(),key.certificate()));
            var verifier=new RedirectSignatureVerifier();
            assertTrue(verifier.isValidForMessage(result.rawQuery(),key.certificate(),wire));
            assertFalse(verifier.isValidForMessage(result.rawQuery(),wrong.certificate(),wire));
            assertFalse(verifier.matchesMessage(result.rawQuery(),Arrays.copyOf(wire,wire.length-1)));
            assertFalse(verifier.matchesMessage(result.rawQuery(),Arrays.copyOf(wire,wire.length+1)));
            var changed=wire.clone();changed[changed.length/2]^=1;
            assertFalse(verifier.isValidForMessage(result.rawQuery(),key.certificate(),changed));
            assertFalse(verifier.matchesMessage(result.rawQuery()+"&"+name+"=x",wire));
            assertFalse(verifier.matchesMessage("SAMLResponse=invalid",wire));
            assertFalse(new RedirectSignatureVerifier().isValid(result.rawQuery(),wrong.certificate()));
            assertFalse(new RedirectSignatureVerifier().isValid(result.rawQuery().replace(name+"=",name+"=x"),key.certificate()));
            if(relay!=null)assertFalse(new RedirectSignatureVerifier().isValid(result.rawQuery().replace("RelayState=","RelayState=x"),key.certificate()));
            assertEquals(result.destination(),encoder.encode(URI.create("https://idp.example/slo"+suffix),xml,relay,key).destination());
            var returned=result.decodedXml();returned[0]=0;assertArrayEquals(wire,result.decodedXml());
        }
    }
    @Test void rejectsAmbiguousEndpointsBeforeSigning() {
        var key=new FilePlanKeyStore(directory,Clock.systemUTC()).getOrCreate("plan_0123456789ABCDEFGHJKMNPQRS");
        var xml=("<p:LogoutRequest xmlns:p='"+P+"'/>").getBytes(StandardCharsets.UTF_8);var encoder=new SignedRedirectEncoder();
        for(var name:List.of("SAMLRequest","SAMLResponse","RelayState","SigAlg","Signature","SAMLEncoding"))
        for(var spelling:List.of(name,"%"+Integer.toHexString(name.charAt(0))+name.substring(1)))
            assertThrows(IllegalArgumentException.class,()->encoder.encode(URI.create("https://idp.example/slo?"+spelling+"=old"),xml,null,key));
        for(var endpoint:List.of("ftp://idp.example/slo","https://user@idp.example/slo","https://idp.example/slo#part","/relative"))
            assertThrows(IllegalArgumentException.class,()->encoder.encode(URI.create(endpoint),xml,null,key));
    }
}
