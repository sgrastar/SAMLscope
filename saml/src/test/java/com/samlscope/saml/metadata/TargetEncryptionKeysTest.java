package com.samlscope.saml.metadata;

import static org.junit.jupiter.api.Assertions.*;
import java.time.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.security.interfaces.RSAPublicKey;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import com.samlscope.core.plan.TargetRole;
import com.samlscope.saml.SamlTestFixtures;
import com.samlscope.saml.crypto.FilePlanKeyStore;

class TargetEncryptionKeysTest {
    @TempDir java.nio.file.Path directory;
    @Test void selectsOnlyTheRequestedRoleAndEncryptionOrOmittedUse() throws Exception {
        var keys=new FilePlanKeyStore(directory,Clock.systemUTC());var plan=SamlTestFixtures.idpPlan();
        var first=keys.getOrCreate(plan.id());var second=keys.getOrCreate(plan.id(),"second");
        String cert=Base64.getEncoder().encodeToString(first.certificate().getEncoded());
        String other=Base64.getEncoder().encodeToString(second.certificate().getEncoded());
        String kd="<md:KeyDescriptor%s><ds:KeyInfo><ds:X509Data><ds:X509Certificate>"+cert+"</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>";
        for(String use:List.of(""," use='encryption'"," use='signing'"," use='other'"," use=' '")) {
            String idp=kd.formatted(use);
            String sp=kd.formatted(" use='encryption'").replace(cert,other);
            var result=new TargetEncryptionKeys().rsaKeys(metadata(idp,sp),"urn:target",TargetRole.IDP);
            assertEquals(use.isEmpty()||use.contains("'encryption'")?1:0,result.size());
            if(!result.isEmpty())assertArrayEquals(first.certificate().getPublicKey().getEncoded(),result.getFirst().getEncoded());
            assertArrayEquals(second.certificate().getPublicKey().getEncoded(),new TargetEncryptionKeys().rsaKeys(metadata(idp,sp),"urn:target",TargetRole.SP).getFirst().getEncoded());
        }
        String base=kd.formatted("");
        var rsa=(RSAPublicKey)first.certificate().getPublicKey();
        String value="<md:KeyDescriptor><ds:KeyInfo><ds:KeyValue><ds:RSAKeyValue><ds:Modulus>"+Base64.getEncoder().encodeToString(rsa.getModulus().toByteArray())+"</ds:Modulus><ds:Exponent>"+Base64.getEncoder().encodeToString(rsa.getPublicExponent().toByteArray())+"</ds:Exponent></ds:RSAKeyValue></ds:KeyValue></ds:KeyInfo></md:KeyDescriptor>";
        assertEquals(1,new TargetEncryptionKeys().rsaKeys(metadata(base+value,""),"urn:target",TargetRole.IDP).size());
        assertEquals(0,new TargetEncryptionKeys().rsaKeys(metadata("<md:Extensions>"+base+"</md:Extensions>",""),"urn:target",TargetRole.IDP).size());
        assertThrows(IllegalArgumentException.class,()->new TargetEncryptionKeys().rsaKeys(metadata(base,""),"urn:other",TargetRole.IDP));
        String duplicate="<md:EntitiesDescriptor xmlns:md='urn:oasis:names:tc:SAML:2.0:metadata'>"+new String(metadata(base,""),StandardCharsets.UTF_8).repeat(2)+"</md:EntitiesDescriptor>";
        assertThrows(IllegalArgumentException.class,()->new TargetEncryptionKeys().rsaKeys(duplicate.getBytes(StandardCharsets.UTF_8),"urn:target",TargetRole.IDP));
    }
    private byte[] metadata(String idp,String sp){return ("<md:EntityDescriptor xmlns:md='urn:oasis:names:tc:SAML:2.0:metadata' xmlns:ds='http://www.w3.org/2000/09/xmldsig#' entityID='urn:target'><md:IDPSSODescriptor protocolSupportEnumeration='urn:oasis:names:tc:SAML:2.0:protocol'>"+idp+"</md:IDPSSODescriptor><md:SPSSODescriptor protocolSupportEnumeration='urn:oasis:names:tc:SAML:2.0:protocol'>"+sp+"</md:SPSSODescriptor></md:EntityDescriptor>").getBytes(StandardCharsets.UTF_8);}
}
