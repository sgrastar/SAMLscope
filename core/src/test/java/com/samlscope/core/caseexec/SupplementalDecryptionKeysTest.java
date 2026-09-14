package com.samlscope.core.caseexec;
import static org.junit.jupiter.api.Assertions.*;
import java.security.*;
import java.time.Instant;
import java.util.*;
import org.junit.jupiter.api.Test;
class SupplementalDecryptionKeysTest {
    static final String HASH="a".repeat(64);
    @Test void rejectsCredentialBearingSourcesAndNonPublicKeyMaterial() throws Exception {
        var rsa=KeyPairGenerator.getInstance("RSA");rsa.initialize(2048);var pair=rsa.generateKeyPair();
        var publicKey=Base64.getEncoder().encodeToString(pair.getPublic().getEncoded());
        var other=Base64.getEncoder().encodeToString(rsa.generateKeyPair().getPublic().getEncoded());
        for(var list:List.of(List.of(publicKey),List.of(publicKey,other)))
        for(var uri:List.of("file:///secret","data:text/plain,secret","javascript:secret","ftp://host/file","/relative",
                "https://user:password@host/path","https://host/path?token=secret","https://host/path#secret",
                "https:///missing-host","not a URI","urn:source:secret","https://host/?")) {
            var error=assertThrows(IllegalArgumentException.class,()->input(uri,list));
            assertFalse(error.getMessage().contains("password")); assertFalse(error.getMessage().contains("secret"));
        }
        var ec=KeyPairGenerator.getInstance("EC");ec.initialize(256);
        var invalid=List.of("", "not-base64", "-----BEGIN PRIVATE KEY-----", Base64.getEncoder().encodeToString(pair.getPrivate().getEncoded()),
                Base64.getEncoder().encodeToString(ec.generateKeyPair().getPublic().getEncoded()),
                Base64.getEncoder().encodeToString(new byte[]{1,2,3}),publicKey.substring(0,20),publicKey+"!",publicKey+"\n");
        for(var uri:List.of("http://localhost:18180/admin/keys","https://idp.example/keys","https://idp.example:443/keys","http://127.0.0.1/keys"))
        for(var value:invalid) {
            var error=assertThrows(IllegalArgumentException.class,()->input(uri,List.of(value)));
            assertEquals("Expected an RSA SubjectPublicKeyInfo public key",error.getMessage());
            assertNull(error.getCause());
        }
        assertThrows(IllegalArgumentException.class,()->input("https://idp.example/keys",List.of(publicKey,publicKey)));
        assertThrows(IllegalArgumentException.class,()->input(null,List.of(publicKey)));
        assertThrows(IllegalArgumentException.class,()->input("https://idp.example/keys",List.of()));
        var input=input("https://idp.example/keys",List.of(publicKey,other));
        assertArrayEquals(pair.getPublic().getEncoded(),input.publicKeys().getFirst().getEncoded());
        assertThrows(UnsupportedOperationException.class,()->input.publicKeysSpkiBase64().clear());
        assertTrue(SupplementalDecryptionKeys.absent("run","entity",HASH,Instant.EPOCH).publicKeys().isEmpty());
    }
    private static SupplementalDecryptionKeys input(String source,List<String> keys) {
        return new SupplementalDecryptionKeys("run","https://idp.example",HASH,source,keys,Instant.EPOCH);
    }
}
