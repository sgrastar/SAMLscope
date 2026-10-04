package com.samlscope.core.caseexec;

import java.net.URI;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.util.*;

/** Explicit test input, never a replacement for the target's published metadata. Empty keys seal absence. */
public record SupplementalDecryptionKeys(String runId, String targetEntityId, String metadataSha256,
        String sourceUri, List<String> publicKeysSpkiBase64, Instant recordedAt) {
    public SupplementalDecryptionKeys {
        if (runId==null || runId.isBlank()) throw new IllegalArgumentException("Run is required");
        if (targetEntityId==null || targetEntityId.isBlank()) throw new IllegalArgumentException("Target entity is required");
        if (metadataSha256==null || !metadataSha256.matches("[0-9a-f]{64}"))
            throw new IllegalArgumentException("Run metadata SHA-256 is required");
        Objects.requireNonNull(recordedAt,"recordedAt");
        publicKeysSpkiBase64=List.copyOf(publicKeysSpkiBase64);
        if (publicKeysSpkiBase64.isEmpty()) {
            if (sourceUri!=null) throw new IllegalArgumentException("Absent keys have no source");
        } else {
            if (sourceUri==null) throw new IllegalArgumentException("Public-key source is required");
            URI source;
            try { source=URI.create(sourceUri); }
            catch (IllegalArgumentException invalid) { throw new IllegalArgumentException("Invalid public-key source"); }
            if (!("http".equalsIgnoreCase(source.getScheme()) || "https".equalsIgnoreCase(source.getScheme())) || source.getHost()==null
                    || source.getUserInfo()!=null || source.getRawQuery()!=null || source.getRawFragment()!=null)
                throw new IllegalArgumentException("Source must be an HTTP(S) reference without credentials, query or fragment");
            var normalized=new ArrayList<String>();
            var unique=new HashSet<String>();
            for(var encoded:publicKeysSpkiBase64) {
                var canonical=Base64.getEncoder().encodeToString(decode(encoded).getEncoded());
                if(!unique.add(canonical)) throw new IllegalArgumentException("Decryption test keys must be distinct");
                normalized.add(canonical);
            }
            publicKeysSpkiBase64=List.copyOf(normalized);
        }
    }
    public List<PublicKey> publicKeys() { return publicKeysSpkiBase64.stream().map(SupplementalDecryptionKeys::decode).toList(); }
    public static SupplementalDecryptionKeys absent(String run,String entity,String metadataSha256,Instant at) {
        return new SupplementalDecryptionKeys(run,entity,metadataSha256,null,List.of(),at);
    }
    private static PublicKey decode(String encoded) {
        try {
            return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(encoded)));
        } catch(Exception invalid) {
            // Do not echo caller input or the parser exception: it could contain private material.
            throw new IllegalArgumentException("Expected an RSA SubjectPublicKeyInfo public key");
        }
    }
}
