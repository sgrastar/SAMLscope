package com.samlscope.core.plan;

import java.time.Instant;
import java.util.Objects;
import java.util.Set;

/** Private reusable target identity. Revisions are accepted metadata snapshots, never live URLs. */
public record TargetConnection(String id, String ownerId, String name, String entityId,
                               Instant createdAt) {
    public TargetConnection {
        for (var value : new String[]{id, ownerId, name, entityId}) {
            if (value == null || value.isBlank()) throw new IllegalArgumentException("Connection identity is required");
        }
        Objects.requireNonNull(createdAt);
    }

    public record Revision(String connectionId, String id, Set<TargetRole> roles,
                           String metadataBase64, Instant createdAt, String privateSourceUrl) {
        public Revision {
            if (connectionId == null || connectionId.isBlank() || id == null || id.isBlank()) {
                throw new IllegalArgumentException("Metadata revision identity is required");
            }
            roles = Set.copyOf(roles);
            if (roles.isEmpty()) throw new IllegalArgumentException("Metadata must provide a target role");
            if (metadataBase64 == null || metadataBase64.isBlank()
                    || java.util.Base64.getDecoder().decode(metadataBase64).length == 0)
                throw new IllegalArgumentException("Metadata bytes are required");
            Objects.requireNonNull(createdAt);
            if (privateSourceUrl != null) {
                var source = java.net.URI.create(privateSourceUrl);
                if (source.getHost() == null || source.getUserInfo() != null || source.getFragment() != null
                        || !("https".equalsIgnoreCase(source.getScheme()) || "http".equalsIgnoreCase(source.getScheme())))
                    throw new IllegalArgumentException("Metadata source must be an HTTP(S) URL without credentials or fragment");
            }
        }
        public static Revision fromBytes(String connectionId, String id, Set<TargetRole> roles,
                byte[] bytes, Instant createdAt) {
            return new Revision(connectionId, id, roles, java.util.Base64.getEncoder().encodeToString(bytes), createdAt, null);
        }
        public Revision withSourceUrl(String url) {
            return new Revision(connectionId, id, roles, metadataBase64, createdAt, url);
        }
        public byte[] metadataBytes() { return java.util.Base64.getDecoder().decode(metadataBase64); }
        public String sha256() {
            try {
                return java.util.HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256").digest(metadataBytes()));
            } catch (java.security.NoSuchAlgorithmException impossible) { throw new IllegalStateException(impossible); }
        }
    }
}
