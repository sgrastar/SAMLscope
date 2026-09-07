package com.samlscope.api.auth;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;

/** Standard issuer + subject identity; email and display name never grant access. */
public record OidcIdentity(String issuer, String subject, String displayName) {
    public OidcIdentity {
        if (issuer == null || issuer.isBlank() || subject == null || subject.isBlank() || subject.length() > 255) {
            throw new IllegalArgumentException("OIDC identity requires issuer and subject");
        }
        displayName = displayName == null || displayName.isBlank() ? "Signed-in user" : displayName;
        if (displayName.length() > 256) displayName = displayName.substring(0, 256);
    }
    public String ownerId() {
        try {
            // Length-prefix the issuer so different pairs cannot share an encoding.
            return "oidc:" + HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest((issuer.length() + ":" + issuer + subject).getBytes(StandardCharsets.UTF_8)));
        } catch (java.security.NoSuchAlgorithmException impossible) {
            throw new IllegalStateException(impossible);
        }
    }
}
