package com.samlscope.saml.metadata;

import java.net.URI;
import java.util.Objects;

/** Explicit independent transport endpoints for the same fixed UI fixture asset. */
public record MetadataUiAssetLocations(URI http, URI https) {
    public MetadataUiAssetLocations {
        validate(http, "http"); validate(https, "https");
    }
    public static MetadataUiAssetLocations forPeer(URI peer) {
        try {
            return new MetadataUiAssetLocations(
                    new URI("http", null, peer.getHost(), peer.getPort(), MetadataUiFixtureAsset.PATH, null, null),
                    new URI("https", null, peer.getHost(), peer.getPort(), MetadataUiFixtureAsset.PATH, null, null));
        } catch (java.net.URISyntaxException invalid) { throw new IllegalArgumentException("Invalid fixture origin", invalid); }
    }
    private static void validate(URI uri, String scheme) {
        Objects.requireNonNull(uri);
        if (!scheme.equals(uri.getScheme()) || uri.getHost() == null || uri.getUserInfo() != null
                || uri.getQuery() != null || uri.getFragment() != null
                || !MetadataUiFixtureAsset.PATH.equals(uri.getPath()) || uri.getPort() == 0 || uri.getPort() > 65535) {
            throw new IllegalArgumentException("Invalid fixed UI asset endpoint");
        }
    }
}
