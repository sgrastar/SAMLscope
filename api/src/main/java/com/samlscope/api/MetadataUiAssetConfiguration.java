package com.samlscope.api;

import java.net.URI;
import java.time.Clock;
import java.util.Map;
import com.samlscope.saml.crypto.FilePlanKeyStore;
import com.samlscope.saml.crypto.XmlSigner;
import com.samlscope.saml.metadata.*;

/** Applies the same explicit fixture transport settings to ordinary and polling metadata. */
final class MetadataUiAssetConfiguration {
    private MetadataUiAssetConfiguration() {}
    static MetadataService create(URI peer, FilePlanKeyStore keys, XmlSigner signer, Clock clock) {
        return new MetadataService(peer, keys, signer, clock, locations(peer, System.getenv()));
    }
    static MetadataUiAssetLocations locations(URI peer, Map<String, String> environment) {
        var http = environment.get("SAMLSCOPE_UI_ASSET_HTTP_URL");
        var https = environment.get("SAMLSCOPE_UI_ASSET_HTTPS_URL");
        if (http == null && https == null) return MetadataUiAssetLocations.forPeer(peer);
        if (http == null || https == null) throw new IllegalArgumentException("Configure both UI asset transport URLs");
        return new MetadataUiAssetLocations(URI.create(http), URI.create(https));
    }
}
