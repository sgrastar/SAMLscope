package com.samlscope.api;

import static org.junit.jupiter.api.Assertions.*;
import java.net.URI;
import java.util.Map;
import org.junit.jupiter.api.Test;

class MetadataUiAssetConfigurationTest {
    private static final URI PEER = URI.create("http://localhost:18080");
    private static final String HTTP = "http://localhost:18480/metadata-lab/ui-fixture.svg";
    private static final String HTTPS = "https://localhost:18443/metadata-lab/ui-fixture.svg";
    @Test void independentOriginsAreExplicitAndFailClosedWhenIncomplete() {
        var origins = MetadataUiAssetConfiguration.locations(PEER, Map.of(
                "SAMLSCOPE_UI_ASSET_HTTP_URL", HTTP, "SAMLSCOPE_UI_ASSET_HTTPS_URL", HTTPS));
        assertEquals(URI.create(HTTP), origins.http());
        assertEquals(URI.create(HTTPS), origins.https());
        assertThrows(IllegalArgumentException.class, () -> MetadataUiAssetConfiguration.locations(PEER,
                Map.of("SAMLSCOPE_UI_ASSET_HTTP_URL", HTTP)));
        for (String invalid : new String[]{HTTP, HTTPS + "?token=secret", HTTPS + "#fragment",
                "https://user:password@localhost:18443/metadata-lab/ui-fixture.svg",
                "https://localhost:18443/other.svg"}) {
            assertThrows(IllegalArgumentException.class, () -> MetadataUiAssetConfiguration.locations(PEER,
                    Map.of("SAMLSCOPE_UI_ASSET_HTTP_URL", HTTP, "SAMLSCOPE_UI_ASSET_HTTPS_URL", invalid)));
        }
    }
}
