package com.samlscope.api;

import static org.junit.jupiter.api.Assertions.*;
import io.javalin.Javalin;
import java.net.URI;
import java.net.http.*;
import org.junit.jupiter.api.Test;
import com.samlscope.saml.metadata.MetadataUiFixtureAsset;

class MetadataUiAssetRoutesTest {
    @Test void networkAssetMatchesTheDataUriPayloadExactly() throws Exception {
        var app = Javalin.create(MetadataUiAssetRoutes::register).start(0);
        try {
            var client = HttpClient.newHttpClient();
            var uri = URI.create("http://localhost:" + app.port() + MetadataUiFixtureAsset.PATH);
            var response = client.send(HttpRequest.newBuilder(uri).GET().build(), HttpResponse.BodyHandlers.ofString());
            assertEquals(200, response.statusCode());
            assertEquals(MetadataUiFixtureAsset.SVG, response.body());
            assertTrue(response.headers().firstValue("Content-Type").orElseThrow().startsWith("image/svg+xml"));
            assertEquals("nosniff", response.headers().firstValue("X-Content-Type-Options").orElseThrow());
        } finally { app.stop(); }
    }
}
