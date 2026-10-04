package com.samlscope.api;

import io.javalin.config.JavalinConfig;
import com.samlscope.saml.metadata.MetadataUiFixtureAsset;

/** Fixed image only. No filename, redirect, user-provided content, or filesystem access. */
final class MetadataUiAssetRoutes {
    private MetadataUiAssetRoutes() {}
    static void register(JavalinConfig app) {
        app.routes.get(MetadataUiFixtureAsset.PATH, ctx -> {
            ctx.contentType("image/svg+xml; charset=utf-8");
            ctx.header("X-Content-Type-Options", "nosniff");
            ctx.header("Content-Security-Policy", "default-src 'none'; sandbox");
            ctx.result(MetadataUiFixtureAsset.SVG);
        });
    }
}
