package com.samlscope.saml.metadata;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

/** Fixed inert UI input, identical for data and network URLs. Not an XSS payload. */
public final class MetadataUiFixtureAsset {
    public static final String PATH = "/metadata-lab/ui-fixture.svg";
    public static final String SVG = "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"180\" height=\"48\">"
            + "<rect width=\"180\" height=\"48\" fill=\"#1d4ed8\"/>"
            + "<text x=\"12\" y=\"30\" fill=\"white\" font-size=\"18\">URL SCHEME</text></svg>";
    private MetadataUiFixtureAsset() {}
    public static String dataUri() {
        return "data:image/svg+xml;base64," + Base64.getEncoder().encodeToString(SVG.getBytes(StandardCharsets.UTF_8));
    }
}
