package com.samlscope.api;

import java.net.URI;
import java.util.Map;

/** Receipt acknowledgement only; never a conformance verdict or a management credential. */
final class PeerCompletionPage {
    static String render(URI workspace, String stylesheet, Map<String, Object> summary) {
        return """
                <!doctype html><html lang="en"><head><meta charset="utf-8">
                <meta name="viewport" content="width=device-width,initial-scale=1">
                <title>Response recorded | SAMLscope</title><link rel="stylesheet" href="%s"></head>
                <body><header>SAMLscope <small>SAML CONFORMANCE</small></header><main>
                <p class="eyebrow">BROWSER ROUND TRIP</p><h1>SAML Response recorded</h1>
                <p>Your IdP response has reached SAMLscope. Return to your Run to review the evidence and continue testing.</p>
                <p class="notice">Recorded does not mean conformance PASS. The approved checks determine the result.</p>
                <a class="button" href="%s">Return to Run workspace</a>
                <p>Next: run the initial checks (M1), then follow the pending interactions.</p>
                <details><summary>Technical response details</summary><pre>%s</pre></details>
                </main></body></html>
                """.formatted(escape(stylesheet), escape(workspace.toString()), escape(summary.toString()));
    }

    private static String escape(String value) {
        return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                .replace("\"", "&quot;").replace("'", "&#39;");
    }
}
