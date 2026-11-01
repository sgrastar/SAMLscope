package com.samlscope.api;

import java.net.URI;

final class HtmlPostPage {
    private HtmlPostPage() {}

    static String render(URI destination, String samlResponse, String relayState, String nonce) {
        return render(destination, "SAMLResponse", samlResponse, relayState, nonce,
                "Continue SAML sign-in", "Continuing to the service provider…");
    }

    static String renderRequest(URI destination, String samlRequest, String relayState, String nonce) {
        return render(destination, "SAMLRequest", samlRequest, relayState, nonce,
                "Run active SAML probe", "Sending the next active probe to the identity provider…");
    }

    private static String render(
            URI destination,
            String parameter,
            String samlMessage,
            String relayState,
            String nonce,
            String title,
            String message) {
        return """
                <!doctype html>
                <html lang="en"><head><meta charset="utf-8">
                <meta name="referrer" content="no-referrer">
                <title>%s</title></head>
                <body><p>%s</p>
                <form method="post" action="%s">
                  <input type="hidden" name="%s" value="%s">
                  %s
                  <noscript><button type="submit">Continue</button></noscript>
                </form>
                <script nonce="%s">document.forms[0].submit()</script></body></html>
                """.formatted(escape(title), escape(message), escape(destination.toString()),
                escape(parameter), escape(samlMessage),
                relayState == null ? "" : "<input type=\"hidden\" name=\"RelayState\" value=\""
                        + escape(relayState) + "\">", escape(nonce));
    }

    private static String escape(String value) {
        return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                .replace("\"", "&quot;").replace("'", "&#39;");
    }
}
