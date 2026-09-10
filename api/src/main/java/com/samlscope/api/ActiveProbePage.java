package com.samlscope.api;

import com.samlscope.runner.ActiveProbeCoordinator;
import java.util.Map;

/** Browser-probe guidance and receipt pages; neither page states a conformance verdict. */
final class ActiveProbePage {
    private ActiveProbePage() {}

    static String start(ActiveProbeCoordinator.Status status, String stylesheet) {
        var freshSession = status.requiresFreshSession()
                ? """
                  <section class="session-check" aria-labelledby="session-heading">
                    <p class="eyebrow">PRIVATE SESSION REQUIRED</p>
                    <h2 id="session-heading">Start without an existing IdP session</h2>
                    <p>Move this page to a new private browser window before continuing. Keep the original Run workspace open.</p>
                    <p><strong>If the IdP shows a sign-in or consent screen during this IsPassive request, do not enter credentials.</strong> Return to the workspace and record that no SAML Response was returned.</p>
                    <label class="confirmation"><input required type="checkbox" name="freshSessionConfirmed" value="true">
                      <span>This private browser context has no active session with the target IdP.</span></label>
                  </section>
                  """
                : """
                  <section class="session-note">
                    <p><strong>Keep the current IdP session.</strong> Sign in only if the target asks during a normal control. SAMLscope does not intentionally clear the session between checks.</p>
                  </section>
                  """;
        return """
                <!doctype html><html lang="en"><head><meta charset="utf-8">
                <meta name="viewport" content="width=device-width,initial-scale=1">
                <meta name="referrer" content="no-referrer">
                <title>Browser check | SAMLscope</title><link rel="stylesheet" href="%s"></head>
                <body><header>SAMLscope <small>SAML CONFORMANCE</small></header><main class="probe-page">
                <div class="probe-heading"><div><p class="eyebrow">BROWSER-ASSISTED CHECK</p>
                <h1>Run one SAML check</h1></div><code class="case-id">%s</code></div>
                <p class="lead">SAMLscope sends one request at a time. After its Response is recorded, this tab stops and lets you return to the Run workspace before the next request.</p>
                <section class="probe-instructions" aria-labelledby="check-heading">
                  <p class="eyebrow">CURRENT CHECK</p><h2 id="check-heading">What SAMLscope will verify</h2><p>%s</p>
                </section>
                <form method="post">%s
                  <button type="submit">Continue with this request</button>
                  <p class="form-note">Quick is one browser campaign containing multiple protocol checks. It does not mean one SAML request or repeated forced sign-ins.</p>
                </form></main></body></html>
                """.formatted(escape(stylesheet), escape(status.caseId()),
                escape(status.instructionsEn()), freshSession);
    }

    static String recorded(
            String stylesheet,
            ActiveProbeCoordinator.Status next,
            Map<String, Object> summary,
            String nonce) {
        var nextStep = next.state() == ActiveProbeCoordinator.State.READY
                ? "The next browser check is ready. Start it from the workspace when you are ready."
                : "This browser campaign has no immediately ready check.";
        return """
                <!doctype html><html lang="en"><head><meta charset="utf-8">
                <meta name="viewport" content="width=device-width,initial-scale=1">
                <meta name="referrer" content="no-referrer">
                <title>Response recorded | SAMLscope</title><link rel="stylesheet" href="%s"></head>
                <body><header>SAMLscope <small>SAML CONFORMANCE</small></header><main>
                <p class="eyebrow">BROWSER CHECK PAUSED</p><h1>SAML Response recorded</h1>
                <p>The response reached SAMLscope. The next request was not sent automatically.</p>
                <p class="notice">Recorded does not mean conformance PASS. The approved checks determine the result.</p>
                <button type="button" id="return-workspace">Close this tab and return to workspace</button>
                <p id="close-help" class="form-note" role="status">Returning to the existing workspace… If this tab remains open, use the button above or close it manually.</p>
                <p>%s</p>
                <details><summary>Technical response details</summary><pre>%s</pre></details>
                <script nonce="%s">var closeHelp=document.getElementById('close-help');function returnToWorkspace(){window.close();setTimeout(function(){closeHelp.textContent='Your browser kept this tab open. Close it manually to return to the existing workspace.'},200)}document.getElementById('return-workspace').addEventListener('click',returnToWorkspace);setTimeout(returnToWorkspace,900)</script>
                </main></body></html>
                """.formatted(escape(stylesheet), escape(nextStep), escape(summary.toString()), escape(nonce));
    }

    private static String escape(String value) {
        return value == null ? "" : value.replace("&", "&amp;").replace("<", "&lt;")
                .replace(">", "&gt;").replace("\"", "&quot;").replace("'", "&#39;");
    }
}
