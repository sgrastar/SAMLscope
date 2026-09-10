package com.samlscope.api;

import static org.junit.jupiter.api.Assertions.*;

import com.samlscope.runner.ActiveProbeCoordinator;
import java.net.URI;
import java.util.Map;
import org.junit.jupiter.api.Test;

class ActiveProbePageTest {
    @Test
    void rendersGuidanceWithoutAllowingMarkupFromCaseData() {
        var status = new ActiveProbeCoordinator.Status(
                "plan_test", ActiveProbeCoordinator.State.READY, "action_test",
                URI.create("https://peer.example/probe"), true, null,
                "<script>case</script>", "Check <unsafe> instructions");

        var html = ActiveProbePage.start(status, "/p/plan_test/ui/completion.css");

        assertTrue(html.contains("Run one SAML check"));
        assertTrue(html.contains("PRIVATE SESSION REQUIRED"));
        assertTrue(html.contains("do not enter credentials"));
        assertTrue(html.contains("&lt;script&gt;case&lt;/script&gt;"));
        assertTrue(html.contains("Check &lt;unsafe&gt; instructions"));
        assertFalse(html.contains("<script>case</script>"));
    }

    @Test
    void receiptPausesBeforeTheNextProbeAndLinksBackToWorkspace() {
        var next = new ActiveProbeCoordinator.Status(
                "plan_test", ActiveProbeCoordinator.State.READY, "action_next",
                URI.create("https://peer.example/probe/next"), false, null,
                "IIP-IDP05-a-idp-01", "next");

        var html = ActiveProbePage.recorded(
                "/p/plan_test/ui/completion.css", next, Map.of("status", "recorded"), "nonce_test");

        assertTrue(html.contains("The next request was not sent automatically"));
        assertTrue(html.contains("Close this tab and return to workspace"));
        assertTrue(html.contains("nonce=\"nonce_test\""));
        assertTrue(html.contains("window.close()"));
        assertTrue(html.contains("setTimeout(returnToWorkspace,900)"));
        assertFalse(html.contains("conformance PASS.</p><a"));
    }
}
