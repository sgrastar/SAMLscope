package com.samlscope.api;

import static org.junit.jupiter.api.Assertions.*;
import java.net.URI;
import java.util.Map;
import org.junit.jupiter.api.Test;

class PeerCompletionPageTest {
    @Test
    void providesWorkspaceReturnWithoutCallingReceiptAConformanceVerdict() {
        var html = PeerCompletionPage.render(URI.create("https://app.example/manage/run_test"),
                "/p/plan_test/ui/completion.css", Map.of("issuer", "<script>alert('x')</script>"));
        assertTrue(html.contains("href=\"https://app.example/manage/run_test\""));
        assertTrue(html.contains("Return to Run workspace"));
        assertTrue(html.contains("Recorded does not mean conformance PASS"));
        assertTrue(html.contains("href=\"/p/plan_test/ui/completion.css\""));
        assertTrue(html.contains("&lt;script&gt;"));
        assertFalse(html.contains("<script>"));
        assertFalse(html.contains("http-equiv"));
        assertTrue(html.contains("<details><summary>Technical response details"));
    }
}
