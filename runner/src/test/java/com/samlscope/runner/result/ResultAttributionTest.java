package com.samlscope.runner.result;

import static org.junit.jupiter.api.Assertions.*;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.Test;

class ResultAttributionTest {
    @Test
    void retainsOnlySelectedSourcesAndDoesNotChangeAssessmentOrExposeTargetStrings() throws Exception {
        var writer = new ResultJsonWriter();
        var mapper = writer.mapper();
        ObjectNode input;
        try (var resource = getClass().getResourceAsStream("/golden/result-v1.json")) {
            input = (ObjectNode) mapper.readTree(resource);
        }
        input.remove("attribution");
        for (var requirement : input.path("requirements")) {
            for (var obligation : requirement.path("obligations")) {
                ((ObjectNode) obligation).put("key", "IIP-G01.a");
            }
        }
        var document = mapper.treeToValue(input, ResultDocument.class);
        var output = mapper.readTree(writer.write(document));
        var attribution = output.path("attribution");
        assertEquals(1, attribution.path("sources").size());
        var source = attribution.path("sources").get(0);
        assertEquals("kantara-fedinterop-impl", source.path("id").asText());
        assertTrue(source.path("notice_text").asText().contains("Internet2"));
        assertTrue(source.path("license_url").asText().contains("3.0/us"));
        assertTrue(attribution.path("original_content_license_text").asText().contains("Section 3"));
        assertEquals(input.path("run"), output.path("run"));
        assertEquals(input.path("coverage"), output.path("coverage"));
        assertFalse(attribution.toString().contains(input.path("target").path("declared_product").asText()));
        assertTrue(attribution.path("unmapped_obligations").isEmpty());

        var unused = "UNRELATED_SOURCE_SENTINEL";
        var html = new String(new ReportHtmlWriter("Apache".getBytes(), "scope".getBytes(),
                ("{\"sources\":[\"" + unused + "\"]}").getBytes())
                .write(writer.write(document).getBytes(StandardCharsets.UTF_8)), StandardCharsets.UTF_8);
        assertFalse(html.contains(Base64.getEncoder().encodeToString(
                ("{\"sources\":[\"" + unused + "\"]}").getBytes())));
        assertTrue(html.contains("r.attribution"));
        // Renderable fixture for the offline smoke check; generated, never hand-edited.
        var qa = java.nio.file.Path.of("build/license-qa");
        java.nio.file.Files.createDirectories(qa);
        var actualReport = new ReportHtmlWriter(
                java.nio.file.Files.readAllBytes(java.nio.file.Path.of("../LICENSE")),
                java.nio.file.Files.readAllBytes(java.nio.file.Path.of("../LICENSING.md")),
                java.nio.file.Files.readAllBytes(java.nio.file.Path.of("../LICENSES/source-notices.json")))
                .write(writer.write(document).getBytes(StandardCharsets.UTF_8));
        java.nio.file.Files.write(qa.resolve("report.html"), actualReport);
        java.nio.file.Files.writeString(qa.resolve("result.json"), writer.write(document));
    }
}
