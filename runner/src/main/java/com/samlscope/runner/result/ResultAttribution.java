package com.samlscope.runner.result;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.TreeSet;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

/** Static, public source metadata only; never reads Run configuration or private evidence. */
final class ResultAttribution {
    private final ObjectMapper mapper;
    private final JsonNode registry;
    private final JsonNode index;
    private final String contentLicense;

    ResultAttribution(ObjectMapper mapper) {
        this.mapper = mapper;
        try {
            registry = mapper.readTree(resource("source-notices.json"));
            index = mapper.readTree(resource("material-index.json"));
            contentLicense = resource("CC-BY-SA-4.0.txt");
        } catch (IOException e) {
            throw new IllegalStateException("Cannot load distribution attribution", e);
        }
    }

    ObjectNode forDocument(ResultDocument document) {
        var ids = new TreeSet<String>();
        var unknown = new TreeSet<String>();
        for (var requirement : document.requirements()) {
            for (var obligation : requirement.obligations()) {
                var selected = index.path("obligation_sources").get(obligation.key());
                if (selected == null) unknown.add(obligation.key());
                else selected.forEach(id -> ids.add(id.asText()));
            }
        }
        var result = mapper.createObjectNode();
        result.put("scope", "CC BY-SA 4.0 applies only to SAMLscope-owned explanatory content. Measurements, verdicts, identifiers and target declarations are not assigned a content license. Third-party material retains its original terms.");
        result.put("original_content_license", "CC-BY-SA-4.0");
        result.put("original_content_attribution", "SAMLscope contributors — explanatory content; https://github.com/sgrastar/SAMLscope");
        result.put("original_content_license_text", contentLicense);
        result.put("modifications", "SAMLscope organizes specification references and adds test explanations and assessment results; this is not an unmodified specification or publisher certification.");
        result.put("review_status", "Source notices and modification credits are retained. Reference-only entries do not grant rights in upstream files; dependency resources have separate package notices.");
        var retained = result.putArray("sources");
        var pending = result.putArray("unresolved_sources");
        for (var id : ids) {
            JsonNode found = null;
            for (var source : registry.path("sources")) {
                if (id.equals(source.path("id").asText())) { found = source; break; }
            }
            if (found != null) retained.add(found.deepCopy());
            else {
                var item = pending.addObject();
                item.put("id", id);
                item.set("reference", index.path("sources").path(id).deepCopy());
                item.put("status", "NOTICE_REVIEW_PENDING");
            }
        }
        var unmapped = result.putArray("unmapped_obligations");
        unknown.forEach(unmapped::add);
        return result;
    }

    private static String resource(String name) throws IOException {
        try (var stream = ResultAttribution.class.getResourceAsStream("/META-INF/samlscope/LICENSES/" + name)) {
            if (stream == null) throw new IOException("Missing attribution resource: " + name);
            return new String(stream.readAllBytes(), StandardCharsets.UTF_8);
        }
    }
}
