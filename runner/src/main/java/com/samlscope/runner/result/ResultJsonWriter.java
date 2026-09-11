package com.samlscope.runner.result;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.samlscope.store.JsonCodec;

/** Deterministic JSON writer for the public schema-v1 result artifact. */
public final class ResultJsonWriter {
    private final ObjectMapper mapper;
    private final ResultAttribution attribution;

    public ResultJsonWriter() {
        mapper = new JsonCodec().mapper().copy()
                .setPropertyNamingStrategy(PropertyNamingStrategies.SNAKE_CASE)
                .enable(SerializationFeature.INDENT_OUTPUT)
                .enable(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS)
                .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
        attribution = new ResultAttribution(mapper);
    }

    public String write(ResultDocument document) {
        try {
            var tree = mapper.<com.fasterxml.jackson.databind.node.ObjectNode>valueToTree(document);
            tree.set("attribution", attribution.forDocument(document));
            return mapper.writeValueAsString(tree) + "\n";
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Could not encode result JSON", e);
        }
    }

    public ObjectMapper mapper() {
        return mapper.copy();
    }
}
