package com.samlscope.store;

import com.fasterxml.jackson.core.*;
import com.fasterxml.jackson.databind.*;
import com.fasterxml.jackson.databind.module.SimpleModule;
import com.samlscope.core.profile.FunctionalProfile;
import java.io.IOException;
import com.samlscope.core.plan.TestPlan.ExecutionPreset;

/** The same stable functional identifiers in persisted documents, HTTP JSON and map keys. */
public final class FunctionalProfileJsonModule extends SimpleModule {
    public FunctionalProfileJsonModule() {
        super("functional-profile-identifiers");
        addDeserializer(ExecutionPreset.class,new JsonDeserializer<>() {
            @Override public ExecutionPreset deserialize(JsonParser parser, DeserializationContext context) throws IOException {
                if (!parser.hasToken(JsonToken.VALUE_STRING))
                    return (ExecutionPreset) context.handleUnexpectedToken(ExecutionPreset.class,parser);
                try { return ExecutionPreset.valueOf(parser.getText()); }
                catch (IllegalArgumentException invalid) {
                    throw context.weirdStringException(parser.getText(),ExecutionPreset.class,"Unknown execution preset");
                }
            }
        });
        addSerializer(FunctionalProfile.class,new JsonSerializer<>() {
            @Override public void serialize(FunctionalProfile value, JsonGenerator generator, SerializerProvider provider) throws IOException {
                generator.writeString(value.id());
            }
        });
        addDeserializer(FunctionalProfile.class,new JsonDeserializer<>() {
            @Override public FunctionalProfile deserialize(JsonParser parser, DeserializationContext context) throws IOException {
                if (!parser.hasToken(JsonToken.VALUE_STRING))
                    return (FunctionalProfile) context.handleUnexpectedToken(FunctionalProfile.class,parser);
                try { return FunctionalProfile.fromId(parser.getText()); }
                catch (IllegalArgumentException invalid) {
                    throw context.weirdStringException(parser.getText(),FunctionalProfile.class,"Unknown functional profile identifier");
                }
            }
        });
        addKeySerializer(FunctionalProfile.class,new JsonSerializer<>() {
            @Override public void serialize(FunctionalProfile value,JsonGenerator generator,SerializerProvider provider) throws IOException {
                generator.writeFieldName(value.id());
            }
        });
        addKeyDeserializer(FunctionalProfile.class,new KeyDeserializer() {
            @Override public Object deserializeKey(String key,DeserializationContext context) throws IOException {
                try { return FunctionalProfile.fromId(key); }
                catch (IllegalArgumentException invalid) {
                    throw context.weirdKeyException(FunctionalProfile.class,key,"Unknown functional profile identifier");
                }
            }
        });
    }
}
