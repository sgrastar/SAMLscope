package com.samlscope.runner.cases;

import com.samlscope.store.JsonCodec;
import java.net.URLClassLoader;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.time.Instant;
import java.util.*;

/** Invoke immutable product parser bytes; emits observations and never an outcome. */
public final class ObserveKeycloakExtensionAttributeParser {
    public static void main(String[] args) throws Exception {
        if (args.length != 4) throw new IllegalArgumentException("native-jars input.xml control.xml output.json");
        var jars = Path.of(args[0]); var input = Files.readAllBytes(Path.of(args[1]));
        var control = Files.readAllBytes(Path.of(args[2])); var urls = new ArrayList<java.net.URL>();
        for (var jar : KeycloakNativeSchemaAdmissionEvidence.NATIVE_JARS.entrySet()) {
            var path = jars.resolve(jar.getKey());
            if (!ExtensionAttributeParserEvidence.sha(Files.readAllBytes(path)).equals(jar.getValue()))
                throw new IllegalArgumentException("Product artifact differs from qualified version");
            if (!jar.getKey().contains("services")) urls.add(path.toUri().toURL());
        }
        var start = Instant.now(); NativeMetadataParserProjection.Observation actual, baseline;
        try (var loader = new URLClassLoader(urls.toArray(java.net.URL[]::new), ClassLoader.getPlatformClassLoader())) {
            actual = NativeMetadataParserProjection.observe(loader, input);
            baseline = NativeMetadataParserProjection.observe(loader, control);
        }
        var output = new LinkedHashMap<String,Object>();
        output.put("nativeMethod", "org.keycloak.saml.processing.core.parsers.saml.SAMLParser#parse(XMLEventReader)");
        output.put("inputSha256", ExtensionAttributeParserEvidence.sha(input));
        output.put("controlSha256", ExtensionAttributeParserEvidence.sha(control));
        output.put("inputTreeBase64", Base64.getEncoder().encodeToString(actual.tree().getBytes(StandardCharsets.UTF_8)));
        output.put("controlTreeBase64", Base64.getEncoder().encodeToString(baseline.tree().getBytes(StandardCharsets.UTF_8)));
        output.put("inputRootType", actual.rootType()); output.put("controlRootType", baseline.rootType());
        output.put("inputEntityIds", actual.entityIds()); output.put("controlEntityIds", baseline.entityIds());
        output.put("inputAffiliationDescriptorPresent", actual.affiliationDescriptorPresent());
        output.put("controlAffiliationDescriptorPresent", baseline.affiliationDescriptorPresent());
        output.put("nativeJars", KeycloakNativeSchemaAdmissionEvidence.NATIVE_JARS);
        output.put("startedAt", start.toString()); output.put("finishedAt", Instant.now().toString());
        output.put("exitCode", 0);
        new JsonCodec().mapper().writeValue(Path.of(args[3]).toFile(), output);
    }
}
