package com.samlscope.api;

import com.samlscope.core.profile.FunctionalProfile;
import java.io.IOException;
import java.util.EnumMap;
import java.util.Map;
import java.util.Properties;

/** Loads only profile definitions named by the independently reviewed release allowlist. */
final class FunctionalProfileDocuments {
    private FunctionalProfileDocuments() {}

    record Bundle(Map<FunctionalProfile, byte[]> artifacts, Map<FunctionalProfile, String> digests) {}

    static Bundle load() {
        var properties = new Properties();
        try (var pins = FunctionalProfileDocuments.class.getResourceAsStream(
                "/profiles/release-pins.properties")) {
            if (pins == null) throw new IllegalStateException("Missing functional profile release pins");
            properties.load(pins);
        } catch (IOException error) {
            throw new IllegalStateException("Could not read functional profile release pins", error);
        }

        var artifacts = new EnumMap<FunctionalProfile, byte[]>(FunctionalProfile.class);
        var digests = new EnumMap<FunctionalProfile, String>(FunctionalProfile.class);
        properties.forEach((rawProfile, rawDigest) -> {
            var profile = FunctionalProfile.fromId(rawProfile.toString());
            var digest = rawDigest.toString();
            if (!digest.matches("sha256:[0-9a-f]{64}")) {
                throw new IllegalStateException("Invalid functional profile release pin: " + profile.id());
            }
            try (var document = FunctionalProfileDocuments.class.getResourceAsStream(
                    "/profiles/" + profile.id() + ".json")) {
                if (document == null) {
                    throw new IllegalStateException("Missing released functional profile: " + profile.id());
                }
                artifacts.put(profile, document.readAllBytes());
                digests.put(profile, digest);
            } catch (IOException error) {
                throw new IllegalStateException("Could not read functional profile: " + profile.id(), error);
            }
        });
        return new Bundle(Map.copyOf(artifacts), Map.copyOf(digests));
    }
}
