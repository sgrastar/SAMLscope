package com.samlscope.saml.normal;

import static org.junit.jupiter.api.Assertions.*;
import java.nio.charset.StandardCharsets;
import java.util.Optional;
import org.junit.jupiter.api.Test;

class SamlTypedStringFixturesTest {
    @Test void everyPlacementHasTypedBoundaryInputsAndDetectableTruncation() {
        var matrix = SamlTypedStringFixtures.matrix();
        assertEquals(80, matrix.size());
        assertEquals(matrix.size(), matrix.stream().map(SamlTypedStringFixtures.Fixture::id).distinct().count());
        for (var fixture : matrix) {
            var root = fixture.create();
            var parsed = SecureXml.parse(SecureXml.serialize(root.getOwnerDocument())).getDocumentElement();
            assertEquals(Optional.empty(), SamlSchemaValidation.stringFixtureValidationFailure(parsed), fixture.id());
            var inspection = SamlSchemaValidation.inspectFixtureStringValues(parsed);
            assertTrue(inspection.schemaValid(), fixture.id());
            var matching = inspection.values().stream().filter(v -> v.value().equals(fixture.value())).toList();
            assertEquals(1, matching.size(), fixture.id());
            assertEquals(fixture.characters().name().endsWith("255") ? 255 : 256,
                    matching.getFirst().value().codePointCount(0, matching.getFirst().value().length()));
            assertEquals(fixture.placement() == SamlTypedStringFixtures.Placement.EXTENSION_STRING_ATTRIBUTE,
                    matching.getFirst().attribute());
            // A target that silently truncates the received value must not match the expected fixture.
            var truncated = fixture.value().substring(0, fixture.value().offsetByCodePoints(0, 254));
            switch (fixture.placement()) {
                case ADVICE_STRING -> parsed.getFirstChild().setTextContent(truncated);
                case EXTENSION_STRING_ATTRIBUTE -> ((org.w3c.dom.Element) parsed.getFirstChild()).setAttribute("value", truncated);
                default -> parsed.setTextContent(truncated);
            }
            var mutated = SamlSchemaValidation.inspectFixtureStringValues(parsed);
            assertTrue(mutated.schemaValid());
            assertTrue(mutated.values().stream().noneMatch(v -> v.value().equals(fixture.value())), fixture.id());
        }
    }

    @Test void customTypeIsOptInAndUnknownTypesDoNotBecomeStrings() {
        var fixture = new SamlTypedStringFixtures.Fixture(SamlTypedStringFixtures.Placement.ATTRIBUTE_VALUE_STRING,
                SamlErrorProbeRequestFactory.Probe.STRING_ASCII_256);
        var root = fixture.create();
        assertFalse(SamlSchemaValidation.inspectStringValues(root, SamlSchemaValidation.SchemaKind.ASSERTION).schemaValid());
        root.setAttributeNS(javax.xml.XMLConstants.W3C_XML_SCHEMA_INSTANCE_NS_URI, "xsi:type", "f:UnknownType");
        assertFalse(SamlSchemaValidation.inspectFixtureStringValues(root).schemaValid());
        assertTrue(SamlSchemaValidation.stringFixtureValidationFailure(root).isPresent());
    }

    @Test void fixtureInstancesDoNotShareMutableDomAndNeverAdvertiseNetworkSchemaLocations() {
        for (var fixture : SamlTypedStringFixtures.matrix()) {
            var first = fixture.create();
            first.setTextContent("mutated");
            var second = fixture.create();
            assertTrue(SamlSchemaValidation.inspectFixtureStringValues(second).values().stream()
                    .anyMatch(v -> v.value().equals(fixture.value())));
            assertFalse(new String(SecureXml.serialize(second.getOwnerDocument()), StandardCharsets.UTF_8).contains("schemaLocation"));
        }
        assertThrows(IllegalArgumentException.class, () -> new SamlTypedStringFixtures.Fixture(
                SamlTypedStringFixtures.Placement.ADVICE_STRING, SamlErrorProbeRequestFactory.Probe.BASELINE_SUCCESS));
    }
}
