package com.samlscope.runner.cases;

import static org.junit.jupiter.api.Assertions.*;
import java.util.*;
import javax.xml.namespace.QName;
import com.samlscope.saml.normal.SecureXml;
import org.junit.jupiter.api.Test;
import org.keycloak.dom.fixture.NativeGetterFixture;

class NativeMetadataParserProjectionTest {
    @Test void retainedForeignAttributesAndEveryNativeGetterChangeTheTree() throws Exception {
        var name = new QName("urn:foreign", "undefined", "foreign");
        var baseline = new NativeGetterFixture("urn:entity", Map.of());
        var retained = new NativeGetterFixture("urn:entity", Map.of(name, "ignored-content"));
        var changedEntity = new NativeGetterFixture("urn:other", Map.of());
        var tree = NativeMetadataParserProjection.project(baseline);
        assertNotEquals(tree, NativeMetadataParserProjection.project(retained));
        assertNotEquals(tree, NativeMetadataParserProjection.project(changedEntity));
        assertTrue(NativeMetadataParserProjection.project(retained).contains("ignored-content"));
        assertTrue(tree.contains("isEnabled"));
    }
    @Test void domAttributesTextAndChildOrderAreNotFiltered() throws Exception {
        var baseline = SecureXml.parse("<r xmlns:f='urn:foreign'><a>one</a><b>two</b></r>".getBytes()).getDocumentElement();
        var withAttribute = (org.w3c.dom.Element) baseline.cloneNode(true);
        withAttribute.setAttributeNS("urn:foreign", "f:undefined", "foreign-value");
        assertNotEquals(NativeMetadataParserProjection.project(baseline), NativeMetadataParserProjection.project(withAttribute));
        var reordered = SecureXml.parse("<r xmlns:f='urn:foreign'><b>two</b><a>one</a></r>".getBytes()).getDocumentElement();
        assertNotEquals(NativeMetadataParserProjection.project(baseline), NativeMetadataParserProjection.project(reordered));
    }
    @Test void mapsAreCanonicalAndListsPreserveOrder() throws Exception {
        var a = new LinkedHashMap<String,String>(); a.put("two", "2"); a.put("one", "1");
        var b = new LinkedHashMap<String,String>(); b.put("one", "1"); b.put("two", "2");
        assertEquals(NativeMetadataParserProjection.project(a), NativeMetadataParserProjection.project(b));
        assertNotEquals(NativeMetadataParserProjection.project(List.of("one", "two")), NativeMetadataParserProjection.project(List.of("two", "one")));
    }
    @Test void unobservableOrRecursiveObjectTypesFailClosed() {
        assertThrows(IllegalArgumentException.class, () -> NativeMetadataParserProjection.project(new Object()));
        var cycle = new ArrayList<Object>(); cycle.add(cycle);
        assertThrows(IllegalArgumentException.class, () -> NativeMetadataParserProjection.project(cycle));
    }
}
