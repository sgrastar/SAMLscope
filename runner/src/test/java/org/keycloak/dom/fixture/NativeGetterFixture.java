package org.keycloak.dom.fixture;

import java.util.Map;
import javax.xml.namespace.QName;

/** Test-only native-shaped object: every getter must be included without attribute filtering. */
public final class NativeGetterFixture {
    private final String entity;
    private final Map<QName,String> attributes;
    public NativeGetterFixture(String entity, Map<QName,String> attributes) { this.entity = entity; this.attributes = attributes; }
    public String getEntityID() { return entity; }
    public Map<QName,String> getOtherAttributes() { return attributes; }
    public boolean isEnabled() { return true; }
}
