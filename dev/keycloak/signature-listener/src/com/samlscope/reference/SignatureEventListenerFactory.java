package com.samlscope.reference;

import java.io.ByteArrayInputStream;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import org.keycloak.Config;
import org.keycloak.events.Event;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.EventListenerProviderFactory;
import org.keycloak.events.EventType;
import org.keycloak.events.admin.AdminEvent;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.w3c.dom.Element;

/** Reference-only observer. It never modifies events, requests, clients or authentication state. */
public final class SignatureEventListenerFactory implements EventListenerProviderFactory {
    public static final String ID = "samlscope-signature-observation";
    private static final String PROTOCOL = "urn:oasis:names:tc:SAML:2.0:protocol";
    private static final String ASSERTION = "urn:oasis:names:tc:SAML:2.0:assertion";
    private static final String ENDPOINT = "http://localhost:18180/realms/samlscope/protocol/saml";

    @Override public EventListenerProvider create(KeycloakSession session) {
        return new EventListenerProvider() {
            @Override public void onEvent(Event event) {
                if (event.getType() != EventType.LOGIN_ERROR || !"invalid_signature".equals(event.getError())) return;
                try {
                    var context = session.getContext();
                    var request = context.getHttpRequest();
                    if (request == null || !"POST".equals(request.getHttpMethod())
                            || context.getRealm() == null || !"samlscope".equals(context.getRealm().getName())) return;
                    // Do not inspect headers, cookies, other fields, identities or credentials.
                    List<String> values = request.getDecodedFormParameters().get("SAMLRequest");
                    if (values == null || values.size() != 1 || values.getFirst().length() > 1_048_576) return;
                    byte[] raw = Base64.getDecoder().decode(values.getFirst());
                    var factory = DocumentBuilderFactory.newInstance();
                    factory.setNamespaceAware(true);
                    factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
                    factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
                    factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
                    factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
                    factory.setExpandEntityReferences(false);
                    factory.setXIncludeAware(false);
                    var builder = factory.newDocumentBuilder();
                    builder.setErrorHandler(new org.xml.sax.helpers.DefaultHandler());
                    Element root = builder.parse(new ByteArrayInputStream(raw)).getDocumentElement();
                    if (!PROTOCOL.equals(root.getNamespaceURI()) || !"AuthnRequest".equals(root.getLocalName())
                            || !ENDPOINT.equals(root.getAttribute("Destination"))) return;
                    String requestId = root.getAttribute("ID");
                    if (!requestId.matches("(?:_action_[0-9a-f]{32}|_metadata_[0-9A-HJKMNP-TV-Z]{26})")) return;
                    var issuers = root.getElementsByTagNameNS(ASSERTION, "Issuer");
                    if (issuers.getLength() != 1 || issuers.item(0).getParentNode() != root) return;
                    String issuer = issuers.item(0).getTextContent();
                    if (!issuer.matches("http://localhost:18080/p/plan_[0-9A-HJKMNP-TV-Z]{26}")) return;
                    if (context.getClient() == null || !issuer.equals(context.getClient().getClientId())) return;
                    if (!"/realms/samlscope/protocol/saml".equals(request.getUri().getRequestUri().getPath())) return;
                    String digest = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(raw));
                    // Every variable is generated or strictly constrained; no untrusted text can inject a log field.
                    System.out.println("SAMLscope-native-signature-v1|" + Instant.now() + "|" + event.getTime()
                            + "|" + requestId + "|" + digest + "|" + issuer + "|LOGIN_ERROR|invalid_signature");
                } catch (Exception unavailable) {
                    // Failure of this observer is missing evidence, never a change to product verification.
                    System.out.println("SAMLscope-native-signature-observation-unavailable");
                }
            }
            @Override public void onEvent(AdminEvent event, boolean includeRepresentation) { }
            @Override public void close() { }
        };
    }
    @Override public String getId() { return ID; }
    @Override public void init(Config.Scope scope) { }
    @Override public void postInit(KeycloakSessionFactory factory) { }
    @Override public void close() { }
}
