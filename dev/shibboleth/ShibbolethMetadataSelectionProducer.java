import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.ByteArrayInputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import net.shibboleth.idp.saml.profile.impl.PopulateBindingAndEndpointContexts;
import net.shibboleth.idp.saml.saml2.profile.config.impl.BrowserSSOProfileConfiguration;
import net.shibboleth.idp.saml.saml2.profile.config.impl.SingleLogoutProfileConfiguration;
import net.shibboleth.profile.context.RelyingPartyContext;
import org.opensaml.core.config.InitializationService;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.profile.context.EventContext;
import org.opensaml.profile.context.ProfileRequestContext;
import org.opensaml.saml.common.binding.AbstractEndpointResolver;
import org.opensaml.saml.common.binding.BindingDescriptor;
import org.opensaml.saml.common.binding.impl.DefaultEndpointResolver;
import org.opensaml.saml.common.messaging.context.SAMLBindingContext;
import org.opensaml.saml.common.messaging.context.SAMLEndpointContext;
import org.opensaml.saml.common.messaging.context.SAMLMetadataContext;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.metadata.AssertionConsumerService;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.SingleLogoutService;
import org.opensaml.saml.saml2.metadata.SPSSODescriptor;
import org.w3c.dom.Element;

/** Public saved-request replay of the stock selector. No HTTP, private key, or IdP setting access. */
public final class ShibbolethMetadataSelectionProducer {
    static final String BROWSER = "http://shibboleth.net/ns/profiles/saml2/sso/browser";
    static final String ECP = "http://shibboleth.net/ns/profiles/saml2/sso/ecp";
    static final String LOGOUT = "http://shibboleth.net/ns/profiles/saml2/logout";
    static final String BEANS = "http://www.springframework.org/schema/beans";
    static final String UTIL = "http://www.springframework.org/schema/util";
    static final String PROPS = "http://www.springframework.org/schema/p";
    static String sha(byte[] raw) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(raw));
    }
    static void require(boolean value) {
        if (!value) throw new IllegalArgumentException("Public native selector input incomplete");
    }
    static byte[] resource(Class<?> cls, String name) throws Exception {
        try (var in = cls.getResourceAsStream(name)) {
            require(in != null);
            return in.readAllBytes();
        }
    }
    static String classHash(Class<?> cls) throws Exception {
        return sha(resource(cls, "/" + cls.getName().replace('.', '/') + ".class"));
    }
    static String jarHash(Class<?> cls) throws Exception {
        return sha(Files.readAllBytes(Path.of(cls.getProtectionDomain().getCodeSource().getLocation().toURI())));
    }
    static List<BindingDescriptor> bindings(Element config, String name) throws Exception {
        var result = new ArrayList<BindingDescriptor>();
        Element list = null;
        var lists = config.getElementsByTagNameNS(UTIL, "list");
        for (int i = 0; i < lists.getLength(); i++) {
            Element e = (Element) lists.item(i);
            if (name.equals(e.getAttribute("id"))) { require(list == null); list = e; }
        }
        require(list != null);
        for (var child = list.getFirstChild(); child != null; child = child.getNextSibling()) {
            if (!(child instanceof Element elem)) continue;
            Element descriptor = elem;
            if ("ref".equals(elem.getLocalName())) {
                descriptor = null;
                var beans = config.getElementsByTagNameNS(BEANS, "bean");
                for (int i = 0; i < beans.getLength(); i++) {
                    Element bean = (Element) beans.item(i);
                    if (elem.getAttribute("bean").equals(bean.getAttribute("id"))) {
                        require(descriptor == null); descriptor = bean;
                    }
                }
                require(descriptor != null);
            }
            require("shibboleth.BindingDescriptor".equals(descriptor.getAttribute("parent")));
            var binding = new BindingDescriptor();
            binding.setId(descriptor.getAttributeNS(PROPS, "id"));
            binding.setShortName(descriptor.getAttributeNS(PROPS, "shortName"));
            binding.setSynchronous("true".equals(descriptor.getAttributeNS(PROPS, "synchronous")));
            binding.setArtifact("true".equals(descriptor.getAttributeNS(PROPS, "artifact")));
            binding.setSignatureCapable("true".equals(descriptor.getAttributeNS(PROPS, "signatureCapable")));
            String activation = descriptor.getAttributeNS(PROPS, "activationCondition");
            require(activation.isEmpty() || activation.equals("%{idp.artifact.enabled:true}"));
            binding.initialize();
            result.add(binding);
        }
        require(!result.isEmpty());
        return result;
    }
    public static void main(String[] args) throws Exception {
        require(args.length == 2);
        var mapper = new ObjectMapper();
        byte[] inputRaw = Files.readAllBytes(Path.of(args[0]));
        JsonNode input = mapper.readTree(inputRaw);
        require("samlscope-native-metadata-selection-input-v1".equals(input.path("schema").asText())
                && "stock-native-consumer".equals(input.path("purpose").asText()));
        InitializationService.initialize();
        var parser = XMLObjectProviderRegistrySupport.getParserPool();
        byte[] bindingRaw = resource(PopulateBindingAndEndpointContexts.class,
                "/net/shibboleth/idp/conf/saml-binding-config.xml");
        Element config = parser.parse(new ByteArrayInputStream(bindingRaw)).getDocumentElement();
        var rows = new ArrayList<Map<String, Object>>();
        require(input.path("records").isArray() && input.path("records").size() == 7);
        for (JsonNode row : input.path("records")) {
            byte[] metadataRaw = Base64.getDecoder().decode(row.path("metadataBase64").asText());
            byte[] requestRaw = Base64.getDecoder().decode(row.path("requestBase64").asText());
            require(sha(metadataRaw).equals(row.path("metadataSha256").asText())
                    && sha(requestRaw).equals(row.path("requestSha256").asText()));
            var orderingResults = new ArrayList<Map<String, Object>>();
            for (boolean inMetadataOrder : List.of(true, false)) {
            var metadata = (EntityDescriptor) XMLObjectSupport.unmarshallFromInputStream(parser,
                    new ByteArrayInputStream(metadataRaw));
            SPSSODescriptor role = metadata.getSPSSODescriptor("urn:oasis:names:tc:SAML:2.0:protocol");
            require(role != null && metadata.getEntityID().equals(input.path("entityId").asText()));
            Element requestDom = parser.parse(new ByteArrayInputStream(requestRaw)).getDocumentElement();
            if ("Envelope".equals(requestDom.getLocalName())) {
                var body = requestDom.getElementsByTagNameNS("http://schemas.xmlsoap.org/soap/envelope/", "Body");
                require(body.getLength() == 1);
                var requests = ((Element) body.item(0)).getElementsByTagNameNS(
                        "urn:oasis:names:tc:SAML:2.0:protocol", "AuthnRequest");
                require(requests.getLength() == 1);
                requestDom = (Element) requests.item(0);
            }
            var request = XMLObjectSupport.getUnmarshaller(requestDom).unmarshall(requestDom);
            var context = new ProfileRequestContext();
            String profile = row.path("profileId").asText();
            require(List.of(BROWSER, ECP, LOGOUT).contains(profile));
            context.setProfileId(profile);
            context.setBrowserProfile(!ECP.equals(profile));
            var inbound = new MessageContext(); inbound.setMessage(request);
            inbound.ensureSubcontext(SAMLBindingContext.class).setBindingUri(row.path("inboundBinding").asText());
            context.setInboundMessageContext(inbound);
            context.setOutboundMessageContext(new MessageContext());
            var rp = new RelyingPartyContext(); rp.setVerified(true); rp.setRelyingPartyId(metadata.getEntityID());
            if (request instanceof AuthnRequest) {
                var cfg = new BrowserSSOProfileConfiguration();
                cfg.setSkipEndpointValidationWhenSigned(false); cfg.setIgnoreRequestSignatures(false);
                rp.setProfileConfig(cfg);
            } else rp.setProfileConfig(new SingleLogoutProfileConfiguration());
            var mdContext = new SAMLMetadataContext(); mdContext.setEntityDescriptor(metadata); mdContext.setRoleDescriptor(role);
            var endpointContext = new SAMLEndpointContext(); var bindingContext = new SAMLBindingContext();
            var resolver = new DefaultEndpointResolver<>();
            resolver.setInMetadataOrder(inMetadataOrder); resolver.initialize();
            String listName = row.path("outgoingList").asText();
            require(List.of("shibboleth.OutgoingSAML2SSOBindings", "shibboleth.OutgoingECPBindings",
                    "shibboleth.OutgoingSAML2SLOFrontBindings", "shibboleth.OutgoingSOAPBindings").contains(listName));
            var descriptors = bindings(config, listName);
            var action = new PopulateBindingAndEndpointContexts();
            action.setEndpointType(request instanceof AuthnRequest
                    ? AssertionConsumerService.DEFAULT_ELEMENT_NAME : SingleLogoutService.DEFAULT_ELEMENT_NAME);
            action.setEndpointResolver(resolver); action.setBindingDescriptorsLookupStrategy(c -> descriptors);
            action.setRelyingPartyContextLookupStrategy(c -> rp); action.setMetadataContextLookupStrategy(c -> mdContext);
            action.setEndpointContextLookupStrategy(c -> endpointContext); action.setBindingContextLookupStrategy(c -> bindingContext);
            action.initialize(); action.execute(context);
            var result = new LinkedHashMap<String, Object>();
            for (String key : List.of("label", "requestReference", "requestSha256", "metadataSha256", "profileId",
                    "inboundBinding", "outgoingList", "observationPurpose")) result.put(key, row.path(key).asText());
            result.put("candidateBindings", descriptors.stream().map(BindingDescriptor::getId).toList());
            var selected = endpointContext.getEndpoint();
            result.put("selectedLocation", selected == null ? null : selected.getLocation());
            result.put("selectedBinding", bindingContext.getBindingUri());
            var event = context.getSubcontext(EventContext.class);
            result.put("event", event == null ? null : String.valueOf(event.getEvent()));
            result.put("inMetadataOrder", inMetadataOrder);
            orderingResults.add(result);
            }
            var selected = new LinkedHashMap<String, Object>(orderingResults.get(0));
            var first = new LinkedHashMap<String, Object>(orderingResults.get(0));
            var second = new LinkedHashMap<String, Object>(orderingResults.get(1));
            first.remove("inMetadataOrder"); second.remove("inMetadataOrder");
            require(first.equals(second));
            selected.remove("inMetadataOrder");
            selected.put("orderingResults", orderingResults);
            rows.add(selected);
        }
        var classHashes = new TreeMap<String, String>();
        for (Class<?> cls : List.of(PopulateBindingAndEndpointContexts.class, DefaultEndpointResolver.class,
                AbstractEndpointResolver.class, BindingDescriptor.class)) classHashes.put(cls.getName(), classHash(cls));
        var result = new LinkedHashMap<String, Object>();
        result.put("schema", "samlscope-native-metadata-selection-output-v1");
        result.put("purpose", "stock-native-consumer"); result.put("runId", input.path("runId").asText());
        result.put("entityId", metadataEntity(input)); result.put("inputSha256", sha(inputRaw));
        result.put("sourceSha256", sha(Files.readAllBytes(Path.of(args[1]))));
        result.put("idpSamlJarSha256", jarHash(PopulateBindingAndEndpointContexts.class));
        result.put("resolverJarSha256", jarHash(DefaultEndpointResolver.class));
        result.put("bindingConfigurationSha256", sha(bindingRaw)); result.put("selectedNativeClassHashes", classHashes);
        result.put("records", rows); result.put("productSettings", 0); result.put("protocolOperations", 0);
        result.put("credentialPosts", 0); result.put("privateKeyRead", false);
        System.out.println(mapper.writeValueAsString(result));
    }
    static String metadataEntity(JsonNode input) { return input.path("entityId").asText(); }
}
