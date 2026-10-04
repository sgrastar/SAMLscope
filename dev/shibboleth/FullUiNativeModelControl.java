import java.io.FileInputStream;
import org.opensaml.core.config.InitializationService;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.SPSSODescriptor;
import net.shibboleth.shared.xml.SerializeSupport;

/** Public native-model detector calibration only. Never a product finding or a production adapter. */
public final class FullUiNativeModelControl {
    public static void main(String[] args) throws Exception {
        if (args.length != 2 || !(args[0].equals("stock") || args[0].equals("ignore-full-ui")))
            throw new IllegalArgumentException("Expected explicit native model control mode and input");
        InitializationService.initialize();
        for (String name : new String[]{"org.opensaml.saml.saml2.metadata.impl.EntityDescriptorImpl",
                "org.opensaml.saml.ext.saml2mdui.impl.UIInfoUnmarshaller",
                "org.opensaml.saml.ext.saml2mdui.impl.DiscoHintsUnmarshaller"}) {
            var type = Class.forName(name);
            var path = java.nio.file.Path.of(type.getProtectionDomain().getCodeSource().getLocation().toURI());
            var hash = java.util.HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256")
                    .digest(java.nio.file.Files.readAllBytes(path)));
            System.err.println("FULL_UI_MODEL_SOURCE|" + name + "|" + hash);
        }
        EntityDescriptor entity;
        try (var input = new FileInputStream(args[1])) {
            entity = (EntityDescriptor) XMLObjectSupport.unmarshallFromInputStream(
                    XMLObjectProviderRegistrySupport.getParserPool(), input);
        }
        var roles = entity.getRoleDescriptors(SPSSODescriptor.DEFAULT_ELEMENT_NAME);
        if (roles.size() != 1 || roles.get(0).getExtensions() == null)
            throw new IllegalArgumentException("Expected one complete SP metadata role");
        if (args[0].equals("ignore-full-ui")) {
            // This deliberately faulty consumer keeps the peer and all non-UI metadata intact.
            roles.get(0).getExtensions().getUnknownXMLObjects().removeIf(value ->
                    value.getElementQName().getNamespaceURI().equals("urn:oasis:names:tc:SAML:metadata:ui")
                    && (value.getElementQName().getLocalPart().equals("UIInfo")
                        || value.getElementQName().getLocalPart().equals("DiscoHints")));
            entity.releaseDOM(); entity.releaseChildrenDOM(true);
        }
        System.out.print(SerializeSupport.prettyPrintXML(XMLObjectSupport.marshall(entity)));
    }
}
