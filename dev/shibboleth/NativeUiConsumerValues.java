import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import net.shibboleth.idp.ui.context.RelyingPartyUIContext;
import org.opensaml.core.config.InitializationService;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.ext.saml2mdui.UIInfo;

/** Product-native supplement to the actual request-bound browser observation.
 * This isolated getter result is not itself a product-conformance verdict.
 */
public final class NativeUiConsumerValues {
    static String hash(byte[] raw)throws Exception{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(raw));}
    public static void main(String[] args)throws Exception {
        if(args.length!=1)throw new IllegalArgumentException("Public fixture directory required");
        InitializationService.initialize();
        var factory=DocumentBuilderFactory.newInstance();factory.setNamespaceAware(true);
        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING,true);
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl",true);
        factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD,"");factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA,"");
        var source=Path.of(RelyingPartyUIContext.class.getProtectionDomain().getCodeSource().getLocation().toURI());
        var sourceHash=hash(Files.readAllBytes(source));
        for(var folder:Files.list(Path.of(args[0])).filter(Files::isDirectory).sorted().toList()) {
            var file=folder.resolve("native-effective-metadata.xml");if(!Files.exists(file))continue;
            var raw=Files.readAllBytes(file);var root=factory.newDocumentBuilder().parse(new java.io.ByteArrayInputStream(raw)).getDocumentElement();
            var object=XMLObjectSupport.getUnmarshaller(root).unmarshall(root);
            if(!(object instanceof EntityDescriptor entity))throw new IllegalArgumentException("Single native entity required");
            var role=entity.getSPSSODescriptor(SAMLConstants.SAML20P_NS);if(role==null)throw new IllegalArgumentException("SP role required");
            var context=new RelyingPartyUIContext().setRPEntityDescriptor(entity).setRPSPSSODescriptor(role)
                .setBrowserLanguageRanges(Locale.LanguageRange.parse("en-US,en")).setFallbackLanguages(List.of("en","fr","de"));
            if(role.getExtensions()!=null) {
                var infos=role.getExtensions().getUnknownXMLObjects(UIInfo.DEFAULT_ELEMENT_NAME);
                if(infos.size()>1)throw new IllegalArgumentException("Unique UIInfo required");
                if(!infos.isEmpty())context.setRPUInfo((UIInfo)infos.get(0));
            }
            if(role.getAttributeConsumingServices().size()>1)throw new IllegalArgumentException("Unique native ACS info required");
            if(!role.getAttributeConsumingServices().isEmpty())context.setRPAttributeConsumingService(role.getAttributeConsumingServices().get(0));
            // Return only fixed public fixture tokens. Never export an unknown/native principal or URL.
            var name=context.getServiceName();var nameToken=name==null?"null":name.equals(entity.getEntityID())?"entity"
                :name.equals(java.net.URI.create(entity.getEntityID()).getHost())?"hostname"
                :name.equals("SAMLscope UI display candidate")?"display":name.equals("SAMLscope service candidate")?"service"
                :name.equals("SAMLscope URL policy control")?"url-control":name.equals("SAMLscope UI display candidate (en)")?"full-control":"other";
            var nodes=root.getElementsByTagNameNS("urn:oasis:names:tc:SAML:metadata:ui","Logo");
            String logo=context.getLogo();var logoToken=logo==null?"null":nodes.getLength()==1&&logo.equals(nodes.item(0).getTextContent())?"candidate":"other";
            System.out.println("SAMLSCOPE_NATIVE_UI\t"+folder.getFileName()+"\t"+hash(raw)+"\t"+nameToken+"\t"+logoToken+"\t"+sourceHash);
        }
    }
}
