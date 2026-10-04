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

/** Installed native getter diagnosis only; no browser execution, request, configuration, or outcome. */
public final class NativeUiUrlProbe {
    static String hash(byte[] raw) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(raw));
    }
    public static void main(String[] args) throws Exception {
        if(args.length!=1)throw new IllegalArgumentException("Fixture directory required");
        InitializationService.initialize();
        var source=Path.of(RelyingPartyUIContext.class.getProtectionDomain().getCodeSource().getLocation().toURI());
        var jarHash=hash(Files.readAllBytes(source));
        var factory=DocumentBuilderFactory.newInstance();factory.setNamespaceAware(true);
        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING,true);
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl",true);
        factory.setFeature("http://xml.org/sax/features/external-general-entities",false);
        factory.setFeature("http://xml.org/sax/features/external-parameter-entities",false);
        factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD,"");factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA,"");
        for(var element:List.of("logo","information","privacy"))for(var scheme:List.of("http","https","data","javascript","file")) {
            var condition="ui-url-"+element+"-"+scheme;
            var raw=Files.readAllBytes(Path.of(args[0]).resolve(condition).resolve("fixture.xml"));
            var root=factory.newDocumentBuilder().parse(new java.io.ByteArrayInputStream(raw)).getDocumentElement();
            var object=XMLObjectSupport.getUnmarshaller(root).unmarshall(root);
            if(!(object instanceof EntityDescriptor entity))throw new IllegalArgumentException("Single entity required");
            var role=entity.getSPSSODescriptor(SAMLConstants.SAML20P_NS);
            if(role==null||role.getExtensions()==null)throw new IllegalArgumentException("SP UI metadata required");
            var infos=role.getExtensions().getUnknownXMLObjects(UIInfo.DEFAULT_ELEMENT_NAME);
            if(infos.size()!=1)throw new IllegalArgumentException("Unique native UIInfo required");
            var info=(UIInfo)infos.get(0);
            var name=switch(element){case "logo"->"Logo";case "information"->"InformationURL";default->"PrivacyStatementURL";};
            var candidates=root.getElementsByTagNameNS("urn:oasis:names:tc:SAML:metadata:ui",name);
            if(candidates.getLength()!=1)throw new IllegalArgumentException("Unique URL required");
            var supplied=candidates.item(0).getTextContent();
            if(!scheme.equals(java.net.URI.create(supplied).getScheme()))throw new IllegalArgumentException("Scheme mismatch");
            var context=new RelyingPartyUIContext().setRPEntityDescriptor(entity).setRPSPSSODescriptor(role)
                    .setRPUInfo(info).setBrowserLanguageRanges(Locale.LanguageRange.parse("en-US,en"))
                    .setFallbackLanguages(List.of("en"));
            var returned=switch(element){case "logo"->context.getLogo();case "information"->context.getInformationURL();
                default->context.getPrivacyStatementURL();};
            var status=returned==null?"null":returned.equals(supplied)?"candidate-returned":"different-value";
            // Only fixed tokens and hashes leave this native probe. No URL, principal, or credential.
            System.out.println("SAMLSCOPE_UI_PROBE\t"+condition+"\t"+hash(raw)+"\t"+status+"\t"+jarHash);
        }
    }
}
