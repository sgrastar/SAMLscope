import java.io.*;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
import com.fasterxml.jackson.databind.*;
import org.opensaml.core.config.InitializationService;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.saml2.metadata.*;
import org.opensaml.security.credential.UsageType;
import org.opensaml.xmlsec.signature.*;

/** Native metadata object producer controls. These outputs are oracle calibration only. */
public final class ObserveShibbolethPublisherControls {
    static final ObjectMapper JSON=new ObjectMapper();
    static final String MD="urn:oasis:names:tc:SAML:2.0:metadata", P="urn:oasis:names:tc:SAML:2.0:protocol";
    static void require(boolean b){if(!b)throw new IllegalArgumentException("Unbound native publisher control");}
    @SuppressWarnings("unchecked") static <T> T build(javax.xml.namespace.QName name){
        var builder=XMLObjectProviderRegistrySupport.getBuilderFactory().getBuilder(name);require(builder!=null);
        return (T)builder.buildObject(name);
    }
    static String sha(byte[] b)throws Exception{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(b));}
    static byte[] produce(JsonNode input,boolean omitTransport)throws Exception{
        EntityDescriptor entity=build(EntityDescriptor.DEFAULT_ELEMENT_NAME);entity.setEntityID(input.path("entityId").asText());
        IDPSSODescriptor role=build(IDPSSODescriptor.DEFAULT_ELEMENT_NAME);role.addSupportedProtocol(P);entity.getRoleDescriptors().add(role);
        for(var row:input.path("roleKeys")){
            String purpose=row.path("purpose").asText();require(Set.of("signing","encryption","transport-authentication").contains(purpose));
            if(omitTransport && purpose.equals("transport-authentication"))continue;
            KeyDescriptor key=build(KeyDescriptor.DEFAULT_ELEMENT_NAME);key.setUse(purpose.equals("encryption")?UsageType.ENCRYPTION:UsageType.SIGNING);
            KeyInfo info=build(KeyInfo.DEFAULT_ELEMENT_NAME);X509Data data=build(X509Data.DEFAULT_ELEMENT_NAME);
            org.opensaml.xmlsec.signature.X509Certificate cert=build(org.opensaml.xmlsec.signature.X509Certificate.DEFAULT_ELEMENT_NAME);
            cert.setValue(row.path("certificateDerBase64").asText());data.getX509Certificates().add(cert);info.getX509Datas().add(data);key.setKeyInfo(info);role.getKeyDescriptors().add(key);
        }
        for(var row:input.path("endpoints")){
            require("SingleSignOnService".equals(row.path("kind").asText()));
            SingleSignOnService endpoint=build(SingleSignOnService.DEFAULT_ELEMENT_NAME);endpoint.setBinding(row.path("binding").asText());endpoint.setLocation(row.path("location").asText());role.getSingleSignOnServices().add(endpoint);
        }
        ByteArrayOutputStream out=new ByteArrayOutputStream();XMLObjectSupport.marshallToOutputStream(entity,out);return out.toByteArray();
    }
    public static void main(String[] args)throws Exception{
        require(args.length==2);Path inputPath=Path.of(args[0]),output=Path.of(args[1]);require(!Files.exists(output));Files.createDirectories(output);
        byte[] raw=Files.readAllBytes(inputPath);JsonNode input=JSON.readTree(raw);
        require("samlscope-shibboleth-publisher-control-input-v1".equals(input.path("schema").asText())&&"oracle-calibration-only".equals(input.path("purpose").asText()));
        require(input.path("roleKeys").isArray()&&input.path("roleKeys").size()==3&&input.path("endpoints").isArray()&&input.path("endpoints").size()==1);
        InitializationService.initialize();byte[] positive=produce(input,false),negative=produce(input,true);
        require(!Arrays.equals(positive,negative));Files.write(output.resolve("positive.xml"),positive);Files.write(output.resolve("negative.xml"),negative);
        var origins=new TreeMap<String,String>();for(var c:List.of(InitializationService.class,XMLObjectSupport.class,org.opensaml.saml.saml2.metadata.impl.EntityDescriptorBuilder.class,net.shibboleth.idp.Version.class))origins.put(c.getName(),c.getProtectionDomain().getCodeSource().getLocation().toString());
        JSON.writerWithDefaultPrettyPrinter().writeValue(output.resolve("observation.json").toFile(),Map.of("schema","samlscope-shibboleth-publisher-control-observation-v1","purpose","oracle-calibration-only","productVersion",net.shibboleth.idp.Version.getVersion(),"inputSha256",sha(raw),"positiveSha256",sha(positive),"negativeSha256",sha(negative),"nativeClassOrigins",origins));
        System.out.println("Native publisher controls produced: positive and transport-key omission");
    }
}
