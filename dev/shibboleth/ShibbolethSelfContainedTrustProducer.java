import java.io.*;
import java.nio.file.*;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.util.*;
import com.fasterxml.jackson.databind.*;
import net.shibboleth.shared.resolver.CriteriaSet;
import org.opensaml.core.config.InitializationService;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml.metadata.resolver.impl.DOMMetadataResolver;
import org.opensaml.saml.metadata.resolver.impl.PredicateRoleDescriptorResolver;
import org.opensaml.saml.security.impl.MetadataCredentialResolver;
import org.opensaml.saml.criterion.EntityRoleCriterion;
import org.opensaml.core.criterion.EntityIdCriterion;
import org.opensaml.security.criteria.UsageCriterion;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.UsageType;
import org.opensaml.security.credential.impl.StaticCredentialResolver;
import org.opensaml.xmlsec.config.impl.DefaultSecurityConfigurationBootstrap;
import org.opensaml.xmlsec.signature.support.impl.ExplicitKeySignatureTrustEngine;
import org.w3c.dom.Element;

/** Public original-backed trust-engine calibration; no private key, settings or protocol operation. */
public final class ShibbolethSelfContainedTrustProducer {
    static String sha(byte[] raw)throws Exception{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(raw));}
    static void require(boolean value){if(!value)throw new IllegalArgumentException("Public native trust fixture incomplete");}
    static String classHash(Class<?> type)throws Exception{try(var in=type.getResourceAsStream("/"+type.getName().replace('.','/')+".class")){require(in!=null);return sha(in.readAllBytes());}}
    public static void main(String[] args)throws Exception {
        require(args.length==3);String selectedPath=args[2];require(List.of("stock-native-signature-encryption","developer-instrumented-additional-anchor").contains(selectedPath));boolean calibration=selectedPath.startsWith("developer-");var mapper=new ObjectMapper();byte[] raw=Files.readAllBytes(Path.of(args[0]));var input=mapper.readTree(raw);
        require("samlscope-shibboleth-self-contained-trust-input-v2".equals(input.path("schema").asText())&&input.path("records").size()==4&&selectedPath.equals(input.path("selectedPath").asText()));
        InitializationService.initialize();var parser=XMLObjectProviderRegistrySupport.getParserPool();
        var keyInfo=DefaultSecurityConfigurationBootstrap.buildBasicInlineKeyInfoCredentialResolver();
        var rows=new ArrayList<Map<String,Object>>();var resolvers=new ArrayList<MetadataCredentialResolver>();
        var requests=new ArrayList<AuthnRequest>();var criteria=new ArrayList<CriteriaSet>();
        for(var row:input.path("records")) {
            byte[] metadata=Base64.getDecoder().decode(row.path("metadataBase64").asText());
            byte[] request=Base64.getDecoder().decode(row.path("requestBase64").asText());
            require(sha(metadata).equals(row.path("metadataSha256").asText())&&sha(request).equals(row.path("requestSha256").asText()));
            Element element=parser.parse(new ByteArrayInputStream(metadata)).getDocumentElement();
            require(element.getAttribute("entityID").equals(row.path("peerEntityId").asText()));
            var document=new DOMMetadataResolver(element);document.setId("public-original-"+row.path("label").asText());document.setRequireValidMetadata(false);document.initialize();
            var roles=new PredicateRoleDescriptorResolver(document);roles.initialize();
            var resolver=new MetadataCredentialResolver();resolver.setRoleDescriptorResolver(roles);resolver.setKeyInfoCredentialResolver(keyInfo);resolver.initialize();
            var message=(AuthnRequest)XMLObjectSupport.unmarshallFromInputStream(parser,new ByteArrayInputStream(request));
            require(message.getSignature()!=null&&message.getIssuer().getValue().equals(element.getAttribute("entityID")));
            var query=new CriteriaSet(new EntityIdCriterion(element.getAttribute("entityID")),new EntityRoleCriterion(SPSSODescriptor.DEFAULT_ELEMENT_NAME),new UsageCriterion(UsageType.SIGNING));
            require(new ExplicitKeySignatureTrustEngine(resolver,keyInfo).validate(message.getSignature(),query));
            resolvers.add(resolver);requests.add(message);criteria.add(query);
        }
        for(int i=0;i<4;i++) {
            var row=input.path("records").get(i);var own=new ArrayList<Credential>();resolvers.get(i).resolve(criteria.get(i)).forEach(own::add);
            var other=new ArrayList<Credential>();resolvers.get(i^1).resolve(criteria.get(i^1)).forEach(other::add);
            require(own.size()==1&&other.size()==1&&own.get(0).getPublicKey()!=null&&other.get(0).getPublicKey()!=null);
            require(!Arrays.equals(own.get(0).getPublicKey().getEncoded(),other.get(0).getPublicKey().getEncoded()));
            var record=new LinkedHashMap<String,Object>();for(String f:List.of("variant","fixtureId","peerEntityId","requestReference","requestId","requestSha256","metadataSha256"))record.put(f,row.path(f).asText());
            boolean stock=new ExplicitKeySignatureTrustEngine(resolvers.get(i),keyInfo).validate(requests.get(i).getSignature(),criteria.get(i));require(stock);
            record.put("stockNativeSignatureAccepted",stock);record.put("stockAdditionalTrustInputSupplied",false);
            record.put("metadataSigningPublicKeySha256",sha(own.get(0).getPublicKey().getEncoded()));
            var encryption=new ArrayList<Credential>();resolvers.get(i).resolve(new CriteriaSet(new EntityIdCriterion(row.path("peerEntityId").asText()),new EntityRoleCriterion(SPSSODescriptor.DEFAULT_ELEMENT_NAME),new UsageCriterion(UsageType.ENCRYPTION))).forEach(encryption::add);
            require(encryption.size()==1&&encryption.get(0).getPublicKey()!=null);record.put("metadataEncryptionPublicKeySha256",sha(encryption.get(0).getPublicKey().getEncoded()));
            if(calibration){
                // A separate developer invocation changes only the resolver, never the running IdP.
                boolean absent=new ExplicitKeySignatureTrustEngine(new StaticCredentialResolver(List.of()),keyInfo).validate(requests.get(i).getSignature(),criteria.get(i));
                boolean present=new ExplicitKeySignatureTrustEngine(new StaticCredentialResolver(own),keyInfo).validate(requests.get(i).getSignature(),criteria.get(i));
                boolean foreign=new ExplicitKeySignatureTrustEngine(new StaticCredentialResolver(other),keyInfo).validate(requests.get(i).getSignature(),criteria.get(i));require(!absent&&present&&!foreign);
                record.put("emptyExternalAnchorsAccepted",absent);record.put("samePublicAnchorSuppliedAccepted",present);record.put("otherPublicAnchorSuppliedAccepted",foreign);
                record.put("selectedConsumer",Map.of("path",selectedPath,"accepted",absent,"additionalTrustInputRequired",true,"additionalTrustInputSupplied",false,"acceptedWithSamePublicAnchorSupplied",present,"otherPublicAnchorSuppliedAccepted",foreign));
            }else record.put("selectedConsumer",Map.of("path",selectedPath,"accepted",stock,"additionalTrustInputRequired",false,"additionalTrustInputSupplied",false));
            rows.add(record);
        }
        var classes=new TreeMap<String,String>();for(Class<?> c:List.of(ExplicitKeySignatureTrustEngine.class,MetadataCredentialResolver.class,PredicateRoleDescriptorResolver.class,DOMMetadataResolver.class,StaticCredentialResolver.class))classes.put(c.getName(),classHash(c));
        var result=new LinkedHashMap<String,Object>();result.put("schema","samlscope-shibboleth-self-contained-trust-diagnostic-v2");result.put("runId",input.path("runId").asText());result.put("inputSha256",sha(raw));result.put("producerSha256",sha(Files.readAllBytes(Path.of(args[1]))));result.put("selectedNativeClassHashes",classes);result.put("records",rows);result.put("purpose","public-native-trust-calibration-only");
        result.put("selectedPath",selectedPath);result.put("counterfactualCalibrationOnly",calibration);
        result.put("productSettings",0);result.put("protocolOperations",0);result.put("credentialPosts",0);result.put("productRestarts",0);result.put("personOperations",0);result.put("privateKeyRead",false);result.put("nativeControlsAdopted",false);
        System.out.println(mapper.writeValueAsString(result));
    }
}
