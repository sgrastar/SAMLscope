import com.fasterxml.jackson.databind.*;
import com.samlscope.store.JsonCodec;
import com.samlscope.saml.crypto.*;
import com.samlscope.saml.normal.SecureXml;
import java.nio.file.*;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.cert.*;
import java.util.*;
import org.w3c.dom.Element;

/** Verify original signed responses and decrypt within the Suite container; never export values or keys. */
public final class VerifyAttributeCapability {
    private static final ObjectMapper JSON=new JsonCodec().mapper();
    private static final String MD="urn:oasis:names:tc:SAML:2.0:metadata",S="urn:oasis:names:tc:SAML:2.0:assertion",P="urn:oasis:names:tc:SAML:2.0:protocol",DS="http://www.w3.org/2000/09/xmldsig#";
    private static String hash(byte[] raw)throws Exception{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(raw));}
    private static void require(boolean condition){if(!condition)throw new IllegalArgumentException("Attribute capability proof failed");}
    private static List<Element> children(Element e,String ns,String name){var out=new ArrayList<Element>();for(var n=e.getFirstChild();n!=null;n=n.getNextSibling())if(n instanceof Element c && ns.equals(c.getNamespaceURI()) && name.equals(c.getLocalName()))out.add(c);return out;}
    public static void main(String[] args)throws Exception{
        Path folder=Path.of(args[0]),data=Path.of(args[1]),output=Path.of(args[2]);
        var result=JSON.readTree(folder.resolve("result.json").toFile());var plan=JSON.readTree(folder.resolve("plan.json").toFile()).at("/plan/plan/id").asText();
        require(plan.matches("plan_[0-9A-HJKMNP-TV-Z]{26}"));
        var targetRaw=Files.readAllBytes(folder.resolve("target-metadata.xml"));require(("sha256:"+hash(targetRaw)).equals(result.at("/target/metadata_digest").asText()));
        var target=SecureXml.parse(targetRaw).getDocumentElement();var certs=new ArrayList<X509Certificate>();
        for(var role:children(target,MD,"IDPSSODescriptor"))for(var descriptor:children(role,MD,"KeyDescriptor")){
            if(!descriptor.getAttribute("use").isEmpty() && !descriptor.getAttribute("use").equals("signing"))continue;
            for(var info:children(descriptor,DS,"KeyInfo"))for(var x509:children(info,DS,"X509Data"))for(var cert:children(x509,DS,"X509Certificate"))
                certs.add((X509Certificate)CertificateFactory.getInstance("X.509").generateCertificate(new java.io.ByteArrayInputStream(Base64.getDecoder().decode(cert.getTextContent().replaceAll("\\s+","")))));
        }
        require(!certs.isEmpty());
        var originals=new HashMap<String,Element>();
        for(var entry:JSON.readTree(folder.resolve("decoded-manifest.json").toFile())){
            var path=folder.resolve(entry.path("file").asText()).normalize();require(path.startsWith(folder.normalize()));
            var raw=Files.readAllBytes(path);require(hash(raw).equals(entry.path("sha256").asText()));
            require(originals.put(entry.path("id").asText(),SecureXml.parse(raw).getDocumentElement())==null);
        }
        var transcripts=JSON.readTree(folder.resolve("transcript.json").toFile());var requests=new HashMap<String,String>();
        for(var e:transcripts){require(e.path("runId").asText().equals(result.at("/run/id").asText()));var xml=originals.get(e.path("id").asText());
            if("OUTBOUND".equals(e.path("direction").asText()) && xml!=null && P.equals(xml.getNamespaceURI()) && "AuthnRequest".equals(xml.getLocalName()))require(requests.put(xml.getAttribute("ID"),e.path("id").asText())==null);
        }
        var observations=new ArrayList<Map<String,Object>>();
        for(var e:transcripts){
            if(!"INBOUND".equals(e.path("direction").asText()) || !e.at("/samlSummary/normalFlowAccepted").asBoolean())continue;
            var response=originals.get(e.path("id").asText());require(response!=null);
            var request=requests.get(response.getAttribute("InResponseTo"));require(request!=null);
            require(response.getAttribute("Destination").equals(e.path("url").asText()));
            require(response.getAttribute("Destination").equals(originals.get(request).getAttribute("AssertionConsumerServiceURL")));
            var verified=new VerifiedSignatureAlgorithms().read(response,target.getAttribute("entityID"),certs);require(verified.stream().anyMatch(v->v.element().equals("Response")));
            var assertions=new ArrayList<>(children(response,S,"Assertion"));
            var encrypted=children(response,S,"EncryptedAssertion");
            if(!encrypted.isEmpty()){
                var key=KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(Files.readAllBytes(data.resolve("keys").resolve(plan).resolve("signing-key.pk8"))));
                for(var wrapper:encrypted)assertions.add(new SamlXmlDecrypter().decrypt(wrapper,key));
            }
            var attributes=new ArrayList<Map<String,String>>();
            for(var assertion:assertions){
                require(S.equals(assertion.getNamespaceURI()) && "Assertion".equals(assertion.getLocalName()));
                require(children(assertion,S,"Issuer").size()==1 && target.getAttribute("entityID").equals(children(assertion,S,"Issuer").getFirst().getTextContent()));
                for(var statement:children(assertion,S,"AttributeStatement"))for(var attribute:children(statement,S,"Attribute"))attributes.add(Map.of("name",attribute.getAttribute("Name"),"name_format",attribute.getAttribute("NameFormat")));
            }
            observations.add(Map.of("request",request,"response",e.path("id").asText(),"response_signature_verified",true,"decrypted_assertions",encrypted.size(),"attributes",attributes));
        }
        require(observations.size()>=2);
        JSON.writerWithDefaultPrettyPrinter().writeValue(output.toFile(),Map.of("run",result.at("/run/id").asText(),"observations",observations,"result_sha256",hash(Files.readAllBytes(folder.resolve("result.json"))),"target_metadata_sha256",hash(targetRaw),"plaintext_persisted",false,"private_key_exported",false));
        System.out.println("Verified attribute responses: "+observations.size());
    }
}
