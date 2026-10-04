import com.fasterxml.jackson.databind.*;
import com.samlscope.saml.crypto.*;
import com.samlscope.saml.normal.SecureXml;
import org.w3c.dom.Element;
import java.nio.file.*;
import java.security.*;
import java.security.cert.*;
import java.util.*;

/** Public-original verification only. Neither target rejection nor a product verdict is inferred here. */
public final class VerifyNativeCertificateRequests {
    static final ObjectMapper JSON=new ObjectMapper();
    static final String MD="urn:oasis:names:tc:SAML:2.0:metadata", DS="http://www.w3.org/2000/09/xmldsig#", S="urn:oasis:names:tc:SAML:2.0:assertion",P="urn:oasis:names:tc:SAML:2.0:protocol";
    static void require(boolean b){if(!b)throw new IllegalArgumentException("Unbound certificate evidence");}
    static String hash(byte[] b)throws Exception{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(b));}
    static JsonNode read(Path p)throws Exception{return JSON.readTree(Files.readAllBytes(p));}
    static List<Element> children(Element e,String ns,String name){var list=new ArrayList<Element>();for(var n=e.getFirstChild();n!=null;n=n.getNextSibling())if(n instanceof Element x&&ns.equals(x.getNamespaceURI())&&name.equals(x.getLocalName()))list.add(x);return list;}
    static Element one(Element e,String ns,String name){var list=children(e,ns,name);require(list.size()==1);return list.getFirst();}
    static X509Certificate cert(Element e)throws Exception{return (X509Certificate)CertificateFactory.getInstance("X.509").generateCertificate(new java.io.ByteArrayInputStream(Base64.getMimeDecoder().decode(e.getTextContent())));}
    public static void main(String[] args)throws Exception{
        Path folder=Path.of(args[0]);var run=read(folder.resolve("created.json")).at("/run/id").asText();
        var entries=new HashMap<String,JsonNode>();var originals=new HashMap<String,byte[]>();
        for(var e:read(folder.resolve("transcript.json"))){require(run.equals(e.path("runId").asText()));require(entries.put(e.path("id").asText(),e)==null);}
        for(var e:read(folder.resolve("decoded-manifest.json"))){var file=folder.resolve(e.path("file").asText()).normalize();require(file.getParent().equals(folder.resolve("decoded")));var raw=Files.readAllBytes(file);require(hash(raw).equals(e.path("sha256").asText()));require(originals.put(e.path("id").asText(),raw)==null);}
        byte[] target=Files.readAllBytes(folder.resolve("target-metadata.xml"));var root=SecureXml.parse(target).getDocumentElement();
        var targetRole=one(root,MD,"IDPSSODescriptor");var issuer=root.getAttribute("entityID");var trusted=new ArrayList<X509Certificate>();var endpoints=new HashSet<String>();
        for(var e:children(targetRole,MD,"SingleSignOnService"))endpoints.add(e.getAttribute("Location"));
        for(var k:children(targetRole,MD,"KeyDescriptor"))if(k.getAttribute("use").isBlank()||"signing".equals(k.getAttribute("use")))for(var i:children(k,DS,"KeyInfo"))for(var d:children(i,DS,"X509Data"))for(var c:children(d,DS,"X509Certificate"))trusted.add(cert(c));
        require(!trusted.isEmpty());var report=new ArrayList<Map<String,Object>>();
        for(var op:read(folder.resolve("operations.json"))){
            var variant=op.path("variant").asText();require(variant.matches("[a-z0-9-]+"));
            var fixture=Files.readAllBytes(folder.resolve(variant).resolve("fixture.xml"));require(hash(fixture).equals(op.path("fixture_sha256").asText()));
            var metadata=SecureXml.parse(fixture).getDocumentElement();var sp=one(metadata,MD,"SPSSODescriptor");var keys=new ArrayList<X509Certificate>();
            for(var k:children(sp,MD,"KeyDescriptor"))if(!"encryption".equals(k.getAttribute("use")))for(var i:children(k,DS,"KeyInfo"))for(var d:children(i,DS,"X509Data"))for(var c:children(d,DS,"X509Certificate"))keys.add(cert(c));
            require(keys.size()==1);var certificate=keys.getFirst();var requests=new ArrayList<Map<String,Object>>();
            for(var e:entries.values())if("OUTBOUND".equals(e.path("direction").asText())&&variant.equals(e.path("samlSummary").path("variant").asText())&&"AuthnRequest".equals(e.path("samlSummary").path("type").asText())){
                var raw=originals.get(e.path("id").asText());require(raw!=null);var request=SecureXml.parse(raw).getDocumentElement();
                require(P.equals(request.getNamespaceURI())&&"AuthnRequest".equals(request.getLocalName()));
                require(metadata.getAttribute("entityID").equals(one(request,S,"Issuer").getTextContent()));
                require(request.getAttribute("ID").equals(e.path("samlSummary").path("id").asText())&&endpoints.contains(request.getAttribute("Destination")));
                boolean valid=new XmlSignatureVerifier().hasValidEnvelopedSignature(request,certificate);
                boolean negative="invalid".equals(e.path("samlSummary").path("metadataSignatureControl").asText());
                require(valid!=negative);
                var responses=new ArrayList<String>();
                for(var received:entries.values())if("INBOUND".equals(received.path("direction").asText())&&"Response".equals(received.path("samlSummary").path("type").asText())){
                    var responseRaw=originals.get(received.path("id").asText());if(responseRaw==null)continue;
                    var response=SecureXml.parse(responseRaw).getDocumentElement();if(!request.getAttribute("ID").equals(response.getAttribute("InResponseTo")))continue;
                    require(new VerifiedSignatureAlgorithms().read(response,issuer,trusted).stream().anyMatch(o->o.element().equals("Response")));
                    require(request.getAttribute("AssertionConsumerServiceURL").equals(response.getAttribute("Destination")));
                    require("urn:oasis:names:tc:SAML:2.0:status:Success".equals(one(one(response,P,"Status"),P,"StatusCode").getAttribute("Value")));
                    responses.add(received.path("id").asText());
                }
                require(responses.size()<=1);
                requests.add(Map.of("request",e.path("id").asText(),"request_id",request.getAttribute("ID"),"request_sha256",hash(raw),"issuer",metadata.getAttribute("entityID"),"signature_valid",valid,"negative_control",negative,"signed_success_responses",responses));
            }
            require(requests.size()==2&&requests.stream().filter(x->Boolean.TRUE.equals(x.get("negative_control"))).count()==1);
            var row=new LinkedHashMap<String,Object>();row.put("variant",variant);row.put("fixture_sha256",hash(fixture));row.put("certificate_sha256",hash(certificate.getEncoded()));row.put("public_key_sha256",hash(certificate.getPublicKey().getEncoded()));row.put("not_before",certificate.getNotBefore().toInstant().toString());row.put("not_after",certificate.getNotAfter().toInstant().toString());row.put("requests",requests);report.add(row);
        }
        JSON.writerWithDefaultPrettyPrinter().writeValue(folder.resolve("verified-certificate-requests.json").toFile(),Map.of("run",run,"target_metadata_sha256",hash(target),"transcript_sha256",hash(Files.readAllBytes(folder.resolve("transcript.json"))),"manifest_sha256",hash(Files.readAllBytes(folder.resolve("decoded-manifest.json"))),"operations_sha256",hash(Files.readAllBytes(folder.resolve("operations.json"))),"observations",report,"verdict_adopted",false));
        System.out.println("Original certificate request matrices verified: "+report.size());
    }
}
