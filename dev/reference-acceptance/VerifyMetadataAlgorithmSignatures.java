import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.samlscope.saml.crypto.VerifiedSignatureAlgorithms;
import com.samlscope.saml.normal.SecureXml;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.*;
import org.w3c.dom.Element;

/** Offline proof over original Run evidence. Does not assign a conformance outcome. */
public final class VerifyMetadataAlgorithmSignatures {
    private static final String MD="urn:oasis:names:tc:SAML:2.0:metadata";
    private static final String DS="http://www.w3.org/2000/09/xmldsig#";
    private static final ObjectMapper JSON=new ObjectMapper();
    private static String hash(byte[] bytes) throws Exception { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes)); }
    private static JsonNode read(Path folder,String file) throws Exception { return JSON.readTree(Files.readAllBytes(folder.resolve(file))); }
    private static void require(boolean value,String message) { if(!value)throw new IllegalArgumentException(message); }
    public static void main(String[] args) throws Exception {
        if(args.length!=1)throw new IllegalArgumentException("Expected evidence directory");
        Path folder=Path.of(args[0]);var result=read(folder,"result.json");var plan=read(folder,"plan.json");
        var run=result.path("run").path("id").asText();
        var entity=plan.path("plan").path("plan").path("target").path("entityId").asText();
        require(!run.isBlank() && !entity.isBlank(),"Run or target missing");
        byte[] metadata=Files.readAllBytes(folder.resolve("target-metadata.xml"));
        require(("sha256:"+hash(metadata)).equals(result.path("target").path("metadata_digest").asText()),"Target metadata differs from Run snapshot");
        var metadataRoot=SecureXml.parse(metadata).getDocumentElement();
        require(MD.equals(metadataRoot.getNamespaceURI()) && "EntityDescriptor".equals(metadataRoot.getLocalName())
                && entity.equals(metadataRoot.getAttribute("entityID")),"Expected one target entity");
        var certificates=new ArrayList<X509Certificate>();
        for(var role:children(metadataRoot,MD,"IDPSSODescriptor")) {
            if(!Arrays.asList(role.getAttribute("protocolSupportEnumeration").split("\\s+")).contains("urn:oasis:names:tc:SAML:2.0:protocol"))continue;
            for(var key:children(role,MD,"KeyDescriptor")) {
                if(!key.getAttribute("use").isBlank() && !"signing".equals(key.getAttribute("use")))continue;
                for(var info:children(key,DS,"KeyInfo"))for(var data:children(info,DS,"X509Data"))for(var cert:children(data,DS,"X509Certificate"))
                    certificates.add((X509Certificate)CertificateFactory.getInstance("X.509").generateCertificate(new java.io.ByteArrayInputStream(
                            Base64.getDecoder().decode(cert.getTextContent().replaceAll("\\s+","")))));
            }
        }
        require(!certificates.isEmpty(),"Pinned target IdP signing keys missing");
        var originals=new HashMap<String,Element>();
        for(var item:read(folder,"decoded-manifest.json")) {
            var file=folder.resolve(item.path("file").asText()).normalize();require(file.startsWith(folder.normalize()),"Invalid original path");
            byte[] raw=Files.readAllBytes(file);require(hash(raw).equals(item.path("sha256").asText()),"Original XML hash mismatch");
            require(originals.put(item.path("id").asText(),SecureXml.parse(raw).getDocumentElement())==null,"Duplicate original ID");
        }
        var entries=new HashMap<String,JsonNode>();
        for(var entry:read(folder,"transcript.json")) {
            require(run.equals(entry.path("runId").asText()),"Cross-Run transcript");
            require(entries.put(entry.path("id").asText(),entry)==null,"Duplicate transcript ID");
        }
        var observations=read(folder,"algorithm-observations.json");require(run.equals(observations.path("run").asText()),"Wrong diagnostic Run");
        var verified=new ArrayList<Map<String,Object>>();
        for(var observation:observations.path("observations")) {
            var requestId=observation.path("request").asText();var responseId=observation.path("response").asText();
            var request=originals.get(requestId);var response=originals.get(responseId);
            require(request!=null && response!=null && request.getAttribute("ID").equals(response.getAttribute("InResponseTo")),"Uncorrelated response");
            var sent=entries.get(requestId);var received=entries.get(responseId);
            require(sent!=null && received!=null && "OUTBOUND".equals(sent.path("direction").asText()) && "INBOUND".equals(received.path("direction").asText()),"Wrong direction");
            require(!"invalid".equals(sent.path("samlSummary").path("metadataSignatureControl").asText()),"Negative request cannot supply normal evidence");
            require(observation.path("variant").asText().equals(sent.path("samlSummary").path("variant").asText()),"Wrong variant");
            var algorithms=new VerifiedSignatureAlgorithms().read(response,entity,certificates);
            verified.add(Map.of("variant",observation.path("variant").asText(),"request",requestId,"response",responseId,
                    "verified_signatures",algorithms,"signed_response_verified",algorithms.stream().anyMatch(a -> a.element().equals("Response")),"affects_verdict",false));
        }
        var report=Map.of("run",run,"target_metadata_sha256",hash(metadata),"observations",verified,
                "scope","Selected-element signatures and request correlation only; metadata selection conformance remains unassigned");
        JSON.writerWithDefaultPrettyPrinter().writeValue(folder.resolve("verified-algorithm-signatures.json").toFile(),report);
        System.out.println("Verified signed responses: "+verified.stream().filter(v -> Boolean.TRUE.equals(v.get("signed_response_verified"))).count()+" / "+verified.size());
    }
    private static List<Element> children(Element parent,String namespace,String name) {
        var result=new ArrayList<Element>();
        for(var node=parent.getFirstChild();node!=null;node=node.getNextSibling())
            if(node instanceof Element e && namespace.equals(e.getNamespaceURI()) && name.equals(e.getLocalName()))result.add(e);
        return result;
    }
}
