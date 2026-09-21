import com.fasterxml.jackson.databind.*;
import com.samlscope.saml.crypto.*;
import com.samlscope.saml.normal.SecureXml;
import org.w3c.dom.Element;
import java.nio.file.*;
import java.security.*;
import java.security.cert.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.*;

/** Run with the Suite data volume read-only; never export private keys or decrypted attributes. */
public final class VerifyNativeProducerAlgorithms {
    static final ObjectMapper JSON = new ObjectMapper();
    static final String MD="urn:oasis:names:tc:SAML:2.0:metadata", DS="http://www.w3.org/2000/09/xmldsig#",
        SAML="urn:oasis:names:tc:SAML:2.0:assertion", P="urn:oasis:names:tc:SAML:2.0:protocol",
        X="http://www.w3.org/2001/04/xmlenc#", X11="http://www.w3.org/2009/xmlenc11#";
    static void require(boolean b) { if(!b)throw new IllegalArgumentException("Unbound native producer evidence"); }
    static String hash(byte[] raw)throws Exception{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(raw));}
    static JsonNode read(Path p)throws Exception{return JSON.readTree(Files.readAllBytes(p));}
    static List<Element> children(Element e,String ns,String name){var out=new ArrayList<Element>();for(var c=e.getFirstChild();c!=null;c=c.getNextSibling())if(c instanceof Element x && ns.equals(x.getNamespaceURI())&&name.equals(x.getLocalName()))out.add(x);return out;}
    static Element one(Element e,String ns,String name){var list=children(e,ns,name);require(list.size()==1);return list.getFirst();}
    static X509Certificate cert(byte[] raw)throws Exception{return (X509Certificate)CertificateFactory.getInstance("X.509").generateCertificate(new java.io.ByteArrayInputStream(raw));}
    public static void main(String[] args)throws Exception{
        require(args.length==3 || (args.length==4 && "simplesamlphp".equals(args[3])));
        boolean ssp=args.length==4;
        Path folder=Path.of(args[0]),data=Path.of(args[1]),output=Path.of(args[2]);
        require(!Files.exists(output));
        var plan=read(folder.resolve("plan.json")).at("/plan/plan/id").asText();
        var run=read(folder.resolve("created.json")).at("/run/id").asText();
        require(plan.matches("plan_[0-9A-HJKMNP-TV-Z]{26}")&&run.matches("run_[0-9A-HJKMNP-TV-Z]{26}"));
        var result=read(folder.resolve("result.json"));require(run.equals(result.at("/run/id").asText()));
        byte[] target=Files.readAllBytes(folder.resolve("target-metadata.xml"));
        require(("sha256:"+hash(target)).equals(result.at("/target/metadata_digest").asText()));
        var metadata=SecureXml.parse(target).getDocumentElement();var issuer=metadata.getAttribute("entityID");
        var trusted=new ArrayList<X509Certificate>();var endpoints=new HashSet<String>();
        var role=one(metadata,MD,"IDPSSODescriptor");
        for(var e:children(role,MD,"SingleSignOnService"))endpoints.add(e.getAttribute("Location"));
        for(var k:children(role,MD,"KeyDescriptor"))if(k.getAttribute("use").isBlank()||k.getAttribute("use").equals("signing"))
            for(var info:children(k,DS,"KeyInfo"))for(var d:children(info,DS,"X509Data"))for(var c:children(d,DS,"X509Certificate"))trusted.add(cert(Base64.getMimeDecoder().decode(c.getTextContent())));
        require(!trusted.isEmpty());
        var keyPath=data.resolve("keys").resolve(plan);
        var own=KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(Files.readAllBytes(keyPath.resolve("signing-key.pk8"))));
        var ownCert=cert(Files.readAllBytes(keyPath.resolve("signing-certificate.der")));
        var sp=SecureXml.parse(Files.readAllBytes(folder.resolve("fixture.xml"))).getDocumentElement();
        var spRole=one(sp,MD,"SPSSODescriptor");boolean keyMatched=false;
        for(var k:children(spRole,MD,"KeyDescriptor"))if(!"signing".equals(k.getAttribute("use")))
            for(var info:children(k,DS,"KeyInfo"))for(var d:children(info,DS,"X509Data"))for(var c:children(d,DS,"X509Certificate"))
                keyMatched|=Arrays.equals(ownCert.getPublicKey().getEncoded(),cert(Base64.getMimeDecoder().decode(c.getTextContent())).getPublicKey().getEncoded());
        require(keyMatched);
        var raw=new HashMap<String,byte[]>();var entries=new HashMap<String,JsonNode>();
        for(var e:read(folder.resolve("transcript.json"))){require(run.equals(e.path("runId").asText()));require(entries.put(e.path("id").asText(),e)==null);}
        for(var m:read(folder.resolve("decoded-manifest.json"))){var path=folder.resolve(m.path("file").asText()).normalize();require(path.getParent().equals(folder.resolve("decoded")));var bytes=Files.readAllBytes(path);require(hash(bytes).equals(m.path("sha256").asText()));require(raw.put(m.path("id").asText(),bytes)==null);}
        var generator=KeyPairGenerator.getInstance("RSA");generator.initialize(2048);var wrong=generator.generateKeyPair().getPrivate();
        var decrypt=new SamlXmlDecrypter();var verifier=new XmlSignatureVerifier();var observations=new ArrayList<Map<String,Object>>();var seen=new HashSet<String>();
        var operations=read(folder.resolve("operations.json"));
        var phaseNames=new HashSet<String>();
        if(ssp)require(operations.path("restored").asBoolean(false)&&"encryption".equals(operations.path("matrix").asText()));
        for(var phase:operations.path("phases")){
            require(run.equals(phase.path("run").asText())&&"recorded".equals(phase.path("receipt").asText()));
            require(phaseNames.add(phase.path("phase").asText()));
            JsonNode sent=null,received=null;
            for(var id:phase.path("added_transcripts")){require(seen.add(id.asText()));var entry=entries.get(id.asText());require(entry!=null);var type=entry.path("samlSummary").path("type").asText();
                if("AuthnRequest".equals(type)&&"OUTBOUND".equals(entry.path("direction").asText())){require(sent==null);sent=entry;}
                if("Response".equals(type)&&"INBOUND".equals(entry.path("direction").asText())){require(received==null);received=entry;}}
            require(sent!=null&&received!=null);
            var request=SecureXml.parse(raw.get(sent.path("id").asText())).getDocumentElement();
            var response=SecureXml.parse(raw.get(received.path("id").asText())).getDocumentElement();
            require(P.equals(request.getNamespaceURI())&&"AuthnRequest".equals(request.getLocalName()));
            require(P.equals(response.getNamespaceURI())&&"Response".equals(response.getLocalName()));
            require(request.getAttribute("ID").equals(response.getAttribute("InResponseTo"))&&endpoints.contains(request.getAttribute("Destination")));
            require(sp.getAttribute("entityID").equals(one(request,SAML,"Issuer").getTextContent()));
            require(request.getAttribute("AssertionConsumerServiceURL").equals(response.getAttribute("Destination")));
            require("urn:oasis:names:tc:SAML:2.0:status:Success".equals(one(one(response,P,"Status"),P,"StatusCode").getAttribute("Value")));
            if("GET".equals(sent.path("method").asText())) {
                require(new com.samlscope.saml.binding.RedirectSignatureVerifier().isValidForMessage(
                    sent.path("rawQuery").asText(),ownCert,raw.get(sent.path("id").asText())));
            } else {
                require("POST".equals(sent.path("method").asText()) && verifier.hasValidEnvelopedSignature(request,ownCert));
            }
            require(new VerifiedSignatureAlgorithms().read(response,issuer,trusted).stream().anyMatch(o->o.element().equals("Response")));
            if(ssp && "unencrypted-control".equals(phase.path("phase").asText())) {
                require(children(response,SAML,"EncryptedAssertion").isEmpty());
                one(response,SAML,"Assertion");
                require(new VerifiedSignatureAlgorithms().read(response,issuer,trusted).stream().anyMatch(o->o.element().equals("Assertion")));
                observations.add(Map.of("phase","unencrypted-control","request",sent.path("id").asText(),
                    "response",received.path("id").asText(),"encrypted",false,"request_signature_verified",true,
                    "response_signature_verified",true,"assertion_signature_verified",true));
                continue;
            }
            var wrapper=one(response,SAML,"EncryptedAssertion");require(children(response,SAML,"Assertion").isEmpty());
            var plain=decrypt.decrypt(wrapper,own);require(SAML.equals(plain.getNamespaceURI())&&"Assertion".equals(plain.getLocalName()));
            require(issuer.equals(one(plain,SAML,"Issuer").getTextContent()));require(trusted.stream().anyMatch(c->verifier.hasValidEnvelopedSignature(plain,c)));
            boolean wrongRejected=false;try{decrypt.decrypt(wrapper,wrong);}catch(com.samlscope.saml.normal.SamlException expected){wrongRejected=true;}require(wrongRejected);
            var changed=(Element)response.cloneNode(true);changed.setAttribute("Destination","https://invalid.example/tampered");
            require(new VerifiedSignatureAlgorithms().read(changed,issuer,trusted).isEmpty());
            var dataMethod=one(one(wrapper,X,"EncryptedData"),X,"EncryptionMethod");
            var encryptedKeys=wrapper.getElementsByTagNameNS(X,"EncryptedKey");require(encryptedKeys.getLength()==1);
            var keyMethod=one((Element)encryptedKeys.item(0),X,"EncryptionMethod");
            var digests=children(keyMethod,DS,"DigestMethod");var mgfs=children(keyMethod,X11,"MGF");require(digests.size()<=1&&mgfs.size()<=1);
            var item=new LinkedHashMap<String,Object>();item.put("phase",phase.path("phase").asText());item.put("request",sent.path("id").asText());item.put("response",received.path("id").asText());
            item.put("data_algorithm",dataMethod.getAttribute("Algorithm"));item.put("transport_algorithm",keyMethod.getAttribute("Algorithm"));
            item.put("digest_algorithm",digests.isEmpty()?DS+"sha1":digests.getFirst().getAttribute("Algorithm"));item.put("mgf_algorithm",mgfs.isEmpty()?null:mgfs.getFirst().getAttribute("Algorithm"));
            item.put("request_signature_verified",true);item.put("response_signature_verified",true);item.put("assertion_signature_verified",true);item.put("decrypted",true);item.put("wrong_key_rejected",true);item.put("tampered_response_rejected",true);observations.add(item);
        }
        if(ssp)require(observations.size()==3 && phaseNames.equals(Set.of("unencrypted-control","encrypted","encrypted-repeat")));
        else require(observations.size()==5);
        JSON.writerWithDefaultPrettyPrinter().writeValue(output.toFile(),Map.of("run",run,"observations",observations,"target_metadata_sha256",hash(target),"operations_sha256",hash(Files.readAllBytes(folder.resolve("operations.json"))),"private_key_exported",false,"plaintext_persisted",false,"verdict_adopted",false,"transcript_sha256",hash(Files.readAllBytes(folder.resolve("transcript.json"))),"manifest_sha256",hash(Files.readAllBytes(folder.resolve("decoded-manifest.json"))),"fixture_sha256",hash(Files.readAllBytes(folder.resolve("fixture.xml")))));
        System.out.println("Verified native producer phases: "+observations.size());
    }
}
