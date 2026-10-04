package com.samlscope.runner.cases;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.cert.*;
import java.time.Instant;
import java.util.*;
import com.fasterxml.jackson.databind.JsonNode;
import com.samlscope.saml.crypto.XmlSignatureVerifier;
import com.samlscope.saml.normal.SecureXml;
import com.samlscope.store.JsonCodec;
import org.w3c.dom.*;

/** Native installed metadata signer/filter observations, including their original code bytes. */
final class ShibbolethRsaSha1CapabilityProof {
    static final String ADAPTER="shibboleth-native-jvm";
    private static final String ENTITY="http://localhost:18280/idp/shibboleth";
    private static final String IMAGE="sha256:3c1b1fa64c58258aefc9e38d4ae60e9f0340731318a472110ea56ce88c18a11a";
    private static final String SOURCE_SHA="e761d0b982c9dd94b12f8e88a78534b0e828f733d892b8214c6d4a30bce46628";
    private static final String LIB="/opt/shibboleth-idp/dist/webapp/WEB-INF/lib/";
    private static final String DS="http://www.w3.org/2000/09/xmldsig#";
    private static final Map<String,List<String>> NATIVE=Map.of(
        "org.opensaml.core.config.InitializationService",List.of("opensaml-core-api-5.2.3.jar","5456c53715746167d75b42a72761ca01632a34de8461a4845f29334b22dfaa92"),
        "org.opensaml.saml.metadata.resolver.filter.impl.SignatureValidationFilter",List.of("opensaml-saml-impl-5.2.3.jar","0c21fa91fdf43423e4907ccae50c0ede86a85cc4f92f411ec5e92c285f22d6c0"),
        "org.opensaml.xmlsec.signature.support.SignatureSupport",List.of("opensaml-xmlsec-api-5.2.3.jar","124c87871a6856a18f617f04318dd4be54c187243e57fcb8d387fd47dd5c1a04"),
        "org.opensaml.xmlsec.signature.support.impl.ExplicitKeySignatureTrustEngine",List.of("opensaml-xmlsec-impl-5.2.3.jar","cdcd9a4020bc1a565b021ee404e92f3b994b553f307ad299ee655c94dc631589"),
        "net.shibboleth.idp.Version",List.of("idp-core-5.2.3.jar","22c8985b087c38552a7dbacab779d73814b1cd9c5b72f5b42eefa8e54a76ad4e"));
    static void verify(JsonNode receipt,byte[] signed) throws Exception {
        var runtime=receipt.path("runtime");
        fields(runtime,Set.of("before","after","productVersion","verifierSource","nativeClasses"));
        var before=json(blob(runtime.path("before")));var after=json(blob(runtime.path("after")));
        inspection(before);inspection(after);
        require(before.path("Id").equals(after.path("Id")) && before.path("Image").equals(after.path("Image"))
                && before.path("State").path("StartedAt").equals(after.path("State").path("StartedAt")));
        require("5.2.3".equals(runtime.path("productVersion").asText()));
        require(SOURCE_SHA.equals(sha(blob(runtime.path("verifierSource")))));
        var classes=runtime.path("nativeClasses");fields(classes,NATIVE.keySet());
        for(var name:NATIVE.keySet()) {
            var node=classes.path(name);fields(node,Set.of("jar","classFile","original"));
            require((LIB+NATIVE.get(name).get(0)).equals(node.path("jar").asText()));
            require((name.replace('.','/')+".class").equals(node.path("classFile").asText()));
            require(NATIVE.get(name).get(1).equals(sha(blob(node.path("original")))));
        }
        var config=receipt.path("configuration");fields(config,Set.of("before","after"));
        var original=json(blob(config.path("before")));var restored=json(blob(config.path("after")));
        fields(original,Set.of("signingKeySha256","signingCertificate","wrongCertificate"));
        fields(restored,Set.of("signingKeySha256","signingCertificate","wrongCertificate"));
        require(original.equals(restored) && original.path("signingKeySha256").asText().matches("[0-9a-f]{64}"));
        var certificate=certificate(blob(original.path("signingCertificate")));
        var wrong=certificate(blob(original.path("wrongCertificate")));
        require(!Arrays.equals(certificate.getPublicKey().getEncoded(),wrong.getPublicKey().getEncoded()));
        var root=SecureXml.parse(signed).getDocumentElement();require(ENTITY.equals(root.getAttribute("entityID")));
        var ds=root.getElementsByTagNameNS(DS,"X509Certificate");require(ds.getLength()>0);
        var embedded=certificate(Base64.getMimeDecoder().decode(ds.item(0).getTextContent()));
        require(Arrays.equals(certificate.getEncoded(),embedded.getEncoded()));
        var unsigned=blob(receipt.path("originalUnsignedMetadata"));var unsignedRoot=SecureXml.parse(unsigned).getDocumentElement();
        require(unsignedRoot.getElementsByTagNameNS(DS,"Signature").getLength()==0);
        require(shape(unsignedRoot).equals(shape(root)));
        for(var mode:List.of("signer","native")) {
            String observation=mode.equals("signer")?"signerObservation":"nativeObservation";
            String exit=mode.equals("signer")?"signerExitCode":"nativeVerifierExitCode";
            String stderr=mode.equals("signer")?"signerStderr":"nativeVerifierStderr";
            require(receipt.path(exit).isIntegralNumber() && receipt.path(exit).asInt(-1)==0);
            require(blob(receipt.path(stderr)).length==0);
            verifyObservation(jsonLine(blob(receipt.path(observation))), mode.equals("signer"),
                    signed,unsigned,certificate,wrong);
        }
        require(Arrays.equals(blob(receipt.path("wrongCertificate")),blob(original.path("wrongCertificate"))));
        var counts=receipt.path("operationCounts");fields(counts,Set.of("productConfigurationWrites","productRestarts","humanOperations","nativeVerificationExecutions"));
        for(var key:List.of("productConfigurationWrites","productRestarts","humanOperations"))
            require(counts.path(key).isIntegralNumber() && counts.path(key).asInt(-1)==0);
        require(counts.path("nativeVerificationExecutions").isIntegralNumber()
                && counts.path("nativeVerificationExecutions").asInt(-1)==2);
    }
    private static void verifyObservation(JsonNode node,boolean signer,byte[] signed,byte[] unsigned,
            X509Certificate certificate,X509Certificate wrong) throws Exception {
        fields(node,Set.of("schema","mode","productVersion","inputSha256","signedSha256","targetEntityId",
            "trustedCertificateSha256","wrongCertificateSha256","nativeClassOrigins","positive","tampered","wrongKey","unsigned",
            "tamperedInputBase64","unsignedInputBase64"));
        require("samlscope-shibboleth-rsa-sha1-native-observation-v1".equals(node.path("schema").asText()));
        require((signer?"sign-and-verify":"verify").equals(node.path("mode").asText()));
        require("5.2.3".equals(node.path("productVersion").asText()) && ENTITY.equals(node.path("targetEntityId").asText()));
        require(sha(signer?unsigned:signed).equals(node.path("inputSha256").asText())
                && sha(signed).equals(node.path("signedSha256").asText()));
        require(sha(certificate.getEncoded()).equals(node.path("trustedCertificateSha256").asText())
                && sha(wrong.getEncoded()).equals(node.path("wrongCertificateSha256").asText()));
        fields(node.path("nativeClassOrigins"),NATIVE.keySet());
        for(var name:NATIVE.keySet())require(("file:"+LIB+NATIVE.get(name).get(0)).equals(node.path("nativeClassOrigins").path(name).asText()));
        for(var control:List.of("positive","tampered","wrongKey","unsigned")) {
            var result=node.path(control);fields(result,Set.of("accepted","exception"));
            boolean accepted=control.equals("positive");require(result.path("accepted").isBoolean() && result.path("accepted").asBoolean()==accepted);
            require(result.path("exception").isTextual() && (accepted?result.path("exception").asText().isEmpty():
                result.path("exception").asText().startsWith("org.opensaml.saml.metadata.resolver.filter.FilterException:")));
        }
        var changedRaw=Base64.getDecoder().decode(node.path("tamperedInputBase64").asText());
        var originalText=new String(signed,StandardCharsets.UTF_8);String marker="entityID=\""+ENTITY+"\"";
        require(originalText.indexOf(marker)>=0 && originalText.indexOf(marker)==originalText.lastIndexOf(marker));
        require(Arrays.equals(changedRaw,originalText.replace(marker,"entityID=\""+ENTITY+"#tampered\"")
                .getBytes(StandardCharsets.UTF_8)));
        var changed=SecureXml.parse(changedRaw).getDocumentElement();
        require((ENTITY+"#tampered").equals(changed.getAttribute("entityID"))
                && changed.getElementsByTagNameNS(DS,"Signature").getLength()==1);
        require(!new XmlSignatureVerifier().hasValidEnvelopedSignature(changed,certificate));
        changed.setAttribute("entityID",ENTITY);require(shape(changed).equals(shape(SecureXml.parse(signed).getDocumentElement())));
        var absent=SecureXml.parse(Base64.getDecoder().decode(node.path("unsignedInputBase64").asText())).getDocumentElement();
        require(absent.getElementsByTagNameNS(DS,"Signature").getLength()==0 && shape(absent).equals(shape(SecureXml.parse(unsigned).getDocumentElement())));
    }
    private static void inspection(JsonNode node) {
        fields(node,Set.of("Id","Image","Name","State","Mounts"));
        require(node.path("Id").asText().matches("[0-9a-f]{64}") && IMAGE.equals(node.path("Image").asText())
                && "/samlscope-reference-shibboleth".equals(node.path("Name").asText()));
        fields(node.path("State"),Set.of("Running","StartedAt"));require(node.path("State").path("Running").isBoolean()
                && node.path("State").path("Running").asBoolean());Instant.parse(node.path("State").path("StartedAt").asText());
        require(node.path("Mounts").isArray());
        for(var mount:node.path("Mounts")) {
            fields(mount,Set.of("Destination"));String path=mount.path("Destination").asText();
            require(!path.isBlank() && !"/".equals(path) && !"/opt".equals(path)
                    && !path.equals("/opt/shibboleth-idp") && !path.startsWith("/opt/shibboleth-idp/dist")
                    && !path.equals("/opt/reference-idp") && !path.startsWith("/opt/reference-idp/dist"));
        }
    }
    private static String shape(Element root) {
        if(DS.equals(root.getNamespaceURI()) && "Signature".equals(root.getLocalName()))return "";
        var attrs=new TreeMap<String,String>();
        for(int i=0;i<root.getAttributes().getLength();i++) {
            var attr=(Attr)root.getAttributes().item(i);
            if("http://www.w3.org/2000/xmlns/".equals(attr.getNamespaceURI()) || (root.getParentNode() instanceof Document && attr.getName().equals("ID")))continue;
            attrs.put(String.valueOf(attr.getNamespaceURI())+":"+attr.getLocalName(),attr.getValue());
        }
        var result=new StringBuilder().append(root.getNamespaceURI()).append(':').append(root.getLocalName()).append(attrs);
        for(Node child=root.getFirstChild();child!=null;child=child.getNextSibling()) {
            if(child instanceof Element element) {
                if(DS.equals(element.getNamespaceURI()) && "Signature".equals(element.getLocalName()))continue;
                result.append('[').append(shape(element)).append(']');
            }
            else if(child.getNodeType()==Node.TEXT_NODE && !child.getTextContent().isBlank())
                result.append(DS.equals(root.getNamespaceURI()) && "X509Certificate".equals(root.getLocalName())?
                        child.getTextContent().replaceAll("\\s+",""):child.getTextContent());
        }
        return result.toString();
    }
    private static JsonNode jsonLine(byte[] raw) throws Exception {
        var lines=new String(raw,StandardCharsets.UTF_8).strip().split("\\R");
        require(lines.length>0 && Arrays.stream(lines).filter(value->value.startsWith("{")).count()==1);
        return json(lines[lines.length-1].getBytes(StandardCharsets.UTF_8));
    }
    private static JsonNode json(byte[] raw) throws Exception {return new JsonCodec().mapper().readTree(raw);}
    private static X509Certificate certificate(byte[] raw) throws Exception {
        return (X509Certificate)CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(raw));
    }
    private static byte[] blob(JsonNode node) throws Exception {
        fields(node,Set.of("base64","sha256"));require(node.path("base64").isTextual() && node.path("sha256").isTextual());
        var raw=Base64.getDecoder().decode(node.path("base64").asText());require(raw.length<=262144 && sha(raw).equals(node.path("sha256").asText()));return raw;
    }
    private static String sha(byte[] raw) throws Exception {return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(raw));}
    private static void fields(JsonNode node,Set<String> expected) {
        require(node.isObject());var keys=new HashSet<String>();node.fieldNames().forEachRemaining(keys::add);require(keys.equals(expected));
    }
    private static void require(boolean proven) {if(!proven)throw new IllegalArgumentException("Native Shibboleth RSA-SHA1 proof unavailable");}
}
