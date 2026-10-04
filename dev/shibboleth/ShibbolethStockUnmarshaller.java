import java.io.*;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.*;
import com.fasterxml.jackson.databind.*;
import org.opensaml.core.config.InitializationService;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.xmlsec.signature.impl.SignatureUnmarshaller;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.algorithms.SignatureAlgorithm;
import org.w3c.dom.Element;

/** Actual stock decoding of public originals. No algorithm settings, keys, HTTP, or verdicts. */
public final class ShibbolethStockUnmarshaller {
    static final ObjectMapper M=new ObjectMapper();
    static final String RSA_MD5="http://www.w3.org/2001/04/xmldsig-more#rsa-md5";
    static final String RSA_SHA256="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
    static String sha(byte[] raw)throws Exception{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(raw));}
    static void require(boolean condition,String message){if(!condition)throw new IllegalArgumentException(message);}
    static byte[] file(Path path,Path folder)throws Exception {
        require(path.toAbsolutePath().normalize().getParent().equals(folder),"Public inputs must be flat in one directory");
        require(Files.isRegularFile(path,LinkOption.NOFOLLOW_LINKS)&&!Files.isSymbolicLink(path)&&Files.size(path)>0&&Files.size(path)<=2097152,"Public file unavailable");
        return Files.readAllBytes(path);
    }
    static Map<String,Object> origin(Class<?> type)throws Exception {
        String resource="/"+type.getName().replace('.','/')+".class";byte[] bytes;
        try(var stream=type.getResourceAsStream(resource)){require(stream!=null,"Native class bytes unavailable");bytes=stream.readAllBytes();}
        Path jar=Path.of(type.getProtectionDomain().getCodeSource().getLocation().toURI()).toAbsolutePath();
        require(Files.isRegularFile(jar,LinkOption.NOFOLLOW_LINKS)&&jar.toString().startsWith("/usr/local/tomcat/webapps/idp/WEB-INF/lib/"),"Class was not loaded from the installed product JAR");
        return Map.of("classSha256",sha(bytes),"jarPath",jar.toString(),"jarSha256",sha(Files.readAllBytes(jar)));
    }
    static Element entity(byte[] raw,String hash)throws Exception {
        require(sha(raw).equals(hash),"Metadata hash changed");var parser=XMLObjectProviderRegistrySupport.getParserPool();var root=parser.parse(new ByteArrayInputStream(raw)).getDocumentElement();
        require("urn:oasis:names:tc:SAML:2.0:metadata".equals(root.getNamespaceURI())&&"EntityDescriptor".equals(root.getLocalName()),"Metadata entity unavailable");return root;
    }
    public static void main(String[] args)throws Exception {
        require(args.length==2,"Public input manifest and source required");Path inputPath=Path.of(args[0]).toAbsolutePath().normalize(),folder=inputPath.getParent();byte[] rawInput=file(inputPath,folder),source=file(Path.of(args[1]).toAbsolutePath().normalize(),folder);var input=M.readTree(rawInput);
        String run=input.path("runId").asText();require(run.matches("run_[0-9A-HJKMNP-TV-Z]{26}"),"Exact Run required");
        InitializationService.initialize();var parser=XMLObjectProviderRegistrySupport.getParserPool();
        byte[] suite=file(Path.of(input.path("suiteMetadataFile").asText()),folder),target=file(Path.of(input.path("targetMetadataFile").asText()),folder);
        Element sp=entity(suite,input.path("suiteMetadataSha256").asText()),idp=entity(target,input.path("targetMetadataSha256").asText());
        require(sp.getAttribute("entityID").equals(input.path("suiteEntityId").asText())&&idp.getAttribute("entityID").equals(input.path("targetEntityId").asText()),"Metadata entity changed");
        var records=new ArrayList<Map<String,Object>>();var fixtures=new HashSet<String>();var references=new HashSet<String>();
        for(var row:input.path("records")) {
            String fixture=row.path("fixtureId").asText(),reference=row.path("requestReference").asText(),id=row.path("requestId").asText();
            require(Set.of("sha256-control","rsa-md5").contains(fixture)&&fixtures.add(fixture)&&reference.matches("tx_[0-9A-HJKMNP-TV-Z]{26}")&&references.add(reference)
                &&row.path("originalPath").asText().equals("transcripts/"+run+"/"+reference+".saml.xml"),"Original Run/reference changed");
            byte[] raw=file(Path.of(row.path("requestFile").asText()),folder);require(sha(raw).equals(row.path("requestSha256").asText()),"Original input hash changed");
            Element root=parser.parse(new ByteArrayInputStream(raw)).getDocumentElement();
            require("urn:oasis:names:tc:SAML:2.0:protocol".equals(root.getNamespaceURI())&&"AuthnRequest".equals(root.getLocalName())&&root.getAttribute("ID").equals(id)
                &&root.getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:assertion","Issuer").getLength()==1,"Request identity changed");
            String issuer=root.getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:assertion","Issuer").item(0).getTextContent();require(issuer.equals(sp.getAttribute("entityID")),"Foreign request issuer");
            var methods=root.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#","SignatureMethod");require(methods.getLength()==1,"Signature method ambiguous");String algorithm=((Element)methods.item(0)).getAttribute("Algorithm");
            require(algorithm.equals(fixture.equals("rsa-md5")?RSA_MD5:RSA_SHA256),"Unexpected native decoder input");
            boolean success=false;String error="";var exceptions=new ArrayList<String>();String started=Instant.now().toString();
            try {
                var object=XMLObjectSupport.unmarshallFromInputStream(parser,new ByteArrayInputStream(raw));
                require(object instanceof AuthnRequest,"Native decoded type changed");var request=(AuthnRequest)object;
                require(request.getID().equals(id)&&request.getIssuer().getValue().equals(issuer),"Native decoded identity changed");success=true;
            } catch(org.opensaml.core.xml.io.UnmarshallingException failure) {
                for(Throwable cause=failure;cause!=null;cause=cause.getCause()) {exceptions.add(cause.getClass().getName());if(!error.isEmpty())error+="\n";error+=cause.getClass().getName()+": "+cause.getMessage();}
            }
            if(fixture.equals("sha256-control"))require(success,"Normal stock decoding failed");
            else require(!success&&exceptions.contains("org.apache.xml.security.exceptions.XMLSecurityException")&&error.contains("It is forbidden to use algorithm "+RSA_MD5+" when secure validation is enabled"),"Expected genuine stock RSA-MD5 rejection unavailable");
            var result=new TreeMap<String,Object>();result.put("fixtureId",fixture);result.put("requestReference",reference);result.put("requestId",id);result.put("requestSha256",sha(raw));result.put("issuer",issuer);result.put("signatureAlgorithm",algorithm);result.put("unmarshalled",success);result.put("nativeExceptionClasses",exceptions);result.put("nativeExceptionText",error);result.put("startedAt",started);result.put("completedAt",Instant.now().toString());records.add(result);
        }
        require(fixtures.equals(Set.of("sha256-control","rsa-md5"))&&records.size()==2,"Two exact same-Run stock decoder controls required");
        var classes=new TreeMap<String,Object>();for(var type:List.of(XMLObjectSupport.class,SignatureUnmarshaller.class,XMLSignature.class,SignatureAlgorithm.class))classes.put(type.getName(),origin(type));
        var output=new TreeMap<String,Object>();output.put("schema","samlscope-shibboleth-stock-unmarshaller-v1");output.put("runId",run);output.put("inputSha256",sha(rawInput));output.put("producerSourceSha256",sha(source));output.put("suiteMetadataSha256",sha(suite));output.put("targetMetadataSha256",sha(target));output.put("suiteEntityId",sp.getAttribute("entityID"));output.put("targetEntityId",idp.getAttribute("entityID"));output.put("nativeClasses",classes);output.put("records",records);output.put("diagnosticOnly",true);output.put("productFinding",false);output.put("privateKeysRead",false);output.put("privateKeyExported",false);output.put("algorithmPolicyChanged",false);
        System.out.println(M.writeValueAsString(output));
    }
}
