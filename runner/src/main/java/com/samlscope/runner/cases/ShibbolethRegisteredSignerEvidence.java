package com.samlscope.runner.cases;

import static com.samlscope.runner.cases.MetadataAlgorithmEvidence.children;
import com.fasterxml.jackson.databind.JsonNode;
import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.transcript.*;
import com.samlscope.saml.crypto.PlanCredentials;
import com.samlscope.saml.normal.*;
import com.samlscope.store.JsonCodec;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.net.URI;
import java.security.MessageDigest;
import java.security.cert.*;
import java.time.Instant;
import java.util.*;
import java.util.function.*;
import java.util.regex.Pattern;
import org.w3c.dom.Element;

/** Two simultaneous native peers, including a valid signature made by the other known peer.
 * Native HTTP errors establish nothing without the product's request-bound signature error.
 * The adapter closes the installed Issuer-scoped SP metadata ExplicitKey path; it makes no global trust-store claim. */
public final class ShibbolethRegisteredSignerEvidence implements RegisteredSignerNativeEvidence {
    public static final String SCHEMA="samlscope-shibboleth-registered-signer-v1";
    public static final String ADAPTER="shibboleth-native-issuer-key-locator-v1";
    public static final String CAMPAIGN="native-registered-signer";
    public static final String KIND="native-registered-signer-evidence";
    private static final String ORIGINAL="samlscope-shibboleth-registered-signer-original-v1";
    private static final String PREPARATION="samlscope-shibboleth-registered-signer-preparation-v1";
    private static final String TARGET="http://localhost:18280/idp/shibboleth", BASE="http://localhost:18080";
    private static final String MD="urn:oasis:names:tc:SAML:2.0:metadata", P="urn:oasis:names:tc:SAML:2.0:protocol", DS="http://www.w3.org/2000/09/xmldsig#";
    private static final List<String> FIXTURES=List.of("local-normal","local-invalid-signature","local-other-signer");
    private final Path directory;
    private final TranscriptContentReader content;
    private final Function<String,byte[]> metadata;
    private final BiFunction<String,String,Optional<PlanCredentials>> keys;
    public ShibbolethRegisteredSignerEvidence(Path directory, TranscriptContentReader content,
            Function<String,byte[]> metadata, BiFunction<String,String,Optional<PlanCredentials>> keys) {
        this.directory=Objects.requireNonNull(directory).toAbsolutePath().normalize();
        this.content=Objects.requireNonNull(content);this.metadata=Objects.requireNonNull(metadata);this.keys=Objects.requireNonNull(keys);
    }
    @Override public String adapter(){return ADAPTER;}
    @Override public String evidenceKind(){return KIND;}
    @Override public boolean exists(String run){return validRun(run)&&Files.exists(directory.resolve(run),LinkOption.NOFOLLOW_LINKS);}
    @Override public boolean hasFinalProof(String run){return validRun(run)&&Files.exists(directory.resolve(run).resolve("manifest.json"),LinkOption.NOFOLLOW_LINKS);}
    private static boolean validRun(String run){return run!=null&&run.matches("run_[0-9A-HJKMNP-TV-Z]{26}");}
    private static void require(boolean condition){if(!condition)throw new IllegalArgumentException("Native signer proof unavailable");}
    static String hash(byte[] bytes)throws Exception{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));}
    private static JsonNode json(byte[] bytes)throws Exception{return new JsonCodec().mapper().readTree(bytes);}
    private static String text(JsonNode node,String field){require(node.path(field).isTextual()&&!node.path(field).asText().isBlank());return node.path(field).asText();}
    private static Instant at(JsonNode node,String field){return Instant.parse(text(node,field));}
    private byte[] raw(Path folder,String name)throws Exception {
        require(!name.isBlank()&&!Path.of(name).isAbsolute());var file=folder.resolve(name).normalize();require(file.startsWith(folder)&&!file.equals(folder));
        for(var p=file;p!=null;p=p.getParent())require(!Files.isSymbolicLink(p));require(Files.isRegularFile(file,LinkOption.NOFOLLOW_LINKS));return Files.readAllBytes(file);
    }
    private byte[] file(Path folder,JsonNode m,String name)throws Exception{var bytes=raw(folder,name);require(hash(bytes).equals(text(m.path("files"),name)));return bytes;}
    private JsonNode node(Path folder,JsonNode m,String name)throws Exception{return json(file(folder,m,name));}
    private Map<String,TranscriptEntry> history(CaseContext c,String run){
        require(validRun(run));var result=new LinkedHashMap<String,TranscriptEntry>();
        for(var e:c.transcript().list(run)){require(run.equals(e.runId())&&result.put(e.id(),e)==null);if(e.decodedSamlRef()!=null)require(("transcripts/"+run+"/"+e.id()+".saml.xml").equals(e.decodedSamlRef()));}return result;
    }
    private byte[] decoded(TranscriptEntry e)throws Exception{require(e!=null&&e.decodedSamlRef()!=null);var bytes=content.readDecodedSaml(e);require(bytes!=null&&bytes.length==e.decodedSamlBytes());return bytes;}
    private JsonNode original(CaseContext c,Path folder,JsonNode m,String name,String kind)throws Exception {
        var ref=m.path("originals").path(name);var e=history(c,c.runId()).get(text(ref,"reference"));var bytes=decoded(e);
        require(hash(bytes).equals(text(ref,"sha256"))&&Arrays.equals(bytes,file(folder,m,"native-originals/"+name+".json")));
        require(e.direction()==Direction.INBOUND&&"POST".equals(e.method())&&Objects.equals(e.status(),204)&&"application/json".equals(e.contentType())&&(BASE+"/p/"+text(m,"planId")+"/sp/paos?run="+c.runId()).equals(e.url()));
        var n=json(bytes);require(ORIGINAL.equals(text(n,"schema"))&&c.runId().equals(text(n,"runId"))&&CAMPAIGN.equals(text(n,"campaignId"))&&kind.equals(text(n,"kind"))&&m.path("targetMetadataSha256").equals(n.path("targetMetadataSha256"))&&at(n,"recordedAt").isBefore(e.timestamp())&&!sensitive(n));return n;
    }
    static boolean sensitive(JsonNode n){
        if(n.isObject()){var fields=n.fields();while(fields.hasNext()){var e=fields.next();String k=e.getKey().toLowerCase(Locale.ROOT).replaceAll("[-_.]","");if(Set.of("cookie","setcookie","authorization","proxyauthorization","password","passwd","secret","credentials","token","accesstoken","refreshtoken","registrationaccesstoken","privatekey","metadatasignprivatekey").contains(k)||sensitive(e.getValue()))return true;}}
        else if(n.isArray())for(var item:n)if(sensitive(item))return true;return false;
    }
    private static List<X509Certificate> spKeys(Element root)throws Exception {
        var roles=children(root,MD,"SPSSODescriptor");require(roles.size()==1);var result=new ArrayList<X509Certificate>();
        for(var kd:children(roles.getFirst(),MD,"KeyDescriptor")){if(!kd.getAttribute("use").isBlank()&&!"signing".equals(kd.getAttribute("use")))continue;var certs=kd.getElementsByTagNameNS(DS,"X509Certificate");for(int i=0;i<certs.getLength();i++)result.add(certificate(certs.item(i).getTextContent()));}require(!result.isEmpty());return result;
    }
    private static X509Certificate certificate(String value)throws Exception{return (X509Certificate)CertificateFactory.getInstance("X.509").generateCertificate(new java.io.ByteArrayInputStream(Base64.getMimeDecoder().decode(value)));}
    private static Set<String> certHashes(List<X509Certificate> certificates)throws Exception{var result=new HashSet<String>();for(var c:certificates)result.add(hash(c.getEncoded()));return result;}
    private static Element fixture(byte[] raw,String entity)throws Exception {var root=SecureXml.parse(raw).getDocumentElement();require(MD.equals(root.getNamespaceURI())&&"EntityDescriptor".equals(root.getLocalName())&&entity.equals(root.getAttribute("entityID"))&&KeycloakSubjectConfirmationEvidence.signed(root,spKeys(root)));return root;}
    private static URI destination(Element target){var roles=children(target,MD,"IDPSSODescriptor");require(roles.size()==1);var urls=new HashSet<String>();for(var e:children(roles.getFirst(),MD,"SingleSignOnService"))if("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST".equals(e.getAttribute("Binding")))urls.add(e.getAttribute("Location"));require(urls.size()==1);var uri=URI.create(urls.iterator().next());require("http".equals(uri.getScheme())&&"localhost".equals(uri.getHost())&&uri.getPort()==18280&&uri.getRawQuery()==null&&uri.getRawFragment()==null);return uri;}
    @Override public Optional<RegisteredSignerProbeInputs> probeInputs(CaseContext c){
        if(!exists(c.runId()))return Optional.empty();try{
            var folder=directory.resolve(c.runId());var raw=raw(folder,"preparation.json");var m=json(raw);
            require(PREPARATION.equals(text(m,"schema"))&&CAMPAIGN.equals(text(m,"campaignId"))&&c.runId().equals(text(m,"localRunId")));
            var targetRaw=metadata.apply(c.runId());require(Arrays.equals(targetRaw,file(folder,m,"target-metadata.xml"))&&hash(targetRaw).equals(text(m,"targetMetadataSha256")));var target=SecureXml.parse(targetRaw).getDocumentElement();require(TARGET.equals(target.getAttribute("entityID")));
            var peers=m.path("peers");require(peers.isArray()&&peers.size()==2);JsonNode local=null,other=null;var ids=new HashSet<String>();var entities=new HashSet<String>();var labels=new HashSet<String>();var certs=new ArrayList<List<X509Certificate>>();
            for(var peer:peers){String run=text(peer,"runId"),plan=text(peer,"planId"),entity=text(peer,"entity"),label=text(peer,"label");require(validRun(run)&&plan.matches("plan_[0-9A-HJKMNP-TV-Z]{26}")&&entity.equals(BASE+"/p/"+plan)&&ids.add(run)&&entities.add(entity)&&Set.of("primary","secondary").contains(label)&&labels.add(label));var known=node(folder,m,label+"/created.json");require(run.equals(known.at("/run/id").asText())&&plan.equals(known.at("/run/planId").asText()));var sp=fixture(file(folder,m,label+"/fixture.xml"),entity);var key=keys.apply(run,"primary").orElseThrow();require(spKeys(sp).stream().anyMatch(cert->Arrays.equals(cert.getPublicKey().getEncoded(),key.certificate().getPublicKey().getEncoded())));certs.add(spKeys(sp));require(Arrays.equals(metadata.apply(run),targetRaw));if(run.equals(c.runId()))local=peer;else other=peer;}
            require(local!=null&&other!=null&&Collections.disjoint(certHashes(certs.get(0)),certHashes(certs.get(1))));var sp=fixture(file(folder,m,text(local,"label")+"/fixture.xml"),text(local,"entity"));return Optional.of(new RegisteredSignerProbeInputs(c.runId(),text(other,"runId"),text(local,"entity"),destination(target),MetadataSupersessionProbeTestCase.acs(sp,0),hash(raw)));
        }catch(Exception unavailable){return Optional.empty();}
    }

    private static final String N="urn:mace:shibboleth:2.0:metadata";
    private static final String XSI="http://www.w3.org/2001/XMLSchema-instance";
    private static final String PROFILE="http://shibboleth.net/ns/profiles/saml2/sso/browser";
    private static final String ENGINE="shibboleth.ExplicitKeySignatureTrustEngine";
    private static final String SHIB_IMAGE="sha256:3c1b1fa64c58258aefc9e38d4ae60e9f0340731318a472110ea56ce88c18a11a";
    private static final Map<String,String> JARS=Map.of(
            "idp-conf-impl","428e389d88bb2abcad19d69bcf759af29f7ce6beb776ccfaa5a6ea76751682ba",
            "idp-saml-impl","1a2a9f867d11c50eeaf2a6140bb5de88b0611d694ea6de2bbfe32f72a4a2998b",
            "opensaml-saml-impl","9f04221e172dc426f90fb3873d0148a0744edbf9e7a37de7ee0e6a34f7b74581",
            "opensaml-xmlsec-impl","cc67fc1bd9cb435cdbe7483ef04513c83cc9619a3015c04ad41bb6cc0eb6e68e",
            "opensaml-saml-api","cce72578ec8df5dd18cb71c88bba89bd196c640281c199ce875e2aa44154f93f");
    private static final Map<String,String> CONFIGS=Map.of(
            "global","ca08485a1b5ef8cf0ac1afb80ff066237759e4fb3d884d087f905d8ca0918bcc",
            "services","0c5de788ebc611af60ebb3bf4071dcd23744f599d64d65bdb0744515d11a77c0",
            "relying-party","64e2a04dfbf2ffa2a582b995bcbf121b634ab7c8766cb8f22d3397d541f31bd5");

    private JsonNode nativeState(CaseContext c,Path folder,JsonNode m,String name,String phase) throws Exception {
        var state=original(c,folder,m,name,"native-registered-peers");
        require(phase.equals(text(state,"phase"))&&at(state,"nativeStartedAt").isBefore(at(state,"nativeFinishedAt"))
                &&!at(state,"nativeFinishedAt").isAfter(at(state,"recordedAt")));
        runtime(state.path("runtime"));
        var initial=phase.equals("initial")||phase.equals("restored");
        String providers=initial?"original-providers.xml":"configured-providers.xml";
        String audit=initial?"original-audit.xml":"configured-audit.xml";
        require(hash(file(folder,m,providers)).equals(text(state,"providersSha256"))
                &&hash(file(folder,m,audit)).equals(text(state,"auditSha256")));
        return state;
    }

    private static String runtime(JsonNode runtime) {
        require(runtime.isObject()&&runtime.path("running").isBoolean()&&runtime.path("running").asBoolean()
                &&text(runtime,"id").matches("[0-9a-f]{64}")&&SHIB_IMAGE.equals(text(runtime,"image"))
                &&runtime.path("mounts").isArray()&&runtime.path("mounts").isEmpty());
        at(runtime,"startedAt");
        return text(runtime,"id")+"|"+text(runtime,"image");
    }

    private void peerReadbacks(Path folder,JsonNode m,JsonNode state,List<Element> fixtures) throws Exception {
        var rows=state.path("peers");require(rows.isArray()&&rows.size()==2);
        for(int i=0;i<2;i++) {
            var peer=m.path("peers").get(i);var row=rows.get(i);String label=text(peer,"label"),entity=text(peer,"entity");
            var expectedPath="/opt/reference-idp/metadata/registered-signer-"+text(peer,"runId")+".xml";
            require(label.equals(text(row,"label"))&&entity.equals(text(row,"entityId"))
                    &&expectedPath.equals(text(row,"sourcePath"))
                    &&hash(file(folder,m,label+"/fixture.xml")).equals(text(row,"sourceSha256"))
                    &&Arrays.equals(file(folder,m,label+"/fixture.xml"),file(folder,m,label+"-source.xml")));
            var query=node(folder,m,text(row,"queryFile"));var command=query.path("command");
            require(command.isArray()&&command.size()==5&&"/opt/reference-idp/bin/mdquery.sh".equals(command.get(0).asText())
                    &&"-u".equals(command.get(1).asText())&&"http://localhost:8080/idp".equals(command.get(2).asText())
                    &&"-e".equals(command.get(3).asText())&&entity.equals(command.get(4).asText())
                    &&query.path("exitCode").isInt()&&query.path("exitCode").asInt()==0&&entity.equals(text(query,"entityId")));
            var stdout=file(folder,m,text(row,"queryStdoutFile"));
            require(hash(stdout).equals(text(query,"stdoutSha256"))
                    &&hash(file(folder,m,text(row,"queryStderrFile"))).equals(text(query,"stderrSha256"))
                    &&!at(query,"recordedAt").isBefore(at(state,"nativeStartedAt"))
                    &&!at(query,"recordedAt").isAfter(at(state,"nativeFinishedAt")));
            var nativePeer=SecureXml.parse(stdout).getDocumentElement();
            require(MD.equals(nativePeer.getNamespaceURI())&&"EntityDescriptor".equals(nativePeer.getLocalName())
                    &&entity.equals(nativePeer.getAttribute("entityID"))
                    &&structure(single(fixtures.get(i),MD,"SPSSODescriptor"))
                            .equals(structure(single(nativePeer,MD,"SPSSODescriptor"))));
        }
    }

    private void configuration(Path folder,JsonNode m) throws Exception {
        for(var kind:List.of("providers","audit"))
            require(Arrays.equals(file(folder,m,"original-"+kind+".xml"),file(folder,m,"final-"+kind+".xml")));
        var originalProviders=SecureXml.parse(file(folder,m,"original-providers.xml")).getDocumentElement();
        var configured=SecureXml.parse(file(folder,m,"configured-providers.xml")).getDocumentElement();
        for(var peer:m.path("peers")) {
            String name="RegisteredSigner"+text(peer,"runId");
            var rows=children(configured,N,"MetadataProvider").stream().filter(e->name.equals(e.getAttribute("id"))).toList();
            require(rows.size()==1);var added=rows.getFirst();
            require("FilesystemMetadataProvider".equals(added.getAttributeNS(XSI,"type"))
                    &&("/opt/reference-idp/metadata/registered-signer-"+text(peer,"runId")+".xml").equals(added.getAttribute("metadataFile"))
                    &&children(added,N,"MetadataFilter").isEmpty());configured.removeChild(added);
        }
        require(structure(originalProviders).equals(structure(configured)));
        var inventory=node(folder,m,"other-provider-inventory.json");
        require(inventory.isArray()&&inventory.equals(node(folder,m,"other-provider-final-readback.json")));
        var expected=new HashSet<String>();var configuredOriginal=originalProviders.getElementsByTagNameNS(N,"MetadataProvider");
        for(int i=0;i<configuredOriginal.getLength();i++) {
            var provider=(Element)configuredOriginal.item(i);
            if("ChainingMetadataProvider".equals(provider.getAttributeNS(XSI,"type")))continue;
            require("FilesystemMetadataProvider".equals(provider.getAttributeNS(XSI,"type"))&&provider.hasAttribute("metadataFile"));
            expected.add(provider.getAttribute("metadataFile").replace("%{idp.home}","/opt/reference-idp"));
        }
        var seen=new HashSet<String>();
        for(var row:inventory) {
            require(seen.add(text(row,"path")));var bytes=file(folder,m,text(row,"file"));
            require(hash(bytes).equals(text(row,"sha256")));var document=SecureXml.parse(bytes);
            var entities=document.getElementsByTagNameNS(MD,"EntityDescriptor");
            for(int i=0;i<entities.getLength();i++)for(var peer:m.path("peers"))
                require(!text(peer,"entity").equals(((Element)entities.item(i)).getAttribute("entityID")));
        }
        require(seen.equals(expected));
        var originalAudit=SecureXml.parse(file(folder,m,"original-audit.xml")).getDocumentElement();
        var audit=SecureXml.parse(file(folder,m,"configured-audit.xml")).getDocumentElement();
        var old=singleAuditFormat(originalAudit);var selected=singleAuditFormat(audit);
        require("SAMLscope-signature-v1|%I|%SP|%e|%S|%XX|%b|%P|%T".equals(selected.getAttribute("value")));
        selected.setAttribute("value",old.getAttribute("value"));require(structure(originalAudit).equals(structure(audit)));
    }

    private static Element singleAuditFormat(Element root) {
        var entries=root.getElementsByTagNameNS("http://www.springframework.org/schema/beans","entry");Element selected=null;
        for(int i=0;i<entries.getLength();i++)if("Shibboleth-Audit".equals(((Element)entries.item(i)).getAttribute("key"))) {
            require(selected==null);selected=(Element)entries.item(i);
        }
        require(selected!=null);return selected;
    }

    private void trustScope(Path folder,JsonNode m,JsonNode initial,JsonNode before,JsonNode after,Instant lastResponse) throws Exception {
        for(var pin:JARS.entrySet())require(pin.getValue().equals(hash(file(folder,m,"native/native-"+pin.getKey()+".jar"))));
        for(var peer:m.path("peers")) {
            String label=text(peer,"label"),entity=text(peer,"entity");
            for(var phase:List.of("before","after")) {
                String prefix="native/trust-probes-"+phase+"-"+label+"-";
                var observed=node(folder,m,prefix+"observed.json");
                require(entity.equals(text(observed,"entityId"))&&PROFILE.equals(text(observed,"profileId"))
                        &&observed.path("privateFieldsExported").isBoolean()&&!observed.path("privateFieldsExported").asBoolean());
                var state=phase.equals("before")?before:after;
                require(within(at(observed,"recordedAt"),at(state,"nativeStartedAt"),at(state,"nativeFinishedAt"))
                        &&(phase.equals("before")?at(state,"nativeStartedAt").isAfter(at(initial,"recordedAt"))
                                :at(state,"nativeStartedAt").isAfter(lastResponse)));
                var nativeJars=observed.path("nativeJars");require(nativeJars.isObject()&&nativeJars.size()==4);
                for(var pin:JARS.entrySet())if(!pin.getKey().equals("opensaml-saml-api"))
                    require(pin.getValue().equals(text(nativeJars,pin.getKey())));
                for(var pin:CONFIGS.entrySet())require(pin.getValue().equals(hash(file(folder,m,prefix+pin.getKey()+".xml"))));
                var classpath=node(folder,m,prefix+"classpath-sha256.json");
                require("1fcd492d07b1ca59600b763c0cddc3be85dc223841a2298bf3719274b66c4cb3".equals(hash(file(folder,m,prefix+"classpath-sha256.json")))
                        &&JARS.get("opensaml-saml-api").equals(text(classpath,"/usr/local/tomcat/webapps/idp/WEB-INF/lib/opensaml-saml-api-5.2.3.jar")));
                var overrides=node(folder,m,prefix+"override-source-inventory.json");require(overrides.isArray()&&overrides.isEmpty());
                var properties=node(folder,m,prefix+"selected-properties.json");require(properties.isObject()&&ENGINE.equals(text(properties,"idp.trust.signatures")));
                for(var fields=properties.fields();fields.hasNext();) {
                    var row=fields.next();require((row.getKey().equals("idp.trust.signatures")&&row.getValue().asText().equals(ENGINE))
                            ||(row.getKey().equals("idp.security.config")&&row.getValue().asText().equals("shibboleth.DefaultSecurityConfiguration"))
                            ||(row.getKey().equals("idp.additionalProperties")&&row.getValue().asText().equals("/credentials/secrets.properties")));
                }
                var flags=node(folder,m,prefix+"process-overrides.json");
                require(flags.path("nativeJavaProcessObserved").asBoolean(false)&&!flags.path("trustOverridePresent").asBoolean(true)
                        &&!flags.path("customAgentPresent").asBoolean(true)&&!flags.path("privateFieldsExported").asBoolean(true));
                ShibbolethSubjectConfirmationEvidence.validateProfile(node(folder,m,prefix+"native-effective-profile.json"));
            }
            for(var suffix:List.of("classpath-sha256.json","override-source-inventory.json","selected-properties.json",
                    "properties-sha256.json","xml-sha256.json","native-effective-profile.json","process-overrides.json"))
                require(Arrays.equals(file(folder,m,"native/trust-probes-before-"+label+"-"+suffix),
                        file(folder,m,"native/trust-probes-after-"+label+"-"+suffix)));
        }
        var conf=file(folder,m,"native/native-idp-conf-impl.jar");
        var rp=SecureXml.parse(zip(conf,"net/shibboleth/idp/conf/relying-party-system.xml")).getDocumentElement();
        var explicit=bean(rp,ENGINE);
        require("org.opensaml.xmlsec.signature.support.impl.ExplicitKeySignatureTrustEngine".equals(explicit.getAttribute("class"))
                &&"shibboleth.MetadataCredentialResolver".equals(explicit.getAttributeNS("http://www.springframework.org/schema/c","resolver-ref")));
        var security=SecureXml.parse(zip(conf,"net/shibboleth/idp/conf/security-system.xml")).getDocumentElement();
        var resolver=bean(security,"shibboleth.MetadataCredentialResolver");
        require("org.opensaml.saml.security.impl.MetadataCredentialResolver".equals(resolver.getAttribute("class"))
                &&"shibboleth.RoleDescriptorResolver".equals(resolver.getAttributeNS("http://www.springframework.org/schema/p","roleDescriptorResolver-ref")));
        // Exact installed bytes close Issuer -> peer EntityID -> EntityId/EntityRole criteria -> metadata credentials.
        require("d662551f7ca197d5329ffb875033daba3dae1ea65807bdff3ebc9af291b3ac13".equals(hash(zip(file(folder,m,"native/native-opensaml-saml-api.jar"),"org/opensaml/saml/common/messaging/context/SAMLPeerEntityContext.class"))));
        var saml=file(folder,m,"native/native-opensaml-saml-impl.jar");
        require("01f227c291ac2336c9c5638a050af4dcee311b974240361ab89fa276ed8babbd".equals(hash(zip(saml,"org/opensaml/saml/common/binding/security/impl/BaseSAMLXMLSignatureSecurityHandler.class")))
                &&"b37276d78f06d8267835574c1c170f951dbc43c62290ea8a8c4df62e22fa9643".equals(hash(zip(saml,"org/opensaml/saml/common/binding/security/impl/SAMLProtocolMessageXMLSignatureSecurityHandler.class")))
                &&"2364eed8b664a21326cfe9cbf08aafae286ed16bedb9e654705d97063f716c07".equals(hash(zip(saml,"org/opensaml/saml/security/impl/MetadataCredentialResolver.class"))));
    }

    /** Only an actual request-bound native audit event closes this refusal; an HTTP error never does. */
    static String[] nativeAudit(byte[] raw,String id,String entity,Instant begin,Instant end) {
        require(!end.isBefore(begin));String[] selected=null;
        for(var line:new String(raw,StandardCharsets.UTF_8).lines().filter(s->!s.isBlank()).toList()) {
            var fields=line.split("\\|",-1);
            require(fields.length==9&&"SAMLscope-signature-v1".equals(fields[0]));
            if(!id.equals(fields[1]))continue;
            require(selected==null&&entity.equals(fields[2])&&"POST".equals(fields[6])&&PROFILE.equals(fields[7])
                    &&within(Instant.parse(fields[8]),begin,end));selected=fields;
        }
        require(selected!=null);return selected;
    }

    static boolean nativeSignatureRejectionPage(byte[] body) {
        var html=new String(body,StandardCharsets.UTF_8);
        var visible=html.replaceAll("(?is)<(?:script|style)\\b[^>]*>.*?</(?:script|style)\\s*>","").replaceAll("(?s)<[^>]*>"," ");
        return body.length>0&&body.length<=262144&&visible.contains("Message Security Error")
                &&!Pattern.compile("(?is)<\\s*(?:form|input)\\b|\\b(?:SAMLRequest|SAMLResponse|Authorization|Cookie|password)\\b").matcher(html).find();
    }

    private record ClockSample(Instant nativeAt,Instant hostStart,Instant hostEnd) {}
    private ClockSample clock(Path folder,JsonNode m,String name) throws Exception {
        var n=node(folder,m,name);var command=n.path("command");
        require("native-product-os-UTC".equals(text(n,"clockDomain"))&&command.isArray()&&command.size()==3
                &&"date".equals(command.get(0).asText())&&"-u".equals(command.get(1).asText())
                &&"+%Y-%m-%dT%H:%M:%S.%NZ".equals(command.get(2).asText()));
        var bytes=file(folder,m,text(n,"nativeClockFile"));require(hash(bytes).equals(text(n,"nativeClockSha256")));
        var nativeAt=Instant.parse(new String(bytes,StandardCharsets.UTF_8).strip());require(nativeAt.equals(at(n,"nativeInstant")));
        var start=at(n,"hostStartedAt");var end=at(n,"hostCompletedAt");require(!end.isBefore(start));
        return new ClockSample(nativeAt,start,end);
    }

    private record Checked(TranscriptEntry request,TranscriptEntry response,boolean success) {}
    private Checked probe(CaseContext c,Path folder,JsonNode m,JsonNode peer,JsonNode otherPeer,
            Element sp,Element other,Element target,JsonNode row,String name) throws Exception {
        String run=text(peer,"runId"),entity=text(peer,"entity");var entries=history(c,run);
        var request=entries.get(text(row,"requestReference"));
        require(request!=null&&request.direction()==Direction.OUTBOUND&&"POST".equals(request.method())
                &&request.timestamp().isAfter(at(m,"configuredAt")));
        String action=ActionIds.derive(run,RegisteredSignerObservationTestCase.CASE,"await-fixture-"+name,0);
        require(name.equals(text(row,"fixture"))&&run.equals(text(row,"runId"))&&action.equals(text(row,"actionId"))
                &&action.equals(request.correlationId()));
        var raw=decoded(request);var q=SecureXml.parse(raw).getDocumentElement();String id=q.getAttribute("ID");
        String acs=MetadataSupersessionProbeTestCase.acs(sp,0).toString();
        require(P.equals(q.getNamespaceURI())&&"AuthnRequest".equals(q.getLocalName())&&("_"+action).equals(id)
                &&entity.equals(KeycloakSubjectConfirmationEvidence.issuer(q))&&destination(target).toString().equals(request.url())
                &&request.url().equals(q.getAttribute("Destination"))&&acs.equals(q.getAttribute("AssertionConsumerServiceURL")));
        require(entries.values().stream().filter(e->e.direction()==Direction.OUTBOUND
                &&(action.equals(e.correlationId())||id.equals(e.samlSummary().get("id")))).count()==1);
        var signer=keys.apply(name.equals("local-other-signer")?text(otherPeer,"runId"):run,"primary").orElseThrow();
        validateRequest(run,name,raw,destination(target),entity,URI.create(acs),signer);
        var issue=Instant.parse(q.getAttribute("IssueInstant"));require(!issue.isAfter(request.timestamp()));
        boolean own=KeycloakSubjectConfirmationEvidence.signed(q,spKeys(sp));
        boolean foreign=KeycloakSubjectConfirmationEvidence.signed(q,spKeys(other));
        require(name.equals("local-normal")?own&&!foreign:name.equals("local-invalid-signature")?!own&&!foreign:!own&&foreign);

        var record=original(c,folder,m,text(row,"nativeHttpOriginal"),"native-http-response");var http=record.path("native");
        require(run.equals(text(record,"observedRunId"))&&request.id().equals(text(record,"requestReference"))
                &&action.equals(text(record,"actionId"))&&"POST".equals(text(http,"method"))
                &&request.url().equals(text(http,"requestUrl"))&&request.url().equals(text(http,"responseUrl"))
                &&id.equals(text(http,"requestId"))&&hash(raw).equals(text(http,"requestSha256")));
        var before=clock(folder,m,text(record,"clockBeforeFile"));var after=clock(folder,m,text(record,"clockAfterFile"));
        require(!after.nativeAt().isBefore(before.nativeAt())&&!before.hostStart().isBefore(at(m,"configuredAt"))
                &&!at(http,"startedAt").isBefore(before.hostEnd())&&!at(http,"startedAt").isBefore(request.timestamp())
                &&!at(http,"finishedAt").isBefore(at(http,"startedAt"))&&!after.hostStart().isBefore(at(http,"finishedAt"))
                &&!after.hostEnd().isAfter(at(m,"completedAt")));
        var audit=nativeAudit(file(folder,m,text(record,"auditFile")),id,entity,before.nativeAt(),after.nativeAt());
        var responses=entries.values().stream().filter(e->e.direction()==Direction.INBOUND
                &&id.equals(e.samlSummary().get("inResponseTo"))).toList();
        var browsers=entries.values().stream().filter(e->e.direction()==Direction.INBOUND&&action.equals(e.correlationId())
                &&"BrowserResponseObservation".equals(e.samlSummary().get("type"))).toList();
        require(responses.size()+browsers.size()==1);boolean success=!responses.isEmpty();TranscriptEntry response;
        if(success) {
            response=responses.getFirst();require(!name.equals("local-invalid-signature")&&"POST".equals(response.method())
                    &&acs.equals(response.url())&&http.path("responseStatus").asInt(-1)==200
                    &&audit[3].isEmpty()&&"Success".equals(audit[4])&&"true".equals(audit[5]));
            var responseBytes=decoded(response);require(hash(responseBytes).equals(text(http,"responseSamlSha256")));
            var reply=SecureXml.parse(responseBytes).getDocumentElement();
            VerifiedResponseAssertion.read(reply,TARGET,MetadataAlgorithmEvidence.signingKeys(target),sp,
                    keys.apply(run,"primary"),id,acs);
        } else {
            response=browsers.getFirst();require(!name.equals("local-normal")&&"BROWSER".equals(response.method())
                    &&Integer.valueOf(400).equals(response.status())&&request.url().equals(response.url())
                    &&("transcripts/"+run+"/"+response.id()+".body").equals(response.bodyRef())
                    &&response.bodyBytes()>0&&response.bodyBytes()<=262144
                    &&http.path("responseStatus").asInt(-1)==400&&"MessageAuthenticationError".equals(audit[3])&&audit[4].isEmpty());
            var body=raw(directory.getParent(),response.bodyRef());
            require(body.length==response.bodyBytes()&&nativeSignatureRejectionPage(body)
                    &&Arrays.equals(body,file(folder,m,text(http,"responseBodyFile")))
                    &&hash(body).equals(text(http,"responseBodySha256"))&&body.length==http.path("responseBodyBytes").asLong(-1));
        }
        require(response.id().equals(text(row,"responseReference"))&&response.id().equals(text(record,"responseReference"))
                &&response.timestamp().isAfter(request.timestamp())&&!at(http,"finishedAt").isAfter(response.timestamp())
                &&response.timestamp().isBefore(at(m,"completedAt"))&&at(record,"recordedAt").isAfter(response.timestamp()));
        return new Checked(request,response,success);
    }

    static void validateRequest(String run,String fixture,byte[] raw,URI destination,String entity,URI acs,
            PlanCredentials signer) {
        require(FIXTURES.contains(fixture));var q=SecureXml.parse(raw).getDocumentElement();
        String action=ActionIds.derive(run,RegisteredSignerObservationTestCase.CASE,"await-fixture-"+fixture,0);
        var expected=new SamlSignedRequestFactory().build(fixture.equals("local-invalid-signature")
                ?SamlSignedRequestFactory.Fixture.BAD_SIGNATURE_VALUE:SamlSignedRequestFactory.Fixture.VALID,
                "_"+action,destination,entity,acs,Instant.parse(q.getAttribute("IssueInstant")),signer);
        require(Arrays.equals(expected,raw));
    }

    private void baselines(CaseContext c,Path folder,JsonNode m,List<Element> fixtures,Element target) throws Exception {
        var rows=m.path("baselines");require(rows.isArray()&&rows.size()==2);
        for(int i=0;i<2;i++) {
            var peer=m.path("peers").get(i);var row=rows.get(i);String run=text(peer,"runId");
            require(run.equals(text(row,"runId")));var history=history(c,run);
            var request=history.get(text(row,"requestReference"));var response=history.get(text(row,"responseReference"));
            require(request!=null&&response!=null&&request.direction()==Direction.OUTBOUND&&response.direction()==Direction.INBOUND
                    &&"GET".equals(request.method())&&"POST".equals(response.method())&&request.timestamp().isBefore(response.timestamp())
                    &&response.timestamp().isBefore(at(m,"configuredAt"))&&Boolean.TRUE.equals(response.samlSummary().get("normalFlowAccepted")));
            var bytes=decoded(request);var q=SecureXml.parse(bytes).getDocumentElement();String id=q.getAttribute("ID");
            var key=keys.apply(run,"primary").orElseThrow();
            require(text(peer,"entity").equals(KeycloakSubjectConfirmationEvidence.issuer(q))
                    &&Set.of("","false","0").contains(q.getAttribute("ForceAuthn"))
                    &&Set.of("","false","0").contains(q.getAttribute("IsPassive"))
                    &&new com.samlscope.saml.binding.RedirectSignatureVerifier().isValidForMessage(request.rawQuery(),key.certificate(),bytes)
                    &&id.equals(response.samlSummary().get("inResponseTo")));
            String acs=MetadataSupersessionProbeTestCase.acs(fixtures.get(i),0).toString();
            require(acs.equals(response.url()));
            VerifiedResponseAssertion.read(SecureXml.parse(decoded(response)).getDocumentElement(),TARGET,
                    MetadataAlgorithmEvidence.signingKeys(target),fixtures.get(i),Optional.of(key),id,acs);
        }
    }

    private void restorationAndCounts(Path folder,JsonNode m) throws Exception {
        var restoration=node(folder,m,"restoration.json");
        require(restoration.path("restored").asBoolean(false)&&restoration.path("errors").isArray()&&restoration.path("errors").isEmpty()
                &&restoration.path("original").equals(restoration.path("final")));
        for(var kind:List.of("providers","audit")) {
            String path="/opt/reference-idp/conf/"+(kind.equals("providers")?"metadata-providers":"audit")+".xml";
            require(hash(file(folder,m,"original-"+kind+".xml")).equals(text(restoration.path("original"),path)));
        }
        var removed=restoration.path("temporarySourcesRemoved");require(removed.isArray()&&removed.size()==2);
        var removalPaths=new HashSet<String>();
        for(var row:removed)require(row.path("absent").isBoolean()&&row.path("absent").asBoolean()&&removalPaths.add(text(row,"path")));
        var expectedRemovals=new HashSet<String>();for(var peer:m.path("peers"))expectedRemovals.add("/opt/reference-idp/metadata/registered-signer-"+text(peer,"runId")+".xml");
        require(removalPaths.equals(expectedRemovals));
        boolean auditChanged=!Arrays.equals(file(folder,m,"original-audit.xml"),file(folder,m,"configured-audit.xml"));
        var expectedWrites=new HashMap<String,Map.Entry<String,String>>();
        expectedWrites.put("prepare-native-providers",Map.entry("/opt/reference-idp/conf/metadata-providers.xml",hash(file(folder,m,"configured-providers.xml"))));
        expectedWrites.put("restore-metadata-providers.xml",Map.entry("/opt/reference-idp/conf/metadata-providers.xml",hash(file(folder,m,"original-providers.xml"))));
        if(auditChanged){
            expectedWrites.put("prepare-audit",Map.entry("/opt/reference-idp/conf/audit.xml",hash(file(folder,m,"configured-audit.xml"))));
            expectedWrites.put("restore-audit.xml",Map.entry("/opt/reference-idp/conf/audit.xml",hash(file(folder,m,"original-audit.xml"))));
        }
        for(var peer:m.path("peers"))expectedWrites.put("prepare-"+text(peer,"label")+"-metadata",Map.entry("/opt/reference-idp/metadata/registered-signer-"+text(peer,"runId")+".xml",hash(file(folder,m,text(peer,"label")+"/fixture.xml"))));
        var operations=node(folder,m,"operations.json");require(operations.isArray());int writes=0,restores=0,reloads=0,restarts=0;
        for(var row:operations) {
            switch(text(row,"operation")) {
                case "write" -> {var expected=expectedWrites.remove(text(row,"label"));require(expected!=null&&row.path("readBack").asBoolean(false)
                        &&expected.getKey().equals(text(row,"path"))&&expected.getValue().equals(text(row,"sha256")));writes++;if(text(row,"label").startsWith("restore-"))restores++;}
                case "reload" -> {require(row.path("completed").asBoolean(false));reloads++;}
                case "restart" -> {require(row.path("completed").asBoolean(false));restarts++;}
                default -> throw new IllegalArgumentException("Unknown native operation");
            }
        }
        require(expectedWrites.isEmpty());
        var counts=node(folder,m,"operation-counts.json");
        require(counts.path("restored").asBoolean(false)&&counts.path("nativeConfigurationWrites").asInt(-1)==writes&&writes==(auditChanged?6:4)
                &&counts.path("restorationWrites").asInt(-1)==restores&&restores==(auditChanged?2:1)
                &&counts.path("metadataReloads").asInt(-1)==reloads&&reloads==(auditChanged?0:2)
                &&counts.path("productRestarts").asInt(-1)==restarts&&restarts==(auditChanged?2:0)
                &&counts.path("outboxProtocolSubmissions").asInt(-1)==6&&counts.path("initialBaselineSubmissions").asInt(-1)==2
                &&counts.path("protocolSubmissions").asInt(-1)==8&&counts.path("credentialPosts").asInt(-1)==1
                &&counts.path("actualOutboxTargetAttempts").asInt(-1)==6
                &&counts.path("nativePostAttempts").asInt(-1)==6&&counts.path("nativeRedirectAttempts").asInt(-1)==2
                &&counts.path("credentialPostAttempts").asInt(-1)==1
                &&counts.path("personOperations").asInt(-1)==0&&counts.path("sameAuthenticatedClient").asBoolean(false)
                &&counts.path("additionalLoginBlocked").asBoolean(false)
                &&counts.path("credentialValuesPersisted").isBoolean()&&!counts.path("credentialValuesPersisted").asBoolean());
    }

    @Override public Optional<CaseOutcome> evaluate(CaseContext c) {
        if(!exists(c.runId()))return Optional.empty();String stage="registered-signer-originals-unproven";
        try {
            require(c.transcriptComplete());var folder=directory.resolve(c.runId());var manifest=raw(folder,"manifest.json");var m=json(manifest);
            require(SCHEMA.equals(text(m,"schema"))&&ADAPTER.equals(text(m,"adapter"))&&CAMPAIGN.equals(text(m,"campaignId"))
                    &&c.runId().equals(text(m,"runId"))&&TARGET.equals(text(m,"targetEntityId"))&&probeInputs(c).isPresent());
            var prep=node(folder,m,"preparation.json");require(m.path("peers").equals(prep.path("peers")));
            var peers=m.path("peers");require(peers.size()==2&&c.runId().equals(text(peers.get(0),"runId"))
                    &&text(m,"planId").equals(text(peers.get(0),"planId"))&&"primary".equals(text(peers.get(0),"label")));
            var targetRaw=metadata.apply(c.runId());require(Arrays.equals(targetRaw,file(folder,m,"target-metadata.xml"))
                    &&hash(targetRaw).equals(text(m,"targetMetadataSha256")));
            var target=SecureXml.parse(targetRaw).getDocumentElement();var fixtures=new ArrayList<Element>();
            for(var peer:peers)fixtures.add(fixture(file(folder,m,text(peer,"label")+"/fixture.xml"),text(peer,"entity")));
            stage="native-signature-configuration-unproven";configuration(folder,m);
            var initial=nativeState(c,folder,m,"initial","initial");var before=nativeState(c,folder,m,"probes-before","configured");
            var after=nativeState(c,folder,m,"probes-after","configured");
            require(runtime(initial.path("runtime")).equals(runtime(before.path("runtime")))
                    &&before.path("runtime").equals(after.path("runtime"))
                    &&at(initial,"recordedAt").isBefore(at(before,"recordedAt"))
                    &&at(before,"recordedAt").equals(at(m,"configuredAt"))&&at(after,"recordedAt").equals(at(m,"completedAt"))
                    &&at(before,"recordedAt").isBefore(at(after,"nativeStartedAt")));
            peerReadbacks(folder,m,before,fixtures);peerReadbacks(folder,m,after,fixtures);baselines(c,folder,m,fixtures,target);
            stage="six-outbox-controls-unproven";var rows=m.path("probes");require(rows.isArray()&&rows.size()==6);
            var expectedOriginals=new HashSet<>(List.of("initial","probes-before","probes-after","restoration"));
            for(var row:rows)require(expectedOriginals.add(text(row,"nativeHttpOriginal")));
            var declaredOriginals=new HashSet<String>();m.path("originals").fieldNames().forEachRemaining(declaredOriginals::add);
            require(declaredOriginals.equals(expectedOriginals));
            var checked=new ArrayList<Checked>();var evidence=new ArrayList<EvidenceRef>();
            for(int i=0;i<2;i++)for(int j=0;j<3;j++) {
                var result=probe(c,folder,m,peers.get(i),peers.get(1-i),fixtures.get(i),fixtures.get(1-i),target,rows.get(i*3+j),FIXTURES.get(j));
                checked.add(result);evidence.add(new EvidenceRef("transcript",result.request().id()));
                evidence.add(new EvidenceRef("transcript",result.response().id()));
            }
            for(int i=1;i<checked.size();i++)require(checked.get(i-1).response().timestamp().isBefore(checked.get(i).request().timestamp()));
            trustScope(folder,m,initial,before,after,checked.getLast().response().timestamp());
            stage="restoration-unproven";var restored=nativeState(c,folder,m,"restoration","restored");
            require(runtime(initial.path("runtime")).equals(runtime(restored.path("runtime")))
                    &&at(restored,"recordedAt").isAfter(at(after,"recordedAt"))&&restored.path("restored").asBoolean(false));
            restorationAndCounts(folder,m);
            evidence.add(new EvidenceRef(KIND,c.runId()+"/manifest.json#"+hash(manifest)));
            for(var ref:m.path("originals"))evidence.add(new EvidenceRef("transcript",text(ref,"reference")));
            boolean accepted=checked.get(2).success()||checked.get(5).success();
            String reason=accepted?"signature.signer.issuer-key-mismatch-accepted":"signature.signer.issuer-key-restriction-observed";
            return Optional.of(new CaseOutcome(accepted?Outcome.VIOLATED:Outcome.SATISFIED,null,reason,reason,
                    evidence.stream().distinct().toList(),Map.of("evidence_adapter",ADAPTER,"native_run_id",c.runId(),
                            "case_id",RegisteredSignerObservationTestCase.CASE,"native_originals_verified",true,
                            "restoration_verified",true,"scope","two-simultaneously-registered-native-saml-peers",
                            "native_receipt_owned",true)));
        } catch(Exception unavailable) {return Optional.of(pending(c.runId(),stage));}
    }

    @Override public CaseOutcome pending(String run,String stage) {
        return new CaseOutcome(Outcome.NOT_VERIFIED,stage,"signature.signer.native-unproven","signature.signer.native-unproven",
                List.of(),Map.of("evidence_adapter",ADAPTER,"native_run_id",run,"case_id",RegisteredSignerObservationTestCase.CASE,
                        "native_receipt_owned",true));
    }
    private static boolean within(Instant at,Instant start,Instant end){return !at.isBefore(start)&&!at.isAfter(end);}
    private static Element single(Element root,String ns,String name){var rows=children(root,ns,name);require(rows.size()==1);return rows.getFirst();}
    private static Element bean(Element root,String id) {
        var rows=root.getElementsByTagNameNS("http://www.springframework.org/schema/beans","bean");Element result=null;
        for(int i=0;i<rows.getLength();i++)if(id.equals(((Element)rows.item(i)).getAttribute("id"))) {require(result==null);result=(Element)rows.item(i);}
        require(result!=null);return result;
    }
    private static byte[] zip(byte[] bytes,String name) throws Exception {
        try(var stream=new java.util.zip.ZipInputStream(new java.io.ByteArrayInputStream(bytes))) {
            for(var entry=stream.getNextEntry();entry!=null;entry=stream.getNextEntry())if(name.equals(entry.getName()))return stream.readAllBytes();
        }
        throw new IllegalArgumentException("Native implementation resource unavailable");
    }
    private static String structure(Element root) {
        var attributes=new TreeMap<String,String>();
        for(int i=0;i<root.getAttributes().getLength();i++) {
            var a=root.getAttributes().item(i);if(!"http://www.w3.org/2000/xmlns/".equals(a.getNamespaceURI()))
                attributes.put(String.valueOf(a.getNamespaceURI())+"|"+a.getLocalName(),a.getNodeValue());
        }
        var text=new StringBuilder(String.valueOf(root.getNamespaceURI())+"|"+root.getLocalName()+attributes);
        for(var child=root.getFirstChild();child!=null;child=child.getNextSibling()) {
            if(child instanceof Element element)text.append(structure(element));
            else if(child.getNodeType()==org.w3c.dom.Node.TEXT_NODE&&!child.getTextContent().isBlank())
                text.append(DS.equals(root.getNamespaceURI())&&"X509Certificate".equals(root.getLocalName())
                        ?child.getTextContent().replaceAll("\\s",""):child.getTextContent().trim());
        }
        return text.toString();
    }
}
