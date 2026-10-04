package com.samlscope.runner.cases;

import static com.samlscope.runner.cases.SloRegisteredSignerEvidence.*;
import com.fasterxml.jackson.databind.JsonNode;
import com.samlscope.core.caseexec.CaseContext;
import com.samlscope.core.evaluation.EvidenceRef;
import com.samlscope.core.transcript.*;
import com.samlscope.saml.normal.SecureXml;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.file.Path;
import java.security.cert.CertificateFactory;
import java.time.Instant;
import java.util.*;
import java.util.regex.Pattern;
import java.util.zip.ZipInputStream;
import org.w3c.dom.Element;

/** Product-specific SLO consumers; an SSO proof cannot be substituted for these native paths. */
public final class SloRegisteredSignerNativeAdapters {
    public static SloRegisteredSignerNativeAdapter[] create(TranscriptContentReader content){
        Objects.requireNonNull(content);
        return new SloRegisteredSignerNativeAdapter[]{new KeycloakSloRegisteredSignerAdapter(),
                new ShibbolethSloRegisteredSignerAdapter(),new SimpleSamlPhpSloRegisteredSignerAdapter()};
    }
    private abstract static class NativeAdapter implements SloRegisteredSignerNativeAdapter {
        abstract String image();
        abstract void source(Originals o,JsonNode m,JsonNode before,JsonNode after)throws Exception;
        Set<String> configuredReadonlyFiles(Originals o,JsonNode m,JsonNode initial,JsonNode before)throws Exception{return Set.of();}
        abstract void peer(Originals o,JsonNode m,JsonNode nativePeer,JsonNode expectedPeer)throws Exception;
        abstract boolean rejected(Originals o,JsonNode m,JsonNode observation,JsonNode n,Element request,byte[] body)throws Exception;
        @Override public Session open(CaseContext context,Path folder,JsonNode m,Originals o,boolean finalProof)throws Exception {
            var initial=state(o,m,"initial");var before=state(o,m,"probes-before");
            require(at(initial,"recordedAt").isBefore(at(before,"recordedAt")));
            var beforeData=readback(o,m,before);var initialData=readback(o,m,initial);
            requireHostedTarget(beforeData,text(m,"targetEntityId"),o.file(m,text(beforeData,"hostedMetadataFile")));
            require(runtime(beforeData).path("image").asText().equals(image()));
            requireReadonlyBindingsUnchanged(initialData,beforeData,configuredReadonlyFiles(o,m,initialData,beforeData));
            require(runtime(initialData).path("id").equals(runtime(beforeData).path("id"))&&runtime(initialData).path("image").equals(runtime(beforeData).path("image")));
            require(beforeData.path("peers").isArray()&&beforeData.path("peers").size()==2&&initialData.path("peers").isArray()&&initialData.path("peers").size()==2);
            for(int i=0;i<2;i++){var old=initialData.path("peers").get(i);require(old.path("present").isBoolean()&&!old.path("present").asBoolean()
                    &&text(m.path("peers").get(i),"entity").equals(text(old,"entity")));peer(o,m,beforeData.path("peers").get(i),m.path("peers").get(i));}
            JsonNode after=finalProof?state(o,m,"probes-after"):before;var afterData=readback(o,m,after);
            requireHostedTarget(afterData,text(m,"targetEntityId"),o.file(m,text(afterData,"hostedMetadataFile")));
            require(runtime(beforeData).equals(runtime(afterData))&&beforeData.path("peers").equals(afterData.path("peers"))
                    &&beforeData.path("operativeConsumer").equals(afterData.path("operativeConsumer")));
            requireReadonlyBindingsUnchanged(beforeData,afterData);source(o,m,beforeData,afterData);
            var references=new ArrayList<EvidenceRef>(List.of(o.originalRef(m,"initial"),o.originalRef(m,"probes-before")));
            if(finalProof){
                require(at(before,"recordedAt").isBefore(at(after,"recordedAt")));var restored=state(o,m,"restoration");var finalData=readback(o,m,restored);
                require(at(restored,"recordedAt").isAfter(at(after,"recordedAt"))&&restored.path("restored").isBoolean()&&restored.path("restored").asBoolean()
                        &&initialData.path("peers").equals(finalData.path("peers"))&&initialData.path("configurationFiles").equals(finalData.path("configurationFiles"))
                        &&runtime(initialData).path("id").equals(runtime(finalData).path("id"))&&runtime(initialData).path("image").equals(runtime(finalData).path("image"))
                        &&runtime(initialData).path("mounts").equals(runtime(finalData).path("mounts")));
                requireReadonlyBindingsUnchanged(initialData,finalData);
                var files=initialData.path("configurationFiles");require(files.isObject()&&!files.isEmpty());var it=files.fieldNames();while(it.hasNext()){var name=it.next();require(Arrays.equals(o.file(m,"original-configuration/"+name),o.file(m,"final-configuration/"+name))
                        &&hash(o.file(m,"original-configuration/"+name)).equals(text(files,name)));}
                var counts=o.node(m,"operation-counts.json");require(counts.path("restored").isBoolean()&&counts.path("restored").asBoolean());
                for(String name:List.of("protocolSubmissions","outboxProtocolSubmissions","credentialPosts","nativeConfigurationWrites","restorationWrites","personOperations","productRestarts"))
                    require(counts.path(name).isIntegralNumber()&&counts.path(name).canConvertToInt()&&counts.path(name).asInt()>=0);
                require(counts.path("outboxProtocolSubmissions").asInt()>=3&&counts.path("protocolSubmissions").asInt()>=counts.path("outboxProtocolSubmissions").asInt());
                references.add(o.originalRef(m,"probes-after"));references.add(o.originalRef(m,"restoration"));
            }
            final JsonNode finalBefore=before,finalAfter=after;
            return new Session(){
                @Override public List<EvidenceRef> registrationEvidence(){return List.copyOf(references);}
                @Override public NativeUse validate(JsonNode observation,String fixture,TranscriptEntry request,Element q,byte[] raw,TranscriptEntry response,Element r)throws Exception {
                    String name=text(observation,"nativeHttpOriginal");var record=o.original(m,name,"native-slo-http-response");var n=record.path("native");
                    require(context.runId().equals(text(record,"observedRunId"))&&fixture.equals(text(record,"fixture"))&&request.id().equals(text(record,"requestReference"))
                            &&request.correlationId().equals(text(record,"actionId"))&&"POST".equals(text(n,"method"))&&request.url().equals(text(n,"requestUrl"))
                            &&q.getAttribute("ID").equals(text(n,"requestId"))&&hash(raw).equals(text(n,"requestSha256"))&&n.path("responseStatus").isInt());
                    var start=at(n,"startedAt");var end=at(n,"finishedAt");require(!start.isBefore(request.timestamp())&&end.isAfter(start)
                            &&start.isAfter(at(finalBefore,"nativeFinishedAt"))&&(!finalProof||end.isBefore(at(finalAfter,"nativeStartedAt")))
                            &&at(record,"recordedAt").isAfter(end));
                    var body=o.file(m,text(n,"responseBodyFile"));require(body.length==n.path("responseBodyBytes").asInt(-1)&&hash(body).equals(text(n,"responseBodySha256")));
                    Decision decision=Decision.UNPROVEN;
                    if(response!=null&&r!=null&&success(r)) {
                        require(n.path("responseSamlSha256").isTextual()&&hash(o.decoded(response)).equals(text(n,"responseSamlSha256"))
                                &&response.id().equals(text(record,"responseReference"))
                                &&!end.isAfter(response.timestamp()));decision=Decision.ACCEPTED;
                        byte[] location=n.has("responseLocationFile")?o.file(m,text(n,"responseLocationFile")):null;
                        requireNativeResponseBinding(n,body,location,o.decoded(response),response.url(),response.rawQuery(),response.method());
                    }else if(rejected(o,m,observation,n,q,body)) decision=Decision.REJECTED_SIGNATURE;
                    return new NativeUse(decision,start,end,List.of(o.originalRef(m,name)));
                }
            };
        }
        private JsonNode state(Originals o,JsonNode m,String name)throws Exception{var n=o.original(m,name,"native-slo-registered-peers");require(name.equals(text(n,"phase"))&&at(n,"nativeFinishedAt").isAfter(at(n,"nativeStartedAt"))&&at(n,"recordedAt").isAfter(at(n,"nativeFinishedAt")));return n;}
        private JsonNode readback(Originals o,JsonNode m,JsonNode n)throws Exception{var b=o.file(m,text(n,"nativeReadbackFile"));require(hash(b).equals(text(n,"nativeReadbackSha256")));var read=json(b);require(read.isObject()&&!sensitive(read));return read;}
        private JsonNode runtime(JsonNode n){var r=n.path("runtime");require(r.isObject()&&r.path("running").isBoolean()&&r.path("running").asBoolean()&&text(r,"id").matches("[0-9a-f]{64}")
                &&text(r,"image").matches("sha256:[0-9a-f]{64}")&&!text(r,"startedAt").isBlank()&&r.path("mounts").isArray());requireRuntimeBindings(n,image());return r;}
        void publicKeys(Originals o,JsonNode m,JsonNode actual,JsonNode peer)throws Exception {
            require(actual.path("present").isBoolean()&&actual.path("present").asBoolean()&&text(peer,"entity").equals(text(actual,"entity")));
            var certs=actual.path("signingCertificates");require(certs.isArray()&&!certs.isEmpty());var hashes=new HashSet<String>();for(var c:certs){require(c.isTextual());var cert=CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(Base64.getDecoder().decode(c.asText())));require(hashes.add(hash(cert.getEncoded())));}
            var fixture=SecureXml.parse(o.file(m,text(peer,"label")+"/fixture.xml")).getDocumentElement();require(hashes.equals(hashes(signingKeys(fixture))));
        }
        void pins(Originals o,JsonNode m,JsonNode state,Map<String,String> required)throws Exception{for(var p:required.entrySet()){require(p.getValue().equals(text(state.path("sourceHashes"),p.getKey()))&&p.getValue().equals(hash(o.file(m,"native-source/"+p.getKey()))));}}
    }
    private static final String REALM_IMPORT_SHA="fb68fa3129b14ee3c57c41d1f0473984ec4c2acf4cecaaaab683661192d45113";
    private static final Map<String,Boolean> SSP_BINDS=Map.of(
            "/var/simplesamlphp/cert/server.pem",false,"/var/simplesamlphp/config/authsources.php",false,
            "/var/simplesamlphp/config/config-override.php",false,"/var/simplesamlphp/metadata/saml20-idp-hosted.php",false,
            "/var/simplesamlphp/metadata/saml20-sp-remote.php",true,"/etc/apache2/sites-enabled/000-default.conf",false,
            "/var/simplesamlphp/cert/server.crt",false);
    /** Only the existing reference data mounts, bound to host/native bytes; executable/source overrides remain excluded. */
    static void requireRuntimeBindings(JsonNode state,String image){
        var mounts=state.path("runtime").path("mounts");require(mounts.isArray());if(mounts.isEmpty()){require(!state.has("mountedFileHashes")||state.path("mountedFileHashes").isEmpty());return;}
        boolean kc="sha256:9d1f1b2b7261ff53c66cb1092dfcdc34a5fb77e81f9e6a6e75b8b6a795de8067".equals(image);
        boolean ssp="sha256:9ae050473c68ce13c5451839cb64257eaa17be3a4d2c9a3f87996bbe0cebb0aa".equals(image);require(kc||ssp);
        var expected=kc?Map.of("/opt/keycloak/data/import/realm-samlscope.json",false):SSP_BINDS;var observed=new HashSet<String>();var hashes=state.path("mountedFileHashes");require(hashes.isObject()&&hashes.size()==expected.size()&&mounts.size()==expected.size());
        for(var mount:mounts){String destination=text(mount,"Destination");require(observed.add(destination)&&expected.containsKey(destination)&&"bind".equals(text(mount,"Type"))
                &&mount.path("RW").isBoolean()&&mount.path("RW").asBoolean()==expected.get(destination)&&mount.path("Source").isTextual()&&!mount.path("Source").asText().isBlank()
                &&"rprivate".equals(text(mount,"Propagation"))&&mount.path("Mode").isTextual()&&(expected.get(destination)?Set.of("","rw").contains(mount.path("Mode").asText()):"ro".equals(mount.path("Mode").asText())));
            var hash=hashes.path(destination);require(hash.isObject()&&text(hash,"source").equals(text(mount,"Source"))&&text(hash,"hostSha256").matches("[0-9a-f]{64}")&&text(hash,"hostSha256").equals(text(hash,"nativeSha256")));
            if(kc)require(REALM_IMPORT_SHA.equals(text(hash,"nativeSha256"))&&text(mount,"Source").endsWith("/dev/keycloak/realm-samlscope.json"));
            else require(text(mount,"Source").contains("/ssp-config/")&&text(mount,"Source").endsWith("/"+(destination.endsWith("000-default.conf")?"http-reference.conf":destination.substring(destination.lastIndexOf('/')+1))));
        }
    }
    private static void requireReadonlyBindingsUnchanged(JsonNode before,JsonNode after){requireReadonlyBindingsUnchanged(before,after,Set.of());}
    private static void requireReadonlyBindingsUnchanged(JsonNode before,JsonNode after,Set<String> configured){
        require(before.path("runtime").path("mounts").equals(after.path("runtime").path("mounts")));
        for(var mount:before.path("runtime").path("mounts"))if(!mount.path("RW").asBoolean()){
            String destination=text(mount,"Destination");if(!configured.contains(destination))require(before.path("mountedFileHashes").path(destination).equals(after.path("mountedFileHashes").path(destination)));
        }
    }
    static final String SSP_HOSTED_PATH="/var/simplesamlphp/metadata/saml20-idp-hosted.php";
    static final String SSP_HOSTED_ORIGINAL_SHA="559eeba5e28f145f0b0bd9ee8c1c147b155babe73d7c19809affdd2147ce8e49";
    static byte[] sspPostBindingOverlay(String entity){
        require("http://localhost:18380/idp".equals(entity));
        return ("\n$metadata[\""+entity+"\"][\"SingleLogoutServiceBinding\"] = [\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\",\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\"];\n").getBytes(StandardCharsets.UTF_8);
    }
    static void requireSspPostBindingChange(byte[] original,byte[] configured,String entity,JsonNode initial,JsonNode before)throws Exception{
        require(hash(original).equals(SSP_HOSTED_ORIGINAL_SHA));var overlay=sspPostBindingOverlay(entity);
        var expected=Arrays.copyOf(original,original.length+overlay.length);System.arraycopy(overlay,0,expected,original.length,overlay.length);require(Arrays.equals(expected,configured));
        for(var pair:List.of(Map.entry(initial,original),Map.entry(before,configured))){
            var state=pair.getKey();String digest=hash(pair.getValue());require(digest.equals(text(state.path("configurationFiles"),"saml20-idp-hosted.php"))
                    &&digest.equals(text(state.path("mountedFileHashes").path(SSP_HOSTED_PATH),"nativeSha256"))
                    &&digest.equals(text(state.path("mountedFileHashes").path(SSP_HOSTED_PATH),"hostSha256")));
        }
        require(before.at("/hostedIdp/singleLogoutServiceBindings").equals(json("[\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\",\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\"]".getBytes(StandardCharsets.UTF_8))));
    }
    private static final class KeycloakSloRegisteredSignerAdapter extends NativeAdapter {
        @Override public String adapter(){return "keycloak-native-slo-issuer-key-v1";}
        @Override String image(){return "sha256:9d1f1b2b7261ff53c66cb1092dfcdc34a5fb77e81f9e6a6e75b8b6a795de8067";}
        @Override void source(Originals o,JsonNode m,JsonNode before,JsonNode after)throws Exception {
            require(KeycloakSelfContainedTrustEvidenceFile.SERVICES_HASH.equals(hash(o.file(m,"native-source/keycloak-services.jar"))));
            require("org.keycloak.protocol.saml.SamlService$PostBindingProtocol".equals(text(before.path("operativeConsumer"),"class"))
                    &&"executeRequest".equals(text(before.path("operativeConsumer"),"method"))&&"LogoutRequestType".equals(text(before.path("operativeConsumer"),"messageClass")));
            for(var s:List.of(before,after)){require(s.path("policies").isObject()&&s.at("/policies/policies/policies").isArray()&&s.at("/policies/policies/policies").isEmpty()
                    &&s.at("/policies/profiles/profiles").isArray()&&s.at("/policies/profiles/profiles").isEmpty());}
        }
        @Override void peer(Originals o,JsonNode m,JsonNode n,JsonNode p)throws Exception{
            publicKeys(o,m,n,p);var client=o.node(m,text(n,"nativeMetadataFile"));require("saml".equals(text(client,"protocol"))&&text(p,"entity").equals(text(client,"clientId"))
                    &&client.path("enabled").isBoolean()&&client.path("enabled").asBoolean()&&"true".equals(text(client.path("attributes"),"saml.client.signature")));
            var key=CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(Base64.getMimeDecoder().decode(text(client.path("attributes"),"saml.signing.certificate"))));
            var certs=n.path("signingCertificates");require(certs.size()==1&&hash(key.getEncoded()).equals(hash(Base64.getDecoder().decode(certs.get(0).asText()))));
        }
        @Override boolean rejected(Originals o,JsonNode m,JsonNode row,JsonNode n,Element q,byte[] body){return n.path("responseStatus").asInt(-1)==400&&text(n,"requestUrl").equals(text(n,"responseUrl"))&&KeycloakRegisteredSignerEvidence.nativeSignatureRejectionPage(body);}
    }
    private static final class SimpleSamlPhpSloRegisteredSignerAdapter extends NativeAdapter {
        @Override public String adapter(){return "simplesamlphp-native-slo-issuer-key-v1";}
        @Override String image(){return "sha256:9ae050473c68ce13c5451839cb64257eaa17be3a4d2c9a3f87996bbe0cebb0aa";}
        private static final Map<String,String> SOURCE=Map.of(
            "native-idp.php","ae55fc922431d29ca6e87654ae2071500a4c3d7185ed80a6fcc5b26eed12495d",
            "native-message.php","ab017ee6cf9fb66db1037e40ed50feff0b277b1a5d43fd8ca774a3d27ce355d2",
            "native-configuration.php","53837359cd60433082d3968843605a864bab97f23be482447bcfef37e7f6946e",
            "native-handler.php","43a0e730d624c5a937f800c4e7e045ff3625eeb0738d81a4ab1dac96f82fe040",
            "native-source.php","48fe4682d980e62416c751b7a39406ebf9664bf539e6a1557e7f54df770398c6",
            "native-signed-helper.php","4928545a8147e4222288def64a992ed8fbf0ba54243079fc3c919470b2cc766c",
            "native-metadata-controller.php","e048fb572f43168187c178e0927f9e6c885031197b8a9c8682539963dde8ec56",
            "native-saml-builder.php","b6c295c053a6b8c178899d3e35c1cf8c9752cd0442e4a45861559c7aa2107591");
        private static final Map<String,String> CLASSES=Map.of("native-idp.php","SimpleSAML\\Module\\saml\\IdP\\SAML2","native-message.php","SimpleSAML\\Module\\saml\\Message","native-configuration.php","SimpleSAML\\Configuration","native-handler.php","SimpleSAML\\Metadata\\MetaDataStorageHandler","native-source.php","SimpleSAML\\Metadata\\MetaDataStorageSource","native-signed-helper.php","SAML2\\SignedElementHelper","native-metadata-controller.php","SimpleSAML\\Module\\saml\\Controller\\Metadata","native-saml-builder.php","SimpleSAML\\Metadata\\SAMLBuilder");
        @Override Set<String> configuredReadonlyFiles(Originals o,JsonNode m,JsonNode initial,JsonNode before)throws Exception{
            if(initial.path("mountedFileHashes").path(SSP_HOSTED_PATH).equals(before.path("mountedFileHashes").path(SSP_HOSTED_PATH)))return Set.of();
            requireSspPostBindingChange(o.file(m,"original-configuration/saml20-idp-hosted.php"),o.file(m,"configured-configuration/saml20-idp-hosted.php"),text(m,"targetEntityId"),initial,before);
            return Set.of(SSP_HOSTED_PATH);
        }
        @Override void source(Originals o,JsonNode m,JsonNode before,JsonNode after)throws Exception {
            require(before.path("selectedClasses").equals(after.path("selectedClasses"))&&before.path("selectedClasses").size()==CLASSES.size());
            for(var c:CLASSES.entrySet()){var actual=before.path("selectedClasses").path(c.getKey());require(c.getValue().equals(text(actual,"class"))&&SOURCE.get(c.getKey()).equals(text(actual,"sha256"))&&text(actual,"sourceFile").startsWith("/var/simplesamlphp/")&&text(actual,"sourceFile").endsWith(c.getValue().substring(c.getValue().lastIndexOf('\\')+1)+".php"));}
            for(var s:List.of(before,after)){pins(o,m,s,SOURCE);require("SimpleSAML\\Module\\saml\\IdP\\SAML2".equals(text(s.path("operativeConsumer"),"class"))
                    &&"receiveLogoutMessage".equals(text(s.path("operativeConsumer"),"method"))&&s.at("/hostedIdp/authproc").isArray()&&s.at("/hostedIdp/authproc").isEmpty());}
            String source=new String(o.file(m,"native-source/native-idp.php"),StandardCharsets.UTF_8);require(source.contains("$spMetadata = $metadata->getMetaDataConfig($spEntityId, 'saml20-sp-remote');")&&source.contains("Message::validateMessage($spMetadata, $idpMetadata, $message);"));
            require(source.contains("$slob = $handler->getGenerated('SingleLogoutServiceBinding'")
                    &&new String(o.file(m,"native-source/native-metadata-controller.php"),StandardCharsets.UTF_8).contains("SAML2_IdP::getHostedMetadata($idpentityid, $this->mdHandler)")
                    &&new String(o.file(m,"native-source/native-saml-builder.php"),StandardCharsets.UTF_8).contains("$e->setSingleLogoutService(self::createEndpoints($metadata->getEndpoints('SingleLogoutService'), false))"));
        }
        @Override void peer(Originals o,JsonNode m,JsonNode n,JsonNode p)throws Exception {
            publicKeys(o,m,n,p);var resolved=o.node(m,text(n,"nativeMetadataFile"));require(text(p,"entity").equals(text(resolved,"metadata-index"))
                    &&resolved.path("validate.logout").isBoolean()&&resolved.path("validate.logout").asBoolean());
            var nativeKeys=resolved.path("keys");require(nativeKeys.isArray());var actual=new HashSet<String>();for(var key:nativeKeys)if(key.path("signing").asBoolean(false)){
                require("X509Certificate".equals(text(key,"type")));var cert=CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(Base64.getMimeDecoder().decode(text(key,"X509Certificate"))));actual.add(hash(cert.getEncoded()));}
            var fixture=SecureXml.parse(o.file(m,text(p,"label")+"/fixture.xml")).getDocumentElement();require(actual.equals(hashes(signingKeys(fixture))));
        }
        @Override boolean rejected(Originals o,JsonNode m,JsonNode row,JsonNode n,Element q,byte[] body)throws Exception {
            if(n.path("responseStatus").asInt(-1)!=500||!text(n,"requestUrl").equals(text(n,"responseUrl")))return false;
            return simpleSamlPhpSignatureRejection(body,issuer(q));
        }
    }
    private static final class ShibbolethSloRegisteredSignerAdapter extends NativeAdapter {
        @Override public String adapter(){return "shibboleth-native-slo-issuer-key-v1";}
        @Override String image(){return "sha256:3c1b1fa64c58258aefc9e38d4ae60e9f0340731318a472110ea56ce88c18a11a";}
        private static final Map<String,String> SOURCE=Map.of(
            "idp-conf-impl.jar","428e389d88bb2abcad19d69bcf759af29f7ce6beb776ccfaa5a6ea76751682ba",
            "idp-saml-impl.jar","1a2a9f867d11c50eeaf2a6140bb5de88b0611d694ea6de2bbfe32f72a4a2998b",
            "opensaml-saml-impl.jar","9f04221e172dc426f90fb3873d0148a0744edbf9e7a37de7ee0e6a34f7b74581",
            "opensaml-xmlsec-impl.jar","cc67fc1bd9cb435cdbe7483ef04513c83cc9619a3015c04ad41bb6cc0eb6e68e",
            "opensaml-saml-api.jar","cce72578ec8df5dd18cb71c88bba89bd196c640281c199ce875e2aa44154f93f",
            "slo-front-abstract-flow.xml","a1031dd5881ebeac3107d9bbe0449811ccb7eca8a74b6536cd47df39e01afdaa",
            "saml-abstract-flow.xml","5dfcd6d610c665179c28bff5381ac3a823e933ce7c1a62bcb66d37312b3fa90e",
            "slo-front-abstract-beans.xml","eaa846982cc5fd7a9f491ae1cb8ba253e1ec4d219de5bf1c3d738977040f06a1",
            "mdquery-view.vm","39be6bbb7be66c48b7649e2d8f8ce9864e741b74b6aae98aeeb2fea5b8c85298",
            "mdquery-flow.xml","564ea63cd533d8d6dd52a4db3bb5c28a478133236879057064d97035c70f5c4e");
        private static final Map<String,String> CONFIGS=Map.of(
            "global","ca08485a1b5ef8cf0ac1afb80ff066237759e4fb3d884d087f905d8ca0918bcc",
            "services","0c5de788ebc611af60ebb3bf4071dcd23744f599d64d65bdb0744515d11a77c0",
            "relying-party","64e2a04dfbf2ffa2a582b995bcbf121b634ab7c8766cb8f22d3397d541f31bd5");
        @Override void source(Originals o,JsonNode m,JsonNode before,JsonNode after)throws Exception{
            for(var s:List.of(before,after)){pins(o,m,s,SOURCE);var consumer=s.path("operativeConsumer");require("http://shibboleth.net/ns/profiles/saml2/logout".equals(text(consumer,"profileId"))
                    &&"shibboleth.ExplicitKeySignatureTrustEngine".equals(text(consumer,"signatureTrustEngine"))&&"shibboleth.MetadataCredentialResolver".equals(text(consumer,"credentialResolver")));
                var profile=o.node(m,text(consumer,"effectiveProfileFile"));require(text(consumer,"profileId").equals(text(profile.path("ProfileConfiguration"),"id"))
                        &&profile.at("/ProfileConfiguration/ignoreRequestSignatures").isBoolean()&&!profile.at("/ProfileConfiguration/ignoreRequestSignatures").asBoolean()
                        &&"shibboleth.DefaultSecurityConfiguration".equals(text(profile.path("RelyingPartyConfiguration"),"securityConfiguration")));
                require(o.node(m,text(consumer,"overrideSourceInventoryFile")).isArray()&&o.node(m,text(consumer,"overrideSourceInventoryFile")).isEmpty());
            }
            for(String phase:List.of("initial","probes-before","probes-after","restoration")) {
                if(!m.path("originals").has(phase)) { require("restoration".equals(phase)||"probes-after".equals(phase));continue; }
                var state=o.original(m,phase,"native-slo-registered-peers");byte[] bytes=o.file(m,text(state,"nativeReadbackFile"));
                require(hash(bytes).equals(text(state,"nativeReadbackSha256")));var data=json(bytes);
                var inventory=o.file(m,text(data,"flowViewOverrideInventoryFile"));require(hash(inventory).equals(text(data,"flowViewOverrideInventorySha256")));requireShibFlowViewInventory(inventory);
                var queries=data.path("metadataQueries");require(queries.isArray()&&queries.size()==2);
                for(int i=0;i<2;i++) {
                    var peer=m.path("peers").get(i);var query=o.node(m,queries.get(i).asText());
                    byte[] stdout=o.file(m,text(query,"stdoutFile")),body=o.file(m,text(query,"responseBodyFile"));
                    boolean present="probes-before".equals(phase)||"probes-after".equals(phase);
                    requireShibMetadataQuery(query,stdout,body,text(peer,"entity"),present,at(state,"nativeStartedAt"),at(state,"nativeFinishedAt"));
                    if(present)require(Arrays.equals(body,o.file(m,text(data.path("peers").get(i),"nativeMetadataFile"))));
                }
            }
            for(var peer:m.path("peers")) {
                String label=text(peer,"label"),entity=text(peer,"entity");
                for(String phase:List.of("probes-before","probes-after")) {
                    if(!m.path("originals").has(phase))continue;
                    var state=o.original(m,phase,"native-slo-registered-peers");String prefix="native-source/trust-"+phase+"-"+label+"-";
                    var observed=o.node(m,prefix+"observed.json");var nativeJars=observed.path("nativeJars");require(nativeJars.isObject()&&nativeJars.size()==4);
                    for(var pin:SOURCE.entrySet())if(pin.getKey().endsWith(".jar")&&!pin.getKey().equals("opensaml-saml-api.jar"))
                        require(pin.getValue().equals(text(nativeJars,pin.getKey().replace(".jar",""))));
                    for(var pin:CONFIGS.entrySet())require(pin.getValue().equals(hash(o.file(m,prefix+pin.getKey()+".xml"))));
                    var classpath=o.node(m,prefix+"classpath-sha256.json");
                    require("1fcd492d07b1ca59600b763c0cddc3be85dc223841a2298bf3719274b66c4cb3".equals(hash(o.file(m,prefix+"classpath-sha256.json")))
                            &&SOURCE.get("opensaml-saml-api.jar").equals(text(classpath,"/usr/local/tomcat/webapps/idp/WEB-INF/lib/opensaml-saml-api-5.2.3.jar")));
                    requireShibTrustScope(observed,o.node(m,prefix+"native-effective-profile.json"),o.node(m,prefix+"selected-properties.json"),
                            o.node(m,prefix+"process-overrides.json"),o.node(m,prefix+"override-source-inventory.json"),entity,at(state,"nativeStartedAt"),at(state,"nativeFinishedAt"));
                    for(String inventory:List.of("properties-sha256.json","xml-sha256.json")) {
                        var values=o.node(m,prefix+inventory);require(values.isObject()&&!values.isEmpty());
                        for(var fields=values.fields();fields.hasNext();)require(fields.next().getValue().asText().matches("[0-9a-f]{64}"));
                    }
                }
                if(m.path("originals").has("probes-after"))for(String suffix:List.of("classpath-sha256.json","override-source-inventory.json","selected-properties.json",
                        "properties-sha256.json","xml-sha256.json","native-effective-profile.json","process-overrides.json"))
                    require(Arrays.equals(o.file(m,"native-source/trust-probes-before-"+label+"-"+suffix),o.file(m,"native-source/trust-probes-after-"+label+"-"+suffix)));
            }
            var conf=o.file(m,"native-source/idp-conf-impl.jar");String rp=new String(zip(conf,"net/shibboleth/idp/conf/relying-party-system.xml"),StandardCharsets.UTF_8);
            String security=new String(zip(conf,"net/shibboleth/idp/conf/security-system.xml"),StandardCharsets.UTF_8);
            require(rp.contains("org.opensaml.xmlsec.signature.support.impl.ExplicitKeySignatureTrustEngine")&&rp.contains("shibboleth.MetadataCredentialResolver")&&security.contains("org.opensaml.saml.security.impl.MetadataCredentialResolver")&&security.contains("shibboleth.RoleDescriptorResolver"));
        }
        @Override void peer(Originals o,JsonNode m,JsonNode n,JsonNode p)throws Exception{publicKeys(o,m,n,p);var root=SecureXml.parse(o.file(m,text(n,"nativeMetadataFile"))).getDocumentElement();require(text(p,"entity").equals(root.getAttribute("entityID"))&&hashes(signingKeys(root)).equals(hashes(signingKeys(SecureXml.parse(o.file(m,text(p,"label")+"/fixture.xml")).getDocumentElement()))));}
        @Override boolean rejected(Originals o,JsonNode m,JsonNode row,JsonNode n,Element q,byte[] body)throws Exception{
            if(n.path("responseStatus").asInt(-1)!=400||!ShibbolethRegisteredSignerEvidence.nativeSignatureRejectionPage(body))return false;
            return shibSignatureRejectionAudit(o.file(m,text(n,"nativeAuditFile")),q.getAttribute("ID"),issuer(q),at(n,"nativeClockBefore"),at(n,"nativeClockAfter"));
        }
    }
    /** Fixed audit format: %e is the event, %S the protocol status, and %XX a boolean XML-signature flag. */
    static boolean shibSignatureRejectionAudit(byte[] audit,String requestId,String requestIssuer,Instant begin,Instant end)throws Exception {
        String[] found=null;
        for(var line:new String(audit,StandardCharsets.UTF_8).lines().filter(s->!s.isBlank()).toList()){
            var fields=line.split("\\|",-1);require(fields.length==9&&"SAMLscope-signature-v1".equals(fields[0]));if(!requestId.equals(fields[1]))continue;
            require(found==null&&requestIssuer.equals(fields[2])&&"MessageAuthenticationError".equals(fields[3])&&fields[4].isEmpty()
                    &&Set.of("true","false").contains(fields[5])&&"POST".equals(fields[6])
                    &&"http://shibboleth.net/ns/profiles/saml2/logout".equals(fields[7])&&!Instant.parse(fields[8]).isBefore(begin)&&!Instant.parse(fields[8]).isAfter(end));found=fields;
        }
        return found!=null;
    }
    /** The stock MetadataQuery view emits exact 404/Not Found only for an absent entity. Transport errors are unqualified. */
    static void requireShibMetadataQuery(JsonNode query,byte[] stdout,byte[] body,String entity,boolean present,Instant begin,Instant end)throws Exception {
        String url="http://localhost:8080/idp/profile/admin/mdquery?entityID="+java.net.URLEncoder.encode(entity,StandardCharsets.UTF_8).replace("+","%20");
        var command=query.path("command");require(command.isArray()&&command.size()==8);
        var expected=List.of("curl","--silent","--show-error","--max-time","20","--write-out","\n%{http_code}",url);
        for(int i=0;i<expected.size();i++)require(expected.get(i).equals(command.get(i).asText()));
        require(entity.equals(text(query,"entity"))&&url.equals(text(query,"url"))&&"GET".equals(text(query,"method"))&&query.path("exitCode").isInt()&&query.path("exitCode").asInt()==0
                &&query.path("responseStatus").isInt()&&query.path("responseStatus").asInt()==(present?200:404)
                &&query.path("responseBodyBytes").asInt(-1)==body.length&&hash(body).equals(text(query,"responseBodySha256"))&&hash(stdout).equals(text(query,"stdoutSha256"))
                &&!at(query,"startedAt").isBefore(begin)&&at(query,"finishedAt").isAfter(at(query,"startedAt"))&&!at(query,"finishedAt").isAfter(end));
        byte[] suffix=("\n"+(present?"200":"404")).getBytes(StandardCharsets.UTF_8);var expectedBytes=Arrays.copyOf(body,body.length+suffix.length);
        System.arraycopy(suffix,0,expectedBytes,body.length,suffix.length);require(Arrays.equals(stdout,expectedBytes));
        if(present) {var root=SecureXml.parse(body).getDocumentElement();require("urn:oasis:names:tc:SAML:2.0:metadata".equals(root.getNamespaceURI())&&"EntityDescriptor".equals(root.getLocalName())&&entity.equals(root.getAttribute("entityID")));}
        else require("Not Found".equals(new String(body,StandardCharsets.UTF_8).strip()));
    }
    /** Source selection must be read from the running SLO profile and selected properties/process facts, for each peer. */
    static void requireShibFlowViewInventory(byte[] bytes) {
        require(bytes.length<=1024*1024);
        for(String path:new String(bytes,StandardCharsets.UTF_8).lines().toList())require(path.startsWith("/opt/reference-idp/")
                &&!path.endsWith("/admin/mdquery.vm")&&!path.contains("/flows/admin/mdquery")&&!path.endsWith(".jar")&&!path.endsWith(".class")
                &&!path.endsWith("/slo-front-abstract-flow.xml")&&!path.endsWith("/slo-front-abstract-beans.xml")&&!path.endsWith("/saml-abstract-flow.xml"));
    }
    /** Source selection must be read from the running SLO profile and selected properties/process facts, for each peer. */
    static void requireShibTrustScope(JsonNode observed,JsonNode profile,JsonNode properties,JsonNode flags,JsonNode overrides,String entity,Instant begin,Instant end) {
        String id="http://shibboleth.net/ns/profiles/saml2/logout",engine="shibboleth.ExplicitKeySignatureTrustEngine";
        require(entity.equals(text(observed,"entityId"))&&id.equals(text(observed,"profileId"))&&observed.path("privateFieldsExported").isBoolean()&&!observed.path("privateFieldsExported").asBoolean()
                &&!at(observed,"recordedAt").isBefore(begin)&&!at(observed,"recordedAt").isAfter(end));
        require(id.equals(text(profile.path("ProfileConfiguration"),"id"))&&profile.at("/ProfileConfiguration/ignoreRequestSignatures").isBoolean()&&!profile.at("/ProfileConfiguration/ignoreRequestSignatures").asBoolean()
                &&"shibboleth.DefaultSecurityConfiguration".equals(text(profile.path("RelyingPartyConfiguration"),"securityConfiguration")));
        require(properties.isObject()&&engine.equals(text(properties,"idp.trust.signatures"))&&overrides.isArray()&&overrides.isEmpty());
        for(var fields=properties.fields();fields.hasNext();) {var row=fields.next();require(row.getValue().isTextual()&&((row.getKey().equals("idp.trust.signatures")&&row.getValue().asText().equals(engine))
                ||(row.getKey().equals("idp.security.config")&&row.getValue().asText().equals("shibboleth.DefaultSecurityConfiguration"))
                ||(row.getKey().equals("idp.additionalProperties")&&row.getValue().asText().equals("/credentials/secrets.properties"))));}
        require(flags.path("nativeJavaProcessObserved").isBoolean()&&flags.path("nativeJavaProcessObserved").asBoolean());
        for(String name:List.of("trustOverridePresent","customAgentPresent","privateFieldsExported"))require(flags.path(name).isBoolean()&&!flags.path(name).asBoolean());
    }
    private static final String LANGUAGE_NAVIGATION="<form\\s+id=\"language-form\"\\s+class=\"pure-form\"\\s+method=\"get\"\\s*>\\s*"
            +"<div\\s+id=\"languageform\"\\s*>\\s*<select\\s+aria-label=\"Language\"\\s+class=\"pure-input-1-4 language-menu\"\\s+name=\"language\"\\s+id=\"language-selector\"\\s*>\\s*"
            +"(?:<option\\s+value=\"[A-Za-z][A-Za-z0-9_-]{0,15}\"(?:\\s+selected=\"selected\")?\\s*>[^<>]*</option>\\s*)+"
            +"</select>\\s*<noscript>\\s*<button\\s+type=\"submit\"\\s+class=\"pure-button\"\\s*>\\s*<i\\s+class=\"fa fa-arrow-right\"\\s*></i>\\s*</button>\\s*</noscript>\\s*</div>\\s*</form>";
    /** Inspect the exact stock public language widget; never rewrite the recorded native bytes. */
    static String withoutPublicLanguageNavigation(String page) {
        var forms=Pattern.compile("(?is)<form\\b[^>]*>.*?</form\\s*>").matcher(page);String selected=null;int count=0;
        while(forms.find())if(Pattern.compile("(?i)<form\\s+id=\"language-form\"(?:\\s|>)").matcher(forms.group()).find()) {
            require(++count==1&&Pattern.compile(LANGUAGE_NAVIGATION,Pattern.CASE_INSENSITIVE|Pattern.DOTALL).matcher(forms.group()).matches());selected=forms.group();
        }
        return selected==null?page:page.replace(selected,"");
    }
    static boolean simpleSamlPhpSignatureRejection(byte[] body,String entity){
        try{String page=withoutPublicLanguageNavigation(new String(body,StandardCharsets.UTF_8));if(body.length==0||body.length>262144||Pattern.compile("(?i)<\\s*(?:form|input|textarea|select)\\b|SAMLResponse|SAMLRequest|session_code|tab_id|client_data|csrf|kc_action|auth_session_id|Authorization\\s*:|Cookie\\s*:").matcher(page).find())return false;
            String visible=page.replaceAll("(?is)<(?:script|style)\\b[^>]*>.*?</(?:script|style)\\s*>","").replaceAll("(?s)<[^>]+>","\n").replace("&quot;","\"").replace("&#34;","\"").replace("&amp;","&");
            var matcher=Pattern.compile("SimpleSAML\\\\+Error\\\\+Error:\\s*(\\{[^\\r\\n]*\\})").matcher(visible);int count=0;while(matcher.find()){var value=json(matcher.group(1).getBytes(StandardCharsets.UTF_8));
                if("NOTVALIDCERTSIGNATURE".equals(value.path("errorCode").asText())&&Pattern.matches("SAML2\\\\+(?:XML\\\\+samlp\\\\+)?LogoutRequest",value.path("%ELEMENT%").asText())&&entity.equals(value.path("%ISSUER%").asText())&&entity.equals(value.path("%ENTITYID%").asText()))count++;}return count==1;
        }catch(Exception unproven){return false;}
    }
    /** The identity must come from the product's public hosted-metadata readback, not a copied manifest label. */
    static void requireHostedTarget(JsonNode nativeReadback,String targetEntityId,byte[] hostedMetadata)throws Exception {
        var root=SecureXml.parse(hostedMetadata).getDocumentElement();
        require("urn:oasis:names:tc:SAML:2.0:metadata".equals(root.getNamespaceURI())&&"EntityDescriptor".equals(root.getLocalName())
                &&targetEntityId.equals(root.getAttribute("entityID"))&&targetEntityId.equals(text(nativeReadback,"hostedEntityId")));
    }
    /** Decode the actual native form/Location. A declared endpoint or hash cannot replace these bytes. */
    static void requireNativeResponseBinding(JsonNode n,byte[] body,byte[] location,byte[] response,String receivedUrl,String rawQuery,String method)throws Exception {
        require(body.length<=1024*1024&&response.length<=1024*1024);
        URI base=URI.create(text(n,"responseUrl"));require(base.isAbsolute()&&base.getFragment()==null);
        URI destination;
        if(n.path("responseStatus").asInt(-1)==200){
            require("POST".equals(method)&&location==null);
            record Form(String method,String action,List<String> responses,boolean bad) { }
            var forms=new ArrayList<Form>();
            var callback=new javax.swing.text.html.HTMLEditorKit.ParserCallback(){
                String currentMethod,currentAction;List<String> values;boolean bad,nested,baseTag;
                @Override public void handleStartTag(javax.swing.text.html.HTML.Tag tag,javax.swing.text.MutableAttributeSet attrs,int position){
                    if(tag==javax.swing.text.html.HTML.Tag.FORM){if(values!=null){nested=true;return;}currentMethod=Objects.toString(attrs.getAttribute(javax.swing.text.html.HTML.Attribute.METHOD),"");currentAction=Objects.toString(attrs.getAttribute(javax.swing.text.html.HTML.Attribute.ACTION),"");values=new ArrayList<>();bad=false;}
                }
                @Override public void handleSimpleTag(javax.swing.text.html.HTML.Tag tag,javax.swing.text.MutableAttributeSet attrs,int position){
                    if(tag==javax.swing.text.html.HTML.Tag.BASE)baseTag=true;
                    if(tag==javax.swing.text.html.HTML.Tag.INPUT&&values!=null){String name=Objects.toString(attrs.getAttribute(javax.swing.text.html.HTML.Attribute.NAME),"");if("SAMLResponse".equals(name))values.add(Objects.toString(attrs.getAttribute(javax.swing.text.html.HTML.Attribute.VALUE),""));else if("SAMLRequest".equals(name))bad=true;}
                }
                @Override public void handleEndTag(javax.swing.text.html.HTML.Tag tag,int position){if(tag==javax.swing.text.html.HTML.Tag.FORM&&values!=null){forms.add(new Form(currentMethod,currentAction,List.copyOf(values),bad||nested||baseTag));values=null;}}
                @Override public void flush(){require(values==null&&!nested&&!baseTag);}
            };
            var utf8=StandardCharsets.UTF_8.newDecoder().decode(java.nio.ByteBuffer.wrap(body)).toString();
            new javax.swing.text.html.parser.ParserDelegator().parse(new java.io.StringReader(utf8),callback,true);callback.flush();
            require(forms.size()==1);var form=forms.getFirst();require(!form.bad&&"POST".equalsIgnoreCase(form.method)&&!form.action.isBlank()&&form.responses.size()==1
                    &&Arrays.equals(Base64.getDecoder().decode(form.responses.getFirst()),response));
            destination=base.resolve(form.action);
        }else{
            require(Set.of(301,302,303).contains(n.path("responseStatus").asInt(-1))&&"GET".equals(method)&&location!=null&&location.length<=1024*1024);
            var locationText=StandardCharsets.UTF_8.newDecoder().decode(java.nio.ByteBuffer.wrap(location)).toString();require(!locationText.isBlank()&&!locationText.contains("\r")&&!locationText.contains("\n"));
            URI redirect=base.resolve(locationText);require(redirect.getRawQuery()!=null&&redirect.getRawQuery().equals(rawQuery));
            var values=new ArrayList<String>();for(var field:redirect.getRawQuery().split("&",-1)){int eq=field.indexOf('=');require(eq>0);String name=URLDecoder.decode(field.substring(0,eq),StandardCharsets.UTF_8);
                require(!"SAMLRequest".equals(name));if("SAMLResponse".equals(name))values.add(URLDecoder.decode(field.substring(eq+1),StandardCharsets.UTF_8));}
            require(values.size()==1);var compressed=Base64.getDecoder().decode(values.getFirst());var inflater=new java.util.zip.Inflater(true);
            try(var stream=new java.util.zip.InflaterInputStream(new ByteArrayInputStream(compressed),inflater)){var decoded=stream.readNBytes(1024*1024+1);require(inflater.finished()&&Arrays.equals(decoded,response));}finally{inflater.end();}
            require(redirect.getFragment()==null);destination=URI.create(responseEndpoint(redirect.toString(),redirect.getRawQuery(),"GET",text(n,"responseSamlEndpoint")));
        }
        require(destination.isAbsolute()&&destination.getFragment()==null&&destination.toString().equals(responseEndpoint(receivedUrl,rawQuery,method,text(n,"responseSamlEndpoint")))
                &&destination.toString().equals(text(n,"responseSamlEndpoint")));
    }
    private static boolean sensitive(JsonNode n){if(n.isObject()){var it=n.fields();while(it.hasNext()){var f=it.next();if(f.getKey().matches("(?i).*(password|private.?key|authorization|cookie|secret|token).*"))return true;if(sensitive(f.getValue()))return true;}}else if(n.isArray())for(var v:n)if(sensitive(v))return true;return false;}
    private static byte[] zip(byte[] jar,String name)throws Exception{try(var zip=new ZipInputStream(new ByteArrayInputStream(jar))){java.util.zip.ZipEntry e;while((e=zip.getNextEntry())!=null)if(name.equals(e.getName()))return zip.readAllBytes();}throw new IllegalArgumentException("Native source entry missing");}
    private SloRegisteredSignerNativeAdapters() { }
}
