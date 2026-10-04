package com.samlscope.runner.cases;

import static com.samlscope.runner.cases.MetadataPublisherKeyInventoryEvidence.*;
import static com.samlscope.runner.cases.MetadataAlgorithmEvidence.children;
import com.fasterxml.jackson.databind.JsonNode;
import com.samlscope.saml.normal.SecureXml;
import com.samlscope.saml.crypto.VerifiedSignatureAlgorithms;
import com.samlscope.saml.binding.RedirectSignatureVerifier;
import com.samlscope.core.transcript.Direction;
import java.io.ByteArrayInputStream;
import java.security.cert.*;
import java.util.*;
import java.util.zip.ZipInputStream;
import org.w3c.dom.Element;

/** A selected running native peer/profile plus its unchanged handler closure is
 * an endpoint inventory. It is deliberately not a complete credential inventory. */
public final class ShibbolethPublisherEndpointInventoryAdapter implements NativeMetadataPublisherInventoryAdapter {
    public static final String ID="shibboleth-stock-publisher-endpoints-v1";
    static final String TARGET="http://localhost:18280/idp/shibboleth", ECP="http://shibboleth.net/ns/profiles/saml2/sso/ecp";
    static final String SOAP="urn:oasis:names:tc:SAML:2.0:bindings:SOAP", FLOW="SAML2/SOAP/ECP";
    static final String ROOT="/opt/reference-idp/", RP=ROOT+"conf/relying-party.xml", PROVIDERS=ROOT+"conf/metadata-providers.xml";
    static final String BEANS="http://www.springframework.org/schema/beans", UTIL="http://www.springframework.org/schema/util";
    static final String CONF="428e389d88bb2abcad19d69bcf759af29f7ce6beb776ccfaa5a6ea76751682ba";
    static final String CONTROL_SOURCE="02b99873ab239a3d40d1c3c2ead3417c4595944bf94a1f84629cc44c8bdc9749";
    private static final com.fasterxml.jackson.databind.ObjectMapper TREE_JSON=new com.samlscope.store.JsonCodec().mapper();
    static final Map<String,String> FIXED_CONFIG=Map.of(ROOT+"conf/global.xml","ca08485a1b5ef8cf0ac1afb80ff066237759e4fb3d884d087f905d8ca0918bcc",
        ROOT+"conf/services.xml","0c5de788ebc611af60ebb3bf4071dcd23744f599d64d65bdb0744515d11a77c0",
        "/usr/local/tomcat/webapps/idp/WEB-INF/web.xml","28ff9c21482971e3ea016f3c9f71f0d0178e05baf40d45561464f0da45a4fd35");
    @Override public String id(){return ID;}
    @Override public Inventory validate(Frame f,JsonNode epoch)throws Exception {
        JsonNode b=state(f,text(epoch,"beforeOriginal"),text(epoch,"id")),a=state(f,text(epoch,"afterOriginal"),text(epoch,"id"));
        for(String field:List.of("runtime","classpathSha256","sourceOverrides","propertiesSha256","selectedProperties","processScope","temporaryPresent"))require(b.path(field).equals(a.path(field)));
        for(String path:List.of(RP,PROVIDERS,ROOT+"conf/global.xml",ROOT+"conf/services.xml","/usr/local/tomcat/webapps/idp/WEB-INF/web.xml"))require(configHash(f,b,path).equals(configHash(f,a,path)));
        for(String name:List.of("browser","ecp"))require(b.path("selectedProfiles").path(name).path("sha256").equals(a.path("selectedProfiles").path(name).path("sha256")));
        require(b.path("selectedPeer").path("sha256").equals(a.path("selectedPeer").path("sha256")));
        var before=f.original(text(epoch,"beforeOriginal"),"native-role-inventory");var after=f.original(text(epoch,"afterOriginal"),"native-role-inventory");
        require(at(before,"nativeFinishedAt").isBefore(at(epoch,"startedAt"))&&at(after,"nativeStartedAt").isAfter(at(epoch,"finishedAt")));
        validateSourceClosure(f,b);validatePeerProfile(f,b);validateBaseline(f,epoch,b);
        return new Inventory(List.of(),List.of(new Endpoint("SingleSignOnService",SOAP,
            TARGET.substring(0,TARGET.lastIndexOf('/'))+"/profile/"+FLOW,"")),Set.of(P),null,
            List.of("current-role-credential-inventory-unproven","transport-authentication-applicability-unproven","other-role-endpoint-scope-unproven"));
    }
    static JsonNode state(Frame f,String label,String epoch)throws Exception {
        var n=f.original(label,"native-role-inventory");require(ID.equals(text(n,"adapter"))&&epoch.equals(text(n,"epochId"))
            &&at(n,"nativeStartedAt").isBefore(at(n,"nativeFinishedAt"))&&!at(n,"nativeFinishedAt").isAfter(at(n,"recordedAt")));
        byte[] raw=f.file(text(n,"readbackFile"));require(hash(raw).equals(text(n,"readbackSha256")));var value=json(raw);
        // Property source paths can contain 'secrets'; this typed map contains
        // public SHA-256 values only, never property contents or credentials.
        var projection=value.deepCopy();((com.fasterxml.jackson.databind.node.ObjectNode)projection).remove("propertiesSha256");
        require(!sensitive(projection)&&value.path("propertiesSha256").isObject());for(var it=value.path("propertiesSha256").fields();it.hasNext();){var row=it.next();require(row.getKey().startsWith(ROOT)&&row.getKey().endsWith(".properties")&&row.getValue().isTextual()&&row.getValue().asText().matches("[a-f0-9]{64}"));}
        require("samlscope-shibboleth-public-publisher-state-v1".equals(text(value,"schema"))
            &&TARGET.equals(text(value,"entityId"))&&text(f.manifest,"peerEntityId").equals(text(value,"peerEntityId"))
            &&n.path("runtime").equals(value.path("runtime")));
        var runtime=value.path("runtime");require(runtime.path("running").asBoolean(false)&&runtime.path("mounts").isArray()&&runtime.path("mounts").isEmpty()
            &&text(runtime,"containerId").matches("[a-f0-9]{64}")&&"sha256:3c1b1fa64c58258aefc9e38d4ae60e9f0340731318a472110ea56ce88c18a11a".equals(text(runtime,"image")));
        at(runtime,"startedAt");return value;
    }
    static void validateSourceClosure(Frame f,JsonNode state)throws Exception {
        for(var pin:FIXED_CONFIG.entrySet())require(pin.getValue().equals(configHash(f,state,pin.getKey())));
        var process=state.path("processScope");require(process.path("nativeJavaProcessObserved").asBoolean(false)
            &&process.path("endpointOverridePresent").isBoolean()&&!process.path("endpointOverridePresent").asBoolean()
            &&process.path("customAgentPresent").isBoolean()&&!process.path("customAgentPresent").asBoolean()
            &&process.path("privateFieldsExported").isBoolean()&&!process.path("privateFieldsExported").asBoolean());
        require(state.path("sourceOverrides").isArray());for(var path:state.path("sourceOverrides"))require(path.asText().startsWith(ROOT+"flows/authn/conditions/")&&path.asText().endsWith("-flow.xml"));
        require(state.path("selectedProperties").equals(json("{\"idp.additionalProperties\":\"/credentials/secrets.properties\"}".getBytes(java.nio.charset.StandardCharsets.UTF_8)))
            &&state.path("propertiesSha256").has(ROOT+"credentials/secrets.properties"));
        byte[] jar=f.file("native-source/idp-conf-impl.jar");require(CONF.equals(hash(jar))
            &&CONF.equals(text(state.path("classpathSha256"),"/usr/local/tomcat/webapps/idp/WEB-INF/lib/idp-conf-impl-5.2.3.jar")));
        Map<String,byte[]> nativeXml=new HashMap<>();try(var zip=new ZipInputStream(new ByteArrayInputStream(jar))){
            for(var entry=zip.getNextEntry();entry!=null;entry=zip.getNextEntry())if(Set.of("net/shibboleth/idp/conf/webflow-config.xml","net/shibboleth/idp/conf/relying-party-system.xml",
                "net/shibboleth/idp/flows/saml/saml2/sso-ecp-flow.xml","net/shibboleth/idp/flows/saml/saml2/sso-ecp-beans.xml","net/shibboleth/idp/flows/saml/saml2/sso-abstract-flow.xml").contains(entry.getName())){
                require(entry.getName().startsWith("net/shibboleth/idp/"));require(nativeXml.put(entry.getName(),zip.readAllBytes())==null);
            }}
        for(var entry:nativeXml.entrySet())require(Arrays.equals(entry.getValue(),f.file("native-source/"+java.nio.file.Path.of(entry.getKey()).getFileName())));
        require(nativeXml.size()==5);
        var flows=SecureXml.parse(nativeXml.get("net/shibboleth/idp/conf/webflow-config.xml")).getDocumentElement();int matches=0;
        for(var e:descendants(flows,"http://www.springframework.org/schema/beans","entry"))if(FLOW.equals(e.getAttribute("key"))){
            require("classpath:/net/shibboleth/idp/flows/saml/saml2/sso-ecp-flow.xml".equals(e.getAttribute("value")));matches++;}
        require(matches==1); // The qualified JAR also pins the native registry factory and ECP initializer.
        var providers=SecureXml.parse(configBytes(f,state,PROVIDERS)).getDocumentElement();
        require("urn:mace:shibboleth:2.0:metadata".equals(providers.getNamespaceURI())&&"MetadataProvider".equals(providers.getLocalName()));
    }
    static void validatePeerProfile(Frame f,JsonNode state)throws Exception {
        String entity=text(f.manifest,"peerEntityId"),plan=text(f.manifest,"planId");require(entity.equals("http://localhost:18080/p/"+plan));
        var selected=state.path("selectedProfiles");require(selected.isObject()&&selected.size()==2);
        JsonNode browser=profile(f,selected.path("browser"),entity,"http://shibboleth.net/ns/profiles/saml2/sso/browser"),ecp=profile(f,selected.path("ecp"),entity,ECP);
        require(browser.path("RelyingPartyConfiguration").equals(ecp.path("RelyingPartyConfiguration"))
            &&browser.at("/ProfileConfiguration/signResponses").isBoolean()&&browser.at("/ProfileConfiguration/signResponses").asBoolean(false)
            &&ecp.at("/ProfileConfiguration/encryptAssertions").isBoolean()&&ecp.at("/ProfileConfiguration/encryptAssertions").asBoolean(false));
        var peer=state.path("selectedPeer");byte[] raw=f.file(text(peer,"file"));require(hash(raw).equals(text(peer,"sha256"))
            &&peer.path("command").equals(json(("[\"env\",\"-u\",\"CLASSPATH\",\"-u\",\"JAVA_OPTS\",\"-u\",\"SHIB_OPTS\",\"/opt/reference-idp/bin/mdquery.sh\",\"-u\",\"http://localhost:8080/idp\",\"-e\",\""+entity+"\"]").getBytes(java.nio.charset.StandardCharsets.UTF_8))));
        var effective=SecureXml.parse(raw).getDocumentElement();var fixture=SecureXml.parse(f.file("fixture.xml")).getDocumentElement();
        require(MD.equals(effective.getNamespaceURI())&&"EntityDescriptor".equals(effective.getLocalName())&&entity.equals(effective.getAttribute("entityID"))
            &&entity.equals(fixture.getAttribute("entityID"))&&keyPins(effective).equals(keyPins(fixture)));
        // mdquery marshals the cached model with signature values cleared and
        // millisecond date precision. Compare the complete operative SP role.
        List<Element> roles=children(effective,MD,"SPSSODescriptor"),fixtureRoles=children(fixture,MD,"SPSSODescriptor");
        require(roles.size()==1&&fixtureRoles.size()==1&&tree(roles.getFirst()).equals(tree(fixtureRoles.getFirst()))
            &&java.time.Instant.parse(effective.getAttribute("validUntil")).toEpochMilli()==java.time.Instant.parse(fixture.getAttribute("validUntil")).toEpochMilli()
            &&children(roles.getFirst(),MD,"AssertionConsumerService").stream().anyMatch(e->"urn:oasis:names:tc:SAML:2.0:bindings:PAOS".equals(e.getAttribute("Binding"))&&e.getAttribute("Location").equals(entity+"/sp/paos")));
        var rp=SecureXml.parse(configBytes(f,state,RP)).getDocumentElement();var overrides=descendants(rp,UTIL,"list").stream().filter(e->"shibboleth.RelyingPartyOverrides".equals(e.getAttribute("id"))).toList();require(overrides.size()==1);
        var peers=children(overrides.getFirst(),BEANS,"bean").stream().filter(e->entity.equals(e.getAttributeNS("http://www.springframework.org/schema/c","relyingPartyIds"))).toList();require(peers.size()==1);
        var bean=peers.getFirst();require("RelyingPartyByName".equals(bean.getAttribute("parent"))&&"PublisherEndpointPeer".equals(bean.getAttribute("id")));
        var props=children(bean,BEANS,"property");require(props.size()==1&&"profileConfigurations".equals(props.getFirst().getAttribute("name")));
        var lists=children(props.getFirst(),BEANS,"list");require(lists.size()==1);var settings=children(lists.getFirst(),BEANS,"bean");var refs=children(lists.getFirst(),BEANS,"ref");
        require(settings.size()==1&&"SAML2.SSO".equals(settings.getFirst().getAttribute("parent"))&&"true".equals(settings.getFirst().getAttributeNS("http://www.springframework.org/schema/p","signResponses"))
            &&refs.size()==3&&refs.stream().map(e->e.getAttribute("bean")).collect(java.util.stream.Collectors.toSet()).equals(Set.of("SAML2.ECP","SAML2.Logout","SAML2.ArtifactResolution")));
    }
    static JsonNode profile(Frame f,JsonNode ref,String entity,String expected)throws Exception {
        byte[] raw=f.file(text(ref,"file"));require(hash(raw).equals(text(ref,"sha256")));var value=json(raw);
        require(value.size()==2&&value.path("RelyingPartyConfiguration").isObject()&&value.path("ProfileConfiguration").isObject()
            &&expected.equals(value.at("/ProfileConfiguration/id").asText())&&TARGET.equals(value.at("/RelyingPartyConfiguration/issuer").asText())
            &&("EntityNames["+entity+",]").equals(value.at("/RelyingPartyConfiguration/id").asText())
            &&"shibboleth.DefaultSecurityConfiguration".equals(value.at("/RelyingPartyConfiguration/securityConfiguration").asText())
            &&ref.path("command").equals(json(("[\"/opt/reference-idp/bin/dumpconfig.sh\",\"-u\",\"http://localhost:8080/idp\",\"--saml2\",\"-r\",\""+entity+"\",\"-P\",\""+expected+"\"]").getBytes(java.nio.charset.StandardCharsets.UTF_8))));
        for(var group:List.of(value.path("RelyingPartyConfiguration"),value.path("ProfileConfiguration")))for(var it=group.elements();it.hasNext();){var v=it.next();require(v.isTextual()||v.isBoolean()||v.isIntegralNumber());}
        return value;
    }
    static void validateBaseline(Frame f,JsonNode epoch,JsonNode state)throws Exception {
        var original=f.original(text(epoch,"baselineOriginal"),"native-peer-baseline");require(text(epoch,"id").equals(text(original,"epochId"))
            &&within(at(original,"nativeStartedAt"),at(epoch,"startedAt"),at(epoch,"finishedAt"))&&within(at(original,"nativeFinishedAt"),at(epoch,"startedAt"),at(epoch,"finishedAt")));
        var request=f.peerTranscript(f.context.runId(),text(original,"requestReference"));var response=f.peerTranscript(f.context.runId(),text(original,"responseReference"));
        require(request.direction()==Direction.OUTBOUND&&response.direction()==Direction.INBOUND&&"GET".equals(request.method())&&"POST".equals(response.method())
            &&request.timestamp().isBefore(response.timestamp())&&within(request.timestamp(),at(original,"nativeStartedAt"),at(original,"nativeFinishedAt"))
            &&within(response.timestamp(),at(original,"nativeStartedAt"),at(original,"nativeFinishedAt")));
        byte[] qraw=f.decoded(request),rraw=f.decoded(response);var q=SecureXml.parse(qraw).getDocumentElement();var r=SecureXml.parse(rraw).getDocumentElement();
        var fixture=SecureXml.parse(f.file(text(original,"fixtureFile"))).getDocumentElement();String entity=text(f.manifest,"peerEntityId"),acs=q.getAttribute("AssertionConsumerServiceURL");
        require(P.equals(q.getNamespaceURI())&&"AuthnRequest".equals(q.getLocalName())&&entity.equals(KeycloakSubjectConfirmationEvidence.issuer(q))
            &&!q.getAttribute("ID").isBlank()&&Set.of("","false","0").contains(q.getAttribute("ForceAuthn"))&&Set.of("","false","0").contains(q.getAttribute("IsPassive"))
            &&request.rawQuery()!=null&&request.url().equals(q.getAttribute("Destination")+"?"+request.rawQuery())
            &&MetadataAlgorithmEvidence.signingKeys(fixture).stream().anyMatch(c->new RedirectSignatureVerifier().isValidForMessage(request.rawQuery(),c,qraw)));
        var target=SecureXml.parse(f.file("target-metadata.xml")).getDocumentElement();var descriptor=role(f.file("target-metadata.xml"),TARGET);
        require(children(descriptor,MD,"SingleSignOnService").stream().anyMatch(e->e.getAttribute("Location").equals(q.getAttribute("Destination")))
            &&response.url().equals(acs)&&q.getAttribute("ID").equals(r.getAttribute("InResponseTo"))&&acs.equals(r.getAttribute("Destination"))
            &&TARGET.equals(KeycloakSubjectConfirmationEvidence.issuer(r))&&P.equals(r.getNamespaceURI())&&"Response".equals(r.getLocalName()));
        var statuses=children(r,P,"Status");require(statuses.size()==1);var codes=children(statuses.getFirst(),P,"StatusCode");require(codes.size()==1&&"urn:oasis:names:tc:SAML:2.0:status:Success".equals(codes.getFirst().getAttribute("Value")));
        require(new VerifiedSignatureAlgorithms().read(r,TARGET,MetadataAlgorithmEvidence.signingKeys(target)).stream().anyMatch(v->"Response".equals(v.element())));
        var sp=children(fixture,MD,"SPSSODescriptor");require(sp.size()==1&&children(sp.getFirst(),MD,"AssertionConsumerService").stream().anyMatch(e->acs.equals(e.getAttribute("Location"))));
        f.used.add(request.id());f.used.add(response.id());
    }
    @Override public void validateTransition(Frame f,JsonNode epoch,byte[] target)throws Exception {
        require("explicit-native-peer-registration".equals(text(epoch,"transition"))&&Arrays.equals(target,f.file(text(epoch,"publicationFile"))));
        var transition=f.original(text(epoch,"transitionOriginal"),"native-configuration-transition");require(text(epoch,"id").equals(text(transition,"epochId"))
            &&"same-run-peer-registration-and-signed-baseline".equals(text(transition,"configurationPurpose"))
            &&at(transition,"nativeStartedAt").isBefore(at(transition,"nativeFinishedAt")));
        var initial=state(f,"initial","initial");var before=state(f,text(epoch,"beforeOriginal"),text(epoch,"id"));
        require(initial.path("runtime").equals(before.path("runtime"))&&initial.path("classpathSha256").equals(before.path("classpathSha256"))
            &&initial.path("propertiesSha256").equals(before.path("propertiesSha256"))&&!initial.path("temporaryPresent").asBoolean()
            &&before.path("temporaryPresent").asBoolean()&&at(f.original("initial","native-role-inventory"),"nativeFinishedAt").isBefore(at(transition,"nativeStartedAt"))
            &&at(transition,"nativeFinishedAt").isBefore(at(f.original(text(epoch,"beforeOriginal"),"native-role-inventory"),"nativeStartedAt")));
        for(var key:FIXED_CONFIG.keySet())require(configHash(f,initial,key).equals(configHash(f,before,key)));
        require(!configHash(f,initial,RP).equals(configHash(f,before,RP))&&!configHash(f,initial,PROVIDERS).equals(configHash(f,before,PROVIDERS)));
        validateMinimalPeerTransition(configBytes(f,initial,RP),configBytes(f,before,RP),configBytes(f,initial,PROVIDERS),configBytes(f,before,PROVIDERS),text(f.manifest,"peerEntityId"),f.context.runId());
    }
    @Override public List<String> validateControls(Frame f,String caseId)throws Exception {
        var c=f.manifest.path("controls");var original=f.original(text(c,"original"),"native-publisher-detector-control");
        require(original.path("positiveControlIds").equals(json("[\"iip-md05-c1-idp-01-positive\"]".getBytes(java.nio.charset.StandardCharsets.UTF_8)))
            &&original.path("negativeControlIds").equals(json("[\"iip-md05-c1-idp-01-negative\"]".getBytes(java.nio.charset.StandardCharsets.UTF_8)))
            &&"oracle-calibration-only".equals(text(original,"purpose")));
        byte[] input=f.file(text(c,"inputFile")),positive=f.file(text(c,"positiveOutputFile")),negative=f.file(text(c,"negativeOutputFile"));
        require(hash(input).equals(text(original,"inputSha256"))&&hash(positive).equals(text(original,"positiveOutputSha256"))&&hash(negative).equals(text(original,"negativeOutputSha256")));
        validateControlInvocation(f,c,original,input,positive,negative);
        var n=json(input);require("samlscope-shibboleth-publisher-control-input-v1".equals(text(n,"schema"))&&"oracle-calibration-only".equals(text(n,"purpose")));
        var keys=new ArrayList<RoleKey>();var purposes=new HashSet<String>();for(var key:n.path("roleKeys")){String purpose=text(key,"purpose");require(purposes.add(purpose));keys.add(new RoleKey(certificateSpki(text(key,"certificateDerBase64")),purpose,"native-builder-calibration"));}
        require(purposes.equals(Set.of("signing","encryption","transport-authentication"))&&keys.stream().map(RoleKey::spkiSha256).distinct().count()==3);
        var endpoints=new ArrayList<Endpoint>();for(var e:n.path("endpoints"))endpoints.add(new Endpoint(text(e,"kind"),text(e,"binding"),text(e,"location"),""));require(endpoints.size()==1);
        var inventory=new Inventory(keys,endpoints,Set.of(P),null,List.of());String entity=text(n,"entityId");require(compare(role(positive,entity),inventory,C1).isEmpty());var omissions=compare(role(negative,entity),inventory,C1);
        require(omissions.equals(List.of("key:transport-authentication:"+keys.stream().filter(k->k.purpose().equals("transport-authentication")).findFirst().orElseThrow().spkiSha256())));
        require(roleKeys(role(positive,entity)).get("encryption").equals(roleKeys(role(negative,entity)).get("encryption")));
        var positiveRole=role(positive,entity);var transport=keys.stream().filter(k->k.purpose().equals("transport-authentication")).findFirst().orElseThrow().spkiSha256();
        int removed=0;for(var key:children(positiveRole,MD,"KeyDescriptor"))if(descendants(key,DS,"X509Certificate").stream().anyMatch(cert->{try{return transport.equals(certificateSpki(cert.getTextContent().replaceAll("\\s+","")));}catch(Exception e){return false;}})){
            positiveRole.removeChild(key);removed++;}
        require(removed==1&&tree(positiveRole).equals(tree(role(negative,entity))));
        // c3 has no native credential inventory in this adapter; these c1 controls never prove it.
        return C1.equals(caseId)?omissions:List.of();
    }
    static void validateControlInvocation(Frame f,JsonNode c,JsonNode original,byte[] input,byte[] positive,byte[] negative)throws Exception {
        require(CONTROL_SOURCE.equals(hash(f.file(text(c,"sourceFile"))))&&CONTROL_SOURCE.equals(text(original,"sourceSha256"))
            &&original.path("ownedHelperRemoved").isBoolean()&&original.path("ownedHelperRemoved").asBoolean());
        var initial=state(f,"initial","initial");var classpath=initial.path("classpathSha256");require(classpath.isObject()&&classpath.size()==127&&classpath.equals(original.path("nativeClasspathSha256")));
        for(var it=classpath.fields();it.hasNext();){var row=it.next();var path=java.nio.file.Path.of(row.getKey());require(path.getParent().toString().equals("/usr/local/tomcat/webapps/idp/WEB-INF/lib")
            &&row.getValue().asText().matches("[a-f0-9]{64}")&&row.getValue().asText().equals(hash(f.file("native-libraries/"+path.getFileName()))));}
        byte[] invocationBytes=f.file(text(c,"invocationsFile")),observationBytes=f.file(text(c,"observationFile"));
        require(hash(invocationBytes).equals(text(original,"invocationsSha256"))&&hash(observationBytes).equals(text(original,"observationSha256")));
        var rows=json(invocationBytes);require(rows.isArray()&&rows.size()==2);String owned="/tmp/samlscope-publisher-controls-"+f.context.runId(),cp="/usr/local/tomcat/webapps/idp/WEB-INF/lib/*";
        var prefix=List.of("docker","exec","samlscope-reference-shibboleth","env","-u","JAVA_OPTS","-u","SHIB_OPTS","-u","CLASSPATH","-u","JAVA_TOOL_OPTIONS","-u","JDK_JAVA_OPTIONS");
        var compile=new ArrayList<>(prefix);compile.addAll(List.of("javac","--release","17","-sourcepath","","-cp",cp,"-d",owned+"/classes",owned+"/ObserveShibbolethPublisherControls.java"));
        var execute=new ArrayList<>(prefix);execute.addAll(List.of("java","-cp",owned+"/classes:"+cp,"ObserveShibbolethPublisherControls",owned+"/input.json",owned+"/output"));
        var mapper=new com.samlscope.store.JsonCodec().mapper();java.time.Instant last=null;
        for(int i=0;i<2;i++){var row=rows.get(i);require((i==0?"compile-native-control":"execute-native-control").equals(text(row,"purpose"))
            &&row.path("command").equals(mapper.valueToTree(i==0?compile:execute))&&row.path("exitCode").asInt(-1)==0
            &&row.path("runtimeBefore").equals(initial.path("runtime"))&&row.path("runtimeAfter").equals(initial.path("runtime"))
            &&at(row,"startedAt").isBefore(at(row,"finishedAt"))&&!at(row,"finishedAt").isAfter(at(original,"recordedAt"))
            &&(last==null||at(row,"startedAt").isAfter(last)));last=at(row,"finishedAt");}
        var observation=json(observationBytes);require("samlscope-shibboleth-publisher-control-observation-v1".equals(text(observation,"schema"))
            &&"oracle-calibration-only".equals(text(observation,"purpose"))&&"5.2.3".equals(text(observation,"productVersion"))
            &&hash(input).equals(text(observation,"inputSha256"))&&hash(positive).equals(text(observation,"positiveSha256"))&&hash(negative).equals(text(observation,"negativeSha256")));
        var origins=observation.path("nativeClassOrigins");require(origins.isObject()&&origins.size()==4);
        for(var entry:Map.of("org.opensaml.core.config.InitializationService","opensaml-core-api-5.2.3.jar","org.opensaml.core.xml.util.XMLObjectSupport","opensaml-core-api-5.2.3.jar",
            "org.opensaml.saml.saml2.metadata.impl.EntityDescriptorBuilder","opensaml-saml-impl-5.2.3.jar","net.shibboleth.idp.Version","idp-core-5.2.3.jar").entrySet())
            require(("file:/usr/local/tomcat/webapps/idp/WEB-INF/lib/"+entry.getValue()).equals(text(origins,entry.getKey()))&&classpath.has("/usr/local/tomcat/webapps/idp/WEB-INF/lib/"+entry.getValue()));
    }
    @Override public void validateRestoration(Frame f)throws Exception {
        var initial=state(f,"initial","initial");var restored=state(f,"restored","restored");require(initial.path("runtime").equals(restored.path("runtime"))
            &&initial.path("classpathSha256").equals(restored.path("classpathSha256"))&&initial.path("propertiesSha256").equals(restored.path("propertiesSha256"))
            &&initial.path("selectedProfiles").isEmpty()&&restored.path("selectedProfiles").isEmpty()&&!restored.path("temporaryPresent").asBoolean());
        for(var key:List.of(RP,PROVIDERS,ROOT+"conf/global.xml",ROOT+"conf/services.xml","/usr/local/tomcat/webapps/idp/WEB-INF/web.xml"))require(configHash(f,initial,key).equals(configHash(f,restored,key)));
        var r=f.original("restoration","native-publisher-restoration");require(r.path("restored").asBoolean(false)&&Arrays.equals(f.file(text(r,"restoredPublicationFile")),f.file("target-metadata.xml"))
            &&text(r,"restoredPublicationSha256").equals(text(f.manifest,"targetMetadataSha256")));
        var count=r.path("operationCounts");require(count.path("productSettings").asInt(-1)==3&&count.path("configurationRestorations").asInt(-1)==2&&count.path("metadataReloads").asInt(-1)==4
            &&count.path("credentialPosts").asInt(-1)==1&&count.path("samlSubmissions").asInt(-1)==1&&count.path("personOperations").asInt(-1)==0&&count.path("productRestarts").asInt(-1)==0);
        var last=f.manifest.path("epochs").get(f.manifest.path("epochs").size()-1);require(at(f.original("restored","native-role-inventory"),"nativeStartedAt").isAfter(at(f.original(text(last,"afterOriginal"),"native-role-inventory"),"nativeFinishedAt"))
            &&at(r,"recordedAt").isAfter(at(f.original("restored","native-role-inventory"),"nativeFinishedAt")));
        validateOperations(f,initial,restored);
    }
    static void validateOperations(Frame f,JsonNode initial,JsonNode restored)throws Exception {
        var ledger=f.original("operations","native-publisher-operation-ledger");byte[] raw=f.file("operations.json"),counts=f.file("operation-counts.json"),reads=f.file("publication-reads.json");
        require(hash(raw).equals(text(ledger,"operationsSha256"))&&hash(counts).equals(text(ledger,"countsSha256"))&&hash(reads).equals(text(ledger,"publicationReadsSha256")));
        var rows=json(raw);require(rows.isArray()&&rows.size()==10);String temporary=ROOT+"metadata/publisher-endpoint-"+f.context.runId()+".xml";
        var labels=List.of("register-peer","register-providers","register-peer-signing","apply-metadata","apply-profile","restore-profile","restore-profile","restore-providers","restore-metadata","restore-peer");
        var kinds=List.of("write","write","write","reload","reload","write","reload","write","reload","remove");
        var before=state(f,"before","stock-selected-peer");
        var paths=Map.of(0,temporary,1,PROVIDERS,2,RP,5,RP,7,PROVIDERS,9,temporary);var services=Map.of(3,"shibboleth.MetadataResolverService",4,"shibboleth.RelyingPartyResolverService",6,"shibboleth.RelyingPartyResolverService",8,"shibboleth.MetadataResolverService");
        var shas=Map.of(0,hash(f.file("fixture.xml")),1,configHash(f,before,PROVIDERS),2,configHash(f,before,RP),5,configHash(f,initial,RP),7,configHash(f,initial,PROVIDERS));
        java.time.Instant previous=null;for(int i=0;i<10;i++){var row=rows.get(i);require(labels.get(i).equals(text(row,"label"))&&kinds.get(i).equals(text(row,"operation"))&&row.path("completed").isBoolean()&&row.path("completed").asBoolean());
            if(paths.containsKey(i))require(paths.get(i).equals(text(row,"path")));if(services.containsKey(i))require(services.get(i).equals(text(row,"service")));if(shas.containsKey(i))require(shas.get(i).equals(text(row,"sha256")));
            if(i<9)require(at(row,"startedAt").isBefore(at(row,"finishedAt"))&&(previous==null||at(row,"startedAt").isAfter(previous)));previous=at(row,"finishedAt");}
        var transition=f.original("transition","native-configuration-transition");require(within(at(rows.get(0),"startedAt"),at(transition,"nativeStartedAt"),at(transition,"nativeFinishedAt"))&&within(at(rows.get(4),"finishedAt"),at(transition,"nativeStartedAt"),at(transition,"nativeFinishedAt"))
            &&at(rows.get(5),"startedAt").isAfter(at(f.original("after","native-role-inventory"),"nativeFinishedAt"))&&at(rows.get(9),"finishedAt").isBefore(at(f.original("restored","native-role-inventory"),"nativeStartedAt")));
        var costs=json(counts);var original=f.original("restoration","native-publisher-restoration");for(var it=original.path("operationCounts").fields();it.hasNext();){var entry=it.next();require(entry.getValue().equals(costs.path(entry.getKey())));}require(costs.path("restored").asBoolean(false));
        var publications=json(reads);require(publications.isArray()&&publications.size()==3);for(var row:publications)require("GET".equals(text(row,"method"))&&TARGET.equals(text(row,"url"))&&row.path("responseStatus").asInt(-1)==200&&text(f.manifest,"targetMetadataSha256").equals(text(row,"sha256")));
    }
    static void validateMinimalPeerTransition(byte[] oldRp,byte[] newRp,byte[] oldProviders,byte[] newProviders,String entity,String run)throws Exception {
        var rp=SecureXml.parse(newRp).getDocumentElement();var peers=descendants(rp,BEANS,"bean").stream().filter(e->entity.equals(e.getAttributeNS("http://www.springframework.org/schema/c","relyingPartyIds"))).toList();require(peers.size()==1);
        require(entity.matches("http://localhost:18080/p/plan_[0-9A-HJKMNP-TV-Z]{26}"));
        var expected=SecureXml.parse(("<bean xmlns='"+BEANS+"' xmlns:c='http://www.springframework.org/schema/c' xmlns:p='http://www.springframework.org/schema/p' id='PublisherEndpointPeer' parent='RelyingPartyByName' c:relyingPartyIds='"+entity+"'><property name='profileConfigurations'><list><bean parent='SAML2.SSO' p:signResponses='true'/><ref bean='SAML2.ECP'/><ref bean='SAML2.Logout'/><ref bean='SAML2.ArtifactResolution'/></list></property></bean>").getBytes(java.nio.charset.StandardCharsets.UTF_8)).getDocumentElement();
        require(tree(peers.getFirst()).equals(tree(expected)));peers.getFirst().getParentNode().removeChild(peers.getFirst());
        require(tree(rp).equals(tree(SecureXml.parse(oldRp).getDocumentElement())));
        var providers=SecureXml.parse(newProviders).getDocumentElement();var added=children(providers,"urn:mace:shibboleth:2.0:metadata","MetadataProvider").stream().filter(e->("PublisherEndpoint"+run).equals(e.getAttribute("id"))).toList();require(added.size()==1);var e=added.getFirst();
        require("FilesystemMetadataProvider".equals(e.getAttributeNS("http://www.w3.org/2001/XMLSchema-instance","type"))&&(ROOT+"metadata/publisher-endpoint-"+run+".xml").equals(e.getAttribute("metadataFile"))&&e.getChildNodes().getLength()==0);
        e.getParentNode().removeChild(e);require(tree(providers).equals(tree(SecureXml.parse(oldProviders).getDocumentElement())));
    }
    /** Namespace prefixes and formatting are immaterial; every real attribute, child and nonblank text remains. */
    static String tree(Element e){var attributes=new TreeMap<String,String>();for(int i=0;i<e.getAttributes().getLength();i++){var a=e.getAttributes().item(i);if(!"http://www.w3.org/2000/xmlns/".equals(a.getNamespaceURI()))attributes.put("{"+Objects.toString(a.getNamespaceURI(),"")+"}"+Objects.toString(a.getLocalName(),a.getNodeName()),a.getNodeValue());}
        var parts=new ArrayList<Object>();for(var n=e.getFirstChild();n!=null;n=n.getNextSibling()){if(n instanceof Element child)parts.add(tree(child));else if((n.getNodeType()==org.w3c.dom.Node.TEXT_NODE||n.getNodeType()==org.w3c.dom.Node.CDATA_SECTION_NODE)&&!n.getNodeValue().isBlank())parts.add(n.getNodeValue().strip());}
        return TREE_JSON.valueToTree(List.of(Objects.toString(e.getNamespaceURI(),""),Objects.toString(e.getLocalName(),e.getTagName()),attributes,parts)).toString();}
    static byte[] configBytes(Frame f,JsonNode state,String path)throws Exception {var ref=state.path("configurationFiles").path(path);byte[] raw=f.file(text(ref,"file"));require(hash(raw).equals(text(ref,"sha256")));return raw;}
    static String configHash(Frame f,JsonNode state,String path)throws Exception{return hash(configBytes(f,state,path));}
    static List<String> keyPins(Element metadata)throws Exception {var result=new ArrayList<String>();for(var c:MetadataAlgorithmEvidence.signingKeys(metadata))result.add(hash(c.getPublicKey().getEncoded()));return List.copyOf(result);}
    static List<Element> descendants(Element root,String ns,String name){var result=new ArrayList<Element>();var all=root.getElementsByTagNameNS(ns,name);for(int i=0;i<all.getLength();i++)result.add((Element)all.item(i));return result;}
}
