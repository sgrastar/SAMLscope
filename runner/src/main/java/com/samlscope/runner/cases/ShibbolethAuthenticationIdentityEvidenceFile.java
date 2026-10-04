package com.samlscope.runner.cases;

import static com.samlscope.runner.cases.MetadataAlgorithmEvidence.children;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.cert.*;
import java.time.Instant;
import java.util.*;
import java.util.function.Function;
import com.fasterxml.jackson.databind.JsonNode;
import com.samlscope.core.caseexec.CaseContext;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.transcript.*;
import com.samlscope.saml.crypto.*;
import com.samlscope.saml.normal.SecureXml;
import com.samlscope.store.JsonCodec;
import org.w3c.dom.Element;

/** Original native Password-only configuration plus correlated success/error controls for SSO01.ae.
 * No browser success or configuration declaration alone can establish the ambient-auth prerequisite.
 */
final class ShibbolethAuthenticationIdentityEvidenceFile {
    static final String SCHEMA="samlscope-shibboleth-authentication-identity-v1";
    static final String AUDIT_FORMAT="SAMLscope-identity-v1|%I|%SP|%u|%e|%S|%AF|%SSO|%b|%P";
    private static final String P="urn:oasis:names:tc:SAML:2.0:protocol";
    private static final String S="urn:oasis:names:tc:SAML:2.0:assertion";
    private static final String MD="urn:oasis:names:tc:SAML:2.0:metadata";
    private static final String DS="http://www.w3.org/2000/09/xmldsig#";
    private static final String B="http://www.springframework.org/schema/beans";
    private static final String U="http://www.springframework.org/schema/util";
    private static final String SP="http://www.springframework.org/schema/p";
    private final Path directory;
    private final TranscriptContentReader content;
    private final Function<String,byte[]> metadata;
    private final SamlDecryptionKeyProvider keys;

    ShibbolethAuthenticationIdentityEvidenceFile(Path directory,TranscriptContentReader content,
            Function<String,byte[]> metadata,SamlDecryptionKeyProvider keys) {
        this.directory=Objects.requireNonNull(directory).toAbsolutePath().normalize();
        this.content=Objects.requireNonNull(content);this.metadata=Objects.requireNonNull(metadata);this.keys=Objects.requireNonNull(keys);
    }

    CaseOutcome evaluate(CaseContext context) {
        String stage="native-configuration-unproven";
        try {
            require(context.transcriptComplete()&&context.runId().matches("run_[0-9A-HJKMNP-TV-Z]{26}"));
            var folder=directory.resolve(context.runId()).normalize();
            require(folder.getParent().equals(directory)&&Files.isDirectory(folder,LinkOption.NOFOLLOW_LINKS));
            var manifest=new JsonCodec().mapper().readTree(raw(folder,"manifest.json"));
            require(SCHEMA.equals(text(manifest,"schema"))&&context.runId().equals(text(manifest,"runId")));
            var targetRaw=metadata.apply(context.runId());
            require(hash(targetRaw).equals(text(manifest,"targetMetadataSha256")));
            var target=SecureXml.parse(targetRaw).getDocumentElement();
            String entity=target.getAttribute("entityID");
            require(MD.equals(target.getNamespaceURI())&&"EntityDescriptor".equals(target.getLocalName())
                    &&"http://localhost:18280/idp/shibboleth".equals(entity)&&entity.equals(text(manifest,"targetEntityId")));
            var targetKeys=MetadataAlgorithmEvidence.signingKeys(target);require(!targetKeys.isEmpty());
            var sp=SecureXml.parse(checked(folder,manifest,"spMetadataFile","spMetadataSha256")).getDocumentElement();
            require(MD.equals(sp.getNamespaceURI())&&"EntityDescriptor".equals(sp.getLocalName())&&!sp.getAttribute("entityID").isBlank());
            var entries=new HashMap<String,TranscriptEntry>();
            for(var entry:context.transcript().list(context.runId()))require(context.runId().equals(entry.runId())&&entries.put(entry.id(),entry)==null);
            stage="positive-request-response-binding-unproven";
            var positive=exchange(entries,manifest.path("positive"),context,sp,target, false);
            stage="identity-unavailable-request-response-binding-unproven";
            var unable=exchange(entries,manifest.path("unable"),context,sp,target,true);
            require(!positive.request().id().equals(unable.request().id())&&!positive.response().id().equals(unable.response().id()));
            var first=positive.request().timestamp().isBefore(unable.request().timestamp())?positive.request().timestamp():unable.request().timestamp();
            var last=positive.response().timestamp().isAfter(unable.response().timestamp())?positive.response().timestamp():unable.response().timestamp();
            stage="native-configuration-unproven";configuration(folder,manifest,first,last);
            stage="ordinary-precredential-authentication-challenge-unproven";challenge(folder,manifest,positive);
            stage="positive-identity-control-unproven";
            Optional<PlanCredentials> credential=Optional.empty();
            if(!children(positive.responseXml(),S,"EncryptedAssertion").isEmpty()) {
                var roles=children(sp,MD,"SPSSODescriptor");require(roles.size()==1);
                var certs=new ArrayList<X509Certificate>();
                for(var descriptor:children(roles.getFirst(),MD,"KeyDescriptor")) {
                    if(!List.of("","encryption").contains(descriptor.getAttribute("use")))continue;
                    var nodes=descriptor.getElementsByTagNameNS(DS,"X509Certificate");
                    for(int i=0;i<nodes.getLength();i++)certs.add((X509Certificate)CertificateFactory.getInstance("X.509")
                            .generateCertificate(new java.io.ByteArrayInputStream(Base64.getMimeDecoder().decode(nodes.item(i).getTextContent()))));
                }
                require(certs.size()==1);credential=Optional.of(new PlanCredentials(keys.keyFor(context.runId()).orElseThrow(),certs.getFirst()));
            }
            var assertion=VerifiedResponseAssertion.read(positive.responseXml(),entity,targetKeys,sp,credential,
                    positive.requestXml().getAttribute("ID"),positive.responseXml().getAttribute("Destination"));
            var authn=children(assertion,S,"AuthnStatement");require(authn.size()==1);
            var contexts=children(authn.getFirst(),S,"AuthnContext");require(contexts.size()==1);
            var classes=children(contexts.getFirst(),S,"AuthnContextClassRef");
            require(classes.size()==1&&List.of("urn:oasis:names:tc:SAML:2.0:ac:classes:Password",
                    "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport").contains(classes.getFirst().getTextContent()));
            var audit=new String(checked(folder,manifest,"auditFile","auditSha256"),StandardCharsets.UTF_8);
            audit(audit,positive,sp.getAttribute("entityID"),context.parameters().testUserHint(),true);
            stage="identity-unavailable-error-control-unproven";
            var response=unable.responseXml();
            var status=children(response,P,"Status");require(status.size()==1);
            var codes=children(status.getFirst(),P,"StatusCode");require(codes.size()==1);
            require(List.of("urn:oasis:names:tc:SAML:2.0:status:Requester","urn:oasis:names:tc:SAML:2.0:status:Responder")
                    .contains(codes.getFirst().getAttribute("Value")));
            var subcodes=children(codes.getFirst(),P,"StatusCode");require(subcodes.size()==1&&
                    "urn:oasis:names:tc:SAML:2.0:status:NoPassive".equals(subcodes.getFirst().getAttribute("Value")));
            require(children(response,S,"Assertion").isEmpty()&&children(response,S,"EncryptedAssertion").isEmpty());
            var verified=new VerifiedSignatureAlgorithms().read(response,entity,targetKeys);
            require(verified.size()==1&&"Response".equals(verified.getFirst().element()));
            audit(audit,unable,sp.getAttribute("entityID"),context.parameters().testUserHint(),false);
            require(!Instant.parse(text(manifest,"completedAt")).isBefore(last));
            return new CaseOutcome(Outcome.SATISFIED,null,"configuration.identity.native-controls-observed",
                "configuration.identity.native-controls-observed",List.of(new EvidenceRef("transcript",positive.request().id()),
                new EvidenceRef("transcript",positive.response().id()),new EvidenceRef("transcript",unable.request().id()),
                new EvidenceRef("transcript",unable.response().id()),new EvidenceRef("native-authentication-identity",context.runId()+"/manifest.json")),
                Map.of("adapter","shibboleth-native-password-only-v1","native_ambient_authentication_excluded",true,
                    "correct_authentication_success",true,"identity_unavailable_error_without_assertion",true,
                    "configuration_restored",true,"attested",false));
        }catch(Exception unproven) {
            return new CaseOutcome(Outcome.NOT_VERIFIED,"ambient_auth_not_excludable",
                    "configuration.identity.native-evidence-unproven","configuration.identity.native-evidence-unproven",
                    List.of(),Map.of("adapter","shibboleth-native-password-only-v1","stage",stage));
        }
    }

    private record Exchange(TranscriptEntry request,TranscriptEntry response,Element requestXml,Element responseXml,String requestSha256) {}
    private Exchange exchange(Map<String,TranscriptEntry> entries,JsonNode row,CaseContext context,Element sp,Element target,boolean passive)throws Exception {
        var request=entries.get(text(row,"requestReference"));var response=entries.get(text(row,"responseReference"));
        require(request!=null&&response!=null&&request.direction()==Direction.OUTBOUND&&response.direction()==Direction.INBOUND
                &&!request.timestamp().isAfter(response.timestamp())&&request.decodedSamlRef()!=null&&response.decodedSamlRef()!=null);
        var requestRaw=content.readDecodedSaml(request);var responseRaw=content.readDecodedSaml(response);
        require(requestRaw.length==request.decodedSamlBytes()&&responseRaw.length==response.decodedSamlBytes());
        var requestXml=SecureXml.parse(requestRaw).getDocumentElement();
        var responseXml=SecureXml.parse(responseRaw).getDocumentElement();
        require(P.equals(requestXml.getNamespaceURI())&&"AuthnRequest".equals(requestXml.getLocalName())
                &&P.equals(responseXml.getNamespaceURI())&&"Response".equals(responseXml.getLocalName())
                &&!requestXml.getAttribute("ID").isBlank()&&requestXml.getAttribute("ID").equals(responseXml.getAttribute("InResponseTo")));
        var issuer=children(requestXml,S,"Issuer");require(issuer.size()==1&&sp.getAttribute("entityID").equals(issuer.getFirst().getTextContent()));
        require(passive==truth(requestXml.getAttribute("IsPassive"))&&passive==truth(requestXml.getAttribute("ForceAuthn")));
        var destination=requestXml.getAttribute("Destination");
        var roles=children(target,MD,"IDPSSODescriptor");require(roles.size()==1&&children(roles.getFirst(),MD,"SingleSignOnService")
            .stream().anyMatch(endpoint->destination.equals(endpoint.getAttribute("Location"))));
        var acs=requestXml.getAttribute("AssertionConsumerServiceURL");
        var spRoles=children(sp,MD,"SPSSODescriptor");require(spRoles.size()==1&&!acs.isBlank()&&children(spRoles.getFirst(),MD,"AssertionConsumerService")
            .stream().anyMatch(endpoint->acs.equals(endpoint.getAttribute("Location"))));
        var requestKeys=new ArrayList<X509Certificate>();
        for(var descriptor:children(spRoles.getFirst(),MD,"KeyDescriptor")) {
            if(!List.of("","signing").contains(descriptor.getAttribute("use")))continue;
            var certs=descriptor.getElementsByTagNameNS(DS,"X509Certificate");
            for(int i=0;i<certs.getLength();i++)requestKeys.add((X509Certificate)CertificateFactory.getInstance("X.509").generateCertificate(
                new java.io.ByteArrayInputStream(Base64.getMimeDecoder().decode(certs.item(i).getTextContent()))));
        }
        require(!requestKeys.isEmpty());
        if("GET".equals(request.method()))require(requestKeys.stream().anyMatch(cert->
            new com.samlscope.saml.binding.RedirectSignatureVerifier().isValidForMessage(request.rawQuery(),cert,requestRaw)));
        else {
            var verifier=new XmlSignatureVerifier();require(verifier.hasValidEnvelopedReferenceDigests(requestXml)
                &&requestKeys.stream().anyMatch(cert->verifier.hasValidEnvelopedSignature(requestXml,cert)));
        }
        require(entries.values().stream().filter(entry->entry.direction()==Direction.INBOUND&&
            requestXml.getAttribute("ID").equals(entry.samlSummary().get("inResponseTo"))).count()==1);
        require(acs.equals(responseXml.getAttribute("Destination"))&&acs.equals(response.url()));
        return new Exchange(request,response,requestXml,responseXml,hash(requestRaw));
    }
    private static boolean truth(String value){return "true".equals(value)||"1".equals(value);}
    private void configuration(Path folder,JsonNode manifest,Instant first,Instant last)throws Exception {
        var files=manifest.path("configurationFiles");require(files.isArray()&&files.size()==10);
        var kinds=new HashSet<String>();
        for(var row:files) {
            String kind=text(row,"kind");require(kinds.add(kind));
            var original=checked(folder,row,"originalFile","originalSha256");
            var configured=checked(folder,row,"configuredFile","configuredSha256");
            require(Arrays.equals(original,checked(folder,row,"finalFile","finalSha256")));
            var backs=row.path("readBacks");require(backs.isArray()&&backs.size()==2);
            var phases=new HashSet<String>();
            for(var back:backs) {
                String phase=text(back,"phase");require(phases.add(phase)&&Arrays.equals(configured,checked(folder,back,"file","sha256")));
                var at=Instant.parse(text(back,"recordedAt"));
                require("before".equals(phase)?!at.isAfter(first):"after".equals(phase)&&!at.isBefore(last));
            }
            require(phases.equals(Set.of("before","after")));
            switch(kind) {
                case "authn-properties" -> {
                    var properties=new Properties();properties.load(new java.io.ByteArrayInputStream(configured));
                    require("Password".equals(properties.getProperty("idp.authn.flows"))&&"false".equals(properties.getProperty("idp.session.enabled"))
                        &&"shibboleth.Conditions.FALSE".equals(properties.getProperty("idp.authn.Password.reuseCondition")));
                }
                case "password-validator" -> {
                    var root=SecureXml.parse(configured).getDocumentElement();var lists=children(root,U,"list");
                    require(lists.size()==1&&"shibboleth.authn.Password.Validators".equals(lists.getFirst().getAttribute("id")));
                    var validators=children(lists.getFirst(),B,"bean");require(validators.size()==1&&
                        "shibboleth.HTPasswdValidator".equals(validators.getFirst().getAttribute("parent"))
                        &&"%{idp.home}/credentials/demo.htpasswd".equals(validators.getFirst().getAttributeNS(SP,"resource")));
                }
                case "global" -> {
                    var root=SecureXml.parse(configured).getDocumentElement();
                    for(var node=root.getFirstChild();node!=null;node=node.getNextSibling())require(!(node instanceof Element));
                }
                case "relying-party" -> {
                    var root=SecureXml.parse(configured).getDocumentElement();
                    require(root.getElementsByTagNameNS(B,"property").getLength()>0);
                    var properties=root.getElementsByTagNameNS(B,"property");
                    for(int i=0;i<properties.getLength();i++)require(!Set.of("authenticationFlows","defaultAuthenticationMethods","forceAuthn")
                        .contains(((Element)properties.item(i)).getAttribute("name")));
                    var overrides=root.getElementsByTagNameNS(U,"list");
                    for(int i=0;i<overrides.getLength();i++) {
                        var list=(Element)overrides.item(i);
                        if("shibboleth.RelyingPartyOverrides".equals(list.getAttribute("id")))require(children(list,B,"bean").isEmpty()&&children(list,B,"ref").isEmpty());
                    }
                }
                case "providers" -> {
                    var old=SecureXml.parse(original).getDocumentElement();var current=SecureXml.parse(configured).getDocumentElement();
                    String ns="urn:mace:shibboleth:2.0:metadata";var oldSources=children(old,ns,"MetadataProvider");
                    var sources=children(current,ns,"MetadataProvider");require(sources.size()==oldSources.size()+1);
                    var source=sources.getFirst();require("DynamicHTTPMetadataProvider".equals(source.getAttributeNS(
                        "http://www.w3.org/2001/XMLSchema-instance","type")));
                    var templates=children(source,ns,"Template");require(templates.size()==1&&
                        "http://samlscope-reference-suite:8080/mdq/${entityID}".equals(templates.getFirst().getTextContent()));
                    for(int i=0;i<oldSources.size();i++)require(oldSources.get(i).isEqualNode(sources.get(i+1)));
                }
                case "audit" -> {
                    var root=SecureXml.parse(configured).getDocumentElement();var maps=children(root,U,"map");boolean matched=false;
                    for(var map:maps)if("shibboleth.AuditFormattingMap".equals(map.getAttribute("id")))for(var entry:children(map,B,"entry"))
                        if("Shibboleth-Audit".equals(entry.getAttribute("key")))matched=AUDIT_FORMAT.equals(entry.getAttribute("value"));
                    require(matched);
                }
                case "condition-base","condition-locked","condition-expired","condition-expiring" ->
                    require(Arrays.equals(configured,checked(folder,row,"packagedOriginalFile","packagedOriginalSha256")));
                default -> throw new IllegalArgumentException("Unknown native configuration");
            }
        }
        require(kinds.equals(Set.of("authn-properties","password-validator","global","relying-party","providers","audit",
            "condition-base","condition-locked","condition-expired","condition-expiring")));
        var parentBefore=checked(folder,manifest,"parentPropertiesFile","parentPropertiesSha256");
        require(Arrays.equals(parentBefore,checked(folder,manifest,"parentPropertiesFinalFile","parentPropertiesFinalSha256")));
        var props=new Properties();props.load(new java.io.ByteArrayInputStream(parentBefore));
        require(props.size()==1&&"Password".equals(props.getProperty("idp.authn.flows")));
        var parentReadbacks=manifest.path("parentPropertiesReadBacks");require(parentReadbacks.isArray()&&parentReadbacks.size()==2);
        var parentPhases=new HashSet<String>();
        for(var row:parentReadbacks) {
            String phase=text(row,"phase");require(parentPhases.add(phase)&&Arrays.equals(parentBefore,checked(folder,row,"file","sha256")));
            var at=Instant.parse(text(row,"recordedAt"));require("before".equals(phase)?!at.isAfter(first):"after".equals(phase)&&!at.isBefore(last));
        }
        require(parentPhases.equals(Set.of("before","after")));
        var system=SecureXml.parse(checked(folder,manifest,"flowDescriptorsFile","flowDescriptorsSha256")).getDocumentElement();
        var password=children(system,B,"bean").stream().filter(bean->"authn/Password".equals(bean.getAttributeNS(SP,"id"))).toList();
        require(password.size()==1&&password.getFirst().getAttributeNS(SP,"reuseCondition-ref")
            .equals("#{'%{idp.authn.Password.reuseCondition:shibboleth.Conditions.TRUE}'.trim()}"));
        var selection=SecureXml.parse(checked(folder,manifest,"flowSelectionFile","flowSelectionSha256")).getDocumentElement();
        var beans=children(selection,B,"bean");
        require(beans.stream().anyMatch(bean->"PotentialFlowsLookup".equals(bean.getAttribute("id"))
            &&bean.getAttributeNS("http://www.springframework.org/schema/c","expression").contains("id matches 'authn/(' + '%{idp.authn.flows:Password}'.trim() + ')'")));
        require(beans.stream().anyMatch(bean->"PopulateSessionContext".equals(bean.getAttribute("id"))
            &&"%{idp.session.enabled:true}".equals(bean.getAttributeNS(SP,"activationCondition"))));
        var conditions=SecureXml.parse(checked(folder,manifest,"conditionsFile","conditionsSha256")).getDocumentElement();
        require(children(conditions,B,"bean").stream().anyMatch(bean->"shibboleth.Conditions.FALSE".equals(bean.getAttribute("id"))
            &&"net.shibboleth.shared.logic.PredicateSupport".equals(bean.getAttribute("class"))&&"alwaysFalse".equals(bean.getAttribute("factory-method"))));
        var inventory=new String(checked(folder,manifest,"customFlowInventoryFile","customFlowInventorySha256"),StandardCharsets.UTF_8).lines().toList();
        require(new HashSet<>(inventory).equals(Set.of("/opt/reference-idp/flows/authn/conditions/conditions-flow.xml",
            "/opt/reference-idp/flows/authn/conditions/account-locked/account-locked-flow.xml",
            "/opt/reference-idp/flows/authn/conditions/expired-password/expired-password-flow.xml",
            "/opt/reference-idp/flows/authn/conditions/expiring-password/expiring-password-flow.xml"))&&inventory.size()==4);
        var operations=new JsonCodec().mapper().readTree(checked(folder,manifest,"operationsFile","operationsSha256"));
        require(operations.isArray());
        boolean prepared=false,restored=false;
        for(var operation:operations) {
            if("product-restart".equals(operation.path("operation").asText())) {
                require(operation.path("completed").asBoolean(false));
                var start=Instant.parse(text(operation,"recordedAt"));var end=Instant.parse(text(operation,"completedAt"));
                require(!end.isBefore(start));
                if(operation.path("label").asText().startsWith("prepare-")){require(!end.isAfter(first));prepared=true;}
                else {require(operation.path("label").asText().startsWith("restore-")&&!start.isBefore(last));restored=true;}
            }else if("product-config-write".equals(operation.path("operation").asText())) {
                var at=Instant.parse(text(operation,"recordedAt"));require(!at.isAfter(first)||!at.isBefore(last));
                require(operation.path("readBack").asBoolean(false));
            }
        }
        require(prepared&&restored);
    }
    private static void challenge(Path folder,JsonNode manifest,Exchange positive)throws Exception {
        var observation=new JsonCodec().mapper().readTree(checked(folder,manifest,"challengeFile","challengeSha256"));
        require("samlscope-native-authentication-challenge-v1".equals(text(observation,"schema")));
        var request=observation.path("request");var response=observation.path("response");
        require(positive.requestXml().getAttribute("ID").equals(text(request,"requestId"))
            &&positive.request().url().equals(text(request,"targetUrl"))
            &&positive.request().rawQuery().equals(text(request,"rawQuery")));
        require(positive.requestSha256().equals(text(request,"requestSha256")));
        var requested=Instant.parse(text(request,"observedAt"));var received=Instant.parse(text(response,"recordedAt"));
        require(!requested.isBefore(positive.request().timestamp())&&!received.isBefore(requested)
            &&!received.isAfter(positive.response().timestamp())&&response.path("status").asInt()==200);
        var uri=java.net.URI.create(text(response,"url"));var destination=java.net.URI.create(positive.requestXml().getAttribute("Destination"));
        require("http".equals(uri.getScheme())&&uri.getHost().equals(destination.getHost())&&uri.getPort()==destination.getPort()
            &&uri.getPath().equals(destination.getPath())&&uri.getRawQuery()!=null&&uri.getRawQuery().matches("execution=e[0-9]+s[0-9]+"));
        var body=new String(checked(folder,response,"bodyFile","bodySha256"),StandardCharsets.UTF_8);
        require(body.matches("(?is).*<input\\b(?=[^>]*\\btype\\s*=\\s*[\"']password[\"'])(?=[^>]*\\bname\\s*=\\s*[\"']j_password[\"'])[^>]*>.*")
            &&body.matches("(?is).*<input\\b[^>]*\\bname\\s*=\\s*[\"']j_username[\"'][^>]*>.*")
            &&!body.contains("SAMLResponse")&&!body.contains("<Assertion"));
        require(!java.util.regex.Pattern.compile("(?is)<input\\b(?=[^>]*\\bname\\s*=\\s*[\"'](?:j_password|password|j_username|username)[\"'])[^>]*\\bvalue\\s*=\\s*[\"'][^\"']+")
            .matcher(body).find());
        var form=java.util.regex.Pattern.compile("(?is)<form\\b[^>]*\\baction\\s*=\\s*[\"']([^\"']+)[\"'][^>]*>").matcher(body);
        boolean action=false;while(form.find())action|=uri.resolve(form.group(1).replace("&amp;","&")).equals(uri);require(action);
        var submissions=observation.path("credentialSubmissions");require(submissions.isArray()&&submissions.size()==1);
        var submission=submissions.get(0);require("POST".equals(text(submission,"method"))&&uri.toString().equals(text(submission,"targetUrl")));
        var submitted=Instant.parse(text(submission,"observedAt"));require(!submitted.isBefore(received)&&!submitted.isAfter(positive.response().timestamp()));
        var names=new HashSet<String>();for(var name:submission.path("fieldNames"))require(name.isTextual()&&names.add(name.asText()));
        require(names.containsAll(Set.of("j_username","j_password")));
    }
    private static void audit(String raw,Exchange exchange,String entity,String user,boolean success) {
        require(!user.isBlank());String marker="SAMLscope-identity-v1|";var matches=new ArrayList<String[]>();
        for(var line:raw.lines().toList()) {
            int offset=line.indexOf(marker);if(offset<0)continue;var fields=line.substring(offset).split("\\|",-1);
            if(fields.length==10&&exchange.requestXml().getAttribute("ID").equals(fields[1]))matches.add(fields);
        }
        require(matches.size()==1);var fields=matches.getFirst();require(entity.equals(fields[2])
                &&"http://shibboleth.net/ns/profiles/saml2/sso/browser".equals(fields[9]));
        if(success)require(user.equals(fields[3])&&"Success".equals(fields[5])&&("".equals(fields[4])||"proceed".equals(fields[4]))
                &&"authn/Password".equals(fields[6])&&"false".equals(fields[7]));
        else require(fields[3].isBlank()&&(fields[4].isBlank()||"NoPassive".equals(fields[4]))
                &&List.of("Requester","Responder").contains(fields[5])&&fields[7].isBlank());
    }
    private static byte[] raw(Path folder,String name)throws Exception {
        require(name.matches("[A-Za-z0-9][A-Za-z0-9._-]*"));var path=folder.resolve(name).normalize();
        require(path.getParent().equals(folder)&&Files.isRegularFile(path,LinkOption.NOFOLLOW_LINKS));return Files.readAllBytes(path);
    }
    private static byte[] checked(Path folder,JsonNode row,String name,String digest)throws Exception {
        var value=raw(folder,text(row,name));require(hash(value).equals(text(row,digest)));return value;
    }
    private static String text(JsonNode row,String key){var value=row.path(key);require(value.isTextual()&&!value.asText().isBlank());return value.asText();}
    private static String hash(byte[] raw)throws Exception{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(raw));}
    private static void require(boolean condition){if(!condition)throw new IllegalArgumentException("Unproven native authentication identity");}
}
