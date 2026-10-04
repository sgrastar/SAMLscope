package com.samlscope.runner.cases;

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
import com.samlscope.saml.binding.RedirectSignatureVerifier;
import com.samlscope.saml.normal.SecureXml;
import com.samlscope.store.JsonCodec;
import org.w3c.dom.Element;

/** Two fresh native SSP peers; the identifying uid comes from verified Assertions, never a receipt claim. */
final class SimpleSamlPhpPersistentPairwiseEvidence {
    static final String SCHEMA="samlscope-simplesamlphp-persistent-pairwise-v1";
    private static final String P="urn:oasis:names:tc:SAML:2.0:protocol", S="urn:oasis:names:tc:SAML:2.0:assertion";
    private static final String MD="urn:oasis:names:tc:SAML:2.0:metadata", DS="http://www.w3.org/2000/09/xmldsig#";
    private static final String FORMAT="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent";
    private static final String RUN="run_[0-9A-HJKMNP-TV-Z]{26}";
    private static final String TARGET="http://localhost:18380/idp";
    private final Path directory;
    private final TranscriptContentReader content;
    private final Function<String,byte[]> metadata;

    SimpleSamlPhpPersistentPairwiseEvidence(Path directory,TranscriptContentReader content,Function<String,byte[]> metadata) {
        this.directory=Objects.requireNonNull(directory).toAbsolutePath().normalize();
        this.content=Objects.requireNonNull(content);this.metadata=Objects.requireNonNull(metadata);
    }

    Optional<CaseOutcome> evaluate(CaseContext context) {
        try {
            require(context.transcriptComplete()&&context.runId().matches(RUN));
            var folder=directory.resolve(context.runId()).normalize();require(folder.getParent().equals(directory)&&Files.isDirectory(folder,LinkOption.NOFOLLOW_LINKS));
            var manifest=new JsonCodec().mapper().readTree(original(folder,"manifest.json"));
            require(SCHEMA.equals(text(manifest,"schema"))&&context.runId().equals(text(manifest,"runId")));
            var targetRaw=metadata.apply(context.runId());require(hash(targetRaw).equals(text(manifest,"targetMetadataSha256")));
            var target=SecureXml.parse(targetRaw).getDocumentElement();
            require(MD.equals(target.getNamespaceURI())&&"EntityDescriptor".equals(target.getLocalName())&&TARGET.equals(target.getAttribute("entityID")));
            var trusted=MetadataAlgorithmEvidence.signingKeys(target);require(!trusted.isEmpty());
            var peers=manifest.path("peers");require(peers.isArray()&&peers.size()==2);
            var observations=new ArrayList<Peer>();var evidence=new LinkedHashSet<EvidenceRef>();
            var allRequests=new HashSet<String>();
            for(var peer:peers) {
                var run=text(peer,"runId");require(run.matches(RUN)&&Arrays.equals(targetRaw,metadata.apply(run)));
                var entity=text(peer,"entityId");
                var created=new JsonCodec().mapper().readTree(checked(folder,peer,"createdFile","createdSha256")).path("run");
                require(run.equals(text(created,"id"))&&entity.equals("http://localhost:18080/p/"+text(created,"planId")));
                var spRaw=checked(folder,peer,"metadataFile","metadataSha256");var sp=SecureXml.parse(spRaw).getDocumentElement();
                require(MD.equals(sp.getNamespaceURI())&&"EntityDescriptor".equals(sp.getLocalName())&&entity.equals(sp.getAttribute("entityID")));
                require(children(sp,MD,"AffiliationDescriptor").isEmpty());
                var roles=children(sp,MD,"SPSSODescriptor");require(roles.size()==1);var role=roles.getFirst();
                require(Arrays.asList(role.getAttribute("protocolSupportEnumeration").split("\\s+")).contains(P));
                var requestKeys=new ArrayList<X509Certificate>();
                for(var descriptor:children(role,MD,"KeyDescriptor")) {
                    if(!List.of("","signing").contains(descriptor.getAttribute("use")))continue;
                    var certs=descriptor.getElementsByTagNameNS(DS,"X509Certificate");
                    for(int i=0;i<certs.getLength();i++)requestKeys.add((X509Certificate)CertificateFactory.getInstance("X.509")
                        .generateCertificate(new java.io.ByteArrayInputStream(Base64.getMimeDecoder().decode(certs.item(i).getTextContent()))));
                }
                require(!requestKeys.isEmpty());
                var entries=new HashMap<String,TranscriptEntry>();
                for(var entry:context.transcript().list(run))require(run.equals(entry.runId())&&entries.put(entry.id(),entry)==null);
                var exchanges=peer.path("exchanges");require(exchanges.isArray()&&exchanges.size()==2);
                String uid=null;var names=new ArrayList<Element>();Instant first=null,last=null;
                for(var exchange:exchanges) {
                    var request=entry(entries,text(exchange,"requestReference"),Direction.OUTBOUND);
                    var response=entry(entries,text(exchange,"responseReference"),Direction.INBOUND);
                    var requestRaw=content.readDecodedSaml(request);var xml=SecureXml.parse(requestRaw).getDocumentElement();
                    require(P.equals(xml.getNamespaceURI())&&"AuthnRequest".equals(xml.getLocalName()));
                    var id=xml.getAttribute("ID");require(!id.isBlank()&&allRequests.add(id)&&id.equals(request.correlationId()));
                    require(children(xml,S,"Issuer").size()==1&&entity.equals(children(xml,S,"Issuer").getFirst().getTextContent()));
                    require(children(xml,P,"Subject").isEmpty()&&children(xml,S,"Subject").isEmpty());
                    // Verify the raw Redirect bytes and the exact deflated XML together.
                    require("GET".equals(request.method())&&requestKeys.stream().anyMatch(k->new RedirectSignatureVerifier()
                        .isValidForMessage(request.rawQuery(),k,requestRaw)));
                    var recipient=xml.getAttribute("AssertionConsumerServiceURL");
                    require(!recipient.isBlank()&&children(role,MD,"AssertionConsumerService").stream().anyMatch(a->recipient.equals(a.getAttribute("Location"))));
                    require(!request.timestamp().isAfter(response.timestamp())&&response.url().equals(recipient)
                        &&Boolean.TRUE.equals(response.samlSummary().get("normalFlowAccepted")));
                    require(entries.values().stream().filter(e->e.direction()==Direction.OUTBOUND&&id.equals(e.correlationId())).count()==1);
                    require(entries.values().stream().filter(e->e.direction()==Direction.INBOUND&&id.equals(e.samlSummary().get("inResponseTo"))).count()==1);
                    var responseXml=SecureXml.parse(content.readDecodedSaml(response)).getDocumentElement();
                    require(children(responseXml,S,"EncryptedAssertion").isEmpty());
                    var assertion=VerifiedResponseAssertion.read(responseXml,TARGET,trusted,sp,Optional.empty(),id,recipient);
                    var subject=children(assertion,S,"Subject");require(subject.size()==1);var name=children(subject.getFirst(),S,"NameID");
                    require(name.size()==1&&FORMAT.equals(name.getFirst().getAttribute("Format"))&&!name.getFirst().getTextContent().isBlank());
                    var values=new ArrayList<String>();
                    for(var statement:children(assertion,S,"AttributeStatement"))for(var attribute:children(statement,S,"Attribute")) {
                        if(!"uid".equals(attribute.getAttribute("Name")))continue;
                        for(var value:children(attribute,S,"AttributeValue"))values.add(value.getTextContent());
                    }
                    require(values.size()==1&&!values.getFirst().isBlank()&&(uid==null||uid.equals(values.getFirst())));
                    uid=values.getFirst();names.add(name.getFirst());
                    first=first==null||request.timestamp().isBefore(first)?request.timestamp():first;
                    last=last==null||response.timestamp().isAfter(last)?response.timestamp():last;
                    evidence.add(new EvidenceRef("transcript","transcript:"+request.id()));evidence.add(new EvidenceRef("transcript","transcript:"+response.id()));
                }
                observations.add(new Peer(run,entity,uid,names,first,last));
            }
            require(context.runId().equals(observations.get(0).run)&&!observations.get(0).run.equals(observations.get(1).run)
                &&!observations.get(0).entity.equals(observations.get(1).entity)&&observations.get(0).uid.equals(observations.get(1).uid));
            configuration(folder,manifest,observations);
            // This adapter proves only the controlled successful conjunction; uncertain histories/affiliations cannot produce a FAIL.
            for(var peer:observations)for(var name:peer.names) {
                require(!name.hasAttribute("NameQualifier")||TARGET.equals(name.getAttribute("NameQualifier")));
                require(!name.hasAttribute("SPNameQualifier")||peer.entity.equals(name.getAttribute("SPNameQualifier")));
                require(!name.hasAttribute("SPProvidedID"));
                require(peer.names.getFirst().getTextContent().equals(name.getTextContent()));
            }
            for(var left:observations.get(0).names)for(var right:observations.get(1).names)require(!left.getTextContent().equals(right.getTextContent()));
            return Optional.of(new CaseOutcome(Outcome.SATISFIED,null,"idp.persistent-pairwise.observed","case.idp.persistent-pairwise.observed",
                List.copyOf(evidence),Map.of("adapter","simplesamlphp-native-persistent-pairwise","peer_count",2,
                    "same_principal_proven",true,"principal_source","signed-identifying-uid","secondary_run",observations.get(1).run)));
        }catch(Exception unproven){return Optional.empty();}
    }

    private void configuration(Path folder,JsonNode manifest,List<Peer> peers)throws Exception {
        for(var name:List.of("hosted","remote","salt")) {
            var row=manifest.path("restoration").path(name);
            require(Arrays.equals(checked(folder,row,"originalFile","originalSha256"),checked(folder,row,"finalFile","finalSha256")));
        }
        require("f0e71a95f229ba3c361f1314f4d5a8c2692f363e456ac099738f28d0d8837e43".equals(hash(original(folder,"native-persistent-filter.php")))
            &&"85ac4708eb8324f9e700fa8e8c09f6c33fa40eaab16fc35bc3e31f46423b0fdd".equals(hash(original(folder,"native-base-generator.php")))
            &&"8465e71fabec88578369eaf780dfe86c6ab3f0f2cdf4b24eb52bf134918f9b48".equals(hash(original(folder,"native-userpass.php")))
            &&"5e47c4c79f5d6cb7b3503f5554fdf4d85e7d3ffac30de1e1cb47358e1add1e7d".equals(hash(original(folder,"native-readback-command.php"))));
        // Bind the executable native setting bytes as well as the product read-back JSON.
        var hostOriginal=original(folder,"hosted-original.php");
        require("559eeba5e28f145f0b0bd9ee8c1c147b155babe73d7c19809affdd2147ce8e49".equals(hash(hostOriginal)));
        var expectedHost=new String(hostOriginal,StandardCharsets.UTF_8)+"\n$metadata['"+TARGET+"'][\"authproc\"] = [20 => [\"class\" => 'saml:PersistentNameID', \"identifyingAttribute\" => \"uid\"]];\n"
            +"$metadata['"+TARGET+"'][\"NameIDFormat\"] = ['"+FORMAT+"'];\n\n";
        require(Arrays.equals(expectedHost.getBytes(StandardCharsets.UTF_8),original(folder,"hosted-configured.php")));
        var remoteOriginal=original(folder,"remote-original.php");var expectedRemote=new StringBuilder(new String(remoteOriginal,StandardCharsets.UTF_8)).append('\n');
        for(int i=0;i<peers.size();i++) {
            var parsed=new JsonCodec().mapper().readTree(original(folder,(i==0?"primary":"secondary")+"-parser.json"));
            require(peers.get(i).entity.equals(text(parsed,"entity_id"))&&parsed.path("validate_authnrequest").asBoolean(false));
            require(!new String(remoteOriginal,StandardCharsets.UTF_8).contains(peers.get(i).entity));
            if(i>0)expectedRemote.append('\n');expectedRemote.append(text(parsed,"php"));
        }
        expectedRemote.append('\n');require(Arrays.equals(expectedRemote.toString().getBytes(StandardCharsets.UTF_8),original(folder,"remote-configured.php")));
        var backs=manifest.path("readBacks");require(backs.isArray()&&backs.size()==4);var seen=new HashSet<String>();String salt=null,authHash=null,principal=null;
        for(var back:backs) {
            var phase=text(back,"phase");require(seen.add(phase));var nativeConfig=new JsonCodec().mapper().readTree(checked(folder,back,"file","sha256"));
            var peer=peers.get(phase.startsWith("primary-")?0:1);var at=Instant.parse(text(back,"recordedAt"));
            if(phase.endsWith("-before"))require(!at.isAfter(peer.first));else require(phase.endsWith("-after")&&!at.isBefore(peer.last));
            require(TARGET.equals(text(nativeConfig,"entityId"))&&nativeConfig.path("hostedNameIDFormat").size()==1
                &&FORMAT.equals(nativeConfig.path("hostedNameIDFormat").get(0).asText()));
            var filter=nativeConfig.path("hostedAuthproc");require(filter.isObject()&&filter.size()==1);
            require("saml:PersistentNameID".equals(text(filter.path("20"),"class"))&&"uid".equals(text(filter.path("20"),"identifyingAttribute"))&&filter.path("20").size()==2);
            var global=nativeConfig.path("globalAuthproc");require(global.isObject()&&global.size()==3
                &&"core:LanguageAdaptor".equals(global.path("30").asText())&&"core:AttributeLimit".equals(global.path("50").asText())
                &&"core:LanguageAdaptor".equals(global.path("99").asText()));
            var value=text(nativeConfig,"saltSha256");require(value.matches("[0-9a-f]{64}")&&(salt==null||salt.equals(value)));salt=value;
            var auth=nativeConfig.path("authenticationSource");
            require("example-userpass".equals(text(auth,"id"))&&"exampleauth:UserPass".equals(text(auth,"class"))&&auth.path("authproc").isNull());
            var authOriginalHash=text(auth,"originalSha256");require(authOriginalHash.matches("[0-9a-f]{64}")&&(authHash==null||authHash.equals(authOriginalHash)));authHash=authOriginalHash;
            var matched=uniquePrincipal(auth.path("users"),peer.uid);
            require(principal==null||principal.equals(matched));principal=matched;
            var remote=nativeConfig.path("peers");require(remote.isObject()&&remote.size()==2);
            for(var member:peers)require(remote.path(member.entity).isObject()&&remote.path(member.entity).path("authproc").isMissingNode()
                &&remote.path(member.entity).path("validate.authnrequest").asBoolean(false));
            for(var kind:List.of("hosted","remote")) {
                var data=checked(folder,back,kind+"File",kind+"Sha256");
                require(Arrays.equals(data,original(folder,kind+"-configured.php")));
            }
        }
        require(seen.equals(Set.of("primary-before","primary-after","secondary-before","secondary-after")));
    }

    private record Peer(String run,String entity,String uid,List<Element> names,Instant first,Instant last){}
    static String uniquePrincipal(JsonNode users,String uid) {
        require(users.isArray()&&users.size()>0);var uids=new HashSet<String>();var principals=new HashSet<String>();String matched=null;
        for(var user:users) {
            var identity=user.path("principal");require(identity.isTextual()&&!identity.asText().isBlank());var attributes=user.path("uid");
            require(attributes.isArray()&&attributes.size()==1&&attributes.get(0).isTextual());
            var identifying=attributes.get(0).asText();require(!identifying.isBlank()&&uids.add(identifying)&&principals.add(identity.asText()));
            if(uid.equals(identifying))matched=identity.asText();
        }
        require(matched!=null);return matched;
    }
    private TranscriptEntry entry(Map<String,TranscriptEntry> entries,String id,Direction direction) {
        var e=entries.get(id);require(e!=null&&e.direction()==direction&&e.decodedSamlRef()!=null);return e;
    }
    private byte[] checked(Path folder,JsonNode object,String file,String sha)throws Exception {
        var raw=original(folder,text(object,file));require(hash(raw).equals(text(object,sha)));return raw;
    }
    private byte[] original(Path folder,String name)throws Exception {
        var path=folder.resolve(name).normalize();require(path.getParent().equals(folder)&&Files.isRegularFile(path,LinkOption.NOFOLLOW_LINKS)&&Files.size(path)<=4_194_304);return Files.readAllBytes(path);
    }
    private String text(JsonNode n,String key){var v=n.path(key);require(v.isTextual()&&!v.asText().isBlank());return v.asText();}
    private static String hash(byte[] raw)throws Exception{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(raw));}
    private static List<Element> children(Element e,String ns,String name){return MetadataAlgorithmEvidence.children(e,ns,name);}
    private static void require(boolean value){if(!value)throw new IllegalArgumentException("Unproven native pairwise evidence");}
}
