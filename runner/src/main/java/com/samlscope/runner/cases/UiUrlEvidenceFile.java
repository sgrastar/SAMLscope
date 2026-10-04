package com.samlscope.runner.cases;

import java.nio.file.*;
import java.security.MessageDigest;
import java.security.cert.*;
import java.time.Instant;
import java.util.*;
import com.fasterxml.jackson.databind.JsonNode;
import com.samlscope.core.caseexec.CaseContext;
import com.samlscope.core.evaluation.EvidenceRef;
import com.samlscope.core.transcript.*;
import com.samlscope.saml.crypto.XmlSignatureVerifier;
import com.samlscope.saml.normal.SecureXml;
import com.samlscope.store.JsonCodec;
import org.w3c.dom.Element;

/** Local-adapter evidence only. The current DOM collector cannot establish native nonuse. */
final class UiUrlEvidenceFile {
    private static final String MD="urn:oasis:names:tc:SAML:2.0:metadata", UI="urn:oasis:names:tc:SAML:metadata:ui",
            P="urn:oasis:names:tc:SAML:2.0:protocol", S="urn:oasis:names:tc:SAML:2.0:assertion", DS="http://www.w3.org/2000/09/xmldsig#";
    record Collected(List<UiUrlComparison.Sample> samples, List<String> issues) {}
    private final Path directory;
    UiUrlEvidenceFile(Path directory) { this.directory=directory.toAbsolutePath().normalize(); }

    Collected read(CaseContext context, byte[] target, TranscriptContentReader content) throws Exception {
        require(context.runId().matches("run_[0-9A-HJKMNP-TV-Z]{26}"));
        var path=directory.resolve(context.runId()+".json");
        if (!Files.exists(path,LinkOption.NOFOLLOW_LINKS)) return new Collected(List.of(),List.of("native_receipt_unavailable"));
        require(Files.isRegularFile(path,LinkOption.NOFOLLOW_LINKS)&&Files.size(path)<=4_194_304);
        var mapper=new JsonCodec().mapper(); var receipt=mapper.readTree(Files.readAllBytes(path));
        require("samlscope-native-ui-url-receipt-v1".equals(text(receipt,"schema")));
        require(context.runId().equals(text(receipt,"runId"))&&hash(target).equals(text(receipt,"targetMetadataSha256")));
        var targetRoot=SecureXml.parse(target).getDocumentElement();
        require(targetRoot.getAttribute("entityID").equals(text(receipt,"targetEntityId")));
        var endpoints=new HashSet<String>();
        for(var e:children(one(targetRoot,MD,"IDPSSODescriptor"),MD,"SingleSignOnService")) endpoints.add(e.getAttribute("Location"));
        var preparation=receipt.path("nativePreparation");
        require("local-adapter-verified".equals(text(preparation,"source"))&&preparation.path("restored").asBoolean(false));
        require(text(preparation,"propertiesSha256").matches("[0-9a-f]{64}")&&text(preparation,"templateSha256").matches("[0-9a-f]{64}"));
        require(preparation.path("templateUnchanged").asBoolean(false)&&"en-US".equals(text(preparation,"preferredLanguage")));
        var entries=new HashMap<String,TranscriptEntry>();
        for(var e:context.transcript().list(context.runId())) require(context.runId().equals(e.runId())&&entries.put(e.id(),e)==null);
        require(receipt.path("observations").isArray()&&receipt.path("observations").size()==15);
        var samples=new ArrayList<UiUrlComparison.Sample>(); var issues=new LinkedHashSet<String>();
        for(var row:receipt.path("observations")) {
            var variant=text(row,"variant"); require(variant.matches("ui-url-(logo|information|privacy)-(http|https|data|javascript|file)"));
            var parts=variant.split("-");
            var condition=new UiUrlComparison.Condition(UiUrlComparison.Element.valueOf(parts[2].toUpperCase(Locale.ROOT)),
                    UiUrlComparison.Scheme.valueOf(parts[3].toUpperCase(Locale.ROOT)));
            var request=entries.get(text(row,"requestReference")); var prepared=entries.get(text(row,"metadataReference"));
            var fetch=entries.get(text(row,"fetchReference")); require(request!=null&&prepared!=null&&fetch!=null);
            require(request.direction()==Direction.OUTBOUND&&prepared.direction()==Direction.OUTBOUND&&fetch.direction()==Direction.INBOUND);
            require("AuthnRequest".equals(request.samlSummary().get("type"))&&variant.equals(request.samlSummary().get("variant")));
            require("MetadataPrepared".equals(prepared.samlSummary().get("type"))&&variant.equals(prepared.samlSummary().get("variant")));
            require("MetadataFetch".equals(fetch.samlSummary().get("type"))&&variant.equals(fetch.samlSummary().get("variant")));
            require(fetch.id().equals(prepared.samlSummary().get("fetchTranscriptId")));
            var metadataRaw=content.readDecodedSaml(prepared); var requestRaw=content.readDecodedSaml(request);
            require(hash(metadataRaw).equals(text(row,"metadataSha256"))&&hash(requestRaw).equals(text(row,"requestSha256")));
            require(hash(metadataRaw).equals(prepared.samlSummary().get("metadataSha256")));
            var browserRaw=Base64.getDecoder().decode(text(row,"browserBase64")); require(hash(browserRaw).equals(text(row,"browserSha256")));
            var browser=mapper.readTree(browserRaw);
            require("samlscope-ui-consumer-observation-v1".equals(text(browser,"schema"))&&context.runId().equals(text(browser,"run_id")));
            require(variant.equals(text(browser,"condition"))&&hash(metadataRaw).equals(text(browser,"fixture_sha256")));
            require(Set.of("observed","not-observed").contains(text(browser,"status")));
            require(browser.path("url_absence_is_nonuse_proof").isBoolean()&&!browser.path("url_absence_is_nonuse_proof").asBoolean());
            require(!browser.path("url_assignment").path("nonuse_proven").asBoolean(false));
            // No caller-supplied decision can turn a DOM absence into verified nonuse.
            require(!row.has("use")&&!row.has("nativeNonuse")&&!row.has("outcome"));
            var sent=browser.path("browser_request");
            require("captured".equals(text(sent,"status"))&&hash(requestRaw).equals(text(sent,"decoded_sha256")));
            require(requestRaw.length==sent.path("decoded_bytes").asInt(-1)&&request.method().equals(text(sent,"method")));
            require("en-US".equals(text(sent,"accept_language"))&&"en-US".equals(text(browser,"preferred_language")));
            require(text(browser,"expected_path").equals(text(sent,"endpoint_path")));
            require(request.url().equals(text(browser,"expected_origin")+text(browser,"expected_path"))&&endpoints.contains(request.url()));
            require("observed".equals(text(browser.path("page_anchor"),"status"))&&"control".equals(text(browser.path("page_anchor"),"selected_candidate")));
            var metadata=SecureXml.parse(metadataRaw).getDocumentElement(); var authn=SecureXml.parse(requestRaw).getDocumentElement();
            require(MD.equals(metadata.getNamespaceURI())&&"EntityDescriptor".equals(metadata.getLocalName()));
            require(P.equals(authn.getNamespaceURI())&&"AuthnRequest".equals(authn.getLocalName()));
            require(request.url().equals(authn.getAttribute("Destination"))&&authn.getAttribute("ID").equals(request.samlSummary().get("id")));
            var entity=metadata.getAttribute("entityID"); require(!entity.isBlank()&&entity.equals(one(authn,S,"Issuer").getTextContent()));
            require(entries.values().stream().filter(e->e.direction()==Direction.OUTBOUND&&authn.getAttribute("ID").equals(e.samlSummary().get("id"))).count()==1);
            var role=one(metadata,MD,"SPSSODescriptor");
            var certNodes=role.getElementsByTagNameNS(DS,"X509Certificate");require(certNodes.getLength()>0);
            var cert=(X509Certificate)CertificateFactory.getInstance("X.509").generateCertificate(new java.io.ByteArrayInputStream(
                    Base64.getMimeDecoder().decode(certNodes.item(0).getTextContent())));
            var verifier=new XmlSignatureVerifier(); require(verifier.hasValidEnvelopedSignature(metadata,cert));
            if("POST".equals(request.method()))require(verifier.hasValidEnvelopedSignature(authn,cert));
            else require("GET".equals(request.method())&&new com.samlscope.saml.binding.RedirectSignatureVerifier().isValidForMessage(request.rawQuery(),cert,requestRaw));
            var info=one(one(role,MD,"Extensions"),UI,"UIInfo");
            var name=switch(condition.element()){case LOGO->"Logo";case INFORMATION->"InformationURL";case PRIVACY->"PrivacyStatementURL";};
            var candidate=one(info,UI,name).getTextContent(); require(parts[3].equals(java.net.URI.create(candidate).getScheme()));
            for(var other:List.of("Logo","InformationURL","PrivacyStatementURL")) require(children(info,UI,other).size()==(other.equals(name)?1:0));
            require(hash(mapper.writeValueAsBytes(new TreeMap<>(Map.of("probe",candidate)))).equals(text(browser,"candidate_mapping_sha256")));
            var observed=Instant.parse(text(browser,"observed_at"));
            require(Instant.parse(metadata.getAttribute("validUntil")).isAfter(observed));
            require(!prepared.timestamp().isBefore(fetch.timestamp())&&!request.timestamp().isBefore(prepared.timestamp()));
            var use=UiUrlComparison.Use.UNOBSERVED;
            if(condition.element()==UiUrlComparison.Element.LOGO) {
                require("logo".equals(text(browser,"kind"))&&"img.service-logo".equals(text(browser,"selector"))
                        &&"native-logo-slot".equals(text(browser,"url_selector_scope")));
                if("observed".equals(text(browser,"status"))&&"probe".equals(text(browser,"selected_candidate"))) use=UiUrlComparison.Use.USED;
            } else {
                require("link".equals(text(browser,"kind")));
                // A URL-matching selector does not establish the native element's semantic role.
                issues.add("native_link_scope_unproven:"+parts[2]);
            }
            var fixed=new TreeMap<String,Object>(); fixed.put("preparation",preparation);fixed.put("endpoint",request.url());
            fixed.put("metadata",fixedMetadata(metadata,variant,context.runId()));
            samples.add(new UiUrlComparison.Sample(context.runId(),entity,condition,hash(mapper.writeValueAsBytes(fixed)),hash(metadataRaw),
                    request.timestamp(),observed,use,List.of(new EvidenceRef("transcript",fetch.id()),new EvidenceRef("transcript",prepared.id()),
                    new EvidenceRef("transcript",request.id()),new EvidenceRef("browser-observation",context.runId()+".json#"+hash(browserRaw)))));
        }
        return new Collected(List.copyOf(samples),List.copyOf(issues));
    }
    private static Object fixedMetadata(Element original,String variant,String run) {
        var root=(Element)original.cloneNode(true); root.removeAttribute("validUntil");
        for(var sig:children(root,DS,"Signature"))root.removeChild(sig);
        var info=one(one(one(root,MD,"SPSSODescriptor"),MD,"Extensions"),UI,"UIInfo");
        for(var name:List.of("Logo","InformationURL","PrivacyStatementURL"))for(var e:children(info,UI,name))info.removeChild(e);
        return structural(root,variant,run);
    }
    private static Object structural(Element element,String variant,String run) {
        var attrs=new TreeMap<String,String>(); var nodes=new ArrayList<Object>();
        for(int i=0;i<element.getAttributes().getLength();i++) {
            var a=element.getAttributes().item(i); if("http://www.w3.org/2000/xmlns/".equals(a.getNamespaceURI()))continue;
            var value=a.getNodeValue();
            if(Set.of("Location","ResponseLocation").contains(a.getLocalName())) {
                var uri=java.net.URI.create(value);require(uri.getRawQuery()!=null&&uri.getFragment()==null);
                var pairs=Arrays.asList(uri.getRawQuery().split("&",-1));
                require(pairs.stream().filter(p->p.startsWith("mdv=")).toList().equals(List.of("mdv="+variant))
                        &&pairs.stream().filter(p->p.startsWith("run=")).toList().equals(List.of("run="+run)));
                value=value.replace("mdv="+variant,"mdv=ui-url-comparison");
            }
            attrs.put(Objects.toString(a.getNamespaceURI(),"")+":"+a.getLocalName(),value);
        }
        for(var child=element.getFirstChild();child!=null;child=child.getNextSibling()) {
            if(child instanceof Element e)nodes.add(structural(e,variant,run));
            else if(child.getNodeValue()!=null&&!child.getNodeValue().isBlank())nodes.add(child.getNodeValue());
        }
        return List.of(Objects.toString(element.getNamespaceURI(),""),element.getLocalName(),attrs,nodes);
    }
    private static List<Element> children(Element e,String ns,String name){return MetadataAlgorithmEvidence.children(e,ns,name);}
    private static Element one(Element e,String ns,String name){var list=children(e,ns,name);require(list.size()==1);return list.getFirst();}
    private static String text(JsonNode n,String key){return n.path(key).asText("");}
    private static String hash(byte[] raw)throws Exception{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(raw));}
    private static void require(boolean b){if(!b)throw new IllegalArgumentException("Unbound native UI URL evidence");}
}
