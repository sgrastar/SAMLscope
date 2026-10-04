package com.samlscope.runner.cases;

import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.*;
import com.fasterxml.jackson.databind.JsonNode;
import com.samlscope.core.caseexec.CaseContext;
import com.samlscope.core.evaluation.EvidenceRef;
import com.samlscope.core.transcript.*;
import com.samlscope.saml.normal.SecureXml;
import com.samlscope.store.JsonCodec;
import org.w3c.dom.Element;

/** Trusted local-adapter receipt. No HTTP upload path; browser evidence is not a target signature. */
final class UiDisplayEvidenceFile {
    private static final String MD = "urn:oasis:names:tc:SAML:2.0:metadata";
    private static final String UI = "urn:oasis:names:tc:SAML:metadata:ui";
    private static final String XML = "http://www.w3.org/XML/1998/namespace";
    private final Path directory;
    UiDisplayEvidenceFile(Path directory) { this.directory = directory.toAbsolutePath().normalize(); }

    List<UiDisplayComparison.Sample> read(CaseContext context, byte[] target, TranscriptContentReader content) throws Exception {
        require(context.runId().matches("run_[0-9A-HJKMNP-TV-Z]{26}"));
        var path = directory.resolve(context.runId() + ".json");
        if (!Files.exists(path, LinkOption.NOFOLLOW_LINKS)) return List.of();
        require(Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS) && Files.size(path) <= 1_048_576);
        var mapper = new JsonCodec().mapper();
        var receipt = mapper.readTree(Files.readAllBytes(path));
        require("samlscope-native-ui-display-receipt-v1".equals(text(receipt, "schema")));
        require(context.runId().equals(text(receipt, "runId")) && hash(target).equals(text(receipt, "targetMetadataSha256")));
        var targetRoot = SecureXml.parse(target).getDocumentElement();
        require(targetRoot.getAttribute("entityID").equals(text(receipt, "targetEntityId")));
        var endpoints = new HashSet<String>();
        for (var endpoint : children(one(targetRoot, MD, "IDPSSODescriptor"), MD, "SingleSignOnService")) {
            endpoints.add(endpoint.getAttribute("Location"));
        }
        var preparation = receipt.path("nativePreparation");
        require("local-adapter-verified".equals(text(preparation, "source")) && preparation.path("restored").asBoolean(false));
        require(text(preparation, "propertiesSha256").matches("[0-9a-f]{64}"));
        require("en-US".equals(text(preparation, "preferredLanguage")));
        require(text(preparation, "templateSha256").matches("[0-9a-f]{64}")
                && preparation.path("templateUnchanged").asBoolean(false));
        var entries = new HashMap<String, TranscriptEntry>();
        for (var entry : context.transcript().list(context.runId())) {
            require(context.runId().equals(entry.runId()) && entries.put(entry.id(), entry) == null);
        }
        require(receipt.path("observations").isArray() && receipt.path("observations").size() == 3);
        var samples = new ArrayList<UiDisplayComparison.Sample>();
        for (var row : receipt.path("observations")) {
            var variant = text(row, "variant");
            var condition = switch (variant) {
                case "ui-consumer-display-all" -> UiDisplayComparison.Condition.ALL;
                case "ui-consumer-display-service" -> UiDisplayComparison.Condition.SERVICE;
                case "ui-consumer-display-entity" -> UiDisplayComparison.Condition.ENTITY;
                default -> throw new IllegalArgumentException("Unknown UI condition");
            };
            var request = entries.get(text(row, "requestReference"));
            var prepared = entries.get(text(row, "metadataReference"));
            var fetch = entries.get(text(row, "fetchReference"));
            require(request != null && prepared != null && fetch != null);
            for (var type : List.of("AuthnRequest", "MetadataPrepared", "MetadataFetch")) {
                require(entries.values().stream().filter(e -> type.equals(e.samlSummary().get("type"))
                        && variant.equals(e.samlSummary().get("variant"))).count() == 1);
            }
            require(request.direction() == Direction.OUTBOUND && prepared.direction() == Direction.OUTBOUND && fetch.direction() == Direction.INBOUND);
            require("AuthnRequest".equals(request.samlSummary().get("type")) && variant.equals(request.samlSummary().get("variant")));
            require("MetadataPrepared".equals(prepared.samlSummary().get("type")) && variant.equals(prepared.samlSummary().get("variant")));
            require("MetadataFetch".equals(fetch.samlSummary().get("type")) && variant.equals(fetch.samlSummary().get("variant")));
            require(fetch.id().equals(prepared.samlSummary().get("fetchTranscriptId")));
            var metadataRaw = content.readDecodedSaml(prepared);
            var requestRaw = content.readDecodedSaml(request);
            require(hash(metadataRaw).equals(text(row, "metadataSha256")) && hash(requestRaw).equals(text(row, "requestSha256")));
            var browserRaw = Base64.getDecoder().decode(text(row, "browserBase64"));
            require(hash(browserRaw).equals(text(row, "browserSha256")));
            var browser = mapper.readTree(browserRaw);
            require("samlscope-ui-consumer-observation-v1".equals(text(browser, "schema")) && "display-name".equals(text(browser, "kind")));
            require(context.runId().equals(text(browser, "run_id")) && variant.equals(text(browser, "condition")));
            require(Set.of("observed", "not-observed").contains(text(browser, "status"))
                    && hash(metadataRaw).equals(text(browser, "fixture_sha256")));
            require("header h1".equals(text(browser, "selector")));
            var sent = browser.path("browser_request");
            require("captured".equals(text(sent, "status")) && hash(requestRaw).equals(text(sent, "decoded_sha256")));
            require(requestRaw.length == sent.path("decoded_bytes").asInt(-1) && request.method().equals(text(sent, "method")));
            require(text(sent, "accept_language").equals(text(preparation, "preferredLanguage"))
                    && text(browser, "preferred_language").equals(text(preparation, "preferredLanguage")));
            require(text(browser, "expected_path").equals(text(sent, "endpoint_path")));
            require(request.url().equals(text(browser, "expected_origin") + text(browser, "expected_path")) && endpoints.contains(request.url()));
            var metadata = SecureXml.parse(metadataRaw).getDocumentElement();
            var authn = SecureXml.parse(requestRaw).getDocumentElement();
            require(MD.equals(metadata.getNamespaceURI()) && "EntityDescriptor".equals(metadata.getLocalName()));
            require("urn:oasis:names:tc:SAML:2.0:protocol".equals(authn.getNamespaceURI()) && "AuthnRequest".equals(authn.getLocalName()));
            require(request.url().equals(authn.getAttribute("Destination")) && authn.getAttribute("ID").equals(request.samlSummary().get("id")));
            var entity = metadata.getAttribute("entityID");
            require(entity.equals(one(authn, "urn:oasis:names:tc:SAML:2.0:assertion", "Issuer").getTextContent()));
            var role = one(metadata, MD, "SPSSODescriptor");
            var displays = descendants(role, UI, "DisplayName");
            var services = descendants(role, MD, "ServiceName");
            require(displays.size() == (condition == UiDisplayComparison.Condition.ALL ? 1 : 0));
            require(services.size() == (condition == UiDisplayComparison.Condition.ENTITY ? 0 : 1));
            if (!displays.isEmpty()) {
                require(displays.getFirst().getParentNode() == one(one(role, MD, "Extensions"), UI, "UIInfo"));
            }
            var candidates = new TreeMap<String, String>();
            candidates.put("entity", "Login to " + entity);
            var hosts = new HashSet<String>();
            for (var acs : children(role, MD, "AssertionConsumerService")) {
                hosts.add(java.net.URI.create(acs.getAttribute("Location")).getHost());
            }
            require(hosts.size() == 1 && !hosts.contains(null));
            candidates.put("hostname", "Login to " + hosts.iterator().next());
            if (!displays.isEmpty()) candidates.put("display", name(displays.getFirst()));
            if (!services.isEmpty()) candidates.put("service", name(services.getFirst()));
            require(new HashSet<>(candidates.values()).size() == candidates.size());
            require(hash(mapper.writeValueAsBytes(candidates)).equals(text(browser, "candidate_mapping_sha256")));
            var observed = Instant.parse(text(browser, "observed_at"));
            require(Instant.parse(metadata.getAttribute("validUntil")).isAfter(observed));
            require(!prepared.timestamp().isBefore(fetch.timestamp()) && !request.timestamp().isBefore(prepared.timestamp()));
            var fixed = new TreeMap<String, String>();
            fixed.put("preparation", preparation.toString()); fixed.put("entity", entity);
            fixed.put("selector", text(browser, "selector")); fixed.put("endpoint", request.url());
            fixed.put("metadata", mapper.writeValueAsString(fixedMetadata(metadata, variant, context.runId())));
            var selection = UiDisplayComparison.Selection.UNOBSERVED;
            if ("observed".equals(text(browser, "status"))) {
                var token = text(browser, "selected_candidate");
                require(candidates.containsKey(token));
                selection = UiDisplayComparison.Selection.valueOf(token.toUpperCase(Locale.ROOT));
            } else require(!browser.has("selected_candidate"));
            samples.add(new UiDisplayComparison.Sample(context.runId(), entity, condition, hash(mapper.writeValueAsBytes(fixed)),
                    hash(metadataRaw), services.isEmpty() ? null : name(services.getFirst()),
                    request.timestamp(), observed, selection,
                    List.of(new EvidenceRef("transcript", fetch.id()), new EvidenceRef("transcript", prepared.id()),
                            new EvidenceRef("transcript", request.id()), new EvidenceRef("browser-observation", context.runId() + ".json#" + hash(browserRaw)))));
        }
        return samples;
    }

    private static String name(Element element) {
        require("en".equals(element.getAttributeNS(XML, "lang")) && !element.getTextContent().isBlank());
        require(childrenAny(element).isEmpty());
        for (int i = 0; i < element.getAttributes().getLength(); i++) {
            var attr = element.getAttributes().item(i);
            require("http://www.w3.org/2000/xmlns/".equals(attr.getNamespaceURI())
                    || XML.equals(attr.getNamespaceURI()) && "lang".equals(attr.getLocalName()));
        }
        return ("Login to " + element.getTextContent()).trim().replaceAll("\\s+", " ");
    }

    /** Structural fingerprint; keep keys and policy, normalize only defined experiment changes. */
    static Object fixedMetadata(Element original, String variant, String run) {
        var metadata = (Element) original.cloneNode(true);
        metadata.removeAttribute("validUntil");
        final String ds = "http://www.w3.org/2000/09/xmldsig#";
        for (var signature : children(metadata, ds, "Signature")) {
            for (var value : descendants(signature, ds, "DigestValue")) value.setTextContent("variable-signature-value");
            for (var value : descendants(signature, ds, "SignatureValue")) value.setTextContent("variable-signature-value");
        }
        var role = one(metadata, MD, "SPSSODescriptor");
        for (var service : children(role, MD, "AttributeConsumingService")) {
            require(service.getAttributes().getLength() == 2 && "0".equals(service.getAttribute("index"))
                    && "true".equals(service.getAttribute("isDefault")) && childrenAny(service).size() == 2);
            one(service, MD, "ServiceName");
            var attribute = one(service, MD, "RequestedAttribute");
            require(attribute.getAttributes().getLength() == 2 && childrenAny(attribute).isEmpty()
                    && "urn:oid:0.9.2342.19200300.100.1.1".equals(attribute.getAttribute("Name"))
                    && "false".equals(attribute.getAttribute("isRequired")));
            role.removeChild(service);
        }
        for (var extension : children(role, MD, "Extensions")) {
            for (var info : children(extension, UI, "UIInfo")) {
                for (var display : children(info, UI, "DisplayName")) info.removeChild(display);
                if (childrenAny(info).isEmpty() && info.getTextContent().isBlank()) extension.removeChild(info);
            }
            if (childrenAny(extension).isEmpty() && extension.getTextContent().isBlank()) role.removeChild(extension);
        }
        return structural(metadata, variant, run);
    }

    private static Object structural(Element element, String variant, String run) {
        var attributes = new TreeMap<String, String>();
        for (int i = 0; i < element.getAttributes().getLength(); i++) {
            var attribute = element.getAttributes().item(i);
            if ("http://www.w3.org/2000/xmlns/".equals(attribute.getNamespaceURI())) continue;
            var value = attribute.getNodeValue();
            if (Set.of("Location", "ResponseLocation").contains(attribute.getLocalName())) {
                var uri = java.net.URI.create(value);
                require(uri.getRawQuery() != null && uri.getFragment() == null);
                var pairs = Arrays.asList(uri.getRawQuery().split("&", -1));
                require(pairs.stream().filter(p -> p.startsWith("mdv=")).toList().equals(List.of("mdv=" + variant))
                        && pairs.stream().filter(p -> p.startsWith("run=")).toList().equals(List.of("run=" + run)));
                value = value.replace("mdv=" + variant, "mdv=display-comparison");
            }
            attributes.put(Objects.toString(attribute.getNamespaceURI(), "") + ":" + attribute.getLocalName(), value);
        }
        var children = new ArrayList<Object>();
        for (var child = element.getFirstChild(); child != null; child = child.getNextSibling()) {
            if (child instanceof Element e) children.add(structural(e, variant, run));
            else if (child.getNodeValue() != null && !child.getNodeValue().isBlank()) children.add(child.getNodeValue());
        }
        return List.of(Objects.toString(element.getNamespaceURI(), ""), element.getLocalName(), attributes, children);
    }

    private static List<Element> descendants(Element parent, String ns, String name) {
        var result = new ArrayList<Element>(); var nodes = parent.getElementsByTagNameNS(ns, name);
        for (int i = 0; i < nodes.getLength(); i++) result.add((Element) nodes.item(i));
        return result;
    }
    private static List<Element> childrenAny(Element parent) {
        var result = new ArrayList<Element>();
        for (var child = parent.getFirstChild(); child != null; child = child.getNextSibling()) if (child instanceof Element e) result.add(e);
        return result;
    }

    private static List<Element> children(Element parent, String ns, String name) {
        var result = new ArrayList<Element>();
        for (var child = parent.getFirstChild(); child != null; child = child.getNextSibling()) {
            if (child instanceof Element e && ns.equals(e.getNamespaceURI()) && name.equals(e.getLocalName())) result.add(e);
        }
        return result;
    }
    private static Element one(Element parent, String ns, String name) {
        var values = children(parent, ns, name); require(values.size() == 1); return values.getFirst();
    }
    private static String text(JsonNode node, String field) { return node.path(field).asText(""); }
    private static String hash(byte[] raw) throws Exception { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(raw)); }
    private static void require(boolean value) { if (!value) throw new IllegalArgumentException("Unbound UI evidence"); }
}
