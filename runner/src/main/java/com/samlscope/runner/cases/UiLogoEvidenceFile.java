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
final class UiLogoEvidenceFile {
    private static final String MD = "urn:oasis:names:tc:SAML:2.0:metadata";
    private static final String UI = "urn:oasis:names:tc:SAML:metadata:ui";
    private static final String XML = "http://www.w3.org/XML/1998/namespace";
    private final Path directory;
    UiLogoEvidenceFile(Path directory) { this.directory = directory.toAbsolutePath().normalize(); }

    List<UiLogoComparison.Sample> read(CaseContext context, byte[] target, TranscriptContentReader content) throws Exception {
        require(context.runId().matches("run_[0-9A-HJKMNP-TV-Z]{26}"));
        var path = directory.resolve(context.runId() + ".json");
        if (!Files.exists(path, LinkOption.NOFOLLOW_LINKS)) return List.of();
        require(Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS) && Files.size(path) <= 1_048_576);
        var mapper = new JsonCodec().mapper();
        var receipt = mapper.readTree(Files.readAllBytes(path));
        require("samlscope-native-ui-logo-receipt-v1".equals(text(receipt, "schema")));
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
        var preferred = Locale.LanguageRange.parse(text(preparation, "preferredLanguage"));
        var fallback = new ArrayList<Locale.LanguageRange>();
        require(preparation.path("fallbackLanguages").isArray());
        for (var language : preparation.path("fallbackLanguages")) fallback.addAll(Locale.LanguageRange.parse(language.asText()));
        var entries = new HashMap<String, TranscriptEntry>();
        for (var entry : context.transcript().list(context.runId())) {
            require(context.runId().equals(entry.runId()) && entries.put(entry.id(), entry) == null);
        }
        require(receipt.path("observations").isArray() && receipt.path("observations").size() == 2);
        var samples = new ArrayList<UiLogoComparison.Sample>();
        for (var row : receipt.path("observations")) {
            var variant = text(row, "variant");
            var condition = switch (variant) {
                case "ui-consumer-logo-localized" -> UiLogoComparison.Condition.PREFERRED_AVAILABLE;
                case "ui-consumer-logo-fallback" -> UiLogoComparison.Condition.PREFERRED_UNAVAILABLE;
                default -> throw new IllegalArgumentException("Unknown UI condition");
            };
            var request = entries.get(text(row, "requestReference"));
            var prepared = entries.get(text(row, "metadataReference"));
            var fetch = entries.get(text(row, "fetchReference"));
            require(request != null && prepared != null && fetch != null);
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
            require("samlscope-ui-consumer-observation-v1".equals(text(browser, "schema")) && "logo".equals(text(browser, "kind")));
            require(context.runId().equals(text(browser, "run_id")) && variant.equals(text(browser, "condition")));
            require("observed".equals(text(browser, "status")) && hash(metadataRaw).equals(text(browser, "fixture_sha256")));
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
            var info = one(one(one(metadata, MD, "SPSSODescriptor"), MD, "Extensions"), UI, "UIInfo");
            var logos = children(info, UI, "Logo");
            require(logos.size() == 2);
            var defaultLogos = logos.stream().filter(e -> !e.hasAttributeNS(XML, "lang")).toList();
            var localizedLogos = logos.stream().filter(e -> e.hasAttributeNS(XML, "lang")).toList();
            require(defaultLogos.size() == 1 && localizedLogos.size() == 1);
            var plain = defaultLogos.getFirst(); var localized = localizedLogos.getFirst();
            var language = localized.getAttributeNS(XML, "lang");
            require(language.matches("[A-Za-z]{2,8}(?:-[A-Za-z0-9]{1,8})*"));
            boolean matches = Locale.lookupTag(preferred, List.of(language)) != null;
            require(condition == UiLogoComparison.Condition.PREFERRED_AVAILABLE ? matches
                    : !matches && Locale.lookupTag(fallback, List.of(language)) == null);
            var observed = Instant.parse(text(browser, "observed_at"));
            require(!prepared.timestamp().isBefore(fetch.timestamp()) && !request.timestamp().isBefore(prepared.timestamp()));
            var fixed = new TreeMap<String, String>();
            fixed.put("preparation", preparation.toString()); fixed.put("entity", entity);
            fixed.put("selector", text(browser, "selector")); fixed.put("endpoint", request.url());
            for (var pair : Map.of("default", plain, "localized", localized).entrySet()) {
                fixed.put(pair.getKey() + "Image", pair.getValue().getTextContent());
                fixed.put(pair.getKey() + "Width", pair.getValue().getAttribute("width"));
                fixed.put(pair.getKey() + "Height", pair.getValue().getAttribute("height"));
            }
            var selection = switch (text(browser, "selected_candidate")) {
                case "localized" -> UiLogoComparison.Selection.LOCALIZED;
                case "default" -> UiLogoComparison.Selection.DEFAULT;
                default -> UiLogoComparison.Selection.UNOBSERVED;
            };
            samples.add(new UiLogoComparison.Sample(context.runId(), entity, condition, hash(mapper.writeValueAsBytes(fixed)),
                    hash(metadataRaw), hash(plain.getTextContent().getBytes(StandardCharsets.UTF_8)),
                    hash(localized.getTextContent().getBytes(StandardCharsets.UTF_8)), request.timestamp(), observed, selection,
                    List.of(new EvidenceRef("transcript", fetch.id()), new EvidenceRef("transcript", prepared.id()),
                            new EvidenceRef("transcript", request.id()), new EvidenceRef("browser-observation", context.runId() + ".json#" + hash(browserRaw)))));
        }
        return samples;
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
