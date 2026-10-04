package com.samlscope.runner.cases;

import com.samlscope.core.caseexec.CaseContext;
import com.samlscope.core.evaluation.CaseOutcome;
import com.samlscope.core.evaluation.EvidenceRef;
import com.samlscope.core.evaluation.Outcome;
import com.samlscope.core.transcript.Direction;
import com.samlscope.core.transcript.TranscriptContentReader;
import com.samlscope.core.transcript.TranscriptEntry;
import com.samlscope.saml.crypto.XmlSignatureVerifier;
import com.samlscope.saml.normal.SecureXml;
import com.samlscope.store.JsonCodec;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;
import org.w3c.dom.Element;

/** Explicit product parser refusal for both G03 DTD fixtures; silence never proves rejection. */
final class NativeDtdRejectionEvidence implements Function<CaseContext, Optional<CaseOutcome>> {
    private static final String PROTOCOL = "urn:oasis:names:tc:SAML:2.0:protocol";
    private static final String ASSERTION = "urn:oasis:names:tc:SAML:2.0:assertion";
    private static final String SIMPLE = "<!DOCTYPE samlp:AuthnRequest>";
    private static final String EXTERNAL = "<!DOCTYPE samlp:AuthnRequest [<!ENTITY % samlscope SYSTEM \"https://invalid.example/samlscope.dtd\"> %samlscope;]>";
    private static final DateTimeFormatter LOG_TIME = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss,SSS");
    private static final DateTimeFormatter SSP_LOG_TIME =
            DateTimeFormatter.ofPattern("EEE MMM dd HH:mm:ss.SSSSSS yyyy", Locale.ENGLISH);
    private final Path directory;
    private final TranscriptContentReader content;
    private final Function<String, byte[]> metadata;

    NativeDtdRejectionEvidence(Path directory, TranscriptContentReader content,
            Function<String, byte[]> metadata) {
        this.directory = Objects.requireNonNull(directory).toAbsolutePath().normalize();
        this.content = Objects.requireNonNull(content);
        this.metadata = Objects.requireNonNull(metadata);
    }

    @Override public Optional<CaseOutcome> apply(CaseContext context) {
        try {
            require(context.runId().matches("run_[0-9A-HJKMNP-TV-Z]{26}"));
            var file = directory.resolve(context.runId() + ".json");
            if (!Files.exists(file, LinkOption.NOFOLLOW_LINKS)) return Optional.empty();
            require(context.transcriptComplete() && Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS)
                    && Files.size(file) <= 32768);
            var rawReceipt = Files.readAllBytes(file);
            var receipt = new JsonCodec().mapper().readTree(rawReceipt);
            require("samlscope-native-dtd-rejection-v1".equals(receipt.path("schema").asText())
                    && context.runId().equals(receipt.path("runId").asText())
                    && Set.of("keycloak-native-parser", "simplesamlphp-native-parser",
                            "shibboleth-native-parser")
                            .contains(receipt.path("adapter").asText())
                    && receipt.path("restored").asBoolean(false)
                    && hash(metadata.apply(context.runId())).equals(receipt.path("targetMetadataSha256").asText()));
            var entries = new HashMap<String, TranscriptEntry>();
            for (var entry : context.transcript().list(context.runId())) {
                require(context.runId().equals(entry.runId()) && entries.put(entry.id(), entry) == null);
            }
            var baselineRequest = entry(entries, receipt.path("baselineRequest").asText(), "baseline-success", Direction.OUTBOUND);
            var baselineResponse = entries.get(receipt.path("baselineResponse").asText());
            require(baselineResponse != null && baselineResponse.direction() == Direction.INBOUND
                    && context.runId().equals(baselineResponse.runId()));
            var baseline = SecureXml.parse(content.readDecodedSaml(baselineRequest)).getDocumentElement();
            var response = SecureXml.parse(content.readDecodedSaml(baselineResponse)).getDocumentElement();
            require(PROTOCOL.equals(baseline.getNamespaceURI()) && "AuthnRequest".equals(baseline.getLocalName())
                    && PROTOCOL.equals(response.getNamespaceURI()) && "Response".equals(response.getLocalName())
                    && baseline.getAttribute("ID").equals(response.getAttribute("InResponseTo"))
                    && baselineResponse.correlationId().equals(baseline.getAttribute("ID"))
                    && "urn:oasis:names:tc:SAML:2.0:status:Success".equals(status(response))
                    && (response.getElementsByTagNameNS(ASSERTION, "Assertion").getLength()
                        + response.getElementsByTagNameNS(ASSERTION, "EncryptedAssertion").getLength()) > 0
                    && Boolean.TRUE.equals(baselineResponse.samlSummary().get("activeProbeAccepted"))
                    && !baselineResponse.timestamp().isBefore(baselineRequest.timestamp()));
            var rows = receipt.path("rejections");
            require(rows.isArray() && rows.size() == 2);
            var seen = new java.util.HashSet<String>();
            var refs = new ArrayList<EvidenceRef>();
            refs.add(new EvidenceRef("transcript", baselineResponse.id()));
            for (var row : rows) {
                var variant = row.path("variant").asText();
                require(Set.of("dtd-authn-request", "dtd-external-entity-authn-request").contains(variant)
                        && seen.add(variant));
                var request = entry(entries, row.path("requestReference").asText(), variant, Direction.OUTBOUND);
                var raw = content.readDecodedSaml(request);
                require(hash(raw).equals(row.path("requestSha256").asText()));
                var xml = new String(raw, StandardCharsets.UTF_8);
                var dtd = variant.equals("dtd-authn-request") ? SIMPLE : EXTERNAL;
                var declarationEnd = xml.indexOf("?>");
                var position = declarationEnd < 0 ? 0 : declarationEnd + 2;
                require(xml.startsWith(dtd, position)
                        && xml.indexOf("<!DOCTYPE", position + dtd.length()) < 0);
                var stripped = xml.substring(0, position) + xml.substring(position + dtd.length());
                var parsed = SecureXml.parse(stripped.getBytes(StandardCharsets.UTF_8)).getDocumentElement();
                require(PROTOCOL.equals(parsed.getNamespaceURI()) && "AuthnRequest".equals(parsed.getLocalName())
                        && parsed.getAttribute("ID").equals("_" + request.samlSummary().get("action_id"))
                        && new XmlSignatureVerifier().hasValidEnvelopedReferenceDigests(parsed));
                require(entries.values().stream().noneMatch(e -> e.direction() == Direction.INBOUND
                        && parsed.getAttribute("ID").equals(e.correlationId())));
                var log = row.path("productLog").asText();
                require(log.length() < 2048 && hash(log.getBytes(StandardCharsets.UTF_8))
                        .equals(row.path("logSha256").asText()));
                var adapter = receipt.path("adapter").asText();
                Instant rejectedAt;
                if ("keycloak-native-parser".equals(adapter)) {
                    require(log.contains("ERROR [org.keycloak.saml.common]")
                            && log.contains("ParsingException") && log.contains("DOCTYPE is disallowed"));
                    rejectedAt = LocalDateTime.parse(log.substring(0, 23), LOG_TIME).toInstant(ZoneOffset.UTC);
                } else if ("simplesamlphp-native-parser".equals(adapter)) {
                    require(log.contains("[php:notice]") && log.contains("[critical] Uncaught Exception:")
                            && log.contains("Dangerous XML detected, DOCTYPE nodes are not allowed in the XML body"));
                    rejectedAt = LocalDateTime.parse(log.substring(1, 32), SSP_LOG_TIME).toInstant(ZoneOffset.UTC);
                } else {
                    require(log.contains("ERROR [net.shibboleth.shared.xml.impl.BasicParserPool:72] - XML Parsing Error")
                            && log.contains("Caused by: org.xml.sax.SAXParseException;")
                            && log.contains("DOCTYPE is disallowed")
                            && log.indexOf('\n') > 0);
                    rejectedAt = LocalDateTime.parse(log.substring(0, 23), LOG_TIME).toInstant(ZoneOffset.UTC);
                }
                require(!rejectedAt.isBefore(request.timestamp())
                        && !rejectedAt.isAfter(request.timestamp().plus(Duration.ofSeconds(5)))
                        && request.timestamp().isAfter(baselineResponse.timestamp()));
                refs.add(new EvidenceRef("transcript", request.id()));
            }
            require(seen.size() == 2);
            return Optional.of(new CaseOutcome(Outcome.SATISFIED, null,
                    "idp.dtd.native-rejection-observed", "idp.dtd.native-rejection-observed",
                    List.copyOf(refs), Map.of("adapter", receipt.path("adapter").asText(),
                            "native_receipt_sha256", hash(rawReceipt), "product_rejections", 2)));
        } catch (Exception unproven) {
            return Optional.of(CaseOutcome.notVerified(
                    "native_dtd_rejection_unproven", "idp.dtd.native-evidence-unproven"));
        }
    }

    private TranscriptEntry entry(Map<String, TranscriptEntry> entries, String ref, String fixture, Direction direction) {
        var value = entries.get(ref);
        require(value != null && value.direction() == direction
                && IdpExecutableBrowserFixtureScenarioTestCase.G03_CASE.equals(value.samlSummary().get("scenario_case_id"))
                && fixture.equals(value.samlSummary().get("fixture_id")));
        return value;
    }

    private static String status(Element response) {
        var statuses = response.getElementsByTagNameNS(PROTOCOL, "StatusCode");
        return statuses.getLength() == 1 ? ((Element) statuses.item(0)).getAttribute("Value") : "";
    }

    private static String hash(byte[] bytes) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
    }

    private static void require(boolean value) {
        if (!value) throw new IllegalArgumentException("Native DTD rejection evidence unproven");
    }
}
